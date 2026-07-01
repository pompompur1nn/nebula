//! A minimal HTTP/HTTPS JSON-RPC client for `monerod` and `monero-wallet-rpc`, implementing the
//! [`MoneroRpc`](crate::verify::MoneroRpc) transport an observer uses to verify deposits.
//!
//! It parses the two responses Nebula's bridge needs: `check_tx_key` (a view-key amount proof) and
//! `get_transactions` (to recover a transaction's `tx_extra`). Both plain `http://` (for a trusted
//! loopback link) and `https://` are supported; for `https://` the server certificate is validated
//! against the webpki root store, and — when the client is configured with certificate pins — the
//! leaf certificate's SHA-256 must additionally match one of the pins, giving MITM-resistant
//! transport ("TLS pins") to a remote wallet-rpc / daemon.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::verify::{MoneroRpc, WalletTxProof};

const TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a Monero RPC response body so a hostile/broken endpoint cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// An HTTP/HTTPS client for a monerod daemon and a monero-wallet-rpc instance.
#[derive(Debug, Clone)]
pub struct HttpMoneroRpc {
    /// Base URL of the wallet-rpc instance, e.g. `http://127.0.0.1:18083` or `https://host:18083`.
    pub wallet_rpc_url: String,
    /// Base URL of the monerod daemon, e.g. `http://127.0.0.1:18081`.
    pub daemon_rpc_url: String,
    /// Optional SHA-256 pins of the leaf TLS certificate(s). When non-empty, an `https://` endpoint
    /// must present a leaf certificate whose SHA-256 matches one of these, on top of normal webpki
    /// chain validation.
    cert_pins: Vec<[u8; 32]>,
}

impl HttpMoneroRpc {
    /// Construct a client from a wallet-rpc and a daemon base URL (trailing slashes are trimmed).
    pub fn new(wallet_rpc_url: impl Into<String>, daemon_rpc_url: impl Into<String>) -> Self {
        let trim = |url: String| url.trim_end_matches('/').to_string();
        HttpMoneroRpc {
            wallet_rpc_url: trim(wallet_rpc_url.into()),
            daemon_rpc_url: trim(daemon_rpc_url.into()),
            cert_pins: Vec::new(),
        }
    }

    /// Pin the leaf TLS certificate(s) by SHA-256. Any `https://` request must then present a leaf
    /// certificate whose SHA-256 is in this set. Ignored for plain `http://`.
    pub fn with_cert_pins(mut self, pins: Vec<[u8; 32]>) -> Self {
        self.cert_pins = pins;
        self
    }

    /// Convenience: parse hex-encoded SHA-256 certificate pins.
    pub fn with_cert_pins_hex(self, pins_hex: &[String]) -> Result<Self, String> {
        let mut pins = Vec::with_capacity(pins_hex.len());
        for pin in pins_hex {
            let bytes =
                hex::decode(pin).map_err(|error| format!("invalid cert pin hex: {error}"))?;
            let array: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "cert pin must be a 32-byte SHA-256".to_string())?;
            pins.push(array);
        }
        Ok(self.with_cert_pins(pins))
    }

    fn post_json(&self, url: &str, body: &Value) -> Result<Value, String> {
        let parsed = parse_url(url)?;
        let body = body.to_string();
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            path = parsed.path,
            authority = parsed.authority,
            len = body.len(),
        );
        let raw = if parsed.https {
            self.https_request(&parsed, &request)?
        } else {
            plain_request(&parsed, &request)?
        };
        let body_start = raw
            .find("\r\n\r\n")
            .ok_or_else(|| "monero rpc response is not valid HTTP".to_string())?
            + 4;
        serde_json::from_str(&raw[body_start..])
            .map_err(|error| format!("monero rpc response is not JSON: {error}"))
    }

    fn https_request(&self, parsed: &ParsedUrl, request: &str) -> Result<String, String> {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = rustls::crypto::ring::default_provider();
        let webpki = WebPkiServerVerifier::builder_with_provider(
            Arc::new(root_store),
            Arc::new(provider.clone()),
        )
        .build()
        .map_err(|error| format!("failed to build monero rpc TLS verifier: {error}"))?;
        let verifier = Arc::new(PinnedServerCertVerifier {
            inner: webpki,
            pins: self.cert_pins.clone(),
        });
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("failed to configure monero rpc TLS versions: {error}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let server_name = ServerName::try_from(parsed.host.clone()).map_err(|error| {
            format!(
                "invalid monero rpc TLS server name {}: {error}",
                parsed.host
            )
        })?;
        let stream = TcpStream::connect((parsed.host.as_str(), parsed.port))
            .map_err(|error| format!("connect to monero rpc {}: {error}", parsed.authority))?;
        stream.set_read_timeout(Some(TIMEOUT)).ok();
        stream.set_write_timeout(Some(TIMEOUT)).ok();
        let connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| format!("failed to start monero rpc TLS: {error}"))?;
        let mut tls = StreamOwned::new(connection, stream);
        while tls.conn.is_handshaking() {
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|error| format!("monero rpc TLS handshake failed: {error}"))?;
        }
        tls.write_all(request.as_bytes())
            .map_err(|error| format!("write to monero rpc: {error}"))?;
        tls.flush()
            .map_err(|error| format!("flush monero rpc request: {error}"))?;
        read_response_limited(&mut tls)
    }
}

impl MoneroRpc for HttpMoneroRpc {
    fn check_tx_key(
        &self,
        txid: &str,
        tx_key: &str,
        address: &str,
    ) -> Result<WalletTxProof, String> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "check_tx_key",
            "params": { "txid": txid, "tx_key": tx_key, "address": address },
        });
        let response = self.post_json(&format!("{}/json_rpc", self.wallet_rpc_url), &request)?;
        if let Some(error) = response.get("error") {
            return Err(format!("wallet-rpc check_tx_key error: {error}"));
        }
        let result = response
            .get("result")
            .ok_or_else(|| "wallet-rpc response missing result".to_string())?;
        let received_atomic = u128::from(
            result
                .get("received")
                .and_then(Value::as_u64)
                .ok_or_else(|| "check_tx_key result missing received".to_string())?,
        );
        let confirmations = result
            .get("confirmations")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let in_pool = result
            .get("in_pool")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok(WalletTxProof {
            received_atomic,
            confirmations,
            in_pool,
        })
    }

    fn tx_extra(&self, txid: &str) -> Result<Vec<u8>, String> {
        let request = json!({ "txs_hashes": [txid], "decode_as_json": true });
        let response = self.post_json(
            &format!("{}/get_transactions", self.daemon_rpc_url),
            &request,
        )?;
        let txs = response
            .get("txs")
            .and_then(Value::as_array)
            .ok_or_else(|| "get_transactions response missing txs".to_string())?;
        let tx = txs
            .first()
            .ok_or_else(|| format!("monero transaction {txid} not found"))?;
        let as_json = tx
            .get("as_json")
            .and_then(Value::as_str)
            .ok_or_else(|| "get_transactions tx missing as_json".to_string())?;
        let decoded: Value = serde_json::from_str(as_json)
            .map_err(|error| format!("monero tx as_json is malformed: {error}"))?;
        let extra = decoded
            .get("extra")
            .and_then(Value::as_array)
            .ok_or_else(|| "monero tx as_json missing extra".to_string())?;
        extra
            .iter()
            .map(|byte| {
                byte.as_u64()
                    .filter(|n| *n <= u64::from(u8::MAX))
                    .map(|n| n as u8)
                    .ok_or_else(|| "monero tx_extra contains a non-byte value".to_string())
            })
            .collect()
    }

    fn custody_unlocked_balance(&self) -> Result<u128, String> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": "get_balance",
            "params": { "account_index": 0 },
        });
        let response = self.post_json(&format!("{}/json_rpc", self.wallet_rpc_url), &request)?;
        if let Some(error) = response.get("error") {
            return Err(format!("wallet-rpc get_balance error: {error}"));
        }
        let result = response
            .get("result")
            .ok_or_else(|| "wallet-rpc response missing result".to_string())?;
        let unlocked = result
            .get("unlocked_balance")
            .and_then(Value::as_u64)
            .ok_or_else(|| "get_balance result missing unlocked_balance".to_string())?;
        Ok(u128::from(unlocked))
    }
}

/// A parsed monero RPC URL.
struct ParsedUrl {
    https: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

/// Parse `http[s]://host[:port]/maybe/path`.
fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!(
            "monero rpc url must start with http:// or https://: {url}"
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("monero rpc url has no host: {url}"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|error| format!("invalid port in {url}: {error}"))?,
        ),
        None => (authority.to_string(), if https { 443 } else { 80 }),
    };
    Ok(ParsedUrl {
        https,
        host,
        port,
        authority: authority.to_string(),
        path: path.to_string(),
    })
}

/// POST over plain HTTP/1.1.
fn plain_request(parsed: &ParsedUrl, request: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port))
        .map_err(|error| format!("connect to monero rpc {}: {error}", parsed.authority))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write to monero rpc: {error}"))?;
    read_response_limited(&mut stream)
}

/// Read an HTTP response, bounded by [`MAX_RESPONSE_BYTES`].
fn read_response_limited(reader: &mut impl Read) -> Result<String, String> {
    let mut buffer = Vec::new();
    reader
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut buffer)
        .map_err(|error| format!("read from monero rpc: {error}"))?;
    if buffer.len() > MAX_RESPONSE_BYTES {
        return Err("monero rpc response exceeded the size limit".to_string());
    }
    String::from_utf8(buffer).map_err(|error| format!("monero rpc response is not UTF-8: {error}"))
}

/// A server-certificate verifier that performs standard webpki chain validation and, when pins are
/// configured, additionally requires the leaf certificate's SHA-256 to match one of them.
#[derive(Debug)]
struct PinnedServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pins: Vec<[u8; 32]>,
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if !self.pins.is_empty() {
            let digest = Sha256::digest(end_entity.as_ref());
            let matched = self.pins.iter().any(|pin| pin[..] == digest[..]);
            if !matched {
                return Err(rustls::Error::General(
                    "monero rpc TLS certificate pin mismatch".to_string(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Spin up a one-shot localhost HTTP server that replies to a single request with `body`.
    fn stub_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        let addr = listener.local_addr().expect("stub server addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 8192];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn parses_check_tx_key_response() {
        let url = stub_server(
            r#"{"id":"0","jsonrpc":"2.0","result":{"confirmations":12,"in_pool":false,"received":1000000000000}}"#,
        );
        let rpc = HttpMoneroRpc::new(url, "http://127.0.0.1:1");
        let proof = rpc.check_tx_key("tx", "key", "addr").unwrap();
        assert_eq!(proof.received_atomic, 1_000_000_000_000);
        assert_eq!(proof.confirmations, 12);
        assert!(!proof.in_pool);
    }

    #[test]
    fn surfaces_wallet_rpc_errors() {
        let url =
            stub_server(r#"{"id":"0","jsonrpc":"2.0","error":{"code":-1,"message":"bad tx_key"}}"#);
        let rpc = HttpMoneroRpc::new(url, "http://127.0.0.1:1");
        assert!(rpc.check_tx_key("tx", "key", "addr").is_err());
    }

    #[test]
    fn parses_tx_extra_from_get_transactions() {
        // monerod nests the decoded transaction (including `extra`) as a stringified JSON field.
        let inner = r#"{\"version\":2,\"extra\":[1,2,3,4]}"#;
        let body: &'static str = Box::leak(
            format!(r#"{{"status":"OK","txs":[{{"as_json":"{inner}"}}]}}"#).into_boxed_str(),
        );
        let url = stub_server(body);
        let rpc = HttpMoneroRpc::new("http://127.0.0.1:1", url);
        assert_eq!(rpc.tx_extra("txid").unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn parses_http_and_https_urls() {
        let http = parse_url("http://127.0.0.1:18081/get_transactions").unwrap();
        assert!(!http.https);
        assert_eq!(http.authority, "127.0.0.1:18081");
        assert_eq!(http.host, "127.0.0.1");
        assert_eq!(http.port, 18081);
        assert_eq!(http.path, "/get_transactions");

        // https is now accepted and defaults to port 443 when unspecified.
        let https = parse_url("https://wallet.example/json_rpc").unwrap();
        assert!(https.https);
        assert_eq!(https.host, "wallet.example");
        assert_eq!(https.port, 443);
        assert_eq!(https.path, "/json_rpc");

        let https_port = parse_url("https://wallet.example:18083").unwrap();
        assert_eq!(https_port.port, 18083);
        assert_eq!(https_port.path, "/");

        // An unsupported scheme is rejected.
        assert!(parse_url("ftp://example.com").is_err());
    }

    #[test]
    fn cert_pins_are_configured_from_hex() {
        let pin = "ab".repeat(32);
        let rpc = HttpMoneroRpc::new("https://a", "https://b")
            .with_cert_pins_hex(&[pin])
            .unwrap();
        assert_eq!(rpc.cert_pins.len(), 1);
        assert_eq!(rpc.cert_pins[0], [0xabu8; 32]);
        // A malformed pin is rejected.
        assert!(HttpMoneroRpc::new("https://a", "https://b")
            .with_cert_pins_hex(&["nothex".to_string()])
            .is_err());
    }
}
