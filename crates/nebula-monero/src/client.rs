//! A minimal HTTP JSON-RPC client for `monerod` and `monero-wallet-rpc`, implementing the
//! [`MoneroRpc`](crate::verify::MoneroRpc) transport an observer uses to verify deposits.
//!
//! This speaks plain HTTP/1.1 (the usual transport to a trusted local wallet-rpc / daemon) and
//! parses the two responses Nebula's bridge needs: `check_tx_key` (a view-key amount proof) and
//! `get_transactions` (to recover a transaction's `tx_extra`). TLS can be layered on later; for a
//! testnet bridge the wallet-rpc is typically reached over a private/loopback link.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};

use crate::verify::{MoneroRpc, WalletTxProof};

const TIMEOUT: Duration = Duration::from_secs(30);

/// An HTTP client for a monerod daemon and a monero-wallet-rpc instance.
#[derive(Debug, Clone)]
pub struct HttpMoneroRpc {
    /// Base URL of the wallet-rpc instance, e.g. `http://127.0.0.1:18083`.
    pub wallet_rpc_url: String,
    /// Base URL of the monerod daemon, e.g. `http://127.0.0.1:18081`.
    pub daemon_rpc_url: String,
}

impl HttpMoneroRpc {
    /// Construct a client from a wallet-rpc and a daemon base URL (trailing slashes are trimmed).
    pub fn new(wallet_rpc_url: impl Into<String>, daemon_rpc_url: impl Into<String>) -> Self {
        let trim = |url: String| url.trim_end_matches('/').to_string();
        HttpMoneroRpc {
            wallet_rpc_url: trim(wallet_rpc_url.into()),
            daemon_rpc_url: trim(daemon_rpc_url.into()),
        }
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
        let response = http_post_json(&format!("{}/json_rpc", self.wallet_rpc_url), &request)?;
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
        let response = http_post_json(
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
}

/// Parse `http://host:port/maybe/path` into (`host:port`, host, `/path`).
fn parse_http_url(url: &str) -> Result<(String, String, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("monero rpc url must start with http://: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("monero rpc url has no host: {url}"));
    }
    let host = authority.split(':').next().unwrap_or(authority).to_string();
    Ok((authority.to_string(), host, path.to_string()))
}

/// POST a JSON body to `url` over plain HTTP/1.1 and parse the JSON response body.
fn http_post_json(url: &str, body: &Value) -> Result<Value, String> {
    let (authority, host, path) = parse_http_url(url)?;
    let body = body.to_string();
    let mut stream = TcpStream::connect(&authority)
        .map_err(|error| format!("connect to monero rpc {authority}: {error}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("write to monero rpc: {error}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read from monero rpc: {error}"))?;
    let body_start = response
        .find("\r\n\r\n")
        .ok_or_else(|| "monero rpc response is not valid HTTP".to_string())?
        + 4;
    serde_json::from_str(&response[body_start..])
        .map_err(|error| format!("monero rpc response is not JSON: {error}"))
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
    fn rejects_non_http_urls() {
        assert!(parse_http_url("https://example.com").is_err());
        let (authority, host, path) =
            parse_http_url("http://127.0.0.1:18081/get_transactions").unwrap();
        assert_eq!(authority, "127.0.0.1:18081");
        assert_eq!(host, "127.0.0.1");
        assert_eq!(path, "/get_transactions");
    }
}
