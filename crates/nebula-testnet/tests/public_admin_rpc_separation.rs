use ed25519_dalek::{Signer, SigningKey};
use nebula_testnet::{
    runtime::{
        serve_runtime_rpc_with_options, withdrawal_authorization_root, RuntimeConfig,
        RuntimeNodeOptions, RuntimeTransaction, MIN_BRIDGE_CONFIRMATIONS,
    },
    NBLA_SYMBOL,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

const ADMIN_TOKEN: &str = "testnet-admin-token";

const ADMIN_METHODS: &[&str] = &[
    "nebula_importSnapshot",
    "nebula_observeBridgeDeposit",
    "nebula_finalizeWithdrawal",
    "nebula_rotateSequencerKey",
    "nebula_reportEquivocation",
    "nebula_produceBlock",
];

#[test]
fn admin_rpc_methods_require_token_before_params() {
    let rpc_addr = start_rpc_server(Some(ADMIN_TOKEN));

    for method in ADMIN_METHODS {
        let missing = rpc_call(&rpc_addr, method, json!({}));
        assert_rpc_error_contains(&missing, "admin token");

        let wrong = rpc_call(&rpc_addr, method, json!({ "admin_token": "wrong-token" }));
        assert_rpc_error_contains(&wrong, "admin token");
    }
}

#[test]
fn public_rpc_methods_remain_callable_without_admin_token() {
    let rpc_addr = start_rpc_server(Some(ADMIN_TOKEN));
    let tx_account = account_id(0x44);
    let withdrawal_account = account_id(0x45);

    let status = rpc_call(&rpc_addr, "nebula_status", json!({}));
    assert_eq!(rpc_result(&status)["node_role"], "sequencer");

    let quote = rpc_call(
        &rpc_addr,
        "nebula_feeQuote",
        json!({
            "fee_asset": NBLA_SYMBOL,
            "gas_units": 1,
            "gas_price_nebulai": 1,
        }),
    );
    assert_eq!(rpc_result(&quote)["payment_asset_symbol"], NBLA_SYMBOL);

    let faucet = rpc_call(
        &rpc_addr,
        "nebula_faucet",
        json!({ "account": tx_account.clone() }),
    );
    assert_eq!(rpc_result(&faucet)["account"], tx_account);
    let withdrawal_faucet = rpc_call(
        &rpc_addr,
        "nebula_faucet",
        json!({ "account": withdrawal_account.clone() }),
    );
    assert_eq!(
        rpc_result(&withdrawal_faucet)["account"],
        withdrawal_account
    );
    assert_eq!(rpc_result(&withdrawal_faucet)["credited_nxmr_units"], 0);
    let bridge_deposit = rpc_call(
        &rpc_addr,
        "nebula_observeBridgeDeposit",
        json!({
            "admin_token": ADMIN_TOKEN,
            "deposit": bridge_deposit(0x45, 1),
        }),
    );
    assert_eq!(rpc_result(&bridge_deposit)["credited"], true);

    let submitted = rpc_call(
        &rpc_addr,
        "nebula_sendTransaction",
        json!({ "tx": signed_transaction(0x44, 0, "bob-public-rpc") }),
    );
    assert_eq!(rpc_result(&submitted)["accepted_to_mempool"], true);

    let withdrawal = rpc_call(
        &rpc_addr,
        "nebula_requestWithdrawal",
        json!({
            "account": withdrawal_account.clone(),
            "monero_address": "monero-testnet-address-0001",
            "amount_nxmr_units": 1,
            "nonce": 0,
            "signature": withdrawal_signature(
                0x45,
                "monero-testnet-address-0001",
                1,
                0
            ),
        }),
    );
    assert_eq!(rpc_result(&withdrawal)["accepted"], true);
}

#[test]
fn metrics_endpoint_exposes_public_rpc_operational_gauges() {
    let rpc_addr = start_rpc_server(Some(ADMIN_TOKEN));

    let (headers, body) =
        http_text(&rpc_addr, "GET", "/metrics", None).expect("metrics endpoint responds");

    assert!(headers.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(body.contains("# HELP nebula_latest_height"));
    assert!(body.contains("nebula_sub_second_blocks 1"));
    assert!(body.contains("nebula_rpc_max_request_bytes "));
    assert!(body.contains("nebula_rpc_max_requests_per_minute 10000"));
    assert!(body.contains("nebula_sync_peer_quorum 1"));
    assert!(body.contains("nebula_sync_quorum_met 0"));
    assert!(body.contains("nebula_sync_quorum_peer_count 0"));
    assert!(body.contains("nebula_sync_successful_peer_count 0"));
    assert!(body.contains("nebula_sync_attempt_count 0"));
    assert!(body.contains("nebula_sync_quorum_rejection_count 0"));
    assert!(body.contains("nebula_sync_import_count 0"));
    assert!(body.contains("nebula_mempool_admission_rejection_count 0"));
    assert!(body.contains("nebula_faucet_nxmr_units 0"));
    assert!(body.contains("nebula_bridge_only_nxmr 1"));
    assert!(body.contains("nebula_bridge_custody_reconciled 1"));
    assert!(body.contains("nebula_nxmr_custody_deficit_units 0"));
    assert!(body.contains("nebula_admin_rpc_enabled 1"));
    assert!(body.contains("nebula_bridge_deposit_count 0"));
    assert!(body.contains("nebula_sequencer_accountability_clean 1"));
    assert!(body.contains("nebula_public_ops_ready "));
}

#[test]
fn health_endpoint_exposes_chain_root_ops_and_backup_evidence() {
    let rpc_addr = start_rpc_server(Some(ADMIN_TOKEN));

    let health = http_json(&rpc_addr, "GET", "/health", None).expect("health endpoint responds");
    let status = rpc_result(&rpc_call(&rpc_addr, "nebula_status", json!({}))).clone();

    assert_eq!(health["ok"], true);
    assert_eq!(health["service"], "nebula-testnet-rpc");
    assert_eq!(health["chain_id"], status["chain_id"]);
    assert_eq!(health["runtime_version"], status["runtime_version"]);
    assert_eq!(health["node_role"], status["node_role"]);
    assert_eq!(health["block_target_ms"], status["block_target_ms"]);
    assert_eq!(health["sub_second_blocks"], true);
    assert_eq!(
        health["sequencer_public_key_hex"],
        status["sequencer_public_key_hex"]
    );
    assert_eq!(health["bridge_policy_root"], status["bridge_policy_root"]);
    assert_eq!(health["sync_peer_quorum"], status["sync_peer_quorum"]);
    assert_eq!(health["sync_quorum_met"], status["sync_quorum_met"]);
    assert_eq!(
        health["sync_quorum_peer_count"],
        status["sync_quorum_peer_count"]
    );
    assert_eq!(health["sync_quorum_height"], status["sync_quorum_height"]);
    assert_eq!(
        health["sync_quorum_latest_hash"],
        status["sync_quorum_latest_hash"]
    );
    assert_eq!(
        health["sync_quorum_state_root"],
        status["sync_quorum_state_root"]
    );
    assert_eq!(health["sync_successful_peer_count"], 0);
    assert_eq!(health["sync_attempt_count"], 0);
    assert_eq!(health["admin_rpc_enabled"], true);
    assert_eq!(health["latest_hash"].as_str().unwrap().len(), 64);
    assert_eq!(health["latest_state_root"].as_str().unwrap().len(), 64);
    assert_eq!(health["current_state_root"].as_str().unwrap().len(), 64);
    assert_eq!(health["snapshot_root"].as_str().unwrap().len(), 64);
    assert_eq!(health["state_root"].as_str().unwrap().len(), 64);
    assert_eq!(health["ops_root"].as_str().unwrap().len(), 64);
    assert_eq!(health["backup_root"].as_str().unwrap().len(), 64);
    assert!(health["public_ops_ready"].is_boolean());
    assert!(health["snapshot_persisted"].is_boolean());
    assert!(health["storage_snapshot_matches_runtime"].is_boolean());
    assert!(health["public_ops_blocking_gaps"].is_array());
}

#[test]
fn accountability_evidence_closes_admin_producer_mutations_but_remains_visible() {
    let rpc_addr = start_rpc_server(Some(ADMIN_TOKEN));

    let block = rpc_call(
        &rpc_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    let block = rpc_result(&block);
    let height = block["height"].as_u64().expect("block height is a u64");
    let first_block_hash = block["block_hash"]
        .as_str()
        .expect("block hash is a string");

    let report = rpc_call(
        &rpc_addr,
        "nebula_reportEquivocation",
        json!({
            "admin_token": ADMIN_TOKEN,
            "height": height,
            "first_block_hash": first_block_hash,
            "second_block_hash": hex_64("second-block"),
            "reporter_id": "operator-a",
            "evidence_root": hex_64("equivocation-evidence"),
        }),
    );
    let report = rpc_result(&report);
    assert_eq!(report["recorded"], true);
    assert_eq!(report["sequencer_accountability_clean"], false);

    let status = rpc_call(&rpc_addr, "nebula_status", json!({}));
    let status = rpc_result(&status);
    assert_eq!(status["accountability_report_count"], 1);
    assert_eq!(status["sequencer_accountability_clean"], false);

    let ops_status = rpc_call(&rpc_addr, "nebula_opsStatus", json!({}));
    let ops_status = rpc_result(&ops_status);
    assert_eq!(ops_status["accountability_report_count"], 1);
    assert_eq!(ops_status["sequencer_accountability_clean"], false);
    assert!(ops_status["blocking_gaps"]
        .as_array()
        .expect("blocking_gaps is an array")
        .iter()
        .any(|gap| gap == "sequencer-accountability-evidence-open"));

    let block_after_evidence = rpc_call(
        &rpc_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    assert_rpc_error_contains(&block_after_evidence, "accountability evidence");

    let rotation_after_evidence = rpc_call(
        &rpc_addr,
        "nebula_rotateSequencerKey",
        json!({
            "admin_token": ADMIN_TOKEN,
            "new_sequencer_secret_key_hex": "4d".repeat(32),
            "operator_id": "operator-a",
            "approval_root": hex_64("rotation-approval"),
        }),
    );
    assert_rpc_error_contains(&rotation_after_evidence, "accountability evidence");
}

fn start_rpc_server(admin_token: Option<&str>) -> String {
    let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve local RPC port");
    let bind_addr = reserved
        .local_addr()
        .expect("reserved listener has local address")
        .to_string();
    drop(reserved);

    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;

    let options = RuntimeNodeOptions {
        admin_token: admin_token.map(str::to_string),
        max_requests_per_minute: 10_000,
        ..RuntimeNodeOptions::default()
    };
    let server_addr = bind_addr.clone();
    thread::spawn(move || {
        serve_runtime_rpc_with_options(&server_addr, config, options)
            .expect("runtime RPC server should keep serving");
    });

    wait_for_rpc(&bind_addr);
    bind_addr
}

fn wait_for_rpc(rpc_addr: &str) {
    for _ in 0..100 {
        if let Ok(response) = http_json(rpc_addr, "GET", "/health", None) {
            if response["ok"] == true {
                return;
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("runtime RPC server did not become ready at {rpc_addr}");
}

fn rpc_call(rpc_addr: &str, method: &str, params: Value) -> Value {
    http_json(
        rpc_addr,
        "POST",
        "/rpc",
        Some(json!({
            "jsonrpc": "2.0",
            "id": method,
            "method": method,
            "params": params,
        })),
    )
    .expect("JSON-RPC request succeeds")
}

fn http_json(
    rpc_addr: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut stream =
        TcpStream::connect(rpc_addr).map_err(|error| format!("connect {rpc_addr}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set read timeout: {error}"))?;

    let body = body.map(|value| value.to_string()).unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {rpc_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .map_err(|error| format!("write request: {error}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read response: {error}"))?;
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(format!("malformed HTTP response: {response}"));
    };
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(format!("{status_line}: {body}"));
    }
    serde_json::from_str(body.trim()).map_err(|error| format!("parse response JSON: {error}"))
}

fn http_text(
    rpc_addr: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(String, String), String> {
    let mut stream =
        TcpStream::connect(rpc_addr).map_err(|error| format!("connect {rpc_addr}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set read timeout: {error}"))?;

    let body = body.map(|value| value.to_string()).unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {rpc_addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .map_err(|error| format!("write request: {error}"))?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| format!("read response: {error}"))?;
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(format!("malformed HTTP response: {response}"));
    };
    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(format!("{status_line}: {body}"));
    }
    Ok((head.to_string(), body.to_string()))
}

fn rpc_result(response: &Value) -> &Value {
    if response.get("error").is_some() {
        panic!("expected JSON-RPC result, got {response}");
    }
    response
        .get("result")
        .unwrap_or_else(|| panic!("missing JSON-RPC result in {response}"))
}

fn assert_rpc_error_contains(response: &Value, expected: &str) {
    let message = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("expected JSON-RPC error containing {expected}, got {response}"));
    assert!(
        message.contains(expected),
        "expected JSON-RPC error containing {expected:?}, got {message:?}"
    );
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn account_id(seed: u8) -> String {
    hex::encode(signing_key(seed).verifying_key().to_bytes())
}

fn sign_root(seed: u8, root: &str) -> String {
    hex::encode(signing_key(seed).sign(root.as_bytes()).to_bytes())
}

fn signed_transaction(seed: u8, nonce: u64, to: &str) -> RuntimeTransaction {
    let mut tx = RuntimeTransaction {
        from: account_id(seed),
        to: to.to_string(),
        amount_nebulai: 1,
        gas_units: 1,
        gas_price_nebulai: 1,
        fee_asset: NBLA_SYMBOL.to_string(),
        nonce,
        signature: String::new(),
        memo: None,
    };
    tx.signature = sign_root(seed, &tx.signing_root());
    tx
}

fn withdrawal_signature(
    seed: u8,
    monero_address: &str,
    amount_nxmr_units: u128,
    nonce: u64,
) -> String {
    sign_root(
        seed,
        &withdrawal_authorization_root(&account_id(seed), monero_address, amount_nxmr_units, nonce),
    )
}

fn bridge_deposit(seed: u8, amount_nxmr_units: u128) -> Value {
    json!({
        "monero_tx_id": hex_64("m45"),
        "account": account_id(seed),
        "amount_nxmr_units": amount_nxmr_units,
        "confirmations": MIN_BRIDGE_CONFIRMATIONS,
        "observer_id": "observer-public-rpc",
        "proof_root": hex_64("p45"),
        "custody_proof_root": hex_64("c45"),
        "relayer_set_root": hex_64("r45"),
        "observer_signature_roots": [hex_64("s45a"), hex_64("s45b")],
        "observed_at_unix_ms": 1,
    })
}

fn hex_64(label: &str) -> String {
    let mut bytes = label.as_bytes().to_vec();
    bytes.resize(32, 0);
    hex::encode(bytes)
}
