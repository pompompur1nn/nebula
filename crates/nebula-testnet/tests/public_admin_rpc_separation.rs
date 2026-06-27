use ed25519_dalek::{Signer, SigningKey};
use nebula_testnet::{
    build_genesis_manifest_json_pretty, build_launch_package_bundle_json_pretty,
    build_operator_acceptance_json_pretty, build_operator_handoff_json_pretty,
    build_runtime_launch_binding_from_jsons, build_runtime_surface_evidence_json_pretty,
    runtime::{
        bridge_observer_deposit_payload_root, bridge_observer_evidence_root,
        sequencer_key_rotation_approval_root, sequencer_key_rotation_payload_root,
        serve_runtime_rpc_with_options, withdrawal_authorization_root,
        withdrawal_operator_approval_root, withdrawal_operator_finalization_payload_root,
        NebulaRuntime, RuntimeBridgeDeposit, RuntimeBridgeObserverEvidence, RuntimeConfig,
        RuntimeLaunchBinding, RuntimeNodeOptions, RuntimePublicTestnetPeerManifestBinding,
        RuntimeSequencerKeyRotationApproval, RuntimeStorage, RuntimeTransaction,
        RuntimeWithdrawalOperatorApproval, RuntimeWithdrawalRequest, MIN_BRIDGE_CONFIRMATIONS,
    },
    sample_deployment_attestation_json_pretty, sample_public_probe_json_pretty,
    sample_public_status_manifest_json_pretty, sample_validator_set_json_pretty,
    verify_runtime_surface_evidence_json, AttestationError, RuntimeSurfaceEvidenceBuildInput,
    CHAIN_ID, NBLA_SYMBOL, NXMR_SYMBOL, RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET,
};
use serde_json::{json, Value};
use std::{
    env,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    let (_public_addr, admin_addr) = start_rpc_server_with_admin(Some(ADMIN_TOKEN));

    for method in ADMIN_METHODS {
        let missing = rpc_call(&admin_addr, method, json!({}));
        assert_rpc_error_contains(&missing, "admin token");

        let wrong = rpc_call(&admin_addr, method, json!({ "admin_token": "wrong-token" }));
        assert_rpc_error_contains(&wrong, "admin token");
    }
}

#[test]
fn public_rpc_rejects_admin_methods_even_with_valid_token() {
    let (public_addr, _admin_addr) = start_rpc_server_with_admin(Some(ADMIN_TOKEN));

    for method in ADMIN_METHODS {
        let rejected = rpc_call(&public_addr, method, json!({ "admin_token": ADMIN_TOKEN }));
        assert_rpc_error_contains(&rejected, "public RPC listener");
    }
}

#[test]
fn public_rpc_methods_remain_callable_without_admin_token() {
    let (rpc_addr, admin_addr) = start_rpc_server_with_admin(Some(ADMIN_TOKEN));
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
        &admin_addr,
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
fn public_rpc_rejects_connections_above_active_connection_cap_before_request() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    let rpc_addr = start_rpc_server_with_config(
        config,
        RuntimeNodeOptions {
            max_active_connections: 1,
            max_requests_per_minute: 10_000,
            ..RuntimeNodeOptions::default()
        },
    );

    let held = TcpStream::connect(&rpc_addr).expect("held connection opens");
    held.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set held read timeout");
    thread::sleep(Duration::from_millis(100));

    let mut rejected = TcpStream::connect(&rpc_addr).expect("second connection opens");
    rejected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set rejected read timeout");
    let mut response = String::new();
    rejected
        .read_to_string(&mut response)
        .expect("read rejection response");

    assert!(
        response.starts_with("HTTP/1.1 503"),
        "expected 503 active connection rejection, got {response:?}"
    );
    assert!(response.contains("active connection limit exceeded"));
    let (_, body) = response
        .split_once("\r\n\r\n")
        .expect("rejection response has body");
    let body = serde_json::from_str::<Value>(body.trim()).expect("rejection body is JSON");
    assert_eq!(body["listener"], "public");
    assert_eq!(body["max_active_connections"], 1);

    drop(held);
    wait_for_rpc(&rpc_addr);
}

#[test]
fn public_rpc_connection_cap_does_not_starve_private_admin_listener() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    let (public_addr, admin_addr) = start_rpc_server_with_config_and_admin(
        config,
        RuntimeNodeOptions {
            admin_token: Some(ADMIN_TOKEN.to_string()),
            max_active_connections: 1,
            max_requests_per_minute: 10_000,
            ..RuntimeNodeOptions::default()
        },
    );

    let held_public = TcpStream::connect(&public_addr).expect("held public connection opens");
    held_public
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set held public read timeout");
    thread::sleep(Duration::from_millis(100));

    let mut rejected_public =
        TcpStream::connect(&public_addr).expect("second public connection opens");
    rejected_public
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set rejected public read timeout");
    let mut response = String::new();
    rejected_public
        .read_to_string(&mut response)
        .expect("read public rejection response");
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "expected public 503 active connection rejection, got {response:?}"
    );
    let (_, body) = response
        .split_once("\r\n\r\n")
        .expect("public rejection response has body");
    let body = serde_json::from_str::<Value>(body.trim()).expect("public rejection body is JSON");
    assert_eq!(body["listener"], "public");
    assert_eq!(body["max_active_connections"], 1);

    let admin_block = rpc_call(
        &admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    assert!(
        rpc_result(&admin_block)["height"]
            .as_u64()
            .expect("admin block height is numeric")
            > 0
    );

    drop(held_public);
    wait_for_rpc(&public_addr);
}

#[test]
fn public_rpc_rate_limit_does_not_starve_private_admin_listener() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    let (public_addr, admin_addr) = start_rpc_server_with_config_and_admin(
        config,
        RuntimeNodeOptions {
            admin_token: Some(ADMIN_TOKEN.to_string()),
            max_requests_per_minute: 10,
            ..RuntimeNodeOptions::default()
        },
    );

    let mut public_rate_limited = false;
    for _ in 0..12 {
        let (headers, body) =
            http_response(&public_addr, "GET", "/status", None).expect("public response");
        let status_line = headers.lines().next().unwrap_or_default();
        if status_line.contains(" 429 ") {
            let body = serde_json::from_str::<Value>(body.trim()).expect("429 body is JSON");
            if body["listener"] == "public" {
                public_rate_limited = true;
                break;
            }
        }
    }
    assert!(
        public_rate_limited,
        "public listener should hit its rate limit"
    );

    let admin_block = rpc_call(
        &admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    assert!(
        rpc_result(&admin_block)["height"]
            .as_u64()
            .expect("admin block height is numeric")
            > 0
    );
}

#[test]
fn trusted_proxy_headers_partition_public_rate_limit_clients() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    let trusted_addr = start_rpc_server_with_config(
        config.clone(),
        RuntimeNodeOptions {
            max_requests_per_minute: 2,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..RuntimeNodeOptions::default()
        },
    );

    for _ in 0..2 {
        let (headers, _body) = http_response_with_headers(
            &trusted_addr,
            "GET",
            "/status",
            &["X-Forwarded-For: 203.0.113.10"],
            None,
        )
        .expect("trusted proxy response");
        assert!(
            headers.lines().next().unwrap_or_default().contains(" 200 "),
            "{headers}"
        );
    }
    let (headers, body) = http_response_with_headers(
        &trusted_addr,
        "GET",
        "/status",
        &["X-Forwarded-For: 203.0.113.10"],
        None,
    )
    .expect("trusted proxy rate limited response");
    assert!(
        headers.lines().next().unwrap_or_default().contains(" 429 "),
        "{headers}: {body}"
    );
    let (headers, _body) = http_response_with_headers(
        &trusted_addr,
        "GET",
        "/status",
        &["X-Forwarded-For: 203.0.113.11"],
        None,
    )
    .expect("second forwarded client response");
    assert!(
        headers.lines().next().unwrap_or_default().contains(" 200 "),
        "{headers}"
    );
    let (headers, body) = http_response_with_headers(
        &trusted_addr,
        "GET",
        "/status",
        &["X-Forwarded-For: 203.0.113.12, 203.0.113.13"],
        None,
    )
    .expect("ambiguous trusted proxy response");
    assert!(
        headers.lines().next().unwrap_or_default().contains(" 400 "),
        "ambiguous trusted proxy header must fail closed: {headers}: {body}"
    );

    let untrusted_addr = start_rpc_server_with_config(
        config,
        RuntimeNodeOptions {
            max_requests_per_minute: 5,
            ..RuntimeNodeOptions::default()
        },
    );
    let mut untrusted_rate_limited = false;
    for index in 20..30 {
        let header = format!("X-Forwarded-For: 203.0.113.{index}");
        let (headers, _body) =
            http_response_with_headers(&untrusted_addr, "GET", "/status", &[header.as_str()], None)
                .expect("untrusted forwarded response");
        if headers.lines().next().unwrap_or_default().contains(" 429 ") {
            untrusted_rate_limited = true;
            break;
        }
        assert!(
            headers.lines().next().unwrap_or_default().contains(" 200 "),
            "{headers}"
        );
    }
    assert!(
        untrusted_rate_limited,
        "untrusted direct clients must not bypass the TCP-peer bucket with varied X-Forwarded-For headers"
    );
}

#[test]
fn public_rpc_rejects_incomplete_declared_body_without_dispatching() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    let rpc_addr = start_rpc_server_with_config(
        config,
        RuntimeNodeOptions {
            max_requests_per_minute: 10_000,
            ..RuntimeNodeOptions::default()
        },
    );
    let account = account_id(0x66);
    let body = json!({
        "jsonrpc": "2.0",
        "id": "short-body-faucet",
        "method": "nebula_faucet",
        "params": { "account": account },
    })
    .to_string();

    let mut stream = TcpStream::connect(&rpc_addr).expect("incomplete request connects");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set incomplete request read timeout");
    write!(
        stream,
        "POST /rpc HTTP/1.1\r\nHost: {rpc_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len() + 100,
        body
    )
    .expect("write incomplete declared request");
    let (headers, response_body) = read_http_response(stream).expect("read incomplete response");
    assert!(
        headers.lines().next().unwrap_or_default().contains(" 400 "),
        "expected 400 for incomplete body, got {headers:?}: {response_body:?}"
    );
    assert!(response_body.contains("incomplete HTTP request body"));

    let account_response = rpc_call(
        &rpc_addr,
        "nebula_getAccount",
        json!({ "account": account }),
    );
    assert_eq!(rpc_result(&account_response)["state"]["nbla_nebulai"], 0);
}

#[test]
fn public_rpc_rate_limit_fires_after_headers_before_reading_declared_body() {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    let rpc_addr = start_rpc_server_with_config(
        config,
        RuntimeNodeOptions {
            max_requests_per_minute: 1,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..RuntimeNodeOptions::default()
        },
    );

    let client_header = "X-Forwarded-For: 203.0.113.200";
    let (headers, _body) =
        http_response_with_headers(&rpc_addr, "GET", "/status", &[client_header], None)
            .expect("first forwarded client request succeeds");
    assert!(
        headers.lines().next().unwrap_or_default().contains(" 200 "),
        "{headers}"
    );

    let mut stream = TcpStream::connect(&rpc_addr).expect("rate-limited request connects");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set rate-limited request read timeout");
    write!(
        stream,
        "POST /rpc HTTP/1.1\r\nHost: {rpc_addr}\r\n{client_header}\r\nContent-Type: application/json\r\nContent-Length: 512\r\nConnection: close\r\n\r\n",
    )
    .expect("write only rate-limited request headers");

    let (headers, response_body) = read_http_response(stream).expect("read rate-limit response");
    assert!(
        headers.lines().next().unwrap_or_default().contains(" 429 "),
        "expected 429 before body read, got {headers:?}: {response_body:?}"
    );
    assert!(response_body.contains("rate limit exceeded"));
}

#[test]
fn metrics_endpoint_exposes_public_rpc_operational_gauges() {
    let (rpc_addr, _admin_addr) = start_rpc_server_with_admin(Some(ADMIN_TOKEN));

    let (headers, body) =
        http_text(&rpc_addr, "GET", "/metrics", None).expect("metrics endpoint responds");

    assert!(headers.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"));
    assert!(body.contains("# HELP nebula_latest_height"));
    assert!(body.contains("nebula_sub_second_blocks 1"));
    assert!(body.contains("nebula_rpc_max_request_bytes "));
    assert!(body.contains("nebula_rpc_max_requests_per_minute 10000"));
    assert!(body.contains("nebula_admin_rpc_max_active_connections "));
    assert!(body.contains("nebula_rpc_client_identity_proxy_aware 0"));
    assert!(body.contains("nebula_rpc_trust_private_proxy_headers 0"));
    assert!(body.contains("nebula_rpc_trusted_proxy_count 0"));
    assert!(body.contains("nebula_sync_peer_quorum 1"));
    assert!(body.contains("nebula_sync_quorum_met 0"));
    assert!(body.contains("nebula_sync_quorum_peer_count 0"));
    assert!(body.contains("nebula_sync_successful_peer_count 0"));
    assert!(body.contains("nebula_sync_attempt_count 0"));
    assert!(body.contains("nebula_sync_quorum_rejection_count 0"));
    assert!(body.contains("nebula_sync_import_count 0"));
    assert!(body.contains("nebula_launch_binding_present 0"));
    assert!(body.contains("nebula_launch_validator_count 0"));
    assert!(body.contains("nebula_launch_operator_count 0"));
    assert!(body.contains("nebula_launch_region_count 0"));
    assert!(body.contains("nebula_mempool_admission_rejection_count 0"));
    assert!(body.contains("nebula_faucet_nbla_nebulai "));
    assert!(body.contains("nebula_faucet_nxmr_units 0"));
    assert!(body.contains("nebula_bridge_only_nxmr 1"));
    assert!(body.contains("nebula_bridge_custody_reconciled 1"));
    assert!(body.contains("nebula_nxmr_custody_deficit_units 0"));
    assert!(body.contains("nebula_admin_rpc_enabled 1"));
    assert!(body.contains("nebula_admin_rpc_private_listener 1"));
    assert!(body.contains("nebula_public_rpc_admin_methods_enabled 0"));
    assert!(body.contains("nebula_default_dev_sequencer_key 1"));
    assert!(body.contains("nebula_bridge_deposit_count 0"));
    assert!(body.contains("nebula_sequencer_accountability_clean 1"));
    assert!(body.contains("nebula_public_ops_ready "));
}

#[test]
fn health_endpoint_exposes_chain_root_ops_and_backup_evidence() {
    let (rpc_addr, _admin_addr) = start_rpc_server_with_admin(Some(ADMIN_TOKEN));

    let health = http_json(&rpc_addr, "GET", "/health", None).expect("health endpoint responds");
    let status = rpc_result(&rpc_call(&rpc_addr, "nebula_status", json!({}))).clone();

    assert_eq!(health["ok"], true);
    assert_eq!(health["service"], "nebula-testnet-rpc");
    assert_eq!(health["chain_id"], status["chain_id"]);
    assert_eq!(health["runtime_version"], status["runtime_version"]);
    assert_eq!(health["launch_binding_present"], false);
    assert_eq!(health["launch_endpoint_url"], serde_json::Value::Null);
    assert_eq!(
        health["launch_package_bundle_root"],
        serde_json::Value::Null
    );
    assert_eq!(health["launch_validator_count"], serde_json::Value::Null);
    assert_eq!(health["node_role"], status["node_role"]);
    assert_eq!(health["block_target_ms"], status["block_target_ms"]);
    assert_eq!(health["sub_second_blocks"], true);
    assert_eq!(
        health["sequencer_public_key_hex"],
        status["sequencer_public_key_hex"]
    );
    assert_eq!(health["bridge_policy_root"], status["bridge_policy_root"]);
    assert_eq!(
        health["bridge_policy"]["deposit_observer_identity_quorum_required"],
        true
    );
    assert_eq!(
        health["bridge_policy"]["withdrawal_operator_identity_quorum_required"],
        true
    );
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
    assert_eq!(health["admin_rpc_private_listener"], true);
    assert_eq!(health["public_rpc_admin_methods_enabled"], false);
    assert_eq!(health["default_dev_sequencer_key"], true);
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
fn launch_bound_follower_exports_verifiable_runtime_surface_evidence() {
    let (sequencer_binding, follower_binding) = verified_launch_bindings();
    let endpoint_url = sequencer_binding.endpoint_url.clone();

    let mut sequencer_config = RuntimeConfig::public_testnet_default();
    sequencer_config.block_target_ms = 999;
    sequencer_config.validator_id = "validator-a".to_string();
    sequencer_config.launch_binding = Some(sequencer_binding.clone());
    sequencer_config.faucet_nbla_nebulai = 0;
    let initial_sequencer_secret_key_hex = "3c".repeat(32);
    sequencer_config.sequencer_public_key_hex =
        hex::encode(signing_key(0x3c).verifying_key().to_bytes());
    let bridge_account_seed = 0x46;
    let bridge_account = account_id(bridge_account_seed);
    let sequencer_data_dir = temp_data_dir("sequencer");
    let sequencer_storage = RuntimeStorage::from_data_dir(&sequencer_data_dir);
    let mut seeded_runtime = NebulaRuntime::with_sequencer_secret(
        sequencer_config.clone(),
        Some(initial_sequencer_secret_key_hex.clone()),
    )
    .expect("seeded sequencer runtime");
    seeded_runtime
        .seed_local_rehearsal_nbla(&bridge_account, 10_000)
        .expect("seed NBLA for launch rehearsal");
    seeded_runtime
        .try_produce_block()
        .expect("commit seeded NBLA block");
    sequencer_storage
        .save_runtime(&seeded_runtime)
        .expect("persist seeded sequencer snapshot");
    let (sequencer_addr, sequencer_admin_addr) = start_rpc_server_with_config_and_admin(
        sequencer_config,
        RuntimeNodeOptions {
            admin_token: Some(ADMIN_TOKEN.to_string()),
            sequencer_secret_key_hex: Some(initial_sequencer_secret_key_hex),
            data_dir: Some(sequencer_data_dir),
            auto_produce_blocks: false,
            max_requests_per_minute: 10_000,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..RuntimeNodeOptions::default()
        },
    );

    let initial_block = rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    assert!(
        rpc_result(&initial_block)["height"]
            .as_u64()
            .expect("initial block height is numeric")
            > 0
    );

    wait_for_json_condition(
        &sequencer_addr,
        "/ops",
        "sequencer public ops ready",
        |ops| ops["public_ops_ready"] == true && ops["latest_height"].as_u64().unwrap_or(0) > 0,
    );
    let initial_status = rpc_result(&rpc_call(&sequencer_addr, "nebula_status", json!({}))).clone();
    let rotation_secret_key_hex = "4d".repeat(32);
    let rotation_public_key_hex = account_id(0x4d);
    let rotation_proof_root = hex_64("live-rotation-proof");
    let rotation_activation_height = initial_status["latest_height"]
        .as_u64()
        .expect("latest_height is numeric")
        + 1;
    let previous_key_history_root = initial_status["sequencer_key_history_root"]
        .as_str()
        .expect("sequencer key history root is a string");
    let old_public_key_hex = initial_status["sequencer_public_key_hex"]
        .as_str()
        .expect("sequencer public key is a string");
    let (rotation_operator_ids, rotation_approval_roots, rotation_approvals) =
        rotation_operator_approval_quorum(
            Some(&sequencer_binding),
            previous_key_history_root,
            rotation_activation_height,
            old_public_key_hex,
            &rotation_public_key_hex,
            &rotation_proof_root,
        );

    let rotation = rpc_call(
        &sequencer_admin_addr,
        "nebula_rotateSequencerKey",
        json!({
            "admin_token": ADMIN_TOKEN,
            "new_sequencer_secret_key_hex": rotation_secret_key_hex,
            "rotation_proof_root": rotation_proof_root,
            "operator_approval_ids": rotation_operator_ids,
            "operator_approval_roots": rotation_approval_roots,
            "operator_approvals": rotation_approvals,
        }),
    );
    let rotation = rpc_result(&rotation);
    assert_eq!(rotation["rotated"], true);
    assert_eq!(
        rotation["rotation"]["operator_approvals"]
            .as_array()
            .expect("rotation operator approvals are an array")
            .len(),
        2
    );
    assert_ne!(
        rotation["sequencer_public_key_hex"],
        initial_status["sequencer_public_key_hex"]
    );
    let rotated_public_key = rotation["sequencer_public_key_hex"]
        .as_str()
        .expect("rotated public key is a string")
        .to_string();

    let bridge_monero_tx_id = hex_64("m45");
    let disabled_faucet = rpc_call(
        &sequencer_addr,
        "nebula_faucet",
        json!({ "account": bridge_account.clone() }),
    );
    assert_rpc_error_contains(&disabled_faucet, "NBLA faucet is disabled");

    let bridge_deposit = rpc_call(
        &sequencer_admin_addr,
        "nebula_observeBridgeDeposit",
        json!({
            "admin_token": ADMIN_TOKEN,
            "deposit": bridge_deposit(bridge_account_seed, 5_000),
        }),
    );
    let bridge_deposit = rpc_result(&bridge_deposit);
    assert_eq!(bridge_deposit["credited"], true);
    assert_eq!(bridge_deposit["account_state"]["nxmr_units"], 5_000);

    let nbla_tx = signed_transaction_with_fee_asset(
        bridge_account_seed,
        0,
        "launch-nbla-gas-recipient",
        NBLA_SYMBOL,
        10,
    );
    let nbla_submit = rpc_call(
        &sequencer_addr,
        "nebula_sendTransaction",
        json!({ "tx": nbla_tx }),
    );
    let nbla_submit = rpc_result(&nbla_submit);
    assert_eq!(nbla_submit["accepted_to_mempool"], true);
    let nbla_tx_id = nbla_submit["tx_id"]
        .as_str()
        .expect("NBLA tx id")
        .to_string();
    rpc_result(&rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    ));
    let nbla_receipt_response = rpc_call(
        &sequencer_addr,
        "nebula_getReceipt",
        json!({ "tx_id": nbla_tx_id }),
    );
    let nbla_receipt = rpc_result(&nbla_receipt_response);
    assert_eq!(nbla_receipt["status"], "included");
    assert_eq!(nbla_receipt["fee_asset"], NBLA_SYMBOL);
    assert_eq!(nbla_receipt["paid_amount_units"], 10);
    assert_eq!(nbla_receipt["buyback_nebulai"], 0);
    assert_eq!(nbla_receipt["validator_reward_nebulai"], 10);

    let nxmr_tx = signed_transaction_with_fee_asset(
        bridge_account_seed,
        1,
        "launch-nxmr-gas-recipient",
        NXMR_SYMBOL,
        1_000,
    );
    let nxmr_submit = rpc_call(
        &sequencer_addr,
        "nebula_sendTransaction",
        json!({ "tx": nxmr_tx }),
    );
    let nxmr_submit = rpc_result(&nxmr_submit);
    assert_eq!(nxmr_submit["accepted_to_mempool"], true);
    let nxmr_tx_id = nxmr_submit["tx_id"]
        .as_str()
        .expect("nXMR tx id")
        .to_string();
    rpc_result(&rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    ));
    let nxmr_receipt_response = rpc_call(
        &sequencer_addr,
        "nebula_getReceipt",
        json!({ "tx_id": nxmr_tx_id }),
    );
    let nxmr_receipt = rpc_result(&nxmr_receipt_response);
    assert_eq!(nxmr_receipt["status"], "included");
    assert_eq!(nxmr_receipt["fee_asset"], NXMR_SYMBOL);
    assert_eq!(nxmr_receipt["paid_amount_units"], 1_000);
    assert_eq!(nxmr_receipt["buyback_nebulai"], 1_000);
    assert_eq!(nxmr_receipt["validator_reward_nebulai"], 1_000);

    let withdrawal = rpc_call(
        &sequencer_addr,
        "nebula_requestWithdrawal",
        json!({
            "account": bridge_account.clone(),
            "monero_address": "9xTestnetMoneroAddressForNebulaWithdrawals",
            "amount_nxmr_units": 2_000,
            "nonce": 2,
            "signature": withdrawal_signature(
                bridge_account_seed,
                "9xTestnetMoneroAddressForNebulaWithdrawals",
                2_000,
                2
            ),
        }),
    );
    let withdrawal = rpc_result(&withdrawal);
    assert_eq!(withdrawal["accepted"], true);
    assert_eq!(withdrawal["withdrawal"]["status"], "operator_pending");
    let withdrawal_id = withdrawal["withdrawal"]["withdrawal_id"]
        .as_str()
        .expect("withdrawal_id is a string")
        .to_string();
    let withdrawal_request =
        serde_json::from_value::<RuntimeWithdrawalRequest>(withdrawal["withdrawal"].clone())
            .expect("withdrawal response carries a runtime withdrawal");
    let finalized_monero_tx_id = hex_64("live-finalized-withdrawal");
    let finalization_proof_root = hex_64("live-finalization-proof");
    let (operator_approval_ids, operator_approval_roots, operator_approvals) =
        operator_approval_quorum(
            &withdrawal_request,
            &finalized_monero_tx_id,
            &finalization_proof_root,
        );

    let finalization = rpc_call(
        &sequencer_admin_addr,
        "nebula_finalizeWithdrawal",
        json!({
            "admin_token": ADMIN_TOKEN,
            "withdrawal_id": withdrawal_id.clone(),
            "finalized_monero_tx_id": finalized_monero_tx_id,
            "finalization_proof_root": finalization_proof_root,
            "operator_approval_ids": operator_approval_ids,
            "operator_approval_roots": operator_approval_roots,
            "operator_approvals": operator_approvals,
        }),
    );
    let finalization = rpc_result(&finalization);
    assert_eq!(finalization["finalized"], true);
    assert_eq!(finalization["withdrawal"]["status"], "finalized");

    let sequencer_lifecycle_status = wait_for_json_condition(
        &sequencer_addr,
        "/status",
        "sequencer lifecycle state committed",
        |status| {
            status["sequencer_key_rotation_count"] == 1
                && status["bridge_deposit_count"] == 1
                && status["withdrawal_request_count"] == 1
                && status["finalized_withdrawal_count"] == 1
                && status["bridge_replay_cache_count"] == 2
                && status["sequencer_public_key_hex"] == rotated_public_key
                && status["total_nxmr_fees_units"] == 1_000
                && status["buyback_pool_nebulai"] == 1_000
                && status["validator_reward_nebulai"] == 1_010
                && status["latest_state_root"] == status["current_state_root"]
                && status["bridge_custody_reconciled"] == true
        },
    );
    assert_eq!(
        sequencer_lifecycle_status["bridge_deposited_nxmr_units"],
        5_000
    );
    assert_eq!(sequencer_lifecycle_status["account_nxmr_units"], 2_000);
    assert_eq!(
        sequencer_lifecycle_status["withdrawal_reserved_nxmr_units"],
        2_000
    );
    assert_eq!(sequencer_lifecycle_status["nxmr_fee_units"], 1_000);
    assert_eq!(
        sequencer_lifecycle_status["nxmr_custody_required_units"],
        5_000
    );
    assert_eq!(sequencer_lifecycle_status["nxmr_custody_surplus_units"], 0);
    assert_eq!(sequencer_lifecycle_status["nxmr_custody_deficit_units"], 0);

    let snapshot_url = format!("http://{sequencer_addr}/snapshot");
    let mut follower_config = RuntimeConfig::public_testnet_default();
    follower_config.block_target_ms = 999;
    follower_config.validator_id = "validator-b".to_string();
    follower_config.produce_blocks = false;
    follower_config.sequencer_public_key_hex = rotated_public_key.clone();
    follower_config.launch_binding = Some(follower_binding.clone());
    let follower_addr = start_rpc_server_with_config(
        follower_config,
        RuntimeNodeOptions {
            data_dir: Some(temp_data_dir("follower")),
            bootstrap_rpc_url: Some(snapshot_url.clone()),
            sync_rpc_url: Some(snapshot_url.clone()),
            sync_peer_quorum: 1,
            public_testnet_peer_manifest: Some(RuntimePublicTestnetPeerManifestBinding {
                public_testnet_peer_manifest_root: "a".repeat(64),
                launch_package_bundle_root: follower_binding.launch_package_bundle_root.clone(),
                snapshot_peer_urls: vec![snapshot_url],
                sync_peer_quorum: 1,
            }),
            max_requests_per_minute: 10_000,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..RuntimeNodeOptions::default()
        },
    );
    rpc_result(&rpc_call(
        &sequencer_admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    ));

    let ops = wait_for_json_condition(&follower_addr, "/ops", "follower public ops ready", |ops| {
        let latest_height = ops["latest_height"].as_u64().unwrap_or(0);
        ops["public_ops_ready"] == true
            && ops["node_role"] == "follower"
            && ops["sync_quorum_met"] == true
            && ops["sync_successful_peer_count"].as_u64().unwrap_or(0) >= 1
            && ops["sync_import_count"].as_u64().unwrap_or(0) >= 1
            && ops["sync_last_import_height"].as_u64() == Some(latest_height)
            && ops["sync_quorum_height"].as_u64() == Some(latest_height)
            && ops["sync_quorum_latest_hash"] == ops["latest_hash"]
            && ops["sync_quorum_state_root"] == ops["current_state_root"]
            && latest_height > 0
    });
    assert_eq!(ops["launch_binding_present"], true);
    assert_eq!(ops["launch_endpoint_url"], endpoint_url);
    assert_eq!(
        ops["launch_package_bundle_root"],
        follower_binding.launch_package_bundle_root
    );
    assert_eq!(ops["public_testnet_peer_manifest_present"], true);
    assert_eq!(
        ops["public_testnet_peer_manifest_root"],
        json!("a".repeat(64))
    );
    assert_eq!(ops["public_testnet_peer_manifest_snapshot_peer_count"], 1);
    assert_eq!(ops["public_testnet_peer_manifest_sync_peer_quorum"], 1);
    assert!(ops["blocking_gaps"].as_array().unwrap().is_empty());

    let evidence = wait_for_runtime_surface_evidence(&follower_addr, &endpoint_url);
    let report = verify_runtime_surface_evidence_json(&evidence.to_string())
        .expect("live follower evidence verifies");

    assert!(report.runtime_surface_ready);
    assert_eq!(report.level, "runtime-surface-attested");
    assert_eq!(report.endpoint_url, endpoint_url);
    assert_eq!(report.chain_id, CHAIN_ID);
    assert!(report.latest_height > 0);
    assert!(report.blocking_gaps.is_empty());
    assert_eq!(evidence["status"]["node_role"], "follower");
    assert_eq!(evidence["status"]["block_target_ms"], 999);
    assert_eq!(evidence["status"]["sub_second_blocks"], true);
    assert_eq!(evidence["status"]["launch_binding_present"], true);
    assert_eq!(evidence["status"]["launch_endpoint_url"], endpoint_url);
    assert_eq!(
        evidence["status"]["sequencer_public_key_hex"],
        rotated_public_key
    );
    assert_eq!(evidence["status"]["sequencer_key_rotation_count"], 1);
    assert_eq!(evidence["status"]["bridge_deposit_count"], 1);
    assert_eq!(evidence["status"]["withdrawal_request_count"], 1);
    assert_eq!(evidence["status"]["finalized_withdrawal_count"], 1);
    assert_eq!(evidence["status"]["bridge_replay_cache_count"], 2);
    assert_eq!(evidence["status"]["faucet_nbla_nebulai"], 0);
    assert_eq!(evidence["status"]["total_nxmr_fees_units"], 1_000);
    assert_eq!(evidence["status"]["buyback_pool_nebulai"], 1_000);
    assert_eq!(evidence["status"]["validator_reward_nebulai"], 1_010);
    assert_eq!(evidence["status"]["bridge_deposited_nxmr_units"], 5_000);
    assert_eq!(evidence["status"]["account_nxmr_units"], 2_000);
    assert_eq!(evidence["status"]["withdrawal_reserved_nxmr_units"], 2_000);
    assert_eq!(evidence["status"]["nxmr_fee_units"], 1_000);
    assert_eq!(evidence["status"]["nxmr_custody_required_units"], 5_000);
    assert_eq!(evidence["status"]["nxmr_custody_surplus_units"], 0);
    assert_eq!(evidence["status"]["nxmr_custody_deficit_units"], 0);
    assert_eq!(evidence["status"]["bridge_custody_reconciled"], true);
    assert_eq!(evidence["health"]["public_ops_ready"], true);
    assert_eq!(evidence["health"]["sync_quorum_met"], true);
    assert_eq!(
        evidence["status"]["sync_import_count"],
        ops["sync_import_count"]
    );
    assert_eq!(
        evidence["status"]["sync_last_import_height"],
        evidence["status"]["latest_height"]
    );
    assert_eq!(
        evidence["status"]["sync_quorum_height"],
        evidence["status"]["latest_height"]
    );
    assert_eq!(
        evidence["status"]["sync_quorum_latest_hash"],
        evidence["status"]["latest_hash"]
    );
    assert_eq!(
        evidence["status"]["sync_quorum_state_root"],
        evidence["status"]["current_state_root"]
    );
    assert_eq!(
        evidence["snapshot"]["config"]["launch_binding"]["endpoint_url"],
        endpoint_url
    );
    assert_eq!(
        evidence["snapshot"]["config"]["launch_binding"]["launch_package_bundle_root"],
        follower_binding.launch_package_bundle_root
    );
    assert_eq!(
        evidence["snapshot"]["bridge_deposits"][bridge_monero_tx_id.as_str()]["amount_nxmr_units"],
        5_000
    );
    assert_eq!(
        evidence["snapshot"]["withdrawals"][withdrawal_id.as_str()]["status"],
        "finalized"
    );
    assert_eq!(evidence["rpc_status"]["result"]["node_role"], "follower");
    assert_eq!(
        evidence["rpc_status"]["result"]["launch_package_bundle_root"],
        follower_binding.launch_package_bundle_root
    );
}

#[test]
fn launch_bound_accountability_report_blocks_public_ops_and_mutations() {
    let (launch_binding, _) = verified_launch_bindings();
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;
    config.validator_id = "validator-a".to_string();
    config.launch_binding = Some(launch_binding);
    config.faucet_nbla_nebulai = 0;
    let initial_sequencer_secret_key_hex = "3d".repeat(32);
    config.sequencer_public_key_hex = hex::encode(signing_key(0x3d).verifying_key().to_bytes());
    let (rpc_addr, admin_addr) = start_rpc_server_with_config_and_admin(
        config,
        RuntimeNodeOptions {
            admin_token: Some(ADMIN_TOKEN.to_string()),
            sequencer_secret_key_hex: Some(initial_sequencer_secret_key_hex),
            data_dir: Some(temp_data_dir("accountability")),
            max_requests_per_minute: 10_000,
            trusted_proxy_ips: vec!["127.0.0.1".to_string()],
            ..RuntimeNodeOptions::default()
        },
    );

    let ops = wait_for_json_condition(&rpc_addr, "/ops", "launch-bound ops ready", |ops| {
        ops["public_ops_ready"] == true && ops["latest_height"].as_u64().unwrap_or(0) > 0
    });
    let height = ops["latest_height"]
        .as_u64()
        .expect("latest height is numeric");
    let first_block_hash = ops["latest_hash"]
        .as_str()
        .expect("latest hash is a string")
        .to_string();

    let report = rpc_call(
        &admin_addr,
        "nebula_reportEquivocation",
        json!({
            "admin_token": ADMIN_TOKEN,
            "height": height,
            "first_block_hash": first_block_hash,
            "second_block_hash": hex_64("launch-bound-second-block"),
            "reporter_id": "operator-a",
            "evidence_root": hex_64("launch-bound-equivocation"),
        }),
    );
    let report = rpc_result(&report);
    assert_eq!(report["recorded"], true);
    assert_eq!(report["report"]["height"], height);
    assert_eq!(report["report"]["reporter_id"], "operator-a");
    assert_eq!(report["sequencer_accountability_clean"], false);
    assert_eq!(report["accountability_root"].as_str().unwrap().len(), 64);

    let ops_after =
        wait_for_json_condition(&rpc_addr, "/ops", "accountability blocks ops", |ops| {
            ops["public_ops_ready"] == false
                && ops["sequencer_accountability_clean"] == false
                && ops["accountability_report_count"] == 1
        });
    assert!(ops_after["blocking_gaps"]
        .as_array()
        .expect("blocking_gaps is an array")
        .iter()
        .any(|gap| gap == "sequencer-accountability-evidence-open"));

    let block_after_evidence = rpc_call(
        &admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    assert_rpc_error_contains(&block_after_evidence, "accountability evidence");

    let rotation_after_evidence = rpc_call(
        &admin_addr,
        "nebula_rotateSequencerKey",
        json!({
            "admin_token": ADMIN_TOKEN,
            "new_sequencer_secret_key_hex": "5e".repeat(32),
            "rotation_proof_root": hex_64("blocked-rotation-proof"),
            "operator_approval_ids": ["operator-a", "operator-b"],
            "operator_approval_roots": [
                hex_64("blocked-rotation-approval-a"),
                hex_64("blocked-rotation-approval-b")
            ],
        }),
    );
    assert_rpc_error_contains(&rotation_after_evidence, "accountability evidence");
}

#[test]
fn accountability_evidence_closes_admin_producer_mutations_but_remains_visible() {
    let (rpc_addr, admin_addr) = start_rpc_server_with_admin(Some(ADMIN_TOKEN));

    let block = rpc_call(
        &admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    let block = rpc_result(&block);
    let height = block["height"].as_u64().expect("block height is a u64");
    let first_block_hash = block["block_hash"]
        .as_str()
        .expect("block hash is a string");

    let report = rpc_call(
        &admin_addr,
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
        &admin_addr,
        "nebula_produceBlock",
        json!({ "admin_token": ADMIN_TOKEN }),
    );
    assert_rpc_error_contains(&block_after_evidence, "accountability evidence");

    let rotation_after_evidence = rpc_call(
        &admin_addr,
        "nebula_rotateSequencerKey",
        json!({
            "admin_token": ADMIN_TOKEN,
            "new_sequencer_secret_key_hex": "4d".repeat(32),
            "rotation_proof_root": hex_64("rotation-proof"),
            "operator_approval_ids": ["operator-a", "operator-b"],
            "operator_approval_roots": [
                hex_64("rotation-approval-a"),
                hex_64("rotation-approval-b")
            ],
        }),
    );
    assert_rpc_error_contains(&rotation_after_evidence, "accountability evidence");
}

fn start_rpc_server_with_config(config: RuntimeConfig, options: RuntimeNodeOptions) -> String {
    let bind_addr = reserve_local_addr();

    let server_addr = bind_addr.clone();
    thread::spawn(move || {
        serve_runtime_rpc_with_options(&server_addr, config, options)
            .expect("runtime RPC server should keep serving");
    });

    wait_for_rpc(&bind_addr);
    bind_addr
}

fn start_rpc_server_with_admin(admin_token: Option<&str>) -> (String, String) {
    let mut config = RuntimeConfig::public_testnet_default();
    config.block_target_ms = 999;

    start_rpc_server_with_config_and_admin(
        config,
        RuntimeNodeOptions {
            admin_token: admin_token.map(str::to_string),
            max_requests_per_minute: 10_000,
            ..RuntimeNodeOptions::default()
        },
    )
}

fn start_rpc_server_with_config_and_admin(
    config: RuntimeConfig,
    mut options: RuntimeNodeOptions,
) -> (String, String) {
    let public_addr = reserve_local_addr();
    let admin_addr = reserve_local_addr();
    options.admin_rpc_bind_addr = Some(admin_addr.clone());

    let server_addr = public_addr.clone();
    thread::spawn(move || {
        serve_runtime_rpc_with_options(&server_addr, config, options)
            .expect("runtime RPC server should keep serving");
    });

    wait_for_rpc(&public_addr);
    wait_for_rpc(&admin_addr);
    (public_addr, admin_addr)
}

fn reserve_local_addr() -> String {
    let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve local RPC port");
    let bind_addr = reserved
        .local_addr()
        .expect("reserved listener has local address")
        .to_string();
    drop(reserved);
    bind_addr
}

fn wait_for_json_condition(
    rpc_addr: &str,
    path: &str,
    label: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Value {
    let mut last = Value::Null;
    for _ in 0..200 {
        if let Ok(response) = http_json(rpc_addr, "GET", path, None) {
            if predicate(&response) {
                return response;
            }
            last = response;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("{label} did not become true at {rpc_addr}{path}; last response: {last}");
}

fn wait_for_runtime_surface_evidence(rpc_addr: &str, endpoint_url: &str) -> Value {
    let mut last = Value::Null;
    for _ in 0..10 {
        match capture_runtime_surface_evidence(rpc_addr, endpoint_url) {
            Ok(evidence) => return evidence,
            Err(error) => {
                last = json!({ "capture_error": error });
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    panic!("runtime surface evidence did not verify at {rpc_addr}; last response: {last}");
}

fn capture_runtime_surface_evidence(rpc_addr: &str, endpoint_url: &str) -> Result<Value, String> {
    let health = http_json(rpc_addr, "GET", "/health", None)?;
    let status = http_json(rpc_addr, "GET", "/status", None)?;
    let rpc_status = rpc_request_value(rpc_addr, "nebula_status", json!({}))?;
    let snapshot = http_json(rpc_addr, "GET", "/snapshot", None)?;
    let ops = http_json(rpc_addr, "GET", "/ops", None)?;
    let rpc_ops_status = rpc_request_value(rpc_addr, "nebula_opsStatus", json!({}))?;
    let backup = http_json(rpc_addr, "GET", "/backup", None)?;
    let rpc_backup_manifest = rpc_request_value(rpc_addr, "nebula_backupManifest", json!({}))?;
    let (_, metrics_text) = http_text(rpc_addr, "GET", "/metrics", None)?;

    let evidence = build_runtime_surface_evidence_json_pretty(RuntimeSurfaceEvidenceBuildInput {
        endpoint_url: endpoint_url.to_string(),
        capture_mode: RUNTIME_SURFACE_CAPTURE_MODE_LOOPBACK_DEVNET.to_string(),
        tls_observation: None,
        captured_at_unix_ms: current_unix_ms(),
        health_json: health.to_string(),
        status_json: status.to_string(),
        snapshot_json: snapshot.to_string(),
        ops_json: ops.to_string(),
        backup_json: backup.to_string(),
        rpc_status_json: rpc_status.to_string(),
        rpc_ops_status_json: rpc_ops_status.to_string(),
        rpc_backup_manifest_json: rpc_backup_manifest.to_string(),
        metrics_text,
    })
    .map_err(format_attestation_error)?;
    serde_json::from_str(&evidence).map_err(|error| format!("evidence JSON parse failed: {error}"))
}

fn rpc_request_value(rpc_addr: &str, method: &str, params: Value) -> Result<Value, String> {
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
}

fn format_attestation_error(error: AttestationError) -> String {
    match error {
        AttestationError::MalformedJson(error) => error,
        AttestationError::Invalid(errors) => errors.join("; "),
    }
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

fn http_response(
    rpc_addr: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<(String, String), String> {
    http_response_with_headers(rpc_addr, method, path, &[], body)
}

fn http_response_with_headers(
    rpc_addr: &str,
    method: &str,
    path: &str,
    extra_headers: &[&str],
    body: Option<Value>,
) -> Result<(String, String), String> {
    let mut stream =
        TcpStream::connect(rpc_addr).map_err(|error| format!("connect {rpc_addr}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set read timeout: {error}"))?;

    let body = body.map(|value| value.to_string()).unwrap_or_default();
    let extra_headers = if extra_headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", extra_headers.join("\r\n"))
    };
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {rpc_addr}\r\n{extra_headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .map_err(|error| format!("write request: {error}"))?;

    read_http_response(stream)
}

fn read_http_response(mut stream: TcpStream) -> Result<(String, String), String> {
    let mut response_bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response_bytes.extend_from_slice(&chunk[..read]),
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset
                    && !response_bytes.is_empty() =>
            {
                break;
            }
            Err(error) => return Err(format!("read response: {error}")),
        }
    }
    let response =
        String::from_utf8(response_bytes).map_err(|error| format!("response UTF-8: {error}"))?;
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(format!("malformed HTTP response: {response}"));
    };
    Ok((head.to_string(), body.to_string()))
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
    signed_transaction_with_fee_asset(seed, nonce, to, NBLA_SYMBOL, 1)
}

fn signed_transaction_with_fee_asset(
    seed: u8,
    nonce: u64,
    to: &str,
    fee_asset: &str,
    gas_units: u128,
) -> RuntimeTransaction {
    let mut tx = RuntimeTransaction {
        from: account_id(seed),
        to: to.to_string(),
        amount_nebulai: 1,
        gas_units,
        gas_price_nebulai: 1,
        fee_asset: fee_asset.to_string(),
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
    let mut deposit = RuntimeBridgeDeposit {
        monero_tx_id: hex_64("m45"),
        account: account_id(seed),
        amount_nxmr_units,
        confirmations: MIN_BRIDGE_CONFIRMATIONS,
        observer_id: "observer-us-east-1".to_string(),
        observer_ids: vec![
            "observer-us-east-1".to_string(),
            "observer-eu-west-1".to_string(),
        ],
        proof_root: hex_64("p45"),
        custody_proof_root: hex_64("c45"),
        relayer_set_root: hex_64("r45"),
        observer_signature_roots: Vec::new(),
        observer_evidence: Vec::new(),
        observed_at_unix_ms: 1,
    };
    let observer_a = observer_evidence(&deposit, "observer-us-east-1", 0xb1);
    let observer_b = observer_evidence(&deposit, "observer-eu-west-1", 0xb2);
    deposit.observer_signature_roots = vec![
        observer_a.evidence_root.clone(),
        observer_b.evidence_root.clone(),
    ];
    deposit.observer_evidence = vec![observer_a, observer_b];
    serde_json::to_value(deposit).expect("bridge deposit serializes")
}

fn observer_evidence(
    deposit: &RuntimeBridgeDeposit,
    observer_id: &str,
    seed: u8,
) -> RuntimeBridgeObserverEvidence {
    let payload_root = bridge_observer_deposit_payload_root(deposit);
    let mut evidence = RuntimeBridgeObserverEvidence {
        observer_id: observer_id.to_string(),
        observer_public_key_hex: account_id(seed),
        payload_root: payload_root.clone(),
        signature: sign_root(seed, &payload_root),
        signed_at_unix_ms: 1,
        evidence_root: String::new(),
    };
    evidence.evidence_root = bridge_observer_evidence_root(&evidence);
    evidence
}

fn operator_approval_quorum(
    withdrawal: &RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<RuntimeWithdrawalOperatorApproval>,
) {
    let approval_a = operator_approval(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
        "operator-a",
        0xa1,
    );
    let approval_b = operator_approval(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
        "operator-b",
        0xa2,
    );
    (
        vec![
            approval_a.operator_id.clone(),
            approval_b.operator_id.clone(),
        ],
        vec![
            approval_a.approval_root.clone(),
            approval_b.approval_root.clone(),
        ],
        vec![approval_a, approval_b],
    )
}

fn operator_approval(
    withdrawal: &RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
    operator_id: &str,
    seed: u8,
) -> RuntimeWithdrawalOperatorApproval {
    let payload_root = withdrawal_operator_finalization_payload_root(
        withdrawal,
        finalized_monero_tx_id,
        finalization_proof_root,
    );
    let mut approval = RuntimeWithdrawalOperatorApproval {
        operator_id: operator_id.to_string(),
        operator_public_key_hex: account_id(seed),
        payload_root: payload_root.clone(),
        signature: sign_root(seed, &payload_root),
        signed_at_unix_ms: 1,
        approval_root: String::new(),
    };
    approval.approval_root = withdrawal_operator_approval_root(&approval);
    approval
}

fn rotation_operator_approval_quorum(
    launch_binding: Option<&RuntimeLaunchBinding>,
    previous_sequencer_key_history_root: &str,
    activation_height: u64,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    rotation_proof_root: &str,
) -> (
    Vec<String>,
    Vec<String>,
    Vec<RuntimeSequencerKeyRotationApproval>,
) {
    let approval_a = rotation_operator_approval(
        launch_binding,
        previous_sequencer_key_history_root,
        activation_height,
        old_public_key_hex,
        new_public_key_hex,
        rotation_proof_root,
        "operator-a",
        0xa1,
    );
    let approval_b = rotation_operator_approval(
        launch_binding,
        previous_sequencer_key_history_root,
        activation_height,
        old_public_key_hex,
        new_public_key_hex,
        rotation_proof_root,
        "operator-b",
        0xa2,
    );
    (
        vec![
            approval_a.operator_id.clone(),
            approval_b.operator_id.clone(),
        ],
        vec![
            approval_a.approval_root.clone(),
            approval_b.approval_root.clone(),
        ],
        vec![approval_a, approval_b],
    )
}

#[allow(clippy::too_many_arguments)]
fn rotation_operator_approval(
    launch_binding: Option<&RuntimeLaunchBinding>,
    previous_sequencer_key_history_root: &str,
    activation_height: u64,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    rotation_proof_root: &str,
    operator_id: &str,
    seed: u8,
) -> RuntimeSequencerKeyRotationApproval {
    let payload_root = sequencer_key_rotation_payload_root(
        launch_binding,
        previous_sequencer_key_history_root,
        activation_height,
        old_public_key_hex,
        new_public_key_hex,
        rotation_proof_root,
    );
    let mut approval = RuntimeSequencerKeyRotationApproval {
        operator_id: operator_id.to_string(),
        operator_public_key_hex: account_id(seed),
        payload_root: payload_root.clone(),
        signature: sign_root(seed, &payload_root),
        signed_at_unix_ms: 1,
        approval_root: String::new(),
    };
    approval.approval_root = sequencer_key_rotation_approval_root(&approval);
    approval
}

fn verified_launch_bindings() -> (RuntimeLaunchBinding, RuntimeLaunchBinding) {
    let deployment_attestation = sample_deployment_attestation_json_pretty();
    let public_status = sample_public_status_manifest_json_pretty();
    let public_probe = sample_public_probe_json_pretty();
    let validator_set = sample_validator_set_json_pretty();
    let operator_handoff =
        build_operator_handoff_json_pretty(&deployment_attestation, &validator_set)
            .expect("operator handoff builds from sample launch artifacts");
    let operator_acceptance = build_operator_acceptance_json_pretty(
        &operator_handoff,
        &deployment_attestation,
        &validator_set,
    )
    .expect("operator acceptance builds from sample launch artifacts");
    let genesis = build_genesis_manifest_json_pretty(&deployment_attestation, &validator_set)
        .expect("genesis manifest builds from sample launch artifacts");
    let launch_package_bundle = build_launch_package_bundle_json_pretty(
        &deployment_attestation,
        &public_status,
        &public_probe,
        &validator_set,
        &operator_handoff,
        &operator_acceptance,
        &genesis,
    )
    .expect("launch package bundle builds from sample launch artifacts");

    let sequencer_binding = build_runtime_launch_binding_from_jsons(
        &deployment_attestation,
        &public_status,
        &public_probe,
        &validator_set,
        &operator_handoff,
        &operator_acceptance,
        &genesis,
        &launch_package_bundle,
        "validator-a",
    )
    .expect("validator-a is admitted in the sample validator set");
    let follower_binding = build_runtime_launch_binding_from_jsons(
        &deployment_attestation,
        &public_status,
        &public_probe,
        &validator_set,
        &operator_handoff,
        &operator_acceptance,
        &genesis,
        &launch_package_bundle,
        "validator-b",
    )
    .expect("validator-b is admitted in the sample validator set");

    (sequencer_binding, follower_binding)
}

fn temp_data_dir(label: &str) -> String {
    let nonce = current_unix_ms();
    let mut path: PathBuf = env::temp_dir();
    path.push(format!("nebula-public-rpc-{label}-{nonce}"));
    path.display().to_string()
}

fn current_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after unix epoch")
        .as_millis()
}

fn hex_64(label: &str) -> String {
    let mut bytes = label.as_bytes().to_vec();
    bytes.resize(32, 0);
    hex::encode(bytes)
}
