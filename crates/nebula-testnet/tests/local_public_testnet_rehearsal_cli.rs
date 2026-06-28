use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_nebula-testnet")
}

fn run_nebula(args: &[&str]) -> String {
    let args = args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    run_nebula_strings(&args)
}

fn run_nebula_strings(args: &[String]) -> String {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("run nebula-testnet");

    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("stdout should be utf8")
}

fn run_nebula_failure_strings(args: &[String]) -> String {
    let output = Command::new(binary())
        .args(args)
        .output()
        .expect("run nebula-testnet");

    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write_nebula_output(args: &[String], path: &Path) {
    fs::write(path, run_nebula_strings(args)).expect("write nebula-testnet output");
}

fn temp_rehearsal_dir() -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "nebula-live-rpc-cli-test-{}-{now}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create temp rehearsal dir");
    dir
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

struct LaunchArtifactPaths {
    public_status: PathBuf,
    public_probe: PathBuf,
    attestation: PathBuf,
    validators: PathBuf,
    handoff: PathBuf,
    acceptance: PathBuf,
    genesis: PathBuf,
    bundle: PathBuf,
}

fn build_sample_launch_artifacts(dir: &Path) -> LaunchArtifactPaths {
    let public_status = dir.join("public-status.json");
    let public_probe = dir.join("public-probe.json");
    let attestation = dir.join("attestation.json");
    let validators = dir.join("validators.json");
    let handoff = dir.join("handoff.json");
    let acceptance = dir.join("acceptance.json");
    let genesis = dir.join("genesis.json");
    let bundle = dir.join("bundle.json");

    write_nebula_output(&args(&["--sample-public-status"]), &public_status);
    write_nebula_output(&args(&["--sample-public-probe"]), &public_probe);
    write_nebula_output(&args(&["--sample-deployment-attestation"]), &attestation);
    write_nebula_output(&args(&["--sample-validator-set"]), &validators);

    write_nebula_output(
        &[
            "--build-operator-handoff".to_string(),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--validator-set".to_string(),
            path_arg(&validators),
        ],
        &handoff,
    );
    write_nebula_output(
        &[
            "--build-operator-acceptance".to_string(),
            "--operator-handoff".to_string(),
            path_arg(&handoff),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--validator-set".to_string(),
            path_arg(&validators),
        ],
        &acceptance,
    );
    write_nebula_output(
        &[
            "--build-genesis-manifest".to_string(),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--validator-set".to_string(),
            path_arg(&validators),
        ],
        &genesis,
    );
    write_nebula_output(
        &[
            "--build-launch-package-bundle".to_string(),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--public-status".to_string(),
            path_arg(&public_status),
            "--public-probe".to_string(),
            path_arg(&public_probe),
            "--validator-set".to_string(),
            path_arg(&validators),
            "--operator-handoff".to_string(),
            path_arg(&handoff),
            "--operator-acceptance".to_string(),
            path_arg(&acceptance),
            "--genesis-manifest".to_string(),
            path_arg(&genesis),
        ],
        &bundle,
    );

    LaunchArtifactPaths {
        public_status,
        public_probe,
        attestation,
        validators,
        handoff,
        acceptance,
        genesis,
        bundle,
    }
}

fn launch_artifact_args(artifacts: &LaunchArtifactPaths) -> Vec<String> {
    vec![
        "--launch-package-bundle".to_string(),
        path_arg(&artifacts.bundle),
        "--deployment-attestation".to_string(),
        path_arg(&artifacts.attestation),
        "--public-status".to_string(),
        path_arg(&artifacts.public_status),
        "--public-probe".to_string(),
        path_arg(&artifacts.public_probe),
        "--validator-set".to_string(),
        path_arg(&artifacts.validators),
        "--operator-handoff".to_string(),
        path_arg(&artifacts.handoff),
        "--operator-acceptance".to_string(),
        path_arg(&artifacts.acceptance),
        "--genesis-manifest".to_string(),
        path_arg(&artifacts.genesis),
    ]
}

fn assert_hex64(value: &Value, field: &str) {
    let root = value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} should be a string"));

    assert_eq!(root.len(), 64, "{field} should be 64 hex characters");
    assert!(
        root.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{field} should be lowercase-or-uppercase hex: {root}"
    );
}

fn assert_u64_at_least(value: &Value, field: &str, minimum: u64) {
    let actual = value[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} should be an unsigned integer"));

    assert!(
        actual >= minimum,
        "{field} should be at least {minimum}, got {actual}"
    );
}

fn write_json_value(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_string_pretty(value).expect("serialize JSON value"),
    )
    .expect("write JSON value");
}

fn value_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} should be a string"))
}

fn rewrite_runtime_surface_peer_manifest_urls(
    runtime_surface: &mut Value,
    peer_manifest_path: &Path,
) {
    let peer_manifest: Value =
        serde_json::from_str(&fs::read_to_string(peer_manifest_path).expect("read peer manifest"))
            .expect("peer manifest json");
    let validator_id = runtime_surface["snapshot"]["config"]["validator_id"]
        .as_str()
        .expect("runtime surface snapshot validator_id");
    let snapshot_peer_urls = peer_manifest["peers"]
        .as_array()
        .expect("peer manifest peers")
        .iter()
        .filter(|peer| value_str(peer, "validator_id") != validator_id)
        .map(|peer| value_str(peer, "snapshot_url").to_string())
        .collect::<Vec<_>>();
    runtime_surface["status"]["public_testnet_peer_manifest_snapshot_peer_urls"] =
        json!(snapshot_peer_urls);

    let status = runtime_surface["status"].clone();
    if runtime_surface["rpc_status"].get("result").is_some() {
        runtime_surface["rpc_status"]["result"] = status;
    } else {
        runtime_surface["rpc_status"] = status;
    }
}

fn sample_secret_key_hex(seed: u8) -> String {
    format!("{seed:02x}").repeat(32)
}

fn write_runtime_surface_capture_inputs(
    dir: &Path,
    runtime_surface_path: &Path,
    peer_manifest_path: Option<&Path>,
) -> Vec<(String, PathBuf)> {
    let mut runtime_surface: Value =
        serde_json::from_str(&fs::read_to_string(runtime_surface_path).expect("read surface"))
            .expect("runtime surface evidence json");
    if let Some(peer_manifest_path) = peer_manifest_path {
        rewrite_runtime_surface_peer_manifest_urls(&mut runtime_surface, peer_manifest_path);
    }

    let fields = [
        ("--health", "health", "health.json"),
        ("--status", "status", "status.json"),
        ("--snapshot", "snapshot", "snapshot.json"),
        ("--ops", "ops", "ops.json"),
        ("--backup", "backup", "backup.json"),
        ("--rpc-status", "rpc_status", "rpc-status.json"),
        ("--rpc-ops-status", "rpc_ops_status", "rpc-ops-status.json"),
        (
            "--rpc-backup-manifest",
            "rpc_backup_manifest",
            "rpc-backup-manifest.json",
        ),
    ];
    let mut args = Vec::new();
    for (flag, field, file_name) in fields {
        let path = dir.join(file_name);
        write_json_value(&path, &runtime_surface[field]);
        args.push((flag.to_string(), path));
    }

    let metrics_path = dir.join("metrics.txt");
    fs::write(
        &metrics_path,
        runtime_surface["metrics_text"]
            .as_str()
            .expect("metrics_text should be a string"),
    )
    .expect("write metrics text");
    args.push(("--metrics".to_string(), metrics_path));
    args
}

#[test]
fn deployment_attestation_cli_builds_with_file_backed_witness_signers() {
    let dir = temp_rehearsal_dir();
    let public_status = dir.join("public-status.json");
    let public_probe = dir.join("public-probe.json");
    let preflight = dir.join("preflight.json");
    let runbook = dir.join("runbook.json");
    let attestation_path = dir.join("file-backed-attestation.json");

    write_nebula_output(&args(&["--sample-public-status"]), &public_status);
    write_nebula_output(&args(&["--sample-public-probe"]), &public_probe);
    write_nebula_output(&args(&["--sample-preflight-receipt"]), &preflight);
    write_nebula_output(&args(&["--sample-runbook-receipt"]), &runbook);
    let sample_attestation: Value =
        serde_json::from_str(&run_nebula(&["--sample-deployment-attestation"]))
            .expect("sample deployment attestation json");

    let mut build_args = vec![
        "--build-deployment-attestation".to_string(),
        "--public-status".to_string(),
        path_arg(&public_status),
        "--public-probe".to_string(),
        path_arg(&public_probe),
        "--preflight-receipt".to_string(),
        path_arg(&preflight),
        "--runbook-receipt".to_string(),
        path_arg(&runbook),
    ];

    for pin in sample_attestation["public_endpoint"]["tls_pins"]
        .as_array()
        .expect("sample tls pins")
    {
        build_args.push("--tls-pin".to_string());
        build_args.push(format!(
            "{},{},{}",
            value_str(pin, "cert_sha256"),
            value_str(pin, "public_key_sha256"),
            pin["not_after_unix_ms"]
                .as_u64()
                .expect("tls pin expiry as u64")
        ));
    }

    for node in sample_attestation["bootstrap_nodes"]
        .as_array()
        .expect("sample bootstrap nodes")
    {
        build_args.push("--bootstrap-node".to_string());
        build_args.push(format!(
            "{},{},{},{}",
            value_str(node, "node_id"),
            value_str(node, "operator_id"),
            value_str(node, "region"),
            value_str(node, "endpoint")
        ));
    }

    for operator in sample_attestation["operators"]
        .as_array()
        .expect("sample operators")
    {
        let operator_id = value_str(operator, "operator_id");
        let secret = match operator_id {
            "operator-a" => sample_secret_key_hex(0xa1),
            "operator-b" => sample_secret_key_hex(0xa2),
            other => panic!("unexpected sample operator {other}"),
        };
        let secret_path = dir.join(format!("{operator_id}.hex"));
        fs::write(&secret_path, format!("{secret}\n")).expect("write operator secret");
        build_args.push("--operator".to_string());
        build_args.push(format!(
            "{},{},{}",
            operator_id,
            value_str(operator, "region"),
            value_str(operator, "public_key")
        ));
        build_args.push("--operator-secret-key-file".to_string());
        build_args.push(format!("{operator_id},{}", path_arg(&secret_path)));
    }

    for observer in sample_attestation["observers"]
        .as_array()
        .expect("sample observers")
    {
        let observer_id = value_str(observer, "observer_id");
        let secret = match observer_id {
            "observer-us-east-1" => sample_secret_key_hex(0xb1),
            "observer-eu-west-1" => sample_secret_key_hex(0xb2),
            other => panic!("unexpected sample observer {other}"),
        };
        let secret_path = dir.join(format!("{observer_id}.hex"));
        fs::write(&secret_path, format!("{secret}\n")).expect("write observer secret");
        build_args.push("--observer".to_string());
        build_args.push(format!(
            "{},{},{}",
            observer_id,
            value_str(observer, "region"),
            value_str(&observer["signature"], "public_key")
        ));
        build_args.push("--observer-secret-key-file".to_string());
        build_args.push(format!("{observer_id},{}", path_arg(&secret_path)));
    }

    build_args.push("--rollback-plan-sha3-256".to_string());
    build_args.push(
        value_str(
            &sample_attestation["rollback_evidence"],
            "rollback_plan_sha3_256",
        )
        .to_string(),
    );
    build_args.push("--rollback-recovery-root".to_string());
    build_args.push(
        value_str(
            &sample_attestation["rollback_evidence"],
            "recovery_point_root",
        )
        .to_string(),
    );
    build_args.push("--rollback-last-drill-unix-ms".to_string());
    build_args.push(
        sample_attestation["rollback_evidence"]["last_drill_unix_ms"]
            .as_u64()
            .expect("rollback drill time as u64")
            .to_string(),
    );

    let attestation_output = run_nebula_strings(&build_args);
    let attestation: Value =
        serde_json::from_str(&attestation_output).expect("built attestation json");
    assert!(attestation["operators"]
        .as_array()
        .expect("operators")
        .iter()
        .all(|operator| operator["verified"] == true));
    assert!(attestation["observers"]
        .as_array()
        .expect("observers")
        .iter()
        .all(|observer| observer["signature"]["verified"] == true));

    fs::write(&attestation_path, attestation_output).expect("write built attestation");
    let verify_output = run_nebula_strings(&[
        "--verify-deployment-attestation".to_string(),
        path_arg(&attestation_path),
        "--json".to_string(),
    ]);
    let report: Value =
        serde_json::from_str(&verify_output).expect("deployment attestation report json");
    assert_eq!(report["public_launch_ready"], true);
    assert_eq!(report["level"], "public-launch-attested");
}

#[test]
fn prove_local_public_testnet_json_reports_rehearsal_ready_but_launch_blocked() {
    let stdout = run_nebula(&["--prove-local-public-testnet", "--json"]);
    let report: Value = serde_json::from_str(&stdout).expect("rehearsal report json");

    assert_eq!(report["local_public_testnet_rehearsed"], true);
    assert_eq!(report["level"], "local-public-testnet-rehearsal-ready");
    assert_eq!(report["public_launch_ready"], false);
    assert_eq!(
        report["public_launch_blocker"],
        "public-launch-deployment-attestation"
    );

    let verified_artifacts = report["verified_artifacts"]
        .as_array()
        .expect("verified_artifacts should be an array");
    assert!(
        verified_artifacts.len() >= 15,
        "expected at least 15 verified artifacts, got {}",
        verified_artifacts.len()
    );

    assert_hex64(&report, "public_testnet_launch_certificate_root");
    assert_hex64(&report, "rehearsal_root");
}

#[test]
fn prove_local_public_testnet_plain_text_smoke_reports_rehearsal_blocker() {
    let stdout = run_nebula(&["--prove-local-public-testnet"]);

    assert!(stdout.contains("local-public-testnet-rehearsal-ready"));
    assert!(stdout.contains("public-launch-deployment-attestation"));
}

#[test]
fn prove_live_rpc_devnet_json_reports_runtime_rehearsal_contract() {
    let stdout = run_nebula(&["--prove-live-rpc-devnet", "--json"]);
    let report: Value = serde_json::from_str(&stdout).expect("live rpc devnet report json");

    assert_eq!(report["live_rpc_devnet_rehearsed"], true);
    assert_eq!(report["level"], "live-rpc-devnet-rehearsal-ready");
    assert_eq!(report["sub_second_blocks"], true);
    assert_eq!(report["public_launch_ready"], false);
    assert_eq!(
        report["public_launch_blocker"],
        "public-launch-deployment-attestation"
    );
    assert_eq!(report["bridge_deposit_count"], 1);
    assert_eq!(report["withdrawal_request_count"], 1);
    assert_eq!(report["finalized_withdrawal_count"], 1);
    assert_eq!(report["runtime_surface_ready"], true);
    assert_u64_at_least(&report, "sync_import_count", 1);
    assert_eq!(report["sync_last_import_height"], report["latest_height"]);
    assert_eq!(report["sync_quorum_height"], report["latest_height"]);

    let block_millis = report["block_millis"]
        .as_u64()
        .expect("block_millis should be an unsigned integer");
    assert!(
        block_millis < 1_000,
        "block_millis should be sub-second, got {block_millis}"
    );
    assert_u64_at_least(&report, "produced_block_count", 2);
    assert_eq!(report["total_nxmr_fees_units"], 1_000);
    assert_eq!(report["buyback_pool_nebulai"], 1_000);
    assert_eq!(report["validator_reward_nebulai"], 1_010);
    assert_eq!(report["bridge_custody_reconciled"], true);
    assert_eq!(report["nxmr_custody_deficit_units"], 0);
    assert_hex64(&report, "runtime_surface_root");
    assert_hex64(&report, "rehearsal_root");
}

#[test]
fn prove_live_rpc_devnet_with_launch_artifacts_binds_rehearsal_to_bundle() {
    let dir = temp_rehearsal_dir();
    let public_status = dir.join("public-status.json");
    let public_probe = dir.join("public-probe.json");
    let attestation = dir.join("attestation.json");
    let validators = dir.join("validators.json");
    let handoff = dir.join("handoff.json");
    let acceptance = dir.join("acceptance.json");
    let genesis = dir.join("genesis.json");
    let bundle = dir.join("bundle.json");
    let peer_manifest = dir.join("peer-manifest.json");

    write_nebula_output(&args(&["--sample-public-status"]), &public_status);
    write_nebula_output(&args(&["--sample-public-probe"]), &public_probe);
    write_nebula_output(&args(&["--sample-deployment-attestation"]), &attestation);
    write_nebula_output(&args(&["--sample-validator-set"]), &validators);

    write_nebula_output(
        &[
            "--build-operator-handoff".to_string(),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--validator-set".to_string(),
            path_arg(&validators),
        ],
        &handoff,
    );
    write_nebula_output(
        &[
            "--build-operator-acceptance".to_string(),
            "--operator-handoff".to_string(),
            path_arg(&handoff),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--validator-set".to_string(),
            path_arg(&validators),
        ],
        &acceptance,
    );
    write_nebula_output(
        &[
            "--build-genesis-manifest".to_string(),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--validator-set".to_string(),
            path_arg(&validators),
        ],
        &genesis,
    );
    write_nebula_output(
        &[
            "--build-launch-package-bundle".to_string(),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--public-status".to_string(),
            path_arg(&public_status),
            "--public-probe".to_string(),
            path_arg(&public_probe),
            "--validator-set".to_string(),
            path_arg(&validators),
            "--operator-handoff".to_string(),
            path_arg(&handoff),
            "--operator-acceptance".to_string(),
            path_arg(&acceptance),
            "--genesis-manifest".to_string(),
            path_arg(&genesis),
        ],
        &bundle,
    );
    write_nebula_output(
        &[
            "--build-public-testnet-peer-manifest".to_string(),
            "--launch-package-bundle".to_string(),
            path_arg(&bundle),
            "--deployment-attestation".to_string(),
            path_arg(&attestation),
            "--public-status".to_string(),
            path_arg(&public_status),
            "--public-probe".to_string(),
            path_arg(&public_probe),
            "--validator-set".to_string(),
            path_arg(&validators),
            "--operator-handoff".to_string(),
            path_arg(&handoff),
            "--operator-acceptance".to_string(),
            path_arg(&acceptance),
            "--genesis-manifest".to_string(),
            path_arg(&genesis),
        ],
        &peer_manifest,
    );

    let runtime_surface = dir.join("live-rpc-devnet-runtime-surface.json");
    let missing_peer_manifest = run_nebula_failure_strings(&[
        "--prove-live-rpc-devnet".to_string(),
        "--launch-package-bundle".to_string(),
        path_arg(&bundle),
        "--deployment-attestation".to_string(),
        path_arg(&attestation),
        "--public-status".to_string(),
        path_arg(&public_status),
        "--public-probe".to_string(),
        path_arg(&public_probe),
        "--validator-set".to_string(),
        path_arg(&validators),
        "--operator-handoff".to_string(),
        path_arg(&handoff),
        "--operator-acceptance".to_string(),
        path_arg(&acceptance),
        "--genesis-manifest".to_string(),
        path_arg(&genesis),
    ]);
    assert!(
        missing_peer_manifest.contains("missing --public-testnet-peer-manifest <path>"),
        "{missing_peer_manifest}"
    );

    let stdout = run_nebula_strings(&[
        "--prove-live-rpc-devnet".to_string(),
        "--launch-package-bundle".to_string(),
        path_arg(&bundle),
        "--public-testnet-peer-manifest".to_string(),
        path_arg(&peer_manifest),
        "--deployment-attestation".to_string(),
        path_arg(&attestation),
        "--public-status".to_string(),
        path_arg(&public_status),
        "--public-probe".to_string(),
        path_arg(&public_probe),
        "--validator-set".to_string(),
        path_arg(&validators),
        "--operator-handoff".to_string(),
        path_arg(&handoff),
        "--operator-acceptance".to_string(),
        path_arg(&acceptance),
        "--genesis-manifest".to_string(),
        path_arg(&genesis),
        "--live-rpc-devnet-runtime-surface-out".to_string(),
        path_arg(&runtime_surface),
        "--json".to_string(),
    ]);
    let report: Value = serde_json::from_str(&stdout).expect("live rpc devnet report json");
    let runtime_surface_evidence: Value =
        serde_json::from_str(&fs::read_to_string(&runtime_surface).expect("read runtime surface"))
            .expect("runtime surface evidence json");
    let bundle_manifest: Value =
        serde_json::from_str(&fs::read_to_string(&bundle).expect("read bundle manifest"))
            .expect("bundle manifest json");
    let peer_manifest_json: Value =
        serde_json::from_str(&fs::read_to_string(&peer_manifest).expect("read peer manifest"))
            .expect("peer manifest json");

    assert_eq!(report["live_rpc_devnet_rehearsed"], true);
    assert_eq!(
        report["endpoint_url"],
        "https://testnet.nebula.example/status"
    );
    assert_eq!(
        report["launch_package_bundle_root"],
        bundle_manifest["root"]
    );
    assert_eq!(
        report["public_testnet_peer_manifest_root"],
        peer_manifest_json["root"]
    );
    let expected_snapshot_peer_count = peer_manifest_json["peers"]
        .as_array()
        .expect("peer manifest peers")
        .len()
        .saturating_sub(1) as u64;
    assert_eq!(
        report["public_testnet_peer_manifest_snapshot_peer_count"].as_u64(),
        Some(expected_snapshot_peer_count)
    );
    assert_eq!(
        report["public_testnet_peer_manifest_snapshot_peer_urls"],
        runtime_surface_evidence["status"]["public_testnet_peer_manifest_snapshot_peer_urls"]
    );
    assert_eq!(
        report["public_testnet_peer_manifest_snapshot_peer_urls"]
            .as_array()
            .expect("rehearsal peer URLs")
            .len(),
        expected_snapshot_peer_count as usize
    );
    assert_eq!(runtime_surface_evidence["capture_mode"], "loopback-devnet");
    assert_eq!(
        runtime_surface_evidence["root"],
        report["runtime_surface_root"]
    );
    assert_eq!(
        runtime_surface_evidence["status"]["launch_package_bundle_root"],
        bundle_manifest["root"]
    );
    assert_eq!(
        runtime_surface_evidence["status"]["public_testnet_peer_manifest_root"],
        peer_manifest_json["root"]
    );
    assert_eq!(
        runtime_surface_evidence["status"]["public_testnet_peer_manifest_snapshot_peer_count"]
            .as_u64(),
        Some(expected_snapshot_peer_count)
    );
    assert_hex64(&report, "launch_package_bundle_root");
    assert_hex64(&report, "public_testnet_peer_manifest_root");
    assert_hex64(&report, "runtime_surface_root");
    assert_hex64(&report, "rehearsal_root");

    fs::remove_dir_all(&dir).expect("remove temp rehearsal dir");
}

#[test]
fn public_testnet_peer_manifest_cli_builds_and_verifies_launch_bound_peers() {
    let dir = temp_rehearsal_dir();
    let artifacts = build_sample_launch_artifacts(&dir);
    let peer_manifest_path = dir.join("peer-manifest.json");

    let mut build_args = vec!["--build-public-testnet-peer-manifest".to_string()];
    build_args.extend(launch_artifact_args(&artifacts));
    write_nebula_output(&build_args, &peer_manifest_path);

    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&peer_manifest_path).expect("read peer manifest"))
            .expect("peer manifest json");
    assert_eq!(
        manifest["endpoint_url"],
        "https://testnet.nebula.example/status"
    );
    assert_hex64(&manifest, "root");
    assert_hex64(&manifest, "launch_package_bundle_root");
    assert_hex64(&manifest, "validator_set_root");

    let peers = manifest["peers"]
        .as_array()
        .expect("peer manifest should include peers");
    assert!(
        peers.len() >= 2,
        "sample peer manifest should carry at least two peers"
    );
    assert_u64_at_least(&manifest, "sync_peer_quorum", 1);

    let mut verify_args = vec![
        "--verify-public-testnet-peer-manifest".to_string(),
        path_arg(&peer_manifest_path),
    ];
    verify_args.extend(launch_artifact_args(&artifacts));
    verify_args.push("--json".to_string());

    let stdout = run_nebula_strings(&verify_args);
    let report: Value = serde_json::from_str(&stdout).expect("peer manifest report json");

    assert_eq!(report["public_testnet_peer_manifest_ready"], true);
    assert_eq!(report["level"], "public-testnet-peer-manifest-attested");
    assert_eq!(
        report["public_testnet_peer_manifest_root"],
        manifest["root"]
    );
    assert_eq!(
        report["launch_package_bundle_root"],
        manifest["launch_package_bundle_root"]
    );
    assert_eq!(report["validator_set_root"], manifest["validator_set_root"]);
    assert_eq!(report["endpoint_url"], manifest["endpoint_url"]);
    assert_eq!(report["sync_peer_quorum"], manifest["sync_peer_quorum"]);
    assert_eq!(report["peer_count"].as_u64(), Some(peers.len() as u64));
    assert!(
        report["rpc_peer_urls"]
            .as_array()
            .expect("rpc peer URLs should be an array")
            .len()
            >= peers.len()
    );
    assert!(
        report["snapshot_peer_urls"]
            .as_array()
            .expect("snapshot peer URLs should be an array")
            .len()
            >= peers.len()
    );

    let mut plain_verify_args = vec![
        "--verify-public-testnet-peer-manifest".to_string(),
        path_arg(&peer_manifest_path),
    ];
    plain_verify_args.extend(launch_artifact_args(&artifacts));
    let plain = run_nebula_strings(&plain_verify_args);
    assert!(plain.contains("Public testnet peer manifest verified at"));
    assert!(plain.contains(
        manifest["root"]
            .as_str()
            .expect("peer manifest root should be a string")
    ));

    let first_validator_id = peers[0]["validator_id"]
        .as_str()
        .expect("peer validator_id should be a string");
    let mut rejected_run_args = vec![
        "--run-rpc".to_string(),
        "--follower".to_string(),
        "--validator-id".to_string(),
        first_validator_id.to_string(),
        "--public-testnet-peer-manifest".to_string(),
        path_arg(&peer_manifest_path),
        "--sync-rpc".to_string(),
        "https://unattested-peer.nebula.example/snapshot".to_string(),
    ];
    rejected_run_args.extend(launch_artifact_args(&artifacts));
    let rejected = run_nebula_failure_strings(&rejected_run_args);
    assert!(
        rejected.contains("not in the verified public testnet peer manifest"),
        "{rejected}"
    );

    fs::remove_dir_all(&dir).expect("remove temp rehearsal dir");
}

#[test]
fn public_testnet_launch_readiness_cli_verifies_external_runtime_surface() {
    let dir = temp_rehearsal_dir();
    let artifacts = build_sample_launch_artifacts(&dir);
    let peer_manifest = dir.join("peer-manifest.json");
    let activation = dir.join("activation.json");
    let join = dir.join("join.json");
    let operator_join_confirmation = dir.join("operator-join-confirmation.json");
    let public_observer_confirmation = dir.join("public-observer-confirmation.json");
    let live_runtime_surface = dir.join("live-rpc-devnet-runtime-surface.json");
    let live_rehearsal = dir.join("live-rpc-devnet.json");
    let external_runtime_surface = dir.join("external-runtime-surface.json");
    let loopback_certificate = dir.join("loopback-launch-certificate.json");
    let external_certificate = dir.join("external-launch-certificate.json");

    let mut peer_args = vec!["--build-public-testnet-peer-manifest".to_string()];
    peer_args.extend(launch_artifact_args(&artifacts));
    write_nebula_output(&peer_args, &peer_manifest);

    let mut activation_args = vec!["--build-validator-activation".to_string()];
    activation_args.extend(launch_artifact_args(&artifacts));
    write_nebula_output(&activation_args, &activation);

    let mut join_args = vec![
        "--build-validator-join".to_string(),
        "--validator-activation".to_string(),
        path_arg(&activation),
    ];
    join_args.extend(launch_artifact_args(&artifacts));
    write_nebula_output(&join_args, &join);

    let mut operator_confirmation_args = vec![
        "--build-operator-join-confirmation".to_string(),
        "--validator-join".to_string(),
        path_arg(&join),
        "--validator-activation".to_string(),
        path_arg(&activation),
    ];
    operator_confirmation_args.extend(launch_artifact_args(&artifacts));
    write_nebula_output(&operator_confirmation_args, &operator_join_confirmation);

    let mut observer_confirmation_args = vec![
        "--build-public-observer-confirmation".to_string(),
        "--operator-join-confirmation".to_string(),
        path_arg(&operator_join_confirmation),
        "--validator-join".to_string(),
        path_arg(&join),
        "--validator-activation".to_string(),
        path_arg(&activation),
    ];
    observer_confirmation_args.extend(launch_artifact_args(&artifacts));
    write_nebula_output(&observer_confirmation_args, &public_observer_confirmation);

    let mut rehearsal_args = vec![
        "--prove-live-rpc-devnet".to_string(),
        "--public-testnet-peer-manifest".to_string(),
        path_arg(&peer_manifest),
        "--live-rpc-devnet-runtime-surface-out".to_string(),
        path_arg(&live_runtime_surface),
        "--json".to_string(),
    ];
    rehearsal_args.extend(launch_artifact_args(&artifacts));
    fs::write(&live_rehearsal, run_nebula_strings(&rehearsal_args))
        .expect("write live RPC rehearsal");

    let attestation: Value = serde_json::from_str(
        &fs::read_to_string(&artifacts.attestation).expect("read attestation"),
    )
    .expect("deployment attestation json");
    let endpoint_url = value_str(&attestation["public_endpoint"], "url");
    let tls_pin = attestation["public_endpoint"]["tls_pins"]
        .as_array()
        .expect("public endpoint TLS pins")
        .first()
        .expect("sample attestation has a TLS pin");
    let tls_pin_arg = format!(
        "{},{},{}",
        value_str(tls_pin, "cert_sha256"),
        value_str(tls_pin, "public_key_sha256"),
        tls_pin["not_after_unix_ms"]
            .as_u64()
            .expect("TLS pin expiry as u64")
    );
    let mut external_surface_args = vec![
        "--build-runtime-surface-evidence".to_string(),
        "--endpoint-url".to_string(),
        endpoint_url.to_string(),
        "--runtime-surface-tls-pin".to_string(),
        tls_pin_arg,
    ];
    for (flag, path) in
        write_runtime_surface_capture_inputs(&dir, &live_runtime_surface, Some(&peer_manifest))
    {
        external_surface_args.push(flag);
        external_surface_args.push(path_arg(&path));
    }
    write_nebula_output(&external_surface_args, &external_runtime_surface);

    let verify_external_surface_args = vec![
        "--verify-runtime-surface-evidence".to_string(),
        path_arg(&external_runtime_surface),
        "--json".to_string(),
    ];
    let external_surface_report: Value =
        serde_json::from_str(&run_nebula_strings(&verify_external_surface_args))
            .expect("external runtime surface report json");
    assert_eq!(external_surface_report["runtime_surface_ready"], true);
    assert_eq!(
        external_surface_report["capture_mode"],
        "external-public-endpoint"
    );

    let certificate_args_for = |runtime_surface: &Path| -> Vec<String> {
        let mut args = vec![
            "--build-public-testnet-launch-certificate".to_string(),
            "--public-observer-confirmation".to_string(),
            path_arg(&public_observer_confirmation),
            "--runtime-surface-evidence".to_string(),
            path_arg(runtime_surface),
            "--public-testnet-peer-manifest".to_string(),
            path_arg(&peer_manifest),
            "--operator-join-confirmation".to_string(),
            path_arg(&operator_join_confirmation),
            "--validator-join".to_string(),
            path_arg(&join),
            "--validator-activation".to_string(),
            path_arg(&activation),
        ];
        args.extend(launch_artifact_args(&artifacts));
        args
    };
    write_nebula_output(
        &certificate_args_for(&live_runtime_surface),
        &loopback_certificate,
    );
    write_nebula_output(
        &certificate_args_for(&external_runtime_surface),
        &external_certificate,
    );

    let certificate_verifier_args_for =
        |certificate: &Path, runtime_surface: &Path| -> Vec<String> {
            let mut args = vec![
                "--verify-public-testnet-launch-certificate".to_string(),
                path_arg(certificate),
                "--public-observer-confirmation".to_string(),
                path_arg(&public_observer_confirmation),
                "--runtime-surface-evidence".to_string(),
                path_arg(runtime_surface),
                "--public-testnet-peer-manifest".to_string(),
                path_arg(&peer_manifest),
                "--operator-join-confirmation".to_string(),
                path_arg(&operator_join_confirmation),
                "--validator-join".to_string(),
                path_arg(&join),
                "--validator-activation".to_string(),
                path_arg(&activation),
            ];
            args.extend(launch_artifact_args(&artifacts));
            args.push("--json".to_string());
            args
        };
    let certificate_report: Value = serde_json::from_str(&run_nebula_strings(
        &certificate_verifier_args_for(&external_certificate, &external_runtime_surface),
    ))
    .expect("launch certificate report json");
    assert_eq!(
        certificate_report["public_testnet_launch_certificate_ready"],
        true
    );
    assert_hex64(
        &certificate_report,
        "public_testnet_launch_certificate_root",
    );
    assert_eq!(
        certificate_report["public_testnet_peer_manifest_snapshot_peer_urls"],
        external_surface_report["public_testnet_peer_manifest_snapshot_peer_urls"]
    );

    let readiness_args_for = |certificate: &Path, runtime_surface: &Path| -> Vec<String> {
        let mut args = vec![
            "--verify-public-testnet-launch-readiness".to_string(),
            path_arg(certificate),
            "--public-observer-confirmation".to_string(),
            path_arg(&public_observer_confirmation),
            "--runtime-surface-evidence".to_string(),
            path_arg(runtime_surface),
            "--public-testnet-peer-manifest".to_string(),
            path_arg(&peer_manifest),
            "--live-rpc-devnet-rehearsal".to_string(),
            path_arg(&live_rehearsal),
            "--live-rpc-devnet-runtime-surface-evidence".to_string(),
            path_arg(&live_runtime_surface),
            "--operator-join-confirmation".to_string(),
            path_arg(&operator_join_confirmation),
            "--validator-join".to_string(),
            path_arg(&join),
            "--validator-activation".to_string(),
            path_arg(&activation),
        ];
        args.extend(launch_artifact_args(&artifacts));
        args.push("--json".to_string());
        args
    };

    let loopback_rejection = run_nebula_failure_strings(&readiness_args_for(
        &loopback_certificate,
        &live_runtime_surface,
    ));
    let loopback_rejection: Value =
        serde_json::from_str(&loopback_rejection).expect("loopback rejection json");
    assert_eq!(loopback_rejection["public_launch_ready"], false);
    assert!(loopback_rejection["blocking_gaps"]
        .as_array()
        .expect("blocking gaps")
        .iter()
        .any(|gap| gap
            == "runtime_surface.capture_mode expected external-public-endpoint but got loopback-devnet"));

    let readiness_report: Value = serde_json::from_str(&run_nebula_strings(&readiness_args_for(
        &external_certificate,
        &external_runtime_surface,
    )))
    .expect("launch readiness report json");
    assert_eq!(readiness_report["public_launch_ready"], true);
    assert_eq!(readiness_report["level"], "public-testnet-launch-ready");
    assert_eq!(
        readiness_report["runtime_surface_capture_mode"],
        "external-public-endpoint"
    );
    assert_hex64(&readiness_report, "public_launch_readiness_root");
    assert_eq!(
        readiness_report["public_testnet_launch_certificate_root"],
        certificate_report["public_testnet_launch_certificate_root"]
    );
    assert_eq!(
        readiness_report["public_testnet_peer_manifest_snapshot_peer_urls"],
        certificate_report["public_testnet_peer_manifest_snapshot_peer_urls"]
    );

    fs::remove_dir_all(&dir).expect("remove temp rehearsal dir");
}

#[test]
fn prove_live_rpc_devnet_plain_text_smoke_reports_level_and_blocker() {
    let stdout = run_nebula(&["--prove-live-rpc-devnet"]);

    assert!(stdout.contains("live-rpc-devnet-rehearsal-ready"));
    assert!(stdout.contains("public-launch-deployment-attestation"));
}
