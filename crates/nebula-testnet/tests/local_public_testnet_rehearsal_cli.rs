use serde_json::Value;
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

    let runtime_surface = dir.join("live-rpc-devnet-runtime-surface.json");
    let stdout = run_nebula_strings(&[
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

    assert_eq!(report["live_rpc_devnet_rehearsed"], true);
    assert_eq!(
        report["endpoint_url"],
        "https://testnet.nebula.example/status"
    );
    assert_eq!(
        report["launch_package_bundle_root"],
        bundle_manifest["root"]
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
    assert_hex64(&report, "launch_package_bundle_root");
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
fn prove_live_rpc_devnet_plain_text_smoke_reports_level_and_blocker() {
    let stdout = run_nebula(&["--prove-live-rpc-devnet"]);

    assert!(stdout.contains("live-rpc-devnet-rehearsal-ready"));
    assert!(stdout.contains("public-launch-deployment-attestation"));
}
