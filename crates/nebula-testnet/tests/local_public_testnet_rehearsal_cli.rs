use serde_json::Value;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_nebula-testnet")
}

fn run_nebula(args: &[&str]) -> String {
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
