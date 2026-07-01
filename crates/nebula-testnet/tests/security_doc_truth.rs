use std::fs;
use std::path::Path;

fn repo_file(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {rel}: {error}"))
}

#[test]
fn security_docs_exist_and_are_nonempty() {
    for doc in ["SECURITY.md", "THREAT_MODEL.md"] {
        assert!(repo_file(doc).len() > 500, "{doc} is missing or too short");
    }
}

#[test]
fn readme_and_nebula_layer2_are_byte_identical() {
    assert_eq!(
        repo_file("README.md"),
        repo_file("docs/NEBULA_LAYER2.md"),
        "README.md must be byte-identical to docs/NEBULA_LAYER2.md (the CI cmp gate)"
    );
}

#[test]
fn security_doc_constants_match_code() {
    let security = repo_file("SECURITY.md");

    assert_eq!(nebula_testnet::runtime::MIN_BRIDGE_CONFIRMATIONS, 10);
    assert_eq!(
        nebula_testnet::runtime::MIN_BRIDGE_DEPOSIT_OBSERVER_QUORUM,
        2
    );
    assert_eq!(nebula_testnet::runtime::MIN_WITHDRAWAL_OPERATOR_QUORUM, 2);
    assert!(
        !nebula_testnet::runtime::bridge_policy().live_value_enabled,
        "SECURITY.md states the bridge runs with live value disabled"
    );
    assert!(
        security.contains("live_value_enabled == false"),
        "SECURITY.md must cite the live-value-disabled invariant"
    );
    assert_eq!(
        nebula_crypto::SchemeId::HybridEd25519MlDsa65.tag(),
        "hybrid-ed25519-mldsa65"
    );
    assert_eq!(nebula_privacy::RANGE_BITS, 64);
}
