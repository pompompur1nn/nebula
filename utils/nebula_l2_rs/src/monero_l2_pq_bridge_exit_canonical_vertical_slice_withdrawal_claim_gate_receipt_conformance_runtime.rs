use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWithdrawalClaimGateReceiptConformanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-withdrawal-claim-gate-receipt-conformance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WITHDRAWAL_CLAIM_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFORMANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-withdrawal-claim-receipt-conformance-v1";
pub const DEFAULT_REFERENCE_HEIGHT: u64 = 4_260_768;
pub const DEFAULT_DEFERRED_RUNTIME_ROOT_LABEL: &str =
    "cargo-runtime-execution-deferred-deterministic-placeholder";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub conformance_suite: String,
    pub reference_height: u64,
    pub runtime_execution_deferred: bool,
    pub deterministic_placeholders_required: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            conformance_suite: CONFORMANCE_SUITE.to_string(),
            reference_height: DEFAULT_REFERENCE_HEIGHT,
            runtime_execution_deferred: true,
            deterministic_placeholders_required: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "conformance_suite": self.conformance_suite,
            "reference_height": self.reference_height,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "deterministic_placeholders_required": self.deterministic_placeholders_required,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceCheck {
    pub label: String,
    pub expected_root: String,
    pub observed_root: String,
    pub matches_expected: bool,
    pub release_blocking: bool,
    pub evidence_root: String,
}

impl ConformanceCheck {
    pub fn deferred(label: impl Into<String>, expected_root: impl Into<String>) -> Self {
        let label = label.into();
        let expected_root = expected_root.into();
        let observed_root = placeholder_observed_root(&label);
        let matches_expected = expected_root == observed_root;
        let release_blocking = !matches_expected;
        let evidence_root = conformance_evidence_root(
            "deferred_check",
            &json!({
                "label": label,
                "expected_root": expected_root,
                "observed_root": observed_root,
                "matches_expected": matches_expected,
                "release_blocking": release_blocking,
                "runtime_execution": "deferred",
            }),
        );

        Self {
            label,
            expected_root,
            observed_root,
            matches_expected,
            release_blocking,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "matches_expected": self.matches_expected,
            "release_blocking": self.release_blocking,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseBlocker {
    pub blocker_id: String,
    pub label: String,
    pub reason: String,
    pub evidence_root: String,
}

impl ReleaseBlocker {
    pub fn from_check(check: &ConformanceCheck) -> Self {
        let reason = "observed_root_is_deferred_runtime_placeholder".to_string();
        let evidence_root = conformance_evidence_root(
            "release_blocker",
            &json!({
                "label": check.label,
                "reason": reason,
                "expected_root": check.expected_root,
                "observed_root": check.observed_root,
                "action": "hold_withdrawal_claim_receipt_release",
            }),
        );
        let blocker_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-BLOCKER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&check.label),
                HashPart::Str(&check.expected_root),
                HashPart::Str(&check.observed_root),
                HashPart::Str(&evidence_root),
            ],
            32,
        );

        Self {
            blocker_id,
            label: check.label.clone(),
            reason,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "label": self.label,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub checks: Vec<ConformanceCheck>,
    pub check_roots: BTreeMap<String, String>,
    pub release_blockers: Vec<ReleaseBlocker>,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub all_roots_conform: bool,
    pub release_blocking: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let expected_roots = expected_withdrawal_claim_receipt_roots(&config);
        let checks = expected_roots
            .iter()
            .map(|(label, expected_root)| ConformanceCheck::deferred(label, expected_root))
            .collect::<Vec<_>>();
        let check_roots = check_root_map(&checks);
        let release_blockers = checks
            .iter()
            .filter(|check| check.release_blocking)
            .map(ReleaseBlocker::from_check)
            .collect::<Vec<_>>();
        let expected_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-EXPECTED",
            &checks
                .iter()
                .map(|check| {
                    json!({
                        "label": check.label,
                        "expected_root": check.expected_root,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let observed_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-OBSERVED",
            &checks
                .iter()
                .map(|check| {
                    json!({
                        "label": check.label,
                        "observed_root": check.observed_root,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let all_roots_conform = checks.iter().all(|check| check.matches_expected);
        let release_blocking = !all_roots_conform
            || !release_blockers.is_empty()
            || !config.production_release_allowed;

        Self {
            config,
            checks,
            check_roots,
            release_blockers,
            expected_receipt_root,
            observed_receipt_root,
            all_roots_conform,
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "checks": self.checks.iter().map(ConformanceCheck::public_record).collect::<Vec<_>>(),
            "check_roots": self.check_roots,
            "release_blockers": self.release_blockers.iter().map(ReleaseBlocker::public_record).collect::<Vec<_>>(),
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "all_roots_conform": self.all_roots_conform,
            "release_blocking": self.release_blocking,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&check_map_root(&self.check_roots)),
                HashPart::Str(&release_blocker_root(&self.release_blockers)),
                HashPart::Str(&self.expected_receipt_root),
                HashPart::Str(&self.observed_receipt_root),
                HashPart::Str(bool_str(self.all_roots_conform)),
                HashPart::Str(bool_str(self.release_blocking)),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn expected_withdrawal_claim_receipt_roots(config: &Config) -> BTreeMap<String, String> {
    let labels = [
        "invocation",
        "preflight",
        "execution_receipt",
        "claim_authorization",
        "settlement_receipt",
        "challenge_window",
        "reserve_proof",
        "pq_withdrawal_authorization",
        "wallet_recovery_payload",
        "privacy_preserving_proof_export",
        "operator_evidence",
        "wallet_visible_receipt",
        "fail_closed_receipt",
        "release_blockers",
    ];

    labels
        .iter()
        .map(|label| {
            (
                (*label).to_string(),
                expected_component_root(label, config.reference_height),
            )
        })
        .collect()
}

pub fn expected_component_root(label: &str, reference_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-EXPECTED-COMPONENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(reference_height),
            HashPart::Str("withdrawal-claim-receipt-runtime-gate"),
        ],
        32,
    )
}

pub fn placeholder_observed_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-PLACEHOLDER-OBSERVED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(DEFAULT_DEFERRED_RUNTIME_ROOT_LABEL),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn conformance_evidence_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-EVIDENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn check_root_map(checks: &[ConformanceCheck]) -> BTreeMap<String, String> {
    checks
        .iter()
        .map(|check| (check.label.clone(), check.state_root()))
        .collect()
}

pub fn check_map_root(records: &BTreeMap<String, String>) -> String {
    let leaves = records
        .iter()
        .map(|(label, root)| json!({ "label": label, "root": root }))
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-CHECK-MAP",
        &leaves,
    )
}

pub fn release_blocker_root(blockers: &[ReleaseBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(ReleaseBlocker::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WITHDRAWAL-CLAIM-GATE-RECEIPT-CONFORMANCE-BLOCKERS",
        &leaves,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
