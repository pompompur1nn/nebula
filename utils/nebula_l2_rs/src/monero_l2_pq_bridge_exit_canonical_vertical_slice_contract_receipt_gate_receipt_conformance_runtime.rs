use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceContractReceiptGateReceiptConformanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-gate-receipt-conformance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "2026-06-19.contract-receipt-gate.receipt-conformance.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const CONFORMANCE_SUITE: &str = "contract-receipt-gate-deterministic-conformance-evidence-v1";
pub const DEFAULT_RUNTIME_EXECUTION_ALLOWED: bool = false;
pub const DEFAULT_RELEASE_ALLOWED: bool = false;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 18_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WALLET_REPLAY_DEPTH: u64 = 2;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-gate-receipt-conformance-runtime";

const CONFORMANCE_LANES: [&str; 15] = [
    "invocation",
    "preflight",
    "execution_receipt",
    "sealed_input",
    "encrypted_effect",
    "contract_receipt",
    "fee_bound",
    "pq_sequencer_auth",
    "metadata_redaction",
    "exit_replayability",
    "operator_evidence",
    "wallet_visible_receipt",
    "fail_closed_receipt",
    "release_blockers",
    "runtime_execution",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub conformance_suite: String,
    pub max_fee_atomic: u64,
    pub min_pq_security_bits: u16,
    pub min_wallet_replay_depth: u64,
    pub runtime_execution_allowed: bool,
    pub release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            conformance_suite: CONFORMANCE_SUITE.to_string(),
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_wallet_replay_depth: DEFAULT_MIN_WALLET_REPLAY_DEPTH,
            runtime_execution_allowed: DEFAULT_RUNTIME_EXECUTION_ALLOWED,
            release_allowed: DEFAULT_RELEASE_ALLOWED,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "conformance_suite": self.conformance_suite,
            "max_fee_atomic": self.max_fee_atomic,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_wallet_replay_depth": self.min_wallet_replay_depth,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "release_allowed": self.release_allowed
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
    pub lane: String,
    pub sequence: u64,
    pub expected_root: String,
    pub observed_root: String,
    pub placeholder_root: String,
    pub conformance_root: String,
    pub matches_expected: bool,
    pub release_blocking: bool,
    pub status: String,
    pub evidence_source: String,
}

impl ConformanceCheck {
    pub fn deferred(lane: &str, sequence: u64) -> Self {
        let expected_root = expected_lane_root(lane, sequence);
        let observed_root = observed_placeholder_root(lane, sequence);
        let placeholder_root = placeholder_marker_root(lane, sequence);
        let matches_expected = expected_root == observed_root;
        let release_blocking = true;
        let status = if matches_expected {
            "conformant_after_runtime".to_string()
        } else {
            "runtime_deferred_observed_placeholder".to_string()
        };
        let conformance_root = conformance_root(
            lane,
            sequence,
            &expected_root,
            &observed_root,
            &placeholder_root,
            matches_expected,
            release_blocking,
        );

        Self {
            lane: lane.to_string(),
            sequence,
            expected_root,
            observed_root,
            placeholder_root,
            conformance_root,
            matches_expected,
            release_blocking,
            status,
            evidence_source: "deterministic_devnet_conformance_placeholder".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "sequence": self.sequence,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "placeholder_root": self.placeholder_root,
            "conformance_root": self.conformance_root,
            "matches_expected": self.matches_expected,
            "release_blocking": self.release_blocking,
            "status": self.status,
            "evidence_source": self.evidence_source
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance-check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub forced_exit_epoch: u64,
    pub checks: Vec<ConformanceCheck>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            runtime_id: format!("{DOMAIN}:devnet"),
            forced_exit_epoch: 42,
            checks: devnet_checks(),
        }
    }

    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .iter()
            .map(ConformanceCheck::public_record)
            .collect::<Vec<_>>();

        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "conformance_suite": CONFORMANCE_SUITE,
            "runtime_id": self.runtime_id,
            "forced_exit_epoch": self.forced_exit_epoch,
            "config": self.config.public_record(),
            "check_count": self.checks.len() as u64,
            "check_root": self.check_root(),
            "release_blocker_root": self.release_blocker_root(),
            "state_root": self.state_root(),
            "checks": checks
        })
    }

    pub fn check_root(&self) -> String {
        let leaves = self
            .checks
            .iter()
            .map(ConformanceCheck::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:checks"), &leaves)
    }

    pub fn release_blocker_root(&self) -> String {
        let leaves = self
            .checks
            .iter()
            .filter(|check| check.release_blocking)
            .map(ConformanceCheck::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:release-blockers"), &leaves)
    }

    pub fn conformance_evidence_root(&self) -> String {
        let leaves = self
            .checks
            .iter()
            .map(|check| {
                json!({
                    "lane": check.lane,
                    "expected_root": check.expected_root,
                    "observed_root": check.observed_root,
                    "conformance_root": check.conformance_root,
                    "matches_expected": check.matches_expected,
                    "release_blocking": check.release_blocking
                })
            })
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:conformance-evidence"), &leaves)
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.forced_exit_epoch),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.check_root()),
                HashPart::Str(&self.release_blocker_root()),
                HashPart::Str(&self.conformance_evidence_root()),
            ],
            32,
        )
    }

    pub fn verify_conformance_evidence(&self) -> Result<()> {
        for check in &self.checks {
            let expected_root = expected_lane_root(&check.lane, check.sequence);
            let observed_root = observed_placeholder_root(&check.lane, check.sequence);
            let placeholder_root = placeholder_marker_root(&check.lane, check.sequence);
            let conformance = conformance_root(
                &check.lane,
                check.sequence,
                &expected_root,
                &observed_root,
                &placeholder_root,
                expected_root == observed_root,
                check.release_blocking,
            );

            if check.expected_root != expected_root {
                return Err(format!("expected root mismatch for lane {}", check.lane));
            }
            if check.observed_root != observed_root {
                return Err(format!("observed root mismatch for lane {}", check.lane));
            }
            if check.placeholder_root != placeholder_root {
                return Err(format!("placeholder root mismatch for lane {}", check.lane));
            }
            if check.conformance_root != conformance {
                return Err(format!("conformance root mismatch for lane {}", check.lane));
            }
            if !check.release_blocking {
                return Err(format!("release blocker missing for lane {}", check.lane));
            }
        }
        Ok(())
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

fn devnet_checks() -> Vec<ConformanceCheck> {
    CONFORMANCE_LANES
        .iter()
        .enumerate()
        .map(|(index, lane)| ConformanceCheck::deferred(lane, index as u64))
        .collect()
}

fn expected_lane_root(lane: &str, sequence: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::U64(sequence),
            HashPart::Str("contract_receipt_gate_expected_conformance"),
        ],
        32,
    )
}

fn observed_placeholder_root(lane: &str, sequence: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:observed-placeholder-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::U64(sequence),
            HashPart::Str("runtime_execution_deferred"),
        ],
        32,
    )
}

fn placeholder_marker_root(lane: &str, sequence: u64) -> String {
    let marker = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "lane": lane,
        "sequence": sequence,
        "runtime_execution_allowed": DEFAULT_RUNTIME_EXECUTION_ALLOWED,
        "release_allowed": DEFAULT_RELEASE_ALLOWED,
        "observed_root_kind": "deterministic_placeholder",
        "release_blocking": true
    });
    record_root("placeholder-marker", &marker)
}

fn conformance_root(
    lane: &str,
    sequence: u64,
    expected_root: &str,
    observed_root: &str,
    placeholder_root: &str,
    matches_expected: bool,
    release_blocking: bool,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:conformance-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::U64(sequence),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Str(placeholder_root),
            HashPart::Str(if matches_expected {
                "match"
            } else {
                "mismatch"
            }),
            HashPart::Str(if release_blocking {
                "release_blocking"
            } else {
                "release_allowed"
            }),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&format!("{DOMAIN}:{label}"), &[HashPart::Json(record)], 32)
}
