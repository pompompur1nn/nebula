use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceContractReceiptGatePreflightRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-gate-preflight-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

pub const PREFLIGHT_SUITE: &str = "contract-receipt-gate-deterministic-preflight-evidence-v1";
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 18_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RELEASE_HOLD: &str = "hold_until_preflight_state_root_is_verified";

const REQUIRED_CHECKS: [&str; 9] = [
    "sealed_input_commitment",
    "encrypted_effect_root",
    "contract_receipt_root",
    "fee_bound",
    "pq_sequencer_auth_root",
    "metadata_redaction",
    "exit_replayability",
    "expected_invocation_root",
    "release_hold",
];

const DEFAULT_FAIL_CLOSED_REASONS: [&str; 8] = [
    "missing_sealed_input_commitment",
    "encrypted_effect_root_mismatch",
    "contract_receipt_root_mismatch",
    "fee_bound_exceeded",
    "pq_sequencer_auth_root_unbound",
    "metadata_redaction_leak",
    "exit_replayability_not_proven",
    "expected_invocation_root_mismatch",
];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub preflight_suite: String,
    pub max_fee_atomic: u64,
    pub min_pq_security_bits: u16,
    pub fail_closed: bool,
    pub runtime_execution_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            preflight_suite: PREFLIGHT_SUITE.to_string(),
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            fail_closed: true,
            runtime_execution_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "preflight_suite": self.preflight_suite,
            "max_fee_atomic": self.max_fee_atomic,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fail_closed": self.fail_closed,
            "runtime_execution_allowed": self.runtime_execution_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreflightEvidence {
    pub label: String,
    pub sequence: u64,
    pub observed_root: String,
    pub expected_root: String,
    pub public_surface: String,
    pub passed: bool,
}

impl PreflightEvidence {
    pub fn new(label: &str, sequence: u64, seed: &str) -> Self {
        let root = scoped_hash(label, seed);
        Self {
            label: label.to_string(),
            sequence,
            observed_root: root.clone(),
            expected_root: root,
            public_surface: "root_only".to_string(),
            passed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "sequence": self.sequence,
            "observed_root": self.observed_root,
            "expected_root": self.expected_root,
            "public_surface": self.public_surface,
            "passed": self.passed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PREFLIGHT-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FailClosedReason {
    pub reason: String,
    pub sequence: u64,
    pub reason_root: String,
    pub enforced: bool,
}

impl FailClosedReason {
    pub fn new(reason: &str, sequence: u64) -> Self {
        Self {
            reason: reason.to_string(),
            sequence,
            reason_root: scoped_hash("fail-closed-reason", reason),
            enforced: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reason": self.reason,
            "sequence": self.sequence,
            "reason_root": self.reason_root,
            "enforced": self.enforced,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("FAIL-CLOSED-REASON", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseHold {
    pub label: String,
    pub hold_root: String,
    pub runtime_execution_allowed: bool,
    pub cargo_execution_allowed: bool,
    pub release_allowed: bool,
}

impl ReleaseHold {
    pub fn devnet() -> Self {
        Self {
            label: DEFAULT_RELEASE_HOLD.to_string(),
            hold_root: scoped_hash("release-hold", DEFAULT_RELEASE_HOLD),
            runtime_execution_allowed: false,
            cargo_execution_allowed: false,
            release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "hold_root": self.hold_root,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "cargo_execution_allowed": self.cargo_execution_allowed,
            "release_allowed": self.release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RELEASE-HOLD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub sealed_input_commitment: PreflightEvidence,
    pub encrypted_effect_root: PreflightEvidence,
    pub contract_receipt_root: PreflightEvidence,
    pub fee_bound: PreflightEvidence,
    pub pq_sequencer_auth_root: PreflightEvidence,
    pub metadata_redaction: PreflightEvidence,
    pub exit_replayability: PreflightEvidence,
    pub expected_invocation_root: PreflightEvidence,
    pub fail_closed_reasons: Vec<FailClosedReason>,
    pub fail_closed_root: String,
    pub release_hold: ReleaseHold,
    pub evidence_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let sealed_input_commitment =
            PreflightEvidence::new("sealed_input_commitment", 0, "devnet-sealed-input-envelope");
        let encrypted_effect_root =
            PreflightEvidence::new("encrypted_effect_root", 1, "devnet-encrypted-effects");
        let contract_receipt_root =
            PreflightEvidence::new("contract_receipt_root", 2, "devnet-contract-receipt");
        let fee_bound = PreflightEvidence::new("fee_bound", 3, "devnet-fee-bound");
        let pq_sequencer_auth_root =
            PreflightEvidence::new("pq_sequencer_auth_root", 4, "devnet-pq-sequencer-auth");
        let metadata_redaction =
            PreflightEvidence::new("metadata_redaction", 5, "devnet-metadata-redaction");
        let exit_replayability =
            PreflightEvidence::new("exit_replayability", 6, "devnet-exit-replayability");
        let expected_invocation_root =
            PreflightEvidence::new("expected_invocation_root", 7, "devnet-expected-invocation");
        let fail_closed_reasons = DEFAULT_FAIL_CLOSED_REASONS
            .iter()
            .enumerate()
            .map(|(index, reason)| FailClosedReason::new(reason, index as u64))
            .collect::<Vec<_>>();
        let fail_closed_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-PREFLIGHT-FAIL-CLOSED",
            &fail_closed_reasons
                .iter()
                .map(FailClosedReason::public_record)
                .collect::<Vec<_>>(),
        );
        let release_hold = ReleaseHold::devnet();
        let mut state = Self {
            config,
            sealed_input_commitment,
            encrypted_effect_root,
            contract_receipt_root,
            fee_bound,
            pq_sequencer_auth_root,
            metadata_redaction,
            exit_replayability,
            expected_invocation_root,
            fail_closed_reasons,
            fail_closed_root,
            release_hold,
            evidence_root: String::new(),
            state_root: String::new(),
        };
        state.evidence_root = state.compute_evidence_root();
        state.state_root = state.compute_state_root();
        state
    }

    pub fn evidence_by_label(&self) -> BTreeMap<String, String> {
        self.evidence_records()
            .into_iter()
            .map(|record| (record.label.clone(), record.state_root()))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "sealed_input_commitment": self.sealed_input_commitment.public_record(),
            "encrypted_effect_root": self.encrypted_effect_root.public_record(),
            "contract_receipt_root": self.contract_receipt_root.public_record(),
            "fee_bound": self.fee_bound.public_record(),
            "pq_sequencer_auth_root": self.pq_sequencer_auth_root.public_record(),
            "metadata_redaction": self.metadata_redaction.public_record(),
            "exit_replayability": self.exit_replayability.public_record(),
            "expected_invocation_root": self.expected_invocation_root.public_record(),
            "evidence_by_label": self.evidence_by_label(),
            "fail_closed_reasons": self.fail_closed_reasons.iter().map(FailClosedReason::public_record).collect::<Vec<_>>(),
            "fail_closed_root": self.fail_closed_root,
            "release_hold": self.release_hold.public_record(),
            "evidence_root": self.evidence_root,
            "state_root": self.state_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !self.config.fail_closed {
            return Err("contract receipt gate preflight must be fail-closed".to_string());
        }
        if self.config.runtime_execution_allowed {
            return Err("runtime execution cannot be allowed during preflight".to_string());
        }
        if self.release_hold.runtime_execution_allowed
            || self.release_hold.cargo_execution_allowed
            || self.release_hold.release_allowed
        {
            return Err(
                "release hold must block cargo, runtime, and release execution".to_string(),
            );
        }
        if self.config.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq sequencer auth security floor is too low".to_string());
        }
        if self.config.max_fee_atomic > DEFAULT_MAX_FEE_ATOMIC {
            return Err("fee bound exceeds preflight maximum".to_string());
        }
        if self.fail_closed_reasons.len() != DEFAULT_FAIL_CLOSED_REASONS.len() {
            return Err("fail-closed reason set changed".to_string());
        }
        if self.evidence_records().len() != REQUIRED_CHECKS.len() - 1 {
            return Err("preflight evidence set changed".to_string());
        }
        if self
            .evidence_records()
            .iter()
            .any(|record| !record.passed || record.observed_root != record.expected_root)
        {
            return Err("preflight evidence root mismatch".to_string());
        }
        if self.fail_closed_root != self.compute_fail_closed_root() {
            return Err("fail-closed root mismatch".to_string());
        }
        if self.evidence_root != self.compute_evidence_root() {
            return Err("evidence root mismatch".to_string());
        }
        if self.state_root != self.compute_state_root() {
            return Err("state root mismatch".to_string());
        }
        Ok(())
    }

    pub fn compute_fail_closed_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-PREFLIGHT-FAIL-CLOSED",
            &self
                .fail_closed_reasons
                .iter()
                .map(FailClosedReason::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn compute_evidence_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-PREFLIGHT-EVIDENCE",
            &self
                .evidence_records()
                .iter()
                .map(PreflightEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-PREFLIGHT-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.compute_evidence_root()),
                HashPart::Str(&self.compute_fail_closed_root()),
                HashPart::Str(&self.release_hold.state_root()),
                HashPart::Str("execution-held"),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
    }

    fn evidence_records(&self) -> Vec<&PreflightEvidence> {
        vec![
            &self.sealed_input_commitment,
            &self.encrypted_effect_root,
            &self.contract_receipt_root,
            &self.fee_bound,
            &self.pq_sequencer_auth_root,
            &self.metadata_redaction,
            &self.exit_replayability,
            &self.expected_invocation_root,
        ]
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

fn scoped_hash(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-PREFLIGHT-DEVNET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-PREFLIGHT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
