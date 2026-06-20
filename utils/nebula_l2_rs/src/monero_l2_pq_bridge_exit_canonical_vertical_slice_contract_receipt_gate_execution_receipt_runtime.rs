use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceContractReceiptGateExecutionReceiptRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-gate-execution-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_ENVELOPE_SUITE: &str =
    "contract-receipt-gate-deterministic-execution-receipt-envelope-v1";
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 18_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WALLET_REPLAY_DEPTH: u64 = 2;
pub const DEFAULT_RELEASE_HOLD: &str = "hold_until_cargo_runtime_execution_is_allowed";

const REQUIRED_ENVELOPES: [&str; 13] = [
    "sealed_input_accepted",
    "encrypted_effect_committed",
    "contract_receipt_emitted",
    "fee_bound_checked",
    "pq_sequencer_auth_root",
    "metadata_redaction_checked",
    "exit_replayability_root",
    "expected_invocation_root",
    "expected_preflight_root",
    "operator_evidence_root",
    "wallet_visible_receipt_root",
    "fail_closed_receipt_root",
    "production_release_hold",
];

const DEFAULT_FAIL_CLOSED_REASONS: [&str; 9] = [
    "sealed_input_not_accepted",
    "encrypted_effect_not_committed",
    "contract_receipt_not_emitted",
    "fee_bound_not_checked",
    "pq_sequencer_auth_root_unbound",
    "metadata_redaction_not_checked",
    "exit_replayability_root_missing",
    "expected_runtime_roots_mismatch",
    "cargo_runtime_execution_deferred",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_envelope_suite: String,
    pub max_fee_atomic: u64,
    pub min_pq_security_bits: u16,
    pub min_wallet_replay_depth: u64,
    pub fail_closed: bool,
    pub cargo_execution_allowed: bool,
    pub runtime_execution_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_envelope_suite: RECEIPT_ENVELOPE_SUITE.to_string(),
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_wallet_replay_depth: DEFAULT_MIN_WALLET_REPLAY_DEPTH,
            fail_closed: true,
            cargo_execution_allowed: false,
            runtime_execution_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_envelope_suite": self.receipt_envelope_suite,
            "max_fee_atomic": self.max_fee_atomic,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_wallet_replay_depth": self.min_wallet_replay_depth,
            "fail_closed": self.fail_closed,
            "cargo_execution_allowed": self.cargo_execution_allowed,
            "runtime_execution_allowed": self.runtime_execution_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEnvelopeEvidence {
    pub label: String,
    pub sequence: u64,
    pub envelope_root: String,
    pub evidence_root: String,
    pub expected_root: String,
    pub public_surface: String,
    pub accepted: bool,
}

impl ReceiptEnvelopeEvidence {
    pub fn new(label: &str, sequence: u64, seed: &str) -> Self {
        let envelope_root = scoped_hash("envelope", label, seed);
        let evidence_root = scoped_hash("evidence", label, &envelope_root);
        Self {
            label: label.to_string(),
            sequence,
            envelope_root: envelope_root.clone(),
            evidence_root,
            expected_root: envelope_root,
            public_surface: "root_only_receipt_envelope".to_string(),
            accepted: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "sequence": self.sequence,
            "envelope_root": self.envelope_root,
            "evidence_root": self.evidence_root,
            "expected_root": self.expected_root,
            "public_surface": self.public_surface,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RECEIPT-ENVELOPE-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailClosedReceipt {
    pub reason: String,
    pub sequence: u64,
    pub receipt_root: String,
    pub enforced: bool,
}

impl FailClosedReceipt {
    pub fn new(reason: &str, sequence: u64) -> Self {
        Self {
            reason: reason.to_string(),
            sequence,
            receipt_root: scoped_hash("fail-closed-receipt", reason, "reject"),
            enforced: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reason": self.reason,
            "sequence": self.sequence,
            "receipt_root": self.receipt_root,
            "enforced": self.enforced,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("FAIL-CLOSED-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionReleaseHold {
    pub label: String,
    pub hold_root: String,
    pub cargo_execution_allowed: bool,
    pub runtime_execution_allowed: bool,
    pub release_allowed: bool,
    pub deferred_execution_receipt_root: String,
}

impl ProductionReleaseHold {
    pub fn devnet() -> Self {
        Self {
            label: DEFAULT_RELEASE_HOLD.to_string(),
            hold_root: scoped_hash("production-release-hold", DEFAULT_RELEASE_HOLD, "held"),
            cargo_execution_allowed: false,
            runtime_execution_allowed: false,
            release_allowed: false,
            deferred_execution_receipt_root: scoped_hash(
                "deferred-execution-receipt",
                DEFAULT_RELEASE_HOLD,
                "receipt-envelope",
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "hold_root": self.hold_root,
            "cargo_execution_allowed": self.cargo_execution_allowed,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "release_allowed": self.release_allowed,
            "deferred_execution_receipt_root": self.deferred_execution_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRODUCTION-RELEASE-HOLD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub sealed_input_accepted: ReceiptEnvelopeEvidence,
    pub encrypted_effect_committed: ReceiptEnvelopeEvidence,
    pub contract_receipt_emitted: ReceiptEnvelopeEvidence,
    pub fee_bound_checked: ReceiptEnvelopeEvidence,
    pub pq_sequencer_auth_root: ReceiptEnvelopeEvidence,
    pub metadata_redaction_checked: ReceiptEnvelopeEvidence,
    pub exit_replayability_root: ReceiptEnvelopeEvidence,
    pub expected_invocation_root: ReceiptEnvelopeEvidence,
    pub expected_preflight_root: ReceiptEnvelopeEvidence,
    pub operator_evidence_root: ReceiptEnvelopeEvidence,
    pub wallet_visible_receipt_root: ReceiptEnvelopeEvidence,
    pub fail_closed_receipt_root: ReceiptEnvelopeEvidence,
    pub fail_closed_receipts: Vec<FailClosedReceipt>,
    pub fail_closed_root: String,
    pub production_release_hold: ProductionReleaseHold,
    pub receipt_envelope_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let sealed_input_accepted =
            ReceiptEnvelopeEvidence::new("sealed_input_accepted", 0, "devnet-sealed-input");
        let encrypted_effect_committed = ReceiptEnvelopeEvidence::new(
            "encrypted_effect_committed",
            1,
            "devnet-encrypted-effect",
        );
        let contract_receipt_emitted =
            ReceiptEnvelopeEvidence::new("contract_receipt_emitted", 2, "devnet-receipt");
        let fee_bound_checked =
            ReceiptEnvelopeEvidence::new("fee_bound_checked", 3, "devnet-fee-bound");
        let pq_sequencer_auth_root =
            ReceiptEnvelopeEvidence::new("pq_sequencer_auth_root", 4, "devnet-pq-auth");
        let metadata_redaction_checked = ReceiptEnvelopeEvidence::new(
            "metadata_redaction_checked",
            5,
            "devnet-metadata-redaction",
        );
        let exit_replayability_root =
            ReceiptEnvelopeEvidence::new("exit_replayability_root", 6, "devnet-replay");
        let expected_invocation_root =
            ReceiptEnvelopeEvidence::new("expected_invocation_root", 7, "devnet-invocation");
        let expected_preflight_root =
            ReceiptEnvelopeEvidence::new("expected_preflight_root", 8, "devnet-preflight");
        let operator_evidence_root =
            ReceiptEnvelopeEvidence::new("operator_evidence_root", 9, "devnet-operator");
        let wallet_visible_receipt_root =
            ReceiptEnvelopeEvidence::new("wallet_visible_receipt_root", 10, "devnet-wallet");
        let fail_closed_receipt_root =
            ReceiptEnvelopeEvidence::new("fail_closed_receipt_root", 11, "devnet-fail-closed");
        let fail_closed_receipts = DEFAULT_FAIL_CLOSED_REASONS
            .iter()
            .enumerate()
            .map(|(index, reason)| FailClosedReceipt::new(reason, index as u64))
            .collect::<Vec<_>>();
        let fail_closed_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-EXECUTION-RECEIPT-FAIL-CLOSED",
            &fail_closed_receipts
                .iter()
                .map(FailClosedReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let production_release_hold = ProductionReleaseHold::devnet();
        let mut state = Self {
            config,
            sealed_input_accepted,
            encrypted_effect_committed,
            contract_receipt_emitted,
            fee_bound_checked,
            pq_sequencer_auth_root,
            metadata_redaction_checked,
            exit_replayability_root,
            expected_invocation_root,
            expected_preflight_root,
            operator_evidence_root,
            wallet_visible_receipt_root,
            fail_closed_receipt_root,
            fail_closed_receipts,
            fail_closed_root,
            production_release_hold,
            receipt_envelope_root: String::new(),
            state_root: String::new(),
        };
        state.receipt_envelope_root = state.compute_receipt_envelope_root();
        state.state_root = state.compute_state_root();
        state
    }

    pub fn evidence_by_label(&self) -> BTreeMap<String, String> {
        self.receipt_envelopes()
            .into_iter()
            .map(|record| (record.label.clone(), record.state_root()))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "sealed_input_accepted": self.sealed_input_accepted.public_record(),
            "encrypted_effect_committed": self.encrypted_effect_committed.public_record(),
            "contract_receipt_emitted": self.contract_receipt_emitted.public_record(),
            "fee_bound_checked": self.fee_bound_checked.public_record(),
            "pq_sequencer_auth_root": self.pq_sequencer_auth_root.public_record(),
            "metadata_redaction_checked": self.metadata_redaction_checked.public_record(),
            "exit_replayability_root": self.exit_replayability_root.public_record(),
            "expected_invocation_root": self.expected_invocation_root.public_record(),
            "expected_preflight_root": self.expected_preflight_root.public_record(),
            "operator_evidence_root": self.operator_evidence_root.public_record(),
            "wallet_visible_receipt_root": self.wallet_visible_receipt_root.public_record(),
            "fail_closed_receipt_root": self.fail_closed_receipt_root.public_record(),
            "evidence_by_label": self.evidence_by_label(),
            "fail_closed_receipts": self.fail_closed_receipts.iter().map(FailClosedReceipt::public_record).collect::<Vec<_>>(),
            "fail_closed_root": self.fail_closed_root,
            "production_release_hold": self.production_release_hold.public_record(),
            "receipt_envelope_root": self.receipt_envelope_root,
            "state_root": self.state_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !self.config.fail_closed {
            return Err("contract receipt gate execution receipt must be fail-closed".to_string());
        }
        if self.config.cargo_execution_allowed || self.config.runtime_execution_allowed {
            return Err("cargo and runtime execution must remain deferred".to_string());
        }
        if self.production_release_hold.cargo_execution_allowed
            || self.production_release_hold.runtime_execution_allowed
            || self.production_release_hold.release_allowed
        {
            return Err(
                "production release hold must block cargo, runtime, and release".to_string(),
            );
        }
        if self.config.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq sequencer auth security floor is too low".to_string());
        }
        if self.config.max_fee_atomic > DEFAULT_MAX_FEE_ATOMIC {
            return Err("fee bound exceeds execution receipt maximum".to_string());
        }
        if self.receipt_envelopes().len() + 1 != REQUIRED_ENVELOPES.len() {
            return Err("receipt envelope evidence set changed".to_string());
        }
        if self.fail_closed_receipts.len() != DEFAULT_FAIL_CLOSED_REASONS.len() {
            return Err("fail-closed receipt set changed".to_string());
        }
        if self
            .receipt_envelopes()
            .iter()
            .any(|record| !record.accepted || record.envelope_root != record.expected_root)
        {
            return Err("receipt envelope expected root mismatch".to_string());
        }
        if self.fail_closed_root != self.compute_fail_closed_root() {
            return Err("fail-closed receipt root mismatch".to_string());
        }
        if self.receipt_envelope_root != self.compute_receipt_envelope_root() {
            return Err("receipt envelope root mismatch".to_string());
        }
        if self.state_root != self.compute_state_root() {
            return Err("state root mismatch".to_string());
        }
        Ok(())
    }

    pub fn compute_fail_closed_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-EXECUTION-RECEIPT-FAIL-CLOSED",
            &self
                .fail_closed_receipts
                .iter()
                .map(FailClosedReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn compute_receipt_envelope_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-EXECUTION-RECEIPT-ENVELOPES",
            &self
                .receipt_envelopes()
                .iter()
                .map(ReceiptEnvelopeEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-EXECUTION-RECEIPT-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.compute_receipt_envelope_root()),
                HashPart::Str(&self.compute_fail_closed_root()),
                HashPart::Str(&self.production_release_hold.state_root()),
                HashPart::Str("execution-receipt-held"),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
    }

    fn receipt_envelopes(&self) -> Vec<&ReceiptEnvelopeEvidence> {
        vec![
            &self.sealed_input_accepted,
            &self.encrypted_effect_committed,
            &self.contract_receipt_emitted,
            &self.fee_bound_checked,
            &self.pq_sequencer_auth_root,
            &self.metadata_redaction_checked,
            &self.exit_replayability_root,
            &self.expected_invocation_root,
            &self.expected_preflight_root,
            &self.operator_evidence_root,
            &self.wallet_visible_receipt_root,
            &self.fail_closed_receipt_root,
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

fn scoped_hash(scope: &str, label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-EXECUTION-RECEIPT-DEVNET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(scope),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-EXECUTION-RECEIPT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
