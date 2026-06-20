use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceContractReceiptGateInvocationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-contract-receipt-gate-invocation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_CONTRACT_RECEIPT_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_GATE_SUITE: &str =
    "minimal-private-contract-action-receipt-gate-invocation-roots-only-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_FEE_ATOMIC: u128 = 18_000_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_FAIL_CLOSED_ROOTS: [&str; 5] = [
    "missing_call_commitment_root",
    "missing_sealed_input_root",
    "missing_receipt_root",
    "pq_auth_not_bound",
    "expected_output_mismatch",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_gate_suite: String,
    pub min_pq_security_bits: u16,
    pub max_fee_atomic: u128,
    pub min_privacy_set_size: u64,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_gate_suite: RECEIPT_GATE_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_gate_suite": self.receipt_gate_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_atomic": self.max_fee_atomic,
            "min_privacy_set_size": self.min_privacy_set_size,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvocationRecord {
    pub label: String,
    pub sequence: u64,
    pub root: String,
    pub required: bool,
    pub public_surface: String,
}

impl InvocationRecord {
    pub fn new(label: &str, sequence: u64, seed: &str) -> Self {
        Self {
            label: label.to_string(),
            sequence,
            root: scoped_hash(label, seed),
            required: true,
            public_surface: "root_only".to_string(),
        }
    }

    pub fn fail_closed(label: &str, sequence: u64) -> Self {
        Self {
            label: label.to_string(),
            sequence,
            root: scoped_hash("fail-closed", label),
            required: true,
            public_surface: "reject_on_absence_or_mismatch".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "sequence": self.sequence,
            "root": self.root,
            "required": self.required,
            "public_surface": self.public_surface,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("INVOCATION-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateInvocation {
    pub invocation_id: String,
    pub call_commitment_root: String,
    pub sealed_input_root: String,
    pub encrypted_effect_root: String,
    pub receipt_root: String,
    pub fee_bound_root: String,
    pub pq_sequencer_auth_root: String,
    pub metadata_redaction_root: String,
    pub exit_replayability_root: String,
    pub expected_output_root: String,
    pub fail_closed_root: String,
    pub accepted: bool,
}

impl GateInvocation {
    pub fn public_record(&self) -> Value {
        json!({
            "invocation_id": self.invocation_id,
            "call_commitment_root": self.call_commitment_root,
            "sealed_input_root": self.sealed_input_root,
            "encrypted_effect_root": self.encrypted_effect_root,
            "receipt_root": self.receipt_root,
            "fee_bound_root": self.fee_bound_root,
            "pq_sequencer_auth_root": self.pq_sequencer_auth_root,
            "metadata_redaction_root": self.metadata_redaction_root,
            "exit_replayability_root": self.exit_replayability_root,
            "expected_output_root": self.expected_output_root,
            "fail_closed_root": self.fail_closed_root,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("GATE-INVOCATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub call_commitment_record: InvocationRecord,
    pub sealed_input_record: InvocationRecord,
    pub encrypted_effect_record: InvocationRecord,
    pub receipt_record: InvocationRecord,
    pub fee_bound_record: InvocationRecord,
    pub pq_sequencer_auth_record: InvocationRecord,
    pub metadata_redaction_record: InvocationRecord,
    pub exit_replayability_record: InvocationRecord,
    pub expected_output_record: InvocationRecord,
    pub fail_closed_records: Vec<InvocationRecord>,
    pub fail_closed_root: String,
    pub gate_invocation: GateInvocation,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let call_commitment_record =
            InvocationRecord::new("call_commitment_root", 0, "devnet-private-contract-call");
        let sealed_input_record =
            InvocationRecord::new("sealed_input_root", 1, "devnet-sealed-input-envelope");
        let encrypted_effect_record =
            InvocationRecord::new("encrypted_effect_root", 2, "devnet-encrypted-effects");
        let receipt_record = InvocationRecord::new("receipt_root", 3, "devnet-contract-receipt");
        let fee_bound_record = InvocationRecord::new("fee_bound_root", 4, "devnet-fee-bound");
        let pq_sequencer_auth_record =
            InvocationRecord::new("pq_sequencer_auth_root", 5, "devnet-pq-sequencer-auth");
        let metadata_redaction_record =
            InvocationRecord::new("metadata_redaction_root", 6, "devnet-metadata-redaction");
        let exit_replayability_record =
            InvocationRecord::new("exit_replayability_root", 7, "devnet-exit-replayability");
        let expected_output_record =
            InvocationRecord::new("expected_output_root", 8, "devnet-expected-output");
        let fail_closed_records = DEFAULT_FAIL_CLOSED_ROOTS
            .iter()
            .enumerate()
            .map(|(index, label)| InvocationRecord::fail_closed(label, index as u64))
            .collect::<Vec<_>>();
        let fail_closed_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-FAIL-CLOSED-ROOTS",
            &fail_closed_records
                .iter()
                .map(InvocationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let gate_invocation = GateInvocation {
            invocation_id: scoped_hash("invocation-id", "devnet-minimal-private-contract-action"),
            call_commitment_root: call_commitment_record.state_root(),
            sealed_input_root: sealed_input_record.state_root(),
            encrypted_effect_root: encrypted_effect_record.state_root(),
            receipt_root: receipt_record.state_root(),
            fee_bound_root: fee_bound_record.state_root(),
            pq_sequencer_auth_root: pq_sequencer_auth_record.state_root(),
            metadata_redaction_root: metadata_redaction_record.state_root(),
            exit_replayability_root: exit_replayability_record.state_root(),
            expected_output_root: expected_output_record.state_root(),
            fail_closed_root: fail_closed_root.clone(),
            accepted: true,
        };
        let mut state = Self {
            config,
            call_commitment_record,
            sealed_input_record,
            encrypted_effect_record,
            receipt_record,
            fee_bound_record,
            pq_sequencer_auth_record,
            metadata_redaction_record,
            exit_replayability_record,
            expected_output_record,
            fail_closed_records,
            fail_closed_root,
            gate_invocation,
            state_root: String::new(),
        };
        state.state_root = state.compute_state_root();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "call_commitment_root": self.gate_invocation.call_commitment_root,
            "sealed_input_root": self.gate_invocation.sealed_input_root,
            "encrypted_effect_root": self.gate_invocation.encrypted_effect_root,
            "receipt_root": self.gate_invocation.receipt_root,
            "fee_bound_root": self.gate_invocation.fee_bound_root,
            "pq_sequencer_auth_root": self.gate_invocation.pq_sequencer_auth_root,
            "metadata_redaction_root": self.gate_invocation.metadata_redaction_root,
            "exit_replayability_root": self.gate_invocation.exit_replayability_root,
            "expected_output_root": self.gate_invocation.expected_output_root,
            "fail_closed_root": self.fail_closed_root,
            "gate_invocation": self.gate_invocation.public_record(),
            "state_root": self.state_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if !self.config.fail_closed {
            return Err("receipt gate invocation must be fail-closed".to_string());
        }
        if !self.gate_invocation.accepted {
            return Err("receipt gate invocation is not accepted".to_string());
        }
        if self.config.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("receipt gate invocation pq security floor is too low".to_string());
        }
        if self.fail_closed_records.len() != DEFAULT_FAIL_CLOSED_ROOTS.len() {
            return Err("receipt gate invocation fail-closed root set changed".to_string());
        }
        if self.state_root != self.compute_state_root() {
            return Err("receipt gate invocation state root mismatch".to_string());
        }
        Ok(())
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-INVOCATION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.gate_invocation.state_root()),
                HashPart::Str(&self.fail_closed_root),
                HashPart::Str(if self.gate_invocation.accepted {
                    "accepted"
                } else {
                    "rejected"
                }),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
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
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-INVOCATION-DEVNET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-RECEIPT-GATE-INVOCATION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
