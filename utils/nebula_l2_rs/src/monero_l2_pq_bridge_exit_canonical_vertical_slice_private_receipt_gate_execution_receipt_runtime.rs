use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateReceiptGateExecutionReceiptRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-execution-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_ENVELOPE_SUITE: &str =
    "monero-l2-pq-bridge-exit-private-receipt-gate-execution-receipt-envelope-v1";
pub const DEFAULT_GATE_ID: &str = "devnet-private-receipt-gate-forced-exit-0001";
pub const DEFAULT_RECEIPT_ID: &str = "devnet-private-receipt-gate-execution-receipt-envelope-0001";
pub const DEFAULT_FORCED_EXIT_ACTION_ID: &str =
    "devnet-forced-exit-action-private-note-transfer-0001";
pub const DEFAULT_EXPECTED_PREFLIGHT_LABEL: &str =
    "canonical-vertical-slice-private-receipt-gate-runtime-preflight-v1";
pub const DEFAULT_EXPECTED_INVOCATION_LABEL: &str =
    "canonical-vertical-slice-private-receipt-gate-runtime-invocation-v1";
pub const DEFAULT_MAX_FEE_PICONERO: u64 = 25_000_000;
pub const DEFAULT_OBSERVED_FEE_PICONERO: u64 = 21_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 192;
pub const DEFAULT_OBSERVED_PQ_SECURITY_BITS: u64 = 192;
pub const DEFAULT_METADATA_BUDGET_BYTES: u64 = 4_096;
pub const DEFAULT_OBSERVED_METADATA_BYTES: u64 = 3_072;
pub const DEFAULT_REQUIRED_RECEIPT_SHARDS: u64 = 3;
pub const DEFAULT_AVAILABLE_RECEIPT_SHARDS: u64 = 3;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-execution-receipt-runtime";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_envelope_suite: String,
    pub gate_id: String,
    pub max_fee_piconero: u64,
    pub min_pq_security_bits: u64,
    pub metadata_budget_bytes: u64,
    pub required_receipt_shards: u64,
    pub expected_preflight_root: String,
    pub expected_invocation_root: String,
    pub runtime_execution_allowed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_envelope_suite: RECEIPT_ENVELOPE_SUITE.to_string(),
            gate_id: DEFAULT_GATE_ID.to_string(),
            max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            metadata_budget_bytes: DEFAULT_METADATA_BUDGET_BYTES,
            required_receipt_shards: DEFAULT_REQUIRED_RECEIPT_SHARDS,
            expected_preflight_root: label_root(
                "expected-preflight",
                DEFAULT_EXPECTED_PREFLIGHT_LABEL,
            ),
            expected_invocation_root: label_root(
                "expected-invocation",
                DEFAULT_EXPECTED_INVOCATION_LABEL,
            ),
            runtime_execution_allowed: false,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_envelope_suite": self.receipt_envelope_suite,
            "gate_id": self.gate_id,
            "max_fee_piconero": self.max_fee_piconero,
            "min_pq_security_bits": self.min_pq_security_bits,
            "metadata_budget_bytes": self.metadata_budget_bytes,
            "required_receipt_shards": self.required_receipt_shards,
            "expected_preflight_root": self.expected_preflight_root,
            "expected_invocation_root": self.expected_invocation_root,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEnvelope {
    pub lane: String,
    pub accepted: bool,
    pub evidence_root: String,
    pub observed_root: String,
    pub expected_root: String,
    pub envelope_root: String,
    pub public_metadata: Value,
}

impl ReceiptEnvelope {
    pub fn new(
        lane: &str,
        accepted: bool,
        observed_root: String,
        expected_root: String,
        public_metadata: Value,
    ) -> Self {
        let evidence_root = domain_hash(
            &format!("{DOMAIN}:evidence-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(&observed_root),
                HashPart::Str(&expected_root),
                HashPart::Str(if accepted { "accepted" } else { "rejected" }),
                HashPart::Json(&public_metadata),
            ],
            32,
        );
        let envelope_root = domain_hash(
            &format!("{DOMAIN}:receipt-envelope"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(RECEIPT_ENVELOPE_SUITE),
                HashPart::Str(lane),
                HashPart::Str(&evidence_root),
            ],
            32,
        );

        Self {
            lane: lane.to_string(),
            accepted,
            evidence_root,
            observed_root,
            expected_root,
            envelope_root,
            public_metadata,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "accepted": self.accepted,
            "evidence_root": self.evidence_root,
            "observed_root": self.observed_root,
            "expected_root": self.expected_root,
            "envelope_root": self.envelope_root,
            "public_metadata": self.public_metadata,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-envelope", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub receipt_id: String,
    pub forced_exit_action_id: String,
    pub nullifier_accepted: ReceiptEnvelope,
    pub output_commitments: ReceiptEnvelope,
    pub encrypted_receipt_shards: ReceiptEnvelope,
    pub fee_cap_checked: ReceiptEnvelope,
    pub pq_authorization: ReceiptEnvelope,
    pub wallet_reconstruction_root: ReceiptEnvelope,
    pub forced_exit_compatibility_root: ReceiptEnvelope,
    pub metadata_budget_checked: ReceiptEnvelope,
    pub expected_invocation_root: ReceiptEnvelope,
    pub expected_preflight_root: ReceiptEnvelope,
    pub operator_evidence_root: ReceiptEnvelope,
    pub wallet_visible_receipt_root: ReceiptEnvelope,
    pub fail_closed_receipt_root: ReceiptEnvelope,
    pub production_release_hold: ReceiptEnvelope,
    pub execution_deferred: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let receipt_id = DEFAULT_RECEIPT_ID.to_string();
        let forced_exit_action_id = DEFAULT_FORCED_EXIT_ACTION_ID.to_string();
        let nullifier_root = leaf_root("nullifier", &forced_exit_action_id);
        let output_root = leaf_root("output-commitments", &forced_exit_action_id);
        let shard_root = leaf_root("encrypted-receipt-shards", &receipt_id);
        let wallet_root = leaf_root("wallet-reconstruction", &receipt_id);
        let forced_exit_root = leaf_root("forced-exit-compatibility", &forced_exit_action_id);
        let fee_root = threshold_root(
            "fee-cap",
            DEFAULT_OBSERVED_FEE_PICONERO,
            config.max_fee_piconero,
        );
        let pq_root = threshold_root(
            "pq-authorization",
            DEFAULT_OBSERVED_PQ_SECURITY_BITS,
            config.min_pq_security_bits,
        );
        let metadata_root = threshold_root(
            "metadata-budget",
            DEFAULT_OBSERVED_METADATA_BYTES,
            config.metadata_budget_bytes,
        );
        let operator_root = merkle_root(
            &format!("{DOMAIN}:operator-evidence"),
            &[json!({
                "forced_exit_action_id": forced_exit_action_id,
                "receipt_id": receipt_id,
                "nullifier_root": nullifier_root,
                "output_commitment_root": output_root,
                "encrypted_receipt_shard_root": shard_root,
            })],
        );
        let wallet_visible_root = merkle_root(
            &format!("{DOMAIN}:wallet-visible-receipt"),
            &[json!({
                "receipt_id": receipt_id,
                "wallet_reconstruction_root": wallet_root,
                "forced_exit_compatibility_root": forced_exit_root,
                "metadata_leak_policy": "bounded-commitments-only",
            })],
        );
        let fail_closed_root = merkle_root(
            &format!("{DOMAIN}:fail-closed-receipt"),
            &[json!({
                "execution_deferred": true,
                "runtime_execution_allowed": config.runtime_execution_allowed,
                "production_release_allowed": config.production_release_allowed,
                "reason": "runtime_execution_not_allowed_for_private_receipt_gate",
            })],
        );

        Self {
            nullifier_accepted: ReceiptEnvelope::new(
                "nullifier_accepted",
                true,
                nullifier_root.clone(),
                nullifier_root,
                json!({"duplicate_hits": 0, "spent_hits": 0}),
            ),
            output_commitments: ReceiptEnvelope::new(
                "output_commitments",
                true,
                output_root.clone(),
                output_root,
                json!({"commitment_count": 2, "recipient_metadata": "committed"}),
            ),
            encrypted_receipt_shards: ReceiptEnvelope::new(
                "encrypted_receipt_shards",
                DEFAULT_AVAILABLE_RECEIPT_SHARDS >= config.required_receipt_shards,
                shard_root.clone(),
                shard_root,
                json!({
                    "available_shards": DEFAULT_AVAILABLE_RECEIPT_SHARDS,
                    "required_shards": config.required_receipt_shards,
                    "encryption_suite": "kyber768-xchacha20poly1305-receipt-shards",
                }),
            ),
            fee_cap_checked: ReceiptEnvelope::new(
                "fee_cap_checked",
                DEFAULT_OBSERVED_FEE_PICONERO <= config.max_fee_piconero,
                fee_root.clone(),
                fee_root,
                json!({
                    "observed_fee_piconero": DEFAULT_OBSERVED_FEE_PICONERO,
                    "max_fee_piconero": config.max_fee_piconero,
                }),
            ),
            pq_authorization: ReceiptEnvelope::new(
                "pq_authorization",
                DEFAULT_OBSERVED_PQ_SECURITY_BITS >= config.min_pq_security_bits,
                pq_root.clone(),
                pq_root,
                json!({
                    "observed_security_bits": DEFAULT_OBSERVED_PQ_SECURITY_BITS,
                    "min_security_bits": config.min_pq_security_bits,
                    "signature_suite": "dilithium3-devnet",
                }),
            ),
            wallet_reconstruction_root: ReceiptEnvelope::new(
                "wallet_reconstruction_root",
                true,
                wallet_root.clone(),
                wallet_root,
                json!({"required_shards": 3, "status": "deterministic"}),
            ),
            forced_exit_compatibility_root: ReceiptEnvelope::new(
                "forced_exit_compatibility_root",
                true,
                forced_exit_root.clone(),
                forced_exit_root,
                json!({"exit_mode": "forced_exit", "bridge_exit_spine": "compatible"}),
            ),
            metadata_budget_checked: ReceiptEnvelope::new(
                "metadata_budget_checked",
                DEFAULT_OBSERVED_METADATA_BYTES <= config.metadata_budget_bytes,
                metadata_root.clone(),
                metadata_root,
                json!({
                    "observed_metadata_bytes": DEFAULT_OBSERVED_METADATA_BYTES,
                    "metadata_budget_bytes": config.metadata_budget_bytes,
                }),
            ),
            expected_invocation_root: ReceiptEnvelope::new(
                "expected_invocation_root",
                true,
                config.expected_invocation_root.clone(),
                config.expected_invocation_root.clone(),
                json!({"gate": "private_receipt", "phase": "invocation"}),
            ),
            expected_preflight_root: ReceiptEnvelope::new(
                "expected_preflight_root",
                true,
                config.expected_preflight_root.clone(),
                config.expected_preflight_root.clone(),
                json!({"gate": "private_receipt", "phase": "preflight"}),
            ),
            operator_evidence_root: ReceiptEnvelope::new(
                "operator_evidence_root",
                true,
                operator_root.clone(),
                operator_root,
                json!({"operator_lane": "forced_exit_private_receipt_gate"}),
            ),
            wallet_visible_receipt_root: ReceiptEnvelope::new(
                "wallet_visible_receipt_root",
                true,
                wallet_visible_root.clone(),
                wallet_visible_root,
                json!({"wallet_visibility": "reconstructable_without_public_recipient_leak"}),
            ),
            fail_closed_receipt_root: ReceiptEnvelope::new(
                "fail_closed_receipt_root",
                true,
                fail_closed_root.clone(),
                fail_closed_root,
                json!({"policy": "fail_closed_while_execution_deferred"}),
            ),
            production_release_hold: ReceiptEnvelope::new(
                "production_release_hold",
                !config.production_release_allowed && !config.runtime_execution_allowed,
                label_root("production-release-hold", "execution-deferred"),
                label_root("production-release-hold", "execution-deferred"),
                json!({"release_hold": true, "cargo_runtime_execution": "deferred"}),
            ),
            config,
            receipt_id,
            forced_exit_action_id,
            execution_deferred: true,
        }
    }

    pub fn envelopes(&self) -> Vec<&ReceiptEnvelope> {
        vec![
            &self.nullifier_accepted,
            &self.output_commitments,
            &self.encrypted_receipt_shards,
            &self.fee_cap_checked,
            &self.pq_authorization,
            &self.wallet_reconstruction_root,
            &self.forced_exit_compatibility_root,
            &self.metadata_budget_checked,
            &self.expected_invocation_root,
            &self.expected_preflight_root,
            &self.operator_evidence_root,
            &self.wallet_visible_receipt_root,
            &self.fail_closed_receipt_root,
            &self.production_release_hold,
        ]
    }

    pub fn all_receipt_evidence_accepted(&self) -> bool {
        self.envelopes()
            .into_iter()
            .all(|envelope| envelope.accepted)
    }

    pub fn envelope_root(&self) -> String {
        let records = self
            .envelopes()
            .into_iter()
            .map(ReceiptEnvelope::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:envelopes"), &records)
    }

    pub fn public_record(&self) -> Value {
        let envelopes = self
            .envelopes()
            .into_iter()
            .map(ReceiptEnvelope::public_record)
            .collect::<Vec<_>>();

        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "receipt_id": self.receipt_id,
            "forced_exit_action_id": self.forced_exit_action_id,
            "execution_deferred": self.execution_deferred,
            "all_receipt_evidence_accepted": self.all_receipt_evidence_accepted(),
            "envelope_root": self.envelope_root(),
            "envelopes": envelopes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
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

fn label_root(label: &str, value: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:label-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn leaf_root(label: &str, subject_id: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:leaf-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject_id),
        ],
        32,
    )
}

fn threshold_root(label: &str, observed: u64, expected: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:threshold-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(observed as i128),
            HashPart::Int(expected as i128),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
