use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateReceiptGateReceiptConformanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-receipt-conformance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFORMANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-private-receipt-gate-receipt-conformance-evidence-v1";
pub const DEFAULT_GATE_ID: &str = "devnet-private-receipt-gate-forced-exit-0001";
pub const DEFAULT_RECEIPT_ID: &str = "devnet-private-receipt-gate-conformance-0001";
pub const DEFAULT_FORCED_EXIT_ACTION_ID: &str =
    "devnet-forced-exit-action-private-note-transfer-0001";
pub const DEFAULT_MAX_FEE_PICONERO: u64 = 25_000_000;
pub const DEFAULT_OBSERVED_FEE_PICONERO: u64 = 21_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 192;
pub const DEFAULT_OBSERVED_PQ_SECURITY_BITS: u64 = 192;
pub const DEFAULT_METADATA_BUDGET_BYTES: u64 = 4_096;
pub const DEFAULT_OBSERVED_METADATA_BYTES: u64 = 3_072;
pub const DEFAULT_REQUIRED_RECEIPT_SHARDS: u64 = 3;
pub const DEFAULT_AVAILABLE_RECEIPT_SHARDS: u64 = 3;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-receipt-conformance-runtime";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub conformance_suite: String,
    pub gate_id: String,
    pub receipt_id: String,
    pub forced_exit_action_id: String,
    pub max_fee_piconero: u64,
    pub observed_fee_piconero: u64,
    pub min_pq_security_bits: u64,
    pub observed_pq_security_bits: u64,
    pub metadata_budget_bytes: u64,
    pub observed_metadata_bytes: u64,
    pub required_receipt_shards: u64,
    pub available_receipt_shards: u64,
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
            conformance_suite: CONFORMANCE_SUITE.to_string(),
            gate_id: DEFAULT_GATE_ID.to_string(),
            receipt_id: DEFAULT_RECEIPT_ID.to_string(),
            forced_exit_action_id: DEFAULT_FORCED_EXIT_ACTION_ID.to_string(),
            max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
            observed_fee_piconero: DEFAULT_OBSERVED_FEE_PICONERO,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_pq_security_bits: DEFAULT_OBSERVED_PQ_SECURITY_BITS,
            metadata_budget_bytes: DEFAULT_METADATA_BUDGET_BYTES,
            observed_metadata_bytes: DEFAULT_OBSERVED_METADATA_BYTES,
            required_receipt_shards: DEFAULT_REQUIRED_RECEIPT_SHARDS,
            available_receipt_shards: DEFAULT_AVAILABLE_RECEIPT_SHARDS,
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
            "conformance_suite": self.conformance_suite,
            "gate_id": self.gate_id,
            "receipt_id": self.receipt_id,
            "forced_exit_action_id": self.forced_exit_action_id,
            "max_fee_piconero": self.max_fee_piconero,
            "observed_fee_piconero": self.observed_fee_piconero,
            "min_pq_security_bits": self.min_pq_security_bits,
            "observed_pq_security_bits": self.observed_pq_security_bits,
            "metadata_budget_bytes": self.metadata_budget_bytes,
            "observed_metadata_bytes": self.observed_metadata_bytes,
            "required_receipt_shards": self.required_receipt_shards,
            "available_receipt_shards": self.available_receipt_shards,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceEvidence {
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub placeholder_observed_root: bool,
    pub conforms: bool,
    pub release_blocking: bool,
    pub evidence_root: String,
    pub public_metadata: Value,
}

impl ConformanceEvidence {
    pub fn deferred(lane: &str, expected_root: String, public_metadata: Value) -> Self {
        let observed_root = deferred_observed_root(lane);
        let conforms = observed_root == expected_root;
        let release_blocking = true;
        let evidence_root = domain_hash(
            &format!("{DOMAIN}:conformance-evidence"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(&expected_root),
                HashPart::Str(&observed_root),
                HashPart::Str(if conforms { "conforms" } else { "mismatch" }),
                HashPart::Str("deferred-observed-root"),
                HashPart::Str("release-blocking"),
                HashPart::Json(&public_metadata),
            ],
            32,
        );

        Self {
            lane: lane.to_string(),
            expected_root,
            observed_root,
            placeholder_observed_root: true,
            conforms,
            release_blocking,
            evidence_root,
            public_metadata,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "placeholder_observed_root": self.placeholder_observed_root,
            "conforms": self.conforms,
            "release_blocking": self.release_blocking,
            "evidence_root": self.evidence_root,
            "public_metadata": self.public_metadata,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub invocation: ConformanceEvidence,
    pub preflight: ConformanceEvidence,
    pub execution_receipt: ConformanceEvidence,
    pub nullifier_hygiene: ConformanceEvidence,
    pub output_commitments: ConformanceEvidence,
    pub encrypted_receipt_shards: ConformanceEvidence,
    pub fee_cap: ConformanceEvidence,
    pub pq_authorization: ConformanceEvidence,
    pub wallet_reconstruction: ConformanceEvidence,
    pub forced_exit_compatibility: ConformanceEvidence,
    pub metadata_budget: ConformanceEvidence,
    pub operator_evidence: ConformanceEvidence,
    pub wallet_visible_receipt: ConformanceEvidence,
    pub fail_closed_receipt: ConformanceEvidence,
    pub release_blockers: ConformanceEvidence,
    pub runtime_execution_deferred: bool,
    pub production_release_blocked: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let receipt_id = config.receipt_id.clone();
        let action_id = config.forced_exit_action_id.clone();

        Self {
            invocation: ConformanceEvidence::deferred(
                "invocation",
                expected_label_root("invocation", "private-receipt-gate-invocation-v1"),
                json!({"gate_id": config.gate_id, "phase": "invocation"}),
            ),
            preflight: ConformanceEvidence::deferred(
                "preflight",
                expected_label_root("preflight", "private-receipt-gate-preflight-v1"),
                json!({"gate_id": config.gate_id, "phase": "preflight"}),
            ),
            execution_receipt: ConformanceEvidence::deferred(
                "execution_receipt",
                expected_label_root(
                    "execution-receipt",
                    "private-receipt-gate-execution-receipt-v1",
                ),
                json!({"receipt_id": receipt_id, "execution_deferred": true}),
            ),
            nullifier_hygiene: ConformanceEvidence::deferred(
                "nullifier_hygiene",
                expected_record_root(
                    "nullifier-hygiene",
                    json!({
                        "forced_exit_action_id": action_id,
                        "duplicate_nullifiers": 0_u64,
                        "spent_nullifier_hits": 0_u64,
                    }),
                ),
                json!({"policy": "no-duplicate-or-spent-nullifier"}),
            ),
            output_commitments: ConformanceEvidence::deferred(
                "output_commitments",
                expected_record_root(
                    "output-commitments",
                    json!({
                        "forced_exit_action_id": action_id,
                        "commitment_count": 2_u64,
                        "recipient_metadata": "committed",
                    }),
                ),
                json!({"recipient_metadata_policy": "commitment-only"}),
            ),
            encrypted_receipt_shards: ConformanceEvidence::deferred(
                "encrypted_receipt_shards",
                expected_record_root(
                    "encrypted-receipt-shards",
                    json!({
                        "receipt_id": receipt_id,
                        "available_shards": config.available_receipt_shards,
                        "required_shards": config.required_receipt_shards,
                        "suite": "kyber768-xchacha20poly1305-receipt-shards",
                    }),
                ),
                json!({"threshold_met": config.available_receipt_shards >= config.required_receipt_shards}),
            ),
            fee_cap: ConformanceEvidence::deferred(
                "fee_cap",
                expected_record_root(
                    "fee-cap",
                    json!({
                        "observed_fee_piconero": config.observed_fee_piconero,
                        "max_fee_piconero": config.max_fee_piconero,
                        "within_cap": config.observed_fee_piconero <= config.max_fee_piconero,
                    }),
                ),
                json!({"asset": "piconero-devnet"}),
            ),
            pq_authorization: ConformanceEvidence::deferred(
                "pq_authorization",
                expected_record_root(
                    "pq-authorization",
                    json!({
                        "observed_security_bits": config.observed_pq_security_bits,
                        "min_security_bits": config.min_pq_security_bits,
                        "threshold_met": config.observed_pq_security_bits >= config.min_pq_security_bits,
                        "signature_suite": "dilithium3-devnet",
                    }),
                ),
                json!({"authorization_domain": "forced-exit-private-receipt"}),
            ),
            wallet_reconstruction: ConformanceEvidence::deferred(
                "wallet_reconstruction",
                expected_record_root(
                    "wallet-reconstruction",
                    json!({
                        "receipt_id": receipt_id,
                        "required_shards": config.required_receipt_shards,
                        "status": "deterministic",
                    }),
                ),
                json!({"wallet_visibility": "reconstructable-from-private-shards"}),
            ),
            forced_exit_compatibility: ConformanceEvidence::deferred(
                "forced_exit_compatibility",
                expected_record_root(
                    "forced-exit-compatibility",
                    json!({
                        "forced_exit_action_id": action_id,
                        "exit_mode": "forced_exit",
                        "bridge_exit_spine": "compatible",
                    }),
                ),
                json!({"canonical_vertical_slice": "private_receipt_gate"}),
            ),
            metadata_budget: ConformanceEvidence::deferred(
                "metadata_budget",
                expected_record_root(
                    "metadata-budget",
                    json!({
                        "observed_metadata_bytes": config.observed_metadata_bytes,
                        "metadata_budget_bytes": config.metadata_budget_bytes,
                        "within_budget": config.observed_metadata_bytes <= config.metadata_budget_bytes,
                    }),
                ),
                json!({"public_metadata_policy": "bounded-commitments-only"}),
            ),
            operator_evidence: ConformanceEvidence::deferred(
                "operator_evidence",
                expected_record_root(
                    "operator-evidence",
                    json!({
                        "forced_exit_action_id": action_id,
                        "receipt_id": receipt_id,
                        "operator_lane": "forced_exit_private_receipt_gate",
                    }),
                ),
                json!({"operator_evidence": "required-before-release"}),
            ),
            wallet_visible_receipt: ConformanceEvidence::deferred(
                "wallet_visible_receipt",
                expected_record_root(
                    "wallet-visible-receipt",
                    json!({
                        "receipt_id": receipt_id,
                        "recipient_leakage": "none",
                        "wallet_reconstruction": "available-after-runtime",
                    }),
                ),
                json!({"visibility": "wallet-visible-private-receipt"}),
            ),
            fail_closed_receipt: ConformanceEvidence::deferred(
                "fail_closed_receipt",
                expected_record_root(
                    "fail-closed-receipt",
                    json!({
                        "runtime_execution_allowed": config.runtime_execution_allowed,
                        "production_release_allowed": config.production_release_allowed,
                        "policy": "fail-closed-while-runtime-execution-deferred",
                    }),
                ),
                json!({"fail_closed": true, "reason": "runtime-execution-deferred"}),
            ),
            release_blockers: ConformanceEvidence::deferred(
                "release_blockers",
                expected_release_blocker_root(&config),
                json!({"production_release_blocked": true, "runtime_execution_deferred": true}),
            ),
            config,
            runtime_execution_deferred: true,
            production_release_blocked: true,
        }
    }

    pub fn evidence(&self) -> Vec<&ConformanceEvidence> {
        vec![
            &self.invocation,
            &self.preflight,
            &self.execution_receipt,
            &self.nullifier_hygiene,
            &self.output_commitments,
            &self.encrypted_receipt_shards,
            &self.fee_cap,
            &self.pq_authorization,
            &self.wallet_reconstruction,
            &self.forced_exit_compatibility,
            &self.metadata_budget,
            &self.operator_evidence,
            &self.wallet_visible_receipt,
            &self.fail_closed_receipt,
            &self.release_blockers,
        ]
    }

    pub fn conformance_root(&self) -> String {
        let records = self
            .evidence()
            .into_iter()
            .map(ConformanceEvidence::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:conformance-root"), &records)
    }

    pub fn release_blocker_root(&self) -> String {
        let records = self
            .evidence()
            .into_iter()
            .filter(|evidence| evidence.release_blocking || !evidence.conforms)
            .map(ConformanceEvidence::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:release-blocker-root"), &records)
    }

    pub fn all_receipt_conformance_passed(&self) -> bool {
        self.evidence()
            .into_iter()
            .all(|evidence| evidence.conforms && !evidence.release_blocking)
    }

    pub fn receipt_conformance_result(&self) -> Result<()> {
        if self.all_receipt_conformance_passed() {
            Ok(())
        } else {
            Err("private_receipt_gate_receipt_conformance_release_blocked".to_string())
        }
    }

    pub fn public_record(&self) -> Value {
        let evidence = self
            .evidence()
            .into_iter()
            .map(ConformanceEvidence::public_record)
            .collect::<Vec<_>>();

        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "production_release_blocked": self.production_release_blocked,
            "all_receipt_conformance_passed": self.all_receipt_conformance_passed(),
            "conformance_root": self.conformance_root(),
            "release_blocker_root": self.release_blocker_root(),
            "evidence": evidence,
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

fn expected_label_root(lane: &str, label: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-label-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CONFORMANCE_SUITE),
            HashPart::Str(lane),
            HashPart::Str(label),
        ],
        32,
    )
}

fn expected_record_root(lane: &str, record: Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-record-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CONFORMANCE_SUITE),
            HashPart::Str(lane),
            HashPart::Json(&record),
        ],
        32,
    )
}

fn deferred_observed_root(lane: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:deferred-observed-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CONFORMANCE_SUITE),
            HashPart::Str(lane),
            HashPart::Str("runtime-execution-deferred"),
            HashPart::Str("placeholder-observed-root"),
        ],
        32,
    )
}

fn expected_release_blocker_root(config: &Config) -> String {
    let records = [
        json!({
            "blocker": "runtime_execution_deferred",
            "active": !config.runtime_execution_allowed,
        }),
        json!({
            "blocker": "production_release_disabled",
            "active": !config.production_release_allowed,
        }),
        json!({
            "blocker": "observed_roots_are_placeholders",
            "active": true,
        }),
    ];
    merkle_root(&format!("{DOMAIN}:expected-release-blockers"), &records)
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
