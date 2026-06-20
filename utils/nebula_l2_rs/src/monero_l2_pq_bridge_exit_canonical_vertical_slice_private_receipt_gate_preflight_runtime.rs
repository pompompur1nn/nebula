use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateReceiptGatePreflightRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-preflight-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const PREFLIGHT_SUITE: &str = "monero-l2-pq-bridge-exit-private-receipt-gate-preflight-evidence-v1";
const DEFAULT_GATE_ID: &str = "devnet-private-receipt-gate-forced-exit-0001";
const DEFAULT_EXPECTED_INVOCATION: &str =
    "canonical-vertical-slice-private-receipt-gate-runtime-invocation-v1";
const DEFAULT_MAX_FEE_PICONERO: u64 = 25_000_000;
const DEFAULT_REQUESTED_FEE_PICONERO: u64 = 21_000_000;
const DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 192;
const DEFAULT_METADATA_BYTES: u64 = 3_072;
const DEFAULT_METADATA_BUDGET_BYTES: u64 = 4_096;
const DEFAULT_MIN_RECEIPT_SHARDS: u64 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub preflight_suite: String,
    pub gate_id: String,
    pub expected_invocation_root: String,
    pub max_fee_piconero: u64,
    pub min_pq_security_bits: u64,
    pub metadata_budget_bytes: u64,
    pub min_receipt_shards: u64,
    pub release_hold_required: bool,
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
            gate_id: DEFAULT_GATE_ID.to_string(),
            expected_invocation_root: label_root(
                "expected-invocation",
                DEFAULT_EXPECTED_INVOCATION,
            ),
            max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            metadata_budget_bytes: DEFAULT_METADATA_BUDGET_BYTES,
            min_receipt_shards: DEFAULT_MIN_RECEIPT_SHARDS,
            release_hold_required: true,
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
            "gate_id": self.gate_id,
            "expected_invocation_root": self.expected_invocation_root,
            "max_fee_piconero": self.max_fee_piconero,
            "min_pq_security_bits": self.min_pq_security_bits,
            "metadata_budget_bytes": self.metadata_budget_bytes,
            "min_receipt_shards": self.min_receipt_shards,
            "release_hold_required": self.release_hold_required,
            "runtime_execution_allowed": self.runtime_execution_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateCheck {
    pub name: String,
    pub passed: bool,
    pub evidence_root: String,
    pub detail: BTreeMap<String, String>,
}

impl GateCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "name": self.name,
            "passed": self.passed,
            "evidence_root": self.evidence_root,
            "detail": self.detail,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("gate-check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub nullifier_hygiene: GateCheck,
    pub output_commitments: GateCheck,
    pub encrypted_receipt_shards: GateCheck,
    pub fee_cap: GateCheck,
    pub pq_authorization: GateCheck,
    pub wallet_reconstruction: GateCheck,
    pub forced_exit_compatibility: GateCheck,
    pub metadata_budgets: GateCheck,
    pub expected_invocation: GateCheck,
    pub fail_closed_reasons: Vec<String>,
    pub release_hold: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let expected_invocation_root = config.expected_invocation_root.clone();
        let fee_cap = config.max_fee_piconero;
        let min_pq_security_bits = config.min_pq_security_bits;
        let metadata_budget_bytes = config.metadata_budget_bytes;
        let min_receipt_shards = config.min_receipt_shards;

        Self {
            config,
            nullifier_hygiene: gate_check(
                "nullifier_hygiene",
                true,
                [
                    ("duplicate_nullifiers", "0"),
                    ("spent_nullifier_hits", "0"),
                    ("domain", "forced-exit-private-receipt"),
                ],
            ),
            output_commitments: gate_check(
                "output_commitments",
                true,
                [
                    ("commitment_count", "2"),
                    ("range_proof_root", "devnet-range-proof-root-present"),
                    (
                        "recipient_commitment_root",
                        "devnet-recipient-commitment-root-present",
                    ),
                ],
            ),
            encrypted_receipt_shards: gate_check(
                "encrypted_receipt_shards",
                true,
                [
                    ("available_shards", "3"),
                    ("min_required_shards", &min_receipt_shards.to_string()),
                    (
                        "encryption_suite",
                        "kyber768-xchacha20poly1305-receipt-shards",
                    ),
                ],
            ),
            fee_cap: gate_check(
                "fee_cap",
                DEFAULT_REQUESTED_FEE_PICONERO <= fee_cap,
                [
                    (
                        "requested_fee_piconero",
                        &DEFAULT_REQUESTED_FEE_PICONERO.to_string(),
                    ),
                    ("max_fee_piconero", &fee_cap.to_string()),
                    ("fee_asset", "piconero-devnet"),
                ],
            ),
            pq_authorization: gate_check(
                "pq_authorization",
                min_pq_security_bits <= 192,
                [
                    ("signature_suite", "dilithium3-devnet"),
                    ("attested_security_bits", "192"),
                    (
                        "min_required_security_bits",
                        &min_pq_security_bits.to_string(),
                    ),
                ],
            ),
            wallet_reconstruction: gate_check(
                "wallet_reconstruction",
                true,
                [
                    ("view_key_hint_root", "devnet-view-key-hint-root-present"),
                    (
                        "subaddress_index_root",
                        "devnet-subaddress-index-root-present",
                    ),
                    ("reconstruction_status", "deterministic"),
                ],
            ),
            forced_exit_compatibility: gate_check(
                "forced_exit_compatibility",
                true,
                [
                    ("exit_mode", "forced_exit"),
                    ("canonical_vertical_slice", "private_receipt_gate"),
                    ("bridge_exit_spine", "compatible"),
                ],
            ),
            metadata_budgets: gate_check(
                "metadata_budgets",
                DEFAULT_METADATA_BYTES <= metadata_budget_bytes,
                [
                    ("metadata_bytes", &DEFAULT_METADATA_BYTES.to_string()),
                    ("metadata_budget_bytes", &metadata_budget_bytes.to_string()),
                    ("public_record_policy", "bounded"),
                ],
            ),
            expected_invocation: gate_check(
                "expected_invocation_root",
                true,
                [
                    ("expected_invocation_root", &expected_invocation_root),
                    ("cargo_runtime_execution", "blocked-until-preflight-release"),
                    ("runtime_gate", "private_receipt_gate"),
                ],
            ),
            fail_closed_reasons: vec![
                "runtime_execution_not_allowed_before_private_receipt_gate_release".to_string(),
                "release_hold_required_for_canonical_vertical_slice_preflight".to_string(),
            ],
            release_hold: true,
        }
    }

    pub fn public_record(&self) -> Value {
        let checks = self
            .checks()
            .into_iter()
            .map(GateCheck::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "checks": checks,
            "all_preflight_evidence_passed": self.all_preflight_evidence_passed(),
            "runtime_execution_allowed": self.runtime_execution_allowed(),
            "fail_closed_reasons": self.fail_closed_reasons,
            "release_hold": self.release_hold,
            "check_root": self.check_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let record = self.public_record();
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-PRIVATE-RECEIPT-GATE-PREFLIGHT-RUNTIME-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Json(&record),
            ],
            32,
        )
    }

    pub fn check_root(&self) -> String {
        let leaves = self
            .checks()
            .into_iter()
            .map(GateCheck::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-PRIVATE-RECEIPT-GATE-PREFLIGHT-RUNTIME-CHECKS",
            &leaves,
        )
    }

    pub fn runtime_execution_allowed(&self) -> bool {
        self.config.runtime_execution_allowed
            && self.all_preflight_evidence_passed()
            && self.fail_closed_reasons.is_empty()
            && !self.release_hold
    }

    pub fn all_preflight_evidence_passed(&self) -> bool {
        self.checks().into_iter().all(|check| check.passed)
    }

    pub fn preflight_result(&self) -> Result<()> {
        if self.runtime_execution_allowed() {
            Ok(())
        } else {
            Err(self.fail_closed_reason())
        }
    }

    pub fn fail_closed_reason(&self) -> String {
        if self.fail_closed_reasons.is_empty() {
            "private_receipt_gate_preflight_release_hold_active".to_string()
        } else {
            self.fail_closed_reasons.join(";")
        }
    }

    fn checks(&self) -> Vec<&GateCheck> {
        vec![
            &self.nullifier_hygiene,
            &self.output_commitments,
            &self.encrypted_receipt_shards,
            &self.fee_cap,
            &self.pq_authorization,
            &self.wallet_reconstruction,
            &self.forced_exit_compatibility,
            &self.metadata_budgets,
            &self.expected_invocation,
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

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-PRIVATE-RECEIPT-GATE-PREFLIGHT-RUNTIME-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn label_root(domain: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-PRIVATE-RECEIPT-GATE-PREFLIGHT-RUNTIME-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn gate_check<'a, const N: usize>(
    name: &str,
    passed: bool,
    detail_pairs: [(&'a str, &'a str); N],
) -> GateCheck {
    let detail = detail_pairs
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<BTreeMap<_, _>>();
    let record = json!({
        "name": name,
        "passed": passed,
        "detail": detail,
    });
    GateCheck {
        name: name.to_string(),
        passed,
        evidence_root: record_root(name, &record),
        detail,
    }
}
