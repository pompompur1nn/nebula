use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceDepositNoteGateReceiptConformanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-gate-receipt-conformance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-gate-receipt-conformance-runtime";
const DEFAULT_BRIDGE_SESSION_LABEL: &str = "canonical-vertical-slice-devnet";
const DEFAULT_RECEIPT_ID: &str = "devnet-deposit-note-gate-receipt-conformance-0001";
const DEFAULT_RELEASE_HOLD: &str = "runtime-execution-deferred";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub bridge_session_label: String,
    pub receipt_id: String,
    pub runtime_execution_deferred: bool,
    pub cargo_execution_deferred: bool,
    pub production_release_allowed: bool,
    pub observed_root_status: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            bridge_session_label: DEFAULT_BRIDGE_SESSION_LABEL.to_string(),
            receipt_id: DEFAULT_RECEIPT_ID.to_string(),
            runtime_execution_deferred: true,
            cargo_execution_deferred: true,
            production_release_allowed: false,
            observed_root_status: "deterministic_deferred_placeholder".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "bridge_session_label": self.bridge_session_label,
            "receipt_id": self.receipt_id,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "cargo_execution_deferred": self.cargo_execution_deferred,
            "production_release_allowed": self.production_release_allowed,
            "observed_root_status": self.observed_root_status,
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
pub struct ReceiptConformanceEvidence {
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub conformance_root: String,
    pub release_blocking: bool,
    pub status: String,
    pub reason: String,
}

impl ReceiptConformanceEvidence {
    pub fn deferred(lane: &str, expected_payload: Value, config: &Config) -> Self {
        let expected_root = lane_expected_root(lane, &expected_payload);
        let observed_root = deferred_observed_root(lane, &expected_root, config);
        let release_blocking = true;
        let status = "release_blocked_observed_root_deferred".to_string();
        let reason = "runtime execution is deferred, so observed receipt evidence is a deterministic release-blocking placeholder".to_string();
        let conformance_root = domain_hash(
            &format!("{DOMAIN}:conformance-evidence"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(&expected_root),
                HashPart::Str(&observed_root),
                HashPart::Str(&status),
                HashPart::Str(&reason),
                HashPart::Str(if release_blocking { "true" } else { "false" }),
            ],
            32,
        );

        Self {
            lane: lane.to_string(),
            expected_root,
            observed_root,
            conformance_root,
            release_blocking,
            status,
            reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "conformance_root": self.conformance_root,
            "release_blocking": self.release_blocking,
            "status": self.status,
            "reason": self.reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(&format!("conformance_{}", self.lane), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bridge_session_id: String,
    pub receipt_id: String,
    pub invocation: ReceiptConformanceEvidence,
    pub preflight: ReceiptConformanceEvidence,
    pub execution_receipt: ReceiptConformanceEvidence,
    pub monero_lock_evidence: ReceiptConformanceEvidence,
    pub watcher_pq_quorum: ReceiptConformanceEvidence,
    pub finality_reorg_evidence: ReceiptConformanceEvidence,
    pub note_commitment: ReceiptConformanceEvidence,
    pub wallet_scan_hint: ReceiptConformanceEvidence,
    pub metadata_redaction: ReceiptConformanceEvidence,
    pub operator_evidence: ReceiptConformanceEvidence,
    pub wallet_visible_receipt: ReceiptConformanceEvidence,
    pub fail_closed_receipt: ReceiptConformanceEvidence,
    pub release_blockers: ReceiptConformanceEvidence,
    pub conformance_root: String,
    pub release_blocker_root: String,
    pub production_release_allowed: bool,
    pub evidence: BTreeMap<String, ReceiptConformanceEvidence>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bridge_session_id = label_root("bridge_session", &config.bridge_session_label);
        let receipt_id = config.receipt_id.clone();

        let mut evidence = BTreeMap::new();
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "invocation",
                json!({"gate": "deposit_note", "phase": "invocation", "bridge_session_id": &bridge_session_id}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "preflight",
                json!({"gate": "deposit_note", "phase": "preflight", "policy": "fail_closed"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "execution_receipt",
                json!({"receipt_id": &receipt_id, "phase": "execution_receipt", "envelope": "deposit_note_gate"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "monero_lock_evidence",
                json!({"expected": "confirmed_monero_lock", "redaction": "amount_and_address_committed"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "watcher_pq_quorum",
                json!({"expected": "pq_watcher_quorum", "threshold": "canonical_devnet_policy"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "finality_reorg_evidence",
                json!({"expected": "finality_depth_and_reorg_probe", "monero_branch": "canonical"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "note_commitment",
                json!({"expected": "deposit_note_commitment", "privacy": "recipient_and_amount_committed"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "wallet_scan_hint",
                json!({"expected": "wallet_scan_hint", "visibility": "wallet_only"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "metadata_redaction",
                json!({"expected": "public_metadata_minimized", "redacted": ["amount", "address", "view_material"]}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "operator_evidence",
                json!({"expected": "operator_attestation_bundle", "scope": "deposit_note_gate"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "wallet_visible_receipt",
                json!({"expected": "wallet_reconstructable_receipt", "public_leakage": "bounded"}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "fail_closed_receipt",
                json!({"expected": "fail_closed_receipt", "release_hold": DEFAULT_RELEASE_HOLD}),
                &config,
            ),
        );
        insert_evidence(
            &mut evidence,
            ReceiptConformanceEvidence::deferred(
                "release_blockers",
                json!({"runtime_execution_deferred": true, "cargo_execution_deferred": true, "production_release_allowed": false}),
                &config,
            ),
        );

        let conformance_root = evidence_root("all_conformance", &evidence);
        let release_blocker_root = release_blocker_root(&evidence);

        let invocation = evidence_value(&evidence, "invocation");
        let preflight = evidence_value(&evidence, "preflight");
        let execution_receipt = evidence_value(&evidence, "execution_receipt");
        let monero_lock_evidence = evidence_value(&evidence, "monero_lock_evidence");
        let watcher_pq_quorum = evidence_value(&evidence, "watcher_pq_quorum");
        let finality_reorg_evidence = evidence_value(&evidence, "finality_reorg_evidence");
        let note_commitment = evidence_value(&evidence, "note_commitment");
        let wallet_scan_hint = evidence_value(&evidence, "wallet_scan_hint");
        let metadata_redaction = evidence_value(&evidence, "metadata_redaction");
        let operator_evidence = evidence_value(&evidence, "operator_evidence");
        let wallet_visible_receipt = evidence_value(&evidence, "wallet_visible_receipt");
        let fail_closed_receipt = evidence_value(&evidence, "fail_closed_receipt");
        let release_blockers = evidence_value(&evidence, "release_blockers");

        Self {
            config,
            bridge_session_id,
            receipt_id,
            invocation,
            preflight,
            execution_receipt,
            monero_lock_evidence,
            watcher_pq_quorum,
            finality_reorg_evidence,
            note_commitment,
            wallet_scan_hint,
            metadata_redaction,
            operator_evidence,
            wallet_visible_receipt,
            fail_closed_receipt,
            release_blockers,
            conformance_root,
            release_blocker_root,
            production_release_allowed: false,
            evidence,
        }
    }

    pub fn all_release_blocking(&self) -> bool {
        self.evidence.values().all(|item| item.release_blocking)
    }

    pub fn public_record(&self) -> Value {
        let evidence = self
            .evidence
            .values()
            .map(ReceiptConformanceEvidence::public_record)
            .collect::<Vec<_>>();

        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "bridge_session_id": self.bridge_session_id,
            "receipt_id": self.receipt_id,
            "runtime_execution_deferred": self.config.runtime_execution_deferred,
            "cargo_execution_deferred": self.config.cargo_execution_deferred,
            "production_release_allowed": self.production_release_allowed,
            "all_release_blocking": self.all_release_blocking(),
            "conformance_root": self.conformance_root,
            "release_blocker_root": self.release_blocker_root,
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

fn insert_evidence(
    evidence: &mut BTreeMap<String, ReceiptConformanceEvidence>,
    item: ReceiptConformanceEvidence,
) {
    evidence.insert(item.lane.clone(), item);
}

fn evidence_value(
    evidence: &BTreeMap<String, ReceiptConformanceEvidence>,
    lane: &str,
) -> ReceiptConformanceEvidence {
    match evidence.get(lane) {
        Some(item) => item.clone(),
        None => ReceiptConformanceEvidence::deferred(
            lane,
            json!({"missing_lane": lane, "status": "deterministic_absent_lane"}),
            &Config::devnet(),
        ),
    }
}

fn lane_expected_root(lane: &str, payload: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn deferred_observed_root(lane: &str, expected_root: &str, config: &Config) -> String {
    domain_hash(
        &format!("{DOMAIN}:observed-root-deferred"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.receipt_id),
            HashPart::Str(lane),
            HashPart::Str(expected_root),
            HashPart::Str(&config.observed_root_status),
            HashPart::Str(DEFAULT_RELEASE_HOLD),
        ],
        32,
    )
}

fn evidence_root(label: &str, evidence: &BTreeMap<String, ReceiptConformanceEvidence>) -> String {
    let leaves = evidence
        .values()
        .map(ReceiptConformanceEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn release_blocker_root(evidence: &BTreeMap<String, ReceiptConformanceEvidence>) -> String {
    let blockers = evidence
        .values()
        .filter(|item| item.release_blocking)
        .map(ReceiptConformanceEvidence::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:release-blockers"), &blockers)
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
