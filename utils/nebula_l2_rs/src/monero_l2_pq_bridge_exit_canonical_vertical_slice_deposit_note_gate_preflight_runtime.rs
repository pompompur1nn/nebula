use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceDepositNoteGatePreflightRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-gate-preflight-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DEFAULT_MONERO_LOCK_HEIGHT: u64 = 912_640;
const DEFAULT_MONERO_OBSERVED_HEIGHT: u64 = 912_704;
const DEFAULT_MIN_FINALITY_DEPTH: u64 = 60;
const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u64 = 6_700;
const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 720;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub min_monero_finality_depth: u64,
    pub min_watcher_weight_bps: u64,
    pub release_hold_blocks: u64,
    pub require_metadata_redaction: bool,
    pub runtime_execution_allowed: bool,
    pub cargo_execution_allowed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            min_monero_finality_depth: DEFAULT_MIN_FINALITY_DEPTH,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            require_metadata_redaction: true,
            runtime_execution_allowed: false,
            cargo_execution_allowed: false,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "min_monero_finality_depth": self.min_monero_finality_depth,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "release_hold_blocks": self.release_hold_blocks,
            "require_metadata_redaction": self.require_metadata_redaction,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "cargo_execution_allowed": self.cargo_execution_allowed,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GateCheck {
    pub check_id: String,
    pub kind: String,
    pub status: String,
    pub required: String,
    pub observed: String,
    pub evidence_root: String,
    pub public_root: String,
}

impl GateCheck {
    pub fn new(kind: &str, status: &str, required: String, observed: String) -> Self {
        let evidence_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-CHECK",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind),
                HashPart::Str(status),
                HashPart::Str(&required),
                HashPart::Str(&observed),
            ],
            32,
        );
        let check_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-CHECK-ID",
            &[HashPart::Str(kind), HashPart::Str(&evidence_root)],
            32,
        );
        let public_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-CHECK-PUBLIC",
            &[HashPart::Str(&check_id), HashPart::Str(&evidence_root)],
            32,
        );
        Self {
            check_id,
            kind: kind.to_string(),
            status: status.to_string(),
            required,
            observed,
            evidence_root,
            public_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "kind": self.kind,
            "status": self.status,
            "required": self.required,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bridge_session_id: String,
    pub deposit_note_gate_id: String,
    pub monero_lock_evidence_root: String,
    pub watcher_pq_quorum_root: String,
    pub finality_depth_root: String,
    pub note_commitment_root: String,
    pub wallet_scan_hint_root: String,
    pub metadata_redaction_root: String,
    pub expected_invocation_root: String,
    pub release_hold_root: String,
    pub check_root: String,
    pub fail_closed_root: String,
    pub runtime_allowed: bool,
    pub cargo_allowed: bool,
    pub release_allowed: bool,
    pub checks: BTreeMap<String, GateCheck>,
    pub fail_closed_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bridge_session_id = label_root("bridge_session", "canonical-vertical-slice-devnet");
        let deposit_note_gate_id = label_root("deposit_note_gate", &bridge_session_id);
        let monero_tx_root = label_root("monero_lock_tx", "devnet-lock-output-0001");
        let deposit_address_root = label_root("monero_deposit_address", "redacted-devnet-address");
        let wallet_view_hint_root = label_root("wallet_view_hint", "scan-window-912640-912704");
        let note_salt_root = label_root("note_salt", "deposit-note-salt-redacted");
        let note_recipient_root = label_root("note_recipient", "pq-wallet-recipient-commitment");

        let monero_lock_evidence = json!({
            "monero_tx_root": monero_tx_root,
            "deposit_address_root": deposit_address_root,
            "locked_atomic_units": 2_500_000_000_000_u64,
            "lock_height": DEFAULT_MONERO_LOCK_HEIGHT,
        });
        let watcher_pq_quorum = json!({
            "watcher_set_root": label_root("watcher_set", "devnet-pq-watchers"),
            "signature_scheme": "falcon-slh-dsa-hybrid",
            "attested_weight_bps": 7_500_u64,
            "attestation_root": label_root("watcher_attestation", "deposit-note-gate"),
        });
        let finality_depth = json!({
            "lock_height": DEFAULT_MONERO_LOCK_HEIGHT,
            "observed_height": DEFAULT_MONERO_OBSERVED_HEIGHT,
            "depth": DEFAULT_MONERO_OBSERVED_HEIGHT - DEFAULT_MONERO_LOCK_HEIGHT,
            "min_depth": config.min_monero_finality_depth,
        });
        let note_commitment = json!({
            "commitment_scheme": "poseidon-compatible-domain-hash-preimage",
            "amount_commitment_root": label_root("amount_commitment", "locked-atomic-units"),
            "recipient_root": note_recipient_root,
            "salt_root": note_salt_root,
            "nullifier_domain_root": label_root("nullifier_domain", "forced-exit-spine"),
        });
        let wallet_scan_hints = json!({
            "view_hint_root": wallet_view_hint_root,
            "scan_from_height": DEFAULT_MONERO_LOCK_HEIGHT,
            "scan_to_height": DEFAULT_MONERO_OBSERVED_HEIGHT,
            "hint_visibility": "redacted-root-only",
        });
        let metadata_redaction = json!({
            "redaction_policy": "public-roots-no-addresses-no-viewkeys-no-plaintext-note",
            "plaintext_fields_removed": 6_u64,
            "redaction_root": label_root("metadata_redaction", "deposit-note-public-record"),
            "public_record_safe": true,
        });
        let expected_invocation = json!({
            "runtime": "deposit-note-gate-preflight",
            "cargo_command_root": label_root("cargo_command", "deferred-until-preflight-ready"),
            "runtime_invocation_root": label_root("runtime_invocation", "deferred-until-preflight-ready"),
            "bridge_session_id": bridge_session_id,
        });
        let release_hold = json!({
            "hold_reason": "preflight-evidence-only",
            "hold_blocks": config.release_hold_blocks,
            "release_authority_root": label_root("release_authority", "not-granted"),
            "production_release_allowed": config.production_release_allowed,
        });

        let monero_lock_evidence_root = record_root("monero_lock_evidence", &monero_lock_evidence);
        let watcher_pq_quorum_root = record_root("watcher_pq_quorum", &watcher_pq_quorum);
        let finality_depth_root = record_root("finality_depth", &finality_depth);
        let note_commitment_root = record_root("note_commitment", &note_commitment);
        let wallet_scan_hint_root = record_root("wallet_scan_hints", &wallet_scan_hints);
        let metadata_redaction_root = record_root("metadata_redaction", &metadata_redaction);
        let expected_invocation_root = record_root("expected_invocation", &expected_invocation);
        let release_hold_root = record_root("release_hold", &release_hold);

        let mut checks = BTreeMap::new();
        insert_check(
            &mut checks,
            GateCheck::new(
                "monero_lock_evidence",
                "ready",
                "monero lock tx, deposit address commitment, and amount must be rooted".to_string(),
                monero_lock_evidence_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "watcher_pq_quorum",
                "ready",
                format!("attested_weight_bps >= {}", config.min_watcher_weight_bps),
                watcher_pq_quorum_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "reorg_finality_depth",
                "ready",
                format!("depth >= {}", config.min_monero_finality_depth),
                finality_depth_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "note_commitment_construction",
                "ready",
                "amount, recipient, salt, and nullifier domain roots must compose note".to_string(),
                note_commitment_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "wallet_scan_hints",
                "ready",
                "wallet scan hints must be bounded and root-only".to_string(),
                wallet_scan_hint_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "metadata_redaction",
                "ready",
                "public record must remove plaintext address, view key, and note material"
                    .to_string(),
                metadata_redaction_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "expected_invocation_root",
                "held",
                "cargo and runtime invocation roots must be deterministic before execution"
                    .to_string(),
                expected_invocation_root.clone(),
            ),
        );
        insert_check(
            &mut checks,
            GateCheck::new(
                "release_hold",
                "held",
                "release must remain held until cargo/runtime execution is explicitly enabled"
                    .to_string(),
                release_hold_root.clone(),
            ),
        );

        let mut fail_closed_reasons = BTreeMap::new();
        fail_closed_reasons.insert(
            "cargo_execution".to_string(),
            "cargo execution is blocked until deposit-note preflight evidence is promoted"
                .to_string(),
        );
        fail_closed_reasons.insert(
            "runtime_execution".to_string(),
            "runtime execution is blocked until expected invocation root is authorized".to_string(),
        );
        fail_closed_reasons.insert(
            "production_release".to_string(),
            "production release is blocked by explicit release hold".to_string(),
        );

        let check_records = checks
            .values()
            .map(GateCheck::public_record)
            .collect::<Vec<_>>();
        let check_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-CHECKS",
            &check_records,
        );
        let fail_closed_records = fail_closed_reasons
            .iter()
            .map(|(kind, reason)| json!({ "kind": kind, "reason": reason }))
            .collect::<Vec<_>>();
        let fail_closed_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-FAIL-CLOSED",
            &fail_closed_records,
        );

        Self {
            config,
            bridge_session_id,
            deposit_note_gate_id,
            monero_lock_evidence_root,
            watcher_pq_quorum_root,
            finality_depth_root,
            note_commitment_root,
            wallet_scan_hint_root,
            metadata_redaction_root,
            expected_invocation_root,
            release_hold_root,
            check_root,
            fail_closed_root,
            runtime_allowed: false,
            cargo_allowed: false,
            release_allowed: false,
            checks,
            fail_closed_reasons,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "bridge_session_id": self.bridge_session_id,
            "deposit_note_gate_id": self.deposit_note_gate_id,
            "monero_lock_evidence_root": self.monero_lock_evidence_root,
            "watcher_pq_quorum_root": self.watcher_pq_quorum_root,
            "finality_depth_root": self.finality_depth_root,
            "note_commitment_root": self.note_commitment_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "metadata_redaction_root": self.metadata_redaction_root,
            "expected_invocation_root": self.expected_invocation_root,
            "release_hold_root": self.release_hold_root,
            "check_root": self.check_root,
            "fail_closed_root": self.fail_closed_root,
            "runtime_allowed": self.runtime_allowed,
            "cargo_allowed": self.cargo_allowed,
            "release_allowed": self.release_allowed,
            "checks": self.checks.values().map(GateCheck::public_record).collect::<Vec<_>>(),
            "fail_closed_reasons": self.fail_closed_reasons,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.bridge_session_id),
                HashPart::Str(&self.deposit_note_gate_id),
                HashPart::Str(&self.monero_lock_evidence_root),
                HashPart::Str(&self.watcher_pq_quorum_root),
                HashPart::Str(&self.finality_depth_root),
                HashPart::Str(&self.note_commitment_root),
                HashPart::Str(&self.wallet_scan_hint_root),
                HashPart::Str(&self.metadata_redaction_root),
                HashPart::Str(&self.expected_invocation_root),
                HashPart::Str(&self.release_hold_root),
                HashPart::Str(&self.check_root),
                HashPart::Str(&self.fail_closed_root),
            ],
            32,
        )
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
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn label_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-PREFLIGHT-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn insert_check(checks: &mut BTreeMap<String, GateCheck>, check: GateCheck) {
    checks.insert(check.kind.clone(), check);
}
