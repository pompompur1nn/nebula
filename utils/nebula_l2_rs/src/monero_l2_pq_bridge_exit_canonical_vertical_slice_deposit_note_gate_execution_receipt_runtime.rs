use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceDepositNoteGateExecutionReceiptRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-deposit-note-gate-execution-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_DEPOSIT_NOTE_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";

const DEFAULT_MONERO_LOCK_HEIGHT: u64 = 912_640;
const DEFAULT_MONERO_OBSERVED_HEIGHT: u64 = 912_704;
const DEFAULT_MIN_MONERO_FINALITY_DEPTH: u64 = 60;
const DEFAULT_REORG_LOOKBACK_BLOCKS: u64 = 18;
const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u64 = 6_700;
const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 720;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub min_monero_finality_depth: u64,
    pub reorg_lookback_blocks: u64,
    pub min_watcher_weight_bps: u64,
    pub release_hold_blocks: u64,
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
            min_monero_finality_depth: DEFAULT_MIN_MONERO_FINALITY_DEPTH,
            reorg_lookback_blocks: DEFAULT_REORG_LOOKBACK_BLOCKS,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
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
            "reorg_lookback_blocks": self.reorg_lookback_blocks,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "release_hold_blocks": self.release_hold_blocks,
            "runtime_execution_allowed": self.runtime_execution_allowed,
            "cargo_execution_allowed": self.cargo_execution_allowed,
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
pub struct ReceiptEnvelope {
    pub envelope_id: String,
    pub lane: String,
    pub status: String,
    pub public_root: String,
    pub private_commitment_root: String,
    pub wallet_visible: bool,
    pub operator_visible: bool,
    pub release_blocking: bool,
}

impl ReceiptEnvelope {
    pub fn new(
        lane: &str,
        status: &str,
        public_payload: Value,
        private_payload: Value,
        wallet_visible: bool,
        operator_visible: bool,
        release_blocking: bool,
    ) -> Self {
        let public_root = record_root(lane, &public_payload);
        let private_commitment_root =
            record_root(&format!("{lane}_private_commitment"), &private_payload);
        let envelope_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-ENVELOPE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(status),
                HashPart::Str(&public_root),
                HashPart::Str(&private_commitment_root),
            ],
            32,
        );

        Self {
            envelope_id,
            lane: lane.to_string(),
            status: status.to_string(),
            public_root,
            private_commitment_root,
            wallet_visible,
            operator_visible,
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "lane": self.lane,
            "status": self.status,
            "public_root": self.public_root,
            "private_commitment_root": self.private_commitment_root,
            "wallet_visible": self.wallet_visible,
            "operator_visible": self.operator_visible,
            "release_blocking": self.release_blocking,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub bridge_session_id: String,
    pub deposit_note_gate_id: String,
    pub monero_lock_evidence_accepted_root: String,
    pub watcher_pq_quorum_root: String,
    pub finality_reorg_check_root: String,
    pub note_commitment_minted_root: String,
    pub wallet_scan_hint_emitted_root: String,
    pub metadata_redaction_checked_root: String,
    pub expected_invocation_root: String,
    pub expected_preflight_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_receipt_root: String,
    pub fail_closed_receipt_root: String,
    pub production_release_hold_root: String,
    pub receipt_envelope_root: String,
    pub runtime_execution_deferred: bool,
    pub cargo_execution_deferred: bool,
    pub production_release_allowed: bool,
    pub receipt_envelopes: BTreeMap<String, ReceiptEnvelope>,
    pub fail_closed_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bridge_session_id = label_root("bridge_session", "canonical-vertical-slice-devnet");
        let deposit_note_gate_id = label_root("deposit_note_gate", &bridge_session_id);

        let mut receipt_envelopes = BTreeMap::new();
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "monero_lock_evidence_accepted",
                "accepted",
                json!({
                    "monero_tx_root": label_root("monero_lock_tx", "devnet-lock-output-0001"),
                    "lock_height": DEFAULT_MONERO_LOCK_HEIGHT,
                    "accepted_height": DEFAULT_MONERO_OBSERVED_HEIGHT,
                    "acceptance_policy": "rooted_lock_output_confirmed",
                }),
                json!({
                    "deposit_address_root": label_root("deposit_address", "redacted-devnet-address"),
                    "amount_commitment_root": label_root("amount_commitment", "locked-atomic-units"),
                    "view_material": "redacted",
                }),
                true,
                true,
                false,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "watcher_pq_quorum",
                "accepted",
                json!({
                    "watcher_set_root": label_root("watcher_set", "devnet-pq-watchers"),
                    "signature_scheme": "ml-dsa-falcon-hybrid",
                    "attested_weight_bps": 7_500_u64,
                    "min_weight_bps": config.min_watcher_weight_bps,
                }),
                json!({
                    "attestation_transcript_root": label_root("watcher_attestation", "deposit-note-gate-execution-receipt"),
                    "individual_signature_roots": label_root("watcher_signatures", "aggregated-redacted"),
                }),
                true,
                true,
                false,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "finality_reorg_checks",
                "accepted",
                json!({
                    "lock_height": DEFAULT_MONERO_LOCK_HEIGHT,
                    "observed_height": DEFAULT_MONERO_OBSERVED_HEIGHT,
                    "observed_depth": DEFAULT_MONERO_OBSERVED_HEIGHT - DEFAULT_MONERO_LOCK_HEIGHT,
                    "min_depth": config.min_monero_finality_depth,
                    "reorg_lookback_blocks": config.reorg_lookback_blocks,
                }),
                json!({
                    "canonical_tip_root": label_root("monero_tip", "devnet-canonical-tip"),
                    "reorg_probe_root": label_root("reorg_probe", "no-competing-chain-detected"),
                }),
                true,
                true,
                false,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "note_commitment_minted",
                "accepted",
                json!({
                    "asset_id": "wxmr-devnet",
                    "note_commitment_root": label_root("note_commitment", "minted-private-deposit-note"),
                    "nullifier_domain_root": label_root("nullifier_domain", "forced-exit-spine"),
                    "mint_event": "deposit_note_minted",
                }),
                json!({
                    "recipient_root": label_root("note_recipient", "pq-wallet-recipient-commitment"),
                    "note_salt_root": label_root("note_salt", "deposit-note-salt-redacted"),
                    "spend_authority": "redacted",
                }),
                true,
                false,
                false,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "wallet_scan_hint_emitted",
                "accepted",
                json!({
                    "scan_from_height": DEFAULT_MONERO_LOCK_HEIGHT,
                    "scan_to_height": DEFAULT_MONERO_OBSERVED_HEIGHT,
                    "hint_visibility": "wallet-visible-root-only",
                    "wallet_hint_root": label_root("wallet_scan_hint", "scan-window-912640-912704"),
                }),
                json!({
                    "view_hint_ciphertext_root": label_root("wallet_view_hint_ciphertext", "redacted"),
                    "wallet_local_recovery_root": label_root("wallet_local_recovery", "deposit-note-reconstructable"),
                }),
                true,
                false,
                false,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "metadata_redaction_checked",
                "accepted",
                json!({
                    "redaction_policy": "public-roots-no-addresses-no-viewkeys-no-plaintext-note",
                    "plaintext_fields_removed": 6_u64,
                    "public_record_safe": true,
                    "metadata_leak_units": 0_u64,
                }),
                json!({
                    "redacted_fields_root": label_root("redacted_fields", "sender-amount-viewkey-spend-authority"),
                    "audit_trace_root": label_root("metadata_redaction_audit", "deposit-note-receipt"),
                }),
                true,
                true,
                false,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "expected_invocation_and_preflight",
                "matched",
                json!({
                    "expected_invocation_root": label_root("expected_invocation", "deposit-note-gate-invocation-runtime"),
                    "expected_preflight_root": label_root("expected_preflight", "deposit-note-gate-preflight-runtime"),
                    "execution_receipt_runtime": PROTOCOL_VERSION,
                }),
                json!({
                    "cargo_command_root": label_root("cargo_command", "deferred-until-runtime-execution-allowed"),
                    "runtime_invocation_root": label_root("runtime_invocation", "deferred-until-runtime-execution-allowed"),
                }),
                false,
                true,
                true,
            ),
        );
        insert_envelope(
            &mut receipt_envelopes,
            ReceiptEnvelope::new(
                "production_release_hold",
                "held",
                json!({
                    "hold_reason": "execution_receipt_recorded_before_cargo_runtime_execution",
                    "hold_blocks": config.release_hold_blocks,
                    "runtime_execution_allowed": config.runtime_execution_allowed,
                    "cargo_execution_allowed": config.cargo_execution_allowed,
                    "production_release_allowed": config.production_release_allowed,
                }),
                json!({
                    "release_authority_root": label_root("release_authority", "not-granted"),
                    "operator_override_root": label_root("operator_override", "not-present"),
                }),
                false,
                true,
                true,
            ),
        );

        let monero_lock_evidence_accepted_root = lane_root(
            &receipt_envelopes,
            "monero_lock_evidence_accepted",
            "missing_monero_lock_evidence",
        );
        let watcher_pq_quorum_root = lane_root(
            &receipt_envelopes,
            "watcher_pq_quorum",
            "missing_watcher_quorum",
        );
        let finality_reorg_check_root = lane_root(
            &receipt_envelopes,
            "finality_reorg_checks",
            "missing_finality_reorg_check",
        );
        let note_commitment_minted_root = lane_root(
            &receipt_envelopes,
            "note_commitment_minted",
            "missing_note_commitment",
        );
        let wallet_scan_hint_emitted_root = lane_root(
            &receipt_envelopes,
            "wallet_scan_hint_emitted",
            "missing_wallet_scan_hint",
        );
        let metadata_redaction_checked_root = lane_root(
            &receipt_envelopes,
            "metadata_redaction_checked",
            "missing_metadata_redaction",
        );
        let expected_invocation_root = label_root(
            "expected_invocation",
            "deposit-note-gate-invocation-runtime",
        );
        let expected_preflight_root =
            label_root("expected_preflight", "deposit-note-gate-preflight-runtime");

        let operator_records = receipt_envelopes
            .values()
            .filter(|envelope| envelope.operator_visible)
            .map(ReceiptEnvelope::public_record)
            .collect::<Vec<_>>();
        let wallet_records = receipt_envelopes
            .values()
            .filter(|envelope| envelope.wallet_visible)
            .map(ReceiptEnvelope::public_record)
            .collect::<Vec<_>>();
        let fail_closed_records = receipt_envelopes
            .values()
            .filter(|envelope| envelope.release_blocking)
            .map(ReceiptEnvelope::public_record)
            .collect::<Vec<_>>();
        let envelope_records = receipt_envelopes
            .values()
            .map(ReceiptEnvelope::public_record)
            .collect::<Vec<_>>();

        let operator_evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-OPERATOR-EVIDENCE",
            &operator_records,
        );
        let wallet_visible_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-WALLET-VISIBLE",
            &wallet_records,
        );
        let fail_closed_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-FAIL-CLOSED",
            &fail_closed_records,
        );
        let receipt_envelope_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-ENVELOPES",
            &envelope_records,
        );

        let mut fail_closed_reasons = BTreeMap::new();
        fail_closed_reasons.insert(
            "cargo_execution_deferred".to_string(),
            "cargo execution evidence is not accepted until execution is explicitly allowed"
                .to_string(),
        );
        fail_closed_reasons.insert(
            "runtime_execution_deferred".to_string(),
            "runtime execution receipt is deterministic but live execution is deferred".to_string(),
        );
        fail_closed_reasons.insert(
            "production_release_hold".to_string(),
            "production release remains held even though deposit-note receipt evidence is rooted"
                .to_string(),
        );

        let production_release_hold_root = record_root(
            "production_release_hold",
            &json!({
                "fail_closed_receipt_root": fail_closed_receipt_root,
                "fail_closed_reasons": fail_closed_reasons,
                "release_allowed": false,
            }),
        );

        Self {
            config,
            bridge_session_id,
            deposit_note_gate_id,
            monero_lock_evidence_accepted_root,
            watcher_pq_quorum_root,
            finality_reorg_check_root,
            note_commitment_minted_root,
            wallet_scan_hint_emitted_root,
            metadata_redaction_checked_root,
            expected_invocation_root,
            expected_preflight_root,
            operator_evidence_root,
            wallet_visible_receipt_root,
            fail_closed_receipt_root,
            production_release_hold_root,
            receipt_envelope_root,
            runtime_execution_deferred: true,
            cargo_execution_deferred: true,
            production_release_allowed: false,
            receipt_envelopes,
            fail_closed_reasons,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "bridge_session_id": self.bridge_session_id,
            "deposit_note_gate_id": self.deposit_note_gate_id,
            "monero_lock_evidence_accepted_root": self.monero_lock_evidence_accepted_root,
            "watcher_pq_quorum_root": self.watcher_pq_quorum_root,
            "finality_reorg_check_root": self.finality_reorg_check_root,
            "note_commitment_minted_root": self.note_commitment_minted_root,
            "wallet_scan_hint_emitted_root": self.wallet_scan_hint_emitted_root,
            "metadata_redaction_checked_root": self.metadata_redaction_checked_root,
            "expected_invocation_root": self.expected_invocation_root,
            "expected_preflight_root": self.expected_preflight_root,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_receipt_root": self.wallet_visible_receipt_root,
            "fail_closed_receipt_root": self.fail_closed_receipt_root,
            "production_release_hold_root": self.production_release_hold_root,
            "receipt_envelope_root": self.receipt_envelope_root,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "cargo_execution_deferred": self.cargo_execution_deferred,
            "production_release_allowed": self.production_release_allowed,
            "receipt_envelopes": self.receipt_envelopes.values().map(ReceiptEnvelope::public_record).collect::<Vec<_>>(),
            "fail_closed_reasons": self.fail_closed_reasons,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.bridge_session_id),
                HashPart::Str(&self.deposit_note_gate_id),
                HashPart::Str(&self.monero_lock_evidence_accepted_root),
                HashPart::Str(&self.watcher_pq_quorum_root),
                HashPart::Str(&self.finality_reorg_check_root),
                HashPart::Str(&self.note_commitment_minted_root),
                HashPart::Str(&self.wallet_scan_hint_emitted_root),
                HashPart::Str(&self.metadata_redaction_checked_root),
                HashPart::Str(&self.expected_invocation_root),
                HashPart::Str(&self.expected_preflight_root),
                HashPart::Str(&self.operator_evidence_root),
                HashPart::Str(&self.wallet_visible_receipt_root),
                HashPart::Str(&self.fail_closed_receipt_root),
                HashPart::Str(&self.production_release_hold_root),
                HashPart::Str(&self.receipt_envelope_root),
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
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-RECORD",
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
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-NOTE-GATE-EXECUTION-RECEIPT-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn lane_root(
    receipt_envelopes: &BTreeMap<String, ReceiptEnvelope>,
    lane: &str,
    missing_label: &str,
) -> String {
    match receipt_envelopes.get(lane) {
        Some(envelope) => envelope.public_root.clone(),
        None => label_root("missing_receipt_envelope", missing_label),
    }
}

fn insert_envelope(
    receipt_envelopes: &mut BTreeMap<String, ReceiptEnvelope>,
    envelope: ReceiptEnvelope,
) {
    receipt_envelopes.insert(envelope.lane.clone(), envelope);
}
