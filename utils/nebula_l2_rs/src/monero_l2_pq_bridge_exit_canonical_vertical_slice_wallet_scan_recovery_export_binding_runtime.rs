use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWalletScanRecoveryExportBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-wallet-scan-recovery-export-binding-runtime-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub bridge_spine_id: String,
    pub wallet_scan_domain: String,
    pub forced_exit_spine_root: String,
    pub max_hint_sets_per_wallet: u64,
    pub max_encrypted_window_span: u64,
    pub max_live_feed_lag_blocks: u64,
    pub max_receipt_observation_lag_blocks: u64,
    pub max_recovery_export_bytes: u64,
    pub allow_release_with_mismatch_records: bool,
    pub privacy_budget_epsilon_micros: u64,
    pub privacy_budget_delta_nanos: u64,
}

impl Config {
    pub fn devnet() -> Self {
        let bridge_spine_id = "monero-l2-pq-forced-exit-canonical-spine".to_string();
        let forced_exit_spine_root = domain_hash(
            "WALLET-SCAN-RECOVERY-FORCED-EXIT-SPINE",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(&bridge_spine_id)],
            32,
        );
        Self {
            chain_id: CHAIN_ID.to_string(),
            bridge_spine_id,
            wallet_scan_domain: "monero-l2-wallet-visible-forced-exit-scan".to_string(),
            forced_exit_spine_root,
            max_hint_sets_per_wallet: 64,
            max_encrypted_window_span: 720,
            max_live_feed_lag_blocks: 6,
            max_receipt_observation_lag_blocks: 12,
            max_recovery_export_bytes: 131_072,
            allow_release_with_mismatch_records: false,
            privacy_budget_epsilon_micros: 25_000,
            privacy_budget_delta_nanos: 10,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_scan_recovery_export_binding_config",
            "chain_id": self.chain_id,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "bridge_spine_id": self.bridge_spine_id,
            "wallet_scan_domain": self.wallet_scan_domain,
            "forced_exit_spine_root": self.forced_exit_spine_root,
            "max_hint_sets_per_wallet": self.max_hint_sets_per_wallet,
            "max_encrypted_window_span": self.max_encrypted_window_span,
            "max_live_feed_lag_blocks": self.max_live_feed_lag_blocks,
            "max_receipt_observation_lag_blocks": self.max_receipt_observation_lag_blocks,
            "max_recovery_export_bytes": self.max_recovery_export_bytes,
            "allow_release_with_mismatch_records": self.allow_release_with_mismatch_records,
            "privacy_budget_epsilon_micros": self.privacy_budget_epsilon_micros,
            "privacy_budget_delta_nanos": self.privacy_budget_delta_nanos,
        })
    }

    pub fn config_root(&self) -> String {
        domain_hash(
            "WALLET-SCAN-RECOVERY-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteHint {
    pub hint_id: String,
    pub wallet_id: String,
    pub note_commitment: String,
    pub view_tag: String,
    pub subaddress_hint: String,
    pub amount_bucket_commitment: String,
    pub forced_exit_claim_id: String,
    pub scan_height: u64,
    pub hint_ciphertext_root: String,
}

impl NoteHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        note_commitment: &str,
        view_tag: &str,
        subaddress_hint: &str,
        amount_bucket_commitment: &str,
        forced_exit_claim_id: &str,
        scan_height: u64,
        hint_ciphertext_root: &str,
    ) -> Self {
        let hint_id = note_hint_id(
            wallet_id,
            note_commitment,
            view_tag,
            subaddress_hint,
            forced_exit_claim_id,
            scan_height,
        );
        Self {
            hint_id,
            wallet_id: wallet_id.to_string(),
            note_commitment: note_commitment.to_string(),
            view_tag: view_tag.to_string(),
            subaddress_hint: subaddress_hint.to_string(),
            amount_bucket_commitment: amount_bucket_commitment.to_string(),
            forced_exit_claim_id: forced_exit_claim_id.to_string(),
            scan_height,
            hint_ciphertext_root: hint_ciphertext_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_visible_note_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "hint_id": self.hint_id,
            "wallet_id": self.wallet_id,
            "note_commitment": self.note_commitment,
            "view_tag": self.view_tag,
            "subaddress_hint": self.subaddress_hint,
            "amount_bucket_commitment": self.amount_bucket_commitment,
            "forced_exit_claim_id": self.forced_exit_claim_id,
            "scan_height": self.scan_height,
            "hint_ciphertext_root": self.hint_ciphertext_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteHintSet {
    pub set_id: String,
    pub wallet_id: String,
    pub scan_epoch: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub forced_exit_spine_root: String,
    pub hints: Vec<NoteHint>,
    pub operator_attestation_root: String,
}

impl NoteHintSet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        scan_epoch: u64,
        first_height: u64,
        last_height: u64,
        forced_exit_spine_root: &str,
        hints: Vec<NoteHint>,
        operator_attestation_root: &str,
    ) -> Self {
        let hint_root = note_hint_root(&hints);
        let set_id = note_hint_set_id(
            wallet_id,
            scan_epoch,
            first_height,
            last_height,
            forced_exit_spine_root,
            &hint_root,
        );
        Self {
            set_id,
            wallet_id: wallet_id.to_string(),
            scan_epoch,
            first_height,
            last_height,
            forced_exit_spine_root: forced_exit_spine_root.to_string(),
            hints,
            operator_attestation_root: operator_attestation_root.to_string(),
        }
    }

    pub fn hint_root(&self) -> String {
        note_hint_root(&self.hints)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_visible_note_hint_set",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "set_id": self.set_id,
            "wallet_id": self.wallet_id,
            "scan_epoch": self.scan_epoch,
            "first_height": self.first_height,
            "last_height": self.last_height,
            "forced_exit_spine_root": self.forced_exit_spine_root,
            "hint_root": self.hint_root(),
            "operator_attestation_root": self.operator_attestation_root,
            "hint_count": self.hints.len() as u64,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedScanWindow {
    pub window_id: String,
    pub wallet_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub ciphertext_root: String,
    pub note_hint_set_id: String,
    pub recovery_policy_id: String,
    pub scan_key_commitment: String,
    pub encrypted_payload_bytes: u64,
}

impl EncryptedScanWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        start_height: u64,
        end_height: u64,
        ciphertext_root: &str,
        note_hint_set_id: &str,
        recovery_policy_id: &str,
        scan_key_commitment: &str,
        encrypted_payload_bytes: u64,
    ) -> Self {
        let window_id = encrypted_scan_window_id(
            wallet_id,
            start_height,
            end_height,
            ciphertext_root,
            note_hint_set_id,
        );
        Self {
            window_id,
            wallet_id: wallet_id.to_string(),
            start_height,
            end_height,
            ciphertext_root: ciphertext_root.to_string(),
            note_hint_set_id: note_hint_set_id.to_string(),
            recovery_policy_id: recovery_policy_id.to_string(),
            scan_key_commitment: scan_key_commitment.to_string(),
            encrypted_payload_bytes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_wallet_scan_window",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "wallet_id": self.wallet_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "ciphertext_root": self.ciphertext_root,
            "note_hint_set_id": self.note_hint_set_id,
            "recovery_policy_id": self.recovery_policy_id,
            "scan_key_commitment": self.scan_key_commitment,
            "encrypted_payload_bytes": self.encrypted_payload_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveFeedLink {
    pub feed_link_id: String,
    pub wallet_id: String,
    pub source_feed_id: String,
    pub forced_exit_spine_root: String,
    pub latest_height: u64,
    pub latest_scan_window_id: String,
    pub delivery_commitment_root: String,
}

impl LiveFeedLink {
    pub fn new(
        wallet_id: &str,
        source_feed_id: &str,
        forced_exit_spine_root: &str,
        latest_height: u64,
        latest_scan_window_id: &str,
        delivery_commitment_root: &str,
    ) -> Self {
        let feed_link_id = live_feed_link_id(
            wallet_id,
            source_feed_id,
            forced_exit_spine_root,
            latest_height,
            latest_scan_window_id,
        );
        Self {
            feed_link_id,
            wallet_id: wallet_id.to_string(),
            source_feed_id: source_feed_id.to_string(),
            forced_exit_spine_root: forced_exit_spine_root.to_string(),
            latest_height,
            latest_scan_window_id: latest_scan_window_id.to_string(),
            delivery_commitment_root: delivery_commitment_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_live_feed_link",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "feed_link_id": self.feed_link_id,
            "wallet_id": self.wallet_id,
            "source_feed_id": self.source_feed_id,
            "forced_exit_spine_root": self.forced_exit_spine_root,
            "latest_height": self.latest_height,
            "latest_scan_window_id": self.latest_scan_window_id,
            "delivery_commitment_root": self.delivery_commitment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedReceiptLink {
    pub receipt_link_id: String,
    pub wallet_id: String,
    pub forced_exit_claim_id: String,
    pub receipt_root: String,
    pub observed_height: u64,
    pub note_hint_id: String,
    pub live_feed_link_id: String,
    pub canonicality_witness_root: String,
}

impl ObservedReceiptLink {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        forced_exit_claim_id: &str,
        receipt_root: &str,
        observed_height: u64,
        note_hint_id: &str,
        live_feed_link_id: &str,
        canonicality_witness_root: &str,
    ) -> Self {
        let receipt_link_id = observed_receipt_link_id(
            wallet_id,
            forced_exit_claim_id,
            receipt_root,
            observed_height,
            note_hint_id,
        );
        Self {
            receipt_link_id,
            wallet_id: wallet_id.to_string(),
            forced_exit_claim_id: forced_exit_claim_id.to_string(),
            receipt_root: receipt_root.to_string(),
            observed_height,
            note_hint_id: note_hint_id.to_string(),
            live_feed_link_id: live_feed_link_id.to_string(),
            canonicality_witness_root: canonicality_witness_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_observed_forced_exit_receipt_link",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "receipt_link_id": self.receipt_link_id,
            "wallet_id": self.wallet_id,
            "forced_exit_claim_id": self.forced_exit_claim_id,
            "receipt_root": self.receipt_root,
            "observed_height": self.observed_height,
            "note_hint_id": self.note_hint_id,
            "live_feed_link_id": self.live_feed_link_id,
            "canonicality_witness_root": self.canonicality_witness_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub wallet_id: String,
    pub window_id: String,
    pub epsilon_micros_limit: u64,
    pub epsilon_micros_used: u64,
    pub delta_nanos_limit: u64,
    pub delta_nanos_used: u64,
    pub linkability_class: String,
    pub leak_check_root: String,
}

impl PrivacyBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        window_id: &str,
        epsilon_micros_limit: u64,
        epsilon_micros_used: u64,
        delta_nanos_limit: u64,
        delta_nanos_used: u64,
        linkability_class: &str,
        leak_check_root: &str,
    ) -> Self {
        let budget_id = privacy_budget_id(wallet_id, window_id, linkability_class, leak_check_root);
        Self {
            budget_id,
            wallet_id: wallet_id.to_string(),
            window_id: window_id.to_string(),
            epsilon_micros_limit,
            epsilon_micros_used,
            delta_nanos_limit,
            delta_nanos_used,
            linkability_class: linkability_class.to_string(),
            leak_check_root: leak_check_root.to_string(),
        }
    }

    pub fn exceeded(&self) -> bool {
        self.epsilon_micros_used > self.epsilon_micros_limit
            || self.delta_nanos_used > self.delta_nanos_limit
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_scan_privacy_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "wallet_id": self.wallet_id,
            "window_id": self.window_id,
            "epsilon_micros_limit": self.epsilon_micros_limit,
            "epsilon_micros_used": self.epsilon_micros_used,
            "delta_nanos_limit": self.delta_nanos_limit,
            "delta_nanos_used": self.delta_nanos_used,
            "linkability_class": self.linkability_class,
            "leak_check_root": self.leak_check_root,
            "exceeded": self.exceeded(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub wallet_id: String,
    pub forced_exit_claim_id: String,
    pub expected_root: String,
    pub observed_root: String,
    pub mismatch_kind: String,
    pub severity: String,
    pub detected_height: u64,
    pub release_blocking: bool,
}

impl MismatchRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        forced_exit_claim_id: &str,
        expected_root: &str,
        observed_root: &str,
        mismatch_kind: &str,
        severity: &str,
        detected_height: u64,
        release_blocking: bool,
    ) -> Self {
        let mismatch_id = mismatch_record_id(
            wallet_id,
            forced_exit_claim_id,
            expected_root,
            observed_root,
            mismatch_kind,
            detected_height,
        );
        Self {
            mismatch_id,
            wallet_id: wallet_id.to_string(),
            forced_exit_claim_id: forced_exit_claim_id.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            mismatch_kind: mismatch_kind.to_string(),
            severity: severity.to_string(),
            detected_height,
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_scan_mismatch_record",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "mismatch_id": self.mismatch_id,
            "wallet_id": self.wallet_id,
            "forced_exit_claim_id": self.forced_exit_claim_id,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "mismatch_kind": self.mismatch_kind,
            "severity": self.severity,
            "detected_height": self.detected_height,
            "release_blocking": self.release_blocking,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryExportPayload {
    pub export_id: String,
    pub wallet_id: String,
    pub recovery_policy_id: String,
    pub export_epoch: u64,
    pub note_hint_set_root: String,
    pub encrypted_window_root: String,
    pub observed_receipt_root: String,
    pub privacy_budget_root: String,
    pub payload_ciphertext_root: String,
    pub payload_manifest_root: String,
    pub payload_bytes: u64,
}

impl RecoveryExportPayload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        recovery_policy_id: &str,
        export_epoch: u64,
        note_hint_set_root: &str,
        encrypted_window_root: &str,
        observed_receipt_root: &str,
        privacy_budget_root: &str,
        payload_ciphertext_root: &str,
        payload_manifest_root: &str,
        payload_bytes: u64,
    ) -> Self {
        let export_id = recovery_export_id(
            wallet_id,
            recovery_policy_id,
            export_epoch,
            note_hint_set_root,
            payload_ciphertext_root,
        );
        Self {
            export_id,
            wallet_id: wallet_id.to_string(),
            recovery_policy_id: recovery_policy_id.to_string(),
            export_epoch,
            note_hint_set_root: note_hint_set_root.to_string(),
            encrypted_window_root: encrypted_window_root.to_string(),
            observed_receipt_root: observed_receipt_root.to_string(),
            privacy_budget_root: privacy_budget_root.to_string(),
            payload_ciphertext_root: payload_ciphertext_root.to_string(),
            payload_manifest_root: payload_manifest_root.to_string(),
            payload_bytes,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "user_recovery_export_payload",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "export_id": self.export_id,
            "wallet_id": self.wallet_id,
            "recovery_policy_id": self.recovery_policy_id,
            "export_epoch": self.export_epoch,
            "note_hint_set_root": self.note_hint_set_root,
            "encrypted_window_root": self.encrypted_window_root,
            "observed_receipt_root": self.observed_receipt_root,
            "privacy_budget_root": self.privacy_budget_root,
            "payload_ciphertext_root": self.payload_ciphertext_root,
            "payload_manifest_root": self.payload_manifest_root,
            "payload_bytes": self.payload_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub wallet_id: String,
    pub export_id: String,
    pub reason: String,
    pub mismatch_root: String,
    pub privacy_budget_root: String,
    pub opened_height: u64,
    pub release_after_height: u64,
    pub active: bool,
}

impl ReleaseHold {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        export_id: &str,
        reason: &str,
        mismatch_root: &str,
        privacy_budget_root: &str,
        opened_height: u64,
        release_after_height: u64,
        active: bool,
    ) -> Self {
        let hold_id = release_hold_id(
            wallet_id,
            export_id,
            reason,
            mismatch_root,
            opened_height,
            release_after_height,
        );
        Self {
            hold_id,
            wallet_id: wallet_id.to_string(),
            export_id: export_id.to_string(),
            reason: reason.to_string(),
            mismatch_root: mismatch_root.to_string(),
            privacy_budget_root: privacy_budget_root.to_string(),
            opened_height,
            release_after_height,
            active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_recovery_export_release_hold",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "hold_id": self.hold_id,
            "wallet_id": self.wallet_id,
            "export_id": self.export_id,
            "reason": self.reason,
            "mismatch_root": self.mismatch_root,
            "privacy_budget_root": self.privacy_budget_root,
            "opened_height": self.opened_height,
            "release_after_height": self.release_after_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub note_hint_root: String,
    pub note_hint_set_root: String,
    pub encrypted_scan_window_root: String,
    pub live_feed_root: String,
    pub observed_receipt_root: String,
    pub privacy_budget_root: String,
    pub mismatch_record_root: String,
    pub recovery_export_root: String,
    pub release_hold_root: String,
    pub wallet_scan_output_root: String,
    pub forced_exit_binding_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_scan_recovery_export_binding_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "note_hint_root": self.note_hint_root,
            "note_hint_set_root": self.note_hint_set_root,
            "encrypted_scan_window_root": self.encrypted_scan_window_root,
            "live_feed_root": self.live_feed_root,
            "observed_receipt_root": self.observed_receipt_root,
            "privacy_budget_root": self.privacy_budget_root,
            "mismatch_record_root": self.mismatch_record_root,
            "recovery_export_root": self.recovery_export_root,
            "release_hold_root": self.release_hold_root,
            "wallet_scan_output_root": self.wallet_scan_output_root,
            "forced_exit_binding_root": self.forced_exit_binding_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub note_hint_sets: Vec<NoteHintSet>,
    pub encrypted_scan_windows: Vec<EncryptedScanWindow>,
    pub live_feed_links: Vec<LiveFeedLink>,
    pub observed_receipt_links: Vec<ObservedReceiptLink>,
    pub privacy_budgets: Vec<PrivacyBudget>,
    pub mismatch_records: Vec<MismatchRecord>,
    pub recovery_exports: Vec<RecoveryExportPayload>,
    pub release_holds: Vec<ReleaseHold>,
    pub wallet_index: BTreeMap<String, Vec<String>>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            note_hint_sets: Vec::new(),
            encrypted_scan_windows: Vec::new(),
            live_feed_links: Vec::new(),
            observed_receipt_links: Vec::new(),
            privacy_budgets: Vec::new(),
            mismatch_records: Vec::new(),
            recovery_exports: Vec::new(),
            release_holds: Vec::new(),
            wallet_index: BTreeMap::new(),
        }
    }

    pub fn bind_hint_set(&mut self, hint_set: NoteHintSet) -> Result<()> {
        if hint_set.last_height < hint_set.first_height {
            return Err("note hint set height range is inverted".to_string());
        }
        let span = hint_set.last_height.saturating_sub(hint_set.first_height);
        if span > self.config.max_encrypted_window_span {
            return Err("note hint set exceeds configured scan span".to_string());
        }
        let wallet_id = hint_set.wallet_id.clone();
        let set_id = hint_set.set_id.clone();
        self.note_hint_sets.push(hint_set);
        self.wallet_index.entry(wallet_id).or_default().push(set_id);
        Ok(())
    }

    pub fn bind_encrypted_scan_window(&mut self, window: EncryptedScanWindow) -> Result<()> {
        if window.end_height < window.start_height {
            return Err("encrypted scan window height range is inverted".to_string());
        }
        let span = window.end_height.saturating_sub(window.start_height);
        if span > self.config.max_encrypted_window_span {
            return Err("encrypted scan window exceeds configured span".to_string());
        }
        self.encrypted_scan_windows.push(window);
        Ok(())
    }

    pub fn bind_live_feed_link(&mut self, link: LiveFeedLink) -> Result<()> {
        if link.forced_exit_spine_root != self.config.forced_exit_spine_root {
            return Err("live feed link is not bound to configured forced-exit spine".to_string());
        }
        self.live_feed_links.push(link);
        Ok(())
    }

    pub fn bind_observed_receipt_link(&mut self, link: ObservedReceiptLink) -> Result<()> {
        self.observed_receipt_links.push(link);
        Ok(())
    }

    pub fn bind_privacy_budget(&mut self, budget: PrivacyBudget) -> Result<()> {
        if budget.epsilon_micros_limit > self.config.privacy_budget_epsilon_micros {
            return Err("privacy budget epsilon limit exceeds config".to_string());
        }
        if budget.delta_nanos_limit > self.config.privacy_budget_delta_nanos {
            return Err("privacy budget delta limit exceeds config".to_string());
        }
        self.privacy_budgets.push(budget);
        Ok(())
    }

    pub fn bind_mismatch_record(&mut self, record: MismatchRecord) -> Result<()> {
        self.mismatch_records.push(record);
        Ok(())
    }

    pub fn bind_recovery_export(&mut self, export: RecoveryExportPayload) -> Result<()> {
        if export.payload_bytes > self.config.max_recovery_export_bytes {
            return Err("recovery export payload exceeds configured byte limit".to_string());
        }
        self.recovery_exports.push(export);
        Ok(())
    }

    pub fn bind_release_hold(&mut self, hold: ReleaseHold) -> Result<()> {
        self.release_holds.push(hold);
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        let note_records = self
            .note_hint_sets
            .iter()
            .flat_map(|set| set.hints.iter().map(NoteHint::public_record))
            .collect::<Vec<_>>();
        let hint_set_records = records(&self.note_hint_sets);
        let window_records = records(&self.encrypted_scan_windows);
        let live_feed_records = records(&self.live_feed_links);
        let receipt_records = records(&self.observed_receipt_links);
        let budget_records = records(&self.privacy_budgets);
        let mismatch_records = records(&self.mismatch_records);
        let export_records = records(&self.recovery_exports);
        let hold_records = records(&self.release_holds);

        let note_hint_root = merkle_root("WALLET-SCAN-NOTE-HINT", &note_records);
        let note_hint_set_root = merkle_root("WALLET-SCAN-NOTE-HINT-SET", &hint_set_records);
        let encrypted_scan_window_root =
            merkle_root("WALLET-SCAN-ENCRYPTED-WINDOW", &window_records);
        let live_feed_root = merkle_root("WALLET-SCAN-LIVE-FEED", &live_feed_records);
        let observed_receipt_root = merkle_root("WALLET-SCAN-OBSERVED-RECEIPT", &receipt_records);
        let privacy_budget_root = merkle_root("WALLET-SCAN-PRIVACY-BUDGET", &budget_records);
        let mismatch_record_root = merkle_root("WALLET-SCAN-MISMATCH", &mismatch_records);
        let recovery_export_root = merkle_root("WALLET-SCAN-RECOVERY-EXPORT", &export_records);
        let release_hold_root = merkle_root("WALLET-SCAN-RELEASE-HOLD", &hold_records);
        let config_root = self.config.config_root();
        let wallet_scan_output_root = wallet_scan_output_root(
            &note_hint_root,
            &note_hint_set_root,
            &encrypted_scan_window_root,
            &live_feed_root,
            &observed_receipt_root,
            &privacy_budget_root,
            &recovery_export_root,
        );
        let forced_exit_binding_root = forced_exit_binding_root(
            &config_root,
            &self.config.forced_exit_spine_root,
            &wallet_scan_output_root,
            &mismatch_record_root,
            &release_hold_root,
        );

        Roots {
            config_root,
            note_hint_root,
            note_hint_set_root,
            encrypted_scan_window_root,
            live_feed_root,
            observed_receipt_root,
            privacy_budget_root,
            mismatch_record_root,
            recovery_export_root,
            release_hold_root,
            wallet_scan_output_root,
            forced_exit_binding_root,
        }
    }

    pub fn release_ready(&self, export_id: &str) -> bool {
        let active_hold = self
            .release_holds
            .iter()
            .any(|hold| hold.export_id == export_id && hold.active);
        let blocking_mismatch = self
            .mismatch_records
            .iter()
            .any(|record| record.release_blocking);
        let exceeded_budget = self.privacy_budgets.iter().any(PrivacyBudget::exceeded);
        !active_hold
            && !exceeded_budget
            && (!blocking_mismatch || self.config.allow_release_with_mismatch_records)
    }

    pub fn public_record(&self) -> Value {
        let wallet_index = self
            .wallet_index
            .iter()
            .map(|(wallet_id, set_ids)| {
                json!({
                    "wallet_id": wallet_id,
                    "hint_set_ids": set_ids,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_wallet_scan_recovery_export_binding_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_SCAN_RECOVERY_EXPORT_BINDING_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "note_hint_set_count": self.note_hint_sets.len() as u64,
            "encrypted_scan_window_count": self.encrypted_scan_windows.len() as u64,
            "live_feed_link_count": self.live_feed_links.len() as u64,
            "observed_receipt_link_count": self.observed_receipt_links.len() as u64,
            "privacy_budget_count": self.privacy_budgets.len() as u64,
            "mismatch_record_count": self.mismatch_records.len() as u64,
            "recovery_export_count": self.recovery_exports.len() as u64,
            "release_hold_count": self.release_holds.len() as u64,
            "wallet_index_root": merkle_root("WALLET-SCAN-WALLET-INDEX", &wallet_index),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "WALLET-SCAN-RECOVERY-EXPORT-BINDING-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let mut state = State::new(config.clone());
    let wallet_a = "wallet-alpha-pq-view";
    let wallet_b = "wallet-beta-recovery-view";
    let claim_a = forced_exit_claim_id(wallet_a, 42_000, "monero-exit-note-a");
    let claim_b = forced_exit_claim_id(wallet_b, 42_006, "monero-exit-note-b");

    let hint_a = NoteHint::new(
        wallet_a,
        "note-commitment-alpha",
        "viewtag-4a",
        "subaddress-hint-main-7",
        "amount-bucket-root-alpha",
        &claim_a,
        42_012,
        &sample_root("hint-ciphertext-alpha"),
    );
    let hint_b = NoteHint::new(
        wallet_b,
        "note-commitment-beta",
        "viewtag-51",
        "subaddress-hint-recovery-2",
        "amount-bucket-root-beta",
        &claim_b,
        42_018,
        &sample_root("hint-ciphertext-beta"),
    );

    let hint_set_a = NoteHintSet::new(
        wallet_a,
        7,
        42_000,
        42_120,
        &config.forced_exit_spine_root,
        vec![hint_a.clone()],
        &sample_root("operator-attestation-alpha"),
    );
    let hint_set_b = NoteHintSet::new(
        wallet_b,
        7,
        42_000,
        42_120,
        &config.forced_exit_spine_root,
        vec![hint_b.clone()],
        &sample_root("operator-attestation-beta"),
    );

    let window_a = EncryptedScanWindow::new(
        wallet_a,
        42_000,
        42_120,
        &sample_root("window-ciphertext-alpha"),
        &hint_set_a.set_id,
        "recovery-policy-alpha",
        &sample_root("scan-key-alpha"),
        8192,
    );
    let window_b = EncryptedScanWindow::new(
        wallet_b,
        42_000,
        42_120,
        &sample_root("window-ciphertext-beta"),
        &hint_set_b.set_id,
        "recovery-policy-beta",
        &sample_root("scan-key-beta"),
        8192,
    );

    let live_a = LiveFeedLink::new(
        wallet_a,
        "watchtower-feed-east",
        &config.forced_exit_spine_root,
        42_121,
        &window_a.window_id,
        &sample_root("delivery-alpha"),
    );
    let live_b = LiveFeedLink::new(
        wallet_b,
        "watchtower-feed-west",
        &config.forced_exit_spine_root,
        42_121,
        &window_b.window_id,
        &sample_root("delivery-beta"),
    );

    let receipt_a = ObservedReceiptLink::new(
        wallet_a,
        &claim_a,
        &sample_root("receipt-alpha"),
        42_122,
        &hint_a.hint_id,
        &live_a.feed_link_id,
        &sample_root("canonicality-alpha"),
    );
    let receipt_b = ObservedReceiptLink::new(
        wallet_b,
        &claim_b,
        &sample_root("receipt-beta"),
        42_123,
        &hint_b.hint_id,
        &live_b.feed_link_id,
        &sample_root("canonicality-beta"),
    );

    let budget_a = PrivacyBudget::new(
        wallet_a,
        &window_a.window_id,
        config.privacy_budget_epsilon_micros,
        11_000,
        config.privacy_budget_delta_nanos,
        3,
        "single-wallet-forced-exit-scan",
        &sample_root("leak-check-alpha"),
    );
    let budget_b = PrivacyBudget::new(
        wallet_b,
        &window_b.window_id,
        config.privacy_budget_epsilon_micros,
        13_000,
        config.privacy_budget_delta_nanos,
        4,
        "single-wallet-forced-exit-scan",
        &sample_root("leak-check-beta"),
    );

    let mismatch = MismatchRecord::new(
        wallet_b,
        &claim_b,
        &sample_root("receipt-beta"),
        &sample_root("receipt-beta-late-feed"),
        "receipt-live-feed-lag",
        "warning",
        42_124,
        false,
    );

    state.bind_hint_set(hint_set_a).ok();
    state.bind_hint_set(hint_set_b).ok();
    state.bind_encrypted_scan_window(window_a.clone()).ok();
    state.bind_encrypted_scan_window(window_b.clone()).ok();
    state.bind_live_feed_link(live_a).ok();
    state.bind_live_feed_link(live_b).ok();
    state.bind_observed_receipt_link(receipt_a).ok();
    state.bind_observed_receipt_link(receipt_b).ok();
    state.bind_privacy_budget(budget_a).ok();
    state.bind_privacy_budget(budget_b).ok();
    state.bind_mismatch_record(mismatch).ok();

    let roots = state.roots();
    let export_a = RecoveryExportPayload::new(
        wallet_a,
        "recovery-policy-alpha",
        7,
        &roots.note_hint_set_root,
        &roots.encrypted_scan_window_root,
        &roots.observed_receipt_root,
        &roots.privacy_budget_root,
        &sample_root("payload-ciphertext-alpha"),
        &sample_root("payload-manifest-alpha"),
        24_576,
    );
    let export_b = RecoveryExportPayload::new(
        wallet_b,
        "recovery-policy-beta",
        7,
        &roots.note_hint_set_root,
        &roots.encrypted_scan_window_root,
        &roots.observed_receipt_root,
        &roots.privacy_budget_root,
        &sample_root("payload-ciphertext-beta"),
        &sample_root("payload-manifest-beta"),
        24_576,
    );
    let hold_b = ReleaseHold::new(
        wallet_b,
        &export_b.export_id,
        "nonblocking-receipt-lag-review",
        &state.roots().mismatch_record_root,
        &state.roots().privacy_budget_root,
        42_124,
        42_136,
        true,
    );

    state.bind_recovery_export(export_a).ok();
    state.bind_recovery_export(export_b).ok();
    state.bind_release_hold(hold_b).ok();
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn records<T>(items: &[T]) -> Vec<Value>
where
    T: PublicRecord,
{
    items.iter().map(PublicRecord::public_record).collect()
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for NoteHintSet {
    fn public_record(&self) -> Value {
        NoteHintSet::public_record(self)
    }
}

impl PublicRecord for EncryptedScanWindow {
    fn public_record(&self) -> Value {
        EncryptedScanWindow::public_record(self)
    }
}

impl PublicRecord for LiveFeedLink {
    fn public_record(&self) -> Value {
        LiveFeedLink::public_record(self)
    }
}

impl PublicRecord for ObservedReceiptLink {
    fn public_record(&self) -> Value {
        ObservedReceiptLink::public_record(self)
    }
}

impl PublicRecord for PrivacyBudget {
    fn public_record(&self) -> Value {
        PrivacyBudget::public_record(self)
    }
}

impl PublicRecord for MismatchRecord {
    fn public_record(&self) -> Value {
        MismatchRecord::public_record(self)
    }
}

impl PublicRecord for RecoveryExportPayload {
    fn public_record(&self) -> Value {
        RecoveryExportPayload::public_record(self)
    }
}

impl PublicRecord for ReleaseHold {
    fn public_record(&self) -> Value {
        ReleaseHold::public_record(self)
    }
}

fn note_hint_root(hints: &[NoteHint]) -> String {
    let records = hints
        .iter()
        .map(NoteHint::public_record)
        .collect::<Vec<_>>();
    merkle_root("WALLET-SCAN-NOTE-HINT-IN-SET", &records)
}

fn wallet_scan_output_root(
    note_hint_root: &str,
    note_hint_set_root: &str,
    encrypted_scan_window_root: &str,
    live_feed_root: &str,
    observed_receipt_root: &str,
    privacy_budget_root: &str,
    recovery_export_root: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-OUTPUT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(note_hint_root),
            HashPart::Str(note_hint_set_root),
            HashPart::Str(encrypted_scan_window_root),
            HashPart::Str(live_feed_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Str(privacy_budget_root),
            HashPart::Str(recovery_export_root),
        ],
        32,
    )
}

fn forced_exit_binding_root(
    config_root: &str,
    forced_exit_spine_root: &str,
    wallet_scan_output_root: &str,
    mismatch_record_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        "FORCED-EXIT-WALLET-SCAN-RECOVERY-BINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(config_root),
            HashPart::Str(forced_exit_spine_root),
            HashPart::Str(wallet_scan_output_root),
            HashPart::Str(mismatch_record_root),
            HashPart::Str(release_hold_root),
        ],
        32,
    )
}

fn note_hint_id(
    wallet_id: &str,
    note_commitment: &str,
    view_tag: &str,
    subaddress_hint: &str,
    forced_exit_claim_id: &str,
    scan_height: u64,
) -> String {
    domain_hash(
        "WALLET-SCAN-NOTE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(note_commitment),
            HashPart::Str(view_tag),
            HashPart::Str(subaddress_hint),
            HashPart::Str(forced_exit_claim_id),
            HashPart::U64(scan_height),
        ],
        32,
    )
}

fn note_hint_set_id(
    wallet_id: &str,
    scan_epoch: u64,
    first_height: u64,
    last_height: u64,
    forced_exit_spine_root: &str,
    hint_root: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-NOTE-HINT-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::U64(scan_epoch),
            HashPart::U64(first_height),
            HashPart::U64(last_height),
            HashPart::Str(forced_exit_spine_root),
            HashPart::Str(hint_root),
        ],
        32,
    )
}

fn encrypted_scan_window_id(
    wallet_id: &str,
    start_height: u64,
    end_height: u64,
    ciphertext_root: &str,
    note_hint_set_id: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-ENCRYPTED-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::U64(start_height),
            HashPart::U64(end_height),
            HashPart::Str(ciphertext_root),
            HashPart::Str(note_hint_set_id),
        ],
        32,
    )
}

fn live_feed_link_id(
    wallet_id: &str,
    source_feed_id: &str,
    forced_exit_spine_root: &str,
    latest_height: u64,
    latest_scan_window_id: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-LIVE-FEED-LINK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(source_feed_id),
            HashPart::Str(forced_exit_spine_root),
            HashPart::U64(latest_height),
            HashPart::Str(latest_scan_window_id),
        ],
        32,
    )
}

fn observed_receipt_link_id(
    wallet_id: &str,
    forced_exit_claim_id: &str,
    receipt_root: &str,
    observed_height: u64,
    note_hint_id: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-OBSERVED-RECEIPT-LINK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(forced_exit_claim_id),
            HashPart::Str(receipt_root),
            HashPart::U64(observed_height),
            HashPart::Str(note_hint_id),
        ],
        32,
    )
}

fn privacy_budget_id(
    wallet_id: &str,
    window_id: &str,
    linkability_class: &str,
    leak_check_root: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(window_id),
            HashPart::Str(linkability_class),
            HashPart::Str(leak_check_root),
        ],
        32,
    )
}

fn mismatch_record_id(
    wallet_id: &str,
    forced_exit_claim_id: &str,
    expected_root: &str,
    observed_root: &str,
    mismatch_kind: &str,
    detected_height: u64,
) -> String {
    domain_hash(
        "WALLET-SCAN-MISMATCH-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(forced_exit_claim_id),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Str(mismatch_kind),
            HashPart::U64(detected_height),
        ],
        32,
    )
}

fn recovery_export_id(
    wallet_id: &str,
    recovery_policy_id: &str,
    export_epoch: u64,
    note_hint_set_root: &str,
    payload_ciphertext_root: &str,
) -> String {
    domain_hash(
        "WALLET-SCAN-RECOVERY-EXPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(recovery_policy_id),
            HashPart::U64(export_epoch),
            HashPart::Str(note_hint_set_root),
            HashPart::Str(payload_ciphertext_root),
        ],
        32,
    )
}

fn release_hold_id(
    wallet_id: &str,
    export_id: &str,
    reason: &str,
    mismatch_root: &str,
    opened_height: u64,
    release_after_height: u64,
) -> String {
    domain_hash(
        "WALLET-SCAN-RECOVERY-RELEASE-HOLD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::Str(export_id),
            HashPart::Str(reason),
            HashPart::Str(mismatch_root),
            HashPart::U64(opened_height),
            HashPart::U64(release_after_height),
        ],
        32,
    )
}

fn forced_exit_claim_id(wallet_id: &str, exit_height: u64, note_label: &str) -> String {
    domain_hash(
        "WALLET-SCAN-FORCED-EXIT-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_id),
            HashPart::U64(exit_height),
            HashPart::Str(note_label),
        ],
        32,
    )
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "WALLET-SCAN-RECOVERY-EXPORT-SAMPLE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}
