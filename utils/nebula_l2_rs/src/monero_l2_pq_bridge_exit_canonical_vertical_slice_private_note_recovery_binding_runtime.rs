use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateNoteRecoveryBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;
pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_NOTE_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-private-note-recovery-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_NOTE_RECOVERY_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-private-note-recovery-binding-runtime";
const DEFAULT_BRIDGE_SESSION_LABEL: &str = "canonical-vertical-slice-private-note-recovery";
const DEFAULT_RECOVERY_BINDING_ID: &str = "devnet-private-note-recovery-binding-0001";
const DEFAULT_FORCED_EXIT_ID: &str = "forced-exit-devnet-escape-spine-0001";
const DEFAULT_MIN_MONERO_FINALITY_DEPTH: u64 = 60;
const DEFAULT_RELEASE_HOLD_BLOCKS: u64 = 720;
const DEFAULT_MAX_ENCRYPTED_PAYLOAD_BYTES: u64 = 4_096;
const DEFAULT_MAX_WALLET_HINT_BYTES: u64 = 96;
const DEFAULT_MAX_METADATA_BYTES: u64 = 512;
const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u64 = 6_700;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub bridge_session_label: String,
    pub recovery_binding_id: String,
    pub forced_exit_id: String,
    pub min_monero_finality_depth: u64,
    pub min_watcher_weight_bps: u64,
    pub release_hold_blocks: u64,
    pub max_encrypted_payload_bytes: u64,
    pub max_wallet_hint_bytes: u64,
    pub max_metadata_bytes: u64,
    pub require_commitment_membership: bool,
    pub require_nullifier_fence: bool,
    pub require_receipt_link: bool,
    pub require_live_feed_link: bool,
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
            bridge_session_label: DEFAULT_BRIDGE_SESSION_LABEL.to_string(),
            recovery_binding_id: DEFAULT_RECOVERY_BINDING_ID.to_string(),
            forced_exit_id: DEFAULT_FORCED_EXIT_ID.to_string(),
            min_monero_finality_depth: DEFAULT_MIN_MONERO_FINALITY_DEPTH,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            release_hold_blocks: DEFAULT_RELEASE_HOLD_BLOCKS,
            max_encrypted_payload_bytes: DEFAULT_MAX_ENCRYPTED_PAYLOAD_BYTES,
            max_wallet_hint_bytes: DEFAULT_MAX_WALLET_HINT_BYTES,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            require_commitment_membership: true,
            require_nullifier_fence: true,
            require_receipt_link: true,
            require_live_feed_link: true,
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
            "bridge_session_label": self.bridge_session_label,
            "recovery_binding_id": self.recovery_binding_id,
            "forced_exit_id": self.forced_exit_id,
            "min_monero_finality_depth": self.min_monero_finality_depth,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "release_hold_blocks": self.release_hold_blocks,
            "max_encrypted_payload_bytes": self.max_encrypted_payload_bytes,
            "max_wallet_hint_bytes": self.max_wallet_hint_bytes,
            "max_metadata_bytes": self.max_metadata_bytes,
            "require_commitment_membership": self.require_commitment_membership,
            "require_nullifier_fence": self.require_nullifier_fence,
            "require_receipt_link": self.require_receipt_link,
            "require_live_feed_link": self.require_live_feed_link,
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
pub struct RecoveredNoteCommitment {
    pub note_id: String,
    pub deposit_lock_root: String,
    pub private_note_root: String,
    pub recovery_transcript_root: String,
    pub commitment_root: String,
    pub amount_piconero_commitment: String,
    pub note_index: u64,
    pub recovered_at_l2_height: u64,
}
impl RecoveredNoteCommitment {
    pub fn devnet(note_id: &str, note_index: u64, recovered_at_l2_height: u64) -> Self {
        let deposit_lock_root = label_root("deposit_lock", note_id);
        let private_note_root = label_root("private_note", note_id);
        let recovery_transcript_root = label_root("recovery_transcript", note_id);
        let amount_piconero_commitment = label_root("amount_commitment", note_id);
        let commitment_root = domain_hash(
            &format!("{DOMAIN}:recovered-note-commitment"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(&deposit_lock_root),
                HashPart::Str(&private_note_root),
                HashPart::Str(&recovery_transcript_root),
                HashPart::Str(&amount_piconero_commitment),
                HashPart::U64(note_index),
                HashPart::U64(recovered_at_l2_height),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            deposit_lock_root,
            private_note_root,
            recovery_transcript_root,
            commitment_root,
            amount_piconero_commitment,
            note_index,
            recovered_at_l2_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "deposit_lock_root": self.deposit_lock_root,
            "private_note_root": self.private_note_root,
            "recovery_transcript_root": self.recovery_transcript_root,
            "commitment_root": self.commitment_root,
            "amount_piconero_commitment": self.amount_piconero_commitment,
            "note_index": self.note_index,
            "recovered_at_l2_height": self.recovered_at_l2_height,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub note_id: String,
    pub nullifier_root: String,
    pub spent_set_snapshot_root: String,
    pub forced_exit_fence_root: String,
    pub duplicate_rejection_root: String,
    pub fence_epoch: u64,
    pub first_valid_l2_height: u64,
    pub last_valid_l2_height: u64,
}
impl NullifierFence {
    pub fn devnet(note_id: &str, fence_epoch: u64, first_valid_l2_height: u64) -> Self {
        let nullifier_root = label_root("nullifier", note_id);
        let spent_set_snapshot_root = label_root("spent_set_snapshot", note_id);
        let duplicate_rejection_root = label_root("duplicate_rejection", note_id);
        let last_valid_l2_height = first_valid_l2_height + DEFAULT_RELEASE_HOLD_BLOCKS;
        let forced_exit_fence_root = domain_hash(
            &format!("{DOMAIN}:nullifier-fence"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&spent_set_snapshot_root),
                HashPart::Str(&duplicate_rejection_root),
                HashPart::U64(fence_epoch),
                HashPart::U64(first_valid_l2_height),
                HashPart::U64(last_valid_l2_height),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            nullifier_root,
            spent_set_snapshot_root,
            forced_exit_fence_root,
            duplicate_rejection_root,
            fence_epoch,
            first_valid_l2_height,
            last_valid_l2_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "nullifier_root": self.nullifier_root,
            "spent_set_snapshot_root": self.spent_set_snapshot_root,
            "forced_exit_fence_root": self.forced_exit_fence_root,
            "duplicate_rejection_root": self.duplicate_rejection_root,
            "fence_epoch": self.fence_epoch,
            "first_valid_l2_height": self.first_valid_l2_height,
            "last_valid_l2_height": self.last_valid_l2_height,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedNotePayload {
    pub note_id: String,
    pub ciphertext_root: String,
    pub payload_commitment_root: String,
    pub encryption_context_root: String,
    pub pq_kem_ciphertext_root: String,
    pub payload_bytes: u64,
    pub payload_version: String,
}
impl EncryptedNotePayload {
    pub fn devnet(note_id: &str, payload_bytes: u64) -> Self {
        let ciphertext_root = label_root("ciphertext", note_id);
        let encryption_context_root = label_root("encryption_context", note_id);
        let pq_kem_ciphertext_root = label_root("pq_kem_ciphertext", note_id);
        let payload_version = "note-payload-v1".to_string();
        let payload_commitment_root = domain_hash(
            &format!("{DOMAIN}:encrypted-note-payload"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(&ciphertext_root),
                HashPart::Str(&encryption_context_root),
                HashPart::Str(&pq_kem_ciphertext_root),
                HashPart::U64(payload_bytes),
                HashPart::Str(&payload_version),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            ciphertext_root,
            payload_commitment_root,
            encryption_context_root,
            pq_kem_ciphertext_root,
            payload_bytes,
            payload_version,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "ciphertext_root": self.ciphertext_root,
            "payload_commitment_root": self.payload_commitment_root,
            "encryption_context_root": self.encryption_context_root,
            "pq_kem_ciphertext_root": self.pq_kem_ciphertext_root,
            "payload_bytes": self.payload_bytes,
            "payload_version": self.payload_version,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub note_id: String,
    pub hint_root: String,
    pub view_tag_root: String,
    pub scan_window_root: String,
    pub hint_bytes: u64,
    pub scan_from_monero_height: u64,
    pub scan_to_monero_height: u64,
}
impl WalletScanHint {
    pub fn devnet(note_id: &str, scan_from_monero_height: u64) -> Self {
        let hint_bytes = 48;
        let view_tag_root = label_root("view_tag", note_id);
        let scan_window_root = domain_hash(
            &format!("{DOMAIN}:wallet-scan-window"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(note_id),
                HashPart::U64(scan_from_monero_height),
                HashPart::U64(scan_from_monero_height + DEFAULT_MIN_MONERO_FINALITY_DEPTH),
            ],
            32,
        );
        let hint_root = domain_hash(
            &format!("{DOMAIN}:wallet-scan-hint"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(&view_tag_root),
                HashPart::Str(&scan_window_root),
                HashPart::U64(hint_bytes),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            hint_root,
            view_tag_root,
            scan_window_root,
            hint_bytes,
            scan_from_monero_height,
            scan_to_monero_height: scan_from_monero_height + DEFAULT_MIN_MONERO_FINALITY_DEPTH,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "hint_root": self.hint_root,
            "view_tag_root": self.view_tag_root,
            "scan_window_root": self.scan_window_root,
            "hint_bytes": self.hint_bytes,
            "scan_from_monero_height": self.scan_from_monero_height,
            "scan_to_monero_height": self.scan_to_monero_height,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceiptLink {
    pub note_id: String,
    pub observed_receipt_root: String,
    pub settlement_receipt_root: String,
    pub bridge_spine_root: String,
    pub link_root: String,
    pub observed_at_monero_height: u64,
    pub watcher_weight_bps: u64,
}
impl ObservedReceiptLink {
    pub fn devnet(note_id: &str, observed_at_monero_height: u64, watcher_weight_bps: u64) -> Self {
        let observed_receipt_root = label_root("observed_receipt", note_id);
        let settlement_receipt_root = label_root("settlement_receipt", note_id);
        let bridge_spine_root = label_root("bridge_forced_exit_spine", note_id);
        let link_root = domain_hash(
            &format!("{DOMAIN}:observed-receipt-link"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(&observed_receipt_root),
                HashPart::Str(&settlement_receipt_root),
                HashPart::Str(&bridge_spine_root),
                HashPart::U64(observed_at_monero_height),
                HashPart::U64(watcher_weight_bps),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            observed_receipt_root,
            settlement_receipt_root,
            bridge_spine_root,
            link_root,
            observed_at_monero_height,
            watcher_weight_bps,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "observed_receipt_root": self.observed_receipt_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "bridge_spine_root": self.bridge_spine_root,
            "link_root": self.link_root,
            "observed_at_monero_height": self.observed_at_monero_height,
            "watcher_weight_bps": self.watcher_weight_bps,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveFeedLink {
    pub note_id: String,
    pub feed_source: String,
    pub monero_header_root: String,
    pub l2_checkpoint_root: String,
    pub feed_link_root: String,
    pub monero_height: u64,
    pub l2_height: u64,
}
impl LiveFeedLink {
    pub fn devnet(note_id: &str, feed_source: &str, monero_height: u64, l2_height: u64) -> Self {
        let monero_header_root = label_root("monero_header", note_id);
        let l2_checkpoint_root = label_root("l2_checkpoint", note_id);
        let feed_link_root = domain_hash(
            &format!("{DOMAIN}:live-feed-link"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(feed_source),
                HashPart::Str(&monero_header_root),
                HashPart::Str(&l2_checkpoint_root),
                HashPart::U64(monero_height),
                HashPart::U64(l2_height),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            feed_source: feed_source.to_string(),
            monero_header_root,
            l2_checkpoint_root,
            feed_link_root,
            monero_height,
            l2_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "feed_source": self.feed_source,
            "monero_header_root": self.monero_header_root,
            "l2_checkpoint_root": self.l2_checkpoint_root,
            "feed_link_root": self.feed_link_root,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataBound {
    pub note_id: String,
    pub metadata_kind: String,
    pub metadata_root: String,
    pub byte_count: u64,
    pub max_byte_count: u64,
    pub bound_root: String,
}
impl MetadataBound {
    pub fn new(note_id: &str, metadata_kind: &str, byte_count: u64, max_byte_count: u64) -> Self {
        let metadata_root = label_root(metadata_kind, note_id);
        let bound_root = domain_hash(
            &format!("{DOMAIN}:metadata-bound"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::Str(metadata_kind),
                HashPart::Str(&metadata_root),
                HashPart::U64(byte_count),
                HashPart::U64(max_byte_count),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            metadata_kind: metadata_kind.to_string(),
            metadata_root,
            byte_count,
            max_byte_count,
            bound_root,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "metadata_kind": self.metadata_kind,
            "metadata_root": self.metadata_root,
            "byte_count": self.byte_count,
            "max_byte_count": self.max_byte_count,
            "bound_root": self.bound_root,
            "within_bound": self.byte_count <= self.max_byte_count,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyMetadataCheck {
    pub note_id: String,
    pub linkability_budget_bits: u64,
    pub max_linkability_budget_bits: u64,
    pub visible_fields_root: String,
    pub encrypted_fields_root: String,
    pub metadata_bounds_root: String,
    pub check_root: String,
}
impl PrivacyMetadataCheck {
    pub fn new(
        note_id: &str,
        linkability_budget_bits: u64,
        max_linkability_budget_bits: u64,
        metadata_bounds_root: &str,
    ) -> Self {
        let visible_fields_root = label_root("visible_fields", note_id);
        let encrypted_fields_root = label_root("encrypted_fields", note_id);
        let check_root = domain_hash(
            &format!("{DOMAIN}:privacy-metadata-check"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(note_id),
                HashPart::U64(linkability_budget_bits),
                HashPart::U64(max_linkability_budget_bits),
                HashPart::Str(&visible_fields_root),
                HashPart::Str(&encrypted_fields_root),
                HashPart::Str(metadata_bounds_root),
            ],
            32,
        );
        Self {
            note_id: note_id.to_string(),
            linkability_budget_bits,
            max_linkability_budget_bits,
            visible_fields_root,
            encrypted_fields_root,
            metadata_bounds_root: metadata_bounds_root.to_string(),
            check_root,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "linkability_budget_bits": self.linkability_budget_bits,
            "max_linkability_budget_bits": self.max_linkability_budget_bits,
            "visible_fields_root": self.visible_fields_root,
            "encrypted_fields_root": self.encrypted_fields_root,
            "metadata_bounds_root": self.metadata_bounds_root,
            "check_root": self.check_root,
            "within_budget": self.linkability_budget_bits <= self.max_linkability_budget_bits,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub note_id: String,
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub severity: String,
    pub release_blocking: bool,
    pub mismatch_root: String,
}
impl MismatchRecord {
    pub fn new(
        mismatch_id: &str,
        note_id: &str,
        lane: &str,
        expected_root: &str,
        observed_root: &str,
        severity: &str,
        release_blocking: bool,
    ) -> Self {
        let release_flag = if release_blocking {
            "release-blocking"
        } else {
            "non-blocking"
        };
        let mismatch_root = domain_hash(
            &format!("{DOMAIN}:mismatch-record"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(mismatch_id),
                HashPart::Str(note_id),
                HashPart::Str(lane),
                HashPart::Str(expected_root),
                HashPart::Str(observed_root),
                HashPart::Str(severity),
                HashPart::Str(release_flag),
            ],
            32,
        );
        Self {
            mismatch_id: mismatch_id.to_string(),
            note_id: note_id.to_string(),
            lane: lane.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            severity: severity.to_string(),
            release_blocking,
            mismatch_root,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "note_id": self.note_id,
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "severity": self.severity,
            "release_blocking": self.release_blocking,
            "mismatch_root": self.mismatch_root,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub note_id: String,
    pub reason: String,
    pub release_blocking: bool,
    pub hold_until_l2_height: u64,
    pub hold_root: String,
}
impl ReleaseHold {
    pub fn new(
        hold_id: &str,
        note_id: &str,
        reason: &str,
        release_blocking: bool,
        hold_until_l2_height: u64,
    ) -> Self {
        let release_flag = if release_blocking {
            "release-blocking"
        } else {
            "non-blocking"
        };
        let hold_root = domain_hash(
            &format!("{DOMAIN}:release-hold"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(hold_id),
                HashPart::Str(note_id),
                HashPart::Str(reason),
                HashPart::Str(release_flag),
                HashPart::U64(hold_until_l2_height),
            ],
            32,
        );
        Self {
            hold_id: hold_id.to_string(),
            note_id: note_id.to_string(),
            reason: reason.to_string(),
            release_blocking,
            hold_until_l2_height,
            hold_root,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "note_id": self.note_id,
            "reason": self.reason,
            "release_blocking": self.release_blocking,
            "hold_until_l2_height": self.hold_until_l2_height,
            "hold_root": self.hold_root,
        })
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BindingRoots {
    pub recovered_note_commitment_root: String,
    pub nullifier_fence_root: String,
    pub encrypted_payload_root: String,
    pub wallet_scan_hint_root: String,
    pub observed_receipt_link_root: String,
    pub live_feed_link_root: String,
    pub metadata_bound_root: String,
    pub privacy_metadata_check_root: String,
    pub mismatch_record_root: String,
    pub release_hold_root: String,
    pub bridge_forced_exit_binding_root: String,
}
impl BindingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "recovered_note_commitment_root": self.recovered_note_commitment_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "observed_receipt_link_root": self.observed_receipt_link_root,
            "live_feed_link_root": self.live_feed_link_root,
            "metadata_bound_root": self.metadata_bound_root,
            "privacy_metadata_check_root": self.privacy_metadata_check_root,
            "mismatch_record_root": self.mismatch_record_root,
            "release_hold_root": self.release_hold_root,
            "bridge_forced_exit_binding_root": self.bridge_forced_exit_binding_root,
        })
    }
    pub fn state_root(&self) -> String {
        record_root("binding_roots", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub l2_tip_height: u64,
    pub monero_tip_height: u64,
    pub forced_exit_epoch: u64,
    pub recovered_note_commitments: Vec<RecoveredNoteCommitment>,
    pub nullifier_fences: Vec<NullifierFence>,
    pub encrypted_payloads: Vec<EncryptedNotePayload>,
    pub wallet_scan_hints: Vec<WalletScanHint>,
    pub observed_receipt_links: Vec<ObservedReceiptLink>,
    pub live_feed_links: Vec<LiveFeedLink>,
    pub metadata_bounds: Vec<MetadataBound>,
    pub privacy_metadata_checks: Vec<PrivacyMetadataCheck>,
    pub mismatch_records: Vec<MismatchRecord>,
    pub release_holds: Vec<ReleaseHold>,
    pub labels: BTreeMap<String, String>,
}
impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let note_ids = [
            "note-recovery-alpha",
            "note-recovery-beta",
            "note-recovery-gamma",
        ];
        let recovered_note_commitments = note_ids
            .iter()
            .enumerate()
            .map(|(index, note_id)| {
                RecoveredNoteCommitment::devnet(note_id, index as u64, 1_260_040 + index as u64)
            })
            .collect::<Vec<_>>();
        let nullifier_fences = note_ids
            .iter()
            .enumerate()
            .map(|(index, note_id)| NullifierFence::devnet(note_id, 42, 1_260_040 + index as u64))
            .collect::<Vec<_>>();
        let encrypted_payloads = note_ids
            .iter()
            .enumerate()
            .map(|(index, note_id)| {
                EncryptedNotePayload::devnet(note_id, 1_024 + index as u64 * 128)
            })
            .collect::<Vec<_>>();
        let wallet_scan_hints = note_ids
            .iter()
            .enumerate()
            .map(|(index, note_id)| WalletScanHint::devnet(note_id, 912_704 + index as u64 * 4))
            .collect::<Vec<_>>();
        let observed_receipt_links = note_ids
            .iter()
            .enumerate()
            .map(|(index, note_id)| {
                ObservedReceiptLink::devnet(note_id, 912_704 + index as u64 * 4, 7_500)
            })
            .collect::<Vec<_>>();
        let live_feed_links = note_ids
            .iter()
            .enumerate()
            .map(|(index, note_id)| {
                LiveFeedLink::devnet(
                    note_id,
                    "monero-header-live-feed-devnet",
                    912_704 + index as u64 * 4,
                    1_260_040 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        let metadata_bounds = devnet_metadata_bounds(&config, &note_ids);
        let metadata_bound_root = merkle_from_records(
            "metadata-bound-devnet-input",
            metadata_bounds
                .iter()
                .map(MetadataBound::public_record)
                .collect(),
        );
        let privacy_metadata_checks = note_ids
            .iter()
            .map(|note_id| PrivacyMetadataCheck::new(note_id, 4, 6, &metadata_bound_root))
            .collect::<Vec<_>>();
        let mismatch_records = vec![MismatchRecord::new(
            "mismatch-devnet-empty-sentinel",
            "all-notes",
            "private-note-recovery-binding",
            &label_root("expected_all_clear", "private-note-recovery-binding"),
            &label_root("observed_all_clear", "private-note-recovery-binding"),
            "none",
            false,
        )];
        let release_holds = note_ids
            .iter()
            .map(|note_id| {
                ReleaseHold::new(
                    &format!("{note_id}-release-hold"),
                    note_id,
                    "monero-finality-and-nullifier-fence",
                    true,
                    1_260_760,
                )
            })
            .collect::<Vec<_>>();
        let labels = BTreeMap::from([
            ("bridge_spine".to_string(), config.forced_exit_id.clone()),
            (
                "recovery_binding".to_string(),
                config.recovery_binding_id.clone(),
            ),
            ("session".to_string(), config.bridge_session_label.clone()),
        ]);
        Self {
            config,
            runtime_id: format!("{DOMAIN}:devnet"),
            l2_tip_height: 1_260_080,
            monero_tip_height: 912_780,
            forced_exit_epoch: 42,
            recovered_note_commitments,
            nullifier_fences,
            encrypted_payloads,
            wallet_scan_hints,
            observed_receipt_links,
            live_feed_links,
            metadata_bounds,
            privacy_metadata_checks,
            mismatch_records,
            release_holds,
            labels,
        }
    }
    pub fn public_record(&self) -> Value {
        let roots = self.binding_roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runtime_id": self.runtime_id,
            "l2_tip_height": self.l2_tip_height,
            "monero_tip_height": self.monero_tip_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "config": self.config.public_record(),
            "labels": self.labels,
            "counts": self.counts_record(),
            "roots": roots.public_record(),
            "recovered_note_commitments": records(self.recovered_note_commitments.iter().map(RecoveredNoteCommitment::public_record)),
            "nullifier_fences": records(self.nullifier_fences.iter().map(NullifierFence::public_record)),
            "encrypted_payloads": records(self.encrypted_payloads.iter().map(EncryptedNotePayload::public_record)),
            "wallet_scan_hints": records(self.wallet_scan_hints.iter().map(WalletScanHint::public_record)),
            "observed_receipt_links": records(self.observed_receipt_links.iter().map(ObservedReceiptLink::public_record)),
            "live_feed_links": records(self.live_feed_links.iter().map(LiveFeedLink::public_record)),
            "metadata_bounds": records(self.metadata_bounds.iter().map(MetadataBound::public_record)),
            "privacy_metadata_checks": records(self.privacy_metadata_checks.iter().map(PrivacyMetadataCheck::public_record)),
            "mismatch_records": records(self.mismatch_records.iter().map(MismatchRecord::public_record)),
            "release_holds": records(self.release_holds.iter().map(ReleaseHold::public_record)),
        })
    }
    pub fn binding_roots(&self) -> BindingRoots {
        let recovered_note_commitment_root = merkle_from_records(
            "recovered-note-commitments",
            self.recovered_note_commitments
                .iter()
                .map(RecoveredNoteCommitment::public_record)
                .collect(),
        );
        let nullifier_fence_root = merkle_from_records(
            "nullifier-fences",
            self.nullifier_fences
                .iter()
                .map(NullifierFence::public_record)
                .collect(),
        );
        let encrypted_payload_root = merkle_from_records(
            "encrypted-payloads",
            self.encrypted_payloads
                .iter()
                .map(EncryptedNotePayload::public_record)
                .collect(),
        );
        let wallet_scan_hint_root = merkle_from_records(
            "wallet-scan-hints",
            self.wallet_scan_hints
                .iter()
                .map(WalletScanHint::public_record)
                .collect(),
        );
        let observed_receipt_link_root = merkle_from_records(
            "observed-receipt-links",
            self.observed_receipt_links
                .iter()
                .map(ObservedReceiptLink::public_record)
                .collect(),
        );
        let live_feed_link_root = merkle_from_records(
            "live-feed-links",
            self.live_feed_links
                .iter()
                .map(LiveFeedLink::public_record)
                .collect(),
        );
        let metadata_bound_root = merkle_from_records(
            "metadata-bounds",
            self.metadata_bounds
                .iter()
                .map(MetadataBound::public_record)
                .collect(),
        );
        let privacy_metadata_check_root = merkle_from_records(
            "privacy-metadata-checks",
            self.privacy_metadata_checks
                .iter()
                .map(PrivacyMetadataCheck::public_record)
                .collect(),
        );
        let mismatch_record_root = merkle_from_records(
            "mismatch-records",
            self.mismatch_records
                .iter()
                .map(MismatchRecord::public_record)
                .collect(),
        );
        let release_hold_root = merkle_from_records(
            "release-holds",
            self.release_holds
                .iter()
                .map(ReleaseHold::public_record)
                .collect(),
        );
        let bridge_forced_exit_binding_root = domain_hash(
            &format!("{DOMAIN}:bridge-forced-exit-binding"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.forced_exit_id),
                HashPart::Str(&self.config.recovery_binding_id),
                HashPart::Str(&recovered_note_commitment_root),
                HashPart::Str(&nullifier_fence_root),
                HashPart::Str(&encrypted_payload_root),
                HashPart::Str(&wallet_scan_hint_root),
                HashPart::Str(&observed_receipt_link_root),
                HashPart::Str(&live_feed_link_root),
                HashPart::Str(&metadata_bound_root),
                HashPart::Str(&privacy_metadata_check_root),
                HashPart::Str(&mismatch_record_root),
                HashPart::Str(&release_hold_root),
                HashPart::U64(self.forced_exit_epoch),
            ],
            32,
        );
        BindingRoots {
            recovered_note_commitment_root,
            nullifier_fence_root,
            encrypted_payload_root,
            wallet_scan_hint_root,
            observed_receipt_link_root,
            live_feed_link_root,
            metadata_bound_root,
            privacy_metadata_check_root,
            mismatch_record_root,
            release_hold_root,
            bridge_forced_exit_binding_root,
        }
    }
    pub fn counts_record(&self) -> Value {
        json!({
            "recovered_note_commitments": self.recovered_note_commitments.len() as u64,
            "nullifier_fences": self.nullifier_fences.len() as u64,
            "encrypted_payloads": self.encrypted_payloads.len() as u64,
            "wallet_scan_hints": self.wallet_scan_hints.len() as u64,
            "observed_receipt_links": self.observed_receipt_links.len() as u64,
            "live_feed_links": self.live_feed_links.len() as u64,
            "metadata_bounds": self.metadata_bounds.len() as u64,
            "privacy_metadata_checks": self.privacy_metadata_checks.len() as u64,
            "mismatch_records": self.mismatch_records.len() as u64,
            "release_holds": self.release_holds.len() as u64,
        })
    }
    pub fn state_root(&self) -> String {
        let roots = self.binding_roots();
        let config_record = self.config.public_record();
        let counts_record = self.counts_record();
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Json(&config_record),
                HashPart::Json(&counts_record),
                HashPart::Str(&self.runtime_id),
                HashPart::U64(self.l2_tip_height),
                HashPart::U64(self.monero_tip_height),
                HashPart::U64(self.forced_exit_epoch),
                HashPart::Str(&roots.state_root()),
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
fn devnet_metadata_bounds(config: &Config, note_ids: &[&str]) -> Vec<MetadataBound> {
    note_ids
        .iter()
        .flat_map(|note_id| {
            [
                MetadataBound::new(
                    note_id,
                    "encrypted_payload_metadata",
                    192,
                    config.max_metadata_bytes,
                ),
                MetadataBound::new(
                    note_id,
                    "wallet_scan_hint_metadata",
                    64,
                    config.max_wallet_hint_bytes,
                ),
                MetadataBound::new(
                    note_id,
                    "observed_receipt_metadata",
                    160,
                    config.max_metadata_bytes,
                ),
            ]
        })
        .collect()
}
fn records<I>(values: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    values.into_iter().collect()
}
fn merkle_from_records(label: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("{DOMAIN}:{label}"), &records)
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
fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}
