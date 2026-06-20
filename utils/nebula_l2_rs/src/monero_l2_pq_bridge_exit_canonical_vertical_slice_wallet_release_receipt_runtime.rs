use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWalletReleaseReceiptRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_RELEASE_RECEIPT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-wallet-release-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_RELEASE_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-wallet-release-receipt-canonical-vertical-slice-v1";
pub const NOTICE_ENCRYPTION_SUITE: &str =
    "xchacha20poly1305-shake256-wallet-release-notice-receipt-v1";
pub const PAYOUT_COMMITMENT_SUITE: &str = "monero-view-key-hidden-payout-commitment-roots-only-v1";
pub const DEFAULT_CONFIRMATION_TARGET: u64 = 10;
pub const DEFAULT_CURRENT_MONERO_HEIGHT: u64 = 3_514_240;
pub const DEFAULT_CURRENT_L2_HEIGHT: u64 = 8_880;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_NOTICE_HINTS: u64 = 4;
pub const DEFAULT_MAX_WALLET_METADATA_FIELDS: u64 = 6;
pub const DEFAULT_MAX_LINKABLE_FIELDS: u64 = 0;
pub const DEFAULT_NOTICE_RETENTION_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_HOLD_REASONS: usize = 12;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReceiptStatus {
    Confirmed,
    PendingConfirmation,
    Held,
    Rejected,
}

impl ReleaseReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::PendingConfirmation => "pending_confirmation",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionLinkStatus {
    Linked,
    Deferred,
    MissingWitness,
    MismatchedPayout,
}

impl InstructionLinkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::Deferred => "deferred",
            Self::MissingWitness => "missing_witness",
            Self::MismatchedPayout => "mismatched_payout",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutCommitmentStatus {
    Committed,
    WaitingForUnlock,
    AmountMismatch,
    RecipientMismatch,
}

impl PayoutCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::WaitingForUnlock => "waiting_for_unlock",
            Self::AmountMismatch => "amount_mismatch",
            Self::RecipientMismatch => "recipient_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeReceiptStatus {
    Delivered,
    PendingScan,
    CiphertextMissing,
    ReceiptExpired,
}

impl NoticeReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::PendingScan => "pending_scan",
            Self::CiphertextMissing => "ciphertext_missing",
            Self::ReceiptExpired => "receipt_expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationStatus {
    Final,
    Waiting,
    ReorgWatch,
    Expired,
}

impl ConfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Final => "final",
            Self::Waiting => "waiting",
            Self::ReorgWatch => "reorg_watch",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReasonKind {
    None,
    AwaitingMoneroConfirmations,
    AwaitingClaimReceipt,
    ObservationRootMismatch,
    ClaimReceiptRootMismatch,
    PrivacyBudgetExceeded,
    NoticeReceiptMissing,
    PayoutCommitmentMismatch,
    WalletInstructionMissing,
    WatcherQuorumPending,
    ChallengeWindowOpen,
    ManualReview,
}

impl HoldReasonKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::AwaitingMoneroConfirmations => "awaiting_monero_confirmations",
            Self::AwaitingClaimReceipt => "awaiting_claim_receipt",
            Self::ObservationRootMismatch => "observation_root_mismatch",
            Self::ClaimReceiptRootMismatch => "claim_receipt_root_mismatch",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::NoticeReceiptMissing => "notice_receipt_missing",
            Self::PayoutCommitmentMismatch => "payout_commitment_mismatch",
            Self::WalletInstructionMissing => "wallet_instruction_missing",
            Self::WatcherQuorumPending => "watcher_quorum_pending",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ManualReview => "manual_review",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_suite: String,
    pub notice_encryption_suite: String,
    pub payout_commitment_suite: String,
    pub confirmation_target: u64,
    pub current_monero_height: u64,
    pub current_l2_height: u64,
    pub min_privacy_set_size: u64,
    pub max_notice_hints: u64,
    pub max_wallet_metadata_fields: u64,
    pub max_linkable_fields: u64,
    pub notice_retention_blocks: u64,
    pub max_hold_reasons: usize,
    pub include_wallet_visible_messages: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            notice_encryption_suite: NOTICE_ENCRYPTION_SUITE.to_string(),
            payout_commitment_suite: PAYOUT_COMMITMENT_SUITE.to_string(),
            confirmation_target: DEFAULT_CONFIRMATION_TARGET,
            current_monero_height: DEFAULT_CURRENT_MONERO_HEIGHT,
            current_l2_height: DEFAULT_CURRENT_L2_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_notice_hints: DEFAULT_MAX_NOTICE_HINTS,
            max_wallet_metadata_fields: DEFAULT_MAX_WALLET_METADATA_FIELDS,
            max_linkable_fields: DEFAULT_MAX_LINKABLE_FIELDS,
            notice_retention_blocks: DEFAULT_NOTICE_RETENTION_BLOCKS,
            max_hold_reasons: DEFAULT_MAX_HOLD_REASONS,
            include_wallet_visible_messages: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_suite": self.receipt_suite,
            "notice_encryption_suite": self.notice_encryption_suite,
            "payout_commitment_suite": self.payout_commitment_suite,
            "confirmation_target": self.confirmation_target,
            "current_monero_height": self.current_monero_height,
            "current_l2_height": self.current_l2_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_notice_hints": self.max_notice_hints,
            "max_wallet_metadata_fields": self.max_wallet_metadata_fields,
            "max_linkable_fields": self.max_linkable_fields,
            "notice_retention_blocks": self.notice_retention_blocks,
            "max_hold_reasons": self.max_hold_reasons,
            "include_wallet_visible_messages": self.include_wallet_visible_messages,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletInstructionLink {
    pub instruction_id: String,
    pub release_instruction_root: String,
    pub wallet_request_root: String,
    pub custody_release_root: String,
    pub authorization_root: String,
    pub nullifier_root: String,
    pub l2_block_height: u64,
    pub instruction_ordinal: u64,
    pub status: InstructionLinkStatus,
}

impl WalletInstructionLink {
    pub fn public_record(&self) -> Value {
        json!({
            "instruction_id": self.instruction_id,
            "release_instruction_root": self.release_instruction_root,
            "wallet_request_root": self.wallet_request_root,
            "custody_release_root": self.custody_release_root,
            "authorization_root": self.authorization_root,
            "nullifier_root": self.nullifier_root,
            "l2_block_height": self.l2_block_height,
            "instruction_ordinal": self.instruction_ordinal,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WALLET-INSTRUCTION-LINK", &self.public_record())
    }

    pub fn linkage_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-INSTRUCTION-LINK",
            &[
                HashPart::Str(&self.instruction_id),
                HashPart::Str(&self.release_instruction_root),
                HashPart::Str(&self.wallet_request_root),
                HashPart::Str(&self.custody_release_root),
                HashPart::Str(&self.authorization_root),
                HashPart::Str(&self.nullifier_root),
                HashPart::U64(self.l2_block_height),
                HashPart::U64(self.instruction_ordinal),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PayoutCommitment {
    pub payout_id: String,
    pub payout_commitment: String,
    pub amount_commitment: String,
    pub recipient_view_tag_root: String,
    pub recipient_subaddress_hint_root: String,
    pub transaction_prefix_root: String,
    pub output_key_root: String,
    pub unlock_height: u64,
    pub monero_broadcast_height: u64,
    pub status: PayoutCommitmentStatus,
}

impl PayoutCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "payout_id": self.payout_id,
            "payout_commitment": self.payout_commitment,
            "amount_commitment": self.amount_commitment,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "recipient_subaddress_hint_root": self.recipient_subaddress_hint_root,
            "transaction_prefix_root": self.transaction_prefix_root,
            "output_key_root": self.output_key_root,
            "unlock_height": self.unlock_height,
            "monero_broadcast_height": self.monero_broadcast_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PAYOUT-COMMITMENT", &self.public_record())
    }

    pub fn evidence_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-PAYOUT-COMMITMENT",
            &[
                HashPart::Str(&self.payout_id),
                HashPart::Str(&self.payout_commitment),
                HashPart::Str(&self.amount_commitment),
                HashPart::Str(&self.recipient_view_tag_root),
                HashPart::Str(&self.recipient_subaddress_hint_root),
                HashPart::Str(&self.transaction_prefix_root),
                HashPart::Str(&self.output_key_root),
                HashPart::U64(self.unlock_height),
                HashPart::U64(self.monero_broadcast_height),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedNoticeReceipt {
    pub notice_id: String,
    pub ciphertext_root: String,
    pub scan_hint_root: String,
    pub delivery_receipt_root: String,
    pub wallet_ephemeral_key_commitment: String,
    pub notice_opening_commitment: String,
    pub retention_start_height: u64,
    pub retention_end_height: u64,
    pub hint_count: u64,
    pub status: NoticeReceiptStatus,
}

impl EncryptedNoticeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "ciphertext_root": self.ciphertext_root,
            "scan_hint_root": self.scan_hint_root,
            "delivery_receipt_root": self.delivery_receipt_root,
            "wallet_ephemeral_key_commitment": self.wallet_ephemeral_key_commitment,
            "notice_opening_commitment": self.notice_opening_commitment,
            "retention_start_height": self.retention_start_height,
            "retention_end_height": self.retention_end_height,
            "hint_count": self.hint_count,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ENCRYPTED-NOTICE-RECEIPT", &self.public_record())
    }

    pub fn receipt_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-ENCRYPTED-NOTICE",
            &[
                HashPart::Str(&self.notice_id),
                HashPart::Str(&self.ciphertext_root),
                HashPart::Str(&self.scan_hint_root),
                HashPart::Str(&self.delivery_receipt_root),
                HashPart::Str(&self.wallet_ephemeral_key_commitment),
                HashPart::Str(&self.notice_opening_commitment),
                HashPart::U64(self.retention_start_height),
                HashPart::U64(self.retention_end_height),
                HashPart::U64(self.hint_count),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseObservation {
    pub observation_id: String,
    pub observer_committee_root: String,
    pub release_event_root: String,
    pub monero_tx_observation_root: String,
    pub watcher_attestation_root: String,
    pub custody_debit_root: String,
    pub l2_inclusion_root: String,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub quorum_weight: u64,
}

impl ReleaseObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "observer_committee_root": self.observer_committee_root,
            "release_event_root": self.release_event_root,
            "monero_tx_observation_root": self.monero_tx_observation_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "custody_debit_root": self.custody_debit_root,
            "l2_inclusion_root": self.l2_inclusion_root,
            "observed_monero_height": self.observed_monero_height,
            "observed_l2_height": self.observed_l2_height,
            "quorum_weight": self.quorum_weight,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("RELEASE-OBSERVATION", &self.public_record())
    }

    pub fn observation_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-OBSERVATION",
            &[
                HashPart::Str(&self.observation_id),
                HashPart::Str(&self.observer_committee_root),
                HashPart::Str(&self.release_event_root),
                HashPart::Str(&self.monero_tx_observation_root),
                HashPart::Str(&self.watcher_attestation_root),
                HashPart::Str(&self.custody_debit_root),
                HashPart::Str(&self.l2_inclusion_root),
                HashPart::U64(self.observed_monero_height),
                HashPart::U64(self.observed_l2_height),
                HashPart::U64(self.quorum_weight),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimReceipt {
    pub claim_id: String,
    pub claim_commitment_root: String,
    pub claimant_wallet_root: String,
    pub claim_nullifier_root: String,
    pub challenge_window_root: String,
    pub adjudication_root: String,
    pub receipt_inclusion_root: String,
    pub claim_l2_height: u64,
    pub accepted: bool,
}

impl ClaimReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "claim_commitment_root": self.claim_commitment_root,
            "claimant_wallet_root": self.claimant_wallet_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "challenge_window_root": self.challenge_window_root,
            "adjudication_root": self.adjudication_root,
            "receipt_inclusion_root": self.receipt_inclusion_root,
            "claim_l2_height": self.claim_l2_height,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CLAIM-RECEIPT", &self.public_record())
    }

    pub fn claim_receipt_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-CLAIM-RECEIPT",
            &[
                HashPart::Str(&self.claim_id),
                HashPart::Str(&self.claim_commitment_root),
                HashPart::Str(&self.claimant_wallet_root),
                HashPart::Str(&self.claim_nullifier_root),
                HashPart::Str(&self.challenge_window_root),
                HashPart::Str(&self.adjudication_root),
                HashPart::Str(&self.receipt_inclusion_root),
                HashPart::U64(self.claim_l2_height),
                HashPart::Str(if self.accepted {
                    "claim_accepted"
                } else {
                    "claim_rejected"
                }),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfirmationTarget {
    pub monero_broadcast_height: u64,
    pub current_monero_height: u64,
    pub required_confirmations: u64,
    pub observed_confirmations: u64,
    pub finality_target_height: u64,
    pub reorg_guard_root: String,
    pub status: ConfirmationStatus,
}

impl ConfirmationTarget {
    pub fn public_record(&self) -> Value {
        json!({
            "monero_broadcast_height": self.monero_broadcast_height,
            "current_monero_height": self.current_monero_height,
            "required_confirmations": self.required_confirmations,
            "observed_confirmations": self.observed_confirmations,
            "finality_target_height": self.finality_target_height,
            "reorg_guard_root": self.reorg_guard_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIRMATION-TARGET", &self.public_record())
    }

    pub fn target_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-CONFIRMATION-TARGET",
            &[
                HashPart::U64(self.monero_broadcast_height),
                HashPart::U64(self.current_monero_height),
                HashPart::U64(self.required_confirmations),
                HashPart::U64(self.observed_confirmations),
                HashPart::U64(self.finality_target_height),
                HashPart::Str(&self.reorg_guard_root),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub privacy_set_size: u64,
    pub notice_hint_count: u64,
    pub wallet_metadata_fields: u64,
    pub linkable_fields: u64,
    pub redacted_field_root: String,
    pub wallet_surface_root: String,
    pub policy_root: String,
}

impl PrivacyBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "privacy_set_size": self.privacy_set_size,
            "notice_hint_count": self.notice_hint_count,
            "wallet_metadata_fields": self.wallet_metadata_fields,
            "linkable_fields": self.linkable_fields,
            "redacted_field_root": self.redacted_field_root,
            "wallet_surface_root": self.wallet_surface_root,
            "policy_root": self.policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRIVACY-BUDGET", &self.public_record())
    }

    pub fn budget_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-PRIVACY-BUDGET",
            &[
                HashPart::Str(&self.budget_id),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.notice_hint_count),
                HashPart::U64(self.wallet_metadata_fields),
                HashPart::U64(self.linkable_fields),
                HashPart::Str(&self.redacted_field_root),
                HashPart::Str(&self.wallet_surface_root),
                HashPart::Str(&self.policy_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserVisibleHoldReason {
    pub reason_id: String,
    pub kind: HoldReasonKind,
    pub severity: u64,
    pub message_code: String,
    pub visible_message: String,
    pub remediation_hint: String,
    pub evidence_root: String,
    pub clear_after_height: u64,
}

impl UserVisibleHoldReason {
    pub fn public_record(&self, include_message: bool) -> Value {
        json!({
            "reason_id": self.reason_id,
            "kind": self.kind.as_str(),
            "severity": self.severity,
            "message_code": self.message_code,
            "visible_message": if include_message { self.visible_message.clone() } else { "redacted".to_string() },
            "remediation_hint": if include_message { self.remediation_hint.clone() } else { "redacted".to_string() },
            "evidence_root": self.evidence_root,
            "clear_after_height": self.clear_after_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("USER-VISIBLE-HOLD-REASON", &self.public_record(true))
    }

    pub fn reason_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-HOLD-REASON",
            &[
                HashPart::Str(&self.reason_id),
                HashPart::Str(self.kind.as_str()),
                HashPart::U64(self.severity),
                HashPart::Str(&self.message_code),
                HashPart::Str(&self.evidence_root),
                HashPart::U64(self.clear_after_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReleaseReceiptRoots {
    pub instruction_link_root: String,
    pub payout_commitment_root: String,
    pub encrypted_notice_receipt_root: String,
    pub release_observation_root: String,
    pub claim_receipt_root: String,
    pub confirmation_target_root: String,
    pub privacy_budget_root: String,
    pub hold_reason_root: String,
    pub summary_root: String,
    pub receipt_root: String,
}

impl WalletReleaseReceiptRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "instruction_link_root": self.instruction_link_root,
            "payout_commitment_root": self.payout_commitment_root,
            "encrypted_notice_receipt_root": self.encrypted_notice_receipt_root,
            "release_observation_root": self.release_observation_root,
            "claim_receipt_root": self.claim_receipt_root,
            "confirmation_target_root": self.confirmation_target_root,
            "privacy_budget_root": self.privacy_budget_root,
            "hold_reason_root": self.hold_reason_root,
            "summary_root": self.summary_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReleaseReceipt {
    pub receipt_id: String,
    pub status: ReleaseReceiptStatus,
    pub wallet_label: String,
    pub instruction_id: String,
    pub payout_id: String,
    pub claim_id: String,
    pub confirmation_status: ConfirmationStatus,
    pub hold_reason_count: u64,
    pub roots: WalletReleaseReceiptRoots,
}

impl WalletReleaseReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "wallet_label": self.wallet_label,
            "instruction_id": self.instruction_id,
            "payout_id": self.payout_id,
            "claim_id": self.claim_id,
            "confirmation_status": self.confirmation_status.as_str(),
            "hold_reason_count": self.hold_reason_count,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WALLET-RELEASE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub wallet_instruction_link: WalletInstructionLink,
    pub payout_commitment: PayoutCommitment,
    pub encrypted_notice_receipt: EncryptedNoticeReceipt,
    pub release_observation: ReleaseObservation,
    pub claim_receipt: ClaimReceipt,
    pub confirmation_target: ConfirmationTarget,
    pub privacy_budget: PrivacyBudget,
    pub hold_reasons: Vec<UserVisibleHoldReason>,
    pub hold_reason_counts: BTreeMap<String, u64>,
    pub receipt: WalletReleaseReceipt,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let wallet_instruction_link = WalletInstructionLink {
            instruction_id: "wallet-release-instruction-devnet-0007".to_string(),
            release_instruction_root: scoped_hash("release-instruction", "custody-release-7"),
            wallet_request_root: scoped_hash("wallet-request", "wallet-alpha-release-request"),
            custody_release_root: scoped_hash("custody-release", "custody-ledger-debit-7"),
            authorization_root: scoped_hash("authorization", "pq-authorized-release-7"),
            nullifier_root: scoped_hash("nullifier", "exit-note-nullifier-7"),
            l2_block_height: DEFAULT_CURRENT_L2_HEIGHT - 8,
            instruction_ordinal: 7,
            status: InstructionLinkStatus::Linked,
        };
        let payout_commitment = PayoutCommitment {
            payout_id: "monero-payout-commitment-devnet-0007".to_string(),
            payout_commitment: scoped_hash("payout-commitment", "recipient-output-7"),
            amount_commitment: scoped_hash("amount-commitment", "hidden-amount-7"),
            recipient_view_tag_root: scoped_hash("view-tag", "wallet-alpha-view-tag"),
            recipient_subaddress_hint_root: scoped_hash(
                "subaddress-hint",
                "wallet-alpha-subaddress",
            ),
            transaction_prefix_root: scoped_hash("tx-prefix", "monero-tx-prefix-7"),
            output_key_root: scoped_hash("output-key", "monero-output-key-7"),
            unlock_height: DEFAULT_CURRENT_MONERO_HEIGHT + 60,
            monero_broadcast_height: DEFAULT_CURRENT_MONERO_HEIGHT - 10,
            status: PayoutCommitmentStatus::Committed,
        };
        let encrypted_notice_receipt = EncryptedNoticeReceipt {
            notice_id: "encrypted-wallet-notice-devnet-0007".to_string(),
            ciphertext_root: scoped_hash("notice-ciphertext", "wallet-alpha-release-notice"),
            scan_hint_root: scoped_hash("notice-scan-hint", "wallet-alpha-hint-bundle"),
            delivery_receipt_root: scoped_hash("notice-delivery", "wallet-alpha-delivery-receipt"),
            wallet_ephemeral_key_commitment: scoped_hash("notice-ephemeral-key", "ephemeral-key-7"),
            notice_opening_commitment: scoped_hash("notice-opening", "opening-commitment-7"),
            retention_start_height: DEFAULT_CURRENT_L2_HEIGHT - 8,
            retention_end_height: DEFAULT_CURRENT_L2_HEIGHT - 8 + DEFAULT_NOTICE_RETENTION_BLOCKS,
            hint_count: 3,
            status: NoticeReceiptStatus::Delivered,
        };
        let release_observation = ReleaseObservation {
            observation_id: "release-observation-devnet-0007".to_string(),
            observer_committee_root: scoped_hash("observer-committee", "watchers-epoch-21"),
            release_event_root: scoped_hash("release-event", "release-event-log-7"),
            monero_tx_observation_root: scoped_hash("monero-observation", "monero-tx-seen-7"),
            watcher_attestation_root: scoped_hash("watcher-attestation", "attested-2-of-3"),
            custody_debit_root: scoped_hash("custody-debit", "custody-balance-debited-7"),
            l2_inclusion_root: scoped_hash("l2-inclusion", "included-at-height-8872"),
            observed_monero_height: DEFAULT_CURRENT_MONERO_HEIGHT - 9,
            observed_l2_height: DEFAULT_CURRENT_L2_HEIGHT - 7,
            quorum_weight: 74,
        };
        let claim_receipt = ClaimReceipt {
            claim_id: "release-claim-devnet-0007".to_string(),
            claim_commitment_root: scoped_hash("claim-commitment", "claim-7"),
            claimant_wallet_root: scoped_hash("claimant-wallet", "wallet-alpha"),
            claim_nullifier_root: scoped_hash("claim-nullifier", "claim-nullifier-7"),
            challenge_window_root: scoped_hash("challenge-window", "closed-window-7"),
            adjudication_root: scoped_hash("adjudication", "accepted-no-challenge"),
            receipt_inclusion_root: scoped_hash("claim-inclusion", "claim-receipt-tree-7"),
            claim_l2_height: DEFAULT_CURRENT_L2_HEIGHT - 6,
            accepted: true,
        };
        let observed_confirmations = confirmation_count(
            DEFAULT_CURRENT_MONERO_HEIGHT,
            payout_commitment.monero_broadcast_height,
        );
        let confirmation_status =
            confirmation_status(observed_confirmations, config.confirmation_target);
        let confirmation_target = ConfirmationTarget {
            monero_broadcast_height: payout_commitment.monero_broadcast_height,
            current_monero_height: DEFAULT_CURRENT_MONERO_HEIGHT,
            required_confirmations: config.confirmation_target,
            observed_confirmations,
            finality_target_height: payout_commitment.monero_broadcast_height
                + config.confirmation_target,
            reorg_guard_root: scoped_hash("reorg-guard", "monero-finality-depth-10"),
            status: confirmation_status,
        };
        let privacy_budget = PrivacyBudget {
            budget_id: "wallet-release-privacy-budget-devnet-0007".to_string(),
            privacy_set_size: 131_072,
            notice_hint_count: encrypted_notice_receipt.hint_count,
            wallet_metadata_fields: 4,
            linkable_fields: 0,
            redacted_field_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-REDACTED-FIELDS",
                &[
                    json!("wallet_address"),
                    json!("plaintext_amount"),
                    json!("exact_subaddress"),
                    json!("view_key_material"),
                    json!("spend_key_material"),
                ],
            ),
            wallet_surface_root: scoped_hash("wallet-surface", "roots-only-wallet-release"),
            policy_root: scoped_hash("privacy-policy", "no-address-no-amount-no-linkage"),
        };
        let hold_reasons = build_hold_reasons(
            &config,
            &wallet_instruction_link,
            &payout_commitment,
            &encrypted_notice_receipt,
            &release_observation,
            &claim_receipt,
            &confirmation_target,
            &privacy_budget,
        );
        let hold_reason_counts = hold_reason_counts(&hold_reasons);
        let roots = receipt_roots(
            &wallet_instruction_link,
            &payout_commitment,
            &encrypted_notice_receipt,
            &release_observation,
            &claim_receipt,
            &confirmation_target,
            &privacy_budget,
            &hold_reasons,
        );
        let status = release_status(
            wallet_instruction_link.status,
            payout_commitment.status,
            encrypted_notice_receipt.status,
            confirmation_target.status,
            claim_receipt.accepted,
            &hold_reasons,
        );
        let receipt = WalletReleaseReceipt {
            receipt_id: receipt_id(&claim_receipt.claim_id, &roots.receipt_root),
            status,
            wallet_label: "wallet-alpha".to_string(),
            instruction_id: wallet_instruction_link.instruction_id.clone(),
            payout_id: payout_commitment.payout_id.clone(),
            claim_id: claim_receipt.claim_id.clone(),
            confirmation_status: confirmation_target.status,
            hold_reason_count: hold_reasons.len() as u64,
            roots,
        };
        let mut state = Self {
            config,
            wallet_instruction_link,
            payout_commitment,
            encrypted_notice_receipt,
            release_observation,
            claim_receipt,
            confirmation_target,
            privacy_budget,
            hold_reasons,
            hold_reason_counts,
            receipt,
            state_root: String::new(),
        };
        state.state_root = state.compute_state_root();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "wallet_instruction_link": self.wallet_instruction_link.public_record(),
            "payout_commitment": self.payout_commitment.public_record(),
            "encrypted_notice_receipt": self.encrypted_notice_receipt.public_record(),
            "release_observation_root": self.release_observation.observation_root(),
            "claim_receipt_root": self.claim_receipt.claim_receipt_root(),
            "confirmation_target": self.confirmation_target.public_record(),
            "privacy_budget": self.privacy_budget.public_record(),
            "hold_reasons": self.hold_reasons.iter().map(|reason| reason.public_record(self.config.include_wallet_visible_messages)).collect::<Vec<_>>(),
            "hold_reason_counts": self.hold_reason_counts,
            "receipt": self.receipt.public_record(),
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-RECEIPT-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.wallet_instruction_link.linkage_root()),
                HashPart::Str(&self.payout_commitment.evidence_root()),
                HashPart::Str(&self.encrypted_notice_receipt.receipt_root()),
                HashPart::Str(&self.release_observation.observation_root()),
                HashPart::Str(&self.claim_receipt.claim_receipt_root()),
                HashPart::Str(&self.confirmation_target.target_root()),
                HashPart::Str(&self.privacy_budget.budget_root()),
                HashPart::Str(&self.receipt.roots.hold_reason_root),
                HashPart::Str(&self.receipt.roots.receipt_root),
                HashPart::Str(self.receipt.status.as_str()),
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

fn build_hold_reasons(
    config: &Config,
    instruction: &WalletInstructionLink,
    payout: &PayoutCommitment,
    notice: &EncryptedNoticeReceipt,
    observation: &ReleaseObservation,
    claim: &ClaimReceipt,
    confirmation: &ConfirmationTarget,
    privacy: &PrivacyBudget,
) -> Vec<UserVisibleHoldReason> {
    let mut reasons = Vec::new();
    if instruction.status != InstructionLinkStatus::Linked {
        reasons.push(hold_reason(
            HoldReasonKind::WalletInstructionMissing,
            90,
            "wallet_instruction_not_linked",
            "Release instruction is not linked to this wallet yet.",
            "Wait for the release instruction witness to be indexed.",
            instruction.linkage_root(),
            config.current_l2_height + 12,
        ));
    }
    if payout.status != PayoutCommitmentStatus::Committed {
        reasons.push(hold_reason(
            HoldReasonKind::PayoutCommitmentMismatch,
            88,
            "payout_commitment_not_ready",
            "Payout commitment does not match the wallet release request.",
            "Keep the receipt and retry after the custody release is reconciled.",
            payout.evidence_root(),
            config.current_monero_height + config.confirmation_target,
        ));
    }
    if notice.status != NoticeReceiptStatus::Delivered {
        reasons.push(hold_reason(
            HoldReasonKind::NoticeReceiptMissing,
            72,
            "encrypted_notice_not_delivered",
            "Encrypted release notice has not been delivered to the wallet.",
            "Rescan the wallet notice lane for the current L2 epoch.",
            notice.receipt_root(),
            notice.retention_end_height,
        ));
    }
    if !claim.accepted {
        reasons.push(hold_reason(
            HoldReasonKind::AwaitingClaimReceipt,
            95,
            "claim_receipt_not_accepted",
            "Release claim receipt is not accepted.",
            "Wait for claim adjudication before treating the payout as final.",
            claim.claim_receipt_root(),
            config.current_l2_height + 24,
        ));
    }
    if confirmation.status != ConfirmationStatus::Final {
        reasons.push(hold_reason(
            HoldReasonKind::AwaitingMoneroConfirmations,
            54,
            "monero_confirmations_pending",
            "Payout transaction is waiting for the configured confirmation target.",
            "Keep the wallet online or rescan after the target height.",
            confirmation.target_root(),
            confirmation.finality_target_height,
        ));
    }
    if observation.quorum_weight < 67 {
        reasons.push(hold_reason(
            HoldReasonKind::WatcherQuorumPending,
            80,
            "watcher_quorum_pending",
            "Release observation is waiting for watcher quorum.",
            "Wait for the observer committee to publish enough attestations.",
            observation.observation_root(),
            config.current_l2_height + 18,
        ));
    }
    if privacy.privacy_set_size < config.min_privacy_set_size
        || privacy.notice_hint_count > config.max_notice_hints
        || privacy.wallet_metadata_fields > config.max_wallet_metadata_fields
        || privacy.linkable_fields > config.max_linkable_fields
    {
        reasons.push(hold_reason(
            HoldReasonKind::PrivacyBudgetExceeded,
            86,
            "privacy_budget_exceeded",
            "Wallet-facing receipt would reveal more metadata than policy allows.",
            "Use the roots-only receipt surface or wait for a larger anonymity set.",
            privacy.budget_root(),
            config.current_l2_height + 36,
        ));
    }
    reasons.truncate(config.max_hold_reasons);
    reasons
}

fn hold_reason(
    kind: HoldReasonKind,
    severity: u64,
    message_code: &str,
    visible_message: &str,
    remediation_hint: &str,
    evidence_root: String,
    clear_after_height: u64,
) -> UserVisibleHoldReason {
    let reason_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-HOLD-REASON-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::U64(severity),
            HashPart::Str(message_code),
            HashPart::Str(&evidence_root),
            HashPart::U64(clear_after_height),
        ],
        32,
    );
    UserVisibleHoldReason {
        reason_id: format!("wallet-release-hold-{message_code}-{reason_root}"),
        kind,
        severity,
        message_code: message_code.to_string(),
        visible_message: visible_message.to_string(),
        remediation_hint: remediation_hint.to_string(),
        evidence_root,
        clear_after_height,
    }
}

fn hold_reason_counts(reasons: &[UserVisibleHoldReason]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for reason in reasons {
        let counter = counts.entry(reason.kind.as_str().to_string()).or_insert(0);
        *counter += 1;
    }
    if counts.is_empty() {
        counts.insert(HoldReasonKind::None.as_str().to_string(), 0);
    }
    counts
}

fn receipt_roots(
    instruction: &WalletInstructionLink,
    payout: &PayoutCommitment,
    notice: &EncryptedNoticeReceipt,
    observation: &ReleaseObservation,
    claim: &ClaimReceipt,
    confirmation: &ConfirmationTarget,
    privacy: &PrivacyBudget,
    hold_reasons: &[UserVisibleHoldReason],
) -> WalletReleaseReceiptRoots {
    let instruction_link_root = instruction.linkage_root();
    let payout_commitment_root = payout.evidence_root();
    let encrypted_notice_receipt_root = notice.receipt_root();
    let release_observation_root = observation.observation_root();
    let claim_receipt_root = claim.claim_receipt_root();
    let confirmation_target_root = confirmation.target_root();
    let privacy_budget_root = privacy.budget_root();
    let hold_reason_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-HOLD-REASONS",
        &hold_reasons
            .iter()
            .map(|reason| reason.public_record(true))
            .collect::<Vec<_>>(),
    );
    let summary_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-SUMMARY",
        &[
            HashPart::Str(&instruction_link_root),
            HashPart::Str(&payout_commitment_root),
            HashPart::Str(&encrypted_notice_receipt_root),
            HashPart::Str(&release_observation_root),
            HashPart::Str(&claim_receipt_root),
            HashPart::Str(&confirmation_target_root),
            HashPart::Str(&privacy_budget_root),
            HashPart::Str(&hold_reason_root),
            HashPart::U64(hold_reasons.len() as u64),
        ],
        32,
    );
    let receipt_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-RECEIPT",
        &[
            HashPart::Str(&summary_root),
            HashPart::Str(&instruction.instruction_id),
            HashPart::Str(&payout.payout_id),
            HashPart::Str(&claim.claim_id),
            HashPart::Str(confirmation.status.as_str()),
            HashPart::U64(confirmation.observed_confirmations),
            HashPart::U64(privacy.privacy_set_size),
        ],
        32,
    );
    WalletReleaseReceiptRoots {
        instruction_link_root,
        payout_commitment_root,
        encrypted_notice_receipt_root,
        release_observation_root,
        claim_receipt_root,
        confirmation_target_root,
        privacy_budget_root,
        hold_reason_root,
        summary_root,
        receipt_root,
    }
}

fn release_status(
    instruction_status: InstructionLinkStatus,
    payout_status: PayoutCommitmentStatus,
    notice_status: NoticeReceiptStatus,
    confirmation_status: ConfirmationStatus,
    claim_accepted: bool,
    hold_reasons: &[UserVisibleHoldReason],
) -> ReleaseReceiptStatus {
    if !claim_accepted
        || instruction_status == InstructionLinkStatus::MismatchedPayout
        || payout_status == PayoutCommitmentStatus::AmountMismatch
        || payout_status == PayoutCommitmentStatus::RecipientMismatch
    {
        return ReleaseReceiptStatus::Rejected;
    }
    if !hold_reasons.is_empty() {
        return ReleaseReceiptStatus::Held;
    }
    if instruction_status == InstructionLinkStatus::Linked
        && payout_status == PayoutCommitmentStatus::Committed
        && notice_status == NoticeReceiptStatus::Delivered
        && confirmation_status == ConfirmationStatus::Final
    {
        return ReleaseReceiptStatus::Confirmed;
    }
    ReleaseReceiptStatus::PendingConfirmation
}

fn confirmation_count(current_height: u64, broadcast_height: u64) -> u64 {
    if current_height >= broadcast_height {
        current_height - broadcast_height + 1
    } else {
        0
    }
}

fn confirmation_status(
    observed_confirmations: u64,
    required_confirmations: u64,
) -> ConfirmationStatus {
    if observed_confirmations >= required_confirmations {
        ConfirmationStatus::Final
    } else if observed_confirmations == 0 {
        ConfirmationStatus::ReorgWatch
    } else {
        ConfirmationStatus::Waiting
    }
}

fn receipt_id(claim_id: &str, receipt_root: &str) -> String {
    format!("wallet-release-receipt-{claim_id}-{receipt_root}")
}

fn scoped_hash(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-RECEIPT-DEVNET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RELEASE-RECEIPT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
