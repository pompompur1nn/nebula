use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceWalletExitReleaseInstructionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_EXIT_RELEASE_INSTRUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-wallet-exit-release-instruction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_WALLET_EXIT_RELEASE_INSTRUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_INSTRUCTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-wallet-exit-release-instruction-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_BATCH_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-wallet-exit-release-instruction-batch-devnet-v1";
pub const DEFAULT_RECOVERY_EPOCH: u64 = 17;
pub const DEFAULT_L2_ACCEPTANCE_HEIGHT: u64 = 101_728;
pub const DEFAULT_MONERO_ANCHOR_HEIGHT: u64 = 3_505_920;
pub const DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 36;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 192;
pub const DEFAULT_MAX_NOTICE_METADATA_FIELDS: u64 = 5;
pub const DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_REQUIRED_RECEIPT_LEAVES: u64 = 6;
pub const DEFAULT_MAX_RELEASES_PER_BATCH: usize = 128;
pub const REQUIRED_RELEASE_LANES: usize = 9;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseLane {
    ExitAcceptance,
    WalletRecoveryBundle,
    DestinationCommitment,
    EncryptedNotice,
    ClaimReceipt,
    Timing,
    Challenge,
    PrivacyBudget,
    HoldReason,
}

impl ReleaseLane {
    pub fn all() -> [Self; REQUIRED_RELEASE_LANES] {
        [
            Self::ExitAcceptance,
            Self::WalletRecoveryBundle,
            Self::DestinationCommitment,
            Self::EncryptedNotice,
            Self::ClaimReceipt,
            Self::Timing,
            Self::Challenge,
            Self::PrivacyBudget,
            Self::HoldReason,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExitAcceptance => "exit_acceptance",
            Self::WalletRecoveryBundle => "wallet_recovery_bundle",
            Self::DestinationCommitment => "destination_commitment",
            Self::EncryptedNotice => "encrypted_notice",
            Self::ClaimReceipt => "claim_receipt",
            Self::Timing => "timing",
            Self::Challenge => "challenge",
            Self::PrivacyBudget => "privacy_budget",
            Self::HoldReason => "hold_reason",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseInstructionStatus {
    Releasable,
    Timelocked,
    Challenged,
    Held,
    PrivacyHeld,
    Revoked,
}

impl ReleaseInstructionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Releasable => "releasable",
            Self::Timelocked => "timelocked",
            Self::Challenged => "challenged",
            Self::Held => "held",
            Self::PrivacyHeld => "privacy_held",
            Self::Revoked => "revoked",
        }
    }

    pub fn wallet_actionable(self) -> bool {
        self == Self::Releasable
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    None,
    WindowOpen,
    EvidenceSubmitted,
    UnderReview,
    ResolvedClear,
    ResolvedBlocked,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WindowOpen => "window_open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::UnderReview => "under_review",
            Self::ResolvedClear => "resolved_clear",
            Self::ResolvedBlocked => "resolved_blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            Self::WindowOpen | Self::EvidenceSubmitted | Self::UnderReview | Self::ResolvedBlocked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReasonKind {
    ChallengeWindowOpen,
    ChallengeEvidencePending,
    WalletBundleQuarantined,
    DestinationCommitmentMismatch,
    NoticeNotDeliverable,
    ClaimReceiptIncomplete,
    ReleaseDelayActive,
    PrivacySetTooSmall,
    MetadataBudgetExceeded,
    OperatorReview,
    RevocationMarker,
}

impl HoldReasonKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ChallengeEvidencePending => "challenge_evidence_pending",
            Self::WalletBundleQuarantined => "wallet_bundle_quarantined",
            Self::DestinationCommitmentMismatch => "destination_commitment_mismatch",
            Self::NoticeNotDeliverable => "notice_not_deliverable",
            Self::ClaimReceiptIncomplete => "claim_receipt_incomplete",
            Self::ReleaseDelayActive => "release_delay_active",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::MetadataBudgetExceeded => "metadata_budget_exceeded",
            Self::OperatorReview => "operator_review",
            Self::RevocationMarker => "revocation_marker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldSeverity {
    Info,
    Watch,
    WalletAction,
    ReleaseStop,
}

impl HoldSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::WalletAction => "wallet_action",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Info => 1,
            Self::Watch => 2,
            Self::WalletAction => 3,
            Self::ReleaseStop => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationMode {
    ViewOnlyPayout,
    SpendAuthorizedPayout,
    RecoveryEscrow,
    DeferredSweep,
}

impl DestinationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewOnlyPayout => "view_only_payout",
            Self::SpendAuthorizedPayout => "spend_authorized_payout",
            Self::RecoveryEscrow => "recovery_escrow",
            Self::DeferredSweep => "deferred_sweep",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeCipherSuite {
    PqHybridSealedBoxV1,
    ViewTagWrappedV1,
    WalletLocalEnvelopeV1,
}

impl NoticeCipherSuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqHybridSealedBoxV1 => "pq_hybrid_sealed_box_v1",
            Self::ViewTagWrappedV1 => "view_tag_wrapped_v1",
            Self::WalletLocalEnvelopeV1 => "wallet_local_envelope_v1",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub release_instruction_suite: String,
    pub vertical_slice_id: String,
    pub release_batch_id: String,
    pub recovery_epoch: u64,
    pub l2_acceptance_height: u64,
    pub monero_anchor_height: u64,
    pub release_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_notice_metadata_fields: u64,
    pub max_privacy_leakage_units: u64,
    pub required_receipt_leaves: u64,
    pub max_releases_per_batch: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            release_instruction_suite: RELEASE_INSTRUCTION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_batch_id: DEFAULT_RELEASE_BATCH_ID.to_string(),
            recovery_epoch: DEFAULT_RECOVERY_EPOCH,
            l2_acceptance_height: DEFAULT_L2_ACCEPTANCE_HEIGHT,
            monero_anchor_height: DEFAULT_MONERO_ANCHOR_HEIGHT,
            release_delay_blocks: DEFAULT_RELEASE_DELAY_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_notice_metadata_fields: DEFAULT_MAX_NOTICE_METADATA_FIELDS,
            max_privacy_leakage_units: DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS,
            required_receipt_leaves: DEFAULT_REQUIRED_RECEIPT_LEAVES,
            max_releases_per_batch: DEFAULT_MAX_RELEASES_PER_BATCH,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "release_instruction_suite": self.release_instruction_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_batch_id": self.release_batch_id,
            "recovery_epoch": self.recovery_epoch,
            "l2_acceptance_height": self.l2_acceptance_height,
            "monero_anchor_height": self.monero_anchor_height,
            "release_delay_blocks": self.release_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_notice_metadata_fields": self.max_notice_metadata_fields,
            "max_privacy_leakage_units": self.max_privacy_leakage_units,
            "required_receipt_leaves": self.required_receipt_leaves,
            "max_releases_per_batch": self.max_releases_per_batch,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletRecoveryBundleLink {
    pub bundle_id: String,
    pub accepted_exit_id: String,
    pub recovery_manifest_root: String,
    pub wallet_export_root: String,
    pub reconstruction_root: String,
    pub bundle_locator_commitment: String,
    pub bundle_policy_root: String,
    pub quarantine: bool,
}

impl WalletRecoveryBundleLink {
    pub fn devnet(config: &Config, ordinal: u64, accepted_exit_id: &str, quarantine: bool) -> Self {
        let recovery_manifest_root = domain_hash(
            "wallet-exit-release-instruction:recovery-manifest-root",
            &[
                HashPart::Str(&config.release_batch_id),
                HashPart::Str(accepted_exit_id),
                HashPart::U64(ordinal),
            ],
            32,
        );
        let wallet_export_root = domain_hash(
            "wallet-exit-release-instruction:wallet-export-root",
            &[
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(accepted_exit_id),
                HashPart::U64(config.recovery_epoch),
            ],
            32,
        );
        let reconstruction_root = domain_hash(
            "wallet-exit-release-instruction:reconstruction-root",
            &[
                HashPart::Str(&recovery_manifest_root),
                HashPart::Str(&wallet_export_root),
                HashPart::U64(ordinal + 1),
            ],
            32,
        );
        let bundle_locator_commitment = domain_hash(
            "wallet-exit-release-instruction:bundle-locator-commitment",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&reconstruction_root),
                HashPart::Str(if quarantine { "quarantined" } else { "active" }),
            ],
            32,
        );
        let bundle_policy = json!({
            "required_roots": [
                recovery_manifest_root,
                wallet_export_root,
                reconstruction_root
            ],
            "quarantine": quarantine,
            "epoch": config.recovery_epoch,
        });
        let bundle_policy_root = record_root("wallet_recovery_bundle_policy", &bundle_policy);
        let bundle_id = domain_hash(
            "wallet-exit-release-instruction:bundle-id",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&bundle_locator_commitment),
                HashPart::Str(&bundle_policy_root),
            ],
            24,
        );
        Self {
            bundle_id,
            accepted_exit_id: accepted_exit_id.to_string(),
            recovery_manifest_root,
            wallet_export_root,
            reconstruction_root,
            bundle_locator_commitment,
            bundle_policy_root,
            quarantine,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "accepted_exit_id": self.accepted_exit_id,
            "recovery_manifest_root": self.recovery_manifest_root,
            "wallet_export_root": self.wallet_export_root,
            "reconstruction_root": self.reconstruction_root,
            "bundle_locator_commitment": self.bundle_locator_commitment,
            "bundle_policy_root": self.bundle_policy_root,
            "quarantine": self.quarantine,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_recovery_bundle_link", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayoutDestinationCommitment {
    pub destination_id: String,
    pub mode: DestinationMode,
    pub view_destination_commitment: String,
    pub spend_destination_commitment: String,
    pub payout_amount_commitment: String,
    pub destination_guard_root: String,
    pub subaddress_hint_commitment: String,
    pub nullifier_binding_root: String,
}

impl PayoutDestinationCommitment {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        accepted_exit_id: &str,
        mode: DestinationMode,
    ) -> Self {
        let view_destination_commitment = domain_hash(
            "wallet-exit-release-instruction:view-destination-commitment",
            &[
                HashPart::Str(&config.chain_id),
                HashPart::Str(accepted_exit_id),
                HashPart::Str(mode.as_str()),
                HashPart::U64(ordinal),
            ],
            32,
        );
        let spend_destination_commitment = domain_hash(
            "wallet-exit-release-instruction:spend-destination-commitment",
            &[
                HashPart::Str(&config.release_batch_id),
                HashPart::Str(&view_destination_commitment),
                HashPart::U64(config.monero_anchor_height + ordinal),
            ],
            32,
        );
        let payout_amount_commitment = domain_hash(
            "wallet-exit-release-instruction:payout-amount-commitment",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&spend_destination_commitment),
                HashPart::Int(25_000_000_000_i128 + (ordinal as i128 * 7_500_000_000_i128)),
            ],
            32,
        );
        let destination_guard_root = merkle_root(
            "wallet-exit-release-instruction:destination-guard-root",
            &[
                json!(view_destination_commitment),
                json!(spend_destination_commitment),
                json!(payout_amount_commitment),
                json!(mode.as_str()),
            ],
        );
        let subaddress_hint_commitment = domain_hash(
            "wallet-exit-release-instruction:subaddress-hint-commitment",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&destination_guard_root),
                HashPart::U64(config.max_notice_metadata_fields),
            ],
            32,
        );
        let nullifier_binding_root = domain_hash(
            "wallet-exit-release-instruction:nullifier-binding-root",
            &[
                HashPart::Str(&destination_guard_root),
                HashPart::Str(&subaddress_hint_commitment),
            ],
            32,
        );
        let destination_id = domain_hash(
            "wallet-exit-release-instruction:destination-id",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(mode.as_str()),
                HashPart::Str(&nullifier_binding_root),
            ],
            24,
        );
        Self {
            destination_id,
            mode,
            view_destination_commitment,
            spend_destination_commitment,
            payout_amount_commitment,
            destination_guard_root,
            subaddress_hint_commitment,
            nullifier_binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "destination_id": self.destination_id,
            "mode": self.mode.as_str(),
            "view_destination_commitment": self.view_destination_commitment,
            "spend_destination_commitment": self.spend_destination_commitment,
            "payout_amount_commitment": self.payout_amount_commitment,
            "destination_guard_root": self.destination_guard_root,
            "subaddress_hint_commitment": self.subaddress_hint_commitment,
            "nullifier_binding_root": self.nullifier_binding_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("payout_destination_commitment", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedWalletNotice {
    pub notice_id: String,
    pub cipher_suite: NoticeCipherSuite,
    pub recipient_hint_commitment: String,
    pub ciphertext_commitment: String,
    pub notice_aad_root: String,
    pub metadata_field_count: u64,
    pub delivery_attempt_root: String,
}

impl EncryptedWalletNotice {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        accepted_exit_id: &str,
        destination: &PayoutDestinationCommitment,
        cipher_suite: NoticeCipherSuite,
        metadata_field_count: u64,
    ) -> Self {
        let recipient_hint_commitment = domain_hash(
            "wallet-exit-release-instruction:recipient-hint-commitment",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&destination.subaddress_hint_commitment),
                HashPart::Str(cipher_suite.as_str()),
            ],
            32,
        );
        let notice_aad = json!({
            "chain_id": config.chain_id,
            "release_batch_id": config.release_batch_id,
            "accepted_exit_id": accepted_exit_id,
            "destination_id": destination.destination_id,
            "metadata_field_count": metadata_field_count,
        });
        let notice_aad_root = record_root("encrypted_wallet_notice_aad", &notice_aad);
        let ciphertext_commitment = domain_hash(
            "wallet-exit-release-instruction:ciphertext-commitment",
            &[
                HashPart::Str(&recipient_hint_commitment),
                HashPart::Str(&notice_aad_root),
                HashPart::U64(ordinal),
            ],
            32,
        );
        let delivery_attempt_root = merkle_root(
            "wallet-exit-release-instruction:delivery-attempt-root",
            &[
                json!(recipient_hint_commitment),
                json!(ciphertext_commitment),
                json!(notice_aad_root),
            ],
        );
        let notice_id = domain_hash(
            "wallet-exit-release-instruction:notice-id",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&ciphertext_commitment),
                HashPart::Str(&delivery_attempt_root),
            ],
            24,
        );
        Self {
            notice_id,
            cipher_suite,
            recipient_hint_commitment,
            ciphertext_commitment,
            notice_aad_root,
            metadata_field_count,
            delivery_attempt_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "notice_id": self.notice_id,
            "cipher_suite": self.cipher_suite.as_str(),
            "recipient_hint_commitment": self.recipient_hint_commitment,
            "ciphertext_commitment": self.ciphertext_commitment,
            "notice_aad_root": self.notice_aad_root,
            "metadata_field_count": self.metadata_field_count,
            "delivery_attempt_root": self.delivery_attempt_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("encrypted_wallet_notice", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimReceiptRoot {
    pub claim_receipt_id: String,
    pub claim_id: String,
    pub receipt_leaf_count: u64,
    pub acceptance_receipt_root: String,
    pub payout_receipt_root: String,
    pub release_receipt_root: String,
    pub claim_receipt_root: String,
}

impl ClaimReceiptRoot {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        accepted_exit_id: &str,
        destination: &PayoutDestinationCommitment,
        leaf_count: u64,
    ) -> Self {
        let claim_id = domain_hash(
            "wallet-exit-release-instruction:claim-id",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(&destination.destination_id),
                HashPart::U64(ordinal),
            ],
            24,
        );
        let acceptance_receipt_root = domain_hash(
            "wallet-exit-release-instruction:acceptance-receipt-root",
            &[
                HashPart::Str(&config.vertical_slice_id),
                HashPart::Str(accepted_exit_id),
                HashPart::U64(config.l2_acceptance_height),
            ],
            32,
        );
        let payout_receipt_root = domain_hash(
            "wallet-exit-release-instruction:payout-receipt-root",
            &[
                HashPart::Str(&claim_id),
                HashPart::Str(&destination.payout_amount_commitment),
                HashPart::U64(leaf_count),
            ],
            32,
        );
        let release_receipt_root = merkle_root(
            "wallet-exit-release-instruction:release-receipt-root",
            &[
                json!(acceptance_receipt_root),
                json!(payout_receipt_root),
                json!(destination.nullifier_binding_root),
            ],
        );
        let claim_receipt_root = domain_hash(
            "wallet-exit-release-instruction:claim-receipt-root",
            &[
                HashPart::Str(&claim_id),
                HashPart::Str(&release_receipt_root),
                HashPart::U64(leaf_count),
            ],
            32,
        );
        let claim_receipt_id = domain_hash(
            "wallet-exit-release-instruction:claim-receipt-id",
            &[HashPart::Str(&claim_id), HashPart::Str(&claim_receipt_root)],
            24,
        );
        Self {
            claim_receipt_id,
            claim_id,
            receipt_leaf_count: leaf_count,
            acceptance_receipt_root,
            payout_receipt_root,
            release_receipt_root,
            claim_receipt_root,
        }
    }

    pub fn complete(&self, config: &Config) -> bool {
        self.receipt_leaf_count >= config.required_receipt_leaves
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_receipt_id": self.claim_receipt_id,
            "claim_id": self.claim_id,
            "receipt_leaf_count": self.receipt_leaf_count,
            "acceptance_receipt_root": self.acceptance_receipt_root,
            "payout_receipt_root": self.payout_receipt_root,
            "release_receipt_root": self.release_receipt_root,
            "claim_receipt_root": self.claim_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("claim_receipt_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseTiming {
    pub accepted_l2_height: u64,
    pub earliest_release_l2_height: u64,
    pub challenge_deadline_l2_height: u64,
    pub monero_anchor_height: u64,
    pub wallet_visible_after_height: u64,
    pub delay_blocks_remaining: u64,
}

impl ReleaseTiming {
    pub fn devnet(config: &Config, ordinal: u64, elapsed_blocks: u64) -> Self {
        let accepted_l2_height = config.l2_acceptance_height + ordinal;
        let earliest_release_l2_height = accepted_l2_height + config.release_delay_blocks;
        let challenge_deadline_l2_height = accepted_l2_height + config.challenge_window_blocks;
        let observed_height = accepted_l2_height + elapsed_blocks;
        let delay_blocks_remaining = earliest_release_l2_height.saturating_sub(observed_height);
        Self {
            accepted_l2_height,
            earliest_release_l2_height,
            challenge_deadline_l2_height,
            monero_anchor_height: config.monero_anchor_height + ordinal,
            wallet_visible_after_height: earliest_release_l2_height,
            delay_blocks_remaining,
        }
    }

    pub fn delay_active(&self) -> bool {
        self.delay_blocks_remaining > 0
    }

    pub fn challenge_window_open(&self) -> bool {
        self.accepted_l2_height + self.delay_blocks_remaining < self.challenge_deadline_l2_height
            && self.delay_blocks_remaining > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accepted_l2_height": self.accepted_l2_height,
            "earliest_release_l2_height": self.earliest_release_l2_height,
            "challenge_deadline_l2_height": self.challenge_deadline_l2_height,
            "monero_anchor_height": self.monero_anchor_height,
            "wallet_visible_after_height": self.wallet_visible_after_height,
            "delay_blocks_remaining": self.delay_blocks_remaining,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_timing", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudget {
    pub privacy_set_size: u64,
    pub notice_metadata_fields: u64,
    pub leakage_units: u64,
    pub destination_hint_count: u64,
    pub budget_root: String,
}

impl PrivacyBudget {
    pub fn devnet(
        config: &Config,
        accepted_exit_id: &str,
        privacy_set_size: u64,
        metadata_fields: u64,
        leakage_units: u64,
        hint_count: u64,
    ) -> Self {
        let budget_record = json!({
            "accepted_exit_id": accepted_exit_id,
            "privacy_set_size": privacy_set_size,
            "notice_metadata_fields": metadata_fields,
            "leakage_units": leakage_units,
            "destination_hint_count": hint_count,
            "min_privacy_set_size": config.min_privacy_set_size,
            "max_notice_metadata_fields": config.max_notice_metadata_fields,
            "max_privacy_leakage_units": config.max_privacy_leakage_units,
        });
        let budget_root = record_root("privacy_budget", &budget_record);
        Self {
            privacy_set_size,
            notice_metadata_fields: metadata_fields,
            leakage_units,
            destination_hint_count: hint_count,
            budget_root,
        }
    }

    pub fn within_budget(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_privacy_set_size
            && self.notice_metadata_fields <= config.max_notice_metadata_fields
            && self.leakage_units <= config.max_privacy_leakage_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "privacy_set_size": self.privacy_set_size,
            "notice_metadata_fields": self.notice_metadata_fields,
            "leakage_units": self.leakage_units,
            "destination_hint_count": self.destination_hint_count,
            "budget_root": self.budget_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("privacy_budget_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserVisibleHoldReason {
    pub reason_id: String,
    pub kind: HoldReasonKind,
    pub severity: HoldSeverity,
    pub wallet_message_code: String,
    pub evidence_root: String,
    pub clears_at_l2_height: Option<u64>,
}

impl UserVisibleHoldReason {
    pub fn new(
        accepted_exit_id: &str,
        kind: HoldReasonKind,
        severity: HoldSeverity,
        evidence_root: &str,
        clears_at_l2_height: Option<u64>,
    ) -> Self {
        let wallet_message_code = format!("wallet_exit_release_{}", kind.as_str());
        let clear_height = clears_at_l2_height.unwrap_or(0);
        let reason_id = domain_hash(
            "wallet-exit-release-instruction:hold-reason-id",
            &[
                HashPart::Str(accepted_exit_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(evidence_root),
                HashPart::U64(clear_height),
            ],
            20,
        );
        Self {
            reason_id,
            kind,
            severity,
            wallet_message_code,
            evidence_root: evidence_root.to_string(),
            clears_at_l2_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reason_id": self.reason_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "wallet_message_code": self.wallet_message_code,
            "evidence_root": self.evidence_root,
            "clears_at_l2_height": self.clears_at_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_visible_hold_reason", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseLaneRecord {
    pub lane: ReleaseLane,
    pub clear: bool,
    pub evidence_root: String,
    pub note: String,
}

impl ReleaseLaneRecord {
    pub fn new(lane: ReleaseLane, clear: bool, evidence_root: String, note: String) -> Self {
        Self {
            lane,
            clear,
            evidence_root,
            note,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "clear": self.clear,
            "evidence_root": self.evidence_root,
            "note": self.note,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletExitReleaseInstruction {
    pub instruction_id: String,
    pub accepted_exit_id: String,
    pub wallet_label: String,
    pub status: ReleaseInstructionStatus,
    pub challenge_status: ChallengeStatus,
    pub recovery_bundle_link: WalletRecoveryBundleLink,
    pub destination_commitment: PayoutDestinationCommitment,
    pub encrypted_notice: EncryptedWalletNotice,
    pub claim_receipt: ClaimReceiptRoot,
    pub release_timing: ReleaseTiming,
    pub privacy_budget: PrivacyBudget,
    pub hold_reasons: Vec<UserVisibleHoldReason>,
    pub lane_records: BTreeMap<String, ReleaseLaneRecord>,
    pub instruction_root: String,
}

impl WalletExitReleaseInstruction {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        wallet_label: &str,
        challenge_status: ChallengeStatus,
        quarantine_bundle: bool,
        elapsed_blocks: u64,
        privacy_set_size: u64,
        metadata_fields: u64,
        leakage_units: u64,
        receipt_leaf_count: u64,
        mode: DestinationMode,
        cipher_suite: NoticeCipherSuite,
    ) -> Self {
        let accepted_exit_id = accepted_exit_id(config, ordinal, wallet_label);
        let recovery_bundle_link =
            WalletRecoveryBundleLink::devnet(config, ordinal, &accepted_exit_id, quarantine_bundle);
        let destination_commitment =
            PayoutDestinationCommitment::devnet(config, ordinal, &accepted_exit_id, mode);
        let encrypted_notice = EncryptedWalletNotice::devnet(
            config,
            ordinal,
            &accepted_exit_id,
            &destination_commitment,
            cipher_suite,
            metadata_fields,
        );
        let claim_receipt = ClaimReceiptRoot::devnet(
            config,
            ordinal,
            &accepted_exit_id,
            &destination_commitment,
            receipt_leaf_count,
        );
        let release_timing = ReleaseTiming::devnet(config, ordinal, elapsed_blocks);
        let privacy_budget = PrivacyBudget::devnet(
            config,
            &accepted_exit_id,
            privacy_set_size,
            metadata_fields,
            leakage_units,
            1 + (ordinal % 2),
        );
        let hold_reasons = derive_hold_reasons(
            config,
            &accepted_exit_id,
            challenge_status,
            &recovery_bundle_link,
            &encrypted_notice,
            &claim_receipt,
            &release_timing,
            &privacy_budget,
        );
        let status = derive_status(
            config,
            challenge_status,
            &recovery_bundle_link,
            &claim_receipt,
            &release_timing,
            &privacy_budget,
            &hold_reasons,
        );
        let lane_records = derive_lane_records(
            config,
            challenge_status,
            &recovery_bundle_link,
            &destination_commitment,
            &encrypted_notice,
            &claim_receipt,
            &release_timing,
            &privacy_budget,
            &hold_reasons,
        );
        let instruction_root = instruction_root(
            &accepted_exit_id,
            status,
            challenge_status,
            &recovery_bundle_link,
            &destination_commitment,
            &encrypted_notice,
            &claim_receipt,
            &release_timing,
            &privacy_budget,
            &hold_reasons,
            &lane_records,
        );
        let instruction_id = domain_hash(
            "wallet-exit-release-instruction:instruction-id",
            &[
                HashPart::Str(&accepted_exit_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&instruction_root),
            ],
            24,
        );
        Self {
            instruction_id,
            accepted_exit_id,
            wallet_label: wallet_label.to_string(),
            status,
            challenge_status,
            recovery_bundle_link,
            destination_commitment,
            encrypted_notice,
            claim_receipt,
            release_timing,
            privacy_budget,
            hold_reasons,
            lane_records,
            instruction_root,
        }
    }

    pub fn actionable(&self) -> bool {
        self.status.wallet_actionable()
    }

    pub fn public_record(&self) -> Value {
        let lanes = self
            .lane_records
            .values()
            .map(ReleaseLaneRecord::public_record)
            .collect::<Vec<_>>();
        let holds = self
            .hold_reasons
            .iter()
            .map(UserVisibleHoldReason::public_record)
            .collect::<Vec<_>>();
        json!({
            "instruction_id": self.instruction_id,
            "accepted_exit_id": self.accepted_exit_id,
            "wallet_label": self.wallet_label,
            "status": self.status.as_str(),
            "challenge_status": self.challenge_status.as_str(),
            "recovery_bundle_link": self.recovery_bundle_link.public_record(),
            "destination_commitment": self.destination_commitment.public_record(),
            "encrypted_notice": self.encrypted_notice.public_record(),
            "claim_receipt": self.claim_receipt.public_record(),
            "release_timing": self.release_timing.public_record(),
            "privacy_budget": self.privacy_budget.public_record(),
            "hold_reasons": holds,
            "lane_records": lanes,
            "instruction_root": self.instruction_root,
            "actionable": self.actionable(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_exit_release_instruction", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseInstructionSummary {
    pub total_instructions: u64,
    pub releasable_count: u64,
    pub held_count: u64,
    pub challenged_count: u64,
    pub privacy_held_count: u64,
    pub revoked_count: u64,
    pub max_hold_severity_score: u64,
    pub summary_root: String,
}

impl ReleaseInstructionSummary {
    pub fn from_instructions(instructions: &[WalletExitReleaseInstruction]) -> Self {
        let mut releasable_count = 0;
        let mut held_count = 0;
        let mut challenged_count = 0;
        let mut privacy_held_count = 0;
        let mut revoked_count = 0;
        let mut max_hold_severity_score = 0;
        for instruction in instructions {
            match instruction.status {
                ReleaseInstructionStatus::Releasable => releasable_count += 1,
                ReleaseInstructionStatus::Timelocked | ReleaseInstructionStatus::Held => {
                    held_count += 1
                }
                ReleaseInstructionStatus::Challenged => challenged_count += 1,
                ReleaseInstructionStatus::PrivacyHeld => privacy_held_count += 1,
                ReleaseInstructionStatus::Revoked => revoked_count += 1,
            }
            for hold in &instruction.hold_reasons {
                max_hold_severity_score = max_hold_severity_score.max(hold.severity.score());
            }
        }
        let summary_value = json!({
            "total_instructions": instructions.len() as u64,
            "releasable_count": releasable_count,
            "held_count": held_count,
            "challenged_count": challenged_count,
            "privacy_held_count": privacy_held_count,
            "revoked_count": revoked_count,
            "max_hold_severity_score": max_hold_severity_score,
        });
        let summary_root = record_root("release_instruction_summary", &summary_value);
        Self {
            total_instructions: instructions.len() as u64,
            releasable_count,
            held_count,
            challenged_count,
            privacy_held_count,
            revoked_count,
            max_hold_severity_score,
            summary_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_instructions": self.total_instructions,
            "releasable_count": self.releasable_count,
            "held_count": self.held_count,
            "challenged_count": self.challenged_count,
            "privacy_held_count": self.privacy_held_count,
            "revoked_count": self.revoked_count,
            "max_hold_severity_score": self.max_hold_severity_score,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub instructions: Vec<WalletExitReleaseInstruction>,
    pub summary: ReleaseInstructionSummary,
    pub roots: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let instructions = vec![
            WalletExitReleaseInstruction::devnet(
                &config,
                0,
                "primary-recovery-wallet",
                ChallengeStatus::ResolvedClear,
                false,
                84,
                256,
                3,
                1,
                8,
                DestinationMode::SpendAuthorizedPayout,
                NoticeCipherSuite::PqHybridSealedBoxV1,
            ),
            WalletExitReleaseInstruction::devnet(
                &config,
                1,
                "view-only-audit-wallet",
                ChallengeStatus::WindowOpen,
                false,
                18,
                224,
                4,
                1,
                6,
                DestinationMode::ViewOnlyPayout,
                NoticeCipherSuite::ViewTagWrappedV1,
            ),
            WalletExitReleaseInstruction::devnet(
                &config,
                2,
                "recovery-escrow-wallet",
                ChallengeStatus::EvidenceSubmitted,
                true,
                44,
                96,
                6,
                3,
                4,
                DestinationMode::RecoveryEscrow,
                NoticeCipherSuite::WalletLocalEnvelopeV1,
            ),
        ];
        let summary = ReleaseInstructionSummary::from_instructions(&instructions);
        let roots = state_roots(&config, &instructions, &summary);
        Self {
            config,
            instructions,
            summary,
            roots,
        }
    }

    pub fn public_record(&self) -> Value {
        let instructions = self
            .instructions
            .iter()
            .map(WalletExitReleaseInstruction::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "instructions": instructions,
            "summary": self.summary.public_record(),
            "roots": self.roots,
        })
    }

    pub fn state_root(&self) -> String {
        let record = self.public_record();
        record_root("state", &record)
    }

    pub fn release_instruction(
        &self,
        instruction_id: &str,
    ) -> Result<&WalletExitReleaseInstruction> {
        self.instructions
            .iter()
            .find(|instruction| instruction.instruction_id == instruction_id)
            .ok_or_else(|| format!("release instruction not found: {instruction_id}"))
    }

    pub fn wallet_public_records(&self) -> Vec<Value> {
        self.instructions
            .iter()
            .map(|instruction| {
                json!({
                    "instruction_id": instruction.instruction_id,
                    "accepted_exit_id": instruction.accepted_exit_id,
                    "wallet_label": instruction.wallet_label,
                    "status": instruction.status.as_str(),
                    "challenge_status": instruction.challenge_status.as_str(),
                    "claim_id": instruction.claim_receipt.claim_id,
                    "claim_receipt_root": instruction.claim_receipt.claim_receipt_root,
                    "earliest_release_l2_height": instruction.release_timing.earliest_release_l2_height,
                    "wallet_visible_after_height": instruction.release_timing.wallet_visible_after_height,
                    "hold_reasons": instruction.hold_reasons.iter().map(UserVisibleHoldReason::public_record).collect::<Vec<_>>(),
                })
            })
            .collect()
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

pub fn validate_state(state: &State) -> Result<()> {
    if state.config.protocol_version != PROTOCOL_VERSION {
        return Err("protocol version mismatch".to_string());
    }
    if state.instructions.len() > state.config.max_releases_per_batch {
        return Err("release instruction batch exceeds configured maximum".to_string());
    }
    for instruction in &state.instructions {
        validate_instruction(&state.config, instruction)?;
    }
    Ok(())
}

pub fn validate_instruction(
    config: &Config,
    instruction: &WalletExitReleaseInstruction,
) -> Result<()> {
    if instruction.recovery_bundle_link.accepted_exit_id != instruction.accepted_exit_id {
        return Err("recovery bundle accepted exit mismatch".to_string());
    }
    if instruction.encrypted_notice.metadata_field_count > config.max_notice_metadata_fields {
        return Err("encrypted notice metadata field count exceeds limit".to_string());
    }
    if instruction.lane_records.len() != REQUIRED_RELEASE_LANES {
        return Err("release lane record count mismatch".to_string());
    }
    let recomputed = instruction_root(
        &instruction.accepted_exit_id,
        instruction.status,
        instruction.challenge_status,
        &instruction.recovery_bundle_link,
        &instruction.destination_commitment,
        &instruction.encrypted_notice,
        &instruction.claim_receipt,
        &instruction.release_timing,
        &instruction.privacy_budget,
        &instruction.hold_reasons,
        &instruction.lane_records,
    );
    if recomputed != instruction.instruction_root {
        return Err("release instruction root mismatch".to_string());
    }
    Ok(())
}

fn derive_status(
    config: &Config,
    challenge_status: ChallengeStatus,
    bundle: &WalletRecoveryBundleLink,
    receipt: &ClaimReceiptRoot,
    timing: &ReleaseTiming,
    privacy_budget: &PrivacyBudget,
    hold_reasons: &[UserVisibleHoldReason],
) -> ReleaseInstructionStatus {
    if hold_reasons
        .iter()
        .any(|reason| reason.kind == HoldReasonKind::RevocationMarker)
    {
        return ReleaseInstructionStatus::Revoked;
    }
    if challenge_status.blocks_release() {
        return ReleaseInstructionStatus::Challenged;
    }
    if !privacy_budget.within_budget(config) {
        return ReleaseInstructionStatus::PrivacyHeld;
    }
    if timing.delay_active() {
        return ReleaseInstructionStatus::Timelocked;
    }
    if bundle.quarantine || !receipt.complete(config) || !hold_reasons.is_empty() {
        return ReleaseInstructionStatus::Held;
    }
    ReleaseInstructionStatus::Releasable
}

fn derive_hold_reasons(
    config: &Config,
    accepted_exit_id: &str,
    challenge_status: ChallengeStatus,
    bundle: &WalletRecoveryBundleLink,
    notice: &EncryptedWalletNotice,
    receipt: &ClaimReceiptRoot,
    timing: &ReleaseTiming,
    privacy_budget: &PrivacyBudget,
) -> Vec<UserVisibleHoldReason> {
    let mut reasons = Vec::new();
    if timing.delay_active() {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::ReleaseDelayActive,
            HoldSeverity::Info,
            &timing.state_root(),
            Some(timing.earliest_release_l2_height),
        ));
    }
    if challenge_status == ChallengeStatus::WindowOpen {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::ChallengeWindowOpen,
            HoldSeverity::Watch,
            &timing.state_root(),
            Some(timing.challenge_deadline_l2_height),
        ));
    }
    if matches!(
        challenge_status,
        ChallengeStatus::EvidenceSubmitted
            | ChallengeStatus::UnderReview
            | ChallengeStatus::ResolvedBlocked
    ) {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::ChallengeEvidencePending,
            HoldSeverity::ReleaseStop,
            &receipt.release_receipt_root,
            None,
        ));
    }
    if bundle.quarantine {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::WalletBundleQuarantined,
            HoldSeverity::ReleaseStop,
            &bundle.bundle_policy_root,
            None,
        ));
    }
    if !receipt.complete(config) {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::ClaimReceiptIncomplete,
            HoldSeverity::WalletAction,
            &receipt.claim_receipt_root,
            None,
        ));
    }
    if notice.metadata_field_count > config.max_notice_metadata_fields {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::NoticeNotDeliverable,
            HoldSeverity::WalletAction,
            &notice.notice_aad_root,
            None,
        ));
    }
    if privacy_budget.privacy_set_size < config.min_privacy_set_size {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::PrivacySetTooSmall,
            HoldSeverity::ReleaseStop,
            &privacy_budget.budget_root,
            None,
        ));
    }
    if privacy_budget.notice_metadata_fields > config.max_notice_metadata_fields
        || privacy_budget.leakage_units > config.max_privacy_leakage_units
    {
        reasons.push(UserVisibleHoldReason::new(
            accepted_exit_id,
            HoldReasonKind::MetadataBudgetExceeded,
            HoldSeverity::ReleaseStop,
            &privacy_budget.budget_root,
            None,
        ));
    }
    reasons
}

fn derive_lane_records(
    config: &Config,
    challenge_status: ChallengeStatus,
    bundle: &WalletRecoveryBundleLink,
    destination: &PayoutDestinationCommitment,
    notice: &EncryptedWalletNotice,
    receipt: &ClaimReceiptRoot,
    timing: &ReleaseTiming,
    privacy_budget: &PrivacyBudget,
    hold_reasons: &[UserVisibleHoldReason],
) -> BTreeMap<String, ReleaseLaneRecord> {
    let mut records = BTreeMap::new();
    records.insert(
        ReleaseLane::ExitAcceptance.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::ExitAcceptance,
            true,
            receipt.acceptance_receipt_root.clone(),
            "accepted exit receipt is anchored".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::WalletRecoveryBundle.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::WalletRecoveryBundle,
            !bundle.quarantine,
            bundle.state_root(),
            "wallet recovery bundle link is bound to accepted exit".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::DestinationCommitment.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::DestinationCommitment,
            true,
            destination.state_root(),
            "view and spend payout destination commitments are deterministic".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::EncryptedNotice.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::EncryptedNotice,
            notice.metadata_field_count <= config.max_notice_metadata_fields,
            notice.state_root(),
            "wallet notice envelope is committed without plaintext disclosure".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::ClaimReceipt.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::ClaimReceipt,
            receipt.complete(config),
            receipt.state_root(),
            "claim receipt root satisfies configured leaf threshold".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::Timing.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::Timing,
            !timing.delay_active(),
            timing.state_root(),
            "release delay and wallet visibility heights are deterministic".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::Challenge.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::Challenge,
            !challenge_status.blocks_release(),
            record_root(
                "challenge_status",
                &json!({"challenge_status": challenge_status.as_str()}),
            ),
            "challenge status is wallet visible".to_string(),
        ),
    );
    records.insert(
        ReleaseLane::PrivacyBudget.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::PrivacyBudget,
            privacy_budget.within_budget(config),
            privacy_budget.state_root(),
            "privacy budget bounds notice metadata and destination hints".to_string(),
        ),
    );
    let hold_root = merkle_root(
        "wallet-exit-release-instruction:hold-reason-lane-root",
        &hold_reasons
            .iter()
            .map(UserVisibleHoldReason::public_record)
            .collect::<Vec<_>>(),
    );
    records.insert(
        ReleaseLane::HoldReason.as_str().to_string(),
        ReleaseLaneRecord::new(
            ReleaseLane::HoldReason,
            hold_reasons.is_empty(),
            hold_root,
            "user-visible hold reasons are included in wallet record".to_string(),
        ),
    );
    records
}

fn instruction_root(
    accepted_exit_id: &str,
    status: ReleaseInstructionStatus,
    challenge_status: ChallengeStatus,
    bundle: &WalletRecoveryBundleLink,
    destination: &PayoutDestinationCommitment,
    notice: &EncryptedWalletNotice,
    receipt: &ClaimReceiptRoot,
    timing: &ReleaseTiming,
    privacy_budget: &PrivacyBudget,
    hold_reasons: &[UserVisibleHoldReason],
    lane_records: &BTreeMap<String, ReleaseLaneRecord>,
) -> String {
    let hold_root = merkle_root(
        "wallet-exit-release-instruction:hold-reason-root",
        &hold_reasons
            .iter()
            .map(UserVisibleHoldReason::public_record)
            .collect::<Vec<_>>(),
    );
    let lane_root = merkle_root(
        "wallet-exit-release-instruction:lane-record-root",
        &lane_records
            .values()
            .map(ReleaseLaneRecord::public_record)
            .collect::<Vec<_>>(),
    );
    domain_hash(
        "wallet-exit-release-instruction:instruction-root",
        &[
            HashPart::Str(accepted_exit_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(challenge_status.as_str()),
            HashPart::Str(&bundle.state_root()),
            HashPart::Str(&destination.state_root()),
            HashPart::Str(&notice.state_root()),
            HashPart::Str(&receipt.state_root()),
            HashPart::Str(&timing.state_root()),
            HashPart::Str(&privacy_budget.state_root()),
            HashPart::Str(&hold_root),
            HashPart::Str(&lane_root),
        ],
        32,
    )
}

fn state_roots(
    config: &Config,
    instructions: &[WalletExitReleaseInstruction],
    summary: &ReleaseInstructionSummary,
) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    roots.insert("config".to_string(), config.state_root());
    roots.insert("summary".to_string(), summary.summary_root.clone());
    roots.insert(
        "instruction_set".to_string(),
        merkle_root(
            "wallet-exit-release-instruction:instruction-set-root",
            &instructions
                .iter()
                .map(WalletExitReleaseInstruction::public_record)
                .collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        "wallet_public_records".to_string(),
        merkle_root(
            "wallet-exit-release-instruction:wallet-public-record-root",
            &instructions
                .iter()
                .map(|instruction| {
                    json!({
                        "instruction_id": instruction.instruction_id,
                        "wallet_label": instruction.wallet_label,
                        "status": instruction.status.as_str(),
                        "claim_receipt_root": instruction.claim_receipt.claim_receipt_root,
                    })
                })
                .collect::<Vec<_>>(),
        ),
    );
    roots
}

fn accepted_exit_id(config: &Config, ordinal: u64, wallet_label: &str) -> String {
    domain_hash(
        "wallet-exit-release-instruction:accepted-exit-id",
        &[
            HashPart::Str(&config.vertical_slice_id),
            HashPart::Str(&config.release_batch_id),
            HashPart::Str(wallet_label),
            HashPart::U64(config.recovery_epoch),
            HashPart::U64(ordinal),
        ],
        24,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("wallet-exit-release-instruction:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}
