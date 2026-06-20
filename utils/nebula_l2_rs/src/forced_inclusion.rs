use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ForcedInclusionResult<T> = Result<T, String>;

pub const FORCED_INCLUSION_PROTOCOL_VERSION: u64 = 1;
pub const FORCED_INCLUSION_PROTOCOL_ID: &str = "nebula-forced-inclusion-v1";
pub const FORCED_INCLUSION_PQ_AUTH_SCHEME: &str = "ML-DSA-65";
pub const FORCED_INCLUSION_PQ_BACKUP_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const FORCED_INCLUSION_KEM_SCHEME: &str = "ML-KEM-768";
pub const FORCED_INCLUSION_DEFAULT_SOFT_DELAY_BLOCKS: u64 = 8;
pub const FORCED_INCLUSION_DEFAULT_HARD_DELAY_BLOCKS: u64 = 32;
pub const FORCED_INCLUSION_DEFAULT_RESCUE_DELAY_BLOCKS: u64 = 40;
pub const FORCED_INCLUSION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const FORCED_INCLUSION_DEFAULT_MONERO_FINALITY_BLOCKS: u64 = 10;
pub const FORCED_INCLUSION_DEFAULT_L1_FINALITY_BLOCKS: u64 = 64;
pub const FORCED_INCLUSION_DEFAULT_MAX_QUEUE_DEPTH: u64 = 4096;
pub const FORCED_INCLUSION_DEFAULT_MAX_TICKET_BYTES: u64 = 96 * 1024;
pub const FORCED_INCLUSION_DEFAULT_MIN_BOND_UNITS: u64 = 4;
pub const FORCED_INCLUSION_DEFAULT_SPONSOR_POOL_UNITS: u64 = 25_000;
pub const FORCED_INCLUSION_DEFAULT_ESCAPE_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const FORCED_INCLUSION_DEFAULT_OPERATOR_ID: &str = "nebula-sequencer-devnet";
pub const FORCED_INCLUSION_DEFAULT_WATCHTOWER_ID: &str = "nebula-watchtower-devnet";
pub const FORCED_INCLUSION_DEFAULT_RESCUE_OPERATOR_ID: &str = "nebula-rescue-committee-devnet";
pub const FORCED_INCLUSION_DEFAULT_PRIVATE_VIEW_TAG_BITS: u16 = 32;
pub const FORCED_INCLUSION_MAX_BPS: u64 = 10_000;
pub const FORCED_INCLUSION_LOW_FEE_MIN_SHARE_BPS: u64 = 2_000;
pub const FORCED_INCLUSION_PRIVATE_MIN_SHARE_BPS: u64 = 2_500;
pub const FORCED_INCLUSION_DEFI_MIN_SHARE_BPS: u64 = 1_500;
pub const FORCED_INCLUSION_CONTRACT_MIN_SHARE_BPS: u64 = 1_500;
pub const FORCED_INCLUSION_EMERGENCY_MIN_SHARE_BPS: u64 = 1_000;
pub const FORCED_INCLUSION_STATUS_ACTIVE: &str = "active";
pub const FORCED_INCLUSION_STATUS_PAUSED: &str = "paused";
pub const FORCED_INCLUSION_STATUS_PENDING: &str = "pending";
pub const FORCED_INCLUSION_STATUS_COMMITTED: &str = "committed";
pub const FORCED_INCLUSION_STATUS_INCLUDED: &str = "included";
pub const FORCED_INCLUSION_STATUS_CLAIMED: &str = "claimed";
pub const FORCED_INCLUSION_STATUS_RESCUE_ELIGIBLE: &str = "rescue_eligible";
pub const FORCED_INCLUSION_STATUS_RESCUE_QUEUED: &str = "rescue_queued";
pub const FORCED_INCLUSION_STATUS_RESCUED: &str = "rescued";
pub const FORCED_INCLUSION_STATUS_CHALLENGED: &str = "challenged";
pub const FORCED_INCLUSION_STATUS_SLASHED: &str = "slashed";
pub const FORCED_INCLUSION_STATUS_REJECTED: &str = "rejected";
pub const FORCED_INCLUSION_STATUS_EXPIRED: &str = "expired";
pub const FORCED_INCLUSION_STATUS_FINALIZED: &str = "finalized";
pub const FORCED_INCLUSION_STATUS_OPEN: &str = "open";
pub const FORCED_INCLUSION_STATUS_RESOLVED: &str = "resolved";
pub const FORCED_INCLUSION_STATUS_DISMISSED: &str = "dismissed";
pub const FORCED_INCLUSION_STATUS_REDEEMED: &str = "redeemed";
pub const FORCED_INCLUSION_STATUS_RESERVED: &str = "reserved";
pub const FORCED_INCLUSION_STATUS_RELEASED: &str = "released";

const VALID_STATE_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_ACTIVE,
    FORCED_INCLUSION_STATUS_PAUSED,
];
const VALID_QUEUE_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_ACTIVE,
    FORCED_INCLUSION_STATUS_PAUSED,
];
const VALID_TICKET_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_PENDING,
    FORCED_INCLUSION_STATUS_COMMITTED,
    FORCED_INCLUSION_STATUS_CLAIMED,
    FORCED_INCLUSION_STATUS_INCLUDED,
    FORCED_INCLUSION_STATUS_RESCUE_ELIGIBLE,
    FORCED_INCLUSION_STATUS_RESCUE_QUEUED,
    FORCED_INCLUSION_STATUS_RESCUED,
    FORCED_INCLUSION_STATUS_CHALLENGED,
    FORCED_INCLUSION_STATUS_REJECTED,
    FORCED_INCLUSION_STATUS_EXPIRED,
    FORCED_INCLUSION_STATUS_FINALIZED,
];
const VALID_ANCHOR_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_PENDING,
    FORCED_INCLUSION_STATUS_COMMITTED,
    FORCED_INCLUSION_STATUS_FINALIZED,
    FORCED_INCLUSION_STATUS_REJECTED,
];
const VALID_CHALLENGE_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_OPEN,
    FORCED_INCLUSION_STATUS_CHALLENGED,
    FORCED_INCLUSION_STATUS_COMMITTED,
    FORCED_INCLUSION_STATUS_RESOLVED,
    FORCED_INCLUSION_STATUS_DISMISSED,
    FORCED_INCLUSION_STATUS_SLASHED,
];
const VALID_RESCUE_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_PENDING,
    FORCED_INCLUSION_STATUS_COMMITTED,
    FORCED_INCLUSION_STATUS_INCLUDED,
    FORCED_INCLUSION_STATUS_RESCUED,
    FORCED_INCLUSION_STATUS_FINALIZED,
];
const VALID_SPONSOR_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_ACTIVE,
    FORCED_INCLUSION_STATUS_RESERVED,
    FORCED_INCLUSION_STATUS_REDEEMED,
    FORCED_INCLUSION_STATUS_RELEASED,
    FORCED_INCLUSION_STATUS_EXPIRED,
    FORCED_INCLUSION_STATUS_PAUSED,
];
const VALID_OPERATOR_ACTION_STATUSES: &[&str] = &[
    FORCED_INCLUSION_STATUS_PENDING,
    FORCED_INCLUSION_STATUS_COMMITTED,
    FORCED_INCLUSION_STATUS_RESOLVED,
    FORCED_INCLUSION_STATUS_SLASHED,
    FORCED_INCLUSION_STATUS_DISMISSED,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeQueueKind {
    Withdrawal,
    PrivateTransfer,
    PublicTransfer,
    TokenOperation,
    DefiCall,
    ContractCall,
    MoneroBridge,
    EmergencyExit,
    Governance,
}

impl EscapeQueueKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Withdrawal => "withdrawal",
            Self::PrivateTransfer => "private_transfer",
            Self::PublicTransfer => "public_transfer",
            Self::TokenOperation => "token_operation",
            Self::DefiCall => "defi_call",
            Self::ContractCall => "contract_call",
            Self::MoneroBridge => "monero_bridge",
            Self::EmergencyExit => "emergency_exit",
            Self::Governance => "governance",
        }
    }

    pub fn default_priority_score(&self) -> u64 {
        match self {
            Self::EmergencyExit => 1_000_000,
            Self::MoneroBridge => 900_000,
            Self::Withdrawal => 850_000,
            Self::PrivateTransfer => 800_000,
            Self::TokenOperation => 750_000,
            Self::DefiCall => 700_000,
            Self::ContractCall => 650_000,
            Self::Governance => 500_000,
            Self::PublicTransfer => 450_000,
        }
    }

    pub fn default_min_share_bps(&self) -> u64 {
        match self {
            Self::EmergencyExit => FORCED_INCLUSION_EMERGENCY_MIN_SHARE_BPS,
            Self::PrivateTransfer => FORCED_INCLUSION_PRIVATE_MIN_SHARE_BPS,
            Self::TokenOperation | Self::DefiCall => FORCED_INCLUSION_DEFI_MIN_SHARE_BPS,
            Self::ContractCall => FORCED_INCLUSION_CONTRACT_MIN_SHARE_BPS,
            Self::Withdrawal | Self::MoneroBridge => FORCED_INCLUSION_LOW_FEE_MIN_SHARE_BPS,
            Self::Governance | Self::PublicTransfer => 500,
        }
    }

    pub fn privacy_preserving_by_default(&self) -> bool {
        matches!(
            self,
            Self::Withdrawal | Self::PrivateTransfer | Self::MoneroBridge | Self::EmergencyExit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InclusionTicketKind {
    PublicTransfer,
    EncryptedTransfer,
    ShieldedWithdrawal,
    TokenMint,
    TokenTransfer,
    TokenBurn,
    DefiSwap,
    DefiLiquidity,
    ContractCall,
    GovernanceAction,
    EmergencyExit,
}

impl InclusionTicketKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicTransfer => "public_transfer",
            Self::EncryptedTransfer => "encrypted_transfer",
            Self::ShieldedWithdrawal => "shielded_withdrawal",
            Self::TokenMint => "token_mint",
            Self::TokenTransfer => "token_transfer",
            Self::TokenBurn => "token_burn",
            Self::DefiSwap => "defi_swap",
            Self::DefiLiquidity => "defi_liquidity",
            Self::ContractCall => "contract_call",
            Self::GovernanceAction => "governance_action",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn requires_encryption(&self) -> bool {
        matches!(
            self,
            Self::EncryptedTransfer | Self::ShieldedWithdrawal | Self::EmergencyExit
        )
    }

    pub fn is_defi_or_contract(&self) -> bool {
        matches!(
            self,
            Self::DefiSwap | Self::DefiLiquidity | Self::ContractCall
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketMetadataVisibility {
    Public,
    CommitmentsOnly,
    ViewTagOnly,
    Encrypted,
    SelectiveDisclosure,
}

impl TicketMetadataVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::CommitmentsOnly => "commitments_only",
            Self::ViewTagOnly => "view_tag_only",
            Self::Encrypted => "encrypted",
            Self::SelectiveDisclosure => "selective_disclosure",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L1AnchorKind {
    MoneroTransaction,
    MoneroBlock,
    MoneroViewKeyCheckpoint,
    EthereumCalldata,
    CelestiaBlob,
    WatchtowerAttestation,
    GovernanceCheckpoint,
}

impl L1AnchorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MoneroTransaction => "monero_transaction",
            Self::MoneroBlock => "monero_block",
            Self::MoneroViewKeyCheckpoint => "monero_view_key_checkpoint",
            Self::EthereumCalldata => "ethereum_calldata",
            Self::CelestiaBlob => "celestia_blob",
            Self::WatchtowerAttestation => "watchtower_attestation",
            Self::GovernanceCheckpoint => "governance_checkpoint",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineMode {
    SequencerWindow,
    MoneroFinality,
    L1Finality,
    WatchtowerObserved,
    EmergencyImmediate,
}

impl DeadlineMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SequencerWindow => "sequencer_window",
            Self::MoneroFinality => "monero_finality",
            Self::L1Finality => "l1_finality",
            Self::WatchtowerObserved => "watchtower_observed",
            Self::EmergencyImmediate => "emergency_immediate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionEvidenceKind {
    MissingFromBatch,
    MissingFromDaBlob,
    PreconfirmationBroken,
    QueueRootMismatch,
    DeadlineExpired,
    InvalidRejection,
}

impl OmissionEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingFromBatch => "missing_from_batch",
            Self::MissingFromDaBlob => "missing_from_da_blob",
            Self::PreconfirmationBroken => "preconfirmation_broken",
            Self::QueueRootMismatch => "queue_root_mismatch",
            Self::DeadlineExpired => "deadline_expired",
            Self::InvalidRejection => "invalid_rejection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InclusionChallengeKind {
    ForceInclude,
    ProveIncluded,
    ProveRejected,
    RescueBatch,
    SlashSequencer,
    RefundSponsor,
}

impl InclusionChallengeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForceInclude => "force_include",
            Self::ProveIncluded => "prove_included",
            Self::ProveRejected => "prove_rejected",
            Self::RescueBatch => "rescue_batch",
            Self::SlashSequencer => "slash_sequencer",
            Self::RefundSponsor => "refund_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RescueManifestKind {
    SingleTicket,
    QueueDrain,
    DeadlineSweep,
    EmergencyExitBatch,
    WatchtowerBatch,
    GovernanceOrdered,
}

impl RescueManifestKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SingleTicket => "single_ticket",
            Self::QueueDrain => "queue_drain",
            Self::DeadlineSweep => "deadline_sweep",
            Self::EmergencyExitBatch => "emergency_exit_batch",
            Self::WatchtowerBatch => "watchtower_batch",
            Self::GovernanceOrdered => "governance_ordered",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipKind {
    LowFeeEscape,
    PrivacySubsidy,
    EmergencyExit,
    WatchtowerRefund,
    DefiDustRelief,
}

impl SponsorshipKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LowFeeEscape => "low_fee_escape",
            Self::PrivacySubsidy => "privacy_subsidy",
            Self::EmergencyExit => "emergency_exit",
            Self::WatchtowerRefund => "watchtower_refund",
            Self::DefiDustRelief => "defi_dust_relief",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorActionKind {
    AcknowledgeTicket,
    IncludeTicket,
    RejectTicket,
    PublishQueueRoot,
    PublishDeadlineRoot,
    PublishRescueManifest,
    RespondChallenge,
    ApplySlash,
    ReleaseSponsorCredit,
}

impl OperatorActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AcknowledgeTicket => "acknowledge_ticket",
            Self::IncludeTicket => "include_ticket",
            Self::RejectTicket => "reject_ticket",
            Self::PublishQueueRoot => "publish_queue_root",
            Self::PublishDeadlineRoot => "publish_deadline_root",
            Self::PublishRescueManifest => "publish_rescue_manifest",
            Self::RespondChallenge => "respond_challenge",
            Self::ApplySlash => "apply_slash",
            Self::ReleaseSponsorCredit => "release_sponsor_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    DeadlineMissed,
    FraudulentRejection,
    QueueRootEquivocation,
    BrokenPreconfirmation,
    RescueManifestOmitted,
    SponsorCreditTheft,
}

impl SlashReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeadlineMissed => "deadline_missed",
            Self::FraudulentRejection => "fraudulent_rejection",
            Self::QueueRootEquivocation => "queue_root_equivocation",
            Self::BrokenPreconfirmation => "broken_preconfirmation",
            Self::RescueManifestOmitted => "rescue_manifest_omitted",
            Self::SponsorCreditTheft => "sponsor_credit_theft",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionConfig {
    pub protocol_version: u64,
    pub protocol_id: String,
    pub pq_auth_scheme: String,
    pub pq_backup_scheme: String,
    pub kem_scheme: String,
    pub default_soft_delay_blocks: u64,
    pub default_hard_delay_blocks: u64,
    pub default_rescue_delay_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub monero_finality_blocks: u64,
    pub l1_finality_blocks: u64,
    pub max_queue_depth: u64,
    pub max_ticket_bytes: u64,
    pub min_bond_units: u64,
    pub low_fee_sponsor_pool_units: u64,
    pub escape_fee_asset_id: String,
    pub operator_id: String,
    pub watchtower_id: String,
    pub rescue_operator_id: String,
}

impl Default for ForcedInclusionConfig {
    fn default() -> Self {
        Self {
            protocol_version: FORCED_INCLUSION_PROTOCOL_VERSION,
            protocol_id: FORCED_INCLUSION_PROTOCOL_ID.to_string(),
            pq_auth_scheme: FORCED_INCLUSION_PQ_AUTH_SCHEME.to_string(),
            pq_backup_scheme: FORCED_INCLUSION_PQ_BACKUP_SCHEME.to_string(),
            kem_scheme: FORCED_INCLUSION_KEM_SCHEME.to_string(),
            default_soft_delay_blocks: FORCED_INCLUSION_DEFAULT_SOFT_DELAY_BLOCKS,
            default_hard_delay_blocks: FORCED_INCLUSION_DEFAULT_HARD_DELAY_BLOCKS,
            default_rescue_delay_blocks: FORCED_INCLUSION_DEFAULT_RESCUE_DELAY_BLOCKS,
            default_challenge_window_blocks: FORCED_INCLUSION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            monero_finality_blocks: FORCED_INCLUSION_DEFAULT_MONERO_FINALITY_BLOCKS,
            l1_finality_blocks: FORCED_INCLUSION_DEFAULT_L1_FINALITY_BLOCKS,
            max_queue_depth: FORCED_INCLUSION_DEFAULT_MAX_QUEUE_DEPTH,
            max_ticket_bytes: FORCED_INCLUSION_DEFAULT_MAX_TICKET_BYTES,
            min_bond_units: FORCED_INCLUSION_DEFAULT_MIN_BOND_UNITS,
            low_fee_sponsor_pool_units: FORCED_INCLUSION_DEFAULT_SPONSOR_POOL_UNITS,
            escape_fee_asset_id: FORCED_INCLUSION_DEFAULT_ESCAPE_FEE_ASSET_ID.to_string(),
            operator_id: FORCED_INCLUSION_DEFAULT_OPERATOR_ID.to_string(),
            watchtower_id: FORCED_INCLUSION_DEFAULT_WATCHTOWER_ID.to_string(),
            rescue_operator_id: FORCED_INCLUSION_DEFAULT_RESCUE_OPERATOR_ID.to_string(),
        }
    }
}

impl ForcedInclusionConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_backup_scheme": self.pq_backup_scheme,
            "kem_scheme": self.kem_scheme,
            "default_soft_delay_blocks": self.default_soft_delay_blocks,
            "default_hard_delay_blocks": self.default_hard_delay_blocks,
            "default_rescue_delay_blocks": self.default_rescue_delay_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "monero_finality_blocks": self.monero_finality_blocks,
            "l1_finality_blocks": self.l1_finality_blocks,
            "max_queue_depth": self.max_queue_depth,
            "max_ticket_bytes": self.max_ticket_bytes,
            "min_bond_units": self.min_bond_units,
            "low_fee_sponsor_pool_units": self.low_fee_sponsor_pool_units,
            "escape_fee_asset_id": self.escape_fee_asset_id,
            "operator_id": self.operator_id,
            "watchtower_id": self.watchtower_id,
            "rescue_operator_id": self.rescue_operator_id,
        })
    }

    pub fn config_root(&self) -> String {
        forced_inclusion_payload_root("FORCED-INCLUSION-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        ensure_positive(
            self.default_hard_delay_blocks,
            "forced inclusion hard delay blocks",
        )?;
        ensure_positive(self.max_queue_depth, "forced inclusion max queue depth")?;
        ensure_positive(self.max_ticket_bytes, "forced inclusion max ticket bytes")?;
        ensure_positive(self.min_bond_units, "forced inclusion min bond units")?;
        ensure_non_empty(&self.escape_fee_asset_id, "forced inclusion fee asset")?;
        ensure_non_empty(&self.operator_id, "forced inclusion operator id")?;
        ensure_non_empty(&self.watchtower_id, "forced inclusion watchtower id")?;
        if self.default_soft_delay_blocks > self.default_hard_delay_blocks {
            return Err("forced inclusion soft delay exceeds hard delay".to_string());
        }
        if self.default_hard_delay_blocks > self.default_rescue_delay_blocks {
            return Err("forced inclusion hard delay exceeds rescue delay".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyPreservingTicketMetadata {
    pub metadata_id: String,
    pub visibility: TicketMetadataVisibility,
    pub owner_scope_commitment: String,
    pub lane_tag_commitment: String,
    pub app_tag_commitment: String,
    pub amount_bucket: String,
    pub fee_bucket: String,
    pub view_tag_prefix: String,
    pub view_tag_bits: u16,
    pub note_commitment_root: String,
    pub nullifier_set_root: String,
    pub disclosure_policy_root: String,
    pub encrypted_metadata_root: String,
    pub selective_disclosure_root: String,
    pub salt_commitment: String,
    pub status: String,
}

impl PrivacyPreservingTicketMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        visibility: TicketMetadataVisibility,
        owner_scope: impl Into<String>,
        lane_tag: impl Into<String>,
        app_tag: impl Into<String>,
        amount_bucket: impl Into<String>,
        fee_bucket: impl Into<String>,
        view_tag_prefix: impl Into<String>,
        view_tag_bits: u16,
        note_commitment_root: impl Into<String>,
        nullifier_set_root: impl Into<String>,
        disclosure_policy_root: impl Into<String>,
        encrypted_metadata_root: impl Into<String>,
        selective_disclosure_root: impl Into<String>,
        salt: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let owner_scope = owner_scope.into();
        let lane_tag = lane_tag.into();
        let app_tag = app_tag.into();
        let amount_bucket = amount_bucket.into();
        let fee_bucket = fee_bucket.into();
        let view_tag_prefix = view_tag_prefix.into();
        let note_commitment_root = note_commitment_root.into();
        let nullifier_set_root = nullifier_set_root.into();
        let disclosure_policy_root = disclosure_policy_root.into();
        let encrypted_metadata_root = encrypted_metadata_root.into();
        let selective_disclosure_root = selective_disclosure_root.into();
        let salt = salt.into();
        ensure_non_empty(&owner_scope, "ticket metadata owner scope")?;
        ensure_non_empty(&lane_tag, "ticket metadata lane tag")?;
        ensure_non_empty(&app_tag, "ticket metadata app tag")?;
        ensure_non_empty(&amount_bucket, "ticket metadata amount bucket")?;
        ensure_non_empty(&fee_bucket, "ticket metadata fee bucket")?;
        validate_view_tag_bits(view_tag_bits)?;
        let mut metadata = Self {
            metadata_id: String::new(),
            visibility,
            owner_scope_commitment: forced_inclusion_commitment(
                "FORCED-INCLUSION-OWNER-SCOPE-COMMITMENT",
                &owner_scope,
                &salt,
            ),
            lane_tag_commitment: forced_inclusion_commitment(
                "FORCED-INCLUSION-LANE-TAG-COMMITMENT",
                &lane_tag,
                &salt,
            ),
            app_tag_commitment: forced_inclusion_commitment(
                "FORCED-INCLUSION-APP-TAG-COMMITMENT",
                &app_tag,
                &salt,
            ),
            amount_bucket,
            fee_bucket,
            view_tag_prefix,
            view_tag_bits,
            note_commitment_root,
            nullifier_set_root,
            disclosure_policy_root,
            encrypted_metadata_root,
            selective_disclosure_root,
            salt_commitment: forced_inclusion_string_root("FORCED-INCLUSION-METADATA-SALT", &salt),
            status: FORCED_INCLUSION_STATUS_ACTIVE.to_string(),
        };
        metadata.metadata_id = privacy_ticket_metadata_id(&metadata.identity_record());
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn devnet_private(
        label: &str,
        lane_tag: &str,
        app_tag: &str,
    ) -> ForcedInclusionResult<Self> {
        let salt = format!("{label}:ticket-metadata-salt");
        Self::new(
            TicketMetadataVisibility::CommitmentsOnly,
            format!("{label}:owner-scope"),
            lane_tag.to_string(),
            app_tag.to_string(),
            "amount_bucket:private-small".to_string(),
            "fee_bucket:sponsored".to_string(),
            devnet_view_tag_prefix(label),
            FORCED_INCLUSION_DEFAULT_PRIVATE_VIEW_TAG_BITS,
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-NOTE-COMMITMENT",
                &format!("{label}:note-root"),
            ),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-NULLIFIER-SET",
                &format!("{label}:nullifier-root"),
            ),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-DISCLOSURE-POLICY",
                &format!("{label}:policy"),
            ),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-ENCRYPTED-METADATA",
                &format!("{label}:encrypted-metadata"),
            ),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-SELECTIVE-DISCLOSURE",
                &format!("{label}:selective-disclosure"),
            ),
            salt,
        )
    }

    pub fn devnet_public(
        label: &str,
        lane_tag: &str,
        app_tag: &str,
    ) -> ForcedInclusionResult<Self> {
        let salt = format!("{label}:public-ticket-metadata-salt");
        Self::new(
            TicketMetadataVisibility::Public,
            format!("{label}:public-owner-scope"),
            lane_tag.to_string(),
            app_tag.to_string(),
            "amount_bucket:public-medium".to_string(),
            "fee_bucket:market".to_string(),
            devnet_view_tag_prefix(label),
            FORCED_INCLUSION_DEFAULT_PRIVATE_VIEW_TAG_BITS,
            forced_inclusion_empty_root("FORCED-INCLUSION-DEVNET-PUBLIC-NOTE"),
            forced_inclusion_empty_root("FORCED-INCLUSION-DEVNET-PUBLIC-NULLIFIER"),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-PUBLIC-DISCLOSURE-POLICY",
                &format!("{label}:public-policy"),
            ),
            forced_inclusion_empty_root("FORCED-INCLUSION-DEVNET-PUBLIC-ENCRYPTED-METADATA"),
            forced_inclusion_empty_root("FORCED-INCLUSION-DEVNET-PUBLIC-SELECTIVE-DISCLOSURE"),
            salt,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_ticket_metadata_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "visibility": self.visibility.as_str(),
            "owner_scope_commitment": self.owner_scope_commitment,
            "lane_tag_commitment": self.lane_tag_commitment,
            "app_tag_commitment": self.app_tag_commitment,
            "amount_bucket": self.amount_bucket,
            "fee_bucket": self.fee_bucket,
            "view_tag_prefix": self.view_tag_prefix,
            "view_tag_bits": self.view_tag_bits,
            "note_commitment_root": self.note_commitment_root,
            "nullifier_set_root": self.nullifier_set_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "selective_disclosure_root": self.selective_disclosure_root,
            "salt_commitment": self.salt_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("ticket metadata record is object");
        object.insert(
            "metadata_id".to_string(),
            Value::String(self.metadata_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "metadata_root".to_string(),
            Value::String(self.metadata_root()),
        );
        record
    }

    pub fn metadata_root(&self) -> String {
        forced_inclusion_payload_root(
            "FORCED-INCLUSION-TICKET-METADATA-ROOT",
            &self.identity_record(),
        )
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.metadata_id != privacy_ticket_metadata_id(&self.identity_record()) {
            return Err("ticket metadata id mismatch".to_string());
        }
        validate_view_tag_bits(self.view_tag_bits)?;
        ensure_status(&self.status, &[FORCED_INCLUSION_STATUS_ACTIVE])?;
        ensure_non_empty(
            &self.owner_scope_commitment,
            "ticket metadata owner commitment",
        )?;
        ensure_non_empty(&self.lane_tag_commitment, "ticket metadata lane tag")?;
        ensure_non_empty(&self.app_tag_commitment, "ticket metadata app tag")?;
        ensure_non_empty(&self.amount_bucket, "ticket metadata amount bucket")?;
        ensure_non_empty(&self.fee_bucket, "ticket metadata fee bucket")?;
        Ok(self.metadata_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1InclusionAnchor {
    pub anchor_id: String,
    pub anchor_kind: L1AnchorKind,
    pub source_chain: String,
    pub l1_height: u64,
    pub l1_block_hash: String,
    pub monero_height: Option<u64>,
    pub monero_txid: Option<String>,
    pub monero_block_hash: Option<String>,
    pub observed_at_l2_height: u64,
    pub confirmations: u64,
    pub finality_threshold: u64,
    pub payload_root: String,
    pub watchtower_attestation_root: String,
    pub status: String,
}

impl L1InclusionAnchor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        anchor_kind: L1AnchorKind,
        source_chain: impl Into<String>,
        l1_height: u64,
        l1_block_hash: impl Into<String>,
        monero_height: Option<u64>,
        monero_txid: Option<String>,
        monero_block_hash: Option<String>,
        observed_at_l2_height: u64,
        confirmations: u64,
        finality_threshold: u64,
        payload_root: impl Into<String>,
        watchtower_attestation_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let source_chain = source_chain.into();
        let l1_block_hash = l1_block_hash.into();
        let payload_root = payload_root.into();
        let watchtower_attestation_root = watchtower_attestation_root.into();
        ensure_non_empty(&source_chain, "l1 inclusion anchor source chain")?;
        ensure_non_empty(&l1_block_hash, "l1 inclusion anchor block hash")?;
        ensure_non_empty(&payload_root, "l1 inclusion anchor payload root")?;
        let mut anchor = Self {
            anchor_id: String::new(),
            anchor_kind,
            source_chain,
            l1_height,
            l1_block_hash,
            monero_height,
            monero_txid,
            monero_block_hash,
            observed_at_l2_height,
            confirmations,
            finality_threshold,
            payload_root,
            watchtower_attestation_root,
            status: if confirmations >= finality_threshold {
                FORCED_INCLUSION_STATUS_FINALIZED.to_string()
            } else {
                FORCED_INCLUSION_STATUS_COMMITTED.to_string()
            },
        };
        anchor.anchor_id = l1_inclusion_anchor_id(&anchor.identity_record());
        anchor.validate()?;
        Ok(anchor)
    }

    pub fn devnet_monero(
        label: &str,
        monero_height: u64,
        observed_at_l2_height: u64,
    ) -> ForcedInclusionResult<Self> {
        Self::new(
            L1AnchorKind::MoneroTransaction,
            "monero-devnet",
            monero_height,
            devnet_hash("devnet-monero-block", label),
            Some(monero_height),
            Some(devnet_hash("devnet-monero-txid", label)),
            Some(devnet_hash("devnet-monero-anchor-block", label)),
            observed_at_l2_height,
            FORCED_INCLUSION_DEFAULT_MONERO_FINALITY_BLOCKS,
            FORCED_INCLUSION_DEFAULT_MONERO_FINALITY_BLOCKS,
            forced_inclusion_string_root("FORCED-INCLUSION-DEVNET-MONERO-ANCHOR-PAYLOAD", label),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-MONERO-WATCHTOWER-ATTESTATION",
                label,
            ),
        )
    }

    pub fn devnet_watchtower(
        label: &str,
        l1_height: u64,
        observed_at_l2_height: u64,
    ) -> ForcedInclusionResult<Self> {
        Self::new(
            L1AnchorKind::WatchtowerAttestation,
            "nebula-l1-watchtower-devnet",
            l1_height,
            devnet_hash("devnet-watchtower-block", label),
            None,
            None,
            None,
            observed_at_l2_height,
            FORCED_INCLUSION_DEFAULT_L1_FINALITY_BLOCKS,
            FORCED_INCLUSION_DEFAULT_L1_FINALITY_BLOCKS,
            forced_inclusion_string_root("FORCED-INCLUSION-DEVNET-WATCHTOWER-PAYLOAD", label),
            forced_inclusion_string_root("FORCED-INCLUSION-DEVNET-WATCHTOWER-ATTESTATION", label),
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_l1_anchor_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "anchor_kind": self.anchor_kind.as_str(),
            "source_chain": self.source_chain,
            "l1_height": self.l1_height,
            "l1_block_hash": self.l1_block_hash,
            "monero_height": self.monero_height,
            "monero_txid": self.monero_txid,
            "monero_block_hash": self.monero_block_hash,
            "observed_at_l2_height": self.observed_at_l2_height,
            "confirmations": self.confirmations,
            "finality_threshold": self.finality_threshold,
            "payload_root": self.payload_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record.as_object_mut().expect("anchor record is object");
        object.insert(
            "anchor_id".to_string(),
            Value::String(self.anchor_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert("is_final".to_string(), Value::Bool(self.is_final()));
        record
    }

    pub fn is_final(&self) -> bool {
        self.confirmations >= self.finality_threshold
            && self.status == FORCED_INCLUSION_STATUS_FINALIZED
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.anchor_id != l1_inclusion_anchor_id(&self.identity_record()) {
            return Err("l1 inclusion anchor id mismatch".to_string());
        }
        ensure_non_empty(&self.source_chain, "l1 inclusion anchor source chain")?;
        ensure_non_empty(&self.l1_block_hash, "l1 inclusion anchor block hash")?;
        ensure_non_empty(&self.payload_root, "l1 inclusion anchor payload root")?;
        ensure_non_empty(
            &self.watchtower_attestation_root,
            "l1 inclusion anchor watchtower root",
        )?;
        ensure_status(&self.status, VALID_ANCHOR_STATUSES)?;
        if matches!(
            self.anchor_kind,
            L1AnchorKind::MoneroTransaction
                | L1AnchorKind::MoneroBlock
                | L1AnchorKind::MoneroViewKeyCheckpoint
        ) && self.monero_height.is_none()
        {
            return Err("monero inclusion anchor requires monero height".to_string());
        }
        Ok(self.anchor_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionDeadline {
    pub deadline_id: String,
    pub ticket_id: Option<String>,
    pub queue_id: String,
    pub queue_sequence: u64,
    pub anchor_id: String,
    pub deadline_mode: DeadlineMode,
    pub submitted_at_height: u64,
    pub earliest_include_height: u64,
    pub soft_deadline_height: u64,
    pub hard_deadline_height: u64,
    pub rescue_after_height: u64,
    pub challenge_after_height: u64,
    pub monero_unlock_height: Option<u64>,
    pub l1_expiry_height: Option<u64>,
    pub status: String,
}

impl InclusionDeadline {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue_id: impl Into<String>,
        queue_sequence: u64,
        anchor_id: impl Into<String>,
        deadline_mode: DeadlineMode,
        submitted_at_height: u64,
        earliest_include_height: u64,
        soft_deadline_height: u64,
        hard_deadline_height: u64,
        rescue_after_height: u64,
        challenge_after_height: u64,
        monero_unlock_height: Option<u64>,
        l1_expiry_height: Option<u64>,
    ) -> ForcedInclusionResult<Self> {
        let queue_id = queue_id.into();
        let anchor_id = anchor_id.into();
        ensure_non_empty(&queue_id, "inclusion deadline queue id")?;
        ensure_non_empty(&anchor_id, "inclusion deadline anchor id")?;
        if earliest_include_height < submitted_at_height {
            return Err("inclusion deadline earliest height before submission".to_string());
        }
        if soft_deadline_height < earliest_include_height {
            return Err("inclusion deadline soft height before earliest include".to_string());
        }
        if hard_deadline_height < soft_deadline_height {
            return Err("inclusion deadline hard height before soft height".to_string());
        }
        if rescue_after_height < hard_deadline_height {
            return Err("inclusion deadline rescue height before hard height".to_string());
        }
        let mut deadline = Self {
            deadline_id: String::new(),
            ticket_id: None,
            queue_id,
            queue_sequence,
            anchor_id,
            deadline_mode,
            submitted_at_height,
            earliest_include_height,
            soft_deadline_height,
            hard_deadline_height,
            rescue_after_height,
            challenge_after_height,
            monero_unlock_height,
            l1_expiry_height,
            status: FORCED_INCLUSION_STATUS_PENDING.to_string(),
        };
        deadline.deadline_id = inclusion_deadline_id(&deadline.identity_record());
        deadline.validate()?;
        Ok(deadline)
    }

    pub fn from_config(
        queue_id: &str,
        queue_sequence: u64,
        anchor: &L1InclusionAnchor,
        queue: &EscapeHatchQueue,
        config: &ForcedInclusionConfig,
        submitted_at_height: u64,
    ) -> ForcedInclusionResult<Self> {
        let soft_delay = queue
            .soft_delay_blocks
            .max(config.default_soft_delay_blocks);
        let hard_delay = queue
            .hard_delay_blocks
            .max(config.default_hard_delay_blocks);
        let rescue_delay = queue
            .rescue_delay_blocks
            .max(config.default_rescue_delay_blocks);
        let deadline_mode = match anchor.anchor_kind {
            L1AnchorKind::MoneroTransaction
            | L1AnchorKind::MoneroBlock
            | L1AnchorKind::MoneroViewKeyCheckpoint => DeadlineMode::MoneroFinality,
            L1AnchorKind::WatchtowerAttestation => DeadlineMode::WatchtowerObserved,
            _ => DeadlineMode::SequencerWindow,
        };
        let monero_unlock_height = anchor
            .monero_height
            .map(|height| height.saturating_add(config.monero_finality_blocks));
        let l1_expiry_height = Some(anchor.l1_height.saturating_add(config.l1_finality_blocks));
        Self::new(
            queue_id,
            queue_sequence,
            &anchor.anchor_id,
            deadline_mode,
            submitted_at_height,
            submitted_at_height,
            submitted_at_height.saturating_add(soft_delay),
            submitted_at_height.saturating_add(hard_delay),
            submitted_at_height.saturating_add(rescue_delay),
            submitted_at_height.saturating_add(config.default_challenge_window_blocks),
            monero_unlock_height,
            l1_expiry_height,
        )
    }

    pub fn attach_ticket_id(&mut self, ticket_id: impl Into<String>) -> ForcedInclusionResult<()> {
        let ticket_id = ticket_id.into();
        ensure_non_empty(&ticket_id, "inclusion deadline ticket id")?;
        self.ticket_id = Some(ticket_id);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record.as_object_mut().expect("deadline record is object");
        object.insert(
            "deadline_id".to_string(),
            Value::String(self.deadline_id.clone()),
        );
        object.insert("ticket_id".to_string(), json!(self.ticket_id));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "deadline_root".to_string(),
            Value::String(self.deadline_root()),
        );
        record
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_deadline_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "queue_id": self.queue_id,
            "queue_sequence": self.queue_sequence,
            "anchor_id": self.anchor_id,
            "deadline_mode": self.deadline_mode.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "earliest_include_height": self.earliest_include_height,
            "soft_deadline_height": self.soft_deadline_height,
            "hard_deadline_height": self.hard_deadline_height,
            "rescue_after_height": self.rescue_after_height,
            "challenge_after_height": self.challenge_after_height,
            "monero_unlock_height": self.monero_unlock_height,
            "l1_expiry_height": self.l1_expiry_height,
        })
    }

    pub fn deadline_root(&self) -> String {
        forced_inclusion_payload_root("FORCED-INCLUSION-DEADLINE-ROOT", &self.identity_record())
    }

    pub fn soft_due_at(&self, height: u64) -> bool {
        height >= self.soft_deadline_height
    }

    pub fn hard_due_at(&self, height: u64) -> bool {
        height >= self.hard_deadline_height
    }

    pub fn rescue_due_at(&self, height: u64) -> bool {
        height >= self.rescue_after_height
    }

    pub fn challenge_due_at(&self, height: u64) -> bool {
        height >= self.challenge_after_height
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.deadline_id != inclusion_deadline_id(&self.identity_record()) {
            return Err("inclusion deadline id mismatch".to_string());
        }
        ensure_non_empty(&self.queue_id, "inclusion deadline queue id")?;
        ensure_non_empty(&self.anchor_id, "inclusion deadline anchor id")?;
        ensure_status(&self.status, VALID_TICKET_STATUSES)?;
        if self.earliest_include_height < self.submitted_at_height {
            return Err("inclusion deadline earliest height before submission".to_string());
        }
        if self.soft_deadline_height < self.earliest_include_height {
            return Err("inclusion deadline soft height before earliest include".to_string());
        }
        if self.hard_deadline_height < self.soft_deadline_height {
            return Err("inclusion deadline hard height before soft height".to_string());
        }
        if self.rescue_after_height < self.hard_deadline_height {
            return Err("inclusion deadline rescue height before hard height".to_string());
        }
        Ok(self.deadline_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeHatchQueue {
    pub queue_id: String,
    pub label: String,
    pub queue_kind: EscapeQueueKind,
    pub priority_score: u64,
    pub max_depth: u64,
    pub min_bond_units: u64,
    pub max_ticket_bytes: u64,
    pub soft_delay_blocks: u64,
    pub hard_delay_blocks: u64,
    pub rescue_delay_blocks: u64,
    pub low_fee_min_share_bps: u64,
    pub privacy_preserving: bool,
    pub next_sequence: u64,
    pub pending_ticket_count: u64,
    pub public_ticket_count: u64,
    pub private_ticket_count: u64,
    pub included_ticket_count: u64,
    pub rescued_ticket_count: u64,
    pub oldest_pending_height: Option<u64>,
    pub ticket_root: String,
    pub deadline_root: String,
    pub sponsor_credit_root: String,
    pub status: String,
}

impl EscapeHatchQueue {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        queue_kind: EscapeQueueKind,
        max_depth: u64,
        min_bond_units: u64,
        max_ticket_bytes: u64,
        soft_delay_blocks: u64,
        hard_delay_blocks: u64,
        rescue_delay_blocks: u64,
    ) -> ForcedInclusionResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "escape hatch queue label")?;
        ensure_positive(max_depth, "escape hatch queue max depth")?;
        ensure_positive(min_bond_units, "escape hatch queue min bond")?;
        ensure_positive(max_ticket_bytes, "escape hatch queue max ticket bytes")?;
        if soft_delay_blocks > hard_delay_blocks {
            return Err("escape hatch queue soft delay exceeds hard delay".to_string());
        }
        if hard_delay_blocks > rescue_delay_blocks {
            return Err("escape hatch queue hard delay exceeds rescue delay".to_string());
        }
        let queue_id = escape_hatch_queue_id(
            &label,
            queue_kind,
            max_depth,
            min_bond_units,
            max_ticket_bytes,
            soft_delay_blocks,
            hard_delay_blocks,
            rescue_delay_blocks,
        );
        Ok(Self {
            queue_id,
            label,
            queue_kind,
            priority_score: queue_kind.default_priority_score(),
            max_depth,
            min_bond_units,
            max_ticket_bytes,
            soft_delay_blocks,
            hard_delay_blocks,
            rescue_delay_blocks,
            low_fee_min_share_bps: queue_kind.default_min_share_bps(),
            privacy_preserving: queue_kind.privacy_preserving_by_default(),
            next_sequence: 0,
            pending_ticket_count: 0,
            public_ticket_count: 0,
            private_ticket_count: 0,
            included_ticket_count: 0,
            rescued_ticket_count: 0,
            oldest_pending_height: None,
            ticket_root: forced_inclusion_empty_root("FORCED-INCLUSION-QUEUE-TICKET"),
            deadline_root: forced_inclusion_empty_root("FORCED-INCLUSION-QUEUE-DEADLINE"),
            sponsor_credit_root: forced_inclusion_empty_root(
                "FORCED-INCLUSION-QUEUE-SPONSOR-CREDIT",
            ),
            status: FORCED_INCLUSION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn devnet(label: &str, queue_kind: EscapeQueueKind) -> ForcedInclusionResult<Self> {
        Self::new(
            label,
            queue_kind,
            FORCED_INCLUSION_DEFAULT_MAX_QUEUE_DEPTH,
            FORCED_INCLUSION_DEFAULT_MIN_BOND_UNITS,
            FORCED_INCLUSION_DEFAULT_MAX_TICKET_BYTES,
            FORCED_INCLUSION_DEFAULT_SOFT_DELAY_BLOCKS,
            FORCED_INCLUSION_DEFAULT_HARD_DELAY_BLOCKS,
            FORCED_INCLUSION_DEFAULT_RESCUE_DELAY_BLOCKS,
        )
    }

    pub fn reserve_sequence(&mut self) -> ForcedInclusionResult<u64> {
        if self.pending_ticket_count >= self.max_depth {
            return Err("escape hatch queue is full".to_string());
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(sequence)
    }

    pub fn update_summary(
        &mut self,
        tickets: &[InclusionTicket],
        sponsor_credits: &[LowFeeSponsorCredit],
    ) {
        let queue_tickets = tickets
            .iter()
            .filter(|ticket| ticket.queue_id == self.queue_id)
            .cloned()
            .collect::<Vec<_>>();
        self.pending_ticket_count = queue_tickets
            .iter()
            .filter(|ticket| ticket.is_pending_like())
            .count() as u64;
        self.public_ticket_count = queue_tickets
            .iter()
            .filter(|ticket| !ticket.ticket_kind.requires_encryption())
            .count() as u64;
        self.private_ticket_count = queue_tickets
            .iter()
            .filter(|ticket| ticket.ticket_kind.requires_encryption())
            .count() as u64;
        self.included_ticket_count = queue_tickets
            .iter()
            .filter(|ticket| ticket.status == FORCED_INCLUSION_STATUS_INCLUDED)
            .count() as u64;
        self.rescued_ticket_count = queue_tickets
            .iter()
            .filter(|ticket| ticket.status == FORCED_INCLUSION_STATUS_RESCUED)
            .count() as u64;
        self.oldest_pending_height = queue_tickets
            .iter()
            .filter(|ticket| ticket.is_pending_like())
            .map(|ticket| ticket.submitted_at_height)
            .min();
        self.ticket_root = forced_inclusion_ticket_root(&queue_tickets);
        let deadlines = queue_tickets
            .iter()
            .map(|ticket| ticket.deadline.clone())
            .collect::<Vec<_>>();
        self.deadline_root = inclusion_deadline_root(&deadlines);
        let queue_sponsor_credits = sponsor_credits
            .iter()
            .filter(|credit| credit.queue_id == self.queue_id)
            .cloned()
            .collect::<Vec<_>>();
        self.sponsor_credit_root = low_fee_sponsor_credit_root(&queue_sponsor_credits);
    }

    pub fn available_depth(&self) -> u64 {
        self.max_depth.saturating_sub(self.pending_ticket_count)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_escape_hatch_queue",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "queue_id": self.queue_id,
            "label": self.label,
            "queue_kind": self.queue_kind.as_str(),
            "priority_score": self.priority_score,
            "max_depth": self.max_depth,
            "available_depth": self.available_depth(),
            "min_bond_units": self.min_bond_units,
            "max_ticket_bytes": self.max_ticket_bytes,
            "soft_delay_blocks": self.soft_delay_blocks,
            "hard_delay_blocks": self.hard_delay_blocks,
            "rescue_delay_blocks": self.rescue_delay_blocks,
            "low_fee_min_share_bps": self.low_fee_min_share_bps,
            "privacy_preserving": self.privacy_preserving,
            "next_sequence": self.next_sequence,
            "pending_ticket_count": self.pending_ticket_count,
            "public_ticket_count": self.public_ticket_count,
            "private_ticket_count": self.private_ticket_count,
            "included_ticket_count": self.included_ticket_count,
            "rescued_ticket_count": self.rescued_ticket_count,
            "oldest_pending_height": self.oldest_pending_height,
            "ticket_root": self.ticket_root,
            "deadline_root": self.deadline_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        ensure_non_empty(&self.queue_id, "escape hatch queue id")?;
        ensure_non_empty(&self.label, "escape hatch queue label")?;
        ensure_positive(self.max_depth, "escape hatch queue max depth")?;
        ensure_positive(self.min_bond_units, "escape hatch queue min bond")?;
        ensure_positive(self.max_ticket_bytes, "escape hatch queue max ticket bytes")?;
        ensure_bps(
            self.low_fee_min_share_bps,
            "escape hatch queue low fee share",
        )?;
        ensure_status(&self.status, VALID_QUEUE_STATUSES)?;
        Ok(self.queue_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionTicket {
    pub ticket_id: String,
    pub queue_id: String,
    pub queue_sequence: u64,
    pub ticket_kind: InclusionTicketKind,
    pub submitter_commitment: String,
    pub owner_commitment: String,
    pub public_payload_root: String,
    pub encrypted_payload_root: String,
    pub calldata_root: String,
    pub metadata: PrivacyPreservingTicketMetadata,
    pub l1_anchor: L1InclusionAnchor,
    pub deadline: InclusionDeadline,
    pub submitted_at_height: u64,
    pub claimed_at_height: Option<u64>,
    pub included_at_height: Option<u64>,
    pub rescued_at_height: Option<u64>,
    pub claimed_in_batch_id: Option<String>,
    pub inclusion_receipt_root: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub bond_units: u64,
    pub sponsor_credit_id: Option<String>,
    pub pq_authorization_root: String,
    pub status: String,
}

impl InclusionTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new_public(
        queue_id: impl Into<String>,
        queue_sequence: u64,
        ticket_kind: InclusionTicketKind,
        submitter_commitment: impl Into<String>,
        owner_commitment: impl Into<String>,
        public_payload: &Value,
        calldata_root: impl Into<String>,
        metadata: PrivacyPreservingTicketMetadata,
        l1_anchor: L1InclusionAnchor,
        deadline: InclusionDeadline,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        bond_units: u64,
        sponsor_credit_id: Option<String>,
        pq_authorization_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        Self::build(
            queue_id,
            queue_sequence,
            ticket_kind,
            submitter_commitment,
            owner_commitment,
            forced_inclusion_payload_root("FORCED-INCLUSION-PUBLIC-TICKET-PAYLOAD", public_payload),
            forced_inclusion_empty_root("FORCED-INCLUSION-ENCRYPTED-TICKET-PAYLOAD"),
            calldata_root,
            metadata,
            l1_anchor,
            deadline,
            fee_asset_id,
            max_fee_units,
            bond_units,
            sponsor_credit_id,
            pq_authorization_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_encrypted(
        queue_id: impl Into<String>,
        queue_sequence: u64,
        ticket_kind: InclusionTicketKind,
        submitter_commitment: impl Into<String>,
        owner_commitment: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        calldata_root: impl Into<String>,
        metadata: PrivacyPreservingTicketMetadata,
        l1_anchor: L1InclusionAnchor,
        deadline: InclusionDeadline,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        bond_units: u64,
        sponsor_credit_id: Option<String>,
        pq_authorization_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        Self::build(
            queue_id,
            queue_sequence,
            ticket_kind,
            submitter_commitment,
            owner_commitment,
            forced_inclusion_empty_root("FORCED-INCLUSION-PUBLIC-TICKET-PAYLOAD"),
            encrypted_payload_root,
            calldata_root,
            metadata,
            l1_anchor,
            deadline,
            fee_asset_id,
            max_fee_units,
            bond_units,
            sponsor_credit_id,
            pq_authorization_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        queue_id: impl Into<String>,
        queue_sequence: u64,
        ticket_kind: InclusionTicketKind,
        submitter_commitment: impl Into<String>,
        owner_commitment: impl Into<String>,
        public_payload_root: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        calldata_root: impl Into<String>,
        metadata: PrivacyPreservingTicketMetadata,
        l1_anchor: L1InclusionAnchor,
        mut deadline: InclusionDeadline,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        bond_units: u64,
        sponsor_credit_id: Option<String>,
        pq_authorization_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let queue_id = queue_id.into();
        let submitter_commitment = submitter_commitment.into();
        let owner_commitment = owner_commitment.into();
        let public_payload_root = public_payload_root.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let calldata_root = calldata_root.into();
        let fee_asset_id = fee_asset_id.into();
        let pq_authorization_root = pq_authorization_root.into();
        ensure_non_empty(&queue_id, "inclusion ticket queue id")?;
        ensure_non_empty(
            &submitter_commitment,
            "inclusion ticket submitter commitment",
        )?;
        ensure_non_empty(&owner_commitment, "inclusion ticket owner commitment")?;
        ensure_non_empty(&public_payload_root, "inclusion ticket public payload root")?;
        ensure_non_empty(
            &encrypted_payload_root,
            "inclusion ticket encrypted payload root",
        )?;
        ensure_non_empty(&calldata_root, "inclusion ticket calldata root")?;
        ensure_non_empty(&fee_asset_id, "inclusion ticket fee asset")?;
        ensure_positive(bond_units, "inclusion ticket bond")?;
        ensure_non_empty(&pq_authorization_root, "inclusion ticket pq authorization")?;
        metadata.validate()?;
        l1_anchor.validate()?;
        deadline.validate()?;
        let ticket_id = inclusion_ticket_id(
            &queue_id,
            queue_sequence,
            ticket_kind,
            &submitter_commitment,
            &owner_commitment,
            &public_payload_root,
            &encrypted_payload_root,
            &calldata_root,
            &metadata.metadata_root(),
            &l1_anchor.anchor_id,
            &deadline.deadline_id,
            &fee_asset_id,
            max_fee_units,
            bond_units,
            sponsor_credit_id.as_deref().unwrap_or("none"),
            &pq_authorization_root,
        );
        deadline.attach_ticket_id(ticket_id.clone())?;
        let submitted_at_height = deadline.submitted_at_height;
        let ticket = Self {
            ticket_id,
            queue_id,
            queue_sequence,
            ticket_kind,
            submitter_commitment,
            owner_commitment,
            public_payload_root,
            encrypted_payload_root,
            calldata_root,
            metadata,
            l1_anchor,
            deadline,
            submitted_at_height,
            claimed_at_height: None,
            included_at_height: None,
            rescued_at_height: None,
            claimed_in_batch_id: None,
            inclusion_receipt_root: forced_inclusion_empty_root("FORCED-INCLUSION-TICKET-RECEIPT"),
            fee_asset_id,
            max_fee_units,
            bond_units,
            sponsor_credit_id,
            pq_authorization_root,
            status: FORCED_INCLUSION_STATUS_PENDING.to_string(),
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn mark_claimed(
        &mut self,
        batch_id: impl Into<String>,
        claimed_at_height: u64,
        receipt_root: impl Into<String>,
    ) -> ForcedInclusionResult<()> {
        let batch_id = batch_id.into();
        let receipt_root = receipt_root.into();
        ensure_non_empty(&batch_id, "inclusion ticket claim batch id")?;
        ensure_non_empty(&receipt_root, "inclusion ticket receipt root")?;
        self.claimed_in_batch_id = Some(batch_id);
        self.claimed_at_height = Some(claimed_at_height);
        self.inclusion_receipt_root = receipt_root;
        self.status = FORCED_INCLUSION_STATUS_CLAIMED.to_string();
        Ok(())
    }

    pub fn mark_included(
        &mut self,
        included_at_height: u64,
        receipt_root: impl Into<String>,
    ) -> ForcedInclusionResult<()> {
        let receipt_root = receipt_root.into();
        ensure_non_empty(&receipt_root, "inclusion ticket inclusion receipt")?;
        self.included_at_height = Some(included_at_height);
        self.inclusion_receipt_root = receipt_root;
        self.status = FORCED_INCLUSION_STATUS_INCLUDED.to_string();
        Ok(())
    }

    pub fn mark_rescue_eligible(&mut self) {
        if self.is_pending_like() {
            self.status = FORCED_INCLUSION_STATUS_RESCUE_ELIGIBLE.to_string();
        }
    }

    pub fn mark_rescue_queued(&mut self) {
        if self.status == FORCED_INCLUSION_STATUS_RESCUE_ELIGIBLE {
            self.status = FORCED_INCLUSION_STATUS_RESCUE_QUEUED.to_string();
        }
    }

    pub fn mark_rescued(
        &mut self,
        rescued_at_height: u64,
        receipt_root: impl Into<String>,
    ) -> ForcedInclusionResult<()> {
        let receipt_root = receipt_root.into();
        ensure_non_empty(&receipt_root, "inclusion ticket rescue receipt")?;
        self.rescued_at_height = Some(rescued_at_height);
        self.inclusion_receipt_root = receipt_root;
        self.status = FORCED_INCLUSION_STATUS_RESCUED.to_string();
        Ok(())
    }

    pub fn is_pending_like(&self) -> bool {
        matches!(
            self.status.as_str(),
            FORCED_INCLUSION_STATUS_PENDING
                | FORCED_INCLUSION_STATUS_COMMITTED
                | FORCED_INCLUSION_STATUS_RESCUE_ELIGIBLE
                | FORCED_INCLUSION_STATUS_RESCUE_QUEUED
                | FORCED_INCLUSION_STATUS_CHALLENGED
        )
    }

    pub fn soft_due_at(&self, height: u64) -> bool {
        self.deadline.soft_due_at(height) && self.is_pending_like()
    }

    pub fn hard_due_at(&self, height: u64) -> bool {
        self.deadline.hard_due_at(height) && self.is_pending_like()
    }

    pub fn rescue_due_at(&self, height: u64) -> bool {
        self.deadline.rescue_due_at(height) && self.is_pending_like()
    }

    pub fn ticket_payload_root(&self) -> String {
        domain_hash(
            "FORCED-INCLUSION-TICKET-PAYLOAD-ROOT",
            &[
                HashPart::Str(&self.public_payload_root),
                HashPart::Str(&self.encrypted_payload_root),
                HashPart::Str(&self.calldata_root),
            ],
            32,
        )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_ticket_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "queue_id": self.queue_id,
            "queue_sequence": self.queue_sequence,
            "ticket_kind": self.ticket_kind.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "owner_commitment": self.owner_commitment,
            "public_payload_root": self.public_payload_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "calldata_root": self.calldata_root,
            "metadata_root": self.metadata.metadata_root(),
            "l1_anchor_id": self.l1_anchor.anchor_id,
            "deadline_id": self.deadline.deadline_id,
            "submitted_at_height": self.submitted_at_height,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "bond_units": self.bond_units,
            "sponsor_credit_id": self.sponsor_credit_id,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record.as_object_mut().expect("ticket record is object");
        object.insert(
            "ticket_id".to_string(),
            Value::String(self.ticket_id.clone()),
        );
        object.insert(
            "ticket_payload_root".to_string(),
            Value::String(self.ticket_payload_root()),
        );
        object.insert("metadata".to_string(), self.metadata.public_record());
        object.insert("l1_anchor".to_string(), self.l1_anchor.public_record());
        object.insert("deadline".to_string(), self.deadline.public_record());
        object.insert(
            "claimed_at_height".to_string(),
            json!(self.claimed_at_height),
        );
        object.insert(
            "included_at_height".to_string(),
            json!(self.included_at_height),
        );
        object.insert(
            "rescued_at_height".to_string(),
            json!(self.rescued_at_height),
        );
        object.insert(
            "claimed_in_batch_id".to_string(),
            json!(self.claimed_in_batch_id),
        );
        object.insert(
            "inclusion_receipt_root".to_string(),
            Value::String(self.inclusion_receipt_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "ticket_root".to_string(),
            Value::String(forced_inclusion_payload_root(
                "FORCED-INCLUSION-TICKET-ROOT",
                &self.identity_record(),
            )),
        );
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        let expected_ticket_id = inclusion_ticket_id(
            &self.queue_id,
            self.queue_sequence,
            self.ticket_kind,
            &self.submitter_commitment,
            &self.owner_commitment,
            &self.public_payload_root,
            &self.encrypted_payload_root,
            &self.calldata_root,
            &self.metadata.metadata_root(),
            &self.l1_anchor.anchor_id,
            &self.deadline.deadline_id,
            &self.fee_asset_id,
            self.max_fee_units,
            self.bond_units,
            self.sponsor_credit_id.as_deref().unwrap_or("none"),
            &self.pq_authorization_root,
        );
        if self.ticket_id != expected_ticket_id {
            return Err("inclusion ticket id mismatch".to_string());
        }
        ensure_non_empty(&self.ticket_id, "inclusion ticket id")?;
        ensure_non_empty(&self.queue_id, "inclusion ticket queue id")?;
        ensure_non_empty(&self.submitter_commitment, "inclusion ticket submitter")?;
        ensure_non_empty(&self.owner_commitment, "inclusion ticket owner")?;
        ensure_non_empty(&self.public_payload_root, "inclusion ticket public payload")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "inclusion ticket encrypted payload",
        )?;
        ensure_non_empty(&self.calldata_root, "inclusion ticket calldata")?;
        ensure_non_empty(&self.fee_asset_id, "inclusion ticket fee asset")?;
        ensure_positive(self.bond_units, "inclusion ticket bond")?;
        ensure_status(&self.status, VALID_TICKET_STATUSES)?;
        self.metadata.validate()?;
        self.l1_anchor.validate()?;
        self.deadline.validate()?;
        if self.deadline.ticket_id.as_deref() != Some(self.ticket_id.as_str()) {
            return Err("inclusion ticket deadline is not attached".to_string());
        }
        Ok(self.ticket_id.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeResponseKind {
    InclusionReceipt,
    ValidRejection,
    RescueCommitted,
    QueueRootCorrection,
    SponsorRefund,
    NoResponse,
}

impl ChallengeResponseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InclusionReceipt => "inclusion_receipt",
            Self::ValidRejection => "valid_rejection",
            Self::RescueCommitted => "rescue_committed",
            Self::QueueRootCorrection => "queue_root_correction",
            Self::SponsorRefund => "sponsor_refund",
            Self::NoResponse => "no_response",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerOmissionEvidence {
    pub evidence_id: String,
    pub evidence_kind: OmissionEvidenceKind,
    pub ticket_id: String,
    pub queue_id: String,
    pub queue_sequence: u64,
    pub operator_id: String,
    pub observer_id: String,
    pub observed_at_height: u64,
    pub omitted_batch_id: String,
    pub omitted_batch_height: u64,
    pub claimed_queue_root: String,
    pub observed_queue_root: String,
    pub expected_ticket_root: String,
    pub sequencer_statement_root: String,
    pub watchtower_trace_root: String,
    pub l1_anchor: L1InclusionAnchor,
    pub deadline_snapshot: InclusionDeadline,
    pub challenge_window_end_height: u64,
    pub status: String,
}

impl SequencerOmissionEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evidence_kind: OmissionEvidenceKind,
        ticket: &InclusionTicket,
        operator_id: impl Into<String>,
        observer_id: impl Into<String>,
        observed_at_height: u64,
        omitted_batch_id: impl Into<String>,
        omitted_batch_height: u64,
        claimed_queue_root: impl Into<String>,
        observed_queue_root: impl Into<String>,
        sequencer_statement_root: impl Into<String>,
        watchtower_trace_root: impl Into<String>,
        challenge_window_blocks: u64,
    ) -> ForcedInclusionResult<Self> {
        let operator_id = operator_id.into();
        let observer_id = observer_id.into();
        let omitted_batch_id = omitted_batch_id.into();
        let claimed_queue_root = claimed_queue_root.into();
        let observed_queue_root = observed_queue_root.into();
        let sequencer_statement_root = sequencer_statement_root.into();
        let watchtower_trace_root = watchtower_trace_root.into();
        ensure_non_empty(&operator_id, "omission evidence operator id")?;
        ensure_non_empty(&observer_id, "omission evidence observer id")?;
        ensure_non_empty(&omitted_batch_id, "omission evidence batch id")?;
        ensure_non_empty(&claimed_queue_root, "omission evidence claimed queue root")?;
        ensure_non_empty(
            &observed_queue_root,
            "omission evidence observed queue root",
        )?;
        ensure_non_empty(
            &sequencer_statement_root,
            "omission evidence sequencer statement root",
        )?;
        ensure_non_empty(
            &watchtower_trace_root,
            "omission evidence watchtower trace root",
        )?;
        ticket.validate()?;
        let mut evidence = Self {
            evidence_id: String::new(),
            evidence_kind,
            ticket_id: ticket.ticket_id.clone(),
            queue_id: ticket.queue_id.clone(),
            queue_sequence: ticket.queue_sequence,
            operator_id,
            observer_id,
            observed_at_height,
            omitted_batch_id,
            omitted_batch_height,
            claimed_queue_root,
            observed_queue_root,
            expected_ticket_root: forced_inclusion_payload_root(
                "FORCED-INCLUSION-OMISSION-EXPECTED-TICKET",
                &ticket.public_record(),
            ),
            sequencer_statement_root,
            watchtower_trace_root,
            l1_anchor: ticket.l1_anchor.clone(),
            deadline_snapshot: ticket.deadline.clone(),
            challenge_window_end_height: observed_at_height.saturating_add(challenge_window_blocks),
            status: FORCED_INCLUSION_STATUS_OPEN.to_string(),
        };
        evidence.evidence_id = sequencer_omission_evidence_id(&evidence.identity_record());
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn is_actionable_at(&self, height: u64) -> bool {
        height >= self.deadline_snapshot.hard_deadline_height
            && height <= self.challenge_window_end_height
            && self.status == FORCED_INCLUSION_STATUS_OPEN
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_omission_evidence_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "evidence_kind": self.evidence_kind.as_str(),
            "ticket_id": self.ticket_id,
            "queue_id": self.queue_id,
            "queue_sequence": self.queue_sequence,
            "operator_id": self.operator_id,
            "observer_id": self.observer_id,
            "observed_at_height": self.observed_at_height,
            "omitted_batch_id": self.omitted_batch_id,
            "omitted_batch_height": self.omitted_batch_height,
            "claimed_queue_root": self.claimed_queue_root,
            "observed_queue_root": self.observed_queue_root,
            "expected_ticket_root": self.expected_ticket_root,
            "sequencer_statement_root": self.sequencer_statement_root,
            "watchtower_trace_root": self.watchtower_trace_root,
            "l1_anchor_id": self.l1_anchor.anchor_id,
            "deadline_id": self.deadline_snapshot.deadline_id,
            "challenge_window_end_height": self.challenge_window_end_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("omission evidence record is object");
        object.insert(
            "evidence_id".to_string(),
            Value::String(self.evidence_id.clone()),
        );
        object.insert("l1_anchor".to_string(), self.l1_anchor.public_record());
        object.insert(
            "deadline_snapshot".to_string(),
            self.deadline_snapshot.public_record(),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "evidence_root".to_string(),
            Value::String(forced_inclusion_payload_root(
                "FORCED-INCLUSION-OMISSION-EVIDENCE-ROOT",
                &self.identity_record(),
            )),
        );
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.evidence_id != sequencer_omission_evidence_id(&self.identity_record()) {
            return Err("omission evidence id mismatch".to_string());
        }
        ensure_non_empty(&self.ticket_id, "omission evidence ticket id")?;
        ensure_non_empty(&self.queue_id, "omission evidence queue id")?;
        ensure_non_empty(&self.operator_id, "omission evidence operator id")?;
        ensure_non_empty(&self.observer_id, "omission evidence observer id")?;
        ensure_non_empty(&self.omitted_batch_id, "omission evidence batch id")?;
        ensure_non_empty(&self.claimed_queue_root, "omission evidence claimed root")?;
        ensure_non_empty(&self.observed_queue_root, "omission evidence observed root")?;
        ensure_non_empty(&self.expected_ticket_root, "omission evidence ticket root")?;
        ensure_non_empty(
            &self.sequencer_statement_root,
            "omission evidence sequencer statement root",
        )?;
        ensure_status(&self.status, VALID_CHALLENGE_STATUSES)?;
        self.l1_anchor.validate()?;
        self.deadline_snapshot.validate()?;
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionChallengeResponse {
    pub response_id: String,
    pub challenge_id: String,
    pub response_kind: ChallengeResponseKind,
    pub operator_id: String,
    pub ticket_id: String,
    pub included_batch_id: Option<String>,
    pub response_payload_root: String,
    pub inclusion_receipt_root: String,
    pub corrected_queue_root: String,
    pub sponsor_refund_root: String,
    pub responded_at_height: u64,
    pub pq_signature_root: String,
    pub status: String,
}

impl InclusionChallengeResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: impl Into<String>,
        response_kind: ChallengeResponseKind,
        operator_id: impl Into<String>,
        ticket_id: impl Into<String>,
        included_batch_id: Option<String>,
        response_payload_root: impl Into<String>,
        inclusion_receipt_root: impl Into<String>,
        corrected_queue_root: impl Into<String>,
        sponsor_refund_root: impl Into<String>,
        responded_at_height: u64,
        pq_signature_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let challenge_id = challenge_id.into();
        let operator_id = operator_id.into();
        let ticket_id = ticket_id.into();
        let response_payload_root = response_payload_root.into();
        let inclusion_receipt_root = inclusion_receipt_root.into();
        let corrected_queue_root = corrected_queue_root.into();
        let sponsor_refund_root = sponsor_refund_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&challenge_id, "challenge response challenge id")?;
        ensure_non_empty(&operator_id, "challenge response operator id")?;
        ensure_non_empty(&ticket_id, "challenge response ticket id")?;
        ensure_non_empty(&response_payload_root, "challenge response payload root")?;
        ensure_non_empty(
            &inclusion_receipt_root,
            "challenge response inclusion receipt root",
        )?;
        ensure_non_empty(
            &corrected_queue_root,
            "challenge response corrected queue root",
        )?;
        ensure_non_empty(
            &sponsor_refund_root,
            "challenge response sponsor refund root",
        )?;
        ensure_non_empty(&pq_signature_root, "challenge response pq signature root")?;
        let mut response = Self {
            response_id: String::new(),
            challenge_id,
            response_kind,
            operator_id,
            ticket_id,
            included_batch_id,
            response_payload_root,
            inclusion_receipt_root,
            corrected_queue_root,
            sponsor_refund_root,
            responded_at_height,
            pq_signature_root,
            status: FORCED_INCLUSION_STATUS_COMMITTED.to_string(),
        };
        response.response_id = inclusion_challenge_response_id(&response.identity_record());
        response.validate()?;
        Ok(response)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_challenge_response_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "response_kind": self.response_kind.as_str(),
            "operator_id": self.operator_id,
            "ticket_id": self.ticket_id,
            "included_batch_id": self.included_batch_id,
            "response_payload_root": self.response_payload_root,
            "inclusion_receipt_root": self.inclusion_receipt_root,
            "corrected_queue_root": self.corrected_queue_root,
            "sponsor_refund_root": self.sponsor_refund_root,
            "responded_at_height": self.responded_at_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("challenge response record is object");
        object.insert(
            "response_id".to_string(),
            Value::String(self.response_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "response_root".to_string(),
            Value::String(forced_inclusion_payload_root(
                "FORCED-INCLUSION-CHALLENGE-RESPONSE-ROOT",
                &self.identity_record(),
            )),
        );
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.response_id != inclusion_challenge_response_id(&self.identity_record()) {
            return Err("challenge response id mismatch".to_string());
        }
        ensure_non_empty(&self.challenge_id, "challenge response challenge id")?;
        ensure_non_empty(&self.operator_id, "challenge response operator id")?;
        ensure_non_empty(&self.ticket_id, "challenge response ticket id")?;
        ensure_status(&self.status, VALID_OPERATOR_ACTION_STATUSES)?;
        Ok(self.response_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionChallenge {
    pub challenge_id: String,
    pub challenge_kind: InclusionChallengeKind,
    pub evidence_id: String,
    pub ticket_id: String,
    pub queue_id: String,
    pub challenger_commitment: String,
    pub operator_id: String,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub resolution_deadline_height: u64,
    pub challenge_bond_units: u64,
    pub requested_action_root: String,
    pub evidence_root: String,
    pub response: Option<InclusionChallengeResponse>,
    pub resolution_root: String,
    pub status: String,
}

impl InclusionChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_kind: InclusionChallengeKind,
        evidence: &SequencerOmissionEvidence,
        challenger_commitment: impl Into<String>,
        opened_at_height: u64,
        response_window_blocks: u64,
        resolution_window_blocks: u64,
        challenge_bond_units: u64,
        requested_action_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let challenger_commitment = challenger_commitment.into();
        let requested_action_root = requested_action_root.into();
        ensure_non_empty(&challenger_commitment, "inclusion challenge challenger")?;
        ensure_positive(challenge_bond_units, "inclusion challenge bond")?;
        ensure_non_empty(
            &requested_action_root,
            "inclusion challenge requested action",
        )?;
        evidence.validate()?;
        let mut challenge = Self {
            challenge_id: String::new(),
            challenge_kind,
            evidence_id: evidence.evidence_id.clone(),
            ticket_id: evidence.ticket_id.clone(),
            queue_id: evidence.queue_id.clone(),
            challenger_commitment,
            operator_id: evidence.operator_id.clone(),
            opened_at_height,
            response_deadline_height: opened_at_height.saturating_add(response_window_blocks),
            resolution_deadline_height: opened_at_height
                .saturating_add(response_window_blocks)
                .saturating_add(resolution_window_blocks),
            challenge_bond_units,
            requested_action_root,
            evidence_root: forced_inclusion_payload_root(
                "FORCED-INCLUSION-CHALLENGE-EVIDENCE",
                &evidence.public_record(),
            ),
            response: None,
            resolution_root: forced_inclusion_empty_root("FORCED-INCLUSION-CHALLENGE-RESOLUTION"),
            status: FORCED_INCLUSION_STATUS_OPEN.to_string(),
        };
        challenge.challenge_id = inclusion_challenge_id(&challenge.identity_record());
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn attach_response(
        &mut self,
        response: InclusionChallengeResponse,
    ) -> ForcedInclusionResult<()> {
        response.validate()?;
        if response.challenge_id != self.challenge_id {
            return Err("challenge response belongs to a different challenge".to_string());
        }
        self.response = Some(response);
        self.status = FORCED_INCLUSION_STATUS_COMMITTED.to_string();
        Ok(())
    }

    pub fn resolve(
        &mut self,
        resolution_root: impl Into<String>,
        slashed: bool,
    ) -> ForcedInclusionResult<()> {
        let resolution_root = resolution_root.into();
        ensure_non_empty(&resolution_root, "inclusion challenge resolution root")?;
        self.resolution_root = resolution_root;
        self.status = if slashed {
            FORCED_INCLUSION_STATUS_SLASHED.to_string()
        } else {
            FORCED_INCLUSION_STATUS_RESOLVED.to_string()
        };
        Ok(())
    }

    pub fn response_overdue_at(&self, height: u64) -> bool {
        self.response.is_none()
            && height > self.response_deadline_height
            && self.status == FORCED_INCLUSION_STATUS_OPEN
    }

    pub fn resolution_overdue_at(&self, height: u64) -> bool {
        height > self.resolution_deadline_height
            && matches!(
                self.status.as_str(),
                FORCED_INCLUSION_STATUS_OPEN | FORCED_INCLUSION_STATUS_COMMITTED
            )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_challenge_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "challenge_kind": self.challenge_kind.as_str(),
            "evidence_id": self.evidence_id,
            "ticket_id": self.ticket_id,
            "queue_id": self.queue_id,
            "challenger_commitment": self.challenger_commitment,
            "operator_id": self.operator_id,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "resolution_deadline_height": self.resolution_deadline_height,
            "challenge_bond_units": self.challenge_bond_units,
            "requested_action_root": self.requested_action_root,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record.as_object_mut().expect("challenge record is object");
        object.insert(
            "challenge_id".to_string(),
            Value::String(self.challenge_id.clone()),
        );
        object.insert(
            "response".to_string(),
            self.response
                .as_ref()
                .map(InclusionChallengeResponse::public_record)
                .unwrap_or(Value::Null),
        );
        object.insert(
            "resolution_root".to_string(),
            Value::String(self.resolution_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "challenge_root".to_string(),
            Value::String(forced_inclusion_payload_root(
                "FORCED-INCLUSION-CHALLENGE-ROOT",
                &self.identity_record(),
            )),
        );
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.challenge_id != inclusion_challenge_id(&self.identity_record()) {
            return Err("inclusion challenge id mismatch".to_string());
        }
        ensure_non_empty(&self.evidence_id, "inclusion challenge evidence id")?;
        ensure_non_empty(&self.ticket_id, "inclusion challenge ticket id")?;
        ensure_non_empty(&self.queue_id, "inclusion challenge queue id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "inclusion challenge challenger",
        )?;
        ensure_non_empty(&self.operator_id, "inclusion challenge operator")?;
        ensure_non_empty(
            &self.requested_action_root,
            "inclusion challenge requested action",
        )?;
        ensure_non_empty(&self.evidence_root, "inclusion challenge evidence root")?;
        ensure_positive(self.challenge_bond_units, "inclusion challenge bond")?;
        ensure_status(&self.status, VALID_CHALLENGE_STATUSES)?;
        if self.response_deadline_height < self.opened_at_height {
            return Err("challenge response deadline before opened height".to_string());
        }
        if self.resolution_deadline_height < self.response_deadline_height {
            return Err("challenge resolution deadline before response deadline".to_string());
        }
        if let Some(response) = &self.response {
            response.validate()?;
        }
        Ok(self.challenge_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RescueManifestItem {
    pub item_id: String,
    pub ticket_id: String,
    pub queue_id: String,
    pub queue_sequence: u64,
    pub rescue_order: u64,
    pub ticket_payload_root: String,
    pub metadata_root: String,
    pub deadline_root: String,
    pub sponsor_credit_id: Option<String>,
    pub expected_state_transition_root: String,
    pub privacy_disclosure_root: String,
    pub low_fee_credit_units: u64,
    pub status: String,
}

impl RescueManifestItem {
    pub fn from_ticket(
        ticket: &InclusionTicket,
        rescue_order: u64,
        expected_state_transition_root: impl Into<String>,
        privacy_disclosure_root: impl Into<String>,
        low_fee_credit_units: u64,
    ) -> ForcedInclusionResult<Self> {
        ticket.validate()?;
        let expected_state_transition_root = expected_state_transition_root.into();
        let privacy_disclosure_root = privacy_disclosure_root.into();
        ensure_non_empty(
            &expected_state_transition_root,
            "rescue manifest item transition root",
        )?;
        ensure_non_empty(
            &privacy_disclosure_root,
            "rescue manifest item disclosure root",
        )?;
        let mut item = Self {
            item_id: String::new(),
            ticket_id: ticket.ticket_id.clone(),
            queue_id: ticket.queue_id.clone(),
            queue_sequence: ticket.queue_sequence,
            rescue_order,
            ticket_payload_root: ticket.ticket_payload_root(),
            metadata_root: ticket.metadata.metadata_root(),
            deadline_root: ticket.deadline.deadline_root(),
            sponsor_credit_id: ticket.sponsor_credit_id.clone(),
            expected_state_transition_root,
            privacy_disclosure_root,
            low_fee_credit_units,
            status: FORCED_INCLUSION_STATUS_PENDING.to_string(),
        };
        item.item_id = rescue_manifest_item_id(&item.identity_record());
        item.validate()?;
        Ok(item)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_rescue_manifest_item_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "queue_id": self.queue_id,
            "queue_sequence": self.queue_sequence,
            "rescue_order": self.rescue_order,
            "ticket_payload_root": self.ticket_payload_root,
            "metadata_root": self.metadata_root,
            "deadline_root": self.deadline_root,
            "sponsor_credit_id": self.sponsor_credit_id,
            "expected_state_transition_root": self.expected_state_transition_root,
            "privacy_disclosure_root": self.privacy_disclosure_root,
            "low_fee_credit_units": self.low_fee_credit_units,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("rescue manifest item record is object");
        object.insert("item_id".to_string(), Value::String(self.item_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.item_id != rescue_manifest_item_id(&self.identity_record()) {
            return Err("rescue manifest item id mismatch".to_string());
        }
        ensure_non_empty(&self.ticket_id, "rescue manifest item ticket id")?;
        ensure_non_empty(&self.queue_id, "rescue manifest item queue id")?;
        ensure_non_empty(
            &self.ticket_payload_root,
            "rescue manifest item payload root",
        )?;
        ensure_non_empty(&self.metadata_root, "rescue manifest item metadata root")?;
        ensure_non_empty(&self.deadline_root, "rescue manifest item deadline root")?;
        ensure_non_empty(
            &self.expected_state_transition_root,
            "rescue manifest item transition root",
        )?;
        ensure_status(&self.status, VALID_RESCUE_STATUSES)?;
        Ok(self.item_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRescueManifest {
    pub manifest_id: String,
    pub manifest_kind: RescueManifestKind,
    pub manifest_index: u64,
    pub operator_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
    pub items: Vec<RescueManifestItem>,
    pub item_root: String,
    pub ticket_root: String,
    pub deadline_root: String,
    pub sponsor_credit_root: String,
    pub operator_action_root: String,
    pub l1_anchor_root: String,
    pub rescue_batch_payload_root: String,
    pub status: String,
}

impl BatchRescueManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_kind: RescueManifestKind,
        manifest_index: u64,
        operator_id: impl Into<String>,
        start_height: u64,
        end_height: u64,
        produced_at_height: u64,
        expires_at_height: u64,
        items: Vec<RescueManifestItem>,
        sponsor_credit_root: impl Into<String>,
        operator_action_root: impl Into<String>,
        l1_anchor_root: impl Into<String>,
        rescue_batch_payload_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let operator_id = operator_id.into();
        let sponsor_credit_root = sponsor_credit_root.into();
        let operator_action_root = operator_action_root.into();
        let l1_anchor_root = l1_anchor_root.into();
        let rescue_batch_payload_root = rescue_batch_payload_root.into();
        ensure_non_empty(&operator_id, "rescue manifest operator id")?;
        ensure_non_empty(&sponsor_credit_root, "rescue manifest sponsor root")?;
        ensure_non_empty(
            &operator_action_root,
            "rescue manifest operator action root",
        )?;
        ensure_non_empty(&l1_anchor_root, "rescue manifest l1 anchor root")?;
        ensure_non_empty(&rescue_batch_payload_root, "rescue manifest payload root")?;
        if end_height < start_height {
            return Err("rescue manifest end height before start height".to_string());
        }
        if expires_at_height < produced_at_height {
            return Err("rescue manifest expires before produced height".to_string());
        }
        let item_root = rescue_manifest_item_root(&items);
        let ticket_root = forced_inclusion_string_set_root(
            "FORCED-INCLUSION-RESCUE-MANIFEST-TICKET-ID",
            &items
                .iter()
                .map(|item| item.ticket_id.clone())
                .collect::<Vec<_>>(),
        );
        let deadline_root = forced_inclusion_string_set_root(
            "FORCED-INCLUSION-RESCUE-MANIFEST-DEADLINE",
            &items
                .iter()
                .map(|item| item.deadline_root.clone())
                .collect::<Vec<_>>(),
        );
        let mut manifest = Self {
            manifest_id: String::new(),
            manifest_kind,
            manifest_index,
            operator_id,
            start_height,
            end_height,
            produced_at_height,
            expires_at_height,
            items,
            item_root,
            ticket_root,
            deadline_root,
            sponsor_credit_root,
            operator_action_root,
            l1_anchor_root,
            rescue_batch_payload_root,
            status: FORCED_INCLUSION_STATUS_PENDING.to_string(),
        };
        manifest.manifest_id = batch_rescue_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn item_count(&self) -> u64 {
        self.items.len() as u64
    }

    pub fn total_low_fee_credit_units(&self) -> u64 {
        self.items
            .iter()
            .map(|item| item.low_fee_credit_units)
            .sum()
    }

    pub fn mark_committed(&mut self) {
        self.status = FORCED_INCLUSION_STATUS_COMMITTED.to_string();
    }

    pub fn mark_finalized(&mut self) {
        self.status = FORCED_INCLUSION_STATUS_FINALIZED.to_string();
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_batch_rescue_manifest_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "manifest_kind": self.manifest_kind.as_str(),
            "manifest_index": self.manifest_index,
            "operator_id": self.operator_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "produced_at_height": self.produced_at_height,
            "expires_at_height": self.expires_at_height,
            "item_root": self.item_root,
            "ticket_root": self.ticket_root,
            "deadline_root": self.deadline_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "operator_action_root": self.operator_action_root,
            "l1_anchor_root": self.l1_anchor_root,
            "rescue_batch_payload_root": self.rescue_batch_payload_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("rescue manifest record is object");
        object.insert(
            "manifest_id".to_string(),
            Value::String(self.manifest_id.clone()),
        );
        object.insert("item_count".to_string(), json!(self.item_count()));
        object.insert(
            "total_low_fee_credit_units".to_string(),
            json!(self.total_low_fee_credit_units()),
        );
        object.insert(
            "items".to_string(),
            Value::Array(
                self.items
                    .iter()
                    .map(RescueManifestItem::public_record)
                    .collect(),
            ),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        object.insert(
            "manifest_root".to_string(),
            Value::String(forced_inclusion_payload_root(
                "FORCED-INCLUSION-BATCH-RESCUE-MANIFEST-ROOT",
                &self.identity_record(),
            )),
        );
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.manifest_id != batch_rescue_manifest_id(&self.identity_record()) {
            return Err("batch rescue manifest id mismatch".to_string());
        }
        ensure_non_empty(&self.operator_id, "batch rescue manifest operator id")?;
        ensure_non_empty(&self.item_root, "batch rescue manifest item root")?;
        ensure_non_empty(&self.ticket_root, "batch rescue manifest ticket root")?;
        ensure_non_empty(&self.deadline_root, "batch rescue manifest deadline root")?;
        ensure_non_empty(
            &self.sponsor_credit_root,
            "batch rescue manifest sponsor credit root",
        )?;
        ensure_status(&self.status, VALID_RESCUE_STATUSES)?;
        for item in &self.items {
            item.validate()?;
        }
        Ok(self.manifest_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorshipPolicy {
    pub policy_id: String,
    pub sponsor_account_commitment: String,
    pub sponsorship_kind: SponsorshipKind,
    pub fee_asset_id: String,
    pub total_budget_units: u64,
    pub reserved_units: u64,
    pub redeemed_units: u64,
    pub released_units: u64,
    pub per_ticket_cap_units: u64,
    pub min_ticket_bond_units: u64,
    pub eligible_queue_root: String,
    pub eligible_ticket_kind_root: String,
    pub expiration_height: u64,
    pub reserve_root: String,
    pub status: String,
}

impl LowFeeSponsorshipPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_account_commitment: impl Into<String>,
        sponsorship_kind: SponsorshipKind,
        fee_asset_id: impl Into<String>,
        total_budget_units: u64,
        per_ticket_cap_units: u64,
        min_ticket_bond_units: u64,
        eligible_queue_ids: &[String],
        eligible_ticket_kinds: &[InclusionTicketKind],
        expiration_height: u64,
    ) -> ForcedInclusionResult<Self> {
        let sponsor_account_commitment = sponsor_account_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(
            &sponsor_account_commitment,
            "low fee sponsorship sponsor account",
        )?;
        ensure_non_empty(&fee_asset_id, "low fee sponsorship fee asset")?;
        ensure_positive(total_budget_units, "low fee sponsorship budget")?;
        ensure_positive(per_ticket_cap_units, "low fee sponsorship per-ticket cap")?;
        ensure_positive(min_ticket_bond_units, "low fee sponsorship min ticket bond")?;
        if per_ticket_cap_units > total_budget_units {
            return Err("low fee sponsorship per-ticket cap exceeds budget".to_string());
        }
        let eligible_queue_root = forced_inclusion_string_set_root(
            "FORCED-INCLUSION-SPONSOR-ELIGIBLE-QUEUE",
            eligible_queue_ids,
        );
        let eligible_ticket_kind_root = forced_inclusion_string_set_root(
            "FORCED-INCLUSION-SPONSOR-ELIGIBLE-TICKET-KIND",
            &eligible_ticket_kinds
                .iter()
                .map(|kind| kind.as_str().to_string())
                .collect::<Vec<_>>(),
        );
        let mut policy = Self {
            policy_id: String::new(),
            sponsor_account_commitment,
            sponsorship_kind,
            fee_asset_id,
            total_budget_units,
            reserved_units: 0,
            redeemed_units: 0,
            released_units: 0,
            per_ticket_cap_units,
            min_ticket_bond_units,
            eligible_queue_root,
            eligible_ticket_kind_root,
            expiration_height,
            reserve_root: forced_inclusion_empty_root("FORCED-INCLUSION-SPONSOR-RESERVE"),
            status: FORCED_INCLUSION_STATUS_ACTIVE.to_string(),
        };
        policy.policy_id = low_fee_sponsorship_policy_id(&policy.identity_record());
        policy.validate()?;
        Ok(policy)
    }

    pub fn available_units(&self) -> u64 {
        self.total_budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.redeemed_units)
            .saturating_sub(self.released_units)
    }

    pub fn can_reserve(&self, ticket: &InclusionTicket, units: u64, height: u64) -> bool {
        self.status == FORCED_INCLUSION_STATUS_ACTIVE
            && height <= self.expiration_height
            && units <= self.per_ticket_cap_units
            && units <= self.available_units()
            && ticket.bond_units >= self.min_ticket_bond_units
            && ticket.fee_asset_id == self.fee_asset_id
    }

    pub fn reserve_units(&mut self, credit: &LowFeeSponsorCredit) -> ForcedInclusionResult<()> {
        credit.validate()?;
        if credit.policy_id != self.policy_id {
            return Err("sponsor credit policy mismatch".to_string());
        }
        if credit.reserved_units > self.available_units() {
            return Err("sponsor policy budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(credit.reserved_units);
        self.reserve_root = forced_inclusion_payload_root(
            "FORCED-INCLUSION-SPONSOR-POLICY-RESERVE",
            &credit.public_record(),
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_low_fee_sponsorship_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "sponsor_account_commitment": self.sponsor_account_commitment,
            "sponsorship_kind": self.sponsorship_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "reserved_units": self.reserved_units,
            "redeemed_units": self.redeemed_units,
            "released_units": self.released_units,
            "available_units": self.available_units(),
            "per_ticket_cap_units": self.per_ticket_cap_units,
            "min_ticket_bond_units": self.min_ticket_bond_units,
            "eligible_queue_root": self.eligible_queue_root,
            "eligible_ticket_kind_root": self.eligible_ticket_kind_root,
            "expiration_height": self.expiration_height,
            "reserve_root": self.reserve_root,
            "status": self.status,
        })
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_low_fee_sponsorship_policy_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "sponsor_account_commitment": self.sponsor_account_commitment,
            "sponsorship_kind": self.sponsorship_kind.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "total_budget_units": self.total_budget_units,
            "per_ticket_cap_units": self.per_ticket_cap_units,
            "min_ticket_bond_units": self.min_ticket_bond_units,
            "eligible_queue_root": self.eligible_queue_root,
            "eligible_ticket_kind_root": self.eligible_ticket_kind_root,
            "expiration_height": self.expiration_height,
        })
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.policy_id != low_fee_sponsorship_policy_id(&self.identity_record()) {
            return Err("low fee sponsorship policy id mismatch".to_string());
        }
        ensure_non_empty(
            &self.sponsor_account_commitment,
            "low fee sponsorship sponsor account",
        )?;
        ensure_non_empty(&self.fee_asset_id, "low fee sponsorship fee asset")?;
        ensure_positive(self.total_budget_units, "low fee sponsorship budget")?;
        ensure_positive(self.per_ticket_cap_units, "low fee sponsorship cap")?;
        ensure_status(&self.status, VALID_SPONSOR_STATUSES)?;
        if self
            .reserved_units
            .saturating_add(self.redeemed_units)
            .saturating_add(self.released_units)
            > self.total_budget_units
        {
            return Err("low fee sponsorship accounting exceeds budget".to_string());
        }
        Ok(self.policy_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorCredit {
    pub credit_id: String,
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub ticket_id: String,
    pub queue_id: String,
    pub fee_asset_id: String,
    pub reserved_units: u64,
    pub redeemed_units: u64,
    pub reservation_height: u64,
    pub expires_at_height: u64,
    pub redemption_height: Option<u64>,
    pub refund_root: String,
    pub status: String,
}

impl LowFeeSponsorCredit {
    pub fn reserve(
        policy: &LowFeeSponsorshipPolicy,
        ticket: &InclusionTicket,
        reserved_units: u64,
        reservation_height: u64,
        expires_at_height: u64,
    ) -> ForcedInclusionResult<Self> {
        policy.validate()?;
        ticket.validate()?;
        if !policy.can_reserve(ticket, reserved_units, reservation_height) {
            return Err("ticket is not eligible for low fee sponsorship".to_string());
        }
        if expires_at_height < reservation_height {
            return Err("sponsor credit expiry before reservation".to_string());
        }
        let mut credit = Self {
            credit_id: String::new(),
            policy_id: policy.policy_id.clone(),
            sponsor_commitment: policy.sponsor_account_commitment.clone(),
            ticket_id: ticket.ticket_id.clone(),
            queue_id: ticket.queue_id.clone(),
            fee_asset_id: ticket.fee_asset_id.clone(),
            reserved_units,
            redeemed_units: 0,
            reservation_height,
            expires_at_height,
            redemption_height: None,
            refund_root: forced_inclusion_empty_root("FORCED-INCLUSION-SPONSOR-REFUND"),
            status: FORCED_INCLUSION_STATUS_RESERVED.to_string(),
        };
        credit.credit_id = low_fee_sponsor_credit_id(&credit.identity_record());
        credit.validate()?;
        Ok(credit)
    }

    pub fn redeem(&mut self, units: u64, redemption_height: u64) -> ForcedInclusionResult<()> {
        if units > self.reserved_units.saturating_sub(self.redeemed_units) {
            return Err("sponsor credit redemption exceeds reserve".to_string());
        }
        self.redeemed_units = self.redeemed_units.saturating_add(units);
        self.redemption_height = Some(redemption_height);
        self.status = FORCED_INCLUSION_STATUS_REDEEMED.to_string();
        Ok(())
    }

    pub fn release(
        &mut self,
        refund_root: impl Into<String>,
        release_height: u64,
    ) -> ForcedInclusionResult<()> {
        let refund_root = refund_root.into();
        ensure_non_empty(&refund_root, "sponsor credit refund root")?;
        self.refund_root = refund_root;
        self.redemption_height = Some(release_height);
        self.status = FORCED_INCLUSION_STATUS_RELEASED.to_string();
        Ok(())
    }

    pub fn unspent_units(&self) -> u64 {
        self.reserved_units.saturating_sub(self.redeemed_units)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
            && matches!(
                self.status.as_str(),
                FORCED_INCLUSION_STATUS_RESERVED | FORCED_INCLUSION_STATUS_ACTIVE
            )
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_low_fee_sponsor_credit_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "sponsor_commitment": self.sponsor_commitment,
            "ticket_id": self.ticket_id,
            "queue_id": self.queue_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_units": self.reserved_units,
            "reservation_height": self.reservation_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("sponsor credit record is object");
        object.insert(
            "credit_id".to_string(),
            Value::String(self.credit_id.clone()),
        );
        object.insert("redeemed_units".to_string(), json!(self.redeemed_units));
        object.insert("unspent_units".to_string(), json!(self.unspent_units()));
        object.insert(
            "redemption_height".to_string(),
            json!(self.redemption_height),
        );
        object.insert(
            "refund_root".to_string(),
            Value::String(self.refund_root.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.credit_id != low_fee_sponsor_credit_id(&self.identity_record()) {
            return Err("low fee sponsor credit id mismatch".to_string());
        }
        ensure_non_empty(&self.policy_id, "low fee sponsor credit policy id")?;
        ensure_non_empty(&self.sponsor_commitment, "low fee sponsor credit sponsor")?;
        ensure_non_empty(&self.ticket_id, "low fee sponsor credit ticket id")?;
        ensure_non_empty(&self.queue_id, "low fee sponsor credit queue id")?;
        ensure_non_empty(&self.fee_asset_id, "low fee sponsor credit fee asset")?;
        ensure_positive(self.reserved_units, "low fee sponsor credit reserve")?;
        ensure_status(&self.status, VALID_SPONSOR_STATUSES)?;
        if self.redeemed_units > self.reserved_units {
            return Err("sponsor credit redeemed amount exceeds reserve".to_string());
        }
        Ok(self.credit_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAction {
    pub action_id: String,
    pub operator_id: String,
    pub action_kind: OperatorActionKind,
    pub target_id: String,
    pub queue_id: Option<String>,
    pub ticket_id: Option<String>,
    pub challenge_id: Option<String>,
    pub evidence_id: Option<String>,
    pub action_payload_root: String,
    pub before_state_root: String,
    pub after_state_root: String,
    pub action_height: u64,
    pub l1_anchor_id: Option<String>,
    pub pq_signature_root: String,
    pub status: String,
}

impl OperatorAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        action_kind: OperatorActionKind,
        target_id: impl Into<String>,
        queue_id: Option<String>,
        ticket_id: Option<String>,
        challenge_id: Option<String>,
        evidence_id: Option<String>,
        action_payload_root: impl Into<String>,
        before_state_root: impl Into<String>,
        after_state_root: impl Into<String>,
        action_height: u64,
        l1_anchor_id: Option<String>,
        pq_signature_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let operator_id = operator_id.into();
        let target_id = target_id.into();
        let action_payload_root = action_payload_root.into();
        let before_state_root = before_state_root.into();
        let after_state_root = after_state_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&operator_id, "operator action operator id")?;
        ensure_non_empty(&target_id, "operator action target id")?;
        ensure_non_empty(&action_payload_root, "operator action payload root")?;
        ensure_non_empty(&before_state_root, "operator action before root")?;
        ensure_non_empty(&after_state_root, "operator action after root")?;
        ensure_non_empty(&pq_signature_root, "operator action pq signature root")?;
        let mut action = Self {
            action_id: String::new(),
            operator_id,
            action_kind,
            target_id,
            queue_id,
            ticket_id,
            challenge_id,
            evidence_id,
            action_payload_root,
            before_state_root,
            after_state_root,
            action_height,
            l1_anchor_id,
            pq_signature_root,
            status: FORCED_INCLUSION_STATUS_COMMITTED.to_string(),
        };
        action.action_id = operator_action_id(&action.identity_record());
        action.validate()?;
        Ok(action)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_operator_action_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "operator_id": self.operator_id,
            "action_kind": self.action_kind.as_str(),
            "target_id": self.target_id,
            "queue_id": self.queue_id,
            "ticket_id": self.ticket_id,
            "challenge_id": self.challenge_id,
            "evidence_id": self.evidence_id,
            "action_payload_root": self.action_payload_root,
            "before_state_root": self.before_state_root,
            "after_state_root": self.after_state_root,
            "action_height": self.action_height,
            "l1_anchor_id": self.l1_anchor_id,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("operator action record is object");
        object.insert(
            "action_id".to_string(),
            Value::String(self.action_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.action_id != operator_action_id(&self.identity_record()) {
            return Err("operator action id mismatch".to_string());
        }
        ensure_non_empty(&self.operator_id, "operator action operator id")?;
        ensure_non_empty(&self.target_id, "operator action target id")?;
        ensure_non_empty(&self.action_payload_root, "operator action payload root")?;
        ensure_non_empty(&self.before_state_root, "operator action before root")?;
        ensure_non_empty(&self.after_state_root, "operator action after root")?;
        ensure_non_empty(&self.pq_signature_root, "operator action pq signature")?;
        ensure_status(&self.status, VALID_OPERATOR_ACTION_STATUSES)?;
        Ok(self.action_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingAction {
    pub slash_id: String,
    pub operator_id: String,
    pub slash_reason: SlashReason,
    pub evidence_id: String,
    pub challenge_id: Option<String>,
    pub operator_action_id: Option<String>,
    pub slash_units: u64,
    pub beneficiary_commitment: String,
    pub bond_root: String,
    pub slash_height: u64,
    pub release_height: u64,
    pub pq_signature_root: String,
    pub status: String,
}

impl SlashingAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        slash_reason: SlashReason,
        evidence_id: impl Into<String>,
        challenge_id: Option<String>,
        operator_action_id: Option<String>,
        slash_units: u64,
        beneficiary_commitment: impl Into<String>,
        bond_root: impl Into<String>,
        slash_height: u64,
        release_height: u64,
        pq_signature_root: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let operator_id = operator_id.into();
        let evidence_id = evidence_id.into();
        let beneficiary_commitment = beneficiary_commitment.into();
        let bond_root = bond_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty(&operator_id, "slashing action operator id")?;
        ensure_non_empty(&evidence_id, "slashing action evidence id")?;
        ensure_non_empty(&beneficiary_commitment, "slashing action beneficiary")?;
        ensure_non_empty(&bond_root, "slashing action bond root")?;
        ensure_non_empty(&pq_signature_root, "slashing action pq signature root")?;
        ensure_positive(slash_units, "slashing action units")?;
        if release_height < slash_height {
            return Err("slashing action release height before slash height".to_string());
        }
        let mut slash = Self {
            slash_id: String::new(),
            operator_id,
            slash_reason,
            evidence_id,
            challenge_id,
            operator_action_id,
            slash_units,
            beneficiary_commitment,
            bond_root,
            slash_height,
            release_height,
            pq_signature_root,
            status: FORCED_INCLUSION_STATUS_SLASHED.to_string(),
        };
        slash.slash_id = slashing_action_id(&slash.identity_record());
        slash.validate()?;
        Ok(slash)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_slashing_action_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "operator_id": self.operator_id,
            "slash_reason": self.slash_reason.as_str(),
            "evidence_id": self.evidence_id,
            "challenge_id": self.challenge_id,
            "operator_action_id": self.operator_action_id,
            "slash_units": self.slash_units,
            "beneficiary_commitment": self.beneficiary_commitment,
            "bond_root": self.bond_root,
            "slash_height": self.slash_height,
            "release_height": self.release_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record.as_object_mut().expect("slash record is object");
        object.insert("slash_id".to_string(), Value::String(self.slash_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.slash_id != slashing_action_id(&self.identity_record()) {
            return Err("slashing action id mismatch".to_string());
        }
        ensure_non_empty(&self.operator_id, "slashing action operator id")?;
        ensure_non_empty(&self.evidence_id, "slashing action evidence id")?;
        ensure_non_empty(&self.beneficiary_commitment, "slashing action beneficiary")?;
        ensure_non_empty(&self.bond_root, "slashing action bond root")?;
        ensure_positive(self.slash_units, "slashing action units")?;
        ensure_status(&self.status, VALID_OPERATOR_ACTION_STATUSES)?;
        Ok(self.slash_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionAuditEvent {
    pub event_id: String,
    pub label: String,
    pub event_kind: String,
    pub event_height: u64,
    pub actor_commitment: String,
    pub subject_id: String,
    pub before_root: String,
    pub after_root: String,
    pub payload_root: String,
    pub status: String,
}

impl ForcedInclusionAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        event_kind: impl Into<String>,
        event_height: u64,
        actor_commitment: impl Into<String>,
        subject_id: impl Into<String>,
        before_root: impl Into<String>,
        after_root: impl Into<String>,
        payload_root: impl Into<String>,
        status: impl Into<String>,
    ) -> ForcedInclusionResult<Self> {
        let label = label.into();
        let event_kind = event_kind.into();
        let actor_commitment = actor_commitment.into();
        let subject_id = subject_id.into();
        let before_root = before_root.into();
        let after_root = after_root.into();
        let payload_root = payload_root.into();
        let status = status.into();
        ensure_non_empty(&label, "forced inclusion audit event label")?;
        ensure_non_empty(&event_kind, "forced inclusion audit event kind")?;
        ensure_non_empty(&actor_commitment, "forced inclusion audit actor")?;
        ensure_non_empty(&subject_id, "forced inclusion audit subject")?;
        ensure_non_empty(&before_root, "forced inclusion audit before root")?;
        ensure_non_empty(&after_root, "forced inclusion audit after root")?;
        ensure_non_empty(&payload_root, "forced inclusion audit payload root")?;
        let mut event = Self {
            event_id: String::new(),
            label,
            event_kind,
            event_height,
            actor_commitment,
            subject_id,
            before_root,
            after_root,
            payload_root,
            status,
        };
        event.event_id = forced_inclusion_audit_event_id(&event.identity_record());
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_audit_event_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "label": self.label,
            "event_kind": self.event_kind,
            "event_height": self.event_height,
            "actor_commitment": self.actor_commitment,
            "subject_id": self.subject_id,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "payload_root": self.payload_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("forced inclusion audit event record is object");
        object.insert("event_id".to_string(), Value::String(self.event_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.event_id != forced_inclusion_audit_event_id(&self.identity_record()) {
            return Err("forced inclusion audit event id mismatch".to_string());
        }
        ensure_non_empty(&self.label, "forced inclusion audit event label")?;
        ensure_non_empty(&self.event_kind, "forced inclusion audit event kind")?;
        ensure_non_empty(&self.actor_commitment, "forced inclusion audit event actor")?;
        ensure_non_empty(&self.subject_id, "forced inclusion audit event subject")?;
        ensure_non_empty(
            &self.before_root,
            "forced inclusion audit event before root",
        )?;
        ensure_non_empty(&self.after_root, "forced inclusion audit event after root")?;
        ensure_non_empty(
            &self.payload_root,
            "forced inclusion audit event payload root",
        )?;
        Ok(self.event_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionPublicRecord {
    pub record_id: String,
    pub source: String,
    pub label: String,
    pub payload_kind: String,
    pub record_root: String,
    pub payload: Value,
    pub published_at_height: u64,
    pub status: String,
}

impl ForcedInclusionPublicRecord {
    pub fn new(
        source: impl Into<String>,
        label: impl Into<String>,
        payload_kind: impl Into<String>,
        payload: &Value,
        published_at_height: u64,
    ) -> ForcedInclusionResult<Self> {
        let source = source.into();
        let label = label.into();
        let payload_kind = payload_kind.into();
        ensure_non_empty(&source, "forced inclusion public record source")?;
        ensure_non_empty(&label, "forced inclusion public record label")?;
        ensure_non_empty(&payload_kind, "forced inclusion public record payload kind")?;
        let record_root = forced_inclusion_payload_root("FORCED-INCLUSION-PUBLIC-RECORD", payload);
        let mut record = Self {
            record_id: String::new(),
            source,
            label,
            payload_kind,
            record_root,
            payload: payload.clone(),
            published_at_height,
            status: FORCED_INCLUSION_STATUS_COMMITTED.to_string(),
        };
        record.record_id = forced_inclusion_public_record_id(&record.identity_record());
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "forced_inclusion_public_record_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "source": self.source,
            "label": self.label,
            "payload_kind": self.payload_kind,
            "record_root": self.record_root,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("forced inclusion public record is object");
        object.insert(
            "record_id".to_string(),
            Value::String(self.record_id.clone()),
        );
        object.insert("payload".to_string(), self.payload.clone());
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        if self.record_id != forced_inclusion_public_record_id(&self.identity_record()) {
            return Err("forced inclusion public record id mismatch".to_string());
        }
        ensure_non_empty(&self.source, "forced inclusion public record source")?;
        ensure_non_empty(&self.label, "forced inclusion public record label")?;
        ensure_non_empty(
            &self.payload_kind,
            "forced inclusion public record payload kind",
        )?;
        ensure_non_empty(&self.record_root, "forced inclusion public record root")?;
        ensure_status(&self.status, VALID_OPERATOR_ACTION_STATUSES)?;
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForcedInclusionState {
    pub height: u64,
    pub config: ForcedInclusionConfig,
    pub queues: BTreeMap<String, EscapeHatchQueue>,
    pub tickets: BTreeMap<String, InclusionTicket>,
    pub omission_evidence: BTreeMap<String, SequencerOmissionEvidence>,
    pub challenges: BTreeMap<String, InclusionChallenge>,
    pub rescue_manifests: BTreeMap<String, BatchRescueManifest>,
    pub sponsorship_policies: BTreeMap<String, LowFeeSponsorshipPolicy>,
    pub sponsor_credits: BTreeMap<String, LowFeeSponsorCredit>,
    pub operator_actions: BTreeMap<String, OperatorAction>,
    pub slashing_actions: BTreeMap<String, SlashingAction>,
    pub audit_events: BTreeMap<String, ForcedInclusionAuditEvent>,
    pub public_records: BTreeMap<String, ForcedInclusionPublicRecord>,
    pub status: String,
}

impl ForcedInclusionState {
    pub fn new(config: ForcedInclusionConfig) -> ForcedInclusionResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            config,
            queues: BTreeMap::new(),
            tickets: BTreeMap::new(),
            omission_evidence: BTreeMap::new(),
            challenges: BTreeMap::new(),
            rescue_manifests: BTreeMap::new(),
            sponsorship_policies: BTreeMap::new(),
            sponsor_credits: BTreeMap::new(),
            operator_actions: BTreeMap::new(),
            slashing_actions: BTreeMap::new(),
            audit_events: BTreeMap::new(),
            public_records: BTreeMap::new(),
            status: FORCED_INCLUSION_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn devnet() -> ForcedInclusionResult<Self> {
        let config = ForcedInclusionConfig::devnet();
        let mut state = Self::new(config.clone())?;
        state.set_height(12)?;

        let withdrawal_queue = EscapeHatchQueue::devnet(
            "devnet-private-withdrawal-escape",
            EscapeQueueKind::Withdrawal,
        )?;
        let private_queue = EscapeHatchQueue::devnet(
            "devnet-private-transfer-escape",
            EscapeQueueKind::PrivateTransfer,
        )?;
        let token_queue = EscapeHatchQueue::devnet(
            "devnet-token-operations-escape",
            EscapeQueueKind::TokenOperation,
        )?;
        let defi_queue = EscapeHatchQueue::devnet("devnet-defi-escape", EscapeQueueKind::DefiCall)?;
        let contract_queue =
            EscapeHatchQueue::devnet("devnet-contract-call-escape", EscapeQueueKind::ContractCall)?;
        let emergency_queue = EscapeHatchQueue::devnet(
            "devnet-emergency-exit-escape",
            EscapeQueueKind::EmergencyExit,
        )?;

        let withdrawal_queue_id = withdrawal_queue.queue_id.clone();
        let private_queue_id = private_queue.queue_id.clone();
        let token_queue_id = token_queue.queue_id.clone();
        let defi_queue_id = defi_queue.queue_id.clone();
        let contract_queue_id = contract_queue.queue_id.clone();
        let emergency_queue_id = emergency_queue.queue_id.clone();

        state.register_queue(withdrawal_queue)?;
        state.register_queue(private_queue)?;
        state.register_queue(token_queue)?;
        state.register_queue(defi_queue)?;
        state.register_queue(contract_queue)?;
        state.register_queue(emergency_queue)?;

        let withdrawal_ticket = state.devnet_ticket(
            &withdrawal_queue_id,
            InclusionTicketKind::ShieldedWithdrawal,
            "alice-shielded-withdrawal",
            true,
            12,
            40,
        )?;
        let withdrawal_ticket_id = state.submit_ticket(withdrawal_ticket)?;

        let private_ticket = state.devnet_ticket(
            &private_queue_id,
            InclusionTicketKind::EncryptedTransfer,
            "bob-private-transfer",
            true,
            13,
            24,
        )?;
        let private_ticket_id = state.submit_ticket(private_ticket)?;

        let token_ticket = state.devnet_ticket(
            &token_queue_id,
            InclusionTicketKind::TokenTransfer,
            "tokenized-wxmr-transfer",
            false,
            14,
            18,
        )?;
        let token_ticket_id = state.submit_ticket(token_ticket)?;

        let defi_ticket = state.devnet_ticket(
            &defi_queue_id,
            InclusionTicketKind::DefiSwap,
            "private-swap-for-stable",
            false,
            15,
            22,
        )?;
        let defi_ticket_id = state.submit_ticket(defi_ticket)?;

        let contract_ticket = state.devnet_ticket(
            &contract_queue_id,
            InclusionTicketKind::ContractCall,
            "vault-rebalance-contract-call",
            false,
            16,
            30,
        )?;
        let contract_ticket_id = state.submit_ticket(contract_ticket)?;

        let emergency_ticket = state.devnet_ticket(
            &emergency_queue_id,
            InclusionTicketKind::EmergencyExit,
            "guardian-emergency-exit",
            true,
            17,
            80,
        )?;
        let emergency_ticket_id = state.submit_ticket(emergency_ticket)?;

        let eligible_queue_ids = vec![
            withdrawal_queue_id.clone(),
            private_queue_id.clone(),
            emergency_queue_id.clone(),
            defi_queue_id.clone(),
        ];
        let eligible_ticket_kinds = vec![
            InclusionTicketKind::ShieldedWithdrawal,
            InclusionTicketKind::EncryptedTransfer,
            InclusionTicketKind::EmergencyExit,
            InclusionTicketKind::DefiSwap,
        ];
        let sponsorship_policy = LowFeeSponsorshipPolicy::new(
            devnet_commitment("sponsor", "low-fee-escape-vault"),
            SponsorshipKind::LowFeeEscape,
            config.escape_fee_asset_id.clone(),
            config.low_fee_sponsor_pool_units,
            250,
            config.min_bond_units,
            &eligible_queue_ids,
            &eligible_ticket_kinds,
            144,
        )?;
        let sponsorship_policy_id = state.register_sponsorship_policy(sponsorship_policy)?;

        let withdrawal_credit_id = {
            let credit = {
                let policy = state
                    .sponsorship_policies
                    .get(&sponsorship_policy_id)
                    .ok_or_else(|| "devnet sponsorship policy missing".to_string())?;
                let ticket = state
                    .tickets
                    .get(&withdrawal_ticket_id)
                    .ok_or_else(|| "devnet withdrawal ticket missing".to_string())?;
                LowFeeSponsorCredit::reserve(policy, ticket, 120, 18, 96)?
            };
            state.reserve_sponsor_credit(credit)?
        };

        let emergency_credit_id = {
            let credit = {
                let policy = state
                    .sponsorship_policies
                    .get(&sponsorship_policy_id)
                    .ok_or_else(|| "devnet sponsorship policy missing".to_string())?;
                let ticket = state
                    .tickets
                    .get(&emergency_ticket_id)
                    .ok_or_else(|| "devnet emergency ticket missing".to_string())?;
                LowFeeSponsorCredit::reserve(policy, ticket, 200, 18, 96)?
            };
            state.reserve_sponsor_credit(credit)?
        };

        state.recompute_queue_summaries();

        let before_root = state.state_root();
        state.set_height(64)?;

        let evidence = {
            let ticket = state
                .tickets
                .get(&withdrawal_ticket_id)
                .ok_or_else(|| "devnet withdrawal ticket missing".to_string())?;
            SequencerOmissionEvidence::new(
                OmissionEvidenceKind::DeadlineExpired,
                ticket,
                config.operator_id.clone(),
                config.watchtower_id.clone(),
                64,
                devnet_hash("devnet-omitted-batch", "batch-42"),
                63,
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-CLAIMED-QUEUE-ROOT",
                    "claimed-withdrawal-queue-root",
                ),
                escape_hatch_queue_root_from_map(&state.queues),
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-SEQUENCER-STATEMENT",
                    "sequencer-claimed-empty-forced-inclusion-window",
                ),
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-WATCHTOWER-TRACE",
                    "watchtower-saw-missing-ticket",
                ),
                config.default_challenge_window_blocks,
            )?
        };
        let evidence_id = state.record_omission_evidence(evidence)?;

        let challenge_id = {
            let evidence = state
                .omission_evidence
                .get(&evidence_id)
                .ok_or_else(|| "devnet omission evidence missing".to_string())?;
            let challenge = InclusionChallenge::new(
                InclusionChallengeKind::SlashSequencer,
                evidence,
                devnet_commitment("challenger", "alice-watchtower"),
                65,
                8,
                24,
                32,
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-REQUESTED-ACTION",
                    "force-include-or-slash",
                ),
            )?;
            state.open_challenge(challenge)?
        };

        let response = InclusionChallengeResponse::new(
            challenge_id.clone(),
            ChallengeResponseKind::NoResponse,
            config.operator_id.clone(),
            withdrawal_ticket_id.clone(),
            None,
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-CHALLENGE-RESPONSE",
                "no-valid-response",
            ),
            forced_inclusion_empty_root("FORCED-INCLUSION-DEVNET-NO-INCLUSION-RECEIPT"),
            escape_hatch_queue_root_from_map(&state.queues),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-SPONSOR-REFUND",
                &withdrawal_credit_id,
            ),
            73,
            devnet_pq_authorization_root("operator-response", &config.operator_id),
        )?;
        state.attach_challenge_response(&challenge_id, response)?;

        let rescue_manifest_id = {
            let ticket = state
                .tickets
                .get(&withdrawal_ticket_id)
                .ok_or_else(|| "devnet withdrawal ticket missing".to_string())?;
            let item = RescueManifestItem::from_ticket(
                ticket,
                0,
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-RESCUE-STATE-TRANSITION",
                    "release-withdrawal-to-monero-address-commitment",
                ),
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-RESCUE-DISCLOSURE",
                    "view-tag-only-disclosure",
                ),
                120,
            )?;
            let mut manifest = BatchRescueManifest::new(
                RescueManifestKind::SingleTicket,
                0,
                config.rescue_operator_id.clone(),
                64,
                80,
                74,
                112,
                vec![item],
                low_fee_sponsor_credit_root_from_map(&state.sponsor_credits),
                operator_action_root_from_map(&state.operator_actions),
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-RESCUE-L1-ANCHOR",
                    "rescue-anchor-root",
                ),
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-RESCUE-BATCH-PAYLOAD",
                    "forced-withdrawal-rescue-batch",
                ),
            )?;
            manifest.mark_committed();
            state.record_rescue_manifest(manifest)?
        };

        let slash_id = {
            let slash = SlashingAction::new(
                config.operator_id.clone(),
                SlashReason::DeadlineMissed,
                evidence_id.clone(),
                Some(challenge_id.clone()),
                None,
                64,
                devnet_commitment("beneficiary", "alice-shielded-withdrawal"),
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-OPERATOR-BOND",
                    "sequencer-bond-slice-64",
                ),
                76,
                112,
                devnet_pq_authorization_root("slash", &config.rescue_operator_id),
            )?;
            state.record_slashing_action(slash)?
        };

        let include_action = OperatorAction::new(
            config.rescue_operator_id.clone(),
            OperatorActionKind::PublishRescueManifest,
            rescue_manifest_id.clone(),
            Some(withdrawal_queue_id.clone()),
            Some(withdrawal_ticket_id.clone()),
            Some(challenge_id.clone()),
            Some(evidence_id.clone()),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-OPERATOR-ACTION",
                "publish-rescue-manifest",
            ),
            before_root.clone(),
            state.state_root(),
            76,
            None,
            devnet_pq_authorization_root("operator-action", &config.rescue_operator_id),
        )?;
        let include_action_id = state.record_operator_action(include_action)?;

        let slash_action = OperatorAction::new(
            config.rescue_operator_id.clone(),
            OperatorActionKind::ApplySlash,
            slash_id.clone(),
            Some(withdrawal_queue_id.clone()),
            Some(withdrawal_ticket_id.clone()),
            Some(challenge_id.clone()),
            Some(evidence_id.clone()),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-SLASH-ACTION",
                "apply-sequencer-slash",
            ),
            before_root.clone(),
            state.state_root(),
            77,
            None,
            devnet_pq_authorization_root("slash-action", &config.rescue_operator_id),
        )?;
        state.record_operator_action(slash_action)?;

        let committed_public_ticket_action = OperatorAction::new(
            config.operator_id.clone(),
            OperatorActionKind::AcknowledgeTicket,
            contract_ticket_id.clone(),
            Some(contract_queue_id.clone()),
            Some(contract_ticket_id.clone()),
            None,
            None,
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-CONTRACT-ACK",
                "contract-call-forced-inclusion-ack",
            ),
            before_root.clone(),
            state.state_root(),
            18,
            None,
            devnet_pq_authorization_root("contract-ack", &config.operator_id),
        )?;
        state.record_operator_action(committed_public_ticket_action)?;

        let audit = ForcedInclusionAuditEvent::new(
            "devnet-forced-inclusion-bootstrap",
            "bootstrap_escape_hatch_records",
            78,
            devnet_commitment("auditor", "forced-inclusion-devnet"),
            withdrawal_ticket_id.clone(),
            before_root,
            state.state_root(),
            forced_inclusion_string_root(
                "FORCED-INCLUSION-DEVNET-AUDIT-PAYLOAD",
                "queues-tickets-evidence-challenges-rescue-sponsors-slash",
            ),
            FORCED_INCLUSION_STATUS_COMMITTED,
        )?;
        state.record_audit_event(audit)?;

        let summary_payload = json!({
            "ticket_ids": [
                withdrawal_ticket_id,
                private_ticket_id,
                token_ticket_id,
                defi_ticket_id,
                contract_ticket_id,
                emergency_ticket_id
            ],
            "sponsor_credit_ids": [withdrawal_credit_id, emergency_credit_id],
            "evidence_id": evidence_id,
            "challenge_id": challenge_id,
            "rescue_manifest_id": rescue_manifest_id,
            "slash_id": slash_id,
            "operator_action_id": include_action_id,
        });
        state.publish_public_record(
            "forced_inclusion_devnet",
            "deterministic_anti_censorship_fixture",
            "summary",
            &summary_payload,
        )?;

        state.recompute_queue_summaries();
        state.validate()?;
        Ok(state)
    }

    fn devnet_ticket(
        &mut self,
        queue_id: &str,
        ticket_kind: InclusionTicketKind,
        label: &str,
        encrypted: bool,
        submitted_at_height: u64,
        max_fee_units: u64,
    ) -> ForcedInclusionResult<InclusionTicket> {
        let queue = self
            .queues
            .get(queue_id)
            .ok_or_else(|| format!("escape hatch queue not found: {queue_id}"))?
            .clone();
        let sequence = self.reserve_queue_sequence(queue_id)?;
        let metadata = if encrypted {
            PrivacyPreservingTicketMetadata::devnet_private(
                label,
                queue.queue_kind.as_str(),
                ticket_kind.as_str(),
            )?
        } else {
            PrivacyPreservingTicketMetadata::devnet_public(
                label,
                queue.queue_kind.as_str(),
                ticket_kind.as_str(),
            )?
        };
        let anchor = if encrypted {
            L1InclusionAnchor::devnet_monero(
                label,
                1000 + submitted_at_height,
                submitted_at_height,
            )?
        } else {
            L1InclusionAnchor::devnet_watchtower(
                label,
                2000 + submitted_at_height,
                submitted_at_height,
            )?
        };
        let deadline = InclusionDeadline::from_config(
            queue_id,
            sequence,
            &anchor,
            &queue,
            &self.config,
            submitted_at_height,
        )?;
        let submitter_commitment = devnet_commitment("submitter", label);
        let owner_commitment = devnet_commitment("owner", label);
        let calldata_root = forced_inclusion_string_root("FORCED-INCLUSION-DEVNET-CALLDATA", label);
        let pq_authorization_root = devnet_pq_authorization_root("ticket", label);
        if encrypted {
            InclusionTicket::new_encrypted(
                queue_id,
                sequence,
                ticket_kind,
                submitter_commitment,
                owner_commitment,
                forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-ENCRYPTED-TICKET-PAYLOAD",
                    label,
                ),
                calldata_root,
                metadata,
                anchor,
                deadline,
                self.config.escape_fee_asset_id.clone(),
                max_fee_units,
                self.config.min_bond_units,
                None,
                pq_authorization_root,
            )
        } else {
            let public_payload = json!({
                "label": label,
                "ticket_kind": ticket_kind.as_str(),
                "queue_kind": queue.queue_kind.as_str(),
                "devnet_effect_root": forced_inclusion_string_root(
                    "FORCED-INCLUSION-DEVNET-PUBLIC-EFFECT",
                    label
                ),
            });
            InclusionTicket::new_public(
                queue_id,
                sequence,
                ticket_kind,
                submitter_commitment,
                owner_commitment,
                &public_payload,
                calldata_root,
                metadata,
                anchor,
                deadline,
                self.config.escape_fee_asset_id.clone(),
                max_fee_units,
                self.config.min_bond_units,
                None,
                pq_authorization_root,
            )
        }
    }

    pub fn set_height(&mut self, height: u64) -> ForcedInclusionResult<()> {
        self.height = height;
        for ticket in self.tickets.values_mut() {
            if ticket.rescue_due_at(height) {
                ticket.mark_rescue_eligible();
            } else if ticket.hard_due_at(height) {
                ticket.status = FORCED_INCLUSION_STATUS_CHALLENGED.to_string();
            }
        }
        for credit in self.sponsor_credits.values_mut() {
            if credit.expired_at(height) {
                credit.status = FORCED_INCLUSION_STATUS_EXPIRED.to_string();
            }
        }
        self.recompute_queue_summaries();
        Ok(())
    }

    pub fn register_queue(&mut self, queue: EscapeHatchQueue) -> ForcedInclusionResult<String> {
        queue.validate()?;
        let queue_id = queue.queue_id.clone();
        if self.queues.contains_key(&queue_id) {
            return Err("escape hatch queue already exists".to_string());
        }
        self.queues.insert(queue_id.clone(), queue);
        self.recompute_queue_summaries();
        Ok(queue_id)
    }

    pub fn reserve_queue_sequence(&mut self, queue_id: &str) -> ForcedInclusionResult<u64> {
        let queue = self
            .queues
            .get_mut(queue_id)
            .ok_or_else(|| format!("escape hatch queue not found: {queue_id}"))?;
        queue.reserve_sequence()
    }

    pub fn submit_ticket(&mut self, ticket: InclusionTicket) -> ForcedInclusionResult<String> {
        ticket.validate()?;
        let queue = self
            .queues
            .get(&ticket.queue_id)
            .ok_or_else(|| "ticket queue is not registered".to_string())?;
        if ticket.bond_units < queue.min_bond_units {
            return Err("ticket bond is below queue minimum".to_string());
        }
        let ticket_id = ticket.ticket_id.clone();
        if self.tickets.contains_key(&ticket_id) {
            return Err("inclusion ticket already exists".to_string());
        }
        self.tickets.insert(ticket_id.clone(), ticket);
        self.recompute_queue_summaries();
        Ok(ticket_id)
    }

    pub fn register_sponsorship_policy(
        &mut self,
        policy: LowFeeSponsorshipPolicy,
    ) -> ForcedInclusionResult<String> {
        policy.validate()?;
        let policy_id = policy.policy_id.clone();
        if self.sponsorship_policies.contains_key(&policy_id) {
            return Err("low fee sponsorship policy already exists".to_string());
        }
        self.sponsorship_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn reserve_sponsor_credit(
        &mut self,
        credit: LowFeeSponsorCredit,
    ) -> ForcedInclusionResult<String> {
        credit.validate()?;
        if !self.tickets.contains_key(&credit.ticket_id) {
            return Err("sponsor credit references unknown ticket".to_string());
        }
        let policy = self
            .sponsorship_policies
            .get_mut(&credit.policy_id)
            .ok_or_else(|| "sponsor credit references unknown policy".to_string())?;
        policy.reserve_units(&credit)?;
        let credit_id = credit.credit_id.clone();
        self.sponsor_credits.insert(credit_id.clone(), credit);
        self.recompute_queue_summaries();
        Ok(credit_id)
    }

    pub fn record_omission_evidence(
        &mut self,
        evidence: SequencerOmissionEvidence,
    ) -> ForcedInclusionResult<String> {
        evidence.validate()?;
        if !self.tickets.contains_key(&evidence.ticket_id) {
            return Err("omission evidence references unknown ticket".to_string());
        }
        let evidence_id = evidence.evidence_id.clone();
        self.omission_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn open_challenge(
        &mut self,
        challenge: InclusionChallenge,
    ) -> ForcedInclusionResult<String> {
        challenge.validate()?;
        if !self.omission_evidence.contains_key(&challenge.evidence_id) {
            return Err("challenge references unknown evidence".to_string());
        }
        let challenge_id = challenge.challenge_id.clone();
        let ticket_id = challenge.ticket_id.clone();
        self.challenges.insert(challenge_id.clone(), challenge);
        if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
            ticket.status = FORCED_INCLUSION_STATUS_CHALLENGED.to_string();
        }
        self.recompute_queue_summaries();
        Ok(challenge_id)
    }

    pub fn attach_challenge_response(
        &mut self,
        challenge_id: &str,
        response: InclusionChallengeResponse,
    ) -> ForcedInclusionResult<()> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| "challenge not found".to_string())?;
        challenge.attach_response(response)
    }

    pub fn record_rescue_manifest(
        &mut self,
        manifest: BatchRescueManifest,
    ) -> ForcedInclusionResult<String> {
        manifest.validate()?;
        let manifest_id = manifest.manifest_id.clone();
        for item in &manifest.items {
            if let Some(ticket) = self.tickets.get_mut(&item.ticket_id) {
                ticket.mark_rescue_queued();
            }
        }
        self.rescue_manifests.insert(manifest_id.clone(), manifest);
        self.recompute_queue_summaries();
        Ok(manifest_id)
    }

    pub fn record_operator_action(
        &mut self,
        action: OperatorAction,
    ) -> ForcedInclusionResult<String> {
        action.validate()?;
        let action_id = action.action_id.clone();
        self.operator_actions.insert(action_id.clone(), action);
        Ok(action_id)
    }

    pub fn record_slashing_action(
        &mut self,
        slash: SlashingAction,
    ) -> ForcedInclusionResult<String> {
        slash.validate()?;
        let slash_id = slash.slash_id.clone();
        self.slashing_actions.insert(slash_id.clone(), slash);
        Ok(slash_id)
    }

    pub fn record_audit_event(
        &mut self,
        event: ForcedInclusionAuditEvent,
    ) -> ForcedInclusionResult<String> {
        event.validate()?;
        let event_id = event.event_id.clone();
        self.audit_events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn publish_public_record(
        &mut self,
        source: impl Into<String>,
        label: impl Into<String>,
        payload_kind: impl Into<String>,
        payload: &Value,
    ) -> ForcedInclusionResult<String> {
        let record =
            ForcedInclusionPublicRecord::new(source, label, payload_kind, payload, self.height)?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn recompute_queue_summaries(&mut self) {
        let tickets = self.tickets.values().cloned().collect::<Vec<_>>();
        let sponsor_credits = self.sponsor_credits.values().cloned().collect::<Vec<_>>();
        for queue in self.queues.values_mut() {
            queue.update_summary(&tickets, &sponsor_credits);
        }
    }

    pub fn due_ticket_root(&self) -> String {
        let tickets = self
            .tickets
            .values()
            .filter(|ticket| ticket.hard_due_at(self.height))
            .cloned()
            .collect::<Vec<_>>();
        forced_inclusion_ticket_root(&tickets)
    }

    pub fn rescue_eligible_ticket_root(&self) -> String {
        let tickets = self
            .tickets
            .values()
            .filter(|ticket| ticket.rescue_due_at(self.height))
            .cloned()
            .collect::<Vec<_>>();
        forced_inclusion_ticket_root(&tickets)
    }

    pub fn operator_slashing_action_root(&self) -> String {
        let leaves = vec![
            json!({
                "label": "operator_action_root",
                "root": operator_action_root_from_map(&self.operator_actions),
            }),
            json!({
                "label": "slashing_action_root",
                "root": slashing_action_root_from_map(&self.slashing_actions),
            }),
        ];
        merkle_root("FORCED-INCLUSION-OPERATOR-SLASHING-ACTION-ROOT", &leaves)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        let object = record.as_object_mut().expect("state record is object");
        object.insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "forced_inclusion_state",
            "chain_id": CHAIN_ID,
            "protocol_version": FORCED_INCLUSION_PROTOCOL_VERSION,
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "queue_count": self.queues.len() as u64,
            "ticket_count": self.tickets.len() as u64,
            "omission_evidence_count": self.omission_evidence.len() as u64,
            "challenge_count": self.challenges.len() as u64,
            "rescue_manifest_count": self.rescue_manifests.len() as u64,
            "sponsorship_policy_count": self.sponsorship_policies.len() as u64,
            "sponsor_credit_count": self.sponsor_credits.len() as u64,
            "operator_action_count": self.operator_actions.len() as u64,
            "slashing_action_count": self.slashing_actions.len() as u64,
            "audit_event_count": self.audit_events.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "queue_root": escape_hatch_queue_root_from_map(&self.queues),
            "ticket_root": forced_inclusion_ticket_root_from_map(&self.tickets),
            "deadline_root": inclusion_deadline_root_from_tickets(&self.tickets),
            "l1_anchor_root": l1_anchor_root_from_tickets(&self.tickets),
            "metadata_root": privacy_ticket_metadata_root_from_tickets(&self.tickets),
            "due_ticket_root": self.due_ticket_root(),
            "rescue_eligible_ticket_root": self.rescue_eligible_ticket_root(),
            "omission_evidence_root": sequencer_omission_evidence_root_from_map(&self.omission_evidence),
            "challenge_root": inclusion_challenge_root_from_map(&self.challenges),
            "rescue_manifest_root": batch_rescue_manifest_root_from_map(&self.rescue_manifests),
            "sponsorship_policy_root": low_fee_sponsorship_policy_root_from_map(&self.sponsorship_policies),
            "sponsor_credit_root": low_fee_sponsor_credit_root_from_map(&self.sponsor_credits),
            "operator_action_root": operator_action_root_from_map(&self.operator_actions),
            "slashing_action_root": slashing_action_root_from_map(&self.slashing_actions),
            "operator_slashing_action_root": self.operator_slashing_action_root(),
            "audit_event_root": forced_inclusion_audit_event_root_from_map(&self.audit_events),
            "public_record_root": forced_inclusion_public_record_root_from_map(&self.public_records),
            "queues": self.queues.values().map(EscapeHatchQueue::public_record).collect::<Vec<_>>(),
            "tickets": self.tickets.values().map(InclusionTicket::public_record).collect::<Vec<_>>(),
            "omission_evidence": self.omission_evidence.values().map(SequencerOmissionEvidence::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(InclusionChallenge::public_record).collect::<Vec<_>>(),
            "rescue_manifests": self.rescue_manifests.values().map(BatchRescueManifest::public_record).collect::<Vec<_>>(),
            "sponsorship_policies": self.sponsorship_policies.values().map(LowFeeSponsorshipPolicy::public_record).collect::<Vec<_>>(),
            "sponsor_credits": self.sponsor_credits.values().map(LowFeeSponsorCredit::public_record).collect::<Vec<_>>(),
            "operator_actions": self.operator_actions.values().map(OperatorAction::public_record).collect::<Vec<_>>(),
            "slashing_actions": self.slashing_actions.values().map(SlashingAction::public_record).collect::<Vec<_>>(),
            "audit_events": self.audit_events.values().map(ForcedInclusionAuditEvent::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(ForcedInclusionPublicRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        forced_inclusion_state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> ForcedInclusionResult<String> {
        self.config.validate()?;
        ensure_status(&self.status, VALID_STATE_STATUSES)?;
        for queue in self.queues.values() {
            queue.validate()?;
        }
        for ticket in self.tickets.values() {
            ticket.validate()?;
            if !self.queues.contains_key(&ticket.queue_id) {
                return Err("state ticket references unknown queue".to_string());
            }
        }
        for evidence in self.omission_evidence.values() {
            evidence.validate()?;
            if !self.tickets.contains_key(&evidence.ticket_id) {
                return Err("state evidence references unknown ticket".to_string());
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.omission_evidence.contains_key(&challenge.evidence_id) {
                return Err("state challenge references unknown evidence".to_string());
            }
        }
        for manifest in self.rescue_manifests.values() {
            manifest.validate()?;
        }
        for policy in self.sponsorship_policies.values() {
            policy.validate()?;
        }
        for credit in self.sponsor_credits.values() {
            credit.validate()?;
            if !self.sponsorship_policies.contains_key(&credit.policy_id) {
                return Err("state sponsor credit references unknown policy".to_string());
            }
            if !self.tickets.contains_key(&credit.ticket_id) {
                return Err("state sponsor credit references unknown ticket".to_string());
            }
        }
        for action in self.operator_actions.values() {
            action.validate()?;
        }
        for slash in self.slashing_actions.values() {
            slash.validate()?;
        }
        for event in self.audit_events.values() {
            event.validate()?;
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn forced_inclusion_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn forced_inclusion_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn forced_inclusion_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn forced_inclusion_commitment(domain: &str, value: &str, salt: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
            HashPart::Str(salt),
        ],
        32,
    )
}

pub fn forced_inclusion_string_set_root(domain: &str, values: &[String]) -> String {
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    let leaves = unique
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_records_by_id(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn privacy_ticket_metadata_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-TICKET-METADATA-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn privacy_ticket_metadata_root(values: &[PrivacyPreservingTicketMetadata]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-TICKET-METADATA-ROOT",
        values
            .iter()
            .map(|value| (value.metadata_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn privacy_ticket_metadata_root_from_tickets(
    values: &BTreeMap<String, InclusionTicket>,
) -> String {
    privacy_ticket_metadata_root(
        &values
            .values()
            .map(|ticket| ticket.metadata.clone())
            .collect::<Vec<_>>(),
    )
}

pub fn l1_inclusion_anchor_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-L1-ANCHOR-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn l1_anchor_root(values: &[L1InclusionAnchor]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-L1-ANCHOR-ROOT",
        values
            .iter()
            .map(|value| (value.anchor_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn l1_anchor_root_from_tickets(values: &BTreeMap<String, InclusionTicket>) -> String {
    l1_anchor_root(
        &values
            .values()
            .map(|ticket| ticket.l1_anchor.clone())
            .collect::<Vec<_>>(),
    )
}

pub fn inclusion_deadline_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-DEADLINE-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn inclusion_deadline_root(values: &[InclusionDeadline]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-DEADLINE-ROOT",
        values
            .iter()
            .map(|value| (value.deadline_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn inclusion_deadline_root_from_tickets(values: &BTreeMap<String, InclusionTicket>) -> String {
    inclusion_deadline_root(
        &values
            .values()
            .map(|ticket| ticket.deadline.clone())
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn escape_hatch_queue_id(
    label: &str,
    queue_kind: EscapeQueueKind,
    max_depth: u64,
    min_bond_units: u64,
    max_ticket_bytes: u64,
    soft_delay_blocks: u64,
    hard_delay_blocks: u64,
    rescue_delay_blocks: u64,
) -> String {
    domain_hash(
        "FORCED-INCLUSION-ESCAPE-HATCH-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(queue_kind.as_str()),
            HashPart::Int(max_depth as i128),
            HashPart::Int(min_bond_units as i128),
            HashPart::Int(max_ticket_bytes as i128),
            HashPart::Int(soft_delay_blocks as i128),
            HashPart::Int(hard_delay_blocks as i128),
            HashPart::Int(rescue_delay_blocks as i128),
        ],
        32,
    )
}

pub fn escape_hatch_queue_root(values: &[EscapeHatchQueue]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-ESCAPE-HATCH-QUEUE-ROOT",
        values
            .iter()
            .map(|value| (value.queue_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn escape_hatch_queue_root_from_map(values: &BTreeMap<String, EscapeHatchQueue>) -> String {
    escape_hatch_queue_root(&values.values().cloned().collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
pub fn inclusion_ticket_id(
    queue_id: &str,
    queue_sequence: u64,
    ticket_kind: InclusionTicketKind,
    submitter_commitment: &str,
    owner_commitment: &str,
    public_payload_root: &str,
    encrypted_payload_root: &str,
    calldata_root: &str,
    metadata_root: &str,
    l1_anchor_id: &str,
    deadline_id: &str,
    fee_asset_id: &str,
    max_fee_units: u64,
    bond_units: u64,
    sponsor_credit_id: &str,
    pq_authorization_root: &str,
) -> String {
    domain_hash(
        "FORCED-INCLUSION-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(queue_id),
            HashPart::Int(queue_sequence as i128),
            HashPart::Str(ticket_kind.as_str()),
            HashPart::Str(submitter_commitment),
            HashPart::Str(owner_commitment),
            HashPart::Str(public_payload_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Str(calldata_root),
            HashPart::Str(metadata_root),
            HashPart::Str(l1_anchor_id),
            HashPart::Str(deadline_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(bond_units as i128),
            HashPart::Str(sponsor_credit_id),
            HashPart::Str(pq_authorization_root),
        ],
        32,
    )
}

pub fn forced_inclusion_ticket_root(values: &[InclusionTicket]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-TICKET-ROOT",
        values
            .iter()
            .map(|value| (value.ticket_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn forced_inclusion_ticket_root_from_map(values: &BTreeMap<String, InclusionTicket>) -> String {
    forced_inclusion_ticket_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn sequencer_omission_evidence_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-OMISSION-EVIDENCE-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn sequencer_omission_evidence_root(values: &[SequencerOmissionEvidence]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-OMISSION-EVIDENCE-ROOT",
        values
            .iter()
            .map(|value| (value.evidence_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn sequencer_omission_evidence_root_from_map(
    values: &BTreeMap<String, SequencerOmissionEvidence>,
) -> String {
    sequencer_omission_evidence_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn inclusion_challenge_response_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-CHALLENGE-RESPONSE-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn inclusion_challenge_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-CHALLENGE-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn inclusion_challenge_root(values: &[InclusionChallenge]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-CHALLENGE-ROOT",
        values
            .iter()
            .map(|value| (value.challenge_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn inclusion_challenge_root_from_map(values: &BTreeMap<String, InclusionChallenge>) -> String {
    inclusion_challenge_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn rescue_manifest_item_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-RESCUE-MANIFEST-ITEM-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn rescue_manifest_item_root(values: &[RescueManifestItem]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-RESCUE-MANIFEST-ITEM-ROOT",
        values
            .iter()
            .map(|value| (value.item_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn batch_rescue_manifest_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-BATCH-RESCUE-MANIFEST-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn batch_rescue_manifest_root(values: &[BatchRescueManifest]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-BATCH-RESCUE-MANIFEST-ROOT",
        values
            .iter()
            .map(|value| (value.manifest_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn batch_rescue_manifest_root_from_map(
    values: &BTreeMap<String, BatchRescueManifest>,
) -> String {
    batch_rescue_manifest_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn low_fee_sponsorship_policy_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-LOW-FEE-SPONSORSHIP-POLICY-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn low_fee_sponsorship_policy_root(values: &[LowFeeSponsorshipPolicy]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-LOW-FEE-SPONSORSHIP-POLICY-ROOT",
        values
            .iter()
            .map(|value| (value.policy_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn low_fee_sponsorship_policy_root_from_map(
    values: &BTreeMap<String, LowFeeSponsorshipPolicy>,
) -> String {
    low_fee_sponsorship_policy_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn low_fee_sponsor_credit_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-LOW-FEE-SPONSOR-CREDIT-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn low_fee_sponsor_credit_root(values: &[LowFeeSponsorCredit]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-LOW-FEE-SPONSOR-CREDIT-ROOT",
        values
            .iter()
            .map(|value| (value.credit_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn low_fee_sponsor_credit_root_from_map(
    values: &BTreeMap<String, LowFeeSponsorCredit>,
) -> String {
    low_fee_sponsor_credit_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn operator_action_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-OPERATOR-ACTION-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn operator_action_root(values: &[OperatorAction]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-OPERATOR-ACTION-ROOT",
        values
            .iter()
            .map(|value| (value.action_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn operator_action_root_from_map(values: &BTreeMap<String, OperatorAction>) -> String {
    operator_action_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn slashing_action_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-SLASHING-ACTION-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn slashing_action_root(values: &[SlashingAction]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-SLASHING-ACTION-ROOT",
        values
            .iter()
            .map(|value| (value.slash_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn slashing_action_root_from_map(values: &BTreeMap<String, SlashingAction>) -> String {
    slashing_action_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn forced_inclusion_audit_event_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-AUDIT-EVENT-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn forced_inclusion_audit_event_root(values: &[ForcedInclusionAuditEvent]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-AUDIT-EVENT-ROOT",
        values
            .iter()
            .map(|value| (value.event_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn forced_inclusion_audit_event_root_from_map(
    values: &BTreeMap<String, ForcedInclusionAuditEvent>,
) -> String {
    forced_inclusion_audit_event_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn forced_inclusion_public_record_id(record: &Value) -> String {
    domain_hash(
        "FORCED-INCLUSION-PUBLIC-RECORD-ID",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn forced_inclusion_public_record_root(values: &[ForcedInclusionPublicRecord]) -> String {
    merkle_records_by_id(
        "FORCED-INCLUSION-PUBLIC-RECORD-ROOT",
        values
            .iter()
            .map(|value| (value.record_id.clone(), value.public_record()))
            .collect(),
    )
}

pub fn forced_inclusion_public_record_root_from_map(
    values: &BTreeMap<String, ForcedInclusionPublicRecord>,
) -> String {
    forced_inclusion_public_record_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn forced_inclusion_state_root_from_record(record: &Value) -> String {
    domain_hash("FORCED-INCLUSION-STATE-ROOT", &[HashPart::Json(record)], 32)
}

pub fn forced_inclusion_deadline_window_root(
    tickets: &BTreeMap<String, InclusionTicket>,
    height: u64,
) -> String {
    let leaves = tickets
        .values()
        .map(|ticket| {
            json!({
                "ticket_id": ticket.ticket_id,
                "soft_due": ticket.soft_due_at(height),
                "hard_due": ticket.hard_due_at(height),
                "rescue_due": ticket.rescue_due_at(height),
                "deadline_id": ticket.deadline.deadline_id,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("FORCED-INCLUSION-DEADLINE-WINDOW-ROOT", &leaves)
}

pub fn forced_inclusion_operator_slash_root(
    operator_actions: &BTreeMap<String, OperatorAction>,
    slashing_actions: &BTreeMap<String, SlashingAction>,
) -> String {
    let leaves = vec![
        json!({
            "label": "operator_actions",
            "root": operator_action_root_from_map(operator_actions),
        }),
        json!({
            "label": "slashing_actions",
            "root": slashing_action_root_from_map(slashing_actions),
        }),
    ];
    merkle_root("FORCED-INCLUSION-OPERATOR-SLASH-ROOT", &leaves)
}

pub fn devnet_hash(domain: &str, label: &str) -> String {
    domain_hash(
        "FORCED-INCLUSION-DEVNET-HASH",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

pub fn devnet_commitment(kind: &str, label: &str) -> String {
    domain_hash(
        "FORCED-INCLUSION-DEVNET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn devnet_pq_authorization_root(kind: &str, label: &str) -> String {
    domain_hash(
        "FORCED-INCLUSION-DEVNET-PQ-AUTHORIZATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(FORCED_INCLUSION_PQ_AUTH_SCHEME),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn devnet_view_tag_prefix(label: &str) -> String {
    domain_hash(
        "FORCED-INCLUSION-DEVNET-VIEW-TAG-PREFIX",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        8,
    )
}

fn validate_view_tag_bits(bits: u16) -> ForcedInclusionResult<()> {
    if !(8..=64).contains(&bits) {
        Err("ticket metadata view tag bits must be between 8 and 64".to_string())
    } else {
        Ok(())
    }
}

fn ensure_non_empty(value: &str, field: &str) -> ForcedInclusionResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> ForcedInclusionResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, field: &str) -> ForcedInclusionResult<()> {
    if value > FORCED_INCLUSION_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn ensure_status(status: &str, allowed: &[&str]) -> ForcedInclusionResult<()> {
    if allowed.contains(&status) {
        Ok(())
    } else {
        Err(format!("invalid status: {status}"))
    }
}
