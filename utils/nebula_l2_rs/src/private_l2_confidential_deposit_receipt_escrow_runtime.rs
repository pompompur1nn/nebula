use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2ConfidentialDepositReceiptEscrowRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-deposit-receipt-escrow-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_372_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-deposit-receipt-v1";
pub const NOTE_PROOF_SUITE: &str = "private-deposit-note-balance-range-nullifier-proof-v1";
pub const MONERO_ANCHOR_SUITE: &str =
    "monero-output-commitment-anchor-with-view-tag-and-ring-context-v1";
pub const PROOF_AGGREGATION_SUITE: &str = "recursive-confidential-deposit-receipt-aggregation-v1";
pub const TOKEN_MINT_AUTH_SUITE: &str =
    "selective-disclosure-deposit-receipt-token-mint-authorization-v1";
pub const SPONSOR_RESERVATION_SUITE: &str =
    "low-fee-confidential-deposit-receipt-sponsor-reservation-v1";
pub const PRIVACY_FENCE_SUITE: &str =
    "deposit-receipt-nullifier-fence-anchor-and-note-anonymity-set-v1";
pub const CHALLENGE_EVIDENCE_SUITE: &str =
    "confidential-deposit-receipt-slashing-challenge-evidence-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_RECEIPT_ASSET_ID: &str = "xmr-deposit-receipt-devnet";
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_NOTE_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_DEPOSIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 120;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 240;
pub const DEFAULT_PROOF_AGGREGATION_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_SPONSOR_RESERVATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MINT_AUTH_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_DISCOUNT_BPS: u64 = 8;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_DEPOSIT_NOTES: usize = 4_194_304;
pub const MAX_MONERO_ANCHORS: usize = 2_097_152;
pub const MAX_ESCROW_WINDOWS: usize = 524_288;
pub const MAX_PROOF_AGGREGATES: usize = 524_288;
pub const MAX_MINT_AUTHORIZATIONS: usize = 2_097_152;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const MAX_CHALLENGES: usize = 1_048_576;
pub const MAX_SLASHING_EVENTS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositLane {
    RetailReceipt,
    DefiCollateral,
    StableMint,
    TokenLaunch,
    VaultShare,
    LpReceipt,
    BridgeLiquidity,
    EmergencyRecovery,
}

impl DepositLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailReceipt => "retail_receipt",
            Self::DefiCollateral => "defi_collateral",
            Self::StableMint => "stable_mint",
            Self::TokenLaunch => "token_launch",
            Self::VaultShare => "vault_share",
            Self::LpReceipt => "lp_receipt",
            Self::BridgeLiquidity => "bridge_liquidity",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::RetailReceipt => config.target_user_fee_bps,
            Self::DefiCollateral | Self::StableMint | Self::VaultShare | Self::LpReceipt => {
                config.target_user_fee_bps.saturating_add(2)
            }
            Self::TokenLaunch | Self::BridgeLiquidity => config.max_user_fee_bps,
            Self::EmergencyRecovery => config.max_user_fee_bps.saturating_mul(2).min(MAX_BPS),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Submitted,
    Anchored,
    Windowed,
    PrivacyFenced,
    Aggregated,
    MintAuthorized,
    ReceiptIssued,
    Rebated,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Anchored => "anchored",
            Self::Windowed => "windowed",
            Self::PrivacyFenced => "privacy_fenced",
            Self::Aggregated => "aggregated",
            Self::MintAuthorized => "mint_authorized",
            Self::ReceiptIssued => "receipt_issued",
            Self::Rebated => "rebated",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Anchored
                | Self::Windowed
                | Self::PrivacyFenced
                | Self::Aggregated
                | Self::MintAuthorized
                | Self::ReceiptIssued
                | Self::Challenged
        )
    }

    pub fn accepts_anchor(self) -> bool {
        matches!(self, Self::Submitted | Self::Anchored)
    }

    pub fn accepts_window(self) -> bool {
        matches!(self, Self::Anchored | Self::Windowed)
    }

    pub fn accepts_fence(self) -> bool {
        matches!(self, Self::Windowed | Self::PrivacyFenced)
    }

    pub fn accepts_aggregation(self) -> bool {
        matches!(self, Self::PrivacyFenced | Self::Aggregated)
    }

    pub fn accepts_mint(self) -> bool {
        matches!(self, Self::Aggregated | Self::MintAuthorized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorStatus {
    Proposed,
    Confirmed,
    Reorged,
    Finalized,
    Disputed,
    Rejected,
}

impl AnchorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Confirmed => "confirmed",
            Self::Reorged => "reorged",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }

    pub fn permits_window(self) -> bool {
        matches!(self, Self::Confirmed | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sealed,
    Aggregating,
    Minting,
    Settled,
    Challenged,
    Slashed,
    Expired,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Aggregating => "aggregating",
            Self::Minting => "minting",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_notes(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }

    pub fn accepts_aggregate(self) -> bool {
        matches!(self, Self::Sealed | Self::Aggregating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofAggregateStatus {
    Proposed,
    Verified,
    Cached,
    Rejected,
    Challenged,
    Slashed,
    Expired,
}

impl ProofAggregateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Cached => "cached",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn permits_mint(self) -> bool {
        matches!(self, Self::Verified | Self::Cached)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MintAuthorizationStatus {
    Draft,
    Authorized,
    Sponsored,
    Minted,
    Receipted,
    Revoked,
    Challenged,
    Slashed,
    Expired,
}

impl MintAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Authorized => "authorized",
            Self::Sponsored => "sponsored",
            Self::Minted => "minted",
            Self::Receipted => "receipted",
            Self::Revoked => "revoked",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn permits_sponsor(self) -> bool {
        matches!(self, Self::Authorized | Self::Sponsored)
    }

    pub fn permits_receipt(self) -> bool {
        matches!(self, Self::Authorized | Self::Sponsored | Self::Minted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Repriced,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Repriced => "repriced",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_consume(self) -> bool {
        matches!(self, Self::Reserved | Self::Repriced)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    NoteSubmitted,
    MoneroAnchorAccepted,
    EscrowWindowOpened,
    EscrowWindowSealed,
    ProofAggregateVerified,
    MintAuthorized,
    SponsorReserved,
    ReceiptMinted,
    RebatePublished,
    ChallengeOpened,
    ChallengeResolved,
    SlashPublished,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoteSubmitted => "note_submitted",
            Self::MoneroAnchorAccepted => "monero_anchor_accepted",
            Self::EscrowWindowOpened => "escrow_window_opened",
            Self::EscrowWindowSealed => "escrow_window_sealed",
            Self::ProofAggregateVerified => "proof_aggregate_verified",
            Self::MintAuthorized => "mint_authorized",
            Self::SponsorReserved => "sponsor_reserved",
            Self::ReceiptMinted => "receipt_minted",
            Self::RebatePublished => "rebate_published",
            Self::ChallengeOpened => "challenge_opened",
            Self::ChallengeResolved => "challenge_resolved",
            Self::SlashPublished => "slash_published",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    SponsorDiscount,
    BatchAggregation,
    ProofCacheHit,
    LowFeeLane,
    OverReservedFee,
    ChallengeReward,
    SlashingShare,
}

impl RebateReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorDiscount => "sponsor_discount",
            Self::BatchAggregation => "batch_aggregation",
            Self::ProofCacheHit => "proof_cache_hit",
            Self::LowFeeLane => "low_fee_lane",
            Self::OverReservedFee => "over_reserved_fee",
            Self::ChallengeReward => "challenge_reward",
            Self::SlashingShare => "slashing_share",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyFenceKind {
    NoteCommitmentSet,
    NullifierSet,
    AnchorRingSet,
    ViewTagBucket,
    SponsorSet,
    MintRecipientSet,
    ChallengeDisclosureSet,
}

impl PrivacyFenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoteCommitmentSet => "note_commitment_set",
            Self::NullifierSet => "nullifier_set",
            Self::AnchorRingSet => "anchor_ring_set",
            Self::ViewTagBucket => "view_tag_bucket",
            Self::SponsorSet => "sponsor_set",
            Self::MintRecipientSet => "mint_recipient_set",
            Self::ChallengeDisclosureSet => "challenge_disclosure_set",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    DoubleSpendNullifier,
    InvalidMoneroAnchor,
    InsufficientConfirmations,
    BrokenBalanceProof,
    InvalidProofAggregate,
    UnauthorizedMint,
    FeeSponsorFraud,
    PrivacyFenceViolation,
    SequencerEquivocation,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::InvalidMoneroAnchor => "invalid_monero_anchor",
            Self::InsufficientConfirmations => "insufficient_confirmations",
            Self::BrokenBalanceProof => "broken_balance_proof",
            Self::InvalidProofAggregate => "invalid_proof_aggregate",
            Self::UnauthorizedMint => "unauthorized_mint",
            Self::FeeSponsorFraud => "fee_sponsor_fraud",
            Self::PrivacyFenceViolation => "privacy_fence_violation",
            Self::SequencerEquivocation => "sequencer_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceRegistered,
    UnderReview,
    ChallengerWins,
    DefenderWins,
    Slashed,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceRegistered => "evidence_registered",
            Self::UnderReview => "under_review",
            Self::ChallengerWins => "challenger_wins",
            Self::DefenderWins => "defender_wins",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_evidence(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EvidenceRegistered | Self::UnderReview
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashTargetKind {
    DepositNote,
    MoneroAnchor,
    EscrowWindow,
    ProofAggregate,
    MintAuthorization,
    SponsorReservation,
    Sequencer,
    Attester,
}

impl SlashTargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositNote => "deposit_note",
            Self::MoneroAnchor => "monero_anchor",
            Self::EscrowWindow => "escrow_window",
            Self::ProofAggregate => "proof_aggregate",
            Self::MintAuthorization => "mint_authorization",
            Self::SponsorReservation => "sponsor_reservation",
            Self::Sequencer => "sequencer",
            Self::Attester => "attester",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub receipt_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub note_proof_suite: String,
    pub monero_anchor_suite: String,
    pub proof_aggregation_suite: String,
    pub token_mint_auth_suite: String,
    pub sponsor_reservation_suite: String,
    pub privacy_fence_suite: String,
    pub challenge_evidence_suite: String,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub min_note_confirmations: u64,
    pub deposit_window_blocks: u64,
    pub reveal_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub proof_aggregation_window_blocks: u64,
    pub sponsor_reservation_ttl_blocks: u64,
    pub mint_auth_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub sponsor_discount_bps: u64,
    pub rebate_bps: u64,
    pub max_deposit_notes: usize,
    pub max_monero_anchors: usize,
    pub max_escrow_windows: usize,
    pub max_proof_aggregates: usize,
    pub max_mint_authorizations: usize,
    pub max_sponsor_reservations: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_privacy_fences: usize,
    pub max_challenges: usize,
    pub max_slashing_events: usize,
    pub max_public_records: usize,
    pub require_pq_attestation: bool,
    pub require_monero_finality: bool,
    pub require_fee_sponsor_for_defi: bool,
    pub allow_emergency_recovery: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            receipt_asset_id: DEFAULT_RECEIPT_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            note_proof_suite: NOTE_PROOF_SUITE.to_string(),
            monero_anchor_suite: MONERO_ANCHOR_SUITE.to_string(),
            proof_aggregation_suite: PROOF_AGGREGATION_SUITE.to_string(),
            token_mint_auth_suite: TOKEN_MINT_AUTH_SUITE.to_string(),
            sponsor_reservation_suite: SPONSOR_RESERVATION_SUITE.to_string(),
            privacy_fence_suite: PRIVACY_FENCE_SUITE.to_string(),
            challenge_evidence_suite: CHALLENGE_EVIDENCE_SUITE.to_string(),
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_note_confirmations: DEFAULT_MIN_NOTE_CONFIRMATIONS,
            deposit_window_blocks: DEFAULT_DEPOSIT_WINDOW_BLOCKS,
            reveal_window_blocks: DEFAULT_REVEAL_WINDOW_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            proof_aggregation_window_blocks: DEFAULT_PROOF_AGGREGATION_WINDOW_BLOCKS,
            sponsor_reservation_ttl_blocks: DEFAULT_SPONSOR_RESERVATION_TTL_BLOCKS,
            mint_auth_ttl_blocks: DEFAULT_MINT_AUTH_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            sponsor_discount_bps: DEFAULT_SPONSOR_DISCOUNT_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            max_deposit_notes: MAX_DEPOSIT_NOTES,
            max_monero_anchors: MAX_MONERO_ANCHORS,
            max_escrow_windows: MAX_ESCROW_WINDOWS,
            max_proof_aggregates: MAX_PROOF_AGGREGATES,
            max_mint_authorizations: MAX_MINT_AUTHORIZATIONS,
            max_sponsor_reservations: MAX_SPONSOR_RESERVATIONS,
            max_receipts: MAX_RECEIPTS,
            max_rebates: MAX_REBATES,
            max_privacy_fences: MAX_PRIVACY_FENCES,
            max_challenges: MAX_CHALLENGES,
            max_slashing_events: MAX_SLASHING_EVENTS,
            max_public_records: MAX_PUBLIC_RECORDS,
            require_pq_attestation: true,
            require_monero_finality: true,
            require_fee_sponsor_for_defi: false,
            allow_emergency_recovery: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("receipt_asset_id", &self.receipt_asset_id)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        ensure_non_empty("note_proof_suite", &self.note_proof_suite)?;
        ensure_non_empty("monero_anchor_suite", &self.monero_anchor_suite)?;
        ensure_non_empty("proof_aggregation_suite", &self.proof_aggregation_suite)?;
        ensure_non_empty("token_mint_auth_suite", &self.token_mint_auth_suite)?;
        ensure_non_empty("sponsor_reservation_suite", &self.sponsor_reservation_suite)?;
        ensure_non_empty("privacy_fence_suite", &self.privacy_fence_suite)?;
        ensure_non_empty("challenge_evidence_suite", &self.challenge_evidence_suite)?;
        ensure_min("schema_version", self.schema_version, 1)?;
        ensure_min("min_privacy_set", self.min_privacy_set, 1)?;
        ensure_min(
            "target_privacy_set",
            self.target_privacy_set,
            self.min_privacy_set,
        )?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err(format!(
                "min_pq_security_bits must be at least {DEFAULT_MIN_PQ_SECURITY_BITS}"
            ));
        }
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_user_fee_bps", self.target_user_fee_bps)?;
        ensure_bps("sponsor_discount_bps", self.sponsor_discount_bps)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target_user_fee_bps exceeds max_user_fee_bps".to_string());
        }
        ensure_min("deposit_window_blocks", self.deposit_window_blocks, 1)?;
        ensure_min("reveal_window_blocks", self.reveal_window_blocks, 1)?;
        ensure_min("challenge_window_blocks", self.challenge_window_blocks, 1)?;
        ensure_min(
            "proof_aggregation_window_blocks",
            self.proof_aggregation_window_blocks,
            1,
        )?;
        ensure_min(
            "sponsor_reservation_ttl_blocks",
            self.sponsor_reservation_ttl_blocks,
            1,
        )?;
        ensure_min("mint_auth_ttl_blocks", self.mint_auth_ttl_blocks, 1)?;
        ensure_min("rebate_ttl_blocks", self.rebate_ttl_blocks, 1)?;
        ensure_capacity("max_deposit_notes", self.max_deposit_notes)?;
        ensure_capacity("max_monero_anchors", self.max_monero_anchors)?;
        ensure_capacity("max_escrow_windows", self.max_escrow_windows)?;
        ensure_capacity("max_proof_aggregates", self.max_proof_aggregates)?;
        ensure_capacity("max_mint_authorizations", self.max_mint_authorizations)?;
        ensure_capacity("max_sponsor_reservations", self.max_sponsor_reservations)?;
        ensure_capacity("max_receipts", self.max_receipts)?;
        ensure_capacity("max_rebates", self.max_rebates)?;
        ensure_capacity("max_privacy_fences", self.max_privacy_fences)?;
        ensure_capacity("max_challenges", self.max_challenges)?;
        ensure_capacity("max_slashing_events", self.max_slashing_events)?;
        ensure_capacity("max_public_records", self.max_public_records)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub deposit_notes: u64,
    pub monero_anchors: u64,
    pub escrow_windows: u64,
    pub proof_aggregates: u64,
    pub mint_authorizations: u64,
    pub sponsor_reservations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub privacy_fences: u64,
    pub challenges: u64,
    pub slashing_events: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub deposit_note_root: String,
    pub monero_anchor_root: String,
    pub escrow_window_root: String,
    pub proof_aggregate_root: String,
    pub mint_authorization_root: String,
    pub sponsor_reservation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub challenge_root: String,
    pub slashing_event_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
    pub used_anchor_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitDepositNoteRequest {
    pub depositor_commitment: String,
    pub lane: DepositLane,
    pub note_commitment: String,
    pub amount_commitment: String,
    pub asset_id: String,
    pub nullifier: String,
    pub monero_tx_commitment: String,
    pub monero_output_commitment: String,
    pub view_tag_bucket: String,
    pub range_proof_root: String,
    pub balance_proof_root: String,
    pub pq_depositor_auth_root: String,
    pub receiver_policy_root: String,
    pub metadata_commitment: String,
    pub privacy_set_size: u64,
    pub fee_commitment: String,
    pub max_fee_bps: u64,
}

impl SubmitDepositNoteRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("depositor_commitment", &self.depositor_commitment)?;
        ensure_non_empty("note_commitment", &self.note_commitment)?;
        ensure_non_empty("amount_commitment", &self.amount_commitment)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_non_empty("monero_tx_commitment", &self.monero_tx_commitment)?;
        ensure_non_empty("monero_output_commitment", &self.monero_output_commitment)?;
        ensure_non_empty("view_tag_bucket", &self.view_tag_bucket)?;
        ensure_non_empty("range_proof_root", &self.range_proof_root)?;
        ensure_non_empty("balance_proof_root", &self.balance_proof_root)?;
        ensure_non_empty("pq_depositor_auth_root", &self.pq_depositor_auth_root)?;
        ensure_non_empty("receiver_policy_root", &self.receiver_policy_root)?;
        ensure_non_empty("metadata_commitment", &self.metadata_commitment)?;
        ensure_non_empty("fee_commitment", &self.fee_commitment)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set,
        )?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("deposit note max_fee_bps exceeds configured limit".to_string());
        }
        if config.require_fee_sponsor_for_defi
            && matches!(
                self.lane,
                DepositLane::DefiCollateral
                    | DepositLane::StableMint
                    | DepositLane::VaultShare
                    | DepositLane::LpReceipt
            )
            && self.fee_commitment.is_empty()
        {
            return Err("defi deposit note requires fee commitment".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterMoneroAnchorRequest {
    pub note_id: String,
    pub anchor_commitment: String,
    pub monero_block_hash: String,
    pub monero_block_height: u64,
    pub monero_tx_root: String,
    pub output_index_commitment: String,
    pub ring_context_root: String,
    pub key_image_fence_root: String,
    pub confirmations: u64,
    pub finality_proof_root: String,
    pub pq_attester_commitment: String,
    pub pq_attestation_root: String,
}

impl RegisterMoneroAnchorRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("note_id", &self.note_id)?;
        ensure_non_empty("anchor_commitment", &self.anchor_commitment)?;
        ensure_non_empty("monero_block_hash", &self.monero_block_hash)?;
        ensure_non_empty("monero_tx_root", &self.monero_tx_root)?;
        ensure_non_empty("output_index_commitment", &self.output_index_commitment)?;
        ensure_non_empty("ring_context_root", &self.ring_context_root)?;
        ensure_non_empty("key_image_fence_root", &self.key_image_fence_root)?;
        ensure_non_empty("finality_proof_root", &self.finality_proof_root)?;
        ensure_non_empty("pq_attester_commitment", &self.pq_attester_commitment)?;
        ensure_non_empty("pq_attestation_root", &self.pq_attestation_root)?;
        ensure_min(
            "confirmations",
            self.confirmations,
            config.min_note_confirmations,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenEscrowWindowRequest {
    pub lane: DepositLane,
    pub operator_commitment: String,
    pub receipt_asset_id: String,
    pub note_ids: Vec<String>,
    pub anchor_ids: Vec<String>,
    pub window_policy_root: String,
    pub fee_policy_root: String,
    pub min_privacy_set: u64,
    pub opens_height: u64,
    pub closes_height: u64,
    pub reveal_deadline_height: u64,
    pub challenge_deadline_height: u64,
}

impl OpenEscrowWindowRequest {
    pub fn validate(&self, config: &Config, current_height: u64) -> Result<()> {
        ensure_non_empty("operator_commitment", &self.operator_commitment)?;
        ensure_non_empty("receipt_asset_id", &self.receipt_asset_id)?;
        ensure_non_empty("window_policy_root", &self.window_policy_root)?;
        ensure_non_empty("fee_policy_root", &self.fee_policy_root)?;
        ensure_non_empty_vec("note_ids", &self.note_ids)?;
        ensure_non_empty_vec("anchor_ids", &self.anchor_ids)?;
        ensure_unique("note_ids", &self.note_ids)?;
        ensure_unique("anchor_ids", &self.anchor_ids)?;
        ensure_min(
            "min_privacy_set",
            self.min_privacy_set,
            config.min_privacy_set,
        )?;
        if self.note_ids.len() != self.anchor_ids.len() {
            return Err("escrow window note_ids and anchor_ids length mismatch".to_string());
        }
        if self.opens_height < current_height {
            return Err("escrow window opens_height is in the past".to_string());
        }
        if self.closes_height <= self.opens_height {
            return Err("escrow window closes_height must exceed opens_height".to_string());
        }
        if self.reveal_deadline_height <= self.closes_height {
            return Err("escrow window reveal deadline must exceed close height".to_string());
        }
        if self.challenge_deadline_height <= self.reveal_deadline_height {
            return Err("escrow window challenge deadline must exceed reveal deadline".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AggregateDepositProofRequest {
    pub window_id: String,
    pub note_ids: Vec<String>,
    pub anchor_ids: Vec<String>,
    pub aggregator_commitment: String,
    pub aggregate_proof_root: String,
    pub recursive_verifier_root: String,
    pub note_commitment_root: String,
    pub nullifier_root: String,
    pub amount_commitment_root: String,
    pub mint_amount_commitment: String,
    pub fee_amount_commitment: String,
    pub privacy_set_root: String,
    pub pq_aggregator_auth_root: String,
    pub proof_weight: u64,
    pub privacy_set_size: u64,
}

impl AggregateDepositProofRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty_vec("note_ids", &self.note_ids)?;
        ensure_non_empty_vec("anchor_ids", &self.anchor_ids)?;
        ensure_unique("note_ids", &self.note_ids)?;
        ensure_unique("anchor_ids", &self.anchor_ids)?;
        ensure_non_empty("aggregator_commitment", &self.aggregator_commitment)?;
        ensure_non_empty("aggregate_proof_root", &self.aggregate_proof_root)?;
        ensure_non_empty("recursive_verifier_root", &self.recursive_verifier_root)?;
        ensure_non_empty("note_commitment_root", &self.note_commitment_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("amount_commitment_root", &self.amount_commitment_root)?;
        ensure_non_empty("mint_amount_commitment", &self.mint_amount_commitment)?;
        ensure_non_empty("fee_amount_commitment", &self.fee_amount_commitment)?;
        ensure_non_empty("privacy_set_root", &self.privacy_set_root)?;
        ensure_non_empty("pq_aggregator_auth_root", &self.pq_aggregator_auth_root)?;
        ensure_min("proof_weight", self.proof_weight, 1)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set,
        )?;
        if self.note_ids.len() != self.anchor_ids.len() {
            return Err("aggregate proof note_ids and anchor_ids length mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizeTokenMintRequest {
    pub aggregate_id: String,
    pub window_id: String,
    pub note_ids: Vec<String>,
    pub token_contract_id: String,
    pub receipt_asset_id: String,
    pub mint_recipient_commitment: String,
    pub mint_amount_commitment: String,
    pub authorization_policy_root: String,
    pub compliance_disclosure_root: String,
    pub pq_authorizer_commitment: String,
    pub pq_authorization_root: String,
    pub expires_height: u64,
}

impl AuthorizeTokenMintRequest {
    pub fn validate(&self, current_height: u64) -> Result<()> {
        ensure_non_empty("aggregate_id", &self.aggregate_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty_vec("note_ids", &self.note_ids)?;
        ensure_unique("note_ids", &self.note_ids)?;
        ensure_non_empty("token_contract_id", &self.token_contract_id)?;
        ensure_non_empty("receipt_asset_id", &self.receipt_asset_id)?;
        ensure_non_empty("mint_recipient_commitment", &self.mint_recipient_commitment)?;
        ensure_non_empty("mint_amount_commitment", &self.mint_amount_commitment)?;
        ensure_non_empty("authorization_policy_root", &self.authorization_policy_root)?;
        ensure_non_empty(
            "compliance_disclosure_root",
            &self.compliance_disclosure_root,
        )?;
        ensure_non_empty("pq_authorizer_commitment", &self.pq_authorizer_commitment)?;
        ensure_non_empty("pq_authorization_root", &self.pq_authorization_root)?;
        if self.expires_height <= current_height {
            return Err("mint authorization expires_height must be in the future".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveFeeSponsorRequest {
    pub mint_authorization_id: String,
    pub window_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_amount: u128,
    pub reserved_fee_commitment: String,
    pub sponsor_policy_root: String,
    pub refund_commitment: String,
    pub discount_bps: u64,
    pub expires_height: u64,
}

impl ReserveFeeSponsorRequest {
    pub fn validate(&self, config: &Config, current_height: u64) -> Result<()> {
        ensure_non_empty("mint_authorization_id", &self.mint_authorization_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("reserved_fee_commitment", &self.reserved_fee_commitment)?;
        ensure_non_empty("sponsor_policy_root", &self.sponsor_policy_root)?;
        ensure_non_empty("refund_commitment", &self.refund_commitment)?;
        ensure_min_u128("max_fee_amount", self.max_fee_amount, 1)?;
        ensure_bps("discount_bps", self.discount_bps)?;
        if self.discount_bps > config.max_user_fee_bps {
            return Err("sponsor discount_bps exceeds max_user_fee_bps".to_string());
        }
        if self.expires_height <= current_height {
            return Err("sponsor reservation expires_height must be in the future".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishReceiptRequest {
    pub subject_id: String,
    pub receipt_kind: ReceiptKind,
    pub window_id: Option<String>,
    pub note_id: Option<String>,
    pub aggregate_id: Option<String>,
    pub mint_authorization_id: Option<String>,
    pub reservation_id: Option<String>,
    pub receipt_commitment: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settlement_root: String,
    pub pq_receipt_signature_root: String,
    pub public_payload: Value,
}

impl PublishReceiptRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("receipt_commitment", &self.receipt_commitment)?;
        ensure_non_empty("state_root_before", &self.state_root_before)?;
        ensure_non_empty("state_root_after", &self.state_root_after)?;
        ensure_non_empty("settlement_root", &self.settlement_root)?;
        ensure_non_empty("pq_receipt_signature_root", &self.pq_receipt_signature_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishRebateRequest {
    pub reservation_id: String,
    pub mint_authorization_id: String,
    pub window_id: String,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub rebate_reason: RebateReason,
    pub rebate_asset_id: String,
    pub rebate_amount: u128,
    pub rebate_commitment: String,
    pub settlement_receipt_id: String,
    pub pq_rebate_signature_root: String,
    pub expires_height: u64,
}

impl PublishRebateRequest {
    pub fn validate(&self, current_height: u64) -> Result<()> {
        ensure_non_empty("reservation_id", &self.reservation_id)?;
        ensure_non_empty("mint_authorization_id", &self.mint_authorization_id)?;
        ensure_non_empty("window_id", &self.window_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("recipient_commitment", &self.recipient_commitment)?;
        ensure_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        ensure_min_u128("rebate_amount", self.rebate_amount, 1)?;
        ensure_non_empty("rebate_commitment", &self.rebate_commitment)?;
        ensure_non_empty("settlement_receipt_id", &self.settlement_receipt_id)?;
        ensure_non_empty("pq_rebate_signature_root", &self.pq_rebate_signature_root)?;
        if self.expires_height <= current_height {
            return Err("rebate expires_height must be in the future".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPrivacyFenceRequest {
    pub subject_id: String,
    pub fence_kind: PrivacyFenceKind,
    pub fence_commitment: String,
    pub privacy_set_root: String,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub anchor_root: String,
    pub disclosure_policy_root: String,
    pub effective_height: u64,
}

impl RegisterPrivacyFenceRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("fence_commitment", &self.fence_commitment)?;
        ensure_non_empty("privacy_set_root", &self.privacy_set_root)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set,
        )?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("anchor_root", &self.anchor_root)?;
        ensure_non_empty("disclosure_policy_root", &self.disclosure_policy_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenChallengeRequest {
    pub subject_id: String,
    pub challenge_kind: ChallengeKind,
    pub challenger_commitment: String,
    pub challenged_party_commitment: String,
    pub evidence_root: String,
    pub private_evidence_commitment: String,
    pub public_evidence: Value,
    pub bond_commitment: String,
    pub requested_slash_target: SlashTargetKind,
    pub requested_slash_amount: u128,
    pub pq_challenger_auth_root: String,
}

impl OpenChallengeRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("challenger_commitment", &self.challenger_commitment)?;
        ensure_non_empty(
            "challenged_party_commitment",
            &self.challenged_party_commitment,
        )?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_non_empty(
            "private_evidence_commitment",
            &self.private_evidence_commitment,
        )?;
        ensure_non_empty("bond_commitment", &self.bond_commitment)?;
        ensure_min_u128("requested_slash_amount", self.requested_slash_amount, 1)?;
        ensure_non_empty("pq_challenger_auth_root", &self.pq_challenger_auth_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolveChallengeRequest {
    pub challenge_id: String,
    pub resolver_commitment: String,
    pub verdict: ChallengeStatus,
    pub resolution_root: String,
    pub slash_target_id: Option<String>,
    pub slash_target_kind: Option<SlashTargetKind>,
    pub slash_amount: u128,
    pub reward_commitment: String,
    pub pq_resolution_signature_root: String,
}

impl ResolveChallengeRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("challenge_id", &self.challenge_id)?;
        ensure_non_empty("resolver_commitment", &self.resolver_commitment)?;
        ensure_non_empty("resolution_root", &self.resolution_root)?;
        ensure_non_empty("reward_commitment", &self.reward_commitment)?;
        ensure_non_empty(
            "pq_resolution_signature_root",
            &self.pq_resolution_signature_root,
        )?;
        if matches!(
            self.verdict,
            ChallengeStatus::Open | ChallengeStatus::EvidenceRegistered
        ) {
            return Err(
                "challenge resolution verdict must be terminal or under_review".to_string(),
            );
        }
        if self.slash_amount > 0
            && (self.slash_target_id.is_none() || self.slash_target_kind.is_none())
        {
            return Err(
                "slash target id and kind are required when slash_amount is nonzero".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DepositNoteRecord {
    pub note_id: String,
    pub request: SubmitDepositNoteRequest,
    pub status: NoteStatus,
    pub anchor_id: Option<String>,
    pub window_id: Option<String>,
    pub aggregate_id: Option<String>,
    pub mint_authorization_id: Option<String>,
    pub receipt_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub created_height: u64,
    pub updated_height: u64,
    pub expires_height: u64,
}

impl DepositNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_note",
            "note_id": self.note_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "anchor_id": self.anchor_id,
            "window_id": self.window_id,
            "aggregate_id": self.aggregate_id,
            "mint_authorization_id": self.mint_authorization_id,
            "receipt_id": self.receipt_id,
            "challenge_ids": self.challenge_ids,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroAnchorRecord {
    pub anchor_id: String,
    pub request: RegisterMoneroAnchorRequest,
    pub status: AnchorStatus,
    pub window_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub created_height: u64,
    pub updated_height: u64,
}

impl MoneroAnchorRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_monero_anchor",
            "anchor_id": self.anchor_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "window_id": self.window_id,
            "challenge_ids": self.challenge_ids,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscrowWindowRecord {
    pub window_id: String,
    pub request: OpenEscrowWindowRequest,
    pub status: WindowStatus,
    pub aggregate_ids: BTreeSet<String>,
    pub mint_authorization_ids: BTreeSet<String>,
    pub reservation_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
    pub challenge_ids: BTreeSet<String>,
    pub created_height: u64,
    pub updated_height: u64,
}

impl EscrowWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_escrow_window",
            "window_id": self.window_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "aggregate_ids": self.aggregate_ids,
            "mint_authorization_ids": self.mint_authorization_ids,
            "reservation_ids": self.reservation_ids,
            "receipt_ids": self.receipt_ids,
            "challenge_ids": self.challenge_ids,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofAggregateRecord {
    pub aggregate_id: String,
    pub request: AggregateDepositProofRequest,
    pub status: ProofAggregateStatus,
    pub mint_authorization_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub created_height: u64,
    pub updated_height: u64,
    pub expires_height: u64,
}

impl ProofAggregateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_proof_aggregate",
            "aggregate_id": self.aggregate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "mint_authorization_id": self.mint_authorization_id,
            "challenge_ids": self.challenge_ids,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintAuthorizationRecord {
    pub mint_authorization_id: String,
    pub request: AuthorizeTokenMintRequest,
    pub status: MintAuthorizationStatus,
    pub reservation_id: Option<String>,
    pub receipt_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub created_height: u64,
    pub updated_height: u64,
}

impl MintAuthorizationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_mint_authorization",
            "mint_authorization_id": self.mint_authorization_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "challenge_ids": self.challenge_ids,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveFeeSponsorRequest,
    pub status: SponsorReservationStatus,
    pub consumed_height: Option<u64>,
    pub rebate_id: Option<String>,
    pub created_height: u64,
    pub updated_height: u64,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "consumed_height": self.consumed_height,
            "rebate_id": self.rebate_id,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub request: PublishReceiptRequest,
    pub created_height: u64,
}

impl ReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub request: PublishRebateRequest,
    pub created_height: u64,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_rebate",
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub request: RegisterPrivacyFenceRequest,
    pub created_height: u64,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_privacy_fence",
            "fence_id": self.fence_id,
            "request": self.request.public_record(),
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub request: OpenChallengeRequest,
    pub status: ChallengeStatus,
    pub resolution: Option<ResolveChallengeRequest>,
    pub created_height: u64,
    pub updated_height: u64,
    pub expires_height: u64,
}

impl ChallengeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_challenge",
            "challenge_id": self.challenge_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "resolution": self.resolution,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEventRecord {
    pub slash_id: String,
    pub challenge_id: String,
    pub target_kind: SlashTargetKind,
    pub target_id: String,
    pub slash_amount: u128,
    pub evidence_root: String,
    pub reward_commitment: String,
    pub created_height: u64,
}

impl SlashingEventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_slashing_event",
            "slash_id": self.slash_id,
            "challenge_id": self.challenge_id,
            "target_kind": self.target_kind.as_str(),
            "target_id": self.target_id,
            "slash_amount": self.slash_amount.to_string(),
            "evidence_root": self.evidence_root,
            "reward_commitment": self.reward_commitment,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub height: u64,
    pub payload: Value,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub deposit_notes: BTreeMap<String, DepositNoteRecord>,
    pub monero_anchors: BTreeMap<String, MoneroAnchorRecord>,
    pub escrow_windows: BTreeMap<String, EscrowWindowRecord>,
    pub proof_aggregates: BTreeMap<String, ProofAggregateRecord>,
    pub mint_authorizations: BTreeMap<String, MintAuthorizationRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub receipts: BTreeMap<String, ReceiptRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub challenges: BTreeMap<String, ChallengeRecord>,
    pub slashing_events: BTreeMap<String, SlashingEventRecord>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub spent_nullifiers: BTreeSet<String>,
    pub used_anchor_commitments: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Result<Self> {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
    }

    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            counters: Counters::default(),
            deposit_notes: BTreeMap::new(),
            monero_anchors: BTreeMap::new(),
            escrow_windows: BTreeMap::new(),
            proof_aggregates: BTreeMap::new(),
            mint_authorizations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            used_anchor_commitments: BTreeSet::new(),
        })
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.height {
            return Err("cannot move runtime height backwards".to_string());
        }
        self.height = height;
        self.expire_old_records();
        Ok(())
    }

    pub fn submit_deposit_note(&mut self, request: SubmitDepositNoteRequest) -> Result<String> {
        self.ensure_capacity(
            "deposit_notes",
            self.deposit_notes.len(),
            self.config.max_deposit_notes,
        )?;
        request.validate(&self.config)?;
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err(format!(
                "deposit nullifier already used: {}",
                request.nullifier
            ));
        }
        let note_id = deposit_note_id(&request, self.height);
        if self.deposit_notes.contains_key(&note_id) {
            return Err(format!("deposit note already exists: {note_id}"));
        }
        self.spent_nullifiers.insert(request.nullifier.clone());
        let record = DepositNoteRecord {
            note_id: note_id.clone(),
            request,
            status: NoteStatus::Submitted,
            anchor_id: None,
            window_id: None,
            aggregate_id: None,
            mint_authorization_id: None,
            receipt_id: None,
            challenge_ids: BTreeSet::new(),
            created_height: self.height,
            updated_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.deposit_window_blocks),
        };
        self.publish("note_submitted", &note_id, record.public_record())?;
        self.deposit_notes.insert(note_id.clone(), record);
        self.counters.deposit_notes = self.counters.deposit_notes.saturating_add(1);
        Ok(note_id)
    }

    pub fn register_monero_anchor(
        &mut self,
        request: RegisterMoneroAnchorRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "monero_anchors",
            self.monero_anchors.len(),
            self.config.max_monero_anchors,
        )?;
        request.validate(&self.config)?;
        if self
            .used_anchor_commitments
            .contains(&request.anchor_commitment)
        {
            return Err(format!(
                "monero anchor commitment already used: {}",
                request.anchor_commitment
            ));
        }
        let note = self.require_note(&request.note_id)?;
        if !note.status.accepts_anchor() {
            return Err(format!(
                "deposit note status does not accept anchor: {}",
                note.status.as_str()
            ));
        }
        let anchor_id = monero_anchor_id(&request, self.height);
        if self.monero_anchors.contains_key(&anchor_id) {
            return Err(format!("monero anchor already exists: {anchor_id}"));
        }
        self.used_anchor_commitments
            .insert(request.anchor_commitment.clone());
        let record = MoneroAnchorRecord {
            anchor_id: anchor_id.clone(),
            request: request.clone(),
            status: if self.config.require_monero_finality {
                AnchorStatus::Finalized
            } else {
                AnchorStatus::Confirmed
            },
            window_id: None,
            challenge_ids: BTreeSet::new(),
            created_height: self.height,
            updated_height: self.height,
        };
        self.monero_anchors
            .insert(anchor_id.clone(), record.clone());
        if let Some(note) = self.deposit_notes.get_mut(&request.note_id) {
            note.status = NoteStatus::Anchored;
            note.anchor_id = Some(anchor_id.clone());
            note.updated_height = self.height;
        }
        self.publish(
            "monero_anchor_registered",
            &anchor_id,
            record.public_record(),
        )?;
        self.counters.monero_anchors = self.counters.monero_anchors.saturating_add(1);
        Ok(anchor_id)
    }

    pub fn open_escrow_window(&mut self, request: OpenEscrowWindowRequest) -> Result<String> {
        self.ensure_capacity(
            "escrow_windows",
            self.escrow_windows.len(),
            self.config.max_escrow_windows,
        )?;
        request.validate(&self.config, self.height)?;
        for (note_id, anchor_id) in request.note_ids.iter().zip(request.anchor_ids.iter()) {
            let note = self.require_note(note_id)?;
            let anchor = self.require_anchor(anchor_id)?;
            if note.anchor_id.as_deref() != Some(anchor_id.as_str()) {
                return Err(format!(
                    "note {note_id} is not linked to anchor {anchor_id}"
                ));
            }
            if !note.status.accepts_window() {
                return Err(format!(
                    "note {note_id} status does not accept escrow window"
                ));
            }
            if !anchor.status.permits_window() {
                return Err(format!(
                    "anchor {anchor_id} is not confirmed for escrow window"
                ));
            }
        }
        let window_id = escrow_window_id(&request, self.height);
        if self.escrow_windows.contains_key(&window_id) {
            return Err(format!("escrow window already exists: {window_id}"));
        }
        let record = EscrowWindowRecord {
            window_id: window_id.clone(),
            request: request.clone(),
            status: WindowStatus::Open,
            aggregate_ids: BTreeSet::new(),
            mint_authorization_ids: BTreeSet::new(),
            reservation_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
            challenge_ids: BTreeSet::new(),
            created_height: self.height,
            updated_height: self.height,
        };
        self.escrow_windows
            .insert(window_id.clone(), record.clone());
        for note_id in &request.note_ids {
            if let Some(note) = self.deposit_notes.get_mut(note_id) {
                note.status = NoteStatus::Windowed;
                note.window_id = Some(window_id.clone());
                note.updated_height = self.height;
            }
        }
        for anchor_id in &request.anchor_ids {
            if let Some(anchor) = self.monero_anchors.get_mut(anchor_id) {
                anchor.window_id = Some(window_id.clone());
                anchor.updated_height = self.height;
            }
        }
        self.publish("escrow_window_opened", &window_id, record.public_record())?;
        self.counters.escrow_windows = self.counters.escrow_windows.saturating_add(1);
        Ok(window_id)
    }

    pub fn seal_escrow_window(&mut self, window_id: &str) -> Result<()> {
        let record = self
            .escrow_windows
            .get_mut(window_id)
            .ok_or_else(|| format!("unknown escrow window: {window_id}"))?;
        if !matches!(record.status, WindowStatus::Open) {
            return Err(format!(
                "escrow window cannot be sealed from status {}",
                record.status.as_str()
            ));
        }
        if self.height < record.request.closes_height {
            return Err("escrow window cannot be sealed before close height".to_string());
        }
        record.status = WindowStatus::Sealed;
        record.updated_height = self.height;
        let payload = record.public_record();
        self.publish("escrow_window_sealed", window_id, payload)?;
        Ok(())
    }

    pub fn register_privacy_fence(
        &mut self,
        request: RegisterPrivacyFenceRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        request.validate(&self.config)?;
        let fence_id = privacy_fence_id(&request, self.height);
        if self.privacy_fences.contains_key(&fence_id) {
            return Err(format!("privacy fence already exists: {fence_id}"));
        }
        let record = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            request: request.clone(),
            created_height: self.height,
        };
        self.privacy_fences.insert(fence_id.clone(), record.clone());
        if let Some(note) = self.deposit_notes.get_mut(&request.subject_id) {
            if note.status.accepts_fence() {
                note.status = NoteStatus::PrivacyFenced;
                note.updated_height = self.height;
            }
        }
        self.publish(
            "privacy_fence_registered",
            &fence_id,
            record.public_record(),
        )?;
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        Ok(fence_id)
    }

    pub fn aggregate_deposit_proofs(
        &mut self,
        request: AggregateDepositProofRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            "proof_aggregates",
            self.proof_aggregates.len(),
            self.config.max_proof_aggregates,
        )?;
        request.validate(&self.config)?;
        let window = self.require_window(&request.window_id)?;
        if !window.status.accepts_aggregate() {
            return Err(format!(
                "escrow window status does not accept aggregate: {}",
                window.status.as_str()
            ));
        }
        for note_id in &request.note_ids {
            let note = self.require_note(note_id)?;
            if note.window_id.as_deref() != Some(request.window_id.as_str()) {
                return Err(format!("note {note_id} is outside aggregate window"));
            }
            if !note.status.accepts_aggregation() {
                return Err(format!("note {note_id} status does not accept aggregation"));
            }
        }
        for anchor_id in &request.anchor_ids {
            let anchor = self.require_anchor(anchor_id)?;
            if anchor.window_id.as_deref() != Some(request.window_id.as_str()) {
                return Err(format!("anchor {anchor_id} is outside aggregate window"));
            }
        }
        let aggregate_id = proof_aggregate_id(&request, self.height);
        if self.proof_aggregates.contains_key(&aggregate_id) {
            return Err(format!("proof aggregate already exists: {aggregate_id}"));
        }
        let record = ProofAggregateRecord {
            aggregate_id: aggregate_id.clone(),
            request: request.clone(),
            status: ProofAggregateStatus::Verified,
            mint_authorization_id: None,
            challenge_ids: BTreeSet::new(),
            created_height: self.height,
            updated_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.proof_aggregation_window_blocks),
        };
        self.proof_aggregates
            .insert(aggregate_id.clone(), record.clone());
        if let Some(window) = self.escrow_windows.get_mut(&request.window_id) {
            window.status = WindowStatus::Aggregating;
            window.aggregate_ids.insert(aggregate_id.clone());
            window.updated_height = self.height;
        }
        for note_id in &request.note_ids {
            if let Some(note) = self.deposit_notes.get_mut(note_id) {
                note.status = NoteStatus::Aggregated;
                note.aggregate_id = Some(aggregate_id.clone());
                note.updated_height = self.height;
            }
        }
        self.publish(
            "proof_aggregate_verified",
            &aggregate_id,
            record.public_record(),
        )?;
        self.counters.proof_aggregates = self.counters.proof_aggregates.saturating_add(1);
        Ok(aggregate_id)
    }

    pub fn authorize_token_mint(&mut self, request: AuthorizeTokenMintRequest) -> Result<String> {
        self.ensure_capacity(
            "mint_authorizations",
            self.mint_authorizations.len(),
            self.config.max_mint_authorizations,
        )?;
        request.validate(self.height)?;
        let aggregate = self.require_aggregate(&request.aggregate_id)?;
        if !aggregate.status.permits_mint() {
            return Err(format!(
                "proof aggregate status does not permit mint: {}",
                aggregate.status.as_str()
            ));
        }
        if aggregate.request.window_id != request.window_id {
            return Err("mint authorization window_id does not match aggregate".to_string());
        }
        for note_id in &request.note_ids {
            let note = self.require_note(note_id)?;
            if note.aggregate_id.as_deref() != Some(request.aggregate_id.as_str()) {
                return Err(format!(
                    "note {note_id} is not in aggregate {}",
                    request.aggregate_id
                ));
            }
            if !note.status.accepts_mint() {
                return Err(format!(
                    "note {note_id} status does not accept mint authorization"
                ));
            }
        }
        let mint_authorization_id = mint_authorization_id(&request, self.height);
        if self
            .mint_authorizations
            .contains_key(&mint_authorization_id)
        {
            return Err(format!(
                "mint authorization already exists: {mint_authorization_id}"
            ));
        }
        let record = MintAuthorizationRecord {
            mint_authorization_id: mint_authorization_id.clone(),
            request: request.clone(),
            status: MintAuthorizationStatus::Authorized,
            reservation_id: None,
            receipt_id: None,
            challenge_ids: BTreeSet::new(),
            created_height: self.height,
            updated_height: self.height,
        };
        self.mint_authorizations
            .insert(mint_authorization_id.clone(), record.clone());
        if let Some(aggregate) = self.proof_aggregates.get_mut(&request.aggregate_id) {
            aggregate.mint_authorization_id = Some(mint_authorization_id.clone());
            aggregate.updated_height = self.height;
        }
        if let Some(window) = self.escrow_windows.get_mut(&request.window_id) {
            window.status = WindowStatus::Minting;
            window
                .mint_authorization_ids
                .insert(mint_authorization_id.clone());
            window.updated_height = self.height;
        }
        for note_id in &request.note_ids {
            if let Some(note) = self.deposit_notes.get_mut(note_id) {
                note.status = NoteStatus::MintAuthorized;
                note.mint_authorization_id = Some(mint_authorization_id.clone());
                note.updated_height = self.height;
            }
        }
        self.publish(
            "mint_authorized",
            &mint_authorization_id,
            record.public_record(),
        )?;
        self.counters.mint_authorizations = self.counters.mint_authorizations.saturating_add(1);
        Ok(mint_authorization_id)
    }

    pub fn reserve_fee_sponsor(&mut self, request: ReserveFeeSponsorRequest) -> Result<String> {
        self.ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )?;
        request.validate(&self.config, self.height)?;
        let auth = self.require_mint_authorization(&request.mint_authorization_id)?;
        if !auth.status.permits_sponsor() {
            return Err(format!(
                "mint authorization status does not permit sponsor: {}",
                auth.status.as_str()
            ));
        }
        if auth.request.window_id != request.window_id {
            return Err(
                "sponsor reservation window_id does not match mint authorization".to_string(),
            );
        }
        let reservation_id = sponsor_reservation_id(&request, self.height);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err(format!(
                "sponsor reservation already exists: {reservation_id}"
            ));
        }
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request: request.clone(),
            status: SponsorReservationStatus::Reserved,
            consumed_height: None,
            rebate_id: None,
            created_height: self.height,
            updated_height: self.height,
        };
        self.sponsor_reservations
            .insert(reservation_id.clone(), record.clone());
        if let Some(auth) = self
            .mint_authorizations
            .get_mut(&request.mint_authorization_id)
        {
            auth.status = MintAuthorizationStatus::Sponsored;
            auth.reservation_id = Some(reservation_id.clone());
            auth.updated_height = self.height;
        }
        if let Some(window) = self.escrow_windows.get_mut(&request.window_id) {
            window.reservation_ids.insert(reservation_id.clone());
            window.updated_height = self.height;
        }
        self.publish("sponsor_reserved", &reservation_id, record.public_record())?;
        self.counters.sponsor_reservations = self.counters.sponsor_reservations.saturating_add(1);
        Ok(reservation_id)
    }

    pub fn publish_receipt(&mut self, request: PublishReceiptRequest) -> Result<String> {
        self.ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        request.validate()?;
        let receipt_id = receipt_id(&request, self.height);
        if self.receipts.contains_key(&receipt_id) {
            return Err(format!("receipt already exists: {receipt_id}"));
        }
        let record = ReceiptRecord {
            receipt_id: receipt_id.clone(),
            request: request.clone(),
            created_height: self.height,
        };
        self.receipts.insert(receipt_id.clone(), record.clone());
        if let Some(note_id) = &request.note_id {
            if let Some(note) = self.deposit_notes.get_mut(note_id) {
                note.status = NoteStatus::ReceiptIssued;
                note.receipt_id = Some(receipt_id.clone());
                note.updated_height = self.height;
            }
        }
        if let Some(auth_id) = &request.mint_authorization_id {
            if let Some(auth) = self.mint_authorizations.get_mut(auth_id) {
                if auth.status.permits_receipt() {
                    auth.status = MintAuthorizationStatus::Receipted;
                    auth.receipt_id = Some(receipt_id.clone());
                    auth.updated_height = self.height;
                }
            }
        }
        if let Some(reservation_id) = &request.reservation_id {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                if reservation.status.can_consume() {
                    reservation.status = SponsorReservationStatus::Consumed;
                    reservation.consumed_height = Some(self.height);
                    reservation.updated_height = self.height;
                }
            }
        }
        if let Some(window_id) = &request.window_id {
            if let Some(window) = self.escrow_windows.get_mut(window_id) {
                window.receipt_ids.insert(receipt_id.clone());
                if matches!(request.receipt_kind, ReceiptKind::ReceiptMinted) {
                    window.status = WindowStatus::Settled;
                }
                window.updated_height = self.height;
            }
        }
        self.publish(
            request.receipt_kind.as_str(),
            &receipt_id,
            record.public_record(),
        )?;
        self.counters.receipts = self.counters.receipts.saturating_add(1);
        Ok(receipt_id)
    }

    pub fn publish_rebate(&mut self, request: PublishRebateRequest) -> Result<String> {
        self.ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        request.validate(self.height)?;
        self.require_reservation(&request.reservation_id)?;
        self.require_mint_authorization(&request.mint_authorization_id)?;
        let rebate_id = rebate_id(&request, self.height);
        if self.rebates.contains_key(&rebate_id) {
            return Err(format!("rebate already exists: {rebate_id}"));
        }
        let record = RebateRecord {
            rebate_id: rebate_id.clone(),
            request: request.clone(),
            created_height: self.height,
        };
        self.rebates.insert(rebate_id.clone(), record.clone());
        if let Some(reservation) = self.sponsor_reservations.get_mut(&request.reservation_id) {
            reservation.status = SponsorReservationStatus::RebateQueued;
            reservation.rebate_id = Some(rebate_id.clone());
            reservation.updated_height = self.height;
        }
        self.publish("rebate_published", &rebate_id, record.public_record())?;
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        Ok(rebate_id)
    }

    pub fn open_challenge(&mut self, request: OpenChallengeRequest) -> Result<String> {
        self.ensure_capacity(
            "challenges",
            self.challenges.len(),
            self.config.max_challenges,
        )?;
        request.validate()?;
        let challenge_id = challenge_id(&request, self.height);
        if self.challenges.contains_key(&challenge_id) {
            return Err(format!("challenge already exists: {challenge_id}"));
        }
        let record = ChallengeRecord {
            challenge_id: challenge_id.clone(),
            request: request.clone(),
            status: ChallengeStatus::Open,
            resolution: None,
            created_height: self.height,
            updated_height: self.height,
            expires_height: self
                .height
                .saturating_add(self.config.challenge_window_blocks),
        };
        self.attach_challenge_to_subject(&request.subject_id, &challenge_id)?;
        self.challenges.insert(challenge_id.clone(), record.clone());
        self.publish("challenge_opened", &challenge_id, record.public_record())?;
        self.counters.challenges = self.counters.challenges.saturating_add(1);
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        request: ResolveChallengeRequest,
    ) -> Result<Option<String>> {
        request.validate()?;
        let (subject_id, evidence_root) = {
            let challenge = self.require_challenge(&request.challenge_id)?;
            if !challenge.status.accepts_evidence() {
                return Err(format!(
                    "challenge does not accept resolution from status {}",
                    challenge.status.as_str()
                ));
            }
            (
                challenge.request.subject_id.clone(),
                challenge.request.evidence_root.clone(),
            )
        };
        let mut slash_id = None;
        if matches!(
            request.verdict,
            ChallengeStatus::ChallengerWins | ChallengeStatus::Slashed
        ) && request.slash_amount > 0
        {
            let target_kind = request
                .slash_target_kind
                .ok_or_else(|| "missing slash target kind".to_string())?;
            let target_id = request
                .slash_target_id
                .clone()
                .ok_or_else(|| "missing slash target id".to_string())?;
            let event = SlashingEventRecord {
                slash_id: slashing_event_id(
                    &request.challenge_id,
                    &target_id,
                    request.slash_amount,
                    self.height,
                ),
                challenge_id: request.challenge_id.clone(),
                target_kind,
                target_id,
                slash_amount: request.slash_amount,
                evidence_root,
                reward_commitment: request.reward_commitment.clone(),
                created_height: self.height,
            };
            self.apply_slash(&event)?;
            slash_id = Some(event.slash_id.clone());
            self.slashing_events
                .insert(event.slash_id.clone(), event.clone());
            self.publish("slash_published", &event.slash_id, event.public_record())?;
            self.counters.slashing_events = self.counters.slashing_events.saturating_add(1);
        }
        if let Some(challenge) = self.challenges.get_mut(&request.challenge_id) {
            challenge.status = request.verdict;
            challenge.resolution = Some(request.clone());
            challenge.updated_height = self.height;
        }
        self.publish(
            "challenge_resolved",
            &request.challenge_id,
            json!({
                "challenge_id": request.challenge_id,
                "subject_id": subject_id,
                "verdict": request.verdict.as_str(),
                "slash_id": slash_id,
            }),
        )?;
        Ok(slash_id)
    }

    pub fn roots(&self) -> Roots {
        let deposit_note_root = records_root(
            "deposit_notes",
            self.deposit_notes
                .values()
                .map(DepositNoteRecord::public_record),
        );
        let monero_anchor_root = records_root(
            "monero_anchors",
            self.monero_anchors
                .values()
                .map(MoneroAnchorRecord::public_record),
        );
        let escrow_window_root = records_root(
            "escrow_windows",
            self.escrow_windows
                .values()
                .map(EscrowWindowRecord::public_record),
        );
        let proof_aggregate_root = records_root(
            "proof_aggregates",
            self.proof_aggregates
                .values()
                .map(ProofAggregateRecord::public_record),
        );
        let mint_authorization_root = records_root(
            "mint_authorizations",
            self.mint_authorizations
                .values()
                .map(MintAuthorizationRecord::public_record),
        );
        let sponsor_reservation_root = records_root(
            "sponsor_reservations",
            self.sponsor_reservations
                .values()
                .map(SponsorReservationRecord::public_record),
        );
        let receipt_root = records_root(
            "receipts",
            self.receipts.values().map(ReceiptRecord::public_record),
        );
        let rebate_root = records_root(
            "rebates",
            self.rebates.values().map(RebateRecord::public_record),
        );
        let privacy_fence_root = records_root(
            "privacy_fences",
            self.privacy_fences
                .values()
                .map(PrivacyFenceRecord::public_record),
        );
        let challenge_root = records_root(
            "challenges",
            self.challenges.values().map(ChallengeRecord::public_record),
        );
        let slashing_event_root = records_root(
            "slashing_events",
            self.slashing_events
                .values()
                .map(SlashingEventRecord::public_record),
        );
        let public_record_root = records_root(
            "public_records",
            self.public_records
                .values()
                .map(PublicRecord::public_record),
        );
        let nullifier_root = string_set_root("spent_nullifiers", &self.spent_nullifiers);
        let used_anchor_root =
            string_set_root("used_anchor_commitments", &self.used_anchor_commitments);
        let root_record = json!({
            "deposit_note_root": deposit_note_root,
            "monero_anchor_root": monero_anchor_root,
            "escrow_window_root": escrow_window_root,
            "proof_aggregate_root": proof_aggregate_root,
            "mint_authorization_root": mint_authorization_root,
            "sponsor_reservation_root": sponsor_reservation_root,
            "receipt_root": receipt_root,
            "rebate_root": rebate_root,
            "privacy_fence_root": privacy_fence_root,
            "challenge_root": challenge_root,
            "slashing_event_root": slashing_event_root,
            "public_record_root": public_record_root,
            "nullifier_root": nullifier_root,
            "used_anchor_root": used_anchor_root,
            "height": self.height,
            "counters": self.counters.public_record(),
        });
        let state_root = state_root_from_record(&root_record);
        Roots {
            deposit_note_root,
            monero_anchor_root,
            escrow_window_root,
            proof_aggregate_root,
            mint_authorization_root,
            sponsor_reservation_root,
            receipt_root,
            rebate_root,
            privacy_fence_root,
            challenge_root,
            slashing_event_root,
            public_record_root,
            nullifier_root,
            used_anchor_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_confidential_deposit_receipt_escrow_state",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn publish(&mut self, record_kind: &str, subject_id: &str, payload: Value) -> Result<()> {
        self.ensure_capacity(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        let record_id = public_record_id(record_kind, subject_id, self.height, &payload);
        if self.public_records.contains_key(&record_id) {
            return Err(format!("public record already exists: {record_id}"));
        }
        let record = PublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            payload,
        };
        self.public_records.insert(record_id, record);
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        Ok(())
    }

    fn require_note(&self, note_id: &str) -> Result<&DepositNoteRecord> {
        self.deposit_notes
            .get(note_id)
            .ok_or_else(|| format!("unknown deposit note: {note_id}"))
    }

    fn require_anchor(&self, anchor_id: &str) -> Result<&MoneroAnchorRecord> {
        self.monero_anchors
            .get(anchor_id)
            .ok_or_else(|| format!("unknown monero anchor: {anchor_id}"))
    }

    fn require_window(&self, window_id: &str) -> Result<&EscrowWindowRecord> {
        self.escrow_windows
            .get(window_id)
            .ok_or_else(|| format!("unknown escrow window: {window_id}"))
    }

    fn require_aggregate(&self, aggregate_id: &str) -> Result<&ProofAggregateRecord> {
        self.proof_aggregates
            .get(aggregate_id)
            .ok_or_else(|| format!("unknown proof aggregate: {aggregate_id}"))
    }

    fn require_mint_authorization(
        &self,
        mint_authorization_id: &str,
    ) -> Result<&MintAuthorizationRecord> {
        self.mint_authorizations
            .get(mint_authorization_id)
            .ok_or_else(|| format!("unknown mint authorization: {mint_authorization_id}"))
    }

    fn require_reservation(&self, reservation_id: &str) -> Result<&SponsorReservationRecord> {
        self.sponsor_reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown sponsor reservation: {reservation_id}"))
    }

    fn require_challenge(&self, challenge_id: &str) -> Result<&ChallengeRecord> {
        self.challenges
            .get(challenge_id)
            .ok_or_else(|| format!("unknown challenge: {challenge_id}"))
    }

    fn attach_challenge_to_subject(&mut self, subject_id: &str, challenge_id: &str) -> Result<()> {
        if let Some(note) = self.deposit_notes.get_mut(subject_id) {
            note.status = NoteStatus::Challenged;
            note.challenge_ids.insert(challenge_id.to_string());
            note.updated_height = self.height;
            return Ok(());
        }
        if let Some(anchor) = self.monero_anchors.get_mut(subject_id) {
            anchor.status = AnchorStatus::Disputed;
            anchor.challenge_ids.insert(challenge_id.to_string());
            anchor.updated_height = self.height;
            return Ok(());
        }
        if let Some(window) = self.escrow_windows.get_mut(subject_id) {
            window.status = WindowStatus::Challenged;
            window.challenge_ids.insert(challenge_id.to_string());
            window.updated_height = self.height;
            return Ok(());
        }
        if let Some(aggregate) = self.proof_aggregates.get_mut(subject_id) {
            aggregate.status = ProofAggregateStatus::Challenged;
            aggregate.challenge_ids.insert(challenge_id.to_string());
            aggregate.updated_height = self.height;
            return Ok(());
        }
        if let Some(auth) = self.mint_authorizations.get_mut(subject_id) {
            auth.status = MintAuthorizationStatus::Challenged;
            auth.challenge_ids.insert(challenge_id.to_string());
            auth.updated_height = self.height;
            return Ok(());
        }
        Err(format!("challenge subject not found: {subject_id}"))
    }

    fn apply_slash(&mut self, event: &SlashingEventRecord) -> Result<()> {
        match event.target_kind {
            SlashTargetKind::DepositNote => {
                let note = self
                    .deposit_notes
                    .get_mut(&event.target_id)
                    .ok_or_else(|| {
                        format!(
                            "slashing target deposit note not found: {}",
                            event.target_id
                        )
                    })?;
                note.status = NoteStatus::Slashed;
                note.updated_height = self.height;
            }
            SlashTargetKind::MoneroAnchor => {
                let anchor = self
                    .monero_anchors
                    .get_mut(&event.target_id)
                    .ok_or_else(|| {
                        format!(
                            "slashing target monero anchor not found: {}",
                            event.target_id
                        )
                    })?;
                anchor.status = AnchorStatus::Rejected;
                anchor.updated_height = self.height;
            }
            SlashTargetKind::EscrowWindow => {
                let window = self
                    .escrow_windows
                    .get_mut(&event.target_id)
                    .ok_or_else(|| {
                        format!(
                            "slashing target escrow window not found: {}",
                            event.target_id
                        )
                    })?;
                window.status = WindowStatus::Slashed;
                window.updated_height = self.height;
            }
            SlashTargetKind::ProofAggregate => {
                let aggregate =
                    self.proof_aggregates
                        .get_mut(&event.target_id)
                        .ok_or_else(|| {
                            format!(
                                "slashing target proof aggregate not found: {}",
                                event.target_id
                            )
                        })?;
                aggregate.status = ProofAggregateStatus::Slashed;
                aggregate.updated_height = self.height;
            }
            SlashTargetKind::MintAuthorization => {
                let auth = self
                    .mint_authorizations
                    .get_mut(&event.target_id)
                    .ok_or_else(|| {
                        format!(
                            "slashing target mint authorization not found: {}",
                            event.target_id
                        )
                    })?;
                auth.status = MintAuthorizationStatus::Slashed;
                auth.updated_height = self.height;
            }
            SlashTargetKind::SponsorReservation => {
                let reservation = self
                    .sponsor_reservations
                    .get_mut(&event.target_id)
                    .ok_or_else(|| {
                        format!(
                            "slashing target sponsor reservation not found: {}",
                            event.target_id
                        )
                    })?;
                reservation.status = SponsorReservationStatus::Slashed;
                reservation.updated_height = self.height;
            }
            SlashTargetKind::Sequencer | SlashTargetKind::Attester => {}
        }
        Ok(())
    }

    fn ensure_capacity(&self, name: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            return Err(format!("{name} capacity exceeded"));
        }
        Ok(())
    }

    fn expire_old_records(&mut self) {
        for note in self.deposit_notes.values_mut() {
            if note.status.is_live()
                && self.height > note.expires_height
                && note.receipt_id.is_none()
            {
                note.status = NoteStatus::Expired;
                note.updated_height = self.height;
            }
        }
        for window in self.escrow_windows.values_mut() {
            if matches!(
                window.status,
                WindowStatus::Open
                    | WindowStatus::Sealed
                    | WindowStatus::Aggregating
                    | WindowStatus::Minting
            ) && self.height > window.request.challenge_deadline_height
            {
                window.status = WindowStatus::Expired;
                window.updated_height = self.height;
            }
        }
        for aggregate in self.proof_aggregates.values_mut() {
            if matches!(
                aggregate.status,
                ProofAggregateStatus::Proposed | ProofAggregateStatus::Verified
            ) && self.height > aggregate.expires_height
                && aggregate.mint_authorization_id.is_none()
            {
                aggregate.status = ProofAggregateStatus::Expired;
                aggregate.updated_height = self.height;
            }
        }
        for auth in self.mint_authorizations.values_mut() {
            if matches!(
                auth.status,
                MintAuthorizationStatus::Authorized | MintAuthorizationStatus::Sponsored
            ) && self.height > auth.request.expires_height
                && auth.receipt_id.is_none()
            {
                auth.status = MintAuthorizationStatus::Expired;
                auth.updated_height = self.height;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.status.can_consume() && self.height > reservation.request.expires_height
            {
                reservation.status = SponsorReservationStatus::Expired;
                reservation.updated_height = self.height;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status.accepts_evidence() && self.height > challenge.expires_height {
                challenge.status = ChallengeStatus::Expired;
                challenge.updated_height = self.height;
            }
        }
    }
}

pub fn deposit_note_id(request: &SubmitDepositNoteRequest, height: u64) -> String {
    id_from_record("deposit_note_id", height, &request.public_record())
}

pub fn monero_anchor_id(request: &RegisterMoneroAnchorRequest, height: u64) -> String {
    id_from_record("monero_anchor_id", height, &request.public_record())
}

pub fn escrow_window_id(request: &OpenEscrowWindowRequest, height: u64) -> String {
    id_from_record("escrow_window_id", height, &request.public_record())
}

pub fn proof_aggregate_id(request: &AggregateDepositProofRequest, height: u64) -> String {
    id_from_record("proof_aggregate_id", height, &request.public_record())
}

pub fn mint_authorization_id(request: &AuthorizeTokenMintRequest, height: u64) -> String {
    id_from_record("mint_authorization_id", height, &request.public_record())
}

pub fn sponsor_reservation_id(request: &ReserveFeeSponsorRequest, height: u64) -> String {
    id_from_record("sponsor_reservation_id", height, &request.public_record())
}

pub fn receipt_id(request: &PublishReceiptRequest, height: u64) -> String {
    id_from_record("receipt_id", height, &request.public_record())
}

pub fn rebate_id(request: &PublishRebateRequest, height: u64) -> String {
    id_from_record("rebate_id", height, &request.public_record())
}

pub fn privacy_fence_id(request: &RegisterPrivacyFenceRequest, height: u64) -> String {
    id_from_record("privacy_fence_id", height, &request.public_record())
}

pub fn challenge_id(request: &OpenChallengeRequest, height: u64) -> String {
    id_from_record("challenge_id", height, &request.public_record())
}

pub fn slashing_event_id(
    challenge_id: &str,
    target_id: &str,
    slash_amount: u128,
    height: u64,
) -> String {
    domain_hash(
        "private_l2_confidential_deposit_receipt_escrow:slashing_event_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(target_id),
            HashPart::Str(&slash_amount.to_string()),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: &str,
    subject_id: &str,
    height: u64,
    payload: &Value,
) -> String {
    domain_hash(
        "private_l2_confidential_deposit_receipt_escrow:public_record_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private_l2_confidential_deposit_receipt_escrow:state_root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("private_l2_confidential_deposit_receipt_escrow:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("private_l2_confidential_deposit_receipt_escrow:{domain}"),
        records,
    )
}

fn id_from_record(domain: &str, height: u64, record: &Value) -> String {
    domain_hash(
        &format!("private_l2_confidential_deposit_receipt_escrow:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(height),
            HashPart::Json(record),
        ],
        32,
    )
}

fn records_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    public_record_root(domain, &values)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn ensure_non_empty_vec(name: &str, value: &[String]) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    for item in value {
        ensure_non_empty(name, item)?;
    }
    Ok(())
}

fn ensure_unique(name: &str, value: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for item in value {
        if !seen.insert(item) {
            return Err(format!("{name} contains duplicate id: {item}"));
        }
    }
    Ok(())
}

fn ensure_min(name: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        return Err(format!("{name} must be at least {min}"));
    }
    Ok(())
}

fn ensure_min_u128(name: &str, value: u128, min: u128) -> Result<()> {
    if value < min {
        return Err(format!("{name} must be at least {min}"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} exceeds {MAX_BPS} bps"));
    }
    Ok(())
}

fn ensure_capacity(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        return Err(format!("{name} must be nonzero"));
    }
    Ok(())
}
