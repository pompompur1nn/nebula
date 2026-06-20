use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PqMevBurnAuctionResult<T> = Result<T, String>;

pub const PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION: &str = "nebula-pq-mev-burn-auction-v1";
pub const PQ_MEV_BURN_AUCTION_SCHEMA_VERSION: u64 = 1;
pub const PQ_MEV_BURN_AUCTION_SECURITY_MODEL: &str =
    "post-quantum-commit-reveal-private-defi-devnet-v1";
pub const PQ_MEV_BURN_AUCTION_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_MEV_BURN_AUCTION_BID_ENCRYPTION_SCHEME: &str = "ML-KEM-1024-threshold-bid-envelope-v1";
pub const PQ_MEV_BURN_AUCTION_COMMITMENT_SCHEME: &str =
    "SHAKE256-domain-separated-bid-commitment-v1";
pub const PQ_MEV_BURN_AUCTION_SEQUENCER_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PQ_MEV_BURN_AUCTION_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_MEV_BURN_AUCTION_ANTI_SANDWICH_PROOF_SCHEME: &str =
    "zk-private-orderflow-no-sandwich-v1";
pub const PQ_MEV_BURN_AUCTION_BURN_RECEIPT_SCHEME: &str =
    "monero-view-key-burn-receipt-shake256-v1";
pub const PQ_MEV_BURN_AUCTION_SPONSOR_DISTRIBUTION_SCHEME: &str =
    "low-fee-sponsor-rebate-distribution-v1";
pub const PQ_MEV_BURN_AUCTION_DEVNET_FEE_ASSET_ID: &str = "dxmr";
pub const PQ_MEV_BURN_AUCTION_DEVNET_BURN_ASSET_ID: &str = "mev-burn-dxmr";
pub const PQ_MEV_BURN_AUCTION_DEVNET_OPERATOR_LABEL: &str = "devnet-pq-mev-burn-operator";
pub const PQ_MEV_BURN_AUCTION_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_COMMIT_WINDOW_BLOCKS: u64 = 6;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_REVEAL_WINDOW_BLOCKS: u64 = 4;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 8;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_BID_TTL_BLOCKS: u64 = 36;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_LOW_FEE_LANE_TTL_BLOCKS: u64 = 240;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_RECEIPT_DELAY_BLOCKS: u64 = 720;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_MAX_BID_BYTES: u64 = 96 * 1024;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_MAX_BIDS_PER_AUCTION: u64 = 512;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 1_500;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_MIN_BURN_BPS: u64 = 6_000;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_SPONSOR_SHARE_BPS: u64 = 2_500;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_PROTOCOL_SHARE_BPS: u64 = 1_500;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_SLASH_BPS: u64 = 3_000;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 75;
pub const PQ_MEV_BURN_AUCTION_DEFAULT_MIN_FAIRNESS_SCORE: u64 = 8_000;
pub const PQ_MEV_BURN_AUCTION_MAX_BPS: u64 = 10_000;
pub const PQ_MEV_BURN_AUCTION_MAX_CONFIG_LANES: usize = 64;
pub const PQ_MEV_BURN_AUCTION_MAX_AUCTIONS: usize = 1_024;
pub const PQ_MEV_BURN_AUCTION_MAX_BIDS: usize = 16_384;
pub const PQ_MEV_BURN_AUCTION_MAX_REVEALS: usize = 16_384;
pub const PQ_MEV_BURN_AUCTION_MAX_COMMITMENTS: usize = 4_096;
pub const PQ_MEV_BURN_AUCTION_MAX_RECEIPTS: usize = 16_384;
pub const PQ_MEV_BURN_AUCTION_MAX_SPONSORS: usize = 512;
pub const PQ_MEV_BURN_AUCTION_MAX_PROOFS: usize = 16_384;
pub const PQ_MEV_BURN_AUCTION_MAX_SLASHING_EVIDENCE: usize = 2_048;
pub const PQ_MEV_BURN_AUCTION_MAX_PUBLIC_RECORDS: usize = 32_768;

const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_CHALLENGED: &str = "challenged";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqMevAuctionLane {
    PrivateDex,
    ConfidentialAmm,
    ConfidentialLending,
    PrivateLiquidation,
    PrivateIntent,
    MoneroBridge,
    LowFeeSwap,
    LowFeeTransfer,
    WalletRecovery,
    ProofSubmission,
    EmergencyExit,
    Maintenance,
}

impl PqMevAuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDex => "private_dex",
            Self::ConfidentialAmm => "confidential_amm",
            Self::ConfidentialLending => "confidential_lending",
            Self::PrivateLiquidation => "private_liquidation",
            Self::PrivateIntent => "private_intent",
            Self::MoneroBridge => "monero_bridge",
            Self::LowFeeSwap => "low_fee_swap",
            Self::LowFeeTransfer => "low_fee_transfer",
            Self::WalletRecovery => "wallet_recovery",
            Self::ProofSubmission => "proof_submission",
            Self::EmergencyExit => "emergency_exit",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn private_defi(self) -> bool {
        matches!(
            self,
            Self::PrivateDex
                | Self::ConfidentialAmm
                | Self::ConfidentialLending
                | Self::PrivateLiquidation
                | Self::PrivateIntent
        )
    }

    pub fn low_fee(self) -> bool {
        matches!(
            self,
            Self::LowFeeSwap
                | Self::LowFeeTransfer
                | Self::WalletRecovery
                | Self::ProofSubmission
                | Self::EmergencyExit
        )
    }

    pub fn fairness_priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 0,
            Self::PrivateLiquidation => 1,
            Self::WalletRecovery => 2,
            Self::MoneroBridge => 3,
            Self::LowFeeTransfer => 4,
            Self::LowFeeSwap => 5,
            Self::PrivateIntent => 6,
            Self::ConfidentialAmm => 7,
            Self::PrivateDex => 8,
            Self::ConfidentialLending => 9,
            Self::ProofSubmission => 10,
            Self::Maintenance => 11,
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyExit => 300,
            Self::WalletRecovery => 500,
            Self::LowFeeTransfer => 700,
            Self::MoneroBridge => 1_100,
            Self::LowFeeSwap => 1_500,
            Self::ProofSubmission => 1_800,
            Self::PrivateIntent => 2_200,
            Self::PrivateDex => 2_500,
            Self::ConfidentialAmm => 2_750,
            Self::ConfidentialLending => 3_000,
            Self::PrivateLiquidation => 3_500,
            Self::Maintenance => 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqMevAuctionStatus {
    Scheduled,
    CommitOpen,
    RevealOpen,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl PqMevAuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_commit(self) -> bool {
        matches!(self, Self::CommitOpen)
    }

    pub fn accepts_reveal(self) -> bool {
        matches!(self, Self::RevealOpen | Self::Settling)
    }

    pub fn final_status(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqMevBidStatus {
    Encrypted,
    Committed,
    Revealed,
    Eligible,
    Winning,
    Burned,
    Refunded,
    Rejected,
    Expired,
}

impl PqMevBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Eligible => "eligible",
            Self::Winning => "winning",
            Self::Burned => "burned",
            Self::Refunded => "refunded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Committed | Self::Revealed | Self::Eligible | Self::Winning
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSequencerCommitmentStatus {
    Draft,
    Committed,
    Revealed,
    Matched,
    Disputed,
    Slashed,
    Expired,
}

impl PqSequencerCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Matched => "matched",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnReceiptStatus {
    Pending,
    Anchored,
    Distributed,
    Disputed,
    Voided,
}

impl BurnReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Anchored => "anchored",
            Self::Distributed => "distributed",
            Self::Disputed => "disputed",
            Self::Voided => "voided",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeLaneStatus {
    Active,
    Congested,
    Sponsored,
    Exhausted,
    Paused,
    Expired,
}

impl LowFeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Congested => "congested",
            Self::Sponsored => "sponsored",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Congested | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiSandwichProofStatus {
    Submitted,
    Verified,
    Rejected,
    Challenged,
    Expired,
}

impl AntiSandwichProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    EarlyReveal,
    BidCensorship,
    RevealWithholding,
    InvalidOrdering,
    SandwichInclusion,
    BurnReceiptMismatch,
    SponsorDistributionMismatch,
    DoubleProposal,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EarlyReveal => "early_reveal",
            Self::BidCensorship => "bid_censorship",
            Self::RevealWithholding => "reveal_withholding",
            Self::InvalidOrdering => "invalid_ordering",
            Self::SandwichInclusion => "sandwich_inclusion",
            Self::BurnReceiptMismatch => "burn_receipt_mismatch",
            Self::SponsorDistributionMismatch => "sponsor_distribution_mismatch",
            Self::DoubleProposal => "double_proposal",
        }
    }

    pub fn severity_weight(self) -> u64 {
        match self {
            Self::DoubleProposal => 100,
            Self::SandwichInclusion => 95,
            Self::EarlyReveal => 90,
            Self::BurnReceiptMismatch => 85,
            Self::SponsorDistributionMismatch => 80,
            Self::BidCensorship => 75,
            Self::RevealWithholding => 70,
            Self::InvalidOrdering => 65,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    AuctionScheduled,
    EncryptedBid,
    SequencerCommitment,
    BidReveal,
    AuctionSettlement,
    BurnReceipt,
    SponsorDistribution,
    LowFeeLane,
    AntiSandwichProof,
    SlashingEvidence,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuctionScheduled => "auction_scheduled",
            Self::EncryptedBid => "encrypted_bid",
            Self::SequencerCommitment => "sequencer_commitment",
            Self::BidReveal => "bid_reveal",
            Self::AuctionSettlement => "auction_settlement",
            Self::BurnReceipt => "burn_receipt",
            Self::SponsorDistribution => "sponsor_distribution",
            Self::LowFeeLane => "low_fee_lane",
            Self::AntiSandwichProof => "anti_sandwich_proof",
            Self::SlashingEvidence => "slashing_evidence",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMevBurnAuctionConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub operator_label: String,
    pub fee_asset_id: String,
    pub burn_asset_id: String,
    pub epoch_blocks: u64,
    pub commit_window_blocks: u64,
    pub reveal_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub low_fee_lane_ttl_blocks: u64,
    pub receipt_delay_blocks: u64,
    pub min_pq_security_bits: u16,
    pub max_bid_bytes: u64,
    pub max_bids_per_auction: u64,
    pub default_low_fee_cap_micro_units: u64,
    pub min_burn_bps: u64,
    pub sponsor_share_bps: u64,
    pub protocol_share_bps: u64,
    pub slash_bps: u64,
    pub max_price_impact_bps: u64,
    pub min_fairness_score: u64,
    pub bid_encryption_scheme: String,
    pub commitment_scheme: String,
    pub sequencer_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub anti_sandwich_proof_scheme: String,
    pub burn_receipt_scheme: String,
    pub sponsor_distribution_scheme: String,
}

impl PqMevBurnAuctionConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_MEV_BURN_AUCTION_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            operator_label: PQ_MEV_BURN_AUCTION_DEVNET_OPERATOR_LABEL.to_string(),
            fee_asset_id: PQ_MEV_BURN_AUCTION_DEVNET_FEE_ASSET_ID.to_string(),
            burn_asset_id: PQ_MEV_BURN_AUCTION_DEVNET_BURN_ASSET_ID.to_string(),
            epoch_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_EPOCH_BLOCKS,
            commit_window_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_COMMIT_WINDOW_BLOCKS,
            reveal_window_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_REVEAL_WINDOW_BLOCKS,
            settlement_window_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            challenge_window_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            bid_ttl_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_BID_TTL_BLOCKS,
            low_fee_lane_ttl_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_LOW_FEE_LANE_TTL_BLOCKS,
            receipt_delay_blocks: PQ_MEV_BURN_AUCTION_DEFAULT_RECEIPT_DELAY_BLOCKS,
            min_pq_security_bits: PQ_MEV_BURN_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_bid_bytes: PQ_MEV_BURN_AUCTION_DEFAULT_MAX_BID_BYTES,
            max_bids_per_auction: PQ_MEV_BURN_AUCTION_DEFAULT_MAX_BIDS_PER_AUCTION,
            default_low_fee_cap_micro_units: PQ_MEV_BURN_AUCTION_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            min_burn_bps: PQ_MEV_BURN_AUCTION_DEFAULT_MIN_BURN_BPS,
            sponsor_share_bps: PQ_MEV_BURN_AUCTION_DEFAULT_SPONSOR_SHARE_BPS,
            protocol_share_bps: PQ_MEV_BURN_AUCTION_DEFAULT_PROTOCOL_SHARE_BPS,
            slash_bps: PQ_MEV_BURN_AUCTION_DEFAULT_SLASH_BPS,
            max_price_impact_bps: PQ_MEV_BURN_AUCTION_DEFAULT_MAX_PRICE_IMPACT_BPS,
            min_fairness_score: PQ_MEV_BURN_AUCTION_DEFAULT_MIN_FAIRNESS_SCORE,
            bid_encryption_scheme: PQ_MEV_BURN_AUCTION_BID_ENCRYPTION_SCHEME.to_string(),
            commitment_scheme: PQ_MEV_BURN_AUCTION_COMMITMENT_SCHEME.to_string(),
            sequencer_signature_scheme: PQ_MEV_BURN_AUCTION_SEQUENCER_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: PQ_MEV_BURN_AUCTION_BACKUP_SIGNATURE_SCHEME.to_string(),
            anti_sandwich_proof_scheme: PQ_MEV_BURN_AUCTION_ANTI_SANDWICH_PROOF_SCHEME.to_string(),
            burn_receipt_scheme: PQ_MEV_BURN_AUCTION_BURN_RECEIPT_SCHEME.to_string(),
            sponsor_distribution_scheme: PQ_MEV_BURN_AUCTION_SPONSOR_DISTRIBUTION_SCHEME
                .to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_burn_auction_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "fee_asset_id": self.fee_asset_id,
            "burn_asset_id": self.burn_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "commit_window_blocks": self.commit_window_blocks,
            "reveal_window_blocks": self.reveal_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "low_fee_lane_ttl_blocks": self.low_fee_lane_ttl_blocks,
            "receipt_delay_blocks": self.receipt_delay_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_bid_bytes": self.max_bid_bytes,
            "max_bids_per_auction": self.max_bids_per_auction,
            "default_low_fee_cap_micro_units": self.default_low_fee_cap_micro_units,
            "min_burn_bps": self.min_burn_bps,
            "sponsor_share_bps": self.sponsor_share_bps,
            "protocol_share_bps": self.protocol_share_bps,
            "slash_bps": self.slash_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "min_fairness_score": self.min_fairness_score,
            "bid_encryption_scheme": self.bid_encryption_scheme,
            "commitment_scheme": self.commitment_scheme,
            "sequencer_signature_scheme": self.sequencer_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "anti_sandwich_proof_scheme": self.anti_sandwich_proof_scheme,
            "burn_receipt_scheme": self.burn_receipt_scheme,
            "sponsor_distribution_scheme": self.sponsor_distribution_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_eq(
            "protocol version",
            &self.protocol_version,
            PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
        )?;
        if self.schema_version != PQ_MEV_BURN_AUCTION_SCHEMA_VERSION {
            return Err("pq mev burn auction schema version mismatch".to_string());
        }
        ensure_eq("chain id", &self.chain_id, CHAIN_ID)?;
        ensure_non_empty("operator label", &self.operator_label)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_non_empty("burn asset id", &self.burn_asset_id)?;
        ensure_positive("epoch blocks", self.epoch_blocks)?;
        ensure_positive("commit window blocks", self.commit_window_blocks)?;
        ensure_positive("reveal window blocks", self.reveal_window_blocks)?;
        ensure_positive("settlement window blocks", self.settlement_window_blocks)?;
        ensure_positive("challenge window blocks", self.challenge_window_blocks)?;
        ensure_positive("bid ttl blocks", self.bid_ttl_blocks)?;
        ensure_positive("low fee lane ttl blocks", self.low_fee_lane_ttl_blocks)?;
        ensure_positive("receipt delay blocks", self.receipt_delay_blocks)?;
        if self.min_pq_security_bits < PQ_MEV_BURN_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("minimum pq security bits below policy floor".to_string());
        }
        ensure_positive("max bid bytes", self.max_bid_bytes)?;
        ensure_positive("max bids per auction", self.max_bids_per_auction)?;
        ensure_positive("default low fee cap", self.default_low_fee_cap_micro_units)?;
        ensure_bps("minimum burn bps", self.min_burn_bps)?;
        ensure_bps("sponsor share bps", self.sponsor_share_bps)?;
        ensure_bps("protocol share bps", self.protocol_share_bps)?;
        ensure_bps("slash bps", self.slash_bps)?;
        ensure_bps("max price impact bps", self.max_price_impact_bps)?;
        ensure_bps("minimum fairness score", self.min_fairness_score)?;
        if self
            .min_burn_bps
            .saturating_add(self.sponsor_share_bps)
            .saturating_add(self.protocol_share_bps)
            > PQ_MEV_BURN_AUCTION_MAX_BPS
        {
            return Err("burn and distribution shares exceed 100%".to_string());
        }
        ensure_eq(
            "bid encryption scheme",
            &self.bid_encryption_scheme,
            PQ_MEV_BURN_AUCTION_BID_ENCRYPTION_SCHEME,
        )?;
        ensure_eq(
            "commitment scheme",
            &self.commitment_scheme,
            PQ_MEV_BURN_AUCTION_COMMITMENT_SCHEME,
        )?;
        ensure_eq(
            "sequencer signature scheme",
            &self.sequencer_signature_scheme,
            PQ_MEV_BURN_AUCTION_SEQUENCER_SIGNATURE_SCHEME,
        )?;
        ensure_eq(
            "backup signature scheme",
            &self.backup_signature_scheme,
            PQ_MEV_BURN_AUCTION_BACKUP_SIGNATURE_SCHEME,
        )?;
        ensure_eq(
            "anti sandwich proof scheme",
            &self.anti_sandwich_proof_scheme,
            PQ_MEV_BURN_AUCTION_ANTI_SANDWICH_PROOF_SCHEME,
        )?;
        ensure_eq(
            "burn receipt scheme",
            &self.burn_receipt_scheme,
            PQ_MEV_BURN_AUCTION_BURN_RECEIPT_SCHEME,
        )?;
        ensure_eq(
            "sponsor distribution scheme",
            &self.sponsor_distribution_scheme,
            PQ_MEV_BURN_AUCTION_SPONSOR_DISTRIBUTION_SCHEME,
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionLaneConfig {
    pub lane_id: String,
    pub lane: PqMevAuctionLane,
    pub display_name: String,
    pub protected: bool,
    pub private_defi: bool,
    pub low_fee: bool,
    pub fee_cap_micro_units: u64,
    pub max_price_impact_bps: u64,
    pub priority_weight: u64,
    pub sponsor_pool_id: String,
    pub policy_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl AuctionLaneConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: PqMevAuctionLane,
        display_name: &str,
        fee_cap_micro_units: u64,
        max_price_impact_bps: u64,
        priority_weight: u64,
        sponsor_pool_id: &str,
        policy_payload: &Value,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("lane display name", display_name)?;
        ensure_positive("fee cap", fee_cap_micro_units)?;
        ensure_bps("max price impact bps", max_price_impact_bps)?;
        ensure_positive("priority weight", priority_weight)?;
        ensure_non_empty("sponsor pool id", sponsor_pool_id)?;
        ensure_window("lane validity", valid_from_height, valid_until_height)?;
        let policy_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-LANE-POLICY", policy_payload);
        let lane_id = pq_mev_lane_id(lane, sponsor_pool_id, valid_from_height);
        Ok(Self {
            lane_id,
            lane,
            display_name: display_name.to_string(),
            protected: lane.low_fee() || lane.private_defi(),
            private_defi: lane.private_defi(),
            low_fee: lane.low_fee(),
            fee_cap_micro_units,
            max_price_impact_bps,
            priority_weight,
            sponsor_pool_id: sponsor_pool_id.to_string(),
            policy_root,
            valid_from_height,
            valid_until_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.valid_from_height && height < self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_auction_lane_config",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "display_name": self.display_name,
            "protected": self.protected,
            "private_defi": self.private_defi,
            "low_fee": self.low_fee,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "max_price_impact_bps": self.max_price_impact_bps,
            "priority_weight": self.priority_weight,
            "sponsor_pool_id": self.sponsor_pool_id,
            "policy_root": self.policy_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn lane_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-LANE", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("lane id", &self.lane_id)?;
        ensure_non_empty("display name", &self.display_name)?;
        ensure_positive("fee cap", self.fee_cap_micro_units)?;
        ensure_bps("max price impact bps", self.max_price_impact_bps)?;
        ensure_positive("priority weight", self.priority_weight)?;
        ensure_non_empty("sponsor pool id", &self.sponsor_pool_id)?;
        ensure_hex_root("policy root", &self.policy_root)?;
        ensure_window(
            "lane validity",
            self.valid_from_height,
            self.valid_until_height,
        )?;
        if self.low_fee != self.lane.low_fee() {
            return Err("lane low fee marker mismatch".to_string());
        }
        if self.private_defi != self.lane.private_defi() {
            return Err("lane private defi marker mismatch".to_string());
        }
        let expected = pq_mev_lane_id(self.lane, &self.sponsor_pool_id, self.valid_from_height);
        if self.lane_id != expected {
            return Err("lane id mismatch".to_string());
        }
        Ok(self.lane_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMevAuction {
    pub auction_id: String,
    pub epoch: u64,
    pub lane_id: String,
    pub lane: PqMevAuctionLane,
    pub proposer_id: String,
    pub blockspace_slot: u64,
    pub commit_start_height: u64,
    pub commit_end_height: u64,
    pub reveal_start_height: u64,
    pub reveal_end_height: u64,
    pub settlement_height: u64,
    pub challenge_end_height: u64,
    pub reserve_price_micro_units: u64,
    pub low_fee_cap_micro_units: u64,
    pub max_price_impact_bps: u64,
    pub encrypted_bid_root: String,
    pub reveal_root: String,
    pub settlement_root: String,
    pub burn_receipt_root: String,
    pub anti_sandwich_root: String,
    pub status: PqMevAuctionStatus,
}

impl PqMevAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        lane_id: &str,
        lane: PqMevAuctionLane,
        proposer_id: &str,
        blockspace_slot: u64,
        commit_start_height: u64,
        config: &PqMevBurnAuctionConfig,
        reserve_price_micro_units: u64,
        low_fee_cap_micro_units: u64,
        max_price_impact_bps: u64,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("auction lane id", lane_id)?;
        ensure_non_empty("auction proposer id", proposer_id)?;
        ensure_positive("blockspace slot", blockspace_slot)?;
        ensure_positive("reserve price", reserve_price_micro_units)?;
        ensure_positive("low fee cap", low_fee_cap_micro_units)?;
        ensure_bps("max price impact bps", max_price_impact_bps)?;
        let commit_end_height = commit_start_height.saturating_add(config.commit_window_blocks);
        let reveal_start_height = commit_end_height;
        let reveal_end_height = reveal_start_height.saturating_add(config.reveal_window_blocks);
        let settlement_height = reveal_end_height.saturating_add(config.settlement_window_blocks);
        let challenge_end_height = settlement_height.saturating_add(config.challenge_window_blocks);
        let encrypted_bid_root = empty_record_root("PQ-MEV-BURN-AUCTION-ENCRYPTED-BIDS");
        let reveal_root = empty_record_root("PQ-MEV-BURN-AUCTION-REVEALS");
        let settlement_root = empty_record_root("PQ-MEV-BURN-AUCTION-SETTLEMENT");
        let burn_receipt_root = empty_record_root("PQ-MEV-BURN-AUCTION-BURN-RECEIPTS");
        let anti_sandwich_root = empty_record_root("PQ-MEV-BURN-AUCTION-ANTI-SANDWICH");
        let auction_id = pq_mev_auction_id(
            epoch,
            lane_id,
            proposer_id,
            blockspace_slot,
            commit_start_height,
        );
        Ok(Self {
            auction_id,
            epoch,
            lane_id: lane_id.to_string(),
            lane,
            proposer_id: proposer_id.to_string(),
            blockspace_slot,
            commit_start_height,
            commit_end_height,
            reveal_start_height,
            reveal_end_height,
            settlement_height,
            challenge_end_height,
            reserve_price_micro_units,
            low_fee_cap_micro_units,
            max_price_impact_bps,
            encrypted_bid_root,
            reveal_root,
            settlement_root,
            burn_receipt_root,
            anti_sandwich_root,
            status: PqMevAuctionStatus::CommitOpen,
        })
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.commit_start_height && height <= self.challenge_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_auction",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "epoch": self.epoch,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "proposer_id": self.proposer_id,
            "blockspace_slot": self.blockspace_slot,
            "commit_start_height": self.commit_start_height,
            "commit_end_height": self.commit_end_height,
            "reveal_start_height": self.reveal_start_height,
            "reveal_end_height": self.reveal_end_height,
            "settlement_height": self.settlement_height,
            "challenge_end_height": self.challenge_end_height,
            "reserve_price_micro_units": self.reserve_price_micro_units,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "max_price_impact_bps": self.max_price_impact_bps,
            "encrypted_bid_root": self.encrypted_bid_root,
            "reveal_root": self.reveal_root,
            "settlement_root": self.settlement_root,
            "burn_receipt_root": self.burn_receipt_root,
            "anti_sandwich_root": self.anti_sandwich_root,
            "status": self.status.as_str(),
        })
    }

    pub fn auction_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("auction id", &self.auction_id)?;
        ensure_non_empty("auction lane id", &self.lane_id)?;
        ensure_non_empty("auction proposer id", &self.proposer_id)?;
        ensure_positive("blockspace slot", self.blockspace_slot)?;
        ensure_window(
            "commit window",
            self.commit_start_height,
            self.commit_end_height,
        )?;
        ensure_window(
            "reveal window",
            self.reveal_start_height,
            self.reveal_end_height,
        )?;
        if self.reveal_start_height < self.commit_end_height {
            return Err("reveal window overlaps commit window".to_string());
        }
        if self.settlement_height < self.reveal_end_height {
            return Err("settlement height precedes reveal close".to_string());
        }
        if self.challenge_end_height < self.settlement_height {
            return Err("challenge height precedes settlement".to_string());
        }
        ensure_positive("reserve price", self.reserve_price_micro_units)?;
        ensure_positive("low fee cap", self.low_fee_cap_micro_units)?;
        ensure_bps("max price impact bps", self.max_price_impact_bps)?;
        ensure_hex_root("encrypted bid root", &self.encrypted_bid_root)?;
        ensure_hex_root("reveal root", &self.reveal_root)?;
        ensure_hex_root("settlement root", &self.settlement_root)?;
        ensure_hex_root("burn receipt root", &self.burn_receipt_root)?;
        ensure_hex_root("anti sandwich root", &self.anti_sandwich_root)?;
        let expected = pq_mev_auction_id(
            self.epoch,
            &self.lane_id,
            &self.proposer_id,
            self.blockspace_slot,
            self.commit_start_height,
        );
        if self.auction_id != expected {
            return Err("auction id mismatch".to_string());
        }
        Ok(self.auction_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlockspaceBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub payer_nullifier: String,
    pub encrypted_payload_root: String,
    pub ciphertext_root: String,
    pub bid_commitment: String,
    pub bid_size_bytes: u64,
    pub max_fee_micro_units: u64,
    pub protected_lane: bool,
    pub private_orderflow: bool,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub pq_security_bits: u16,
    pub encryption_scheme: String,
    pub status: PqMevBidStatus,
}

impl EncryptedBlockspaceBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        bidder_commitment: &str,
        payer_nullifier: &str,
        sealed_payload: &Value,
        bid_size_bytes: u64,
        max_fee_micro_units: u64,
        protected_lane: bool,
        private_orderflow: bool,
        submitted_at_height: u64,
        config: &PqMevBurnAuctionConfig,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("bid auction id", auction_id)?;
        ensure_non_empty("bidder commitment", bidder_commitment)?;
        ensure_non_empty("payer nullifier", payer_nullifier)?;
        ensure_positive("bid size bytes", bid_size_bytes)?;
        if bid_size_bytes > config.max_bid_bytes {
            return Err("encrypted bid exceeds max bid bytes".to_string());
        }
        ensure_positive("max fee", max_fee_micro_units)?;
        let encrypted_payload_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-SEALED-BID", sealed_payload);
        let ciphertext_root =
            pq_mev_string_root("PQ-MEV-BURN-AUCTION-CIPHERTEXT", &encrypted_payload_root);
        let bid_commitment = pq_mev_bid_commitment(
            auction_id,
            bidder_commitment,
            payer_nullifier,
            &encrypted_payload_root,
            submitted_at_height,
        );
        let expires_at_height = submitted_at_height.saturating_add(config.bid_ttl_blocks);
        let bid_id = pq_mev_bid_id(auction_id, &bid_commitment, submitted_at_height);
        Ok(Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            payer_nullifier: payer_nullifier.to_string(),
            encrypted_payload_root,
            ciphertext_root,
            bid_commitment,
            bid_size_bytes,
            max_fee_micro_units,
            protected_lane,
            private_orderflow,
            submitted_at_height,
            expires_at_height,
            pq_security_bits: config.min_pq_security_bits,
            encryption_scheme: config.bid_encryption_scheme.clone(),
            status: PqMevBidStatus::Encrypted,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.active() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_blockspace_bid",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "payer_nullifier": self.payer_nullifier,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_root": self.ciphertext_root,
            "bid_commitment": self.bid_commitment,
            "bid_size_bytes": self.bid_size_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "protected_lane": self.protected_lane,
            "private_orderflow": self.private_orderflow,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_security_bits": self.pq_security_bits,
            "encryption_scheme": self.encryption_scheme,
            "status": self.status.as_str(),
        })
    }

    pub fn bid_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-BID", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("bid id", &self.bid_id)?;
        ensure_non_empty("bid auction id", &self.auction_id)?;
        ensure_non_empty("bidder commitment", &self.bidder_commitment)?;
        ensure_non_empty("payer nullifier", &self.payer_nullifier)?;
        ensure_hex_root("encrypted payload root", &self.encrypted_payload_root)?;
        ensure_hex_root("ciphertext root", &self.ciphertext_root)?;
        ensure_hex_root("bid commitment", &self.bid_commitment)?;
        ensure_positive("bid size bytes", self.bid_size_bytes)?;
        ensure_positive("max fee", self.max_fee_micro_units)?;
        ensure_window("bid ttl", self.submitted_at_height, self.expires_at_height)?;
        if self.pq_security_bits < PQ_MEV_BURN_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("encrypted bid pq security bits below policy floor".to_string());
        }
        ensure_eq(
            "bid encryption scheme",
            &self.encryption_scheme,
            PQ_MEV_BURN_AUCTION_BID_ENCRYPTION_SCHEME,
        )?;
        let expected_commitment = pq_mev_bid_commitment(
            &self.auction_id,
            &self.bidder_commitment,
            &self.payer_nullifier,
            &self.encrypted_payload_root,
            self.submitted_at_height,
        );
        if self.bid_commitment != expected_commitment {
            return Err("bid commitment mismatch".to_string());
        }
        let expected_id = pq_mev_bid_id(
            &self.auction_id,
            &self.bid_commitment,
            self.submitted_at_height,
        );
        if self.bid_id != expected_id {
            return Err("bid id mismatch".to_string());
        }
        Ok(self.bid_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSequencerCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub proposer_id: String,
    pub sequencer_key_root: String,
    pub encrypted_bid_root: String,
    pub ordering_commitment_root: String,
    pub private_orderflow_root: String,
    pub low_fee_lane_root: String,
    pub pq_signature_root: String,
    pub backup_signature_root: String,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub status: PqSequencerCommitmentStatus,
}

impl PqSequencerCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        proposer_id: &str,
        sequencer_key_label: &str,
        encrypted_bid_root: &str,
        ordering_payload: &Value,
        private_orderflow_payload: &Value,
        low_fee_lane_payload: &Value,
        committed_at_height: u64,
        config: &PqMevBurnAuctionConfig,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("commitment auction id", auction_id)?;
        ensure_non_empty("commitment proposer id", proposer_id)?;
        ensure_non_empty("sequencer key label", sequencer_key_label)?;
        ensure_hex_root("encrypted bid root", encrypted_bid_root)?;
        let sequencer_key_root =
            pq_mev_string_root("PQ-MEV-BURN-AUCTION-SEQUENCER-KEY", sequencer_key_label);
        let ordering_commitment_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-ORDERING", ordering_payload);
        let private_orderflow_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-PRIVATE-ORDERFLOW",
            private_orderflow_payload,
        );
        let low_fee_lane_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-LOW-FEE-LANE",
            low_fee_lane_payload,
        );
        let pq_signature_root = pq_mev_string_root(
            "PQ-MEV-BURN-AUCTION-COMMITMENT-SIGNATURE",
            &format!(
                "{auction_id}:{proposer_id}:{}",
                config.sequencer_signature_scheme
            ),
        );
        let backup_signature_root = pq_mev_string_root(
            "PQ-MEV-BURN-AUCTION-COMMITMENT-BACKUP-SIGNATURE",
            &format!(
                "{auction_id}:{proposer_id}:{}",
                config.backup_signature_scheme
            ),
        );
        let reveal_deadline_height =
            committed_at_height.saturating_add(config.reveal_window_blocks);
        let commitment_id = pq_mev_sequencer_commitment_id(
            auction_id,
            proposer_id,
            &ordering_commitment_root,
            committed_at_height,
        );
        Ok(Self {
            commitment_id,
            auction_id: auction_id.to_string(),
            proposer_id: proposer_id.to_string(),
            sequencer_key_root,
            encrypted_bid_root: encrypted_bid_root.to_string(),
            ordering_commitment_root,
            private_orderflow_root,
            low_fee_lane_root,
            pq_signature_root,
            backup_signature_root,
            committed_at_height,
            reveal_deadline_height,
            status: PqSequencerCommitmentStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sequencer_commitment",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "proposer_id": self.proposer_id,
            "sequencer_key_root": self.sequencer_key_root,
            "encrypted_bid_root": self.encrypted_bid_root,
            "ordering_commitment_root": self.ordering_commitment_root,
            "private_orderflow_root": self.private_orderflow_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "pq_signature_root": self.pq_signature_root,
            "backup_signature_root": self.backup_signature_root,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn commitment_root(&self) -> String {
        pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-SEQUENCER-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("commitment id", &self.commitment_id)?;
        ensure_non_empty("commitment auction id", &self.auction_id)?;
        ensure_non_empty("commitment proposer id", &self.proposer_id)?;
        ensure_hex_root("sequencer key root", &self.sequencer_key_root)?;
        ensure_hex_root("encrypted bid root", &self.encrypted_bid_root)?;
        ensure_hex_root("ordering commitment root", &self.ordering_commitment_root)?;
        ensure_hex_root("private orderflow root", &self.private_orderflow_root)?;
        ensure_hex_root("low fee lane root", &self.low_fee_lane_root)?;
        ensure_hex_root("pq signature root", &self.pq_signature_root)?;
        ensure_hex_root("backup signature root", &self.backup_signature_root)?;
        ensure_window(
            "commitment reveal deadline",
            self.committed_at_height,
            self.reveal_deadline_height,
        )?;
        let expected = pq_mev_sequencer_commitment_id(
            &self.auction_id,
            &self.proposer_id,
            &self.ordering_commitment_root,
            self.committed_at_height,
        );
        if self.commitment_id != expected {
            return Err("sequencer commitment id mismatch".to_string());
        }
        Ok(self.commitment_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BidReveal {
    pub reveal_id: String,
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub clear_bid_root: String,
    pub bid_amount_micro_units: u64,
    pub burn_amount_micro_units: u64,
    pub sponsor_rebate_micro_units: u64,
    pub solver_fee_micro_units: u64,
    pub clearing_priority: u64,
    pub reveal_nullifier: String,
    pub revealed_at_height: u64,
    pub pq_signature_root: String,
    pub status: PqMevBidStatus,
}

impl BidReveal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bid_id: &str,
        auction_id: &str,
        bidder_commitment: &str,
        clear_payload: &Value,
        bid_amount_micro_units: u64,
        clearing_priority: u64,
        reveal_nullifier: &str,
        revealed_at_height: u64,
        config: &PqMevBurnAuctionConfig,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("reveal bid id", bid_id)?;
        ensure_non_empty("reveal auction id", auction_id)?;
        ensure_non_empty("reveal bidder commitment", bidder_commitment)?;
        ensure_positive("bid amount", bid_amount_micro_units)?;
        ensure_positive("clearing priority", clearing_priority)?;
        ensure_non_empty("reveal nullifier", reveal_nullifier)?;
        let clear_bid_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-CLEAR-BID", clear_payload);
        let burn_amount_micro_units = bps_portion(bid_amount_micro_units, config.min_burn_bps);
        let sponsor_rebate_micro_units =
            bps_portion(bid_amount_micro_units, config.sponsor_share_bps);
        let solver_fee_micro_units = bid_amount_micro_units
            .saturating_sub(burn_amount_micro_units)
            .saturating_sub(sponsor_rebate_micro_units)
            .saturating_sub(bps_portion(
                bid_amount_micro_units,
                config.protocol_share_bps,
            ));
        let pq_signature_root = pq_mev_string_root(
            "PQ-MEV-BURN-AUCTION-REVEAL-SIGNATURE",
            &format!("{bid_id}:{auction_id}:{bidder_commitment}:{reveal_nullifier}"),
        );
        let reveal_id = pq_mev_reveal_id(bid_id, auction_id, &clear_bid_root, revealed_at_height);
        Ok(Self {
            reveal_id,
            bid_id: bid_id.to_string(),
            auction_id: auction_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            clear_bid_root,
            bid_amount_micro_units,
            burn_amount_micro_units,
            sponsor_rebate_micro_units,
            solver_fee_micro_units,
            clearing_priority,
            reveal_nullifier: reveal_nullifier.to_string(),
            revealed_at_height,
            pq_signature_root,
            status: PqMevBidStatus::Revealed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_bid_reveal",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "reveal_id": self.reveal_id,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "clear_bid_root": self.clear_bid_root,
            "bid_amount_micro_units": self.bid_amount_micro_units,
            "burn_amount_micro_units": self.burn_amount_micro_units,
            "sponsor_rebate_micro_units": self.sponsor_rebate_micro_units,
            "solver_fee_micro_units": self.solver_fee_micro_units,
            "clearing_priority": self.clearing_priority,
            "reveal_nullifier": self.reveal_nullifier,
            "revealed_at_height": self.revealed_at_height,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn reveal_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-BID-REVEAL", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("reveal id", &self.reveal_id)?;
        ensure_non_empty("reveal bid id", &self.bid_id)?;
        ensure_non_empty("reveal auction id", &self.auction_id)?;
        ensure_non_empty("reveal bidder commitment", &self.bidder_commitment)?;
        ensure_hex_root("clear bid root", &self.clear_bid_root)?;
        ensure_positive("bid amount", self.bid_amount_micro_units)?;
        ensure_positive("clearing priority", self.clearing_priority)?;
        ensure_non_empty("reveal nullifier", &self.reveal_nullifier)?;
        ensure_hex_root("pq signature root", &self.pq_signature_root)?;
        if self
            .burn_amount_micro_units
            .saturating_add(self.sponsor_rebate_micro_units)
            .saturating_add(self.solver_fee_micro_units)
            > self.bid_amount_micro_units
        {
            return Err("reveal allocations exceed bid amount".to_string());
        }
        let expected = pq_mev_reveal_id(
            &self.bid_id,
            &self.auction_id,
            &self.clear_bid_root,
            self.revealed_at_height,
        );
        if self.reveal_id != expected {
            return Err("bid reveal id mismatch".to_string());
        }
        Ok(self.reveal_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionSettlement {
    pub settlement_id: String,
    pub auction_id: String,
    pub winning_bid_id: String,
    pub winning_reveal_id: String,
    pub clearing_root: String,
    pub ordered_bid_root: String,
    pub total_bid_micro_units: u64,
    pub burned_micro_units: u64,
    pub sponsor_distribution_micro_units: u64,
    pub protocol_distribution_micro_units: u64,
    pub solver_fee_micro_units: u64,
    pub included_private_orderflow_count: u64,
    pub low_fee_protected_count: u64,
    pub fairness_score: u64,
    pub settled_at_height: u64,
}

impl AuctionSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        winning_bid_id: &str,
        winning_reveal_id: &str,
        ordered_bids: &[Value],
        total_bid_micro_units: u64,
        burned_micro_units: u64,
        sponsor_distribution_micro_units: u64,
        protocol_distribution_micro_units: u64,
        solver_fee_micro_units: u64,
        included_private_orderflow_count: u64,
        low_fee_protected_count: u64,
        fairness_score: u64,
        settled_at_height: u64,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("settlement auction id", auction_id)?;
        ensure_non_empty("settlement winning bid id", winning_bid_id)?;
        ensure_non_empty("settlement winning reveal id", winning_reveal_id)?;
        ensure_positive("total bid amount", total_bid_micro_units)?;
        ensure_positive("burned amount", burned_micro_units)?;
        ensure_bps("fairness score", fairness_score)?;
        let ordered_bid_root = pq_mev_record_root("PQ-MEV-BURN-AUCTION-ORDERED-BIDS", ordered_bids);
        let clearing_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-CLEARING",
            &json!({
                "auction_id": auction_id,
                "winning_bid_id": winning_bid_id,
                "winning_reveal_id": winning_reveal_id,
                "ordered_bid_root": ordered_bid_root,
                "total_bid_micro_units": total_bid_micro_units,
                "burned_micro_units": burned_micro_units,
                "sponsor_distribution_micro_units": sponsor_distribution_micro_units,
                "protocol_distribution_micro_units": protocol_distribution_micro_units,
                "solver_fee_micro_units": solver_fee_micro_units,
                "fairness_score": fairness_score,
            }),
        );
        let settlement_id = pq_mev_settlement_id(
            auction_id,
            winning_bid_id,
            &clearing_root,
            settled_at_height,
        );
        Ok(Self {
            settlement_id,
            auction_id: auction_id.to_string(),
            winning_bid_id: winning_bid_id.to_string(),
            winning_reveal_id: winning_reveal_id.to_string(),
            clearing_root,
            ordered_bid_root,
            total_bid_micro_units,
            burned_micro_units,
            sponsor_distribution_micro_units,
            protocol_distribution_micro_units,
            solver_fee_micro_units,
            included_private_orderflow_count,
            low_fee_protected_count,
            fairness_score,
            settled_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_auction_settlement",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "settlement_id": self.settlement_id,
            "auction_id": self.auction_id,
            "winning_bid_id": self.winning_bid_id,
            "winning_reveal_id": self.winning_reveal_id,
            "clearing_root": self.clearing_root,
            "ordered_bid_root": self.ordered_bid_root,
            "total_bid_micro_units": self.total_bid_micro_units,
            "burned_micro_units": self.burned_micro_units,
            "sponsor_distribution_micro_units": self.sponsor_distribution_micro_units,
            "protocol_distribution_micro_units": self.protocol_distribution_micro_units,
            "solver_fee_micro_units": self.solver_fee_micro_units,
            "included_private_orderflow_count": self.included_private_orderflow_count,
            "low_fee_protected_count": self.low_fee_protected_count,
            "fairness_score": self.fairness_score,
            "settled_at_height": self.settled_at_height,
        })
    }

    pub fn settlement_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-SETTLEMENT", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("settlement id", &self.settlement_id)?;
        ensure_non_empty("settlement auction id", &self.auction_id)?;
        ensure_non_empty("settlement winning bid id", &self.winning_bid_id)?;
        ensure_non_empty("settlement winning reveal id", &self.winning_reveal_id)?;
        ensure_hex_root("clearing root", &self.clearing_root)?;
        ensure_hex_root("ordered bid root", &self.ordered_bid_root)?;
        ensure_positive("total bid amount", self.total_bid_micro_units)?;
        ensure_positive("burned amount", self.burned_micro_units)?;
        ensure_bps("fairness score", self.fairness_score)?;
        if self
            .burned_micro_units
            .saturating_add(self.sponsor_distribution_micro_units)
            .saturating_add(self.protocol_distribution_micro_units)
            .saturating_add(self.solver_fee_micro_units)
            > self.total_bid_micro_units
        {
            return Err("settlement allocations exceed total bid".to_string());
        }
        let expected = pq_mev_settlement_id(
            &self.auction_id,
            &self.winning_bid_id,
            &self.clearing_root,
            self.settled_at_height,
        );
        if self.settlement_id != expected {
            return Err("settlement id mismatch".to_string());
        }
        Ok(self.settlement_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub settlement_id: String,
    pub burn_asset_id: String,
    pub burn_amount_micro_units: u64,
    pub burn_address_commitment: String,
    pub monero_tx_commitment: String,
    pub view_key_proof_root: String,
    pub anchored_at_height: u64,
    pub matures_at_height: u64,
    pub status: BurnReceiptStatus,
}

impl BurnReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        settlement_id: &str,
        burn_asset_id: &str,
        burn_amount_micro_units: u64,
        burn_address_label: &str,
        monero_tx_label: &str,
        view_key_payload: &Value,
        anchored_at_height: u64,
        config: &PqMevBurnAuctionConfig,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("burn auction id", auction_id)?;
        ensure_non_empty("burn settlement id", settlement_id)?;
        ensure_non_empty("burn asset id", burn_asset_id)?;
        ensure_positive("burn amount", burn_amount_micro_units)?;
        ensure_non_empty("burn address label", burn_address_label)?;
        ensure_non_empty("monero tx label", monero_tx_label)?;
        let burn_address_commitment =
            pq_mev_string_root("PQ-MEV-BURN-AUCTION-BURN-ADDRESS", burn_address_label);
        let monero_tx_commitment =
            pq_mev_string_root("PQ-MEV-BURN-AUCTION-MONERO-TX", monero_tx_label);
        let view_key_proof_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-VIEW-KEY-PROOF",
            view_key_payload,
        );
        let matures_at_height = anchored_at_height.saturating_add(config.receipt_delay_blocks);
        let receipt_id = pq_mev_burn_receipt_id(
            auction_id,
            settlement_id,
            &monero_tx_commitment,
            anchored_at_height,
        );
        Ok(Self {
            receipt_id,
            auction_id: auction_id.to_string(),
            settlement_id: settlement_id.to_string(),
            burn_asset_id: burn_asset_id.to_string(),
            burn_amount_micro_units,
            burn_address_commitment,
            monero_tx_commitment,
            view_key_proof_root,
            anchored_at_height,
            matures_at_height,
            status: BurnReceiptStatus::Anchored,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_burn_receipt",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "settlement_id": self.settlement_id,
            "burn_asset_id": self.burn_asset_id,
            "burn_amount_micro_units": self.burn_amount_micro_units,
            "burn_address_commitment": self.burn_address_commitment,
            "monero_tx_commitment": self.monero_tx_commitment,
            "view_key_proof_root": self.view_key_proof_root,
            "anchored_at_height": self.anchored_at_height,
            "matures_at_height": self.matures_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-BURN-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("receipt auction id", &self.auction_id)?;
        ensure_non_empty("receipt settlement id", &self.settlement_id)?;
        ensure_non_empty("burn asset id", &self.burn_asset_id)?;
        ensure_positive("burn amount", self.burn_amount_micro_units)?;
        ensure_hex_root("burn address commitment", &self.burn_address_commitment)?;
        ensure_hex_root("monero tx commitment", &self.monero_tx_commitment)?;
        ensure_hex_root("view key proof root", &self.view_key_proof_root)?;
        ensure_window(
            "burn receipt maturity",
            self.anchored_at_height,
            self.matures_at_height,
        )?;
        let expected = pq_mev_burn_receipt_id(
            &self.auction_id,
            &self.settlement_id,
            &self.monero_tx_commitment,
            self.anchored_at_height,
        );
        if self.receipt_id != expected {
            return Err("burn receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorDistribution {
    pub distribution_id: String,
    pub sponsor_pool_id: String,
    pub auction_id: String,
    pub settlement_id: String,
    pub receipt_id: String,
    pub distributed_micro_units: u64,
    pub sponsor_count: u64,
    pub distribution_root: String,
    pub rebate_receipt_root: String,
    pub distributed_at_height: u64,
}

impl FeeSponsorDistribution {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_pool_id: &str,
        auction_id: &str,
        settlement_id: &str,
        receipt_id: &str,
        distributed_micro_units: u64,
        sponsor_count: u64,
        distribution_payload: &Value,
        rebate_payload: &Value,
        distributed_at_height: u64,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("sponsor pool id", sponsor_pool_id)?;
        ensure_non_empty("distribution auction id", auction_id)?;
        ensure_non_empty("distribution settlement id", settlement_id)?;
        ensure_non_empty("distribution receipt id", receipt_id)?;
        ensure_positive("distributed amount", distributed_micro_units)?;
        ensure_positive("sponsor count", sponsor_count)?;
        let distribution_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-SPONSOR-DISTRIBUTION-PAYLOAD",
            distribution_payload,
        );
        let rebate_receipt_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-SPONSOR-REBATE", rebate_payload);
        let distribution_id = pq_mev_sponsor_distribution_id(
            sponsor_pool_id,
            auction_id,
            settlement_id,
            distributed_at_height,
        );
        Ok(Self {
            distribution_id,
            sponsor_pool_id: sponsor_pool_id.to_string(),
            auction_id: auction_id.to_string(),
            settlement_id: settlement_id.to_string(),
            receipt_id: receipt_id.to_string(),
            distributed_micro_units,
            sponsor_count,
            distribution_root,
            rebate_receipt_root,
            distributed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_fee_sponsor_distribution",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "distribution_id": self.distribution_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "auction_id": self.auction_id,
            "settlement_id": self.settlement_id,
            "receipt_id": self.receipt_id,
            "distributed_micro_units": self.distributed_micro_units,
            "sponsor_count": self.sponsor_count,
            "distribution_root": self.distribution_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "distributed_at_height": self.distributed_at_height,
        })
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("distribution id", &self.distribution_id)?;
        ensure_non_empty("distribution sponsor pool id", &self.sponsor_pool_id)?;
        ensure_non_empty("distribution auction id", &self.auction_id)?;
        ensure_non_empty("distribution settlement id", &self.settlement_id)?;
        ensure_non_empty("distribution receipt id", &self.receipt_id)?;
        ensure_positive("distributed amount", self.distributed_micro_units)?;
        ensure_positive("sponsor count", self.sponsor_count)?;
        ensure_hex_root("distribution root", &self.distribution_root)?;
        ensure_hex_root("rebate receipt root", &self.rebate_receipt_root)?;
        let expected = pq_mev_sponsor_distribution_id(
            &self.sponsor_pool_id,
            &self.auction_id,
            &self.settlement_id,
            self.distributed_at_height,
        );
        if self.distribution_id != expected {
            return Err("sponsor distribution id mismatch".to_string());
        }
        Ok(self.distribution_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProtectedLane {
    pub protected_lane_id: String,
    pub lane_id: String,
    pub lane: PqMevAuctionLane,
    pub sponsor_pool_id: String,
    pub fee_cap_micro_units: u64,
    pub reserved_capacity_units: u64,
    pub used_capacity_units: u64,
    pub protected_orderflow_root: String,
    pub reservation_nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: LowFeeLaneStatus,
}

impl LowFeeProtectedLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_id: &str,
        lane: PqMevAuctionLane,
        sponsor_pool_id: &str,
        fee_cap_micro_units: u64,
        reserved_capacity_units: u64,
        orderflow_payload: &Value,
        opened_at_height: u64,
        config: &PqMevBurnAuctionConfig,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("protected lane id", lane_id)?;
        ensure_non_empty("protected sponsor pool id", sponsor_pool_id)?;
        ensure_positive("protected fee cap", fee_cap_micro_units)?;
        ensure_positive("reserved capacity", reserved_capacity_units)?;
        let protected_orderflow_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-PROTECTED-ORDERFLOW",
            orderflow_payload,
        );
        let reservation_nullifier_root = pq_mev_string_root(
            "PQ-MEV-BURN-AUCTION-PROTECTED-RESERVATION-NULLIFIER",
            &format!("{lane_id}:{sponsor_pool_id}:{opened_at_height}"),
        );
        let expires_at_height = opened_at_height.saturating_add(config.low_fee_lane_ttl_blocks);
        let protected_lane_id =
            pq_mev_protected_lane_id(lane_id, sponsor_pool_id, opened_at_height);
        Ok(Self {
            protected_lane_id,
            lane_id: lane_id.to_string(),
            lane,
            sponsor_pool_id: sponsor_pool_id.to_string(),
            fee_cap_micro_units,
            reserved_capacity_units,
            used_capacity_units: 0,
            protected_orderflow_root,
            reservation_nullifier_root,
            opened_at_height,
            expires_at_height,
            status: LowFeeLaneStatus::Sponsored,
        })
    }

    pub fn available_capacity_units(&self) -> u64 {
        self.reserved_capacity_units
            .saturating_sub(self.used_capacity_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.usable() && height >= self.opened_at_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_low_fee_protected_lane",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "protected_lane_id": self.protected_lane_id,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "sponsor_pool_id": self.sponsor_pool_id,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "reserved_capacity_units": self.reserved_capacity_units,
            "used_capacity_units": self.used_capacity_units,
            "available_capacity_units": self.available_capacity_units(),
            "protected_orderflow_root": self.protected_orderflow_root,
            "reservation_nullifier_root": self.reservation_nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("protected lane id", &self.protected_lane_id)?;
        ensure_non_empty("protected lane config id", &self.lane_id)?;
        ensure_non_empty("protected lane sponsor pool id", &self.sponsor_pool_id)?;
        ensure_positive("protected fee cap", self.fee_cap_micro_units)?;
        ensure_positive("reserved capacity", self.reserved_capacity_units)?;
        if self.used_capacity_units > self.reserved_capacity_units {
            return Err("protected lane usage exceeds reserved capacity".to_string());
        }
        ensure_hex_root("protected orderflow root", &self.protected_orderflow_root)?;
        ensure_hex_root(
            "reservation nullifier root",
            &self.reservation_nullifier_root,
        )?;
        ensure_window(
            "protected lane ttl",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        let expected =
            pq_mev_protected_lane_id(&self.lane_id, &self.sponsor_pool_id, self.opened_at_height);
        if self.protected_lane_id != expected {
            return Err("protected lane id mismatch".to_string());
        }
        Ok(self.protected_lane_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOrderflowAntiSandwichProof {
    pub proof_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub lane_id: String,
    pub private_orderflow_root: String,
    pub pre_state_commitment: String,
    pub post_state_commitment: String,
    pub price_bound_root: String,
    pub no_same_solver_backrun_root: String,
    pub proof_root: String,
    pub max_price_impact_bps: u64,
    pub fairness_score: u64,
    pub submitted_at_height: u64,
    pub status: AntiSandwichProofStatus,
}

impl PrivateOrderflowAntiSandwichProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        bid_id: &str,
        lane_id: &str,
        private_orderflow_payload: &Value,
        pre_state_label: &str,
        post_state_label: &str,
        price_bound_payload: &Value,
        no_backrun_payload: &Value,
        max_price_impact_bps: u64,
        fairness_score: u64,
        submitted_at_height: u64,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("anti sandwich auction id", auction_id)?;
        ensure_non_empty("anti sandwich bid id", bid_id)?;
        ensure_non_empty("anti sandwich lane id", lane_id)?;
        ensure_non_empty("pre state label", pre_state_label)?;
        ensure_non_empty("post state label", post_state_label)?;
        ensure_bps("max price impact bps", max_price_impact_bps)?;
        ensure_bps("fairness score", fairness_score)?;
        let private_orderflow_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-ANTI-SANDWICH-ORDERFLOW",
            private_orderflow_payload,
        );
        let pre_state_commitment =
            pq_mev_string_root("PQ-MEV-BURN-AUCTION-PRE-STATE", pre_state_label);
        let post_state_commitment =
            pq_mev_string_root("PQ-MEV-BURN-AUCTION-POST-STATE", post_state_label);
        let price_bound_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-PRICE-BOUND",
            price_bound_payload,
        );
        let no_same_solver_backrun_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-NO-SAME-SOLVER-BACKRUN",
            no_backrun_payload,
        );
        let proof_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-ANTI-SANDWICH-PROOF",
            &json!({
                "auction_id": auction_id,
                "bid_id": bid_id,
                "lane_id": lane_id,
                "private_orderflow_root": private_orderflow_root,
                "pre_state_commitment": pre_state_commitment,
                "post_state_commitment": post_state_commitment,
                "price_bound_root": price_bound_root,
                "no_same_solver_backrun_root": no_same_solver_backrun_root,
                "max_price_impact_bps": max_price_impact_bps,
                "fairness_score": fairness_score,
            }),
        );
        let proof_id = pq_mev_anti_sandwich_proof_id(auction_id, bid_id, &proof_root);
        Ok(Self {
            proof_id,
            auction_id: auction_id.to_string(),
            bid_id: bid_id.to_string(),
            lane_id: lane_id.to_string(),
            private_orderflow_root,
            pre_state_commitment,
            post_state_commitment,
            price_bound_root,
            no_same_solver_backrun_root,
            proof_root,
            max_price_impact_bps,
            fairness_score,
            submitted_at_height,
            status: AntiSandwichProofStatus::Verified,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_private_orderflow_anti_sandwich_proof",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "proof_id": self.proof_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "lane_id": self.lane_id,
            "private_orderflow_root": self.private_orderflow_root,
            "pre_state_commitment": self.pre_state_commitment,
            "post_state_commitment": self.post_state_commitment,
            "price_bound_root": self.price_bound_root,
            "no_same_solver_backrun_root": self.no_same_solver_backrun_root,
            "proof_root": self.proof_root,
            "max_price_impact_bps": self.max_price_impact_bps,
            "fairness_score": self.fairness_score,
            "submitted_at_height": self.submitted_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("anti sandwich proof id", &self.proof_id)?;
        ensure_non_empty("anti sandwich auction id", &self.auction_id)?;
        ensure_non_empty("anti sandwich bid id", &self.bid_id)?;
        ensure_non_empty("anti sandwich lane id", &self.lane_id)?;
        ensure_hex_root("private orderflow root", &self.private_orderflow_root)?;
        ensure_hex_root("pre state commitment", &self.pre_state_commitment)?;
        ensure_hex_root("post state commitment", &self.post_state_commitment)?;
        ensure_hex_root("price bound root", &self.price_bound_root)?;
        ensure_hex_root(
            "no same solver backrun root",
            &self.no_same_solver_backrun_root,
        )?;
        ensure_hex_root("proof root", &self.proof_root)?;
        ensure_bps("max price impact bps", self.max_price_impact_bps)?;
        ensure_bps("fairness score", self.fairness_score)?;
        let expected =
            pq_mev_anti_sandwich_proof_id(&self.auction_id, &self.bid_id, &self.proof_root);
        if self.proof_id != expected {
            return Err("anti sandwich proof id mismatch".to_string());
        }
        Ok(self.proof_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposerSlashingEvidence {
    pub evidence_id: String,
    pub auction_id: String,
    pub proposer_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub offending_commitment_id: String,
    pub evidence_root: String,
    pub witness_root: String,
    pub slash_bps: u64,
    pub slash_amount_micro_units: u64,
    pub submitted_at_height: u64,
    pub challenge_deadline_height: u64,
    pub resolved: bool,
}

impl ProposerSlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        proposer_id: &str,
        evidence_kind: SlashingEvidenceKind,
        offending_commitment_id: &str,
        evidence_payload: &Value,
        witness_payload: &Value,
        slash_base_micro_units: u64,
        submitted_at_height: u64,
        config: &PqMevBurnAuctionConfig,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("slashing auction id", auction_id)?;
        ensure_non_empty("slashing proposer id", proposer_id)?;
        ensure_non_empty("offending commitment id", offending_commitment_id)?;
        ensure_positive("slash base amount", slash_base_micro_units)?;
        let evidence_root = pq_mev_burn_auction_payload_root(
            "PQ-MEV-BURN-AUCTION-SLASH-EVIDENCE",
            evidence_payload,
        );
        let witness_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-SLASH-WITNESS", witness_payload);
        let severity_adjusted_bps = config
            .slash_bps
            .saturating_mul(evidence_kind.severity_weight())
            / 100;
        let slash_bps = severity_adjusted_bps.min(PQ_MEV_BURN_AUCTION_MAX_BPS);
        let slash_amount_micro_units = bps_portion(slash_base_micro_units, slash_bps);
        let challenge_deadline_height =
            submitted_at_height.saturating_add(config.challenge_window_blocks);
        let evidence_id = pq_mev_slashing_evidence_id(
            auction_id,
            proposer_id,
            evidence_kind,
            &evidence_root,
            submitted_at_height,
        );
        Ok(Self {
            evidence_id,
            auction_id: auction_id.to_string(),
            proposer_id: proposer_id.to_string(),
            evidence_kind,
            offending_commitment_id: offending_commitment_id.to_string(),
            evidence_root,
            witness_root,
            slash_bps,
            slash_amount_micro_units,
            submitted_at_height,
            challenge_deadline_height,
            resolved: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_proposer_slashing_evidence",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "auction_id": self.auction_id,
            "proposer_id": self.proposer_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "offending_commitment_id": self.offending_commitment_id,
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "slash_bps": self.slash_bps,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "submitted_at_height": self.submitted_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "resolved": self.resolved,
        })
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("slashing evidence id", &self.evidence_id)?;
        ensure_non_empty("slashing auction id", &self.auction_id)?;
        ensure_non_empty("slashing proposer id", &self.proposer_id)?;
        ensure_non_empty("offending commitment id", &self.offending_commitment_id)?;
        ensure_hex_root("slashing evidence root", &self.evidence_root)?;
        ensure_hex_root("slashing witness root", &self.witness_root)?;
        ensure_bps("slash bps", self.slash_bps)?;
        ensure_positive("slash amount", self.slash_amount_micro_units)?;
        ensure_window(
            "slashing challenge window",
            self.submitted_at_height,
            self.challenge_deadline_height,
        )?;
        let expected = pq_mev_slashing_evidence_id(
            &self.auction_id,
            &self.proposer_id,
            self.evidence_kind,
            &self.evidence_root,
            self.submitted_at_height,
        );
        if self.evidence_id != expected {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl DeterministicPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> PqMevBurnAuctionResult<Self> {
        ensure_non_empty("public record subject id", subject_id)?;
        let payload_root =
            pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = pq_mev_public_record_id(
            record_kind,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        Ok(Self {
            record_id,
            record_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_deterministic_public_record",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_non_empty("public record id", &self.record_id)?;
        ensure_non_empty("public record subject id", &self.subject_id)?;
        ensure_hex_root("public record payload root", &self.payload_root)?;
        let expected = pq_mev_public_record_id(
            self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMevBurnAuctionRoots {
    pub config_root: String,
    pub lane_config_root: String,
    pub auction_root: String,
    pub encrypted_bid_root: String,
    pub sequencer_commitment_root: String,
    pub reveal_root: String,
    pub settlement_root: String,
    pub burn_receipt_root: String,
    pub low_fee_lane_root: String,
    pub anti_sandwich_proof_root: String,
    pub slashing_evidence_root: String,
    pub sponsor_distribution_root: String,
    pub public_record_root: String,
}

impl PqMevBurnAuctionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_burn_auction_roots",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "lane_config_root": self.lane_config_root,
            "auction_root": self.auction_root,
            "encrypted_bid_root": self.encrypted_bid_root,
            "sequencer_commitment_root": self.sequencer_commitment_root,
            "reveal_root": self.reveal_root,
            "settlement_root": self.settlement_root,
            "burn_receipt_root": self.burn_receipt_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "anti_sandwich_proof_root": self.anti_sandwich_proof_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "sponsor_distribution_root": self.sponsor_distribution_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-ROOTS", &self.public_record())
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        ensure_hex_root("config root", &self.config_root)?;
        ensure_hex_root("lane config root", &self.lane_config_root)?;
        ensure_hex_root("auction root", &self.auction_root)?;
        ensure_hex_root("encrypted bid root", &self.encrypted_bid_root)?;
        ensure_hex_root("sequencer commitment root", &self.sequencer_commitment_root)?;
        ensure_hex_root("reveal root", &self.reveal_root)?;
        ensure_hex_root("settlement root", &self.settlement_root)?;
        ensure_hex_root("burn receipt root", &self.burn_receipt_root)?;
        ensure_hex_root("low fee lane root", &self.low_fee_lane_root)?;
        ensure_hex_root("anti sandwich proof root", &self.anti_sandwich_proof_root)?;
        ensure_hex_root("slashing evidence root", &self.slashing_evidence_root)?;
        ensure_hex_root("sponsor distribution root", &self.sponsor_distribution_root)?;
        ensure_hex_root("public record root", &self.public_record_root)?;
        Ok(self.roots_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMevBurnAuctionCounters {
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub low_fee_lane_count: u64,
    pub auction_count: u64,
    pub active_auction_count: u64,
    pub encrypted_bid_count: u64,
    pub active_bid_count: u64,
    pub commitment_count: u64,
    pub reveal_count: u64,
    pub settlement_count: u64,
    pub burn_receipt_count: u64,
    pub anti_sandwich_proof_count: u64,
    pub verified_anti_sandwich_proof_count: u64,
    pub slashing_evidence_count: u64,
    pub sponsor_distribution_count: u64,
    pub public_record_count: u64,
    pub total_bid_micro_units: u64,
    pub total_burned_micro_units: u64,
    pub total_sponsor_distribution_micro_units: u64,
    pub total_low_fee_capacity_units: u64,
    pub total_low_fee_used_units: u64,
    pub average_fairness_score: u64,
}

impl PqMevBurnAuctionCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_mev_burn_auction_counters",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "lane_count": self.lane_count,
            "active_lane_count": self.active_lane_count,
            "low_fee_lane_count": self.low_fee_lane_count,
            "auction_count": self.auction_count,
            "active_auction_count": self.active_auction_count,
            "encrypted_bid_count": self.encrypted_bid_count,
            "active_bid_count": self.active_bid_count,
            "commitment_count": self.commitment_count,
            "reveal_count": self.reveal_count,
            "settlement_count": self.settlement_count,
            "burn_receipt_count": self.burn_receipt_count,
            "anti_sandwich_proof_count": self.anti_sandwich_proof_count,
            "verified_anti_sandwich_proof_count": self.verified_anti_sandwich_proof_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "sponsor_distribution_count": self.sponsor_distribution_count,
            "public_record_count": self.public_record_count,
            "total_bid_micro_units": self.total_bid_micro_units,
            "total_burned_micro_units": self.total_burned_micro_units,
            "total_sponsor_distribution_micro_units": self.total_sponsor_distribution_micro_units,
            "total_low_fee_capacity_units": self.total_low_fee_capacity_units,
            "total_low_fee_used_units": self.total_low_fee_used_units,
            "average_fairness_score": self.average_fairness_score,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMevBurnAuctionState {
    pub config: PqMevBurnAuctionConfig,
    pub height: u64,
    pub epoch: u64,
    pub status: String,
    pub lane_configs: BTreeMap<String, AuctionLaneConfig>,
    pub auctions: BTreeMap<String, PqMevAuction>,
    pub encrypted_bids: BTreeMap<String, EncryptedBlockspaceBid>,
    pub sequencer_commitments: BTreeMap<String, PqSequencerCommitment>,
    pub bid_reveals: BTreeMap<String, BidReveal>,
    pub settlements: BTreeMap<String, AuctionSettlement>,
    pub burn_receipts: BTreeMap<String, BurnReceipt>,
    pub low_fee_lanes: BTreeMap<String, LowFeeProtectedLane>,
    pub anti_sandwich_proofs: BTreeMap<String, PrivateOrderflowAntiSandwichProof>,
    pub slashing_evidence: BTreeMap<String, ProposerSlashingEvidence>,
    pub sponsor_distributions: BTreeMap<String, FeeSponsorDistribution>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl PqMevBurnAuctionState {
    pub fn with_config(config: PqMevBurnAuctionConfig) -> PqMevBurnAuctionResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            epoch: 0,
            status: STATE_STATUS_ACTIVE.to_string(),
            lane_configs: BTreeMap::new(),
            auctions: BTreeMap::new(),
            encrypted_bids: BTreeMap::new(),
            sequencer_commitments: BTreeMap::new(),
            bid_reveals: BTreeMap::new(),
            settlements: BTreeMap::new(),
            burn_receipts: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            anti_sandwich_proofs: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            sponsor_distributions: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PqMevBurnAuctionResult<Self> {
        let mut state = Self::with_config(PqMevBurnAuctionConfig::devnet())?;
        state.set_height(42)?;
        state.insert_lane_config(AuctionLaneConfig::new(
            PqMevAuctionLane::PrivateDex,
            "Private DEX blockspace",
            PqMevAuctionLane::PrivateDex.default_fee_cap_micro_units(),
            state.config.max_price_impact_bps,
            80,
            "devnet-private-defi-sponsors",
            &json!({"uniform_clearing": true, "anti_sandwich_required": true}),
            state.height,
            state.height.saturating_add(state.config.epoch_blocks),
        )?)?;
        state.insert_lane_config(AuctionLaneConfig::new(
            PqMevAuctionLane::LowFeeSwap,
            "Low fee protected swaps",
            PqMevAuctionLane::LowFeeSwap.default_fee_cap_micro_units(),
            state.config.max_price_impact_bps,
            95,
            "devnet-low-fee-sponsors",
            &json!({"fee_cap": "strict", "sponsor_distribution": true}),
            state.height,
            state
                .height
                .saturating_add(state.config.low_fee_lane_ttl_blocks),
        )?)?;
        state.insert_lane_config(AuctionLaneConfig::new(
            PqMevAuctionLane::MoneroBridge,
            "Monero bridge exits",
            PqMevAuctionLane::MoneroBridge.default_fee_cap_micro_units(),
            state.config.max_price_impact_bps,
            90,
            "devnet-bridge-sponsors",
            &json!({"bridge_exit_protected": true, "burn_receipts_required": true}),
            state.height,
            state
                .height
                .saturating_add(state.config.low_fee_lane_ttl_blocks),
        )?)?;

        let private_lane_id = state
            .lane_configs
            .values()
            .find(|lane| lane.lane == PqMevAuctionLane::PrivateDex)
            .map(|lane| lane.lane_id.clone())
            .ok_or_else(|| "missing devnet private dex lane".to_string())?;
        let low_fee_lane_id = state
            .lane_configs
            .values()
            .find(|lane| lane.lane == PqMevAuctionLane::LowFeeSwap)
            .map(|lane| lane.lane_id.clone())
            .ok_or_else(|| "missing devnet low fee lane".to_string())?;

        let auction = PqMevAuction::new(
            state.epoch,
            &private_lane_id,
            PqMevAuctionLane::PrivateDex,
            "devnet-proposer-alpha",
            1,
            state.height,
            &state.config,
            1_000,
            state.config.default_low_fee_cap_micro_units,
            state.config.max_price_impact_bps,
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_auction(auction)?;

        let low_fee_lane = LowFeeProtectedLane::new(
            &low_fee_lane_id,
            PqMevAuctionLane::LowFeeSwap,
            "devnet-low-fee-sponsors",
            state.config.default_low_fee_cap_micro_units,
            50_000,
            &json!({"lane": "low_fee_swap", "reserved_for": "small-private-defi"}),
            state.height,
            &state.config,
        )?;
        state.insert_low_fee_lane(low_fee_lane)?;

        let bid_one = EncryptedBlockspaceBid::new(
            &auction_id,
            "devnet-bidder-alpha",
            "nullifier-alpha",
            &json!({"sealed": "alpha", "lane": "private_dex"}),
            32_768,
            12_500,
            true,
            true,
            state.height,
            &state.config,
        )?;
        let bid_one_id = bid_one.bid_id.clone();
        state.insert_encrypted_bid(bid_one)?;
        let bid_two = EncryptedBlockspaceBid::new(
            &auction_id,
            "devnet-bidder-beta",
            "nullifier-beta",
            &json!({"sealed": "beta", "lane": "private_dex"}),
            28_672,
            9_500,
            true,
            true,
            state.height.saturating_add(1),
            &state.config,
        )?;
        state.insert_encrypted_bid(bid_two)?;

        let encrypted_bid_root = state.roots().encrypted_bid_root;
        let commitment = PqSequencerCommitment::new(
            &auction_id,
            "devnet-proposer-alpha",
            "devnet-sequencer-key-alpha",
            &encrypted_bid_root,
            &json!({"sort": "fairness_then_bid", "slot": 1}),
            &json!({"private_orderflow": ["alpha", "beta"]}),
            &json!({"low_fee_lane_id": low_fee_lane_id}),
            state.height.saturating_add(1),
            &state.config,
        )?;
        let commitment_id = commitment.commitment_id.clone();
        state.insert_sequencer_commitment(commitment)?;

        let reveal = BidReveal::new(
            &bid_one_id,
            &auction_id,
            "devnet-bidder-alpha",
            &json!({"amount": 12_500, "route": "sealed-uniform-clearing"}),
            12_500,
            1,
            "reveal-nullifier-alpha",
            state
                .height
                .saturating_add(state.config.commit_window_blocks),
            &state.config,
        )?;
        let reveal_id = reveal.reveal_id.clone();
        state.insert_bid_reveal(reveal)?;

        let anti_sandwich = PrivateOrderflowAntiSandwichProof::new(
            &auction_id,
            &bid_one_id,
            &private_lane_id,
            &json!({"orders": ["alpha"], "batch": "devnet"}),
            "pre-state-alpha",
            "post-state-alpha",
            &json!({"max_price_impact_bps": state.config.max_price_impact_bps}),
            &json!({"same_solver_backrun": false}),
            state.config.max_price_impact_bps,
            9_250,
            state.height.saturating_add(7),
        )?;
        state.insert_anti_sandwich_proof(anti_sandwich)?;

        let settlement = AuctionSettlement::new(
            &auction_id,
            &bid_one_id,
            &reveal_id,
            &[json!({"bid_id": bid_one_id, "priority": 1})],
            12_500,
            7_500,
            3_125,
            1_875,
            0,
            1,
            1,
            9_250,
            state.height.saturating_add(12),
        )?;
        let settlement_id = settlement.settlement_id.clone();
        state.insert_settlement(settlement)?;

        let receipt = BurnReceipt::new(
            &auction_id,
            &settlement_id,
            &state.config.burn_asset_id,
            7_500,
            "devnet-burn-address-alpha",
            "devnet-monero-burn-tx-alpha",
            &json!({"view_key": "committed", "confirmations": 10}),
            state.height.saturating_add(14),
            &state.config,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        state.insert_burn_receipt(receipt)?;

        state.insert_sponsor_distribution(FeeSponsorDistribution::new(
            "devnet-low-fee-sponsors",
            &auction_id,
            &settlement_id,
            &receipt_id,
            3_125,
            3,
            &json!({"sponsors": ["foundation", "bridge-guild", "wallet-guild"]}),
            &json!({"rebate_receipts": 3}),
            state.height.saturating_add(15),
        )?)?;

        state.insert_slashing_evidence(ProposerSlashingEvidence::new(
            &auction_id,
            "devnet-proposer-alpha",
            SlashingEvidenceKind::RevealWithholding,
            &commitment_id,
            &json!({"devnet_demo": true, "withheld_reveal_count": 0}),
            &json!({"watchtower": "devnet-watchtower-alpha"}),
            50_000,
            state.height.saturating_add(16),
            &state.config,
        )?)?;

        state.refresh_auction_roots()?;
        state.rebuild_public_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqMevBurnAuctionResult<()> {
        self.height = height;
        self.epoch = if self.config.epoch_blocks == 0 {
            0
        } else {
            height / self.config.epoch_blocks
        };
        for auction in self.auctions.values_mut() {
            if height < auction.commit_start_height {
                auction.status = PqMevAuctionStatus::Scheduled;
            } else if height < auction.commit_end_height {
                auction.status = PqMevAuctionStatus::CommitOpen;
            } else if height < auction.reveal_end_height {
                auction.status = PqMevAuctionStatus::RevealOpen;
            } else if height < auction.settlement_height {
                auction.status = PqMevAuctionStatus::Settling;
            } else if height <= auction.challenge_end_height && !auction.status.final_status() {
                auction.status = PqMevAuctionStatus::Settled;
            } else if height > auction.challenge_end_height && !auction.status.final_status() {
                auction.status = PqMevAuctionStatus::Expired;
            }
        }
        for bid in self.encrypted_bids.values_mut() {
            if height >= bid.expires_at_height && bid.status.active() {
                bid.status = PqMevBidStatus::Expired;
            }
        }
        for lane in self.low_fee_lanes.values_mut() {
            if height >= lane.expires_at_height && lane.status.usable() {
                lane.status = LowFeeLaneStatus::Expired;
            }
        }
        self.refresh_auction_roots()?;
        Ok(())
    }

    pub fn roots(&self) -> PqMevBurnAuctionRoots {
        PqMevBurnAuctionRoots {
            config_root: self.config.config_root(),
            lane_config_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-LANE-CONFIG-ROOT",
                self.lane_configs
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            auction_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-AUCTION-ROOT",
                self.auctions
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            encrypted_bid_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-ENCRYPTED-BID-ROOT",
                self.encrypted_bids
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            sequencer_commitment_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-SEQUENCER-COMMITMENT-ROOT",
                self.sequencer_commitments
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            reveal_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-REVEAL-ROOT",
                self.bid_reveals
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            settlement_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-SETTLEMENT-ROOT",
                self.settlements
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            burn_receipt_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-BURN-RECEIPT-ROOT",
                self.burn_receipts
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            low_fee_lane_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-LOW-FEE-LANE-ROOT",
                self.low_fee_lanes
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            anti_sandwich_proof_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-ANTI-SANDWICH-PROOF-ROOT",
                self.anti_sandwich_proofs
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            slashing_evidence_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-SLASHING-EVIDENCE-ROOT",
                self.slashing_evidence
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            sponsor_distribution_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-SPONSOR-DISTRIBUTION-ROOT",
                self.sponsor_distributions
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
            public_record_root: keyed_record_root(
                "PQ-MEV-BURN-AUCTION-PUBLIC-RECORD-ROOT",
                self.public_records
                    .iter()
                    .map(|(id, record)| (id, record.public_record())),
            ),
        }
    }

    pub fn counters(&self) -> PqMevBurnAuctionCounters {
        let active_lane_count = self
            .lane_configs
            .values()
            .filter(|lane| lane.active_at(self.height))
            .count() as u64;
        let low_fee_lane_count = self.low_fee_lanes.len() as u64;
        let active_auction_count = self
            .auctions
            .values()
            .filter(|auction| {
                auction.contains_height(self.height) && !auction.status.final_status()
            })
            .count() as u64;
        let active_bid_count = self
            .encrypted_bids
            .values()
            .filter(|bid| bid.active_at(self.height))
            .count() as u64;
        let total_bid_micro_units = self
            .bid_reveals
            .values()
            .map(|reveal| reveal.bid_amount_micro_units)
            .sum::<u64>();
        let total_burned_micro_units = self
            .burn_receipts
            .values()
            .map(|receipt| receipt.burn_amount_micro_units)
            .sum::<u64>();
        let total_sponsor_distribution_micro_units = self
            .sponsor_distributions
            .values()
            .map(|distribution| distribution.distributed_micro_units)
            .sum::<u64>();
        let total_low_fee_capacity_units = self
            .low_fee_lanes
            .values()
            .map(|lane| lane.reserved_capacity_units)
            .sum::<u64>();
        let total_low_fee_used_units = self
            .low_fee_lanes
            .values()
            .map(|lane| lane.used_capacity_units)
            .sum::<u64>();
        let fairness_sum = self
            .settlements
            .values()
            .map(|settlement| settlement.fairness_score)
            .sum::<u64>();
        let average_fairness_score = if self.settlements.is_empty() {
            0
        } else {
            fairness_sum / self.settlements.len() as u64
        };
        PqMevBurnAuctionCounters {
            lane_count: self.lane_configs.len() as u64,
            active_lane_count,
            low_fee_lane_count,
            auction_count: self.auctions.len() as u64,
            active_auction_count,
            encrypted_bid_count: self.encrypted_bids.len() as u64,
            active_bid_count,
            commitment_count: self.sequencer_commitments.len() as u64,
            reveal_count: self.bid_reveals.len() as u64,
            settlement_count: self.settlements.len() as u64,
            burn_receipt_count: self.burn_receipts.len() as u64,
            anti_sandwich_proof_count: self.anti_sandwich_proofs.len() as u64,
            verified_anti_sandwich_proof_count: self
                .anti_sandwich_proofs
                .values()
                .filter(|proof| proof.status.accepted())
                .count() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            sponsor_distribution_count: self.sponsor_distributions.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_bid_micro_units,
            total_burned_micro_units,
            total_sponsor_distribution_micro_units,
            total_low_fee_capacity_units,
            total_low_fee_used_units,
            average_fairness_score,
        }
    }

    pub fn state_root(&self) -> String {
        pq_mev_burn_auction_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PqMevBurnAuctionResult<String> {
        self.config.validate()?;
        require_state_status(&self.status)?;
        bounded_len(
            "lane configs",
            self.lane_configs.len(),
            PQ_MEV_BURN_AUCTION_MAX_CONFIG_LANES,
        )?;
        bounded_len(
            "auctions",
            self.auctions.len(),
            PQ_MEV_BURN_AUCTION_MAX_AUCTIONS,
        )?;
        bounded_len(
            "encrypted bids",
            self.encrypted_bids.len(),
            PQ_MEV_BURN_AUCTION_MAX_BIDS,
        )?;
        bounded_len(
            "bid reveals",
            self.bid_reveals.len(),
            PQ_MEV_BURN_AUCTION_MAX_REVEALS,
        )?;
        bounded_len(
            "sequencer commitments",
            self.sequencer_commitments.len(),
            PQ_MEV_BURN_AUCTION_MAX_COMMITMENTS,
        )?;
        bounded_len(
            "burn receipts",
            self.burn_receipts.len(),
            PQ_MEV_BURN_AUCTION_MAX_RECEIPTS,
        )?;
        bounded_len(
            "low fee lanes",
            self.low_fee_lanes.len(),
            PQ_MEV_BURN_AUCTION_MAX_CONFIG_LANES,
        )?;
        bounded_len(
            "anti sandwich proofs",
            self.anti_sandwich_proofs.len(),
            PQ_MEV_BURN_AUCTION_MAX_PROOFS,
        )?;
        bounded_len(
            "slashing evidence",
            self.slashing_evidence.len(),
            PQ_MEV_BURN_AUCTION_MAX_SLASHING_EVIDENCE,
        )?;
        bounded_len(
            "sponsor distributions",
            self.sponsor_distributions.len(),
            PQ_MEV_BURN_AUCTION_MAX_SPONSORS,
        )?;
        bounded_len(
            "public records",
            self.public_records.len(),
            PQ_MEV_BURN_AUCTION_MAX_PUBLIC_RECORDS,
        )?;

        let mut lane_ids = BTreeSet::<String>::new();
        for (id, lane) in &self.lane_configs {
            let validated = lane.validate()?;
            if id != &validated {
                return Err("lane config map key mismatch".to_string());
            }
            if !lane_ids.insert(validated) {
                return Err("duplicate lane id".to_string());
            }
        }

        let mut auction_ids = BTreeSet::<String>::new();
        for (id, auction) in &self.auctions {
            let validated = auction.validate()?;
            if id != &validated {
                return Err("auction map key mismatch".to_string());
            }
            if !self.lane_configs.contains_key(&auction.lane_id) {
                return Err("auction references missing lane".to_string());
            }
            if !auction_ids.insert(validated) {
                return Err("duplicate auction id".to_string());
            }
        }

        let mut bid_nullifiers = BTreeSet::<String>::new();
        for (id, bid) in &self.encrypted_bids {
            let validated = bid.validate()?;
            if id != &validated {
                return Err("encrypted bid map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&bid.auction_id) {
                return Err("encrypted bid references missing auction".to_string());
            }
            if bid.bid_size_bytes > self.config.max_bid_bytes {
                return Err("encrypted bid exceeds configured size limit".to_string());
            }
            if !bid_nullifiers.insert(bid.payer_nullifier.clone()) {
                return Err("duplicate encrypted bid payer nullifier".to_string());
            }
        }

        for (id, commitment) in &self.sequencer_commitments {
            let validated = commitment.validate()?;
            if id != &validated {
                return Err("sequencer commitment map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&commitment.auction_id) {
                return Err("sequencer commitment references missing auction".to_string());
            }
        }

        let mut reveal_nullifiers = BTreeSet::<String>::new();
        for (id, reveal) in &self.bid_reveals {
            let validated = reveal.validate()?;
            if id != &validated {
                return Err("bid reveal map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&reveal.auction_id) {
                return Err("bid reveal references missing auction".to_string());
            }
            if !self.encrypted_bids.contains_key(&reveal.bid_id) {
                return Err("bid reveal references missing encrypted bid".to_string());
            }
            if !reveal_nullifiers.insert(reveal.reveal_nullifier.clone()) {
                return Err("duplicate bid reveal nullifier".to_string());
            }
        }

        for (id, settlement) in &self.settlements {
            let validated = settlement.validate()?;
            if id != &validated {
                return Err("settlement map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&settlement.auction_id) {
                return Err("settlement references missing auction".to_string());
            }
            if !self.encrypted_bids.contains_key(&settlement.winning_bid_id) {
                return Err("settlement references missing winning bid".to_string());
            }
            if !self.bid_reveals.contains_key(&settlement.winning_reveal_id) {
                return Err("settlement references missing winning reveal".to_string());
            }
            if settlement.fairness_score < self.config.min_fairness_score {
                return Err("settlement fairness score below configured floor".to_string());
            }
        }

        for (id, receipt) in &self.burn_receipts {
            let validated = receipt.validate()?;
            if id != &validated {
                return Err("burn receipt map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&receipt.auction_id) {
                return Err("burn receipt references missing auction".to_string());
            }
            if !self.settlements.contains_key(&receipt.settlement_id) {
                return Err("burn receipt references missing settlement".to_string());
            }
            if receipt.burn_asset_id != self.config.burn_asset_id {
                return Err("burn receipt asset id mismatch".to_string());
            }
        }

        for (id, lane) in &self.low_fee_lanes {
            let validated = lane.validate()?;
            if id != &validated {
                return Err("low fee lane map key mismatch".to_string());
            }
            if !self.lane_configs.contains_key(&lane.lane_id) {
                return Err("low fee lane references missing lane config".to_string());
            }
        }

        for (id, proof) in &self.anti_sandwich_proofs {
            let validated = proof.validate()?;
            if id != &validated {
                return Err("anti sandwich proof map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&proof.auction_id) {
                return Err("anti sandwich proof references missing auction".to_string());
            }
            if !self.encrypted_bids.contains_key(&proof.bid_id) {
                return Err("anti sandwich proof references missing bid".to_string());
            }
            if !self.lane_configs.contains_key(&proof.lane_id) {
                return Err("anti sandwich proof references missing lane".to_string());
            }
        }

        for (id, evidence) in &self.slashing_evidence {
            let validated = evidence.validate()?;
            if id != &validated {
                return Err("slashing evidence map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&evidence.auction_id) {
                return Err("slashing evidence references missing auction".to_string());
            }
            if !self
                .sequencer_commitments
                .contains_key(&evidence.offending_commitment_id)
            {
                return Err("slashing evidence references missing commitment".to_string());
            }
        }

        for (id, distribution) in &self.sponsor_distributions {
            let validated = distribution.validate()?;
            if id != &validated {
                return Err("sponsor distribution map key mismatch".to_string());
            }
            if !self.auctions.contains_key(&distribution.auction_id) {
                return Err("sponsor distribution references missing auction".to_string());
            }
            if !self.settlements.contains_key(&distribution.settlement_id) {
                return Err("sponsor distribution references missing settlement".to_string());
            }
            if !self.burn_receipts.contains_key(&distribution.receipt_id) {
                return Err("sponsor distribution references missing receipt".to_string());
            }
        }

        let mut public_record_sequences = BTreeSet::<u64>::new();
        for (id, record) in &self.public_records {
            let validated = record.validate()?;
            if id != &validated {
                return Err("public record map key mismatch".to_string());
            }
            if !public_record_sequences.insert(record.sequence) {
                return Err("duplicate public record sequence".to_string());
            }
        }

        let roots = self.roots();
        roots.validate()?;
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_mev_burn_auction_state",
            "protocol_version": PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION,
            "schema_version": PQ_MEV_BURN_AUCTION_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "status": self.status,
            "security_model": PQ_MEV_BURN_AUCTION_SECURITY_MODEL,
            "hash_suite": PQ_MEV_BURN_AUCTION_HASH_SUITE,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "active_auction_ids": self.active_auction_ids(),
            "active_low_fee_lane_ids": self.active_low_fee_lane_ids(),
        })
    }

    fn insert_lane_config(&mut self, lane: AuctionLaneConfig) -> PqMevBurnAuctionResult<()> {
        lane.validate()?;
        if self.lane_configs.contains_key(&lane.lane_id) {
            return Err("duplicate lane config".to_string());
        }
        self.lane_configs.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    fn insert_auction(&mut self, auction: PqMevAuction) -> PqMevBurnAuctionResult<()> {
        auction.validate()?;
        if !self.lane_configs.contains_key(&auction.lane_id) {
            return Err("auction references missing lane".to_string());
        }
        if self.auctions.contains_key(&auction.auction_id) {
            return Err("duplicate auction".to_string());
        }
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    fn insert_encrypted_bid(&mut self, bid: EncryptedBlockspaceBid) -> PqMevBurnAuctionResult<()> {
        bid.validate()?;
        if !self.auctions.contains_key(&bid.auction_id) {
            return Err("encrypted bid references missing auction".to_string());
        }
        if self.encrypted_bids.contains_key(&bid.bid_id) {
            return Err("duplicate encrypted bid".to_string());
        }
        self.encrypted_bids.insert(bid.bid_id.clone(), bid);
        self.refresh_auction_roots()?;
        Ok(())
    }

    fn insert_sequencer_commitment(
        &mut self,
        commitment: PqSequencerCommitment,
    ) -> PqMevBurnAuctionResult<()> {
        commitment.validate()?;
        if !self.auctions.contains_key(&commitment.auction_id) {
            return Err("sequencer commitment references missing auction".to_string());
        }
        if self
            .sequencer_commitments
            .contains_key(&commitment.commitment_id)
        {
            return Err("duplicate sequencer commitment".to_string());
        }
        self.sequencer_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    fn insert_bid_reveal(&mut self, reveal: BidReveal) -> PqMevBurnAuctionResult<()> {
        reveal.validate()?;
        if !self.encrypted_bids.contains_key(&reveal.bid_id) {
            return Err("reveal references missing bid".to_string());
        }
        if self.bid_reveals.contains_key(&reveal.reveal_id) {
            return Err("duplicate bid reveal".to_string());
        }
        self.bid_reveals.insert(reveal.reveal_id.clone(), reveal);
        self.refresh_auction_roots()?;
        Ok(())
    }

    fn insert_settlement(&mut self, settlement: AuctionSettlement) -> PqMevBurnAuctionResult<()> {
        settlement.validate()?;
        if self.settlements.contains_key(&settlement.settlement_id) {
            return Err("duplicate settlement".to_string());
        }
        self.settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.refresh_auction_roots()?;
        Ok(())
    }

    fn insert_burn_receipt(&mut self, receipt: BurnReceipt) -> PqMevBurnAuctionResult<()> {
        receipt.validate()?;
        if self.burn_receipts.contains_key(&receipt.receipt_id) {
            return Err("duplicate burn receipt".to_string());
        }
        self.burn_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        self.refresh_auction_roots()?;
        Ok(())
    }

    fn insert_low_fee_lane(&mut self, lane: LowFeeProtectedLane) -> PqMevBurnAuctionResult<()> {
        lane.validate()?;
        if self.low_fee_lanes.contains_key(&lane.protected_lane_id) {
            return Err("duplicate low fee lane".to_string());
        }
        self.low_fee_lanes
            .insert(lane.protected_lane_id.clone(), lane);
        Ok(())
    }

    fn insert_anti_sandwich_proof(
        &mut self,
        proof: PrivateOrderflowAntiSandwichProof,
    ) -> PqMevBurnAuctionResult<()> {
        proof.validate()?;
        if self.anti_sandwich_proofs.contains_key(&proof.proof_id) {
            return Err("duplicate anti sandwich proof".to_string());
        }
        self.anti_sandwich_proofs
            .insert(proof.proof_id.clone(), proof);
        self.refresh_auction_roots()?;
        Ok(())
    }

    fn insert_slashing_evidence(
        &mut self,
        evidence: ProposerSlashingEvidence,
    ) -> PqMevBurnAuctionResult<()> {
        evidence.validate()?;
        if self.slashing_evidence.contains_key(&evidence.evidence_id) {
            return Err("duplicate slashing evidence".to_string());
        }
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }

    fn insert_sponsor_distribution(
        &mut self,
        distribution: FeeSponsorDistribution,
    ) -> PqMevBurnAuctionResult<()> {
        distribution.validate()?;
        if self
            .sponsor_distributions
            .contains_key(&distribution.distribution_id)
        {
            return Err("duplicate sponsor distribution".to_string());
        }
        self.sponsor_distributions
            .insert(distribution.distribution_id.clone(), distribution);
        Ok(())
    }

    fn refresh_auction_roots(&mut self) -> PqMevBurnAuctionResult<()> {
        let mut bid_records_by_auction = BTreeMap::<String, Vec<Value>>::new();
        for bid in self.encrypted_bids.values() {
            bid_records_by_auction
                .entry(bid.auction_id.clone())
                .or_default()
                .push(bid.public_record());
        }
        let mut reveal_records_by_auction = BTreeMap::<String, Vec<Value>>::new();
        for reveal in self.bid_reveals.values() {
            reveal_records_by_auction
                .entry(reveal.auction_id.clone())
                .or_default()
                .push(reveal.public_record());
        }
        let mut settlement_records_by_auction = BTreeMap::<String, Vec<Value>>::new();
        for settlement in self.settlements.values() {
            settlement_records_by_auction
                .entry(settlement.auction_id.clone())
                .or_default()
                .push(settlement.public_record());
        }
        let mut receipt_records_by_auction = BTreeMap::<String, Vec<Value>>::new();
        for receipt in self.burn_receipts.values() {
            receipt_records_by_auction
                .entry(receipt.auction_id.clone())
                .or_default()
                .push(receipt.public_record());
        }
        let mut proof_records_by_auction = BTreeMap::<String, Vec<Value>>::new();
        for proof in self.anti_sandwich_proofs.values() {
            proof_records_by_auction
                .entry(proof.auction_id.clone())
                .or_default()
                .push(proof.public_record());
        }
        for auction in self.auctions.values_mut() {
            auction.encrypted_bid_root = pq_mev_record_root(
                "PQ-MEV-BURN-AUCTION-AUCTION-BIDS",
                records_for(&bid_records_by_auction, &auction.auction_id).as_slice(),
            );
            auction.reveal_root = pq_mev_record_root(
                "PQ-MEV-BURN-AUCTION-AUCTION-REVEALS",
                records_for(&reveal_records_by_auction, &auction.auction_id).as_slice(),
            );
            auction.settlement_root = pq_mev_record_root(
                "PQ-MEV-BURN-AUCTION-AUCTION-SETTLEMENTS",
                records_for(&settlement_records_by_auction, &auction.auction_id).as_slice(),
            );
            auction.burn_receipt_root = pq_mev_record_root(
                "PQ-MEV-BURN-AUCTION-AUCTION-BURN-RECEIPTS",
                records_for(&receipt_records_by_auction, &auction.auction_id).as_slice(),
            );
            auction.anti_sandwich_root = pq_mev_record_root(
                "PQ-MEV-BURN-AUCTION-AUCTION-ANTI-SANDWICH",
                records_for(&proof_records_by_auction, &auction.auction_id).as_slice(),
            );
        }
        Ok(())
    }

    fn rebuild_public_records(&mut self) -> PqMevBurnAuctionResult<()> {
        self.public_records.clear();
        let mut sequence = 0_u64;
        let mut records = Vec::<DeterministicPublicRecord>::new();
        for auction in self.auctions.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::AuctionScheduled,
                &auction.auction_id,
                &auction.public_record(),
                auction.commit_start_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for bid in self.encrypted_bids.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::EncryptedBid,
                &bid.bid_id,
                &bid.public_record(),
                bid.submitted_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for commitment in self.sequencer_commitments.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::SequencerCommitment,
                &commitment.commitment_id,
                &commitment.public_record(),
                commitment.committed_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for reveal in self.bid_reveals.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::BidReveal,
                &reveal.reveal_id,
                &reveal.public_record(),
                reveal.revealed_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for settlement in self.settlements.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::AuctionSettlement,
                &settlement.settlement_id,
                &settlement.public_record(),
                settlement.settled_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for receipt in self.burn_receipts.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::BurnReceipt,
                &receipt.receipt_id,
                &receipt.public_record(),
                receipt.anchored_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for distribution in self.sponsor_distributions.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::SponsorDistribution,
                &distribution.distribution_id,
                &distribution.public_record(),
                distribution.distributed_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for lane in self.low_fee_lanes.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::LowFeeLane,
                &lane.protected_lane_id,
                &lane.public_record(),
                lane.opened_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for proof in self.anti_sandwich_proofs.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::AntiSandwichProof,
                &proof.proof_id,
                &proof.public_record(),
                proof.submitted_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for evidence in self.slashing_evidence.values() {
            records.push(DeterministicPublicRecord::new(
                PublicRecordKind::SlashingEvidence,
                &evidence.evidence_id,
                &evidence.public_record(),
                evidence.submitted_at_height,
                sequence,
            )?);
            sequence = sequence.saturating_add(1);
        }
        for record in records {
            self.public_records.insert(record.record_id.clone(), record);
        }
        Ok(())
    }

    fn active_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| {
                auction.contains_height(self.height) && !auction.status.final_status()
            })
            .map(|auction| auction.auction_id.clone())
            .collect::<Vec<_>>()
    }

    fn active_low_fee_lane_ids(&self) -> Vec<String> {
        self.low_fee_lanes
            .values()
            .filter(|lane| lane.active_at(self.height))
            .map(|lane| lane.protected_lane_id.clone())
            .collect::<Vec<_>>()
    }
}

pub fn pq_mev_burn_auction_state_root_from_record(record: &Value) -> String {
    pq_mev_burn_auction_payload_root("PQ-MEV-BURN-AUCTION-STATE", record)
}

pub fn pq_mev_burn_auction_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_mev_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn pq_mev_record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        return empty_record_root(domain);
    }
    let mut level = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            domain_hash(
                &format!("{domain}:leaf"),
                &[
                    HashPart::Str(PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION),
                    HashPart::Str(CHAIN_ID),
                    HashPart::Int(index as i128),
                    HashPart::Json(record),
                ],
                32,
            )
        })
        .collect::<Vec<_>>();
    while level.len() > 1 {
        let mut next = Vec::<String>::new();
        for chunk in level.chunks(2) {
            let left = chunk[0].as_str();
            let right = chunk.get(1).map(String::as_str).unwrap_or(left);
            next.push(domain_hash(
                &format!("{domain}:node"),
                &[
                    HashPart::Str(PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION),
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(left),
                    HashPart::Str(right),
                ],
                32,
            ));
        }
        level = next;
    }
    match level.first() {
        Some(root) => root.clone(),
        None => empty_record_root(domain),
    }
}

pub fn empty_record_root(domain: &str) -> String {
    domain_hash(
        &format!("{domain}:empty"),
        &[
            HashPart::Str(PQ_MEV_BURN_AUCTION_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
        ],
        32,
    )
}

pub fn pq_mev_lane_id(
    lane: PqMevAuctionLane,
    sponsor_pool_id: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-LANE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(sponsor_pool_id),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_auction_id(
    epoch: u64,
    lane_id: &str,
    proposer_id: &str,
    blockspace_slot: u64,
    commit_start_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Str(lane_id),
            HashPart::Str(proposer_id),
            HashPart::Int(blockspace_slot as i128),
            HashPart::Int(commit_start_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_bid_commitment(
    auction_id: &str,
    bidder_commitment: &str,
    payer_nullifier: &str,
    encrypted_payload_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-BID-COMMITMENT",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(payer_nullifier),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_bid_id(auction_id: &str, bid_commitment: &str, submitted_at_height: u64) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-BID-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bid_commitment),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_sequencer_commitment_id(
    auction_id: &str,
    proposer_id: &str,
    ordering_commitment_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-SEQUENCER-COMMITMENT-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(proposer_id),
            HashPart::Str(ordering_commitment_root),
            HashPart::Int(committed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_reveal_id(
    bid_id: &str,
    auction_id: &str,
    clear_bid_root: &str,
    revealed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-REVEAL-ID",
        &[
            HashPart::Str(bid_id),
            HashPart::Str(auction_id),
            HashPart::Str(clear_bid_root),
            HashPart::Int(revealed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_settlement_id(
    auction_id: &str,
    winning_bid_id: &str,
    clearing_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-SETTLEMENT-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(winning_bid_id),
            HashPart::Str(clearing_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_burn_receipt_id(
    auction_id: &str,
    settlement_id: &str,
    monero_tx_commitment: &str,
    anchored_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-BURN-RECEIPT-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(settlement_id),
            HashPart::Str(monero_tx_commitment),
            HashPart::Int(anchored_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_sponsor_distribution_id(
    sponsor_pool_id: &str,
    auction_id: &str,
    settlement_id: &str,
    distributed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-SPONSOR-DISTRIBUTION-ID",
        &[
            HashPart::Str(sponsor_pool_id),
            HashPart::Str(auction_id),
            HashPart::Str(settlement_id),
            HashPart::Int(distributed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_protected_lane_id(
    lane_id: &str,
    sponsor_pool_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-PROTECTED-LANE-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_pool_id),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_anti_sandwich_proof_id(auction_id: &str, bid_id: &str, proof_root: &str) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-ANTI-SANDWICH-PROOF-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

pub fn pq_mev_slashing_evidence_id(
    auction_id: &str,
    proposer_id: &str,
    evidence_kind: SlashingEvidenceKind,
    evidence_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(proposer_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn pq_mev_public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PQ-MEV-BURN-AUCTION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn keyed_record_root<'a, I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = (&'a String, Value)>,
{
    let leaves = records
        .into_iter()
        .map(|(id, record)| json!({"id": id, "record": record}))
        .collect::<Vec<_>>();
    pq_mev_record_root(domain, &leaves)
}

fn records_for(records: &BTreeMap<String, Vec<Value>>, key: &str) -> Vec<Value> {
    match records.get(key) {
        Some(values) => values.clone(),
        None => Vec::new(),
    }
}

fn bps_portion(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / PQ_MEV_BURN_AUCTION_MAX_BPS
}

fn ensure_non_empty(label: &str, value: &str) -> PqMevBurnAuctionResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> PqMevBurnAuctionResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> PqMevBurnAuctionResult<()> {
    if value > PQ_MEV_BURN_AUCTION_MAX_BPS {
        return Err(format!("{label} exceeds 100%"));
    }
    Ok(())
}

fn ensure_eq(label: &str, actual: &str, expected: &str) -> PqMevBurnAuctionResult<()> {
    if actual != expected {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}

fn ensure_window(label: &str, start: u64, end: u64) -> PqMevBurnAuctionResult<()> {
    if end <= start {
        return Err(format!("{label} end must follow start"));
    }
    Ok(())
}

fn ensure_hex_root(label: &str, value: &str) -> PqMevBurnAuctionResult<()> {
    if value.len() != 64 {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex encoded"));
    }
    Ok(())
}

fn bounded_len(label: &str, actual: usize, max: usize) -> PqMevBurnAuctionResult<()> {
    if actual > max {
        return Err(format!("{label} exceeds configured bound"));
    }
    Ok(())
}

fn require_state_status(status: &str) -> PqMevBurnAuctionResult<()> {
    match status {
        STATE_STATUS_ACTIVE | STATE_STATUS_CHALLENGED | STATE_STATUS_HALTED => Ok(()),
        _ => Err("pq mev burn auction state status is unknown".to_string()),
    }
}
