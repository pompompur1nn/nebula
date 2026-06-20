use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqPrivateOrderflowEncryptedAuctioneerResult<T> = Result<T, String>;

pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PROTOCOL_VERSION: &str =
    "nebula-pq-private-orderflow-encrypted-auctioneer-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_HASH_SUITE: &str =
    "shake256-domain-separated-canonical-json-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PQ_KEM_SUITE: &str =
    "ml-kem-1024-threshold-orderflow-envelope-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PQ_SIGNATURE_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-128s";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_TRANSCRIPT_SUITE: &str =
    "threshold-decryption-transcript-shake256-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_FAIRNESS_SUITE: &str =
    "sealed-fair-ordering-window-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MEV_BURN_SUITE: &str =
    "mev-burn-receipt-private-orderflow-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_NULLIFIER_SUITE: &str =
    "private-orderflow-nullifier-fence-v1";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEVNET_OPERATOR: &str =
    "devnet-pq-private-orderflow-auctioneer";
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_COMMIT_WINDOW_BLOCKS: u64 = 8;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_FAIRNESS_WINDOW_BLOCKS: u64 = 5;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_DECRYPTION_WINDOW_BLOCKS: u64 = 6;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 12;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 480;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_PRIVACY_BUCKET_SIZE: u64 = 64;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MIN_SOLVER_BOND: u64 = 1_000_000;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MIN_MEV_BURN_BPS: u64 = 6_500;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_LOW_FEE_LANE_BPS: u64 = 1_000;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_PROTOCOL_FEE_BPS: u64 = 500;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MIN_FAIRNESS_SCORE: u64 = 8_500;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MAX_ORDER_BYTES: u64 = 128 * 1024;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS: u64 = 10_000;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_AUCTIONS: usize = 1_024;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BIDS: usize = 16_384;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_SOLVERS: usize = 512;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_TRANSCRIPTS: usize = 16_384;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_RECEIPTS: usize = 16_384;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BUCKETS: usize = 512;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_SPONSORS: usize = 512;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_FENCES: usize = 32_768;
pub const PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_AUDIT_EVENTS: usize = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    PrivateDex,
    ConfidentialAmm,
    PrivateLiquidation,
    CrossRollupIntent,
    LowFeeSwap,
    LowFeeTransfer,
    WalletRecovery,
    ProofMarket,
    SponsorOnly,
    EmergencyExit,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDex => "private_dex",
            Self::ConfidentialAmm => "confidential_amm",
            Self::PrivateLiquidation => "private_liquidation",
            Self::CrossRollupIntent => "cross_rollup_intent",
            Self::LowFeeSwap => "low_fee_swap",
            Self::LowFeeTransfer => "low_fee_transfer",
            Self::WalletRecovery => "wallet_recovery",
            Self::ProofMarket => "proof_market",
            Self::SponsorOnly => "sponsor_only",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyExit => 0,
            Self::WalletRecovery => 1,
            Self::PrivateLiquidation => 2,
            Self::LowFeeTransfer => 3,
            Self::LowFeeSwap => 4,
            Self::CrossRollupIntent => 5,
            Self::ConfidentialAmm => 6,
            Self::PrivateDex => 7,
            Self::ProofMarket => 8,
            Self::SponsorOnly => 9,
        }
    }

    pub fn is_low_fee(self) -> bool {
        matches!(
            self,
            Self::LowFeeSwap
                | Self::LowFeeTransfer
                | Self::WalletRecovery
                | Self::SponsorOnly
                | Self::EmergencyExit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Scheduled,
    CommitOpen,
    FairnessLocked,
    Decrypting,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::CommitOpen => "commit_open",
            Self::FairnessLocked => "fairness_locked",
            Self::Decrypting => "decrypting",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_bid(self) -> bool {
        matches!(self, Self::CommitOpen)
    }

    pub fn final_status(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    FairnessQueued,
    TranscriptReady,
    Eligible,
    Winning,
    Sponsored,
    Rejected,
    Slashed,
    Refunded,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::FairnessQueued => "fairness_queued",
            Self::TranscriptReady => "transcript_ready",
            Self::Eligible => "eligible",
            Self::Winning => "winning",
            Self::Sponsored => "sponsored",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Bonded,
    Active,
    CoolingDown,
    Slashed,
    Suspended,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonded => "bonded",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Slashed => "slashed",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    AuctionOpened,
    BidSealed,
    FairnessLocked,
    TranscriptPublished,
    WinnerSelected,
    MevBurned,
    SponsorCredited,
    NullifierRejected,
    SolverSlashed,
}

impl AuditEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuctionOpened => "auction_opened",
            Self::BidSealed => "bid_sealed",
            Self::FairnessLocked => "fairness_locked",
            Self::TranscriptPublished => "transcript_published",
            Self::WinnerSelected => "winner_selected",
            Self::MevBurned => "mev_burned",
            Self::SponsorCredited => "sponsor_credited",
            Self::NullifierRejected => "nullifier_rejected",
            Self::SolverSlashed => "solver_slashed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub commit_window_blocks: u64,
    pub fairness_window_blocks: u64,
    pub decryption_window_blocks: u64,
    pub settlement_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub privacy_bucket_size: u64,
    pub min_solver_bond: u64,
    pub min_mev_burn_bps: u64,
    pub low_fee_lane_bps: u64,
    pub protocol_fee_bps: u64,
    pub min_fairness_score: u64,
    pub max_order_bytes: u64,
    pub operator_label: String,
    pub paused: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            epoch_blocks: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_EPOCH_BLOCKS,
            commit_window_blocks:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_COMMIT_WINDOW_BLOCKS,
            fairness_window_blocks:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_FAIRNESS_WINDOW_BLOCKS,
            decryption_window_blocks:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_DECRYPTION_WINDOW_BLOCKS,
            settlement_window_blocks:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            challenge_window_blocks:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            replay_window_blocks:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_REPLAY_WINDOW_BLOCKS,
            privacy_bucket_size:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_PRIVACY_BUCKET_SIZE,
            min_solver_bond: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MIN_SOLVER_BOND,
            min_mev_burn_bps: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MIN_MEV_BURN_BPS,
            low_fee_lane_bps: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_LOW_FEE_LANE_BPS,
            protocol_fee_bps: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_PROTOCOL_FEE_BPS,
            min_fairness_score:
                PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MIN_FAIRNESS_SCORE,
            max_order_bytes: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEFAULT_MAX_ORDER_BYTES,
            operator_label: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_DEVNET_OPERATOR.to_string(),
            paused: false,
        }
    }
}

impl Config {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        if self.epoch_blocks == 0 {
            return Err("epoch blocks must be positive".to_string());
        }
        if self.commit_window_blocks == 0 {
            return Err("commit window blocks must be positive".to_string());
        }
        if self.fairness_window_blocks == 0 {
            return Err("fairness window blocks must be positive".to_string());
        }
        if self.decryption_window_blocks == 0 {
            return Err("decryption window blocks must be positive".to_string());
        }
        if self.settlement_window_blocks == 0 {
            return Err("settlement window blocks must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("challenge window blocks must be positive".to_string());
        }
        if self.replay_window_blocks < self.epoch_blocks {
            return Err("replay window must cover at least one epoch".to_string());
        }
        if self.privacy_bucket_size == 0 {
            return Err("privacy bucket size must be positive".to_string());
        }
        if self.min_solver_bond == 0 {
            return Err("solver bond must be positive".to_string());
        }
        if self.min_mev_burn_bps > PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS {
            return Err("minimum mev burn bps exceeds max bps".to_string());
        }
        if self.low_fee_lane_bps > PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS {
            return Err("low fee lane bps exceeds max bps".to_string());
        }
        if self.protocol_fee_bps > PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS {
            return Err("protocol fee bps exceeds max bps".to_string());
        }
        if self.min_fairness_score > PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS {
            return Err("minimum fairness score exceeds max bps".to_string());
        }
        if self.max_order_bytes == 0 {
            return Err("max order bytes must be positive".to_string());
        }
        if self.operator_label.trim().is_empty() {
            return Err("operator label cannot be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_encrypted_auctioneer_config",
            "protocol_version": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PROTOCOL_VERSION,
            "hash_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_HASH_SUITE,
            "pq_kem_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PQ_KEM_SUITE,
            "pq_signature_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PQ_SIGNATURE_SUITE,
            "transcript_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_TRANSCRIPT_SUITE,
            "fairness_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_FAIRNESS_SUITE,
            "mev_burn_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MEV_BURN_SUITE,
            "nullifier_suite": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_NULLIFIER_SUITE,
            "epoch_blocks": self.epoch_blocks,
            "commit_window_blocks": self.commit_window_blocks,
            "fairness_window_blocks": self.fairness_window_blocks,
            "decryption_window_blocks": self.decryption_window_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "privacy_bucket_size": self.privacy_bucket_size,
            "min_solver_bond": self.min_solver_bond,
            "min_mev_burn_bps": self.min_mev_burn_bps,
            "low_fee_lane_bps": self.low_fee_lane_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "min_fairness_score": self.min_fairness_score,
            "max_order_bytes": self.max_order_bytes,
            "operator_label": self.operator_label,
            "paused": self.paused,
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedAuction {
    pub auction_id: String,
    pub lane: AuctionLane,
    pub status: AuctionStatus,
    pub epoch: u64,
    pub opens_at_height: u64,
    pub commit_ends_at_height: u64,
    pub fairness_ends_at_height: u64,
    pub decryption_ends_at_height: u64,
    pub settlement_ends_at_height: u64,
    pub challenge_ends_at_height: u64,
    pub orderflow_commitment_root: String,
    pub threshold_committee_root: String,
    pub fairness_policy_root: String,
    pub sponsor_lane_id: String,
    pub min_bid_micro_units: u64,
    pub max_order_bytes: u64,
}

impl EncryptedAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        lane: AuctionLane,
        epoch: u64,
        opens_at_height: u64,
        config: &Config,
        orderflow_commitment_root: &str,
        threshold_committee_root: &str,
        fairness_policy_root: &str,
        sponsor_lane_id: &str,
        min_bid_micro_units: u64,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<Self> {
        let commit_ends_at_height = opens_at_height.saturating_add(config.commit_window_blocks);
        let fairness_ends_at_height =
            commit_ends_at_height.saturating_add(config.fairness_window_blocks);
        let decryption_ends_at_height =
            fairness_ends_at_height.saturating_add(config.decryption_window_blocks);
        let settlement_ends_at_height =
            decryption_ends_at_height.saturating_add(config.settlement_window_blocks);
        let challenge_ends_at_height =
            settlement_ends_at_height.saturating_add(config.challenge_window_blocks);
        let auction = Self {
            auction_id: auction_id.to_string(),
            lane,
            status: AuctionStatus::CommitOpen,
            epoch,
            opens_at_height,
            commit_ends_at_height,
            fairness_ends_at_height,
            decryption_ends_at_height,
            settlement_ends_at_height,
            challenge_ends_at_height,
            orderflow_commitment_root: orderflow_commitment_root.to_string(),
            threshold_committee_root: threshold_committee_root.to_string(),
            fairness_policy_root: fairness_policy_root.to_string(),
            sponsor_lane_id: sponsor_lane_id.to_string(),
            min_bid_micro_units,
            max_order_bytes: config.max_order_bytes,
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("orderflow commitment root", &self.orderflow_commitment_root)?;
        require_nonempty("threshold committee root", &self.threshold_committee_root)?;
        require_nonempty("fairness policy root", &self.fairness_policy_root)?;
        if self.commit_ends_at_height <= self.opens_at_height {
            return Err("auction commit end must be after open height".to_string());
        }
        if self.fairness_ends_at_height <= self.commit_ends_at_height {
            return Err("auction fairness end must be after commit end".to_string());
        }
        if self.decryption_ends_at_height <= self.fairness_ends_at_height {
            return Err("auction decryption end must be after fairness end".to_string());
        }
        if self.settlement_ends_at_height <= self.decryption_ends_at_height {
            return Err("auction settlement end must be after decryption end".to_string());
        }
        if self.challenge_ends_at_height <= self.settlement_ends_at_height {
            return Err("auction challenge end must be after settlement end".to_string());
        }
        if self.max_order_bytes == 0 {
            return Err("auction max order bytes must be positive".to_string());
        }
        Ok(())
    }

    pub fn update_status_for_height(&mut self, height: u64) {
        if self.status.final_status() || self.status == AuctionStatus::Challenged {
            return;
        }
        self.status = if height < self.opens_at_height {
            AuctionStatus::Scheduled
        } else if height <= self.commit_ends_at_height {
            AuctionStatus::CommitOpen
        } else if height <= self.fairness_ends_at_height {
            AuctionStatus::FairnessLocked
        } else if height <= self.decryption_ends_at_height {
            AuctionStatus::Decrypting
        } else if height <= self.settlement_ends_at_height {
            AuctionStatus::Settling
        } else if height <= self.challenge_ends_at_height {
            AuctionStatus::Settled
        } else {
            AuctionStatus::Expired
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_encrypted_auction",
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "lane_priority": self.lane.priority(),
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "opens_at_height": self.opens_at_height,
            "commit_ends_at_height": self.commit_ends_at_height,
            "fairness_ends_at_height": self.fairness_ends_at_height,
            "decryption_ends_at_height": self.decryption_ends_at_height,
            "settlement_ends_at_height": self.settlement_ends_at_height,
            "challenge_ends_at_height": self.challenge_ends_at_height,
            "orderflow_commitment_root": self.orderflow_commitment_root,
            "threshold_committee_root": self.threshold_committee_root,
            "fairness_policy_root": self.fairness_policy_root,
            "sponsor_lane_id": self.sponsor_lane_id,
            "min_bid_micro_units": self.min_bid_micro_units,
            "max_order_bytes": self.max_order_bytes,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-AUCTION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBond {
    pub solver_id: String,
    pub pq_identity_commitment: String,
    pub bond_commitment: String,
    pub bond_amount: u64,
    pub supported_lanes: BTreeSet<AuctionLane>,
    pub status: SolverStatus,
    pub joined_at_height: u64,
    pub slash_count: u64,
    pub reliability_score_bps: u64,
}

impl SolverBond {
    pub fn new(
        solver_id: &str,
        pq_identity_commitment: &str,
        bond_commitment: &str,
        bond_amount: u64,
        supported_lanes: BTreeSet<AuctionLane>,
        joined_at_height: u64,
        config: &Config,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<Self> {
        let solver = Self {
            solver_id: solver_id.to_string(),
            pq_identity_commitment: pq_identity_commitment.to_string(),
            bond_commitment: bond_commitment.to_string(),
            bond_amount,
            supported_lanes,
            status: SolverStatus::Active,
            joined_at_height,
            slash_count: 0,
            reliability_score_bps: PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS,
        };
        solver.validate(config)?;
        Ok(solver)
    }

    pub fn validate(&self, config: &Config) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("solver id", &self.solver_id)?;
        require_nonempty("pq identity commitment", &self.pq_identity_commitment)?;
        require_nonempty("bond commitment", &self.bond_commitment)?;
        if self.bond_amount < config.min_solver_bond {
            return Err("solver bond below minimum".to_string());
        }
        if self.supported_lanes.is_empty() {
            return Err("solver must support at least one lane".to_string());
        }
        if self.reliability_score_bps > PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS {
            return Err("solver reliability score exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn can_bid_lane(&self, lane: AuctionLane) -> bool {
        self.status == SolverStatus::Active && self.supported_lanes.contains(&lane)
    }

    pub fn public_record(&self) -> Value {
        let lanes = self
            .supported_lanes
            .iter()
            .map(|lane| lane.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "pq_private_orderflow_solver_bond",
            "solver_id": self.solver_id,
            "pq_identity_commitment": self.pq_identity_commitment,
            "bond_commitment": self.bond_commitment,
            "bond_amount": self.bond_amount,
            "supported_lanes": lanes,
            "status": self.status.as_str(),
            "joined_at_height": self.joined_at_height,
            "slash_count": self.slash_count,
            "reliability_score_bps": self.reliability_score_bps,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-SOLVER-BOND",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBid {
    pub bid_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub status: BidStatus,
    pub ciphertext_hash: String,
    pub bid_commitment: String,
    pub nullifier: String,
    pub privacy_bucket_id: String,
    pub sponsor_lane_id: String,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub max_fee_micro_units: u64,
    pub bond_lock: u64,
    pub order_bytes: u64,
    pub fairness_score_bps: u64,
}

impl SealedBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bid_id: &str,
        auction: &EncryptedAuction,
        solver: &SolverBond,
        ciphertext_hash: &str,
        bid_commitment: &str,
        nullifier: &str,
        privacy_bucket_id: &str,
        sponsor_lane_id: &str,
        sealed_at_height: u64,
        max_fee_micro_units: u64,
        bond_lock: u64,
        order_bytes: u64,
        fairness_score_bps: u64,
        config: &Config,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<Self> {
        let bid = Self {
            bid_id: bid_id.to_string(),
            auction_id: auction.auction_id.clone(),
            solver_id: solver.solver_id.clone(),
            status: BidStatus::Sealed,
            ciphertext_hash: ciphertext_hash.to_string(),
            bid_commitment: bid_commitment.to_string(),
            nullifier: nullifier.to_string(),
            privacy_bucket_id: privacy_bucket_id.to_string(),
            sponsor_lane_id: sponsor_lane_id.to_string(),
            sealed_at_height,
            expires_at_height: sealed_at_height.saturating_add(config.replay_window_blocks),
            max_fee_micro_units,
            bond_lock,
            order_bytes,
            fairness_score_bps,
        };
        bid.validate(auction, solver, config)?;
        Ok(bid)
    }

    pub fn validate(
        &self,
        auction: &EncryptedAuction,
        solver: &SolverBond,
        config: &Config,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("bid id", &self.bid_id)?;
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("solver id", &self.solver_id)?;
        require_nonempty("ciphertext hash", &self.ciphertext_hash)?;
        require_nonempty("bid commitment", &self.bid_commitment)?;
        require_nonempty("nullifier", &self.nullifier)?;
        require_nonempty("privacy bucket id", &self.privacy_bucket_id)?;
        if self.auction_id != auction.auction_id {
            return Err("bid auction id does not match auction".to_string());
        }
        if self.solver_id != solver.solver_id {
            return Err("bid solver id does not match solver".to_string());
        }
        if !solver.can_bid_lane(auction.lane) {
            return Err("solver cannot bid this auction lane".to_string());
        }
        if !auction.status.accepts_bid() {
            return Err("auction is not accepting sealed bids".to_string());
        }
        if self.sealed_at_height < auction.opens_at_height
            || self.sealed_at_height > auction.commit_ends_at_height
        {
            return Err("bid sealed outside commit window".to_string());
        }
        if self.max_fee_micro_units < auction.min_bid_micro_units {
            return Err("bid max fee below auction minimum".to_string());
        }
        if self.bond_lock > solver.bond_amount {
            return Err("bid bond lock exceeds solver bond".to_string());
        }
        if self.order_bytes == 0 || self.order_bytes > config.max_order_bytes {
            return Err("bid order bytes outside configured range".to_string());
        }
        if self.fairness_score_bps < config.min_fairness_score {
            return Err("bid fairness score below minimum".to_string());
        }
        if self.fairness_score_bps > PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BPS {
            return Err("bid fairness score exceeds max bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_sealed_bid",
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "ciphertext_hash": self.ciphertext_hash,
            "bid_commitment": self.bid_commitment,
            "nullifier": self.nullifier,
            "privacy_bucket_id": self.privacy_bucket_id,
            "sponsor_lane_id": self.sponsor_lane_id,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "max_fee_micro_units": self.max_fee_micro_units,
            "bond_lock": self.bond_lock,
            "order_bytes": self.order_bytes,
            "fairness_score_bps": self.fairness_score_bps,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-SEALED-BID",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessWindow {
    pub window_id: String,
    pub auction_id: String,
    pub lane: AuctionLane,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub sealed_bid_root: String,
    pub arrival_order_root: String,
    pub tie_breaker_seed_commitment: String,
    pub eligible_bid_count: u64,
    pub low_fee_reserved_slots: u64,
}

impl FairnessWindow {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("fairness window id", &self.window_id)?;
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("sealed bid root", &self.sealed_bid_root)?;
        require_nonempty("arrival order root", &self.arrival_order_root)?;
        require_nonempty(
            "tie breaker seed commitment",
            &self.tie_breaker_seed_commitment,
        )?;
        if self.closes_at_height <= self.opens_at_height {
            return Err("fairness window close must be after open".to_string());
        }
        if self.low_fee_reserved_slots > self.eligible_bid_count {
            return Err("low fee reserved slots exceed eligible bids".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_fairness_window",
            "window_id": self.window_id,
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "sealed_bid_root": self.sealed_bid_root,
            "arrival_order_root": self.arrival_order_root,
            "tie_breaker_seed_commitment": self.tie_breaker_seed_commitment,
            "eligible_bid_count": self.eligible_bid_count,
            "low_fee_reserved_slots": self.low_fee_reserved_slots,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-FAIRNESS-WINDOW",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdTranscript {
    pub transcript_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub committee_root: String,
    pub decryption_share_root: String,
    pub transcript_proof_root: String,
    pub decrypted_order_commitment: String,
    pub published_at_height: u64,
    pub threshold: u64,
    pub share_count: u64,
    pub accepted: bool,
}

impl ThresholdTranscript {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("transcript id", &self.transcript_id)?;
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("bid id", &self.bid_id)?;
        require_nonempty("committee root", &self.committee_root)?;
        require_nonempty("decryption share root", &self.decryption_share_root)?;
        require_nonempty("transcript proof root", &self.transcript_proof_root)?;
        require_nonempty(
            "decrypted order commitment",
            &self.decrypted_order_commitment,
        )?;
        if self.threshold == 0 {
            return Err("transcript threshold must be positive".to_string());
        }
        if self.share_count < self.threshold {
            return Err("transcript share count below threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_threshold_transcript",
            "transcript_id": self.transcript_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "committee_root": self.committee_root,
            "decryption_share_root": self.decryption_share_root,
            "transcript_proof_root": self.transcript_proof_root,
            "decrypted_order_commitment": self.decrypted_order_commitment,
            "published_at_height": self.published_at_height,
            "threshold": self.threshold,
            "share_count": self.share_count,
            "accepted": self.accepted,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-THRESHOLD-TRANSCRIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MevBurnReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub solver_id: String,
    pub burn_asset_id: String,
    pub burn_amount: u64,
    pub protocol_fee_amount: u64,
    pub sponsor_credit_amount: u64,
    pub burn_commitment: String,
    pub beneficiary_commitment: String,
    pub emitted_at_height: u64,
}

impl MevBurnReceipt {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("receipt id", &self.receipt_id)?;
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("bid id", &self.bid_id)?;
        require_nonempty("solver id", &self.solver_id)?;
        require_nonempty("burn asset id", &self.burn_asset_id)?;
        require_nonempty("burn commitment", &self.burn_commitment)?;
        require_nonempty("beneficiary commitment", &self.beneficiary_commitment)?;
        if self.burn_amount == 0 {
            return Err("burn amount must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_mev_burn_receipt",
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "solver_id": self.solver_id,
            "burn_asset_id": self.burn_asset_id,
            "burn_amount": self.burn_amount,
            "protocol_fee_amount": self.protocol_fee_amount,
            "sponsor_credit_amount": self.sponsor_credit_amount,
            "burn_commitment": self.burn_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-MEV-BURN-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBucket {
    pub bucket_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub bucket_commitment: String,
    pub member_root: String,
    pub sealed_bid_count: u64,
    pub sponsor_bid_count: u64,
    pub capacity: u64,
}

impl PrivacyBucket {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("privacy bucket id", &self.bucket_id)?;
        require_nonempty("bucket commitment", &self.bucket_commitment)?;
        require_nonempty("member root", &self.member_root)?;
        if self.capacity == 0 {
            return Err("privacy bucket capacity must be positive".to_string());
        }
        if self.sealed_bid_count > self.capacity {
            return Err("privacy bucket sealed bid count exceeds capacity".to_string());
        }
        if self.sponsor_bid_count > self.sealed_bid_count {
            return Err("privacy bucket sponsor count exceeds sealed bids".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_privacy_bucket",
            "bucket_id": self.bucket_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "bucket_commitment": self.bucket_commitment,
            "member_root": self.member_root,
            "sealed_bid_count": self.sealed_bid_count,
            "sponsor_bid_count": self.sponsor_bid_count,
            "capacity": self.capacity,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-PRIVACY-BUCKET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorLane {
    pub sponsor_lane_id: String,
    pub sponsor_commitment: String,
    pub lane: AuctionLane,
    pub budget_commitment: String,
    pub fee_cap_micro_units: u64,
    pub remaining_budget_micro_units: u64,
    pub reserved_slots: u64,
    pub active: bool,
}

impl SponsorLane {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("sponsor lane id", &self.sponsor_lane_id)?;
        require_nonempty("sponsor commitment", &self.sponsor_commitment)?;
        require_nonempty("budget commitment", &self.budget_commitment)?;
        if !self.lane.is_low_fee() {
            return Err("sponsor lane must target a low fee lane".to_string());
        }
        if self.fee_cap_micro_units == 0 {
            return Err("sponsor lane fee cap must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_sponsor_lane",
            "sponsor_lane_id": self.sponsor_lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "budget_commitment": self.budget_commitment,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "remaining_budget_micro_units": self.remaining_budget_micro_units,
            "reserved_slots": self.reserved_slots,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-SPONSOR-LANE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub nullifier: String,
    pub auction_id: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub source_commitment: String,
    pub rejected_count: u64,
}

impl ReplayFence {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("replay fence id", &self.fence_id)?;
        require_nonempty("nullifier", &self.nullifier)?;
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("source commitment", &self.source_commitment)?;
        if self.expires_at_height <= self.first_seen_height {
            return Err("replay fence expiry must be after first seen height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_replay_fence",
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "auction_id": self.auction_id,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "source_commitment": self.source_commitment,
            "rejected_count": self.rejected_count,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-REPLAY-FENCE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub kind: AuditEventKind,
    pub auction_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub emitted_at_height: u64,
}

impl AuditEvent {
    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        require_nonempty("audit event id", &self.event_id)?;
        require_nonempty("auction id", &self.auction_id)?;
        require_nonempty("subject id", &self.subject_id)?;
        require_nonempty("evidence root", &self.evidence_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_audit_event",
            "event_id": self.event_id,
            "event_kind": self.kind.as_str(),
            "auction_id": self.auction_id,
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-AUDIT-EVENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub auction_root: String,
    pub sealed_bid_root: String,
    pub solver_bond_root: String,
    pub fairness_window_root: String,
    pub threshold_transcript_root: String,
    pub mev_burn_receipt_root: String,
    pub privacy_bucket_root: String,
    pub sponsor_lane_root: String,
    pub replay_fence_root: String,
    pub audit_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_encrypted_auctioneer_roots",
            "config_root": self.config_root,
            "auction_root": self.auction_root,
            "sealed_bid_root": self.sealed_bid_root,
            "solver_bond_root": self.solver_bond_root,
            "fairness_window_root": self.fairness_window_root,
            "threshold_transcript_root": self.threshold_transcript_root,
            "mev_burn_receipt_root": self.mev_burn_receipt_root,
            "privacy_bucket_root": self.privacy_bucket_root,
            "sponsor_lane_root": self.sponsor_lane_root,
            "replay_fence_root": self.replay_fence_root,
            "audit_event_root": self.audit_event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub height: u64,
    pub auctions: u64,
    pub active_auctions: u64,
    pub sealed_bids: u64,
    pub eligible_bids: u64,
    pub winning_bids: u64,
    pub bonded_solvers: u64,
    pub active_solvers: u64,
    pub fairness_windows: u64,
    pub threshold_transcripts: u64,
    pub accepted_transcripts: u64,
    pub mev_burn_receipts: u64,
    pub privacy_buckets: u64,
    pub sponsor_lanes: u64,
    pub replay_fences: u64,
    pub audit_events: u64,
    pub total_burn_amount: u64,
    pub total_sponsor_credit: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_private_orderflow_encrypted_auctioneer_counters",
            "height": self.height,
            "auctions": self.auctions,
            "active_auctions": self.active_auctions,
            "sealed_bids": self.sealed_bids,
            "eligible_bids": self.eligible_bids,
            "winning_bids": self.winning_bids,
            "bonded_solvers": self.bonded_solvers,
            "active_solvers": self.active_solvers,
            "fairness_windows": self.fairness_windows,
            "threshold_transcripts": self.threshold_transcripts,
            "accepted_transcripts": self.accepted_transcripts,
            "mev_burn_receipts": self.mev_burn_receipts,
            "privacy_buckets": self.privacy_buckets,
            "sponsor_lanes": self.sponsor_lanes,
            "replay_fences": self.replay_fences,
            "audit_events": self.audit_events,
            "total_burn_amount": self.total_burn_amount,
            "total_sponsor_credit": self.total_sponsor_credit,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub auctions: BTreeMap<String, EncryptedAuction>,
    pub sealed_bids: BTreeMap<String, SealedBid>,
    pub solver_bonds: BTreeMap<String, SolverBond>,
    pub fairness_windows: BTreeMap<String, FairnessWindow>,
    pub threshold_transcripts: BTreeMap<String, ThresholdTranscript>,
    pub mev_burn_receipts: BTreeMap<String, MevBurnReceipt>,
    pub privacy_buckets: BTreeMap<String, PrivacyBucket>,
    pub sponsor_lanes: BTreeMap<String, SponsorLane>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub audit_events: BTreeMap<String, AuditEvent>,
}

impl State {
    pub fn new(config: Config) -> PqPrivateOrderflowEncryptedAuctioneerResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            config,
            auctions: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            solver_bonds: BTreeMap::new(),
            fairness_windows: BTreeMap::new(),
            threshold_transcripts: BTreeMap::new(),
            mev_burn_receipts: BTreeMap::new(),
            privacy_buckets: BTreeMap::new(),
            sponsor_lanes: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            audit_events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PqPrivateOrderflowEncryptedAuctioneerResult<State> {
        let config = Config::default();
        let mut state = State::new(config)?;
        state.set_height(42_000)?;

        let low_fee_lane = SponsorLane {
            sponsor_lane_id: "devnet-low-fee-sponsor-lane".to_string(),
            sponsor_commitment: sample_root("sponsor", "low-fee-public-goods"),
            lane: AuctionLane::LowFeeTransfer,
            budget_commitment: sample_root("budget", "low-fee-transfer-budget"),
            fee_cap_micro_units: 750,
            remaining_budget_micro_units: 25_000_000,
            reserved_slots: 16,
            active: true,
        };
        state.insert_sponsor_lane(low_fee_lane)?;

        let recovery_lane = SponsorLane {
            sponsor_lane_id: "devnet-wallet-recovery-sponsor-lane".to_string(),
            sponsor_commitment: sample_root("sponsor", "wallet-recovery-public-goods"),
            lane: AuctionLane::WalletRecovery,
            budget_commitment: sample_root("budget", "wallet-recovery-budget"),
            fee_cap_micro_units: 500,
            remaining_budget_micro_units: 15_000_000,
            reserved_slots: 8,
            active: true,
        };
        state.insert_sponsor_lane(recovery_lane)?;

        let mut solver_lanes = BTreeSet::new();
        solver_lanes.insert(AuctionLane::PrivateDex);
        solver_lanes.insert(AuctionLane::ConfidentialAmm);
        solver_lanes.insert(AuctionLane::LowFeeTransfer);
        let solver_a = SolverBond::new(
            "devnet-solver-alpha",
            &sample_root("solver-identity", "alpha"),
            &sample_root("solver-bond", "alpha"),
            3_000_000,
            solver_lanes,
            41_000,
            &state.config,
        )?;
        state.insert_solver_bond(solver_a)?;

        let mut solver_lanes = BTreeSet::new();
        solver_lanes.insert(AuctionLane::PrivateLiquidation);
        solver_lanes.insert(AuctionLane::CrossRollupIntent);
        solver_lanes.insert(AuctionLane::WalletRecovery);
        let solver_b = SolverBond::new(
            "devnet-solver-beta",
            &sample_root("solver-identity", "beta"),
            &sample_root("solver-bond", "beta"),
            4_500_000,
            solver_lanes,
            41_060,
            &state.config,
        )?;
        state.insert_solver_bond(solver_b)?;

        let auction_a = EncryptedAuction::new(
            "devnet-private-dex-auction-0001",
            AuctionLane::PrivateDex,
            350,
            41_990,
            &state.config,
            &sample_root("orderflow", "private-dex-0001"),
            &sample_root("committee", "private-dex-threshold"),
            &sample_root("fairness", "private-dex-policy"),
            "",
            2_500,
        )?;
        state.insert_auction(auction_a)?;

        let auction_b = EncryptedAuction::new(
            "devnet-low-fee-transfer-auction-0001",
            AuctionLane::LowFeeTransfer,
            350,
            41_995,
            &state.config,
            &sample_root("orderflow", "low-fee-transfer-0001"),
            &sample_root("committee", "low-fee-transfer-threshold"),
            &sample_root("fairness", "low-fee-transfer-policy"),
            "devnet-low-fee-sponsor-lane",
            500,
        )?;
        state.insert_auction(auction_b)?;

        let auction_c = EncryptedAuction::new(
            "devnet-wallet-recovery-auction-0001",
            AuctionLane::WalletRecovery,
            350,
            41_996,
            &state.config,
            &sample_root("orderflow", "wallet-recovery-0001"),
            &sample_root("committee", "wallet-recovery-threshold"),
            &sample_root("fairness", "wallet-recovery-policy"),
            "devnet-wallet-recovery-sponsor-lane",
            300,
        )?;
        state.insert_auction(auction_c)?;

        state.insert_privacy_bucket(PrivacyBucket {
            bucket_id: "devnet-private-dex-bucket-0001".to_string(),
            lane: AuctionLane::PrivateDex,
            epoch: 350,
            bucket_commitment: sample_root("bucket", "private-dex-0001"),
            member_root: sample_root("bucket-members", "private-dex-0001"),
            sealed_bid_count: 2,
            sponsor_bid_count: 0,
            capacity: state.config.privacy_bucket_size,
        })?;
        state.insert_privacy_bucket(PrivacyBucket {
            bucket_id: "devnet-low-fee-transfer-bucket-0001".to_string(),
            lane: AuctionLane::LowFeeTransfer,
            epoch: 350,
            bucket_commitment: sample_root("bucket", "low-fee-transfer-0001"),
            member_root: sample_root("bucket-members", "low-fee-transfer-0001"),
            sealed_bid_count: 1,
            sponsor_bid_count: 1,
            capacity: state.config.privacy_bucket_size,
        })?;

        let auction = state.auction("devnet-private-dex-auction-0001")?.clone();
        let solver = state.solver("devnet-solver-alpha")?.clone();
        let bid_a = SealedBid::new(
            "devnet-sealed-bid-alpha-0001",
            &auction,
            &solver,
            &sample_root("ciphertext", "alpha-private-dex"),
            &sample_root("bid-commitment", "alpha-private-dex"),
            &sample_root("nullifier", "alpha-private-dex"),
            "devnet-private-dex-bucket-0001",
            "",
            41_996,
            5_200,
            600_000,
            24_576,
            9_200,
            &state.config,
        )?;
        state.insert_sealed_bid(bid_a)?;

        let auction = state
            .auction("devnet-low-fee-transfer-auction-0001")?
            .clone();
        let solver = state.solver("devnet-solver-alpha")?.clone();
        let bid_b = SealedBid::new(
            "devnet-sealed-bid-alpha-low-fee-0001",
            &auction,
            &solver,
            &sample_root("ciphertext", "alpha-low-fee-transfer"),
            &sample_root("bid-commitment", "alpha-low-fee-transfer"),
            &sample_root("nullifier", "alpha-low-fee-transfer"),
            "devnet-low-fee-transfer-bucket-0001",
            "devnet-low-fee-sponsor-lane",
            41_998,
            900,
            300_000,
            8_192,
            9_700,
            &state.config,
        )?;
        state.insert_sealed_bid(bid_b)?;

        state.insert_fairness_window(FairnessWindow {
            window_id: "devnet-private-dex-fairness-window-0001".to_string(),
            auction_id: "devnet-private-dex-auction-0001".to_string(),
            lane: AuctionLane::PrivateDex,
            opens_at_height: 41_998,
            closes_at_height: 42_003,
            sealed_bid_root: state.sealed_bid_root(),
            arrival_order_root: sample_root("arrival", "private-dex-0001"),
            tie_breaker_seed_commitment: sample_root("tie-breaker", "private-dex-0001"),
            eligible_bid_count: 1,
            low_fee_reserved_slots: 0,
        })?;

        state.insert_threshold_transcript(ThresholdTranscript {
            transcript_id: "devnet-transcript-alpha-0001".to_string(),
            auction_id: "devnet-private-dex-auction-0001".to_string(),
            bid_id: "devnet-sealed-bid-alpha-0001".to_string(),
            committee_root: sample_root("committee", "private-dex-threshold"),
            decryption_share_root: sample_root("shares", "alpha-private-dex"),
            transcript_proof_root: sample_root("transcript-proof", "alpha-private-dex"),
            decrypted_order_commitment: sample_root("decrypted-order", "alpha-private-dex"),
            published_at_height: 42_004,
            threshold: 5,
            share_count: 7,
            accepted: true,
        })?;

        state.insert_mev_burn_receipt(MevBurnReceipt {
            receipt_id: "devnet-mev-burn-alpha-0001".to_string(),
            auction_id: "devnet-private-dex-auction-0001".to_string(),
            bid_id: "devnet-sealed-bid-alpha-0001".to_string(),
            solver_id: "devnet-solver-alpha".to_string(),
            burn_asset_id: "dxmr".to_string(),
            burn_amount: 3_380,
            protocol_fee_amount: 260,
            sponsor_credit_amount: 0,
            burn_commitment: sample_root("burn", "alpha-private-dex"),
            beneficiary_commitment: sample_root("beneficiary", "protocol-burn-vault"),
            emitted_at_height: 42_009,
        })?;

        state.insert_replay_fence(ReplayFence {
            fence_id: "devnet-replay-fence-alpha-0001".to_string(),
            nullifier: sample_root("nullifier", "alpha-private-dex"),
            auction_id: "devnet-private-dex-auction-0001".to_string(),
            first_seen_height: 41_996,
            expires_at_height: 42_476,
            source_commitment: sample_root("source", "alpha-private-dex"),
            rejected_count: 0,
        })?;

        state.insert_audit_event(AuditEvent {
            event_id: "devnet-audit-auction-opened-0001".to_string(),
            kind: AuditEventKind::AuctionOpened,
            auction_id: "devnet-private-dex-auction-0001".to_string(),
            subject_id: "devnet-private-dex-auction-0001".to_string(),
            evidence_root: sample_root("audit", "auction-opened-private-dex"),
            emitted_at_height: 41_990,
        })?;
        state.insert_audit_event(AuditEvent {
            event_id: "devnet-audit-mev-burn-0001".to_string(),
            kind: AuditEventKind::MevBurned,
            auction_id: "devnet-private-dex-auction-0001".to_string(),
            subject_id: "devnet-mev-burn-alpha-0001".to_string(),
            evidence_root: sample_root("audit", "mev-burn-alpha"),
            emitted_at_height: 42_009,
        })?;

        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        self.config.validate()?;
        enforce_len(
            "auctions",
            self.auctions.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_AUCTIONS,
        )?;
        enforce_len(
            "sealed bids",
            self.sealed_bids.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BIDS,
        )?;
        enforce_len(
            "solver bonds",
            self.solver_bonds.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_SOLVERS,
        )?;
        enforce_len(
            "fairness windows",
            self.fairness_windows.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_AUCTIONS,
        )?;
        enforce_len(
            "threshold transcripts",
            self.threshold_transcripts.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_TRANSCRIPTS,
        )?;
        enforce_len(
            "mev burn receipts",
            self.mev_burn_receipts.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_RECEIPTS,
        )?;
        enforce_len(
            "privacy buckets",
            self.privacy_buckets.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_BUCKETS,
        )?;
        enforce_len(
            "sponsor lanes",
            self.sponsor_lanes.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_SPONSORS,
        )?;
        enforce_len(
            "replay fences",
            self.replay_fences.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_FENCES,
        )?;
        enforce_len(
            "audit events",
            self.audit_events.len(),
            PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_MAX_AUDIT_EVENTS,
        )?;

        let mut nullifiers = BTreeSet::new();
        for auction in self.auctions.values() {
            auction.validate()?;
        }
        for solver in self.solver_bonds.values() {
            solver.validate(&self.config)?;
        }
        for bid in self.sealed_bids.values() {
            let auction = self.auction(&bid.auction_id)?;
            let solver = self.solver(&bid.solver_id)?;
            bid.validate(auction, solver, &self.config)?;
            if !nullifiers.insert(bid.nullifier.clone()) {
                return Err("duplicate sealed bid nullifier".to_string());
            }
        }
        for window in self.fairness_windows.values() {
            window.validate()?;
            self.auction(&window.auction_id)?;
        }
        for transcript in self.threshold_transcripts.values() {
            transcript.validate()?;
            self.auction(&transcript.auction_id)?;
            self.bid(&transcript.bid_id)?;
        }
        for receipt in self.mev_burn_receipts.values() {
            receipt.validate()?;
            self.auction(&receipt.auction_id)?;
            self.bid(&receipt.bid_id)?;
            self.solver(&receipt.solver_id)?;
        }
        for bucket in self.privacy_buckets.values() {
            bucket.validate()?;
        }
        for sponsor in self.sponsor_lanes.values() {
            sponsor.validate()?;
        }
        for fence in self.replay_fences.values() {
            fence.validate()?;
            self.auction(&fence.auction_id)?;
        }
        for event in self.audit_events.values() {
            event.validate()?;
            self.auction(&event.auction_id)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        self.height = height;
        self.update_height(height)
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        self.height = height;
        for auction in self.auctions.values_mut() {
            auction.update_status_for_height(height);
        }
        self.prune_expired_replay_fences();
        self.validate()
    }

    pub fn insert_auction(
        &mut self,
        auction: EncryptedAuction,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        auction.validate()?;
        if self.auctions.contains_key(&auction.auction_id) {
            return Err("auction already exists".to_string());
        }
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_solver_bond(
        &mut self,
        solver: SolverBond,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        solver.validate(&self.config)?;
        if self.solver_bonds.contains_key(&solver.solver_id) {
            return Err("solver already exists".to_string());
        }
        self.solver_bonds.insert(solver.solver_id.clone(), solver);
        Ok(())
    }

    pub fn insert_sealed_bid(
        &mut self,
        bid: SealedBid,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        let auction = self.auction(&bid.auction_id)?;
        let solver = self.solver(&bid.solver_id)?;
        bid.validate(auction, solver, &self.config)?;
        if self.sealed_bids.contains_key(&bid.bid_id) {
            return Err("sealed bid already exists".to_string());
        }
        if self
            .sealed_bids
            .values()
            .any(|existing| existing.nullifier == bid.nullifier)
        {
            return Err("sealed bid nullifier already used".to_string());
        }
        self.sealed_bids.insert(bid.bid_id.clone(), bid);
        Ok(())
    }

    pub fn insert_fairness_window(
        &mut self,
        window: FairnessWindow,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        window.validate()?;
        self.auction(&window.auction_id)?;
        if self.fairness_windows.contains_key(&window.window_id) {
            return Err("fairness window already exists".to_string());
        }
        self.fairness_windows
            .insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn insert_threshold_transcript(
        &mut self,
        transcript: ThresholdTranscript,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        transcript.validate()?;
        self.auction(&transcript.auction_id)?;
        self.bid(&transcript.bid_id)?;
        if self
            .threshold_transcripts
            .contains_key(&transcript.transcript_id)
        {
            return Err("threshold transcript already exists".to_string());
        }
        self.threshold_transcripts
            .insert(transcript.transcript_id.clone(), transcript);
        Ok(())
    }

    pub fn insert_mev_burn_receipt(
        &mut self,
        receipt: MevBurnReceipt,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        receipt.validate()?;
        self.auction(&receipt.auction_id)?;
        self.bid(&receipt.bid_id)?;
        self.solver(&receipt.solver_id)?;
        if self.mev_burn_receipts.contains_key(&receipt.receipt_id) {
            return Err("mev burn receipt already exists".to_string());
        }
        self.mev_burn_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_privacy_bucket(
        &mut self,
        bucket: PrivacyBucket,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        bucket.validate()?;
        if self.privacy_buckets.contains_key(&bucket.bucket_id) {
            return Err("privacy bucket already exists".to_string());
        }
        self.privacy_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    pub fn insert_sponsor_lane(
        &mut self,
        sponsor: SponsorLane,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        sponsor.validate()?;
        if self.sponsor_lanes.contains_key(&sponsor.sponsor_lane_id) {
            return Err("sponsor lane already exists".to_string());
        }
        self.sponsor_lanes
            .insert(sponsor.sponsor_lane_id.clone(), sponsor);
        Ok(())
    }

    pub fn insert_replay_fence(
        &mut self,
        fence: ReplayFence,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        fence.validate()?;
        self.auction(&fence.auction_id)?;
        if self.replay_fences.contains_key(&fence.fence_id) {
            return Err("replay fence already exists".to_string());
        }
        if self
            .replay_fences
            .values()
            .any(|existing| existing.nullifier == fence.nullifier)
        {
            return Err("replay fence nullifier already exists".to_string());
        }
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    pub fn insert_audit_event(
        &mut self,
        event: AuditEvent,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
        event.validate()?;
        self.auction(&event.auction_id)?;
        if self.audit_events.contains_key(&event.event_id) {
            return Err("audit event already exists".to_string());
        }
        self.audit_events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn auction(
        &self,
        auction_id: &str,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<&EncryptedAuction> {
        self.auctions
            .get(auction_id)
            .ok_or_else(|| format!("auction not found: {auction_id}"))
    }

    pub fn solver(
        &self,
        solver_id: &str,
    ) -> PqPrivateOrderflowEncryptedAuctioneerResult<&SolverBond> {
        self.solver_bonds
            .get(solver_id)
            .ok_or_else(|| format!("solver not found: {solver_id}"))
    }

    pub fn bid(&self, bid_id: &str) -> PqPrivateOrderflowEncryptedAuctioneerResult<&SealedBid> {
        self.sealed_bids
            .get(bid_id)
            .ok_or_else(|| format!("sealed bid not found: {bid_id}"))
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.root(),
            auction_root: self.auction_root(),
            sealed_bid_root: self.sealed_bid_root(),
            solver_bond_root: self.solver_bond_root(),
            fairness_window_root: self.fairness_window_root(),
            threshold_transcript_root: self.threshold_transcript_root(),
            mev_burn_receipt_root: self.mev_burn_receipt_root(),
            privacy_bucket_root: self.privacy_bucket_root(),
            sponsor_lane_root: self.sponsor_lane_root(),
            replay_fence_root: self.replay_fence_root(),
            audit_event_root: self.audit_event_root(),
            state_root: String::new(),
        };
        roots.state_root = self.state_root_from_roots(&roots);
        roots
    }

    pub fn counters(&self) -> Counters {
        Counters {
            height: self.height,
            auctions: self.auctions.len() as u64,
            active_auctions: self
                .auctions
                .values()
                .filter(|auction| !auction.status.final_status())
                .count() as u64,
            sealed_bids: self.sealed_bids.len() as u64,
            eligible_bids: self
                .sealed_bids
                .values()
                .filter(|bid| {
                    matches!(
                        bid.status,
                        BidStatus::Eligible
                            | BidStatus::Winning
                            | BidStatus::Sponsored
                            | BidStatus::TranscriptReady
                    )
                })
                .count() as u64,
            winning_bids: self
                .sealed_bids
                .values()
                .filter(|bid| bid.status == BidStatus::Winning)
                .count() as u64,
            bonded_solvers: self.solver_bonds.len() as u64,
            active_solvers: self
                .solver_bonds
                .values()
                .filter(|solver| solver.status == SolverStatus::Active)
                .count() as u64,
            fairness_windows: self.fairness_windows.len() as u64,
            threshold_transcripts: self.threshold_transcripts.len() as u64,
            accepted_transcripts: self
                .threshold_transcripts
                .values()
                .filter(|transcript| transcript.accepted)
                .count() as u64,
            mev_burn_receipts: self.mev_burn_receipts.len() as u64,
            privacy_buckets: self.privacy_buckets.len() as u64,
            sponsor_lanes: self.sponsor_lanes.len() as u64,
            replay_fences: self.replay_fences.len() as u64,
            audit_events: self.audit_events.len() as u64,
            total_burn_amount: self
                .mev_burn_receipts
                .values()
                .map(|receipt| receipt.burn_amount)
                .sum(),
            total_sponsor_credit: self
                .mev_burn_receipts
                .values()
                .map(|receipt| receipt.sponsor_credit_amount)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "pq_private_orderflow_encrypted_auctioneer_state",
            "protocol_version": PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "auctions": self.auctions.values().map(EncryptedAuction::public_record).collect::<Vec<_>>(),
            "sealed_bids": self.sealed_bids.values().map(SealedBid::public_record).collect::<Vec<_>>(),
            "solver_bonds": self.solver_bonds.values().map(SolverBond::public_record).collect::<Vec<_>>(),
            "fairness_windows": self.fairness_windows.values().map(FairnessWindow::public_record).collect::<Vec<_>>(),
            "threshold_transcripts": self.threshold_transcripts.values().map(ThresholdTranscript::public_record).collect::<Vec<_>>(),
            "mev_burn_receipts": self.mev_burn_receipts.values().map(MevBurnReceipt::public_record).collect::<Vec<_>>(),
            "privacy_buckets": self.privacy_buckets.values().map(PrivacyBucket::public_record).collect::<Vec<_>>(),
            "sponsor_lanes": self.sponsor_lanes.values().map(SponsorLane::public_record).collect::<Vec<_>>(),
            "replay_fences": self.replay_fences.values().map(ReplayFence::public_record).collect::<Vec<_>>(),
            "audit_events": self.audit_events.values().map(AuditEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn auction_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-AUCTION-ROOT",
            &self
                .auctions
                .values()
                .map(EncryptedAuction::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sealed_bid_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-SEALED-BID-ROOT",
            &self
                .sealed_bids
                .values()
                .map(SealedBid::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn solver_bond_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-SOLVER-BOND-ROOT",
            &self
                .solver_bonds
                .values()
                .map(SolverBond::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn fairness_window_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-FAIRNESS-WINDOW-ROOT",
            &self
                .fairness_windows
                .values()
                .map(FairnessWindow::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn threshold_transcript_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-THRESHOLD-TRANSCRIPT-ROOT",
            &self
                .threshold_transcripts
                .values()
                .map(ThresholdTranscript::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn mev_burn_receipt_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-MEV-BURN-RECEIPT-ROOT",
            &self
                .mev_burn_receipts
                .values()
                .map(MevBurnReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn privacy_bucket_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-PRIVACY-BUCKET-ROOT",
            &self
                .privacy_buckets
                .values()
                .map(PrivacyBucket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsor_lane_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-SPONSOR-LANE-ROOT",
            &self
                .sponsor_lanes
                .values()
                .map(SponsorLane::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn replay_fence_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-REPLAY-FENCE-ROOT",
            &self
                .replay_fences
                .values()
                .map(ReplayFence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn audit_event_root(&self) -> String {
        merkle_root(
            "PQ-PRIVATE-ORDERFLOW-AUDIT-EVENT-ROOT",
            &self
                .audit_events
                .values()
                .map(AuditEvent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn state_root_from_roots(&self, roots: &Roots) -> String {
        domain_hash(
            "PQ-PRIVATE-ORDERFLOW-ENCRYPTED-AUCTIONEER-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PQ_PRIVATE_ORDERFLOW_ENCRYPTED_AUCTIONEER_PROTOCOL_VERSION),
                HashPart::Str(&self.height.to_string()),
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.auction_root),
                HashPart::Str(&roots.sealed_bid_root),
                HashPart::Str(&roots.solver_bond_root),
                HashPart::Str(&roots.fairness_window_root),
                HashPart::Str(&roots.threshold_transcript_root),
                HashPart::Str(&roots.mev_burn_receipt_root),
                HashPart::Str(&roots.privacy_bucket_root),
                HashPart::Str(&roots.sponsor_lane_root),
                HashPart::Str(&roots.replay_fence_root),
                HashPart::Str(&roots.audit_event_root),
            ],
            32,
        )
    }

    fn prune_expired_replay_fences(&mut self) {
        let height = self.height;
        self.replay_fences
            .retain(|_, fence| fence.expires_at_height >= height);
    }
}

pub fn root_from_record(record: &serde_json::Value) -> String {
    domain_hash(
        "PQ-PRIVATE-ORDERFLOW-ENCRYPTED-AUCTIONEER-RECORD",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> PqPrivateOrderflowEncryptedAuctioneerResult<State> {
    State::devnet()
}

pub fn bid_commitment(
    auction_id: &str,
    solver_id: &str,
    ciphertext_hash: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "PQ-PRIVATE-ORDERFLOW-BID-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(ciphertext_hash),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn nullifier_for_orderflow(
    auction_id: &str,
    solver_id: &str,
    orderflow_secret_commitment: &str,
) -> String {
    domain_hash(
        "PQ-PRIVATE-ORDERFLOW-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(orderflow_secret_commitment),
        ],
        32,
    )
}

pub fn fairness_policy_root(
    lane: AuctionLane,
    min_fairness_score: u64,
    low_fee_reserved_slots: u64,
    policy_commitment: &str,
) -> String {
    domain_hash(
        "PQ-PRIVATE-ORDERFLOW-FAIRNESS-POLICY",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(&min_fairness_score.to_string()),
            HashPart::Str(&low_fee_reserved_slots.to_string()),
            HashPart::Str(policy_commitment),
        ],
        32,
    )
}

fn sample_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PQ-PRIVATE-ORDERFLOW-DEVNET-SAMPLE",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

fn require_nonempty(label: &str, value: &str) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn enforce_len(
    label: &str,
    len: usize,
    max: usize,
) -> PqPrivateOrderflowEncryptedAuctioneerResult<()> {
    if len > max {
        return Err(format!("{label} exceeds maximum length"));
    }
    Ok(())
}
