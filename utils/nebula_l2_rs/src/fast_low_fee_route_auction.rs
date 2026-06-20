use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type FastLowFeeRouteAuctionResult<T> = Result<T, String>;

pub const FAST_LOW_FEE_ROUTE_AUCTION_PROTOCOL_VERSION: &str =
    "nebula-fast-low-fee-route-auction-v1";
pub const PROTOCOL_VERSION: &str = FAST_LOW_FEE_ROUTE_AUCTION_PROTOCOL_VERSION;
pub const FAST_LOW_FEE_ROUTE_AUCTION_SCHEMA_VERSION: u64 = 1;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_HEIGHT: u64 = 1_152;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_BASE_ASSET_ID: &str = "wxmr-devnet";
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const FAST_LOW_FEE_ROUTE_AUCTION_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FAST_LOW_FEE_ROUTE_AUCTION_SEALED_BID_SCHEME: &str =
    "ml-kem-1024+shake256-sealed-route-bid-v1";
pub const FAST_LOW_FEE_ROUTE_AUCTION_SOLVER_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-128f-route-solver-v1";
pub const FAST_LOW_FEE_ROUTE_AUCTION_SETTLEMENT_HINT_SCHEME: &str =
    "private-settlement-hint-root-v1";
pub const FAST_LOW_FEE_ROUTE_AUCTION_MONERO_EXIT_SCHEME: &str =
    "monero-subaddress-lane-commitment-v1";
pub const FAST_LOW_FEE_ROUTE_AUCTION_REBATE_SCHEME: &str = "surplus-rebate-nullifier-commitment-v1";
pub const FAST_LOW_FEE_ROUTE_AUCTION_CHALLENGE_SCHEME: &str = "route-auction-challenge-record-v1";
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_EPOCH_BLOCKS: u64 = 12;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_COMMIT_TTL_BLOCKS: u64 = 8;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_REVEAL_TTL_BLOCKS: u64 = 4;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 36;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_SOLVER_BOND_UNITS: u64 = 50_000_000_000;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_FEE_BPS: u64 = 35;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_MONERO_EXIT_FEE_BPS: u64 = 45;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_SETTLEMENT_HINTS: usize = 64;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_BATCH_ROUTES: usize = 512;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_COMPRESSED_BYTES: usize = 196_608;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_REBATE_SHARE_BPS: u64 = 8_000;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_QOS_SCORE: u64 = 7_000;
pub const FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_TARGET_LATENCY_MS: u64 = 250;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_BPS: u64 = 10_000;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_AUCTIONS: usize = 16_384;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_SOLVERS: usize = 8_192;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_BIDS: usize = 262_144;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_FEE_CAPS: usize = 65_536;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_BATCHES: usize = 65_536;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_HINTS: usize = 262_144;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_MONERO_LANES: usize = 4_096;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_REBATES: usize = 262_144;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_CHALLENGES: usize = 65_536;
pub const FAST_LOW_FEE_ROUTE_AUCTION_MAX_EVENTS: usize = 262_144;
pub const FAST_LOW_FEE_ROUTE_AUCTION_STATE_ACTIVE: &str = "active";
pub const FAST_LOW_FEE_ROUTE_AUCTION_STATE_CHALLENGED: &str = "challenged";
pub const FAST_LOW_FEE_ROUTE_AUCTION_STATE_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteFlowKind {
    Swap,
    MoneroExit,
    ContractCall,
    StableSwap,
    LiquidityUnwind,
    BridgeExit,
    WalletRecovery,
}

impl RouteFlowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::MoneroExit => "monero_exit",
            Self::ContractCall => "contract_call",
            Self::StableSwap => "stable_swap",
            Self::LiquidityUnwind => "liquidity_unwind",
            Self::BridgeExit => "bridge_exit",
            Self::WalletRecovery => "wallet_recovery",
        }
    }

    pub fn default_lane(self) -> RouteLaneKind {
        match self {
            Self::Swap => RouteLaneKind::PrivateSwap,
            Self::MoneroExit => RouteLaneKind::MoneroExit,
            Self::ContractCall => RouteLaneKind::PrivateContract,
            Self::StableSwap => RouteLaneKind::StableLowFee,
            Self::LiquidityUnwind => RouteLaneKind::UrgentExit,
            Self::BridgeExit => RouteLaneKind::BridgeExit,
            Self::WalletRecovery => RouteLaneKind::WalletRecovery,
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::LiquidityUnwind => 1_150,
            Self::MoneroExit => 1_000,
            Self::BridgeExit => 850,
            Self::ContractCall => 740,
            Self::Swap => 620,
            Self::StableSwap => 430,
            Self::WalletRecovery => 380,
        }
    }

    pub fn requires_private_hint(self) -> bool {
        matches!(
            self,
            Self::Swap
                | Self::MoneroExit
                | Self::ContractCall
                | Self::StableSwap
                | Self::WalletRecovery
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLaneKind {
    LowFee,
    StableLowFee,
    PrivateSwap,
    PrivateContract,
    MoneroExit,
    BridgeExit,
    WalletRecovery,
    UrgentExit,
}

impl RouteLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::StableLowFee => "stable_low_fee",
            Self::PrivateSwap => "private_swap",
            Self::PrivateContract => "private_contract",
            Self::MoneroExit => "monero_exit",
            Self::BridgeExit => "bridge_exit",
            Self::WalletRecovery => "wallet_recovery",
            Self::UrgentExit => "urgent_exit",
        }
    }

    pub fn is_monero_exit(self) -> bool {
        matches!(self, Self::MoneroExit | Self::WalletRecovery)
    }

    pub fn low_fee_priority(self) -> u64 {
        match self {
            Self::WalletRecovery => 1_000,
            Self::LowFee => 950,
            Self::StableLowFee => 900,
            Self::MoneroExit => 840,
            Self::PrivateSwap => 760,
            Self::PrivateContract => 700,
            Self::BridgeExit => 650,
            Self::UrgentExit => 500,
        }
    }

    pub fn default_fee_cap_bps(self, config: &FastLowFeeRouteAuctionConfig) -> u64 {
        match self {
            Self::LowFee | Self::StableLowFee | Self::WalletRecovery => config.low_fee_target_bps,
            Self::MoneroExit => config.max_monero_exit_fee_bps,
            Self::UrgentExit => config.max_fee_bps.saturating_add(20),
            Self::PrivateSwap | Self::PrivateContract | Self::BridgeExit => config.max_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    CommitClosed,
    RevealOpen,
    Solving,
    BatchPosted,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::CommitClosed => "commit_closed",
            Self::RevealOpen => "reveal_open",
            Self::Solving => "solving",
            Self::BatchPosted => "batch_posted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_commit(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_reveal(self) -> bool {
        matches!(self, Self::RevealOpen | Self::Solving)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedBidStatus {
    Committed,
    Revealed,
    Eligible,
    Selected,
    Settling,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

impl SealedBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Revealed | Self::Eligible | Self::Selected | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverStatus {
    Bonding,
    Active,
    Throttled,
    Paused,
    Slashed,
    Retired,
}

impl SolverStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bonding => "bonding",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_bid(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    CanonicalJson,
    ZstdCanonicalJson,
    RouteDeltaV1,
    ZkSummaryV1,
}

impl CompressionCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalJson => "canonical_json",
            Self::ZstdCanonicalJson => "zstd_canonical_json",
            Self::RouteDeltaV1 => "route_delta_v1",
            Self::ZkSummaryV1 => "zk_summary_v1",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Compressed,
    HintLocked,
    Posted,
    Settling,
    Settled,
    Challenged,
    Reverted,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Compressed => "compressed",
            Self::HintLocked => "hint_locked",
            Self::Posted => "posted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
        }
    }

    pub fn final_for_rebates(self) -> bool {
        matches!(self, Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStatus {
    Open,
    Locked,
    Consumed,
    Expired,
    Disputed,
}

impl HintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroExitLaneStatus {
    Open,
    Congested,
    Reserved,
    SettlementLocked,
    Draining,
    Paused,
    Closed,
}

impl MoneroExitLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::Reserved => "reserved",
            Self::SettlementLocked => "settlement_locked",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_exits(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Claimed,
    DonatedToFeePool,
    Disputed,
    Voided,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::DonatedToFeePool => "donated_to_fee_pool",
            Self::Disputed => "disputed",
            Self::Voided => "voided",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidReveal,
    FeeCapExceeded,
    QosMisreport,
    HintLeak,
    MoneroLaneFailure,
    CompressionFraud,
    RebateWithheld,
    SettlementTimeout,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidReveal => "invalid_reveal",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::QosMisreport => "qos_misreport",
            Self::HintLeak => "hint_leak",
            Self::MoneroLaneFailure => "monero_lane_failure",
            Self::CompressionFraud => "compression_fraud",
            Self::RebateWithheld => "rebate_withheld",
            Self::SettlementTimeout => "settlement_timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceQueued,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceQueued => "evidence_queued",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLowFeeRouteAuctionConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub epoch_blocks: u64,
    pub commit_ttl_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_solver_bond_units: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub max_monero_exit_fee_bps: u64,
    pub max_settlement_hints: usize,
    pub max_batch_routes: usize,
    pub max_compressed_bytes: usize,
    pub rebate_share_bps: u64,
    pub slash_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_qos_score: u64,
    pub target_latency_ms: u64,
    pub sealed_bid_scheme: String,
    pub solver_auth_scheme: String,
    pub settlement_hint_scheme: String,
    pub monero_exit_scheme: String,
    pub rebate_scheme: String,
    pub challenge_scheme: String,
    pub hash_suite: String,
}

impl Default for FastLowFeeRouteAuctionConfig {
    fn default() -> Self {
        Self {
            protocol_version: FAST_LOW_FEE_ROUTE_AUCTION_PROTOCOL_VERSION.to_string(),
            schema_version: FAST_LOW_FEE_ROUTE_AUCTION_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_FEE_ASSET_ID.to_string(),
            base_asset_id: FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_BASE_ASSET_ID.to_string(),
            quote_asset_id: FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_QUOTE_ASSET_ID.to_string(),
            epoch_blocks: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_EPOCH_BLOCKS,
            commit_ttl_blocks: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_COMMIT_TTL_BLOCKS,
            reveal_ttl_blocks: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_REVEAL_TTL_BLOCKS,
            settlement_ttl_blocks: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            challenge_window_blocks: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_solver_bond_units: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_SOLVER_BOND_UNITS,
            min_pq_security_bits: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_FEE_BPS,
            low_fee_target_bps: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_LOW_FEE_TARGET_BPS,
            max_monero_exit_fee_bps: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_MONERO_EXIT_FEE_BPS,
            max_settlement_hints: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_SETTLEMENT_HINTS,
            max_batch_routes: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_BATCH_ROUTES,
            max_compressed_bytes: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MAX_COMPRESSED_BYTES,
            rebate_share_bps: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_REBATE_SHARE_BPS,
            slash_bps: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_SLASH_BPS,
            min_privacy_set_size: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_qos_score: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_QOS_SCORE,
            target_latency_ms: FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_TARGET_LATENCY_MS,
            sealed_bid_scheme: FAST_LOW_FEE_ROUTE_AUCTION_SEALED_BID_SCHEME.to_string(),
            solver_auth_scheme: FAST_LOW_FEE_ROUTE_AUCTION_SOLVER_AUTH_SCHEME.to_string(),
            settlement_hint_scheme: FAST_LOW_FEE_ROUTE_AUCTION_SETTLEMENT_HINT_SCHEME.to_string(),
            monero_exit_scheme: FAST_LOW_FEE_ROUTE_AUCTION_MONERO_EXIT_SCHEME.to_string(),
            rebate_scheme: FAST_LOW_FEE_ROUTE_AUCTION_REBATE_SCHEME.to_string(),
            challenge_scheme: FAST_LOW_FEE_ROUTE_AUCTION_CHALLENGE_SCHEME.to_string(),
            hash_suite: FAST_LOW_FEE_ROUTE_AUCTION_HASH_SUITE.to_string(),
        }
    }
}

impl FastLowFeeRouteAuctionConfig {
    pub fn validate(&self) -> FastLowFeeRouteAuctionResult<()> {
        if self.protocol_version != FAST_LOW_FEE_ROUTE_AUCTION_PROTOCOL_VERSION {
            return Err("route auction protocol version mismatch".to_string());
        }
        if self.schema_version != FAST_LOW_FEE_ROUTE_AUCTION_SCHEMA_VERSION {
            return Err("route auction schema version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("route auction chain id mismatch".to_string());
        }
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("base_asset_id", &self.base_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        require_non_zero("epoch_blocks", self.epoch_blocks)?;
        require_non_zero("commit_ttl_blocks", self.commit_ttl_blocks)?;
        require_non_zero("reveal_ttl_blocks", self.reveal_ttl_blocks)?;
        require_non_zero("settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        require_non_zero("challenge_window_blocks", self.challenge_window_blocks)?;
        require_non_zero("min_solver_bond_units", self.min_solver_bond_units)?;
        if self.min_pq_security_bits < FAST_LOW_FEE_ROUTE_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("route auction pq security bits below floor".to_string());
        }
        validate_bps("max_fee_bps", self.max_fee_bps)?;
        validate_bps("low_fee_target_bps", self.low_fee_target_bps)?;
        validate_bps("max_monero_exit_fee_bps", self.max_monero_exit_fee_bps)?;
        validate_bps("rebate_share_bps", self.rebate_share_bps)?;
        validate_bps("slash_bps", self.slash_bps)?;
        if self.low_fee_target_bps > self.max_fee_bps {
            return Err("low fee target exceeds max fee cap".to_string());
        }
        if self.max_settlement_hints == 0 || self.max_batch_routes == 0 {
            return Err("route auction batch and hint limits must be non-zero".to_string());
        }
        if self.max_compressed_bytes == 0 {
            return Err("route auction compressed byte limit must be non-zero".to_string());
        }
        require_non_zero("min_privacy_set_size", self.min_privacy_set_size)?;
        require_non_zero("min_qos_score", self.min_qos_score)?;
        require_non_zero("target_latency_ms", self.target_latency_ms)?;
        require_non_empty("sealed_bid_scheme", &self.sealed_bid_scheme)?;
        require_non_empty("solver_auth_scheme", &self.solver_auth_scheme)?;
        require_non_empty("settlement_hint_scheme", &self.settlement_hint_scheme)?;
        require_non_empty("monero_exit_scheme", &self.monero_exit_scheme)?;
        require_non_empty("rebate_scheme", &self.rebate_scheme)?;
        require_non_empty("challenge_scheme", &self.challenge_scheme)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "commit_ttl_blocks": self.commit_ttl_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_solver_bond_units": self.min_solver_bond_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "max_monero_exit_fee_bps": self.max_monero_exit_fee_bps,
            "max_settlement_hints": self.max_settlement_hints,
            "max_batch_routes": self.max_batch_routes,
            "max_compressed_bytes": self.max_compressed_bytes,
            "rebate_share_bps": self.rebate_share_bps,
            "slash_bps": self.slash_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_qos_score": self.min_qos_score,
            "target_latency_ms": self.target_latency_ms,
            "sealed_bid_scheme": self.sealed_bid_scheme,
            "solver_auth_scheme": self.solver_auth_scheme,
            "settlement_hint_scheme": self.settlement_hint_scheme,
            "monero_exit_scheme": self.monero_exit_scheme,
            "rebate_scheme": self.rebate_scheme,
            "challenge_scheme": self.challenge_scheme,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-AUCTION-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAuction {
    pub auction_id: String,
    pub epoch: u64,
    pub flow_kind: RouteFlowKind,
    pub lane_kind: RouteLaneKind,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub fee_asset_id: String,
    pub notional_units: u128,
    pub min_output_units_commitment: String,
    pub fee_cap_id: String,
    pub private_intent_root: String,
    pub solver_allowlist_root: String,
    pub opened_height: u64,
    pub commit_deadline_height: u64,
    pub reveal_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub challenge_deadline_height: u64,
    pub status: AuctionStatus,
    pub winning_batch_id: String,
    pub metadata_root: String,
}

impl RouteAuction {
    pub fn new(
        epoch: u64,
        flow_kind: RouteFlowKind,
        input_asset_id: &str,
        output_asset_id: &str,
        notional_units: u128,
        min_output_units_commitment: &str,
        fee_cap_id: &str,
        private_intent_root: &str,
        opened_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        config.validate()?;
        require_non_empty("input_asset_id", input_asset_id)?;
        require_non_empty("output_asset_id", output_asset_id)?;
        require_non_empty("min_output_units_commitment", min_output_units_commitment)?;
        require_non_empty("fee_cap_id", fee_cap_id)?;
        require_non_empty("private_intent_root", private_intent_root)?;
        require_non_zero_u128("notional_units", notional_units)?;
        let lane_kind = flow_kind.default_lane();
        let commit_deadline_height = opened_height.saturating_add(config.commit_ttl_blocks);
        let reveal_deadline_height =
            commit_deadline_height.saturating_add(config.reveal_ttl_blocks);
        let settlement_deadline_height =
            reveal_deadline_height.saturating_add(config.settlement_ttl_blocks);
        let challenge_deadline_height =
            settlement_deadline_height.saturating_add(config.challenge_window_blocks);
        let metadata_root = route_auction_metadata_root(&json!({
            "lane": lane_kind.as_str(),
            "flow": flow_kind.as_str(),
            "privacy_required": flow_kind.requires_private_hint(),
        }));
        let auction_id = derive_auction_id(
            epoch,
            flow_kind,
            lane_kind,
            input_asset_id,
            output_asset_id,
            notional_units,
            min_output_units_commitment,
            fee_cap_id,
            private_intent_root,
            opened_height,
            &metadata_root,
        );
        Ok(Self {
            auction_id,
            epoch,
            flow_kind,
            lane_kind,
            input_asset_id: input_asset_id.to_string(),
            output_asset_id: output_asset_id.to_string(),
            fee_asset_id: config.fee_asset_id.clone(),
            notional_units,
            min_output_units_commitment: min_output_units_commitment.to_string(),
            fee_cap_id: fee_cap_id.to_string(),
            private_intent_root: private_intent_root.to_string(),
            solver_allowlist_root: merkle_root("FAST-LOW-FEE-ROUTE-AUCTION-ALLOWLIST", &[]),
            opened_height,
            commit_deadline_height,
            reveal_deadline_height,
            settlement_deadline_height,
            challenge_deadline_height,
            status: AuctionStatus::Open,
            winning_batch_id: String::new(),
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "epoch": self.epoch,
            "flow_kind": self.flow_kind.as_str(),
            "lane_kind": self.lane_kind.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "notional_units": self.notional_units.to_string(),
            "min_output_units_commitment": self.min_output_units_commitment,
            "fee_cap_id": self.fee_cap_id,
            "private_intent_root": self.private_intent_root,
            "solver_allowlist_root": self.solver_allowlist_root,
            "opened_height": self.opened_height,
            "commit_deadline_height": self.commit_deadline_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "status": self.status.as_str(),
            "winning_batch_id": self.winning_batch_id,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-AUCTION", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("auction_id", &self.auction_id)?;
        require_non_empty("input_asset_id", &self.input_asset_id)?;
        require_non_empty("output_asset_id", &self.output_asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty(
            "min_output_units_commitment",
            &self.min_output_units_commitment,
        )?;
        require_non_empty("fee_cap_id", &self.fee_cap_id)?;
        require_non_empty("private_intent_root", &self.private_intent_root)?;
        require_non_empty("solver_allowlist_root", &self.solver_allowlist_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero_u128("notional_units", self.notional_units)?;
        if self.fee_asset_id != config.fee_asset_id {
            return Err("auction fee asset does not match config".to_string());
        }
        if self.commit_deadline_height < self.opened_height {
            return Err("auction commit deadline before open height".to_string());
        }
        if self.reveal_deadline_height < self.commit_deadline_height {
            return Err("auction reveal deadline before commit deadline".to_string());
        }
        if self.settlement_deadline_height < self.reveal_deadline_height {
            return Err("auction settlement deadline before reveal deadline".to_string());
        }
        if self.challenge_deadline_height < self.settlement_deadline_height {
            return Err("auction challenge deadline before settlement deadline".to_string());
        }
        if self.status.terminal()
            && self.winning_batch_id.is_empty()
            && self.status == AuctionStatus::Settled
        {
            return Err("settled auction missing winning batch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteFeeCap {
    pub fee_cap_id: String,
    pub lane_kind: RouteLaneKind,
    pub payer_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub max_fee_units: u64,
    pub low_fee_sponsor_units: u64,
    pub rebate_share_bps: u64,
    pub expires_at_height: u64,
    pub policy_root: String,
    pub metadata_root: String,
}

impl RouteFeeCap {
    pub fn new(
        lane_kind: RouteLaneKind,
        payer_commitment: &str,
        max_fee_units: u64,
        low_fee_sponsor_units: u64,
        expires_at_height: u64,
        policy_root: &str,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        config.validate()?;
        require_non_empty("payer_commitment", payer_commitment)?;
        require_non_empty("policy_root", policy_root)?;
        require_non_zero("max_fee_units", max_fee_units)?;
        require_non_zero("expires_at_height", expires_at_height)?;
        let max_fee_bps = lane_kind.default_fee_cap_bps(config);
        let metadata_root = route_auction_metadata_root(&json!({
            "fee_cap_policy": "low_fee_route_cap",
            "lane_kind": lane_kind.as_str(),
        }));
        let fee_cap_id = derive_fee_cap_id(
            lane_kind,
            payer_commitment,
            &config.fee_asset_id,
            max_fee_bps,
            max_fee_units,
            low_fee_sponsor_units,
            expires_at_height,
            policy_root,
            &metadata_root,
        );
        Ok(Self {
            fee_cap_id,
            lane_kind,
            payer_commitment: payer_commitment.to_string(),
            fee_asset_id: config.fee_asset_id.clone(),
            max_fee_bps,
            max_fee_units,
            low_fee_sponsor_units,
            rebate_share_bps: config.rebate_share_bps,
            expires_at_height,
            policy_root: policy_root.to_string(),
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "lane_kind": self.lane_kind.as_str(),
            "payer_commitment": self.payer_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "max_fee_units": self.max_fee_units,
            "low_fee_sponsor_units": self.low_fee_sponsor_units,
            "rebate_share_bps": self.rebate_share_bps,
            "expires_at_height": self.expires_at_height,
            "policy_root": self.policy_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-FEE-CAP", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("fee_cap_id", &self.fee_cap_id)?;
        require_non_empty("payer_commitment", &self.payer_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("policy_root", &self.policy_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("max_fee_units", self.max_fee_units)?;
        require_non_zero("expires_at_height", self.expires_at_height)?;
        validate_bps("max_fee_bps", self.max_fee_bps)?;
        validate_bps("rebate_share_bps", self.rebate_share_bps)?;
        if self.max_fee_bps > config.max_monero_exit_fee_bps && self.lane_kind.is_monero_exit() {
            return Err("monero exit fee cap exceeds configured monero lane cap".to_string());
        }
        if !self.lane_kind.is_monero_exit()
            && self.max_fee_bps > config.max_fee_bps.saturating_add(20)
        {
            return Err("route fee cap exceeds configured route fee cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverQos {
    pub solver_id: String,
    pub status: SolverStatus,
    pub bond_asset_id: String,
    pub bonded_units: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub lane_permissions: BTreeSet<RouteLaneKind>,
    pub successful_routes: u64,
    pub failed_routes: u64,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub privacy_incidents: u64,
    pub fee_cap_violations: u64,
    pub qos_score: u64,
    pub last_updated_height: u64,
    pub metadata_root: String,
}

impl SolverQos {
    pub fn new(
        solver_label: &str,
        bonded_units: u64,
        pq_security_bits: u16,
        lane_permissions: BTreeSet<RouteLaneKind>,
        attestation_root: &str,
        height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        config.validate()?;
        require_non_empty("solver_label", solver_label)?;
        require_non_empty("attestation_root", attestation_root)?;
        require_non_zero("bonded_units", bonded_units)?;
        require_non_zero("height", height)?;
        if bonded_units < config.min_solver_bond_units {
            return Err("solver bond below route auction minimum".to_string());
        }
        if pq_security_bits < config.min_pq_security_bits {
            return Err("solver pq security bits below route auction minimum".to_string());
        }
        if lane_permissions.is_empty() {
            return Err("solver must have at least one lane permission".to_string());
        }
        let metadata_root = route_auction_metadata_root(&json!({
            "solver_label": solver_label,
            "auth_scheme": config.solver_auth_scheme,
        }));
        let solver_id = derive_solver_id(
            solver_label,
            bonded_units,
            pq_security_bits,
            attestation_root,
            height,
            &metadata_root,
        );
        Ok(Self {
            solver_id,
            status: SolverStatus::Active,
            bond_asset_id: config.fee_asset_id.clone(),
            bonded_units,
            pq_security_bits,
            attestation_root: attestation_root.to_string(),
            lane_permissions,
            successful_routes: 0,
            failed_routes: 0,
            median_latency_ms: config.target_latency_ms,
            p95_latency_ms: config.target_latency_ms.saturating_mul(2),
            privacy_incidents: 0,
            fee_cap_violations: 0,
            qos_score: 10_000,
            last_updated_height: height,
            metadata_root,
        })
    }

    pub fn can_bid_lane(
        &self,
        lane_kind: RouteLaneKind,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> bool {
        self.status.can_bid()
            && self.qos_score >= config.min_qos_score
            && self.lane_permissions.contains(&lane_kind)
            && self.privacy_incidents == 0
    }

    pub fn record_route_result(
        &mut self,
        success: bool,
        latency_ms: u64,
        privacy_incident: bool,
        fee_cap_violation: bool,
        height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_zero("height", height)?;
        if success {
            self.successful_routes = self.successful_routes.saturating_add(1);
        } else {
            self.failed_routes = self.failed_routes.saturating_add(1);
        }
        self.median_latency_ms = rolling_average(self.median_latency_ms, latency_ms);
        self.p95_latency_ms = self.p95_latency_ms.max(latency_ms);
        if privacy_incident {
            self.privacy_incidents = self.privacy_incidents.saturating_add(1);
        }
        if fee_cap_violation {
            self.fee_cap_violations = self.fee_cap_violations.saturating_add(1);
        }
        self.qos_score = compute_qos_score(
            self.successful_routes,
            self.failed_routes,
            self.median_latency_ms,
            self.p95_latency_ms,
            self.privacy_incidents,
            self.fee_cap_violations,
            config.target_latency_ms,
        );
        self.last_updated_height = height;
        if self.qos_score < config.min_qos_score {
            self.status = SolverStatus::Throttled;
        }
        if self.privacy_incidents > 0 || self.fee_cap_violations > 2 {
            self.status = SolverStatus::Paused;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let lane_permissions = self
            .lane_permissions
            .iter()
            .map(|lane| Value::String(lane.as_str().to_string()))
            .collect::<Vec<_>>();
        json!({
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "bond_asset_id": self.bond_asset_id,
            "bonded_units": self.bonded_units,
            "pq_security_bits": self.pq_security_bits,
            "attestation_root": self.attestation_root,
            "lane_permissions": lane_permissions,
            "successful_routes": self.successful_routes,
            "failed_routes": self.failed_routes,
            "median_latency_ms": self.median_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "privacy_incidents": self.privacy_incidents,
            "fee_cap_violations": self.fee_cap_violations,
            "qos_score": self.qos_score,
            "last_updated_height": self.last_updated_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-SOLVER-QOS", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("bond_asset_id", &self.bond_asset_id)?;
        require_non_empty("attestation_root", &self.attestation_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("bonded_units", self.bonded_units)?;
        require_non_zero("last_updated_height", self.last_updated_height)?;
        if self.bonded_units < config.min_solver_bond_units {
            return Err("solver bond below configured minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("solver pq security below configured minimum".to_string());
        }
        if self.lane_permissions.is_empty() {
            return Err("solver lane permission set is empty".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRouteBid {
    pub bid_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub lane_kind: RouteLaneKind,
    pub commitment_hash: String,
    pub encrypted_route_hint_root: String,
    pub fee_bid_bps: u64,
    pub max_fee_units: u64,
    pub expected_output_commitment: String,
    pub solver_qos_score: u64,
    pub submitted_height: u64,
    pub reveal_deadline_height: u64,
    pub status: SealedBidStatus,
    pub reveal_hash: String,
    pub metadata_root: String,
}

impl SealedRouteBid {
    pub fn commit(
        auction: &RouteAuction,
        solver: &SolverQos,
        commitment_hash: &str,
        encrypted_route_hint_root: &str,
        fee_bid_bps: u64,
        max_fee_units: u64,
        expected_output_commitment: &str,
        submitted_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        auction.validate(config)?;
        solver.validate(config)?;
        require_non_empty("commitment_hash", commitment_hash)?;
        require_non_empty("encrypted_route_hint_root", encrypted_route_hint_root)?;
        require_non_empty("expected_output_commitment", expected_output_commitment)?;
        require_non_zero("max_fee_units", max_fee_units)?;
        require_non_zero("submitted_height", submitted_height)?;
        validate_bps("fee_bid_bps", fee_bid_bps)?;
        if !auction.status.accepts_commit() {
            return Err("auction does not accept bid commitments".to_string());
        }
        if submitted_height > auction.commit_deadline_height {
            return Err("sealed bid submitted after commit deadline".to_string());
        }
        if !solver.can_bid_lane(auction.lane_kind, config) {
            return Err("solver is not eligible for auction lane".to_string());
        }
        if fee_bid_bps > auction.lane_kind.default_fee_cap_bps(config) {
            return Err("sealed bid exceeds lane fee cap".to_string());
        }
        let metadata_root = route_auction_metadata_root(&json!({
            "sealed_bid_scheme": config.sealed_bid_scheme,
            "lane_kind": auction.lane_kind.as_str(),
        }));
        let bid_id = derive_bid_id(
            &auction.auction_id,
            &solver.solver_id,
            auction.lane_kind,
            commitment_hash,
            encrypted_route_hint_root,
            fee_bid_bps,
            max_fee_units,
            expected_output_commitment,
            submitted_height,
            &metadata_root,
        );
        Ok(Self {
            bid_id,
            auction_id: auction.auction_id.clone(),
            solver_id: solver.solver_id.clone(),
            lane_kind: auction.lane_kind,
            commitment_hash: commitment_hash.to_string(),
            encrypted_route_hint_root: encrypted_route_hint_root.to_string(),
            fee_bid_bps,
            max_fee_units,
            expected_output_commitment: expected_output_commitment.to_string(),
            solver_qos_score: solver.qos_score,
            submitted_height,
            reveal_deadline_height: auction.reveal_deadline_height,
            status: SealedBidStatus::Committed,
            reveal_hash: String::new(),
            metadata_root,
        })
    }

    pub fn reveal(
        &mut self,
        reveal_payload_root: &str,
        height: u64,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("reveal_payload_root", reveal_payload_root)?;
        require_non_zero("height", height)?;
        if self.status != SealedBidStatus::Committed {
            return Err("sealed bid is not in committed status".to_string());
        }
        if height > self.reveal_deadline_height {
            self.status = SealedBidStatus::Expired;
            return Err("sealed bid reveal after deadline".to_string());
        }
        self.reveal_hash = derive_bid_reveal_hash(&self.bid_id, reveal_payload_root, height);
        self.status = SealedBidStatus::Revealed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "lane_kind": self.lane_kind.as_str(),
            "commitment_hash": self.commitment_hash,
            "encrypted_route_hint_root": self.encrypted_route_hint_root,
            "fee_bid_bps": self.fee_bid_bps,
            "max_fee_units": self.max_fee_units,
            "expected_output_commitment": self.expected_output_commitment,
            "solver_qos_score": self.solver_qos_score,
            "submitted_height": self.submitted_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "status": self.status.as_str(),
            "reveal_hash": self.reveal_hash,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-SEALED-BID", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("bid_id", &self.bid_id)?;
        require_non_empty("auction_id", &self.auction_id)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("commitment_hash", &self.commitment_hash)?;
        require_non_empty("encrypted_route_hint_root", &self.encrypted_route_hint_root)?;
        require_non_empty(
            "expected_output_commitment",
            &self.expected_output_commitment,
        )?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("max_fee_units", self.max_fee_units)?;
        require_non_zero("submitted_height", self.submitted_height)?;
        validate_bps("fee_bid_bps", self.fee_bid_bps)?;
        if self.fee_bid_bps > self.lane_kind.default_fee_cap_bps(config) {
            return Err("sealed bid fee exceeds configured lane cap".to_string());
        }
        if self.status != SealedBidStatus::Committed {
            require_non_empty("reveal_hash", &self.reveal_hash)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementHint {
    pub hint_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub solver_id: String,
    pub encrypted_hint_root: String,
    pub nullifier_root: String,
    pub relay_path_root: String,
    pub privacy_set_size: u64,
    pub expiry_height: u64,
    pub status: HintStatus,
    pub metadata_root: String,
}

impl PrivateSettlementHint {
    pub fn new(
        auction_id: &str,
        bid_id: &str,
        solver_id: &str,
        encrypted_hint_root: &str,
        nullifier_root: &str,
        relay_path_root: &str,
        privacy_set_size: u64,
        expiry_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        require_non_empty("auction_id", auction_id)?;
        require_non_empty("bid_id", bid_id)?;
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("encrypted_hint_root", encrypted_hint_root)?;
        require_non_empty("nullifier_root", nullifier_root)?;
        require_non_empty("relay_path_root", relay_path_root)?;
        require_non_zero("privacy_set_size", privacy_set_size)?;
        require_non_zero("expiry_height", expiry_height)?;
        if privacy_set_size < config.min_privacy_set_size {
            return Err("settlement hint privacy set below configured minimum".to_string());
        }
        let metadata_root = route_auction_metadata_root(&json!({
            "settlement_hint_scheme": config.settlement_hint_scheme,
            "hint_visibility": "encrypted",
        }));
        let hint_id = derive_hint_id(
            auction_id,
            bid_id,
            solver_id,
            encrypted_hint_root,
            nullifier_root,
            relay_path_root,
            privacy_set_size,
            expiry_height,
            &metadata_root,
        );
        Ok(Self {
            hint_id,
            auction_id: auction_id.to_string(),
            bid_id: bid_id.to_string(),
            solver_id: solver_id.to_string(),
            encrypted_hint_root: encrypted_hint_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            relay_path_root: relay_path_root.to_string(),
            privacy_set_size,
            expiry_height,
            status: HintStatus::Open,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "solver_id": self.solver_id,
            "encrypted_hint_root": self.encrypted_hint_root,
            "nullifier_root": self.nullifier_root,
            "relay_path_root": self.relay_path_root,
            "privacy_set_size": self.privacy_set_size,
            "expiry_height": self.expiry_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-SETTLEMENT-HINT", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("hint_id", &self.hint_id)?;
        require_non_empty("auction_id", &self.auction_id)?;
        require_non_empty("bid_id", &self.bid_id)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("encrypted_hint_root", &self.encrypted_hint_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        require_non_empty("relay_path_root", &self.relay_path_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("privacy_set_size", self.privacy_set_size)?;
        require_non_zero("expiry_height", self.expiry_height)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("settlement hint privacy set below minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitLane {
    pub lane_id: String,
    pub monero_network: String,
    pub lane_kind: RouteLaneKind,
    pub subaddress_view_tag_root: String,
    pub reserve_commitment_root: String,
    pub fee_oracle_root: String,
    pub available_liquidity_atomic_units: u128,
    pub reserved_liquidity_atomic_units: u128,
    pub max_exit_fee_bps: u64,
    pub target_confirmation_blocks: u64,
    pub status: MoneroExitLaneStatus,
    pub opened_height: u64,
    pub metadata_root: String,
}

impl MoneroExitLane {
    pub fn new(
        monero_network: &str,
        lane_kind: RouteLaneKind,
        subaddress_view_tag_root: &str,
        reserve_commitment_root: &str,
        fee_oracle_root: &str,
        available_liquidity_atomic_units: u128,
        target_confirmation_blocks: u64,
        opened_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        require_non_empty("monero_network", monero_network)?;
        require_non_empty("subaddress_view_tag_root", subaddress_view_tag_root)?;
        require_non_empty("reserve_commitment_root", reserve_commitment_root)?;
        require_non_empty("fee_oracle_root", fee_oracle_root)?;
        require_non_zero_u128(
            "available_liquidity_atomic_units",
            available_liquidity_atomic_units,
        )?;
        require_non_zero("target_confirmation_blocks", target_confirmation_blocks)?;
        require_non_zero("opened_height", opened_height)?;
        if !lane_kind.is_monero_exit() {
            return Err("monero exit lane must use monero-compatible lane kind".to_string());
        }
        let metadata_root = route_auction_metadata_root(&json!({
            "monero_exit_scheme": config.monero_exit_scheme,
            "network": monero_network,
        }));
        let lane_id = derive_monero_lane_id(
            monero_network,
            lane_kind,
            subaddress_view_tag_root,
            reserve_commitment_root,
            fee_oracle_root,
            available_liquidity_atomic_units,
            target_confirmation_blocks,
            opened_height,
            &metadata_root,
        );
        Ok(Self {
            lane_id,
            monero_network: monero_network.to_string(),
            lane_kind,
            subaddress_view_tag_root: subaddress_view_tag_root.to_string(),
            reserve_commitment_root: reserve_commitment_root.to_string(),
            fee_oracle_root: fee_oracle_root.to_string(),
            available_liquidity_atomic_units,
            reserved_liquidity_atomic_units: 0,
            max_exit_fee_bps: config.max_monero_exit_fee_bps,
            target_confirmation_blocks,
            status: MoneroExitLaneStatus::Open,
            opened_height,
            metadata_root,
        })
    }

    pub fn reserve(&mut self, amount_atomic_units: u128) -> FastLowFeeRouteAuctionResult<()> {
        require_non_zero_u128("amount_atomic_units", amount_atomic_units)?;
        if !self.status.accepts_exits() {
            return Err("monero exit lane does not accept reservations".to_string());
        }
        let available_after_reserved = self
            .available_liquidity_atomic_units
            .saturating_sub(self.reserved_liquidity_atomic_units);
        if amount_atomic_units > available_after_reserved {
            return Err("monero exit lane has insufficient unreserved liquidity".to_string());
        }
        self.reserved_liquidity_atomic_units = self
            .reserved_liquidity_atomic_units
            .saturating_add(amount_atomic_units);
        if self.reserved_liquidity_atomic_units >= self.available_liquidity_atomic_units {
            self.status = MoneroExitLaneStatus::Reserved;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "monero_network": self.monero_network,
            "lane_kind": self.lane_kind.as_str(),
            "subaddress_view_tag_root": self.subaddress_view_tag_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "fee_oracle_root": self.fee_oracle_root,
            "available_liquidity_atomic_units": self.available_liquidity_atomic_units.to_string(),
            "reserved_liquidity_atomic_units": self.reserved_liquidity_atomic_units.to_string(),
            "max_exit_fee_bps": self.max_exit_fee_bps,
            "target_confirmation_blocks": self.target_confirmation_blocks,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-MONERO-EXIT-LANE", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("subaddress_view_tag_root", &self.subaddress_view_tag_root)?;
        require_non_empty("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_non_empty("fee_oracle_root", &self.fee_oracle_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero_u128(
            "available_liquidity_atomic_units",
            self.available_liquidity_atomic_units,
        )?;
        require_non_zero(
            "target_confirmation_blocks",
            self.target_confirmation_blocks,
        )?;
        require_non_zero("opened_height", self.opened_height)?;
        validate_bps("max_exit_fee_bps", self.max_exit_fee_bps)?;
        if !self.lane_kind.is_monero_exit() {
            return Err("monero lane uses non-monero route lane".to_string());
        }
        if self.max_exit_fee_bps > config.max_monero_exit_fee_bps {
            return Err("monero lane fee cap exceeds config".to_string());
        }
        if self.reserved_liquidity_atomic_units > self.available_liquidity_atomic_units {
            return Err("monero lane reserved liquidity exceeds available liquidity".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedRouteBatch {
    pub batch_id: String,
    pub auction_ids: BTreeSet<String>,
    pub selected_bid_ids: BTreeSet<String>,
    pub solver_id: String,
    pub lane_kind: RouteLaneKind,
    pub codec: CompressionCodec,
    pub uncompressed_route_root: String,
    pub compressed_payload_root: String,
    pub settlement_hint_root: String,
    pub monero_exit_lane_root: String,
    pub fee_cap_root: String,
    pub route_count: usize,
    pub compressed_bytes: usize,
    pub aggregate_fee_units: u64,
    pub aggregate_rebate_units: u64,
    pub posted_height: u64,
    pub settlement_deadline_height: u64,
    pub status: BatchStatus,
    pub metadata_root: String,
}

impl CompressedRouteBatch {
    pub fn new(
        selected_bids: &[SealedRouteBid],
        solver_id: &str,
        lane_kind: RouteLaneKind,
        codec: CompressionCodec,
        uncompressed_route_root: &str,
        compressed_payload_root: &str,
        settlement_hint_root: &str,
        monero_exit_lane_root: &str,
        fee_cap_root: &str,
        compressed_bytes: usize,
        posted_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("uncompressed_route_root", uncompressed_route_root)?;
        require_non_empty("compressed_payload_root", compressed_payload_root)?;
        require_non_empty("settlement_hint_root", settlement_hint_root)?;
        require_non_empty("monero_exit_lane_root", monero_exit_lane_root)?;
        require_non_empty("fee_cap_root", fee_cap_root)?;
        require_non_zero("posted_height", posted_height)?;
        if selected_bids.is_empty() {
            return Err("compressed route batch requires at least one selected bid".to_string());
        }
        if selected_bids.len() > config.max_batch_routes {
            return Err("compressed route batch exceeds max route count".to_string());
        }
        if compressed_bytes == 0 || compressed_bytes > config.max_compressed_bytes {
            return Err("compressed route batch byte size outside configured bounds".to_string());
        }
        let mut auction_ids = BTreeSet::new();
        let mut selected_bid_ids = BTreeSet::new();
        let mut aggregate_fee_units = 0_u64;
        for bid in selected_bids {
            bid.validate(config)?;
            if bid.solver_id != solver_id {
                return Err("batch selected bid solver mismatch".to_string());
            }
            if bid.lane_kind != lane_kind {
                return Err("batch selected bid lane mismatch".to_string());
            }
            auction_ids.insert(bid.auction_id.clone());
            selected_bid_ids.insert(bid.bid_id.clone());
            aggregate_fee_units = aggregate_fee_units.saturating_add(bid.max_fee_units);
        }
        let aggregate_rebate_units =
            compute_rebate_units(aggregate_fee_units, config.rebate_share_bps);
        let metadata_root = route_auction_metadata_root(&json!({
            "codec": codec.as_str(),
            "lane_kind": lane_kind.as_str(),
            "batch_kind": "fast_low_fee_route",
        }));
        let settlement_deadline_height = posted_height.saturating_add(config.settlement_ttl_blocks);
        let batch_id = derive_batch_id(
            &auction_ids,
            &selected_bid_ids,
            solver_id,
            lane_kind,
            codec,
            uncompressed_route_root,
            compressed_payload_root,
            settlement_hint_root,
            monero_exit_lane_root,
            fee_cap_root,
            posted_height,
            &metadata_root,
        );
        Ok(Self {
            batch_id,
            auction_ids,
            selected_bid_ids,
            solver_id: solver_id.to_string(),
            lane_kind,
            codec,
            uncompressed_route_root: uncompressed_route_root.to_string(),
            compressed_payload_root: compressed_payload_root.to_string(),
            settlement_hint_root: settlement_hint_root.to_string(),
            monero_exit_lane_root: monero_exit_lane_root.to_string(),
            fee_cap_root: fee_cap_root.to_string(),
            route_count: selected_bids.len(),
            compressed_bytes,
            aggregate_fee_units,
            aggregate_rebate_units,
            posted_height,
            settlement_deadline_height,
            status: BatchStatus::Compressed,
            metadata_root,
        })
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.route_count == 0 || self.compressed_bytes == 0 {
            return 0;
        }
        let nominal_uncompressed = (self.route_count as u64).saturating_mul(512);
        if nominal_uncompressed == 0 {
            return 0;
        }
        ((self.compressed_bytes as u64).saturating_mul(FAST_LOW_FEE_ROUTE_AUCTION_MAX_BPS))
            / nominal_uncompressed
    }

    pub fn public_record(&self) -> Value {
        let auction_ids = self
            .auction_ids
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        let selected_bid_ids = self
            .selected_bid_ids
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        json!({
            "batch_id": self.batch_id,
            "auction_ids": auction_ids,
            "selected_bid_ids": selected_bid_ids,
            "solver_id": self.solver_id,
            "lane_kind": self.lane_kind.as_str(),
            "codec": self.codec.as_str(),
            "uncompressed_route_root": self.uncompressed_route_root,
            "compressed_payload_root": self.compressed_payload_root,
            "settlement_hint_root": self.settlement_hint_root,
            "monero_exit_lane_root": self.monero_exit_lane_root,
            "fee_cap_root": self.fee_cap_root,
            "route_count": self.route_count,
            "compressed_bytes": self.compressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "aggregate_fee_units": self.aggregate_fee_units,
            "aggregate_rebate_units": self.aggregate_rebate_units,
            "posted_height": self.posted_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-COMPRESSED-BATCH", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("uncompressed_route_root", &self.uncompressed_route_root)?;
        require_non_empty("compressed_payload_root", &self.compressed_payload_root)?;
        require_non_empty("settlement_hint_root", &self.settlement_hint_root)?;
        require_non_empty("monero_exit_lane_root", &self.monero_exit_lane_root)?;
        require_non_empty("fee_cap_root", &self.fee_cap_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("posted_height", self.posted_height)?;
        if self.auction_ids.is_empty() || self.selected_bid_ids.is_empty() {
            return Err("compressed batch has empty route or bid set".to_string());
        }
        if self.route_count == 0 || self.route_count > config.max_batch_routes {
            return Err("compressed batch route count outside configured bounds".to_string());
        }
        if self.compressed_bytes == 0 || self.compressed_bytes > config.max_compressed_bytes {
            return Err("compressed batch bytes outside configured bounds".to_string());
        }
        if self.settlement_deadline_height < self.posted_height {
            return Err("compressed batch settlement deadline before post height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateAccountingEntry {
    pub rebate_id: String,
    pub batch_id: String,
    pub auction_id: String,
    pub payer_commitment: String,
    pub solver_id: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub claim_nullifier_hash: String,
    pub status: RebateStatus,
    pub accrued_height: u64,
    pub claim_deadline_height: u64,
    pub metadata_root: String,
}

impl RebateAccountingEntry {
    pub fn new(
        batch_id: &str,
        auction_id: &str,
        payer_commitment: &str,
        solver_id: &str,
        gross_fee_units: u64,
        claim_nullifier_hash: &str,
        accrued_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        require_non_empty("batch_id", batch_id)?;
        require_non_empty("auction_id", auction_id)?;
        require_non_empty("payer_commitment", payer_commitment)?;
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("claim_nullifier_hash", claim_nullifier_hash)?;
        require_non_zero("gross_fee_units", gross_fee_units)?;
        require_non_zero("accrued_height", accrued_height)?;
        let rebate_units = compute_rebate_units(gross_fee_units, config.rebate_share_bps);
        let claim_deadline_height =
            accrued_height.saturating_add(config.challenge_window_blocks.saturating_mul(10));
        let metadata_root = route_auction_metadata_root(&json!({
            "rebate_scheme": config.rebate_scheme,
            "rebate_share_bps": config.rebate_share_bps,
        }));
        let rebate_id = derive_rebate_id(
            batch_id,
            auction_id,
            payer_commitment,
            solver_id,
            &config.fee_asset_id,
            gross_fee_units,
            rebate_units,
            claim_nullifier_hash,
            accrued_height,
            &metadata_root,
        );
        Ok(Self {
            rebate_id,
            batch_id: batch_id.to_string(),
            auction_id: auction_id.to_string(),
            payer_commitment: payer_commitment.to_string(),
            solver_id: solver_id.to_string(),
            fee_asset_id: config.fee_asset_id.clone(),
            gross_fee_units,
            rebate_units,
            claim_nullifier_hash: claim_nullifier_hash.to_string(),
            status: RebateStatus::Accrued,
            accrued_height,
            claim_deadline_height,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "auction_id": self.auction_id,
            "payer_commitment": self.payer_commitment,
            "solver_id": self.solver_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "claim_nullifier_hash": self.claim_nullifier_hash,
            "status": self.status.as_str(),
            "accrued_height": self.accrued_height,
            "claim_deadline_height": self.claim_deadline_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-REBATE", &self.public_record())
    }

    pub fn validate(&self) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("rebate_id", &self.rebate_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("auction_id", &self.auction_id)?;
        require_non_empty("payer_commitment", &self.payer_commitment)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("claim_nullifier_hash", &self.claim_nullifier_hash)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("gross_fee_units", self.gross_fee_units)?;
        require_non_zero("accrued_height", self.accrued_height)?;
        if self.rebate_units > self.gross_fee_units {
            return Err("rebate exceeds gross fee".to_string());
        }
        if self.claim_deadline_height < self.accrued_height {
            return Err("rebate claim deadline before accrual height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub target_id: String,
    pub challenger_commitment: String,
    pub solver_id: String,
    pub evidence_root: String,
    pub claimed_loss_units: u64,
    pub slash_units: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub resolution_root: String,
    pub metadata_root: String,
}

impl ChallengeRecord {
    pub fn new(
        kind: ChallengeKind,
        target_id: &str,
        challenger_commitment: &str,
        solver_id: &str,
        evidence_root: &str,
        claimed_loss_units: u64,
        opened_height: u64,
        config: &FastLowFeeRouteAuctionConfig,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        require_non_empty("target_id", target_id)?;
        require_non_empty("challenger_commitment", challenger_commitment)?;
        require_non_empty("solver_id", solver_id)?;
        require_non_empty("evidence_root", evidence_root)?;
        require_non_zero("opened_height", opened_height)?;
        let slash_units = compute_rebate_units(claimed_loss_units, config.slash_bps);
        let deadline_height = opened_height.saturating_add(config.challenge_window_blocks);
        let metadata_root = route_auction_metadata_root(&json!({
            "challenge_scheme": config.challenge_scheme,
            "kind": kind.as_str(),
        }));
        let challenge_id = derive_challenge_id(
            kind,
            target_id,
            challenger_commitment,
            solver_id,
            evidence_root,
            claimed_loss_units,
            slash_units,
            opened_height,
            &metadata_root,
        );
        Ok(Self {
            challenge_id,
            kind,
            status: ChallengeStatus::Open,
            target_id: target_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            solver_id: solver_id.to_string(),
            evidence_root: evidence_root.to_string(),
            claimed_loss_units,
            slash_units,
            opened_height,
            deadline_height,
            resolution_root: String::new(),
            metadata_root,
        })
    }

    pub fn resolve(
        &mut self,
        accepted: bool,
        resolution_root: &str,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("resolution_root", resolution_root)?;
        if !matches!(
            self.status,
            ChallengeStatus::Open | ChallengeStatus::EvidenceQueued
        ) {
            return Err("challenge is not open for resolution".to_string());
        }
        self.resolution_root = resolution_root.to_string();
        self.status = if accepted {
            ChallengeStatus::Accepted
        } else {
            ChallengeStatus::Rejected
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "solver_id": self.solver_id,
            "evidence_root": self.evidence_root,
            "claimed_loss_units": self.claimed_loss_units,
            "slash_units": self.slash_units,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "resolution_root": self.resolution_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("challenge_id", &self.challenge_id)?;
        require_non_empty("target_id", &self.target_id)?;
        require_non_empty("challenger_commitment", &self.challenger_commitment)?;
        require_non_empty("solver_id", &self.solver_id)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        require_non_zero("opened_height", self.opened_height)?;
        if self.deadline_height < self.opened_height {
            return Err("challenge deadline before open height".to_string());
        }
        if matches!(
            self.status,
            ChallengeStatus::Accepted | ChallengeStatus::Rejected | ChallengeStatus::Slashed
        ) {
            require_non_empty("resolution_root", &self.resolution_root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAuctionEvent {
    pub event_id: String,
    pub height: u64,
    pub event_kind: String,
    pub target_id: String,
    pub payload_root: String,
}

impl RouteAuctionEvent {
    pub fn new(
        height: u64,
        event_kind: &str,
        target_id: &str,
        payload_root: &str,
    ) -> FastLowFeeRouteAuctionResult<Self> {
        require_non_zero("height", height)?;
        require_non_empty("event_kind", event_kind)?;
        require_non_empty("target_id", target_id)?;
        require_non_empty("payload_root", payload_root)?;
        let event_id = domain_hash(
            "FAST-LOW-FEE-ROUTE-AUCTION-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(height as i128),
                HashPart::Str(event_kind),
                HashPart::Str(target_id),
                HashPart::Str(payload_root),
            ],
            32,
        );
        Ok(Self {
            event_id,
            height,
            event_kind: event_kind.to_string(),
            target_id: target_id.to_string(),
            payload_root: payload_root.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "event_kind": self.event_kind,
            "target_id": self.target_id,
            "payload_root": self.payload_root,
        })
    }

    pub fn state_root(&self) -> String {
        route_auction_payload_root("FAST-LOW-FEE-ROUTE-AUCTION-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLowFeeRouteAuctionRoots {
    pub config_root: String,
    pub auction_root: String,
    pub solver_root: String,
    pub bid_root: String,
    pub fee_cap_root: String,
    pub batch_root: String,
    pub settlement_hint_root: String,
    pub monero_exit_lane_root: String,
    pub rebate_root: String,
    pub challenge_root: String,
    pub event_root: String,
}

impl FastLowFeeRouteAuctionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "auction_root": self.auction_root,
            "solver_root": self.solver_root,
            "bid_root": self.bid_root,
            "fee_cap_root": self.fee_cap_root,
            "batch_root": self.batch_root,
            "settlement_hint_root": self.settlement_hint_root,
            "monero_exit_lane_root": self.monero_exit_lane_root,
            "rebate_root": self.rebate_root,
            "challenge_root": self.challenge_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLowFeeRouteAuctionCounters {
    pub auctions: usize,
    pub solvers: usize,
    pub bids: usize,
    pub fee_caps: usize,
    pub batches: usize,
    pub settlement_hints: usize,
    pub monero_exit_lanes: usize,
    pub rebates: usize,
    pub challenges: usize,
    pub events: usize,
    pub active_auctions: usize,
    pub active_solvers: usize,
    pub open_challenges: usize,
    pub claimable_rebates: usize,
}

impl FastLowFeeRouteAuctionCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "auctions": self.auctions,
            "solvers": self.solvers,
            "bids": self.bids,
            "fee_caps": self.fee_caps,
            "batches": self.batches,
            "settlement_hints": self.settlement_hints,
            "monero_exit_lanes": self.monero_exit_lanes,
            "rebates": self.rebates,
            "challenges": self.challenges,
            "events": self.events,
            "active_auctions": self.active_auctions,
            "active_solvers": self.active_solvers,
            "open_challenges": self.open_challenges,
            "claimable_rebates": self.claimable_rebates,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastLowFeeRouteAuctionState {
    pub config: FastLowFeeRouteAuctionConfig,
    pub height: u64,
    pub status: String,
    pub auctions: BTreeMap<String, RouteAuction>,
    pub solvers: BTreeMap<String, SolverQos>,
    pub bids: BTreeMap<String, SealedRouteBid>,
    pub fee_caps: BTreeMap<String, RouteFeeCap>,
    pub batches: BTreeMap<String, CompressedRouteBatch>,
    pub settlement_hints: BTreeMap<String, PrivateSettlementHint>,
    pub monero_exit_lanes: BTreeMap<String, MoneroExitLane>,
    pub rebates: BTreeMap<String, RebateAccountingEntry>,
    pub challenges: BTreeMap<String, ChallengeRecord>,
    pub events: BTreeMap<String, RouteAuctionEvent>,
}

impl Default for FastLowFeeRouteAuctionState {
    fn default() -> Self {
        Self {
            config: FastLowFeeRouteAuctionConfig::default(),
            height: 0,
            status: FAST_LOW_FEE_ROUTE_AUCTION_STATE_ACTIVE.to_string(),
            auctions: BTreeMap::new(),
            solvers: BTreeMap::new(),
            bids: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_hints: BTreeMap::new(),
            monero_exit_lanes: BTreeMap::new(),
            rebates: BTreeMap::new(),
            challenges: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl FastLowFeeRouteAuctionState {
    pub fn new(config: FastLowFeeRouteAuctionConfig) -> FastLowFeeRouteAuctionResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> FastLowFeeRouteAuctionResult<Self> {
        let config = FastLowFeeRouteAuctionConfig::default();
        let mut state = Self::new(config)?;
        state.set_height(FAST_LOW_FEE_ROUTE_AUCTION_DEVNET_HEIGHT);
        let fee_cap = RouteFeeCap::new(
            RouteLaneKind::MoneroExit,
            "payer:commitment:devnet:route:001",
            2_000_000,
            250_000,
            state.height.saturating_add(240),
            &route_auction_metadata_root(&json!({"policy": "devnet-low-fee-cap"})),
            &state.config,
        )?;
        state.insert_fee_cap(fee_cap.clone())?;
        let auction = RouteAuction::new(
            0,
            RouteFlowKind::MoneroExit,
            &state.config.base_asset_id,
            &state.config.quote_asset_id,
            50_000_000_000,
            "min-output:commitment:devnet:001",
            &fee_cap.fee_cap_id,
            &route_auction_metadata_root(&json!({"private_intent": "devnet-monero-exit"})),
            state.height,
            &state.config,
        )?;
        state.insert_auction(auction.clone())?;
        let mut lanes = BTreeSet::new();
        lanes.insert(RouteLaneKind::LowFee);
        lanes.insert(RouteLaneKind::PrivateSwap);
        lanes.insert(RouteLaneKind::MoneroExit);
        lanes.insert(RouteLaneKind::WalletRecovery);
        let solver = SolverQos::new(
            "devnet-route-solver-0",
            state.config.min_solver_bond_units.saturating_mul(2),
            state.config.min_pq_security_bits,
            lanes,
            &route_auction_metadata_root(&json!({"attestation": "devnet-solver-qos"})),
            state.height,
            &state.config,
        )?;
        state.insert_solver(solver.clone())?;
        let lane = MoneroExitLane::new(
            "monero-devnet",
            RouteLaneKind::MoneroExit,
            &route_auction_metadata_root(&json!({"view_tags": "devnet"})),
            &route_auction_metadata_root(&json!({"reserve": "devnet"})),
            &route_auction_metadata_root(&json!({"fee_oracle": "devnet"})),
            500_000_000_000,
            10,
            state.height,
            &state.config,
        )?;
        state.insert_monero_exit_lane(lane)?;
        let bid = SealedRouteBid::commit(
            &auction,
            &solver,
            "sealed:bid:commitment:devnet:001",
            &route_auction_metadata_root(&json!({"encrypted_route": "devnet"})),
            state.config.low_fee_target_bps,
            1_750_000,
            "expected-output:commitment:devnet:001",
            state.height,
            &state.config,
        )?;
        state.insert_bid(bid.clone())?;
        let hint = PrivateSettlementHint::new(
            &auction.auction_id,
            &bid.bid_id,
            &solver.solver_id,
            &route_auction_metadata_root(&json!({"hint": "encrypted-devnet"})),
            &route_auction_metadata_root(&json!({"nullifiers": "devnet"})),
            &route_auction_metadata_root(&json!({"relay": "devnet"})),
            state.config.min_privacy_set_size,
            state
                .height
                .saturating_add(state.config.settlement_ttl_blocks),
            &state.config,
        )?;
        state.insert_settlement_hint(hint)?;
        let batch = CompressedRouteBatch::new(
            &[bid.clone()],
            &solver.solver_id,
            RouteLaneKind::MoneroExit,
            CompressionCodec::RouteDeltaV1,
            &route_auction_metadata_root(&json!({"routes": "uncompressed-devnet"})),
            &route_auction_metadata_root(&json!({"routes": "compressed-devnet"})),
            &state.settlement_hint_root(),
            &state.monero_exit_lane_root(),
            &state.fee_cap_root(),
            384,
            state.height.saturating_add(2),
            &state.config,
        )?;
        state.insert_batch(batch.clone())?;
        let rebate = RebateAccountingEntry::new(
            &batch.batch_id,
            &auction.auction_id,
            &fee_cap.payer_commitment,
            &solver.solver_id,
            bid.max_fee_units,
            "rebate:nullifier:devnet:001",
            state.height.saturating_add(3),
            &state.config,
        )?;
        state.insert_rebate(rebate)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn roots(&self) -> FastLowFeeRouteAuctionRoots {
        FastLowFeeRouteAuctionRoots {
            config_root: self.config.state_root(),
            auction_root: self.auction_root(),
            solver_root: self.solver_root(),
            bid_root: self.bid_root(),
            fee_cap_root: self.fee_cap_root(),
            batch_root: self.batch_root(),
            settlement_hint_root: self.settlement_hint_root(),
            monero_exit_lane_root: self.monero_exit_lane_root(),
            rebate_root: self.rebate_root(),
            challenge_root: self.challenge_root(),
            event_root: self.event_root(),
        }
    }

    pub fn counters(&self) -> FastLowFeeRouteAuctionCounters {
        FastLowFeeRouteAuctionCounters {
            auctions: self.auctions.len(),
            solvers: self.solvers.len(),
            bids: self.bids.len(),
            fee_caps: self.fee_caps.len(),
            batches: self.batches.len(),
            settlement_hints: self.settlement_hints.len(),
            monero_exit_lanes: self.monero_exit_lanes.len(),
            rebates: self.rebates.len(),
            challenges: self.challenges.len(),
            events: self.events.len(),
            active_auctions: self
                .auctions
                .values()
                .filter(|auction| !auction.status.terminal())
                .count(),
            active_solvers: self
                .solvers
                .values()
                .filter(|solver| solver.status.can_bid())
                .count(),
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| {
                    matches!(
                        challenge.status,
                        ChallengeStatus::Open | ChallengeStatus::EvidenceQueued
                    )
                })
                .count(),
            claimable_rebates: self
                .rebates
                .values()
                .filter(|rebate| rebate.status == RebateStatus::Claimable)
                .count(),
        }
    }

    pub fn insert_auction(&mut self, auction: RouteAuction) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "auctions",
            self.auctions.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_AUCTIONS,
        )?;
        auction.validate(&self.config)?;
        if self.auctions.contains_key(&auction.auction_id) {
            return Err("duplicate route auction id".to_string());
        }
        self.record_event(
            "auction_inserted",
            &auction.auction_id,
            &auction.state_root(),
        )?;
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_solver(&mut self, solver: SolverQos) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "solvers",
            self.solvers.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_SOLVERS,
        )?;
        solver.validate(&self.config)?;
        if self.solvers.contains_key(&solver.solver_id) {
            return Err("duplicate route solver id".to_string());
        }
        self.record_event("solver_inserted", &solver.solver_id, &solver.state_root())?;
        self.solvers.insert(solver.solver_id.clone(), solver);
        Ok(())
    }

    pub fn insert_bid(&mut self, bid: SealedRouteBid) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity("bids", self.bids.len(), FAST_LOW_FEE_ROUTE_AUCTION_MAX_BIDS)?;
        bid.validate(&self.config)?;
        if self.bids.contains_key(&bid.bid_id) {
            return Err("duplicate sealed route bid id".to_string());
        }
        let auction = self
            .auctions
            .get(&bid.auction_id)
            .ok_or_else(|| "sealed bid references unknown auction".to_string())?;
        if !auction.status.accepts_commit() && bid.status == SealedBidStatus::Committed {
            return Err("sealed bid references auction closed to commits".to_string());
        }
        let solver = self
            .solvers
            .get(&bid.solver_id)
            .ok_or_else(|| "sealed bid references unknown solver".to_string())?;
        if !solver.can_bid_lane(bid.lane_kind, &self.config) {
            return Err("sealed bid solver is not eligible for lane".to_string());
        }
        self.record_event("bid_inserted", &bid.bid_id, &bid.state_root())?;
        self.bids.insert(bid.bid_id.clone(), bid);
        Ok(())
    }

    pub fn insert_fee_cap(&mut self, fee_cap: RouteFeeCap) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "fee_caps",
            self.fee_caps.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_FEE_CAPS,
        )?;
        fee_cap.validate(&self.config)?;
        if self.fee_caps.contains_key(&fee_cap.fee_cap_id) {
            return Err("duplicate route fee cap id".to_string());
        }
        self.record_event(
            "fee_cap_inserted",
            &fee_cap.fee_cap_id,
            &fee_cap.state_root(),
        )?;
        self.fee_caps.insert(fee_cap.fee_cap_id.clone(), fee_cap);
        Ok(())
    }

    pub fn insert_batch(
        &mut self,
        batch: CompressedRouteBatch,
    ) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "batches",
            self.batches.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_BATCHES,
        )?;
        batch.validate(&self.config)?;
        if self.batches.contains_key(&batch.batch_id) {
            return Err("duplicate compressed route batch id".to_string());
        }
        for auction_id in &batch.auction_ids {
            if !self.auctions.contains_key(auction_id) {
                return Err("compressed batch references unknown auction".to_string());
            }
        }
        for bid_id in &batch.selected_bid_ids {
            if !self.bids.contains_key(bid_id) {
                return Err("compressed batch references unknown bid".to_string());
            }
        }
        self.record_event("batch_inserted", &batch.batch_id, &batch.state_root())?;
        self.batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_settlement_hint(
        &mut self,
        hint: PrivateSettlementHint,
    ) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "settlement_hints",
            self.settlement_hints.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_HINTS,
        )?;
        hint.validate(&self.config)?;
        if self.settlement_hints.contains_key(&hint.hint_id) {
            return Err("duplicate private settlement hint id".to_string());
        }
        self.record_event(
            "settlement_hint_inserted",
            &hint.hint_id,
            &hint.state_root(),
        )?;
        self.settlement_hints.insert(hint.hint_id.clone(), hint);
        Ok(())
    }

    pub fn insert_monero_exit_lane(
        &mut self,
        lane: MoneroExitLane,
    ) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "monero_exit_lanes",
            self.monero_exit_lanes.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_MONERO_LANES,
        )?;
        lane.validate(&self.config)?;
        if self.monero_exit_lanes.contains_key(&lane.lane_id) {
            return Err("duplicate monero exit lane id".to_string());
        }
        self.record_event(
            "monero_exit_lane_inserted",
            &lane.lane_id,
            &lane.state_root(),
        )?;
        self.monero_exit_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_rebate(
        &mut self,
        rebate: RebateAccountingEntry,
    ) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "rebates",
            self.rebates.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_REBATES,
        )?;
        rebate.validate()?;
        if self.rebates.contains_key(&rebate.rebate_id) {
            return Err("duplicate rebate id".to_string());
        }
        self.record_event("rebate_inserted", &rebate.rebate_id, &rebate.state_root())?;
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: ChallengeRecord,
    ) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "challenges",
            self.challenges.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_CHALLENGES,
        )?;
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("duplicate challenge id".to_string());
        }
        self.status = FAST_LOW_FEE_ROUTE_AUCTION_STATE_CHALLENGED.to_string();
        self.record_event(
            "challenge_inserted",
            &challenge.challenge_id,
            &challenge.state_root(),
        )?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn mark_batch_settled(
        &mut self,
        batch_id: &str,
        height: u64,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("batch_id", batch_id)?;
        require_non_zero("height", height)?;
        let (event_target, event_root) = {
            let batch = self
                .batches
                .get_mut(batch_id)
                .ok_or_else(|| "unknown compressed route batch".to_string())?;
            if height > batch.settlement_deadline_height {
                batch.status = BatchStatus::Expired;
                return Err("batch settlement after deadline".to_string());
            }
            batch.status = BatchStatus::Settled;
            (batch.batch_id.clone(), batch.state_root())
        };
        self.record_event("batch_settled", &event_target, &event_root)?;
        Ok(())
    }

    pub fn claim_rebate(
        &mut self,
        rebate_id: &str,
        height: u64,
    ) -> FastLowFeeRouteAuctionResult<()> {
        require_non_empty("rebate_id", rebate_id)?;
        require_non_zero("height", height)?;
        let (event_target, event_root) = {
            let rebate = self
                .rebates
                .get_mut(rebate_id)
                .ok_or_else(|| "unknown route rebate".to_string())?;
            if height > rebate.claim_deadline_height {
                rebate.status = RebateStatus::DonatedToFeePool;
                return Err("rebate claim after deadline".to_string());
            }
            if !matches!(
                rebate.status,
                RebateStatus::Accrued | RebateStatus::Claimable
            ) {
                return Err("rebate is not claimable".to_string());
            }
            rebate.status = RebateStatus::Claimed;
            (rebate.rebate_id.clone(), rebate.state_root())
        };
        self.record_event("rebate_claimed", &event_target, &event_root)?;
        Ok(())
    }

    pub fn validate(&self) -> FastLowFeeRouteAuctionResult<()> {
        self.config.validate()?;
        require_non_empty("status", &self.status)?;
        if !matches!(
            self.status.as_str(),
            FAST_LOW_FEE_ROUTE_AUCTION_STATE_ACTIVE
                | FAST_LOW_FEE_ROUTE_AUCTION_STATE_CHALLENGED
                | FAST_LOW_FEE_ROUTE_AUCTION_STATE_HALTED
        ) {
            return Err("unknown route auction state status".to_string());
        }
        self.validate_capacity()?;
        for fee_cap in self.fee_caps.values() {
            fee_cap.validate(&self.config)?;
        }
        for auction in self.auctions.values() {
            auction.validate(&self.config)?;
            if !self.fee_caps.contains_key(&auction.fee_cap_id) {
                return Err("auction references missing fee cap".to_string());
            }
        }
        for solver in self.solvers.values() {
            solver.validate(&self.config)?;
        }
        for bid in self.bids.values() {
            bid.validate(&self.config)?;
            if !self.auctions.contains_key(&bid.auction_id) {
                return Err("bid references missing auction".to_string());
            }
            if !self.solvers.contains_key(&bid.solver_id) {
                return Err("bid references missing solver".to_string());
            }
        }
        for hint in self.settlement_hints.values() {
            hint.validate(&self.config)?;
            if !self.auctions.contains_key(&hint.auction_id) {
                return Err("hint references missing auction".to_string());
            }
            if !self.bids.contains_key(&hint.bid_id) {
                return Err("hint references missing bid".to_string());
            }
        }
        for lane in self.monero_exit_lanes.values() {
            lane.validate(&self.config)?;
        }
        for batch in self.batches.values() {
            batch.validate(&self.config)?;
        }
        for rebate in self.rebates.values() {
            rebate.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "status": self.status,
            "state_root": self.state_root(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "config": self.config.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "FAST-LOW-FEE-ROUTE-AUCTION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.height as i128),
                HashPart::Str(&self.status),
                HashPart::Json(&self.roots().public_record()),
                HashPart::Json(&self.counters().public_record()),
            ],
            32,
        )
    }

    pub fn auction_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-AUCTIONS",
            self.auctions
                .values()
                .map(RouteAuction::public_record)
                .collect(),
        )
    }

    pub fn solver_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-SOLVERS",
            self.solvers
                .values()
                .map(SolverQos::public_record)
                .collect(),
        )
    }

    pub fn bid_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-BIDS",
            self.bids
                .values()
                .map(SealedRouteBid::public_record)
                .collect(),
        )
    }

    pub fn fee_cap_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-FEE-CAPS",
            self.fee_caps
                .values()
                .map(RouteFeeCap::public_record)
                .collect(),
        )
    }

    pub fn batch_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-BATCHES",
            self.batches
                .values()
                .map(CompressedRouteBatch::public_record)
                .collect(),
        )
    }

    pub fn settlement_hint_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-HINTS",
            self.settlement_hints
                .values()
                .map(PrivateSettlementHint::public_record)
                .collect(),
        )
    }

    pub fn monero_exit_lane_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-MONERO-LANES",
            self.monero_exit_lanes
                .values()
                .map(MoneroExitLane::public_record)
                .collect(),
        )
    }

    pub fn rebate_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-REBATES",
            self.rebates
                .values()
                .map(RebateAccountingEntry::public_record)
                .collect(),
        )
    }

    pub fn challenge_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-CHALLENGES",
            self.challenges
                .values()
                .map(ChallengeRecord::public_record)
                .collect(),
        )
    }

    pub fn event_root(&self) -> String {
        map_merkle_root(
            "FAST-LOW-FEE-ROUTE-AUCTION-EVENTS",
            self.events
                .values()
                .map(RouteAuctionEvent::public_record)
                .collect(),
        )
    }

    fn validate_capacity(&self) -> FastLowFeeRouteAuctionResult<()> {
        self.ensure_capacity(
            "auctions",
            self.auctions.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_AUCTIONS,
        )?;
        self.ensure_capacity(
            "solvers",
            self.solvers.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_SOLVERS,
        )?;
        self.ensure_capacity("bids", self.bids.len(), FAST_LOW_FEE_ROUTE_AUCTION_MAX_BIDS)?;
        self.ensure_capacity(
            "fee_caps",
            self.fee_caps.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_FEE_CAPS,
        )?;
        self.ensure_capacity(
            "batches",
            self.batches.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_BATCHES,
        )?;
        self.ensure_capacity(
            "settlement_hints",
            self.settlement_hints.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_HINTS,
        )?;
        self.ensure_capacity(
            "monero_exit_lanes",
            self.monero_exit_lanes.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_MONERO_LANES,
        )?;
        self.ensure_capacity(
            "rebates",
            self.rebates.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_REBATES,
        )?;
        self.ensure_capacity(
            "challenges",
            self.challenges.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_CHALLENGES,
        )?;
        self.ensure_capacity(
            "events",
            self.events.len(),
            FAST_LOW_FEE_ROUTE_AUCTION_MAX_EVENTS,
        )?;
        Ok(())
    }

    fn ensure_capacity(
        &self,
        label: &str,
        current: usize,
        max: usize,
    ) -> FastLowFeeRouteAuctionResult<()> {
        if current >= max {
            return Err(format!("{label} capacity exceeded"));
        }
        Ok(())
    }

    fn record_event(
        &mut self,
        event_kind: &str,
        target_id: &str,
        payload_root: &str,
    ) -> FastLowFeeRouteAuctionResult<()> {
        if self.events.len() >= FAST_LOW_FEE_ROUTE_AUCTION_MAX_EVENTS {
            return Err("route auction event capacity exceeded".to_string());
        }
        let event = RouteAuctionEvent::new(self.height, event_kind, target_id, payload_root)?;
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }
}

pub fn compute_rebate_units(gross_fee_units: u64, rebate_share_bps: u64) -> u64 {
    gross_fee_units.saturating_mul(rebate_share_bps) / FAST_LOW_FEE_ROUTE_AUCTION_MAX_BPS
}

pub fn compute_effective_fee_bps(gross_fee_units: u64, notional_units: u128) -> u64 {
    if gross_fee_units == 0 || notional_units == 0 {
        return 0;
    }
    let numerator =
        (gross_fee_units as u128).saturating_mul(FAST_LOW_FEE_ROUTE_AUCTION_MAX_BPS as u128);
    let bps = numerator / notional_units;
    if bps > u64::MAX as u128 {
        u64::MAX
    } else {
        bps as u64
    }
}

pub fn route_auction_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn route_auction_metadata_root(metadata: &Value) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-AUCTION-METADATA",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(metadata)],
        32,
    )
}

pub fn derive_auction_id(
    epoch: u64,
    flow_kind: RouteFlowKind,
    lane_kind: RouteLaneKind,
    input_asset_id: &str,
    output_asset_id: &str,
    notional_units: u128,
    min_output_units_commitment: &str,
    fee_cap_id: &str,
    private_intent_root: &str,
    opened_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(flow_kind.as_str()),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(input_asset_id),
            HashPart::Str(output_asset_id),
            HashPart::Int(saturating_i128_from_u128(notional_units)),
            HashPart::Str(min_output_units_commitment),
            HashPart::Str(fee_cap_id),
            HashPart::Str(private_intent_root),
            HashPart::Int(opened_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_fee_cap_id(
    lane_kind: RouteLaneKind,
    payer_commitment: &str,
    fee_asset_id: &str,
    max_fee_bps: u64,
    max_fee_units: u64,
    low_fee_sponsor_units: u64,
    expires_at_height: u64,
    policy_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-FEE-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(payer_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(low_fee_sponsor_units as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(policy_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_solver_id(
    solver_label: &str,
    bonded_units: u64,
    pq_security_bits: u16,
    attestation_root: &str,
    height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-SOLVER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(solver_label),
            HashPart::Int(bonded_units as i128),
            HashPart::Int(pq_security_bits as i128),
            HashPart::Str(attestation_root),
            HashPart::Int(height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_bid_id(
    auction_id: &str,
    solver_id: &str,
    lane_kind: RouteLaneKind,
    commitment_hash: &str,
    encrypted_route_hint_root: &str,
    fee_bid_bps: u64,
    max_fee_units: u64,
    expected_output_commitment: &str,
    submitted_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-SEALED-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(solver_id),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(commitment_hash),
            HashPart::Str(encrypted_route_hint_root),
            HashPart::Int(fee_bid_bps as i128),
            HashPart::Int(max_fee_units as i128),
            HashPart::Str(expected_output_commitment),
            HashPart::Int(submitted_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_bid_reveal_hash(bid_id: &str, reveal_payload_root: &str, height: u64) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-BID-REVEAL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bid_id),
            HashPart::Str(reveal_payload_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn derive_hint_id(
    auction_id: &str,
    bid_id: &str,
    solver_id: &str,
    encrypted_hint_root: &str,
    nullifier_root: &str,
    relay_path_root: &str,
    privacy_set_size: u64,
    expiry_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-SETTLEMENT-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(solver_id),
            HashPart::Str(encrypted_hint_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(relay_path_root),
            HashPart::Int(privacy_set_size as i128),
            HashPart::Int(expiry_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_monero_lane_id(
    monero_network: &str,
    lane_kind: RouteLaneKind,
    subaddress_view_tag_root: &str,
    reserve_commitment_root: &str,
    fee_oracle_root: &str,
    available_liquidity_atomic_units: u128,
    target_confirmation_blocks: u64,
    opened_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-MONERO-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(monero_network),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(subaddress_view_tag_root),
            HashPart::Str(reserve_commitment_root),
            HashPart::Str(fee_oracle_root),
            HashPart::Int(saturating_i128_from_u128(available_liquidity_atomic_units)),
            HashPart::Int(target_confirmation_blocks as i128),
            HashPart::Int(opened_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_batch_id(
    auction_ids: &BTreeSet<String>,
    selected_bid_ids: &BTreeSet<String>,
    solver_id: &str,
    lane_kind: RouteLaneKind,
    codec: CompressionCodec,
    uncompressed_route_root: &str,
    compressed_payload_root: &str,
    settlement_hint_root: &str,
    monero_exit_lane_root: &str,
    fee_cap_root: &str,
    posted_height: u64,
    metadata_root: &str,
) -> String {
    let auction_id_root = merkle_root(
        "FAST-LOW-FEE-ROUTE-BATCH-AUCTION-IDS",
        &auction_ids
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>(),
    );
    let bid_id_root = merkle_root(
        "FAST-LOW-FEE-ROUTE-BATCH-BID-IDS",
        &selected_bid_ids
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>(),
    );
    domain_hash(
        "FAST-LOW-FEE-ROUTE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&auction_id_root),
            HashPart::Str(&bid_id_root),
            HashPart::Str(solver_id),
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(codec.as_str()),
            HashPart::Str(uncompressed_route_root),
            HashPart::Str(compressed_payload_root),
            HashPart::Str(settlement_hint_root),
            HashPart::Str(monero_exit_lane_root),
            HashPart::Str(fee_cap_root),
            HashPart::Int(posted_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_rebate_id(
    batch_id: &str,
    auction_id: &str,
    payer_commitment: &str,
    solver_id: &str,
    fee_asset_id: &str,
    gross_fee_units: u64,
    rebate_units: u64,
    claim_nullifier_hash: &str,
    accrued_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(auction_id),
            HashPart::Str(payer_commitment),
            HashPart::Str(solver_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(rebate_units as i128),
            HashPart::Str(claim_nullifier_hash),
            HashPart::Int(accrued_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn derive_challenge_id(
    kind: ChallengeKind,
    target_id: &str,
    challenger_commitment: &str,
    solver_id: &str,
    evidence_root: &str,
    claimed_loss_units: u64,
    slash_units: u64,
    opened_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "FAST-LOW-FEE-ROUTE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(solver_id),
            HashPart::Str(evidence_root),
            HashPart::Int(claimed_loss_units as i128),
            HashPart::Int(slash_units as i128),
            HashPart::Int(opened_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

fn compute_qos_score(
    successful_routes: u64,
    failed_routes: u64,
    median_latency_ms: u64,
    p95_latency_ms: u64,
    privacy_incidents: u64,
    fee_cap_violations: u64,
    target_latency_ms: u64,
) -> u64 {
    let total_routes = successful_routes.saturating_add(failed_routes).max(1);
    let success_score = successful_routes.saturating_mul(6_000) / total_routes;
    let latency_score = if median_latency_ms <= target_latency_ms {
        2_000
    } else {
        2_000_u64.saturating_sub(
            median_latency_ms
                .saturating_sub(target_latency_ms)
                .saturating_mul(2),
        )
    };
    let tail_score = if p95_latency_ms <= target_latency_ms.saturating_mul(3) {
        1_000
    } else {
        1_000_u64.saturating_sub(p95_latency_ms.saturating_sub(target_latency_ms.saturating_mul(3)))
    };
    let incident_penalty = privacy_incidents
        .saturating_mul(2_000)
        .saturating_add(fee_cap_violations.saturating_mul(750));
    success_score
        .saturating_add(latency_score)
        .saturating_add(tail_score)
        .saturating_add(1_000)
        .saturating_sub(incident_penalty)
        .min(10_000)
}

fn rolling_average(previous: u64, next: u64) -> u64 {
    previous.saturating_mul(3).saturating_add(next) / 4
}

fn map_merkle_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn validate_bps(label: &str, value: u64) -> FastLowFeeRouteAuctionResult<()> {
    if value > FAST_LOW_FEE_ROUTE_AUCTION_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> FastLowFeeRouteAuctionResult<()> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn require_non_zero(label: &str, value: u64) -> FastLowFeeRouteAuctionResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn require_non_zero_u128(label: &str, value: u128) -> FastLowFeeRouteAuctionResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn saturating_i128_from_u128(value: u128) -> i128 {
    if value > i128::MAX as u128 {
        i128::MAX
    } else {
        value as i128
    }
}
