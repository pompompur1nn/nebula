use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroFastExitLiquidityAuctionResult<T> = Result<T, String>;

pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_PROTOCOL_VERSION: &str =
    "nebula-monero-fast-exit-liquidity-auction-v1";
pub const PROTOCOL_VERSION: &str = MONERO_FAST_EXIT_LIQUIDITY_AUCTION_PROTOCOL_VERSION;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_SCHEMA_VERSION: u64 = 1;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_HEIGHT: u64 = 384;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_PQ_QUOTE_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87-fast-exit-quote-v1";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_BACKUP_SIGNATURE_SCHEME: &str =
    "SLH-DSA-SHAKE-128s-fast-exit-watchtower-v1";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_RESERVE_COMMITMENT_SCHEME: &str =
    "monero-reserve-commitment-shake256-v1";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_EXIT_COMMITMENT_SCHEME: &str =
    "shielded-exit-demand-nullifier-set-v1";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_SETTLEMENT_ROOT_SCHEME: &str =
    "batch-settlement-merkle-roots-v1";
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 6;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 48;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 24;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_LOW_FEE_TTL_BLOCKS: u64 = 240;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MAX_EXIT_FEE_BPS: u64 = 120;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_FAST_FEE_BPS: u64 = 80;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_LOW_FEE_BPS: u64 = 15;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_EMERGENCY_FEE_BPS: u64 = 150;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_FEE_FLOOR_PICONERO: u64 = 2_000;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MIN_LP_BOND_PICONERO: u64 = 5_000_000_000;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_SLASH_BPS: u64 = 3_000;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MAX_BATCH_EXITS: usize = 128;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MAX_MATCHES_PER_BATCH: usize = 256;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_BPS: u64 = 10_000;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_LANES: usize = 32;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_AUCTIONS: usize = 2_048;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_DEMANDS: usize = 32_768;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_RESERVES: usize = 8_192;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_QUOTES: usize = 65_536;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_MATCHES: usize = 65_536;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_SETTLEMENTS: usize = 16_384;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_EVIDENCE: usize = 4_096;
pub const MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_PUBLIC_RECORDS: usize = 131_072;

const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_CHALLENGED: &str = "challenged";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastExitLane {
    LowFee,
    Standard,
    Fast,
    DefiArb,
    TokenRedemption,
    SmartContractExit,
    WalletRecovery,
    Emergency,
}

impl FastExitLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::DefiArb => "defi_arb",
            Self::TokenRedemption => "token_redemption",
            Self::SmartContractExit => "smart_contract_exit",
            Self::WalletRecovery => "wallet_recovery",
            Self::Emergency => "emergency",
        }
    }

    pub fn privacy_priority(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::WalletRecovery => 900,
            Self::LowFee => 850,
            Self::SmartContractExit => 760,
            Self::TokenRedemption => 720,
            Self::Fast => 680,
            Self::Standard => 500,
            Self::DefiArb => 430,
        }
    }

    pub fn fee_bps(self, config: &FastExitAuctionConfig) -> u64 {
        match self {
            Self::LowFee | Self::WalletRecovery => config.low_fee_bps,
            Self::Emergency => config.emergency_fee_bps,
            Self::Fast | Self::DefiArb => config.fast_fee_bps,
            Self::Standard | Self::TokenRedemption | Self::SmartContractExit => {
                config.max_exit_fee_bps.min(config.fast_fee_bps)
            }
        }
    }

    pub fn is_low_fee(self) -> bool {
        matches!(self, Self::LowFee | Self::WalletRecovery)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Scheduled,
    Collecting,
    QuoteOpen,
    Matching,
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
            Self::Collecting => "collecting",
            Self::QuoteOpen => "quote_open",
            Self::Matching => "matching",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_demand(self) -> bool {
        matches!(self, Self::Scheduled | Self::Collecting | Self::QuoteOpen)
    }

    pub fn accepts_quote(self) -> bool {
        matches!(self, Self::QuoteOpen | Self::Matching)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitDemandStatus {
    Submitted,
    Committed,
    QuoteRequested,
    Matched,
    BatchLocked,
    Settling,
    Settled,
    Cancelled,
    Expired,
    Rejected,
}

impl ExitDemandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Committed => "committed",
            Self::QuoteRequested => "quote_requested",
            Self::Matched => "matched",
            Self::BatchLocked => "batch_locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Committed
                | Self::QuoteRequested
                | Self::Matched
                | Self::BatchLocked
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Advertised,
    Attested,
    QuoteOpen,
    Allocated,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl ReserveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Attested => "attested",
            Self::QuoteOpen => "quote_open",
            Self::Allocated => "allocated",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_quote(self) -> bool {
        matches!(self, Self::Attested | Self::QuoteOpen | Self::Allocated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Sealed,
    Attested,
    Eligible,
    Winning,
    Filled,
    Refunded,
    Disputed,
    Slashed,
    Expired,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Eligible => "eligible",
            Self::Winning => "winning",
            Self::Filled => "filled",
            Self::Refunded => "refunded",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Attested | Self::Eligible | Self::Winning
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStatus {
    Proposed,
    Locked,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

impl MatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Locked => "locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Planned,
    Broadcast,
    Confirming,
    Finalized,
    Reorged,
    Disputed,
    Failed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Broadcast => "broadcast",
            Self::Confirming => "confirming",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Disputed => "disputed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    QuoteEquivocation,
    ReserveShortfall,
    SettlementTimeout,
    InvalidPqAttestation,
    FeeOvercharge,
    NullifierReuse,
    BatchRootMismatch,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuoteEquivocation => "quote_equivocation",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::SettlementTimeout => "settlement_timeout",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::FeeOvercharge => "fee_overcharge",
            Self::NullifierReuse => "nullifier_reuse",
            Self::BatchRootMismatch => "batch_root_mismatch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitAuctionConfig {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_quote_scheme: String,
    pub backup_signature_scheme: String,
    pub reserve_commitment_scheme: String,
    pub exit_commitment_scheme: String,
    pub settlement_root_scheme: String,
    pub auction_window_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub low_fee_ttl_blocks: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub max_exit_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub low_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub fee_floor_piconero: u64,
    pub min_lp_bond_piconero: u64,
    pub slash_bps: u64,
    pub min_pq_security_bits: u16,
    pub max_batch_exits: usize,
    pub max_matches_per_batch: usize,
}

impl FastExitAuctionConfig {
    pub fn devnet() -> Self {
        Self {
            config_id: "monero-fast-exit-liquidity-auction-devnet-config".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_HASH_SUITE.to_string(),
            pq_quote_scheme: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_PQ_QUOTE_SCHEME.to_string(),
            backup_signature_scheme: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_BACKUP_SIGNATURE_SCHEME
                .to_string(),
            reserve_commitment_scheme: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_RESERVE_COMMITMENT_SCHEME
                .to_string(),
            exit_commitment_scheme: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_EXIT_COMMITMENT_SCHEME
                .to_string(),
            settlement_root_scheme: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_SETTLEMENT_ROOT_SCHEME
                .to_string(),
            auction_window_blocks: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_AUCTION_WINDOW_BLOCKS,
            quote_ttl_blocks: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_QUOTE_TTL_BLOCKS,
            settlement_ttl_blocks: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            challenge_window_blocks:
                MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            low_fee_ttl_blocks: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_LOW_FEE_TTL_BLOCKS,
            min_reserve_coverage_bps:
                MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            max_exit_fee_bps: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MAX_EXIT_FEE_BPS,
            fast_fee_bps: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_FAST_FEE_BPS,
            low_fee_bps: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_LOW_FEE_BPS,
            emergency_fee_bps: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_EMERGENCY_FEE_BPS,
            fee_floor_piconero: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_FEE_FLOOR_PICONERO,
            min_lp_bond_piconero: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MIN_LP_BOND_PICONERO,
            slash_bps: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_SLASH_BPS,
            min_pq_security_bits: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_batch_exits: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MAX_BATCH_EXITS,
            max_matches_per_batch: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEFAULT_MAX_MATCHES_PER_BATCH,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_quote_scheme": self.pq_quote_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "reserve_commitment_scheme": self.reserve_commitment_scheme,
            "exit_commitment_scheme": self.exit_commitment_scheme,
            "settlement_root_scheme": self.settlement_root_scheme,
            "auction_window_blocks": self.auction_window_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "low_fee_ttl_blocks": self.low_fee_ttl_blocks,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "max_exit_fee_bps": self.max_exit_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "fee_floor_piconero": self.fee_floor_piconero,
            "min_lp_bond_piconero": self.min_lp_bond_piconero,
            "slash_bps": self.slash_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_batch_exits": self.max_batch_exits,
            "max_matches_per_batch": self.max_matches_per_batch,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("config_id", &self.config_id)?;
        ensure_equal("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_equal("chain_id", &self.chain_id, CHAIN_ID)?;
        ensure_positive("auction_window_blocks", self.auction_window_blocks)?;
        ensure_positive("quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive("settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        ensure_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        ensure_coverage_bps("min_reserve_coverage_bps", self.min_reserve_coverage_bps)?;
        ensure_coverage_bps(
            "target_reserve_coverage_bps",
            self.target_reserve_coverage_bps,
        )?;
        ensure_bps("max_exit_fee_bps", self.max_exit_fee_bps)?;
        ensure_bps("fast_fee_bps", self.fast_fee_bps)?;
        ensure_bps("low_fee_bps", self.low_fee_bps)?;
        ensure_bps("emergency_fee_bps", self.emergency_fee_bps)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        if self.target_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("target_reserve_coverage_bps below min_reserve_coverage_bps".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits below 128".to_string());
        }
        if self.max_batch_exits == 0 || self.max_matches_per_batch == 0 {
            return Err("batch limits must be positive".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanePolicy {
    pub lane_id: String,
    pub lane: FastExitLane,
    pub enabled: bool,
    pub max_fee_bps: u64,
    pub max_exit_units: u64,
    pub privacy_bucket_units: u64,
    pub min_ring_size: u64,
    pub max_batch_delay_blocks: u64,
    pub sponsor_budget_piconero: u64,
}

impl LanePolicy {
    pub fn new(lane: FastExitLane, config: &FastExitAuctionConfig) -> Self {
        let lane_id = format!("lane-{}", lane.as_str());
        let max_fee_bps = lane.fee_bps(config);
        let max_batch_delay_blocks = if lane.is_low_fee() {
            config.low_fee_ttl_blocks
        } else {
            config.settlement_ttl_blocks
        };
        Self {
            lane_id,
            lane,
            enabled: true,
            max_fee_bps,
            max_exit_units: 5_000_000_000_000,
            privacy_bucket_units: 10_000_000,
            min_ring_size: 16,
            max_batch_delay_blocks,
            sponsor_budget_piconero: if lane.is_low_fee() { 50_000_000 } else { 0 },
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "enabled": self.enabled,
            "max_fee_bps": self.max_fee_bps,
            "max_exit_units": self.max_exit_units,
            "privacy_bucket_units": self.privacy_bucket_units,
            "min_ring_size": self.min_ring_size,
            "max_batch_delay_blocks": self.max_batch_delay_blocks,
            "sponsor_budget_piconero": self.sponsor_budget_piconero,
            "privacy_priority": self.lane.privacy_priority(),
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("LANE-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        ensure_positive("max_exit_units", self.max_exit_units)?;
        ensure_positive("privacy_bucket_units", self.privacy_bucket_units)?;
        ensure_positive("min_ring_size", self.min_ring_size)?;
        ensure_positive("max_batch_delay_blocks", self.max_batch_delay_blocks)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityAuction {
    pub auction_id: String,
    pub lane: FastExitLane,
    pub status: AuctionStatus,
    pub opened_height: u64,
    pub quote_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub challenge_deadline_height: u64,
    pub demand_root_hint: String,
    pub reserve_root_hint: String,
    pub min_fill_units: u64,
    pub max_fill_units: u64,
    pub clearing_fee_bps: u64,
}

impl LiquidityAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "quote_deadline_height": self.quote_deadline_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "demand_root_hint": self.demand_root_hint,
            "reserve_root_hint": self.reserve_root_hint,
            "min_fill_units": self.min_fill_units,
            "max_fill_units": self.max_fill_units,
            "clearing_fee_bps": self.clearing_fee_bps,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("AUCTION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("auction_id", &self.auction_id)?;
        ensure_non_empty("demand_root_hint", &self.demand_root_hint)?;
        ensure_non_empty("reserve_root_hint", &self.reserve_root_hint)?;
        ensure_ordered_heights(
            self.opened_height,
            self.quote_deadline_height,
            self.settlement_deadline_height,
            self.challenge_deadline_height,
        )?;
        ensure_positive("min_fill_units", self.min_fill_units)?;
        ensure_positive("max_fill_units", self.max_fill_units)?;
        if self.max_fill_units < self.min_fill_units {
            return Err("auction max_fill_units below min_fill_units".to_string());
        }
        ensure_bps("clearing_fee_bps", self.clearing_fee_bps)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedExitDemand {
    pub demand_id: String,
    pub auction_id: String,
    pub lane: FastExitLane,
    pub status: ExitDemandStatus,
    pub amount_commitment: String,
    pub nullifier_commitment: String,
    pub destination_subaddress_commitment: String,
    pub range_proof_root: String,
    pub privacy_bucket_units: u64,
    pub max_fee_bps: u64,
    pub sponsor_commitment: Option<String>,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl ShieldedExitDemand {
    pub fn public_record(&self) -> Value {
        json!({
            "demand_id": self.demand_id,
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "amount_commitment": self.amount_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "destination_subaddress_commitment": self.destination_subaddress_commitment,
            "range_proof_root": self.range_proof_root,
            "privacy_bucket_units": self.privacy_bucket_units,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_commitment": self.sponsor_commitment,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("SHIELDED-EXIT-DEMAND", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("demand_id", &self.demand_id)?;
        ensure_non_empty("auction_id", &self.auction_id)?;
        ensure_non_empty("amount_commitment", &self.amount_commitment)?;
        ensure_non_empty("nullifier_commitment", &self.nullifier_commitment)?;
        ensure_non_empty(
            "destination_subaddress_commitment",
            &self.destination_subaddress_commitment,
        )?;
        ensure_non_empty("range_proof_root", &self.range_proof_root)?;
        ensure_positive("privacy_bucket_units", self.privacy_bucket_units)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        if self.expires_height <= self.submitted_height {
            return Err("exit demand expires_height must exceed submitted_height".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LpReserveCommitment {
    pub reserve_id: String,
    pub lp_id: String,
    pub status: ReserveStatus,
    pub reserve_commitment: String,
    pub reserve_view_tag_root: String,
    pub max_fill_units: u64,
    pub available_units: u64,
    pub min_fee_bps: u64,
    pub bond_commitment: String,
    pub pq_public_key_commitment: String,
    pub attestation_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl LpReserveCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "lp_id": self.lp_id,
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "reserve_view_tag_root": self.reserve_view_tag_root,
            "max_fill_units": self.max_fill_units,
            "available_units": self.available_units,
            "min_fee_bps": self.min_fee_bps,
            "bond_commitment": self.bond_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "attestation_root": self.attestation_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("LP-RESERVE-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("reserve_id", &self.reserve_id)?;
        ensure_non_empty("lp_id", &self.lp_id)?;
        ensure_non_empty("reserve_commitment", &self.reserve_commitment)?;
        ensure_non_empty("reserve_view_tag_root", &self.reserve_view_tag_root)?;
        ensure_positive("max_fill_units", self.max_fill_units)?;
        ensure_positive("available_units", self.available_units)?;
        if self.available_units > self.max_fill_units {
            return Err("reserve available_units exceeds max_fill_units".to_string());
        }
        ensure_bps("min_fee_bps", self.min_fee_bps)?;
        ensure_non_empty("bond_commitment", &self.bond_commitment)?;
        ensure_non_empty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        ensure_non_empty("attestation_root", &self.attestation_root)?;
        if self.expires_height <= self.opened_height {
            return Err("reserve expires_height must exceed opened_height".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuoteAttestation {
    pub quote_id: String,
    pub auction_id: String,
    pub reserve_id: String,
    pub demand_commitment_root: String,
    pub encrypted_quote_root: String,
    pub fee_bps: u64,
    pub fill_units: u64,
    pub status: QuoteStatus,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub signer_commitment: String,
    pub signature_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PqQuoteAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "reserve_id": self.reserve_id,
            "demand_commitment_root": self.demand_commitment_root,
            "encrypted_quote_root": self.encrypted_quote_root,
            "fee_bps": self.fee_bps,
            "fill_units": self.fill_units,
            "status": self.status.as_str(),
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "signer_commitment": self.signer_commitment,
            "signature_root": self.signature_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("PQ-QUOTE-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("quote_id", &self.quote_id)?;
        ensure_non_empty("auction_id", &self.auction_id)?;
        ensure_non_empty("reserve_id", &self.reserve_id)?;
        ensure_non_empty("demand_commitment_root", &self.demand_commitment_root)?;
        ensure_non_empty("encrypted_quote_root", &self.encrypted_quote_root)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        ensure_positive("fill_units", self.fill_units)?;
        ensure_non_empty("pq_scheme", &self.pq_scheme)?;
        if self.pq_security_bits < 128 {
            return Err("pq quote security below 128 bits".to_string());
        }
        ensure_non_empty("signer_commitment", &self.signer_commitment)?;
        ensure_non_empty("signature_root", &self.signature_root)?;
        if self.expires_height <= self.submitted_height {
            return Err("quote expires_height must exceed submitted_height".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitLiquidityMatch {
    pub match_id: String,
    pub auction_id: String,
    pub demand_id: String,
    pub reserve_id: String,
    pub quote_id: String,
    pub status: MatchStatus,
    pub matched_units: u64,
    pub fee_bps: u64,
    pub low_fee_rebate_piconero: u64,
    pub encrypted_payout_plan_root: String,
    pub lp_fill_commitment: String,
    pub locked_height: u64,
    pub settlement_deadline_height: u64,
}

impl ExitLiquidityMatch {
    pub fn public_record(&self) -> Value {
        json!({
            "match_id": self.match_id,
            "auction_id": self.auction_id,
            "demand_id": self.demand_id,
            "reserve_id": self.reserve_id,
            "quote_id": self.quote_id,
            "status": self.status.as_str(),
            "matched_units": self.matched_units,
            "fee_bps": self.fee_bps,
            "low_fee_rebate_piconero": self.low_fee_rebate_piconero,
            "encrypted_payout_plan_root": self.encrypted_payout_plan_root,
            "lp_fill_commitment": self.lp_fill_commitment,
            "locked_height": self.locked_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("EXIT-LIQUIDITY-MATCH", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("match_id", &self.match_id)?;
        ensure_non_empty("auction_id", &self.auction_id)?;
        ensure_non_empty("demand_id", &self.demand_id)?;
        ensure_non_empty("reserve_id", &self.reserve_id)?;
        ensure_non_empty("quote_id", &self.quote_id)?;
        ensure_positive("matched_units", self.matched_units)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        ensure_non_empty(
            "encrypted_payout_plan_root",
            &self.encrypted_payout_plan_root,
        )?;
        ensure_non_empty("lp_fill_commitment", &self.lp_fill_commitment)?;
        if self.settlement_deadline_height <= self.locked_height {
            return Err("match settlement_deadline_height must exceed locked_height".to_string());
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSettlementRoot {
    pub batch_id: String,
    pub auction_id: String,
    pub status: SettlementStatus,
    pub match_root: String,
    pub payout_root: String,
    pub nullifier_root: String,
    pub fee_root: String,
    pub reserve_debit_root: String,
    pub monero_txset_root: String,
    pub watchtower_attestation_root: String,
    pub settlement_height: u64,
    pub monero_unlock_height: u64,
    pub finalized_height: Option<u64>,
}

impl BatchSettlementRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "auction_id": self.auction_id,
            "status": self.status.as_str(),
            "match_root": self.match_root,
            "payout_root": self.payout_root,
            "nullifier_root": self.nullifier_root,
            "fee_root": self.fee_root,
            "reserve_debit_root": self.reserve_debit_root,
            "monero_txset_root": self.monero_txset_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "settlement_height": self.settlement_height,
            "monero_unlock_height": self.monero_unlock_height,
            "finalized_height": self.finalized_height,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("BATCH-SETTLEMENT-ROOT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("batch_id", &self.batch_id)?;
        ensure_non_empty("auction_id", &self.auction_id)?;
        for (name, root) in [
            ("match_root", &self.match_root),
            ("payout_root", &self.payout_root),
            ("nullifier_root", &self.nullifier_root),
            ("fee_root", &self.fee_root),
            ("reserve_debit_root", &self.reserve_debit_root),
            ("monero_txset_root", &self.monero_txset_root),
            (
                "watchtower_attestation_root",
                &self.watchtower_attestation_root,
            ),
        ] {
            ensure_non_empty(name, root)?;
        }
        ensure_positive("settlement_height", self.settlement_height)?;
        if self.monero_unlock_height < self.settlement_height {
            return Err("monero_unlock_height below settlement_height".to_string());
        }
        if let Some(finalized_height) = self.finalized_height {
            if finalized_height < self.settlement_height {
                return Err("finalized_height below settlement_height".to_string());
            }
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub accused_id: String,
    pub related_auction_id: String,
    pub related_quote_id: Option<String>,
    pub related_match_id: Option<String>,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub slash_amount_piconero: u64,
    pub accepted: bool,
    pub submitted_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind.as_str(),
            "accused_id": self.accused_id,
            "related_auction_id": self.related_auction_id,
            "related_quote_id": self.related_quote_id,
            "related_match_id": self.related_match_id,
            "evidence_root": self.evidence_root,
            "reporter_commitment": self.reporter_commitment,
            "slash_amount_piconero": self.slash_amount_piconero,
            "accepted": self.accepted,
            "submitted_height": self.submitted_height,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("SLASHING-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        ensure_non_empty("evidence_id", &self.evidence_id)?;
        ensure_non_empty("accused_id", &self.accused_id)?;
        ensure_non_empty("related_auction_id", &self.related_auction_id)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_non_empty("reporter_commitment", &self.reporter_commitment)?;
        ensure_positive("slash_amount_piconero", self.slash_amount_piconero)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitAuctionRoots {
    pub config_root: String,
    pub lane_root: String,
    pub auction_root: String,
    pub demand_root: String,
    pub reserve_root: String,
    pub quote_root: String,
    pub match_root: String,
    pub settlement_root: String,
    pub evidence_root: String,
    pub public_record_root: String,
}

impl FastExitAuctionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "auction_root": self.auction_root,
            "demand_root": self.demand_root,
            "reserve_root": self.reserve_root,
            "quote_root": self.quote_root,
            "match_root": self.match_root,
            "settlement_root": self.settlement_root,
            "evidence_root": self.evidence_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("ROOTS", &self.public_record())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        for (name, root) in [
            ("config_root", &self.config_root),
            ("lane_root", &self.lane_root),
            ("auction_root", &self.auction_root),
            ("demand_root", &self.demand_root),
            ("reserve_root", &self.reserve_root),
            ("quote_root", &self.quote_root),
            ("match_root", &self.match_root),
            ("settlement_root", &self.settlement_root),
            ("evidence_root", &self.evidence_root),
            ("public_record_root", &self.public_record_root),
        ] {
            ensure_non_empty(name, root)?;
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastExitAuctionCounters {
    pub lane_count: usize,
    pub auction_count: usize,
    pub demand_count: usize,
    pub active_demand_count: usize,
    pub reserve_count: usize,
    pub quote_count: usize,
    pub active_quote_count: usize,
    pub match_count: usize,
    pub settlement_count: usize,
    pub evidence_count: usize,
    pub accepted_evidence_count: usize,
    pub public_record_count: usize,
    pub total_matched_units: u64,
    pub total_available_reserve_units: u64,
}

impl FastExitAuctionCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "auction_count": self.auction_count,
            "demand_count": self.demand_count,
            "active_demand_count": self.active_demand_count,
            "reserve_count": self.reserve_count,
            "quote_count": self.quote_count,
            "active_quote_count": self.active_quote_count,
            "match_count": self.match_count,
            "settlement_count": self.settlement_count,
            "evidence_count": self.evidence_count,
            "accepted_evidence_count": self.accepted_evidence_count,
            "public_record_count": self.public_record_count,
            "total_matched_units": self.total_matched_units,
            "total_available_reserve_units": self.total_available_reserve_units,
        })
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFastExitLiquidityAuctionState {
    pub config: FastExitAuctionConfig,
    pub height: u64,
    pub status: String,
    pub lanes: BTreeMap<String, LanePolicy>,
    pub auctions: BTreeMap<String, LiquidityAuction>,
    pub demands: BTreeMap<String, ShieldedExitDemand>,
    pub reserves: BTreeMap<String, LpReserveCommitment>,
    pub quotes: BTreeMap<String, PqQuoteAttestation>,
    pub matches: BTreeMap<String, ExitLiquidityMatch>,
    pub settlements: BTreeMap<String, BatchSettlementRoot>,
    pub evidence: BTreeMap<String, SlashingEvidence>,
    pub public_records: BTreeMap<String, Value>,
}

impl MoneroFastExitLiquidityAuctionState {
    pub fn devnet() -> MoneroFastExitLiquidityAuctionResult<Self> {
        let config = FastExitAuctionConfig::devnet();
        let mut state = Self {
            config,
            height: MONERO_FAST_EXIT_LIQUIDITY_AUCTION_DEVNET_HEIGHT,
            status: STATE_STATUS_ACTIVE.to_string(),
            lanes: BTreeMap::new(),
            auctions: BTreeMap::new(),
            demands: BTreeMap::new(),
            reserves: BTreeMap::new(),
            quotes: BTreeMap::new(),
            matches: BTreeMap::new(),
            settlements: BTreeMap::new(),
            evidence: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        for lane in [
            FastExitLane::LowFee,
            FastExitLane::Standard,
            FastExitLane::Fast,
            FastExitLane::DefiArb,
            FastExitLane::TokenRedemption,
            FastExitLane::SmartContractExit,
            FastExitLane::WalletRecovery,
            FastExitLane::Emergency,
        ] {
            state.insert_lane(LanePolicy::new(lane, &state.config))?;
        }
        let auction = LiquidityAuction {
            auction_id: "fast-exit-auction-devnet-0001".to_string(),
            lane: FastExitLane::LowFee,
            status: AuctionStatus::QuoteOpen,
            opened_height: state.height,
            quote_deadline_height: state.height + state.config.auction_window_blocks,
            settlement_deadline_height: state.height + state.config.settlement_ttl_blocks,
            challenge_deadline_height: state.height
                + state.config.settlement_ttl_blocks
                + state.config.challenge_window_blocks,
            demand_root_hint: fast_exit_empty_root("DEVNET-DEMAND-HINT"),
            reserve_root_hint: fast_exit_empty_root("DEVNET-RESERVE-HINT"),
            min_fill_units: 10_000_000,
            max_fill_units: 1_000_000_000_000,
            clearing_fee_bps: state.config.low_fee_bps,
        };
        state.insert_auction(auction)?;
        let reserve = LpReserveCommitment {
            reserve_id: "devnet-lp-reserve-001".to_string(),
            lp_id: "devnet-lp-alpha".to_string(),
            status: ReserveStatus::QuoteOpen,
            reserve_commitment: fast_exit_tagged_root("DEVNET-RESERVE", "alpha"),
            reserve_view_tag_root: fast_exit_tagged_root("DEVNET-VIEW-TAGS", "alpha"),
            max_fill_units: 2_000_000_000_000,
            available_units: 1_500_000_000_000,
            min_fee_bps: state.config.low_fee_bps,
            bond_commitment: fast_exit_tagged_root("DEVNET-BOND", "alpha"),
            pq_public_key_commitment: fast_exit_tagged_root("DEVNET-PQ-PK", "alpha"),
            attestation_root: fast_exit_tagged_root("DEVNET-RESERVE-ATTESTATION", "alpha"),
            opened_height: state.height,
            expires_height: state.height + 500,
        };
        state.insert_reserve(reserve)?;
        let demand = ShieldedExitDemand {
            demand_id: "devnet-demand-001".to_string(),
            auction_id: "fast-exit-auction-devnet-0001".to_string(),
            lane: FastExitLane::LowFee,
            status: ExitDemandStatus::QuoteRequested,
            amount_commitment: fast_exit_tagged_root("DEVNET-DEMAND-AMOUNT", "001"),
            nullifier_commitment: fast_exit_tagged_root("DEVNET-DEMAND-NULLIFIER", "001"),
            destination_subaddress_commitment: fast_exit_tagged_root("DEVNET-SUBADDRESS", "001"),
            range_proof_root: fast_exit_tagged_root("DEVNET-RANGE-PROOF", "001"),
            privacy_bucket_units: 10_000_000,
            max_fee_bps: state.config.low_fee_bps,
            sponsor_commitment: Some(fast_exit_tagged_root("DEVNET-SPONSOR", "001")),
            submitted_height: state.height,
            expires_height: state.height + state.config.low_fee_ttl_blocks,
        };
        state.insert_demand(demand)?;
        let quote = PqQuoteAttestation {
            quote_id: "devnet-quote-001".to_string(),
            auction_id: "fast-exit-auction-devnet-0001".to_string(),
            reserve_id: "devnet-lp-reserve-001".to_string(),
            demand_commitment_root: state.demands["devnet-demand-001"].state_root(),
            encrypted_quote_root: fast_exit_tagged_root("DEVNET-ENCRYPTED-QUOTE", "001"),
            fee_bps: state.config.low_fee_bps,
            fill_units: 10_000_000,
            status: QuoteStatus::Eligible,
            pq_scheme: state.config.pq_quote_scheme.clone(),
            pq_security_bits: state.config.min_pq_security_bits,
            signer_commitment: fast_exit_tagged_root("DEVNET-LP-SIGNER", "alpha"),
            signature_root: fast_exit_tagged_root("DEVNET-QUOTE-SIGNATURE", "001"),
            submitted_height: state.height + 1,
            expires_height: state.height + state.config.quote_ttl_blocks,
        };
        state.insert_quote(quote)?;
        let matched = ExitLiquidityMatch {
            match_id: "devnet-match-001".to_string(),
            auction_id: "fast-exit-auction-devnet-0001".to_string(),
            demand_id: "devnet-demand-001".to_string(),
            reserve_id: "devnet-lp-reserve-001".to_string(),
            quote_id: "devnet-quote-001".to_string(),
            status: MatchStatus::Locked,
            matched_units: 10_000_000,
            fee_bps: state.config.low_fee_bps,
            low_fee_rebate_piconero: 5_000,
            encrypted_payout_plan_root: fast_exit_tagged_root("DEVNET-PAYOUT-PLAN", "001"),
            lp_fill_commitment: fast_exit_tagged_root("DEVNET-LP-FILL", "001"),
            locked_height: state.height + 2,
            settlement_deadline_height: state.height + state.config.settlement_ttl_blocks,
        };
        state.insert_match(matched)?;
        let settlement = BatchSettlementRoot {
            batch_id: "devnet-settlement-batch-001".to_string(),
            auction_id: "fast-exit-auction-devnet-0001".to_string(),
            status: SettlementStatus::Broadcast,
            match_root: state.matches["devnet-match-001"].state_root(),
            payout_root: fast_exit_tagged_root("DEVNET-PAYOUT-ROOT", "001"),
            nullifier_root: fast_exit_tagged_root("DEVNET-NULLIFIER-ROOT", "001"),
            fee_root: fast_exit_tagged_root("DEVNET-FEE-ROOT", "001"),
            reserve_debit_root: fast_exit_tagged_root("DEVNET-RESERVE-DEBIT", "001"),
            monero_txset_root: fast_exit_tagged_root("DEVNET-MONERO-TXSET", "001"),
            watchtower_attestation_root: fast_exit_tagged_root("DEVNET-WATCHTOWER", "001"),
            settlement_height: state.height + 3,
            monero_unlock_height: state.height + 13,
            finalized_height: None,
        };
        state.insert_settlement(settlement)?;
        state.refresh_public_records();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroFastExitLiquidityAuctionResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        for auction in self.auctions.values_mut() {
            if !auction.status.terminal() && height > auction.challenge_deadline_height {
                auction.status = AuctionStatus::Expired;
            }
        }
        for demand in self.demands.values_mut() {
            if demand.status.active() && height > demand.expires_height {
                demand.status = ExitDemandStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if quote.status.active() && height > quote.expires_height {
                quote.status = QuoteStatus::Expired;
            }
        }
        self.refresh_public_records();
        self.validate()?;
        Ok(())
    }

    pub fn roots(&self) -> FastExitAuctionRoots {
        FastExitAuctionRoots {
            config_root: self.config.state_root(),
            lane_root: map_merkle_root("LANES", &self.lanes),
            auction_root: map_merkle_root("AUCTIONS", &self.auctions),
            demand_root: map_merkle_root("DEMANDS", &self.demands),
            reserve_root: map_merkle_root("RESERVES", &self.reserves),
            quote_root: map_merkle_root("QUOTES", &self.quotes),
            match_root: map_merkle_root("MATCHES", &self.matches),
            settlement_root: map_merkle_root("SETTLEMENTS", &self.settlements),
            evidence_root: map_merkle_root("EVIDENCE", &self.evidence),
            public_record_root: merkle_root(
                "MONERO-FAST-EXIT-LIQUIDITY-AUCTION:PUBLIC-RECORDS",
                &self
                    .public_records
                    .iter()
                    .map(|(key, value)| json!({"key": key, "value": value}))
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> FastExitAuctionCounters {
        FastExitAuctionCounters {
            lane_count: self.lanes.len(),
            auction_count: self.auctions.len(),
            demand_count: self.demands.len(),
            active_demand_count: self
                .demands
                .values()
                .filter(|demand| demand.status.active())
                .count(),
            reserve_count: self.reserves.len(),
            quote_count: self.quotes.len(),
            active_quote_count: self
                .quotes
                .values()
                .filter(|quote| quote.status.active())
                .count(),
            match_count: self.matches.len(),
            settlement_count: self.settlements.len(),
            evidence_count: self.evidence.len(),
            accepted_evidence_count: self
                .evidence
                .values()
                .filter(|evidence| evidence.accepted)
                .count(),
            public_record_count: self.public_records.len(),
            total_matched_units: self
                .matches
                .values()
                .map(|matched| matched.matched_units)
                .sum(),
            total_available_reserve_units: self
                .reserves
                .values()
                .map(|reserve| reserve.available_units)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        fast_exit_payload_root("STATE", &self.public_record_without_state_root())
    }

    pub fn validate(&self) -> MoneroFastExitLiquidityAuctionResult<String> {
        self.config.validate()?;
        ensure_non_empty("status", &self.status)?;
        if !matches!(
            self.status.as_str(),
            STATE_STATUS_ACTIVE | STATE_STATUS_CHALLENGED | STATE_STATUS_HALTED
        ) {
            return Err("invalid fast exit auction state status".to_string());
        }
        ensure_len(
            "lanes",
            self.lanes.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_LANES,
        )?;
        ensure_len(
            "auctions",
            self.auctions.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_AUCTIONS,
        )?;
        ensure_len(
            "demands",
            self.demands.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_DEMANDS,
        )?;
        ensure_len(
            "reserves",
            self.reserves.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_RESERVES,
        )?;
        ensure_len(
            "quotes",
            self.quotes.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_QUOTES,
        )?;
        ensure_len(
            "matches",
            self.matches.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_MATCHES,
        )?;
        ensure_len(
            "settlements",
            self.settlements.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_SETTLEMENTS,
        )?;
        ensure_len(
            "evidence",
            self.evidence.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_EVIDENCE,
        )?;
        ensure_len(
            "public_records",
            self.public_records.len(),
            MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_PUBLIC_RECORDS,
        )?;
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for auction in self.auctions.values() {
            auction.validate()?;
        }
        for demand in self.demands.values() {
            demand.validate()?;
            if !self.auctions.contains_key(&demand.auction_id) {
                return Err(format!(
                    "demand {} references missing auction",
                    demand.demand_id
                ));
            }
        }
        for reserve in self.reserves.values() {
            reserve.validate()?;
            if reserve.status.can_quote()
                && reserve.min_fee_bps
                    > self
                        .config
                        .max_exit_fee_bps
                        .max(self.config.emergency_fee_bps)
            {
                return Err(format!(
                    "reserve {} min fee exceeds configured cap",
                    reserve.reserve_id
                ));
            }
        }
        for quote in self.quotes.values() {
            quote.validate()?;
            if !self.auctions.contains_key(&quote.auction_id) {
                return Err(format!(
                    "quote {} references missing auction",
                    quote.quote_id
                ));
            }
            let reserve = self
                .reserves
                .get(&quote.reserve_id)
                .ok_or_else(|| format!("quote {} references missing reserve", quote.quote_id))?;
            if quote.fill_units > reserve.max_fill_units {
                return Err(format!("quote {} exceeds reserve max fill", quote.quote_id));
            }
            if quote.pq_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "quote {} below configured PQ security",
                    quote.quote_id
                ));
            }
        }
        let mut matched_demands = BTreeSet::new();
        for matched in self.matches.values() {
            matched.validate()?;
            if !matched_demands.insert(matched.demand_id.clone()) {
                return Err(format!(
                    "demand {} matched more than once",
                    matched.demand_id
                ));
            }
            let demand = self
                .demands
                .get(&matched.demand_id)
                .ok_or_else(|| format!("match {} references missing demand", matched.match_id))?;
            let quote = self
                .quotes
                .get(&matched.quote_id)
                .ok_or_else(|| format!("match {} references missing quote", matched.match_id))?;
            if matched.fee_bps > demand.max_fee_bps {
                return Err(format!("match {} fee exceeds demand cap", matched.match_id));
            }
            if matched.fee_bps != quote.fee_bps {
                return Err(format!(
                    "match {} fee does not equal quote fee",
                    matched.match_id
                ));
            }
            if matched.matched_units > quote.fill_units {
                return Err(format!("match {} exceeds quote fill", matched.match_id));
            }
        }
        for settlement in self.settlements.values() {
            settlement.validate()?;
            if !self.auctions.contains_key(&settlement.auction_id) {
                return Err(format!(
                    "settlement {} references missing auction",
                    settlement.batch_id
                ));
            }
        }
        for evidence in self.evidence.values() {
            evidence.validate()?;
            if !self.auctions.contains_key(&evidence.related_auction_id) {
                return Err(format!(
                    "evidence {} references missing auction",
                    evidence.evidence_id
                ));
            }
        }
        self.roots().validate()?;
        Ok(self.state_root())
    }

    pub fn insert_lane(&mut self, lane: LanePolicy) -> MoneroFastExitLiquidityAuctionResult<()> {
        lane.validate()?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_auction(
        &mut self,
        auction: LiquidityAuction,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        auction.validate()?;
        self.auctions.insert(auction.auction_id.clone(), auction);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_demand(
        &mut self,
        demand: ShieldedExitDemand,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        demand.validate()?;
        if !self.auctions.contains_key(&demand.auction_id) {
            return Err("cannot insert demand for missing auction".to_string());
        }
        self.demands.insert(demand.demand_id.clone(), demand);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_reserve(
        &mut self,
        reserve: LpReserveCommitment,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        reserve.validate()?;
        self.reserves.insert(reserve.reserve_id.clone(), reserve);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_quote(
        &mut self,
        quote: PqQuoteAttestation,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        quote.validate()?;
        if !self.auctions.contains_key(&quote.auction_id) {
            return Err("cannot insert quote for missing auction".to_string());
        }
        if !self.reserves.contains_key(&quote.reserve_id) {
            return Err("cannot insert quote for missing reserve".to_string());
        }
        self.quotes.insert(quote.quote_id.clone(), quote);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_match(
        &mut self,
        matched: ExitLiquidityMatch,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        matched.validate()?;
        if !self.demands.contains_key(&matched.demand_id) {
            return Err("cannot insert match for missing demand".to_string());
        }
        if !self.quotes.contains_key(&matched.quote_id) {
            return Err("cannot insert match for missing quote".to_string());
        }
        self.matches.insert(matched.match_id.clone(), matched);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_settlement(
        &mut self,
        settlement: BatchSettlementRoot,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        settlement.validate()?;
        if !self.auctions.contains_key(&settlement.auction_id) {
            return Err("cannot insert settlement for missing auction".to_string());
        }
        self.settlements
            .insert(settlement.batch_id.clone(), settlement);
        self.refresh_public_records();
        Ok(())
    }

    pub fn insert_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> MoneroFastExitLiquidityAuctionResult<()> {
        evidence.validate()?;
        if !self.auctions.contains_key(&evidence.related_auction_id) {
            return Err("cannot insert evidence for missing auction".to_string());
        }
        if evidence.accepted {
            self.status = STATE_STATUS_CHALLENGED.to_string();
        }
        self.evidence.insert(evidence.evidence_id.clone(), evidence);
        self.refresh_public_records();
        Ok(())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    fn refresh_public_records(&mut self) {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        for (id, lane) in &self.lanes {
            records.insert(format!("lane:{id}"), lane.public_record());
        }
        for (id, auction) in &self.auctions {
            records.insert(format!("auction:{id}"), auction.public_record());
        }
        for (id, demand) in &self.demands {
            records.insert(format!("demand:{id}"), demand.public_record());
        }
        for (id, reserve) in &self.reserves {
            records.insert(format!("reserve:{id}"), reserve.public_record());
        }
        for (id, quote) in &self.quotes {
            records.insert(format!("quote:{id}"), quote.public_record());
        }
        for (id, matched) in &self.matches {
            records.insert(format!("match:{id}"), matched.public_record());
        }
        for (id, settlement) in &self.settlements {
            records.insert(format!("settlement:{id}"), settlement.public_record());
        }
        for (id, evidence) in &self.evidence {
            records.insert(format!("evidence:{id}"), evidence.public_record());
        }
        self.public_records = records;
    }
}

pub trait FastExitPublicRecord {
    fn public_record(&self) -> Value;
}

impl FastExitPublicRecord for LanePolicy {
    fn public_record(&self) -> Value {
        LanePolicy::public_record(self)
    }
}

impl FastExitPublicRecord for LiquidityAuction {
    fn public_record(&self) -> Value {
        LiquidityAuction::public_record(self)
    }
}

impl FastExitPublicRecord for ShieldedExitDemand {
    fn public_record(&self) -> Value {
        ShieldedExitDemand::public_record(self)
    }
}

impl FastExitPublicRecord for LpReserveCommitment {
    fn public_record(&self) -> Value {
        LpReserveCommitment::public_record(self)
    }
}

impl FastExitPublicRecord for PqQuoteAttestation {
    fn public_record(&self) -> Value {
        PqQuoteAttestation::public_record(self)
    }
}

impl FastExitPublicRecord for ExitLiquidityMatch {
    fn public_record(&self) -> Value {
        ExitLiquidityMatch::public_record(self)
    }
}

impl FastExitPublicRecord for BatchSettlementRoot {
    fn public_record(&self) -> Value {
        BatchSettlementRoot::public_record(self)
    }
}

impl FastExitPublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

fn map_merkle_root<T: FastExitPublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-FAST-EXIT-LIQUIDITY-AUCTION:{domain}"),
        &leaves,
    )
}

fn fast_exit_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-FAST-EXIT-LIQUIDITY-AUCTION:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn fast_exit_empty_root(domain: &str) -> String {
    domain_hash(
        &format!("MONERO-FAST-EXIT-LIQUIDITY-AUCTION:{domain}:EMPTY"),
        &[],
        32,
    )
}

fn fast_exit_tagged_root(domain: &str, tag: &str) -> String {
    domain_hash(
        &format!("MONERO-FAST-EXIT-LIQUIDITY-AUCTION:{domain}"),
        &[HashPart::Str(tag)],
        32,
    )
}

fn ensure_non_empty(field: &str, value: &str) -> MoneroFastExitLiquidityAuctionResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> MoneroFastExitLiquidityAuctionResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> MoneroFastExitLiquidityAuctionResult<()> {
    if value > MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn ensure_coverage_bps(field: &str, value: u64) -> MoneroFastExitLiquidityAuctionResult<()> {
    if value < MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_BPS {
        Err(format!("{field} must cover at least 100%"))
    } else if value > MONERO_FAST_EXIT_LIQUIDITY_AUCTION_MAX_BPS * 3 {
        Err(format!("{field} exceeds conservative coverage ceiling"))
    } else {
        Ok(())
    }
}

fn ensure_equal(
    field: &str,
    actual: &str,
    expected: &str,
) -> MoneroFastExitLiquidityAuctionResult<()> {
    if actual != expected {
        Err(format!("{field} must be {expected}"))
    } else {
        Ok(())
    }
}

fn ensure_len(field: &str, len: usize, max: usize) -> MoneroFastExitLiquidityAuctionResult<()> {
    if len > max {
        Err(format!("{field} exceeds max length {max}"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    opened: u64,
    quote_deadline: u64,
    settlement_deadline: u64,
    challenge_deadline: u64,
) -> MoneroFastExitLiquidityAuctionResult<()> {
    if opened >= quote_deadline {
        return Err("quote_deadline_height must exceed opened_height".to_string());
    }
    if quote_deadline > settlement_deadline {
        return Err("settlement_deadline_height below quote_deadline_height".to_string());
    }
    if settlement_deadline > challenge_deadline {
        return Err("challenge_deadline_height below settlement_deadline_height".to_string());
    }
    Ok(())
}
