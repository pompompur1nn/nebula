use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialLendingResult<T> = Result<T, String>;

pub const CONFIDENTIAL_LENDING_PROTOCOL_VERSION: &str = "nebula-confidential-lending-v1";
pub const CONFIDENTIAL_LENDING_COMMITMENT_SCHEME: &str =
    "devnet-shake256-private-lending-commitment-v1";
pub const CONFIDENTIAL_LENDING_NOTE_ENCRYPTION_SCHEME: &str = "devnet-xwing-note-envelope-root-v1";
pub const CONFIDENTIAL_LENDING_RANGE_PROOF_SCHEME: &str = "devnet-mock-pq-range-proof-v1";
pub const CONFIDENTIAL_LENDING_HEALTH_PROOF_SCHEME: &str = "devnet-private-health-bucket-proof-v1";
pub const CONFIDENTIAL_LENDING_PQ_AUTH_SCHEME: &str = "ml-dsa-87-devnet-authorization-v1";
pub const CONFIDENTIAL_LENDING_PQ_ATTESTATION_SCHEME: &str =
    "slh-dsa-shake-256f-devnet-attestation-v1";
pub const CONFIDENTIAL_LENDING_ORACLE_SCHEME: &str = "threshold-oracle-guard-root-v1";
pub const CONFIDENTIAL_LENDING_AUCTION_SCHEME: &str = "private-dutch-auction-bid-root-v1";
pub const CONFIDENTIAL_LENDING_DISCLOSURE_SCHEME: &str = "bucket-only-lending-disclosure-root-v1";
pub const CONFIDENTIAL_LENDING_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_LENDING_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_LENDING_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_LENDING_BLOCKS_PER_YEAR: u64 = 2_628_000;
pub const CONFIDENTIAL_LENDING_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_LENDING_DEFAULT_ORACLE_DEVIATION_BPS: u64 = 650;
pub const CONFIDENTIAL_LENDING_DEFAULT_HEALTH_BUCKET_TTL_BLOCKS: u64 = 16;
pub const CONFIDENTIAL_LENDING_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 48;
pub const CONFIDENTIAL_LENDING_DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 21_600;
pub const CONFIDENTIAL_LENDING_DEFAULT_LOW_FEE_LANE: &str = "small-private-lending";
pub const CONFIDENTIAL_LENDING_DEVNET_HEIGHT: u64 = 104;
pub const CONFIDENTIAL_LENDING_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_LENDING_DEVNET_DEBT_ASSET_ID: &str = "usdd-devnet";
pub const CONFIDENTIAL_LENDING_DEVNET_RESERVE_ASSET_ID: &str = "dlend-reserve-devnet";
pub const CONFIDENTIAL_LENDING_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-usdd-devnet";
pub const CONFIDENTIAL_LENDING_DEVNET_WXMR_PRICE: u64 = 162 * CONFIDENTIAL_LENDING_PRICE_SCALE;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialLendingMarketStatus {
    Active,
    BorrowPaused,
    SupplyPaused,
    LiquidationOnly,
    ReduceOnly,
    Paused,
    Retired,
}

impl ConfidentialLendingMarketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::BorrowPaused => "borrow_paused",
            Self::SupplyPaused => "supply_paused",
            Self::LiquidationOnly => "liquidation_only",
            Self::ReduceOnly => "reduce_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn allows_supply(&self) -> bool {
        matches!(self, Self::Active | Self::BorrowPaused)
    }

    pub fn allows_borrow(&self) -> bool {
        matches!(self, Self::Active | Self::SupplyPaused)
    }

    pub fn allows_liquidation(&self) -> bool {
        matches!(
            self,
            Self::Active
                | Self::BorrowPaused
                | Self::SupplyPaused
                | Self::LiquidationOnly
                | Self::ReduceOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BorrowerCommitmentStatus {
    Pending,
    Open,
    Frozen,
    Liquidating,
    Settled,
    Closed,
    Expired,
}

impl BorrowerCommitmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Frozen => "frozen",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Pending | Self::Open | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialNoteStatus {
    Pending,
    Active,
    Locked,
    Encumbered,
    Liquidating,
    Spent,
    Released,
    Expired,
}

impl ConfidentialNoteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Encumbered => "encumbered",
            Self::Liquidating => "liquidating",
            Self::Spent => "spent",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_open(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Active | Self::Locked | Self::Encumbered | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthBucket {
    NoDebt,
    SuperSafe,
    Healthy,
    Watch,
    Unsafe,
    Liquidatable,
    Insolvent,
}

impl HealthBucket {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoDebt => "no_debt",
            Self::SuperSafe => "super_safe",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Unsafe => "unsafe",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }

    pub fn floor_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::SuperSafe => 20_000,
            Self::Healthy => 15_000,
            Self::Watch => 12_500,
            Self::Unsafe => 10_000,
            Self::Liquidatable => 8_000,
            Self::Insolvent => 0,
        }
    }

    pub fn ceiling_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::SuperSafe => u64::MAX - 1,
            Self::Healthy => 19_999,
            Self::Watch => 14_999,
            Self::Unsafe => 12_499,
            Self::Liquidatable => 9_999,
            Self::Insolvent => 7_999,
        }
    }

    pub fn from_health_factor_bps(health_factor_bps: u64) -> Self {
        if health_factor_bps == u64::MAX {
            Self::NoDebt
        } else if health_factor_bps >= 20_000 {
            Self::SuperSafe
        } else if health_factor_bps >= 15_000 {
            Self::Healthy
        } else if health_factor_bps >= 12_500 {
            Self::Watch
        } else if health_factor_bps >= 10_000 {
            Self::Unsafe
        } else if health_factor_bps >= 8_000 {
            Self::Liquidatable
        } else {
            Self::Insolvent
        }
    }

    pub fn can_liquidate(&self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleGuardAction {
    Allow,
    Watch,
    FreezeBorrow,
    BlockLiquidation,
    FreezeMarket,
}

impl OracleGuardAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Watch => "watch",
            Self::FreezeBorrow => "freeze_borrow",
            Self::BlockLiquidation => "block_liquidation",
            Self::FreezeMarket => "freeze_market",
        }
    }

    pub fn allows_borrow(&self) -> bool {
        matches!(self, Self::Allow | Self::Watch | Self::BlockLiquidation)
    }

    pub fn allows_liquidation(&self) -> bool {
        matches!(self, Self::Allow | Self::Watch | Self::FreezeBorrow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateAuctionStatus {
    Preview,
    Open,
    Clearing,
    ChallengeOpen,
    Settled,
    Cancelled,
    Expired,
}

impl PrivateAuctionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Open => "open",
            Self::Clearing => "clearing",
            Self::ChallengeOpen => "challenge_open",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBidStatus {
    Committed,
    Eligible,
    RevealedToCircuit,
    Selected,
    Settled,
    Refunded,
    Expired,
}

impl PrivateBidStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Eligible => "eligible",
            Self::RevealedToCircuit => "revealed_to_circuit",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSponsorshipStatus {
    Reserved,
    Active,
    Applied,
    Reclaimed,
    Expired,
    Revoked,
}

impl LowFeeSponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationDecision {
    Approve,
    Watch,
    ReduceCaps,
    PauseBorrow,
    PauseLiquidation,
    Reject,
}

impl PqAuthorizationDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Watch => "watch",
            Self::ReduceCaps => "reduce_caps",
            Self::PauseBorrow => "pause_borrow",
            Self::PauseLiquidation => "pause_liquidation",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialRiskSeverity {
    Info,
    Watch,
    Elevated,
    Critical,
}

impl ConfidentialRiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Info => 500,
            Self::Watch => 2_500,
            Self::Elevated => 6_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskControlScope {
    Global,
    Market,
    Oracle,
    HealthBucket,
    Auction,
    LowFeeSponsor,
    PqCommittee,
}

impl RiskControlScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Market => "market",
            Self::Oracle => "oracle",
            Self::HealthBucket => "health_bucket",
            Self::Auction => "auction",
            Self::LowFeeSponsor => "low_fee_sponsor",
            Self::PqCommittee => "pq_committee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskControlStatus {
    Closed,
    Watching,
    Open,
    CoolingDown,
    Retired,
}

impl RiskControlStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Watching => "watching",
            Self::Open => "open",
            Self::CoolingDown => "cooling_down",
            Self::Retired => "retired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Watching | Self::Open | Self::CoolingDown)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveFundStatus {
    Active,
    Draining,
    Paused,
    Exhausted,
    Retired,
}

impl ReserveFundStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingConfig {
    pub protocol_version: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub reserve_asset_id: String,
    pub commitment_scheme: String,
    pub note_encryption_scheme: String,
    pub range_proof_scheme: String,
    pub health_proof_scheme: String,
    pub pq_authorization_scheme: String,
    pub pq_attestation_scheme: String,
    pub oracle_scheme: String,
    pub auction_scheme: String,
    pub disclosure_scheme: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub blocks_per_year: u64,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub reserve_factor_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub max_oracle_deviation_bps: u64,
    pub default_health_bucket_ttl_blocks: u64,
    pub default_auction_ttl_blocks: u64,
    pub default_commitment_ttl_blocks: u64,
    pub min_private_borrow_units: u64,
    pub max_private_borrow_units: u64,
    pub sponsored_small_borrow_limit_units: u64,
    pub sponsored_max_fee_units: u64,
    pub default_low_fee_lane: String,
    pub metadata_root: String,
}

impl Default for ConfidentialLendingConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl ConfidentialLendingConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_LENDING_PROTOCOL_VERSION.to_string(),
            collateral_asset_id: CONFIDENTIAL_LENDING_DEVNET_COLLATERAL_ASSET_ID.to_string(),
            debt_asset_id: CONFIDENTIAL_LENDING_DEVNET_DEBT_ASSET_ID.to_string(),
            reserve_asset_id: CONFIDENTIAL_LENDING_DEVNET_RESERVE_ASSET_ID.to_string(),
            commitment_scheme: CONFIDENTIAL_LENDING_COMMITMENT_SCHEME.to_string(),
            note_encryption_scheme: CONFIDENTIAL_LENDING_NOTE_ENCRYPTION_SCHEME.to_string(),
            range_proof_scheme: CONFIDENTIAL_LENDING_RANGE_PROOF_SCHEME.to_string(),
            health_proof_scheme: CONFIDENTIAL_LENDING_HEALTH_PROOF_SCHEME.to_string(),
            pq_authorization_scheme: CONFIDENTIAL_LENDING_PQ_AUTH_SCHEME.to_string(),
            pq_attestation_scheme: CONFIDENTIAL_LENDING_PQ_ATTESTATION_SCHEME.to_string(),
            oracle_scheme: CONFIDENTIAL_LENDING_ORACLE_SCHEME.to_string(),
            auction_scheme: CONFIDENTIAL_LENDING_AUCTION_SCHEME.to_string(),
            disclosure_scheme: CONFIDENTIAL_LENDING_DISCLOSURE_SCHEME.to_string(),
            price_scale: CONFIDENTIAL_LENDING_PRICE_SCALE,
            index_scale: CONFIDENTIAL_LENDING_INDEX_SCALE,
            blocks_per_year: CONFIDENTIAL_LENDING_BLOCKS_PER_YEAR,
            collateral_factor_bps: 6_500,
            liquidation_threshold_bps: 8_250,
            liquidation_bonus_bps: 700,
            reserve_factor_bps: 1_250,
            protocol_fee_bps: 75,
            max_oracle_staleness_blocks: CONFIDENTIAL_LENDING_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            max_oracle_deviation_bps: CONFIDENTIAL_LENDING_DEFAULT_ORACLE_DEVIATION_BPS,
            default_health_bucket_ttl_blocks: CONFIDENTIAL_LENDING_DEFAULT_HEALTH_BUCKET_TTL_BLOCKS,
            default_auction_ttl_blocks: CONFIDENTIAL_LENDING_DEFAULT_AUCTION_TTL_BLOCKS,
            default_commitment_ttl_blocks: CONFIDENTIAL_LENDING_DEFAULT_COMMITMENT_TTL_BLOCKS,
            min_private_borrow_units: 1_000_000,
            max_private_borrow_units: 250_000_000_000,
            sponsored_small_borrow_limit_units: 25_000_000,
            sponsored_max_fee_units: 5_000,
            default_low_fee_lane: CONFIDENTIAL_LENDING_DEFAULT_LOW_FEE_LANE.to_string(),
            metadata_root: confidential_lending_payload_root(
                "CONFIDENTIAL-LENDING-CONFIG-METADATA",
                &json!({"mode": "devnet", "privacy": "bucketed-private-lending"}),
            ),
        }
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.protocol_version, "config protocol_version")?;
        ensure_non_empty(&self.collateral_asset_id, "config collateral_asset_id")?;
        ensure_non_empty(&self.debt_asset_id, "config debt_asset_id")?;
        ensure_non_empty(&self.reserve_asset_id, "config reserve_asset_id")?;
        ensure_non_empty(&self.commitment_scheme, "config commitment_scheme")?;
        ensure_non_empty(
            &self.note_encryption_scheme,
            "config note_encryption_scheme",
        )?;
        ensure_non_empty(&self.range_proof_scheme, "config range_proof_scheme")?;
        ensure_non_empty(&self.health_proof_scheme, "config health_proof_scheme")?;
        ensure_non_empty(
            &self.pq_authorization_scheme,
            "config pq_authorization_scheme",
        )?;
        ensure_non_empty(&self.pq_attestation_scheme, "config pq_attestation_scheme")?;
        ensure_non_empty(&self.oracle_scheme, "config oracle_scheme")?;
        ensure_non_empty(&self.auction_scheme, "config auction_scheme")?;
        ensure_non_empty(&self.disclosure_scheme, "config disclosure_scheme")?;
        ensure_non_empty(&self.default_low_fee_lane, "config default_low_fee_lane")?;
        ensure_bps(self.collateral_factor_bps, "config collateral_factor_bps")?;
        ensure_bps(
            self.liquidation_threshold_bps,
            "config liquidation_threshold_bps",
        )?;
        ensure_bps(self.liquidation_bonus_bps, "config liquidation_bonus_bps")?;
        ensure_bps(self.reserve_factor_bps, "config reserve_factor_bps")?;
        ensure_bps(self.protocol_fee_bps, "config protocol_fee_bps")?;
        ensure_bps(
            self.max_oracle_deviation_bps,
            "config max_oracle_deviation_bps",
        )?;
        if self.collateral_factor_bps >= self.liquidation_threshold_bps {
            return Err("config collateral factor must be below liquidation threshold".to_string());
        }
        if self.price_scale == 0 || self.index_scale == 0 || self.blocks_per_year == 0 {
            return Err("config scales and blocks_per_year must be positive".to_string());
        }
        if self.max_oracle_staleness_blocks == 0
            || self.default_health_bucket_ttl_blocks == 0
            || self.default_auction_ttl_blocks == 0
            || self.default_commitment_ttl_blocks == 0
        {
            return Err("config ttl and staleness settings must be positive".to_string());
        }
        if self.min_private_borrow_units == 0
            || self.min_private_borrow_units > self.max_private_borrow_units
        {
            return Err("config private borrow bounds are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "commitment_scheme": self.commitment_scheme,
            "note_encryption_scheme": self.note_encryption_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "health_proof_scheme": self.health_proof_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "oracle_scheme": self.oracle_scheme,
            "auction_scheme": self.auction_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "blocks_per_year": self.blocks_per_year,
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "default_health_bucket_ttl_blocks": self.default_health_bucket_ttl_blocks,
            "default_auction_ttl_blocks": self.default_auction_ttl_blocks,
            "default_commitment_ttl_blocks": self.default_commitment_ttl_blocks,
            "min_private_borrow_units": self.min_private_borrow_units,
            "max_private_borrow_units": self.max_private_borrow_units,
            "sponsored_small_borrow_limit_units": self.sponsored_small_borrow_limit_units,
            "sponsored_max_fee_units": self.sponsored_max_fee_units,
            "default_low_fee_lane": self.default_low_fee_lane,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        confidential_lending_payload_root("CONFIDENTIAL-LENDING-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingMarket {
    pub market_id: String,
    pub display_name: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub oracle_feed_id: String,
    pub low_fee_lane: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub reserve_factor_bps: u64,
    pub protocol_fee_bps: u64,
    pub base_borrow_rate_bps: u64,
    pub kink_utilization_bps: u64,
    pub jump_borrow_rate_bps: u64,
    pub supply_cap_units: u64,
    pub borrow_cap_units: u64,
    pub private_borrow_floor_units: u64,
    pub total_collateral_upper_bound_units: u64,
    pub total_debt_upper_bound_units: u64,
    pub reserve_floor_units: u64,
    pub created_at_height: u64,
    pub status: ConfidentialLendingMarketStatus,
    pub oracle_guard_root: String,
    pub health_bucket_root: String,
    pub risk_control_root: String,
    pub pq_authorization_root: String,
    pub metadata_root: String,
}

impl ConfidentialLendingMarket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        display_name: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        oracle_feed_id: &str,
        low_fee_lane: &str,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        liquidation_bonus_bps: u64,
        reserve_factor_bps: u64,
        protocol_fee_bps: u64,
        supply_cap_units: u64,
        borrow_cap_units: u64,
        private_borrow_floor_units: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(display_name, "market display_name")?;
        ensure_non_empty(collateral_asset_id, "market collateral_asset_id")?;
        ensure_non_empty(debt_asset_id, "market debt_asset_id")?;
        ensure_non_empty(oracle_feed_id, "market oracle_feed_id")?;
        ensure_non_empty(low_fee_lane, "market low_fee_lane")?;
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-MARKET-METADATA", metadata);
        let market_id = confidential_lending_market_id(
            display_name,
            collateral_asset_id,
            debt_asset_id,
            oracle_feed_id,
            created_at_height,
            &metadata_root,
        );
        let market = Self {
            market_id,
            display_name: display_name.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            price_scale: CONFIDENTIAL_LENDING_PRICE_SCALE,
            index_scale: CONFIDENTIAL_LENDING_INDEX_SCALE,
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            reserve_factor_bps,
            protocol_fee_bps,
            base_borrow_rate_bps: 250,
            kink_utilization_bps: 7_500,
            jump_borrow_rate_bps: 2_400,
            supply_cap_units,
            borrow_cap_units,
            private_borrow_floor_units,
            total_collateral_upper_bound_units: 0,
            total_debt_upper_bound_units: 0,
            reserve_floor_units: 0,
            created_at_height,
            status: ConfidentialLendingMarketStatus::Active,
            oracle_guard_root: merkle_root("CONFIDENTIAL-LENDING-ORACLE-GUARD", &[]),
            health_bucket_root: merkle_root("CONFIDENTIAL-LENDING-HEALTH-BUCKET", &[]),
            risk_control_root: merkle_root("CONFIDENTIAL-LENDING-RISK-CONTROL", &[]),
            pq_authorization_root: merkle_root("CONFIDENTIAL-LENDING-PQ-AUTHORIZATION", &[]),
            metadata_root,
        };
        market.validate()?;
        Ok(market)
    }

    pub fn wxmr_usdd_devnet(created_at_height: u64) -> ConfidentialLendingResult<Self> {
        Self::new(
            "wXMR private lending devnet",
            CONFIDENTIAL_LENDING_DEVNET_COLLATERAL_ASSET_ID,
            CONFIDENTIAL_LENDING_DEVNET_DEBT_ASSET_ID,
            CONFIDENTIAL_LENDING_DEVNET_ORACLE_FEED_ID,
            CONFIDENTIAL_LENDING_DEFAULT_LOW_FEE_LANE,
            6_500,
            8_250,
            700,
            1_250,
            75,
            15_000_000_000_000,
            2_500_000_000_000,
            1_000_000,
            created_at_height,
            &json!({
                "environment": "devnet",
                "privacy": "borrower commitments plus encrypted collateral and debt notes",
                "oracle": "threshold guarded health buckets"
            }),
        )
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.market_id, "market market_id")?;
        ensure_non_empty(&self.display_name, "market display_name")?;
        ensure_non_empty(&self.collateral_asset_id, "market collateral_asset_id")?;
        ensure_non_empty(&self.debt_asset_id, "market debt_asset_id")?;
        ensure_non_empty(&self.oracle_feed_id, "market oracle_feed_id")?;
        ensure_non_empty(&self.low_fee_lane, "market low_fee_lane")?;
        ensure_bps(self.collateral_factor_bps, "market collateral_factor_bps")?;
        ensure_bps(
            self.liquidation_threshold_bps,
            "market liquidation_threshold_bps",
        )?;
        ensure_bps(self.liquidation_bonus_bps, "market liquidation_bonus_bps")?;
        ensure_bps(self.reserve_factor_bps, "market reserve_factor_bps")?;
        ensure_bps(self.protocol_fee_bps, "market protocol_fee_bps")?;
        ensure_bps(self.kink_utilization_bps, "market kink_utilization_bps")?;
        if self.collateral_factor_bps >= self.liquidation_threshold_bps {
            return Err("market collateral factor must be below liquidation threshold".to_string());
        }
        if self.price_scale == 0 || self.index_scale == 0 {
            return Err("market scales must be positive".to_string());
        }
        if self.supply_cap_units == 0 || self.borrow_cap_units == 0 {
            return Err("market caps must be positive".to_string());
        }
        Ok(())
    }

    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(self.total_debt_upper_bound_units, self.supply_cap_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_market",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "display_name": self.display_name,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "low_fee_lane": self.low_fee_lane,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "base_borrow_rate_bps": self.base_borrow_rate_bps,
            "kink_utilization_bps": self.kink_utilization_bps,
            "jump_borrow_rate_bps": self.jump_borrow_rate_bps,
            "supply_cap_units": self.supply_cap_units,
            "borrow_cap_units": self.borrow_cap_units,
            "private_borrow_floor_units": self.private_borrow_floor_units,
            "total_collateral_upper_bound_units": self.total_collateral_upper_bound_units,
            "total_debt_upper_bound_units": self.total_debt_upper_bound_units,
            "reserve_floor_units": self.reserve_floor_units,
            "utilization_bps": self.utilization_bps(),
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
            "oracle_guard_root": self.oracle_guard_root,
            "health_bucket_root": self.health_bucket_root,
            "risk_control_root": self.risk_control_root,
            "pq_authorization_root": self.pq_authorization_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBorrowerCommitment {
    pub commitment_id: String,
    pub market_id: String,
    pub borrower_commitment: String,
    pub spend_nullifier_hash: String,
    pub view_tag_root: String,
    pub private_credit_score_commitment: String,
    pub collateral_note_root: String,
    pub debt_note_root: String,
    pub pq_authorization_root: String,
    pub attestation_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: BorrowerCommitmentStatus,
    pub metadata_root: String,
}

impl PrivateBorrowerCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        borrower_label: &str,
        spend_nullifier_hash: &str,
        view_tag_root: &str,
        private_credit_score_commitment: &str,
        pq_authorization_root: &str,
        attestation_root: &str,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "borrower market_id")?;
        ensure_non_empty(borrower_label, "borrower label")?;
        ensure_non_empty(spend_nullifier_hash, "borrower spend_nullifier_hash")?;
        ensure_non_empty(view_tag_root, "borrower view_tag_root")?;
        let borrower_commitment = confidential_lending_account_commitment(borrower_label);
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-BORROWER-METADATA", metadata);
        let commitment_id = confidential_lending_borrower_commitment_id(
            market_id,
            &borrower_commitment,
            spend_nullifier_hash,
            pq_authorization_root,
            opened_at_height,
            nonce,
            &metadata_root,
        );
        let commitment = Self {
            commitment_id,
            market_id: market_id.to_string(),
            borrower_commitment,
            spend_nullifier_hash: spend_nullifier_hash.to_string(),
            view_tag_root: view_tag_root.to_string(),
            private_credit_score_commitment: private_credit_score_commitment.to_string(),
            collateral_note_root: merkle_root("CONFIDENTIAL-LENDING-COLLATERAL-NOTE", &[]),
            debt_note_root: merkle_root("CONFIDENTIAL-LENDING-DEBT-NOTE", &[]),
            pq_authorization_root: pq_authorization_root.to_string(),
            attestation_root: attestation_root.to_string(),
            opened_at_height,
            expires_at_height,
            nonce,
            status: BorrowerCommitmentStatus::Open,
            metadata_root,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.commitment_id, "borrower commitment_id")?;
        ensure_non_empty(&self.market_id, "borrower market_id")?;
        ensure_non_empty(&self.borrower_commitment, "borrower commitment")?;
        ensure_non_empty(&self.spend_nullifier_hash, "borrower spend_nullifier_hash")?;
        ensure_non_empty(&self.view_tag_root, "borrower view_tag_root")?;
        ensure_non_empty(
            &self.pq_authorization_root,
            "borrower pq_authorization_root",
        )?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("borrower commitment expiry must exceed open height".to_string());
        }
        Ok(())
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.is_open() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_borrower_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "spend_nullifier_hash": self.spend_nullifier_hash,
            "view_tag_root": self.view_tag_root,
            "private_credit_score_commitment": self.private_credit_score_commitment,
            "collateral_note_root": self.collateral_note_root,
            "debt_note_root": self.debt_note_root,
            "pq_authorization_root": self.pq_authorization_root,
            "attestation_root": self.attestation_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCollateralNote {
    pub note_id: String,
    pub market_id: String,
    pub borrower_commitment_id: String,
    pub collateral_asset_id: String,
    pub amount_bucket: String,
    pub amount_commitment: String,
    pub ciphertext_root: String,
    pub owner_view_key_commitment: String,
    pub range_proof_root: String,
    pub encumbrance_root: String,
    pub created_at_height: u64,
    pub locked_until_height: u64,
    pub nonce: u64,
    pub status: ConfidentialNoteStatus,
    pub metadata_root: String,
}

impl EncryptedCollateralNote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        borrower_commitment_id: &str,
        collateral_asset_id: &str,
        amount_bucket: &str,
        amount_units: u64,
        blinding: &str,
        ciphertext: &Value,
        owner_view_key_commitment: &str,
        encumbrance_root: &str,
        created_at_height: u64,
        locked_until_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "collateral note market_id")?;
        ensure_non_empty(
            borrower_commitment_id,
            "collateral note borrower_commitment_id",
        )?;
        ensure_non_empty(collateral_asset_id, "collateral note asset")?;
        ensure_non_empty(amount_bucket, "collateral note amount_bucket")?;
        ensure_non_empty(blinding, "collateral note blinding")?;
        let amount_commitment =
            confidential_lending_amount_commitment("collateral", amount_units, blinding);
        let ciphertext_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-COLLATERAL-CIPHERTEXT",
            ciphertext,
        );
        let range_proof_root = confidential_lending_proof_root(
            CONFIDENTIAL_LENDING_RANGE_PROOF_SCHEME,
            &amount_commitment,
            &ciphertext_root,
        );
        let metadata_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-COLLATERAL-NOTE-METADATA",
            metadata,
        );
        let note_id = confidential_lending_collateral_note_id(
            market_id,
            borrower_commitment_id,
            collateral_asset_id,
            &amount_commitment,
            created_at_height,
            nonce,
            &metadata_root,
        );
        let note = Self {
            note_id,
            market_id: market_id.to_string(),
            borrower_commitment_id: borrower_commitment_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            amount_bucket: amount_bucket.to_string(),
            amount_commitment,
            ciphertext_root,
            owner_view_key_commitment: owner_view_key_commitment.to_string(),
            range_proof_root,
            encumbrance_root: encumbrance_root.to_string(),
            created_at_height,
            locked_until_height,
            nonce,
            status: ConfidentialNoteStatus::Encumbered,
            metadata_root,
        };
        note.validate()?;
        Ok(note)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.note_id, "collateral note note_id")?;
        ensure_non_empty(&self.market_id, "collateral note market_id")?;
        ensure_non_empty(
            &self.borrower_commitment_id,
            "collateral note borrower_commitment_id",
        )?;
        ensure_non_empty(&self.collateral_asset_id, "collateral note asset")?;
        ensure_non_empty(&self.amount_bucket, "collateral note amount_bucket")?;
        ensure_non_empty(&self.amount_commitment, "collateral note amount_commitment")?;
        ensure_non_empty(&self.ciphertext_root, "collateral note ciphertext_root")?;
        ensure_non_empty(
            &self.owner_view_key_commitment,
            "collateral note owner_view_key_commitment",
        )?;
        ensure_non_empty(&self.range_proof_root, "collateral note range_proof_root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_collateral_note",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "note_id": self.note_id,
            "market_id": self.market_id,
            "borrower_commitment_id": self.borrower_commitment_id,
            "collateral_asset_id": self.collateral_asset_id,
            "amount_bucket": self.amount_bucket,
            "amount_commitment": self.amount_commitment,
            "ciphertext_root": self.ciphertext_root,
            "owner_view_key_commitment": self.owner_view_key_commitment,
            "range_proof_root": self.range_proof_root,
            "encumbrance_root": self.encumbrance_root,
            "created_at_height": self.created_at_height,
            "locked_until_height": self.locked_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDebtNote {
    pub note_id: String,
    pub market_id: String,
    pub borrower_commitment_id: String,
    pub debt_asset_id: String,
    pub principal_bucket: String,
    pub principal_commitment: String,
    pub scaled_debt_commitment: String,
    pub interest_index: u64,
    pub ciphertext_root: String,
    pub nullifier_root: String,
    pub range_proof_root: String,
    pub created_at_height: u64,
    pub maturity_height: u64,
    pub nonce: u64,
    pub status: ConfidentialNoteStatus,
    pub metadata_root: String,
}

impl EncryptedDebtNote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        borrower_commitment_id: &str,
        debt_asset_id: &str,
        principal_bucket: &str,
        principal_units: u64,
        scaled_debt_units: u64,
        blinding: &str,
        interest_index: u64,
        ciphertext: &Value,
        nullifier_root: &str,
        created_at_height: u64,
        maturity_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "debt note market_id")?;
        ensure_non_empty(borrower_commitment_id, "debt note borrower_commitment_id")?;
        ensure_non_empty(debt_asset_id, "debt note asset")?;
        ensure_non_empty(principal_bucket, "debt note principal_bucket")?;
        ensure_non_empty(blinding, "debt note blinding")?;
        ensure_non_empty(nullifier_root, "debt note nullifier_root")?;
        let principal_commitment =
            confidential_lending_amount_commitment("debt_principal", principal_units, blinding);
        let scaled_debt_commitment =
            confidential_lending_amount_commitment("scaled_debt", scaled_debt_units, blinding);
        let ciphertext_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-DEBT-CIPHERTEXT", ciphertext);
        let public_input_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-DEBT-NOTE-PUBLIC-INPUT",
            &json!({
                "principal_commitment": principal_commitment,
                "scaled_debt_commitment": scaled_debt_commitment,
                "interest_index": interest_index,
            }),
        );
        let range_proof_root = confidential_lending_proof_root(
            CONFIDENTIAL_LENDING_RANGE_PROOF_SCHEME,
            &public_input_root,
            &ciphertext_root,
        );
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-DEBT-NOTE-METADATA", metadata);
        let note_id = confidential_lending_debt_note_id(
            market_id,
            borrower_commitment_id,
            debt_asset_id,
            &principal_commitment,
            created_at_height,
            nonce,
            &metadata_root,
        );
        let note = Self {
            note_id,
            market_id: market_id.to_string(),
            borrower_commitment_id: borrower_commitment_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            principal_bucket: principal_bucket.to_string(),
            principal_commitment,
            scaled_debt_commitment,
            interest_index,
            ciphertext_root,
            nullifier_root: nullifier_root.to_string(),
            range_proof_root,
            created_at_height,
            maturity_height,
            nonce,
            status: ConfidentialNoteStatus::Active,
            metadata_root,
        };
        note.validate()?;
        Ok(note)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.note_id, "debt note note_id")?;
        ensure_non_empty(&self.market_id, "debt note market_id")?;
        ensure_non_empty(
            &self.borrower_commitment_id,
            "debt note borrower_commitment_id",
        )?;
        ensure_non_empty(&self.debt_asset_id, "debt note asset")?;
        ensure_non_empty(&self.principal_bucket, "debt note principal_bucket")?;
        ensure_non_empty(&self.principal_commitment, "debt note principal_commitment")?;
        ensure_non_empty(
            &self.scaled_debt_commitment,
            "debt note scaled_debt_commitment",
        )?;
        ensure_non_empty(&self.ciphertext_root, "debt note ciphertext_root")?;
        ensure_non_empty(&self.nullifier_root, "debt note nullifier_root")?;
        ensure_non_empty(&self.range_proof_root, "debt note range_proof_root")?;
        if self.interest_index == 0 {
            return Err("debt note interest index must be positive".to_string());
        }
        if self.maturity_height <= self.created_at_height {
            return Err("debt note maturity must exceed create height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_debt_note",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "note_id": self.note_id,
            "market_id": self.market_id,
            "borrower_commitment_id": self.borrower_commitment_id,
            "debt_asset_id": self.debt_asset_id,
            "principal_bucket": self.principal_bucket,
            "principal_commitment": self.principal_commitment,
            "scaled_debt_commitment": self.scaled_debt_commitment,
            "interest_index": self.interest_index,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "range_proof_root": self.range_proof_root,
            "created_at_height": self.created_at_height,
            "maturity_height": self.maturity_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingInterestIndexSnapshot {
    pub snapshot_id: String,
    pub market_id: String,
    pub height: u64,
    pub supply_index: u64,
    pub borrow_index: u64,
    pub utilization_bps: u64,
    pub borrow_rate_bps: u64,
    pub reserve_rate_bps: u64,
    pub total_supplied_upper_bound_units: u64,
    pub total_borrowed_upper_bound_units: u64,
    pub previous_snapshot_id: String,
    pub metadata_root: String,
}

impl LendingInterestIndexSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        height: u64,
        supply_index: u64,
        borrow_index: u64,
        utilization_bps: u64,
        borrow_rate_bps: u64,
        reserve_rate_bps: u64,
        total_supplied_upper_bound_units: u64,
        total_borrowed_upper_bound_units: u64,
        previous_snapshot_id: &str,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "index market_id")?;
        ensure_bps(utilization_bps, "index utilization_bps")?;
        ensure_bps(reserve_rate_bps, "index reserve_rate_bps")?;
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-INDEX-METADATA", metadata);
        let snapshot_id = confidential_lending_interest_index_snapshot_id(
            market_id,
            height,
            supply_index,
            borrow_index,
            utilization_bps,
            previous_snapshot_id,
            &metadata_root,
        );
        let snapshot = Self {
            snapshot_id,
            market_id: market_id.to_string(),
            height,
            supply_index,
            borrow_index,
            utilization_bps,
            borrow_rate_bps,
            reserve_rate_bps,
            total_supplied_upper_bound_units,
            total_borrowed_upper_bound_units,
            previous_snapshot_id: previous_snapshot_id.to_string(),
            metadata_root,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.snapshot_id, "index snapshot_id")?;
        ensure_non_empty(&self.market_id, "index market_id")?;
        ensure_bps(self.utilization_bps, "index utilization_bps")?;
        ensure_bps(self.reserve_rate_bps, "index reserve_rate_bps")?;
        if self.supply_index == 0 || self.borrow_index == 0 {
            return Err("index values must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_interest_index_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "market_id": self.market_id,
            "height": self.height,
            "supply_index": self.supply_index,
            "borrow_index": self.borrow_index,
            "utilization_bps": self.utilization_bps,
            "borrow_rate_bps": self.borrow_rate_bps,
            "reserve_rate_bps": self.reserve_rate_bps,
            "total_supplied_upper_bound_units": self.total_supplied_upper_bound_units,
            "total_borrowed_upper_bound_units": self.total_borrowed_upper_bound_units,
            "previous_snapshot_id": self.previous_snapshot_id,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleGuardedHealthBucket {
    pub bucket_id: String,
    pub market_id: String,
    pub bucket: HealthBucket,
    pub oracle_feed_id: String,
    pub oracle_root: String,
    pub reference_price_units: u64,
    pub spot_price_units: u64,
    pub twap_price_units: u64,
    pub median_price_units: u64,
    pub max_staleness_blocks: u64,
    pub observed_at_height: u64,
    pub snapshot_height: u64,
    pub expires_at_height: u64,
    pub position_count: u64,
    pub collateral_lower_bound_units: u64,
    pub debt_upper_bound_units: u64,
    pub guard_action: OracleGuardAction,
    pub public_input_root: String,
    pub proof_root: String,
    pub metadata_root: String,
}

impl OracleGuardedHealthBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        bucket: HealthBucket,
        oracle_feed_id: &str,
        reference_price_units: u64,
        spot_price_units: u64,
        twap_price_units: u64,
        median_price_units: u64,
        observed_at_height: u64,
        snapshot_height: u64,
        ttl_blocks: u64,
        position_count: u64,
        collateral_lower_bound_units: u64,
        debt_upper_bound_units: u64,
        guard_action: OracleGuardAction,
        oracle_sources: &[Value],
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "health bucket market_id")?;
        ensure_non_empty(oracle_feed_id, "health bucket oracle_feed_id")?;
        if ttl_blocks == 0 {
            return Err("health bucket ttl must be positive".to_string());
        }
        let oracle_root = sorted_merkle_root(
            "CONFIDENTIAL-LENDING-ORACLE-SOURCE",
            oracle_sources.to_vec(),
            "source",
        );
        let public_input = json!({
            "market_id": market_id,
            "bucket": bucket.as_str(),
            "oracle_feed_id": oracle_feed_id,
            "oracle_root": oracle_root,
            "reference_price_units": reference_price_units,
            "spot_price_units": spot_price_units,
            "twap_price_units": twap_price_units,
            "median_price_units": median_price_units,
            "position_count": position_count,
            "collateral_lower_bound_units": collateral_lower_bound_units,
            "debt_upper_bound_units": debt_upper_bound_units,
        });
        let public_input_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-HEALTH-BUCKET-PUBLIC-INPUT",
            &public_input,
        );
        let proof_root = confidential_lending_proof_root(
            CONFIDENTIAL_LENDING_HEALTH_PROOF_SCHEME,
            &public_input_root,
            &oracle_root,
        );
        let metadata_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-HEALTH-BUCKET-METADATA",
            metadata,
        );
        let bucket_id = confidential_lending_health_bucket_id(
            market_id,
            bucket,
            snapshot_height,
            position_count,
            debt_upper_bound_units,
            &public_input_root,
            &metadata_root,
        );
        let bucket = Self {
            bucket_id,
            market_id: market_id.to_string(),
            bucket,
            oracle_feed_id: oracle_feed_id.to_string(),
            oracle_root,
            reference_price_units,
            spot_price_units,
            twap_price_units,
            median_price_units,
            max_staleness_blocks: CONFIDENTIAL_LENDING_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            observed_at_height,
            snapshot_height,
            expires_at_height: snapshot_height.saturating_add(ttl_blocks),
            position_count,
            collateral_lower_bound_units,
            debt_upper_bound_units,
            guard_action,
            public_input_root,
            proof_root,
            metadata_root,
        };
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.bucket_id, "health bucket id")?;
        ensure_non_empty(&self.market_id, "health bucket market_id")?;
        ensure_non_empty(&self.oracle_feed_id, "health bucket oracle_feed_id")?;
        ensure_non_empty(&self.oracle_root, "health bucket oracle_root")?;
        ensure_non_empty(&self.public_input_root, "health bucket public_input_root")?;
        ensure_non_empty(&self.proof_root, "health bucket proof_root")?;
        if self.reference_price_units == 0
            || self.spot_price_units == 0
            || self.twap_price_units == 0
            || self.median_price_units == 0
        {
            return Err("health bucket oracle prices must be positive".to_string());
        }
        if self.expires_at_height <= self.snapshot_height {
            return Err("health bucket expiry must exceed snapshot height".to_string());
        }
        Ok(())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn is_oracle_stale_at(&self, height: u64) -> bool {
        height.saturating_sub(self.observed_at_height) > self.max_staleness_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_guarded_health_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "market_id": self.market_id,
            "bucket": self.bucket.as_str(),
            "oracle_feed_id": self.oracle_feed_id,
            "oracle_root": self.oracle_root,
            "reference_price_units": self.reference_price_units,
            "spot_price_units": self.spot_price_units,
            "twap_price_units": self.twap_price_units,
            "median_price_units": self.median_price_units,
            "max_staleness_blocks": self.max_staleness_blocks,
            "observed_at_height": self.observed_at_height,
            "snapshot_height": self.snapshot_height,
            "expires_at_height": self.expires_at_height,
            "position_count": self.position_count,
            "collateral_lower_bound_units": self.collateral_lower_bound_units,
            "debt_upper_bound_units": self.debt_upper_bound_units,
            "guard_action": self.guard_action.as_str(),
            "public_input_root": self.public_input_root,
            "proof_root": self.proof_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationAuction {
    pub auction_id: String,
    pub market_id: String,
    pub borrower_commitment_id: String,
    pub collateral_note_id: String,
    pub debt_note_id: String,
    pub health_bucket_id: String,
    pub collateral_bucket: String,
    pub debt_bucket: String,
    pub start_price_commitment: String,
    pub floor_price_commitment: String,
    pub bid_commitment_root: String,
    pub settlement_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_blocks: u64,
    pub nonce: u64,
    pub status: PrivateAuctionStatus,
    pub metadata_root: String,
}

impl PrivateLiquidationAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        borrower_commitment_id: &str,
        collateral_note_id: &str,
        debt_note_id: &str,
        health_bucket_id: &str,
        collateral_bucket: &str,
        debt_bucket: &str,
        start_price_commitment: &str,
        floor_price_commitment: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
        challenge_window_blocks: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "auction market_id")?;
        ensure_non_empty(borrower_commitment_id, "auction borrower_commitment_id")?;
        ensure_non_empty(collateral_note_id, "auction collateral_note_id")?;
        ensure_non_empty(debt_note_id, "auction debt_note_id")?;
        ensure_non_empty(health_bucket_id, "auction health_bucket_id")?;
        ensure_non_empty(collateral_bucket, "auction collateral_bucket")?;
        ensure_non_empty(debt_bucket, "auction debt_bucket")?;
        ensure_non_empty(start_price_commitment, "auction start_price_commitment")?;
        ensure_non_empty(floor_price_commitment, "auction floor_price_commitment")?;
        if ttl_blocks == 0 || challenge_window_blocks == 0 {
            return Err("auction ttl and challenge window must be positive".to_string());
        }
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-AUCTION-METADATA", metadata);
        let auction_id = confidential_lending_liquidation_auction_id(
            market_id,
            borrower_commitment_id,
            collateral_note_id,
            debt_note_id,
            health_bucket_id,
            opened_at_height,
            nonce,
            &metadata_root,
        );
        let auction = Self {
            auction_id,
            market_id: market_id.to_string(),
            borrower_commitment_id: borrower_commitment_id.to_string(),
            collateral_note_id: collateral_note_id.to_string(),
            debt_note_id: debt_note_id.to_string(),
            health_bucket_id: health_bucket_id.to_string(),
            collateral_bucket: collateral_bucket.to_string(),
            debt_bucket: debt_bucket.to_string(),
            start_price_commitment: start_price_commitment.to_string(),
            floor_price_commitment: floor_price_commitment.to_string(),
            bid_commitment_root: merkle_root("CONFIDENTIAL-LENDING-PRIVATE-BID", &[]),
            settlement_root: merkle_root("CONFIDENTIAL-LENDING-AUCTION-SETTLEMENT", &[]),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            challenge_window_blocks,
            nonce,
            status: PrivateAuctionStatus::Open,
            metadata_root,
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.auction_id, "auction id")?;
        ensure_non_empty(&self.market_id, "auction market_id")?;
        ensure_non_empty(
            &self.borrower_commitment_id,
            "auction borrower_commitment_id",
        )?;
        ensure_non_empty(&self.collateral_note_id, "auction collateral_note_id")?;
        ensure_non_empty(&self.debt_note_id, "auction debt_note_id")?;
        ensure_non_empty(&self.health_bucket_id, "auction health_bucket_id")?;
        ensure_non_empty(
            &self.start_price_commitment,
            "auction start_price_commitment",
        )?;
        ensure_non_empty(
            &self.floor_price_commitment,
            "auction floor_price_commitment",
        )?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("auction expiry must exceed open height".to_string());
        }
        Ok(())
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            PrivateAuctionStatus::Open | PrivateAuctionStatus::Clearing
        ) && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "borrower_commitment_id": self.borrower_commitment_id,
            "collateral_note_id": self.collateral_note_id,
            "debt_note_id": self.debt_note_id,
            "health_bucket_id": self.health_bucket_id,
            "collateral_bucket": self.collateral_bucket,
            "debt_bucket": self.debt_bucket,
            "start_price_commitment": self.start_price_commitment,
            "floor_price_commitment": self.floor_price_commitment,
            "bid_commitment_root": self.bid_commitment_root,
            "settlement_root": self.settlement_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub repay_amount_commitment: String,
    pub max_price_commitment: String,
    pub encrypted_bid_root: String,
    pub proof_root: String,
    pub sponsorship_id: String,
    pub priority_fee_commitment: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: PrivateBidStatus,
    pub metadata_root: String,
}

impl PrivateLiquidationBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        bidder_label: &str,
        repay_units: u64,
        max_price_units: u64,
        priority_fee_units: u64,
        blinding: &str,
        encrypted_bid: &Value,
        sponsorship_id: &str,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(auction_id, "bid auction_id")?;
        ensure_non_empty(bidder_label, "bid bidder_label")?;
        ensure_non_empty(blinding, "bid blinding")?;
        let bidder_commitment = confidential_lending_account_commitment(bidder_label);
        let repay_amount_commitment =
            confidential_lending_amount_commitment("bid_repay", repay_units, blinding);
        let max_price_commitment =
            confidential_lending_amount_commitment("bid_max_price", max_price_units, blinding);
        let priority_fee_commitment = confidential_lending_amount_commitment(
            "bid_priority_fee",
            priority_fee_units,
            blinding,
        );
        let encrypted_bid_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-PRIVATE-BID-CIPHERTEXT",
            encrypted_bid,
        );
        let public_input_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-PRIVATE-BID-PUBLIC-INPUT",
            &json!({
                "auction_id": auction_id,
                "bidder_commitment": bidder_commitment,
                "repay_amount_commitment": repay_amount_commitment,
                "max_price_commitment": max_price_commitment,
                "priority_fee_commitment": priority_fee_commitment,
            }),
        );
        let proof_root = confidential_lending_proof_root(
            CONFIDENTIAL_LENDING_AUCTION_SCHEME,
            &public_input_root,
            &encrypted_bid_root,
        );
        let metadata_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-PRIVATE-BID-METADATA",
            metadata,
        );
        let bid_id = confidential_lending_private_bid_id(
            auction_id,
            &bidder_commitment,
            &repay_amount_commitment,
            &max_price_commitment,
            submitted_at_height,
            nonce,
            &metadata_root,
        );
        let bid = Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment,
            repay_amount_commitment,
            max_price_commitment,
            encrypted_bid_root,
            proof_root,
            sponsorship_id: sponsorship_id.to_string(),
            priority_fee_commitment,
            submitted_at_height,
            expires_at_height,
            nonce,
            status: PrivateBidStatus::Committed,
            metadata_root,
        };
        bid.validate()?;
        Ok(bid)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.bid_id, "bid id")?;
        ensure_non_empty(&self.auction_id, "bid auction_id")?;
        ensure_non_empty(&self.bidder_commitment, "bid bidder_commitment")?;
        ensure_non_empty(&self.repay_amount_commitment, "bid repay_amount_commitment")?;
        ensure_non_empty(&self.max_price_commitment, "bid max_price_commitment")?;
        ensure_non_empty(&self.encrypted_bid_root, "bid encrypted_bid_root")?;
        ensure_non_empty(&self.proof_root, "bid proof_root")?;
        ensure_non_empty(&self.priority_fee_commitment, "bid priority_fee_commitment")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("bid expiry must exceed submit height".to_string());
        }
        Ok(())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            PrivateBidStatus::Committed
                | PrivateBidStatus::Eligible
                | PrivateBidStatus::RevealedToCircuit
        ) && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_liquidation_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "repay_amount_commitment": self.repay_amount_commitment,
            "max_price_commitment": self.max_price_commitment,
            "encrypted_bid_root": self.encrypted_bid_root,
            "proof_root": self.proof_root,
            "sponsorship_id": self.sponsorship_id,
            "priority_fee_commitment": self.priority_fee_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLendingSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub market_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub remaining_fee_units: u64,
    pub max_rebate_bps: u64,
    pub max_operation_fee_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: LowFeeSponsorshipStatus,
    pub policy_root: String,
}

impl LowFeeLendingSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        beneficiary_label: &str,
        market_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        reserved_fee_units: u64,
        max_rebate_bps: u64,
        max_operation_fee_units: u64,
        policy: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(sponsor_label, "sponsorship sponsor")?;
        ensure_non_empty(beneficiary_label, "sponsorship beneficiary")?;
        ensure_non_empty(market_id, "sponsorship market_id")?;
        ensure_non_empty(lane_id, "sponsorship lane_id")?;
        ensure_non_empty(fee_asset_id, "sponsorship fee_asset_id")?;
        ensure_bps(max_rebate_bps, "sponsorship max_rebate_bps")?;
        let sponsor_commitment = confidential_lending_account_commitment(sponsor_label);
        let beneficiary_commitment = confidential_lending_account_commitment(beneficiary_label);
        let policy_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-SPONSORSHIP-POLICY", policy);
        let sponsorship_id = confidential_lending_sponsorship_id(
            &sponsor_commitment,
            &beneficiary_commitment,
            market_id,
            lane_id,
            created_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            beneficiary_commitment,
            market_id: market_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            reserved_fee_units,
            remaining_fee_units: reserved_fee_units,
            max_rebate_bps,
            max_operation_fee_units,
            created_at_height,
            expires_at_height,
            nonce,
            status: LowFeeSponsorshipStatus::Active,
            policy_root,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor_commitment")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship beneficiary_commitment",
        )?;
        ensure_non_empty(&self.market_id, "sponsorship market_id")?;
        ensure_non_empty(&self.lane_id, "sponsorship lane_id")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee_asset_id")?;
        ensure_non_empty(&self.policy_root, "sponsorship policy_root")?;
        ensure_bps(self.max_rebate_bps, "sponsorship max_rebate_bps")?;
        if self.remaining_fee_units > self.reserved_fee_units {
            return Err("sponsorship remaining fee exceeds reserved fee".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("sponsorship expiry must exceed create height".to_string());
        }
        Ok(())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            LowFeeSponsorshipStatus::Reserved | LowFeeSponsorshipStatus::Active
        ) && self.remaining_fee_units > 0
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_lending_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "market_id": self.market_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "remaining_fee_units": self.remaining_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "max_operation_fee_units": self.max_operation_fee_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLendingAuthorization {
    pub authorization_id: String,
    pub market_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub committee_id: String,
    pub signer_set_root: String,
    pub authorization_scheme: String,
    pub attestation_scheme: String,
    pub authorization_root: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub decision: PqAuthorizationDecision,
    pub severity: ConfidentialRiskSeverity,
    pub risk_score_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub metadata_root: String,
}

impl PqLendingAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        subject_kind: &str,
        subject_id: &str,
        committee_id: &str,
        signer_set: &[String],
        decision: PqAuthorizationDecision,
        severity: ConfidentialRiskSeverity,
        risk_score_bps: u64,
        authorization_payload: &Value,
        attestation_payload: &Value,
        signature_payload: &Value,
        valid_from_height: u64,
        valid_until_height: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "pq authorization market_id")?;
        ensure_non_empty(subject_kind, "pq authorization subject_kind")?;
        ensure_non_empty(subject_id, "pq authorization subject_id")?;
        ensure_non_empty(committee_id, "pq authorization committee_id")?;
        ensure_bps(risk_score_bps, "pq authorization risk_score_bps")?;
        let signer_set_root =
            confidential_lending_string_set_root("CONFIDENTIAL-LENDING-PQ-SIGNER-SET", signer_set);
        let authorization_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-PQ-AUTHORIZATION-PAYLOAD",
            authorization_payload,
        );
        let attestation_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-PQ-ATTESTATION-PAYLOAD",
            attestation_payload,
        );
        let signature_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-PQ-SIGNATURE-PAYLOAD",
            signature_payload,
        );
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-PQ-AUTH-METADATA", metadata);
        let authorization_id = confidential_lending_pq_authorization_id(
            market_id,
            subject_kind,
            subject_id,
            committee_id,
            &authorization_root,
            valid_from_height,
        );
        let authorization = Self {
            authorization_id,
            market_id: market_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            committee_id: committee_id.to_string(),
            signer_set_root,
            authorization_scheme: CONFIDENTIAL_LENDING_PQ_AUTH_SCHEME.to_string(),
            attestation_scheme: CONFIDENTIAL_LENDING_PQ_ATTESTATION_SCHEME.to_string(),
            authorization_root,
            attestation_root,
            signature_root,
            decision,
            severity,
            risk_score_bps,
            valid_from_height,
            valid_until_height,
            metadata_root,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.authorization_id, "pq authorization id")?;
        ensure_non_empty(&self.market_id, "pq authorization market_id")?;
        ensure_non_empty(&self.subject_kind, "pq authorization subject_kind")?;
        ensure_non_empty(&self.subject_id, "pq authorization subject_id")?;
        ensure_non_empty(&self.committee_id, "pq authorization committee_id")?;
        ensure_non_empty(&self.signer_set_root, "pq authorization signer_set_root")?;
        ensure_non_empty(
            &self.authorization_scheme,
            "pq authorization authorization_scheme",
        )?;
        ensure_non_empty(
            &self.attestation_scheme,
            "pq authorization attestation_scheme",
        )?;
        ensure_non_empty(
            &self.authorization_root,
            "pq authorization authorization_root",
        )?;
        ensure_non_empty(&self.attestation_root, "pq authorization attestation_root")?;
        ensure_non_empty(&self.signature_root, "pq authorization signature_root")?;
        ensure_bps(self.risk_score_bps, "pq authorization risk_score_bps")?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("pq authorization validity must have positive duration".to_string());
        }
        Ok(())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.valid_from_height <= height && height <= self.valid_until_height
    }

    pub fn effective_risk_score_bps(&self) -> u64 {
        self.risk_score_bps.max(self.severity.score_bps())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_lending_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "market_id": self.market_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "committee_id": self.committee_id,
            "signer_set_root": self.signer_set_root,
            "authorization_scheme": self.authorization_scheme,
            "attestation_scheme": self.attestation_scheme,
            "authorization_root": self.authorization_root,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "decision": self.decision.as_str(),
            "severity": self.severity.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "effective_risk_score_bps": self.effective_risk_score_bps(),
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRiskControl {
    pub control_id: String,
    pub scope: RiskControlScope,
    pub subject_id: String,
    pub trigger_metric: String,
    pub threshold_bps: u64,
    pub observed_bps: u64,
    pub action: OracleGuardAction,
    pub severity: ConfidentialRiskSeverity,
    pub status: RiskControlStatus,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl ConfidentialRiskControl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: RiskControlScope,
        subject_id: &str,
        trigger_metric: &str,
        threshold_bps: u64,
        observed_bps: u64,
        action: OracleGuardAction,
        severity: ConfidentialRiskSeverity,
        status: RiskControlStatus,
        evidence: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(subject_id, "risk control subject_id")?;
        ensure_non_empty(trigger_metric, "risk control trigger_metric")?;
        ensure_bps(threshold_bps, "risk control threshold_bps")?;
        ensure_bps(observed_bps, "risk control observed_bps")?;
        let evidence_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-RISK-EVIDENCE", evidence);
        let metadata_root = confidential_lending_payload_root(
            "CONFIDENTIAL-LENDING-RISK-CONTROL-METADATA",
            metadata,
        );
        let control_id = confidential_lending_risk_control_id(
            scope,
            subject_id,
            trigger_metric,
            &evidence_root,
            opened_at_height,
        );
        let control = Self {
            control_id,
            scope,
            subject_id: subject_id.to_string(),
            trigger_metric: trigger_metric.to_string(),
            threshold_bps,
            observed_bps,
            action,
            severity,
            status,
            evidence_root,
            opened_at_height,
            expires_at_height,
            metadata_root,
        };
        control.validate()?;
        Ok(control)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.control_id, "risk control id")?;
        ensure_non_empty(&self.subject_id, "risk control subject_id")?;
        ensure_non_empty(&self.trigger_metric, "risk control trigger_metric")?;
        ensure_non_empty(&self.evidence_root, "risk control evidence_root")?;
        ensure_bps(self.threshold_bps, "risk control threshold_bps")?;
        ensure_bps(self.observed_bps, "risk control observed_bps")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("risk control expiry must exceed open height".to_string());
        }
        Ok(())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_risk_control",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "control_id": self.control_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "trigger_metric": self.trigger_metric,
            "threshold_bps": self.threshold_bps,
            "observed_bps": self.observed_bps,
            "action": self.action.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingReserveAccounting {
    pub reserve_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub controller_commitment: String,
    pub balance_floor_units: u64,
    pub target_units: u64,
    pub deficit_ceiling_units: u64,
    pub reserve_factor_bps: u64,
    pub withdrawal_delay_blocks: u64,
    pub recorded_at_height: u64,
    pub status: ReserveFundStatus,
    pub metadata_root: String,
}

impl LendingReserveAccounting {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        asset_id: &str,
        controller_label: &str,
        balance_floor_units: u64,
        target_units: u64,
        deficit_ceiling_units: u64,
        reserve_factor_bps: u64,
        withdrawal_delay_blocks: u64,
        recorded_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(market_id, "reserve market_id")?;
        ensure_non_empty(asset_id, "reserve asset_id")?;
        ensure_non_empty(controller_label, "reserve controller")?;
        ensure_bps(reserve_factor_bps, "reserve reserve_factor_bps")?;
        let controller_commitment = confidential_lending_account_commitment(controller_label);
        let metadata_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-RESERVE-METADATA", metadata);
        let reserve_id = confidential_lending_reserve_id(
            market_id,
            asset_id,
            &controller_commitment,
            recorded_at_height,
            &metadata_root,
        );
        let reserve = Self {
            reserve_id,
            market_id: market_id.to_string(),
            asset_id: asset_id.to_string(),
            controller_commitment,
            balance_floor_units,
            target_units,
            deficit_ceiling_units,
            reserve_factor_bps,
            withdrawal_delay_blocks,
            recorded_at_height,
            status: ReserveFundStatus::Active,
            metadata_root,
        };
        reserve.validate()?;
        Ok(reserve)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.reserve_id, "reserve id")?;
        ensure_non_empty(&self.market_id, "reserve market_id")?;
        ensure_non_empty(&self.asset_id, "reserve asset_id")?;
        ensure_non_empty(&self.controller_commitment, "reserve controller_commitment")?;
        ensure_bps(self.reserve_factor_bps, "reserve reserve_factor_bps")?;
        if self.target_units == 0 {
            return Err("reserve target must be positive".to_string());
        }
        Ok(())
    }

    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(self.balance_floor_units, self.target_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_reserve_accounting",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "reserve_id": self.reserve_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "controller_commitment": self.controller_commitment,
            "balance_floor_units": self.balance_floor_units,
            "target_units": self.target_units,
            "deficit_ceiling_units": self.deficit_ceiling_units,
            "reserve_factor_bps": self.reserve_factor_bps,
            "withdrawal_delay_blocks": self.withdrawal_delay_blocks,
            "recorded_at_height": self.recorded_at_height,
            "coverage_bps": self.coverage_bps(),
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl ConfidentialLendingPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> ConfidentialLendingResult<Self> {
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject_id")?;
        let payload_root =
            confidential_lending_payload_root("CONFIDENTIAL-LENDING-PUBLIC-PAYLOAD", payload);
        let record_id = confidential_lending_public_record_id(
            record_kind,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> ConfidentialLendingResult<()> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.record_kind, "public record kind")?;
        ensure_non_empty(&self.subject_id, "public record subject_id")?;
        ensure_non_empty(&self.payload_root, "public record payload_root")?;
        let expected_id = confidential_lending_public_record_id(
            &self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected_id {
            return Err("public record id does not match deterministic fields".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingCounters {
    pub market_count: u64,
    pub borrower_commitment_count: u64,
    pub active_borrower_commitment_count: u64,
    pub collateral_note_count: u64,
    pub active_collateral_note_count: u64,
    pub debt_note_count: u64,
    pub active_debt_note_count: u64,
    pub interest_index_count: u64,
    pub oracle_guard_count: u64,
    pub liquidatable_bucket_count: u64,
    pub liquidation_auction_count: u64,
    pub open_liquidation_auction_count: u64,
    pub private_bid_count: u64,
    pub live_private_bid_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub pq_authorization_count: u64,
    pub active_pq_authorization_count: u64,
    pub active_risk_control_count: u64,
    pub reserve_accounting_count: u64,
    pub public_record_count: u64,
    pub total_debt_upper_bound_units: u64,
    pub total_collateral_upper_bound_units: u64,
    pub total_reserve_floor_units: u64,
    pub aggregate_risk_score_bps: u64,
}

impl ConfidentialLendingCounters {
    pub fn risk_status(&self) -> &'static str {
        confidential_lending_risk_status(self.aggregate_risk_score_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "market_count": self.market_count,
            "borrower_commitment_count": self.borrower_commitment_count,
            "active_borrower_commitment_count": self.active_borrower_commitment_count,
            "collateral_note_count": self.collateral_note_count,
            "active_collateral_note_count": self.active_collateral_note_count,
            "debt_note_count": self.debt_note_count,
            "active_debt_note_count": self.active_debt_note_count,
            "interest_index_count": self.interest_index_count,
            "oracle_guard_count": self.oracle_guard_count,
            "liquidatable_bucket_count": self.liquidatable_bucket_count,
            "liquidation_auction_count": self.liquidation_auction_count,
            "open_liquidation_auction_count": self.open_liquidation_auction_count,
            "private_bid_count": self.private_bid_count,
            "live_private_bid_count": self.live_private_bid_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "pq_authorization_count": self.pq_authorization_count,
            "active_pq_authorization_count": self.active_pq_authorization_count,
            "active_risk_control_count": self.active_risk_control_count,
            "reserve_accounting_count": self.reserve_accounting_count,
            "public_record_count": self.public_record_count,
            "total_debt_upper_bound_units": self.total_debt_upper_bound_units,
            "total_collateral_upper_bound_units": self.total_collateral_upper_bound_units,
            "total_reserve_floor_units": self.total_reserve_floor_units,
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps,
            "risk_status": self.risk_status(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingRoots {
    pub config_root: String,
    pub market_root: String,
    pub borrower_commitment_root: String,
    pub collateral_note_root: String,
    pub debt_note_root: String,
    pub interest_index_root: String,
    pub oracle_guard_root: String,
    pub health_bucket_root: String,
    pub liquidation_auction_root: String,
    pub private_bid_root: String,
    pub low_fee_sponsorship_root: String,
    pub pq_authorization_root: String,
    pub risk_control_root: String,
    pub reserve_accounting_root: String,
    pub public_record_root: String,
}

impl ConfidentialLendingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_lending_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "market_root": self.market_root,
            "borrower_commitment_root": self.borrower_commitment_root,
            "collateral_note_root": self.collateral_note_root,
            "debt_note_root": self.debt_note_root,
            "interest_index_root": self.interest_index_root,
            "oracle_guard_root": self.oracle_guard_root,
            "health_bucket_root": self.health_bucket_root,
            "liquidation_auction_root": self.liquidation_auction_root,
            "private_bid_root": self.private_bid_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_authorization_root": self.pq_authorization_root,
            "risk_control_root": self.risk_control_root,
            "reserve_accounting_root": self.reserve_accounting_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_lending_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialLendingConfig,
    pub markets: BTreeMap<String, ConfidentialLendingMarket>,
    pub borrower_commitments: BTreeMap<String, PrivateBorrowerCommitment>,
    pub collateral_notes: BTreeMap<String, EncryptedCollateralNote>,
    pub debt_notes: BTreeMap<String, EncryptedDebtNote>,
    pub interest_indexes: BTreeMap<String, LendingInterestIndexSnapshot>,
    pub oracle_guards: BTreeMap<String, OracleGuardedHealthBucket>,
    pub liquidation_auctions: BTreeMap<String, PrivateLiquidationAuction>,
    pub private_bids: BTreeMap<String, PrivateLiquidationBid>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeLendingSponsorship>,
    pub pq_authorizations: BTreeMap<String, PqLendingAuthorization>,
    pub risk_controls: BTreeMap<String, ConfidentialRiskControl>,
    pub reserve_accounting: BTreeMap<String, LendingReserveAccounting>,
    pub public_records: BTreeMap<String, ConfidentialLendingPublicRecord>,
}

impl Default for ConfidentialLendingState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidentialLendingState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: ConfidentialLendingConfig::default(),
            markets: BTreeMap::new(),
            borrower_commitments: BTreeMap::new(),
            collateral_notes: BTreeMap::new(),
            debt_notes: BTreeMap::new(),
            interest_indexes: BTreeMap::new(),
            oracle_guards: BTreeMap::new(),
            liquidation_auctions: BTreeMap::new(),
            private_bids: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            risk_controls: BTreeMap::new(),
            reserve_accounting: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: ConfidentialLendingConfig) -> ConfidentialLendingResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> ConfidentialLendingResult<Self> {
        let mut state = Self::with_config(ConfidentialLendingConfig::devnet())?;
        state.set_height(CONFIDENTIAL_LENDING_DEVNET_HEIGHT);
        let collateral_asset_id = state.config.collateral_asset_id.clone();
        let debt_asset_id = state.config.debt_asset_id.clone();
        let reserve_asset_id = state.config.reserve_asset_id.clone();
        let default_low_fee_lane = state.config.default_low_fee_lane.clone();
        let default_commitment_ttl_blocks = state.config.default_commitment_ttl_blocks;
        let default_health_bucket_ttl_blocks = state.config.default_health_bucket_ttl_blocks;
        let default_auction_ttl_blocks = state.config.default_auction_ttl_blocks;
        let sponsored_max_fee_units = state.config.sponsored_max_fee_units;

        let market = ConfidentialLendingMarket::wxmr_usdd_devnet(state.height.saturating_sub(72))?;
        let market_id = market.market_id.clone();
        state.insert_market(market)?;

        let reserve = LendingReserveAccounting::new(
            &market_id,
            &reserve_asset_id,
            "devnet-lending-reserve-council",
            750_000_000,
            1_250_000_000,
            250_000_000,
            state.config.reserve_factor_bps,
            48,
            state.height.saturating_sub(32),
            &json!({"source": "foundation_floor", "liquidity": "private_usdd"}),
        )?;
        state.insert_reserve_accounting(reserve)?;

        let pq = PqLendingAuthorization::new(
            &market_id,
            "market",
            &market_id,
            "devnet-lending-risk-committee",
            &[
                "ml-dsa-member-1".to_string(),
                "ml-dsa-member-2".to_string(),
                "slh-dsa-member-3".to_string(),
            ],
            PqAuthorizationDecision::Approve,
            ConfidentialRiskSeverity::Watch,
            2_000,
            &json!({
                "action": "launch_private_lending_market",
                "caps": "devnet",
                "quantum_resistant": true
            }),
            &json!({"threshold": "2-of-3", "scheme": CONFIDENTIAL_LENDING_PQ_ATTESTATION_SCHEME}),
            &json!({"aggregate_signature_root": "devnet-pq-lending-market-sig-root"}),
            state.height.saturating_sub(10),
            state.height.saturating_add(7_200),
            &json!({"review": "initial devnet launch caps"}),
        )?;
        let pq_authorization_root = confidential_lending_pq_authorization_root(&[pq.clone()]);
        state.insert_pq_authorization(pq)?;

        if let Some(market) = state.markets.get_mut(&market_id) {
            market.pq_authorization_root = pq_authorization_root.clone();
        }

        let borrower = PrivateBorrowerCommitment::new(
            &market_id,
            "devnet-alice-private-lending",
            &confidential_lending_string_root(
                "CONFIDENTIAL-LENDING-DEVNET-SPEND-NULLIFIER",
                "alice-note-0",
            ),
            &confidential_lending_string_root(
                "CONFIDENTIAL-LENDING-DEVNET-VIEW-TAGS",
                "alice-view-tags",
            ),
            &confidential_lending_amount_commitment(
                "private_credit_score",
                7_200,
                "alice-credit-blinding",
            ),
            &pq_authorization_root,
            &confidential_lending_string_root(
                "CONFIDENTIAL-LENDING-DEVNET-BORROWER-ATTESTATION",
                "alice-attestation",
            ),
            state.height.saturating_sub(24),
            state.height.saturating_add(default_commitment_ttl_blocks),
            state.next_nonce(),
            &json!({"borrower": "alice", "privacy": "note-level ciphertexts"}),
        )?;
        let borrower_id = borrower.commitment_id.clone();
        state.insert_borrower_commitment(borrower)?;

        let collateral = EncryptedCollateralNote::new(
            &market_id,
            &borrower_id,
            &collateral_asset_id,
            "wxmr_100_500",
            250_000_000_000,
            "alice-collateral-blinding-1",
            &json!({
                "kem": CONFIDENTIAL_LENDING_NOTE_ENCRYPTION_SCHEME,
                "ciphertext_root_hint": "alice-wxmr-note-ciphertext"
            }),
            &confidential_lending_account_commitment("alice-view-key"),
            &confidential_lending_string_root(
                "CONFIDENTIAL-LENDING-DEVNET-ENCUMBRANCE",
                "alice-collateral-encumbered-for-debt",
            ),
            state.height.saturating_sub(20),
            state.height.saturating_add(144),
            state.next_nonce(),
            &json!({"asset": "wXMR", "amount_bucket": "100-500"}),
        )?;
        let collateral_note_id = collateral.note_id.clone();
        state.insert_collateral_note(collateral)?;

        let debt = EncryptedDebtNote::new(
            &market_id,
            &borrower_id,
            &debt_asset_id,
            "usdd_10k_25k",
            18_000_000_000,
            18_000_000_000,
            "alice-debt-blinding-1",
            CONFIDENTIAL_LENDING_INDEX_SCALE,
            &json!({
                "kem": CONFIDENTIAL_LENDING_NOTE_ENCRYPTION_SCHEME,
                "ciphertext_root_hint": "alice-usdd-debt-note-ciphertext"
            }),
            &confidential_lending_string_root(
                "CONFIDENTIAL-LENDING-DEVNET-DEBT-NULLIFIER",
                "alice-debt-nullifier",
            ),
            state.height.saturating_sub(18),
            state.height.saturating_add(21_600),
            state.next_nonce(),
            &json!({"borrow": "private usdd", "rate_mode": "floating"}),
        )?;
        let debt_note_id = debt.note_id.clone();
        state.insert_debt_note(debt)?;

        let index = LendingInterestIndexSnapshot::new(
            &market_id,
            state.height.saturating_sub(1),
            CONFIDENTIAL_LENDING_INDEX_SCALE.saturating_add(1_000_000),
            CONFIDENTIAL_LENDING_INDEX_SCALE.saturating_add(2_500_000),
            4_800,
            725,
            95,
            3_250_000_000_000,
            156_000_000_000,
            "",
            &json!({"mode": "bounded-private-utilization", "blocks": 24}),
        )?;
        state.insert_interest_index(index)?;

        let health = OracleGuardedHealthBucket::new(
            &market_id,
            HealthBucket::Healthy,
            CONFIDENTIAL_LENDING_DEVNET_ORACLE_FEED_ID,
            CONFIDENTIAL_LENDING_DEVNET_WXMR_PRICE,
            CONFIDENTIAL_LENDING_DEVNET_WXMR_PRICE.saturating_sub(CONFIDENTIAL_LENDING_PRICE_SCALE),
            CONFIDENTIAL_LENDING_DEVNET_WXMR_PRICE
                .saturating_sub(CONFIDENTIAL_LENDING_PRICE_SCALE / 2),
            CONFIDENTIAL_LENDING_DEVNET_WXMR_PRICE,
            state.height.saturating_sub(1),
            state.height,
            default_health_bucket_ttl_blocks,
            1,
            40_000_000_000,
            18_000_000_000,
            OracleGuardAction::Watch,
            &[
                json!({"source": "devnet-median-1", "height": state.height - 2}),
                json!({"source": "devnet-median-2", "height": state.height - 1}),
                json!({"source": "devnet-median-3", "height": state.height - 1}),
            ],
            &json!({"privacy": "bucket-only", "proof": "health-factor-above-liquidation"}),
        )?;
        let health_bucket_id = health.bucket_id.clone();
        state.insert_oracle_guard(health)?;

        let risk_control = ConfidentialRiskControl::new(
            RiskControlScope::Oracle,
            &market_id,
            "oracle_deviation_bps",
            state.config.max_oracle_deviation_bps,
            190,
            OracleGuardAction::Watch,
            ConfidentialRiskSeverity::Watch,
            RiskControlStatus::Watching,
            &json!({"oracle_feed_id": CONFIDENTIAL_LENDING_DEVNET_ORACLE_FEED_ID, "committee": "3-of-5"}),
            state.height.saturating_sub(1),
            state.height.saturating_add(24),
            &json!({"action": "watch only during launch"}),
        )?;
        state.insert_risk_control(risk_control)?;

        let sponsorship = LowFeeLendingSponsorship::new(
            "devnet-foundation-paymaster",
            "devnet-alice-private-lending",
            &market_id,
            &default_low_fee_lane,
            &debt_asset_id,
            250_000,
            8_000,
            sponsored_max_fee_units,
            &json!({
                "target": "small_private_borrows_and_liquidation_bids",
                "max_borrow_units": state.config.sponsored_small_borrow_limit_units
            }),
            state.height.saturating_sub(8),
            state.height.saturating_add(360),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_low_fee_sponsorship(sponsorship)?;

        let auction = PrivateLiquidationAuction::new(
            &market_id,
            &borrower_id,
            &collateral_note_id,
            &debt_note_id,
            &health_bucket_id,
            "wxmr_50_100",
            "usdd_10k_25k",
            &confidential_lending_amount_commitment(
                "auction_start_price",
                CONFIDENTIAL_LENDING_DEVNET_WXMR_PRICE,
                "auction-start-blinding",
            ),
            &confidential_lending_amount_commitment(
                "auction_floor_price",
                128 * CONFIDENTIAL_LENDING_PRICE_SCALE,
                "auction-floor-blinding",
            ),
            state.height.saturating_sub(3),
            default_auction_ttl_blocks,
            18,
            state.next_nonce(),
            &json!({"reason": "seeded liquidation path", "private_bids": true}),
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_liquidation_auction(auction)?;

        let bid = PrivateLiquidationBid::new(
            &auction_id,
            "devnet-keeper-private-bidder",
            10_000_000_000,
            155 * CONFIDENTIAL_LENDING_PRICE_SCALE,
            1_500,
            "keeper-bid-blinding-1",
            &json!({"sealed_bid": "devnet-keeper-ciphertext", "route": "usdd-repay"}),
            &sponsorship_id,
            state.height.saturating_sub(2),
            state.height.saturating_add(30),
            state.next_nonce(),
            &json!({"fee": "sponsored", "auction": "private_dutch"}),
        )?;
        state.insert_private_bid(bid)?;

        let summary = ConfidentialLendingPublicRecord::new(
            "devnet_state_root",
            &market_id,
            &json!({
                "height": state.height,
                "market_id": market_id,
                "state_root": state.state_root(),
                "privacy": "commitment roots only"
            }),
            state.height,
            state.next_nonce(),
        )?;
        state.insert_public_record(summary)?;

        state.refresh_market_roots();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_market(
        &mut self,
        market: ConfidentialLendingMarket,
    ) -> ConfidentialLendingResult<ConfidentialLendingMarket> {
        market.validate()?;
        self.markets
            .insert(market.market_id.clone(), market.clone());
        Ok(market)
    }

    pub fn insert_borrower_commitment(
        &mut self,
        commitment: PrivateBorrowerCommitment,
    ) -> ConfidentialLendingResult<PrivateBorrowerCommitment> {
        commitment.validate()?;
        ensure_state_market(&self.markets, &commitment.market_id, "borrower commitment")?;
        self.borrower_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    pub fn insert_collateral_note(
        &mut self,
        note: EncryptedCollateralNote,
    ) -> ConfidentialLendingResult<EncryptedCollateralNote> {
        note.validate()?;
        ensure_state_market(&self.markets, &note.market_id, "collateral note")?;
        if !self
            .borrower_commitments
            .contains_key(&note.borrower_commitment_id)
        {
            return Err("collateral note references unknown borrower commitment".to_string());
        }
        self.collateral_notes
            .insert(note.note_id.clone(), note.clone());
        Ok(note)
    }

    pub fn insert_debt_note(
        &mut self,
        note: EncryptedDebtNote,
    ) -> ConfidentialLendingResult<EncryptedDebtNote> {
        note.validate()?;
        ensure_state_market(&self.markets, &note.market_id, "debt note")?;
        if !self
            .borrower_commitments
            .contains_key(&note.borrower_commitment_id)
        {
            return Err("debt note references unknown borrower commitment".to_string());
        }
        self.debt_notes.insert(note.note_id.clone(), note.clone());
        Ok(note)
    }

    pub fn insert_interest_index(
        &mut self,
        snapshot: LendingInterestIndexSnapshot,
    ) -> ConfidentialLendingResult<LendingInterestIndexSnapshot> {
        snapshot.validate()?;
        ensure_state_market(&self.markets, &snapshot.market_id, "interest index")?;
        self.interest_indexes
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn insert_oracle_guard(
        &mut self,
        guard: OracleGuardedHealthBucket,
    ) -> ConfidentialLendingResult<OracleGuardedHealthBucket> {
        guard.validate()?;
        ensure_state_market(&self.markets, &guard.market_id, "oracle guard")?;
        self.oracle_guards
            .insert(guard.bucket_id.clone(), guard.clone());
        Ok(guard)
    }

    pub fn insert_liquidation_auction(
        &mut self,
        auction: PrivateLiquidationAuction,
    ) -> ConfidentialLendingResult<PrivateLiquidationAuction> {
        auction.validate()?;
        ensure_state_market(&self.markets, &auction.market_id, "liquidation auction")?;
        if !self
            .borrower_commitments
            .contains_key(&auction.borrower_commitment_id)
        {
            return Err("auction references unknown borrower commitment".to_string());
        }
        if !self
            .collateral_notes
            .contains_key(&auction.collateral_note_id)
        {
            return Err("auction references unknown collateral note".to_string());
        }
        if !self.debt_notes.contains_key(&auction.debt_note_id) {
            return Err("auction references unknown debt note".to_string());
        }
        if !self.oracle_guards.contains_key(&auction.health_bucket_id) {
            return Err("auction references unknown health bucket".to_string());
        }
        self.liquidation_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        Ok(auction)
    }

    pub fn insert_private_bid(
        &mut self,
        bid: PrivateLiquidationBid,
    ) -> ConfidentialLendingResult<PrivateLiquidationBid> {
        bid.validate()?;
        if !self.liquidation_auctions.contains_key(&bid.auction_id) {
            return Err("private bid references unknown auction".to_string());
        }
        if !bid.sponsorship_id.is_empty()
            && !self.low_fee_sponsorships.contains_key(&bid.sponsorship_id)
        {
            return Err("private bid references unknown sponsorship".to_string());
        }
        self.private_bids.insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeLendingSponsorship,
    ) -> ConfidentialLendingResult<LowFeeLendingSponsorship> {
        sponsorship.validate()?;
        ensure_state_market(&self.markets, &sponsorship.market_id, "sponsorship")?;
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_pq_authorization(
        &mut self,
        authorization: PqLendingAuthorization,
    ) -> ConfidentialLendingResult<PqLendingAuthorization> {
        authorization.validate()?;
        ensure_state_market(&self.markets, &authorization.market_id, "pq authorization")?;
        self.pq_authorizations.insert(
            authorization.authorization_id.clone(),
            authorization.clone(),
        );
        Ok(authorization)
    }

    pub fn insert_risk_control(
        &mut self,
        control: ConfidentialRiskControl,
    ) -> ConfidentialLendingResult<ConfidentialRiskControl> {
        control.validate()?;
        if matches!(
            control.scope,
            RiskControlScope::Market | RiskControlScope::Oracle
        ) {
            ensure_state_market(&self.markets, &control.subject_id, "risk control")?;
        }
        self.risk_controls
            .insert(control.control_id.clone(), control.clone());
        Ok(control)
    }

    pub fn insert_reserve_accounting(
        &mut self,
        reserve: LendingReserveAccounting,
    ) -> ConfidentialLendingResult<LendingReserveAccounting> {
        reserve.validate()?;
        ensure_state_market(&self.markets, &reserve.market_id, "reserve")?;
        self.reserve_accounting
            .insert(reserve.reserve_id.clone(), reserve.clone());
        Ok(reserve)
    }

    pub fn insert_public_record(
        &mut self,
        record: ConfidentialLendingPublicRecord,
    ) -> ConfidentialLendingResult<ConfidentialLendingPublicRecord> {
        record.validate()?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn refresh_market_roots(&mut self) {
        let market_ids = self.markets.keys().cloned().collect::<Vec<_>>();
        for market_id in market_ids {
            let oracle_guard_root = confidential_lending_oracle_guard_root(
                &self
                    .oracle_guards
                    .values()
                    .filter(|guard| guard.market_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let health_bucket_root = oracle_guard_root.clone();
            let risk_control_root = confidential_lending_risk_control_root(
                &self
                    .risk_controls
                    .values()
                    .filter(|control| control.subject_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let pq_authorization_root = confidential_lending_pq_authorization_root(
                &self
                    .pq_authorizations
                    .values()
                    .filter(|authorization| authorization.market_id == market_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let total_collateral_upper_bound_units = self
                .collateral_notes
                .values()
                .filter(|note| note.market_id == market_id && note.status.counts_as_open())
                .count() as u64
                * 500_000_000_000;
            let total_debt_upper_bound_units = self
                .debt_notes
                .values()
                .filter(|note| note.market_id == market_id && note.status.counts_as_open())
                .count() as u64
                * 25_000_000_000;
            let reserve_floor_units = self
                .reserve_accounting
                .values()
                .filter(|reserve| reserve.market_id == market_id)
                .fold(0_u64, |total, reserve| {
                    total.saturating_add(reserve.balance_floor_units)
                });
            if let Some(market) = self.markets.get_mut(&market_id) {
                market.oracle_guard_root = oracle_guard_root;
                market.health_bucket_root = health_bucket_root;
                market.risk_control_root = risk_control_root;
                market.pq_authorization_root = pq_authorization_root;
                market.total_collateral_upper_bound_units = total_collateral_upper_bound_units;
                market.total_debt_upper_bound_units = total_debt_upper_bound_units;
                market.reserve_floor_units = reserve_floor_units;
            }
        }

        let borrower_ids = self
            .borrower_commitments
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for borrower_id in borrower_ids {
            let collateral_note_root = confidential_lending_collateral_note_root(
                &self
                    .collateral_notes
                    .values()
                    .filter(|note| note.borrower_commitment_id == borrower_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let debt_note_root = confidential_lending_debt_note_root(
                &self
                    .debt_notes
                    .values()
                    .filter(|note| note.borrower_commitment_id == borrower_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(commitment) = self.borrower_commitments.get_mut(&borrower_id) {
                commitment.collateral_note_root = collateral_note_root;
                commitment.debt_note_root = debt_note_root;
            }
        }

        let auction_ids = self
            .liquidation_auctions
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for auction_id in auction_ids {
            let bid_commitment_root = confidential_lending_private_bid_root(
                &self
                    .private_bids
                    .values()
                    .filter(|bid| bid.auction_id == auction_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(auction) = self.liquidation_auctions.get_mut(&auction_id) {
                auction.bid_commitment_root = bid_commitment_root;
            }
        }
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn market_root(&self) -> String {
        confidential_lending_market_root(&self.markets.values().cloned().collect::<Vec<_>>())
    }

    pub fn borrower_commitment_root(&self) -> String {
        confidential_lending_borrower_commitment_root(
            &self
                .borrower_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn collateral_note_root(&self) -> String {
        confidential_lending_collateral_note_root(
            &self.collateral_notes.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn debt_note_root(&self) -> String {
        confidential_lending_debt_note_root(&self.debt_notes.values().cloned().collect::<Vec<_>>())
    }

    pub fn interest_index_root(&self) -> String {
        confidential_lending_interest_index_root(
            &self.interest_indexes.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn oracle_guard_root(&self) -> String {
        confidential_lending_oracle_guard_root(
            &self.oracle_guards.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn health_bucket_root(&self) -> String {
        self.oracle_guard_root()
    }

    pub fn liquidation_auction_root(&self) -> String {
        confidential_lending_liquidation_auction_root(
            &self
                .liquidation_auctions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_bid_root(&self) -> String {
        confidential_lending_private_bid_root(
            &self.private_bids.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        confidential_lending_low_fee_sponsorship_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_authorization_root(&self) -> String {
        confidential_lending_pq_authorization_root(
            &self.pq_authorizations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn risk_control_root(&self) -> String {
        confidential_lending_risk_control_root(
            &self.risk_controls.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn reserve_accounting_root(&self) -> String {
        confidential_lending_reserve_accounting_root(
            &self
                .reserve_accounting
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        confidential_lending_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> ConfidentialLendingRoots {
        ConfidentialLendingRoots {
            config_root: self.config_root(),
            market_root: self.market_root(),
            borrower_commitment_root: self.borrower_commitment_root(),
            collateral_note_root: self.collateral_note_root(),
            debt_note_root: self.debt_note_root(),
            interest_index_root: self.interest_index_root(),
            oracle_guard_root: self.oracle_guard_root(),
            health_bucket_root: self.health_bucket_root(),
            liquidation_auction_root: self.liquidation_auction_root(),
            private_bid_root: self.private_bid_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            pq_authorization_root: self.pq_authorization_root(),
            risk_control_root: self.risk_control_root(),
            reserve_accounting_root: self.reserve_accounting_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_roots(&self) -> ConfidentialLendingRoots {
        self.roots()
    }

    pub fn counters(&self) -> ConfidentialLendingCounters {
        ConfidentialLendingCounters {
            market_count: self.markets.len() as u64,
            borrower_commitment_count: self.borrower_commitments.len() as u64,
            active_borrower_commitment_count: self
                .borrower_commitments
                .values()
                .filter(|commitment| commitment.active_at(self.height))
                .count() as u64,
            collateral_note_count: self.collateral_notes.len() as u64,
            active_collateral_note_count: self
                .collateral_notes
                .values()
                .filter(|note| note.status.counts_as_open())
                .count() as u64,
            debt_note_count: self.debt_notes.len() as u64,
            active_debt_note_count: self
                .debt_notes
                .values()
                .filter(|note| note.status.counts_as_open())
                .count() as u64,
            interest_index_count: self.interest_indexes.len() as u64,
            oracle_guard_count: self.oracle_guards.len() as u64,
            liquidatable_bucket_count: self
                .oracle_guards
                .values()
                .filter(|guard| guard.bucket.can_liquidate())
                .count() as u64,
            liquidation_auction_count: self.liquidation_auctions.len() as u64,
            open_liquidation_auction_count: self
                .liquidation_auctions
                .values()
                .filter(|auction| auction.is_open_at(self.height))
                .count() as u64,
            private_bid_count: self.private_bids.len() as u64,
            live_private_bid_count: self
                .private_bids
                .values()
                .filter(|bid| bid.is_live_at(self.height))
                .count() as u64,
            active_low_fee_sponsorship_count: self.active_low_fee_sponsorship_count(),
            pq_authorization_count: self.pq_authorizations.len() as u64,
            active_pq_authorization_count: self
                .pq_authorizations
                .values()
                .filter(|authorization| authorization.is_active_at(self.height))
                .count() as u64,
            active_risk_control_count: self
                .risk_controls
                .values()
                .filter(|control| control.is_active_at(self.height))
                .count() as u64,
            reserve_accounting_count: self.reserve_accounting.len() as u64,
            public_record_count: self.public_records.len() as u64,
            total_debt_upper_bound_units: self.total_debt_upper_bound_units(),
            total_collateral_upper_bound_units: self.total_collateral_upper_bound_units(),
            total_reserve_floor_units: self.total_reserve_floor_units(),
            aggregate_risk_score_bps: self.aggregate_risk_score_bps(),
        }
    }

    pub fn market_ids(&self) -> Vec<String> {
        self.markets.keys().cloned().collect()
    }

    pub fn active_market_ids(&self) -> Vec<String> {
        self.markets
            .values()
            .filter(|market| {
                matches!(
                    market.status,
                    ConfidentialLendingMarketStatus::Active
                        | ConfidentialLendingMarketStatus::BorrowPaused
                        | ConfidentialLendingMarketStatus::SupplyPaused
                        | ConfidentialLendingMarketStatus::LiquidationOnly
                )
            })
            .map(|market| market.market_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_low_fee_sponsorship_count(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.is_active_at(self.height))
            .count() as u64
    }

    pub fn total_debt_upper_bound_units(&self) -> u64 {
        self.markets.values().fold(0_u64, |total, market| {
            total.saturating_add(market.total_debt_upper_bound_units)
        })
    }

    pub fn total_collateral_upper_bound_units(&self) -> u64 {
        self.markets.values().fold(0_u64, |total, market| {
            total.saturating_add(market.total_collateral_upper_bound_units)
        })
    }

    pub fn total_reserve_floor_units(&self) -> u64 {
        self.reserve_accounting
            .values()
            .fold(0_u64, |total, reserve| {
                total.saturating_add(reserve.balance_floor_units)
            })
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.pq_authorizations
            .values()
            .filter(|authorization| authorization.is_active_at(self.height))
            .map(PqLendingAuthorization::effective_risk_score_bps)
            .chain(
                self.risk_controls
                    .values()
                    .filter(|control| control.is_active_at(self.height))
                    .map(|control| control.severity.score_bps().max(control.observed_bps)),
            )
            .max()
            .unwrap_or(0)
    }

    pub fn state_root(&self) -> String {
        confidential_lending_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("confidential lending state public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ConfidentialLendingResult<String> {
        self.config.validate()?;
        for (id, market) in &self.markets {
            if id != &market.market_id {
                return Err("state market map key does not match market id".to_string());
            }
            market.validate()?;
        }
        for (id, commitment) in &self.borrower_commitments {
            if id != &commitment.commitment_id {
                return Err("state borrower map key does not match commitment id".to_string());
            }
            commitment.validate()?;
            ensure_state_market(&self.markets, &commitment.market_id, "borrower commitment")?;
        }
        for (id, note) in &self.collateral_notes {
            if id != &note.note_id {
                return Err("state collateral note key does not match note id".to_string());
            }
            note.validate()?;
            ensure_state_market(&self.markets, &note.market_id, "collateral note")?;
            if !self
                .borrower_commitments
                .contains_key(&note.borrower_commitment_id)
            {
                return Err("collateral note references missing borrower commitment".to_string());
            }
        }
        for (id, note) in &self.debt_notes {
            if id != &note.note_id {
                return Err("state debt note key does not match note id".to_string());
            }
            note.validate()?;
            ensure_state_market(&self.markets, &note.market_id, "debt note")?;
            if !self
                .borrower_commitments
                .contains_key(&note.borrower_commitment_id)
            {
                return Err("debt note references missing borrower commitment".to_string());
            }
        }
        for (id, snapshot) in &self.interest_indexes {
            if id != &snapshot.snapshot_id {
                return Err("state index key does not match snapshot id".to_string());
            }
            snapshot.validate()?;
            ensure_state_market(&self.markets, &snapshot.market_id, "interest index")?;
        }
        for (id, guard) in &self.oracle_guards {
            if id != &guard.bucket_id {
                return Err("state oracle guard key does not match bucket id".to_string());
            }
            guard.validate()?;
            ensure_state_market(&self.markets, &guard.market_id, "oracle guard")?;
        }
        for (id, auction) in &self.liquidation_auctions {
            if id != &auction.auction_id {
                return Err("state auction key does not match auction id".to_string());
            }
            auction.validate()?;
            ensure_state_market(&self.markets, &auction.market_id, "auction")?;
            if !self
                .borrower_commitments
                .contains_key(&auction.borrower_commitment_id)
            {
                return Err("auction references missing borrower commitment".to_string());
            }
            if !self
                .collateral_notes
                .contains_key(&auction.collateral_note_id)
            {
                return Err("auction references missing collateral note".to_string());
            }
            if !self.debt_notes.contains_key(&auction.debt_note_id) {
                return Err("auction references missing debt note".to_string());
            }
            if !self.oracle_guards.contains_key(&auction.health_bucket_id) {
                return Err("auction references missing health bucket".to_string());
            }
        }
        for (id, bid) in &self.private_bids {
            if id != &bid.bid_id {
                return Err("state bid key does not match bid id".to_string());
            }
            bid.validate()?;
            if !self.liquidation_auctions.contains_key(&bid.auction_id) {
                return Err("bid references missing auction".to_string());
            }
            if !bid.sponsorship_id.is_empty()
                && !self.low_fee_sponsorships.contains_key(&bid.sponsorship_id)
            {
                return Err("bid references missing sponsorship".to_string());
            }
        }
        for (id, sponsorship) in &self.low_fee_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("state sponsorship key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
            ensure_state_market(&self.markets, &sponsorship.market_id, "sponsorship")?;
        }
        for (id, authorization) in &self.pq_authorizations {
            if id != &authorization.authorization_id {
                return Err("state pq authorization key does not match id".to_string());
            }
            authorization.validate()?;
            ensure_state_market(&self.markets, &authorization.market_id, "pq authorization")?;
        }
        for (id, control) in &self.risk_controls {
            if id != &control.control_id {
                return Err("state risk control key does not match id".to_string());
            }
            control.validate()?;
            if matches!(
                control.scope,
                RiskControlScope::Market | RiskControlScope::Oracle
            ) {
                ensure_state_market(&self.markets, &control.subject_id, "risk control")?;
            }
        }
        for (id, reserve) in &self.reserve_accounting {
            if id != &reserve.reserve_id {
                return Err("state reserve key does not match reserve id".to_string());
            }
            reserve.validate()?;
            ensure_state_market(&self.markets, &reserve.market_id, "reserve")?;
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let counters = self.counters();
        json!({
            "kind": "confidential_lending_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_LENDING_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "market_ids": self.market_ids(),
            "active_market_ids": self.active_market_ids(),
            "counters": counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }
}

pub fn confidential_lending_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn confidential_lending_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn confidential_lending_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn confidential_lending_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn confidential_lending_proof_root(
    proof_system: &str,
    public_input_root: &str,
    private_witness_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_root),
        ],
        32,
    )
}

pub fn confidential_lending_account_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_lending_amount_commitment(label: &str, units: u64, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_lending_market_root(markets: &[ConfidentialLendingMarket]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-MARKET",
        markets
            .iter()
            .map(ConfidentialLendingMarket::public_record)
            .collect(),
        "market_id",
    )
}

pub fn confidential_lending_borrower_commitment_root(
    commitments: &[PrivateBorrowerCommitment],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-BORROWER-COMMITMENT",
        commitments
            .iter()
            .map(PrivateBorrowerCommitment::public_record)
            .collect(),
        "commitment_id",
    )
}

pub fn confidential_lending_collateral_note_root(notes: &[EncryptedCollateralNote]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-COLLATERAL-NOTE",
        notes
            .iter()
            .map(EncryptedCollateralNote::public_record)
            .collect(),
        "note_id",
    )
}

pub fn confidential_lending_debt_note_root(notes: &[EncryptedDebtNote]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-DEBT-NOTE",
        notes.iter().map(EncryptedDebtNote::public_record).collect(),
        "note_id",
    )
}

pub fn confidential_lending_interest_index_root(
    indexes: &[LendingInterestIndexSnapshot],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-INTEREST-INDEX",
        indexes
            .iter()
            .map(LendingInterestIndexSnapshot::public_record)
            .collect(),
        "snapshot_id",
    )
}

pub fn confidential_lending_oracle_guard_root(guards: &[OracleGuardedHealthBucket]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-ORACLE-GUARD",
        guards
            .iter()
            .map(OracleGuardedHealthBucket::public_record)
            .collect(),
        "bucket_id",
    )
}

pub fn confidential_lending_health_bucket_root(buckets: &[OracleGuardedHealthBucket]) -> String {
    confidential_lending_oracle_guard_root(buckets)
}

pub fn confidential_lending_liquidation_auction_root(
    auctions: &[PrivateLiquidationAuction],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-LIQUIDATION-AUCTION",
        auctions
            .iter()
            .map(PrivateLiquidationAuction::public_record)
            .collect(),
        "auction_id",
    )
}

pub fn confidential_lending_private_bid_root(bids: &[PrivateLiquidationBid]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-PRIVATE-BID",
        bids.iter()
            .map(PrivateLiquidationBid::public_record)
            .collect(),
        "bid_id",
    )
}

pub fn confidential_lending_low_fee_sponsorship_root(
    sponsorships: &[LowFeeLendingSponsorship],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-LOW-FEE-SPONSORSHIP",
        sponsorships
            .iter()
            .map(LowFeeLendingSponsorship::public_record)
            .collect(),
        "sponsorship_id",
    )
}

pub fn confidential_lending_pq_authorization_root(
    authorizations: &[PqLendingAuthorization],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-PQ-AUTHORIZATION",
        authorizations
            .iter()
            .map(PqLendingAuthorization::public_record)
            .collect(),
        "authorization_id",
    )
}

pub fn confidential_lending_risk_control_root(controls: &[ConfidentialRiskControl]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-RISK-CONTROL",
        controls
            .iter()
            .map(ConfidentialRiskControl::public_record)
            .collect(),
        "control_id",
    )
}

pub fn confidential_lending_reserve_accounting_root(
    reserves: &[LendingReserveAccounting],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-RESERVE-ACCOUNTING",
        reserves
            .iter()
            .map(LendingReserveAccounting::public_record)
            .collect(),
        "reserve_id",
    )
}

pub fn confidential_lending_public_record_root(
    records: &[ConfidentialLendingPublicRecord],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-LENDING-PUBLIC-RECORD",
        records
            .iter()
            .map(ConfidentialLendingPublicRecord::public_record)
            .collect(),
        "record_id",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_lending_market_id(
    display_name: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    oracle_feed_id: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(display_name),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_lending_borrower_commitment_id(
    market_id: &str,
    borrower_commitment: &str,
    spend_nullifier_hash: &str,
    pq_authorization_root: &str,
    opened_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-BORROWER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(borrower_commitment),
            HashPart::Str(spend_nullifier_hash),
            HashPart::Str(pq_authorization_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_lending_collateral_note_id(
    market_id: &str,
    borrower_commitment_id: &str,
    collateral_asset_id: &str,
    amount_commitment: &str,
    created_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-COLLATERAL-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(borrower_commitment_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(amount_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_lending_debt_note_id(
    market_id: &str,
    borrower_commitment_id: &str,
    debt_asset_id: &str,
    principal_commitment: &str,
    created_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-DEBT-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(borrower_commitment_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(principal_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_lending_interest_index_snapshot_id(
    market_id: &str,
    height: u64,
    supply_index: u64,
    borrow_index: u64,
    utilization_bps: u64,
    previous_snapshot_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-INTEREST-INDEX-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Int(height as i128),
            HashPart::Int(supply_index as i128),
            HashPart::Int(borrow_index as i128),
            HashPart::Int(utilization_bps as i128),
            HashPart::Str(previous_snapshot_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_lending_health_bucket_id(
    market_id: &str,
    bucket: HealthBucket,
    snapshot_height: u64,
    position_count: u64,
    debt_upper_bound_units: u64,
    public_input_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-HEALTH-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(bucket.as_str()),
            HashPart::Int(snapshot_height as i128),
            HashPart::Int(position_count as i128),
            HashPart::Int(debt_upper_bound_units as i128),
            HashPart::Str(public_input_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_lending_liquidation_auction_id(
    market_id: &str,
    borrower_commitment_id: &str,
    collateral_note_id: &str,
    debt_note_id: &str,
    health_bucket_id: &str,
    opened_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-LIQUIDATION-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(borrower_commitment_id),
            HashPart::Str(collateral_note_id),
            HashPart::Str(debt_note_id),
            HashPart::Str(health_bucket_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_lending_private_bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    repay_amount_commitment: &str,
    max_price_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-PRIVATE-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(repay_amount_commitment),
            HashPart::Str(max_price_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_lending_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    market_id: &str,
    lane_id: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(market_id),
            HashPart::Str(lane_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_lending_pq_authorization_id(
    market_id: &str,
    subject_kind: &str,
    subject_id: &str,
    committee_id: &str,
    authorization_root: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(committee_id),
            HashPart::Str(authorization_root),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn confidential_lending_risk_control_id(
    scope: RiskControlScope,
    subject_id: &str,
    trigger_metric: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-RISK-CONTROL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(trigger_metric),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_lending_reserve_id(
    market_id: &str,
    asset_id: &str,
    controller_commitment: &str,
    recorded_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-RESERVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
            HashPart::Str(controller_commitment),
            HashPart::Int(recorded_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_lending_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-LENDING-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn confidential_lending_risk_status(score_bps: u64) -> &'static str {
    if score_bps >= 9_000 {
        "critical"
    } else if score_bps >= 6_000 {
        "elevated"
    } else if score_bps >= 2_500 {
        "watch"
    } else {
        "normal"
    }
}

pub fn confidential_lending_health_factor_bps(
    collateral_value_units: u64,
    debt_value_units: u64,
) -> u64 {
    if debt_value_units == 0 {
        return u64::MAX;
    }
    ratio_bps(collateral_value_units, debt_value_units)
}

pub fn confidential_lending_value_units(amount_units: u64, price_units: u64) -> u64 {
    mul_div_floor(amount_units, price_units, CONFIDENTIAL_LENDING_PRICE_SCALE)
}

pub fn confidential_lending_bps_mul_floor(units: u64, bps: u64) -> u64 {
    mul_div_floor(units, bps, CONFIDENTIAL_LENDING_MAX_BPS)
}

pub fn confidential_lending_bps_mul_ceil(units: u64, bps: u64) -> u64 {
    mul_div_ceil(units, bps, CONFIDENTIAL_LENDING_MAX_BPS)
}

pub fn confidential_lending_annualized_bps_accrual(
    amount_units: u64,
    annual_bps: u64,
    blocks: u64,
) -> u64 {
    let numerator = (amount_units as u128)
        .saturating_mul(annual_bps as u128)
        .saturating_mul(blocks as u128);
    let denominator = (CONFIDENTIAL_LENDING_MAX_BPS as u128)
        .saturating_mul(CONFIDENTIAL_LENDING_BLOCKS_PER_YEAR as u128);
    if denominator == 0 {
        return 0;
    }
    (numerator / denominator).min(u64::MAX as u128) as u64
}

fn sorted_merkle_root(domain: &str, mut leaves: Vec<Value>, sort_key: &str) -> String {
    leaves.sort_by_key(|record| {
        record
            .get(sort_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialLendingResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ConfidentialLendingResult<()> {
    if value > CONFIDENTIAL_LENDING_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_state_market(
    markets: &BTreeMap<String, ConfidentialLendingMarket>,
    market_id: &str,
    label: &str,
) -> ConfidentialLendingResult<()> {
    if markets.contains_key(market_id) {
        Ok(())
    } else {
        Err(format!(
            "{label} references unknown confidential lending market"
        ))
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let value = (numerator as u128).saturating_mul(CONFIDENTIAL_LENDING_MAX_BPS as u128)
        / denominator as u128;
    value.min(u64::MAX as u128) as u64
}

fn mul_div_floor(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let result = (value as u128).saturating_mul(multiplier as u128) / denominator as u128;
    result.min(u64::MAX as u128) as u64
}

fn mul_div_ceil(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let numerator = (value as u128).saturating_mul(multiplier as u128);
    let denominator = denominator as u128;
    let result = numerator.saturating_add(denominator.saturating_sub(1)) / denominator;
    result.min(u64::MAX as u128) as u64
}
