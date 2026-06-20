use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LendingMarketResult<T> = Result<T, String>;

pub const LENDING_MARKET_PROTOCOL_VERSION: &str = "nebula-lending-market-v1";
pub const LENDING_MARKET_MAX_BPS: u64 = 10_000;
pub const LENDING_MARKET_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const LENDING_MARKET_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const LENDING_MARKET_BLOCKS_PER_YEAR: u64 = 2_628_000;
pub const LENDING_MARKET_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 40;
pub const LENDING_MARKET_DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 120;
pub const LENDING_MARKET_DEFAULT_HEALTH_BUCKET_TTL_BLOCKS: u64 = 16;
pub const LENDING_MARKET_DEFAULT_ORACLE_STALENESS_BLOCKS: u64 = 16;
pub const LENDING_MARKET_DEFAULT_ORACLE_DEVIATION_BPS: u64 = 650;
pub const LENDING_MARKET_DEFAULT_TWAP_DEVIATION_BPS: u64 = 500;
pub const LENDING_MARKET_DEFAULT_CLOSE_FACTOR_BPS: u64 = 5_000;
pub const LENDING_MARKET_DEFAULT_RESERVE_TARGET_BPS: u64 = 1_500;
pub const LENDING_MARKET_DEFAULT_MIN_LIQUIDATION_DEBT_UNITS: u64 = 1_000;
pub const LENDING_MARKET_DEFAULT_LOW_FEE_LANE: &str = "small_defi_liquidations";
pub const LENDING_MARKET_PRIVATE_BORROW_PROOF_SYSTEM: &str = "pq-private-lending-borrow-devnet";
pub const LENDING_MARKET_HEALTH_BUCKET_PROOF_SYSTEM: &str =
    "pq-private-lending-health-bucket-devnet";
pub const LENDING_MARKET_DEVNET_HEIGHT: u64 = 64;
pub const LENDING_MARKET_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const LENDING_MARKET_DEVNET_DEBT_ASSET_ID: &str = "usdd-devnet";
pub const LENDING_MARKET_DEVNET_GOV_ASSET_ID: &str = "dnr-devnet";
pub const LENDING_MARKET_DEVNET_SHARE_ASSET_ID: &str = "dlend-wxmr-usdd-devnet";
pub const LENDING_MARKET_DEVNET_MARKET_LABEL: &str = "wXMR private lending devnet";
pub const LENDING_MARKET_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-usdd-devnet";
pub const LENDING_MARKET_DEVNET_WXMR_PRICE: u64 = 160 * LENDING_MARKET_PRICE_SCALE;
pub const LENDING_MARKET_STATUS_ACTIVE: &str = "active";
pub const LENDING_MARKET_STATUS_OPEN: &str = "open";
pub const LENDING_MARKET_STATUS_PENDING: &str = "pending";
pub const LENDING_MARKET_STATUS_SETTLED: &str = "settled";
pub const LENDING_MARKET_STATUS_EXPIRED: &str = "expired";
pub const LENDING_MARKET_STATUS_CANCELLED: &str = "cancelled";
pub const LENDING_MARKET_STATUS_PAUSED: &str = "paused";
pub const LENDING_MARKET_STATUS_RETIRED: &str = "retired";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LendingRiskTier {
    Core,
    Stable,
    Growth,
    Isolation,
    Experimental,
}

impl LendingRiskTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Stable => "stable",
            Self::Growth => "growth",
            Self::Isolation => "isolation",
            Self::Experimental => "experimental",
        }
    }

    pub fn default_collateral_factor_bps(&self) -> u64 {
        match self {
            Self::Stable => 8_000,
            Self::Core => 6_500,
            Self::Growth => 5_000,
            Self::Isolation => 4_000,
            Self::Experimental => 2_500,
        }
    }

    pub fn default_liquidation_threshold_bps(&self) -> u64 {
        match self {
            Self::Stable => 8_800,
            Self::Core => 8_000,
            Self::Growth => 6_500,
            Self::Isolation => 5_500,
            Self::Experimental => 3_500,
        }
    }

    pub fn default_liquidation_bonus_bps(&self) -> u64 {
        match self {
            Self::Stable => 300,
            Self::Core => 600,
            Self::Growth => 850,
            Self::Isolation => 1_200,
            Self::Experimental => 1_800,
        }
    }

    pub fn default_borrow_cap_units(&self) -> u64 {
        match self {
            Self::Stable => 250_000_000,
            Self::Core => 100_000_000,
            Self::Growth => 35_000_000,
            Self::Isolation => 12_000_000,
            Self::Experimental => 2_500_000,
        }
    }

    pub fn priority_score(&self) -> u64 {
        match self {
            Self::Stable => 10,
            Self::Core => 20,
            Self::Growth => 40,
            Self::Isolation => 70,
            Self::Experimental => 100,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LendingMarketStatus {
    Active,
    ReduceOnly,
    BorrowPaused,
    SupplyPaused,
    LiquidationOnly,
    Paused,
    Retired,
}

impl LendingMarketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReduceOnly => "reduce_only",
            Self::BorrowPaused => "borrow_paused",
            Self::SupplyPaused => "supply_paused",
            Self::LiquidationOnly => "liquidation_only",
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
        !matches!(self, Self::Paused | Self::Retired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterestCurveKind {
    Stable,
    Kinked,
    Jump,
    GovernanceControlled,
}

impl InterestCurveKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Kinked => "kinked",
            Self::Jump => "jump",
            Self::GovernanceControlled => "governance_controlled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BorrowVisibility {
    Public,
    Shielded,
    Private,
    Stealth,
}

impl BorrowVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Shielded => "shielded",
            Self::Private => "private",
            Self::Stealth => "stealth",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthFactorBucket {
    NoDebt,
    Healthy,
    Watch,
    Unsafe,
    Liquidatable,
    Insolvent,
}

impl HealthFactorBucket {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoDebt => "no_debt",
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Unsafe => "unsafe",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }

    pub fn from_health_factor_bps(health_factor_bps: u64) -> Self {
        if health_factor_bps == u64::MAX {
            Self::NoDebt
        } else if health_factor_bps >= 15_000 {
            Self::Healthy
        } else if health_factor_bps >= 12_000 {
            Self::Watch
        } else if health_factor_bps >= 10_000 {
            Self::Unsafe
        } else if health_factor_bps >= 7_500 {
            Self::Liquidatable
        } else {
            Self::Insolvent
        }
    }

    pub fn floor_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::Healthy => 15_000,
            Self::Watch => 12_000,
            Self::Unsafe => 10_000,
            Self::Liquidatable => 7_500,
            Self::Insolvent => 0,
        }
    }

    pub fn ceiling_bps(&self) -> u64 {
        match self {
            Self::NoDebt => u64::MAX,
            Self::Healthy => u64::MAX - 1,
            Self::Watch => 14_999,
            Self::Unsafe => 11_999,
            Self::Liquidatable => 9_999,
            Self::Insolvent => 7_499,
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
pub enum LiquidationAuctionStatus {
    Pending,
    Open,
    Settled,
    Cancelled,
    Expired,
}

impl LiquidationAuctionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LossRecordStatus {
    Pending,
    CoveredByReserve,
    Socialized,
    WrittenOff,
    Recovered,
}

impl LossRecordStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::CoveredByReserve => "covered_by_reserve",
            Self::Socialized => "socialized",
            Self::WrittenOff => "written_off",
            Self::Recovered => "recovered",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolFeeEventKind {
    BorrowInterest,
    Origination,
    Liquidation,
    ReserveSweep,
    SponsorshipRebate,
}

impl ProtocolFeeEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BorrowInterest => "borrow_interest",
            Self::Origination => "origination",
            Self::Liquidation => "liquidation",
            Self::ReserveSweep => "reserve_sweep",
            Self::SponsorshipRebate => "sponsorship_rebate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingMarketConfig {
    pub protocol_version: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub blocks_per_year: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_twap_deviation_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub default_auction_ttl_blocks: u64,
    pub default_commitment_ttl_blocks: u64,
    pub default_health_bucket_ttl_blocks: u64,
    pub min_liquidation_debt_units: u64,
    pub default_close_factor_bps: u64,
    pub liquidation_protocol_fee_bps: u64,
    pub reserve_target_bps: u64,
    pub low_fee_liquidation_lane: String,
    pub private_borrow_proof_system: String,
    pub health_bucket_proof_system: String,
    pub metadata_root: String,
}

impl Default for LendingMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: LENDING_MARKET_PROTOCOL_VERSION.to_string(),
            price_scale: LENDING_MARKET_PRICE_SCALE,
            index_scale: LENDING_MARKET_INDEX_SCALE,
            blocks_per_year: LENDING_MARKET_BLOCKS_PER_YEAR,
            max_oracle_deviation_bps: LENDING_MARKET_DEFAULT_ORACLE_DEVIATION_BPS,
            max_twap_deviation_bps: LENDING_MARKET_DEFAULT_TWAP_DEVIATION_BPS,
            max_oracle_staleness_blocks: LENDING_MARKET_DEFAULT_ORACLE_STALENESS_BLOCKS,
            default_auction_ttl_blocks: LENDING_MARKET_DEFAULT_AUCTION_TTL_BLOCKS,
            default_commitment_ttl_blocks: LENDING_MARKET_DEFAULT_COMMITMENT_TTL_BLOCKS,
            default_health_bucket_ttl_blocks: LENDING_MARKET_DEFAULT_HEALTH_BUCKET_TTL_BLOCKS,
            min_liquidation_debt_units: LENDING_MARKET_DEFAULT_MIN_LIQUIDATION_DEBT_UNITS,
            default_close_factor_bps: LENDING_MARKET_DEFAULT_CLOSE_FACTOR_BPS,
            liquidation_protocol_fee_bps: 75,
            reserve_target_bps: LENDING_MARKET_DEFAULT_RESERVE_TARGET_BPS,
            low_fee_liquidation_lane: LENDING_MARKET_DEFAULT_LOW_FEE_LANE.to_string(),
            private_borrow_proof_system: LENDING_MARKET_PRIVATE_BORROW_PROOF_SYSTEM.to_string(),
            health_bucket_proof_system: LENDING_MARKET_HEALTH_BUCKET_PROOF_SYSTEM.to_string(),
            metadata_root: lending_market_payload_root(
                "LENDING-MARKET-CONFIG-METADATA",
                &json!({"mode": "default"}),
            ),
        }
    }
}

impl LendingMarketConfig {
    pub fn validate(&self) -> LendingMarketResult<()> {
        ensure_non_empty(&self.protocol_version, "lending config protocol_version")?;
        ensure_non_empty(
            &self.low_fee_liquidation_lane,
            "lending config low_fee_liquidation_lane",
        )?;
        ensure_non_empty(
            &self.private_borrow_proof_system,
            "lending config private_borrow_proof_system",
        )?;
        ensure_non_empty(
            &self.health_bucket_proof_system,
            "lending config health_bucket_proof_system",
        )?;
        validate_bps(
            "lending config max_oracle_deviation_bps",
            self.max_oracle_deviation_bps,
        )?;
        validate_bps(
            "lending config max_twap_deviation_bps",
            self.max_twap_deviation_bps,
        )?;
        validate_bps(
            "lending config default_close_factor_bps",
            self.default_close_factor_bps,
        )?;
        validate_bps(
            "lending config liquidation_protocol_fee_bps",
            self.liquidation_protocol_fee_bps,
        )?;
        validate_bps("lending config reserve_target_bps", self.reserve_target_bps)?;
        if self.price_scale == 0 || self.index_scale == 0 || self.blocks_per_year == 0 {
            return Err("lending config scales and blocks_per_year must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "blocks_per_year": self.blocks_per_year,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "max_twap_deviation_bps": self.max_twap_deviation_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "default_auction_ttl_blocks": self.default_auction_ttl_blocks,
            "default_commitment_ttl_blocks": self.default_commitment_ttl_blocks,
            "default_health_bucket_ttl_blocks": self.default_health_bucket_ttl_blocks,
            "min_liquidation_debt_units": self.min_liquidation_debt_units,
            "default_close_factor_bps": self.default_close_factor_bps,
            "liquidation_protocol_fee_bps": self.liquidation_protocol_fee_bps,
            "reserve_target_bps": self.reserve_target_bps,
            "low_fee_liquidation_lane": self.low_fee_liquidation_lane,
            "private_borrow_proof_system": self.private_borrow_proof_system,
            "health_bucket_proof_system": self.health_bucket_proof_system,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        lending_market_payload_root("LENDING-MARKET-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingRiskTierConfig {
    pub tier_id: String,
    pub risk_tier: LendingRiskTier,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub reserve_factor_bps: u64,
    pub protocol_fee_bps: u64,
    pub close_factor_bps: u64,
    pub borrow_cap_units: u64,
    pub min_collateral_value_units: u64,
    pub isolation_mode: bool,
    pub private_borrow_required: bool,
    pub active: bool,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl LendingRiskTierConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        risk_tier: LendingRiskTier,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        liquidation_bonus_bps: u64,
        reserve_factor_bps: u64,
        protocol_fee_bps: u64,
        close_factor_bps: u64,
        borrow_cap_units: u64,
        min_collateral_value_units: u64,
        isolation_mode: bool,
        private_borrow_required: bool,
        active: bool,
        created_at_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        let metadata_root = lending_market_payload_root("LENDING-RISK-TIER-METADATA", metadata);
        let tier_id = lending_risk_tier_id(
            risk_tier,
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            reserve_factor_bps,
            protocol_fee_bps,
            close_factor_bps,
            borrow_cap_units,
            min_collateral_value_units,
            isolation_mode,
            private_borrow_required,
            created_at_height,
            &metadata_root,
        );
        let config = Self {
            tier_id,
            risk_tier,
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            reserve_factor_bps,
            protocol_fee_bps,
            close_factor_bps,
            borrow_cap_units,
            min_collateral_value_units,
            isolation_mode,
            private_borrow_required,
            active,
            created_at_height,
            metadata_root,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn devnet(risk_tier: LendingRiskTier, created_at_height: u64) -> LendingMarketResult<Self> {
        Self::new(
            risk_tier,
            risk_tier.default_collateral_factor_bps(),
            risk_tier.default_liquidation_threshold_bps(),
            risk_tier.default_liquidation_bonus_bps(),
            match risk_tier {
                LendingRiskTier::Stable => 700,
                LendingRiskTier::Core => 1_000,
                LendingRiskTier::Growth => 1_500,
                LendingRiskTier::Isolation => 2_000,
                LendingRiskTier::Experimental => 3_500,
            },
            match risk_tier {
                LendingRiskTier::Stable => 25,
                LendingRiskTier::Core => 50,
                LendingRiskTier::Growth => 90,
                LendingRiskTier::Isolation => 125,
                LendingRiskTier::Experimental => 200,
            },
            LENDING_MARKET_DEFAULT_CLOSE_FACTOR_BPS,
            risk_tier.default_borrow_cap_units(),
            match risk_tier {
                LendingRiskTier::Stable => 10_000,
                LendingRiskTier::Core => 50_000,
                LendingRiskTier::Growth => 100_000,
                LendingRiskTier::Isolation => 250_000,
                LendingRiskTier::Experimental => 500_000,
            },
            matches!(
                risk_tier,
                LendingRiskTier::Isolation | LendingRiskTier::Experimental
            ),
            !matches!(risk_tier, LendingRiskTier::Stable),
            true,
            created_at_height,
            &json!({"mode": "devnet", "risk_tier": risk_tier.as_str()}),
        )
    }

    pub fn validate(&self) -> LendingMarketResult<()> {
        validate_bps(
            "risk tier collateral_factor_bps",
            self.collateral_factor_bps,
        )?;
        validate_bps(
            "risk tier liquidation_threshold_bps",
            self.liquidation_threshold_bps,
        )?;
        validate_bps(
            "risk tier liquidation_bonus_bps",
            self.liquidation_bonus_bps,
        )?;
        validate_bps("risk tier reserve_factor_bps", self.reserve_factor_bps)?;
        validate_bps("risk tier protocol_fee_bps", self.protocol_fee_bps)?;
        validate_bps("risk tier close_factor_bps", self.close_factor_bps)?;
        if self.collateral_factor_bps > self.liquidation_threshold_bps {
            return Err("risk tier collateral factor exceeds liquidation threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_risk_tier_config",
            "chain_id": CHAIN_ID,
            "tier_id": self.tier_id,
            "risk_tier": self.risk_tier.as_str(),
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "close_factor_bps": self.close_factor_bps,
            "borrow_cap_units": self.borrow_cap_units,
            "min_collateral_value_units": self.min_collateral_value_units,
            "isolation_mode": self.isolation_mode,
            "private_borrow_required": self.private_borrow_required,
            "active": self.active,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn tier_root(&self) -> String {
        lending_market_payload_root("LENDING-RISK-TIER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingCollateralMarket {
    pub market_id: String,
    pub market_label: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub share_asset_id: String,
    pub risk_tier: LendingRiskTier,
    pub status: LendingMarketStatus,
    pub collateral_decimals: u8,
    pub debt_decimals: u8,
    pub total_supplied_units: u64,
    pub total_supply_scaled_units: u64,
    pub total_borrowed_principal_units: u64,
    pub total_borrowed_scaled_units: u64,
    pub total_collateral_locked_units: u64,
    pub reserve_units: u64,
    pub protocol_fee_units: u64,
    pub supply_cap_units: u64,
    pub borrow_cap_units: u64,
    pub min_borrow_units: u64,
    pub oracle_feed_id: String,
    pub oracle_guard_id: String,
    pub interest_curve_id: String,
    pub current_supply_index: u64,
    pub current_borrow_index: u64,
    pub last_accrual_height: u64,
    pub low_fee_lane: String,
    pub privacy_root: String,
    pub metadata_root: String,
}

impl LendingCollateralMarket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_label: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        share_asset_id: &str,
        risk_tier: LendingRiskTier,
        status: LendingMarketStatus,
        collateral_decimals: u8,
        debt_decimals: u8,
        supply_cap_units: u64,
        borrow_cap_units: u64,
        min_borrow_units: u64,
        oracle_feed_id: &str,
        low_fee_lane: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_label, "lending market label")?;
        ensure_non_empty(collateral_asset_id, "lending collateral asset_id")?;
        ensure_non_empty(debt_asset_id, "lending debt asset_id")?;
        ensure_non_empty(share_asset_id, "lending share asset_id")?;
        ensure_non_empty(oracle_feed_id, "lending oracle feed_id")?;
        ensure_non_empty(low_fee_lane, "lending low_fee_lane")?;
        let metadata_root = lending_market_payload_root("LENDING-MARKET-METADATA", metadata);
        let market_id = lending_collateral_market_id(
            market_label,
            collateral_asset_id,
            debt_asset_id,
            share_asset_id,
            risk_tier,
            supply_cap_units,
            borrow_cap_units,
            oracle_feed_id,
            created_at_height,
            &metadata_root,
        );
        let privacy_root = lending_market_payload_root(
            "LENDING-MARKET-PRIVACY-ROOT",
            &json!({
                "market_label": market_label,
                "collateral_asset_id": collateral_asset_id,
                "debt_asset_id": debt_asset_id,
                "mode": "empty"
            }),
        );
        let market = Self {
            market_id,
            market_label: market_label.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            share_asset_id: share_asset_id.to_string(),
            risk_tier,
            status,
            collateral_decimals,
            debt_decimals,
            total_supplied_units: 0,
            total_supply_scaled_units: 0,
            total_borrowed_principal_units: 0,
            total_borrowed_scaled_units: 0,
            total_collateral_locked_units: 0,
            reserve_units: 0,
            protocol_fee_units: 0,
            supply_cap_units,
            borrow_cap_units,
            min_borrow_units,
            oracle_feed_id: oracle_feed_id.to_string(),
            oracle_guard_id: String::new(),
            interest_curve_id: String::new(),
            current_supply_index: LENDING_MARKET_INDEX_SCALE,
            current_borrow_index: LENDING_MARKET_INDEX_SCALE,
            last_accrual_height: created_at_height,
            low_fee_lane: low_fee_lane.to_string(),
            privacy_root,
            metadata_root,
        };
        market.validate()?;
        Ok(market)
    }

    pub fn validate(&self) -> LendingMarketResult<()> {
        ensure_non_empty(&self.market_id, "lending market_id")?;
        ensure_non_empty(
            &self.collateral_asset_id,
            "lending market collateral_asset_id",
        )?;
        ensure_non_empty(&self.debt_asset_id, "lending market debt_asset_id")?;
        ensure_non_empty(&self.share_asset_id, "lending market share_asset_id")?;
        if self.supply_cap_units == 0 || self.borrow_cap_units == 0 {
            return Err("lending market caps must be positive".to_string());
        }
        if self.current_supply_index == 0 || self.current_borrow_index == 0 {
            return Err("lending market indexes must be positive".to_string());
        }
        Ok(())
    }

    pub fn available_liquidity_units(&self) -> u64 {
        self.total_supplied_units
            .saturating_sub(self.total_borrowed_principal_units)
            .saturating_sub(self.reserve_units)
    }

    pub fn borrow_capacity_units(&self) -> u64 {
        self.borrow_cap_units
            .saturating_sub(self.total_borrowed_principal_units)
    }

    pub fn supply_capacity_units(&self) -> u64 {
        self.supply_cap_units
            .saturating_sub(self.total_supplied_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(
            self.total_borrowed_principal_units,
            self.total_supplied_units.max(1),
        )
        .min(LENDING_MARKET_MAX_BPS)
    }

    pub fn reserve_coverage_bps(&self) -> u64 {
        ratio_bps(
            self.reserve_units,
            self.total_borrowed_principal_units.max(1),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_collateral_market",
            "chain_id": CHAIN_ID,
            "market_id": self.market_id,
            "market_label": self.market_label,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "share_asset_id": self.share_asset_id,
            "risk_tier": self.risk_tier.as_str(),
            "status": self.status.as_str(),
            "collateral_decimals": self.collateral_decimals,
            "debt_decimals": self.debt_decimals,
            "total_supplied_units": self.total_supplied_units,
            "total_supply_scaled_units": self.total_supply_scaled_units,
            "total_borrowed_principal_units": self.total_borrowed_principal_units,
            "total_borrowed_scaled_units": self.total_borrowed_scaled_units,
            "total_collateral_locked_units": self.total_collateral_locked_units,
            "reserve_units": self.reserve_units,
            "protocol_fee_units": self.protocol_fee_units,
            "available_liquidity_units": self.available_liquidity_units(),
            "borrow_capacity_units": self.borrow_capacity_units(),
            "supply_capacity_units": self.supply_capacity_units(),
            "supply_cap_units": self.supply_cap_units,
            "borrow_cap_units": self.borrow_cap_units,
            "min_borrow_units": self.min_borrow_units,
            "utilization_bps": self.utilization_bps(),
            "reserve_coverage_bps": self.reserve_coverage_bps(),
            "oracle_feed_id": self.oracle_feed_id,
            "oracle_guard_id": self.oracle_guard_id,
            "interest_curve_id": self.interest_curve_id,
            "current_supply_index": self.current_supply_index,
            "current_borrow_index": self.current_borrow_index,
            "last_accrual_height": self.last_accrual_height,
            "low_fee_lane": self.low_fee_lane,
            "privacy_root": self.privacy_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn market_root(&self) -> String {
        lending_market_payload_root("LENDING-COLLATERAL-MARKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingCollateralRule {
    pub rule_id: String,
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub risk_tier: LendingRiskTier,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub protocol_fee_bps: u64,
    pub reserve_factor_bps: u64,
    pub close_factor_bps: u64,
    pub min_collateral_value_units: u64,
    pub max_position_debt_units: u64,
    pub isolated_debt_cap_units: u64,
    pub oracle_feed_id: String,
    pub active: bool,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl LendingCollateralRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        risk_tier: LendingRiskTier,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        liquidation_bonus_bps: u64,
        protocol_fee_bps: u64,
        reserve_factor_bps: u64,
        close_factor_bps: u64,
        min_collateral_value_units: u64,
        max_position_debt_units: u64,
        isolated_debt_cap_units: u64,
        oracle_feed_id: &str,
        active: bool,
        created_at_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "collateral rule market_id")?;
        ensure_non_empty(collateral_asset_id, "collateral rule collateral_asset_id")?;
        ensure_non_empty(debt_asset_id, "collateral rule debt_asset_id")?;
        ensure_non_empty(oracle_feed_id, "collateral rule oracle_feed_id")?;
        let metadata_root =
            lending_market_payload_root("LENDING-COLLATERAL-RULE-METADATA", metadata);
        let rule_id = lending_collateral_rule_id(
            market_id,
            collateral_asset_id,
            debt_asset_id,
            risk_tier,
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            protocol_fee_bps,
            reserve_factor_bps,
            close_factor_bps,
            min_collateral_value_units,
            max_position_debt_units,
            isolated_debt_cap_units,
            oracle_feed_id,
            created_at_height,
            &metadata_root,
        );
        let rule = Self {
            rule_id,
            market_id: market_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            risk_tier,
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            protocol_fee_bps,
            reserve_factor_bps,
            close_factor_bps,
            min_collateral_value_units,
            max_position_debt_units,
            isolated_debt_cap_units,
            oracle_feed_id: oracle_feed_id.to_string(),
            active,
            created_at_height,
            metadata_root,
        };
        rule.validate()?;
        Ok(rule)
    }

    pub fn validate(&self) -> LendingMarketResult<()> {
        validate_bps(
            "collateral rule collateral_factor_bps",
            self.collateral_factor_bps,
        )?;
        validate_bps(
            "collateral rule liquidation_threshold_bps",
            self.liquidation_threshold_bps,
        )?;
        validate_bps(
            "collateral rule liquidation_bonus_bps",
            self.liquidation_bonus_bps,
        )?;
        validate_bps("collateral rule protocol_fee_bps", self.protocol_fee_bps)?;
        validate_bps(
            "collateral rule reserve_factor_bps",
            self.reserve_factor_bps,
        )?;
        validate_bps("collateral rule close_factor_bps", self.close_factor_bps)?;
        if self.collateral_factor_bps > self.liquidation_threshold_bps {
            return Err(
                "collateral rule collateral factor exceeds liquidation threshold".to_string(),
            );
        }
        if self.max_position_debt_units == 0 {
            return Err("collateral rule max_position_debt_units must be positive".to_string());
        }
        Ok(())
    }

    pub fn max_debt_for_collateral_value(&self, collateral_value_units: u64) -> u64 {
        bps_mul_floor(collateral_value_units, self.collateral_factor_bps)
            .min(self.max_position_debt_units)
    }

    pub fn liquidation_value_units(&self, collateral_value_units: u64) -> u64 {
        bps_mul_floor(collateral_value_units, self.liquidation_threshold_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_collateral_rule",
            "chain_id": CHAIN_ID,
            "rule_id": self.rule_id,
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "risk_tier": self.risk_tier.as_str(),
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "close_factor_bps": self.close_factor_bps,
            "min_collateral_value_units": self.min_collateral_value_units,
            "max_position_debt_units": self.max_position_debt_units,
            "isolated_debt_cap_units": self.isolated_debt_cap_units,
            "oracle_feed_id": self.oracle_feed_id,
            "active": self.active,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn rule_root(&self) -> String {
        lending_market_payload_root("LENDING-COLLATERAL-RULE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingInterestRateModel {
    pub curve_id: String,
    pub market_id: String,
    pub curve_kind: InterestCurveKind,
    pub base_rate_bps: u64,
    pub kink_utilization_bps: u64,
    pub jump_utilization_bps: u64,
    pub slope1_bps: u64,
    pub slope2_bps: u64,
    pub slope3_bps: u64,
    pub reserve_factor_bps: u64,
    pub protocol_fee_bps: u64,
    pub min_borrow_rate_bps: u64,
    pub max_borrow_rate_bps: u64,
    pub created_at_height: u64,
    pub active: bool,
    pub metadata_root: String,
}

impl LendingInterestRateModel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        curve_kind: InterestCurveKind,
        base_rate_bps: u64,
        kink_utilization_bps: u64,
        jump_utilization_bps: u64,
        slope1_bps: u64,
        slope2_bps: u64,
        slope3_bps: u64,
        reserve_factor_bps: u64,
        protocol_fee_bps: u64,
        min_borrow_rate_bps: u64,
        max_borrow_rate_bps: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "interest model market_id")?;
        let metadata_root =
            lending_market_payload_root("LENDING-INTEREST-MODEL-METADATA", metadata);
        let curve_id = lending_interest_curve_id(
            market_id,
            curve_kind,
            base_rate_bps,
            kink_utilization_bps,
            jump_utilization_bps,
            slope1_bps,
            slope2_bps,
            slope3_bps,
            reserve_factor_bps,
            protocol_fee_bps,
            min_borrow_rate_bps,
            max_borrow_rate_bps,
            created_at_height,
            &metadata_root,
        );
        let model = Self {
            curve_id,
            market_id: market_id.to_string(),
            curve_kind,
            base_rate_bps,
            kink_utilization_bps,
            jump_utilization_bps,
            slope1_bps,
            slope2_bps,
            slope3_bps,
            reserve_factor_bps,
            protocol_fee_bps,
            min_borrow_rate_bps,
            max_borrow_rate_bps,
            created_at_height,
            active: true,
            metadata_root,
        };
        model.validate()?;
        Ok(model)
    }

    pub fn validate(&self) -> LendingMarketResult<()> {
        validate_bps(
            "interest model kink_utilization_bps",
            self.kink_utilization_bps,
        )?;
        validate_bps(
            "interest model jump_utilization_bps",
            self.jump_utilization_bps,
        )?;
        validate_bps("interest model reserve_factor_bps", self.reserve_factor_bps)?;
        validate_bps("interest model protocol_fee_bps", self.protocol_fee_bps)?;
        if self.kink_utilization_bps > self.jump_utilization_bps {
            return Err("interest model kink exceeds jump utilization".to_string());
        }
        if self.min_borrow_rate_bps > self.max_borrow_rate_bps {
            return Err("interest model min borrow rate exceeds max".to_string());
        }
        Ok(())
    }

    pub fn borrow_rate_bps(&self, utilization_bps: u64) -> u64 {
        let util = utilization_bps.min(LENDING_MARKET_MAX_BPS);
        let raw = match self.curve_kind {
            InterestCurveKind::Stable => self
                .base_rate_bps
                .saturating_add(bps_mul_floor(self.slope1_bps, util)),
            InterestCurveKind::Kinked | InterestCurveKind::GovernanceControlled => {
                if util <= self.kink_utilization_bps {
                    self.base_rate_bps.saturating_add(mul_div_floor(
                        self.slope1_bps,
                        util,
                        self.kink_utilization_bps.max(1),
                    ))
                } else {
                    let first = self.base_rate_bps.saturating_add(self.slope1_bps);
                    let excess = util.saturating_sub(self.kink_utilization_bps);
                    let width = LENDING_MARKET_MAX_BPS.saturating_sub(self.kink_utilization_bps);
                    first.saturating_add(mul_div_floor(self.slope2_bps, excess, width.max(1)))
                }
            }
            InterestCurveKind::Jump => {
                if util <= self.kink_utilization_bps {
                    self.base_rate_bps.saturating_add(mul_div_floor(
                        self.slope1_bps,
                        util,
                        self.kink_utilization_bps.max(1),
                    ))
                } else if util <= self.jump_utilization_bps {
                    let first = self.base_rate_bps.saturating_add(self.slope1_bps);
                    let excess = util.saturating_sub(self.kink_utilization_bps);
                    let width = self
                        .jump_utilization_bps
                        .saturating_sub(self.kink_utilization_bps);
                    first.saturating_add(mul_div_floor(self.slope2_bps, excess, width.max(1)))
                } else {
                    let second = self
                        .base_rate_bps
                        .saturating_add(self.slope1_bps)
                        .saturating_add(self.slope2_bps);
                    let excess = util.saturating_sub(self.jump_utilization_bps);
                    let width = LENDING_MARKET_MAX_BPS.saturating_sub(self.jump_utilization_bps);
                    second.saturating_add(mul_div_floor(self.slope3_bps, excess, width.max(1)))
                }
            }
        };
        raw.max(self.min_borrow_rate_bps)
            .min(self.max_borrow_rate_bps)
    }

    pub fn supply_rate_bps(&self, utilization_bps: u64) -> u64 {
        let borrow_rate = self.borrow_rate_bps(utilization_bps);
        let lender_share_bps = LENDING_MARKET_MAX_BPS.saturating_sub(self.reserve_factor_bps);
        bps_mul_floor(
            bps_mul_floor(borrow_rate, utilization_bps),
            lender_share_bps,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_interest_rate_model",
            "chain_id": CHAIN_ID,
            "curve_id": self.curve_id,
            "market_id": self.market_id,
            "curve_kind": self.curve_kind.as_str(),
            "base_rate_bps": self.base_rate_bps,
            "kink_utilization_bps": self.kink_utilization_bps,
            "jump_utilization_bps": self.jump_utilization_bps,
            "slope1_bps": self.slope1_bps,
            "slope2_bps": self.slope2_bps,
            "slope3_bps": self.slope3_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "min_borrow_rate_bps": self.min_borrow_rate_bps,
            "max_borrow_rate_bps": self.max_borrow_rate_bps,
            "created_at_height": self.created_at_height,
            "active": self.active,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn model_root(&self) -> String {
        lending_market_payload_root("LENDING-INTEREST-RATE-MODEL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingInterestIndexSnapshot {
    pub snapshot_id: String,
    pub market_id: String,
    pub height: u64,
    pub utilization_bps: u64,
    pub supply_index: u64,
    pub borrow_index: u64,
    pub supply_rate_bps: u64,
    pub borrow_rate_bps: u64,
    pub reserve_factor_bps: u64,
    pub total_supplied_units: u64,
    pub total_borrowed_principal_units: u64,
    pub total_borrowed_scaled_units: u64,
    pub reserve_units: u64,
    pub protocol_fee_units: u64,
    pub accrued_interest_units: u64,
    pub reserve_accrual_units: u64,
    pub protocol_fee_accrual_units: u64,
    pub previous_snapshot_id: String,
    pub metadata_root: String,
}

impl LendingInterestIndexSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market: &LendingCollateralMarket,
        supply_rate_bps: u64,
        borrow_rate_bps: u64,
        reserve_factor_bps: u64,
        accrued_interest_units: u64,
        reserve_accrual_units: u64,
        protocol_fee_accrual_units: u64,
        height: u64,
        previous_snapshot_id: &str,
        metadata: &Value,
    ) -> Self {
        let metadata_root =
            lending_market_payload_root("LENDING-INDEX-SNAPSHOT-METADATA", metadata);
        let snapshot_id = lending_interest_index_snapshot_id(
            &market.market_id,
            height,
            market.current_supply_index,
            market.current_borrow_index,
            market.total_supplied_units,
            market.total_borrowed_principal_units,
            previous_snapshot_id,
            &metadata_root,
        );
        Self {
            snapshot_id,
            market_id: market.market_id.clone(),
            height,
            utilization_bps: market.utilization_bps(),
            supply_index: market.current_supply_index,
            borrow_index: market.current_borrow_index,
            supply_rate_bps,
            borrow_rate_bps,
            reserve_factor_bps,
            total_supplied_units: market.total_supplied_units,
            total_borrowed_principal_units: market.total_borrowed_principal_units,
            total_borrowed_scaled_units: market.total_borrowed_scaled_units,
            reserve_units: market.reserve_units,
            protocol_fee_units: market.protocol_fee_units,
            accrued_interest_units,
            reserve_accrual_units,
            protocol_fee_accrual_units,
            previous_snapshot_id: previous_snapshot_id.to_string(),
            metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_interest_index_snapshot",
            "chain_id": CHAIN_ID,
            "snapshot_id": self.snapshot_id,
            "market_id": self.market_id,
            "height": self.height,
            "utilization_bps": self.utilization_bps,
            "supply_index": self.supply_index,
            "borrow_index": self.borrow_index,
            "supply_rate_bps": self.supply_rate_bps,
            "borrow_rate_bps": self.borrow_rate_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "total_supplied_units": self.total_supplied_units,
            "total_borrowed_principal_units": self.total_borrowed_principal_units,
            "total_borrowed_scaled_units": self.total_borrowed_scaled_units,
            "reserve_units": self.reserve_units,
            "protocol_fee_units": self.protocol_fee_units,
            "accrued_interest_units": self.accrued_interest_units,
            "reserve_accrual_units": self.reserve_accrual_units,
            "protocol_fee_accrual_units": self.protocol_fee_accrual_units,
            "previous_snapshot_id": self.previous_snapshot_id,
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
    pub encrypted_position_root: String,
    pub stealth_address_root: String,
    pub proof_system: String,
    pub verification_key_root: String,
    pub public_input_root: String,
    pub quantum_auth_root: String,
    pub risk_tier: LendingRiskTier,
    pub visibility: BorrowVisibility,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
    pub metadata_root: String,
}

impl PrivateBorrowerCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        borrower_commitment: &str,
        spend_nullifier_hash: &str,
        view_tag_root: &str,
        encrypted_position_root: &str,
        stealth_address_root: &str,
        proof_system: &str,
        verification_key_root: &str,
        risk_tier: LendingRiskTier,
        visibility: BorrowVisibility,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "borrower commitment market_id")?;
        ensure_non_empty(borrower_commitment, "borrower commitment")?;
        ensure_non_empty(spend_nullifier_hash, "borrower commitment nullifier")?;
        ensure_non_empty(proof_system, "borrower commitment proof_system")?;
        ensure_non_empty(
            verification_key_root,
            "borrower commitment verification_key_root",
        )?;
        let metadata_root =
            lending_market_payload_root("LENDING-BORROWER-COMMITMENT-METADATA", metadata);
        let public_inputs = json!({
            "market_id": market_id,
            "borrower_commitment": borrower_commitment,
            "spend_nullifier_hash": spend_nullifier_hash,
            "view_tag_root": view_tag_root,
            "encrypted_position_root": encrypted_position_root,
            "stealth_address_root": stealth_address_root,
            "risk_tier": risk_tier.as_str(),
            "visibility": visibility.as_str(),
            "created_at_height": created_at_height,
            "expires_at_height": created_at_height.saturating_add(ttl_blocks),
        });
        let public_input_root =
            lending_market_payload_root("LENDING-PRIVATE-BORROW-PUBLIC-INPUT", &public_inputs);
        let quantum_auth_root = lending_market_payload_root(
            "LENDING-PRIVATE-BORROW-PQ-AUTH",
            &json!({
                "proof_system": proof_system,
                "verification_key_root": verification_key_root,
                "public_input_root": public_input_root,
                "nonce": nonce,
            }),
        );
        let commitment_id = private_borrower_commitment_id(
            market_id,
            borrower_commitment,
            spend_nullifier_hash,
            &public_input_root,
            &quantum_auth_root,
            created_at_height,
            nonce,
            &metadata_root,
        );
        Ok(Self {
            commitment_id,
            market_id: market_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            spend_nullifier_hash: spend_nullifier_hash.to_string(),
            view_tag_root: view_tag_root.to_string(),
            encrypted_position_root: encrypted_position_root.to_string(),
            stealth_address_root: stealth_address_root.to_string(),
            proof_system: proof_system.to_string(),
            verification_key_root: verification_key_root.to_string(),
            public_input_root,
            quantum_auth_root,
            risk_tier,
            visibility,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            nonce,
            status: LENDING_MARKET_STATUS_OPEN.to_string(),
            metadata_root,
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_borrower_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "spend_nullifier_hash": self.spend_nullifier_hash,
            "view_tag_root": self.view_tag_root,
            "encrypted_position_root": self.encrypted_position_root,
            "stealth_address_root": self.stealth_address_root,
            "proof_system": self.proof_system,
            "verification_key_root": self.verification_key_root,
            "public_input_root": self.public_input_root,
            "quantum_auth_root": self.quantum_auth_root,
            "risk_tier": self.risk_tier.as_str(),
            "visibility": self.visibility.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingSupplyPosition {
    pub position_id: String,
    pub market_id: String,
    pub supplier_commitment: String,
    pub asset_id: String,
    pub supplied_units: u64,
    pub scaled_supply_units: u64,
    pub supply_index_snapshot: u64,
    pub opened_height: u64,
    pub last_update_height: u64,
    pub unlock_height: u64,
    pub reusable_collateral: bool,
    pub privacy_commitment_id: String,
    pub status: String,
    pub metadata_root: String,
}

impl LendingSupplyPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        supplier_commitment: &str,
        asset_id: &str,
        supplied_units: u64,
        current_supply_index: u64,
        opened_height: u64,
        unlock_height: u64,
        reusable_collateral: bool,
        privacy_commitment_id: &str,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "supply position market_id")?;
        ensure_non_empty(supplier_commitment, "supply position supplier_commitment")?;
        ensure_non_empty(asset_id, "supply position asset_id")?;
        if supplied_units == 0 {
            return Err("supply position supplied units must be positive".to_string());
        }
        if current_supply_index == 0 {
            return Err("supply position current supply index must be positive".to_string());
        }
        let metadata_root =
            lending_market_payload_root("LENDING-SUPPLY-POSITION-METADATA", metadata);
        let scaled_supply_units = mul_div_floor(
            supplied_units,
            LENDING_MARKET_INDEX_SCALE,
            current_supply_index,
        );
        let position_id = lending_supply_position_id(
            market_id,
            supplier_commitment,
            asset_id,
            supplied_units,
            scaled_supply_units,
            opened_height,
            nonce,
            &metadata_root,
        );
        Ok(Self {
            position_id,
            market_id: market_id.to_string(),
            supplier_commitment: supplier_commitment.to_string(),
            asset_id: asset_id.to_string(),
            supplied_units,
            scaled_supply_units,
            supply_index_snapshot: current_supply_index,
            opened_height,
            last_update_height: opened_height,
            unlock_height,
            reusable_collateral,
            privacy_commitment_id: privacy_commitment_id.to_string(),
            status: LENDING_MARKET_STATUS_ACTIVE.to_string(),
            metadata_root,
        })
    }

    pub fn current_supply_units(&self, current_supply_index: u64) -> u64 {
        mul_div_floor(
            self.scaled_supply_units,
            current_supply_index,
            LENDING_MARKET_INDEX_SCALE,
        )
    }

    pub fn accrued_supply_units(&self, current_supply_index: u64) -> u64 {
        self.current_supply_units(current_supply_index)
            .saturating_sub(self.supplied_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_supply_position",
            "chain_id": CHAIN_ID,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "supplier_commitment": self.supplier_commitment,
            "asset_id": self.asset_id,
            "supplied_units": self.supplied_units,
            "scaled_supply_units": self.scaled_supply_units,
            "supply_index_snapshot": self.supply_index_snapshot,
            "opened_height": self.opened_height,
            "last_update_height": self.last_update_height,
            "unlock_height": self.unlock_height,
            "reusable_collateral": self.reusable_collateral,
            "privacy_commitment_id": self.privacy_commitment_id,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn position_root(&self) -> String {
        lending_market_payload_root("LENDING-SUPPLY-POSITION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingBorrowPosition {
    pub position_id: String,
    pub market_id: String,
    pub borrower_commitment: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_units: u64,
    pub collateral_value_units: u64,
    pub debt_principal_units: u64,
    pub scaled_debt_units: u64,
    pub borrow_index_snapshot: u64,
    pub origination_fee_units: u64,
    pub reserve_contribution_units: u64,
    pub health_bucket: HealthFactorBucket,
    pub health_factor_bps: u64,
    pub risk_tier: LendingRiskTier,
    pub private_commitment_id: String,
    pub oracle_guard_id: String,
    pub opened_height: u64,
    pub last_update_height: u64,
    pub maturity_height: u64,
    pub nonce: u64,
    pub status: String,
    pub metadata_root: String,
}

impl LendingBorrowPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        borrower_commitment: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        collateral_units: u64,
        collateral_value_units: u64,
        debt_principal_units: u64,
        current_borrow_index: u64,
        origination_fee_units: u64,
        reserve_contribution_units: u64,
        liquidation_threshold_bps: u64,
        risk_tier: LendingRiskTier,
        private_commitment_id: &str,
        oracle_guard_id: &str,
        opened_height: u64,
        maturity_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "borrow position market_id")?;
        ensure_non_empty(borrower_commitment, "borrow position borrower_commitment")?;
        ensure_non_empty(collateral_asset_id, "borrow position collateral_asset_id")?;
        ensure_non_empty(debt_asset_id, "borrow position debt_asset_id")?;
        if collateral_units == 0 || collateral_value_units == 0 {
            return Err("borrow position collateral must be positive".to_string());
        }
        if debt_principal_units == 0 {
            return Err("borrow position debt principal must be positive".to_string());
        }
        if current_borrow_index == 0 {
            return Err("borrow position current borrow index must be positive".to_string());
        }
        let metadata_root =
            lending_market_payload_root("LENDING-BORROW-POSITION-METADATA", metadata);
        let scaled_debt_units = mul_div_floor(
            debt_principal_units,
            LENDING_MARKET_INDEX_SCALE,
            current_borrow_index,
        );
        let liquidation_value_units =
            bps_mul_floor(collateral_value_units, liquidation_threshold_bps);
        let health_factor_bps = health_factor_bps(liquidation_value_units, debt_principal_units);
        let health_bucket = HealthFactorBucket::from_health_factor_bps(health_factor_bps);
        let position_id = lending_borrow_position_id(
            market_id,
            borrower_commitment,
            collateral_asset_id,
            debt_asset_id,
            collateral_units,
            debt_principal_units,
            scaled_debt_units,
            opened_height,
            nonce,
            &metadata_root,
        );
        Ok(Self {
            position_id,
            market_id: market_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            collateral_units,
            collateral_value_units,
            debt_principal_units,
            scaled_debt_units,
            borrow_index_snapshot: current_borrow_index,
            origination_fee_units,
            reserve_contribution_units,
            health_bucket,
            health_factor_bps,
            risk_tier,
            private_commitment_id: private_commitment_id.to_string(),
            oracle_guard_id: oracle_guard_id.to_string(),
            opened_height,
            last_update_height: opened_height,
            maturity_height,
            nonce,
            status: LENDING_MARKET_STATUS_ACTIVE.to_string(),
            metadata_root,
        })
    }

    pub fn current_debt_units(&self, current_borrow_index: u64) -> u64 {
        mul_div_ceil(
            self.scaled_debt_units,
            current_borrow_index,
            LENDING_MARKET_INDEX_SCALE,
        )
    }

    pub fn interest_accrued_units(&self, current_borrow_index: u64) -> u64 {
        self.current_debt_units(current_borrow_index)
            .saturating_sub(self.debt_principal_units)
    }

    pub fn refresh_health(
        &mut self,
        current_debt_units: u64,
        liquidation_threshold_bps: u64,
        height: u64,
    ) {
        let liquidation_value_units =
            bps_mul_floor(self.collateral_value_units, liquidation_threshold_bps);
        self.health_factor_bps = health_factor_bps(liquidation_value_units, current_debt_units);
        self.health_bucket = HealthFactorBucket::from_health_factor_bps(self.health_factor_bps);
        self.last_update_height = height;
    }

    pub fn max_close_units(&self, current_debt_units: u64, close_factor_bps: u64) -> u64 {
        bps_mul_ceil(current_debt_units, close_factor_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_borrow_position",
            "chain_id": CHAIN_ID,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_units": self.collateral_units,
            "collateral_value_units": self.collateral_value_units,
            "debt_principal_units": self.debt_principal_units,
            "scaled_debt_units": self.scaled_debt_units,
            "borrow_index_snapshot": self.borrow_index_snapshot,
            "origination_fee_units": self.origination_fee_units,
            "reserve_contribution_units": self.reserve_contribution_units,
            "health_bucket": self.health_bucket.as_str(),
            "health_factor_bps": self.health_factor_bps,
            "risk_tier": self.risk_tier.as_str(),
            "private_commitment_id": self.private_commitment_id,
            "oracle_guard_id": self.oracle_guard_id,
            "opened_height": self.opened_height,
            "last_update_height": self.last_update_height,
            "maturity_height": self.maturity_height,
            "nonce": self.nonce,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn position_root(&self) -> String {
        lending_market_payload_root("LENDING-BORROW-POSITION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingOracleGuard {
    pub guard_id: String,
    pub market_id: String,
    pub oracle_feed_id: String,
    pub reference_price: u64,
    pub spot_price: u64,
    pub twap_price: u64,
    pub median_price: u64,
    pub max_deviation_bps: u64,
    pub max_twap_deviation_bps: u64,
    pub max_staleness_blocks: u64,
    pub observed_at_height: u64,
    pub created_at_height: u64,
    pub action: OracleGuardAction,
    pub source_root: String,
    pub reason_root: String,
    pub metadata_root: String,
}

impl LendingOracleGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        oracle_feed_id: &str,
        reference_price: u64,
        spot_price: u64,
        twap_price: u64,
        median_price: u64,
        max_deviation_bps: u64,
        max_twap_deviation_bps: u64,
        max_staleness_blocks: u64,
        observed_at_height: u64,
        created_at_height: u64,
        source: &Value,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "oracle guard market_id")?;
        ensure_non_empty(oracle_feed_id, "oracle guard feed_id")?;
        if reference_price == 0 || spot_price == 0 || twap_price == 0 || median_price == 0 {
            return Err("oracle guard prices must be positive".to_string());
        }
        validate_bps("oracle guard max_deviation_bps", max_deviation_bps)?;
        validate_bps(
            "oracle guard max_twap_deviation_bps",
            max_twap_deviation_bps,
        )?;
        let source_root = lending_market_payload_root("LENDING-ORACLE-SOURCE", source);
        let metadata_root = lending_market_payload_root("LENDING-ORACLE-GUARD-METADATA", metadata);
        let spot_deviation = deviation_bps(spot_price, reference_price);
        let median_deviation = deviation_bps(median_price, reference_price);
        let twap_deviation = deviation_bps(twap_price, reference_price);
        let worst_deviation = spot_deviation.max(median_deviation);
        let action = if worst_deviation > max_deviation_bps.saturating_mul(2)
            || twap_deviation > max_twap_deviation_bps.saturating_mul(2)
        {
            OracleGuardAction::FreezeMarket
        } else if worst_deviation > max_deviation_bps {
            OracleGuardAction::FreezeBorrow
        } else if twap_deviation > max_twap_deviation_bps {
            OracleGuardAction::BlockLiquidation
        } else if worst_deviation > max_deviation_bps / 2
            || twap_deviation > max_twap_deviation_bps / 2
        {
            OracleGuardAction::Watch
        } else {
            OracleGuardAction::Allow
        };
        let reason_root = lending_market_payload_root(
            "LENDING-ORACLE-GUARD-REASON",
            &json!({
                "spot_deviation_bps": spot_deviation,
                "median_deviation_bps": median_deviation,
                "twap_deviation_bps": twap_deviation,
                "action": action.as_str(),
            }),
        );
        let guard_id = lending_oracle_guard_id(
            market_id,
            oracle_feed_id,
            reference_price,
            spot_price,
            twap_price,
            median_price,
            observed_at_height,
            created_at_height,
            &source_root,
            &metadata_root,
        );
        Ok(Self {
            guard_id,
            market_id: market_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            reference_price,
            spot_price,
            twap_price,
            median_price,
            max_deviation_bps,
            max_twap_deviation_bps,
            max_staleness_blocks,
            observed_at_height,
            created_at_height,
            action,
            source_root,
            reason_root,
            metadata_root,
        })
    }

    pub fn is_stale_at(&self, height: u64) -> bool {
        height.saturating_sub(self.observed_at_height) > self.max_staleness_blocks
    }

    pub fn allows_borrow_at(&self, height: u64) -> bool {
        !self.is_stale_at(height) && self.action.allows_borrow()
    }

    pub fn allows_liquidation_at(&self, height: u64) -> bool {
        !self.is_stale_at(height) && self.action.allows_liquidation()
    }

    pub fn worst_deviation_bps(&self) -> u64 {
        deviation_bps(self.spot_price, self.reference_price)
            .max(deviation_bps(self.median_price, self.reference_price))
            .max(deviation_bps(self.twap_price, self.reference_price))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_oracle_guard",
            "chain_id": CHAIN_ID,
            "guard_id": self.guard_id,
            "market_id": self.market_id,
            "oracle_feed_id": self.oracle_feed_id,
            "reference_price": self.reference_price,
            "spot_price": self.spot_price,
            "twap_price": self.twap_price,
            "median_price": self.median_price,
            "max_deviation_bps": self.max_deviation_bps,
            "max_twap_deviation_bps": self.max_twap_deviation_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "observed_at_height": self.observed_at_height,
            "created_at_height": self.created_at_height,
            "action": self.action.as_str(),
            "allows_borrow": self.action.allows_borrow(),
            "allows_liquidation": self.action.allows_liquidation(),
            "worst_deviation_bps": self.worst_deviation_bps(),
            "source_root": self.source_root,
            "reason_root": self.reason_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingHealthBucketRecord {
    pub bucket_id: String,
    pub market_id: String,
    pub bucket: HealthFactorBucket,
    pub bucket_floor_bps: u64,
    pub bucket_ceiling_bps: u64,
    pub position_count: u64,
    pub debt_units: u64,
    pub collateral_value_units: u64,
    pub commitment_root: String,
    pub snapshot_height: u64,
    pub expires_at_height: u64,
    pub proof_system: String,
    pub public_input_root: String,
    pub metadata_root: String,
}

impl LendingHealthBucketRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        bucket: HealthFactorBucket,
        position_count: u64,
        debt_units: u64,
        collateral_value_units: u64,
        position_commitments: &[String],
        snapshot_height: u64,
        ttl_blocks: u64,
        proof_system: &str,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "health bucket market_id")?;
        ensure_non_empty(proof_system, "health bucket proof_system")?;
        let commitment_root = lending_market_string_set_root(
            "LENDING-HEALTH-BUCKET-COMMITMENTS",
            position_commitments,
        );
        let public_input_root = lending_market_payload_root(
            "LENDING-HEALTH-BUCKET-PUBLIC-INPUT",
            &json!({
                "market_id": market_id,
                "bucket": bucket.as_str(),
                "position_count": position_count,
                "debt_units": debt_units,
                "collateral_value_units": collateral_value_units,
                "commitment_root": commitment_root,
                "snapshot_height": snapshot_height,
                "expires_at_height": snapshot_height.saturating_add(ttl_blocks),
            }),
        );
        let metadata_root = lending_market_payload_root("LENDING-HEALTH-BUCKET-METADATA", metadata);
        let bucket_id = lending_health_bucket_id(
            market_id,
            bucket,
            snapshot_height,
            position_count,
            debt_units,
            &commitment_root,
            &public_input_root,
            &metadata_root,
        );
        Ok(Self {
            bucket_id,
            market_id: market_id.to_string(),
            bucket,
            bucket_floor_bps: bucket.floor_bps(),
            bucket_ceiling_bps: bucket.ceiling_bps(),
            position_count,
            debt_units,
            collateral_value_units,
            commitment_root,
            snapshot_height,
            expires_at_height: snapshot_height.saturating_add(ttl_blocks),
            proof_system: proof_system.to_string(),
            public_input_root,
            metadata_root,
        })
    }

    pub fn is_expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_health_bucket_record",
            "chain_id": CHAIN_ID,
            "bucket_id": self.bucket_id,
            "market_id": self.market_id,
            "bucket": self.bucket.as_str(),
            "bucket_floor_bps": self.bucket_floor_bps,
            "bucket_ceiling_bps": self.bucket_ceiling_bps,
            "position_count": self.position_count,
            "debt_units": self.debt_units,
            "collateral_value_units": self.collateral_value_units,
            "commitment_root": self.commitment_root,
            "snapshot_height": self.snapshot_height,
            "expires_at_height": self.expires_at_height,
            "proof_system": self.proof_system,
            "public_input_root": self.public_input_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingLiquidationAuction {
    pub auction_id: String,
    pub market_id: String,
    pub position_id: String,
    pub borrower_commitment: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_units: u64,
    pub debt_to_cover_units: u64,
    pub start_price_units: u64,
    pub floor_price_units: u64,
    pub current_price_units: u64,
    pub liquidation_bonus_bps: u64,
    pub protocol_fee_bps: u64,
    pub keeper_reward_units: u64,
    pub sponsor_id: String,
    pub oracle_guard_id: String,
    pub health_bucket_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub settlement_height: u64,
    pub status: LiquidationAuctionStatus,
    pub metadata_root: String,
}

impl LendingLiquidationAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        position_id: &str,
        borrower_commitment: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        collateral_units: u64,
        debt_to_cover_units: u64,
        start_price_units: u64,
        floor_price_units: u64,
        liquidation_bonus_bps: u64,
        protocol_fee_bps: u64,
        keeper_reward_units: u64,
        sponsor_id: &str,
        oracle_guard_id: &str,
        health_bucket_id: &str,
        start_height: u64,
        ttl_blocks: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "liquidation auction market_id")?;
        ensure_non_empty(position_id, "liquidation auction position_id")?;
        ensure_non_empty(
            borrower_commitment,
            "liquidation auction borrower_commitment",
        )?;
        ensure_non_empty(
            collateral_asset_id,
            "liquidation auction collateral_asset_id",
        )?;
        ensure_non_empty(debt_asset_id, "liquidation auction debt_asset_id")?;
        if collateral_units == 0 || debt_to_cover_units == 0 {
            return Err("liquidation auction collateral and debt must be positive".to_string());
        }
        if floor_price_units > start_price_units {
            return Err("liquidation auction floor price exceeds start price".to_string());
        }
        validate_bps(
            "liquidation auction liquidation_bonus_bps",
            liquidation_bonus_bps,
        )?;
        validate_bps("liquidation auction protocol_fee_bps", protocol_fee_bps)?;
        let metadata_root =
            lending_market_payload_root("LENDING-LIQUIDATION-AUCTION-METADATA", metadata);
        let auction_id = lending_liquidation_auction_id(
            market_id,
            position_id,
            borrower_commitment,
            collateral_units,
            debt_to_cover_units,
            start_price_units,
            floor_price_units,
            start_height,
            ttl_blocks,
            &metadata_root,
        );
        Ok(Self {
            auction_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            collateral_units,
            debt_to_cover_units,
            start_price_units,
            floor_price_units,
            current_price_units: start_price_units,
            liquidation_bonus_bps,
            protocol_fee_bps,
            keeper_reward_units,
            sponsor_id: sponsor_id.to_string(),
            oracle_guard_id: oracle_guard_id.to_string(),
            health_bucket_id: health_bucket_id.to_string(),
            start_height,
            end_height: start_height.saturating_add(ttl_blocks),
            settlement_height: 0,
            status: LiquidationAuctionStatus::Open,
            metadata_root,
        })
    }

    pub fn accepts_height(&self, height: u64) -> bool {
        self.status == LiquidationAuctionStatus::Open
            && height >= self.start_height
            && height <= self.end_height
    }

    pub fn price_at_height(&self, height: u64) -> u64 {
        if height <= self.start_height {
            return self.start_price_units;
        }
        if height >= self.end_height {
            return self.floor_price_units;
        }
        let elapsed = height.saturating_sub(self.start_height);
        let duration = self.end_height.saturating_sub(self.start_height).max(1);
        let discount = self
            .start_price_units
            .saturating_sub(self.floor_price_units);
        self.start_price_units
            .saturating_sub(mul_div_floor(discount, elapsed, duration))
            .max(self.floor_price_units)
    }

    pub fn refresh_price(&mut self, height: u64) {
        self.current_price_units = self.price_at_height(height);
        if height > self.end_height && self.status == LiquidationAuctionStatus::Open {
            self.status = LiquidationAuctionStatus::Expired;
        }
    }

    pub fn collateral_claim_units(&self, repay_units: u64) -> u64 {
        let base = mul_div_floor(
            repay_units,
            LENDING_MARKET_PRICE_SCALE,
            self.current_price_units.max(1),
        );
        let bonus = bps_mul_floor(base, self.liquidation_bonus_bps);
        base.saturating_add(bonus).min(self.collateral_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_liquidation_auction",
            "chain_id": CHAIN_ID,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_units": self.collateral_units,
            "debt_to_cover_units": self.debt_to_cover_units,
            "start_price_units": self.start_price_units,
            "floor_price_units": self.floor_price_units,
            "current_price_units": self.current_price_units,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "keeper_reward_units": self.keeper_reward_units,
            "sponsor_id": self.sponsor_id,
            "oracle_guard_id": self.oracle_guard_id,
            "health_bucket_id": self.health_bucket_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "settlement_height": self.settlement_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingLiquidationBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub repay_units: u64,
    pub max_collateral_price_units: u64,
    pub requested_sponsorship_units: u64,
    pub bid_score_units: u64,
    pub submitted_height: u64,
    pub status: String,
    pub metadata_root: String,
}

impl LendingLiquidationBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        bidder_commitment: &str,
        repay_units: u64,
        max_collateral_price_units: u64,
        requested_sponsorship_units: u64,
        submitted_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(auction_id, "liquidation bid auction_id")?;
        ensure_non_empty(bidder_commitment, "liquidation bid bidder_commitment")?;
        if repay_units == 0 {
            return Err("liquidation bid repay_units must be positive".to_string());
        }
        let metadata_root =
            lending_market_payload_root("LENDING-LIQUIDATION-BID-METADATA", metadata);
        let bid_score_units = repay_units
            .saturating_mul(10)
            .saturating_sub(requested_sponsorship_units);
        let bid_id = lending_liquidation_bid_id(
            auction_id,
            bidder_commitment,
            repay_units,
            max_collateral_price_units,
            requested_sponsorship_units,
            submitted_height,
            nonce,
            &metadata_root,
        );
        Ok(Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            repay_units,
            max_collateral_price_units,
            requested_sponsorship_units,
            bid_score_units,
            submitted_height,
            status: LENDING_MARKET_STATUS_OPEN.to_string(),
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_liquidation_bid",
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "repay_units": self.repay_units,
            "max_collateral_price_units": self.max_collateral_price_units,
            "requested_sponsorship_units": self.requested_sponsorship_units,
            "bid_score_units": self.bid_score_units,
            "submitted_height": self.submitted_height,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeLiquidationSponsorship {
    pub sponsorship_id: String,
    pub auction_id: String,
    pub market_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub applied_fee_units: u64,
    pub max_rebate_bps: u64,
    pub keeper_reward_boost_units: u64,
    pub low_fee_lane: String,
    pub bond_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
    pub metadata_root: String,
}

impl LowFeeLiquidationSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        market_id: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        reserved_fee_units: u64,
        max_rebate_bps: u64,
        keeper_reward_boost_units: u64,
        low_fee_lane: &str,
        bond_id: &str,
        created_at_height: u64,
        ttl_blocks: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(auction_id, "sponsorship auction_id")?;
        ensure_non_empty(market_id, "sponsorship market_id")?;
        ensure_non_empty(sponsor_commitment, "sponsorship sponsor_commitment")?;
        ensure_non_empty(fee_asset_id, "sponsorship fee_asset_id")?;
        ensure_non_empty(low_fee_lane, "sponsorship low_fee_lane")?;
        validate_bps("sponsorship max_rebate_bps", max_rebate_bps)?;
        let metadata_root = lending_market_payload_root("LENDING-SPONSORSHIP-METADATA", metadata);
        let sponsorship_id = lending_sponsorship_id(
            auction_id,
            market_id,
            sponsor_commitment,
            fee_asset_id,
            reserved_fee_units,
            max_rebate_bps,
            created_at_height,
            &metadata_root,
        );
        Ok(Self {
            sponsorship_id,
            auction_id: auction_id.to_string(),
            market_id: market_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            reserved_fee_units,
            applied_fee_units: 0,
            max_rebate_bps,
            keeper_reward_boost_units,
            low_fee_lane: low_fee_lane.to_string(),
            bond_id: bond_id.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: SponsorshipStatus::Reserved,
            metadata_root,
        })
    }

    pub fn is_active(&self, height: u64) -> bool {
        self.status == SponsorshipStatus::Reserved && height <= self.expires_at_height
    }

    pub fn available_fee_units(&self) -> u64 {
        self.reserved_fee_units
            .saturating_sub(self.applied_fee_units)
    }

    pub fn apply_units(&mut self, requested_units: u64) -> u64 {
        let applied = requested_units.min(self.available_fee_units());
        self.applied_fee_units = self.applied_fee_units.saturating_add(applied);
        if self.available_fee_units() == 0 {
            self.status = SponsorshipStatus::Applied;
        }
        applied
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_liquidation_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "applied_fee_units": self.applied_fee_units,
            "available_fee_units": self.available_fee_units(),
            "max_rebate_bps": self.max_rebate_bps,
            "keeper_reward_boost_units": self.keeper_reward_boost_units,
            "low_fee_lane": self.low_fee_lane,
            "bond_id": self.bond_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingReserveFund {
    pub fund_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub target_units: u64,
    pub available_units: u64,
    pub pending_inflow_units: u64,
    pub pending_outflow_units: u64,
    pub total_contributed_units: u64,
    pub total_withdrawn_units: u64,
    pub coverage_floor_bps: u64,
    pub status: ReserveFundStatus,
    pub controller_commitment: String,
    pub last_update_height: u64,
    pub metadata_root: String,
}

impl LendingReserveFund {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        asset_id: &str,
        target_units: u64,
        initial_units: u64,
        coverage_floor_bps: u64,
        controller_commitment: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "reserve fund market_id")?;
        ensure_non_empty(asset_id, "reserve fund asset_id")?;
        ensure_non_empty(controller_commitment, "reserve fund controller_commitment")?;
        validate_bps("reserve fund coverage_floor_bps", coverage_floor_bps)?;
        let metadata_root = lending_market_payload_root("LENDING-RESERVE-FUND-METADATA", metadata);
        let fund_id = lending_reserve_fund_id(
            market_id,
            asset_id,
            target_units,
            initial_units,
            controller_commitment,
            created_at_height,
            &metadata_root,
        );
        Ok(Self {
            fund_id,
            market_id: market_id.to_string(),
            asset_id: asset_id.to_string(),
            target_units,
            available_units: initial_units,
            pending_inflow_units: 0,
            pending_outflow_units: 0,
            total_contributed_units: initial_units,
            total_withdrawn_units: 0,
            coverage_floor_bps,
            status: if initial_units == 0 {
                ReserveFundStatus::Exhausted
            } else {
                ReserveFundStatus::Active
            },
            controller_commitment: controller_commitment.to_string(),
            last_update_height: created_at_height,
            metadata_root,
        })
    }

    pub fn available_after_pending_units(&self) -> u64 {
        self.available_units
            .saturating_add(self.pending_inflow_units)
            .saturating_sub(self.pending_outflow_units)
    }

    pub fn coverage_bps(&self, liability_units: u64) -> u64 {
        ratio_bps(self.available_after_pending_units(), liability_units.max(1))
    }

    pub fn contribute(&mut self, units: u64, height: u64) {
        self.available_units = self.available_units.saturating_add(units);
        self.total_contributed_units = self.total_contributed_units.saturating_add(units);
        self.last_update_height = height;
        if self.available_units > 0 && self.status == ReserveFundStatus::Exhausted {
            self.status = ReserveFundStatus::Active;
        }
    }

    pub fn withdraw(&mut self, units: u64, height: u64) -> u64 {
        let withdrawn = units.min(self.available_units);
        self.available_units = self.available_units.saturating_sub(withdrawn);
        self.total_withdrawn_units = self.total_withdrawn_units.saturating_add(withdrawn);
        self.last_update_height = height;
        if self.available_units == 0 {
            self.status = ReserveFundStatus::Exhausted;
        }
        withdrawn
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_reserve_fund",
            "chain_id": CHAIN_ID,
            "fund_id": self.fund_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "target_units": self.target_units,
            "available_units": self.available_units,
            "pending_inflow_units": self.pending_inflow_units,
            "pending_outflow_units": self.pending_outflow_units,
            "available_after_pending_units": self.available_after_pending_units(),
            "total_contributed_units": self.total_contributed_units,
            "total_withdrawn_units": self.total_withdrawn_units,
            "coverage_floor_bps": self.coverage_floor_bps,
            "status": self.status.as_str(),
            "controller_commitment": self.controller_commitment,
            "last_update_height": self.last_update_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingBadDebtRecord {
    pub bad_debt_id: String,
    pub market_id: String,
    pub position_id: String,
    pub borrower_commitment: String,
    pub debt_asset_id: String,
    pub principal_units: u64,
    pub interest_units: u64,
    pub penalty_units: u64,
    pub recovered_units: u64,
    pub reserve_covered_units: u64,
    pub socialized_units: u64,
    pub discovered_at_height: u64,
    pub status: LossRecordStatus,
    pub oracle_guard_root: String,
    pub liquidation_auction_id: String,
    pub metadata_root: String,
}

impl LendingBadDebtRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        position_id: &str,
        borrower_commitment: &str,
        debt_asset_id: &str,
        principal_units: u64,
        interest_units: u64,
        penalty_units: u64,
        discovered_at_height: u64,
        oracle_guard_root: &str,
        liquidation_auction_id: &str,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "bad debt market_id")?;
        ensure_non_empty(position_id, "bad debt position_id")?;
        ensure_non_empty(borrower_commitment, "bad debt borrower_commitment")?;
        ensure_non_empty(debt_asset_id, "bad debt debt_asset_id")?;
        let metadata_root = lending_market_payload_root("LENDING-BAD-DEBT-METADATA", metadata);
        let bad_debt_id = lending_bad_debt_id(
            market_id,
            position_id,
            borrower_commitment,
            principal_units,
            interest_units,
            penalty_units,
            discovered_at_height,
            liquidation_auction_id,
            &metadata_root,
        );
        Ok(Self {
            bad_debt_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            principal_units,
            interest_units,
            penalty_units,
            recovered_units: 0,
            reserve_covered_units: 0,
            socialized_units: 0,
            discovered_at_height,
            status: LossRecordStatus::Pending,
            oracle_guard_root: oracle_guard_root.to_string(),
            liquidation_auction_id: liquidation_auction_id.to_string(),
            metadata_root,
        })
    }

    pub fn total_loss_units(&self) -> u64 {
        self.principal_units
            .saturating_add(self.interest_units)
            .saturating_add(self.penalty_units)
    }

    pub fn outstanding_units(&self) -> u64 {
        self.total_loss_units()
            .saturating_sub(self.recovered_units)
            .saturating_sub(self.reserve_covered_units)
            .saturating_sub(self.socialized_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_bad_debt_record",
            "chain_id": CHAIN_ID,
            "bad_debt_id": self.bad_debt_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "borrower_commitment": self.borrower_commitment,
            "debt_asset_id": self.debt_asset_id,
            "principal_units": self.principal_units,
            "interest_units": self.interest_units,
            "penalty_units": self.penalty_units,
            "total_loss_units": self.total_loss_units(),
            "recovered_units": self.recovered_units,
            "reserve_covered_units": self.reserve_covered_units,
            "socialized_units": self.socialized_units,
            "outstanding_units": self.outstanding_units(),
            "discovered_at_height": self.discovered_at_height,
            "status": self.status.as_str(),
            "oracle_guard_root": self.oracle_guard_root,
            "liquidation_auction_id": self.liquidation_auction_id,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingSocializedLossRecord {
    pub loss_id: String,
    pub market_id: String,
    pub debt_asset_id: String,
    pub bad_debt_id: String,
    pub loss_units: u64,
    pub per_supply_share_index_delta: u64,
    pub affected_supply_root: String,
    pub reserve_coverage_units: u64,
    pub insurance_coverage_units: u64,
    pub applied_height: u64,
    pub status: LossRecordStatus,
    pub metadata_root: String,
}

impl LendingSocializedLossRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        debt_asset_id: &str,
        bad_debt_id: &str,
        loss_units: u64,
        total_supply_scaled_units: u64,
        affected_supply_root: &str,
        reserve_coverage_units: u64,
        insurance_coverage_units: u64,
        applied_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "socialized loss market_id")?;
        ensure_non_empty(debt_asset_id, "socialized loss debt_asset_id")?;
        ensure_non_empty(bad_debt_id, "socialized loss bad_debt_id")?;
        if loss_units == 0 {
            return Err("socialized loss units must be positive".to_string());
        }
        let metadata_root =
            lending_market_payload_root("LENDING-SOCIALIZED-LOSS-METADATA", metadata);
        let per_supply_share_index_delta = mul_div_ceil(
            loss_units,
            LENDING_MARKET_INDEX_SCALE,
            total_supply_scaled_units.max(1),
        );
        let loss_id = lending_socialized_loss_id(
            market_id,
            debt_asset_id,
            bad_debt_id,
            loss_units,
            per_supply_share_index_delta,
            affected_supply_root,
            applied_height,
            &metadata_root,
        );
        Ok(Self {
            loss_id,
            market_id: market_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            bad_debt_id: bad_debt_id.to_string(),
            loss_units,
            per_supply_share_index_delta,
            affected_supply_root: affected_supply_root.to_string(),
            reserve_coverage_units,
            insurance_coverage_units,
            applied_height,
            status: LossRecordStatus::Socialized,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_socialized_loss_record",
            "chain_id": CHAIN_ID,
            "loss_id": self.loss_id,
            "market_id": self.market_id,
            "debt_asset_id": self.debt_asset_id,
            "bad_debt_id": self.bad_debt_id,
            "loss_units": self.loss_units,
            "per_supply_share_index_delta": self.per_supply_share_index_delta,
            "affected_supply_root": self.affected_supply_root,
            "reserve_coverage_units": self.reserve_coverage_units,
            "insurance_coverage_units": self.insurance_coverage_units,
            "applied_height": self.applied_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingProtocolFeeLedger {
    pub ledger_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub accrued_units: u64,
    pub collected_units: u64,
    pub swept_units: u64,
    pub waived_units: u64,
    pub last_update_height: u64,
    pub recipient_commitment: String,
    pub metadata_root: String,
}

impl LendingProtocolFeeLedger {
    pub fn new(
        market_id: &str,
        asset_id: &str,
        recipient_commitment: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "fee ledger market_id")?;
        ensure_non_empty(asset_id, "fee ledger asset_id")?;
        ensure_non_empty(recipient_commitment, "fee ledger recipient_commitment")?;
        let metadata_root = lending_market_payload_root("LENDING-FEE-LEDGER-METADATA", metadata);
        let ledger_id = lending_fee_ledger_id(
            market_id,
            asset_id,
            recipient_commitment,
            created_at_height,
            &metadata_root,
        );
        Ok(Self {
            ledger_id,
            market_id: market_id.to_string(),
            asset_id: asset_id.to_string(),
            accrued_units: 0,
            collected_units: 0,
            swept_units: 0,
            waived_units: 0,
            last_update_height: created_at_height,
            recipient_commitment: recipient_commitment.to_string(),
            metadata_root,
        })
    }

    pub fn pending_units(&self) -> u64 {
        self.accrued_units
            .saturating_sub(self.collected_units)
            .saturating_sub(self.swept_units)
            .saturating_sub(self.waived_units)
    }

    pub fn accrue(&mut self, units: u64, height: u64) {
        self.accrued_units = self.accrued_units.saturating_add(units);
        self.last_update_height = height;
    }

    pub fn collect(&mut self, units: u64, height: u64) -> u64 {
        let collected = units.min(self.pending_units());
        self.collected_units = self.collected_units.saturating_add(collected);
        self.last_update_height = height;
        collected
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_protocol_fee_ledger",
            "chain_id": CHAIN_ID,
            "ledger_id": self.ledger_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "accrued_units": self.accrued_units,
            "collected_units": self.collected_units,
            "swept_units": self.swept_units,
            "waived_units": self.waived_units,
            "pending_units": self.pending_units(),
            "last_update_height": self.last_update_height,
            "recipient_commitment": self.recipient_commitment,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingProtocolFeeAccrual {
    pub accrual_id: String,
    pub market_id: String,
    pub position_id: String,
    pub asset_id: String,
    pub event_kind: ProtocolFeeEventKind,
    pub gross_units: u64,
    pub reserve_units: u64,
    pub protocol_fee_units: u64,
    pub keeper_reward_units: u64,
    pub low_fee_rebate_units: u64,
    pub height: u64,
    pub ledger_id: String,
    pub metadata_root: String,
}

impl LendingProtocolFeeAccrual {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        position_id: &str,
        asset_id: &str,
        event_kind: ProtocolFeeEventKind,
        gross_units: u64,
        reserve_units: u64,
        protocol_fee_units: u64,
        keeper_reward_units: u64,
        low_fee_rebate_units: u64,
        height: u64,
        ledger_id: &str,
        metadata: &Value,
    ) -> LendingMarketResult<Self> {
        ensure_non_empty(market_id, "fee accrual market_id")?;
        ensure_non_empty(asset_id, "fee accrual asset_id")?;
        ensure_non_empty(ledger_id, "fee accrual ledger_id")?;
        let metadata_root = lending_market_payload_root("LENDING-FEE-ACCRUAL-METADATA", metadata);
        let accrual_id = lending_fee_accrual_id(
            market_id,
            position_id,
            asset_id,
            event_kind,
            gross_units,
            reserve_units,
            protocol_fee_units,
            keeper_reward_units,
            low_fee_rebate_units,
            height,
            ledger_id,
            &metadata_root,
        );
        Ok(Self {
            accrual_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            asset_id: asset_id.to_string(),
            event_kind,
            gross_units,
            reserve_units,
            protocol_fee_units,
            keeper_reward_units,
            low_fee_rebate_units,
            height,
            ledger_id: ledger_id.to_string(),
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_protocol_fee_accrual",
            "chain_id": CHAIN_ID,
            "accrual_id": self.accrual_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "asset_id": self.asset_id,
            "event_kind": self.event_kind.as_str(),
            "gross_units": self.gross_units,
            "reserve_units": self.reserve_units,
            "protocol_fee_units": self.protocol_fee_units,
            "keeper_reward_units": self.keeper_reward_units,
            "low_fee_rebate_units": self.low_fee_rebate_units,
            "height": self.height,
            "ledger_id": self.ledger_id,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingMarketState {
    pub height: u64,
    pub config: LendingMarketConfig,
    pub markets: BTreeMap<String, LendingCollateralMarket>,
    pub collateral_rules: BTreeMap<String, LendingCollateralRule>,
    pub interest_models: BTreeMap<String, LendingInterestRateModel>,
    pub interest_snapshots: BTreeMap<String, LendingInterestIndexSnapshot>,
    pub private_borrower_commitments: BTreeMap<String, PrivateBorrowerCommitment>,
    pub supply_positions: BTreeMap<String, LendingSupplyPosition>,
    pub borrow_positions: BTreeMap<String, LendingBorrowPosition>,
    pub oracle_guards: BTreeMap<String, LendingOracleGuard>,
    pub risk_tiers: BTreeMap<String, LendingRiskTierConfig>,
    pub liquidation_auctions: BTreeMap<String, LendingLiquidationAuction>,
    pub liquidation_bids: BTreeMap<String, LendingLiquidationBid>,
    pub liquidation_sponsorships: BTreeMap<String, LowFeeLiquidationSponsorship>,
    pub health_buckets: BTreeMap<String, LendingHealthBucketRecord>,
    pub bad_debts: BTreeMap<String, LendingBadDebtRecord>,
    pub socialized_losses: BTreeMap<String, LendingSocializedLossRecord>,
    pub reserve_funds: BTreeMap<String, LendingReserveFund>,
    pub fee_ledgers: BTreeMap<String, LendingProtocolFeeLedger>,
    pub fee_accruals: BTreeMap<String, LendingProtocolFeeAccrual>,
}

impl LendingMarketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: LendingMarketConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn devnet() -> LendingMarketResult<Self> {
        let mut state = Self::with_config(LendingMarketConfig::default());
        state.config.validate()?;
        state.set_height(LENDING_MARKET_DEVNET_HEIGHT);

        for tier in [
            LendingRiskTier::Stable,
            LendingRiskTier::Core,
            LendingRiskTier::Growth,
            LendingRiskTier::Isolation,
            LendingRiskTier::Experimental,
        ] {
            state.insert_risk_tier(LendingRiskTierConfig::devnet(tier, 0)?)?;
        }

        let market = LendingCollateralMarket::new(
            LENDING_MARKET_DEVNET_MARKET_LABEL,
            LENDING_MARKET_DEVNET_COLLATERAL_ASSET_ID,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            LENDING_MARKET_DEVNET_SHARE_ASSET_ID,
            LendingRiskTier::Core,
            LendingMarketStatus::Active,
            12,
            6,
            20_000_000_000,
            8_000_000,
            50_000,
            LENDING_MARKET_DEVNET_ORACLE_FEED_ID,
            &state.config.low_fee_liquidation_lane,
            0,
            &json!({
                "mode": "devnet",
                "description": "Monero-backed private borrow market"
            }),
        )?;
        let market_id = market.market_id.clone();
        state.insert_market(market)?;

        let guard = LendingOracleGuard::new(
            &market_id,
            LENDING_MARKET_DEVNET_ORACLE_FEED_ID,
            LENDING_MARKET_DEVNET_WXMR_PRICE,
            LENDING_MARKET_DEVNET_WXMR_PRICE,
            LENDING_MARKET_DEVNET_WXMR_PRICE.saturating_sub(LENDING_MARKET_DEVNET_WXMR_PRICE / 400),
            LENDING_MARKET_DEVNET_WXMR_PRICE.saturating_sub(LENDING_MARKET_DEVNET_WXMR_PRICE / 500),
            state.config.max_oracle_deviation_bps,
            state.config.max_twap_deviation_bps,
            state.config.max_oracle_staleness_blocks,
            state.height,
            0,
            &json!({
                "sources": ["devnet-oracle-a", "devnet-oracle-b", "amm-twap-devnet"],
                "aggregation": "median-plus-twap"
            }),
            &json!({"mode": "devnet", "guard": "baseline"}),
        )?;
        let guard_id = guard.guard_id.clone();
        state.insert_oracle_guard(guard)?;

        let rule = LendingCollateralRule::new(
            &market_id,
            LENDING_MARKET_DEVNET_COLLATERAL_ASSET_ID,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            LendingRiskTier::Core,
            6_500,
            8_000,
            600,
            75,
            1_000,
            state.config.default_close_factor_bps,
            100_000,
            1_500_000,
            8_000_000,
            LENDING_MARKET_DEVNET_ORACLE_FEED_ID,
            true,
            0,
            &json!({
                "mode": "devnet",
                "collateral": LENDING_MARKET_DEVNET_COLLATERAL_ASSET_ID,
                "debt": LENDING_MARKET_DEVNET_DEBT_ASSET_ID
            }),
        )?;
        state.insert_collateral_rule(rule)?;

        let interest_model = LendingInterestRateModel::new(
            &market_id,
            InterestCurveKind::Jump,
            120,
            7_000,
            9_000,
            700,
            4_200,
            18_000,
            1_000,
            60,
            120,
            25_000,
            0,
            &json!({"mode": "devnet", "target": "fast low-fee stable borrowing"}),
        )?;
        let curve_id = interest_model.curve_id.clone();
        state.insert_interest_model(interest_model)?;

        if let Some(market) = state.markets.get_mut(&market_id) {
            market.oracle_guard_id = guard_id.clone();
            market.interest_curve_id = curve_id.clone();
        }

        let reserve = LendingReserveFund::new(
            &market_id,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            800_000,
            250_000,
            1_500,
            &lending_account_commitment("devnet-reserve-council"),
            state.height,
            &json!({"mode": "devnet", "purpose": "bad debt first loss"}),
        )?;
        state.insert_reserve_fund(reserve)?;

        let ledger = LendingProtocolFeeLedger::new(
            &market_id,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            &lending_account_commitment("devnet-protocol-fee-vault"),
            state.height,
            &json!({"mode": "devnet", "asset": LENDING_MARKET_DEVNET_DEBT_ASSET_ID}),
        )?;
        state.insert_fee_ledger(ledger)?;

        let supplier_alice = lending_account_commitment("devnet-alice-supplier");
        let supplier_bob = lending_account_commitment("devnet-bob-supplier");
        let borrower_carol = lending_account_commitment("devnet-carol-borrower");
        let borrower_dan = lending_account_commitment("devnet-dan-borrower");
        let keeper = lending_account_commitment("devnet-liquidation-keeper");

        state.supply_liquidity(
            &market_id,
            &supplier_alice,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            3_250_000,
            state.height,
            true,
            "devnet-supply-privacy-1",
            1,
            &json!({"wallet": "alice", "lane": "private"}),
        )?;
        state.supply_liquidity(
            &market_id,
            &supplier_bob,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            2_000_000,
            state.height,
            false,
            "devnet-supply-privacy-2",
            2,
            &json!({"wallet": "bob", "lane": "public"}),
        )?;

        let carol_commitment = state.open_private_borrower_commitment(
            &market_id,
            &borrower_carol,
            "devnet-carol-nullifier-1",
            &lending_market_string_root("LENDING-DEVNET-VIEW-TAG", "carol"),
            &lending_market_string_root("LENDING-DEVNET-ENCRYPTED-POSITION", "carol"),
            &lending_market_string_root("LENDING-DEVNET-STEALTH-ADDRESS", "carol"),
            LendingRiskTier::Core,
            BorrowVisibility::Private,
            1,
            &json!({"mode": "devnet", "borrower": "carol"}),
        )?;
        let dan_commitment = state.open_private_borrower_commitment(
            &market_id,
            &borrower_dan,
            "devnet-dan-nullifier-1",
            &lending_market_string_root("LENDING-DEVNET-VIEW-TAG", "dan"),
            &lending_market_string_root("LENDING-DEVNET-ENCRYPTED-POSITION", "dan"),
            &lending_market_string_root("LENDING-DEVNET-STEALTH-ADDRESS", "dan"),
            LendingRiskTier::Core,
            BorrowVisibility::Stealth,
            2,
            &json!({"mode": "devnet", "borrower": "dan"}),
        )?;

        state.open_borrow_position(
            &market_id,
            &borrower_carol,
            10_000,
            LENDING_MARKET_DEVNET_WXMR_PRICE,
            700_000,
            &carol_commitment.commitment_id,
            1,
            state.height.saturating_add(10_080),
            &json!({"mode": "devnet", "position": "healthy private borrow"}),
        )?;
        let dan_position = state.open_borrow_position(
            &market_id,
            &borrower_dan,
            4_000,
            LENDING_MARKET_DEVNET_WXMR_PRICE,
            380_000,
            &dan_commitment.commitment_id,
            2,
            state.height.saturating_add(5_040),
            &json!({"mode": "devnet", "position": "price shock candidate"}),
        )?;

        if let Some(position) = state.borrow_positions.get_mut(&dan_position.position_id) {
            position.collateral_value_units = 430_000;
            position.refresh_health(390_000, 8_000, state.height);
        }

        state.accrue_interest_for_market(&market_id, state.height.saturating_add(6))?;
        state.set_height(LENDING_MARKET_DEVNET_HEIGHT.saturating_add(6));
        state.refresh_health_buckets(&market_id)?;

        let liquidatable_bucket = state
            .health_buckets
            .values()
            .find(|bucket| {
                bucket.market_id == market_id && bucket.bucket == HealthFactorBucket::Liquidatable
            })
            .map(|bucket| bucket.bucket_id.clone())
            .unwrap_or_else(|| lending_market_string_root("LENDING-DEVNET-EMPTY-BUCKET", "none"));

        let auction = state.open_liquidation_auction(
            &dan_position.position_id,
            250_000,
            LENDING_MARKET_DEVNET_WXMR_PRICE.saturating_sub(LENDING_MARKET_DEVNET_WXMR_PRICE / 8),
            LENDING_MARKET_DEVNET_WXMR_PRICE.saturating_sub(LENDING_MARKET_DEVNET_WXMR_PRICE / 3),
            0,
            &guard_id,
            &liquidatable_bucket,
            &json!({"mode": "devnet", "reason": "price shock bucket"}),
        )?;
        let sponsorship = LowFeeLiquidationSponsorship::new(
            &auction.auction_id,
            &market_id,
            &lending_account_commitment("devnet-liquidation-sponsor"),
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            2_000,
            7_500,
            250,
            &state.config.low_fee_liquidation_lane,
            "devnet-liquidation-bond-1",
            state.height,
            32,
            &json!({
                "lane": state.config.low_fee_liquidation_lane,
                "purpose": "low-fee liquidation sponsorship"
            }),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_liquidation_sponsorship(sponsorship)?;
        if let Some(auction) = state.liquidation_auctions.get_mut(&auction.auction_id) {
            auction.sponsor_id = sponsorship_id;
        }
        let bid = state.place_liquidation_bid(
            &auction.auction_id,
            &keeper,
            auction.debt_to_cover_units.min(245_000).max(1),
            LENDING_MARKET_DEVNET_WXMR_PRICE,
            600,
            1,
            &json!({"mode": "devnet", "keeper": "primary"}),
        )?;
        state.settle_liquidation_auction(&auction.auction_id, Some(&bid.bid_id))?;

        let bad_debt = state.record_bad_debt(
            &market_id,
            &dan_position.position_id,
            &borrower_dan,
            LENDING_MARKET_DEVNET_DEBT_ASSET_ID,
            15_000,
            1_200,
            500,
            &auction.auction_id,
            &json!({"mode": "devnet", "reason": "residual dust after liquidation"}),
        )?;
        state.cover_bad_debt_with_reserve(&bad_debt.bad_debt_id, 8_000)?;
        state.socialize_bad_debt_loss(
            &bad_debt.bad_debt_id,
            3_500,
            &json!({"mode": "devnet", "reason": "dust socialized to supply index"}),
        )?;

        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for commitment in self.private_borrower_commitments.values_mut() {
            if commitment.is_expired_at(height) && commitment.status == LENDING_MARKET_STATUS_OPEN {
                commitment.status = LENDING_MARKET_STATUS_EXPIRED.to_string();
            }
        }
        for sponsorship in self.liquidation_sponsorships.values_mut() {
            if height > sponsorship.expires_at_height
                && sponsorship.status == SponsorshipStatus::Reserved
            {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for auction in self.liquidation_auctions.values_mut() {
            auction.refresh_price(height);
        }
    }

    pub fn advance_height(&mut self, blocks: u64) -> u64 {
        let height = self.height.saturating_add(blocks);
        self.set_height(height);
        self.height
    }

    pub fn insert_market(
        &mut self,
        market: LendingCollateralMarket,
    ) -> LendingMarketResult<LendingCollateralMarket> {
        market.validate()?;
        self.markets
            .insert(market.market_id.clone(), market.clone());
        Ok(market)
    }

    pub fn insert_collateral_rule(
        &mut self,
        rule: LendingCollateralRule,
    ) -> LendingMarketResult<LendingCollateralRule> {
        rule.validate()?;
        if !self.markets.contains_key(&rule.market_id) {
            return Err("collateral rule references unknown lending market".to_string());
        }
        self.collateral_rules
            .insert(rule.rule_id.clone(), rule.clone());
        Ok(rule)
    }

    pub fn insert_interest_model(
        &mut self,
        model: LendingInterestRateModel,
    ) -> LendingMarketResult<LendingInterestRateModel> {
        model.validate()?;
        if !self.markets.contains_key(&model.market_id) {
            return Err("interest model references unknown lending market".to_string());
        }
        self.interest_models
            .insert(model.curve_id.clone(), model.clone());
        Ok(model)
    }

    pub fn insert_oracle_guard(
        &mut self,
        guard: LendingOracleGuard,
    ) -> LendingMarketResult<LendingOracleGuard> {
        if !self.markets.contains_key(&guard.market_id) {
            return Err("oracle guard references unknown lending market".to_string());
        }
        self.oracle_guards
            .insert(guard.guard_id.clone(), guard.clone());
        Ok(guard)
    }

    pub fn insert_risk_tier(
        &mut self,
        tier: LendingRiskTierConfig,
    ) -> LendingMarketResult<LendingRiskTierConfig> {
        tier.validate()?;
        self.risk_tiers.insert(tier.tier_id.clone(), tier.clone());
        Ok(tier)
    }

    pub fn insert_reserve_fund(
        &mut self,
        fund: LendingReserveFund,
    ) -> LendingMarketResult<LendingReserveFund> {
        if !self.markets.contains_key(&fund.market_id) {
            return Err("reserve fund references unknown lending market".to_string());
        }
        self.reserve_funds
            .insert(fund.fund_id.clone(), fund.clone());
        Ok(fund)
    }

    pub fn insert_fee_ledger(
        &mut self,
        ledger: LendingProtocolFeeLedger,
    ) -> LendingMarketResult<LendingProtocolFeeLedger> {
        if !self.markets.contains_key(&ledger.market_id) {
            return Err("fee ledger references unknown lending market".to_string());
        }
        self.fee_ledgers
            .insert(ledger.ledger_id.clone(), ledger.clone());
        Ok(ledger)
    }

    pub fn insert_liquidation_sponsorship(
        &mut self,
        sponsorship: LowFeeLiquidationSponsorship,
    ) -> LendingMarketResult<LowFeeLiquidationSponsorship> {
        if !self.markets.contains_key(&sponsorship.market_id) {
            return Err("liquidation sponsorship references unknown lending market".to_string());
        }
        self.liquidation_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn supply_liquidity(
        &mut self,
        market_id: &str,
        supplier_commitment: &str,
        asset_id: &str,
        supplied_units: u64,
        unlock_height: u64,
        reusable_collateral: bool,
        privacy_commitment_id: &str,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<LendingSupplyPosition> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        if !market.status.allows_supply() {
            return Err("lending market does not allow supply".to_string());
        }
        if asset_id != market.debt_asset_id {
            return Err("supply asset must match market debt liquidity asset".to_string());
        }
        if supplied_units > market.supply_capacity_units() {
            return Err("supply exceeds lending market cap".to_string());
        }
        let position = LendingSupplyPosition::new(
            market_id,
            supplier_commitment,
            asset_id,
            supplied_units,
            market.current_supply_index,
            self.height,
            unlock_height,
            reusable_collateral,
            privacy_commitment_id,
            nonce,
            metadata,
        )?;
        let market = self
            .markets
            .get_mut(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?;
        market.total_supplied_units = market.total_supplied_units.saturating_add(supplied_units);
        market.total_supply_scaled_units = market
            .total_supply_scaled_units
            .saturating_add(position.scaled_supply_units);
        self.supply_positions
            .insert(position.position_id.clone(), position.clone());
        Ok(position)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_private_borrower_commitment(
        &mut self,
        market_id: &str,
        borrower_commitment: &str,
        spend_nullifier_hash: &str,
        view_tag_root: &str,
        encrypted_position_root: &str,
        stealth_address_root: &str,
        risk_tier: LendingRiskTier,
        visibility: BorrowVisibility,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<PrivateBorrowerCommitment> {
        if !self.markets.contains_key(market_id) {
            return Err("unknown lending market".to_string());
        }
        let commitment = PrivateBorrowerCommitment::new(
            market_id,
            borrower_commitment,
            spend_nullifier_hash,
            view_tag_root,
            encrypted_position_root,
            stealth_address_root,
            &self.config.private_borrow_proof_system,
            &lending_market_string_root("LENDING-PRIVATE-BORROW-VK", market_id),
            risk_tier,
            visibility,
            self.height,
            self.config.default_commitment_ttl_blocks,
            nonce,
            metadata,
        )?;
        self.private_borrower_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_borrow_position(
        &mut self,
        market_id: &str,
        borrower_commitment: &str,
        collateral_units: u64,
        collateral_price_units: u64,
        debt_units: u64,
        private_commitment_id: &str,
        nonce: u64,
        maturity_height: u64,
        metadata: &Value,
    ) -> LendingMarketResult<LendingBorrowPosition> {
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        if !market.status.allows_borrow() {
            return Err("lending market does not allow borrow".to_string());
        }
        if debt_units < market.min_borrow_units {
            return Err("borrow amount is below market minimum".to_string());
        }
        if debt_units > market.borrow_capacity_units() {
            return Err("borrow exceeds lending market borrow cap".to_string());
        }
        if debt_units > market.available_liquidity_units() {
            return Err("borrow exceeds lending market available liquidity".to_string());
        }
        let rule = self.active_rule_for_market(market_id)?.clone();
        if !private_commitment_id.is_empty() {
            let commitment = self
                .private_borrower_commitments
                .get(private_commitment_id)
                .ok_or_else(|| "unknown private borrower commitment".to_string())?;
            if commitment.market_id != market_id
                || commitment.borrower_commitment != borrower_commitment
            {
                return Err("private borrower commitment mismatch".to_string());
            }
            if commitment.is_expired_at(self.height) {
                return Err("private borrower commitment expired".to_string());
            }
        }
        let guard_id = if market.oracle_guard_id.is_empty() {
            String::new()
        } else {
            let guard = self
                .oracle_guards
                .get(&market.oracle_guard_id)
                .ok_or_else(|| "market oracle guard missing".to_string())?;
            if !guard.allows_borrow_at(self.height) {
                return Err("oracle guard blocks lending borrow".to_string());
            }
            guard.guard_id.clone()
        };
        let collateral_value_units = value_units(collateral_units, collateral_price_units);
        if collateral_value_units < rule.min_collateral_value_units {
            return Err("borrow collateral value below rule minimum".to_string());
        }
        let max_debt = rule.max_debt_for_collateral_value(collateral_value_units);
        if debt_units > max_debt {
            return Err("borrow exceeds collateral rule debt capacity".to_string());
        }
        let origination_fee_units = bps_mul_ceil(debt_units, rule.protocol_fee_bps);
        let reserve_contribution_units = bps_mul_ceil(debt_units, rule.reserve_factor_bps);
        let position = LendingBorrowPosition::new(
            market_id,
            borrower_commitment,
            &market.collateral_asset_id,
            &market.debt_asset_id,
            collateral_units,
            collateral_value_units,
            debt_units,
            market.current_borrow_index,
            origination_fee_units,
            reserve_contribution_units,
            rule.liquidation_threshold_bps,
            rule.risk_tier,
            private_commitment_id,
            &guard_id,
            self.height,
            maturity_height,
            nonce,
            metadata,
        )?;
        let ledger_id = self.ensure_protocol_fee_ledger(market_id)?;
        if let Some(ledger) = self.fee_ledgers.get_mut(&ledger_id) {
            ledger.accrue(origination_fee_units, self.height);
        }
        if let Some(market) = self.markets.get_mut(market_id) {
            market.total_borrowed_principal_units = market
                .total_borrowed_principal_units
                .saturating_add(debt_units);
            market.total_borrowed_scaled_units = market
                .total_borrowed_scaled_units
                .saturating_add(position.scaled_debt_units);
            market.total_collateral_locked_units = market
                .total_collateral_locked_units
                .saturating_add(collateral_units);
            market.reserve_units = market
                .reserve_units
                .saturating_add(reserve_contribution_units);
            market.protocol_fee_units = market
                .protocol_fee_units
                .saturating_add(origination_fee_units);
        }
        let accrual = LendingProtocolFeeAccrual::new(
            market_id,
            &position.position_id,
            &market.debt_asset_id,
            ProtocolFeeEventKind::Origination,
            debt_units,
            reserve_contribution_units,
            origination_fee_units,
            0,
            0,
            self.height,
            &ledger_id,
            &json!({"source": "open_borrow_position"}),
        )?;
        self.fee_accruals
            .insert(accrual.accrual_id.clone(), accrual);
        self.borrow_positions
            .insert(position.position_id.clone(), position.clone());
        if let Some(commitment) = self
            .private_borrower_commitments
            .get_mut(private_commitment_id)
        {
            commitment.status = LENDING_MARKET_STATUS_SETTLED.to_string();
        }
        Ok(position)
    }

    pub fn accrue_interest_for_market(
        &mut self,
        market_id: &str,
        target_height: u64,
    ) -> LendingMarketResult<LendingInterestIndexSnapshot> {
        let market_snapshot = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        let model = self
            .interest_model_for_market(&market_snapshot)
            .ok_or_else(|| "missing lending interest model".to_string())?
            .clone();
        let previous_snapshot_id = self
            .interest_snapshots
            .values()
            .filter(|snapshot| snapshot.market_id == market_id)
            .max_by(|left, right| left.height.cmp(&right.height))
            .map(|snapshot| snapshot.snapshot_id.clone())
            .unwrap_or_default();
        let blocks = target_height.saturating_sub(market_snapshot.last_accrual_height);
        let utilization = market_snapshot.utilization_bps();
        let borrow_rate_bps = model.borrow_rate_bps(utilization);
        let supply_rate_bps = model.supply_rate_bps(utilization);
        let accrued_interest_units = annualized_bps_accrual(
            market_snapshot.total_borrowed_principal_units,
            borrow_rate_bps,
            blocks,
        );
        let reserve_accrual_units = bps_mul_floor(accrued_interest_units, model.reserve_factor_bps);
        let protocol_fee_accrual_units =
            bps_mul_floor(accrued_interest_units, model.protocol_fee_bps);
        let borrow_index_delta = annualized_bps_accrual(
            market_snapshot.current_borrow_index,
            borrow_rate_bps,
            blocks,
        );
        let supply_index_delta = annualized_bps_accrual(
            market_snapshot.current_supply_index,
            supply_rate_bps,
            blocks,
        );
        {
            let market = self
                .markets
                .get_mut(market_id)
                .ok_or_else(|| "unknown lending market".to_string())?;
            market.current_borrow_index = market
                .current_borrow_index
                .saturating_add(borrow_index_delta);
            market.current_supply_index = market
                .current_supply_index
                .saturating_add(supply_index_delta);
            market.total_borrowed_principal_units = market
                .total_borrowed_principal_units
                .saturating_add(accrued_interest_units);
            market.reserve_units = market.reserve_units.saturating_add(reserve_accrual_units);
            market.protocol_fee_units = market
                .protocol_fee_units
                .saturating_add(protocol_fee_accrual_units);
            market.last_accrual_height = target_height;
        }
        let market_after = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        let snapshot = LendingInterestIndexSnapshot::new(
            &market_after,
            supply_rate_bps,
            borrow_rate_bps,
            model.reserve_factor_bps,
            accrued_interest_units,
            reserve_accrual_units,
            protocol_fee_accrual_units,
            target_height,
            &previous_snapshot_id,
            &json!({"source": "accrue_interest_for_market"}),
        );
        let ledger_id = self.ensure_protocol_fee_ledger(market_id)?;
        if let Some(ledger) = self.fee_ledgers.get_mut(&ledger_id) {
            ledger.accrue(protocol_fee_accrual_units, target_height);
        }
        if protocol_fee_accrual_units > 0 || reserve_accrual_units > 0 {
            let accrual = LendingProtocolFeeAccrual::new(
                market_id,
                "",
                &market_after.debt_asset_id,
                ProtocolFeeEventKind::BorrowInterest,
                accrued_interest_units,
                reserve_accrual_units,
                protocol_fee_accrual_units,
                0,
                0,
                target_height,
                &ledger_id,
                &json!({"snapshot_id": snapshot.snapshot_id}),
            )?;
            self.fee_accruals
                .insert(accrual.accrual_id.clone(), accrual);
        }
        self.interest_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn refresh_health_buckets(
        &mut self,
        market_id: &str,
    ) -> LendingMarketResult<Vec<LendingHealthBucketRecord>> {
        let rule = self.active_rule_for_market(market_id)?.clone();
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        let mut buckets: BTreeMap<HealthFactorBucket, (u64, u64, u64, Vec<String>)> =
            BTreeMap::new();
        for position in self.borrow_positions.values_mut() {
            if position.market_id != market_id || position.status != LENDING_MARKET_STATUS_ACTIVE {
                continue;
            }
            let current_debt = position.current_debt_units(market.current_borrow_index);
            position.refresh_health(current_debt, rule.liquidation_threshold_bps, self.height);
            let entry = buckets
                .entry(position.health_bucket)
                .or_insert_with(|| (0, 0, 0, Vec::new()));
            entry.0 = entry.0.saturating_add(1);
            entry.1 = entry.1.saturating_add(current_debt);
            entry.2 = entry.2.saturating_add(position.collateral_value_units);
            entry.3.push(position.borrower_commitment.clone());
        }
        let mut created = Vec::new();
        for bucket in [
            HealthFactorBucket::NoDebt,
            HealthFactorBucket::Healthy,
            HealthFactorBucket::Watch,
            HealthFactorBucket::Unsafe,
            HealthFactorBucket::Liquidatable,
            HealthFactorBucket::Insolvent,
        ] {
            let (position_count, debt_units, collateral_value_units, commitments) = buckets
                .remove(&bucket)
                .unwrap_or_else(|| (0, 0, 0, Vec::new()));
            let record = LendingHealthBucketRecord::new(
                market_id,
                bucket,
                position_count,
                debt_units,
                collateral_value_units,
                &commitments,
                self.height,
                self.config.default_health_bucket_ttl_blocks,
                &self.config.health_bucket_proof_system,
                &json!({"source": "refresh_health_buckets"}),
            )?;
            self.health_buckets
                .insert(record.bucket_id.clone(), record.clone());
            created.push(record);
        }
        Ok(created)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_liquidation_auction(
        &mut self,
        position_id: &str,
        debt_to_cover_units: u64,
        start_price_units: u64,
        floor_price_units: u64,
        keeper_reward_units: u64,
        oracle_guard_id: &str,
        health_bucket_id: &str,
        metadata: &Value,
    ) -> LendingMarketResult<LendingLiquidationAuction> {
        let position = self
            .borrow_positions
            .get(position_id)
            .ok_or_else(|| "unknown borrow position".to_string())?
            .clone();
        if !position.health_bucket.can_liquidate() {
            return Err("borrow position is not in a liquidatable health bucket".to_string());
        }
        let market = self
            .markets
            .get(&position.market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        if !market.status.allows_liquidation() {
            return Err("lending market blocks liquidations".to_string());
        }
        if !oracle_guard_id.is_empty() {
            let guard = self
                .oracle_guards
                .get(oracle_guard_id)
                .ok_or_else(|| "unknown liquidation oracle guard".to_string())?;
            if !guard.allows_liquidation_at(self.height) {
                return Err("oracle guard blocks liquidation".to_string());
            }
        }
        let rule = self.active_rule_for_market(&position.market_id)?.clone();
        let current_debt = position.current_debt_units(market.current_borrow_index);
        if current_debt < self.config.min_liquidation_debt_units {
            return Err("borrow position debt below liquidation minimum".to_string());
        }
        let close_units = position.max_close_units(current_debt, rule.close_factor_bps);
        let debt_to_cover_units = debt_to_cover_units.min(close_units).min(current_debt);
        let auction = LendingLiquidationAuction::new(
            &position.market_id,
            position_id,
            &position.borrower_commitment,
            &position.collateral_asset_id,
            &position.debt_asset_id,
            position.collateral_units,
            debt_to_cover_units,
            start_price_units,
            floor_price_units,
            rule.liquidation_bonus_bps,
            self.config.liquidation_protocol_fee_bps,
            keeper_reward_units,
            "",
            oracle_guard_id,
            health_bucket_id,
            self.height,
            self.config.default_auction_ttl_blocks,
            metadata,
        )?;
        self.liquidation_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        Ok(auction)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn place_liquidation_bid(
        &mut self,
        auction_id: &str,
        bidder_commitment: &str,
        repay_units: u64,
        max_collateral_price_units: u64,
        requested_sponsorship_units: u64,
        nonce: u64,
        metadata: &Value,
    ) -> LendingMarketResult<LendingLiquidationBid> {
        let auction = self
            .liquidation_auctions
            .get(auction_id)
            .ok_or_else(|| "unknown liquidation auction".to_string())?;
        if !auction.accepts_height(self.height) {
            return Err("liquidation auction is not accepting bids".to_string());
        }
        if repay_units > auction.debt_to_cover_units {
            return Err("liquidation bid exceeds auction debt_to_cover".to_string());
        }
        if max_collateral_price_units < auction.current_price_units {
            return Err("liquidation bid max price below auction price".to_string());
        }
        let bid = LendingLiquidationBid::new(
            auction_id,
            bidder_commitment,
            repay_units,
            max_collateral_price_units,
            requested_sponsorship_units,
            self.height,
            nonce,
            metadata,
        )?;
        self.liquidation_bids
            .insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn settle_liquidation_auction(
        &mut self,
        auction_id: &str,
        bid_id: Option<&str>,
    ) -> LendingMarketResult<LendingLiquidationAuction> {
        let auction = self
            .liquidation_auctions
            .get(auction_id)
            .ok_or_else(|| "unknown liquidation auction".to_string())?
            .clone();
        if auction.status != LiquidationAuctionStatus::Open {
            return Err("liquidation auction is not open".to_string());
        }
        let selected_bid_id = if let Some(bid_id) = bid_id {
            bid_id.to_string()
        } else {
            self.liquidation_bids
                .values()
                .filter(|bid| {
                    bid.auction_id == auction_id && bid.status == LENDING_MARKET_STATUS_OPEN
                })
                .max_by(|left, right| {
                    left.bid_score_units
                        .cmp(&right.bid_score_units)
                        .then_with(|| left.repay_units.cmp(&right.repay_units))
                        .then_with(|| {
                            right
                                .requested_sponsorship_units
                                .cmp(&left.requested_sponsorship_units)
                        })
                })
                .map(|bid| bid.bid_id.clone())
                .ok_or_else(|| "liquidation auction has no open bids".to_string())?
        };
        let bid = self
            .liquidation_bids
            .get(&selected_bid_id)
            .ok_or_else(|| "unknown liquidation bid".to_string())?
            .clone();
        if bid.auction_id != auction_id {
            return Err("liquidation bid auction mismatch".to_string());
        }
        let repay_units = bid.repay_units.min(auction.debt_to_cover_units);
        let collateral_claim_units = auction.collateral_claim_units(repay_units);
        let protocol_fee_units = bps_mul_ceil(repay_units, auction.protocol_fee_bps);
        let mut low_fee_rebate_units = 0;
        if !auction.sponsor_id.is_empty() {
            if let Some(sponsorship) = self.liquidation_sponsorships.get_mut(&auction.sponsor_id) {
                low_fee_rebate_units = sponsorship.apply_units(bid.requested_sponsorship_units);
            }
        }
        let market = self
            .markets
            .get(&auction.market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        let scaled_repay_units = mul_div_floor(
            repay_units,
            LENDING_MARKET_INDEX_SCALE,
            market.current_borrow_index.max(1),
        );
        if let Some(position) = self.borrow_positions.get_mut(&auction.position_id) {
            position.debt_principal_units =
                position.debt_principal_units.saturating_sub(repay_units);
            position.scaled_debt_units = position
                .scaled_debt_units
                .saturating_sub(scaled_repay_units);
            position.collateral_units = position
                .collateral_units
                .saturating_sub(collateral_claim_units);
            position.collateral_value_units = position.collateral_value_units.saturating_sub(
                value_units(collateral_claim_units, auction.current_price_units),
            );
            position.last_update_height = self.height;
            if position.debt_principal_units == 0 {
                position.status = LENDING_MARKET_STATUS_SETTLED.to_string();
                position.health_bucket = HealthFactorBucket::NoDebt;
                position.health_factor_bps = u64::MAX;
            }
        }
        if let Some(market) = self.markets.get_mut(&auction.market_id) {
            market.total_borrowed_principal_units = market
                .total_borrowed_principal_units
                .saturating_sub(repay_units);
            market.total_borrowed_scaled_units = market
                .total_borrowed_scaled_units
                .saturating_sub(scaled_repay_units);
            market.total_collateral_locked_units = market
                .total_collateral_locked_units
                .saturating_sub(collateral_claim_units);
            market.protocol_fee_units =
                market.protocol_fee_units.saturating_add(protocol_fee_units);
        }
        let ledger_id = self.ensure_protocol_fee_ledger(&auction.market_id)?;
        if let Some(ledger) = self.fee_ledgers.get_mut(&ledger_id) {
            ledger.accrue(protocol_fee_units, self.height);
        }
        let accrual = LendingProtocolFeeAccrual::new(
            &auction.market_id,
            &auction.position_id,
            &auction.debt_asset_id,
            ProtocolFeeEventKind::Liquidation,
            repay_units,
            0,
            protocol_fee_units,
            auction.keeper_reward_units,
            low_fee_rebate_units,
            self.height,
            &ledger_id,
            &json!({"auction_id": auction.auction_id, "bid_id": bid.bid_id}),
        )?;
        self.fee_accruals
            .insert(accrual.accrual_id.clone(), accrual);
        for open_bid in self.liquidation_bids.values_mut() {
            if open_bid.auction_id == auction_id {
                open_bid.status = if open_bid.bid_id == selected_bid_id {
                    LENDING_MARKET_STATUS_SETTLED.to_string()
                } else {
                    LENDING_MARKET_STATUS_CANCELLED.to_string()
                };
            }
        }
        let settled = self
            .liquidation_auctions
            .get_mut(auction_id)
            .ok_or_else(|| "unknown liquidation auction".to_string())?;
        settled.status = LiquidationAuctionStatus::Settled;
        settled.settlement_height = self.height;
        settled.current_price_units = settled.price_at_height(self.height);
        Ok(settled.clone())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_bad_debt(
        &mut self,
        market_id: &str,
        position_id: &str,
        borrower_commitment: &str,
        debt_asset_id: &str,
        principal_units: u64,
        interest_units: u64,
        penalty_units: u64,
        liquidation_auction_id: &str,
        metadata: &Value,
    ) -> LendingMarketResult<LendingBadDebtRecord> {
        let bad_debt = LendingBadDebtRecord::new(
            market_id,
            position_id,
            borrower_commitment,
            debt_asset_id,
            principal_units,
            interest_units,
            penalty_units,
            self.height,
            &self.oracle_guard_root_for_market(market_id),
            liquidation_auction_id,
            metadata,
        )?;
        self.bad_debts
            .insert(bad_debt.bad_debt_id.clone(), bad_debt.clone());
        Ok(bad_debt)
    }

    pub fn cover_bad_debt_with_reserve(
        &mut self,
        bad_debt_id: &str,
        requested_units: u64,
    ) -> LendingMarketResult<u64> {
        let bad_debt = self
            .bad_debts
            .get(bad_debt_id)
            .ok_or_else(|| "unknown bad debt record".to_string())?
            .clone();
        let fund_id = self
            .reserve_funds
            .values()
            .find(|fund| {
                fund.market_id == bad_debt.market_id && fund.asset_id == bad_debt.debt_asset_id
            })
            .map(|fund| fund.fund_id.clone())
            .ok_or_else(|| "reserve fund for bad debt not found".to_string())?;
        let outstanding = bad_debt.outstanding_units();
        let covered = {
            let fund = self
                .reserve_funds
                .get_mut(&fund_id)
                .ok_or_else(|| "reserve fund for bad debt not found".to_string())?;
            fund.withdraw(requested_units.min(outstanding), self.height)
        };
        if let Some(record) = self.bad_debts.get_mut(bad_debt_id) {
            record.reserve_covered_units = record.reserve_covered_units.saturating_add(covered);
            record.status = if record.outstanding_units() == 0 {
                LossRecordStatus::CoveredByReserve
            } else {
                LossRecordStatus::Pending
            };
        }
        Ok(covered)
    }

    pub fn socialize_bad_debt_loss(
        &mut self,
        bad_debt_id: &str,
        requested_units: u64,
        metadata: &Value,
    ) -> LendingMarketResult<LendingSocializedLossRecord> {
        let bad_debt = self
            .bad_debts
            .get(bad_debt_id)
            .ok_or_else(|| "unknown bad debt record".to_string())?
            .clone();
        let market = self
            .markets
            .get(&bad_debt.market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        let loss_units = requested_units.min(bad_debt.outstanding_units());
        if loss_units == 0 {
            return Err("socialized loss requested units resolves to zero".to_string());
        }
        let affected_supply_root = self.supply_position_root_for_market(&bad_debt.market_id);
        let loss = LendingSocializedLossRecord::new(
            &bad_debt.market_id,
            &bad_debt.debt_asset_id,
            bad_debt_id,
            loss_units,
            market.total_supply_scaled_units,
            &affected_supply_root,
            bad_debt.reserve_covered_units,
            0,
            self.height,
            metadata,
        )?;
        if let Some(record) = self.bad_debts.get_mut(bad_debt_id) {
            record.socialized_units = record.socialized_units.saturating_add(loss_units);
            record.status = if record.outstanding_units() == 0 {
                LossRecordStatus::Socialized
            } else {
                LossRecordStatus::Pending
            };
        }
        if let Some(market) = self.markets.get_mut(&bad_debt.market_id) {
            market.current_supply_index = market
                .current_supply_index
                .saturating_sub(loss.per_supply_share_index_delta);
        }
        self.socialized_losses
            .insert(loss.loss_id.clone(), loss.clone());
        Ok(loss)
    }

    pub fn collect_protocol_fees(
        &mut self,
        market_id: &str,
        requested_units: u64,
    ) -> LendingMarketResult<u64> {
        let ledger_id = self.ensure_protocol_fee_ledger(market_id)?;
        let collected = self
            .fee_ledgers
            .get_mut(&ledger_id)
            .ok_or_else(|| "protocol fee ledger missing".to_string())?
            .collect(requested_units, self.height);
        if let Some(market) = self.markets.get_mut(market_id) {
            market.protocol_fee_units = market.protocol_fee_units.saturating_sub(collected);
        }
        Ok(collected)
    }

    pub fn active_rule_for_market(
        &self,
        market_id: &str,
    ) -> LendingMarketResult<&LendingCollateralRule> {
        self.collateral_rules
            .values()
            .filter(|rule| rule.market_id == market_id && rule.active)
            .max_by(|left, right| {
                left.created_at_height
                    .cmp(&right.created_at_height)
                    .then_with(|| left.rule_id.cmp(&right.rule_id))
            })
            .ok_or_else(|| "no active collateral rule for lending market".to_string())
    }

    fn interest_model_for_market(
        &self,
        market: &LendingCollateralMarket,
    ) -> Option<&LendingInterestRateModel> {
        if !market.interest_curve_id.is_empty() {
            return self.interest_models.get(&market.interest_curve_id);
        }
        self.interest_models
            .values()
            .find(|model| model.market_id == market.market_id && model.active)
    }

    fn ensure_protocol_fee_ledger(&mut self, market_id: &str) -> LendingMarketResult<String> {
        if let Some(ledger) = self
            .fee_ledgers
            .values()
            .find(|ledger| ledger.market_id == market_id)
        {
            return Ok(ledger.ledger_id.clone());
        }
        let market = self
            .markets
            .get(market_id)
            .ok_or_else(|| "unknown lending market".to_string())?
            .clone();
        let ledger = LendingProtocolFeeLedger::new(
            market_id,
            &market.debt_asset_id,
            &lending_account_commitment("protocol-fee-vault"),
            self.height,
            &json!({"source": "ensure_protocol_fee_ledger"}),
        )?;
        let ledger_id = ledger.ledger_id.clone();
        self.fee_ledgers.insert(ledger_id.clone(), ledger);
        Ok(ledger_id)
    }

    pub fn market_ids(&self) -> Vec<String> {
        self.markets.keys().cloned().collect()
    }

    pub fn risk_tier_ids(&self) -> Vec<String> {
        self.risk_tiers.keys().cloned().collect()
    }

    pub fn active_market_count(&self) -> u64 {
        self.markets
            .values()
            .filter(|market| market.status == LendingMarketStatus::Active)
            .count() as u64
    }

    pub fn active_borrow_position_count(&self) -> u64 {
        self.borrow_positions
            .values()
            .filter(|position| position.status == LENDING_MARKET_STATUS_ACTIVE)
            .count() as u64
    }

    pub fn active_supply_position_count(&self) -> u64 {
        self.supply_positions
            .values()
            .filter(|position| position.status == LENDING_MARKET_STATUS_ACTIVE)
            .count() as u64
    }

    pub fn open_liquidation_auction_count(&self) -> u64 {
        self.liquidation_auctions
            .values()
            .filter(|auction| auction.status == LiquidationAuctionStatus::Open)
            .count() as u64
    }

    pub fn liquidatable_position_count(&self) -> u64 {
        self.borrow_positions
            .values()
            .filter(|position| position.health_bucket.can_liquidate())
            .count() as u64
    }

    pub fn total_supplied_units(&self) -> u64 {
        self.markets.values().fold(0_u64, |total, market| {
            total.saturating_add(market.total_supplied_units)
        })
    }

    pub fn total_borrowed_principal_units(&self) -> u64 {
        self.markets.values().fold(0_u64, |total, market| {
            total.saturating_add(market.total_borrowed_principal_units)
        })
    }

    pub fn total_available_liquidity_units(&self) -> u64 {
        self.markets.values().fold(0_u64, |total, market| {
            total.saturating_add(market.available_liquidity_units())
        })
    }

    pub fn total_reserve_units(&self) -> u64 {
        self.reserve_funds.values().fold(0_u64, |total, fund| {
            total.saturating_add(fund.available_after_pending_units())
        })
    }

    pub fn total_protocol_fee_pending_units(&self) -> u64 {
        self.fee_ledgers.values().fold(0_u64, |total, ledger| {
            total.saturating_add(ledger.pending_units())
        })
    }

    pub fn total_bad_debt_outstanding_units(&self) -> u64 {
        self.bad_debts.values().fold(0_u64, |total, record| {
            total.saturating_add(record.outstanding_units())
        })
    }

    pub fn aggregate_utilization_bps(&self) -> u64 {
        ratio_bps(
            self.total_borrowed_principal_units(),
            self.total_supplied_units().max(1),
        )
        .min(LENDING_MARKET_MAX_BPS)
    }

    pub fn worst_health_bucket(&self) -> HealthFactorBucket {
        self.borrow_positions
            .values()
            .map(|position| position.health_bucket)
            .max()
            .unwrap_or(HealthFactorBucket::NoDebt)
    }

    pub fn collateral_market_root(&self) -> String {
        merkle_root(
            "LENDING-COLLATERAL-MARKET",
            &self
                .markets
                .values()
                .map(LendingCollateralMarket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn collateral_rule_root(&self) -> String {
        merkle_root(
            "LENDING-COLLATERAL-RULE",
            &self
                .collateral_rules
                .values()
                .map(LendingCollateralRule::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn interest_model_root(&self) -> String {
        merkle_root(
            "LENDING-INTEREST-MODEL",
            &self
                .interest_models
                .values()
                .map(LendingInterestRateModel::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn interest_snapshot_root(&self) -> String {
        merkle_root(
            "LENDING-INTEREST-SNAPSHOT",
            &self
                .interest_snapshots
                .values()
                .map(LendingInterestIndexSnapshot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_borrower_commitment_root(&self) -> String {
        merkle_root(
            "LENDING-PRIVATE-BORROWER-COMMITMENT",
            &self
                .private_borrower_commitments
                .values()
                .map(PrivateBorrowerCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn supply_position_root(&self) -> String {
        merkle_root(
            "LENDING-SUPPLY-POSITION",
            &self
                .supply_positions
                .values()
                .map(LendingSupplyPosition::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn borrow_position_root(&self) -> String {
        merkle_root(
            "LENDING-BORROW-POSITION",
            &self
                .borrow_positions
                .values()
                .map(LendingBorrowPosition::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn oracle_guard_root(&self) -> String {
        merkle_root(
            "LENDING-ORACLE-GUARD",
            &self
                .oracle_guards
                .values()
                .map(LendingOracleGuard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn risk_tier_root(&self) -> String {
        merkle_root(
            "LENDING-RISK-TIER-CONFIG",
            &self
                .risk_tiers
                .values()
                .map(LendingRiskTierConfig::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_auction_root(&self) -> String {
        merkle_root(
            "LENDING-LIQUIDATION-AUCTION",
            &self
                .liquidation_auctions
                .values()
                .map(LendingLiquidationAuction::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_bid_root(&self) -> String {
        merkle_root(
            "LENDING-LIQUIDATION-BID",
            &self
                .liquidation_bids
                .values()
                .map(LendingLiquidationBid::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_sponsorship_root(&self) -> String {
        merkle_root(
            "LENDING-LIQUIDATION-SPONSORSHIP",
            &self
                .liquidation_sponsorships
                .values()
                .map(LowFeeLiquidationSponsorship::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn health_bucket_root(&self) -> String {
        merkle_root(
            "LENDING-HEALTH-BUCKET",
            &self
                .health_buckets
                .values()
                .map(LendingHealthBucketRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn bad_debt_root(&self) -> String {
        merkle_root(
            "LENDING-BAD-DEBT",
            &self
                .bad_debts
                .values()
                .map(LendingBadDebtRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn socialized_loss_root(&self) -> String {
        merkle_root(
            "LENDING-SOCIALIZED-LOSS",
            &self
                .socialized_losses
                .values()
                .map(LendingSocializedLossRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn reserve_fund_root(&self) -> String {
        merkle_root(
            "LENDING-RESERVE-FUND",
            &self
                .reserve_funds
                .values()
                .map(LendingReserveFund::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn protocol_fee_ledger_root(&self) -> String {
        merkle_root(
            "LENDING-PROTOCOL-FEE-LEDGER",
            &self
                .fee_ledgers
                .values()
                .map(LendingProtocolFeeLedger::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn protocol_fee_accrual_root(&self) -> String {
        merkle_root(
            "LENDING-PROTOCOL-FEE-ACCRUAL",
            &self
                .fee_accruals
                .values()
                .map(LendingProtocolFeeAccrual::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn market_surface_root(&self) -> String {
        merkle_root(
            "LENDING-MARKET-SURFACE",
            &[json!({
                "collateral_market_root": self.collateral_market_root(),
                "collateral_rule_root": self.collateral_rule_root(),
                "interest_model_root": self.interest_model_root(),
                "risk_tier_root": self.risk_tier_root(),
            })],
        )
    }

    pub fn position_surface_root(&self) -> String {
        merkle_root(
            "LENDING-POSITION-SURFACE",
            &[json!({
                "supply_position_root": self.supply_position_root(),
                "borrow_position_root": self.borrow_position_root(),
                "private_borrower_commitment_root": self.private_borrower_commitment_root(),
                "health_bucket_root": self.health_bucket_root(),
            })],
        )
    }

    pub fn liquidation_surface_root(&self) -> String {
        merkle_root(
            "LENDING-LIQUIDATION-SURFACE",
            &[json!({
                "liquidation_auction_root": self.liquidation_auction_root(),
                "liquidation_bid_root": self.liquidation_bid_root(),
                "liquidation_sponsorship_root": self.liquidation_sponsorship_root(),
                "open_liquidation_auction_count": self.open_liquidation_auction_count(),
            })],
        )
    }

    pub fn accounting_surface_root(&self) -> String {
        merkle_root(
            "LENDING-ACCOUNTING-SURFACE",
            &[json!({
                "interest_snapshot_root": self.interest_snapshot_root(),
                "reserve_fund_root": self.reserve_fund_root(),
                "protocol_fee_ledger_root": self.protocol_fee_ledger_root(),
                "protocol_fee_accrual_root": self.protocol_fee_accrual_root(),
                "bad_debt_root": self.bad_debt_root(),
                "socialized_loss_root": self.socialized_loss_root(),
            })],
        )
    }

    pub fn risk_surface_root(&self) -> String {
        merkle_root(
            "LENDING-RISK-SURFACE",
            &[json!({
                "oracle_guard_root": self.oracle_guard_root(),
                "health_bucket_root": self.health_bucket_root(),
                "bad_debt_root": self.bad_debt_root(),
                "risk_tier_root": self.risk_tier_root(),
                "worst_health_bucket": self.worst_health_bucket().as_str(),
            })],
        )
    }

    pub fn privacy_surface_root(&self) -> String {
        merkle_root(
            "LENDING-PRIVACY-SURFACE",
            &[json!({
                "private_borrower_commitment_root": self.private_borrower_commitment_root(),
                "health_bucket_root": self.health_bucket_root(),
                "health_bucket_proof_system": self.config.health_bucket_proof_system,
                "private_borrow_proof_system": self.config.private_borrow_proof_system,
            })],
        )
    }

    pub fn state_root(&self) -> String {
        lending_market_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("lending market state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "lending_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": LENDING_MARKET_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "market_ids": self.market_ids(),
            "risk_tier_ids": self.risk_tier_ids(),
            "collateral_market_root": self.collateral_market_root(),
            "collateral_rule_root": self.collateral_rule_root(),
            "interest_model_root": self.interest_model_root(),
            "interest_snapshot_root": self.interest_snapshot_root(),
            "private_borrower_commitment_root": self.private_borrower_commitment_root(),
            "supply_position_root": self.supply_position_root(),
            "borrow_position_root": self.borrow_position_root(),
            "oracle_guard_root": self.oracle_guard_root(),
            "risk_tier_root": self.risk_tier_root(),
            "liquidation_auction_root": self.liquidation_auction_root(),
            "liquidation_bid_root": self.liquidation_bid_root(),
            "liquidation_sponsorship_root": self.liquidation_sponsorship_root(),
            "health_bucket_root": self.health_bucket_root(),
            "bad_debt_root": self.bad_debt_root(),
            "socialized_loss_root": self.socialized_loss_root(),
            "reserve_fund_root": self.reserve_fund_root(),
            "protocol_fee_ledger_root": self.protocol_fee_ledger_root(),
            "protocol_fee_accrual_root": self.protocol_fee_accrual_root(),
            "market_surface_root": self.market_surface_root(),
            "position_surface_root": self.position_surface_root(),
            "liquidation_surface_root": self.liquidation_surface_root(),
            "accounting_surface_root": self.accounting_surface_root(),
            "risk_surface_root": self.risk_surface_root(),
            "privacy_surface_root": self.privacy_surface_root(),
            "market_count": self.markets.len() as u64,
            "active_market_count": self.active_market_count(),
            "collateral_rule_count": self.collateral_rules.len() as u64,
            "interest_model_count": self.interest_models.len() as u64,
            "interest_snapshot_count": self.interest_snapshots.len() as u64,
            "private_borrower_commitment_count": self.private_borrower_commitments.len() as u64,
            "supply_position_count": self.supply_positions.len() as u64,
            "active_supply_position_count": self.active_supply_position_count(),
            "borrow_position_count": self.borrow_positions.len() as u64,
            "active_borrow_position_count": self.active_borrow_position_count(),
            "oracle_guard_count": self.oracle_guards.len() as u64,
            "risk_tier_count": self.risk_tiers.len() as u64,
            "liquidation_auction_count": self.liquidation_auctions.len() as u64,
            "open_liquidation_auction_count": self.open_liquidation_auction_count(),
            "liquidation_bid_count": self.liquidation_bids.len() as u64,
            "liquidation_sponsorship_count": self.liquidation_sponsorships.len() as u64,
            "health_bucket_count": self.health_buckets.len() as u64,
            "bad_debt_count": self.bad_debts.len() as u64,
            "socialized_loss_count": self.socialized_losses.len() as u64,
            "reserve_fund_count": self.reserve_funds.len() as u64,
            "fee_ledger_count": self.fee_ledgers.len() as u64,
            "fee_accrual_count": self.fee_accruals.len() as u64,
            "total_supplied_units": self.total_supplied_units(),
            "total_borrowed_principal_units": self.total_borrowed_principal_units(),
            "total_available_liquidity_units": self.total_available_liquidity_units(),
            "aggregate_utilization_bps": self.aggregate_utilization_bps(),
            "total_reserve_units": self.total_reserve_units(),
            "total_protocol_fee_pending_units": self.total_protocol_fee_pending_units(),
            "total_bad_debt_outstanding_units": self.total_bad_debt_outstanding_units(),
            "liquidatable_position_count": self.liquidatable_position_count(),
            "worst_health_bucket": self.worst_health_bucket().as_str(),
            "status": lending_status_from_bucket(self.worst_health_bucket()),
        })
    }

    fn oracle_guard_root_for_market(&self, market_id: &str) -> String {
        merkle_root(
            "LENDING-ORACLE-GUARD-MARKET",
            &self
                .oracle_guards
                .values()
                .filter(|guard| guard.market_id == market_id)
                .map(LendingOracleGuard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn supply_position_root_for_market(&self, market_id: &str) -> String {
        merkle_root(
            "LENDING-SUPPLY-POSITION-MARKET",
            &self
                .supply_positions
                .values()
                .filter(|position| position.market_id == market_id)
                .map(LendingSupplyPosition::public_record)
                .collect::<Vec<_>>(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn lending_risk_tier_id(
    risk_tier: LendingRiskTier,
    collateral_factor_bps: u64,
    liquidation_threshold_bps: u64,
    liquidation_bonus_bps: u64,
    reserve_factor_bps: u64,
    protocol_fee_bps: u64,
    close_factor_bps: u64,
    borrow_cap_units: u64,
    min_collateral_value_units: u64,
    isolation_mode: bool,
    private_borrow_required: bool,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-RISK-TIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(risk_tier.as_str()),
            HashPart::Int(collateral_factor_bps as i128),
            HashPart::Int(liquidation_threshold_bps as i128),
            HashPart::Int(liquidation_bonus_bps as i128),
            HashPart::Int(reserve_factor_bps as i128),
            HashPart::Int(protocol_fee_bps as i128),
            HashPart::Int(close_factor_bps as i128),
            HashPart::Int(borrow_cap_units as i128),
            HashPart::Int(min_collateral_value_units as i128),
            HashPart::Int(isolation_mode as i128),
            HashPart::Int(private_borrow_required as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_collateral_market_id(
    market_label: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    share_asset_id: &str,
    risk_tier: LendingRiskTier,
    supply_cap_units: u64,
    borrow_cap_units: u64,
    oracle_feed_id: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-COLLATERAL-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_label),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(share_asset_id),
            HashPart::Str(risk_tier.as_str()),
            HashPart::Int(supply_cap_units as i128),
            HashPart::Int(borrow_cap_units as i128),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_collateral_rule_id(
    market_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    risk_tier: LendingRiskTier,
    collateral_factor_bps: u64,
    liquidation_threshold_bps: u64,
    liquidation_bonus_bps: u64,
    protocol_fee_bps: u64,
    reserve_factor_bps: u64,
    close_factor_bps: u64,
    min_collateral_value_units: u64,
    max_position_debt_units: u64,
    isolated_debt_cap_units: u64,
    oracle_feed_id: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-COLLATERAL-RULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(risk_tier.as_str()),
            HashPart::Int(collateral_factor_bps as i128),
            HashPart::Int(liquidation_threshold_bps as i128),
            HashPart::Int(liquidation_bonus_bps as i128),
            HashPart::Int(protocol_fee_bps as i128),
            HashPart::Int(reserve_factor_bps as i128),
            HashPart::Int(close_factor_bps as i128),
            HashPart::Int(min_collateral_value_units as i128),
            HashPart::Int(max_position_debt_units as i128),
            HashPart::Int(isolated_debt_cap_units as i128),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_interest_curve_id(
    market_id: &str,
    curve_kind: InterestCurveKind,
    base_rate_bps: u64,
    kink_utilization_bps: u64,
    jump_utilization_bps: u64,
    slope1_bps: u64,
    slope2_bps: u64,
    slope3_bps: u64,
    reserve_factor_bps: u64,
    protocol_fee_bps: u64,
    min_borrow_rate_bps: u64,
    max_borrow_rate_bps: u64,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-INTEREST-CURVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(curve_kind.as_str()),
            HashPart::Int(base_rate_bps as i128),
            HashPart::Int(kink_utilization_bps as i128),
            HashPart::Int(jump_utilization_bps as i128),
            HashPart::Int(slope1_bps as i128),
            HashPart::Int(slope2_bps as i128),
            HashPart::Int(slope3_bps as i128),
            HashPart::Int(reserve_factor_bps as i128),
            HashPart::Int(protocol_fee_bps as i128),
            HashPart::Int(min_borrow_rate_bps as i128),
            HashPart::Int(max_borrow_rate_bps as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_interest_index_snapshot_id(
    market_id: &str,
    height: u64,
    supply_index: u64,
    borrow_index: u64,
    total_supplied_units: u64,
    total_borrowed_principal_units: u64,
    previous_snapshot_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-INTEREST-INDEX-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Int(height as i128),
            HashPart::Int(supply_index as i128),
            HashPart::Int(borrow_index as i128),
            HashPart::Int(total_supplied_units as i128),
            HashPart::Int(total_borrowed_principal_units as i128),
            HashPart::Str(previous_snapshot_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_borrower_commitment_id(
    market_id: &str,
    borrower_commitment: &str,
    spend_nullifier_hash: &str,
    public_input_root: &str,
    quantum_auth_root: &str,
    created_at_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-PRIVATE-BORROWER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(borrower_commitment),
            HashPart::Str(spend_nullifier_hash),
            HashPart::Str(public_input_root),
            HashPart::Str(quantum_auth_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_supply_position_id(
    market_id: &str,
    supplier_commitment: &str,
    asset_id: &str,
    supplied_units: u64,
    scaled_supply_units: u64,
    opened_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-SUPPLY-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(supplier_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(supplied_units as i128),
            HashPart::Int(scaled_supply_units as i128),
            HashPart::Int(opened_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_borrow_position_id(
    market_id: &str,
    borrower_commitment: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    collateral_units: u64,
    debt_principal_units: u64,
    scaled_debt_units: u64,
    opened_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-BORROW-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(borrower_commitment),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Int(collateral_units as i128),
            HashPart::Int(debt_principal_units as i128),
            HashPart::Int(scaled_debt_units as i128),
            HashPart::Int(opened_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_oracle_guard_id(
    market_id: &str,
    oracle_feed_id: &str,
    reference_price: u64,
    spot_price: u64,
    twap_price: u64,
    median_price: u64,
    observed_at_height: u64,
    created_at_height: u64,
    source_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-ORACLE-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(reference_price as i128),
            HashPart::Int(spot_price as i128),
            HashPart::Int(twap_price as i128),
            HashPart::Int(median_price as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(source_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_health_bucket_id(
    market_id: &str,
    bucket: HealthFactorBucket,
    snapshot_height: u64,
    position_count: u64,
    debt_units: u64,
    commitment_root: &str,
    public_input_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-HEALTH-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(bucket.as_str()),
            HashPart::Int(snapshot_height as i128),
            HashPart::Int(position_count as i128),
            HashPart::Int(debt_units as i128),
            HashPart::Str(commitment_root),
            HashPart::Str(public_input_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_liquidation_auction_id(
    market_id: &str,
    position_id: &str,
    borrower_commitment: &str,
    collateral_units: u64,
    debt_to_cover_units: u64,
    start_price_units: u64,
    floor_price_units: u64,
    start_height: u64,
    ttl_blocks: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-LIQUIDATION-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(borrower_commitment),
            HashPart::Int(collateral_units as i128),
            HashPart::Int(debt_to_cover_units as i128),
            HashPart::Int(start_price_units as i128),
            HashPart::Int(floor_price_units as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(ttl_blocks as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_liquidation_bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    repay_units: u64,
    max_collateral_price_units: u64,
    requested_sponsorship_units: u64,
    submitted_height: u64,
    nonce: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-LIQUIDATION-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Int(repay_units as i128),
            HashPart::Int(max_collateral_price_units as i128),
            HashPart::Int(requested_sponsorship_units as i128),
            HashPart::Int(submitted_height as i128),
            HashPart::Int(nonce as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_sponsorship_id(
    auction_id: &str,
    market_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    reserved_fee_units: u64,
    max_rebate_bps: u64,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-LIQUIDATION-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(market_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(reserved_fee_units as i128),
            HashPart::Int(max_rebate_bps as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_reserve_fund_id(
    market_id: &str,
    asset_id: &str,
    target_units: u64,
    initial_units: u64,
    controller_commitment: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-RESERVE-FUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
            HashPart::Int(target_units as i128),
            HashPart::Int(initial_units as i128),
            HashPart::Str(controller_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_bad_debt_id(
    market_id: &str,
    position_id: &str,
    borrower_commitment: &str,
    principal_units: u64,
    interest_units: u64,
    penalty_units: u64,
    discovered_at_height: u64,
    liquidation_auction_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-BAD-DEBT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(borrower_commitment),
            HashPart::Int(principal_units as i128),
            HashPart::Int(interest_units as i128),
            HashPart::Int(penalty_units as i128),
            HashPart::Int(discovered_at_height as i128),
            HashPart::Str(liquidation_auction_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_socialized_loss_id(
    market_id: &str,
    debt_asset_id: &str,
    bad_debt_id: &str,
    loss_units: u64,
    per_supply_share_index_delta: u64,
    affected_supply_root: &str,
    applied_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-SOCIALIZED-LOSS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(bad_debt_id),
            HashPart::Int(loss_units as i128),
            HashPart::Int(per_supply_share_index_delta as i128),
            HashPart::Str(affected_supply_root),
            HashPart::Int(applied_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn lending_fee_ledger_id(
    market_id: &str,
    asset_id: &str,
    recipient_commitment: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-PROTOCOL-FEE-LEDGER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
            HashPart::Str(recipient_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lending_fee_accrual_id(
    market_id: &str,
    position_id: &str,
    asset_id: &str,
    event_kind: ProtocolFeeEventKind,
    gross_units: u64,
    reserve_units: u64,
    protocol_fee_units: u64,
    keeper_reward_units: u64,
    low_fee_rebate_units: u64,
    height: u64,
    ledger_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "LENDING-PROTOCOL-FEE-ACCRUAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(asset_id),
            HashPart::Str(event_kind.as_str()),
            HashPart::Int(gross_units as i128),
            HashPart::Int(reserve_units as i128),
            HashPart::Int(protocol_fee_units as i128),
            HashPart::Int(keeper_reward_units as i128),
            HashPart::Int(low_fee_rebate_units as i128),
            HashPart::Int(height as i128),
            HashPart::Str(ledger_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn lending_account_commitment(label: &str) -> String {
    domain_hash(
        "LENDING-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn lending_market_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn lending_market_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn lending_market_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn lending_market_state_root_from_record(record: &Value) -> String {
    lending_market_payload_root("LENDING-MARKET-STATE-ROOT", record)
}

pub fn lending_status_from_bucket(bucket: HealthFactorBucket) -> &'static str {
    match bucket {
        HealthFactorBucket::NoDebt | HealthFactorBucket::Healthy => "healthy",
        HealthFactorBucket::Watch => "watch",
        HealthFactorBucket::Unsafe => "unsafe",
        HealthFactorBucket::Liquidatable => "liquidatable",
        HealthFactorBucket::Insolvent => "insolvent",
    }
}

pub fn value_units(amount_units: u64, price_units: u64) -> u64 {
    mul_div_floor(amount_units, price_units, LENDING_MARKET_PRICE_SCALE)
}

pub fn health_factor_bps(liquidation_collateral_value_units: u64, debt_value_units: u64) -> u64 {
    if debt_value_units == 0 {
        return u64::MAX;
    }
    ratio_bps(liquidation_collateral_value_units, debt_value_units)
}

pub fn annualized_bps_accrual(base_units: u64, rate_bps: u64, blocks: u64) -> u64 {
    let numerator = (rate_bps as u128).saturating_mul(blocks as u128);
    let denominator =
        (LENDING_MARKET_MAX_BPS as u128).saturating_mul(LENDING_MARKET_BLOCKS_PER_YEAR as u128);
    let value = (base_units as u128).saturating_mul(numerator) / denominator.max(1);
    value.min(u64::MAX as u128) as u64
}

pub fn bps_mul_floor(units: u64, bps: u64) -> u64 {
    mul_div_floor(units, bps, LENDING_MARKET_MAX_BPS)
}

pub fn bps_mul_ceil(units: u64, bps: u64) -> u64 {
    mul_div_ceil(units, bps, LENDING_MARKET_MAX_BPS)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    mul_div_floor(numerator, LENDING_MARKET_MAX_BPS, denominator)
}

pub fn deviation_bps(value: u64, reference: u64) -> u64 {
    if reference == 0 {
        return u64::MAX;
    }
    let delta = value.max(reference).saturating_sub(value.min(reference));
    ratio_bps(delta, reference)
}

pub fn mul_div_floor(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let result = (value as u128).saturating_mul(multiplier as u128) / denominator as u128;
    result.min(u64::MAX as u128) as u64
}

pub fn mul_div_ceil(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let numerator = (value as u128).saturating_mul(multiplier as u128);
    let denominator = denominator as u128;
    let result = numerator.saturating_add(denominator.saturating_sub(1)) / denominator;
    result.min(u64::MAX as u128) as u64
}

pub fn validate_bps(label: &str, value: u64) -> LendingMarketResult<()> {
    if value > LENDING_MARKET_MAX_BPS {
        return Err(format!("{label} exceeds max basis points"));
    }
    Ok(())
}

pub fn ensure_non_empty(value: &str, label: &str) -> LendingMarketResult<()> {
    if value.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(())
}
