use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const DEFI_RISK_PROTOCOL_VERSION: &str = "nebula-defi-risk-v1";
pub const DEFI_RISK_MAX_BPS: u64 = 10_000;
pub const DEFI_RISK_DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 750;
pub const DEFI_RISK_DEFAULT_MAX_TWAP_DEVIATION_BPS: u64 = 500;
pub const DEFI_RISK_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const DEFI_RISK_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 40;
pub const DEFI_RISK_DEFAULT_ASSESSMENT_TTL_BLOCKS: u64 = 32;
pub const DEFI_RISK_DEFAULT_CIRCUIT_COOLDOWN_BLOCKS: u64 = 20;
pub const DEFI_RISK_LOW_FEE_LIQUIDATION_LANE: &str = "small-defi-liquidations";
pub const DEFI_RISK_PRICE_SCALE: u64 = 1_000_000_000_000;

pub type DefiRiskResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DefiRiskSeverity {
    Healthy,
    Watch,
    Warn,
    Critical,
}

impl DefiRiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Healthy => 0,
            Self::Watch => 2_500,
            Self::Warn => 6_000,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DefiCircuitScope {
    Global,
    Market,
    Pool,
    Oracle,
    Liquidation,
    InsuranceFund,
    LowFeeSponsor,
    Custom(String),
}

impl DefiCircuitScope {
    pub fn as_str(&self) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::Market => "market".to_string(),
            Self::Pool => "pool".to_string(),
            Self::Oracle => "oracle".to_string(),
            Self::Liquidation => "liquidation".to_string(),
            Self::InsuranceFund => "insurance_fund".to_string(),
            Self::LowFeeSponsor => "low_fee_sponsor".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DefiCircuitStatus {
    Closed,
    Watching,
    Open,
    CoolingDown,
    Retired,
}

impl DefiCircuitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Watching => "watching",
            Self::Open => "open",
            Self::CoolingDown => "cooling_down",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OracleGuardAction {
    Allow,
    Watch,
    BlockLiquidation,
    FreezeMarket,
}

impl OracleGuardAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Watch => "watch",
            Self::BlockLiquidation => "block_liquidation",
            Self::FreezeMarket => "freeze_market",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InsuranceFundStatus {
    Active,
    Draining,
    Paused,
    Exhausted,
    Retired,
}

impl InsuranceFundStatus {
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UtilizationCurveKind {
    Linear,
    Kinked,
    Jump,
    Stable,
}

impl UtilizationCurveKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::Kinked => "kinked",
            Self::Jump => "jump",
            Self::Stable => "stable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingCollateralFactor {
    pub factor_id: String,
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub protocol_fee_bps: u64,
    pub reserve_factor_bps: u64,
    pub close_factor_bps: u64,
    pub min_collateral_value_units: u64,
    pub max_debt_units: u64,
    pub oracle_feed_id: String,
    pub created_at_height: u64,
    pub active: bool,
    pub metadata_root: String,
}

impl LendingCollateralFactor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        liquidation_bonus_bps: u64,
        protocol_fee_bps: u64,
        reserve_factor_bps: u64,
        close_factor_bps: u64,
        min_collateral_value_units: u64,
        max_debt_units: u64,
        oracle_feed_id: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> DefiRiskResult<Self> {
        let metadata_root =
            defi_risk_payload_root("DEFI-RISK-COLLATERAL-FACTOR-METADATA", metadata);
        let factor_id = defi_risk_collateral_factor_id(
            market_id,
            collateral_asset_id,
            debt_asset_id,
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            protocol_fee_bps,
            reserve_factor_bps,
            close_factor_bps,
            min_collateral_value_units,
            max_debt_units,
            oracle_feed_id,
            created_at_height,
            &metadata_root,
        );
        let factor = Self {
            factor_id,
            market_id: market_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            collateral_factor_bps,
            liquidation_threshold_bps,
            liquidation_bonus_bps,
            protocol_fee_bps,
            reserve_factor_bps,
            close_factor_bps,
            min_collateral_value_units,
            max_debt_units,
            oracle_feed_id: oracle_feed_id.to_string(),
            created_at_height,
            active: true,
            metadata_root,
        };
        factor.validate()?;
        Ok(factor)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.market_id, "collateral factor market_id")?;
        ensure_non_empty(
            &self.collateral_asset_id,
            "collateral factor collateral_asset_id",
        )?;
        ensure_non_empty(&self.debt_asset_id, "collateral factor debt_asset_id")?;
        ensure_non_empty(&self.oracle_feed_id, "collateral factor oracle_feed_id")?;
        if self.collateral_asset_id == self.debt_asset_id {
            return Err("collateral factor assets must be distinct".to_string());
        }
        ensure_bps(self.collateral_factor_bps, "collateral_factor_bps")?;
        ensure_bps(self.liquidation_threshold_bps, "liquidation_threshold_bps")?;
        ensure_bps(self.reserve_factor_bps, "reserve_factor_bps")?;
        ensure_bps(self.close_factor_bps, "close_factor_bps")?;
        if self.collateral_factor_bps > self.liquidation_threshold_bps {
            return Err("collateral factor cannot exceed liquidation threshold".to_string());
        }
        if self.protocol_fee_bps > self.liquidation_bonus_bps {
            return Err("protocol fee cannot exceed liquidation bonus".to_string());
        }
        if self.factor_id
            != defi_risk_collateral_factor_id(
                &self.market_id,
                &self.collateral_asset_id,
                &self.debt_asset_id,
                self.collateral_factor_bps,
                self.liquidation_threshold_bps,
                self.liquidation_bonus_bps,
                self.protocol_fee_bps,
                self.reserve_factor_bps,
                self.close_factor_bps,
                self.min_collateral_value_units,
                self.max_debt_units,
                &self.oracle_feed_id,
                self.created_at_height,
                &self.metadata_root,
            )
        {
            return Err("collateral factor id mismatch".to_string());
        }
        Ok(())
    }

    pub fn max_borrow_value_units(&self, collateral_value_units: u64) -> u64 {
        mul_bps(collateral_value_units, self.collateral_factor_bps)
    }

    pub fn liquidation_threshold_value_units(&self, collateral_value_units: u64) -> u64 {
        mul_bps(collateral_value_units, self.liquidation_threshold_bps)
    }

    pub fn liquidation_bonus_units(&self, repay_value_units: u64) -> u64 {
        mul_bps(repay_value_units, self.liquidation_bonus_bps)
    }

    pub fn health_factor_bps(&self, collateral_value_units: u64, debt_value_units: u64) -> u64 {
        if debt_value_units == 0 {
            return u64::MAX;
        }
        ratio_bps_unbounded(
            self.liquidation_threshold_value_units(collateral_value_units),
            debt_value_units,
        )
    }

    pub fn is_liquidatable(&self, collateral_value_units: u64, debt_value_units: u64) -> bool {
        debt_value_units > self.liquidation_threshold_value_units(collateral_value_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_collateral_factor",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "factor_id": self.factor_id,
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "close_factor_bps": self.close_factor_bps,
            "min_collateral_value_units": self.min_collateral_value_units,
            "max_debt_units": self.max_debt_units,
            "oracle_feed_id": self.oracle_feed_id,
            "created_at_height": self.created_at_height,
            "active": self.active,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtilizationCurve {
    pub curve_id: String,
    pub market_id: String,
    pub curve_kind: UtilizationCurveKind,
    pub base_rate_bps: u64,
    pub kink_utilization_bps: u64,
    pub target_utilization_bps: u64,
    pub slope1_bps: u64,
    pub slope2_bps: u64,
    pub reserve_factor_bps: u64,
    pub max_borrow_rate_bps: u64,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl UtilizationCurve {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        curve_kind: UtilizationCurveKind,
        base_rate_bps: u64,
        kink_utilization_bps: u64,
        target_utilization_bps: u64,
        slope1_bps: u64,
        slope2_bps: u64,
        reserve_factor_bps: u64,
        max_borrow_rate_bps: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> DefiRiskResult<Self> {
        let metadata_root =
            defi_risk_payload_root("DEFI-RISK-UTILIZATION-CURVE-METADATA", metadata);
        let curve_id = defi_risk_utilization_curve_id(
            market_id,
            &curve_kind,
            base_rate_bps,
            kink_utilization_bps,
            target_utilization_bps,
            slope1_bps,
            slope2_bps,
            reserve_factor_bps,
            max_borrow_rate_bps,
            created_at_height,
            &metadata_root,
        );
        let curve = Self {
            curve_id,
            market_id: market_id.to_string(),
            curve_kind,
            base_rate_bps,
            kink_utilization_bps,
            target_utilization_bps,
            slope1_bps,
            slope2_bps,
            reserve_factor_bps,
            max_borrow_rate_bps,
            created_at_height,
            metadata_root,
        };
        curve.validate()?;
        Ok(curve)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.market_id, "utilization curve market_id")?;
        ensure_bps(self.kink_utilization_bps, "kink_utilization_bps")?;
        ensure_bps(self.target_utilization_bps, "target_utilization_bps")?;
        ensure_bps(self.reserve_factor_bps, "reserve_factor_bps")?;
        if self.max_borrow_rate_bps < self.base_rate_bps {
            return Err("max borrow rate cannot be lower than base rate".to_string());
        }
        if matches!(
            &self.curve_kind,
            UtilizationCurveKind::Kinked | UtilizationCurveKind::Jump
        ) && self.kink_utilization_bps == 0
        {
            return Err("kinked utilization curve requires a positive kink".to_string());
        }
        if matches!(&self.curve_kind, UtilizationCurveKind::Stable)
            && self.target_utilization_bps == 0
        {
            return Err("stable utilization curve requires a positive target".to_string());
        }
        if self.curve_id
            != defi_risk_utilization_curve_id(
                &self.market_id,
                &self.curve_kind,
                self.base_rate_bps,
                self.kink_utilization_bps,
                self.target_utilization_bps,
                self.slope1_bps,
                self.slope2_bps,
                self.reserve_factor_bps,
                self.max_borrow_rate_bps,
                self.created_at_height,
                &self.metadata_root,
            )
        {
            return Err("utilization curve id mismatch".to_string());
        }
        Ok(())
    }

    pub fn utilization_bps(
        &self,
        cash_units: u64,
        borrowed_units: u64,
        reserved_units: u64,
    ) -> u64 {
        if borrowed_units == 0 {
            return 0;
        }
        let supplied_units = cash_units
            .saturating_add(borrowed_units)
            .saturating_sub(reserved_units);
        ratio_bps(borrowed_units, supplied_units.max(1))
    }

    pub fn borrow_rate_bps(
        &self,
        cash_units: u64,
        borrowed_units: u64,
        reserved_units: u64,
    ) -> u64 {
        let utilization_bps = self.utilization_bps(cash_units, borrowed_units, reserved_units);
        let rate = match &self.curve_kind {
            UtilizationCurveKind::Linear => self
                .base_rate_bps
                .saturating_add(mul_bps(self.slope1_bps, utilization_bps)),
            UtilizationCurveKind::Kinked | UtilizationCurveKind::Jump => {
                if utilization_bps <= self.kink_utilization_bps {
                    self.base_rate_bps.saturating_add(proportional(
                        self.slope1_bps,
                        utilization_bps,
                        self.kink_utilization_bps.max(1),
                    ))
                } else {
                    let below_kink = self.base_rate_bps.saturating_add(self.slope1_bps);
                    below_kink.saturating_add(proportional(
                        self.slope2_bps,
                        utilization_bps.saturating_sub(self.kink_utilization_bps),
                        DEFI_RISK_MAX_BPS
                            .saturating_sub(self.kink_utilization_bps)
                            .max(1),
                    ))
                }
            }
            UtilizationCurveKind::Stable => {
                if utilization_bps <= self.target_utilization_bps {
                    self.base_rate_bps.saturating_add(proportional(
                        self.slope1_bps,
                        utilization_bps,
                        self.target_utilization_bps.max(1),
                    ))
                } else {
                    let below_target = self.base_rate_bps.saturating_add(self.slope1_bps);
                    below_target.saturating_add(proportional(
                        self.slope2_bps,
                        utilization_bps.saturating_sub(self.target_utilization_bps),
                        DEFI_RISK_MAX_BPS
                            .saturating_sub(self.target_utilization_bps)
                            .max(1),
                    ))
                }
            }
        };
        rate.min(self.max_borrow_rate_bps)
    }

    pub fn supply_rate_bps(
        &self,
        cash_units: u64,
        borrowed_units: u64,
        reserved_units: u64,
    ) -> u64 {
        let utilization_bps = self.utilization_bps(cash_units, borrowed_units, reserved_units);
        let gross_supply_rate = mul_bps(
            self.borrow_rate_bps(cash_units, borrowed_units, reserved_units),
            utilization_bps,
        );
        mul_bps(
            gross_supply_rate,
            DEFI_RISK_MAX_BPS.saturating_sub(self.reserve_factor_bps),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "utilization_curve",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "curve_id": self.curve_id,
            "market_id": self.market_id,
            "curve_kind": self.curve_kind.as_str(),
            "base_rate_bps": self.base_rate_bps,
            "kink_utilization_bps": self.kink_utilization_bps,
            "target_utilization_bps": self.target_utilization_bps,
            "slope1_bps": self.slope1_bps,
            "slope2_bps": self.slope2_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "max_borrow_rate_bps": self.max_borrow_rate_bps,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmPoolRisk {
    pub pool_risk_id: String,
    pub pool_id: String,
    pub market_id: String,
    pub asset_a_id: String,
    pub asset_b_id: String,
    pub reserve_a_units: u64,
    pub reserve_b_units: u64,
    pub spot_price: u64,
    pub twap_price: u64,
    pub oracle_price: u64,
    pub max_price_impact_bps: u64,
    pub max_inventory_skew_bps: u64,
    pub min_liquidity_units: u64,
    pub fee_bps: u64,
    pub volatility_bps: u64,
    pub assessed_at_height: u64,
    pub severity: DefiRiskSeverity,
    pub metadata_root: String,
}

impl AmmPoolRisk {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        market_id: &str,
        asset_a_id: &str,
        asset_b_id: &str,
        reserve_a_units: u64,
        reserve_b_units: u64,
        spot_price: u64,
        twap_price: u64,
        oracle_price: u64,
        max_price_impact_bps: u64,
        max_inventory_skew_bps: u64,
        min_liquidity_units: u64,
        fee_bps: u64,
        volatility_bps: u64,
        assessed_at_height: u64,
        metadata: &Value,
    ) -> DefiRiskResult<Self> {
        let metadata_root = defi_risk_payload_root("DEFI-RISK-AMM-POOL-METADATA", metadata);
        let severity = severity_from_score(amm_pool_risk_score_bps(
            reserve_a_units,
            reserve_b_units,
            spot_price,
            twap_price,
            oracle_price,
            max_inventory_skew_bps,
            min_liquidity_units,
            volatility_bps,
        ));
        let pool_risk_id = defi_risk_amm_pool_risk_id(
            pool_id,
            market_id,
            asset_a_id,
            asset_b_id,
            reserve_a_units,
            reserve_b_units,
            spot_price,
            twap_price,
            oracle_price,
            max_price_impact_bps,
            max_inventory_skew_bps,
            min_liquidity_units,
            fee_bps,
            volatility_bps,
            assessed_at_height,
            &metadata_root,
        );
        let risk = Self {
            pool_risk_id,
            pool_id: pool_id.to_string(),
            market_id: market_id.to_string(),
            asset_a_id: asset_a_id.to_string(),
            asset_b_id: asset_b_id.to_string(),
            reserve_a_units,
            reserve_b_units,
            spot_price,
            twap_price,
            oracle_price,
            max_price_impact_bps,
            max_inventory_skew_bps,
            min_liquidity_units,
            fee_bps,
            volatility_bps,
            assessed_at_height,
            severity,
            metadata_root,
        };
        risk.validate()?;
        Ok(risk)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.pool_id, "amm pool_id")?;
        ensure_non_empty(&self.market_id, "amm market_id")?;
        ensure_non_empty(&self.asset_a_id, "amm asset_a_id")?;
        ensure_non_empty(&self.asset_b_id, "amm asset_b_id")?;
        if self.asset_a_id == self.asset_b_id {
            return Err("amm pool assets must be distinct".to_string());
        }
        ensure_bps(self.max_price_impact_bps, "max_price_impact_bps")?;
        ensure_bps(self.max_inventory_skew_bps, "max_inventory_skew_bps")?;
        ensure_bps(self.fee_bps, "fee_bps")?;
        ensure_bps(self.volatility_bps, "volatility_bps")?;
        if self.pool_risk_id
            != defi_risk_amm_pool_risk_id(
                &self.pool_id,
                &self.market_id,
                &self.asset_a_id,
                &self.asset_b_id,
                self.reserve_a_units,
                self.reserve_b_units,
                self.spot_price,
                self.twap_price,
                self.oracle_price,
                self.max_price_impact_bps,
                self.max_inventory_skew_bps,
                self.min_liquidity_units,
                self.fee_bps,
                self.volatility_bps,
                self.assessed_at_height,
                &self.metadata_root,
            )
        {
            return Err("amm pool risk id mismatch".to_string());
        }
        Ok(())
    }

    pub fn liquidity_units(&self) -> u64 {
        self.reserve_a_units.min(self.reserve_b_units)
    }

    pub fn inventory_skew_bps(&self) -> u64 {
        let larger = self.reserve_a_units.max(self.reserve_b_units);
        let smaller = self.reserve_a_units.min(self.reserve_b_units);
        ratio_bps(
            larger.saturating_sub(smaller),
            larger.saturating_add(smaller).max(1),
        )
    }

    pub fn spot_twap_deviation_bps(&self) -> u64 {
        price_deviation_bps(self.spot_price, self.twap_price)
    }

    pub fn oracle_deviation_bps(&self) -> u64 {
        price_deviation_bps(self.spot_price, self.oracle_price)
    }

    pub fn price_impact_bps(&self, input_units: u64, reserve_in_units: u64) -> u64 {
        ratio_bps(
            input_units,
            reserve_in_units.saturating_add(input_units).max(1),
        )
    }

    pub fn risk_score_bps(&self) -> u64 {
        amm_pool_risk_score_bps(
            self.reserve_a_units,
            self.reserve_b_units,
            self.spot_price,
            self.twap_price,
            self.oracle_price,
            self.max_inventory_skew_bps,
            self.min_liquidity_units,
            self.volatility_bps,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "amm_pool_risk",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "pool_risk_id": self.pool_risk_id,
            "pool_id": self.pool_id,
            "market_id": self.market_id,
            "asset_a_id": self.asset_a_id,
            "asset_b_id": self.asset_b_id,
            "reserve_a_units": self.reserve_a_units,
            "reserve_b_units": self.reserve_b_units,
            "spot_price": self.spot_price,
            "twap_price": self.twap_price,
            "oracle_price": self.oracle_price,
            "spot_twap_deviation_bps": self.spot_twap_deviation_bps(),
            "oracle_deviation_bps": self.oracle_deviation_bps(),
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_inventory_skew_bps": self.max_inventory_skew_bps,
            "inventory_skew_bps": self.inventory_skew_bps(),
            "min_liquidity_units": self.min_liquidity_units,
            "liquidity_units": self.liquidity_units(),
            "fee_bps": self.fee_bps,
            "volatility_bps": self.volatility_bps,
            "assessed_at_height": self.assessed_at_height,
            "severity": self.severity.as_str(),
            "risk_score_bps": self.risk_score_bps(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleDeviationGuard {
    pub guard_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub reference_price: u64,
    pub observed_price: u64,
    pub twap_price: u64,
    pub reference_deviation_bps: u64,
    pub twap_deviation_bps: u64,
    pub max_deviation_bps: u64,
    pub max_twap_deviation_bps: u64,
    pub max_staleness_blocks: u64,
    pub observed_at_height: u64,
    pub checked_at_height: u64,
    pub action: OracleGuardAction,
    pub allows_liquidation: bool,
    pub evidence_root: String,
}

impl OracleDeviationGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        feed_id: &str,
        reference_price: u64,
        observed_price: u64,
        twap_price: u64,
        max_deviation_bps: u64,
        max_twap_deviation_bps: u64,
        max_staleness_blocks: u64,
        observed_at_height: u64,
        checked_at_height: u64,
        evidence: &Value,
    ) -> DefiRiskResult<Self> {
        ensure_bps(max_deviation_bps, "max_deviation_bps")?;
        ensure_bps(max_twap_deviation_bps, "max_twap_deviation_bps")?;
        let reference_deviation_bps = price_deviation_bps(observed_price, reference_price);
        let twap_deviation_bps = price_deviation_bps(observed_price, twap_price);
        let stale = checked_at_height.saturating_sub(observed_at_height) > max_staleness_blocks;
        let action = oracle_guard_action(
            reference_deviation_bps,
            twap_deviation_bps,
            max_deviation_bps,
            max_twap_deviation_bps,
            stale,
        );
        let allows_liquidation =
            matches!(&action, OracleGuardAction::Allow | OracleGuardAction::Watch);
        let evidence_root = defi_risk_payload_root("DEFI-RISK-ORACLE-GUARD-EVIDENCE", evidence);
        let guard_id = defi_risk_oracle_deviation_guard_id(
            market_id,
            feed_id,
            reference_price,
            observed_price,
            twap_price,
            reference_deviation_bps,
            twap_deviation_bps,
            max_deviation_bps,
            max_twap_deviation_bps,
            max_staleness_blocks,
            observed_at_height,
            checked_at_height,
            &action,
            allows_liquidation,
            &evidence_root,
        );
        let guard = Self {
            guard_id,
            market_id: market_id.to_string(),
            feed_id: feed_id.to_string(),
            reference_price,
            observed_price,
            twap_price,
            reference_deviation_bps,
            twap_deviation_bps,
            max_deviation_bps,
            max_twap_deviation_bps,
            max_staleness_blocks,
            observed_at_height,
            checked_at_height,
            action,
            allows_liquidation,
            evidence_root,
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.market_id, "oracle guard market_id")?;
        ensure_non_empty(&self.feed_id, "oracle guard feed_id")?;
        ensure_bps(self.max_deviation_bps, "max_deviation_bps")?;
        ensure_bps(self.max_twap_deviation_bps, "max_twap_deviation_bps")?;
        if self.reference_deviation_bps
            != price_deviation_bps(self.observed_price, self.reference_price)
        {
            return Err("oracle guard reference deviation mismatch".to_string());
        }
        if self.twap_deviation_bps != price_deviation_bps(self.observed_price, self.twap_price) {
            return Err("oracle guard twap deviation mismatch".to_string());
        }
        if self.guard_id
            != defi_risk_oracle_deviation_guard_id(
                &self.market_id,
                &self.feed_id,
                self.reference_price,
                self.observed_price,
                self.twap_price,
                self.reference_deviation_bps,
                self.twap_deviation_bps,
                self.max_deviation_bps,
                self.max_twap_deviation_bps,
                self.max_staleness_blocks,
                self.observed_at_height,
                self.checked_at_height,
                &self.action,
                self.allows_liquidation,
                &self.evidence_root,
            )
        {
            return Err("oracle guard id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_stale(&self) -> bool {
        self.checked_at_height
            .saturating_sub(self.observed_at_height)
            > self.max_staleness_blocks
    }

    pub fn risk_score_bps(&self) -> u64 {
        if matches!(&self.action, OracleGuardAction::FreezeMarket) {
            return 10_000;
        }
        if matches!(&self.action, OracleGuardAction::BlockLiquidation) {
            return 8_000;
        }
        self.reference_deviation_bps
            .max(self.twap_deviation_bps)
            .min(10_000)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_deviation_guard",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "guard_id": self.guard_id,
            "market_id": self.market_id,
            "feed_id": self.feed_id,
            "reference_price": self.reference_price,
            "observed_price": self.observed_price,
            "twap_price": self.twap_price,
            "reference_deviation_bps": self.reference_deviation_bps,
            "twap_deviation_bps": self.twap_deviation_bps,
            "max_deviation_bps": self.max_deviation_bps,
            "max_twap_deviation_bps": self.max_twap_deviation_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "observed_at_height": self.observed_at_height,
            "checked_at_height": self.checked_at_height,
            "is_stale": self.is_stale(),
            "action": self.action.as_str(),
            "allows_liquidation": self.allows_liquidation,
            "risk_score_bps": self.risk_score_bps(),
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationAuction {
    pub auction_id: String,
    pub position_id: String,
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub borrower_commitment: String,
    pub collateral_amount: u64,
    pub debt_amount: u64,
    pub protected_price: u64,
    pub min_repay_units: u64,
    pub start_discount_bps: u64,
    pub max_discount_bps: u64,
    pub discount_step_bps: u64,
    pub lot_count: u64,
    pub started_at_height: u64,
    pub expires_at_height: u64,
    pub status: LiquidationAuctionStatus,
    pub oracle_guard_id: String,
    pub risk_commitment_id: String,
    pub winning_bid_commitment: String,
    pub settlement_root: String,
}

impl LiquidationAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        position_id: &str,
        market_id: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        borrower_commitment: &str,
        collateral_amount: u64,
        debt_amount: u64,
        protected_price: u64,
        min_repay_units: u64,
        start_discount_bps: u64,
        max_discount_bps: u64,
        discount_step_bps: u64,
        lot_count: u64,
        started_at_height: u64,
        ttl_blocks: u64,
        oracle_guard_id: &str,
        risk_commitment_id: &str,
    ) -> DefiRiskResult<Self> {
        ensure_bps(start_discount_bps, "start_discount_bps")?;
        ensure_bps(max_discount_bps, "max_discount_bps")?;
        let lot_count = lot_count.max(1);
        let expires_at_height = started_at_height.saturating_add(ttl_blocks.max(1));
        let auction_id = defi_risk_liquidation_auction_id(
            position_id,
            market_id,
            collateral_asset_id,
            debt_asset_id,
            borrower_commitment,
            collateral_amount,
            debt_amount,
            protected_price,
            min_repay_units,
            start_discount_bps,
            max_discount_bps,
            discount_step_bps,
            lot_count,
            started_at_height,
            expires_at_height,
            oracle_guard_id,
            risk_commitment_id,
        );
        let auction = Self {
            auction_id,
            position_id: position_id.to_string(),
            market_id: market_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            borrower_commitment: borrower_commitment.to_string(),
            collateral_amount,
            debt_amount,
            protected_price,
            min_repay_units,
            start_discount_bps,
            max_discount_bps,
            discount_step_bps,
            lot_count,
            started_at_height,
            expires_at_height,
            status: LiquidationAuctionStatus::Open,
            oracle_guard_id: oracle_guard_id.to_string(),
            risk_commitment_id: risk_commitment_id.to_string(),
            winning_bid_commitment: String::new(),
            settlement_root: defi_risk_payload_root(
                "DEFI-RISK-LIQUIDATION-AUCTION-UNSETTLED",
                &json!({"auction_id": "pending"}),
            ),
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.position_id, "auction position_id")?;
        ensure_non_empty(&self.market_id, "auction market_id")?;
        ensure_non_empty(&self.collateral_asset_id, "auction collateral_asset_id")?;
        ensure_non_empty(&self.debt_asset_id, "auction debt_asset_id")?;
        ensure_non_empty(&self.borrower_commitment, "auction borrower_commitment")?;
        ensure_bps(self.start_discount_bps, "start_discount_bps")?;
        ensure_bps(self.max_discount_bps, "max_discount_bps")?;
        if self.start_discount_bps > self.max_discount_bps {
            return Err("auction start discount cannot exceed max discount".to_string());
        }
        if self.expires_at_height <= self.started_at_height {
            return Err("auction expiration must be after start".to_string());
        }
        if self.auction_id
            != defi_risk_liquidation_auction_id(
                &self.position_id,
                &self.market_id,
                &self.collateral_asset_id,
                &self.debt_asset_id,
                &self.borrower_commitment,
                self.collateral_amount,
                self.debt_amount,
                self.protected_price,
                self.min_repay_units,
                self.start_discount_bps,
                self.max_discount_bps,
                self.discount_step_bps,
                self.lot_count,
                self.started_at_height,
                self.expires_at_height,
                &self.oracle_guard_id,
                &self.risk_commitment_id,
            )
        {
            return Err("liquidation auction id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_open(&self, height: u64) -> bool {
        matches!(&self.status, LiquidationAuctionStatus::Open)
            && height >= self.started_at_height
            && height <= self.expires_at_height
    }

    pub fn current_discount_bps(&self, height: u64) -> u64 {
        let elapsed = height.saturating_sub(self.started_at_height);
        self.start_discount_bps
            .saturating_add(elapsed.saturating_mul(self.discount_step_bps))
            .min(self.max_discount_bps)
    }

    pub fn protected_collateral_value_units(&self) -> u64 {
        scaled_value_units(self.collateral_amount, self.protected_price)
    }

    pub fn discounted_collateral_value_units(&self, height: u64) -> u64 {
        let retained_bps = DEFI_RISK_MAX_BPS.saturating_sub(self.current_discount_bps(height));
        mul_bps(self.protected_collateral_value_units(), retained_bps).max(self.min_repay_units)
    }

    pub fn settle(
        &self,
        keeper_label: &str,
        bid_units: u64,
        settled_at_height: u64,
        settlement: &Value,
    ) -> DefiRiskResult<Self> {
        if !self.is_open(settled_at_height) {
            return Err("auction is not open at settlement height".to_string());
        }
        if bid_units < self.min_repay_units {
            return Err("auction bid is below minimum repay units".to_string());
        }
        let settlement_root = defi_risk_payload_root("DEFI-RISK-AUCTION-SETTLEMENT", settlement);
        let winning_bid_commitment = domain_hash(
            "DEFI-RISK-AUCTION-WINNING-BID",
            &[
                HashPart::Str(&self.auction_id),
                HashPart::Str(keeper_label),
                HashPart::Int(bid_units as i128),
                HashPart::Int(settled_at_height as i128),
                HashPart::Str(&settlement_root),
            ],
            32,
        );
        let mut settled = self.clone();
        settled.status = LiquidationAuctionStatus::Settled;
        settled.winning_bid_commitment = winning_bid_commitment;
        settled.settlement_root = settlement_root;
        Ok(settled)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_amount": self.collateral_amount,
            "debt_amount": self.debt_amount,
            "protected_price": self.protected_price,
            "protected_collateral_value_units": self.protected_collateral_value_units(),
            "min_repay_units": self.min_repay_units,
            "start_discount_bps": self.start_discount_bps,
            "max_discount_bps": self.max_discount_bps,
            "discount_step_bps": self.discount_step_bps,
            "lot_count": self.lot_count,
            "started_at_height": self.started_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "oracle_guard_id": self.oracle_guard_id,
            "risk_commitment_id": self.risk_commitment_id,
            "winning_bid_commitment": self.winning_bid_commitment,
            "settlement_root": self.settlement_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuranceFund {
    pub fund_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub balance_units: u64,
    pub reserved_units: u64,
    pub target_balance_units: u64,
    pub max_payout_per_auction_units: u64,
    pub premium_bps: u64,
    pub status: InsuranceFundStatus,
    pub manager_commitment: String,
    pub accounting_root: String,
    pub updated_at_height: u64,
}

impl InsuranceFund {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        asset_id: &str,
        balance_units: u64,
        reserved_units: u64,
        target_balance_units: u64,
        max_payout_per_auction_units: u64,
        premium_bps: u64,
        manager_label: &str,
        accounting: &Value,
        updated_at_height: u64,
    ) -> DefiRiskResult<Self> {
        ensure_bps(premium_bps, "premium_bps")?;
        let manager_commitment = defi_risk_string_root("DEFI-RISK-FUND-MANAGER", manager_label);
        let accounting_root = defi_risk_payload_root("DEFI-RISK-FUND-ACCOUNTING", accounting);
        let fund_id = defi_risk_insurance_fund_id(
            market_id,
            asset_id,
            target_balance_units,
            max_payout_per_auction_units,
            premium_bps,
            &manager_commitment,
        );
        let fund = Self {
            fund_id,
            market_id: market_id.to_string(),
            asset_id: asset_id.to_string(),
            balance_units,
            reserved_units,
            target_balance_units,
            max_payout_per_auction_units,
            premium_bps,
            status: InsuranceFundStatus::Active,
            manager_commitment,
            accounting_root,
            updated_at_height,
        };
        fund.validate()?;
        Ok(fund)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.market_id, "insurance fund market_id")?;
        ensure_non_empty(&self.asset_id, "insurance fund asset_id")?;
        ensure_non_empty(
            &self.manager_commitment,
            "insurance fund manager_commitment",
        )?;
        ensure_bps(self.premium_bps, "premium_bps")?;
        if self.reserved_units > self.balance_units {
            return Err("insurance fund reserved units exceed balance".to_string());
        }
        if self.fund_id
            != defi_risk_insurance_fund_id(
                &self.market_id,
                &self.asset_id,
                self.target_balance_units,
                self.max_payout_per_auction_units,
                self.premium_bps,
                &self.manager_commitment,
            )
        {
            return Err("insurance fund id mismatch".to_string());
        }
        Ok(())
    }

    pub fn available_units(&self) -> u64 {
        if matches!(
            &self.status,
            InsuranceFundStatus::Paused | InsuranceFundStatus::Retired
        ) {
            return 0;
        }
        self.balance_units.saturating_sub(self.reserved_units)
    }

    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(self.balance_units, self.target_balance_units.max(1))
    }

    pub fn can_cover(&self, amount_units: u64) -> bool {
        amount_units <= self.max_payout_per_auction_units && amount_units <= self.available_units()
    }

    pub fn reserve_payout(&mut self, amount_units: u64) -> DefiRiskResult<()> {
        if !self.can_cover(amount_units) {
            return Err("insurance fund cannot cover payout".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(amount_units);
        if self.available_units() == 0 {
            self.status = InsuranceFundStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "insurance_fund",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "fund_id": self.fund_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "balance_units": self.balance_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "target_balance_units": self.target_balance_units,
            "coverage_bps": self.coverage_bps(),
            "max_payout_per_auction_units": self.max_payout_per_auction_units,
            "premium_bps": self.premium_bps,
            "status": self.status.as_str(),
            "manager_commitment": self.manager_commitment,
            "accounting_root": self.accounting_root,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiCircuitBreaker {
    pub circuit_id: String,
    pub scope: DefiCircuitScope,
    pub subject_id: String,
    pub status: DefiCircuitStatus,
    pub severity: DefiRiskSeverity,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub cooldown_blocks: u64,
    pub trigger_root: String,
    pub operator_commitment: String,
    pub action: String,
    pub reason_root: String,
}

impl DefiCircuitBreaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DefiCircuitScope,
        subject_id: &str,
        status: DefiCircuitStatus,
        severity: DefiRiskSeverity,
        opened_at_height: u64,
        cooldown_blocks: u64,
        trigger_root: &str,
        operator_label: &str,
        action: &str,
        reason: &Value,
    ) -> DefiRiskResult<Self> {
        let closes_at_height = opened_at_height.saturating_add(cooldown_blocks);
        let operator_commitment =
            defi_risk_string_root("DEFI-RISK-CIRCUIT-OPERATOR", operator_label);
        let reason_root = defi_risk_payload_root("DEFI-RISK-CIRCUIT-REASON", reason);
        let circuit_id = defi_risk_circuit_breaker_id(
            &scope,
            subject_id,
            opened_at_height,
            cooldown_blocks,
            trigger_root,
            &operator_commitment,
        );
        let circuit = Self {
            circuit_id,
            scope,
            subject_id: subject_id.to_string(),
            status,
            severity,
            opened_at_height,
            closes_at_height,
            cooldown_blocks,
            trigger_root: trigger_root.to_string(),
            operator_commitment,
            action: action.to_string(),
            reason_root,
        };
        circuit.validate()?;
        Ok(circuit)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.subject_id, "circuit subject_id")?;
        ensure_non_empty(&self.trigger_root, "circuit trigger_root")?;
        ensure_non_empty(&self.operator_commitment, "circuit operator_commitment")?;
        if self.cooldown_blocks == 0 {
            return Err("circuit cooldown blocks must be positive".to_string());
        }
        if self.circuit_id
            != defi_risk_circuit_breaker_id(
                &self.scope,
                &self.subject_id,
                self.opened_at_height,
                self.cooldown_blocks,
                &self.trigger_root,
                &self.operator_commitment,
            )
        {
            return Err("defi circuit breaker id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_active(&self, height: u64) -> bool {
        match &self.status {
            DefiCircuitStatus::Open => {
                self.closes_at_height == 0 || height <= self.closes_at_height
            }
            DefiCircuitStatus::CoolingDown => height <= self.closes_at_height,
            _ => false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_circuit_breaker",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "circuit_id": self.circuit_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "cooldown_blocks": self.cooldown_blocks,
            "trigger_root": self.trigger_root,
            "operator_commitment": self.operator_commitment,
            "action": self.action,
            "reason_root": self.reason_root,
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
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub keeper_reward_units: u64,
    pub max_relay_delay_blocks: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
    pub budget_root: String,
}

impl LowFeeLiquidationSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        market_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        keeper_reward_units: u64,
        max_relay_delay_blocks: u64,
        reserved_at_height: u64,
        expires_at_height: u64,
        budget: &Value,
    ) -> DefiRiskResult<Self> {
        let sponsor_commitment =
            defi_risk_string_root("DEFI-RISK-LIQUIDATION-SPONSOR", sponsor_label);
        let budget_root = defi_risk_payload_root("DEFI-RISK-LIQUIDATION-SPONSOR-BUDGET", budget);
        let sponsorship_id = defi_risk_low_fee_liquidation_sponsorship_id(
            auction_id,
            market_id,
            &sponsor_commitment,
            fee_asset_id,
            gross_fee_units,
            sponsored_fee_units,
            keeper_reward_units,
            max_relay_delay_blocks,
            reserved_at_height,
            expires_at_height,
            &budget_root,
        );
        let sponsorship = Self {
            sponsorship_id,
            auction_id: auction_id.to_string(),
            market_id: market_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            sponsored_fee_units,
            keeper_reward_units,
            max_relay_delay_blocks,
            reserved_at_height,
            expires_at_height,
            status: SponsorshipStatus::Reserved,
            budget_root,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.auction_id, "sponsorship auction_id")?;
        ensure_non_empty(&self.market_id, "sponsorship market_id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor_commitment")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee_asset_id")?;
        if self.sponsored_fee_units > self.gross_fee_units {
            return Err("sponsored fee cannot exceed gross fee".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height {
            return Err("sponsorship expiration must be after reservation".to_string());
        }
        if self.sponsorship_id
            != defi_risk_low_fee_liquidation_sponsorship_id(
                &self.auction_id,
                &self.market_id,
                &self.sponsor_commitment,
                &self.fee_asset_id,
                self.gross_fee_units,
                self.sponsored_fee_units,
                self.keeper_reward_units,
                self.max_relay_delay_blocks,
                self.reserved_at_height,
                self.expires_at_height,
                &self.budget_root,
            )
        {
            return Err("low fee liquidation sponsorship id mismatch".to_string());
        }
        Ok(())
    }

    pub fn net_fee_units(&self) -> u64 {
        self.gross_fee_units
            .saturating_sub(self.sponsored_fee_units)
    }

    pub fn is_active(&self, height: u64) -> bool {
        matches!(&self.status, SponsorshipStatus::Reserved)
            && height >= self.reserved_at_height
            && height <= self.expires_at_height
    }

    pub fn apply(&self) -> Self {
        let mut applied = self.clone();
        applied.status = SponsorshipStatus::Applied;
        applied
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_liquidation_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "net_fee_units": self.net_fee_units(),
            "keeper_reward_units": self.keeper_reward_units,
            "max_relay_delay_blocks": self.max_relay_delay_blocks,
            "low_fee_lane": DEFI_RISK_LOW_FEE_LIQUIDATION_LANE,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiRiskCommitment {
    pub commitment_id: String,
    pub market_id: String,
    pub position_commitment: String,
    pub owner_commitment: String,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub health_factor_commitment: String,
    pub liquidation_threshold_commitment: String,
    pub nonce_commitment: String,
    pub public_input_root: String,
    pub proof_root: String,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
}

impl DefiRiskCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        position_label: &str,
        owner_label: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        collateral_amount: u64,
        debt_amount: u64,
        collateral_price: u64,
        debt_price: u64,
        liquidation_threshold_bps: u64,
        nonce: u64,
        committed_at_height: u64,
        ttl_blocks: u64,
    ) -> DefiRiskResult<Self> {
        ensure_non_empty(market_id, "risk commitment market_id")?;
        ensure_non_empty(position_label, "risk commitment position_label")?;
        ensure_non_empty(owner_label, "risk commitment owner_label")?;
        ensure_non_empty(collateral_asset_id, "risk commitment collateral_asset_id")?;
        ensure_non_empty(debt_asset_id, "risk commitment debt_asset_id")?;
        ensure_bps(liquidation_threshold_bps, "liquidation_threshold_bps")?;
        let nonce_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-NONCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(market_id),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let position_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-POSITION",
            &[
                HashPart::Str(position_label),
                HashPart::Str(&nonce_commitment),
            ],
            32,
        );
        let owner_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-OWNER",
            &[HashPart::Str(owner_label), HashPart::Str(&nonce_commitment)],
            32,
        );
        let collateral_value_units = scaled_value_units(collateral_amount, collateral_price);
        let debt_value_units = scaled_value_units(debt_amount, debt_price);
        let health_factor_bps = if debt_value_units == 0 {
            u64::MAX
        } else {
            ratio_bps_unbounded(
                mul_bps(collateral_value_units, liquidation_threshold_bps),
                debt_value_units,
            )
        };
        let collateral_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-COLLATERAL",
            &[
                HashPart::Str(collateral_asset_id),
                HashPart::Int(collateral_amount as i128),
                HashPart::Int(collateral_price as i128),
                HashPart::Str(&nonce_commitment),
            ],
            32,
        );
        let debt_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-DEBT",
            &[
                HashPart::Str(debt_asset_id),
                HashPart::Int(debt_amount as i128),
                HashPart::Int(debt_price as i128),
                HashPart::Str(&nonce_commitment),
            ],
            32,
        );
        let health_factor_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-HEALTH",
            &[
                HashPart::Int(health_factor_bps as i128),
                HashPart::Str(&nonce_commitment),
            ],
            32,
        );
        let liquidation_threshold_commitment = domain_hash(
            "DEFI-RISK-COMMITMENT-LIQUIDATION-THRESHOLD",
            &[
                HashPart::Int(liquidation_threshold_bps as i128),
                HashPart::Str(&nonce_commitment),
            ],
            32,
        );
        let public_inputs = json!({
            "market_id": market_id,
            "position_commitment": position_commitment,
            "owner_commitment": owner_commitment,
            "collateral_commitment": collateral_commitment,
            "debt_commitment": debt_commitment,
            "health_factor_commitment": health_factor_commitment,
            "liquidation_threshold_commitment": liquidation_threshold_commitment,
            "nonce_commitment": nonce_commitment,
        });
        let public_input_root =
            defi_risk_payload_root("DEFI-RISK-COMMITMENT-PUBLIC-INPUTS", &public_inputs);
        let proof_root = domain_hash(
            "DEFI-RISK-COMMITMENT-PROOF",
            &[
                HashPart::Str(&public_input_root),
                HashPart::Str(&nonce_commitment),
                HashPart::Int(committed_at_height as i128),
            ],
            32,
        );
        let expires_at_height = committed_at_height.saturating_add(ttl_blocks.max(1));
        let commitment_id = defi_risk_commitment_id(
            market_id,
            public_inputs["position_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["owner_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["collateral_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["debt_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["health_factor_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["liquidation_threshold_commitment"]
                .as_str()
                .unwrap_or_default(),
            public_inputs["nonce_commitment"]
                .as_str()
                .unwrap_or_default(),
            &public_input_root,
            &proof_root,
            committed_at_height,
            expires_at_height,
        );
        let commitment = Self {
            commitment_id,
            market_id: market_id.to_string(),
            position_commitment: public_inputs["position_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            owner_commitment: public_inputs["owner_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            collateral_commitment: public_inputs["collateral_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            debt_commitment: public_inputs["debt_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            health_factor_commitment: public_inputs["health_factor_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            liquidation_threshold_commitment: public_inputs["liquidation_threshold_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            nonce_commitment: public_inputs["nonce_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            public_input_root,
            proof_root,
            committed_at_height,
            expires_at_height,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.market_id, "risk commitment market_id")?;
        ensure_non_empty(
            &self.position_commitment,
            "risk commitment position_commitment",
        )?;
        ensure_non_empty(&self.owner_commitment, "risk commitment owner_commitment")?;
        ensure_non_empty(
            &self.collateral_commitment,
            "risk commitment collateral_commitment",
        )?;
        ensure_non_empty(&self.debt_commitment, "risk commitment debt_commitment")?;
        ensure_non_empty(
            &self.health_factor_commitment,
            "risk commitment health_factor_commitment",
        )?;
        ensure_non_empty(
            &self.liquidation_threshold_commitment,
            "risk commitment liquidation_threshold_commitment",
        )?;
        if self.expires_at_height <= self.committed_at_height {
            return Err("risk commitment expiration must be after commit height".to_string());
        }
        if self.commitment_id
            != defi_risk_commitment_id(
                &self.market_id,
                &self.position_commitment,
                &self.owner_commitment,
                &self.collateral_commitment,
                &self.debt_commitment,
                &self.health_factor_commitment,
                &self.liquidation_threshold_commitment,
                &self.nonce_commitment,
                &self.public_input_root,
                &self.proof_root,
                self.committed_at_height,
                self.expires_at_height,
            )
        {
            return Err("defi risk commitment id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_fresh(&self, height: u64) -> bool {
        height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_risk_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "market_id": self.market_id,
            "position_commitment": self.position_commitment,
            "owner_commitment": self.owner_commitment,
            "collateral_commitment": self.collateral_commitment,
            "debt_commitment": self.debt_commitment,
            "health_factor_commitment": self.health_factor_commitment,
            "liquidation_threshold_commitment": self.liquidation_threshold_commitment,
            "nonce_commitment": self.nonce_commitment,
            "public_input_root": self.public_input_root,
            "proof_root": self.proof_root,
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiRiskAssessment {
    pub assessment_id: String,
    pub market_id: String,
    pub height: u64,
    pub collateral_factor_root: String,
    pub amm_pool_risk_root: String,
    pub oracle_guard_root: String,
    pub utilization_curve_root: String,
    pub liquidation_auction_root: String,
    pub insurance_fund_root: String,
    pub sponsorship_root: String,
    pub risk_commitment_root: String,
    pub circuit_root: String,
    pub aggregate_risk_score_bps: u64,
    pub status: String,
    pub expires_at_height: u64,
}

impl DefiRiskAssessment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        height: u64,
        collateral_factor_root: &str,
        amm_pool_risk_root: &str,
        oracle_guard_root: &str,
        utilization_curve_root: &str,
        liquidation_auction_root: &str,
        insurance_fund_root: &str,
        sponsorship_root: &str,
        risk_commitment_root: &str,
        circuit_root: &str,
        aggregate_risk_score_bps: u64,
        ttl_blocks: u64,
    ) -> DefiRiskResult<Self> {
        let expires_at_height = height.saturating_add(ttl_blocks.max(1));
        let status = risk_status_from_score(aggregate_risk_score_bps);
        let assessment_id = defi_risk_assessment_id(
            market_id,
            height,
            collateral_factor_root,
            amm_pool_risk_root,
            oracle_guard_root,
            utilization_curve_root,
            liquidation_auction_root,
            insurance_fund_root,
            sponsorship_root,
            risk_commitment_root,
            circuit_root,
            aggregate_risk_score_bps,
            &status,
            expires_at_height,
        );
        let assessment = Self {
            assessment_id,
            market_id: market_id.to_string(),
            height,
            collateral_factor_root: collateral_factor_root.to_string(),
            amm_pool_risk_root: amm_pool_risk_root.to_string(),
            oracle_guard_root: oracle_guard_root.to_string(),
            utilization_curve_root: utilization_curve_root.to_string(),
            liquidation_auction_root: liquidation_auction_root.to_string(),
            insurance_fund_root: insurance_fund_root.to_string(),
            sponsorship_root: sponsorship_root.to_string(),
            risk_commitment_root: risk_commitment_root.to_string(),
            circuit_root: circuit_root.to_string(),
            aggregate_risk_score_bps,
            status,
            expires_at_height,
        };
        assessment.validate()?;
        Ok(assessment)
    }

    pub fn validate(&self) -> DefiRiskResult<()> {
        ensure_non_empty(&self.market_id, "assessment market_id")?;
        if self.expires_at_height <= self.height {
            return Err("assessment expiration must be after height".to_string());
        }
        if self.assessment_id
            != defi_risk_assessment_id(
                &self.market_id,
                self.height,
                &self.collateral_factor_root,
                &self.amm_pool_risk_root,
                &self.oracle_guard_root,
                &self.utilization_curve_root,
                &self.liquidation_auction_root,
                &self.insurance_fund_root,
                &self.sponsorship_root,
                &self.risk_commitment_root,
                &self.circuit_root,
                self.aggregate_risk_score_bps,
                &self.status,
                self.expires_at_height,
            )
        {
            return Err("defi risk assessment id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_risk_assessment",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "assessment_id": self.assessment_id,
            "market_id": self.market_id,
            "height": self.height,
            "collateral_factor_root": self.collateral_factor_root,
            "amm_pool_risk_root": self.amm_pool_risk_root,
            "oracle_guard_root": self.oracle_guard_root,
            "utilization_curve_root": self.utilization_curve_root,
            "liquidation_auction_root": self.liquidation_auction_root,
            "insurance_fund_root": self.insurance_fund_root,
            "sponsorship_root": self.sponsorship_root,
            "risk_commitment_root": self.risk_commitment_root,
            "circuit_root": self.circuit_root,
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps,
            "status": self.status,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiRiskState {
    pub height: u64,
    pub collateral_factors: BTreeMap<String, LendingCollateralFactor>,
    pub utilization_curves: BTreeMap<String, UtilizationCurve>,
    pub amm_pool_risks: BTreeMap<String, AmmPoolRisk>,
    pub oracle_guards: BTreeMap<String, OracleDeviationGuard>,
    pub liquidation_auctions: BTreeMap<String, LiquidationAuction>,
    pub insurance_funds: BTreeMap<String, InsuranceFund>,
    pub circuit_breakers: BTreeMap<String, DefiCircuitBreaker>,
    pub sponsorships: BTreeMap<String, LowFeeLiquidationSponsorship>,
    pub risk_commitments: BTreeMap<String, DefiRiskCommitment>,
    pub assessments: BTreeMap<String, DefiRiskAssessment>,
}

impl DefiRiskState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> DefiRiskResult<Self> {
        let mut state = Self::new();
        let market_id = "wxmr-usdd-devnet";
        let collateral_asset_id = "wxmr-devnet";
        let debt_asset_id = "usdd-devnet";
        let oracle_feed_id = "feed-wxmr-usdd-devnet";
        let wxmr_price = 125_u64.saturating_mul(DEFI_RISK_PRICE_SCALE);
        let usdd_price = DEFI_RISK_PRICE_SCALE;

        let collateral_factor = LendingCollateralFactor::new(
            market_id,
            collateral_asset_id,
            debt_asset_id,
            6_500,
            8_000,
            600,
            100,
            1_000,
            5_000,
            100_000,
            10_000_000,
            oracle_feed_id,
            0,
            &json!({"mode": "devnet", "collateral": "monero-backed"}),
        )?;
        state.insert_collateral_factor(collateral_factor)?;

        let utilization_curve = UtilizationCurve::new(
            market_id,
            UtilizationCurveKind::Kinked,
            100,
            8_000,
            7_500,
            500,
            4_000,
            1_000,
            8_000,
            0,
            &json!({"mode": "devnet", "target": "low-fee stable borrow"}),
        )?;
        state.insert_utilization_curve(utilization_curve)?;

        let pool_risk = AmmPoolRisk::new(
            "wxmr-usdd-amm-devnet",
            market_id,
            collateral_asset_id,
            debt_asset_id,
            2_000_000,
            250_000_000,
            wxmr_price,
            wxmr_price.saturating_sub(wxmr_price / 200),
            wxmr_price,
            400,
            2_000,
            1_000_000,
            30,
            250,
            0,
            &json!({"mode": "devnet", "guard": "constant-product"}),
        )?;
        state.insert_amm_pool_risk(pool_risk)?;

        let guard = OracleDeviationGuard::new(
            market_id,
            oracle_feed_id,
            wxmr_price,
            wxmr_price.saturating_sub(wxmr_price / 250),
            wxmr_price.saturating_sub(wxmr_price / 300),
            DEFI_RISK_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            DEFI_RISK_DEFAULT_MAX_TWAP_DEVIATION_BPS,
            DEFI_RISK_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            0,
            0,
            &json!({"source_set": ["devnet-oracle-a", "devnet-oracle-b"]}),
        )?;
        let guard_id = guard.guard_id.clone();
        state.insert_oracle_guard(guard)?;

        let insurance_fund = InsuranceFund::new(
            market_id,
            debt_asset_id,
            2_000_000,
            0,
            5_000_000,
            500_000,
            50,
            "devnet-defi-risk-council",
            &json!({"funding": "devnet-bootstrap", "asset": debt_asset_id}),
            0,
        )?;
        state.insert_insurance_fund(insurance_fund)?;

        let commitment = DefiRiskCommitment::new(
            market_id,
            "devnet-position-0",
            "devnet-borrower-0",
            collateral_asset_id,
            debt_asset_id,
            10_000,
            700_000,
            wxmr_price,
            usdd_price,
            8_000,
            7,
            0,
            DEFI_RISK_DEFAULT_ASSESSMENT_TTL_BLOCKS,
        )?;
        let risk_commitment_id = commitment.commitment_id.clone();
        let borrower_commitment = commitment.owner_commitment.clone();
        state.insert_risk_commitment(commitment)?;

        let auction = LiquidationAuction::new(
            "devnet-position-0",
            market_id,
            collateral_asset_id,
            debt_asset_id,
            &borrower_commitment,
            10_000,
            700_000,
            wxmr_price,
            350_000,
            300,
            1_500,
            50,
            4,
            0,
            DEFI_RISK_DEFAULT_AUCTION_TTL_BLOCKS,
            &guard_id,
            &risk_commitment_id,
        )?;
        let auction_id = auction.auction_id.clone();
        state.insert_liquidation_auction(auction)?;

        let sponsorship = LowFeeLiquidationSponsorship::new(
            &auction_id,
            market_id,
            "devnet-liquidation-sponsor",
            debt_asset_id,
            200,
            150,
            25,
            3,
            0,
            20,
            &json!({"budget_units": 10_000, "lane": DEFI_RISK_LOW_FEE_LIQUIDATION_LANE}),
        )?;
        state.insert_sponsorship(sponsorship)?;

        let trigger_root = defi_risk_payload_root(
            "DEFI-RISK-DEVNET-CIRCUIT-TRIGGER",
            &json!({"market_id": market_id, "mode": "baseline"}),
        );
        let circuit = DefiCircuitBreaker::new(
            DefiCircuitScope::Market,
            market_id,
            DefiCircuitStatus::Closed,
            DefiRiskSeverity::Healthy,
            0,
            DEFI_RISK_DEFAULT_CIRCUIT_COOLDOWN_BLOCKS,
            &trigger_root,
            "devnet-defi-risk-operator",
            "monitor",
            &json!({"reason": "devnet baseline closed circuit"}),
        )?;
        state.insert_circuit_breaker(circuit)?;
        state.build_assessment(market_id, DEFI_RISK_DEFAULT_ASSESSMENT_TTL_BLOCKS)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_collateral_factor(
        &mut self,
        factor: LendingCollateralFactor,
    ) -> DefiRiskResult<LendingCollateralFactor> {
        factor.validate()?;
        self.collateral_factors
            .insert(factor.factor_id.clone(), factor.clone());
        Ok(factor)
    }

    pub fn insert_utilization_curve(
        &mut self,
        curve: UtilizationCurve,
    ) -> DefiRiskResult<UtilizationCurve> {
        curve.validate()?;
        self.utilization_curves
            .insert(curve.curve_id.clone(), curve.clone());
        Ok(curve)
    }

    pub fn insert_amm_pool_risk(&mut self, risk: AmmPoolRisk) -> DefiRiskResult<AmmPoolRisk> {
        risk.validate()?;
        self.amm_pool_risks
            .insert(risk.pool_risk_id.clone(), risk.clone());
        Ok(risk)
    }

    pub fn insert_oracle_guard(
        &mut self,
        guard: OracleDeviationGuard,
    ) -> DefiRiskResult<OracleDeviationGuard> {
        guard.validate()?;
        self.oracle_guards
            .insert(guard.guard_id.clone(), guard.clone());
        Ok(guard)
    }

    pub fn insert_liquidation_auction(
        &mut self,
        auction: LiquidationAuction,
    ) -> DefiRiskResult<LiquidationAuction> {
        auction.validate()?;
        if !auction.oracle_guard_id.is_empty() {
            let guard = self
                .oracle_guards
                .get(&auction.oracle_guard_id)
                .ok_or_else(|| "liquidation auction oracle guard is missing".to_string())?;
            if !guard.allows_liquidation {
                return Err("oracle guard blocks liquidation auction".to_string());
            }
        }
        self.liquidation_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        Ok(auction)
    }

    pub fn insert_insurance_fund(&mut self, fund: InsuranceFund) -> DefiRiskResult<InsuranceFund> {
        fund.validate()?;
        self.insurance_funds
            .insert(fund.fund_id.clone(), fund.clone());
        Ok(fund)
    }

    pub fn insert_circuit_breaker(
        &mut self,
        circuit: DefiCircuitBreaker,
    ) -> DefiRiskResult<DefiCircuitBreaker> {
        circuit.validate()?;
        self.circuit_breakers
            .insert(circuit.circuit_id.clone(), circuit.clone());
        Ok(circuit)
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeLiquidationSponsorship,
    ) -> DefiRiskResult<LowFeeLiquidationSponsorship> {
        sponsorship.validate()?;
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_risk_commitment(
        &mut self,
        commitment: DefiRiskCommitment,
    ) -> DefiRiskResult<DefiRiskCommitment> {
        commitment.validate()?;
        self.risk_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    pub fn insert_assessment(
        &mut self,
        assessment: DefiRiskAssessment,
    ) -> DefiRiskResult<DefiRiskAssessment> {
        assessment.validate()?;
        self.assessments
            .insert(assessment.assessment_id.clone(), assessment.clone());
        Ok(assessment)
    }

    pub fn build_assessment(
        &mut self,
        market_id: &str,
        ttl_blocks: u64,
    ) -> DefiRiskResult<DefiRiskAssessment> {
        ensure_non_empty(market_id, "assessment market_id")?;
        let score = self.market_risk_score_bps(market_id);
        let assessment = DefiRiskAssessment::new(
            market_id,
            self.height,
            &self.collateral_factor_root_for_market(market_id),
            &self.amm_pool_risk_root_for_market(market_id),
            &self.oracle_guard_root_for_market(market_id),
            &self.utilization_curve_root_for_market(market_id),
            &self.liquidation_auction_root_for_market(market_id),
            &self.insurance_fund_root_for_market(market_id),
            &self.sponsorship_root_for_market(market_id),
            &self.risk_commitment_root_for_market(market_id),
            &self.circuit_root_for_market(market_id),
            score,
            ttl_blocks,
        )?;
        self.insert_assessment(assessment.clone())?;
        Ok(assessment)
    }

    pub fn collateral_factor_root(&self) -> String {
        lending_collateral_factor_root(
            &self
                .collateral_factors
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn utilization_curve_root(&self) -> String {
        utilization_curve_root(
            &self
                .utilization_curves
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn amm_pool_risk_root(&self) -> String {
        amm_pool_risk_root(&self.amm_pool_risks.values().cloned().collect::<Vec<_>>())
    }

    pub fn oracle_guard_root(&self) -> String {
        oracle_deviation_guard_root(&self.oracle_guards.values().cloned().collect::<Vec<_>>())
    }

    pub fn liquidation_auction_root(&self) -> String {
        liquidation_auction_root(
            &self
                .liquidation_auctions
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn insurance_fund_root(&self) -> String {
        insurance_fund_root(&self.insurance_funds.values().cloned().collect::<Vec<_>>())
    }

    pub fn circuit_root(&self) -> String {
        defi_circuit_breaker_root(&self.circuit_breakers.values().cloned().collect::<Vec<_>>())
    }

    pub fn sponsorship_root(&self) -> String {
        low_fee_liquidation_sponsorship_root(
            &self.sponsorships.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn risk_commitment_root(&self) -> String {
        defi_risk_commitment_root(&self.risk_commitments.values().cloned().collect::<Vec<_>>())
    }

    pub fn assessment_root(&self) -> String {
        defi_risk_assessment_root(&self.assessments.values().cloned().collect::<Vec<_>>())
    }

    pub fn active_circuit_subjects(&self, height: u64) -> Vec<String> {
        self.circuit_breakers
            .values()
            .filter(|circuit| circuit.is_active(height))
            .map(|circuit| circuit.subject_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn blocked_liquidation_market_ids(&self) -> Vec<String> {
        self.oracle_guards
            .values()
            .filter(|guard| !guard.allows_liquidation)
            .map(|guard| guard.market_id.clone())
            .chain(
                self.circuit_breakers
                    .values()
                    .filter(|circuit| {
                        circuit.is_active(self.height)
                            && matches!(
                                &circuit.scope,
                                DefiCircuitScope::Global
                                    | DefiCircuitScope::Market
                                    | DefiCircuitScope::Liquidation
                            )
                    })
                    .map(|circuit| circuit.subject_id.clone()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn total_insurance_available_units(&self) -> u64 {
        self.insurance_funds.values().fold(0_u64, |total, fund| {
            total.saturating_add(fund.available_units())
        })
    }

    pub fn total_sponsored_fee_units(&self) -> u64 {
        self.sponsorships
            .values()
            .fold(0_u64, |total, sponsorship| {
                total.saturating_add(sponsorship.sponsored_fee_units)
            })
    }

    pub fn active_sponsorship_count(&self) -> u64 {
        self.sponsorships
            .values()
            .filter(|sponsorship| sponsorship.is_active(self.height))
            .count() as u64
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.market_ids()
            .iter()
            .map(|market_id| self.market_risk_score_bps(market_id))
            .max()
            .unwrap_or(0)
    }

    pub fn market_risk_score_bps(&self, market_id: &str) -> u64 {
        let pool_score = self
            .amm_pool_risks
            .values()
            .filter(|risk| risk.market_id == market_id)
            .map(AmmPoolRisk::risk_score_bps)
            .max()
            .unwrap_or(0);
        let oracle_score = self
            .oracle_guards
            .values()
            .filter(|guard| guard.market_id == market_id)
            .map(OracleDeviationGuard::risk_score_bps)
            .max()
            .unwrap_or(0);
        let circuit_score = self
            .circuit_breakers
            .values()
            .filter(|circuit| {
                circuit.subject_id == market_id
                    || matches!(&circuit.scope, DefiCircuitScope::Global)
            })
            .filter(|circuit| circuit.is_active(self.height))
            .map(|circuit| circuit.severity.score_bps())
            .max()
            .unwrap_or(0);
        let fund_score = self
            .insurance_funds
            .values()
            .filter(|fund| fund.market_id == market_id)
            .map(|fund| {
                let coverage_bps = fund.coverage_bps();
                if coverage_bps < 2_500 {
                    9_000
                } else if coverage_bps < 5_000 {
                    6_000
                } else if coverage_bps < 10_000 {
                    2_500
                } else {
                    0
                }
            })
            .max()
            .unwrap_or(0);
        let open_auction_pressure = self
            .liquidation_auctions
            .values()
            .filter(|auction| auction.market_id == market_id && auction.is_open(self.height))
            .count() as u64
            * 1_000;
        pool_score
            .max(oracle_score)
            .max(circuit_score)
            .max(fund_score)
            .max(open_auction_pressure)
            .min(10_000)
    }

    pub fn state_root(&self) -> String {
        defi_risk_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("defi risk state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn market_ids(&self) -> Vec<String> {
        self.collateral_factors
            .values()
            .map(|factor| factor.market_id.clone())
            .chain(
                self.amm_pool_risks
                    .values()
                    .map(|risk| risk.market_id.clone()),
            )
            .chain(
                self.oracle_guards
                    .values()
                    .map(|guard| guard.market_id.clone()),
            )
            .chain(
                self.liquidation_auctions
                    .values()
                    .map(|auction| auction.market_id.clone()),
            )
            .chain(
                self.insurance_funds
                    .values()
                    .map(|fund| fund.market_id.clone()),
            )
            .chain(
                self.risk_commitments
                    .values()
                    .map(|commitment| commitment.market_id.clone()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "defi_risk_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_RISK_PROTOCOL_VERSION,
            "height": self.height,
            "collateral_factor_count": self.collateral_factors.len() as u64,
            "utilization_curve_count": self.utilization_curves.len() as u64,
            "amm_pool_risk_count": self.amm_pool_risks.len() as u64,
            "oracle_guard_count": self.oracle_guards.len() as u64,
            "liquidation_auction_count": self.liquidation_auctions.len() as u64,
            "insurance_fund_count": self.insurance_funds.len() as u64,
            "circuit_breaker_count": self.circuit_breakers.len() as u64,
            "sponsorship_count": self.sponsorships.len() as u64,
            "risk_commitment_count": self.risk_commitments.len() as u64,
            "assessment_count": self.assessments.len() as u64,
            "market_ids": self.market_ids(),
            "collateral_factor_root": self.collateral_factor_root(),
            "utilization_curve_root": self.utilization_curve_root(),
            "amm_pool_risk_root": self.amm_pool_risk_root(),
            "oracle_guard_root": self.oracle_guard_root(),
            "liquidation_auction_root": self.liquidation_auction_root(),
            "insurance_fund_root": self.insurance_fund_root(),
            "circuit_root": self.circuit_root(),
            "sponsorship_root": self.sponsorship_root(),
            "risk_commitment_root": self.risk_commitment_root(),
            "assessment_root": self.assessment_root(),
            "active_circuit_subjects": self.active_circuit_subjects(self.height),
            "blocked_liquidation_market_ids": self.blocked_liquidation_market_ids(),
            "active_sponsorship_count": self.active_sponsorship_count(),
            "total_insurance_available_units": self.total_insurance_available_units(),
            "total_sponsored_fee_units": self.total_sponsored_fee_units(),
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps(),
            "status": risk_status_from_score(self.aggregate_risk_score_bps()),
        })
    }

    fn collateral_factor_root_for_market(&self, market_id: &str) -> String {
        lending_collateral_factor_root(
            &self
                .collateral_factors
                .values()
                .filter(|factor| factor.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn utilization_curve_root_for_market(&self, market_id: &str) -> String {
        utilization_curve_root(
            &self
                .utilization_curves
                .values()
                .filter(|curve| curve.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn amm_pool_risk_root_for_market(&self, market_id: &str) -> String {
        amm_pool_risk_root(
            &self
                .amm_pool_risks
                .values()
                .filter(|risk| risk.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn oracle_guard_root_for_market(&self, market_id: &str) -> String {
        oracle_deviation_guard_root(
            &self
                .oracle_guards
                .values()
                .filter(|guard| guard.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn liquidation_auction_root_for_market(&self, market_id: &str) -> String {
        liquidation_auction_root(
            &self
                .liquidation_auctions
                .values()
                .filter(|auction| auction.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn insurance_fund_root_for_market(&self, market_id: &str) -> String {
        insurance_fund_root(
            &self
                .insurance_funds
                .values()
                .filter(|fund| fund.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn sponsorship_root_for_market(&self, market_id: &str) -> String {
        low_fee_liquidation_sponsorship_root(
            &self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn risk_commitment_root_for_market(&self, market_id: &str) -> String {
        defi_risk_commitment_root(
            &self
                .risk_commitments
                .values()
                .filter(|commitment| commitment.market_id == market_id)
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    fn circuit_root_for_market(&self, market_id: &str) -> String {
        defi_circuit_breaker_root(
            &self
                .circuit_breakers
                .values()
                .filter(|circuit| {
                    circuit.subject_id == market_id
                        || matches!(&circuit.scope, DefiCircuitScope::Global)
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_collateral_factor_id(
    market_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    collateral_factor_bps: u64,
    liquidation_threshold_bps: u64,
    liquidation_bonus_bps: u64,
    protocol_fee_bps: u64,
    reserve_factor_bps: u64,
    close_factor_bps: u64,
    min_collateral_value_units: u64,
    max_debt_units: u64,
    oracle_feed_id: &str,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-COLLATERAL-FACTOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Int(collateral_factor_bps as i128),
            HashPart::Int(liquidation_threshold_bps as i128),
            HashPart::Int(liquidation_bonus_bps as i128),
            HashPart::Int(protocol_fee_bps as i128),
            HashPart::Int(reserve_factor_bps as i128),
            HashPart::Int(close_factor_bps as i128),
            HashPart::Int(min_collateral_value_units as i128),
            HashPart::Int(max_debt_units as i128),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_utilization_curve_id(
    market_id: &str,
    curve_kind: &UtilizationCurveKind,
    base_rate_bps: u64,
    kink_utilization_bps: u64,
    target_utilization_bps: u64,
    slope1_bps: u64,
    slope2_bps: u64,
    reserve_factor_bps: u64,
    max_borrow_rate_bps: u64,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-UTILIZATION-CURVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(curve_kind.as_str()),
            HashPart::Int(base_rate_bps as i128),
            HashPart::Int(kink_utilization_bps as i128),
            HashPart::Int(target_utilization_bps as i128),
            HashPart::Int(slope1_bps as i128),
            HashPart::Int(slope2_bps as i128),
            HashPart::Int(reserve_factor_bps as i128),
            HashPart::Int(max_borrow_rate_bps as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_amm_pool_risk_id(
    pool_id: &str,
    market_id: &str,
    asset_a_id: &str,
    asset_b_id: &str,
    reserve_a_units: u64,
    reserve_b_units: u64,
    spot_price: u64,
    twap_price: u64,
    oracle_price: u64,
    max_price_impact_bps: u64,
    max_inventory_skew_bps: u64,
    min_liquidity_units: u64,
    fee_bps: u64,
    volatility_bps: u64,
    assessed_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-AMM-POOL-RISK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(market_id),
            HashPart::Str(asset_a_id),
            HashPart::Str(asset_b_id),
            HashPart::Int(reserve_a_units as i128),
            HashPart::Int(reserve_b_units as i128),
            HashPart::Int(spot_price as i128),
            HashPart::Int(twap_price as i128),
            HashPart::Int(oracle_price as i128),
            HashPart::Int(max_price_impact_bps as i128),
            HashPart::Int(max_inventory_skew_bps as i128),
            HashPart::Int(min_liquidity_units as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(volatility_bps as i128),
            HashPart::Int(assessed_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_oracle_deviation_guard_id(
    market_id: &str,
    feed_id: &str,
    reference_price: u64,
    observed_price: u64,
    twap_price: u64,
    reference_deviation_bps: u64,
    twap_deviation_bps: u64,
    max_deviation_bps: u64,
    max_twap_deviation_bps: u64,
    max_staleness_blocks: u64,
    observed_at_height: u64,
    checked_at_height: u64,
    action: &OracleGuardAction,
    allows_liquidation: bool,
    evidence_root: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-ORACLE-DEVIATION-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(feed_id),
            HashPart::Int(reference_price as i128),
            HashPart::Int(observed_price as i128),
            HashPart::Int(twap_price as i128),
            HashPart::Int(reference_deviation_bps as i128),
            HashPart::Int(twap_deviation_bps as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Int(max_twap_deviation_bps as i128),
            HashPart::Int(max_staleness_blocks as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(checked_at_height as i128),
            HashPart::Str(action.as_str()),
            HashPart::Str(if allows_liquidation { "allow" } else { "deny" }),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_liquidation_auction_id(
    position_id: &str,
    market_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    borrower_commitment: &str,
    collateral_amount: u64,
    debt_amount: u64,
    protected_price: u64,
    min_repay_units: u64,
    start_discount_bps: u64,
    max_discount_bps: u64,
    discount_step_bps: u64,
    lot_count: u64,
    started_at_height: u64,
    expires_at_height: u64,
    oracle_guard_id: &str,
    risk_commitment_id: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-LIQUIDATION-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(position_id),
            HashPart::Str(market_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(borrower_commitment),
            HashPart::Int(collateral_amount as i128),
            HashPart::Int(debt_amount as i128),
            HashPart::Int(protected_price as i128),
            HashPart::Int(min_repay_units as i128),
            HashPart::Int(start_discount_bps as i128),
            HashPart::Int(max_discount_bps as i128),
            HashPart::Int(discount_step_bps as i128),
            HashPart::Int(lot_count as i128),
            HashPart::Int(started_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(oracle_guard_id),
            HashPart::Str(risk_commitment_id),
        ],
        32,
    )
}

pub fn defi_risk_insurance_fund_id(
    market_id: &str,
    asset_id: &str,
    target_balance_units: u64,
    max_payout_per_auction_units: u64,
    premium_bps: u64,
    manager_commitment: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-INSURANCE-FUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
            HashPart::Int(target_balance_units as i128),
            HashPart::Int(max_payout_per_auction_units as i128),
            HashPart::Int(premium_bps as i128),
            HashPart::Str(manager_commitment),
        ],
        32,
    )
}

pub fn defi_risk_circuit_breaker_id(
    scope: &DefiCircuitScope,
    subject_id: &str,
    opened_at_height: u64,
    cooldown_blocks: u64,
    trigger_root: &str,
    operator_commitment: &str,
) -> String {
    let scope = scope.as_str();
    domain_hash(
        "DEFI-RISK-CIRCUIT-BREAKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&scope),
            HashPart::Str(subject_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(cooldown_blocks as i128),
            HashPart::Str(trigger_root),
            HashPart::Str(operator_commitment),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_low_fee_liquidation_sponsorship_id(
    auction_id: &str,
    market_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    gross_fee_units: u64,
    sponsored_fee_units: u64,
    keeper_reward_units: u64,
    max_relay_delay_blocks: u64,
    reserved_at_height: u64,
    expires_at_height: u64,
    budget_root: &str,
) -> String {
    domain_hash(
        "DEFI-RISK-LOW-FEE-LIQUIDATION-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(market_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(keeper_reward_units as i128),
            HashPart::Int(max_relay_delay_blocks as i128),
            HashPart::Int(reserved_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(budget_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_commitment_id(
    market_id: &str,
    position_commitment: &str,
    owner_commitment: &str,
    collateral_commitment: &str,
    debt_commitment: &str,
    health_factor_commitment: &str,
    liquidation_threshold_commitment: &str,
    nonce_commitment: &str,
    public_input_root: &str,
    proof_root: &str,
    committed_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "DEFI-RISK-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_commitment),
            HashPart::Str(owner_commitment),
            HashPart::Str(collateral_commitment),
            HashPart::Str(debt_commitment),
            HashPart::Str(health_factor_commitment),
            HashPart::Str(liquidation_threshold_commitment),
            HashPart::Str(nonce_commitment),
            HashPart::Str(public_input_root),
            HashPart::Str(proof_root),
            HashPart::Int(committed_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_risk_assessment_id(
    market_id: &str,
    height: u64,
    collateral_factor_root: &str,
    amm_pool_risk_root: &str,
    oracle_guard_root: &str,
    utilization_curve_root: &str,
    liquidation_auction_root: &str,
    insurance_fund_root: &str,
    sponsorship_root: &str,
    risk_commitment_root: &str,
    circuit_root: &str,
    aggregate_risk_score_bps: u64,
    status: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "DEFI-RISK-ASSESSMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Int(height as i128),
            HashPart::Str(collateral_factor_root),
            HashPart::Str(amm_pool_risk_root),
            HashPart::Str(oracle_guard_root),
            HashPart::Str(utilization_curve_root),
            HashPart::Str(liquidation_auction_root),
            HashPart::Str(insurance_fund_root),
            HashPart::Str(sponsorship_root),
            HashPart::Str(risk_commitment_root),
            HashPart::Str(circuit_root),
            HashPart::Int(aggregate_risk_score_bps as i128),
            HashPart::Str(status),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn lending_collateral_factor_root(factors: &[LendingCollateralFactor]) -> String {
    let mut factors = factors.to_vec();
    factors.sort_by(|left, right| left.factor_id.cmp(&right.factor_id));
    merkle_root(
        "DEFI-RISK-COLLATERAL-FACTOR",
        &factors
            .iter()
            .map(LendingCollateralFactor::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn utilization_curve_root(curves: &[UtilizationCurve]) -> String {
    let mut curves = curves.to_vec();
    curves.sort_by(|left, right| left.curve_id.cmp(&right.curve_id));
    merkle_root(
        "DEFI-RISK-UTILIZATION-CURVE",
        &curves
            .iter()
            .map(UtilizationCurve::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn amm_pool_risk_root(risks: &[AmmPoolRisk]) -> String {
    let mut risks = risks.to_vec();
    risks.sort_by(|left, right| left.pool_risk_id.cmp(&right.pool_risk_id));
    merkle_root(
        "DEFI-RISK-AMM-POOL",
        &risks
            .iter()
            .map(AmmPoolRisk::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn oracle_deviation_guard_root(guards: &[OracleDeviationGuard]) -> String {
    let mut guards = guards.to_vec();
    guards.sort_by(|left, right| left.guard_id.cmp(&right.guard_id));
    merkle_root(
        "DEFI-RISK-ORACLE-GUARD",
        &guards
            .iter()
            .map(OracleDeviationGuard::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn liquidation_auction_root(auctions: &[LiquidationAuction]) -> String {
    let mut auctions = auctions.to_vec();
    auctions.sort_by(|left, right| left.auction_id.cmp(&right.auction_id));
    merkle_root(
        "DEFI-RISK-LIQUIDATION-AUCTION",
        &auctions
            .iter()
            .map(LiquidationAuction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn insurance_fund_root(funds: &[InsuranceFund]) -> String {
    let mut funds = funds.to_vec();
    funds.sort_by(|left, right| left.fund_id.cmp(&right.fund_id));
    merkle_root(
        "DEFI-RISK-INSURANCE-FUND",
        &funds
            .iter()
            .map(InsuranceFund::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn defi_circuit_breaker_root(circuits: &[DefiCircuitBreaker]) -> String {
    let mut circuits = circuits.to_vec();
    circuits.sort_by(|left, right| left.circuit_id.cmp(&right.circuit_id));
    merkle_root(
        "DEFI-RISK-CIRCUIT-BREAKER",
        &circuits
            .iter()
            .map(DefiCircuitBreaker::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_liquidation_sponsorship_root(
    sponsorships: &[LowFeeLiquidationSponsorship],
) -> String {
    let mut sponsorships = sponsorships.to_vec();
    sponsorships.sort_by(|left, right| left.sponsorship_id.cmp(&right.sponsorship_id));
    merkle_root(
        "DEFI-RISK-LOW-FEE-LIQUIDATION-SPONSORSHIP",
        &sponsorships
            .iter()
            .map(LowFeeLiquidationSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn defi_risk_commitment_root(commitments: &[DefiRiskCommitment]) -> String {
    let mut commitments = commitments.to_vec();
    commitments.sort_by(|left, right| left.commitment_id.cmp(&right.commitment_id));
    merkle_root(
        "DEFI-RISK-COMMITMENT",
        &commitments
            .iter()
            .map(DefiRiskCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn defi_risk_assessment_root(assessments: &[DefiRiskAssessment]) -> String {
    let mut assessments = assessments.to_vec();
    assessments.sort_by(|left, right| left.assessment_id.cmp(&right.assessment_id));
    merkle_root(
        "DEFI-RISK-ASSESSMENT",
        &assessments
            .iter()
            .map(DefiRiskAssessment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn defi_risk_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn defi_risk_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn defi_risk_string_set_root(domain: &str, values: &[String]) -> String {
    let values = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &values)
}

pub fn defi_risk_state_root_from_record(record: &Value) -> String {
    domain_hash("DEFI-RISK-STATE", &[HashPart::Json(record)], 32)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return DEFI_RISK_MAX_BPS;
    }
    proportional(DEFI_RISK_MAX_BPS, numerator, denominator).min(DEFI_RISK_MAX_BPS)
}

pub fn ratio_bps_unbounded(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    proportional(DEFI_RISK_MAX_BPS, numerator, denominator)
}

pub fn price_deviation_bps(left: u64, right: u64) -> u64 {
    if left == right {
        return 0;
    }
    let larger = left.max(right);
    let smaller = left.min(right);
    ratio_bps_unbounded(larger.saturating_sub(smaller), smaller.max(1))
}

pub fn mul_bps(value: u64, bps: u64) -> u64 {
    proportional(value, bps, DEFI_RISK_MAX_BPS)
}

pub fn scaled_value_units(amount: u64, price: u64) -> u64 {
    proportional(amount, price, DEFI_RISK_PRICE_SCALE)
}

pub fn risk_status_from_score(score_bps: u64) -> String {
    if score_bps >= 8_000 {
        "critical"
    } else if score_bps >= 5_000 {
        "warn"
    } else if score_bps > 0 {
        "watch"
    } else {
        "healthy"
    }
    .to_string()
}

pub fn severity_from_score(score_bps: u64) -> DefiRiskSeverity {
    if score_bps >= 8_000 {
        DefiRiskSeverity::Critical
    } else if score_bps >= 5_000 {
        DefiRiskSeverity::Warn
    } else if score_bps > 0 {
        DefiRiskSeverity::Watch
    } else {
        DefiRiskSeverity::Healthy
    }
}

fn oracle_guard_action(
    reference_deviation_bps: u64,
    twap_deviation_bps: u64,
    max_deviation_bps: u64,
    max_twap_deviation_bps: u64,
    stale: bool,
) -> OracleGuardAction {
    if stale
        || reference_deviation_bps > max_deviation_bps.saturating_mul(2)
        || twap_deviation_bps > max_twap_deviation_bps.saturating_mul(2)
    {
        OracleGuardAction::FreezeMarket
    } else if reference_deviation_bps > max_deviation_bps
        || twap_deviation_bps > max_twap_deviation_bps
    {
        OracleGuardAction::BlockLiquidation
    } else if reference_deviation_bps > mul_bps(max_deviation_bps, 8_000)
        || twap_deviation_bps > mul_bps(max_twap_deviation_bps, 8_000)
    {
        OracleGuardAction::Watch
    } else {
        OracleGuardAction::Allow
    }
}

fn amm_pool_risk_score_bps(
    reserve_a_units: u64,
    reserve_b_units: u64,
    spot_price: u64,
    twap_price: u64,
    oracle_price: u64,
    max_inventory_skew_bps: u64,
    min_liquidity_units: u64,
    volatility_bps: u64,
) -> u64 {
    let liquidity_units = reserve_a_units.min(reserve_b_units);
    let inventory_skew_bps = {
        let larger = reserve_a_units.max(reserve_b_units);
        let smaller = reserve_a_units.min(reserve_b_units);
        ratio_bps(
            larger.saturating_sub(smaller),
            larger.saturating_add(smaller).max(1),
        )
    };
    let liquidity_score = if liquidity_units < min_liquidity_units {
        8_000
    } else {
        0
    };
    let skew_score = if inventory_skew_bps > max_inventory_skew_bps {
        6_000
    } else {
        inventory_skew_bps
    };
    liquidity_score
        .max(skew_score)
        .max(price_deviation_bps(spot_price, twap_price).min(10_000))
        .max(price_deviation_bps(spot_price, oracle_price).min(10_000))
        .max(volatility_bps.min(10_000))
}

fn proportional(value: u64, numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let value = (value as u128).saturating_mul(numerator as u128) / denominator as u128;
    value.min(u64::MAX as u128) as u64
}

fn ensure_bps(value: u64, label: &str) -> DefiRiskResult<()> {
    if value > DEFI_RISK_MAX_BPS {
        return Err(format!("{label} cannot exceed 10000 bps"));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> DefiRiskResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}
