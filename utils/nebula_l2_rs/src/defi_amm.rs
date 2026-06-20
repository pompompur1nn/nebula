use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DefiAmmResult<T> = Result<T, String>;

pub const DEFI_AMM_PROTOCOL_VERSION: &str = "nebula-defi-amm-v1";
pub const DEFI_AMM_MAX_BPS: u64 = 10_000;
pub const DEFI_AMM_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const DEFI_AMM_DEFAULT_FEE_BPS: u64 = 18;
pub const DEFI_AMM_DEFAULT_PROTOCOL_FEE_SHARE_BPS: u64 = 1_500;
pub const DEFI_AMM_DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 800;
pub const DEFI_AMM_DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 600;
pub const DEFI_AMM_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 16;
pub const DEFI_AMM_DEFAULT_TWAP_WINDOW_BLOCKS: u64 = 120;
pub const DEFI_AMM_DEFAULT_TICK_SPACING: i64 = 60;
pub const DEFI_AMM_DEFAULT_MIN_TICK: i64 = -9_600;
pub const DEFI_AMM_DEFAULT_MAX_TICK: i64 = 9_600;
pub const DEFI_AMM_DEFAULT_MIN_PRIVATE_SWAP_DELAY_BLOCKS: u64 = 2;
pub const DEFI_AMM_DEFAULT_MAX_PRIVATE_SWAP_DELAY_BLOCKS: u64 = 96;
pub const DEFI_AMM_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 24;
pub const DEFI_AMM_DEFAULT_LOW_FEE_REBATE_CAP_BPS: u64 = 7_500;
pub const DEFI_AMM_DEFAULT_MAX_ROUTE_HOPS: u64 = 4;
pub const DEFI_AMM_DEFAULT_MIN_POSITION_LIQUIDITY: u64 = 1;
pub const DEFI_AMM_DEVNET_HEIGHT: u64 = 42;
pub const DEFI_AMM_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFI_AMM_DEVNET_STABLE_ASSET_ID: &str = "usdd-devnet";
pub const DEFI_AMM_DEVNET_GOV_ASSET_ID: &str = "dnr-devnet";
pub const DEFI_AMM_DEVNET_LOW_FEE_LANE: &str = "small_defi";
pub const DEFI_AMM_PRIVATE_SWAP_PROOF_SYSTEM: &str = "pq-private-amm-swap-devnet";
pub const DEFI_AMM_ROUTE_PROOF_SYSTEM: &str = "pq-amm-route-guard-devnet";
pub const DEFI_AMM_STATUS_ACTIVE: &str = "active";
pub const DEFI_AMM_STATUS_PENDING: &str = "pending";
pub const DEFI_AMM_STATUS_REVEALED: &str = "revealed";
pub const DEFI_AMM_STATUS_SETTLED: &str = "settled";
pub const DEFI_AMM_STATUS_EXPIRED: &str = "expired";
pub const DEFI_AMM_STATUS_CANCELLED: &str = "cancelled";
pub const DEFI_AMM_STATUS_PAUSED: &str = "paused";
pub const DEFI_AMM_STATUS_KILLED: &str = "killed";
pub const DEFI_AMM_STATUS_VERIFIED: &str = "verified";
pub const DEFI_AMM_STATUS_REJECTED: &str = "rejected";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiAmmPoolKind {
    ConstantProduct,
    Stable,
    Concentrated,
}

impl DefiAmmPoolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::Stable => "stable",
            Self::Concentrated => "concentrated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiAmmSwapVisibility {
    Public,
    Sealed,
    Private,
    PrivateBatch,
}

impl DefiAmmSwapVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Sealed => "sealed",
            Self::Private => "private",
            Self::PrivateBatch => "private_batch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiAmmGuardAction {
    Allow,
    Watch,
    ReduceOnly,
    PausePool,
    KillPool,
}

impl DefiAmmGuardAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::PausePool => "pause_pool",
            Self::KillPool => "kill_pool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiAmmRiskMode {
    Normal,
    Watch,
    ReduceOnly,
    Paused,
    Killed,
}

impl DefiAmmRiskMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Paused => "paused",
            Self::Killed => "killed",
        }
    }

    pub fn blocks_trading(&self) -> bool {
        matches!(self, Self::Paused | Self::Killed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiAmmSwitchScope {
    Global,
    Pool,
    Route,
    OracleGuard,
    PrivateSwapCircuit,
    LowFeeRebate,
}

impl DefiAmmSwitchScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Pool => "pool",
            Self::Route => "route",
            Self::OracleGuard => "oracle_guard",
            Self::PrivateSwapCircuit => "private_swap_circuit",
            Self::LowFeeRebate => "low_fee_rebate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmConfig {
    pub protocol_version: String,
    pub max_fee_bps: u64,
    pub protocol_fee_share_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub default_twap_window_blocks: u64,
    pub min_private_swap_delay_blocks: u64,
    pub max_private_swap_delay_blocks: u64,
    pub default_tick_spacing: i64,
    pub default_min_tick: i64,
    pub default_max_tick: i64,
    pub min_position_liquidity: u64,
    pub max_route_hops: u64,
    pub route_ttl_blocks: u64,
    pub low_fee_rebate_cap_bps: u64,
    pub private_swap_proof_system: String,
    pub route_proof_system: String,
    pub metadata_root: String,
}

impl Default for DefiAmmConfig {
    fn default() -> Self {
        Self {
            protocol_version: DEFI_AMM_PROTOCOL_VERSION.to_string(),
            max_fee_bps: 100,
            protocol_fee_share_bps: DEFI_AMM_DEFAULT_PROTOCOL_FEE_SHARE_BPS,
            max_price_impact_bps: DEFI_AMM_DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_oracle_deviation_bps: DEFI_AMM_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            max_oracle_staleness_blocks: DEFI_AMM_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            default_twap_window_blocks: DEFI_AMM_DEFAULT_TWAP_WINDOW_BLOCKS,
            min_private_swap_delay_blocks: DEFI_AMM_DEFAULT_MIN_PRIVATE_SWAP_DELAY_BLOCKS,
            max_private_swap_delay_blocks: DEFI_AMM_DEFAULT_MAX_PRIVATE_SWAP_DELAY_BLOCKS,
            default_tick_spacing: DEFI_AMM_DEFAULT_TICK_SPACING,
            default_min_tick: DEFI_AMM_DEFAULT_MIN_TICK,
            default_max_tick: DEFI_AMM_DEFAULT_MAX_TICK,
            min_position_liquidity: DEFI_AMM_DEFAULT_MIN_POSITION_LIQUIDITY,
            max_route_hops: DEFI_AMM_DEFAULT_MAX_ROUTE_HOPS,
            route_ttl_blocks: DEFI_AMM_DEFAULT_ROUTE_TTL_BLOCKS,
            low_fee_rebate_cap_bps: DEFI_AMM_DEFAULT_LOW_FEE_REBATE_CAP_BPS,
            private_swap_proof_system: DEFI_AMM_PRIVATE_SWAP_PROOF_SYSTEM.to_string(),
            route_proof_system: DEFI_AMM_ROUTE_PROOF_SYSTEM.to_string(),
            metadata_root: defi_amm_payload_root(
                "DEFI-AMM-CONFIG-METADATA",
                &json!({"mode": "default"}),
            ),
        }
    }
}

impl DefiAmmConfig {
    pub fn validate(&self) -> DefiAmmResult<()> {
        validate_bps("max_fee_bps", self.max_fee_bps)?;
        validate_bps("protocol_fee_share_bps", self.protocol_fee_share_bps)?;
        validate_bps("max_price_impact_bps", self.max_price_impact_bps)?;
        validate_bps("max_oracle_deviation_bps", self.max_oracle_deviation_bps)?;
        validate_bps("low_fee_rebate_cap_bps", self.low_fee_rebate_cap_bps)?;
        if self.default_tick_spacing == 0 {
            return Err("AMM default tick spacing cannot be zero".to_string());
        }
        if self.default_min_tick >= self.default_max_tick {
            return Err("AMM default tick bounds are invalid".to_string());
        }
        if self.min_private_swap_delay_blocks > self.max_private_swap_delay_blocks {
            return Err("AMM private swap delay bounds are invalid".to_string());
        }
        if self.max_route_hops == 0 {
            return Err("AMM max route hops must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "max_fee_bps": self.max_fee_bps,
            "protocol_fee_share_bps": self.protocol_fee_share_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "default_twap_window_blocks": self.default_twap_window_blocks,
            "min_private_swap_delay_blocks": self.min_private_swap_delay_blocks,
            "max_private_swap_delay_blocks": self.max_private_swap_delay_blocks,
            "default_tick_spacing": self.default_tick_spacing,
            "default_min_tick": self.default_min_tick,
            "default_max_tick": self.default_max_tick,
            "min_position_liquidity": self.min_position_liquidity,
            "max_route_hops": self.max_route_hops,
            "route_ttl_blocks": self.route_ttl_blocks,
            "low_fee_rebate_cap_bps": self.low_fee_rebate_cap_bps,
            "private_swap_proof_system": self.private_swap_proof_system,
            "route_proof_system": self.route_proof_system,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        defi_amm_payload_root("DEFI-AMM-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPoolConfig {
    pub pool_id: String,
    pub pool_kind: DefiAmmPoolKind,
    pub asset_x_id: String,
    pub asset_y_id: String,
    pub lp_asset_id: String,
    pub fee_bps: u64,
    pub tick_spacing: i64,
    pub min_tick: i64,
    pub max_tick: i64,
    pub min_liquidity: u64,
    pub max_price_impact_bps: u64,
    pub oracle_guard_id: String,
    pub low_fee_lane_id: String,
    pub circuit_profile_id: String,
    pub created_at_height: u64,
    pub status: String,
    pub metadata_root: String,
}

impl DefiAmmPoolConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_kind: DefiAmmPoolKind,
        asset_x_id: &str,
        asset_y_id: &str,
        lp_asset_id: &str,
        fee_bps: u64,
        tick_spacing: i64,
        min_tick: i64,
        max_tick: i64,
        min_liquidity: u64,
        max_price_impact_bps: u64,
        oracle_guard_id: &str,
        low_fee_lane_id: &str,
        circuit_profile_id: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> DefiAmmResult<Self> {
        if asset_x_id.is_empty() || asset_y_id.is_empty() || lp_asset_id.is_empty() {
            return Err("AMM pool asset identifiers cannot be empty".to_string());
        }
        if asset_x_id == asset_y_id {
            return Err("AMM pool requires two distinct assets".to_string());
        }
        validate_bps("fee_bps", fee_bps)?;
        validate_bps("max_price_impact_bps", max_price_impact_bps)?;
        if tick_spacing == 0 {
            return Err("AMM pool tick spacing cannot be zero".to_string());
        }
        if min_tick >= max_tick {
            return Err("AMM pool tick bounds are invalid".to_string());
        }
        let metadata_root = defi_amm_payload_root("DEFI-AMM-POOL-METADATA", metadata);
        let pool_id = defi_amm_pool_id(
            pool_kind,
            asset_x_id,
            asset_y_id,
            lp_asset_id,
            fee_bps,
            tick_spacing,
            min_tick,
            max_tick,
            &metadata_root,
        );
        Ok(Self {
            pool_id,
            pool_kind,
            asset_x_id: asset_x_id.to_string(),
            asset_y_id: asset_y_id.to_string(),
            lp_asset_id: lp_asset_id.to_string(),
            fee_bps,
            tick_spacing,
            min_tick,
            max_tick,
            min_liquidity,
            max_price_impact_bps,
            oracle_guard_id: oracle_guard_id.to_string(),
            low_fee_lane_id: low_fee_lane_id.to_string(),
            circuit_profile_id: circuit_profile_id.to_string(),
            created_at_height,
            status: DEFI_AMM_STATUS_ACTIVE.to_string(),
            metadata_root,
        })
    }

    pub fn validate(&self) -> DefiAmmResult<()> {
        if self.asset_x_id.is_empty() || self.asset_y_id.is_empty() || self.lp_asset_id.is_empty() {
            return Err("AMM pool asset identifiers cannot be empty".to_string());
        }
        if self.asset_x_id == self.asset_y_id {
            return Err("AMM pool requires distinct assets".to_string());
        }
        validate_bps("fee_bps", self.fee_bps)?;
        validate_bps("max_price_impact_bps", self.max_price_impact_bps)?;
        if self.tick_spacing == 0 || self.min_tick >= self.max_tick {
            return Err("AMM pool tick policy is invalid".to_string());
        }
        let expected = defi_amm_pool_id(
            self.pool_kind,
            &self.asset_x_id,
            &self.asset_y_id,
            &self.lp_asset_id,
            self.fee_bps,
            self.tick_spacing,
            self.min_tick,
            self.max_tick,
            &self.metadata_root,
        );
        if self.pool_id != expected {
            return Err("AMM pool id mismatch".to_string());
        }
        Ok(())
    }

    pub fn contains_asset(&self, asset_id: &str) -> bool {
        self.asset_x_id == asset_id || self.asset_y_id == asset_id
    }

    pub fn other_asset(&self, asset_id: &str) -> DefiAmmResult<String> {
        if self.asset_x_id == asset_id {
            Ok(self.asset_y_id.clone())
        } else if self.asset_y_id == asset_id {
            Ok(self.asset_x_id.clone())
        } else {
            Err("asset is not in AMM pool".to_string())
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_pool_config",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_AMM_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "asset_x_id": self.asset_x_id,
            "asset_y_id": self.asset_y_id,
            "lp_asset_id": self.lp_asset_id,
            "fee_bps": self.fee_bps,
            "tick_spacing": self.tick_spacing,
            "min_tick": self.min_tick,
            "max_tick": self.max_tick,
            "min_liquidity": self.min_liquidity,
            "max_price_impact_bps": self.max_price_impact_bps,
            "oracle_guard_id": self.oracle_guard_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "circuit_profile_id": self.circuit_profile_id,
            "created_at_height": self.created_at_height,
            "status": self.status,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        defi_amm_pool_config_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPoolState {
    pub pool_id: String,
    pub reserve_x: u64,
    pub reserve_y: u64,
    pub active_liquidity: u64,
    pub lp_supply: u64,
    pub protocol_fee_x: u64,
    pub protocol_fee_y: u64,
    pub fee_growth_global_x: u64,
    pub fee_growth_global_y: u64,
    pub volume_x: u64,
    pub volume_y: u64,
    pub swap_count: u64,
    pub current_tick: i64,
    pub sqrt_price_x64: u64,
    pub last_updated_height: u64,
}

impl DefiAmmPoolState {
    pub fn new(
        config: &DefiAmmPoolConfig,
        reserve_x: u64,
        reserve_y: u64,
        lp_supply: u64,
        current_tick: i64,
        height: u64,
    ) -> Self {
        let active_liquidity =
            integer_sqrt_u128((reserve_x as u128).saturating_mul(reserve_y as u128));
        Self {
            pool_id: config.pool_id.clone(),
            reserve_x,
            reserve_y,
            active_liquidity,
            lp_supply,
            protocol_fee_x: 0,
            protocol_fee_y: 0,
            fee_growth_global_x: 0,
            fee_growth_global_y: 0,
            volume_x: 0,
            volume_y: 0,
            swap_count: 0,
            current_tick,
            sqrt_price_x64: tick_sqrt_price_x64(current_tick),
            last_updated_height: height,
        }
    }

    pub fn reserves_for_asset(
        &self,
        config: &DefiAmmPoolConfig,
        asset_in_id: &str,
    ) -> DefiAmmResult<(u64, u64, String)> {
        if asset_in_id == config.asset_x_id {
            Ok((self.reserve_x, self.reserve_y, config.asset_y_id.clone()))
        } else if asset_in_id == config.asset_y_id {
            Ok((self.reserve_y, self.reserve_x, config.asset_x_id.clone()))
        } else {
            Err("asset is not in AMM pool".to_string())
        }
    }

    pub fn price_x_to_y_scaled(&self) -> u64 {
        scaled_ratio(self.reserve_y, self.reserve_x)
    }

    pub fn price_y_to_x_scaled(&self) -> u64 {
        scaled_ratio(self.reserve_x, self.reserve_y)
    }

    pub fn pool_value_units(&self) -> u64 {
        self.reserve_x.saturating_add(self.reserve_y)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_pool_state",
            "chain_id": CHAIN_ID,
            "pool_id": self.pool_id,
            "reserve_x": self.reserve_x,
            "reserve_y": self.reserve_y,
            "active_liquidity": self.active_liquidity,
            "lp_supply": self.lp_supply,
            "protocol_fee_x": self.protocol_fee_x,
            "protocol_fee_y": self.protocol_fee_y,
            "fee_growth_global_x": self.fee_growth_global_x,
            "fee_growth_global_y": self.fee_growth_global_y,
            "volume_x": self.volume_x,
            "volume_y": self.volume_y,
            "swap_count": self.swap_count,
            "current_tick": self.current_tick,
            "sqrt_price_x64": self.sqrt_price_x64,
            "price_x_to_y_scaled": self.price_x_to_y_scaled(),
            "price_y_to_x_scaled": self.price_y_to_x_scaled(),
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn pool_root(&self) -> String {
        defi_amm_pool_state_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmTick {
    pub tick_id: String,
    pub pool_id: String,
    pub tick_index: i64,
    pub sqrt_price_x64: u64,
    pub liquidity_gross: u64,
    pub liquidity_net: i128,
    pub fee_growth_outside_x: u64,
    pub fee_growth_outside_y: u64,
    pub initialized: bool,
    pub last_crossed_height: u64,
}

impl DefiAmmTick {
    pub fn new(
        pool_id: &str,
        tick_index: i64,
        liquidity_gross: u64,
        liquidity_net: i128,
        last_crossed_height: u64,
    ) -> Self {
        Self {
            tick_id: defi_amm_tick_id(pool_id, tick_index),
            pool_id: pool_id.to_string(),
            tick_index,
            sqrt_price_x64: tick_sqrt_price_x64(tick_index),
            liquidity_gross,
            liquidity_net,
            fee_growth_outside_x: 0,
            fee_growth_outside_y: 0,
            initialized: liquidity_gross > 0 || liquidity_net != 0,
            last_crossed_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_tick",
            "chain_id": CHAIN_ID,
            "tick_id": self.tick_id,
            "pool_id": self.pool_id,
            "tick_index": self.tick_index,
            "sqrt_price_x64": self.sqrt_price_x64,
            "liquidity_gross": self.liquidity_gross,
            "liquidity_net": self.liquidity_net.to_string(),
            "fee_growth_outside_x": self.fee_growth_outside_x,
            "fee_growth_outside_y": self.fee_growth_outside_y,
            "initialized": self.initialized,
            "last_crossed_height": self.last_crossed_height,
        })
    }

    pub fn tick_root(&self) -> String {
        defi_amm_tick_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmLiquidityRange {
    pub range_id: String,
    pub pool_id: String,
    pub lower_tick: i64,
    pub upper_tick: i64,
    pub liquidity: u64,
    pub token_x_deposit: u64,
    pub token_y_deposit: u64,
    pub fee_growth_inside_last_x: u64,
    pub fee_growth_inside_last_y: u64,
    pub reward_growth_inside_last: u64,
    pub created_at_height: u64,
    pub active: bool,
}

impl DefiAmmLiquidityRange {
    pub fn new(
        pool_id: &str,
        lower_tick: i64,
        upper_tick: i64,
        liquidity: u64,
        token_x_deposit: u64,
        token_y_deposit: u64,
        created_at_height: u64,
    ) -> DefiAmmResult<Self> {
        if lower_tick >= upper_tick {
            return Err("AMM liquidity range tick bounds are invalid".to_string());
        }
        Ok(Self {
            range_id: defi_amm_liquidity_range_id(pool_id, lower_tick, upper_tick, liquidity),
            pool_id: pool_id.to_string(),
            lower_tick,
            upper_tick,
            liquidity,
            token_x_deposit,
            token_y_deposit,
            fee_growth_inside_last_x: 0,
            fee_growth_inside_last_y: 0,
            reward_growth_inside_last: 0,
            created_at_height,
            active: liquidity > 0,
        })
    }

    pub fn contains_tick(&self, tick: i64) -> bool {
        tick >= self.lower_tick && tick < self.upper_tick
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_liquidity_range",
            "chain_id": CHAIN_ID,
            "range_id": self.range_id,
            "pool_id": self.pool_id,
            "lower_tick": self.lower_tick,
            "upper_tick": self.upper_tick,
            "liquidity": self.liquidity,
            "token_x_deposit": self.token_x_deposit,
            "token_y_deposit": self.token_y_deposit,
            "fee_growth_inside_last_x": self.fee_growth_inside_last_x,
            "fee_growth_inside_last_y": self.fee_growth_inside_last_y,
            "reward_growth_inside_last": self.reward_growth_inside_last,
            "created_at_height": self.created_at_height,
            "active": self.active,
        })
    }

    pub fn range_root(&self) -> String {
        defi_amm_liquidity_range_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmLpPosition {
    pub position_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub range_id: String,
    pub lower_tick: i64,
    pub upper_tick: i64,
    pub liquidity: u64,
    pub lp_units: u64,
    pub token_x_deposit: u64,
    pub token_y_deposit: u64,
    pub fee_owed_x: u64,
    pub fee_owed_y: u64,
    pub rebate_credit_units: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub encrypted_owner_payload_hash: String,
    pub nonce: u64,
    pub status: String,
}

impl DefiAmmLpPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        pool_id: &str,
        range_id: &str,
        lower_tick: i64,
        upper_tick: i64,
        liquidity: u64,
        lp_units: u64,
        token_x_deposit: u64,
        token_y_deposit: u64,
        opened_at_height: u64,
        nonce: u64,
        encrypted_owner_payload_hash: &str,
    ) -> Self {
        let owner_commitment = defi_amm_account_commitment(owner_label);
        let position_id = defi_amm_lp_position_id(
            &owner_commitment,
            pool_id,
            range_id,
            lower_tick,
            upper_tick,
            liquidity,
            nonce,
        );
        Self {
            position_id,
            owner_commitment,
            pool_id: pool_id.to_string(),
            range_id: range_id.to_string(),
            lower_tick,
            upper_tick,
            liquidity,
            lp_units,
            token_x_deposit,
            token_y_deposit,
            fee_owed_x: 0,
            fee_owed_y: 0,
            rebate_credit_units: 0,
            opened_at_height,
            updated_at_height: opened_at_height,
            encrypted_owner_payload_hash: encrypted_owner_payload_hash.to_string(),
            nonce,
            status: DEFI_AMM_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn position_value_units(&self) -> u64 {
        self.token_x_deposit
            .saturating_add(self.token_y_deposit)
            .saturating_add(self.fee_owed_x)
            .saturating_add(self.fee_owed_y)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_lp_position",
            "chain_id": CHAIN_ID,
            "position_id": self.position_id,
            "owner_commitment": self.owner_commitment,
            "pool_id": self.pool_id,
            "range_id": self.range_id,
            "lower_tick": self.lower_tick,
            "upper_tick": self.upper_tick,
            "liquidity": self.liquidity,
            "lp_units": self.lp_units,
            "token_x_deposit": self.token_x_deposit,
            "token_y_deposit": self.token_y_deposit,
            "fee_owed_x": self.fee_owed_x,
            "fee_owed_y": self.fee_owed_y,
            "rebate_credit_units": self.rebate_credit_units,
            "position_value_units": self.position_value_units(),
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "encrypted_owner_payload_hash": self.encrypted_owner_payload_hash,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn position_root(&self) -> String {
        defi_amm_lp_position_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmSwapQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_in: u64,
    pub amount_in_after_fee: u64,
    pub amount_out: u64,
    pub pool_fee_units: u64,
    pub protocol_fee_units: u64,
    pub fee_bps: u64,
    pub price_impact_bps: u64,
    pub reserve_in_before: u64,
    pub reserve_out_before: u64,
    pub reserve_in_after: u64,
    pub reserve_out_after: u64,
}

impl DefiAmmSwapQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in: u64,
        amount_in_after_fee: u64,
        amount_out: u64,
        pool_fee_units: u64,
        protocol_fee_units: u64,
        fee_bps: u64,
        price_impact_bps: u64,
        reserve_in_before: u64,
        reserve_out_before: u64,
    ) -> Self {
        let reserve_in_after = reserve_in_before.saturating_add(amount_in_after_fee);
        let reserve_out_after = reserve_out_before.saturating_sub(amount_out);
        let quote_id = defi_amm_swap_quote_id(
            pool_id,
            asset_in_id,
            asset_out_id,
            amount_in,
            amount_out,
            fee_bps,
            reserve_in_before,
            reserve_out_before,
        );
        Self {
            quote_id,
            pool_id: pool_id.to_string(),
            asset_in_id: asset_in_id.to_string(),
            asset_out_id: asset_out_id.to_string(),
            amount_in,
            amount_in_after_fee,
            amount_out,
            pool_fee_units,
            protocol_fee_units,
            fee_bps,
            price_impact_bps,
            reserve_in_before,
            reserve_out_before,
            reserve_in_after,
            reserve_out_after,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_swap_quote",
            "chain_id": CHAIN_ID,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_in": self.amount_in,
            "amount_in_after_fee": self.amount_in_after_fee,
            "amount_out": self.amount_out,
            "pool_fee_units": self.pool_fee_units,
            "protocol_fee_units": self.protocol_fee_units,
            "fee_bps": self.fee_bps,
            "price_impact_bps": self.price_impact_bps,
            "reserve_in_before": self.reserve_in_before,
            "reserve_out_before": self.reserve_out_before,
            "reserve_in_after": self.reserve_in_after,
            "reserve_out_after": self.reserve_out_after,
        })
    }

    pub fn quote_root(&self) -> String {
        defi_amm_payload_root("DEFI-AMM-SWAP-QUOTE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmRoutePlan {
    pub route_id: String,
    pub pool_ids: Vec<String>,
    pub asset_path: Vec<String>,
    pub input_amount: u64,
    pub expected_output_amount: u64,
    pub worst_case_output_amount: u64,
    pub route_fee_bps: u64,
    pub price_impact_bps: u64,
    pub twap_guard_root: String,
    pub rebate_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl DefiAmmRoutePlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_ids: Vec<String>,
        asset_path: Vec<String>,
        input_amount: u64,
        expected_output_amount: u64,
        worst_case_output_amount: u64,
        route_fee_bps: u64,
        price_impact_bps: u64,
        twap_guard_root: &str,
        rebate_id: Option<String>,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> DefiAmmResult<Self> {
        if pool_ids.is_empty() {
            return Err("AMM route must include at least one pool".to_string());
        }
        if asset_path.len() != pool_ids.len().saturating_add(1) {
            return Err("AMM route asset path length does not match pool hops".to_string());
        }
        validate_bps("route_fee_bps", route_fee_bps)?;
        validate_bps("price_impact_bps", price_impact_bps)?;
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let route_id = defi_amm_route_id(
            &pool_ids,
            &asset_path,
            input_amount,
            expected_output_amount,
            worst_case_output_amount,
            created_at_height,
        );
        Ok(Self {
            route_id,
            pool_ids,
            asset_path,
            input_amount,
            expected_output_amount,
            worst_case_output_amount,
            route_fee_bps,
            price_impact_bps,
            twap_guard_root: twap_guard_root.to_string(),
            rebate_id,
            created_at_height,
            expires_at_height,
            status: DEFI_AMM_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn hop_count(&self) -> u64 {
        self.pool_ids.len() as u64
    }

    pub fn route_commitment(&self) -> String {
        defi_amm_route_commitment(&self.pool_ids, &self.asset_path)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_route_plan",
            "chain_id": CHAIN_ID,
            "route_id": self.route_id,
            "route_commitment": self.route_commitment(),
            "pool_ids": self.pool_ids,
            "asset_path": self.asset_path,
            "hop_count": self.hop_count(),
            "input_amount": self.input_amount,
            "expected_output_amount": self.expected_output_amount,
            "worst_case_output_amount": self.worst_case_output_amount,
            "route_fee_bps": self.route_fee_bps,
            "price_impact_bps": self.price_impact_bps,
            "twap_guard_root": self.twap_guard_root,
            "rebate_id": self.rebate_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn route_root(&self) -> String {
        defi_amm_route_plan_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPrivateSwapCommitment {
    pub commitment_id: String,
    pub pool_id: String,
    pub route_commitment: String,
    pub asset_in_commitment: String,
    pub asset_out_commitment: String,
    pub amount_in_bucket: u64,
    pub min_amount_out_bucket: u64,
    pub max_fee_bps: u64,
    pub max_price_impact_bps: u64,
    pub nullifier_hash: String,
    pub recipient_commitment: String,
    pub solver_commitment: String,
    pub encrypted_payload_hash: String,
    pub proof_public_input_root: String,
    pub proof_commitment_root: String,
    pub circuit_profile_id: String,
    pub commit_height: u64,
    pub reveal_after_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl DefiAmmPrivateSwapCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        route_commitment: &str,
        asset_in_id: &str,
        asset_out_id: &str,
        amount_in_bucket: u64,
        min_amount_out_bucket: u64,
        max_fee_bps: u64,
        max_price_impact_bps: u64,
        nullifier_label: &str,
        recipient_label: &str,
        solver_label: &str,
        encrypted_payload_hash: &str,
        circuit_profile_id: &str,
        commit_height: u64,
        reveal_delay_blocks: u64,
        ttl_blocks: u64,
    ) -> DefiAmmResult<Self> {
        validate_bps("max_fee_bps", max_fee_bps)?;
        validate_bps("max_price_impact_bps", max_price_impact_bps)?;
        let asset_in_commitment = defi_amm_asset_commitment(asset_in_id);
        let asset_out_commitment = defi_amm_asset_commitment(asset_out_id);
        let nullifier_hash = defi_amm_nullifier_hash(nullifier_label);
        let recipient_commitment = defi_amm_account_commitment(recipient_label);
        let solver_commitment = defi_amm_account_commitment(solver_label);
        let reveal_after_height = commit_height.saturating_add(reveal_delay_blocks);
        let expires_at_height = commit_height.saturating_add(ttl_blocks);
        let proof_public_input_root = defi_amm_private_swap_public_input_root(
            pool_id,
            route_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            amount_in_bucket,
            min_amount_out_bucket,
            max_fee_bps,
            max_price_impact_bps,
        );
        let proof_commitment_root = defi_amm_private_swap_proof_commitment_root(
            &nullifier_hash,
            &recipient_commitment,
            encrypted_payload_hash,
            &proof_public_input_root,
            circuit_profile_id,
        );
        let commitment_id = defi_amm_private_swap_commitment_id(
            pool_id,
            route_commitment,
            &asset_in_commitment,
            &asset_out_commitment,
            amount_in_bucket,
            min_amount_out_bucket,
            &nullifier_hash,
            &recipient_commitment,
            &solver_commitment,
            commit_height,
        );
        Ok(Self {
            commitment_id,
            pool_id: pool_id.to_string(),
            route_commitment: route_commitment.to_string(),
            asset_in_commitment,
            asset_out_commitment,
            amount_in_bucket,
            min_amount_out_bucket,
            max_fee_bps,
            max_price_impact_bps,
            nullifier_hash,
            recipient_commitment,
            solver_commitment,
            encrypted_payload_hash: encrypted_payload_hash.to_string(),
            proof_public_input_root,
            proof_commitment_root,
            circuit_profile_id: circuit_profile_id.to_string(),
            commit_height,
            reveal_after_height,
            expires_at_height,
            status: DEFI_AMM_STATUS_PENDING.to_string(),
        })
    }

    pub fn can_reveal_at(&self, height: u64) -> bool {
        height >= self.reveal_after_height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_private_swap_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "pool_id": self.pool_id,
            "route_commitment": self.route_commitment,
            "asset_in_commitment": self.asset_in_commitment,
            "asset_out_commitment": self.asset_out_commitment,
            "amount_in_bucket": self.amount_in_bucket,
            "min_amount_out_bucket": self.min_amount_out_bucket,
            "max_fee_bps": self.max_fee_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "nullifier_hash": self.nullifier_hash,
            "recipient_commitment": self.recipient_commitment,
            "solver_commitment": self.solver_commitment,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "proof_public_input_root": self.proof_public_input_root,
            "proof_commitment_root": self.proof_commitment_root,
            "circuit_profile_id": self.circuit_profile_id,
            "commit_height": self.commit_height,
            "reveal_after_height": self.reveal_after_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn commitment_root(&self) -> String {
        defi_amm_private_swap_commitment_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPublicSwapReceipt {
    pub receipt_id: String,
    pub visibility: DefiAmmSwapVisibility,
    pub tx_public_hash: String,
    pub block_height: u64,
    pub pool_id: String,
    pub route_id: Option<String>,
    pub route_commitment: String,
    pub asset_in_id: String,
    pub asset_out_id: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub pool_fee_units: u64,
    pub protocol_fee_units: u64,
    pub network_fee_units: u64,
    pub rebate_units: u64,
    pub price_impact_bps: u64,
    pub quote_root: String,
    pub twap_observation_root: String,
    pub oracle_guard_root: String,
    pub proof_root: String,
    pub pool_before_root: String,
    pub pool_after_root: String,
    pub status: String,
}

impl DefiAmmPublicSwapReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        visibility: DefiAmmSwapVisibility,
        tx_public_hash: &str,
        block_height: u64,
        pool_id: &str,
        route_id: Option<String>,
        route_commitment: &str,
        quote: &DefiAmmSwapQuote,
        network_fee_units: u64,
        rebate_units: u64,
        twap_observation_root: &str,
        oracle_guard_root: &str,
        proof_root: &str,
        pool_before_root: &str,
        pool_after_root: &str,
    ) -> Self {
        let receipt_id = defi_amm_public_swap_receipt_id(
            tx_public_hash,
            block_height,
            pool_id,
            &quote.asset_in_id,
            &quote.asset_out_id,
            quote.amount_in,
            quote.amount_out,
            pool_before_root,
            pool_after_root,
        );
        Self {
            receipt_id,
            visibility,
            tx_public_hash: tx_public_hash.to_string(),
            block_height,
            pool_id: pool_id.to_string(),
            route_id,
            route_commitment: route_commitment.to_string(),
            asset_in_id: quote.asset_in_id.clone(),
            asset_out_id: quote.asset_out_id.clone(),
            amount_in: quote.amount_in,
            amount_out: quote.amount_out,
            pool_fee_units: quote.pool_fee_units,
            protocol_fee_units: quote.protocol_fee_units,
            network_fee_units,
            rebate_units,
            price_impact_bps: quote.price_impact_bps,
            quote_root: quote.quote_root(),
            twap_observation_root: twap_observation_root.to_string(),
            oracle_guard_root: oracle_guard_root.to_string(),
            proof_root: proof_root.to_string(),
            pool_before_root: pool_before_root.to_string(),
            pool_after_root: pool_after_root.to_string(),
            status: DEFI_AMM_STATUS_SETTLED.to_string(),
        }
    }

    pub fn net_fee_units(&self) -> u64 {
        self.pool_fee_units
            .saturating_add(self.protocol_fee_units)
            .saturating_add(self.network_fee_units)
            .saturating_sub(self.rebate_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_public_swap_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "visibility": self.visibility.as_str(),
            "tx_public_hash": self.tx_public_hash,
            "block_height": self.block_height,
            "pool_id": self.pool_id,
            "route_id": self.route_id,
            "route_commitment": self.route_commitment,
            "asset_in_id": self.asset_in_id,
            "asset_out_id": self.asset_out_id,
            "amount_in": self.amount_in,
            "amount_out": self.amount_out,
            "pool_fee_units": self.pool_fee_units,
            "protocol_fee_units": self.protocol_fee_units,
            "network_fee_units": self.network_fee_units,
            "rebate_units": self.rebate_units,
            "net_fee_units": self.net_fee_units(),
            "price_impact_bps": self.price_impact_bps,
            "quote_root": self.quote_root,
            "twap_observation_root": self.twap_observation_root,
            "oracle_guard_root": self.oracle_guard_root,
            "proof_root": self.proof_root,
            "pool_before_root": self.pool_before_root,
            "pool_after_root": self.pool_after_root,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        defi_amm_public_swap_receipt_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmTwapObservation {
    pub observation_id: String,
    pub pool_id: String,
    pub block_height: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub reserve_x: u64,
    pub reserve_y: u64,
    pub price_x_to_y_scaled: u64,
    pub price_y_to_x_scaled: u64,
    pub cumulative_x_to_y: u64,
    pub cumulative_y_to_x: u64,
    pub source_count: u64,
    pub status: String,
}

impl DefiAmmTwapObservation {
    pub fn new(
        pool_id: &str,
        block_height: u64,
        window_start_height: u64,
        window_end_height: u64,
        reserve_x: u64,
        reserve_y: u64,
        source_count: u64,
    ) -> Self {
        let price_x_to_y_scaled = scaled_ratio(reserve_y, reserve_x);
        let price_y_to_x_scaled = scaled_ratio(reserve_x, reserve_y);
        let window_blocks = window_end_height.saturating_sub(window_start_height).max(1);
        let cumulative_x_to_y = price_x_to_y_scaled.saturating_mul(window_blocks);
        let cumulative_y_to_x = price_y_to_x_scaled.saturating_mul(window_blocks);
        let observation_id = defi_amm_twap_observation_id(
            pool_id,
            block_height,
            window_start_height,
            window_end_height,
            price_x_to_y_scaled,
            price_y_to_x_scaled,
        );
        Self {
            observation_id,
            pool_id: pool_id.to_string(),
            block_height,
            window_start_height,
            window_end_height,
            reserve_x,
            reserve_y,
            price_x_to_y_scaled,
            price_y_to_x_scaled,
            cumulative_x_to_y,
            cumulative_y_to_x,
            source_count,
            status: DEFI_AMM_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn window_blocks(&self) -> u64 {
        self.window_end_height
            .saturating_sub(self.window_start_height)
            .max(1)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_twap_observation",
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "pool_id": self.pool_id,
            "block_height": self.block_height,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "window_blocks": self.window_blocks(),
            "reserve_x": self.reserve_x,
            "reserve_y": self.reserve_y,
            "price_x_to_y_scaled": self.price_x_to_y_scaled,
            "price_y_to_x_scaled": self.price_y_to_x_scaled,
            "cumulative_x_to_y": self.cumulative_x_to_y,
            "cumulative_y_to_x": self.cumulative_y_to_x,
            "source_count": self.source_count,
            "status": self.status,
        })
    }

    pub fn observation_root(&self) -> String {
        defi_amm_twap_observation_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmOracleGuard {
    pub guard_id: String,
    pub pool_id: String,
    pub oracle_feed_id: String,
    pub reference_price_scaled: u64,
    pub twap_price_scaled: u64,
    pub max_deviation_bps: u64,
    pub max_staleness_blocks: u64,
    pub observed_deviation_bps: u64,
    pub last_oracle_height: u64,
    pub last_twap_height: u64,
    pub action: DefiAmmGuardAction,
    pub evidence_root: String,
    pub active: bool,
}

impl DefiAmmOracleGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: &str,
        oracle_feed_id: &str,
        reference_price_scaled: u64,
        twap_price_scaled: u64,
        max_deviation_bps: u64,
        max_staleness_blocks: u64,
        last_oracle_height: u64,
        last_twap_height: u64,
        evidence: &Value,
    ) -> DefiAmmResult<Self> {
        validate_bps("max_deviation_bps", max_deviation_bps)?;
        let observed_deviation_bps = deviation_bps(reference_price_scaled, twap_price_scaled);
        let action = if observed_deviation_bps > max_deviation_bps.saturating_mul(2) {
            DefiAmmGuardAction::PausePool
        } else if observed_deviation_bps > max_deviation_bps {
            DefiAmmGuardAction::Watch
        } else {
            DefiAmmGuardAction::Allow
        };
        let evidence_root = defi_amm_payload_root("DEFI-AMM-ORACLE-GUARD-EVIDENCE", evidence);
        let guard_id = defi_amm_oracle_guard_id(
            pool_id,
            oracle_feed_id,
            reference_price_scaled,
            twap_price_scaled,
            max_deviation_bps,
            last_oracle_height,
            last_twap_height,
            &evidence_root,
        );
        Ok(Self {
            guard_id,
            pool_id: pool_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            reference_price_scaled,
            twap_price_scaled,
            max_deviation_bps,
            max_staleness_blocks,
            observed_deviation_bps,
            last_oracle_height,
            last_twap_height,
            action,
            evidence_root,
            active: true,
        })
    }

    pub fn is_stale_at(&self, height: u64) -> bool {
        height.saturating_sub(self.last_oracle_height) > self.max_staleness_blocks
            || height.saturating_sub(self.last_twap_height) > self.max_staleness_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_oracle_guard",
            "chain_id": CHAIN_ID,
            "guard_id": self.guard_id,
            "pool_id": self.pool_id,
            "oracle_feed_id": self.oracle_feed_id,
            "reference_price_scaled": self.reference_price_scaled,
            "twap_price_scaled": self.twap_price_scaled,
            "max_deviation_bps": self.max_deviation_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "observed_deviation_bps": self.observed_deviation_bps,
            "last_oracle_height": self.last_oracle_height,
            "last_twap_height": self.last_twap_height,
            "action": self.action.as_str(),
            "evidence_root": self.evidence_root,
            "active": self.active,
        })
    }

    pub fn guard_root(&self) -> String {
        defi_amm_oracle_guard_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmLowFeeRoutingRebate {
    pub rebate_id: String,
    pub route_id: String,
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub eligible_fee_units: u64,
    pub rebate_bps: u64,
    pub rebate_units: u64,
    pub anti_spam_bond_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub status: String,
}

impl DefiAmmLowFeeRoutingRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: &str,
        lane_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        gross_fee_units: u64,
        eligible_fee_units: u64,
        rebate_bps: u64,
        anti_spam_bond_id: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> DefiAmmResult<Self> {
        validate_bps("rebate_bps", rebate_bps)?;
        let sponsor_commitment = defi_amm_account_commitment(sponsor_label);
        let rebate_units = bps_mul_floor(eligible_fee_units.min(gross_fee_units), rebate_bps);
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let rebate_id = defi_amm_low_fee_rebate_id(
            route_id,
            lane_id,
            &sponsor_commitment,
            fee_asset_id,
            gross_fee_units,
            eligible_fee_units,
            rebate_bps,
            created_at_height,
        );
        Ok(Self {
            rebate_id,
            route_id: route_id.to_string(),
            lane_id: lane_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            gross_fee_units,
            eligible_fee_units,
            rebate_bps,
            rebate_units,
            anti_spam_bond_id: anti_spam_bond_id.to_string(),
            created_at_height,
            expires_at_height,
            settled_at_height: None,
            status: DEFI_AMM_STATUS_PENDING.to_string(),
        })
    }

    pub fn mark_settled(&mut self, height: u64) {
        self.settled_at_height = Some(height);
        self.status = DEFI_AMM_STATUS_SETTLED.to_string();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_low_fee_routing_rebate",
            "chain_id": CHAIN_ID,
            "rebate_id": self.rebate_id,
            "route_id": self.route_id,
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "eligible_fee_units": self.eligible_fee_units,
            "rebate_bps": self.rebate_bps,
            "rebate_units": self.rebate_units,
            "anti_spam_bond_id": self.anti_spam_bond_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }

    pub fn rebate_root(&self) -> String {
        defi_amm_low_fee_rebate_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPrivateSwapCircuitProfile {
    pub profile_id: String,
    pub proof_system: String,
    pub circuit_family: String,
    pub version: u64,
    pub verifying_key_root: String,
    pub parameter_root: String,
    pub public_input_schema_root: String,
    pub private_witness_schema_root: String,
    pub max_constraints: u64,
    pub recursion_depth: u64,
    pub pq_transcript_root: String,
    pub active: bool,
}

impl DefiAmmPrivateSwapCircuitProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_system: &str,
        circuit_family: &str,
        version: u64,
        verifying_key_root: &str,
        parameter_root: &str,
        public_input_schema: &Value,
        private_witness_schema: &Value,
        max_constraints: u64,
        recursion_depth: u64,
        pq_transcript_root: &str,
    ) -> Self {
        let public_input_schema_root =
            defi_amm_payload_root("DEFI-AMM-CIRCUIT-PUBLIC-INPUT-SCHEMA", public_input_schema);
        let private_witness_schema_root = defi_amm_payload_root(
            "DEFI-AMM-CIRCUIT-PRIVATE-WITNESS-SCHEMA",
            private_witness_schema,
        );
        let profile_id = defi_amm_circuit_profile_id(
            proof_system,
            circuit_family,
            version,
            verifying_key_root,
            parameter_root,
            &public_input_schema_root,
            &private_witness_schema_root,
            recursion_depth,
        );
        Self {
            profile_id,
            proof_system: proof_system.to_string(),
            circuit_family: circuit_family.to_string(),
            version,
            verifying_key_root: verifying_key_root.to_string(),
            parameter_root: parameter_root.to_string(),
            public_input_schema_root,
            private_witness_schema_root,
            max_constraints,
            recursion_depth,
            pq_transcript_root: pq_transcript_root.to_string(),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_private_swap_circuit_profile",
            "chain_id": CHAIN_ID,
            "profile_id": self.profile_id,
            "proof_system": self.proof_system,
            "circuit_family": self.circuit_family,
            "version": self.version,
            "verifying_key_root": self.verifying_key_root,
            "parameter_root": self.parameter_root,
            "public_input_schema_root": self.public_input_schema_root,
            "private_witness_schema_root": self.private_witness_schema_root,
            "max_constraints": self.max_constraints,
            "recursion_depth": self.recursion_depth,
            "pq_transcript_root": self.pq_transcript_root,
            "active": self.active,
        })
    }

    pub fn profile_root(&self) -> String {
        defi_amm_circuit_profile_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPrivateSwapProofRecord {
    pub proof_id: String,
    pub commitment_id: String,
    pub receipt_id: Option<String>,
    pub profile_id: String,
    pub public_input_root: String,
    pub private_witness_commitment: String,
    pub proof_root: String,
    pub recursive_accumulator_root: String,
    pub verifier_manifest_root: String,
    pub proof_size_bytes: u64,
    pub verified_at_height: u64,
    pub status: String,
}

impl DefiAmmPrivateSwapProofRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment_id: &str,
        receipt_id: Option<String>,
        profile_id: &str,
        public_input_root: &str,
        private_witness_label: &str,
        recursive_accumulator_root: &str,
        verifier_manifest_root: &str,
        proof_size_bytes: u64,
        verified_at_height: u64,
    ) -> Self {
        let private_witness_commitment = defi_amm_witness_commitment(private_witness_label);
        let proof_root = defi_amm_private_swap_proof_root(
            commitment_id,
            receipt_id.as_deref().unwrap_or(""),
            profile_id,
            public_input_root,
            &private_witness_commitment,
            recursive_accumulator_root,
            verifier_manifest_root,
        );
        let proof_id = defi_amm_private_swap_proof_id(
            commitment_id,
            receipt_id.as_deref().unwrap_or(""),
            profile_id,
            &proof_root,
            verified_at_height,
        );
        Self {
            proof_id,
            commitment_id: commitment_id.to_string(),
            receipt_id,
            profile_id: profile_id.to_string(),
            public_input_root: public_input_root.to_string(),
            private_witness_commitment,
            proof_root,
            recursive_accumulator_root: recursive_accumulator_root.to_string(),
            verifier_manifest_root: verifier_manifest_root.to_string(),
            proof_size_bytes,
            verified_at_height,
            status: DEFI_AMM_STATUS_VERIFIED.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_private_swap_proof_record",
            "chain_id": CHAIN_ID,
            "proof_id": self.proof_id,
            "commitment_id": self.commitment_id,
            "receipt_id": self.receipt_id,
            "profile_id": self.profile_id,
            "public_input_root": self.public_input_root,
            "private_witness_commitment": self.private_witness_commitment,
            "proof_root": self.proof_root,
            "recursive_accumulator_root": self.recursive_accumulator_root,
            "verifier_manifest_root": self.verifier_manifest_root,
            "proof_size_bytes": self.proof_size_bytes,
            "verified_at_height": self.verified_at_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        defi_amm_private_swap_proof_record_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmRiskControl {
    pub control_id: String,
    pub pool_id: Option<String>,
    pub mode: DefiAmmRiskMode,
    pub max_trade_units: u64,
    pub max_trade_bps_of_pool: u64,
    pub max_price_impact_bps: u64,
    pub min_liquidity_units: u64,
    pub max_oracle_deviation_bps: u64,
    pub volume_window_blocks: u64,
    pub volume_cap_units: u64,
    pub triggered_volume_units: u64,
    pub triggered_at_height: Option<u64>,
    pub expires_at_height: Option<u64>,
    pub reason_root: String,
    pub active: bool,
}

impl DefiAmmRiskControl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_id: Option<String>,
        mode: DefiAmmRiskMode,
        max_trade_units: u64,
        max_trade_bps_of_pool: u64,
        max_price_impact_bps: u64,
        min_liquidity_units: u64,
        max_oracle_deviation_bps: u64,
        volume_window_blocks: u64,
        volume_cap_units: u64,
        triggered_volume_units: u64,
        triggered_at_height: Option<u64>,
        expires_at_height: Option<u64>,
        reason: &Value,
    ) -> DefiAmmResult<Self> {
        validate_bps("max_trade_bps_of_pool", max_trade_bps_of_pool)?;
        validate_bps("max_price_impact_bps", max_price_impact_bps)?;
        validate_bps("max_oracle_deviation_bps", max_oracle_deviation_bps)?;
        let reason_root = defi_amm_payload_root("DEFI-AMM-RISK-CONTROL-REASON", reason);
        let control_id = defi_amm_risk_control_id(
            pool_id.as_deref().unwrap_or("global"),
            mode,
            max_trade_units,
            max_trade_bps_of_pool,
            max_price_impact_bps,
            min_liquidity_units,
            volume_window_blocks,
            volume_cap_units,
            &reason_root,
        );
        Ok(Self {
            control_id,
            pool_id,
            mode,
            max_trade_units,
            max_trade_bps_of_pool,
            max_price_impact_bps,
            min_liquidity_units,
            max_oracle_deviation_bps,
            volume_window_blocks,
            volume_cap_units,
            triggered_volume_units,
            triggered_at_height,
            expires_at_height,
            reason_root,
            active: true,
        })
    }

    pub fn applies_to_pool(&self, pool_id: &str) -> bool {
        self.pool_id
            .as_deref()
            .is_none_or(|target| target == pool_id)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.active
            && self
                .expires_at_height
                .is_none_or(|expires| height <= expires)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_risk_control",
            "chain_id": CHAIN_ID,
            "control_id": self.control_id,
            "pool_id": self.pool_id,
            "mode": self.mode.as_str(),
            "max_trade_units": self.max_trade_units,
            "max_trade_bps_of_pool": self.max_trade_bps_of_pool,
            "max_price_impact_bps": self.max_price_impact_bps,
            "min_liquidity_units": self.min_liquidity_units,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "volume_window_blocks": self.volume_window_blocks,
            "volume_cap_units": self.volume_cap_units,
            "triggered_volume_units": self.triggered_volume_units,
            "triggered_at_height": self.triggered_at_height,
            "expires_at_height": self.expires_at_height,
            "reason_root": self.reason_root,
            "active": self.active,
        })
    }

    pub fn control_root(&self) -> String {
        defi_amm_risk_control_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmPauseSwitch {
    pub switch_id: String,
    pub scope: DefiAmmSwitchScope,
    pub target_id: String,
    pub paused: bool,
    pub reason_root: String,
    pub set_by_commitment: String,
    pub set_at_height: u64,
    pub expires_at_height: Option<u64>,
    pub nonce: u64,
}

impl DefiAmmPauseSwitch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DefiAmmSwitchScope,
        target_id: &str,
        paused: bool,
        reason: &Value,
        set_by_label: &str,
        set_at_height: u64,
        expires_at_height: Option<u64>,
        nonce: u64,
    ) -> Self {
        let reason_root = defi_amm_payload_root("DEFI-AMM-PAUSE-SWITCH-REASON", reason);
        let set_by_commitment = defi_amm_account_commitment(set_by_label);
        let switch_id = defi_amm_pause_switch_id(
            scope,
            target_id,
            paused,
            &reason_root,
            &set_by_commitment,
            set_at_height,
            nonce,
        );
        Self {
            switch_id,
            scope,
            target_id: target_id.to_string(),
            paused,
            reason_root,
            set_by_commitment,
            set_at_height,
            expires_at_height,
            nonce,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.paused
            && self
                .expires_at_height
                .is_none_or(|expires| height <= expires)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_pause_switch",
            "chain_id": CHAIN_ID,
            "switch_id": self.switch_id,
            "scope": self.scope.as_str(),
            "target_id": self.target_id,
            "paused": self.paused,
            "reason_root": self.reason_root,
            "set_by_commitment": self.set_by_commitment,
            "set_at_height": self.set_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn switch_root(&self) -> String {
        defi_amm_pause_switch_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmKillSwitch {
    pub kill_id: String,
    pub scope: DefiAmmSwitchScope,
    pub target_id: String,
    pub killed: bool,
    pub requires_governance_unwind: bool,
    pub reason_root: String,
    pub set_by_commitment: String,
    pub set_at_height: u64,
    pub unwind_deadline_height: u64,
    pub final_state_root: String,
}

impl DefiAmmKillSwitch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DefiAmmSwitchScope,
        target_id: &str,
        killed: bool,
        requires_governance_unwind: bool,
        reason: &Value,
        set_by_label: &str,
        set_at_height: u64,
        unwind_deadline_height: u64,
        final_state_root: &str,
    ) -> Self {
        let reason_root = defi_amm_payload_root("DEFI-AMM-KILL-SWITCH-REASON", reason);
        let set_by_commitment = defi_amm_account_commitment(set_by_label);
        let kill_id = defi_amm_kill_switch_id(
            scope,
            target_id,
            killed,
            requires_governance_unwind,
            &reason_root,
            &set_by_commitment,
            set_at_height,
            final_state_root,
        );
        Self {
            kill_id,
            scope,
            target_id: target_id.to_string(),
            killed,
            requires_governance_unwind,
            reason_root,
            set_by_commitment,
            set_at_height,
            unwind_deadline_height,
            final_state_root: final_state_root.to_string(),
        }
    }

    pub fn active(&self) -> bool {
        self.killed
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_amm_kill_switch",
            "chain_id": CHAIN_ID,
            "kill_id": self.kill_id,
            "scope": self.scope.as_str(),
            "target_id": self.target_id,
            "killed": self.killed,
            "requires_governance_unwind": self.requires_governance_unwind,
            "reason_root": self.reason_root,
            "set_by_commitment": self.set_by_commitment,
            "set_at_height": self.set_at_height,
            "unwind_deadline_height": self.unwind_deadline_height,
            "final_state_root": self.final_state_root,
        })
    }

    pub fn kill_root(&self) -> String {
        defi_amm_kill_switch_root(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiAmmState {
    pub height: u64,
    pub config: DefiAmmConfig,
    pub pool_configs: BTreeMap<String, DefiAmmPoolConfig>,
    pub pools: BTreeMap<String, DefiAmmPoolState>,
    pub ticks: BTreeMap<String, DefiAmmTick>,
    pub liquidity_ranges: BTreeMap<String, DefiAmmLiquidityRange>,
    pub lp_positions: BTreeMap<String, DefiAmmLpPosition>,
    pub route_plans: BTreeMap<String, DefiAmmRoutePlan>,
    pub private_swap_commitments: BTreeMap<String, DefiAmmPrivateSwapCommitment>,
    pub public_swap_receipts: BTreeMap<String, DefiAmmPublicSwapReceipt>,
    pub twap_observations: BTreeMap<String, DefiAmmTwapObservation>,
    pub oracle_guards: BTreeMap<String, DefiAmmOracleGuard>,
    pub low_fee_rebates: BTreeMap<String, DefiAmmLowFeeRoutingRebate>,
    pub circuit_profiles: BTreeMap<String, DefiAmmPrivateSwapCircuitProfile>,
    pub private_swap_proofs: BTreeMap<String, DefiAmmPrivateSwapProofRecord>,
    pub risk_controls: BTreeMap<String, DefiAmmRiskControl>,
    pub pause_switches: BTreeMap<String, DefiAmmPauseSwitch>,
    pub kill_switches: BTreeMap<String, DefiAmmKillSwitch>,
}

impl DefiAmmState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: DefiAmmConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::with_config(DefiAmmConfig::default());
        state.set_height(DEFI_AMM_DEVNET_HEIGHT);

        let private_profile = DefiAmmPrivateSwapCircuitProfile::new(
            DEFI_AMM_PRIVATE_SWAP_PROOF_SYSTEM,
            "private_amm_swap",
            1,
            &defi_amm_string_root("DEFI-AMM-DEVNET-VK", "private-swap-vk"),
            &defi_amm_string_root("DEFI-AMM-DEVNET-PARAMS", "private-swap-params"),
            &json!({
                "public_inputs": [
                    "pool_root",
                    "route_commitment",
                    "asset_commitments",
                    "amount_buckets",
                    "nullifier_hash",
                    "recipient_commitment"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "input_note_opening",
                    "recipient_view_key",
                    "amount",
                    "slippage_limit",
                    "range_proof_randomness"
                ]
            }),
            2_800_000,
            2,
            &defi_amm_string_root("DEFI-AMM-DEVNET-PQ-TRANSCRIPT", "private-swap"),
        );
        let route_profile = DefiAmmPrivateSwapCircuitProfile::new(
            DEFI_AMM_ROUTE_PROOF_SYSTEM,
            "route_guard",
            1,
            &defi_amm_string_root("DEFI-AMM-DEVNET-VK", "route-vk"),
            &defi_amm_string_root("DEFI-AMM-DEVNET-PARAMS", "route-params"),
            &json!({
                "public_inputs": [
                    "route_root",
                    "twap_guard_root",
                    "oracle_guard_root",
                    "rebate_root"
                ]
            }),
            &json!({
                "private_witnesses": [
                    "solver_ordering",
                    "sealed_amounts",
                    "rebate_budget_opening"
                ]
            }),
            1_400_000,
            1,
            &defi_amm_string_root("DEFI-AMM-DEVNET-PQ-TRANSCRIPT", "route-proof"),
        );
        let private_profile_id = private_profile.profile_id.clone();
        let route_profile_id = route_profile.profile_id.clone();
        state.insert_circuit_profile(private_profile);
        state.insert_circuit_profile(route_profile);

        let wxmr_usdd_config = DefiAmmPoolConfig::new(
            DefiAmmPoolKind::Concentrated,
            DEFI_AMM_DEVNET_FEE_ASSET_ID,
            DEFI_AMM_DEVNET_STABLE_ASSET_ID,
            "lp-wxmr-usdd-devnet",
            18,
            60,
            -5_400,
            5_400,
            10_000,
            650,
            "guard-wxmr-usdd-devnet",
            DEFI_AMM_DEVNET_LOW_FEE_LANE,
            &private_profile_id,
            1,
            &json!({"name": "wXMR/USDD concentrated devnet pool"}),
        )
        .expect("devnet wxmr/usdd pool config");
        let wxmr_dnr_config = DefiAmmPoolConfig::new(
            DefiAmmPoolKind::ConstantProduct,
            DEFI_AMM_DEVNET_FEE_ASSET_ID,
            DEFI_AMM_DEVNET_GOV_ASSET_ID,
            "lp-wxmr-dnr-devnet",
            24,
            120,
            -7_200,
            7_200,
            5_000,
            900,
            "guard-wxmr-dnr-devnet",
            DEFI_AMM_DEVNET_LOW_FEE_LANE,
            &private_profile_id,
            1,
            &json!({"name": "wXMR/DNR constant product devnet pool"}),
        )
        .expect("devnet wxmr/dnr pool config");
        let dnr_usdd_config = DefiAmmPoolConfig::new(
            DefiAmmPoolKind::Stable,
            DEFI_AMM_DEVNET_GOV_ASSET_ID,
            DEFI_AMM_DEVNET_STABLE_ASSET_ID,
            "lp-dnr-usdd-devnet",
            9,
            60,
            -3_600,
            3_600,
            5_000,
            500,
            "guard-dnr-usdd-devnet",
            DEFI_AMM_DEVNET_LOW_FEE_LANE,
            &route_profile_id,
            1,
            &json!({"name": "DNR/USDD stable devnet pool"}),
        )
        .expect("devnet dnr/usdd pool config");

        let wxmr_usdd_pool = DefiAmmPoolState::new(
            &wxmr_usdd_config,
            12_000_000_000,
            1_920_000_000_000,
            151_000_000_000,
            120,
            state.height,
        );
        let wxmr_dnr_pool = DefiAmmPoolState::new(
            &wxmr_dnr_config,
            7_500_000_000,
            600_000_000_000,
            67_000_000_000,
            -180,
            state.height,
        );
        let dnr_usdd_pool = DefiAmmPoolState::new(
            &dnr_usdd_config,
            500_000_000_000,
            775_000_000_000,
            622_000_000_000,
            40,
            state.height,
        );

        let wxmr_usdd_pool_id = wxmr_usdd_config.pool_id.clone();
        let wxmr_dnr_pool_id = wxmr_dnr_config.pool_id.clone();
        let dnr_usdd_pool_id = dnr_usdd_config.pool_id.clone();
        state.insert_pool_config(wxmr_usdd_config);
        state.insert_pool_config(wxmr_dnr_config);
        state.insert_pool_config(dnr_usdd_config);
        state.insert_pool(wxmr_usdd_pool);
        state.insert_pool(wxmr_dnr_pool);
        state.insert_pool(dnr_usdd_pool);

        state.install_devnet_ticks_and_ranges(&wxmr_usdd_pool_id, -600, 600, 90_000_000_000);
        state.install_devnet_ticks_and_ranges(&wxmr_dnr_pool_id, -960, 960, 60_000_000_000);
        state.install_devnet_ticks_and_ranges(&dnr_usdd_pool_id, -480, 480, 220_000_000_000);

        let wxmr_usdd_range = state
            .liquidity_ranges
            .values()
            .find(|range| range.pool_id == wxmr_usdd_pool_id && range.lower_tick == -600)
            .expect("devnet wxmr/usdd range")
            .clone();
        let wxmr_dnr_range = state
            .liquidity_ranges
            .values()
            .find(|range| range.pool_id == wxmr_dnr_pool_id && range.lower_tick == -960)
            .expect("devnet wxmr/dnr range")
            .clone();
        let dnr_usdd_range = state
            .liquidity_ranges
            .values()
            .find(|range| range.pool_id == dnr_usdd_pool_id && range.lower_tick == -480)
            .expect("devnet dnr/usdd range")
            .clone();

        state.insert_lp_position(DefiAmmLpPosition::new(
            "devnet-alice-lp",
            &wxmr_usdd_pool_id,
            &wxmr_usdd_range.range_id,
            wxmr_usdd_range.lower_tick,
            wxmr_usdd_range.upper_tick,
            55_000_000_000,
            70_000_000_000,
            4_500_000_000,
            720_000_000_000,
            2,
            1,
            &defi_amm_string_root("DEFI-AMM-DEVNET-OWNER-PAYLOAD", "alice-wxmr-usdd"),
        ));
        state.insert_lp_position(DefiAmmLpPosition::new(
            "devnet-bob-lp",
            &wxmr_dnr_pool_id,
            &wxmr_dnr_range.range_id,
            wxmr_dnr_range.lower_tick,
            wxmr_dnr_range.upper_tick,
            32_000_000_000,
            36_000_000_000,
            2_500_000_000,
            200_000_000_000,
            2,
            2,
            &defi_amm_string_root("DEFI-AMM-DEVNET-OWNER-PAYLOAD", "bob-wxmr-dnr"),
        ));
        state.insert_lp_position(DefiAmmLpPosition::new(
            "devnet-carol-lp",
            &dnr_usdd_pool_id,
            &dnr_usdd_range.range_id,
            dnr_usdd_range.lower_tick,
            dnr_usdd_range.upper_tick,
            140_000_000_000,
            146_000_000_000,
            110_000_000_000,
            170_000_000_000,
            2,
            3,
            &defi_amm_string_root("DEFI-AMM-DEVNET-OWNER-PAYLOAD", "carol-dnr-usdd"),
        ));

        state.install_devnet_oracle_and_twap(
            &wxmr_usdd_pool_id,
            "wxmr-usdd-feed-devnet",
            160_000_000_000,
        );
        state.install_devnet_oracle_and_twap(
            &wxmr_dnr_pool_id,
            "wxmr-dnr-feed-devnet",
            80_000_000_000,
        );
        state.install_devnet_oracle_and_twap(
            &dnr_usdd_pool_id,
            "dnr-usdd-feed-devnet",
            1_550_000_000_000,
        );

        let direct_quote = state
            .quote_exact_input(&wxmr_usdd_pool_id, DEFI_AMM_DEVNET_FEE_ASSET_ID, 25_000_000)
            .expect("devnet direct quote");
        let direct_route = DefiAmmRoutePlan::new(
            vec![wxmr_usdd_pool_id.clone()],
            vec![
                DEFI_AMM_DEVNET_FEE_ASSET_ID.to_string(),
                DEFI_AMM_DEVNET_STABLE_ASSET_ID.to_string(),
            ],
            direct_quote.amount_in,
            direct_quote.amount_out,
            bps_mul_floor(direct_quote.amount_out, 9_850),
            direct_quote.fee_bps,
            direct_quote.price_impact_bps,
            &state.twap_guard_root(),
            None,
            state.height,
            state.config.route_ttl_blocks,
        )
        .expect("devnet direct route");
        let direct_route_id = direct_route.route_id.clone();
        state.insert_route_plan(direct_route);

        let multi_route_commitment = defi_amm_route_commitment(
            &[wxmr_dnr_pool_id.clone(), dnr_usdd_pool_id.clone()],
            &[
                DEFI_AMM_DEVNET_FEE_ASSET_ID.to_string(),
                DEFI_AMM_DEVNET_GOV_ASSET_ID.to_string(),
                DEFI_AMM_DEVNET_STABLE_ASSET_ID.to_string(),
            ],
        );
        let multi_expected = state
            .quote_route_exact_input(
                &[wxmr_dnr_pool_id.clone(), dnr_usdd_pool_id.clone()],
                &[
                    DEFI_AMM_DEVNET_FEE_ASSET_ID.to_string(),
                    DEFI_AMM_DEVNET_GOV_ASSET_ID.to_string(),
                    DEFI_AMM_DEVNET_STABLE_ASSET_ID.to_string(),
                ],
                18_000_000,
            )
            .expect("devnet multi route quote");
        let multi_route = DefiAmmRoutePlan::new(
            vec![wxmr_dnr_pool_id.clone(), dnr_usdd_pool_id.clone()],
            vec![
                DEFI_AMM_DEVNET_FEE_ASSET_ID.to_string(),
                DEFI_AMM_DEVNET_GOV_ASSET_ID.to_string(),
                DEFI_AMM_DEVNET_STABLE_ASSET_ID.to_string(),
            ],
            18_000_000,
            multi_expected,
            bps_mul_floor(multi_expected, 9_700),
            33,
            180,
            &state.twap_guard_root(),
            None,
            state.height,
            state.config.route_ttl_blocks,
        )
        .expect("devnet multi route");
        let multi_route_id = multi_route.route_id.clone();
        state.insert_route_plan(multi_route);

        let direct_rebate = DefiAmmLowFeeRoutingRebate::new(
            &direct_route_id,
            DEFI_AMM_DEVNET_LOW_FEE_LANE,
            "devnet-foundation",
            DEFI_AMM_DEVNET_FEE_ASSET_ID,
            direct_quote.pool_fee_units.saturating_add(6),
            12,
            5_000,
            "devnet-amm-bond-1",
            state.height,
            48,
        )
        .expect("devnet direct rebate");
        let direct_rebate_id = direct_rebate.rebate_id.clone();
        state.insert_low_fee_rebate(direct_rebate);
        if let Some(route) = state.route_plans.get_mut(&direct_route_id) {
            route.rebate_id = Some(direct_rebate_id);
        }

        let private_commitment = DefiAmmPrivateSwapCommitment::new(
            &wxmr_usdd_pool_id,
            &state.route_plans[&direct_route_id].route_commitment(),
            DEFI_AMM_DEVNET_FEE_ASSET_ID,
            DEFI_AMM_DEVNET_STABLE_ASSET_ID,
            25_000_000,
            bps_mul_floor(direct_quote.amount_out, 9_850),
            30,
            650,
            "devnet-private-nullifier-1",
            "devnet-private-recipient-1",
            "devnet-solver-1",
            &defi_amm_string_root("DEFI-AMM-DEVNET-ENCRYPTED-PAYLOAD", "private-swap-1"),
            &private_profile_id,
            state.height,
            state.config.min_private_swap_delay_blocks,
            64,
        )
        .expect("devnet private commitment");
        let private_commitment_id = private_commitment.commitment_id.clone();
        let private_public_input_root = private_commitment.proof_public_input_root.clone();
        state.insert_private_swap_commitment(private_commitment);

        let proof_record = DefiAmmPrivateSwapProofRecord::new(
            &private_commitment_id,
            None,
            &private_profile_id,
            &private_public_input_root,
            "devnet-private-witness-1",
            &defi_amm_string_root("DEFI-AMM-DEVNET-RECURSIVE-ACCUMULATOR", "private-swap-1"),
            &defi_amm_string_root("DEFI-AMM-DEVNET-VERIFIER-MANIFEST", "private-swap-1"),
            96_768,
            state.height,
        );
        let proof_root = proof_record.proof_root.clone();
        state.insert_private_swap_proof(proof_record);

        let pool_before_root = state.pools[&wxmr_usdd_pool_id].pool_root();
        let mut simulated_pool = state.pools[&wxmr_usdd_pool_id].clone();
        apply_quote_to_pool(
            &mut simulated_pool,
            &state.pool_configs[&wxmr_usdd_pool_id],
            &direct_quote,
            state.config.protocol_fee_share_bps,
            state.height,
        );
        let pool_after_root = simulated_pool.pool_root();
        let receipt = DefiAmmPublicSwapReceipt::new(
            DefiAmmSwapVisibility::Private,
            &defi_amm_string_root("DEFI-AMM-DEVNET-TX", "private-swap-1"),
            state.height,
            &wxmr_usdd_pool_id,
            Some(direct_route_id.clone()),
            &state.route_plans[&direct_route_id].route_commitment(),
            &direct_quote,
            6,
            6,
            &state.twap_observation_root(),
            &state.oracle_guard_root(),
            &proof_root,
            &pool_before_root,
            &pool_after_root,
        );
        state.insert_public_swap_receipt(receipt);

        state.insert_risk_control(
            DefiAmmRiskControl::new(
                None,
                DefiAmmRiskMode::Normal,
                250_000_000,
                350,
                state.config.max_price_impact_bps,
                1_000_000,
                state.config.max_oracle_deviation_bps,
                24,
                1_000_000_000,
                0,
                None,
                None,
                &json!({"scope": "global", "mode": "devnet normal limits"}),
            )
            .expect("devnet global risk control"),
        );
        state.insert_risk_control(
            DefiAmmRiskControl::new(
                Some(wxmr_usdd_pool_id.clone()),
                DefiAmmRiskMode::Watch,
                100_000_000,
                250,
                650,
                10_000,
                600,
                12,
                400_000_000,
                25_000_000,
                Some(state.height),
                Some(state.height.saturating_add(48)),
                &json!({"pool": "wxmr-usdd", "reason": "devnet concentrated-liquidity watch band"}),
            )
            .expect("devnet pool risk control"),
        );

        state.insert_pause_switch(DefiAmmPauseSwitch::new(
            DefiAmmSwitchScope::Global,
            "defi-amm",
            false,
            &json!({"mode": "devnet active"}),
            "devnet-governance",
            state.height,
            None,
            1,
        ));
        state.insert_pause_switch(DefiAmmPauseSwitch::new(
            DefiAmmSwitchScope::Pool,
            &wxmr_dnr_pool_id,
            false,
            &json!({"pool": "wxmr-dnr", "mode": "active"}),
            "devnet-risk-council",
            state.height,
            None,
            2,
        ));
        state.insert_kill_switch(DefiAmmKillSwitch::new(
            DefiAmmSwitchScope::Global,
            "defi-amm",
            false,
            true,
            &json!({"mode": "armed but inactive"}),
            "devnet-governance",
            state.height,
            state.height.saturating_add(10_080),
            &merkle_root("DEFI-AMM-DEVNET-FINAL-STATE", &[]),
        ));

        let private_multi_commitment = DefiAmmPrivateSwapCommitment::new(
            &wxmr_dnr_pool_id,
            &multi_route_commitment,
            DEFI_AMM_DEVNET_FEE_ASSET_ID,
            DEFI_AMM_DEVNET_STABLE_ASSET_ID,
            18_000_000,
            bps_mul_floor(multi_expected, 9_650),
            45,
            900,
            "devnet-private-nullifier-2",
            "devnet-private-recipient-2",
            "devnet-solver-2",
            &defi_amm_string_root("DEFI-AMM-DEVNET-ENCRYPTED-PAYLOAD", "private-route-2"),
            &route_profile_id,
            state.height.saturating_sub(1),
            state.config.min_private_swap_delay_blocks,
            72,
        )
        .expect("devnet private route commitment");
        state.insert_private_swap_commitment(private_multi_commitment);

        let multi_rebate_id = defi_amm_low_fee_rebate_id(
            &multi_route_id,
            DEFI_AMM_DEVNET_LOW_FEE_LANE,
            &defi_amm_account_commitment("devnet-routing-sponsor"),
            DEFI_AMM_DEVNET_FEE_ASSET_ID,
            18,
            14,
            4_000,
            state.height,
        );
        if let Some(route) = state.route_plans.get_mut(&multi_route_id) {
            route.rebate_id = Some(multi_rebate_id);
        }

        state
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) -> u64 {
        self.height = self.height.saturating_add(blocks);
        self.height
    }

    pub fn insert_pool_config(&mut self, config: DefiAmmPoolConfig) {
        self.pool_configs.insert(config.pool_id.clone(), config);
    }

    pub fn insert_pool(&mut self, pool: DefiAmmPoolState) {
        self.pools.insert(pool.pool_id.clone(), pool);
    }

    pub fn insert_tick(&mut self, tick: DefiAmmTick) {
        self.ticks.insert(tick.tick_id.clone(), tick);
    }

    pub fn insert_liquidity_range(&mut self, range: DefiAmmLiquidityRange) {
        self.liquidity_ranges.insert(range.range_id.clone(), range);
    }

    pub fn insert_lp_position(&mut self, position: DefiAmmLpPosition) {
        self.lp_positions
            .insert(position.position_id.clone(), position);
    }

    pub fn insert_route_plan(&mut self, route: DefiAmmRoutePlan) {
        self.route_plans.insert(route.route_id.clone(), route);
    }

    pub fn insert_private_swap_commitment(&mut self, commitment: DefiAmmPrivateSwapCommitment) {
        self.private_swap_commitments
            .insert(commitment.commitment_id.clone(), commitment);
    }

    pub fn insert_public_swap_receipt(&mut self, receipt: DefiAmmPublicSwapReceipt) {
        self.public_swap_receipts
            .insert(receipt.receipt_id.clone(), receipt);
    }

    pub fn insert_twap_observation(&mut self, observation: DefiAmmTwapObservation) {
        self.twap_observations
            .insert(observation.observation_id.clone(), observation);
    }

    pub fn insert_oracle_guard(&mut self, guard: DefiAmmOracleGuard) {
        self.oracle_guards.insert(guard.guard_id.clone(), guard);
    }

    pub fn insert_low_fee_rebate(&mut self, rebate: DefiAmmLowFeeRoutingRebate) {
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
    }

    pub fn insert_circuit_profile(&mut self, profile: DefiAmmPrivateSwapCircuitProfile) {
        self.circuit_profiles
            .insert(profile.profile_id.clone(), profile);
    }

    pub fn insert_private_swap_proof(&mut self, proof: DefiAmmPrivateSwapProofRecord) {
        self.private_swap_proofs
            .insert(proof.proof_id.clone(), proof);
    }

    pub fn insert_risk_control(&mut self, control: DefiAmmRiskControl) {
        self.risk_controls
            .insert(control.control_id.clone(), control);
    }

    pub fn insert_pause_switch(&mut self, switch: DefiAmmPauseSwitch) {
        self.pause_switches.insert(switch.switch_id.clone(), switch);
    }

    pub fn insert_kill_switch(&mut self, switch: DefiAmmKillSwitch) {
        self.kill_switches.insert(switch.kill_id.clone(), switch);
    }

    pub fn quote_exact_input(
        &self,
        pool_id: &str,
        asset_in_id: &str,
        amount_in: u64,
    ) -> DefiAmmResult<DefiAmmSwapQuote> {
        if amount_in == 0 {
            return Err("AMM quote amount must be positive".to_string());
        }
        self.ensure_pool_trade_enabled(pool_id)?;
        let config = self
            .pool_configs
            .get(pool_id)
            .ok_or_else(|| "AMM pool config not found".to_string())?;
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "AMM pool state not found".to_string())?;
        let (reserve_in, reserve_out, asset_out_id) =
            pool.reserves_for_asset(config, asset_in_id)?;
        if reserve_in == 0 || reserve_out == 0 {
            return Err("AMM pool has no liquidity".to_string());
        }
        let pool_fee_units = bps_mul_floor(amount_in, config.fee_bps);
        let protocol_fee_units = bps_mul_floor(pool_fee_units, self.config.protocol_fee_share_bps);
        let amount_in_after_fee = amount_in.saturating_sub(pool_fee_units);
        let amount_out = match config.pool_kind {
            DefiAmmPoolKind::ConstantProduct | DefiAmmPoolKind::Concentrated => {
                constant_product_output(amount_in_after_fee, reserve_in, reserve_out)
            }
            DefiAmmPoolKind::Stable => {
                stable_pool_output(amount_in_after_fee, reserve_in, reserve_out)
            }
        };
        if amount_out == 0 || amount_out >= reserve_out {
            return Err("AMM quote output is outside pool liquidity".to_string());
        }
        let price_impact_bps =
            price_impact_bps(amount_in_after_fee, amount_out, reserve_in, reserve_out);
        let quote = DefiAmmSwapQuote::new(
            pool_id,
            asset_in_id,
            &asset_out_id,
            amount_in,
            amount_in_after_fee,
            amount_out,
            pool_fee_units,
            protocol_fee_units,
            config.fee_bps,
            price_impact_bps,
            reserve_in,
            reserve_out,
        );
        self.enforce_risk_controls(pool_id, amount_in, reserve_in, price_impact_bps)?;
        Ok(quote)
    }

    pub fn quote_route_exact_input(
        &self,
        pool_ids: &[String],
        asset_path: &[String],
        amount_in: u64,
    ) -> DefiAmmResult<u64> {
        if pool_ids.is_empty() || asset_path.len() != pool_ids.len().saturating_add(1) {
            return Err("AMM route quote path is invalid".to_string());
        }
        if pool_ids.len() as u64 > self.config.max_route_hops {
            return Err("AMM route exceeds hop limit".to_string());
        }
        let mut amount = amount_in;
        for (pool_id, asset_pair) in pool_ids.iter().zip(asset_path.windows(2)) {
            let quote = self.quote_exact_input(pool_id, &asset_pair[0], amount)?;
            if quote.asset_out_id != asset_pair[1] {
                return Err("AMM route asset path mismatch".to_string());
            }
            amount = quote.amount_out;
        }
        Ok(amount)
    }

    pub fn record_public_swap(
        &mut self,
        pool_id: &str,
        asset_in_id: &str,
        amount_in: u64,
        tx_public_hash: &str,
        network_fee_units: u64,
    ) -> DefiAmmResult<DefiAmmPublicSwapReceipt> {
        let quote = self.quote_exact_input(pool_id, asset_in_id, amount_in)?;
        let config = self
            .pool_configs
            .get(pool_id)
            .ok_or_else(|| "AMM pool config not found".to_string())?
            .clone();
        let pool_before_root = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "AMM pool state not found".to_string())?
            .pool_root();
        {
            let pool = self
                .pools
                .get_mut(pool_id)
                .ok_or_else(|| "AMM pool state not found".to_string())?;
            apply_quote_to_pool(
                pool,
                &config,
                &quote,
                self.config.protocol_fee_share_bps,
                self.height,
            );
        }
        let pool_after_root = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "AMM pool state not found".to_string())?
            .pool_root();
        let route_commitment = defi_amm_route_commitment(
            &[pool_id.to_string()],
            &[quote.asset_in_id.clone(), quote.asset_out_id.clone()],
        );
        let receipt = DefiAmmPublicSwapReceipt::new(
            DefiAmmSwapVisibility::Public,
            tx_public_hash,
            self.height,
            pool_id,
            None,
            &route_commitment,
            &quote,
            network_fee_units,
            0,
            &self.twap_observation_root(),
            &self.oracle_guard_root(),
            &merkle_root("DEFI-AMM-PUBLIC-SWAP-PROOF", &[]),
            &pool_before_root,
            &pool_after_root,
        );
        self.insert_public_swap_receipt(receipt.clone());
        Ok(receipt)
    }

    pub fn ensure_pool_trade_enabled(&self, pool_id: &str) -> DefiAmmResult<()> {
        if self.is_scope_killed(DefiAmmSwitchScope::Global, "defi-amm") {
            return Err("AMM global kill switch is active".to_string());
        }
        if self.is_scope_killed(DefiAmmSwitchScope::Pool, pool_id) {
            return Err("AMM pool kill switch is active".to_string());
        }
        if self.is_scope_paused(DefiAmmSwitchScope::Global, "defi-amm") {
            return Err("AMM global pause switch is active".to_string());
        }
        if self.is_scope_paused(DefiAmmSwitchScope::Pool, pool_id) {
            return Err("AMM pool pause switch is active".to_string());
        }
        Ok(())
    }

    pub fn is_scope_paused(&self, scope: DefiAmmSwitchScope, target_id: &str) -> bool {
        self.pause_switches.values().any(|switch| {
            switch.scope == scope && switch.target_id == target_id && switch.active_at(self.height)
        })
    }

    pub fn is_scope_killed(&self, scope: DefiAmmSwitchScope, target_id: &str) -> bool {
        self.kill_switches
            .values()
            .any(|switch| switch.scope == scope && switch.target_id == target_id && switch.active())
    }

    pub fn enforce_risk_controls(
        &self,
        pool_id: &str,
        amount_in: u64,
        reserve_in: u64,
        price_impact_bps: u64,
    ) -> DefiAmmResult<()> {
        for control in self.risk_controls.values() {
            if !control.active_at(self.height) || !control.applies_to_pool(pool_id) {
                continue;
            }
            if control.mode.blocks_trading() {
                return Err("AMM risk control blocks trading".to_string());
            }
            if control.max_trade_units > 0 && amount_in > control.max_trade_units {
                return Err("AMM trade exceeds risk max_trade_units".to_string());
            }
            let pool_bps_limit = bps_mul_floor(reserve_in, control.max_trade_bps_of_pool);
            if pool_bps_limit > 0 && amount_in > pool_bps_limit {
                return Err("AMM trade exceeds pool percentage risk limit".to_string());
            }
            if control.max_price_impact_bps > 0 && price_impact_bps > control.max_price_impact_bps {
                return Err("AMM trade exceeds price impact risk limit".to_string());
            }
            if control.volume_cap_units > 0
                && control.triggered_volume_units.saturating_add(amount_in)
                    > control.volume_cap_units
            {
                return Err("AMM trade exceeds volume risk limit".to_string());
            }
        }
        Ok(())
    }

    pub fn pool_config_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-POOL-CONFIG",
            &self
                .pool_configs
                .values()
                .map(DefiAmmPoolConfig::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pool_state_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-POOL-STATE",
            &self
                .pools
                .values()
                .map(DefiAmmPoolState::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn tick_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-TICK",
            &self
                .ticks
                .values()
                .map(DefiAmmTick::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn liquidity_range_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-LIQUIDITY-RANGE",
            &self
                .liquidity_ranges
                .values()
                .map(DefiAmmLiquidityRange::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn lp_position_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-LP-POSITION",
            &self
                .lp_positions
                .values()
                .map(DefiAmmLpPosition::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn route_plan_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-ROUTE-PLAN",
            &self
                .route_plans
                .values()
                .map(DefiAmmRoutePlan::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_swap_commitment_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-PRIVATE-SWAP-COMMITMENT",
            &self
                .private_swap_commitments
                .values()
                .map(DefiAmmPrivateSwapCommitment::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_swap_receipt_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-PUBLIC-SWAP-RECEIPT",
            &self
                .public_swap_receipts
                .values()
                .map(DefiAmmPublicSwapReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn twap_observation_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-TWAP-OBSERVATION",
            &self
                .twap_observations
                .values()
                .map(DefiAmmTwapObservation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn oracle_guard_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-ORACLE-GUARD",
            &self
                .oracle_guards
                .values()
                .map(DefiAmmOracleGuard::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn twap_guard_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-TWAP-GUARD",
            &[json!({
                "twap_observation_root": self.twap_observation_root(),
                "oracle_guard_root": self.oracle_guard_root(),
                "twap_observation_count": self.twap_observations.len() as u64,
                "oracle_guard_count": self.oracle_guards.len() as u64,
            })],
        )
    }

    pub fn low_fee_rebate_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-LOW-FEE-REBATE",
            &self
                .low_fee_rebates
                .values()
                .map(DefiAmmLowFeeRoutingRebate::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn circuit_profile_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-CIRCUIT-PROFILE",
            &self
                .circuit_profiles
                .values()
                .map(DefiAmmPrivateSwapCircuitProfile::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_swap_proof_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-PRIVATE-SWAP-PROOF",
            &self
                .private_swap_proofs
                .values()
                .map(DefiAmmPrivateSwapProofRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn risk_control_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-RISK-CONTROL",
            &self
                .risk_controls
                .values()
                .map(DefiAmmRiskControl::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn pause_switch_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-PAUSE-SWITCH",
            &self
                .pause_switches
                .values()
                .map(DefiAmmPauseSwitch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn kill_switch_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-KILL-SWITCH",
            &self
                .kill_switches
                .values()
                .map(DefiAmmKillSwitch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn control_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-CONTROL",
            &[json!({
                "risk_control_root": self.risk_control_root(),
                "pause_switch_root": self.pause_switch_root(),
                "kill_switch_root": self.kill_switch_root(),
                "risk_control_count": self.risk_controls.len() as u64,
                "pause_switch_count": self.pause_switches.len() as u64,
                "kill_switch_count": self.kill_switches.len() as u64,
            })],
        )
    }

    pub fn proof_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-PROOF-SURFACE",
            &[json!({
                "circuit_profile_root": self.circuit_profile_root(),
                "private_swap_proof_root": self.private_swap_proof_root(),
                "private_swap_commitment_root": self.private_swap_commitment_root(),
                "circuit_profile_count": self.circuit_profiles.len() as u64,
                "private_swap_proof_count": self.private_swap_proofs.len() as u64,
            })],
        )
    }

    pub fn liquidity_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-LIQUIDITY",
            &[json!({
                "pool_state_root": self.pool_state_root(),
                "tick_root": self.tick_root(),
                "liquidity_range_root": self.liquidity_range_root(),
                "lp_position_root": self.lp_position_root(),
                "total_active_liquidity": self.total_active_liquidity(),
                "total_lp_position_value_units": self.total_lp_position_value_units(),
            })],
        )
    }

    pub fn swap_surface_root(&self) -> String {
        merkle_root(
            "DEFI-AMM-SWAP-SURFACE",
            &[json!({
                "route_plan_root": self.route_plan_root(),
                "private_swap_commitment_root": self.private_swap_commitment_root(),
                "public_swap_receipt_root": self.public_swap_receipt_root(),
                "low_fee_rebate_root": self.low_fee_rebate_root(),
            })],
        )
    }

    pub fn state_root(&self) -> String {
        defi_amm_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("defi AMM state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "defi_amm_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DEFI_AMM_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "pool_config_root": self.pool_config_root(),
            "pool_state_root": self.pool_state_root(),
            "tick_root": self.tick_root(),
            "liquidity_range_root": self.liquidity_range_root(),
            "lp_position_root": self.lp_position_root(),
            "liquidity_root": self.liquidity_root(),
            "route_plan_root": self.route_plan_root(),
            "private_swap_commitment_root": self.private_swap_commitment_root(),
            "public_swap_receipt_root": self.public_swap_receipt_root(),
            "swap_surface_root": self.swap_surface_root(),
            "twap_observation_root": self.twap_observation_root(),
            "oracle_guard_root": self.oracle_guard_root(),
            "twap_guard_root": self.twap_guard_root(),
            "low_fee_rebate_root": self.low_fee_rebate_root(),
            "circuit_profile_root": self.circuit_profile_root(),
            "private_swap_proof_root": self.private_swap_proof_root(),
            "proof_root": self.proof_root(),
            "risk_control_root": self.risk_control_root(),
            "pause_switch_root": self.pause_switch_root(),
            "kill_switch_root": self.kill_switch_root(),
            "control_root": self.control_root(),
            "pool_config_count": self.pool_configs.len() as u64,
            "pool_count": self.pools.len() as u64,
            "tick_count": self.ticks.len() as u64,
            "liquidity_range_count": self.liquidity_ranges.len() as u64,
            "lp_position_count": self.lp_positions.len() as u64,
            "route_plan_count": self.route_plans.len() as u64,
            "private_swap_commitment_count": self.private_swap_commitments.len() as u64,
            "pending_private_swap_count": self.pending_private_swap_count(),
            "public_swap_receipt_count": self.public_swap_receipts.len() as u64,
            "twap_observation_count": self.twap_observations.len() as u64,
            "oracle_guard_count": self.oracle_guards.len() as u64,
            "low_fee_rebate_count": self.low_fee_rebates.len() as u64,
            "circuit_profile_count": self.circuit_profiles.len() as u64,
            "private_swap_proof_count": self.private_swap_proofs.len() as u64,
            "risk_control_count": self.risk_controls.len() as u64,
            "pause_switch_count": self.pause_switches.len() as u64,
            "kill_switch_count": self.kill_switches.len() as u64,
            "active_pool_count": self.active_pool_count(),
            "active_pause_count": self.active_pause_count(),
            "active_kill_count": self.active_kill_count(),
            "total_active_liquidity": self.total_active_liquidity(),
            "total_lp_position_value_units": self.total_lp_position_value_units(),
            "total_protocol_fee_units": self.total_protocol_fee_units(),
            "total_rebate_units": self.total_rebate_units(),
        })
    }

    pub fn active_pool_count(&self) -> u64 {
        self.pool_configs
            .values()
            .filter(|config| config.status == DEFI_AMM_STATUS_ACTIVE)
            .count() as u64
    }

    pub fn active_pause_count(&self) -> u64 {
        self.pause_switches
            .values()
            .filter(|switch| switch.active_at(self.height))
            .count() as u64
    }

    pub fn active_kill_count(&self) -> u64 {
        self.kill_switches
            .values()
            .filter(|switch| switch.active())
            .count() as u64
    }

    pub fn pending_private_swap_count(&self) -> u64 {
        self.private_swap_commitments
            .values()
            .filter(|commitment| commitment.status == DEFI_AMM_STATUS_PENDING)
            .count() as u64
    }

    pub fn total_active_liquidity(&self) -> u64 {
        self.pools.values().fold(0_u64, |total, pool| {
            total.saturating_add(pool.active_liquidity)
        })
    }

    pub fn total_lp_position_value_units(&self) -> u64 {
        self.lp_positions.values().fold(0_u64, |total, position| {
            total.saturating_add(position.position_value_units())
        })
    }

    pub fn total_protocol_fee_units(&self) -> u64 {
        self.pools.values().fold(0_u64, |total, pool| {
            total
                .saturating_add(pool.protocol_fee_x)
                .saturating_add(pool.protocol_fee_y)
        })
    }

    pub fn total_rebate_units(&self) -> u64 {
        self.low_fee_rebates.values().fold(0_u64, |total, rebate| {
            total.saturating_add(rebate.rebate_units)
        })
    }

    fn install_devnet_ticks_and_ranges(
        &mut self,
        pool_id: &str,
        lower_tick: i64,
        upper_tick: i64,
        liquidity: u64,
    ) {
        self.insert_tick(DefiAmmTick::new(
            pool_id,
            lower_tick,
            liquidity,
            liquidity as i128,
            self.height,
        ));
        self.insert_tick(DefiAmmTick::new(pool_id, 0, liquidity, 0, self.height));
        self.insert_tick(DefiAmmTick::new(
            pool_id,
            upper_tick,
            liquidity,
            -(liquidity as i128),
            self.height,
        ));
        let range = DefiAmmLiquidityRange::new(
            pool_id,
            lower_tick,
            upper_tick,
            liquidity,
            liquidity / 12,
            liquidity.saturating_mul(16),
            self.height,
        )
        .expect("devnet AMM liquidity range");
        self.insert_liquidity_range(range);
    }

    fn install_devnet_oracle_and_twap(
        &mut self,
        pool_id: &str,
        feed_id: &str,
        reference_price_scaled: u64,
    ) {
        let pool = self.pools.get(pool_id).expect("devnet AMM pool");
        let observation = DefiAmmTwapObservation::new(
            pool_id,
            self.height,
            self.height
                .saturating_sub(self.config.default_twap_window_blocks),
            self.height,
            pool.reserve_x,
            pool.reserve_y,
            4,
        );
        let twap_price = observation.price_x_to_y_scaled;
        self.insert_twap_observation(observation);
        let guard = DefiAmmOracleGuard::new(
            pool_id,
            feed_id,
            reference_price_scaled,
            twap_price,
            self.config.max_oracle_deviation_bps,
            self.config.max_oracle_staleness_blocks,
            self.height.saturating_sub(1),
            self.height,
            &json!({
                "feed_id": feed_id,
                "mode": "deterministic_devnet",
                "reference_price_scaled": reference_price_scaled,
                "twap_price_scaled": twap_price,
            }),
        )
        .expect("devnet oracle guard");
        self.insert_oracle_guard(guard);
    }
}

pub fn apply_quote_to_pool(
    pool: &mut DefiAmmPoolState,
    config: &DefiAmmPoolConfig,
    quote: &DefiAmmSwapQuote,
    protocol_fee_share_bps: u64,
    height: u64,
) {
    let pool_fee_kept = quote
        .pool_fee_units
        .saturating_sub(bps_mul_floor(quote.pool_fee_units, protocol_fee_share_bps));
    if quote.asset_in_id == config.asset_x_id {
        pool.reserve_x = pool
            .reserve_x
            .saturating_add(quote.amount_in_after_fee)
            .saturating_add(pool_fee_kept);
        pool.reserve_y = pool.reserve_y.saturating_sub(quote.amount_out);
        pool.protocol_fee_x = pool.protocol_fee_x.saturating_add(quote.protocol_fee_units);
        pool.volume_x = pool.volume_x.saturating_add(quote.amount_in);
        pool.fee_growth_global_x = pool.fee_growth_global_x.saturating_add(pool_fee_kept);
    } else {
        pool.reserve_y = pool
            .reserve_y
            .saturating_add(quote.amount_in_after_fee)
            .saturating_add(pool_fee_kept);
        pool.reserve_x = pool.reserve_x.saturating_sub(quote.amount_out);
        pool.protocol_fee_y = pool.protocol_fee_y.saturating_add(quote.protocol_fee_units);
        pool.volume_y = pool.volume_y.saturating_add(quote.amount_in);
        pool.fee_growth_global_y = pool.fee_growth_global_y.saturating_add(pool_fee_kept);
    }
    pool.active_liquidity =
        integer_sqrt_u128((pool.reserve_x as u128).saturating_mul(pool.reserve_y as u128));
    pool.sqrt_price_x64 = tick_sqrt_price_x64(pool.current_tick);
    pool.swap_count = pool.swap_count.saturating_add(1);
    pool.last_updated_height = height;
}

pub fn validate_bps(label: &str, value: u64) -> DefiAmmResult<()> {
    if value > DEFI_AMM_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

pub fn bps_mul_floor(amount: u64, bps: u64) -> u64 {
    let product = (amount as u128).saturating_mul(bps.min(DEFI_AMM_MAX_BPS) as u128);
    u128_to_u64_saturating(product / DEFI_AMM_MAX_BPS as u128)
}

pub fn scaled_ratio(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let scaled = (numerator as u128).saturating_mul(DEFI_AMM_PRICE_SCALE as u128);
    u128_to_u64_saturating(scaled / denominator as u128)
}

pub fn constant_product_output(amount_in_after_fee: u64, reserve_in: u64, reserve_out: u64) -> u64 {
    if amount_in_after_fee == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let numerator = (amount_in_after_fee as u128).saturating_mul(reserve_out as u128);
    let denominator = (reserve_in as u128).saturating_add(amount_in_after_fee as u128);
    u128_to_u64_saturating(numerator / denominator)
}

pub fn stable_pool_output(amount_in_after_fee: u64, reserve_in: u64, reserve_out: u64) -> u64 {
    if amount_in_after_fee == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let imbalance = reserve_in.abs_diff(reserve_out);
    let imbalance_bps = if reserve_in.saturating_add(reserve_out) == 0 {
        0
    } else {
        u128_to_u64_saturating(
            (imbalance as u128).saturating_mul(DEFI_AMM_MAX_BPS as u128)
                / reserve_in.saturating_add(reserve_out) as u128,
        )
    };
    let stable_discount_bps = imbalance_bps.min(250);
    let near_par_output =
        amount_in_after_fee.saturating_sub(bps_mul_floor(amount_in_after_fee, stable_discount_bps));
    near_par_output.min(reserve_out.saturating_sub(1))
}

pub fn price_impact_bps(
    amount_in_after_fee: u64,
    amount_out: u64,
    reserve_in: u64,
    reserve_out: u64,
) -> u64 {
    if amount_in_after_fee == 0 || amount_out == 0 || reserve_in == 0 || reserve_out == 0 {
        return 0;
    }
    let spot_out = u128_to_u64_saturating(
        (amount_in_after_fee as u128).saturating_mul(reserve_out as u128) / reserve_in as u128,
    );
    if spot_out == 0 || amount_out >= spot_out {
        return 0;
    }
    u128_to_u64_saturating(
        (spot_out.saturating_sub(amount_out) as u128).saturating_mul(DEFI_AMM_MAX_BPS as u128)
            / spot_out as u128,
    )
}

pub fn deviation_bps(reference: u64, observed: u64) -> u64 {
    if reference == 0 {
        return if observed == 0 { 0 } else { DEFI_AMM_MAX_BPS };
    }
    u128_to_u64_saturating(
        (reference.abs_diff(observed) as u128).saturating_mul(DEFI_AMM_MAX_BPS as u128)
            / reference as u128,
    )
}

pub fn tick_sqrt_price_x64(tick_index: i64) -> u64 {
    let step = 1_000_000_u64;
    if tick_index >= 0 {
        DEFI_AMM_PRICE_SCALE.saturating_add((tick_index as u64).saturating_mul(step))
    } else {
        DEFI_AMM_PRICE_SCALE
            .saturating_sub(abs_i64_to_u64(tick_index).saturating_mul(step))
            .max(1)
    }
}

pub fn integer_sqrt_u128(value: u128) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut x0 = value;
    let mut x1 = (x0.saturating_add(value / x0)) / 2;
    while x1 < x0 {
        x0 = x1;
        x1 = (x0.saturating_add(value / x0)) / 2;
    }
    u128_to_u64_saturating(x0)
}

pub fn u128_to_u64_saturating(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

pub fn abs_i64_to_u64(value: i64) -> u64 {
    if value == i64::MIN {
        (i64::MAX as u64).saturating_add(1)
    } else if value < 0 {
        (-value) as u64
    } else {
        value as u64
    }
}

pub fn defi_amm_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn defi_amm_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "DEFI-AMM-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn defi_amm_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn defi_amm_string_set_root(domain: &str, values: &[String]) -> String {
    let mut leaves = values.to_vec();
    leaves.sort();
    merkle_root(
        domain,
        &leaves.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

pub fn defi_amm_account_commitment(label: &str) -> String {
    domain_hash(
        "DEFI-AMM-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn defi_amm_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "DEFI-AMM-ASSET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn defi_amm_nullifier_hash(label: &str) -> String {
    domain_hash(
        "DEFI-AMM-NULLIFIER-HASH",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn defi_amm_witness_commitment(label: &str) -> String {
    domain_hash(
        "DEFI-AMM-WITNESS-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_pool_id(
    pool_kind: DefiAmmPoolKind,
    asset_x_id: &str,
    asset_y_id: &str,
    lp_asset_id: &str,
    fee_bps: u64,
    tick_spacing: i64,
    min_tick: i64,
    max_tick: i64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_kind.as_str()),
            HashPart::Str(asset_x_id),
            HashPart::Str(asset_y_id),
            HashPart::Str(lp_asset_id),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(tick_spacing as i128),
            HashPart::Int(min_tick as i128),
            HashPart::Int(max_tick as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn defi_amm_pool_config_root(config: &DefiAmmPoolConfig) -> String {
    defi_amm_payload_root("DEFI-AMM-POOL-CONFIG-ROOT", &config.public_record())
}

pub fn defi_amm_pool_state_root(pool: &DefiAmmPoolState) -> String {
    defi_amm_payload_root("DEFI-AMM-POOL-STATE-ROOT", &pool.public_record())
}

pub fn defi_amm_tick_id(pool_id: &str, tick_index: i64) -> String {
    domain_hash(
        "DEFI-AMM-TICK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(tick_index as i128),
        ],
        32,
    )
}

pub fn defi_amm_tick_root(tick: &DefiAmmTick) -> String {
    defi_amm_payload_root("DEFI-AMM-TICK-ROOT", &tick.public_record())
}

pub fn defi_amm_liquidity_range_id(
    pool_id: &str,
    lower_tick: i64,
    upper_tick: i64,
    liquidity: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-LIQUIDITY-RANGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(lower_tick as i128),
            HashPart::Int(upper_tick as i128),
            HashPart::Int(liquidity as i128),
        ],
        32,
    )
}

pub fn defi_amm_liquidity_range_root(range: &DefiAmmLiquidityRange) -> String {
    defi_amm_payload_root("DEFI-AMM-LIQUIDITY-RANGE-ROOT", &range.public_record())
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_lp_position_id(
    owner_commitment: &str,
    pool_id: &str,
    range_id: &str,
    lower_tick: i64,
    upper_tick: i64,
    liquidity: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-LP-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(pool_id),
            HashPart::Str(range_id),
            HashPart::Int(lower_tick as i128),
            HashPart::Int(upper_tick as i128),
            HashPart::Int(liquidity as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn defi_amm_lp_position_root(position: &DefiAmmLpPosition) -> String {
    defi_amm_payload_root("DEFI-AMM-LP-POSITION-ROOT", &position.public_record())
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_swap_quote_id(
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    amount_in: u64,
    amount_out: u64,
    fee_bps: u64,
    reserve_in_before: u64,
    reserve_out_before: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-SWAP-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(amount_in as i128),
            HashPart::Int(amount_out as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(reserve_in_before as i128),
            HashPart::Int(reserve_out_before as i128),
        ],
        32,
    )
}

pub fn defi_amm_route_commitment(pool_ids: &[String], asset_path: &[String]) -> String {
    let pool_leaves = pool_ids
        .iter()
        .enumerate()
        .map(|(index, pool_id)| json!({"index": index as u64, "pool_id": pool_id}))
        .collect::<Vec<_>>();
    let asset_leaves = asset_path
        .iter()
        .enumerate()
        .map(|(index, asset_id)| json!({"index": index as u64, "asset_id": asset_id}))
        .collect::<Vec<_>>();
    let pool_root = merkle_root("DEFI-AMM-ROUTE-POOL-PATH", &pool_leaves);
    let asset_root = merkle_root("DEFI-AMM-ROUTE-ASSET-PATH", &asset_leaves);
    domain_hash(
        "DEFI-AMM-ROUTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&pool_root),
            HashPart::Str(&asset_root),
            HashPart::Int(pool_ids.len() as i128),
            HashPart::Int(asset_path.len() as i128),
        ],
        32,
    )
}

pub fn defi_amm_route_id(
    pool_ids: &[String],
    asset_path: &[String],
    input_amount: u64,
    expected_output_amount: u64,
    worst_case_output_amount: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&defi_amm_route_commitment(pool_ids, asset_path)),
            HashPart::Int(input_amount as i128),
            HashPart::Int(expected_output_amount as i128),
            HashPart::Int(worst_case_output_amount as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn defi_amm_route_plan_root(route: &DefiAmmRoutePlan) -> String {
    defi_amm_payload_root("DEFI-AMM-ROUTE-PLAN-ROOT", &route.public_record())
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_private_swap_public_input_root(
    pool_id: &str,
    route_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_bucket: u64,
    min_amount_out_bucket: u64,
    max_fee_bps: u64,
    max_price_impact_bps: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-PRIVATE-SWAP-PUBLIC-INPUT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(route_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Int(amount_in_bucket as i128),
            HashPart::Int(min_amount_out_bucket as i128),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Int(max_price_impact_bps as i128),
        ],
        32,
    )
}

pub fn defi_amm_private_swap_proof_commitment_root(
    nullifier_hash: &str,
    recipient_commitment: &str,
    encrypted_payload_hash: &str,
    proof_public_input_root: &str,
    circuit_profile_id: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-PRIVATE-SWAP-PROOF-COMMITMENT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier_hash),
            HashPart::Str(recipient_commitment),
            HashPart::Str(encrypted_payload_hash),
            HashPart::Str(proof_public_input_root),
            HashPart::Str(circuit_profile_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_private_swap_commitment_id(
    pool_id: &str,
    route_commitment: &str,
    asset_in_commitment: &str,
    asset_out_commitment: &str,
    amount_in_bucket: u64,
    min_amount_out_bucket: u64,
    nullifier_hash: &str,
    recipient_commitment: &str,
    solver_commitment: &str,
    commit_height: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-PRIVATE-SWAP-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(route_commitment),
            HashPart::Str(asset_in_commitment),
            HashPart::Str(asset_out_commitment),
            HashPart::Int(amount_in_bucket as i128),
            HashPart::Int(min_amount_out_bucket as i128),
            HashPart::Str(nullifier_hash),
            HashPart::Str(recipient_commitment),
            HashPart::Str(solver_commitment),
            HashPart::Int(commit_height as i128),
        ],
        32,
    )
}

pub fn defi_amm_private_swap_commitment_root(commitment: &DefiAmmPrivateSwapCommitment) -> String {
    defi_amm_payload_root(
        "DEFI-AMM-PRIVATE-SWAP-COMMITMENT-ROOT",
        &commitment.public_record(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_public_swap_receipt_id(
    tx_public_hash: &str,
    block_height: u64,
    pool_id: &str,
    asset_in_id: &str,
    asset_out_id: &str,
    amount_in: u64,
    amount_out: u64,
    pool_before_root: &str,
    pool_after_root: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-PUBLIC-SWAP-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tx_public_hash),
            HashPart::Int(block_height as i128),
            HashPart::Str(pool_id),
            HashPart::Str(asset_in_id),
            HashPart::Str(asset_out_id),
            HashPart::Int(amount_in as i128),
            HashPart::Int(amount_out as i128),
            HashPart::Str(pool_before_root),
            HashPart::Str(pool_after_root),
        ],
        32,
    )
}

pub fn defi_amm_public_swap_receipt_root(receipt: &DefiAmmPublicSwapReceipt) -> String {
    defi_amm_payload_root(
        "DEFI-AMM-PUBLIC-SWAP-RECEIPT-ROOT",
        &receipt.public_record(),
    )
}

pub fn defi_amm_twap_observation_id(
    pool_id: &str,
    block_height: u64,
    window_start_height: u64,
    window_end_height: u64,
    price_x_to_y_scaled: u64,
    price_y_to_x_scaled: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-TWAP-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Int(block_height as i128),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
            HashPart::Int(price_x_to_y_scaled as i128),
            HashPart::Int(price_y_to_x_scaled as i128),
        ],
        32,
    )
}

pub fn defi_amm_twap_observation_root(observation: &DefiAmmTwapObservation) -> String {
    defi_amm_payload_root(
        "DEFI-AMM-TWAP-OBSERVATION-ROOT",
        &observation.public_record(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_oracle_guard_id(
    pool_id: &str,
    oracle_feed_id: &str,
    reference_price_scaled: u64,
    twap_price_scaled: u64,
    max_deviation_bps: u64,
    last_oracle_height: u64,
    last_twap_height: u64,
    evidence_root: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-ORACLE-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(reference_price_scaled as i128),
            HashPart::Int(twap_price_scaled as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Int(last_oracle_height as i128),
            HashPart::Int(last_twap_height as i128),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn defi_amm_oracle_guard_root(guard: &DefiAmmOracleGuard) -> String {
    defi_amm_payload_root("DEFI-AMM-ORACLE-GUARD-ROOT", &guard.public_record())
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_low_fee_rebate_id(
    route_id: &str,
    lane_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    gross_fee_units: u64,
    eligible_fee_units: u64,
    rebate_bps: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(eligible_fee_units as i128),
            HashPart::Int(rebate_bps as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn defi_amm_low_fee_rebate_root(rebate: &DefiAmmLowFeeRoutingRebate) -> String {
    defi_amm_payload_root("DEFI-AMM-LOW-FEE-REBATE-ROOT", &rebate.public_record())
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_circuit_profile_id(
    proof_system: &str,
    circuit_family: &str,
    version: u64,
    verifying_key_root: &str,
    parameter_root: &str,
    public_input_schema_root: &str,
    private_witness_schema_root: &str,
    recursion_depth: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-CIRCUIT-PROFILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(circuit_family),
            HashPart::Int(version as i128),
            HashPart::Str(verifying_key_root),
            HashPart::Str(parameter_root),
            HashPart::Str(public_input_schema_root),
            HashPart::Str(private_witness_schema_root),
            HashPart::Int(recursion_depth as i128),
        ],
        32,
    )
}

pub fn defi_amm_circuit_profile_root(profile: &DefiAmmPrivateSwapCircuitProfile) -> String {
    defi_amm_payload_root("DEFI-AMM-CIRCUIT-PROFILE-ROOT", &profile.public_record())
}

pub fn defi_amm_private_swap_proof_root(
    commitment_id: &str,
    receipt_id: &str,
    profile_id: &str,
    public_input_root: &str,
    private_witness_commitment: &str,
    recursive_accumulator_root: &str,
    verifier_manifest_root: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-PRIVATE-SWAP-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(commitment_id),
            HashPart::Str(receipt_id),
            HashPart::Str(profile_id),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_commitment),
            HashPart::Str(recursive_accumulator_root),
            HashPart::Str(verifier_manifest_root),
        ],
        32,
    )
}

pub fn defi_amm_private_swap_proof_id(
    commitment_id: &str,
    receipt_id: &str,
    profile_id: &str,
    proof_root: &str,
    verified_at_height: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-PRIVATE-SWAP-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(commitment_id),
            HashPart::Str(receipt_id),
            HashPart::Str(profile_id),
            HashPart::Str(proof_root),
            HashPart::Int(verified_at_height as i128),
        ],
        32,
    )
}

pub fn defi_amm_private_swap_proof_record_root(proof: &DefiAmmPrivateSwapProofRecord) -> String {
    defi_amm_payload_root(
        "DEFI-AMM-PRIVATE-SWAP-PROOF-RECORD-ROOT",
        &proof.public_record(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn defi_amm_risk_control_id(
    pool_id: &str,
    mode: DefiAmmRiskMode,
    max_trade_units: u64,
    max_trade_bps_of_pool: u64,
    max_price_impact_bps: u64,
    min_liquidity_units: u64,
    volume_window_blocks: u64,
    volume_cap_units: u64,
    reason_root: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-RISK-CONTROL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(mode.as_str()),
            HashPart::Int(max_trade_units as i128),
            HashPart::Int(max_trade_bps_of_pool as i128),
            HashPart::Int(max_price_impact_bps as i128),
            HashPart::Int(min_liquidity_units as i128),
            HashPart::Int(volume_window_blocks as i128),
            HashPart::Int(volume_cap_units as i128),
            HashPart::Str(reason_root),
        ],
        32,
    )
}

pub fn defi_amm_risk_control_root(control: &DefiAmmRiskControl) -> String {
    defi_amm_payload_root("DEFI-AMM-RISK-CONTROL-ROOT", &control.public_record())
}

pub fn defi_amm_pause_switch_id(
    scope: DefiAmmSwitchScope,
    target_id: &str,
    paused: bool,
    reason_root: &str,
    set_by_commitment: &str,
    set_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "DEFI-AMM-PAUSE-SWITCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(if paused { "paused" } else { "unpaused" }),
            HashPart::Str(reason_root),
            HashPart::Str(set_by_commitment),
            HashPart::Int(set_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn defi_amm_pause_switch_root(switch: &DefiAmmPauseSwitch) -> String {
    defi_amm_payload_root("DEFI-AMM-PAUSE-SWITCH-ROOT", &switch.public_record())
}

pub fn defi_amm_kill_switch_id(
    scope: DefiAmmSwitchScope,
    target_id: &str,
    killed: bool,
    requires_governance_unwind: bool,
    reason_root: &str,
    set_by_commitment: &str,
    set_at_height: u64,
    final_state_root: &str,
) -> String {
    domain_hash(
        "DEFI-AMM-KILL-SWITCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(if killed { "killed" } else { "armed" }),
            HashPart::Str(if requires_governance_unwind {
                "governance_unwind"
            } else {
                "instant"
            }),
            HashPart::Str(reason_root),
            HashPart::Str(set_by_commitment),
            HashPart::Int(set_at_height as i128),
            HashPart::Str(final_state_root),
        ],
        32,
    )
}

pub fn defi_amm_kill_switch_root(switch: &DefiAmmKillSwitch) -> String {
    defi_amm_payload_root("DEFI-AMM-KILL-SWITCH-ROOT", &switch.public_record())
}
