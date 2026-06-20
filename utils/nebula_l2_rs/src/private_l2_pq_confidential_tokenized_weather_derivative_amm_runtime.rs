use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedWeatherDerivativeAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_WEATHER_DERIVATIVE_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-weather-derivative-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_WEATHER_DERIVATIVE_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_486_400;
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_COLLATERAL_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_WEATHER_INDEX_NAMESPACE: &str = "nebula.weather.derivatives.devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_TOKEN_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-weather-index-token-v1";
pub const ORACLE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-192f-confidential-weather-oracle-attestation-v1";
pub const SEALED_AMM_SUITE: &str = "ml-kem-1024-sealed-weather-derivative-amm-pool-v1";
pub const MARGIN_NOTE_SUITE: &str =
    "private-weather-derivative-margin-note-range-nullifier-proof-v1";
pub const SETTLEMENT_SUITE: &str = "zk-pq-confidential-weather-trigger-settlement-batch-v1";
pub const REBATE_SUITE: &str = "private-weather-amm-low-fee-credit-rebate-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "selective-disclosure-weather-amm-public-record-v1";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 6;
pub const DEFAULT_LP_REBATE_BPS: u64 = 5;
pub const DEFAULT_TRADER_REBATE_BPS: u64 = 4;
pub const DEFAULT_MIN_MARGIN_BPS: u64 = 1_500;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 900;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_POOL_STALENESS_BLOCKS: u64 = 48;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 450;
pub const DEFAULT_MAX_POOL_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_MIN_LIQUIDITY_UNITS: u128 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_WEATHER_TOKENS: usize = 262_144;
pub const MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const MAX_AMM_POOLS: usize = 262_144;
pub const MAX_MARGIN_NOTES: usize = 4_194_304;
pub const MAX_TRIGGER_SETTLEMENTS: usize = 1_048_576;
pub const MAX_GUARDRAILS: usize = 524_288;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_REDACTIONS: usize = 4_194_304;
pub const MAX_PUBLIC_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WeatherIndexKind {
    TemperatureHigh,
    TemperatureLow,
    HeatingDegreeDay,
    CoolingDegreeDay,
    RainfallTotal,
    SnowfallTotal,
    WindSpeedPeak,
    HurricaneLandfall,
    DroughtSeverity,
    CropStressBasket,
}

impl WeatherIndexKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TemperatureHigh => "temperature_high",
            Self::TemperatureLow => "temperature_low",
            Self::HeatingDegreeDay => "heating_degree_day",
            Self::CoolingDegreeDay => "cooling_degree_day",
            Self::RainfallTotal => "rainfall_total",
            Self::SnowfallTotal => "snowfall_total",
            Self::WindSpeedPeak => "wind_speed_peak",
            Self::HurricaneLandfall => "hurricane_landfall",
            Self::DroughtSeverity => "drought_severity",
            Self::CropStressBasket => "crop_stress_basket",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativePayoffKind {
    BinaryTrigger,
    CappedLinear,
    FloorLinear,
    Straddle,
    RangeAccrual,
    VarianceBasket,
}

impl DerivativePayoffKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BinaryTrigger => "binary_trigger",
            Self::CappedLinear => "capped_linear",
            Self::FloorLinear => "floor_linear",
            Self::Straddle => "straddle",
            Self::RangeAccrual => "range_accrual",
            Self::VarianceBasket => "variance_basket",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    Draft,
    Listed,
    Trading,
    ObservationLocked,
    Triggered,
    Settled,
    Halted,
    Cancelled,
}

impl TokenStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Listed => "listed",
            Self::Trading => "trading",
            Self::ObservationLocked => "observation_locked",
            Self::Triggered => "triggered",
            Self::Settled => "settled",
            Self::Halted => "halted",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_trade(self) -> bool {
        matches!(self, Self::Listed | Self::Trading)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Submitted,
    QuorumCandidate,
    QuorumReached,
    Disputed,
    Accepted,
    Expired,
    Slashed,
}

impl OracleAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::QuorumCandidate => "quorum_candidate",
            Self::QuorumReached => "quorum_reached",
            Self::Disputed => "disputed",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Seeded,
    Active,
    Guarded,
    Paused,
    Settling,
    Settled,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seeded => "seeded",
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::Paused => "paused",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongWeather,
    ShortWeather,
    LongVolatility,
    ShortVolatility,
    LpInventory,
    KeeperHedge,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongWeather => "long_weather",
            Self::ShortWeather => "short_weather",
            Self::LongVolatility => "long_volatility",
            Self::ShortVolatility => "short_volatility",
            Self::LpInventory => "lp_inventory",
            Self::KeeperHedge => "keeper_hedge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginStatus {
    Reserved,
    Active,
    UnderMaintenance,
    Liquidating,
    Settled,
    Released,
    Cancelled,
}

impl MarginStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::UnderMaintenance => "under_maintenance",
            Self::Liquidating => "liquidating",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    PendingOracle,
    TriggerMatched,
    ProofQueued,
    Settled,
    Rebated,
    Disputed,
    Cancelled,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingOracle => "pending_oracle",
            Self::TriggerMatched => "trigger_matched",
            Self::ProofQueued => "proof_queued",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailAction {
    Allow,
    WidenSpread,
    CapTrade,
    PausePool,
    RequireKeeper,
    EmergencySettle,
}

impl GuardrailAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::WidenSpread => "widen_spread",
            Self::CapTrade => "cap_trade",
            Self::PausePool => "pause_pool",
            Self::RequireKeeper => "require_keeper",
            Self::EmergencySettle => "emergency_settle",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub collateral_asset_id: String,
    pub fee_asset_id: String,
    pub weather_index_namespace: String,
    pub hash_suite: String,
    pub pq_token_suite: String,
    pub oracle_attestation_suite: String,
    pub sealed_amm_suite: String,
    pub margin_note_suite: String,
    pub settlement_suite: String,
    pub privacy_redaction_suite: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub oracle_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub pool_staleness_blocks: u64,
    pub max_fee_bps: u64,
    pub target_fee_bps: u64,
    pub lp_rebate_bps: u64,
    pub trader_rebate_bps: u64,
    pub min_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_pool_utilization_bps: u64,
    pub min_liquidity_units: u128,
    pub max_weather_tokens: usize,
    pub max_oracle_attestations: usize,
    pub max_amm_pools: usize,
    pub max_margin_notes: usize,
    pub max_trigger_settlements: usize,
    pub max_guardrails: usize,
    pub max_rebates: usize,
    pub max_redactions: usize,
    pub max_public_events: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            collateral_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            weather_index_namespace: DEFAULT_WEATHER_INDEX_NAMESPACE.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_token_suite: PQ_TOKEN_SUITE.to_string(),
            oracle_attestation_suite: ORACLE_ATTESTATION_SUITE.to_string(),
            sealed_amm_suite: SEALED_AMM_SUITE.to_string(),
            margin_note_suite: MARGIN_NOTE_SUITE.to_string(),
            settlement_suite: SETTLEMENT_SUITE.to_string(),
            privacy_redaction_suite: PRIVACY_REDACTION_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            pool_staleness_blocks: DEFAULT_POOL_STALENESS_BLOCKS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            lp_rebate_bps: DEFAULT_LP_REBATE_BPS,
            trader_rebate_bps: DEFAULT_TRADER_REBATE_BPS,
            min_margin_bps: DEFAULT_MIN_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_pool_utilization_bps: DEFAULT_MAX_POOL_UTILIZATION_BPS,
            min_liquidity_units: DEFAULT_MIN_LIQUIDITY_UNITS,
            max_weather_tokens: MAX_WEATHER_TOKENS,
            max_oracle_attestations: MAX_ORACLE_ATTESTATIONS,
            max_amm_pools: MAX_AMM_POOLS,
            max_margin_notes: MAX_MARGIN_NOTES,
            max_trigger_settlements: MAX_TRIGGER_SETTLEMENTS,
            max_guardrails: MAX_GUARDRAILS,
            max_rebates: MAX_REBATES,
            max_redactions: MAX_REDACTIONS,
            max_public_events: MAX_PUBLIC_EVENTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        ensure_bps("target_fee_bps", self.target_fee_bps)?;
        ensure_bps("lp_rebate_bps", self.lp_rebate_bps)?;
        ensure_bps("trader_rebate_bps", self.trader_rebate_bps)?;
        ensure_bps("min_margin_bps", self.min_margin_bps)?;
        ensure_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        ensure_bps("max_price_impact_bps", self.max_price_impact_bps)?;
        ensure_bps("max_pool_utilization_bps", self.max_pool_utilization_bps)?;
        if self.target_fee_bps > self.max_fee_bps {
            return Err("target_fee_bps exceeds max_fee_bps".to_string());
        }
        if self.maintenance_margin_bps > self.min_margin_bps {
            return Err("maintenance_margin_bps exceeds min_margin_bps".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below generated runtime floor".to_string());
        }
        if self.oracle_quorum == 0 {
            return Err("oracle_quorum must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "collateral_asset_id": self.collateral_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "weather_index_namespace": self.weather_index_namespace,
            "hash_suite": self.hash_suite,
            "pq_token_suite": self.pq_token_suite,
            "oracle_attestation_suite": self.oracle_attestation_suite,
            "sealed_amm_suite": self.sealed_amm_suite,
            "margin_note_suite": self.margin_note_suite,
            "settlement_suite": self.settlement_suite,
            "privacy_redaction_suite": self.privacy_redaction_suite,
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "target_privacy_set_size": self.target_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits
            },
            "fees": {
                "max_fee_bps": self.max_fee_bps,
                "target_fee_bps": self.target_fee_bps,
                "lp_rebate_bps": self.lp_rebate_bps,
                "trader_rebate_bps": self.trader_rebate_bps
            },
            "risk": {
                "min_margin_bps": self.min_margin_bps,
                "maintenance_margin_bps": self.maintenance_margin_bps,
                "max_price_impact_bps": self.max_price_impact_bps,
                "max_pool_utilization_bps": self.max_pool_utilization_bps,
                "min_liquidity_units": self.min_liquidity_units.to_string()
            },
            "oracle": {
                "oracle_quorum": self.oracle_quorum,
                "oracle_ttl_blocks": self.oracle_ttl_blocks,
                "settlement_delay_blocks": self.settlement_delay_blocks,
                "pool_staleness_blocks": self.pool_staleness_blocks
            },
            "limits": {
                "max_weather_tokens": self.max_weather_tokens,
                "max_oracle_attestations": self.max_oracle_attestations,
                "max_amm_pools": self.max_amm_pools,
                "max_margin_notes": self.max_margin_notes,
                "max_trigger_settlements": self.max_trigger_settlements,
                "max_guardrails": self.max_guardrails,
                "max_rebates": self.max_rebates,
                "max_redactions": self.max_redactions,
                "max_public_events": self.max_public_events
            }
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub weather_tokens: u64,
    pub oracle_attestations: u64,
    pub amm_pools: u64,
    pub margin_notes: u64,
    pub trigger_settlements: u64,
    pub guardrails: u64,
    pub rebates: u64,
    pub redactions: u64,
    pub public_events: u64,
    pub total_swaps: u64,
    pub total_liquidity_updates: u64,
    pub total_settled_notional: u128,
    pub total_fee_credits: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "weather_tokens": self.weather_tokens,
            "oracle_attestations": self.oracle_attestations,
            "amm_pools": self.amm_pools,
            "margin_notes": self.margin_notes,
            "trigger_settlements": self.trigger_settlements,
            "guardrails": self.guardrails,
            "rebates": self.rebates,
            "redactions": self.redactions,
            "public_events": self.public_events,
            "total_swaps": self.total_swaps,
            "total_liquidity_updates": self.total_liquidity_updates,
            "total_settled_notional": self.total_settled_notional.to_string(),
            "total_fee_credits": self.total_fee_credits.to_string()
        })
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub weather_token_root: String,
    pub oracle_attestation_root: String,
    pub amm_pool_root: String,
    pub margin_note_root: String,
    pub trigger_settlement_root: String,
    pub guardrail_root: String,
    pub rebate_root: String,
    pub redaction_root: String,
    pub operator_summary_root: String,
    pub public_event_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = empty_root();
        Self {
            config_root: empty.clone(),
            weather_token_root: empty.clone(),
            oracle_attestation_root: empty.clone(),
            amm_pool_root: empty.clone(),
            margin_note_root: empty.clone(),
            trigger_settlement_root: empty.clone(),
            guardrail_root: empty.clone(),
            rebate_root: empty.clone(),
            redaction_root: empty.clone(),
            operator_summary_root: empty.clone(),
            public_event_root: empty.clone(),
            counters_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "weather_token_root": self.weather_token_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "amm_pool_root": self.amm_pool_root,
            "margin_note_root": self.margin_note_root,
            "trigger_settlement_root": self.trigger_settlement_root,
            "guardrail_root": self.guardrail_root,
            "rebate_root": self.rebate_root,
            "redaction_root": self.redaction_root,
            "operator_summary_root": self.operator_summary_root,
            "public_event_root": self.public_event_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WeatherIndexToken {
    pub token_id: String,
    pub index_kind: WeatherIndexKind,
    pub payoff_kind: DerivativePayoffKind,
    pub region_code: String,
    pub station_commitment_root: String,
    pub observation_start_block: u64,
    pub observation_end_block: u64,
    pub settlement_block: u64,
    pub strike_micro_units: i128,
    pub cap_micro_units: Option<i128>,
    pub tick_size_micro_units: u64,
    pub collateral_asset_id: String,
    pub quote_decimals: u8,
    pub max_notional: u128,
    pub oracle_committee_root: String,
    pub metadata_commitment: String,
    pub pq_issuer_key_commitment: String,
    pub privacy_set_size: u64,
    pub status: TokenStatus,
}

impl WeatherIndexToken {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: impl Into<String>,
        index_kind: WeatherIndexKind,
        payoff_kind: DerivativePayoffKind,
        region_code: impl Into<String>,
        observation_start_block: u64,
        observation_end_block: u64,
        settlement_block: u64,
        strike_micro_units: i128,
        cap_micro_units: Option<i128>,
        max_notional: u128,
    ) -> Self {
        let token_id = token_id.into();
        let region_code = region_code.into();
        Self {
            station_commitment_root: deterministic_id("station-root", &[&token_id, &region_code]),
            oracle_committee_root: deterministic_id("oracle-committee", &[&token_id]),
            metadata_commitment: deterministic_id("token-metadata", &[&token_id]),
            pq_issuer_key_commitment: deterministic_id("pq-issuer", &[&token_id]),
            token_id,
            index_kind,
            payoff_kind,
            region_code,
            observation_start_block,
            observation_end_block,
            settlement_block,
            strike_micro_units,
            cap_micro_units,
            tick_size_micro_units: 1_000,
            collateral_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
            quote_decimals: 6,
            max_notional,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            status: TokenStatus::Listed,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.observation_start_block >= self.observation_end_block {
            return Err(format!(
                "token {} has invalid observation window",
                self.token_id
            ));
        }
        if self.observation_end_block >= self.settlement_block {
            return Err(format!(
                "token {} settles before observations close",
                self.token_id
            ));
        }
        if self.max_notional == 0 {
            return Err(format!("token {} max_notional is zero", self.token_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("token {} privacy set below minimum", self.token_id));
        }
        Ok(())
    }

    pub fn payoff_micro_units(&self, observed_micro_units: i128) -> i128 {
        match self.payoff_kind {
            DerivativePayoffKind::BinaryTrigger => {
                if observed_micro_units >= self.strike_micro_units {
                    self.cap_micro_units.unwrap_or(1_000_000)
                } else {
                    0
                }
            }
            DerivativePayoffKind::CappedLinear => {
                let raw = observed_micro_units
                    .saturating_sub(self.strike_micro_units)
                    .max(0);
                self.cap_micro_units.map_or(raw, |cap| raw.min(cap))
            }
            DerivativePayoffKind::FloorLinear => self
                .strike_micro_units
                .saturating_sub(observed_micro_units)
                .max(0),
            DerivativePayoffKind::Straddle => {
                (observed_micro_units.saturating_sub(self.strike_micro_units)).abs()
            }
            DerivativePayoffKind::RangeAccrual => {
                let cap = self.cap_micro_units.unwrap_or(self.strike_micro_units);
                if observed_micro_units >= self.strike_micro_units && observed_micro_units <= cap {
                    1_000_000
                } else {
                    0
                }
            }
            DerivativePayoffKind::VarianceBasket => {
                let delta = observed_micro_units.saturating_sub(self.strike_micro_units);
                delta.saturating_mul(delta) / 1_000_000
            }
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_id": self.token_id,
            "index_kind": self.index_kind.as_str(),
            "payoff_kind": self.payoff_kind.as_str(),
            "region_code": self.region_code,
            "station_commitment_root": self.station_commitment_root,
            "observation_start_block": self.observation_start_block,
            "observation_end_block": self.observation_end_block,
            "settlement_block": self.settlement_block,
            "strike_micro_units": self.strike_micro_units.to_string(),
            "cap_micro_units": self.cap_micro_units.map(|value| value.to_string()),
            "tick_size_micro_units": self.tick_size_micro_units,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_decimals": self.quote_decimals,
            "max_notional": self.max_notional.to_string(),
            "oracle_committee_root": self.oracle_committee_root,
            "metadata_commitment": self.metadata_commitment,
            "pq_issuer_key_commitment": self.pq_issuer_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        payload_root("WEATHER-TOKEN", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleWeatherAttestation {
    pub attestation_id: String,
    pub token_id: String,
    pub oracle_set_root: String,
    pub observation_commitment: String,
    pub observed_micro_units: i128,
    pub confidence_bps: u64,
    pub station_sample_root: String,
    pub signature_aggregate_root: String,
    pub submitted_block: u64,
    pub valid_until_block: u64,
    pub quorum_weight: u16,
    pub pq_security_bits: u16,
    pub dispute_nullifier_root: String,
    pub status: OracleAttestationStatus,
}

impl OracleWeatherAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        token_id: impl Into<String>,
        observed_micro_units: i128,
        submitted_block: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let token_id = token_id.into();
        Self {
            oracle_set_root: deterministic_id("oracle-set", &[&token_id]),
            observation_commitment: deterministic_id(
                "weather-observation",
                &[&attestation_id, &observed_micro_units.to_string()],
            ),
            station_sample_root: deterministic_id("station-sample", &[&attestation_id]),
            signature_aggregate_root: deterministic_id("oracle-sigs", &[&attestation_id]),
            dispute_nullifier_root: deterministic_id("oracle-disputes", &[&attestation_id]),
            attestation_id,
            token_id,
            observed_micro_units,
            confidence_bps: 9_850,
            submitted_block,
            valid_until_block: submitted_block.saturating_add(config.oracle_ttl_blocks),
            quorum_weight: config.oracle_quorum,
            pq_security_bits: config.min_pq_security_bits,
            status: OracleAttestationStatus::QuorumReached,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_bps("confidence_bps", self.confidence_bps)?;
        if self.quorum_weight < config.oracle_quorum {
            return Err(format!(
                "attestation {} below oracle quorum",
                self.attestation_id
            ));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below pq security floor",
                self.attestation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "token_id": self.token_id,
            "oracle_set_root": self.oracle_set_root,
            "observation_commitment": self.observation_commitment,
            "observed_micro_units": self.observed_micro_units.to_string(),
            "confidence_bps": self.confidence_bps,
            "station_sample_root": self.station_sample_root,
            "signature_aggregate_root": self.signature_aggregate_root,
            "submitted_block": self.submitted_block,
            "valid_until_block": self.valid_until_block,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "dispute_nullifier_root": self.dispute_nullifier_root,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        payload_root("ORACLE-ATTESTATION", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedAmmPool {
    pub pool_id: String,
    pub token_id: String,
    pub sealed_long_reserve: String,
    pub sealed_short_reserve: String,
    pub sealed_collateral_reserve: String,
    pub invariant_commitment: String,
    pub lp_share_root: String,
    pub fee_vault_commitment: String,
    pub liquidity_units: u128,
    pub open_interest_long: u128,
    pub open_interest_short: u128,
    pub last_price_micro_units: u128,
    pub spread_bps: u64,
    pub fee_bps: u64,
    pub utilization_bps: u64,
    pub last_rebalance_block: u64,
    pub privacy_set_size: u64,
    pub keeper_set_root: String,
    pub status: PoolStatus,
}

impl SealedAmmPool {
    pub fn new(
        pool_id: impl Into<String>,
        token_id: impl Into<String>,
        liquidity_units: u128,
        price_micro_units: u128,
        block_height: u64,
        config: &Config,
    ) -> Self {
        let pool_id = pool_id.into();
        let token_id = token_id.into();
        Self {
            sealed_long_reserve: deterministic_id("sealed-long-reserve", &[&pool_id]),
            sealed_short_reserve: deterministic_id("sealed-short-reserve", &[&pool_id]),
            sealed_collateral_reserve: deterministic_id("sealed-collateral-reserve", &[&pool_id]),
            invariant_commitment: deterministic_id("weather-amm-invariant", &[&pool_id]),
            lp_share_root: deterministic_id("lp-share-root", &[&pool_id]),
            fee_vault_commitment: deterministic_id("fee-vault", &[&pool_id]),
            keeper_set_root: deterministic_id("keeper-set", &[&pool_id]),
            pool_id,
            token_id,
            liquidity_units,
            open_interest_long: 0,
            open_interest_short: 0,
            last_price_micro_units: price_micro_units,
            spread_bps: 12,
            fee_bps: config.target_fee_bps,
            utilization_bps: 0,
            last_rebalance_block: block_height,
            privacy_set_size: config.target_privacy_set_size,
            status: PoolStatus::Active,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.liquidity_units < config.min_liquidity_units {
            return Err(format!("pool {} below minimum liquidity", self.pool_id));
        }
        ensure_bps("pool fee_bps", self.fee_bps)?;
        ensure_bps("pool spread_bps", self.spread_bps)?;
        ensure_bps("pool utilization_bps", self.utilization_bps)?;
        if self.utilization_bps > config.max_pool_utilization_bps {
            return Err(format!("pool {} utilization above guardrail", self.pool_id));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("pool {} privacy set below minimum", self.pool_id));
        }
        Ok(())
    }

    pub fn quote_trade(
        &self,
        side: PositionSide,
        notional: u128,
        config: &Config,
    ) -> Result<TradeQuote> {
        if self.status != PoolStatus::Active && self.status != PoolStatus::Guarded {
            return Err(format!("pool {} is not accepting trades", self.pool_id));
        }
        if notional == 0 {
            return Err("notional must be positive".to_string());
        }
        let price_impact_bps = price_impact_bps(notional, self.liquidity_units);
        if price_impact_bps > config.max_price_impact_bps {
            return Err(format!(
                "trade impact {} bps exceeds {} bps",
                price_impact_bps, config.max_price_impact_bps
            ));
        }
        let directional_spread_bps = match side {
            PositionSide::LongWeather | PositionSide::LongVolatility => self.spread_bps,
            PositionSide::ShortWeather | PositionSide::ShortVolatility => self.spread_bps / 2,
            PositionSide::LpInventory | PositionSide::KeeperHedge => 0,
        };
        let gross_quote = apply_bps(
            notional.saturating_mul(self.last_price_micro_units) / 1_000_000,
            MAX_BPS.saturating_add(directional_spread_bps + price_impact_bps),
        );
        let fee_amount = apply_bps(gross_quote, self.fee_bps.min(config.max_fee_bps));
        Ok(TradeQuote {
            pool_id: self.pool_id.clone(),
            token_id: self.token_id.clone(),
            side,
            notional,
            price_micro_units: self.last_price_micro_units,
            price_impact_bps,
            spread_bps: directional_spread_bps,
            fee_bps: self.fee_bps.min(config.max_fee_bps),
            fee_amount,
            total_collateral_due: gross_quote.saturating_add(fee_amount),
        })
    }

    pub fn apply_trade(&mut self, quote: &TradeQuote) {
        match quote.side {
            PositionSide::LongWeather | PositionSide::LongVolatility => {
                self.open_interest_long = self.open_interest_long.saturating_add(quote.notional)
            }
            PositionSide::ShortWeather | PositionSide::ShortVolatility => {
                self.open_interest_short = self.open_interest_short.saturating_add(quote.notional)
            }
            PositionSide::LpInventory | PositionSide::KeeperHedge => {}
        }
        let total_open = self
            .open_interest_long
            .saturating_add(self.open_interest_short);
        self.utilization_bps = if self.liquidity_units == 0 {
            MAX_BPS
        } else {
            ((total_open.saturating_mul(MAX_BPS as u128)) / self.liquidity_units) as u64
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "token_id": self.token_id,
            "sealed_long_reserve": self.sealed_long_reserve,
            "sealed_short_reserve": self.sealed_short_reserve,
            "sealed_collateral_reserve": self.sealed_collateral_reserve,
            "invariant_commitment": self.invariant_commitment,
            "lp_share_root": self.lp_share_root,
            "fee_vault_commitment": self.fee_vault_commitment,
            "liquidity_units": self.liquidity_units.to_string(),
            "open_interest_long": self.open_interest_long.to_string(),
            "open_interest_short": self.open_interest_short.to_string(),
            "last_price_micro_units": self.last_price_micro_units.to_string(),
            "spread_bps": self.spread_bps,
            "fee_bps": self.fee_bps,
            "utilization_bps": self.utilization_bps,
            "last_rebalance_block": self.last_rebalance_block,
            "privacy_set_size": self.privacy_set_size,
            "keeper_set_root": self.keeper_set_root,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEALED-AMM-POOL", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TradeQuote {
    pub pool_id: String,
    pub token_id: String,
    pub side: PositionSide,
    pub notional: u128,
    pub price_micro_units: u128,
    pub price_impact_bps: u64,
    pub spread_bps: u64,
    pub fee_bps: u64,
    pub fee_amount: u128,
    pub total_collateral_due: u128,
}

impl TradeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "token_id": self.token_id,
            "side": self.side.as_str(),
            "notional": self.notional.to_string(),
            "price_micro_units": self.price_micro_units.to_string(),
            "price_impact_bps": self.price_impact_bps,
            "spread_bps": self.spread_bps,
            "fee_bps": self.fee_bps,
            "fee_amount": self.fee_amount.to_string(),
            "total_collateral_due": self.total_collateral_due.to_string()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginNote {
    pub note_id: String,
    pub pool_id: String,
    pub token_id: String,
    pub owner_commitment: String,
    pub nullifier_hash: String,
    pub side: PositionSide,
    pub notional: u128,
    pub initial_margin: u128,
    pub maintenance_margin: u128,
    pub entry_price_micro_units: u128,
    pub fee_paid: u128,
    pub range_proof_root: String,
    pub encrypted_terms: String,
    pub opened_block: u64,
    pub status: MarginStatus,
}

impl MarginNote {
    pub fn from_quote(
        note_id: impl Into<String>,
        quote: &TradeQuote,
        opened_block: u64,
        config: &Config,
    ) -> Self {
        let note_id = note_id.into();
        let initial_margin = apply_bps(quote.notional, config.min_margin_bps);
        let maintenance_margin = apply_bps(quote.notional, config.maintenance_margin_bps);
        Self {
            owner_commitment: deterministic_id("margin-owner", &[&note_id]),
            nullifier_hash: deterministic_id("margin-nullifier", &[&note_id]),
            range_proof_root: deterministic_id("margin-range-proof", &[&note_id]),
            encrypted_terms: deterministic_id("encrypted-margin-terms", &[&note_id]),
            note_id,
            pool_id: quote.pool_id.clone(),
            token_id: quote.token_id.clone(),
            side: quote.side,
            notional: quote.notional,
            initial_margin,
            maintenance_margin,
            entry_price_micro_units: quote.price_micro_units,
            fee_paid: quote.fee_amount,
            opened_block,
            status: MarginStatus::Active,
        }
    }

    pub fn mark_settled(&mut self) {
        self.status = MarginStatus::Settled;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "token_id": self.token_id,
            "owner_commitment": self.owner_commitment,
            "nullifier_hash": self.nullifier_hash,
            "side": self.side.as_str(),
            "notional": self.notional.to_string(),
            "initial_margin": self.initial_margin.to_string(),
            "maintenance_margin": self.maintenance_margin.to_string(),
            "entry_price_micro_units": self.entry_price_micro_units.to_string(),
            "fee_paid": self.fee_paid.to_string(),
            "range_proof_root": self.range_proof_root,
            "encrypted_terms": self.encrypted_terms,
            "opened_block": self.opened_block,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        payload_root("MARGIN-NOTE", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventTriggerSettlement {
    pub settlement_id: String,
    pub token_id: String,
    pub attestation_id: String,
    pub pool_id: String,
    pub settled_note_root: String,
    pub payout_commitment_root: String,
    pub observed_micro_units: i128,
    pub payoff_micro_units: i128,
    pub settled_notional: u128,
    pub proof_aggregate_root: String,
    pub rebate_batch_id: String,
    pub created_block: u64,
    pub finalized_block: Option<u64>,
    pub status: SettlementStatus,
}

impl EventTriggerSettlement {
    pub fn new(
        settlement_id: impl Into<String>,
        token: &WeatherIndexToken,
        attestation: &OracleWeatherAttestation,
        pool_id: impl Into<String>,
        settled_note_root: impl Into<String>,
        settled_notional: u128,
        created_block: u64,
    ) -> Self {
        let settlement_id = settlement_id.into();
        let payoff_micro_units = token.payoff_micro_units(attestation.observed_micro_units);
        Self {
            payout_commitment_root: deterministic_id("payout-root", &[&settlement_id]),
            proof_aggregate_root: deterministic_id("settlement-proof", &[&settlement_id]),
            rebate_batch_id: deterministic_id("settlement-rebate-batch", &[&settlement_id]),
            settlement_id,
            token_id: token.token_id.clone(),
            attestation_id: attestation.attestation_id.clone(),
            pool_id: pool_id.into(),
            settled_note_root: settled_note_root.into(),
            observed_micro_units: attestation.observed_micro_units,
            payoff_micro_units,
            settled_notional,
            created_block,
            finalized_block: None,
            status: SettlementStatus::TriggerMatched,
        }
    }

    pub fn finalize(&mut self, finalized_block: u64) {
        self.finalized_block = Some(finalized_block);
        self.status = SettlementStatus::Settled;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "token_id": self.token_id,
            "attestation_id": self.attestation_id,
            "pool_id": self.pool_id,
            "settled_note_root": self.settled_note_root,
            "payout_commitment_root": self.payout_commitment_root,
            "observed_micro_units": self.observed_micro_units.to_string(),
            "payoff_micro_units": self.payoff_micro_units.to_string(),
            "settled_notional": self.settled_notional.to_string(),
            "proof_aggregate_root": self.proof_aggregate_root,
            "rebate_batch_id": self.rebate_batch_id,
            "created_block": self.created_block,
            "finalized_block": self.finalized_block,
            "status": self.status.as_str()
        })
    }

    pub fn root(&self) -> String {
        payload_root("TRIGGER-SETTLEMENT", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityGuardrail {
    pub guardrail_id: String,
    pub pool_id: String,
    pub checked_block: u64,
    pub utilization_bps: u64,
    pub price_impact_bps: u64,
    pub oracle_age_blocks: u64,
    pub liquidity_units: u128,
    pub action: GuardrailAction,
    pub reason_code: String,
    pub keeper_authorization_root: String,
}

impl LiquidityGuardrail {
    pub fn evaluate(
        guardrail_id: impl Into<String>,
        pool: &SealedAmmPool,
        trade_notional: u128,
        oracle_age_blocks: u64,
        block_height: u64,
        config: &Config,
    ) -> Self {
        let guardrail_id = guardrail_id.into();
        let impact = price_impact_bps(trade_notional, pool.liquidity_units);
        let (action, reason_code) = if oracle_age_blocks > config.pool_staleness_blocks {
            (GuardrailAction::RequireKeeper, "oracle_stale")
        } else if pool.utilization_bps > config.max_pool_utilization_bps {
            (GuardrailAction::PausePool, "utilization_limit")
        } else if impact > config.max_price_impact_bps {
            (GuardrailAction::CapTrade, "price_impact_limit")
        } else if pool.liquidity_units < config.min_liquidity_units {
            (GuardrailAction::PausePool, "liquidity_floor")
        } else {
            (GuardrailAction::Allow, "within_limits")
        };
        Self {
            pool_id: pool.pool_id.clone(),
            checked_block: block_height,
            utilization_bps: pool.utilization_bps,
            price_impact_bps: impact,
            oracle_age_blocks,
            liquidity_units: pool.liquidity_units,
            action,
            reason_code: reason_code.to_string(),
            keeper_authorization_root: deterministic_id("keeper-authorization", &[&guardrail_id]),
            guardrail_id,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guardrail_id": self.guardrail_id,
            "pool_id": self.pool_id,
            "checked_block": self.checked_block,
            "utilization_bps": self.utilization_bps,
            "price_impact_bps": self.price_impact_bps,
            "oracle_age_blocks": self.oracle_age_blocks,
            "liquidity_units": self.liquidity_units.to_string(),
            "action": self.action.as_str(),
            "reason_code": self.reason_code,
            "keeper_authorization_root": self.keeper_authorization_root
        })
    }

    pub fn root(&self) -> String {
        payload_root("LIQUIDITY-GUARDRAIL", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditRebate {
    pub rebate_id: String,
    pub beneficiary_commitment: String,
    pub source_id: String,
    pub pool_id: String,
    pub fee_paid: u128,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub credit_asset_id: String,
    pub claim_nullifier: String,
    pub sponsor_vault_commitment: String,
    pub expires_block: u64,
    pub claimed: bool,
}

impl FeeCreditRebate {
    pub fn new(
        rebate_id: impl Into<String>,
        source_id: impl Into<String>,
        pool_id: impl Into<String>,
        fee_paid: u128,
        rebate_bps: u64,
        expires_block: u64,
        config: &Config,
    ) -> Self {
        let rebate_id = rebate_id.into();
        Self {
            beneficiary_commitment: deterministic_id("rebate-beneficiary", &[&rebate_id]),
            source_id: source_id.into(),
            pool_id: pool_id.into(),
            fee_paid,
            rebate_amount: apply_bps(fee_paid, rebate_bps),
            rebate_bps,
            credit_asset_id: config.fee_asset_id.clone(),
            claim_nullifier: deterministic_id("rebate-nullifier", &[&rebate_id]),
            sponsor_vault_commitment: deterministic_id("rebate-sponsor-vault", &[&rebate_id]),
            expires_block,
            claimed: false,
            rebate_id,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "source_id": self.source_id,
            "pool_id": self.pool_id,
            "fee_paid": self.fee_paid.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "credit_asset_id": self.credit_asset_id,
            "claim_nullifier": self.claim_nullifier,
            "sponsor_vault_commitment": self.sponsor_vault_commitment,
            "expires_block": self.expires_block,
            "claimed": self.claimed
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-CREDIT-REBATE", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub source_kind: String,
    pub source_id: String,
    pub disclosed_fields: BTreeSet<String>,
    pub redacted_fields_root: String,
    pub selective_disclosure_proof_root: String,
    pub privacy_set_size: u64,
    pub issued_block: u64,
}

impl PrivacyRedaction {
    pub fn new(
        redaction_id: impl Into<String>,
        source_kind: impl Into<String>,
        source_id: impl Into<String>,
        fields: impl IntoIterator<Item = impl Into<String>>,
        privacy_set_size: u64,
        issued_block: u64,
    ) -> Self {
        let redaction_id = redaction_id.into();
        Self {
            source_kind: source_kind.into(),
            source_id: source_id.into(),
            disclosed_fields: fields.into_iter().map(Into::into).collect(),
            redacted_fields_root: deterministic_id("redacted-fields", &[&redaction_id]),
            selective_disclosure_proof_root: deterministic_id(
                "selective-disclosure",
                &[&redaction_id],
            ),
            privacy_set_size,
            issued_block,
            redaction_id,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "disclosed_fields": self.disclosed_fields,
            "redacted_fields_root": self.redacted_fields_root,
            "selective_disclosure_proof_root": self.selective_disclosure_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_block": self.issued_block
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-REDACTION", &[self.public_record()])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub block_height: u64,
    pub active_tokens: u64,
    pub active_pools: u64,
    pub total_liquidity_units: u128,
    pub total_open_interest: u128,
    pub guarded_pools: u64,
    pub settled_notional: u128,
    pub fee_credit_rebates: u128,
    pub min_privacy_set_size: u64,
    pub root_commitment: String,
}

impl OperatorSummary {
    pub fn from_state(summary_id: impl Into<String>, state: &State) -> Self {
        let total_liquidity_units = state
            .amm_pools
            .values()
            .map(|pool| pool.liquidity_units)
            .fold(0_u128, u128::saturating_add);
        let total_open_interest = state
            .amm_pools
            .values()
            .map(|pool| {
                pool.open_interest_long
                    .saturating_add(pool.open_interest_short)
            })
            .fold(0_u128, u128::saturating_add);
        let guarded_pools = state
            .amm_pools
            .values()
            .filter(|pool| pool.status == PoolStatus::Guarded)
            .count() as u64;
        let active_tokens = state
            .weather_tokens
            .values()
            .filter(|token| token.status.accepts_trade())
            .count() as u64;
        let active_pools = state
            .amm_pools
            .values()
            .filter(|pool| matches!(pool.status, PoolStatus::Active | PoolStatus::Guarded))
            .count() as u64;
        let settled_notional = state
            .trigger_settlements
            .values()
            .map(|settlement| settlement.settled_notional)
            .fold(0_u128, u128::saturating_add);
        let fee_credit_rebates = state
            .rebates
            .values()
            .map(|rebate| rebate.rebate_amount)
            .fold(0_u128, u128::saturating_add);
        let min_privacy_set_size = state
            .privacy_redactions
            .values()
            .map(|redaction| redaction.privacy_set_size)
            .min()
            .unwrap_or(state.config.min_privacy_set_size);
        let summary_id = summary_id.into();
        Self {
            root_commitment: deterministic_id("operator-summary", &[&summary_id]),
            summary_id,
            block_height: state.block_height,
            active_tokens,
            active_pools,
            total_liquidity_units,
            total_open_interest,
            guarded_pools,
            settled_notional,
            fee_credit_rebates,
            min_privacy_set_size,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "block_height": self.block_height,
            "active_tokens": self.active_tokens,
            "active_pools": self.active_pools,
            "total_liquidity_units": self.total_liquidity_units.to_string(),
            "total_open_interest": self.total_open_interest.to_string(),
            "guarded_pools": self.guarded_pools,
            "settled_notional": self.settled_notional.to_string(),
            "fee_credit_rebates": self.fee_credit_rebates.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "root_commitment": self.root_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub block_height: u64,
    pub payload_root: String,
}

impl PublicEvent {
    pub fn new(
        event_id: impl Into<String>,
        event_kind: impl Into<String>,
        subject_id: impl Into<String>,
        block_height: u64,
        payload: &Value,
    ) -> Self {
        let event_id = event_id.into();
        Self {
            payload_root: payload_root("PUBLIC-EVENT-PAYLOAD", &[payload.clone()]),
            event_id,
            event_kind: event_kind.into(),
            subject_id: subject_id.into(),
            block_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "block_height": self.block_height,
            "payload_root": self.payload_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub block_height: u64,
    pub weather_tokens: BTreeMap<String, WeatherIndexToken>,
    pub oracle_attestations: BTreeMap<String, OracleWeatherAttestation>,
    pub amm_pools: BTreeMap<String, SealedAmmPool>,
    pub margin_notes: BTreeMap<String, MarginNote>,
    pub trigger_settlements: BTreeMap<String, EventTriggerSettlement>,
    pub guardrails: BTreeMap<String, LiquidityGuardrail>,
    pub rebates: BTreeMap<String, FeeCreditRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_events: BTreeMap<String, PublicEvent>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config, block_height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            block_height,
            weather_tokens: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            margin_notes: BTreeMap::new(),
            trigger_settlements: BTreeMap::new(),
            guardrails: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_events: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT)
            .expect("generated devnet weather derivative AMM config is valid");
        seed_devnet(&mut state)
            .expect("generated devnet weather derivative AMM fixtures are valid");
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            weather_token_root: map_root(
                "WEATHER-TOKENS",
                self.weather_tokens
                    .values()
                    .map(WeatherIndexToken::public_record),
            ),
            oracle_attestation_root: map_root(
                "ORACLE-ATTESTATIONS",
                self.oracle_attestations
                    .values()
                    .map(OracleWeatherAttestation::public_record),
            ),
            amm_pool_root: map_root(
                "AMM-POOLS",
                self.amm_pools.values().map(SealedAmmPool::public_record),
            ),
            margin_note_root: map_root(
                "MARGIN-NOTES",
                self.margin_notes.values().map(MarginNote::public_record),
            ),
            trigger_settlement_root: map_root(
                "TRIGGER-SETTLEMENTS",
                self.trigger_settlements
                    .values()
                    .map(EventTriggerSettlement::public_record),
            ),
            guardrail_root: map_root(
                "LIQUIDITY-GUARDRAILS",
                self.guardrails
                    .values()
                    .map(LiquidityGuardrail::public_record),
            ),
            rebate_root: map_root(
                "FEE-CREDIT-REBATES",
                self.rebates.values().map(FeeCreditRebate::public_record),
            ),
            redaction_root: map_root(
                "PRIVACY-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            operator_summary_root: map_root(
                "OPERATOR-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
            public_event_root: map_root(
                "PUBLIC-EVENTS",
                self.public_events.values().map(PublicEvent::public_record),
            ),
            counters_root: self.counters.root(),
            state_root: self.state_root(),
        }
    }

    pub fn refresh_roots(&mut self) {
        self.counters.weather_tokens = self.weather_tokens.len() as u64;
        self.counters.oracle_attestations = self.oracle_attestations.len() as u64;
        self.counters.amm_pools = self.amm_pools.len() as u64;
        self.counters.margin_notes = self.margin_notes.len() as u64;
        self.counters.trigger_settlements = self.trigger_settlements.len() as u64;
        self.counters.guardrails = self.guardrails.len() as u64;
        self.counters.rebates = self.rebates.len() as u64;
        self.counters.redactions = self.privacy_redactions.len() as u64;
        self.counters.public_events = self.public_events.len() as u64;
        self.roots = self.roots();
    }

    pub fn list_weather_token(&mut self, token: WeatherIndexToken) -> Result<String> {
        ensure_capacity(
            "weather_tokens",
            self.weather_tokens.len(),
            self.config.max_weather_tokens,
        )?;
        token.validate(&self.config)?;
        let token_id = token.token_id.clone();
        let payload = token.public_record();
        self.weather_tokens.insert(token_id.clone(), token);
        self.publish("weather_token_listed", &token_id, payload)?;
        self.refresh_roots();
        Ok(token_id)
    }

    pub fn submit_oracle_attestation(
        &mut self,
        attestation: OracleWeatherAttestation,
    ) -> Result<String> {
        ensure_capacity(
            "oracle_attestations",
            self.oracle_attestations.len(),
            self.config.max_oracle_attestations,
        )?;
        if !self.weather_tokens.contains_key(&attestation.token_id) {
            return Err(format!("unknown token {}", attestation.token_id));
        }
        attestation.validate(&self.config)?;
        let attestation_id = attestation.attestation_id.clone();
        let payload = attestation.public_record();
        self.oracle_attestations
            .insert(attestation_id.clone(), attestation);
        self.publish("oracle_weather_attested", &attestation_id, payload)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_pool(&mut self, pool: SealedAmmPool) -> Result<String> {
        ensure_capacity("amm_pools", self.amm_pools.len(), self.config.max_amm_pools)?;
        if !self.weather_tokens.contains_key(&pool.token_id) {
            return Err(format!("unknown token {}", pool.token_id));
        }
        pool.validate(&self.config)?;
        let pool_id = pool.pool_id.clone();
        let payload = pool.public_record();
        self.amm_pools.insert(pool_id.clone(), pool);
        self.publish("sealed_amm_pool_opened", &pool_id, payload)?;
        self.counters.total_liquidity_updates =
            self.counters.total_liquidity_updates.saturating_add(1);
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn trade(
        &mut self,
        pool_id: &str,
        side: PositionSide,
        notional: u128,
        note_id: impl Into<String>,
    ) -> Result<String> {
        ensure_capacity(
            "margin_notes",
            self.margin_notes.len(),
            self.config.max_margin_notes,
        )?;
        let pool_snapshot = self
            .amm_pools
            .get(pool_id)
            .ok_or_else(|| format!("unknown pool {}", pool_id))?
            .clone();
        let token = self
            .weather_tokens
            .get(&pool_snapshot.token_id)
            .ok_or_else(|| format!("unknown token {}", pool_snapshot.token_id))?;
        if !token.status.accepts_trade() {
            return Err(format!("token {} is not tradable", token.token_id));
        }
        let guardrail_id = deterministic_id(
            "guardrail",
            &[pool_id, &self.counters.guardrails.to_string()],
        );
        let guardrail = LiquidityGuardrail::evaluate(
            guardrail_id,
            &pool_snapshot,
            notional,
            self.config.pool_staleness_blocks.saturating_sub(1),
            self.block_height,
            &self.config,
        );
        let guardrail_action = guardrail.action;
        self.record_guardrail(guardrail)?;
        if guardrail_action != GuardrailAction::Allow {
            return Err(format!("trade blocked by guardrail {:?}", guardrail_action));
        }
        let quote = pool_snapshot.quote_trade(side, notional, &self.config)?;
        let note = MarginNote::from_quote(note_id, &quote, self.block_height, &self.config);
        let note_id = note.note_id.clone();
        let rebate_id = deterministic_id("trade-rebate", &[&note_id]);
        let rebate = FeeCreditRebate::new(
            rebate_id,
            &note_id,
            pool_id,
            note.fee_paid,
            self.config.trader_rebate_bps,
            self.block_height.saturating_add(2_880),
            &self.config,
        );
        self.counters.total_swaps = self.counters.total_swaps.saturating_add(1);
        self.counters.total_fee_credits = self
            .counters
            .total_fee_credits
            .saturating_add(rebate.rebate_amount);
        self.margin_notes.insert(note_id.clone(), note.clone());
        self.rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        if let Some(pool) = self.amm_pools.get_mut(pool_id) {
            pool.apply_trade(&quote);
        }
        self.publish("margin_note_opened", &note_id, note.public_record())?;
        self.publish(
            "fee_credit_rebate_reserved",
            &rebate.rebate_id,
            rebate.public_record(),
        )?;
        self.refresh_roots();
        Ok(note_id)
    }

    pub fn settle_event_trigger(
        &mut self,
        settlement_id: impl Into<String>,
        token_id: &str,
        attestation_id: &str,
        pool_id: &str,
    ) -> Result<String> {
        ensure_capacity(
            "trigger_settlements",
            self.trigger_settlements.len(),
            self.config.max_trigger_settlements,
        )?;
        let token = self
            .weather_tokens
            .get(token_id)
            .ok_or_else(|| format!("unknown token {}", token_id))?
            .clone();
        let attestation = self
            .oracle_attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown attestation {}", attestation_id))?
            .clone();
        if attestation.token_id != token_id {
            return Err("attestation token mismatch".to_string());
        }
        let settled_notes: Vec<Value> = self
            .margin_notes
            .values()
            .filter(|note| {
                note.pool_id == pool_id
                    && note.token_id == token_id
                    && note.status == MarginStatus::Active
            })
            .map(MarginNote::public_record)
            .collect();
        let settled_note_root = payload_root("SETTLED-NOTES", &settled_notes);
        let settled_notional = self
            .margin_notes
            .values()
            .filter(|note| {
                note.pool_id == pool_id
                    && note.token_id == token_id
                    && note.status == MarginStatus::Active
            })
            .map(|note| note.notional)
            .fold(0_u128, u128::saturating_add);
        for note in self.margin_notes.values_mut().filter(|note| {
            note.pool_id == pool_id
                && note.token_id == token_id
                && note.status == MarginStatus::Active
        }) {
            note.mark_settled();
        }
        let mut settlement = EventTriggerSettlement::new(
            settlement_id,
            &token,
            &attestation,
            pool_id,
            settled_note_root,
            settled_notional,
            self.block_height,
        );
        settlement.finalize(
            self.block_height
                .saturating_add(self.config.settlement_delay_blocks),
        );
        let settlement_id = settlement.settlement_id.clone();
        if let Some(pool) = self.amm_pools.get_mut(pool_id) {
            pool.status = PoolStatus::Settling;
        }
        self.counters.total_settled_notional = self
            .counters
            .total_settled_notional
            .saturating_add(settled_notional);
        self.trigger_settlements
            .insert(settlement_id.clone(), settlement.clone());
        self.publish(
            "weather_event_trigger_settled",
            &settlement_id,
            settlement.public_record(),
        )?;
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn redact_public_record(
        &mut self,
        source_kind: impl Into<String>,
        source_id: impl Into<String>,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<String> {
        ensure_capacity(
            "privacy_redactions",
            self.privacy_redactions.len(),
            self.config.max_redactions,
        )?;
        let redaction_id = deterministic_id("redaction", &[&self.counters.redactions.to_string()]);
        let redaction = PrivacyRedaction::new(
            redaction_id.clone(),
            source_kind,
            source_id,
            fields,
            self.config.target_privacy_set_size,
            self.block_height,
        );
        let payload = redaction.public_record();
        self.privacy_redactions
            .insert(redaction_id.clone(), redaction);
        self.publish("privacy_redaction_published", &redaction_id, payload)?;
        self.refresh_roots();
        Ok(redaction_id)
    }

    pub fn add_operator_summary(&mut self, summary_id: impl Into<String>) -> Result<String> {
        let summary = OperatorSummary::from_state(summary_id, self);
        let summary_id = summary.summary_id.clone();
        let payload = summary.public_record();
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.publish("operator_summary_published", &summary_id, payload)?;
        self.refresh_roots();
        Ok(summary_id)
    }

    fn record_guardrail(&mut self, guardrail: LiquidityGuardrail) -> Result<()> {
        ensure_capacity(
            "guardrails",
            self.guardrails.len(),
            self.config.max_guardrails,
        )?;
        let guardrail_id = guardrail.guardrail_id.clone();
        let payload = guardrail.public_record();
        self.guardrails.insert(guardrail_id.clone(), guardrail);
        self.publish("liquidity_guardrail_evaluated", &guardrail_id, payload)
    }

    fn publish(&mut self, event_kind: &str, subject_id: &str, payload: Value) -> Result<()> {
        ensure_capacity(
            "public_events",
            self.public_events.len(),
            self.config.max_public_events,
        )?;
        let event_id = deterministic_id(
            "public-event",
            &[
                event_kind,
                subject_id,
                &self.public_events.len().to_string(),
            ],
        );
        let event = PublicEvent::new(
            event_id.clone(),
            event_kind,
            subject_id,
            self.block_height,
            &payload,
        );
        self.public_events.insert(event_id, event);
        Ok(())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_tokenized_weather_derivative_amm_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "block_height": self.block_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "weather_tokens": public_map(&self.weather_tokens, WeatherIndexToken::public_record),
            "oracle_attestations": public_map(&self.oracle_attestations, OracleWeatherAttestation::public_record),
            "amm_pools": public_map(&self.amm_pools, SealedAmmPool::public_record),
            "margin_notes": public_map(&self.margin_notes, MarginNote::public_record),
            "trigger_settlements": public_map(&self.trigger_settlements, EventTriggerSettlement::public_record),
            "guardrails": public_map(&self.guardrails, LiquidityGuardrail::public_record),
            "rebates": public_map(&self.rebates, FeeCreditRebate::public_record),
            "privacy_redactions": public_map(&self.privacy_redactions, PrivacyRedaction::public_record),
            "operator_summaries": public_map(&self.operator_summaries, OperatorSummary::public_record),
            "public_events": public_map(&self.public_events, PublicEvent::public_record)
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    state.block_height = state.block_height.saturating_add(12);
    let _ = state.add_operator_summary("weather-amm-demo-summary");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_pq_confidential_tokenized_weather_derivative_amm_runtime_public_record() -> Value
{
    State::devnet().public_record()
}

fn seed_devnet(state: &mut State) -> Result<()> {
    let heat = WeatherIndexToken::new(
        "wx-nyc-heatday-2026w29",
        WeatherIndexKind::CoolingDegreeDay,
        DerivativePayoffKind::CappedLinear,
        "US-NY-NYC",
        DEVNET_HEIGHT + 10,
        DEVNET_HEIGHT + 730,
        DEVNET_HEIGHT + 760,
        75_000_000,
        Some(25_000_000),
        75_000_000_000,
    );
    let rain = WeatherIndexToken::new(
        "wx-iowa-rainfall-2026q3",
        WeatherIndexKind::RainfallTotal,
        DerivativePayoffKind::RangeAccrual,
        "US-IA-CORN-BELT",
        DEVNET_HEIGHT + 20,
        DEVNET_HEIGHT + 2_180,
        DEVNET_HEIGHT + 2_240,
        180_000,
        Some(420_000),
        125_000_000_000,
    );
    let heat_id = state.list_weather_token(heat)?;
    let rain_id = state.list_weather_token(rain)?;
    let heat_pool = SealedAmmPool::new(
        "pool-wx-nyc-heatday-dusd",
        &heat_id,
        250_000_000_000,
        525_000,
        state.block_height,
        &state.config,
    );
    let rain_pool = SealedAmmPool::new(
        "pool-wx-iowa-rainfall-dusd",
        &rain_id,
        375_000_000_000,
        440_000,
        state.block_height,
        &state.config,
    );
    state.open_pool(heat_pool)?;
    state.open_pool(rain_pool)?;
    let heat_attestation = OracleWeatherAttestation::new(
        "attest-wx-nyc-heatday-prelim",
        &heat_id,
        83_250_000,
        state.block_height + 32,
        &state.config,
    );
    state.submit_oracle_attestation(heat_attestation)?;
    state.trade(
        "pool-wx-nyc-heatday-dusd",
        PositionSide::LongWeather,
        12_500_000_000,
        "margin-note-heat-long-0001",
    )?;
    state.trade(
        "pool-wx-iowa-rainfall-dusd",
        PositionSide::ShortWeather,
        9_000_000_000,
        "margin-note-rain-short-0001",
    )?;
    state.redact_public_record(
        "margin_note",
        "margin-note-heat-long-0001",
        [
            "note_id", "pool_id", "token_id", "side", "notional", "status",
        ],
    )?;
    state.settle_event_trigger(
        "settle-wx-nyc-heatday-prelim",
        &heat_id,
        "attest-wx-nyc-heatday-prelim",
        "pool-wx-nyc-heatday-dusd",
    )?;
    state.add_operator_summary("operator-summary-devnet-weather-amm")?;
    Ok(())
}

fn ensure_eq(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{} mismatch: expected {}, got {}",
            name, expected, actual
        ))
    }
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value <= MAX_BPS {
        Ok(())
    } else {
        Err(format!("{} exceeds {} bps", name, MAX_BPS))
    }
}

fn ensure_capacity(name: &str, len: usize, max: usize) -> Result<()> {
    if len < max {
        Ok(())
    } else {
        Err(format!("{} capacity exceeded: {} >= {}", name, len, max))
    }
}

fn apply_bps(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn price_impact_bps(notional: u128, liquidity: u128) -> u64 {
    if liquidity == 0 {
        return MAX_BPS;
    }
    ((notional.saturating_mul(MAX_BPS as u128)) / liquidity).min(MAX_BPS as u128) as u64
}

fn public_map<T, F>(map: &BTreeMap<String, T>, record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    Value::Array(
        map.iter()
            .map(|(id, item)| json!({"id": id, "record": record(item)}))
            .collect(),
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records: Vec<Value> = records.into_iter().collect();
    payload_root(domain, &records)
}

fn empty_root() -> String {
    payload_root("EMPTY", &[])
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-WEATHER-DERIVATIVE-AMM-STATE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Json(record),
        ],
    )
}

fn payload_root(domain: &str, records: &[Value]) -> String {
    let leaves: Vec<String> = records
        .iter()
        .map(|record| {
            domain_hash(
                domain,
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(HASH_SUITE),
                    HashPart::Json(record),
                ],
            )
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = vec![HashPart::Str(PROTOCOL_VERSION), HashPart::Str(domain)];
    hash_parts.extend(parts.iter().map(|part| HashPart::Str(part)));
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-WEATHER-DERIVATIVE-AMM-ID",
        &hash_parts,
    )
}
