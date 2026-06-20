use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialPerpsResult<T> = Result<T, String>;

pub const CONFIDENTIAL_PERPS_PROTOCOL_VERSION: &str = "nebula-confidential-perps-v1";
pub const CONFIDENTIAL_PERPS_COMMITMENT_SCHEME: &str = "devnet-shake256-sealed-perps-v1";
pub const CONFIDENTIAL_PERPS_RANGE_PROOF_SCHEME: &str = "devnet-mock-pq-range-proof-v1";
pub const CONFIDENTIAL_PERPS_PQ_SIGNATURE_SCHEME: &str = "ml-dsa-87-devnet-attestation-v1";
pub const CONFIDENTIAL_PERPS_ORACLE_SCHEME: &str = "threshold-oracle-root-v1";
pub const CONFIDENTIAL_PERPS_SETTLEMENT_ADAPTER_SCHEME: &str =
    "zk-contract-settlement-adapter-root-v1";
pub const CONFIDENTIAL_PERPS_LIQUIDATION_QUEUE_SCHEME: &str =
    "private-priority-queue-commitment-v1";
pub const CONFIDENTIAL_PERPS_DEFAULT_FUNDING_INTERVAL_BLOCKS: u64 = 24;
pub const CONFIDENTIAL_PERPS_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const CONFIDENTIAL_PERPS_DEFAULT_POSITION_TTL_BLOCKS: u64 = 7_200;
pub const CONFIDENTIAL_PERPS_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_PERPS_DEFAULT_LOW_FEE_LANE: &str = "small-private-perps";
pub const CONFIDENTIAL_PERPS_DEVNET_HEIGHT: u64 = 96;
pub const CONFIDENTIAL_PERPS_DEVNET_BASE_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_PERPS_DEVNET_STABLE_ASSET_ID: &str = "usdd-devnet";
pub const CONFIDENTIAL_PERPS_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_PERPS_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_PERPS_DEFAULT_MAX_LEVERAGE_BPS: u64 = 50_000;
pub const CONFIDENTIAL_PERPS_DEFAULT_INITIAL_MARGIN_BPS: u64 = 2_000;
pub const CONFIDENTIAL_PERPS_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 1_250;
pub const CONFIDENTIAL_PERPS_DEFAULT_SMALL_TRADE_NOTIONAL_UNITS: u64 = 25_000_000_000;
pub const CONFIDENTIAL_PERPS_DEFAULT_SMALL_TRADE_MAX_FEE_UNITS: u64 = 5_000;
pub const CONFIDENTIAL_PERPS_DEFAULT_RISK_COMMITTEE_THRESHOLD: u64 = 4;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerpMarketStatus {
    Active,
    ReduceOnly,
    Paused,
    Settling,
    Retired,
}

impl PerpMarketStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReduceOnly => "reduce_only",
            Self::Paused => "paused",
            Self::Settling => "settling",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_new_positions(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
}

impl PositionSide {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Open,
    PendingClose,
    Liquidating,
    Challenged,
    Closed,
}

impl PositionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PendingClose => "pending_close",
            Self::Liquidating => "liquidating",
            Self::Challenged => "challenged",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Active,
    Frozen,
    Draining,
    Settled,
}

impl VaultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Draining => "draining",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingStatus {
    Pending,
    Committed,
    Applied,
    Challenged,
}

impl FundingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Queued,
    ChallengeOpen,
    Executable,
    Executed,
    Cancelled,
    Expired,
}

impl LiquidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ChallengeOpen => "challenge_open",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerScope {
    Global,
    Market,
    Oracle,
    Liquidation,
    Funding,
    Settlement,
    InsuranceFund,
    LowFeeSponsor,
    Custom(String),
}

impl CircuitBreakerScope {
    pub fn as_str(&self) -> String {
        match self {
            Self::Global => "global".to_string(),
            Self::Market => "market".to_string(),
            Self::Oracle => "oracle".to_string(),
            Self::Liquidation => "liquidation".to_string(),
            Self::Funding => "funding".to_string(),
            Self::Settlement => "settlement".to_string(),
            Self::InsuranceFund => "insurance_fund".to_string(),
            Self::LowFeeSponsor => "low_fee_sponsor".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerStatus {
    Closed,
    Watching,
    Open,
    CoolingDown,
    Retired,
}

impl CircuitBreakerStatus {
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
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Healthy,
    Watch,
    Warn,
    Critical,
}

impl RiskSeverity {
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
            Self::Warn => 6_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAdapterStatus {
    Active,
    Paused,
    Deprecated,
}

impl SettlementAdapterStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deprecated => "deprecated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDecision {
    Approve,
    Warn,
    Pause,
    Resume,
}

impl AttestationDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Warn => "warn",
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyPauseStatus {
    Proposed,
    Active,
    Released,
    Rejected,
    Expired,
}

impl EmergencyPauseStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Released => "released",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPerpsConfig {
    pub protocol_version: String,
    pub commitment_scheme: String,
    pub range_proof_scheme: String,
    pub oracle_scheme: String,
    pub pq_signature_scheme: String,
    pub settlement_adapter_scheme: String,
    pub default_funding_interval_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub default_position_ttl_blocks: u64,
    pub max_oracle_staleness_blocks: u64,
    pub max_leverage_bps: u64,
    pub min_initial_margin_bps: u64,
    pub min_maintenance_margin_bps: u64,
    pub small_trade_notional_units: u64,
    pub small_trade_max_fee_units: u64,
    pub default_low_fee_lane: String,
    pub fee_asset_id: String,
    pub risk_committee_threshold: u64,
}

impl Default for ConfidentialPerpsConfig {
    fn default() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_PERPS_PROTOCOL_VERSION.to_string(),
            commitment_scheme: CONFIDENTIAL_PERPS_COMMITMENT_SCHEME.to_string(),
            range_proof_scheme: CONFIDENTIAL_PERPS_RANGE_PROOF_SCHEME.to_string(),
            oracle_scheme: CONFIDENTIAL_PERPS_ORACLE_SCHEME.to_string(),
            pq_signature_scheme: CONFIDENTIAL_PERPS_PQ_SIGNATURE_SCHEME.to_string(),
            settlement_adapter_scheme: CONFIDENTIAL_PERPS_SETTLEMENT_ADAPTER_SCHEME.to_string(),
            default_funding_interval_blocks: CONFIDENTIAL_PERPS_DEFAULT_FUNDING_INTERVAL_BLOCKS,
            default_challenge_window_blocks: CONFIDENTIAL_PERPS_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_position_ttl_blocks: CONFIDENTIAL_PERPS_DEFAULT_POSITION_TTL_BLOCKS,
            max_oracle_staleness_blocks: CONFIDENTIAL_PERPS_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            max_leverage_bps: CONFIDENTIAL_PERPS_DEFAULT_MAX_LEVERAGE_BPS,
            min_initial_margin_bps: CONFIDENTIAL_PERPS_DEFAULT_INITIAL_MARGIN_BPS,
            min_maintenance_margin_bps: CONFIDENTIAL_PERPS_DEFAULT_MAINTENANCE_MARGIN_BPS,
            small_trade_notional_units: CONFIDENTIAL_PERPS_DEFAULT_SMALL_TRADE_NOTIONAL_UNITS,
            small_trade_max_fee_units: CONFIDENTIAL_PERPS_DEFAULT_SMALL_TRADE_MAX_FEE_UNITS,
            default_low_fee_lane: CONFIDENTIAL_PERPS_DEFAULT_LOW_FEE_LANE.to_string(),
            fee_asset_id: CONFIDENTIAL_PERPS_DEVNET_STABLE_ASSET_ID.to_string(),
            risk_committee_threshold: CONFIDENTIAL_PERPS_DEFAULT_RISK_COMMITTEE_THRESHOLD,
        }
    }
}

impl ConfidentialPerpsConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "commitment_scheme": self.commitment_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "oracle_scheme": self.oracle_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "settlement_adapter_scheme": self.settlement_adapter_scheme,
            "default_funding_interval_blocks": self.default_funding_interval_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "default_position_ttl_blocks": self.default_position_ttl_blocks,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "max_leverage_bps": self.max_leverage_bps,
            "min_initial_margin_bps": self.min_initial_margin_bps,
            "min_maintenance_margin_bps": self.min_maintenance_margin_bps,
            "small_trade_notional_units": self.small_trade_notional_units,
            "small_trade_max_fee_units": self.small_trade_max_fee_units,
            "default_low_fee_lane": self.default_low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "risk_committee_threshold": self.risk_committee_threshold,
        })
    }

    pub fn config_root(&self) -> String {
        confidential_perps_payload_root("CONFIDENTIAL-PERPS-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.protocol_version, "config protocol_version")?;
        ensure_non_empty(&self.commitment_scheme, "config commitment_scheme")?;
        ensure_non_empty(&self.range_proof_scheme, "config range_proof_scheme")?;
        ensure_non_empty(&self.oracle_scheme, "config oracle_scheme")?;
        ensure_non_empty(&self.pq_signature_scheme, "config pq_signature_scheme")?;
        ensure_non_empty(
            &self.settlement_adapter_scheme,
            "config settlement_adapter_scheme",
        )?;
        ensure_non_empty(&self.default_low_fee_lane, "config default_low_fee_lane")?;
        ensure_non_empty(&self.fee_asset_id, "config fee_asset_id")?;
        if self.default_funding_interval_blocks == 0 {
            return Err("config funding interval must be positive".to_string());
        }
        if self.default_challenge_window_blocks == 0 {
            return Err("config challenge window must be positive".to_string());
        }
        if self.default_position_ttl_blocks <= self.default_challenge_window_blocks {
            return Err("config position ttl must exceed challenge window".to_string());
        }
        if self.max_oracle_staleness_blocks == 0 {
            return Err("config oracle staleness limit must be positive".to_string());
        }
        if self.max_leverage_bps < CONFIDENTIAL_PERPS_MAX_BPS {
            return Err("config max leverage must be at least 1x".to_string());
        }
        ensure_bps(self.min_initial_margin_bps, "config min_initial_margin_bps")?;
        ensure_bps(
            self.min_maintenance_margin_bps,
            "config min_maintenance_margin_bps",
        )?;
        if self.min_initial_margin_bps < self.min_maintenance_margin_bps {
            return Err("config initial margin must cover maintenance margin".to_string());
        }
        if self.small_trade_notional_units == 0 {
            return Err("config small trade notional must be positive".to_string());
        }
        if self.risk_committee_threshold == 0 {
            return Err("config risk committee threshold must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPerpMarket {
    pub market_id: String,
    pub display_name: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub margin_asset_id: String,
    pub oracle_feed_id: String,
    pub funding_oracle_root: String,
    pub price_scale: u64,
    pub max_leverage_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub taker_fee_bps: u64,
    pub maker_fee_bps: u64,
    pub min_position_notional_units: u64,
    pub max_position_notional_units: u64,
    pub open_interest_cap_units: u64,
    pub long_open_interest_units: u64,
    pub short_open_interest_units: u64,
    pub funding_interval_blocks: u64,
    pub challenge_window_blocks: u64,
    pub created_at_height: u64,
    pub status: PerpMarketStatus,
    pub risk_cap_root: String,
    pub settlement_adapter_root: String,
    pub metadata_root: String,
}

impl ConfidentialPerpMarket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        display_name: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        margin_asset_id: &str,
        oracle_feed_id: &str,
        max_leverage_bps: u64,
        initial_margin_bps: u64,
        maintenance_margin_bps: u64,
        min_position_notional_units: u64,
        max_position_notional_units: u64,
        open_interest_cap_units: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(display_name, "perp market display_name")?;
        ensure_non_empty(base_asset_id, "perp market base_asset_id")?;
        ensure_non_empty(quote_asset_id, "perp market quote_asset_id")?;
        ensure_non_empty(margin_asset_id, "perp market margin_asset_id")?;
        ensure_non_empty(oracle_feed_id, "perp market oracle_feed_id")?;
        let market_id = confidential_perps_market_id(
            base_asset_id,
            quote_asset_id,
            margin_asset_id,
            oracle_feed_id,
            created_at_height,
        );
        let market = Self {
            market_id,
            display_name: display_name.to_string(),
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            margin_asset_id: margin_asset_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            funding_oracle_root: merkle_root("CONFIDENTIAL-PERPS-FUNDING-ORACLE", &[]),
            price_scale: CONFIDENTIAL_PERPS_PRICE_SCALE,
            max_leverage_bps,
            initial_margin_bps,
            maintenance_margin_bps,
            taker_fee_bps: 8,
            maker_fee_bps: 2,
            min_position_notional_units,
            max_position_notional_units,
            open_interest_cap_units,
            long_open_interest_units: 0,
            short_open_interest_units: 0,
            funding_interval_blocks: CONFIDENTIAL_PERPS_DEFAULT_FUNDING_INTERVAL_BLOCKS,
            challenge_window_blocks: CONFIDENTIAL_PERPS_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            created_at_height,
            status: PerpMarketStatus::Active,
            risk_cap_root: merkle_root("CONFIDENTIAL-PERPS-RISK-CAP", &[]),
            settlement_adapter_root: merkle_root("CONFIDENTIAL-PERPS-SETTLEMENT-ADAPTER", &[]),
            metadata_root: confidential_perps_payload_root(
                "CONFIDENTIAL-PERPS-MARKET-METADATA",
                metadata,
            ),
        };
        market.validate()?;
        Ok(market)
    }

    pub fn wxmr_stable_pair(
        stable_asset_id: &str,
        oracle_feed_id: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> ConfidentialPerpsResult<Self> {
        Self::new(
            "wXMR / private stable perpetual",
            CONFIDENTIAL_PERPS_DEVNET_BASE_ASSET_ID,
            stable_asset_id,
            stable_asset_id,
            oracle_feed_id,
            CONFIDENTIAL_PERPS_DEFAULT_MAX_LEVERAGE_BPS,
            CONFIDENTIAL_PERPS_DEFAULT_INITIAL_MARGIN_BPS,
            CONFIDENTIAL_PERPS_DEFAULT_MAINTENANCE_MARGIN_BPS,
            1_000_000,
            250_000_000_000,
            2_000_000_000_000,
            created_at_height,
            metadata,
        )
    }

    pub fn remaining_open_interest_units(&self) -> u64 {
        self.open_interest_cap_units
            .saturating_sub(self.long_open_interest_units)
            .saturating_sub(self.short_open_interest_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perp_market",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_PERPS_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "display_name": self.display_name,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "margin_asset_id": self.margin_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "funding_oracle_root": self.funding_oracle_root,
            "price_scale": self.price_scale,
            "max_leverage_bps": self.max_leverage_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "maker_fee_bps": self.maker_fee_bps,
            "min_position_notional_units": self.min_position_notional_units,
            "max_position_notional_units": self.max_position_notional_units,
            "open_interest_cap_units": self.open_interest_cap_units,
            "long_open_interest_units": self.long_open_interest_units,
            "short_open_interest_units": self.short_open_interest_units,
            "remaining_open_interest_units": self.remaining_open_interest_units(),
            "funding_interval_blocks": self.funding_interval_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
            "accepts_new_positions": self.status.accepts_new_positions(),
            "risk_cap_root": self.risk_cap_root,
            "settlement_adapter_root": self.settlement_adapter_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn market_root(&self) -> String {
        confidential_perps_payload_root("CONFIDENTIAL-PERPS-MARKET", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.market_id, "perp market market_id")?;
        ensure_non_empty(&self.display_name, "perp market display_name")?;
        ensure_non_empty(&self.base_asset_id, "perp market base_asset_id")?;
        ensure_non_empty(&self.quote_asset_id, "perp market quote_asset_id")?;
        ensure_non_empty(&self.margin_asset_id, "perp market margin_asset_id")?;
        ensure_non_empty(&self.oracle_feed_id, "perp market oracle_feed_id")?;
        ensure_non_empty(&self.funding_oracle_root, "perp market funding_oracle_root")?;
        ensure_non_empty(&self.risk_cap_root, "perp market risk_cap_root")?;
        ensure_non_empty(
            &self.settlement_adapter_root,
            "perp market settlement_adapter_root",
        )?;
        ensure_non_empty(&self.metadata_root, "perp market metadata_root")?;
        ensure_bps(self.initial_margin_bps, "perp market initial_margin_bps")?;
        ensure_bps(
            self.maintenance_margin_bps,
            "perp market maintenance_margin_bps",
        )?;
        ensure_bps(self.taker_fee_bps, "perp market taker_fee_bps")?;
        ensure_bps(self.maker_fee_bps, "perp market maker_fee_bps")?;
        if self.initial_margin_bps < self.maintenance_margin_bps {
            return Err("perp market initial margin must cover maintenance margin".to_string());
        }
        if self.max_leverage_bps < CONFIDENTIAL_PERPS_MAX_BPS {
            return Err("perp market max leverage must be at least 1x".to_string());
        }
        if self.funding_interval_blocks == 0 {
            return Err("perp market funding interval must be positive".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("perp market challenge window must be positive".to_string());
        }
        if self.min_position_notional_units == 0
            || self.max_position_notional_units < self.min_position_notional_units
        {
            return Err("perp market position notional bounds are invalid".to_string());
        }
        if self.open_interest_cap_units < self.max_position_notional_units {
            return Err("perp market open interest cap must cover max position".to_string());
        }
        let open_interest = self
            .long_open_interest_units
            .saturating_add(self.short_open_interest_units);
        if open_interest > self.open_interest_cap_units {
            return Err("perp market open interest exceeds cap".to_string());
        }
        let expected_id = confidential_perps_market_id(
            &self.base_asset_id,
            &self.quote_asset_id,
            &self.margin_asset_id,
            &self.oracle_feed_id,
            self.created_at_height,
        );
        if self.market_id != expected_id {
            return Err("perp market id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpRiskCap {
    pub cap_id: String,
    pub market_id: String,
    pub cap_version: u64,
    pub max_open_interest_units: u64,
    pub max_skew_bps: u64,
    pub max_single_position_units: u64,
    pub max_leverage_bps: u64,
    pub maintenance_margin_bps: u64,
    pub oracle_staleness_limit_blocks: u64,
    pub liquidator_notional_cap_units: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub committee_attestation_root: String,
}

impl PerpRiskCap {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        cap_version: u64,
        max_open_interest_units: u64,
        max_skew_bps: u64,
        max_single_position_units: u64,
        max_leverage_bps: u64,
        maintenance_margin_bps: u64,
        oracle_staleness_limit_blocks: u64,
        liquidator_notional_cap_units: u64,
        active_from_height: u64,
        expires_at_height: u64,
        committee_attestation_root: impl Into<String>,
    ) -> ConfidentialPerpsResult<Self> {
        let committee_attestation_root = committee_attestation_root.into();
        let cap_id = confidential_perps_risk_cap_id(market_id, cap_version, active_from_height);
        let cap = Self {
            cap_id,
            market_id: market_id.to_string(),
            cap_version,
            max_open_interest_units,
            max_skew_bps,
            max_single_position_units,
            max_leverage_bps,
            maintenance_margin_bps,
            oracle_staleness_limit_blocks,
            liquidator_notional_cap_units,
            active_from_height,
            expires_at_height,
            committee_attestation_root,
        };
        cap.validate()?;
        Ok(cap)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_risk_cap",
            "chain_id": CHAIN_ID,
            "cap_id": self.cap_id,
            "market_id": self.market_id,
            "cap_version": self.cap_version,
            "max_open_interest_units": self.max_open_interest_units,
            "max_skew_bps": self.max_skew_bps,
            "max_single_position_units": self.max_single_position_units,
            "max_leverage_bps": self.max_leverage_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "oracle_staleness_limit_blocks": self.oracle_staleness_limit_blocks,
            "liquidator_notional_cap_units": self.liquidator_notional_cap_units,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "committee_attestation_root": self.committee_attestation_root,
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.cap_id, "risk cap cap_id")?;
        ensure_non_empty(&self.market_id, "risk cap market_id")?;
        ensure_non_empty(
            &self.committee_attestation_root,
            "risk cap committee_attestation_root",
        )?;
        ensure_bps(self.max_skew_bps, "risk cap max_skew_bps")?;
        ensure_bps(
            self.maintenance_margin_bps,
            "risk cap maintenance_margin_bps",
        )?;
        if self.max_open_interest_units == 0 || self.max_single_position_units == 0 {
            return Err("risk cap open interest limits must be positive".to_string());
        }
        if self.max_single_position_units > self.max_open_interest_units {
            return Err("risk cap single position exceeds open interest cap".to_string());
        }
        if self.max_leverage_bps < CONFIDENTIAL_PERPS_MAX_BPS {
            return Err("risk cap max leverage must be at least 1x".to_string());
        }
        if self.oracle_staleness_limit_blocks == 0 {
            return Err("risk cap oracle staleness limit must be positive".to_string());
        }
        if self.expires_at_height <= self.active_from_height {
            return Err("risk cap expiry must be after activation".to_string());
        }
        let expected_id = confidential_perps_risk_cap_id(
            &self.market_id,
            self.cap_version,
            self.active_from_height,
        );
        if self.cap_id != expected_id {
            return Err("risk cap id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginVaultCommitment {
    pub vault_id: String,
    pub owner_commitment: String,
    pub margin_asset_id: String,
    pub balance_commitment: String,
    pub locked_margin_commitment: String,
    pub insurance_escrow_commitment: String,
    pub nullifier_root: String,
    pub withdrawal_queue_root: String,
    pub proof_root: String,
    pub opened_at_height: u64,
    pub last_update_height: u64,
    pub nonce: u64,
    pub status: VaultStatus,
}

impl MarginVaultCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        margin_asset_id: &str,
        balance_units: u64,
        locked_margin_units: u64,
        insurance_escrow_units: u64,
        opened_at_height: u64,
        nonce: u64,
        proof_payload: &Value,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(owner_label, "margin vault owner_label")?;
        ensure_non_empty(margin_asset_id, "margin vault margin_asset_id")?;
        let owner_commitment = confidential_perps_account_commitment(owner_label);
        let balance_commitment = confidential_perps_amount_commitment(
            "vault_balance",
            balance_units,
            &confidential_perps_blinding(owner_label, nonce, "vault_balance"),
        );
        let locked_margin_commitment = confidential_perps_amount_commitment(
            "vault_locked_margin",
            locked_margin_units,
            &confidential_perps_blinding(owner_label, nonce, "vault_locked"),
        );
        let insurance_escrow_commitment = confidential_perps_amount_commitment(
            "vault_insurance_escrow",
            insurance_escrow_units,
            &confidential_perps_blinding(owner_label, nonce, "vault_insurance"),
        );
        let proof_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-MARGIN-VAULT-PROOF", proof_payload);
        let vault_id = confidential_perps_margin_vault_id(
            &owner_commitment,
            margin_asset_id,
            opened_at_height,
            nonce,
        );
        let vault = Self {
            vault_id,
            owner_commitment,
            margin_asset_id: margin_asset_id.to_string(),
            balance_commitment,
            locked_margin_commitment,
            insurance_escrow_commitment,
            nullifier_root: merkle_root("CONFIDENTIAL-PERPS-MARGIN-NULLIFIER", &[]),
            withdrawal_queue_root: merkle_root("CONFIDENTIAL-PERPS-MARGIN-WITHDRAWAL", &[]),
            proof_root,
            opened_at_height,
            last_update_height: opened_at_height,
            nonce,
            status: VaultStatus::Active,
        };
        vault.validate()?;
        Ok(vault)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_margin_vault",
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "margin_asset_id": self.margin_asset_id,
            "balance_commitment": self.balance_commitment,
            "locked_margin_commitment": self.locked_margin_commitment,
            "insurance_escrow_commitment": self.insurance_escrow_commitment,
            "nullifier_root": self.nullifier_root,
            "withdrawal_queue_root": self.withdrawal_queue_root,
            "proof_root": self.proof_root,
            "opened_at_height": self.opened_at_height,
            "last_update_height": self.last_update_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.vault_id, "margin vault vault_id")?;
        ensure_non_empty(&self.owner_commitment, "margin vault owner_commitment")?;
        ensure_non_empty(&self.margin_asset_id, "margin vault margin_asset_id")?;
        ensure_non_empty(&self.balance_commitment, "margin vault balance_commitment")?;
        ensure_non_empty(
            &self.locked_margin_commitment,
            "margin vault locked_margin_commitment",
        )?;
        ensure_non_empty(
            &self.insurance_escrow_commitment,
            "margin vault insurance_escrow_commitment",
        )?;
        ensure_non_empty(&self.nullifier_root, "margin vault nullifier_root")?;
        ensure_non_empty(
            &self.withdrawal_queue_root,
            "margin vault withdrawal_queue_root",
        )?;
        ensure_non_empty(&self.proof_root, "margin vault proof_root")?;
        if self.last_update_height < self.opened_at_height {
            return Err("margin vault update height predates open height".to_string());
        }
        let expected_id = confidential_perps_margin_vault_id(
            &self.owner_commitment,
            &self.margin_asset_id,
            self.opened_at_height,
            self.nonce,
        );
        if self.vault_id != expected_id {
            return Err("margin vault id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPositionCommitment {
    pub position_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub side_commitment: String,
    pub size_commitment: String,
    pub entry_price_commitment: String,
    pub margin_vault_id: String,
    pub leverage_bps: u64,
    pub liquidation_price_commitment: String,
    pub funding_checkpoint_id: String,
    pub order_commitment_root: String,
    pub privacy_budget_id: String,
    pub proof_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: PositionStatus,
}

impl SealedPositionCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        owner_label: &str,
        side: PositionSide,
        size_units: u64,
        entry_price_units: u64,
        margin_vault_id: &str,
        leverage_bps: u64,
        liquidation_price_units: u64,
        funding_checkpoint_id: &str,
        privacy_budget_id: &str,
        order_payload: &Value,
        proof_payload: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "position market_id")?;
        ensure_non_empty(owner_label, "position owner_label")?;
        ensure_non_empty(margin_vault_id, "position margin_vault_id")?;
        ensure_non_empty(funding_checkpoint_id, "position funding_checkpoint_id")?;
        ensure_non_empty(privacy_budget_id, "position privacy_budget_id")?;
        let owner_commitment = confidential_perps_account_commitment(owner_label);
        let side_commitment = confidential_perps_side_commitment(
            &side,
            &confidential_perps_blinding(owner_label, nonce, "position_side"),
        );
        let size_commitment = confidential_perps_amount_commitment(
            "position_size",
            size_units,
            &confidential_perps_blinding(owner_label, nonce, "position_size"),
        );
        let entry_price_commitment = confidential_perps_price_commitment(
            "entry_price",
            entry_price_units,
            &confidential_perps_blinding(owner_label, nonce, "entry_price"),
        );
        let liquidation_price_commitment = confidential_perps_price_commitment(
            "liquidation_price",
            liquidation_price_units,
            &confidential_perps_blinding(owner_label, nonce, "liquidation_price"),
        );
        let order_commitment_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-SEALED-ORDER", order_payload);
        let proof_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-POSITION-PROOF", proof_payload);
        let position_id = confidential_perps_position_id(
            market_id,
            &owner_commitment,
            margin_vault_id,
            &side_commitment,
            &size_commitment,
            nonce,
        );
        let position = Self {
            position_id,
            market_id: market_id.to_string(),
            owner_commitment,
            side_commitment,
            size_commitment,
            entry_price_commitment,
            margin_vault_id: margin_vault_id.to_string(),
            leverage_bps,
            liquidation_price_commitment,
            funding_checkpoint_id: funding_checkpoint_id.to_string(),
            order_commitment_root,
            privacy_budget_id: privacy_budget_id.to_string(),
            proof_root,
            opened_at_height,
            expires_at_height,
            nonce,
            status: PositionStatus::Open,
        };
        position.validate()?;
        Ok(position)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_sealed_position",
            "chain_id": CHAIN_ID,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "side_commitment": self.side_commitment,
            "size_commitment": self.size_commitment,
            "entry_price_commitment": self.entry_price_commitment,
            "margin_vault_id": self.margin_vault_id,
            "leverage_bps": self.leverage_bps,
            "liquidation_price_commitment": self.liquidation_price_commitment,
            "funding_checkpoint_id": self.funding_checkpoint_id,
            "order_commitment_root": self.order_commitment_root,
            "privacy_budget_id": self.privacy_budget_id,
            "proof_root": self.proof_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.position_id, "position position_id")?;
        ensure_non_empty(&self.market_id, "position market_id")?;
        ensure_non_empty(&self.owner_commitment, "position owner_commitment")?;
        ensure_non_empty(&self.side_commitment, "position side_commitment")?;
        ensure_non_empty(&self.size_commitment, "position size_commitment")?;
        ensure_non_empty(
            &self.entry_price_commitment,
            "position entry_price_commitment",
        )?;
        ensure_non_empty(&self.margin_vault_id, "position margin_vault_id")?;
        ensure_non_empty(
            &self.liquidation_price_commitment,
            "position liquidation_price_commitment",
        )?;
        ensure_non_empty(
            &self.funding_checkpoint_id,
            "position funding_checkpoint_id",
        )?;
        ensure_non_empty(
            &self.order_commitment_root,
            "position order_commitment_root",
        )?;
        ensure_non_empty(&self.privacy_budget_id, "position privacy_budget_id")?;
        ensure_non_empty(&self.proof_root, "position proof_root")?;
        if self.leverage_bps < CONFIDENTIAL_PERPS_MAX_BPS {
            return Err("position leverage must be at least 1x".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("position expiry must be after open height".to_string());
        }
        let expected_id = confidential_perps_position_id(
            &self.market_id,
            &self.owner_commitment,
            &self.margin_vault_id,
            &self.side_commitment,
            &self.size_commitment,
            self.nonce,
        );
        if self.position_id != expected_id {
            return Err("position id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingRateCommitment {
    pub funding_id: String,
    pub market_id: String,
    pub interval_index: u64,
    pub interval_start_height: u64,
    pub interval_end_height: u64,
    pub oracle_root: String,
    pub premium_twap_commitment: String,
    pub interest_rate_commitment: String,
    pub funding_rate_commitment: String,
    pub long_payment_commitment: String,
    pub short_payment_commitment: String,
    pub proof_root: String,
    pub committed_at_height: u64,
    pub applies_at_height: u64,
    pub status: FundingStatus,
}

impl FundingRateCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        interval_index: u64,
        interval_start_height: u64,
        interval_end_height: u64,
        oracle_root: &str,
        premium_twap_bps: i64,
        interest_rate_bps: i64,
        funding_rate_bps: i64,
        committed_at_height: u64,
        proof_payload: &Value,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "funding market_id")?;
        ensure_non_empty(oracle_root, "funding oracle_root")?;
        let funding_id = confidential_perps_funding_id(
            market_id,
            interval_index,
            oracle_root,
            committed_at_height,
        );
        let blinding = confidential_perps_blinding(market_id, interval_index, "funding");
        let funding = Self {
            funding_id,
            market_id: market_id.to_string(),
            interval_index,
            interval_start_height,
            interval_end_height,
            oracle_root: oracle_root.to_string(),
            premium_twap_commitment: confidential_perps_signed_commitment(
                "premium_twap_bps",
                premium_twap_bps,
                &blinding,
            ),
            interest_rate_commitment: confidential_perps_signed_commitment(
                "interest_rate_bps",
                interest_rate_bps,
                &blinding,
            ),
            funding_rate_commitment: confidential_perps_signed_commitment(
                "funding_rate_bps",
                funding_rate_bps,
                &blinding,
            ),
            long_payment_commitment: confidential_perps_signed_commitment(
                "long_payment_bps",
                -funding_rate_bps,
                &blinding,
            ),
            short_payment_commitment: confidential_perps_signed_commitment(
                "short_payment_bps",
                funding_rate_bps,
                &blinding,
            ),
            proof_root: confidential_perps_payload_root(
                "CONFIDENTIAL-PERPS-FUNDING-PROOF",
                proof_payload,
            ),
            committed_at_height,
            applies_at_height: interval_end_height.saturating_add(1),
            status: FundingStatus::Committed,
        };
        funding.validate()?;
        Ok(funding)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_funding_rate_commitment",
            "chain_id": CHAIN_ID,
            "funding_id": self.funding_id,
            "market_id": self.market_id,
            "interval_index": self.interval_index,
            "interval_start_height": self.interval_start_height,
            "interval_end_height": self.interval_end_height,
            "oracle_root": self.oracle_root,
            "premium_twap_commitment": self.premium_twap_commitment,
            "interest_rate_commitment": self.interest_rate_commitment,
            "funding_rate_commitment": self.funding_rate_commitment,
            "long_payment_commitment": self.long_payment_commitment,
            "short_payment_commitment": self.short_payment_commitment,
            "proof_root": self.proof_root,
            "committed_at_height": self.committed_at_height,
            "applies_at_height": self.applies_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.funding_id, "funding funding_id")?;
        ensure_non_empty(&self.market_id, "funding market_id")?;
        ensure_non_empty(&self.oracle_root, "funding oracle_root")?;
        ensure_non_empty(
            &self.premium_twap_commitment,
            "funding premium_twap_commitment",
        )?;
        ensure_non_empty(
            &self.interest_rate_commitment,
            "funding interest_rate_commitment",
        )?;
        ensure_non_empty(
            &self.funding_rate_commitment,
            "funding funding_rate_commitment",
        )?;
        ensure_non_empty(
            &self.long_payment_commitment,
            "funding long_payment_commitment",
        )?;
        ensure_non_empty(
            &self.short_payment_commitment,
            "funding short_payment_commitment",
        )?;
        ensure_non_empty(&self.proof_root, "funding proof_root")?;
        if self.interval_end_height <= self.interval_start_height {
            return Err("funding interval end must be after start".to_string());
        }
        if self.applies_at_height <= self.interval_end_height {
            return Err("funding apply height must follow interval".to_string());
        }
        let expected_id = confidential_perps_funding_id(
            &self.market_id,
            self.interval_index,
            &self.oracle_root,
            self.committed_at_height,
        );
        if self.funding_id != expected_id {
            return Err("funding id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleRootCommitment {
    pub oracle_root_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub price_commitment: String,
    pub confidence_commitment: String,
    pub source_root: String,
    pub aggregator_commitment: String,
    pub median_update_height: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub attestation_root: String,
    pub status: String,
}

impl OracleRootCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        feed_id: &str,
        price_units: u64,
        confidence_bps: u64,
        source_payloads: &[Value],
        aggregator_label: &str,
        median_update_height: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        attestation_payload: &Value,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "oracle root market_id")?;
        ensure_non_empty(feed_id, "oracle root feed_id")?;
        ensure_non_empty(aggregator_label, "oracle root aggregator_label")?;
        let source_root = merkle_root("CONFIDENTIAL-PERPS-ORACLE-SOURCE", source_payloads);
        let attestation_root = confidential_perps_payload_root(
            "CONFIDENTIAL-PERPS-ORACLE-ATTESTATION",
            attestation_payload,
        );
        let oracle_root_id = confidential_perps_oracle_root_id(
            market_id,
            feed_id,
            &source_root,
            median_update_height,
        );
        let oracle = Self {
            oracle_root_id,
            market_id: market_id.to_string(),
            feed_id: feed_id.to_string(),
            price_commitment: confidential_perps_price_commitment(
                "oracle_price",
                price_units,
                &confidential_perps_blinding(feed_id, median_update_height, "oracle_price"),
            ),
            confidence_commitment: confidential_perps_amount_commitment(
                "oracle_confidence_bps",
                confidence_bps,
                &confidential_perps_blinding(feed_id, median_update_height, "oracle_confidence"),
            ),
            source_root,
            aggregator_commitment: confidential_perps_account_commitment(aggregator_label),
            median_update_height,
            valid_from_height,
            valid_until_height,
            attestation_root,
            status: "active".to_string(),
        };
        oracle.validate()?;
        Ok(oracle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_oracle_root",
            "chain_id": CHAIN_ID,
            "oracle_scheme": CONFIDENTIAL_PERPS_ORACLE_SCHEME,
            "oracle_root_id": self.oracle_root_id,
            "market_id": self.market_id,
            "feed_id": self.feed_id,
            "price_commitment": self.price_commitment,
            "confidence_commitment": self.confidence_commitment,
            "source_root": self.source_root,
            "aggregator_commitment": self.aggregator_commitment,
            "median_update_height": self.median_update_height,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "attestation_root": self.attestation_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.oracle_root_id, "oracle root id")?;
        ensure_non_empty(&self.market_id, "oracle root market_id")?;
        ensure_non_empty(&self.feed_id, "oracle root feed_id")?;
        ensure_non_empty(&self.price_commitment, "oracle root price_commitment")?;
        ensure_non_empty(
            &self.confidence_commitment,
            "oracle root confidence_commitment",
        )?;
        ensure_non_empty(&self.source_root, "oracle root source_root")?;
        ensure_non_empty(
            &self.aggregator_commitment,
            "oracle root aggregator_commitment",
        )?;
        ensure_non_empty(&self.attestation_root, "oracle root attestation_root")?;
        ensure_non_empty(&self.status, "oracle root status")?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("oracle root valid_until must be after valid_from".to_string());
        }
        if self.median_update_height < self.valid_from_height
            || self.median_update_height > self.valid_until_height
        {
            return Err("oracle root median update must be inside validity window".to_string());
        }
        let expected_id = confidential_perps_oracle_root_id(
            &self.market_id,
            &self.feed_id,
            &self.source_root,
            self.median_update_height,
        );
        if self.oracle_root_id != expected_id {
            return Err("oracle root id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLiquidationQueueEntry {
    pub liquidation_id: String,
    pub market_id: String,
    pub position_id: String,
    pub keeper_commitment: String,
    pub trigger_price_commitment: String,
    pub maintenance_margin_commitment: String,
    pub debt_commitment: String,
    pub collateral_commitment: String,
    pub queue_priority_commitment: String,
    pub evidence_root: String,
    pub challenge_window_start: u64,
    pub challenge_window_end: u64,
    pub executable_at_height: u64,
    pub submitted_at_height: u64,
    pub nonce: u64,
    pub status: LiquidationStatus,
}

impl PrivateLiquidationQueueEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        position_id: &str,
        keeper_label: &str,
        trigger_price_units: u64,
        maintenance_margin_units: u64,
        debt_units: u64,
        collateral_units: u64,
        priority_units: u64,
        evidence_payload: &Value,
        submitted_at_height: u64,
        challenge_window_blocks: u64,
        nonce: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "liquidation market_id")?;
        ensure_non_empty(position_id, "liquidation position_id")?;
        ensure_non_empty(keeper_label, "liquidation keeper_label")?;
        if challenge_window_blocks == 0 {
            return Err("liquidation challenge window must be positive".to_string());
        }
        let keeper_commitment = confidential_perps_account_commitment(keeper_label);
        let evidence_root = confidential_perps_payload_root(
            "CONFIDENTIAL-PERPS-LIQUIDATION-EVIDENCE",
            evidence_payload,
        );
        let liquidation_id = confidential_perps_liquidation_id(
            market_id,
            position_id,
            &keeper_commitment,
            submitted_at_height,
            nonce,
        );
        let entry = Self {
            liquidation_id,
            market_id: market_id.to_string(),
            position_id: position_id.to_string(),
            keeper_commitment,
            trigger_price_commitment: confidential_perps_price_commitment(
                "liquidation_trigger",
                trigger_price_units,
                &confidential_perps_blinding(position_id, nonce, "liquidation_trigger"),
            ),
            maintenance_margin_commitment: confidential_perps_amount_commitment(
                "maintenance_margin",
                maintenance_margin_units,
                &confidential_perps_blinding(position_id, nonce, "maintenance_margin"),
            ),
            debt_commitment: confidential_perps_amount_commitment(
                "liquidation_debt",
                debt_units,
                &confidential_perps_blinding(position_id, nonce, "liquidation_debt"),
            ),
            collateral_commitment: confidential_perps_amount_commitment(
                "liquidation_collateral",
                collateral_units,
                &confidential_perps_blinding(position_id, nonce, "liquidation_collateral"),
            ),
            queue_priority_commitment: confidential_perps_amount_commitment(
                "liquidation_priority",
                priority_units,
                &confidential_perps_blinding(position_id, nonce, "liquidation_priority"),
            ),
            evidence_root,
            challenge_window_start: submitted_at_height,
            challenge_window_end: submitted_at_height.saturating_add(challenge_window_blocks),
            executable_at_height: submitted_at_height
                .saturating_add(challenge_window_blocks)
                .saturating_add(1),
            submitted_at_height,
            nonce,
            status: LiquidationStatus::ChallengeOpen,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_private_liquidation_queue_entry",
            "chain_id": CHAIN_ID,
            "queue_scheme": CONFIDENTIAL_PERPS_LIQUIDATION_QUEUE_SCHEME,
            "liquidation_id": self.liquidation_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "keeper_commitment": self.keeper_commitment,
            "trigger_price_commitment": self.trigger_price_commitment,
            "maintenance_margin_commitment": self.maintenance_margin_commitment,
            "debt_commitment": self.debt_commitment,
            "collateral_commitment": self.collateral_commitment,
            "queue_priority_commitment": self.queue_priority_commitment,
            "evidence_root": self.evidence_root,
            "challenge_window_start": self.challenge_window_start,
            "challenge_window_end": self.challenge_window_end,
            "executable_at_height": self.executable_at_height,
            "submitted_at_height": self.submitted_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.liquidation_id, "liquidation liquidation_id")?;
        ensure_non_empty(&self.market_id, "liquidation market_id")?;
        ensure_non_empty(&self.position_id, "liquidation position_id")?;
        ensure_non_empty(&self.keeper_commitment, "liquidation keeper_commitment")?;
        ensure_non_empty(
            &self.trigger_price_commitment,
            "liquidation trigger_price_commitment",
        )?;
        ensure_non_empty(
            &self.maintenance_margin_commitment,
            "liquidation maintenance_margin_commitment",
        )?;
        ensure_non_empty(&self.debt_commitment, "liquidation debt_commitment")?;
        ensure_non_empty(
            &self.collateral_commitment,
            "liquidation collateral_commitment",
        )?;
        ensure_non_empty(
            &self.queue_priority_commitment,
            "liquidation queue_priority_commitment",
        )?;
        ensure_non_empty(&self.evidence_root, "liquidation evidence_root")?;
        if self.challenge_window_end <= self.challenge_window_start {
            return Err("liquidation challenge window is invalid".to_string());
        }
        if self.executable_at_height <= self.challenge_window_end {
            return Err("liquidation executable height must follow challenge window".to_string());
        }
        if self.submitted_at_height != self.challenge_window_start {
            return Err("liquidation submitted height must open challenge window".to_string());
        }
        let expected_id = confidential_perps_liquidation_id(
            &self.market_id,
            &self.position_id,
            &self.keeper_commitment,
            self.submitted_at_height,
            self.nonce,
        );
        if self.liquidation_id != expected_id {
            return Err("liquidation id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationChallenge {
    pub challenge_id: String,
    pub liquidation_id: String,
    pub challenger_commitment: String,
    pub counter_evidence_root: String,
    pub bond_commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub status: ChallengeStatus,
}

impl LiquidationChallenge {
    pub fn new(
        liquidation_id: &str,
        challenger_label: &str,
        bond_units: u64,
        counter_evidence: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(liquidation_id, "challenge liquidation_id")?;
        ensure_non_empty(challenger_label, "challenge challenger_label")?;
        let challenger_commitment = confidential_perps_account_commitment(challenger_label);
        let counter_evidence_root = confidential_perps_payload_root(
            "CONFIDENTIAL-PERPS-LIQUIDATION-CHALLENGE",
            counter_evidence,
        );
        let bond_commitment = confidential_perps_amount_commitment(
            "liquidation_challenge_bond",
            bond_units,
            &confidential_perps_blinding(challenger_label, opened_at_height, "challenge_bond"),
        );
        let challenge_id = confidential_perps_liquidation_challenge_id(
            liquidation_id,
            &challenger_commitment,
            &counter_evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            liquidation_id: liquidation_id.to_string(),
            challenger_commitment,
            counter_evidence_root,
            bond_commitment,
            opened_at_height,
            expires_at_height,
            resolved_at_height: None,
            status: ChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_liquidation_challenge",
            "chain_id": CHAIN_ID,
            "challenge_id": self.challenge_id,
            "liquidation_id": self.liquidation_id,
            "challenger_commitment": self.challenger_commitment,
            "counter_evidence_root": self.counter_evidence_root,
            "bond_commitment": self.bond_commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.challenge_id, "challenge challenge_id")?;
        ensure_non_empty(&self.liquidation_id, "challenge liquidation_id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "challenge challenger_commitment",
        )?;
        ensure_non_empty(
            &self.counter_evidence_root,
            "challenge counter_evidence_root",
        )?;
        ensure_non_empty(&self.bond_commitment, "challenge bond_commitment")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("challenge expiry must be after open height".to_string());
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err("challenge resolved height predates open height".to_string());
            }
        }
        let expected_id = confidential_perps_liquidation_challenge_id(
            &self.liquidation_id,
            &self.challenger_commitment,
            &self.counter_evidence_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected_id {
            return Err("challenge id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsuranceFund {
    pub fund_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub reserve_commitment: String,
    pub pending_payout_commitment: String,
    pub reserve_floor_units: u64,
    pub pending_payout_floor_units: u64,
    pub target_coverage_bps: u64,
    pub last_rebalance_height: u64,
    pub sponsor_root: String,
    pub payout_queue_root: String,
    pub status: VaultStatus,
}

impl InsuranceFund {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        asset_id: &str,
        reserve_floor_units: u64,
        pending_payout_floor_units: u64,
        target_coverage_bps: u64,
        last_rebalance_height: u64,
        sponsor_payloads: &[Value],
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "insurance fund market_id")?;
        ensure_non_empty(asset_id, "insurance fund asset_id")?;
        let fund_id = confidential_perps_insurance_fund_id(market_id, asset_id);
        let fund = Self {
            fund_id,
            market_id: market_id.to_string(),
            asset_id: asset_id.to_string(),
            reserve_commitment: confidential_perps_amount_commitment(
                "insurance_reserve",
                reserve_floor_units,
                &confidential_perps_blinding(market_id, last_rebalance_height, "insurance_reserve"),
            ),
            pending_payout_commitment: confidential_perps_amount_commitment(
                "insurance_pending_payout",
                pending_payout_floor_units,
                &confidential_perps_blinding(market_id, last_rebalance_height, "insurance_payout"),
            ),
            reserve_floor_units,
            pending_payout_floor_units,
            target_coverage_bps,
            last_rebalance_height,
            sponsor_root: merkle_root("CONFIDENTIAL-PERPS-INSURANCE-SPONSOR", sponsor_payloads),
            payout_queue_root: merkle_root("CONFIDENTIAL-PERPS-INSURANCE-PAYOUT", &[]),
            status: VaultStatus::Active,
        };
        fund.validate()?;
        Ok(fund)
    }

    pub fn available_floor_units(&self) -> u64 {
        self.reserve_floor_units
            .saturating_sub(self.pending_payout_floor_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_insurance_fund",
            "chain_id": CHAIN_ID,
            "fund_id": self.fund_id,
            "market_id": self.market_id,
            "asset_id": self.asset_id,
            "reserve_commitment": self.reserve_commitment,
            "pending_payout_commitment": self.pending_payout_commitment,
            "reserve_floor_units": self.reserve_floor_units,
            "pending_payout_floor_units": self.pending_payout_floor_units,
            "available_floor_units": self.available_floor_units(),
            "target_coverage_bps": self.target_coverage_bps,
            "last_rebalance_height": self.last_rebalance_height,
            "sponsor_root": self.sponsor_root,
            "payout_queue_root": self.payout_queue_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.fund_id, "insurance fund fund_id")?;
        ensure_non_empty(&self.market_id, "insurance fund market_id")?;
        ensure_non_empty(&self.asset_id, "insurance fund asset_id")?;
        ensure_non_empty(
            &self.reserve_commitment,
            "insurance fund reserve_commitment",
        )?;
        ensure_non_empty(
            &self.pending_payout_commitment,
            "insurance fund pending_payout_commitment",
        )?;
        ensure_non_empty(&self.sponsor_root, "insurance fund sponsor_root")?;
        ensure_non_empty(&self.payout_queue_root, "insurance fund payout_queue_root")?;
        ensure_bps(
            self.target_coverage_bps,
            "insurance fund target_coverage_bps",
        )?;
        if self.pending_payout_floor_units > self.reserve_floor_units {
            return Err("insurance fund pending payout exceeds reserve floor".to_string());
        }
        let expected_id = confidential_perps_insurance_fund_id(&self.market_id, &self.asset_id);
        if self.fund_id != expected_id {
            return Err("insurance fund id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpCircuitBreaker {
    pub circuit_id: String,
    pub scope: CircuitBreakerScope,
    pub subject_id: String,
    pub trigger_root: String,
    pub threshold_bps: u64,
    pub observed_bps: u64,
    pub opened_at_height: u64,
    pub closes_at_height: Option<u64>,
    pub cooldown_until_height: Option<u64>,
    pub severity: RiskSeverity,
    pub status: CircuitBreakerStatus,
    pub guardian_attestation_root: String,
}

impl PerpCircuitBreaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: CircuitBreakerScope,
        subject_id: &str,
        trigger_payload: &Value,
        threshold_bps: u64,
        observed_bps: u64,
        opened_at_height: u64,
        closes_at_height: Option<u64>,
        severity: RiskSeverity,
        status: CircuitBreakerStatus,
        guardian_attestation_root: impl Into<String>,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(subject_id, "circuit breaker subject_id")?;
        let trigger_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-CIRCUIT-TRIGGER", trigger_payload);
        let scope_label = scope.as_str();
        let circuit_id = confidential_perps_circuit_breaker_id(
            &scope_label,
            subject_id,
            &trigger_root,
            opened_at_height,
        );
        let circuit = Self {
            circuit_id,
            scope,
            subject_id: subject_id.to_string(),
            trigger_root,
            threshold_bps,
            observed_bps,
            opened_at_height,
            closes_at_height,
            cooldown_until_height: closes_at_height.map(|height| height.saturating_add(8)),
            severity,
            status,
            guardian_attestation_root: guardian_attestation_root.into(),
        };
        circuit.validate()?;
        Ok(circuit)
    }

    pub fn is_active(&self, height: u64) -> bool {
        matches!(&self.status, CircuitBreakerStatus::Open)
            && height >= self.opened_at_height
            && self
                .closes_at_height
                .map(|close| height <= close)
                .unwrap_or(true)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_circuit_breaker",
            "chain_id": CHAIN_ID,
            "circuit_id": self.circuit_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "trigger_root": self.trigger_root,
            "threshold_bps": self.threshold_bps,
            "observed_bps": self.observed_bps,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "cooldown_until_height": self.cooldown_until_height,
            "severity": self.severity.as_str(),
            "severity_score_bps": self.severity.score_bps(),
            "status": self.status.as_str(),
            "guardian_attestation_root": self.guardian_attestation_root,
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.circuit_id, "circuit breaker circuit_id")?;
        ensure_non_empty(&self.subject_id, "circuit breaker subject_id")?;
        ensure_non_empty(&self.trigger_root, "circuit breaker trigger_root")?;
        ensure_non_empty(
            &self.guardian_attestation_root,
            "circuit breaker guardian_attestation_root",
        )?;
        ensure_bps(self.threshold_bps, "circuit breaker threshold_bps")?;
        ensure_bps(self.observed_bps, "circuit breaker observed_bps")?;
        if let Some(close) = self.closes_at_height {
            if close <= self.opened_at_height {
                return Err("circuit breaker close height must follow open height".to_string());
            }
        }
        if let (Some(close), Some(cooldown)) = (self.closes_at_height, self.cooldown_until_height) {
            if cooldown < close {
                return Err("circuit breaker cooldown cannot precede close height".to_string());
            }
        }
        let scope_label = self.scope.as_str();
        let expected_id = confidential_perps_circuit_breaker_id(
            &scope_label,
            &self.subject_id,
            &self.trigger_root,
            self.opened_at_height,
        );
        if self.circuit_id != expected_id {
            return Err("circuit breaker id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeOrderSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub market_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub max_notional_units: u64,
    pub sponsored_fee_units: u64,
    pub used_fee_units: u64,
    pub order_count_limit: u64,
    pub used_order_count: u64,
    pub commitment_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub nonce: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeOrderSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        beneficiary_label: &str,
        market_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        max_notional_units: u64,
        sponsored_fee_units: u64,
        order_count_limit: u64,
        policy_payload: &Value,
        valid_from_height: u64,
        valid_until_height: u64,
        nonce: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(sponsor_label, "sponsorship sponsor_label")?;
        ensure_non_empty(beneficiary_label, "sponsorship beneficiary_label")?;
        ensure_non_empty(market_id, "sponsorship market_id")?;
        ensure_non_empty(lane_id, "sponsorship lane_id")?;
        ensure_non_empty(fee_asset_id, "sponsorship fee_asset_id")?;
        let sponsor_commitment = confidential_perps_account_commitment(sponsor_label);
        let beneficiary_commitment = confidential_perps_account_commitment(beneficiary_label);
        let commitment_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-LOW-FEE-POLICY", policy_payload);
        let sponsorship_id = confidential_perps_low_fee_sponsorship_id(
            &sponsor_commitment,
            &beneficiary_commitment,
            market_id,
            lane_id,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            beneficiary_commitment,
            market_id: market_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_notional_units,
            sponsored_fee_units,
            used_fee_units: 0,
            order_count_limit,
            used_order_count: 0,
            commitment_root,
            valid_from_height,
            valid_until_height,
            nonce,
            status: SponsorshipStatus::Reserved,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.sponsored_fee_units.saturating_sub(self.used_fee_units)
    }

    pub fn is_active(&self, height: u64) -> bool {
        matches!(
            &self.status,
            SponsorshipStatus::Reserved | SponsorshipStatus::Applied
        ) && height >= self.valid_from_height
            && height <= self.valid_until_height
            && self.remaining_fee_units() > 0
            && self.used_order_count < self.order_count_limit
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_low_fee_order_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "market_id": self.market_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "max_notional_units": self.max_notional_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "used_fee_units": self.used_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "order_count_limit": self.order_count_limit,
            "used_order_count": self.used_order_count,
            "commitment_root": self.commitment_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship sponsorship_id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor_commitment")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship beneficiary_commitment",
        )?;
        ensure_non_empty(&self.market_id, "sponsorship market_id")?;
        ensure_non_empty(&self.lane_id, "sponsorship lane_id")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee_asset_id")?;
        ensure_non_empty(&self.commitment_root, "sponsorship commitment_root")?;
        if self.max_notional_units == 0 || self.sponsored_fee_units == 0 {
            return Err("sponsorship notional and fee units must be positive".to_string());
        }
        if self.used_fee_units > self.sponsored_fee_units {
            return Err("sponsorship used fees exceed sponsored fees".to_string());
        }
        if self.order_count_limit == 0 || self.used_order_count > self.order_count_limit {
            return Err("sponsorship order counts are invalid".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("sponsorship valid_until must be after valid_from".to_string());
        }
        let expected_id = confidential_perps_low_fee_sponsorship_id(
            &self.sponsor_commitment,
            &self.beneficiary_commitment,
            &self.market_id,
            &self.lane_id,
            self.nonce,
        );
        if self.sponsorship_id != expected_id {
            return Err("sponsorship id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAdapterRoot {
    pub adapter_id: String,
    pub market_id: String,
    pub adapter_kind: String,
    pub contract_id: String,
    pub method_selector_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub event_root: String,
    pub token_registry_root: String,
    pub bridge_exit_root: String,
    pub privacy_adapter_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub status: SettlementAdapterStatus,
}

impl SettlementAdapterRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        adapter_kind: &str,
        contract_id: &str,
        method_selectors: &[Value],
        pre_state_root: &str,
        post_state_root: &str,
        events: &[Value],
        token_registry_root: &str,
        bridge_exit_root: &str,
        privacy_adapter_root: &str,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "settlement adapter market_id")?;
        ensure_non_empty(adapter_kind, "settlement adapter adapter_kind")?;
        ensure_non_empty(contract_id, "settlement adapter contract_id")?;
        ensure_non_empty(pre_state_root, "settlement adapter pre_state_root")?;
        ensure_non_empty(post_state_root, "settlement adapter post_state_root")?;
        ensure_non_empty(
            token_registry_root,
            "settlement adapter token_registry_root",
        )?;
        ensure_non_empty(bridge_exit_root, "settlement adapter bridge_exit_root")?;
        ensure_non_empty(
            privacy_adapter_root,
            "settlement adapter privacy_adapter_root",
        )?;
        let method_selector_root =
            merkle_root("CONFIDENTIAL-PERPS-SETTLEMENT-METHOD", method_selectors);
        let event_root = merkle_root("CONFIDENTIAL-PERPS-SETTLEMENT-EVENT", events);
        let adapter_id = confidential_perps_settlement_adapter_id(
            market_id,
            adapter_kind,
            contract_id,
            valid_from_height,
        );
        let adapter = Self {
            adapter_id,
            market_id: market_id.to_string(),
            adapter_kind: adapter_kind.to_string(),
            contract_id: contract_id.to_string(),
            method_selector_root,
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            event_root,
            token_registry_root: token_registry_root.to_string(),
            bridge_exit_root: bridge_exit_root.to_string(),
            privacy_adapter_root: privacy_adapter_root.to_string(),
            valid_from_height,
            valid_until_height,
            status: SettlementAdapterStatus::Active,
        };
        adapter.validate()?;
        Ok(adapter)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_settlement_adapter_root",
            "chain_id": CHAIN_ID,
            "adapter_scheme": CONFIDENTIAL_PERPS_SETTLEMENT_ADAPTER_SCHEME,
            "adapter_id": self.adapter_id,
            "market_id": self.market_id,
            "adapter_kind": self.adapter_kind,
            "contract_id": self.contract_id,
            "method_selector_root": self.method_selector_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "event_root": self.event_root,
            "token_registry_root": self.token_registry_root,
            "bridge_exit_root": self.bridge_exit_root,
            "privacy_adapter_root": self.privacy_adapter_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.adapter_id, "settlement adapter adapter_id")?;
        ensure_non_empty(&self.market_id, "settlement adapter market_id")?;
        ensure_non_empty(&self.adapter_kind, "settlement adapter adapter_kind")?;
        ensure_non_empty(&self.contract_id, "settlement adapter contract_id")?;
        ensure_non_empty(
            &self.method_selector_root,
            "settlement adapter method_selector_root",
        )?;
        ensure_non_empty(&self.pre_state_root, "settlement adapter pre_state_root")?;
        ensure_non_empty(&self.post_state_root, "settlement adapter post_state_root")?;
        ensure_non_empty(&self.event_root, "settlement adapter event_root")?;
        ensure_non_empty(
            &self.token_registry_root,
            "settlement adapter token_registry_root",
        )?;
        ensure_non_empty(
            &self.bridge_exit_root,
            "settlement adapter bridge_exit_root",
        )?;
        ensure_non_empty(
            &self.privacy_adapter_root,
            "settlement adapter privacy_adapter_root",
        )?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("settlement adapter valid_until must be after valid_from".to_string());
        }
        let expected_id = confidential_perps_settlement_adapter_id(
            &self.market_id,
            &self.adapter_kind,
            &self.contract_id,
            self.valid_from_height,
        );
        if self.adapter_id != expected_id {
            return Err("settlement adapter id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskCommitteeAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub member_commitment: String,
    pub market_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub decision: AttestationDecision,
    pub risk_score_bps: u64,
    pub payload_root: String,
    pub pq_signature_root: String,
    pub signature_scheme: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqRiskCommitteeAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee_id: &str,
        member_label: &str,
        market_id: &str,
        subject_kind: &str,
        subject_id: &str,
        decision: AttestationDecision,
        risk_score_bps: u64,
        payload: &Value,
        signature_payload: &Value,
        attested_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(committee_id, "attestation committee_id")?;
        ensure_non_empty(member_label, "attestation member_label")?;
        ensure_non_empty(market_id, "attestation market_id")?;
        ensure_non_empty(subject_kind, "attestation subject_kind")?;
        ensure_non_empty(subject_id, "attestation subject_id")?;
        let member_commitment = confidential_perps_account_commitment(member_label);
        let payload_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-PQ-ATTESTATION-PAYLOAD", payload);
        let pq_signature_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-PQ-SIGNATURE", signature_payload);
        let attestation_id = confidential_perps_pq_attestation_id(
            committee_id,
            &member_commitment,
            subject_kind,
            subject_id,
            attested_at_height,
        );
        let attestation = Self {
            attestation_id,
            committee_id: committee_id.to_string(),
            member_commitment,
            market_id: market_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            decision,
            risk_score_bps,
            payload_root,
            pq_signature_root,
            signature_scheme: CONFIDENTIAL_PERPS_PQ_SIGNATURE_SCHEME.to_string(),
            attested_at_height,
            expires_at_height,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_pq_risk_committee_attestation",
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "member_commitment": self.member_commitment,
            "market_id": self.market_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "decision": self.decision.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "payload_root": self.payload_root,
            "pq_signature_root": self.pq_signature_root,
            "signature_scheme": self.signature_scheme,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.attestation_id, "attestation attestation_id")?;
        ensure_non_empty(&self.committee_id, "attestation committee_id")?;
        ensure_non_empty(&self.member_commitment, "attestation member_commitment")?;
        ensure_non_empty(&self.market_id, "attestation market_id")?;
        ensure_non_empty(&self.subject_kind, "attestation subject_kind")?;
        ensure_non_empty(&self.subject_id, "attestation subject_id")?;
        ensure_non_empty(&self.payload_root, "attestation payload_root")?;
        ensure_non_empty(&self.pq_signature_root, "attestation pq_signature_root")?;
        ensure_non_empty(&self.signature_scheme, "attestation signature_scheme")?;
        ensure_bps(self.risk_score_bps, "attestation risk_score_bps")?;
        if self.expires_at_height <= self.attested_at_height {
            return Err("attestation expiry must be after attested height".to_string());
        }
        let expected_id = confidential_perps_pq_attestation_id(
            &self.committee_id,
            &self.member_commitment,
            &self.subject_kind,
            &self.subject_id,
            self.attested_at_height,
        );
        if self.attestation_id != expected_id {
            return Err("attestation id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyMarketPause {
    pub pause_id: String,
    pub market_id: String,
    pub reason_root: String,
    pub initiated_by_commitment: String,
    pub committee_attestation_root: String,
    pub trigger_circuit_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub status: EmergencyPauseStatus,
}

impl EmergencyMarketPause {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        reason_payload: &Value,
        initiated_by_label: &str,
        committee_attestation_root: &str,
        trigger_circuit_id: &str,
        start_height: u64,
        end_height: u64,
        status: EmergencyPauseStatus,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(market_id, "emergency pause market_id")?;
        ensure_non_empty(initiated_by_label, "emergency pause initiated_by_label")?;
        ensure_non_empty(
            committee_attestation_root,
            "emergency pause committee_attestation_root",
        )?;
        ensure_non_empty(trigger_circuit_id, "emergency pause trigger_circuit_id")?;
        let reason_root = confidential_perps_payload_root(
            "CONFIDENTIAL-PERPS-EMERGENCY-PAUSE-REASON",
            reason_payload,
        );
        let initiated_by_commitment = confidential_perps_account_commitment(initiated_by_label);
        let pause_id = confidential_perps_emergency_pause_id(market_id, &reason_root, start_height);
        let pause = Self {
            pause_id,
            market_id: market_id.to_string(),
            reason_root,
            initiated_by_commitment,
            committee_attestation_root: committee_attestation_root.to_string(),
            trigger_circuit_id: trigger_circuit_id.to_string(),
            start_height,
            end_height,
            status,
        };
        pause.validate()?;
        Ok(pause)
    }

    pub fn is_active(&self, height: u64) -> bool {
        matches!(&self.status, EmergencyPauseStatus::Active)
            && height >= self.start_height
            && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_emergency_market_pause",
            "chain_id": CHAIN_ID,
            "pause_id": self.pause_id,
            "market_id": self.market_id,
            "reason_root": self.reason_root,
            "initiated_by_commitment": self.initiated_by_commitment,
            "committee_attestation_root": self.committee_attestation_root,
            "trigger_circuit_id": self.trigger_circuit_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.pause_id, "emergency pause pause_id")?;
        ensure_non_empty(&self.market_id, "emergency pause market_id")?;
        ensure_non_empty(&self.reason_root, "emergency pause reason_root")?;
        ensure_non_empty(
            &self.initiated_by_commitment,
            "emergency pause initiated_by_commitment",
        )?;
        ensure_non_empty(
            &self.committee_attestation_root,
            "emergency pause committee_attestation_root",
        )?;
        ensure_non_empty(
            &self.trigger_circuit_id,
            "emergency pause trigger_circuit_id",
        )?;
        if self.end_height <= self.start_height {
            return Err("emergency pause end height must be after start height".to_string());
        }
        let expected_id = confidential_perps_emergency_pause_id(
            &self.market_id,
            &self.reason_root,
            self.start_height,
        );
        if self.pause_id != expected_id {
            return Err("emergency pause id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPerpsPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl ConfidentialPerpsPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> ConfidentialPerpsResult<Self> {
        ensure_non_empty(record_kind, "public record kind")?;
        ensure_non_empty(subject_id, "public record subject_id")?;
        let payload_root =
            confidential_perps_payload_root("CONFIDENTIAL-PERPS-PUBLIC-RECORD-PAYLOAD", payload);
        let record_id = confidential_perps_public_record_id(
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

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_public_record",
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<()> {
        ensure_non_empty(&self.record_id, "public record record_id")?;
        ensure_non_empty(&self.record_kind, "public record record_kind")?;
        ensure_non_empty(&self.subject_id, "public record subject_id")?;
        ensure_non_empty(&self.payload_root, "public record payload_root")?;
        let expected_id = confidential_perps_public_record_id(
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPerpsStateRoots {
    pub config_root: String,
    pub market_root: String,
    pub risk_cap_root: String,
    pub margin_vault_root: String,
    pub position_root: String,
    pub funding_rate_root: String,
    pub oracle_root: String,
    pub liquidation_queue_root: String,
    pub liquidation_challenge_root: String,
    pub insurance_fund_root: String,
    pub circuit_breaker_root: String,
    pub low_fee_sponsorship_root: String,
    pub settlement_adapter_root: String,
    pub pq_attestation_root: String,
    pub emergency_pause_root: String,
    pub public_record_root: String,
}

impl ConfidentialPerpsStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_perps_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_PERPS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "market_root": self.market_root,
            "risk_cap_root": self.risk_cap_root,
            "margin_vault_root": self.margin_vault_root,
            "position_root": self.position_root,
            "funding_rate_root": self.funding_rate_root,
            "oracle_root": self.oracle_root,
            "liquidation_queue_root": self.liquidation_queue_root,
            "liquidation_challenge_root": self.liquidation_challenge_root,
            "insurance_fund_root": self.insurance_fund_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "settlement_adapter_root": self.settlement_adapter_root,
            "pq_attestation_root": self.pq_attestation_root,
            "emergency_pause_root": self.emergency_pause_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_perps_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialPerpsState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialPerpsConfig,
    pub markets: BTreeMap<String, ConfidentialPerpMarket>,
    pub risk_caps: BTreeMap<String, PerpRiskCap>,
    pub margin_vaults: BTreeMap<String, MarginVaultCommitment>,
    pub positions: BTreeMap<String, SealedPositionCommitment>,
    pub funding_rate_commitments: BTreeMap<String, FundingRateCommitment>,
    pub oracle_roots: BTreeMap<String, OracleRootCommitment>,
    pub liquidation_queue: BTreeMap<String, PrivateLiquidationQueueEntry>,
    pub liquidation_challenges: BTreeMap<String, LiquidationChallenge>,
    pub insurance_funds: BTreeMap<String, InsuranceFund>,
    pub circuit_breakers: BTreeMap<String, PerpCircuitBreaker>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeOrderSponsorship>,
    pub settlement_adapters: BTreeMap<String, SettlementAdapterRoot>,
    pub pq_attestations: BTreeMap<String, PqRiskCommitteeAttestation>,
    pub emergency_pauses: BTreeMap<String, EmergencyMarketPause>,
    pub public_records: BTreeMap<String, ConfidentialPerpsPublicRecord>,
}

impl Default for ConfidentialPerpsState {
    fn default() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: ConfidentialPerpsConfig::default(),
            markets: BTreeMap::new(),
            risk_caps: BTreeMap::new(),
            margin_vaults: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_rate_commitments: BTreeMap::new(),
            oracle_roots: BTreeMap::new(),
            liquidation_queue: BTreeMap::new(),
            liquidation_challenges: BTreeMap::new(),
            insurance_funds: BTreeMap::new(),
            circuit_breakers: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            settlement_adapters: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            emergency_pauses: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl ConfidentialPerpsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: ConfidentialPerpsConfig) -> ConfidentialPerpsResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> ConfidentialPerpsResult<Self> {
        let mut state = Self::with_config(ConfidentialPerpsConfig::default())?;
        state.set_height(CONFIDENTIAL_PERPS_DEVNET_HEIGHT);

        let market_metadata = json!({
            "environment": "devnet",
            "pair": "wXMR/USDD",
            "privacy": "sealed positions, aggregate public caps",
            "settlement": "contract_vm_adapter",
            "oracle_policy": "threshold median root",
        });
        let mut market = ConfidentialPerpMarket::wxmr_stable_pair(
            CONFIDENTIAL_PERPS_DEVNET_STABLE_ASSET_ID,
            "oracle-wxmr-usdd-devnet",
            state.height.saturating_sub(40),
            &market_metadata,
        )?;
        let market_id = market.market_id.clone();

        let risk_attestation_root = confidential_perps_string_root(
            "CONFIDENTIAL-PERPS-DEVNET-RISK-ATTESTATION",
            "risk-committee-genesis-root",
        );
        let risk_cap = PerpRiskCap::new(
            &market_id,
            1,
            2_000_000_000_000,
            3_000,
            250_000_000_000,
            CONFIDENTIAL_PERPS_DEFAULT_MAX_LEVERAGE_BPS,
            CONFIDENTIAL_PERPS_DEFAULT_MAINTENANCE_MARGIN_BPS,
            CONFIDENTIAL_PERPS_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            75_000_000_000,
            state.height.saturating_sub(32),
            state.height.saturating_add(7_200),
            risk_attestation_root.clone(),
        )?;

        let settlement_adapter = SettlementAdapterRoot::new(
            &market_id,
            "contract_vm_perp_settlement",
            "contract-confidential-perps-devnet",
            &[
                json!({"method": "settle_private_fill", "selector": "0xperp01"}),
                json!({"method": "apply_funding_root", "selector": "0xperp02"}),
                json!({"method": "execute_private_liquidation", "selector": "0xperp03"}),
            ],
            &confidential_perps_string_root("CONFIDENTIAL-PERPS-DEVNET-PRE-STATE", "pre"),
            &confidential_perps_string_root("CONFIDENTIAL-PERPS-DEVNET-POST-STATE", "post"),
            &[json!({"event": "ConfidentialPerpSettlementRoot", "version": 1})],
            &confidential_perps_string_root("CONFIDENTIAL-PERPS-DEVNET-TOKEN-REGISTRY", "tokens"),
            &confidential_perps_string_root("CONFIDENTIAL-PERPS-DEVNET-BRIDGE-EXIT", "bridge"),
            &confidential_perps_string_root("CONFIDENTIAL-PERPS-DEVNET-PRIVACY-ADAPTER", "privacy"),
            state.height.saturating_sub(32),
            state.height.saturating_add(7_200),
        )?;
        market.risk_cap_root = confidential_perps_risk_cap_root(&[risk_cap.clone()]);
        market.settlement_adapter_root =
            confidential_perps_settlement_adapter_root(&[settlement_adapter.clone()]);
        market.long_open_interest_units = 12_000_000_000;
        market.short_open_interest_units = 6_000_000_000;
        state.insert_market(market)?;
        state.insert_risk_cap(risk_cap)?;
        state.insert_settlement_adapter(settlement_adapter)?;

        let oracle = OracleRootCommitment::new(
            &market_id,
            "oracle-wxmr-usdd-devnet",
            178_500_000_000,
            35,
            &[
                json!({"source": "devnet-median-1", "height": state.height - 2}),
                json!({"source": "devnet-median-2", "height": state.height - 2}),
                json!({"source": "devnet-median-3", "height": state.height - 1}),
            ],
            "devnet-oracle-committee",
            state.height.saturating_sub(1),
            state.height.saturating_sub(4),
            state.height.saturating_add(8),
            &json!({"threshold": "3-of-5", "pq_signature_scheme": CONFIDENTIAL_PERPS_PQ_SIGNATURE_SCHEME}),
        )?;
        let oracle_root = oracle.oracle_root_id.clone();
        state.insert_oracle_root(oracle)?;

        let funding = FundingRateCommitment::new(
            &market_id,
            4,
            state.height.saturating_sub(24),
            state.height,
            &oracle_root,
            12,
            1,
            13,
            state.height,
            &json!({"method": "private_premium_twap", "sample_count": 24}),
        )?;
        let funding_id = funding.funding_id.clone();
        state.insert_funding_rate_commitment(funding)?;

        let vault = MarginVaultCommitment::new(
            "devnet-alice-perps",
            CONFIDENTIAL_PERPS_DEVNET_STABLE_ASSET_ID,
            5_000_000_000,
            850_000_000,
            25_000_000,
            state.height.saturating_sub(12),
            state.next_nonce(),
            &json!({"range_proof": CONFIDENTIAL_PERPS_RANGE_PROOF_SCHEME, "asset": "USDD"}),
        )?;
        let vault_id = vault.vault_id.clone();
        state.insert_margin_vault(vault)?;

        let default_low_fee_lane = state.config.default_low_fee_lane.clone();
        let default_position_ttl_blocks = state.config.default_position_ttl_blocks;
        let fee_asset_id = state.config.fee_asset_id.clone();
        let small_trade_notional_units = state.config.small_trade_notional_units;
        let small_trade_max_fee_units = state.config.small_trade_max_fee_units;
        let default_challenge_window_blocks = state.config.default_challenge_window_blocks;

        let position = SealedPositionCommitment::new(
            &market_id,
            "devnet-alice-perps",
            PositionSide::Long,
            12_000_000_000,
            178_000_000_000,
            &vault_id,
            30_000,
            151_000_000_000,
            &funding_id,
            "devnet-alice-privacy-budget",
            &json!({"order_type": "sealed_limit", "sponsored": true, "fee_lane": default_low_fee_lane}),
            &json!({"solvency": "range_and_margin_proof", "pq_soundness": "devnet-128-bit"}),
            state.height.saturating_sub(8),
            state.height.saturating_add(default_position_ttl_blocks),
            state.next_nonce(),
        )?;
        let position_id = position.position_id.clone();
        state.insert_position(position)?;

        let sponsorship = LowFeeOrderSponsorship::new(
            "devnet-foundation-paymaster",
            "devnet-alice-perps",
            &market_id,
            &default_low_fee_lane,
            &fee_asset_id,
            small_trade_notional_units,
            50_000,
            64,
            &json!({"target": "small_private_perps", "max_fee_units": small_trade_max_fee_units}),
            state.height.saturating_sub(6),
            state.height.saturating_add(180),
            state.next_nonce(),
        )?;
        state.insert_low_fee_sponsorship(sponsorship)?;

        let liquidation = PrivateLiquidationQueueEntry::new(
            &market_id,
            &position_id,
            "devnet-keeper-1",
            150_500_000_000,
            720_000_000,
            3_650_000_000,
            4_420_000_000,
            95,
            &json!({"reason": "maintenance_margin_watch", "oracle_root": oracle_root}),
            state.height.saturating_sub(3),
            default_challenge_window_blocks,
            state.next_nonce(),
        )?;
        let liquidation_id = liquidation.liquidation_id.clone();
        state.insert_liquidation_queue_entry(liquidation)?;

        let challenge = LiquidationChallenge::new(
            &liquidation_id,
            "devnet-alice-watchtower",
            25_000,
            &json!({"counter_price_root": "devnet-counter-oracle-root", "claim": "oracle_staleness"}),
            state.height.saturating_sub(2),
            state.height.saturating_add(16),
        )?;
        state.insert_liquidation_challenge(challenge)?;

        let insurance = InsuranceFund::new(
            &market_id,
            CONFIDENTIAL_PERPS_DEVNET_STABLE_ASSET_ID,
            300_000_000_000,
            1_500_000_000,
            1_500,
            state.height.saturating_sub(10),
            &[json!({"sponsor": "devnet-foundation", "floor_units": 200_000_000_000_u64})],
        )?;
        state.insert_insurance_fund(insurance)?;

        let circuit = PerpCircuitBreaker::new(
            CircuitBreakerScope::Oracle,
            &market_id,
            &json!({"metric": "oracle_deviation_bps", "observed": 420, "threshold": 750}),
            750,
            420,
            state.height.saturating_sub(1),
            Some(state.height.saturating_add(24)),
            RiskSeverity::Watch,
            CircuitBreakerStatus::Watching,
            risk_attestation_root.clone(),
        )?;
        let circuit_id = circuit.circuit_id.clone();
        state.insert_circuit_breaker(circuit)?;

        let attestation = PqRiskCommitteeAttestation::new(
            "devnet-risk-committee",
            "committee-member-ml-dsa-1",
            &market_id,
            "risk_cap",
            &state
                .risk_caps
                .values()
                .next()
                .expect("devnet risk cap")
                .cap_id,
            AttestationDecision::Approve,
            2_500,
            &json!({"policy": "launch_caps", "quantum_resistant": true}),
            &json!({"signature": "devnet-pq-signature-root"}),
            state.height.saturating_sub(2),
            state.height.saturating_add(720),
        )?;
        let attestation_root = confidential_perps_pq_attestation_root(&[attestation.clone()]);
        state.insert_pq_attestation(attestation)?;

        let pause = EmergencyMarketPause::new(
            &market_id,
            &json!({"reason": "oracle_committee_can_pause_if_threshold_breached"}),
            "committee-member-ml-dsa-1",
            &attestation_root,
            &circuit_id,
            state.height.saturating_add(1),
            state.height.saturating_add(25),
            EmergencyPauseStatus::Proposed,
        )?;
        state.insert_emergency_pause(pause)?;

        let state_record = ConfidentialPerpsPublicRecord::new(
            "devnet_state_root",
            &market_id,
            &json!({
                "state_root": state.state_root(),
                "market_id": market_id,
                "height": state.height,
            }),
            state.height,
            state.next_nonce(),
        )?;
        state.insert_public_record(state_record)?;

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
        market: ConfidentialPerpMarket,
    ) -> ConfidentialPerpsResult<ConfidentialPerpMarket> {
        market.validate()?;
        self.markets
            .insert(market.market_id.clone(), market.clone());
        Ok(market)
    }

    pub fn insert_risk_cap(&mut self, cap: PerpRiskCap) -> ConfidentialPerpsResult<PerpRiskCap> {
        cap.validate()?;
        self.risk_caps.insert(cap.cap_id.clone(), cap.clone());
        Ok(cap)
    }

    pub fn insert_margin_vault(
        &mut self,
        vault: MarginVaultCommitment,
    ) -> ConfidentialPerpsResult<MarginVaultCommitment> {
        vault.validate()?;
        self.margin_vaults
            .insert(vault.vault_id.clone(), vault.clone());
        Ok(vault)
    }

    pub fn insert_position(
        &mut self,
        position: SealedPositionCommitment,
    ) -> ConfidentialPerpsResult<SealedPositionCommitment> {
        position.validate()?;
        self.positions
            .insert(position.position_id.clone(), position.clone());
        Ok(position)
    }

    pub fn insert_funding_rate_commitment(
        &mut self,
        funding: FundingRateCommitment,
    ) -> ConfidentialPerpsResult<FundingRateCommitment> {
        funding.validate()?;
        self.funding_rate_commitments
            .insert(funding.funding_id.clone(), funding.clone());
        Ok(funding)
    }

    pub fn insert_oracle_root(
        &mut self,
        oracle: OracleRootCommitment,
    ) -> ConfidentialPerpsResult<OracleRootCommitment> {
        oracle.validate()?;
        self.oracle_roots
            .insert(oracle.oracle_root_id.clone(), oracle.clone());
        Ok(oracle)
    }

    pub fn insert_liquidation_queue_entry(
        &mut self,
        liquidation: PrivateLiquidationQueueEntry,
    ) -> ConfidentialPerpsResult<PrivateLiquidationQueueEntry> {
        liquidation.validate()?;
        self.liquidation_queue
            .insert(liquidation.liquidation_id.clone(), liquidation.clone());
        Ok(liquidation)
    }

    pub fn insert_liquidation_challenge(
        &mut self,
        challenge: LiquidationChallenge,
    ) -> ConfidentialPerpsResult<LiquidationChallenge> {
        challenge.validate()?;
        self.liquidation_challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    pub fn insert_insurance_fund(
        &mut self,
        fund: InsuranceFund,
    ) -> ConfidentialPerpsResult<InsuranceFund> {
        fund.validate()?;
        self.insurance_funds
            .insert(fund.fund_id.clone(), fund.clone());
        Ok(fund)
    }

    pub fn insert_circuit_breaker(
        &mut self,
        circuit: PerpCircuitBreaker,
    ) -> ConfidentialPerpsResult<PerpCircuitBreaker> {
        circuit.validate()?;
        self.circuit_breakers
            .insert(circuit.circuit_id.clone(), circuit.clone());
        Ok(circuit)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeOrderSponsorship,
    ) -> ConfidentialPerpsResult<LowFeeOrderSponsorship> {
        sponsorship.validate()?;
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_settlement_adapter(
        &mut self,
        adapter: SettlementAdapterRoot,
    ) -> ConfidentialPerpsResult<SettlementAdapterRoot> {
        adapter.validate()?;
        self.settlement_adapters
            .insert(adapter.adapter_id.clone(), adapter.clone());
        Ok(adapter)
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqRiskCommitteeAttestation,
    ) -> ConfidentialPerpsResult<PqRiskCommitteeAttestation> {
        attestation.validate()?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn insert_emergency_pause(
        &mut self,
        pause: EmergencyMarketPause,
    ) -> ConfidentialPerpsResult<EmergencyMarketPause> {
        pause.validate()?;
        self.emergency_pauses
            .insert(pause.pause_id.clone(), pause.clone());
        Ok(pause)
    }

    pub fn insert_public_record(
        &mut self,
        record: ConfidentialPerpsPublicRecord,
    ) -> ConfidentialPerpsResult<ConfidentialPerpsPublicRecord> {
        record.validate()?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn market_root(&self) -> String {
        confidential_perps_market_root(&self.markets.values().cloned().collect::<Vec<_>>())
    }

    pub fn risk_cap_root(&self) -> String {
        confidential_perps_risk_cap_root(&self.risk_caps.values().cloned().collect::<Vec<_>>())
    }

    pub fn margin_vault_root(&self) -> String {
        confidential_perps_margin_vault_root(
            &self.margin_vaults.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn position_root(&self) -> String {
        confidential_perps_position_root(&self.positions.values().cloned().collect::<Vec<_>>())
    }

    pub fn funding_rate_root(&self) -> String {
        confidential_perps_funding_rate_root(
            &self
                .funding_rate_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn oracle_root(&self) -> String {
        confidential_perps_oracle_commitment_root(
            &self.oracle_roots.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_queue_root(&self) -> String {
        confidential_perps_liquidation_queue_root(
            &self.liquidation_queue.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_challenge_root(&self) -> String {
        confidential_perps_liquidation_challenge_root(
            &self
                .liquidation_challenges
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn insurance_fund_root(&self) -> String {
        confidential_perps_insurance_fund_root(
            &self.insurance_funds.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn circuit_breaker_root(&self) -> String {
        confidential_perps_circuit_breaker_root(
            &self.circuit_breakers.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        confidential_perps_low_fee_sponsorship_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn settlement_adapter_root(&self) -> String {
        confidential_perps_settlement_adapter_root(
            &self
                .settlement_adapters
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        confidential_perps_pq_attestation_root(
            &self.pq_attestations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn emergency_pause_root(&self) -> String {
        confidential_perps_emergency_pause_root(
            &self.emergency_pauses.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        confidential_perps_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn state_roots(&self) -> ConfidentialPerpsStateRoots {
        ConfidentialPerpsStateRoots {
            config_root: self.config_root(),
            market_root: self.market_root(),
            risk_cap_root: self.risk_cap_root(),
            margin_vault_root: self.margin_vault_root(),
            position_root: self.position_root(),
            funding_rate_root: self.funding_rate_root(),
            oracle_root: self.oracle_root(),
            liquidation_queue_root: self.liquidation_queue_root(),
            liquidation_challenge_root: self.liquidation_challenge_root(),
            insurance_fund_root: self.insurance_fund_root(),
            circuit_breaker_root: self.circuit_breaker_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            settlement_adapter_root: self.settlement_adapter_root(),
            pq_attestation_root: self.pq_attestation_root(),
            emergency_pause_root: self.emergency_pause_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn market_ids(&self) -> Vec<String> {
        self.markets.keys().cloned().collect()
    }

    pub fn active_pause_market_ids(&self) -> Vec<String> {
        self.emergency_pauses
            .values()
            .filter(|pause| pause.is_active(self.height))
            .map(|pause| pause.market_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_circuit_subjects(&self) -> Vec<String> {
        self.circuit_breakers
            .values()
            .filter(|circuit| circuit.is_active(self.height))
            .map(|circuit| circuit.subject_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn total_insurance_floor_units(&self) -> u64 {
        self.insurance_funds.values().fold(0_u64, |total, fund| {
            total.saturating_add(fund.available_floor_units())
        })
    }

    pub fn active_low_fee_sponsorship_count(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.is_active(self.height))
            .count() as u64
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.circuit_breakers
            .values()
            .map(|circuit| circuit.severity.score_bps())
            .chain(
                self.pq_attestations
                    .values()
                    .map(|attestation| attestation.risk_score_bps),
            )
            .max()
            .unwrap_or(0)
    }

    pub fn state_root(&self) -> String {
        confidential_perps_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("confidential perps state public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ConfidentialPerpsResult<String> {
        self.config.validate()?;
        for (id, market) in &self.markets {
            if id != &market.market_id {
                return Err("state market map key does not match market id".to_string());
            }
            market.validate()?;
        }
        for (id, cap) in &self.risk_caps {
            if id != &cap.cap_id {
                return Err("state risk cap map key does not match cap id".to_string());
            }
            cap.validate()?;
            ensure_state_market(&self.markets, &cap.market_id, "risk cap")?;
        }
        for (id, vault) in &self.margin_vaults {
            if id != &vault.vault_id {
                return Err("state margin vault map key does not match vault id".to_string());
            }
            vault.validate()?;
        }
        for (id, position) in &self.positions {
            if id != &position.position_id {
                return Err("state position map key does not match position id".to_string());
            }
            position.validate()?;
            ensure_state_market(&self.markets, &position.market_id, "position")?;
            if !self.margin_vaults.contains_key(&position.margin_vault_id) {
                return Err("position references missing margin vault".to_string());
            }
        }
        for (id, funding) in &self.funding_rate_commitments {
            if id != &funding.funding_id {
                return Err("state funding map key does not match funding id".to_string());
            }
            funding.validate()?;
            ensure_state_market(&self.markets, &funding.market_id, "funding")?;
        }
        for (id, oracle) in &self.oracle_roots {
            if id != &oracle.oracle_root_id {
                return Err("state oracle map key does not match oracle root id".to_string());
            }
            oracle.validate()?;
            ensure_state_market(&self.markets, &oracle.market_id, "oracle root")?;
        }
        for (id, liquidation) in &self.liquidation_queue {
            if id != &liquidation.liquidation_id {
                return Err("state liquidation map key does not match liquidation id".to_string());
            }
            liquidation.validate()?;
            ensure_state_market(&self.markets, &liquidation.market_id, "liquidation")?;
            if !self.positions.contains_key(&liquidation.position_id) {
                return Err("liquidation references missing position".to_string());
            }
        }
        for (id, challenge) in &self.liquidation_challenges {
            if id != &challenge.challenge_id {
                return Err("state challenge map key does not match challenge id".to_string());
            }
            challenge.validate()?;
            if !self
                .liquidation_queue
                .contains_key(&challenge.liquidation_id)
            {
                return Err("challenge references missing liquidation".to_string());
            }
        }
        for (id, fund) in &self.insurance_funds {
            if id != &fund.fund_id {
                return Err("state insurance fund map key does not match fund id".to_string());
            }
            fund.validate()?;
            ensure_state_market(&self.markets, &fund.market_id, "insurance fund")?;
        }
        for (id, circuit) in &self.circuit_breakers {
            if id != &circuit.circuit_id {
                return Err("state circuit map key does not match circuit id".to_string());
            }
            circuit.validate()?;
            if matches!(
                &circuit.scope,
                CircuitBreakerScope::Market | CircuitBreakerScope::Oracle
            ) {
                ensure_state_market(&self.markets, &circuit.subject_id, "circuit breaker")?;
            }
        }
        for (id, sponsorship) in &self.low_fee_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("state sponsorship map key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
            ensure_state_market(&self.markets, &sponsorship.market_id, "sponsorship")?;
        }
        for (id, adapter) in &self.settlement_adapters {
            if id != &adapter.adapter_id {
                return Err("state adapter map key does not match adapter id".to_string());
            }
            adapter.validate()?;
            ensure_state_market(&self.markets, &adapter.market_id, "settlement adapter")?;
        }
        for (id, attestation) in &self.pq_attestations {
            if id != &attestation.attestation_id {
                return Err("state attestation map key does not match attestation id".to_string());
            }
            attestation.validate()?;
            ensure_state_market(&self.markets, &attestation.market_id, "attestation")?;
        }
        for (id, pause) in &self.emergency_pauses {
            if id != &pause.pause_id {
                return Err("state pause map key does not match pause id".to_string());
            }
            pause.validate()?;
            ensure_state_market(&self.markets, &pause.market_id, "emergency pause")?;
            if !self
                .circuit_breakers
                .contains_key(&pause.trigger_circuit_id)
            {
                return Err("emergency pause references missing circuit breaker".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record map key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.state_roots();
        json!({
            "kind": "confidential_perps_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_PERPS_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "market_count": self.markets.len() as u64,
            "risk_cap_count": self.risk_caps.len() as u64,
            "margin_vault_count": self.margin_vaults.len() as u64,
            "position_count": self.positions.len() as u64,
            "funding_rate_commitment_count": self.funding_rate_commitments.len() as u64,
            "oracle_root_count": self.oracle_roots.len() as u64,
            "liquidation_queue_count": self.liquidation_queue.len() as u64,
            "liquidation_challenge_count": self.liquidation_challenges.len() as u64,
            "insurance_fund_count": self.insurance_funds.len() as u64,
            "circuit_breaker_count": self.circuit_breakers.len() as u64,
            "low_fee_sponsorship_count": self.low_fee_sponsorships.len() as u64,
            "settlement_adapter_count": self.settlement_adapters.len() as u64,
            "pq_attestation_count": self.pq_attestations.len() as u64,
            "emergency_pause_count": self.emergency_pauses.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "market_ids": self.market_ids(),
            "active_pause_market_ids": self.active_pause_market_ids(),
            "active_circuit_subjects": self.active_circuit_subjects(),
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count(),
            "total_insurance_floor_units": self.total_insurance_floor_units(),
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps(),
            "risk_status": risk_status_from_score(self.aggregate_risk_score_bps()),
            "roots": roots.public_record(),
        })
    }
}

pub fn confidential_perps_state_root(state: &ConfidentialPerpsState) -> String {
    state.state_root()
}

pub fn confidential_perps_market_root(markets: &[ConfidentialPerpMarket]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-MARKET",
        &markets
            .iter()
            .map(|market| market.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_risk_cap_root(caps: &[PerpRiskCap]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-RISK-CAP",
        &caps
            .iter()
            .map(|cap| cap.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_margin_vault_root(vaults: &[MarginVaultCommitment]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-MARGIN-VAULT",
        &vaults
            .iter()
            .map(|vault| vault.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_position_root(positions: &[SealedPositionCommitment]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-POSITION",
        &positions
            .iter()
            .map(|position| position.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_funding_rate_root(funding: &[FundingRateCommitment]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-FUNDING-RATE",
        &funding
            .iter()
            .map(|funding| funding.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_oracle_commitment_root(oracles: &[OracleRootCommitment]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-ORACLE-ROOT",
        &oracles
            .iter()
            .map(|oracle| oracle.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_liquidation_queue_root(
    liquidations: &[PrivateLiquidationQueueEntry],
) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-LIQUIDATION-QUEUE",
        &liquidations
            .iter()
            .map(|liquidation| liquidation.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_liquidation_challenge_root(
    challenges: &[LiquidationChallenge],
) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-LIQUIDATION-CHALLENGE",
        &challenges
            .iter()
            .map(|challenge| challenge.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_insurance_fund_root(funds: &[InsuranceFund]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-INSURANCE-FUND",
        &funds
            .iter()
            .map(|fund| fund.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_circuit_breaker_root(circuits: &[PerpCircuitBreaker]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-CIRCUIT-BREAKER",
        &circuits
            .iter()
            .map(|circuit| circuit.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_low_fee_sponsorship_root(
    sponsorships: &[LowFeeOrderSponsorship],
) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-LOW-FEE-SPONSORSHIP",
        &sponsorships
            .iter()
            .map(|sponsorship| sponsorship.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_settlement_adapter_root(adapters: &[SettlementAdapterRoot]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-SETTLEMENT-ADAPTER",
        &adapters
            .iter()
            .map(|adapter| adapter.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_pq_attestation_root(
    attestations: &[PqRiskCommitteeAttestation],
) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-PQ-ATTESTATION",
        &attestations
            .iter()
            .map(|attestation| attestation.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_emergency_pause_root(pauses: &[EmergencyMarketPause]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-EMERGENCY-PAUSE",
        &pauses
            .iter()
            .map(|pause| pause.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_public_record_root(records: &[ConfidentialPerpsPublicRecord]) -> String {
    merkle_root(
        "CONFIDENTIAL-PERPS-PUBLIC-RECORD",
        &records
            .iter()
            .map(|record| record.public_record())
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_perps_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn confidential_perps_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn confidential_perps_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn confidential_perps_string_set_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn confidential_perps_market_id(
    base_asset_id: &str,
    quote_asset_id: &str,
    margin_asset_id: &str,
    oracle_feed_id: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Str(margin_asset_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_risk_cap_id(
    market_id: &str,
    cap_version: u64,
    active_from_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-RISK-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Int(cap_version as i128),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_margin_vault_id(
    owner_commitment: &str,
    margin_asset_id: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-MARGIN-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(margin_asset_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_perps_position_id(
    market_id: &str,
    owner_commitment: &str,
    margin_vault_id: &str,
    side_commitment: &str,
    size_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(margin_vault_id),
            HashPart::Str(side_commitment),
            HashPart::Str(size_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_perps_funding_id(
    market_id: &str,
    interval_index: u64,
    oracle_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-FUNDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Int(interval_index as i128),
            HashPart::Str(oracle_root),
            HashPart::Int(committed_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_oracle_root_id(
    market_id: &str,
    feed_id: &str,
    source_root: &str,
    median_update_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-ORACLE-ROOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(feed_id),
            HashPart::Str(source_root),
            HashPart::Int(median_update_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_liquidation_id(
    market_id: &str,
    position_id: &str,
    keeper_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-LIQUIDATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(keeper_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_perps_liquidation_challenge_id(
    liquidation_id: &str,
    challenger_commitment: &str,
    counter_evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-LIQUIDATION-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(liquidation_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(counter_evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_insurance_fund_id(market_id: &str, asset_id: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-INSURANCE-FUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(asset_id),
        ],
        32,
    )
}

pub fn confidential_perps_circuit_breaker_id(
    scope: &str,
    subject_id: &str,
    trigger_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-CIRCUIT-BREAKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope),
            HashPart::Str(subject_id),
            HashPart::Str(trigger_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_low_fee_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    market_id: &str,
    lane_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(market_id),
            HashPart::Str(lane_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_perps_settlement_adapter_id(
    market_id: &str,
    adapter_kind: &str,
    contract_id: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-SETTLEMENT-ADAPTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(adapter_kind),
            HashPart::Str(contract_id),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_pq_attestation_id(
    committee_id: &str,
    member_commitment: &str,
    subject_kind: &str,
    subject_id: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(member_commitment),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_emergency_pause_id(
    market_id: &str,
    reason_root: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-EMERGENCY-PAUSE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(reason_root),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn confidential_perps_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-PUBLIC-RECORD-ID",
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

pub fn confidential_perps_account_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_perps_asset_commitment(asset_id: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-ASSET-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(asset_id)],
        32,
    )
}

pub fn confidential_perps_blinding(
    subject: impl ToString,
    nonce: impl ToString,
    purpose: &str,
) -> String {
    let subject = subject.to_string();
    let nonce = nonce.to_string();
    domain_hash(
        "CONFIDENTIAL-PERPS-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&subject),
            HashPart::Str(&nonce),
            HashPart::Str(purpose),
        ],
        32,
    )
}

pub fn confidential_perps_amount_commitment(label: &str, value: u64, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(value as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_perps_signed_commitment(label: &str, value: i64, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-SIGNED-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(value as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_perps_price_commitment(
    label: &str,
    price_units: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-PRICE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(price_units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_perps_side_commitment(side: &PositionSide, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-PERPS-SIDE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(side.as_str()),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn risk_status_from_score(score_bps: u64) -> &'static str {
    if score_bps >= 9_000 {
        "critical"
    } else if score_bps >= 6_000 {
        "warn"
    } else if score_bps >= 2_500 {
        "watch"
    } else {
        "healthy"
    }
}

fn ensure_non_empty(value: &str, field: &str) -> ConfidentialPerpsResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn ensure_bps(value: u64, field: &str) -> ConfidentialPerpsResult<()> {
    if value > CONFIDENTIAL_PERPS_MAX_BPS {
        return Err(format!("{field} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_state_market(
    markets: &BTreeMap<String, ConfidentialPerpMarket>,
    market_id: &str,
    subject: &str,
) -> ConfidentialPerpsResult<()> {
    if !markets.contains_key(market_id) {
        return Err(format!("{subject} references missing market"));
    }
    Ok(())
}
