use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedLiquidityBackstopPerpsRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedLiquidityBackstopPerpsRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_BACKSTOP_PERPS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-liquidity-backstop-perps-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_BACKSTOP_PERPS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_184_800;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_238_400;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SOLVENCY_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-backstop-perps-solvency-v1";
pub const PQ_ORACLE_SUITE: &str =
    "pq-threshold-oracle-attestation+median-price+funding-index+staleness-v1";
pub const ENCRYPTED_ORDER_SUITE: &str =
    "ml-kem-1024-sealed-confidential-tokenized-backstop-perps-order-v1";
pub const CONFIDENTIAL_MARGIN_SUITE: &str =
    "ringct-margin-cohort+amount-commitment+range-proof+viewtag-v1";
pub const BACKSTOP_SHARE_SUITE: &str =
    "confidential-tokenized-liquidity-backstop-share+nav-proof-v1";
pub const FUNDING_SETTLEMENT_SUITE: &str =
    "low-fee-confidential-perps-funding-settlement+netted-index-v1";
pub const LIQUIDATION_REBATE_SUITE: &str =
    "confidential-liquidation-rebate-coupon+operator-safe-summary-v1";
pub const REDACTION_BUDGET_SUITE: &str =
    "operator-safe-tokenized-backstop-perps-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str =
    "redacted-tokenized-liquidity-backstop-perps-operator-summary-v1";
pub const DEFAULT_COLLATERAL_ASSET_ID: &str = "asset:wxmr";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "asset:private-usd";
pub const DEFAULT_BACKSTOP_SHARE_ASSET_ID: &str = "asset:tlbp-share";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_600;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 780;
pub const DEFAULT_BACKSTOP_TARGET_BPS: u64 = 1_250;
pub const DEFAULT_BACKSTOP_MIN_SOLVENCY_BPS: u64 = 10_800;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: u64 = 1_000;
pub const DEFAULT_LIQUIDATION_PENALTY_BPS: u64 = 325;
pub const DEFAULT_LIQUIDATOR_REBATE_BPS: u64 = 42;
pub const DEFAULT_OPERATOR_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_ORDER_FEE_BPS: u64 = 14;
pub const DEFAULT_ORACLE_STALENESS_BLOCKS: u64 = 24;
pub const DEFAULT_SOLVENCY_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FUNDING_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 192;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_560;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    Linear,
    Inverse,
    Quanto,
    TokenizedIndex,
    Volatility,
    FundingOnly,
}

impl MarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::Inverse => "inverse",
            Self::Quanto => "quanto",
            Self::TokenizedIndex => "tokenized_index",
            Self::Volatility => "volatility",
            Self::FundingOnly => "funding_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Open,
    FundingOnly,
    ReduceOnly,
    LiquidationOnly,
    Paused,
    Settling,
    Closed,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::FundingOnly => "funding_only",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Paused => "paused",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(
            self,
            Self::Open | Self::FundingOnly | Self::ReduceOnly | Self::Settling
        )
    }

    pub fn accepts_liquidations(self) -> bool {
        matches!(
            self,
            Self::Open | Self::FundingOnly | Self::ReduceOnly | Self::LiquidationOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Long,
    Short,
    BackstopMint,
    BackstopRedeem,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::BackstopMint => "backstop_mint",
            Self::BackstopRedeem => "backstop_redeem",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Encrypted,
    Admitted,
    Matched,
    Rejected,
    Cancelled,
    Expired,
    Settled,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Admitted => "admitted",
            Self::Matched => "matched",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Forming,
    Active,
    FundingLocked,
    Deleveraging,
    LiquidationQueued,
    Insolvent,
    Closed,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::FundingLocked => "funding_locked",
            Self::Deleveraging => "deleveraging",
            Self::LiquidationQueued => "liquidation_queued",
            Self::Insolvent => "insolvent",
            Self::Closed => "closed",
        }
    }

    pub fn is_risky(self) -> bool {
        matches!(
            self,
            Self::Deleveraging | Self::LiquidationQueued | Self::Insolvent
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    OraclePrice,
    FundingIndex,
    Solvency,
    BackstopNav,
    LiquidationEligibility,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OraclePrice => "oracle_price",
            Self::FundingIndex => "funding_index",
            Self::Solvency => "solvency",
            Self::BackstopNav => "backstop_nav",
            Self::LiquidationEligibility => "liquidation_eligibility",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    QuorumVerified,
    Applied,
    Superseded,
    Expired,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::QuorumVerified => "quorum_verified",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    Netting,
    Applied,
    Rebased,
    Disputed,
    Reverted,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Netting => "netting",
            Self::Applied => "applied",
            Self::Rebased => "rebased",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Committed,
    Claimable,
    Claimed,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Committed => "committed",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Orders,
    Margin,
    Oracle,
    Solvency,
    Rebates,
    OperatorSummary,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Orders => "orders",
            Self::Margin => "margin",
            Self::Oracle => "oracle",
            Self::Solvency => "solvency",
            Self::Rebates => "rebates",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub backstop_share_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_solvency_suite: String,
    pub pq_oracle_suite: String,
    pub encrypted_order_suite: String,
    pub confidential_margin_suite: String,
    pub backstop_share_suite: String,
    pub funding_settlement_suite: String,
    pub liquidation_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub backstop_target_bps: u64,
    pub backstop_min_solvency_bps: u64,
    pub max_funding_rate_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub liquidator_rebate_bps: u64,
    pub operator_rebate_bps: u64,
    pub max_order_fee_bps: u64,
    pub oracle_staleness_blocks: u64,
    pub solvency_ttl_blocks: u64,
    pub funding_epoch_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_public_redaction_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            collateral_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            backstop_share_asset_id: DEFAULT_BACKSTOP_SHARE_ASSET_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_solvency_suite: PQ_SOLVENCY_SUITE.to_string(),
            pq_oracle_suite: PQ_ORACLE_SUITE.to_string(),
            encrypted_order_suite: ENCRYPTED_ORDER_SUITE.to_string(),
            confidential_margin_suite: CONFIDENTIAL_MARGIN_SUITE.to_string(),
            backstop_share_suite: BACKSTOP_SHARE_SUITE.to_string(),
            funding_settlement_suite: FUNDING_SETTLEMENT_SUITE.to_string(),
            liquidation_rebate_suite: LIQUIDATION_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            backstop_target_bps: DEFAULT_BACKSTOP_TARGET_BPS,
            backstop_min_solvency_bps: DEFAULT_BACKSTOP_MIN_SOLVENCY_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            liquidator_rebate_bps: DEFAULT_LIQUIDATOR_REBATE_BPS,
            operator_rebate_bps: DEFAULT_OPERATOR_REBATE_BPS,
            max_order_fee_bps: DEFAULT_MAX_ORDER_FEE_BPS,
            oracle_staleness_blocks: DEFAULT_ORACLE_STALENESS_BLOCKS,
            solvency_ttl_blocks: DEFAULT_SOLVENCY_TTL_BLOCKS,
            funding_epoch_blocks: DEFAULT_FUNDING_EPOCH_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol_version mismatch".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("min_pq_security_bits below generated runtime floor".to_string());
        }
        ensure_bps("initial_margin_bps", self.initial_margin_bps)?;
        ensure_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        ensure_bps("backstop_target_bps", self.backstop_target_bps)?;
        ensure_bps("max_funding_rate_bps", self.max_funding_rate_bps)?;
        ensure_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        ensure_bps("liquidator_rebate_bps", self.liquidator_rebate_bps)?;
        ensure_bps("operator_rebate_bps", self.operator_rebate_bps)?;
        ensure_bps("max_order_fee_bps", self.max_order_fee_bps)?;
        if self.initial_margin_bps <= self.maintenance_margin_bps {
            return Err("initial_margin_bps must exceed maintenance_margin_bps".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target_privacy_set_size must be >= min_privacy_set_size".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "backstop_share_asset_id": self.backstop_share_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_solvency_suite": self.pq_solvency_suite,
            "pq_oracle_suite": self.pq_oracle_suite,
            "encrypted_order_suite": self.encrypted_order_suite,
            "confidential_margin_suite": self.confidential_margin_suite,
            "backstop_share_suite": self.backstop_share_suite,
            "funding_settlement_suite": self.funding_settlement_suite,
            "liquidation_rebate_suite": self.liquidation_rebate_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "operator_summary_suite": self.operator_summary_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "backstop_target_bps": self.backstop_target_bps,
            "backstop_min_solvency_bps": self.backstop_min_solvency_bps,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "liquidator_rebate_bps": self.liquidator_rebate_bps,
            "operator_rebate_bps": self.operator_rebate_bps,
            "max_order_fee_bps": self.max_order_fee_bps,
            "oracle_staleness_blocks": self.oracle_staleness_blocks,
            "solvency_ttl_blocks": self.solvency_ttl_blocks,
            "funding_epoch_blocks": self.funding_epoch_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "max_public_redaction_bytes": self.max_public_redaction_bytes,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub markets: u64,
    pub margin_cohorts: u64,
    pub encrypted_orders: u64,
    pub pq_attestations: u64,
    pub funding_settlements: u64,
    pub liquidation_rebates: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub total_orders_admitted: u64,
    pub total_orders_matched: u64,
    pub total_orders_rejected: u64,
    pub total_liquidations: u64,
    pub total_backstop_draws: u64,
    pub total_funding_epochs: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "margin_cohorts": self.margin_cohorts,
            "encrypted_orders": self.encrypted_orders,
            "pq_attestations": self.pq_attestations,
            "funding_settlements": self.funding_settlements,
            "liquidation_rebates": self.liquidation_rebates,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "total_orders_admitted": self.total_orders_admitted,
            "total_orders_matched": self.total_orders_matched,
            "total_orders_rejected": self.total_orders_rejected,
            "total_liquidations": self.total_liquidations,
            "total_backstop_draws": self.total_backstop_draws,
            "total_funding_epochs": self.total_funding_epochs,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub markets_root: String,
    pub margin_cohorts_root: String,
    pub encrypted_orders_root: String,
    pub pq_attestations_root: String,
    pub funding_settlements_root: String,
    pub liquidation_rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub counters_root: String,
    pub config_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "markets_root": self.markets_root,
            "margin_cohorts_root": self.margin_cohorts_root,
            "encrypted_orders_root": self.encrypted_orders_root,
            "pq_attestations_root": self.pq_attestations_root,
            "funding_settlements_root": self.funding_settlements_root,
            "liquidation_rebates_root": self.liquidation_rebates_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "counters_root": self.counters_root,
            "config_root": self.config_root,
        })
    }

    pub fn root(&self) -> String {
        runtime_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackstopPerpMarket {
    pub market_id: String,
    pub symbol: String,
    pub kind: MarketKind,
    pub status: MarketStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub collateral_asset_id: String,
    pub backstop_share_asset_id: String,
    pub price_oracle_committee_id: String,
    pub solvency_committee_id: String,
    pub margin_table_root: String,
    pub risk_parameter_root: String,
    pub open_interest_commitment_root: String,
    pub backstop_nav_commitment_root: String,
    pub latest_price_attestation_id: String,
    pub latest_solvency_attestation_id: String,
    pub funding_index: i128,
    pub funding_rate_bps: i64,
    pub max_leverage_bps: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub min_order_notional: u64,
    pub backstop_liquidity_committed: u64,
    pub backstop_liquidity_available: u64,
    pub insurance_buffer_committed: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl BackstopPerpMarket {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("market_id", &self.market_id)?;
        ensure_hash("margin_table_root", &self.margin_table_root)?;
        ensure_hash("risk_parameter_root", &self.risk_parameter_root)?;
        ensure_hash(
            "open_interest_commitment_root",
            &self.open_interest_commitment_root,
        )?;
        ensure_hash(
            "backstop_nav_commitment_root",
            &self.backstop_nav_commitment_root,
        )?;
        ensure_bps("maker_fee_bps", self.maker_fee_bps)?;
        ensure_bps("taker_fee_bps", self.taker_fee_bps)?;
        if self.maker_fee_bps > config.max_order_fee_bps {
            return Err(format!("market {} maker fee exceeds cap", self.market_id));
        }
        if self.taker_fee_bps > config.max_order_fee_bps {
            return Err(format!("market {} taker fee exceeds cap", self.market_id));
        }
        if self.backstop_liquidity_available > self.backstop_liquidity_committed {
            return Err(format!(
                "market {} available backstop exceeds committed",
                self.market_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "symbol": self.symbol,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "backstop_share_asset_id": self.backstop_share_asset_id,
            "price_oracle_committee_id": self.price_oracle_committee_id,
            "solvency_committee_id": self.solvency_committee_id,
            "margin_table_root": self.margin_table_root,
            "risk_parameter_root": self.risk_parameter_root,
            "open_interest_commitment_root": self.open_interest_commitment_root,
            "backstop_nav_commitment_root": self.backstop_nav_commitment_root,
            "latest_price_attestation_id": self.latest_price_attestation_id,
            "latest_solvency_attestation_id": self.latest_solvency_attestation_id,
            "funding_index": self.funding_index.to_string(),
            "funding_rate_bps": self.funding_rate_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "min_order_notional": self.min_order_notional,
            "backstop_liquidity_committed": self.backstop_liquidity_committed,
            "backstop_liquidity_available": self.backstop_liquidity_available,
            "insurance_buffer_committed": self.insurance_buffer_committed,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn backstop_utilization_bps(&self) -> u64 {
        if self.backstop_liquidity_committed == 0 {
            return 0;
        }
        let used = self
            .backstop_liquidity_committed
            .saturating_sub(self.backstop_liquidity_available);
        bps(used, self.backstop_liquidity_committed)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginCohort {
    pub cohort_id: String,
    pub market_id: String,
    pub status: CohortStatus,
    pub cohort_epoch: u64,
    pub participant_set_root: String,
    pub margin_commitment_root: String,
    pub position_commitment_root: String,
    pub nullifier_root: String,
    pub view_tag_root: String,
    pub encrypted_delta_root: String,
    pub aggregate_notional_commitment: String,
    pub aggregate_margin_commitment: String,
    pub long_open_interest_commitment: String,
    pub short_open_interest_commitment: String,
    pub maintenance_margin_bps: u64,
    pub initial_margin_bps: u64,
    pub privacy_set_size: u64,
    pub risky_accounts: u64,
    pub liquidation_queue_size: u64,
    pub opened_height: u64,
    pub last_rebalance_height: u64,
}

impl MarginCohort {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
    ) -> Result<()> {
        ensure_id("cohort_id", &self.cohort_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_hash("participant_set_root", &self.participant_set_root)?;
        ensure_hash("margin_commitment_root", &self.margin_commitment_root)?;
        ensure_hash("position_commitment_root", &self.position_commitment_root)?;
        ensure_hash("nullifier_root", &self.nullifier_root)?;
        ensure_hash("view_tag_root", &self.view_tag_root)?;
        ensure_hash("encrypted_delta_root", &self.encrypted_delta_root)?;
        ensure_hash(
            "aggregate_notional_commitment",
            &self.aggregate_notional_commitment,
        )?;
        ensure_hash(
            "aggregate_margin_commitment",
            &self.aggregate_margin_commitment,
        )?;
        ensure_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        ensure_bps("initial_margin_bps", self.initial_margin_bps)?;
        if self.initial_margin_bps <= self.maintenance_margin_bps {
            return Err(format!(
                "cohort {} initial margin must exceed maintenance",
                self.cohort_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("cohort {} privacy set below floor", self.cohort_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "market_id": self.market_id,
            "status": self.status.as_str(),
            "cohort_epoch": self.cohort_epoch,
            "participant_set_root": self.participant_set_root,
            "margin_commitment_root": self.margin_commitment_root,
            "position_commitment_root": self.position_commitment_root,
            "nullifier_root": self.nullifier_root,
            "view_tag_root": self.view_tag_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "aggregate_notional_commitment": self.aggregate_notional_commitment,
            "aggregate_margin_commitment": self.aggregate_margin_commitment,
            "long_open_interest_commitment": self.long_open_interest_commitment,
            "short_open_interest_commitment": self.short_open_interest_commitment,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "privacy_set_size": self.privacy_set_size,
            "risky_accounts": self.risky_accounts,
            "liquidation_queue_size": self.liquidation_queue_size,
            "opened_height": self.opened_height,
            "last_rebalance_height": self.last_rebalance_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedOrder {
    pub order_id: String,
    pub market_id: String,
    pub cohort_id: String,
    pub side: OrderSide,
    pub status: OrderStatus,
    pub owner_view_tag: String,
    pub nullifier_hash: String,
    pub order_commitment: String,
    pub amount_commitment: String,
    pub limit_price_commitment: String,
    pub margin_delta_commitment: String,
    pub encrypted_payload_hash: String,
    pub kem_ciphertext_hash: String,
    pub pq_authorization_root: String,
    pub fee_commitment: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub admitted_height: u64,
    pub expires_height: u64,
}

impl EncryptedOrder {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
        cohorts: &BTreeMap<String, MarginCohort>,
    ) -> Result<()> {
        ensure_id("order_id", &self.order_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_known("cohort_id", &self.cohort_id, cohorts)?;
        ensure_hash("nullifier_hash", &self.nullifier_hash)?;
        ensure_hash("order_commitment", &self.order_commitment)?;
        ensure_hash("amount_commitment", &self.amount_commitment)?;
        ensure_hash("limit_price_commitment", &self.limit_price_commitment)?;
        ensure_hash("margin_delta_commitment", &self.margin_delta_commitment)?;
        ensure_hash("encrypted_payload_hash", &self.encrypted_payload_hash)?;
        ensure_hash("kem_ciphertext_hash", &self.kem_ciphertext_hash)?;
        ensure_hash("pq_authorization_root", &self.pq_authorization_root)?;
        ensure_hash("fee_commitment", &self.fee_commitment)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_order_fee_bps {
            return Err(format!(
                "order {} max_fee_bps exceeds config",
                self.order_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("order {} privacy set below floor", self.order_id));
        }
        if self.expires_height <= self.admitted_height {
            return Err(format!("order {} expires before admission", self.order_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "market_id": self.market_id,
            "cohort_id": self.cohort_id,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "owner_view_tag": self.owner_view_tag,
            "nullifier_hash": self.nullifier_hash,
            "order_commitment": self.order_commitment,
            "amount_commitment": self.amount_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "margin_delta_commitment": self.margin_delta_commitment,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_commitment": self.fee_commitment,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "admitted_height": self.admitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSolvencyOracleAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub market_id: String,
    pub committee_id: String,
    pub signer_set_root: String,
    pub transcript_hash: String,
    pub oracle_payload_root: String,
    pub solvency_payload_root: String,
    pub price_commitment: String,
    pub funding_index_commitment: String,
    pub backstop_nav_commitment: String,
    pub liabilities_commitment: String,
    pub assets_commitment: String,
    pub quorum_bps: u64,
    pub pq_security_bits: u16,
    pub observed_height: u64,
    pub valid_until_height: u64,
}

impl PqSolvencyOracleAttestation {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
    ) -> Result<()> {
        ensure_id("attestation_id", &self.attestation_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_hash("signer_set_root", &self.signer_set_root)?;
        ensure_hash("transcript_hash", &self.transcript_hash)?;
        ensure_hash("oracle_payload_root", &self.oracle_payload_root)?;
        ensure_hash("solvency_payload_root", &self.solvency_payload_root)?;
        ensure_hash("price_commitment", &self.price_commitment)?;
        ensure_hash("funding_index_commitment", &self.funding_index_commitment)?;
        ensure_hash("backstop_nav_commitment", &self.backstop_nav_commitment)?;
        ensure_hash("liabilities_commitment", &self.liabilities_commitment)?;
        ensure_hash("assets_commitment", &self.assets_commitment)?;
        ensure_bps("quorum_bps", self.quorum_bps)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} pq security below config",
                self.attestation_id
            ));
        }
        if self.valid_until_height <= self.observed_height {
            return Err(format!(
                "attestation {} valid_until_height must exceed observed_height",
                self.attestation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "market_id": self.market_id,
            "committee_id": self.committee_id,
            "signer_set_root": self.signer_set_root,
            "transcript_hash": self.transcript_hash,
            "oracle_payload_root": self.oracle_payload_root,
            "solvency_payload_root": self.solvency_payload_root,
            "price_commitment": self.price_commitment,
            "funding_index_commitment": self.funding_index_commitment,
            "backstop_nav_commitment": self.backstop_nav_commitment,
            "liabilities_commitment": self.liabilities_commitment,
            "assets_commitment": self.assets_commitment,
            "quorum_bps": self.quorum_bps,
            "pq_security_bits": self.pq_security_bits,
            "observed_height": self.observed_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingSettlement {
    pub settlement_id: String,
    pub market_id: String,
    pub cohort_id: String,
    pub status: SettlementStatus,
    pub epoch: u64,
    pub funding_rate_bps: i64,
    pub previous_funding_index: i128,
    pub next_funding_index: i128,
    pub net_long_debit_commitment: String,
    pub net_short_credit_commitment: String,
    pub backstop_credit_commitment: String,
    pub settlement_note_root: String,
    pub nullifier_root: String,
    pub pq_attestation_id: String,
    pub applied_height: u64,
}

impl FundingSettlement {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
        cohorts: &BTreeMap<String, MarginCohort>,
        attestations: &BTreeMap<String, PqSolvencyOracleAttestation>,
    ) -> Result<()> {
        ensure_id("settlement_id", &self.settlement_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_known("cohort_id", &self.cohort_id, cohorts)?;
        ensure_known("pq_attestation_id", &self.pq_attestation_id, attestations)?;
        ensure_hash("net_long_debit_commitment", &self.net_long_debit_commitment)?;
        ensure_hash(
            "net_short_credit_commitment",
            &self.net_short_credit_commitment,
        )?;
        ensure_hash(
            "backstop_credit_commitment",
            &self.backstop_credit_commitment,
        )?;
        ensure_hash("settlement_note_root", &self.settlement_note_root)?;
        ensure_hash("nullifier_root", &self.nullifier_root)?;
        if self.funding_rate_bps.unsigned_abs() > config.max_funding_rate_bps {
            return Err(format!(
                "settlement {} funding rate exceeds cap",
                self.settlement_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "market_id": self.market_id,
            "cohort_id": self.cohort_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "funding_rate_bps": self.funding_rate_bps,
            "previous_funding_index": self.previous_funding_index.to_string(),
            "next_funding_index": self.next_funding_index.to_string(),
            "net_long_debit_commitment": self.net_long_debit_commitment,
            "net_short_credit_commitment": self.net_short_credit_commitment,
            "backstop_credit_commitment": self.backstop_credit_commitment,
            "settlement_note_root": self.settlement_note_root,
            "nullifier_root": self.nullifier_root,
            "pq_attestation_id": self.pq_attestation_id,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationRebate {
    pub rebate_id: String,
    pub market_id: String,
    pub cohort_id: String,
    pub status: RebateStatus,
    pub liquidator_nullifier_hash: String,
    pub liquidated_position_commitment: String,
    pub liquidation_attestation_id: String,
    pub rebate_commitment: String,
    pub penalty_commitment: String,
    pub backstop_draw_commitment: String,
    pub claim_note_root: String,
    pub claim_nullifier_root: String,
    pub liquidator_rebate_bps: u64,
    pub operator_rebate_bps: u64,
    pub accrued_height: u64,
    pub claimable_after_height: u64,
    pub expires_height: u64,
}

impl LiquidationRebate {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
        cohorts: &BTreeMap<String, MarginCohort>,
        attestations: &BTreeMap<String, PqSolvencyOracleAttestation>,
    ) -> Result<()> {
        ensure_id("rebate_id", &self.rebate_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_known("cohort_id", &self.cohort_id, cohorts)?;
        ensure_known(
            "liquidation_attestation_id",
            &self.liquidation_attestation_id,
            attestations,
        )?;
        ensure_hash("liquidator_nullifier_hash", &self.liquidator_nullifier_hash)?;
        ensure_hash(
            "liquidated_position_commitment",
            &self.liquidated_position_commitment,
        )?;
        ensure_hash("rebate_commitment", &self.rebate_commitment)?;
        ensure_hash("penalty_commitment", &self.penalty_commitment)?;
        ensure_hash("backstop_draw_commitment", &self.backstop_draw_commitment)?;
        ensure_hash("claim_note_root", &self.claim_note_root)?;
        ensure_hash("claim_nullifier_root", &self.claim_nullifier_root)?;
        ensure_bps("liquidator_rebate_bps", self.liquidator_rebate_bps)?;
        ensure_bps("operator_rebate_bps", self.operator_rebate_bps)?;
        if self.liquidator_rebate_bps > config.liquidator_rebate_bps {
            return Err(format!(
                "rebate {} liquidator bps exceeds cap",
                self.rebate_id
            ));
        }
        if self.operator_rebate_bps > config.operator_rebate_bps {
            return Err(format!(
                "rebate {} operator bps exceeds cap",
                self.rebate_id
            ));
        }
        if self.expires_height <= self.claimable_after_height {
            return Err(format!(
                "rebate {} expires before claim window",
                self.rebate_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "market_id": self.market_id,
            "cohort_id": self.cohort_id,
            "status": self.status.as_str(),
            "liquidator_nullifier_hash": self.liquidator_nullifier_hash,
            "liquidated_position_commitment": self.liquidated_position_commitment,
            "liquidation_attestation_id": self.liquidation_attestation_id,
            "rebate_commitment": self.rebate_commitment,
            "penalty_commitment": self.penalty_commitment,
            "backstop_draw_commitment": self.backstop_draw_commitment,
            "claim_note_root": self.claim_note_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "liquidator_rebate_bps": self.liquidator_rebate_bps,
            "operator_rebate_bps": self.operator_rebate_bps,
            "accrued_height": self.accrued_height,
            "claimable_after_height": self.claimable_after_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope: RedactionScope,
    pub operator_id: String,
    pub market_id: String,
    pub allowance_units: u64,
    pub consumed_units: u64,
    pub max_public_bytes: u64,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
    pub audit_note_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl RedactionBudget {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
    ) -> Result<()> {
        ensure_id("budget_id", &self.budget_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_hash("redacted_field_root", &self.redacted_field_root)?;
        ensure_hash("disclosure_policy_root", &self.disclosure_policy_root)?;
        ensure_hash("audit_note_root", &self.audit_note_root)?;
        if self.consumed_units > self.allowance_units {
            return Err(format!(
                "budget {} consumed exceeds allowance",
                self.budget_id
            ));
        }
        if self.allowance_units > config.redaction_budget_units {
            return Err(format!(
                "budget {} exceeds config allowance",
                self.budget_id
            ));
        }
        if self.max_public_bytes > config.max_public_redaction_bytes {
            return Err(format!(
                "budget {} public bytes exceeds cap",
                self.budget_id
            ));
        }
        if self.expires_height <= self.opened_height {
            return Err(format!("budget {} expires before opening", self.budget_id));
        }
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.allowance_units.saturating_sub(self.consumed_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "scope": self.scope.as_str(),
            "operator_id": self.operator_id,
            "market_id": self.market_id,
            "allowance_units": self.allowance_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "max_public_bytes": self.max_public_bytes,
            "redacted_field_root": self.redacted_field_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "audit_note_root": self.audit_note_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub market_id: String,
    pub summary_epoch: u64,
    pub redaction_budget_id: String,
    pub public_markets: u64,
    pub active_cohorts: u64,
    pub encrypted_orders_seen: u64,
    pub encrypted_orders_matched: u64,
    pub liquidations_executed: u64,
    pub funding_settlements_applied: u64,
    pub backstop_utilization_bps: u64,
    pub solvency_ratio_bps: u64,
    pub pq_attestation_quorum_bps: u64,
    pub privacy_set_floor: u64,
    pub withheld_order_count_commitment: String,
    pub withheld_margin_delta_commitment: String,
    pub withheld_rebate_commitment: String,
    pub operator_signature_root: String,
    pub emitted_height: u64,
}

impl OperatorSummary {
    pub fn validate(
        &self,
        config: &Config,
        markets: &BTreeMap<String, BackstopPerpMarket>,
        budgets: &BTreeMap<String, RedactionBudget>,
    ) -> Result<()> {
        ensure_id("summary_id", &self.summary_id)?;
        ensure_known("market_id", &self.market_id, markets)?;
        ensure_known("redaction_budget_id", &self.redaction_budget_id, budgets)?;
        ensure_bps("backstop_utilization_bps", self.backstop_utilization_bps)?;
        ensure_bps("pq_attestation_quorum_bps", self.pq_attestation_quorum_bps)?;
        ensure_hash(
            "withheld_order_count_commitment",
            &self.withheld_order_count_commitment,
        )?;
        ensure_hash(
            "withheld_margin_delta_commitment",
            &self.withheld_margin_delta_commitment,
        )?;
        ensure_hash(
            "withheld_rebate_commitment",
            &self.withheld_rebate_commitment,
        )?;
        ensure_hash("operator_signature_root", &self.operator_signature_root)?;
        if self.privacy_set_floor < config.min_privacy_set_size {
            return Err(format!(
                "summary {} privacy floor below config",
                self.summary_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "market_id": self.market_id,
            "summary_epoch": self.summary_epoch,
            "redaction_budget_id": self.redaction_budget_id,
            "public_markets": self.public_markets,
            "active_cohorts": self.active_cohorts,
            "encrypted_orders_seen": self.encrypted_orders_seen,
            "encrypted_orders_matched": self.encrypted_orders_matched,
            "liquidations_executed": self.liquidations_executed,
            "funding_settlements_applied": self.funding_settlements_applied,
            "backstop_utilization_bps": self.backstop_utilization_bps,
            "solvency_ratio_bps": self.solvency_ratio_bps,
            "pq_attestation_quorum_bps": self.pq_attestation_quorum_bps,
            "privacy_set_floor": self.privacy_set_floor,
            "withheld_order_count_commitment": self.withheld_order_count_commitment,
            "withheld_margin_delta_commitment": self.withheld_margin_delta_commitment,
            "withheld_rebate_commitment": self.withheld_rebate_commitment,
            "operator_signature_root": self.operator_signature_root,
            "emitted_height": self.emitted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub monero_height: u64,
    pub markets: BTreeMap<String, BackstopPerpMarket>,
    pub margin_cohorts: BTreeMap<String, MarginCohort>,
    pub encrypted_orders: BTreeMap<String, EncryptedOrder>,
    pub pq_attestations: BTreeMap<String, PqSolvencyOracleAttestation>,
    pub funding_settlements: BTreeMap<String, FundingSettlement>,
    pub liquidation_rebates: BTreeMap<String, LiquidationRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            markets: BTreeMap::new(),
            margin_cohorts: BTreeMap::new(),
            encrypted_orders: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            funding_settlements: BTreeMap::new(),
            liquidation_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            counters: Counters::default(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let counters_record = self.counters.public_record();
        Roots {
            markets_root: map_root(
                "MARKETS",
                self.markets.values().map(BackstopPerpMarket::public_record),
            ),
            margin_cohorts_root: map_root(
                "MARGIN-COHORTS",
                self.margin_cohorts
                    .values()
                    .map(MarginCohort::public_record),
            ),
            encrypted_orders_root: map_root(
                "ENCRYPTED-ORDERS",
                self.encrypted_orders
                    .values()
                    .map(EncryptedOrder::public_record),
            ),
            pq_attestations_root: map_root(
                "PQ-ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqSolvencyOracleAttestation::public_record),
            ),
            funding_settlements_root: map_root(
                "FUNDING-SETTLEMENTS",
                self.funding_settlements
                    .values()
                    .map(FundingSettlement::public_record),
            ),
            liquidation_rebates_root: map_root(
                "LIQUIDATION-REBATES",
                self.liquidation_rebates
                    .values()
                    .map(LiquidationRebate::public_record),
            ),
            redaction_budgets_root: map_root(
                "REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            operator_summaries_root: map_root(
                "OPERATOR-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
            counters_root: runtime_hash("COUNTERS", &[HashPart::Json(&counters_record)]),
            config_root: runtime_hash("CONFIG", &[HashPart::Json(&config_record)]),
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_unique_nullifiers(
            self.encrypted_orders
                .values()
                .map(|order| &order.nullifier_hash),
        )?;
        for market in self.markets.values() {
            market.validate(&self.config)?;
        }
        for cohort in self.margin_cohorts.values() {
            cohort.validate(&self.config, &self.markets)?;
        }
        for order in self.encrypted_orders.values() {
            order.validate(&self.config, &self.markets, &self.margin_cohorts)?;
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate(&self.config, &self.markets)?;
        }
        for settlement in self.funding_settlements.values() {
            settlement.validate(
                &self.config,
                &self.markets,
                &self.margin_cohorts,
                &self.pq_attestations,
            )?;
        }
        for rebate in self.liquidation_rebates.values() {
            rebate.validate(
                &self.config,
                &self.markets,
                &self.margin_cohorts,
                &self.pq_attestations,
            )?;
        }
        for budget in self.redaction_budgets.values() {
            budget.validate(&self.config, &self.markets)?;
        }
        for summary in self.operator_summaries.values() {
            summary.validate(&self.config, &self.markets, &self.redaction_budgets)?;
        }
        Ok(())
    }

    pub fn recompute_counters(&mut self) {
        self.counters.markets = self.markets.len() as u64;
        self.counters.margin_cohorts = self.margin_cohorts.len() as u64;
        self.counters.encrypted_orders = self.encrypted_orders.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.counters.funding_settlements = self.funding_settlements.len() as u64;
        self.counters.liquidation_rebates = self.liquidation_rebates.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.total_orders_admitted = self
            .encrypted_orders
            .values()
            .filter(|order| !matches!(order.status, OrderStatus::Encrypted))
            .count() as u64;
        self.counters.total_orders_matched = self
            .encrypted_orders
            .values()
            .filter(|order| matches!(order.status, OrderStatus::Matched | OrderStatus::Settled))
            .count() as u64;
        self.counters.total_orders_rejected = self
            .encrypted_orders
            .values()
            .filter(|order| matches!(order.status, OrderStatus::Rejected))
            .count() as u64;
        self.counters.total_liquidations = self.liquidation_rebates.len() as u64;
        self.counters.total_backstop_draws = self
            .liquidation_rebates
            .values()
            .filter(|rebate| {
                matches!(
                    rebate.status,
                    RebateStatus::Claimable | RebateStatus::Claimed
                )
            })
            .count() as u64;
        self.counters.total_funding_epochs = self.funding_settlements.len() as u64;
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let market_a = sample_market("xmr-usd-perp", "XMR-USD-PERP", MarketKind::Linear, 0);
    let market_b = sample_market(
        "hashrate-basket-perp",
        "XMR-HASH-PERP",
        MarketKind::TokenizedIndex,
        1,
    );
    state.markets.insert(market_a.market_id.clone(), market_a);
    state.markets.insert(market_b.market_id.clone(), market_b);

    let cohort_a = sample_cohort(
        "cohort-xmr-usd-alpha",
        "xmr-usd-perp",
        CohortStatus::Active,
        0,
    );
    let cohort_b = sample_cohort(
        "cohort-hashrate-watch",
        "hashrate-basket-perp",
        CohortStatus::Deleveraging,
        1,
    );
    state
        .margin_cohorts
        .insert(cohort_a.cohort_id.clone(), cohort_a);
    state
        .margin_cohorts
        .insert(cohort_b.cohort_id.clone(), cohort_b);

    let oracle_a = sample_attestation(
        "attest-xmr-usd-price-0",
        "xmr-usd-perp",
        AttestationKind::OraclePrice,
        0,
    );
    let oracle_b = sample_attestation(
        "attest-hashrate-solvency-0",
        "hashrate-basket-perp",
        AttestationKind::Solvency,
        1,
    );
    state
        .pq_attestations
        .insert(oracle_a.attestation_id.clone(), oracle_a);
    state
        .pq_attestations
        .insert(oracle_b.attestation_id.clone(), oracle_b);

    for order in [
        sample_order(
            "order-xmr-long-0",
            "xmr-usd-perp",
            "cohort-xmr-usd-alpha",
            OrderSide::Long,
            OrderStatus::Matched,
            0,
        ),
        sample_order(
            "order-xmr-short-1",
            "xmr-usd-perp",
            "cohort-xmr-usd-alpha",
            OrderSide::Short,
            OrderStatus::Admitted,
            1,
        ),
        sample_order(
            "order-hash-backstop-0",
            "hashrate-basket-perp",
            "cohort-hashrate-watch",
            OrderSide::BackstopMint,
            OrderStatus::Settled,
            2,
        ),
    ] {
        state.encrypted_orders.insert(order.order_id.clone(), order);
    }

    let funding = sample_funding(
        "funding-xmr-epoch-4420",
        "xmr-usd-perp",
        "cohort-xmr-usd-alpha",
        "attest-xmr-usd-price-0",
        0,
    );
    state
        .funding_settlements
        .insert(funding.settlement_id.clone(), funding);
    let rebate = sample_rebate(
        "rebate-hashrate-0",
        "hashrate-basket-perp",
        "cohort-hashrate-watch",
        "attest-hashrate-solvency-0",
        0,
    );
    state
        .liquidation_rebates
        .insert(rebate.rebate_id.clone(), rebate);
    let budget = sample_budget(
        "budget-operator-alpha-xmr",
        "operator-alpha",
        "xmr-usd-perp",
        RedactionScope::OperatorSummary,
        0,
    );
    state
        .redaction_budgets
        .insert(budget.budget_id.clone(), budget);
    let summary = sample_summary(
        "summary-operator-alpha-4420",
        "operator-alpha",
        "xmr-usd-perp",
        "budget-operator-alpha-xmr",
        0,
    );
    state
        .operator_summaries
        .insert(summary.summary_id.clone(), summary);
    state.recompute_counters();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    let roots = state.roots();
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "height": state.height,
        "monero_height": state.monero_height,
        "config": state.config.public_record(),
        "counters": state.counters.public_record(),
        "roots": roots.public_record(),
        "state_root": roots.root(),
        "markets": values_record(state.markets.values().map(BackstopPerpMarket::public_record)),
        "margin_cohorts": values_record(state.margin_cohorts.values().map(MarginCohort::public_record)),
        "encrypted_orders": values_record(state.encrypted_orders.values().map(EncryptedOrder::public_record)),
        "pq_attestations": values_record(state.pq_attestations.values().map(PqSolvencyOracleAttestation::public_record)),
        "funding_settlements": values_record(state.funding_settlements.values().map(FundingSettlement::public_record)),
        "liquidation_rebates": values_record(state.liquidation_rebates.values().map(LiquidationRebate::public_record)),
        "redaction_budgets": values_record(state.redaction_budgets.values().map(RedactionBudget::public_record)),
        "operator_summaries": values_record(state.operator_summaries.values().map(OperatorSummary::public_record)),
    })
}

pub fn state_root(state: &State) -> String {
    runtime_hash(
        "STATE",
        &[HashPart::Json(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "height": state.height,
            "monero_height": state.monero_height,
            "roots": state.roots().public_record(),
        }))],
    )
}

fn sample_market(id: &str, symbol: &str, kind: MarketKind, index: u64) -> BackstopPerpMarket {
    BackstopPerpMarket {
        market_id: id.to_string(),
        symbol: symbol.to_string(),
        kind,
        status: MarketStatus::Open,
        base_asset_id: format!("asset:{}", symbol.to_ascii_lowercase()),
        quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        collateral_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        backstop_share_asset_id: DEFAULT_BACKSTOP_SHARE_ASSET_ID.to_string(),
        price_oracle_committee_id: format!("committee:oracle:{index}"),
        solvency_committee_id: format!("committee:solvency:{index}"),
        margin_table_root: sample_hash("margin-table", index),
        risk_parameter_root: sample_hash("risk-parameter", index),
        open_interest_commitment_root: sample_hash("open-interest", index),
        backstop_nav_commitment_root: sample_hash("backstop-nav", index),
        latest_price_attestation_id: format!("attest-{}-price-0", id.replace('_', "-")),
        latest_solvency_attestation_id: format!("attest-{}-solvency-0", id.replace('_', "-")),
        funding_index: 1_000_000 + index as i128 * 11,
        funding_rate_bps: if index == 0 { 9 } else { -7 },
        max_leverage_bps: 50_000,
        maker_fee_bps: 3,
        taker_fee_bps: 9,
        min_order_notional: 50_000,
        backstop_liquidity_committed: 5_000_000_000 + index * 750_000_000,
        backstop_liquidity_available: 4_550_000_000 + index * 650_000_000,
        insurance_buffer_committed: 220_000_000 + index * 35_000_000,
        created_height: DEVNET_HEIGHT - 7_200 + index * 100,
        updated_height: DEVNET_HEIGHT - index,
    }
}

fn sample_cohort(id: &str, market_id: &str, status: CohortStatus, index: u64) -> MarginCohort {
    MarginCohort {
        cohort_id: id.to_string(),
        market_id: market_id.to_string(),
        status,
        cohort_epoch: 4_420 + index,
        participant_set_root: sample_hash("participant-set", index),
        margin_commitment_root: sample_hash("margin-commitment", index),
        position_commitment_root: sample_hash("position-commitment", index),
        nullifier_root: sample_hash("cohort-nullifier", index),
        view_tag_root: sample_hash("view-tag", index),
        encrypted_delta_root: sample_hash("encrypted-delta", index),
        aggregate_notional_commitment: sample_hash("aggregate-notional", index),
        aggregate_margin_commitment: sample_hash("aggregate-margin", index),
        long_open_interest_commitment: sample_hash("long-open-interest", index),
        short_open_interest_commitment: sample_hash("short-open-interest", index),
        maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
        initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE + index * 16_384,
        risky_accounts: index + 3,
        liquidation_queue_size: if status.is_risky() { 7 + index } else { 0 },
        opened_height: DEVNET_HEIGHT - 1_440 + index * 32,
        last_rebalance_height: DEVNET_HEIGHT - 24 + index,
    }
}

fn sample_order(
    id: &str,
    market_id: &str,
    cohort_id: &str,
    side: OrderSide,
    status: OrderStatus,
    index: u64,
) -> EncryptedOrder {
    EncryptedOrder {
        order_id: id.to_string(),
        market_id: market_id.to_string(),
        cohort_id: cohort_id.to_string(),
        side,
        status,
        owner_view_tag: format!("vt{:04}", index + 31),
        nullifier_hash: sample_hash("order-nullifier", index),
        order_commitment: sample_hash("order", index),
        amount_commitment: sample_hash("amount", index),
        limit_price_commitment: sample_hash("limit-price", index),
        margin_delta_commitment: sample_hash("margin-delta", index),
        encrypted_payload_hash: sample_hash("encrypted-payload", index),
        kem_ciphertext_hash: sample_hash("kem-ciphertext", index),
        pq_authorization_root: sample_hash("pq-authorization", index),
        fee_commitment: sample_hash("fee", index),
        max_fee_bps: DEFAULT_MAX_ORDER_FEE_BPS,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE + index * 1_024,
        admitted_height: DEVNET_HEIGHT - 40 + index,
        expires_height: DEVNET_HEIGHT + 160 + index,
    }
}

fn sample_attestation(
    id: &str,
    market_id: &str,
    kind: AttestationKind,
    index: u64,
) -> PqSolvencyOracleAttestation {
    let payload_root = sample_hash("attestation-payload", index);
    PqSolvencyOracleAttestation {
        attestation_id: id.to_string(),
        kind,
        status: AttestationStatus::Applied,
        market_id: market_id.to_string(),
        committee_id: format!("committee:pq:{index}"),
        signer_set_root: sample_hash("signer-set", index),
        transcript_hash: runtime_hash(
            "ATTESTATION-TRANSCRIPT",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(market_id),
                HashPart::Str(&payload_root),
            ],
        ),
        oracle_payload_root: payload_root,
        solvency_payload_root: sample_hash("solvency-payload", index),
        price_commitment: sample_hash("price", index),
        funding_index_commitment: sample_hash("funding-index", index),
        backstop_nav_commitment: sample_hash("nav", index),
        liabilities_commitment: sample_hash("liabilities", index),
        assets_commitment: sample_hash("assets", index),
        quorum_bps: 8_500,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        observed_height: DEVNET_HEIGHT - 8 + index,
        valid_until_height: DEVNET_HEIGHT + DEFAULT_ORACLE_STALENESS_BLOCKS + index,
    }
}

fn sample_funding(
    id: &str,
    market_id: &str,
    cohort_id: &str,
    attestation_id: &str,
    index: u64,
) -> FundingSettlement {
    FundingSettlement {
        settlement_id: id.to_string(),
        market_id: market_id.to_string(),
        cohort_id: cohort_id.to_string(),
        status: SettlementStatus::Applied,
        epoch: 4_420 + index,
        funding_rate_bps: 9,
        previous_funding_index: 1_000_000,
        next_funding_index: 1_000_009,
        net_long_debit_commitment: sample_hash("long-debit", index),
        net_short_credit_commitment: sample_hash("short-credit", index),
        backstop_credit_commitment: sample_hash("backstop-credit", index),
        settlement_note_root: sample_hash("settlement-note", index),
        nullifier_root: sample_hash("funding-nullifier", index),
        pq_attestation_id: attestation_id.to_string(),
        applied_height: DEVNET_HEIGHT - 2 + index,
    }
}

fn sample_rebate(
    id: &str,
    market_id: &str,
    cohort_id: &str,
    attestation_id: &str,
    index: u64,
) -> LiquidationRebate {
    LiquidationRebate {
        rebate_id: id.to_string(),
        market_id: market_id.to_string(),
        cohort_id: cohort_id.to_string(),
        status: RebateStatus::Claimable,
        liquidator_nullifier_hash: sample_hash("liquidator-nullifier", index),
        liquidated_position_commitment: sample_hash("liquidated-position", index),
        liquidation_attestation_id: attestation_id.to_string(),
        rebate_commitment: sample_hash("rebate", index),
        penalty_commitment: sample_hash("penalty", index),
        backstop_draw_commitment: sample_hash("backstop-draw", index),
        claim_note_root: sample_hash("claim-note", index),
        claim_nullifier_root: sample_hash("claim-nullifier", index),
        liquidator_rebate_bps: DEFAULT_LIQUIDATOR_REBATE_BPS,
        operator_rebate_bps: DEFAULT_OPERATOR_REBATE_BPS,
        accrued_height: DEVNET_HEIGHT - 3 + index,
        claimable_after_height: DEVNET_HEIGHT + 9 + index,
        expires_height: DEVNET_HEIGHT + 7_200 + index,
    }
}

fn sample_budget(
    id: &str,
    operator_id: &str,
    market_id: &str,
    scope: RedactionScope,
    index: u64,
) -> RedactionBudget {
    RedactionBudget {
        budget_id: id.to_string(),
        scope,
        operator_id: operator_id.to_string(),
        market_id: market_id.to_string(),
        allowance_units: DEFAULT_REDACTION_BUDGET_UNITS,
        consumed_units: 37 + index,
        max_public_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
        redacted_field_root: sample_hash("redacted-field", index),
        disclosure_policy_root: sample_hash("disclosure-policy", index),
        audit_note_root: sample_hash("audit-note", index),
        opened_height: DEVNET_HEIGHT - 720 + index,
        expires_height: DEVNET_HEIGHT + 7_200 + index,
    }
}

fn sample_summary(
    id: &str,
    operator_id: &str,
    market_id: &str,
    budget_id: &str,
    index: u64,
) -> OperatorSummary {
    OperatorSummary {
        summary_id: id.to_string(),
        operator_id: operator_id.to_string(),
        market_id: market_id.to_string(),
        summary_epoch: 4_420 + index,
        redaction_budget_id: budget_id.to_string(),
        public_markets: 2,
        active_cohorts: 2,
        encrypted_orders_seen: 3,
        encrypted_orders_matched: 2,
        liquidations_executed: 1,
        funding_settlements_applied: 1,
        backstop_utilization_bps: 900,
        solvency_ratio_bps: 12_700,
        pq_attestation_quorum_bps: 8_500,
        privacy_set_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
        withheld_order_count_commitment: sample_hash("withheld-orders", index),
        withheld_margin_delta_commitment: sample_hash("withheld-margin", index),
        withheld_rebate_commitment: sample_hash("withheld-rebate", index),
        operator_signature_root: sample_hash("operator-signature", index),
        emitted_height: DEVNET_HEIGHT + index,
    }
}

fn values_record<I>(records: I) -> Value
where
    I: IntoIterator<Item = Value>,
{
    Value::Array(records.into_iter().collect())
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(&format!("TLBP-{domain}"), &values)
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-LIQUIDITY-BACKSTOP-PERPS-RUNTIME:{domain}"),
        parts,
        32,
    )
}

fn sample_hash(label: &str, index: u64) -> String {
    runtime_hash(
        "DEVNET-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(index)],
    )
}

fn ensure_id(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!("{field} exceeds generated runtime id limit"));
    }
    Ok(())
}

fn ensure_hash(field: &str, value: &str) -> Result<()> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(format!("{field} must be a 32-byte hex hash"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{field} must be <= {MAX_BPS}"));
    }
    Ok(())
}

fn ensure_known<T>(field: &str, key: &str, map: &BTreeMap<String, T>) -> Result<()> {
    if !map.contains_key(key) {
        return Err(format!("{field} references unknown id {key}"));
    }
    Ok(())
}

fn ensure_unique_nullifiers<'a, I>(nullifiers: I) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut seen = BTreeSet::new();
    for nullifier in nullifiers {
        if !seen.insert(nullifier) {
            return Err(format!("duplicate encrypted order nullifier {nullifier}"));
        }
    }
    Ok(())
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    ((numerator as u128 * MAX_BPS as u128) / denominator as u128) as u64
}
