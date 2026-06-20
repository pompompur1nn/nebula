use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialFeeCreditPerpsAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_CREDIT_PERPS_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-credit-perps-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_CREDIT_PERPS_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_QUOTE_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-low-fee-confidential-perps-amm-quote-v1";
pub const CONFIDENTIAL_PERPS_POOL_SCHEME: &str =
    "private-low-fee-confidential-fee-credit-perps-amm-pool-root-v1";
pub const FEE_CREDIT_MARGIN_NOTE_SCHEME: &str = "private-fee-credit-margin-note-settlement-root-v1";
pub const FUNDING_RATE_INTENT_SCHEME: &str =
    "sealed-confidential-perps-funding-rate-intent-nullifier-root-v1";
pub const PQ_QUOTE_ATTESTATION_SCHEME: &str =
    "pq-confidential-fee-credit-perps-amm-quote-attestation-root-v1";
pub const LIQUIDITY_GUARDRAIL_SCHEME: &str =
    "low-fee-confidential-perps-amm-liquidity-guardrail-root-v1";
pub const REBATE_SETTLEMENT_SCHEME: &str = "private-fee-credit-perps-amm-rebate-settlement-root-v1";
pub const BATCH_CLEARING_SCHEME: &str = "private-fee-credit-perps-amm-batch-clearing-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "operator-safe-low-fee-confidential-perps-amm-summary-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-low-fee-pq-confidential-fee-credit-perps-amm-public-record-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "private-l2-low-fee-pq-confidential-fee-credit-perps-amm-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_884_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_508_000;
pub const DEVNET_EPOCH: u64 = 8_224;
pub const DEVNET_AMM_ID: &str = "private-low-fee-fee-credit-perps-amm-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "pxmr-private-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_FEE_CREDIT_ASSET_ID: &str = "nebula-fee-credit-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "nebula-low-fee-rebate-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_LP_FEE_BPS: u64 = 2;
pub const DEFAULT_LIQUIDATION_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 10;
pub const DEFAULT_REBATE_COVER_BPS: u64 = 9_700;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_QUOTE_QUORUM: u16 = 3;
pub const DEFAULT_FUNDING_QUORUM: u16 = 3;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 20;
pub const DEFAULT_MARGIN_NOTE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CLEARING_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 4_096;
pub const DEFAULT_MIN_LIQUIDITY_UNITS: u128 = 50_000;
pub const DEFAULT_MIN_VAULT_COVERAGE_BPS: u64 = 10_900;
pub const DEFAULT_MAX_UTILIZATION_BPS: u64 = 8_150;
pub const DEFAULT_MAX_SKEW_BPS: u64 = 5_750;
pub const DEFAULT_MAX_PRICE_IMPACT_BPS: u64 = 55;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 325;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 5_000;
pub const DEFAULT_MIN_MAINTENANCE_MARGIN_BPS: u64 = 650;
pub const MAX_POOLS: usize = 262_144;
pub const MAX_MARGIN_NOTES: usize = 1_048_576;
pub const MAX_FUNDING_INTENTS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_GUARDRAILS: usize = 524_288;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_NULLIFIERS: usize = 4_194_304;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerpsMarketKind {
    XmrUsd,
    BtcUsd,
    EthUsd,
    XmrBtc,
    PrivateBasket,
    PrivateVolatility,
    PrivateRates,
    PrivateHashrate,
}

impl PerpsMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XmrUsd => "xmr_usd",
            Self::BtcUsd => "btc_usd",
            Self::EthUsd => "eth_usd",
            Self::XmrBtc => "xmr_btc",
            Self::PrivateBasket => "private_basket",
            Self::PrivateVolatility => "private_volatility",
            Self::PrivateRates => "private_rates",
            Self::PrivateHashrate => "private_hashrate",
        }
    }

    pub fn base_risk_weight_bps(self) -> u64 {
        match self {
            Self::XmrUsd => 1_000,
            Self::BtcUsd => 1_050,
            Self::EthUsd => 1_100,
            Self::XmrBtc => 1_220,
            Self::PrivateBasket => 1_350,
            Self::PrivateVolatility => 1_900,
            Self::PrivateRates => 1_450,
            Self::PrivateHashrate => 1_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Warmup,
    Active,
    FundingPaused,
    ReduceOnly,
    Degraded,
    Draining,
    Settled,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Active => "active",
            Self::FundingPaused => "funding_paused",
            Self::ReduceOnly => "reduce_only",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_trades(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Warmup | Self::Active | Self::Degraded)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::ReduceOnly | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
    Flat,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::Flat => "flat",
        }
    }

    pub fn sign(self) -> i128 {
        match self {
            Self::Long => 1,
            Self::Short => -1,
            Self::Flat => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginNoteStatus {
    Draft,
    Committed,
    Reserved,
    Netted,
    Settled,
    Rebated,
    LiquidationReserved,
    Expired,
    Quarantined,
}

impl MarginNoteStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Committed | Self::Reserved | Self::Rebated)
    }

    pub fn clearable(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Netted | Self::LiquidationReserved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingIntentStatus {
    Submitted,
    PrivacyChecked,
    Quoted,
    Attested,
    Batched,
    Cleared,
    Settled,
    Rebated,
    Expired,
    Rejected,
    Cancelled,
}

impl FundingIntentStatus {
    pub fn clearable(self) -> bool {
        matches!(self, Self::Attested | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPurpose {
    Quote,
    FundingRate,
    MarginSolvency,
    LiquidityGuardrail,
    RebateSettlement,
    BatchClearing,
    OperatorSummary,
}

impl AttestationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quote => "quote",
            Self::FundingRate => "funding_rate",
            Self::MarginSolvency => "margin_solvency",
            Self::LiquidityGuardrail => "liquidity_guardrail",
            Self::RebateSettlement => "rebate_settlement",
            Self::BatchClearing => "batch_clearing",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Verified,
    Used,
    Expired,
    Disputed,
    Slashed,
}

impl AttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Used)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailKind {
    MinCoverage,
    MaxUtilization,
    MaxSkew,
    MaxPriceImpact,
    FundingClamp,
    PrivacySetFloor,
    PqQuorum,
    LiquidationBackstop,
}

impl GuardrailKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinCoverage => "min_coverage",
            Self::MaxUtilization => "max_utilization",
            Self::MaxSkew => "max_skew",
            Self::MaxPriceImpact => "max_price_impact",
            Self::FundingClamp => "funding_clamp",
            Self::PrivacySetFloor => "privacy_set_floor",
            Self::PqQuorum => "pq_quorum",
            Self::LiquidationBackstop => "liquidation_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailStatus {
    Observing,
    Passed,
    Clamped,
    Triggered,
    Quarantined,
    Released,
}

impl GuardrailStatus {
    pub fn blocks_clearing(self) -> bool {
        matches!(self, Self::Triggered | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Allocated,
    Voucherized,
    Settled,
    Distributed,
    Expired,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    Proposed,
    Attested,
    Guarded,
    Settling,
    Settled,
    Rebated,
    Disputed,
    Quarantined,
}

impl ClearingBatchStatus {
    pub fn finalized(self) -> bool {
        matches!(self, Self::Settled | Self::Rebated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorHealth {
    Green,
    Watch,
    Degraded,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_quote_attestation_suite: String,
    pub confidential_pool_scheme: String,
    pub fee_credit_margin_note_scheme: String,
    pub funding_rate_intent_scheme: String,
    pub pq_quote_attestation_scheme: String,
    pub liquidity_guardrail_scheme: String,
    pub rebate_settlement_scheme: String,
    pub batch_clearing_scheme: String,
    pub operator_summary_scheme: String,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub liquidation_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub rebate_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quote_quorum: u16,
    pub funding_quorum: u16,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub margin_note_ttl_blocks: u64,
    pub clearing_window_blocks: u64,
    pub dispute_window_blocks: u64,
    pub max_batch_items: usize,
    pub min_liquidity_units: u128,
    pub min_vault_coverage_bps: u64,
    pub max_utilization_bps: u64,
    pub max_skew_bps: u64,
    pub max_price_impact_bps: u64,
    pub max_funding_rate_bps: i64,
    pub max_leverage_bps: u64,
    pub min_maintenance_margin_bps: u64,
    pub max_pools: usize,
    pub max_margin_notes: usize,
    pub max_funding_intents: usize,
    pub max_attestations: usize,
    pub max_guardrails: usize,
    pub max_rebates: usize,
    pub max_batches: usize,
    pub max_operator_summaries: usize,
    pub max_nullifiers: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_quote_attestation_suite: PQ_QUOTE_ATTESTATION_SUITE.to_string(),
            confidential_pool_scheme: CONFIDENTIAL_PERPS_POOL_SCHEME.to_string(),
            fee_credit_margin_note_scheme: FEE_CREDIT_MARGIN_NOTE_SCHEME.to_string(),
            funding_rate_intent_scheme: FUNDING_RATE_INTENT_SCHEME.to_string(),
            pq_quote_attestation_scheme: PQ_QUOTE_ATTESTATION_SCHEME.to_string(),
            liquidity_guardrail_scheme: LIQUIDITY_GUARDRAIL_SCHEME.to_string(),
            rebate_settlement_scheme: REBATE_SETTLEMENT_SCHEME.to_string(),
            batch_clearing_scheme: BATCH_CLEARING_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps: DEFAULT_LP_FEE_BPS,
            liquidation_fee_bps: DEFAULT_LIQUIDATION_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            rebate_cover_bps: DEFAULT_REBATE_COVER_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            quote_quorum: DEFAULT_QUOTE_QUORUM,
            funding_quorum: DEFAULT_FUNDING_QUORUM,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            margin_note_ttl_blocks: DEFAULT_MARGIN_NOTE_TTL_BLOCKS,
            clearing_window_blocks: DEFAULT_CLEARING_WINDOW_BLOCKS,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            min_liquidity_units: DEFAULT_MIN_LIQUIDITY_UNITS,
            min_vault_coverage_bps: DEFAULT_MIN_VAULT_COVERAGE_BPS,
            max_utilization_bps: DEFAULT_MAX_UTILIZATION_BPS,
            max_skew_bps: DEFAULT_MAX_SKEW_BPS,
            max_price_impact_bps: DEFAULT_MAX_PRICE_IMPACT_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            min_maintenance_margin_bps: DEFAULT_MIN_MAINTENANCE_MARGIN_BPS,
            max_pools: MAX_POOLS,
            max_margin_notes: MAX_MARGIN_NOTES,
            max_funding_intents: MAX_FUNDING_INTENTS,
            max_attestations: MAX_ATTESTATIONS,
            max_guardrails: MAX_GUARDRAILS,
            max_rebates: MAX_REBATES,
            max_batches: MAX_BATCHES,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
            max_nullifiers: MAX_NULLIFIERS,
            max_events: MAX_EVENTS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        ensure!(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee exceeds user cap"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS,
            "user fee cap exceeds max bps"
        );
        ensure!(
            self.protocol_fee_bps + self.lp_fee_bps <= self.max_user_fee_bps,
            "protocol and lp fee exceed user cap"
        );
        ensure!(
            self.rebate_cover_bps <= MAX_BPS,
            "rebate cover exceeds max bps"
        );
        ensure!(
            self.min_privacy_set_size <= self.batch_privacy_set_size,
            "batch privacy set below per-intent floor"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits below runtime floor"
        );
        ensure!(self.quote_quorum > 0, "quote quorum must be non-zero");
        ensure!(self.funding_quorum > 0, "funding quorum must be non-zero");
        ensure!(self.max_batch_items > 0, "batch size must be non-zero");
        ensure!(
            self.max_funding_rate_bps.unsigned_abs() <= MAX_BPS,
            "funding clamp exceeds max bps"
        );
        Ok(())
    }

    pub fn effective_trade_fee_bps(&self) -> u64 {
        self.low_fee_bps
            .max(self.protocol_fee_bps + self.lp_fee_bps)
            .min(self.max_user_fee_bps)
    }

    pub fn target_rebate_amount(&self, notional_units: u128) -> u128 {
        bps_amount(notional_units, self.target_rebate_bps)
    }

    pub fn maintenance_margin(&self, notional_units: u128) -> u128 {
        bps_amount(notional_units, self.min_maintenance_margin_bps)
    }

    pub fn max_leverage_multiple(&self) -> u64 {
        if self.max_leverage_bps == 0 {
            return 0;
        }
        MAX_BPS / self.max_leverage_bps.max(1)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub margin_notes: u64,
    pub funding_intents: u64,
    pub quote_attestations: u64,
    pub guardrails: u64,
    pub rebate_settlements: u64,
    pub clearing_batches: u64,
    pub operator_summaries: u64,
    pub nullifiers: u64,
    pub events: u64,
    pub total_notional_units: u128,
    pub total_margin_units: u128,
    pub total_fee_credit_units: u128,
    pub total_rebate_units: u128,
    pub total_protocol_fee_units: u128,
    pub total_lp_fee_units: u128,
    pub total_cleared_items: u64,
    pub total_quarantined_items: u64,
}

impl Counters {
    pub fn record_pool(&mut self) {
        self.pools += 1;
        self.events += 1;
    }

    pub fn record_margin_note(&mut self, note: &FeeCreditMarginNote) {
        self.margin_notes += 1;
        self.total_margin_units = self
            .total_margin_units
            .saturating_add(note.margin_commitment_units);
        self.total_fee_credit_units = self
            .total_fee_credit_units
            .saturating_add(note.fee_credit_units);
        self.events += 1;
    }

    pub fn record_funding_intent(&mut self, intent: &FundingRateIntent) {
        self.funding_intents += 1;
        self.total_notional_units = self
            .total_notional_units
            .saturating_add(intent.notional_units);
        self.events += 1;
    }

    pub fn record_attestation(&mut self) {
        self.quote_attestations += 1;
        self.events += 1;
    }

    pub fn record_guardrail(&mut self, blocked: bool) {
        self.guardrails += 1;
        if blocked {
            self.total_quarantined_items += 1;
        }
        self.events += 1;
    }

    pub fn record_rebate(&mut self, rebate: &RebateSettlement) {
        self.rebate_settlements += 1;
        self.total_rebate_units = self.total_rebate_units.saturating_add(rebate.rebate_units);
        self.events += 1;
    }

    pub fn record_batch(&mut self, batch: &BatchClearing) {
        self.clearing_batches += 1;
        self.total_cleared_items = self
            .total_cleared_items
            .saturating_add(batch.intent_ids.len() as u64);
        self.total_protocol_fee_units = self
            .total_protocol_fee_units
            .saturating_add(batch.protocol_fee_units);
        self.total_lp_fee_units = self.total_lp_fee_units.saturating_add(batch.lp_fee_units);
        self.events += 1;
    }

    pub fn record_operator_summary(&mut self) {
        self.operator_summaries += 1;
        self.events += 1;
    }

    pub fn record_nullifier(&mut self) {
        self.nullifiers += 1;
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub pools_root: String,
    pub margin_notes_root: String,
    pub funding_intents_root: String,
    pub pq_quote_attestations_root: String,
    pub liquidity_guardrails_root: String,
    pub rebate_settlements_root: String,
    pub batch_clearings_root: String,
    pub operator_summaries_root: String,
    pub nullifiers_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let mut roots = Self {
            pools_root: merkle_root(CONFIDENTIAL_PERPS_POOL_SCHEME, &[]),
            margin_notes_root: merkle_root(FEE_CREDIT_MARGIN_NOTE_SCHEME, &[]),
            funding_intents_root: merkle_root(FUNDING_RATE_INTENT_SCHEME, &[]),
            pq_quote_attestations_root: merkle_root(PQ_QUOTE_ATTESTATION_SCHEME, &[]),
            liquidity_guardrails_root: merkle_root(LIQUIDITY_GUARDRAIL_SCHEME, &[]),
            rebate_settlements_root: merkle_root(REBATE_SETTLEMENT_SCHEME, &[]),
            batch_clearings_root: merkle_root(BATCH_CLEARING_SCHEME, &[]),
            operator_summaries_root: merkle_root(OPERATOR_SUMMARY_SCHEME, &[]),
            nullifiers_root: merkle_root("fee-credit-perps-amm-nullifiers", &[]),
            events_root: merkle_root("fee-credit-perps-amm-events", &[]),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "private-l2-low-fee-pq-confidential-fee-credit-perps-amm-state-root",
            &[
                HashPart::Str(&self.pools_root),
                HashPart::Str(&self.margin_notes_root),
                HashPart::Str(&self.funding_intents_root),
                HashPart::Str(&self.pq_quote_attestations_root),
                HashPart::Str(&self.liquidity_guardrails_root),
                HashPart::Str(&self.rebate_settlements_root),
                HashPart::Str(&self.batch_clearings_root),
                HashPart::Str(&self.operator_summaries_root),
                HashPart::Str(&self.nullifiers_root),
                HashPart::Str(&self.events_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pools_root": self.pools_root,
            "margin_notes_root": self.margin_notes_root,
            "funding_intents_root": self.funding_intents_root,
            "pq_quote_attestations_root": self.pq_quote_attestations_root,
            "liquidity_guardrails_root": self.liquidity_guardrails_root,
            "rebate_settlements_root": self.rebate_settlements_root,
            "batch_clearings_root": self.batch_clearings_root,
            "operator_summaries_root": self.operator_summaries_root,
            "nullifiers_root": self.nullifiers_root,
            "events_root": self.events_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialPerpsPool {
    pub pool_id: String,
    pub market_kind: PerpsMarketKind,
    pub status: PoolStatus,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub fee_credit_asset_id: String,
    pub amm_commitment: String,
    pub lp_share_commitment: String,
    pub mark_price_commitment: String,
    pub index_price_commitment: String,
    pub liquidity_units: u128,
    pub open_interest_long_units: u128,
    pub open_interest_short_units: u128,
    pub virtual_base_reserve_units: u128,
    pub virtual_quote_reserve_units: u128,
    pub fee_credit_reserve_units: u128,
    pub rebate_reserve_units: u128,
    pub insurance_fund_units: u128,
    pub min_trade_notional_units: u128,
    pub max_trade_notional_units: u128,
    pub funding_index_bps: i64,
    pub last_funding_block: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub operator_id: String,
    pub guardrail_ids: BTreeSet<String>,
    pub metadata_commitment: String,
}

impl ConfidentialPerpsPool {
    pub fn new(
        pool_id: impl Into<String>,
        market_kind: PerpsMarketKind,
        collateral_asset_id: impl Into<String>,
        quote_asset_id: impl Into<String>,
        fee_credit_asset_id: impl Into<String>,
        liquidity_units: u128,
        operator_id: impl Into<String>,
        height: u64,
    ) -> Self {
        let pool_id = pool_id.into();
        let operator_id = operator_id.into();
        Self {
            amm_commitment: commitment("pool-amm", &[&pool_id, market_kind.as_str()]),
            lp_share_commitment: commitment("pool-lp", &[&pool_id, &operator_id]),
            mark_price_commitment: commitment("pool-mark", &[&pool_id, "mark"]),
            index_price_commitment: commitment("pool-index", &[&pool_id, "index"]),
            pool_id,
            market_kind,
            status: PoolStatus::Warmup,
            collateral_asset_id: collateral_asset_id.into(),
            quote_asset_id: quote_asset_id.into(),
            fee_credit_asset_id: fee_credit_asset_id.into(),
            liquidity_units,
            open_interest_long_units: 0,
            open_interest_short_units: 0,
            virtual_base_reserve_units: liquidity_units.saturating_mul(2),
            virtual_quote_reserve_units: liquidity_units.saturating_mul(200),
            fee_credit_reserve_units: bps_amount(liquidity_units, 65),
            rebate_reserve_units: bps_amount(liquidity_units, 95),
            insurance_fund_units: bps_amount(liquidity_units, 220),
            min_trade_notional_units: 10,
            max_trade_notional_units: liquidity_units / 8,
            funding_index_bps: 0,
            last_funding_block: height,
            created_at_height: height,
            updated_at_height: height,
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            operator_id,
            guardrail_ids: BTreeSet::new(),
            metadata_commitment: commitment("pool-metadata", &[market_kind.as_str()]),
        }
    }

    pub fn activate(mut self) -> Self {
        self.status = PoolStatus::Active;
        self
    }

    pub fn skew_units(&self) -> i128 {
        self.open_interest_long_units as i128 - self.open_interest_short_units as i128
    }

    pub fn total_open_interest_units(&self) -> u128 {
        self.open_interest_long_units
            .saturating_add(self.open_interest_short_units)
    }

    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(self.total_open_interest_units(), self.liquidity_units)
    }

    pub fn coverage_bps(&self) -> u64 {
        ratio_bps(
            self.liquidity_units
                .saturating_add(self.insurance_fund_units)
                .saturating_add(self.rebate_reserve_units),
            self.total_open_interest_units().max(1),
        )
    }

    pub fn skew_bps(&self) -> u64 {
        ratio_bps(
            self.skew_units().unsigned_abs(),
            self.total_open_interest_units().max(1),
        )
    }

    pub fn quote_trade_fee(&self, config: &Config, notional_units: u128) -> u128 {
        let risk_weight = self.market_kind.base_risk_weight_bps();
        let utilization_adder = self.utilization_bps() / 1_000;
        let fee_bps = config
            .effective_trade_fee_bps()
            .saturating_add(utilization_adder)
            .saturating_mul(risk_weight)
            / MAX_BPS;
        bps_amount(notional_units, fee_bps.max(config.low_fee_bps))
    }

    pub fn quote_rebate(&self, config: &Config, notional_units: u128) -> u128 {
        config
            .target_rebate_amount(notional_units)
            .min(self.rebate_reserve_units)
    }

    pub fn price_impact_bps(&self, notional_units: u128) -> u64 {
        ratio_bps(notional_units, self.virtual_quote_reserve_units.max(1))
    }

    pub fn can_accept_trade(
        &self,
        config: &Config,
        side: PositionSide,
        notional_units: u128,
    ) -> Result<()> {
        ensure!(
            self.status.accepts_trades(),
            "pool {} does not accept trades",
            self.pool_id
        );
        ensure!(
            notional_units >= self.min_trade_notional_units,
            "trade below pool minimum"
        );
        ensure!(
            notional_units <= self.max_trade_notional_units,
            "trade above pool maximum"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "pool privacy set below floor"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pool pq security below floor"
        );
        ensure!(
            self.price_impact_bps(notional_units) <= config.max_price_impact_bps,
            "price impact exceeds guardrail"
        );
        let projected_long = if side == PositionSide::Long {
            self.open_interest_long_units.saturating_add(notional_units)
        } else {
            self.open_interest_long_units
        };
        let projected_short = if side == PositionSide::Short {
            self.open_interest_short_units
                .saturating_add(notional_units)
        } else {
            self.open_interest_short_units
        };
        let projected_total = projected_long.saturating_add(projected_short);
        let projected_skew = (projected_long as i128 - projected_short as i128).unsigned_abs();
        ensure!(
            ratio_bps(projected_total, self.liquidity_units) <= config.max_utilization_bps,
            "utilization exceeds guardrail"
        );
        ensure!(
            ratio_bps(projected_skew, projected_total.max(1)) <= config.max_skew_bps,
            "skew exceeds guardrail"
        );
        Ok(())
    }

    pub fn apply_intent(&mut self, intent: &FundingRateIntent, height: u64) -> Result<()> {
        self.can_accept_trade(&Config::default(), intent.side, intent.notional_units)?;
        match intent.side {
            PositionSide::Long => {
                self.open_interest_long_units = self
                    .open_interest_long_units
                    .saturating_add(intent.notional_units);
            }
            PositionSide::Short => {
                self.open_interest_short_units = self
                    .open_interest_short_units
                    .saturating_add(intent.notional_units);
            }
            PositionSide::Flat => {}
        }
        self.fee_credit_reserve_units = self
            .fee_credit_reserve_units
            .saturating_add(intent.max_fee_credit_units);
        self.updated_at_height = height;
        Ok(())
    }

    pub fn apply_funding(&mut self, funding_delta_bps: i64, height: u64) {
        self.funding_index_bps = self.funding_index_bps.saturating_add(funding_delta_bps);
        self.last_funding_block = height;
        self.updated_at_height = height;
    }

    pub fn add_guardrail(&mut self, guardrail_id: impl Into<String>) {
        self.guardrail_ids.insert(guardrail_id.into());
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            "confidential-perps-pool",
            &[HashPart::Str(&self.pool_id), HashPart::Json(&self.leaf())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditMarginNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub position_commitment: String,
    pub margin_commitment: String,
    pub fee_credit_commitment: String,
    pub nullifier: String,
    pub status: MarginNoteStatus,
    pub side: PositionSide,
    pub notional_units: u128,
    pub margin_commitment_units: u128,
    pub fee_credit_units: u128,
    pub maintenance_margin_units: u128,
    pub leverage_bps: u64,
    pub entry_funding_index_bps: i64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub settlement_hint_commitment: String,
}

impl FeeCreditMarginNote {
    pub fn new(
        note_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        pool: &ConfidentialPerpsPool,
        side: PositionSide,
        notional_units: u128,
        margin_units: u128,
        fee_credit_units: u128,
        config: &Config,
        height: u64,
    ) -> Self {
        let note_id = note_id.into();
        let owner_commitment = owner_commitment.into();
        Self {
            position_commitment: commitment(
                "note-position",
                &[&note_id, &pool.pool_id, side.as_str()],
            ),
            margin_commitment: commitment("note-margin", &[&note_id, &margin_units.to_string()]),
            fee_credit_commitment: commitment(
                "note-fee-credit",
                &[&note_id, &fee_credit_units.to_string()],
            ),
            nullifier: commitment("note-nullifier", &[&note_id, &owner_commitment]),
            note_id,
            owner_commitment,
            pool_id: pool.pool_id.clone(),
            status: MarginNoteStatus::Committed,
            side,
            notional_units,
            margin_commitment_units: margin_units,
            fee_credit_units,
            maintenance_margin_units: config.maintenance_margin(notional_units),
            leverage_bps: ratio_bps(notional_units, margin_units.max(1)),
            entry_funding_index_bps: pool.funding_index_bps,
            created_at_height: height,
            expires_at_height: height.saturating_add(config.margin_note_ttl_blocks),
            privacy_set_size: config.batch_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            settlement_hint_commitment: commitment("note-settlement-hint", &[&note_id]),
        }
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(self.status.spendable(), "margin note is not spendable");
        ensure!(height <= self.expires_at_height, "margin note expired");
        ensure!(
            self.margin_commitment_units >= self.maintenance_margin_units,
            "margin below maintenance"
        );
        ensure!(
            self.leverage_bps <= config.max_leverage_bps,
            "leverage exceeds runtime cap"
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "margin note privacy set below floor"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "margin note pq security below floor"
        );
        Ok(())
    }

    pub fn reserve_for_clearing(&mut self) -> Result<()> {
        ensure!(self.status.spendable(), "margin note cannot be reserved");
        self.status = MarginNoteStatus::Reserved;
        Ok(())
    }

    pub fn settle(&mut self) {
        self.status = MarginNoteStatus::Settled;
    }

    pub fn rebate(&mut self, rebate_units: u128) {
        self.fee_credit_units = self.fee_credit_units.saturating_add(rebate_units);
        self.status = MarginNoteStatus::Rebated;
    }

    pub fn funding_pnl_units(&self, current_funding_index_bps: i64) -> i128 {
        let delta_bps = current_funding_index_bps.saturating_sub(self.entry_funding_index_bps);
        self.side.sign() * bps_amount(self.notional_units, delta_bps.unsigned_abs()) as i128
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingRateIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub margin_note_id: String,
    pub side: PositionSide,
    pub status: FundingIntentStatus,
    pub notional_units: u128,
    pub max_fee_credit_units: u128,
    pub min_rebate_units: u128,
    pub limit_price_commitment: String,
    pub oracle_round_commitment: String,
    pub funding_rate_limit_bps: i64,
    pub liquidation_guard_bps: u64,
    pub nullifier: String,
    pub quote_attestation_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub metadata_commitment: String,
}

impl FundingRateIntent {
    pub fn new(
        intent_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        pool_id: impl Into<String>,
        margin_note_id: impl Into<String>,
        side: PositionSide,
        notional_units: u128,
        config: &Config,
        height: u64,
    ) -> Self {
        let intent_id = intent_id.into();
        let owner_commitment = owner_commitment.into();
        let pool_id = pool_id.into();
        let margin_note_id = margin_note_id.into();
        Self {
            limit_price_commitment: commitment("intent-limit-price", &[&intent_id, &pool_id]),
            oracle_round_commitment: commitment("intent-oracle-round", &[&intent_id]),
            nullifier: commitment("intent-nullifier", &[&intent_id, &owner_commitment]),
            metadata_commitment: commitment("intent-metadata", &[&intent_id, side.as_str()]),
            intent_id,
            owner_commitment,
            pool_id,
            margin_note_id,
            side,
            status: FundingIntentStatus::Submitted,
            notional_units,
            max_fee_credit_units: bps_amount(notional_units, config.max_user_fee_bps),
            min_rebate_units: bps_amount(notional_units, config.target_rebate_bps / 2),
            funding_rate_limit_bps: config.max_funding_rate_bps,
            liquidation_guard_bps: config.min_maintenance_margin_bps,
            quote_attestation_id: None,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(config.intent_ttl_blocks),
            privacy_set_size: config.batch_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
        }
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(height <= self.expires_at_height, "funding intent expired");
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "intent privacy set below floor"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "intent pq security below floor"
        );
        ensure!(
            self.max_fee_credit_units <= bps_amount(self.notional_units, config.max_user_fee_bps),
            "intent fee credit exceeds user cap"
        );
        ensure!(
            self.funding_rate_limit_bps.unsigned_abs()
                <= config.max_funding_rate_bps.unsigned_abs(),
            "intent funding limit exceeds runtime clamp"
        );
        Ok(())
    }

    pub fn attach_attestation(&mut self, attestation_id: impl Into<String>) {
        self.quote_attestation_id = Some(attestation_id.into());
        self.status = FundingIntentStatus::Attested;
    }

    pub fn mark_privacy_checked(&mut self) {
        self.status = FundingIntentStatus::PrivacyChecked;
    }

    pub fn mark_batched(&mut self) {
        self.status = FundingIntentStatus::Batched;
    }

    pub fn settle(&mut self) {
        self.status = FundingIntentStatus::Settled;
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqQuoteAttestation {
    pub attestation_id: String,
    pub purpose: AttestationPurpose,
    pub status: AttestationStatus,
    pub pool_id: String,
    pub intent_id: String,
    pub committee_id: String,
    pub quote_commitment: String,
    pub mark_price_commitment: String,
    pub funding_rate_commitment: String,
    pub fee_credit_commitment: String,
    pub rebate_commitment: String,
    pub guardrail_commitment: String,
    pub transcript_hash: String,
    pub aggregate_signature: String,
    pub ml_kem_ciphertext_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_fallback_root: String,
    pub quorum_weight: u16,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PqQuoteAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        purpose: AttestationPurpose,
        pool_id: impl Into<String>,
        intent_id: impl Into<String>,
        config: &Config,
        height: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let pool_id = pool_id.into();
        let intent_id = intent_id.into();
        let committee_id = commitment("attestation-committee", &[&pool_id, purpose.as_str()]);
        let transcript_hash = commitment("attestation-transcript", &[&attestation_id, &intent_id]);
        Self {
            quote_commitment: commitment("attestation-quote", &[&attestation_id]),
            mark_price_commitment: commitment("attestation-mark", &[&attestation_id]),
            funding_rate_commitment: commitment("attestation-funding", &[&attestation_id]),
            fee_credit_commitment: commitment("attestation-fee-credit", &[&attestation_id]),
            rebate_commitment: commitment("attestation-rebate", &[&attestation_id]),
            guardrail_commitment: commitment("attestation-guardrail", &[&attestation_id]),
            aggregate_signature: commitment("attestation-aggregate-signature", &[&transcript_hash]),
            ml_kem_ciphertext_root: commitment("attestation-ml-kem", &[&attestation_id]),
            ml_dsa_signature_root: commitment("attestation-ml-dsa", &[&attestation_id]),
            slh_dsa_fallback_root: commitment("attestation-slh-dsa", &[&attestation_id]),
            attestation_id,
            purpose,
            status: AttestationStatus::Verified,
            pool_id,
            intent_id,
            committee_id,
            transcript_hash,
            quorum_weight: config.quote_quorum,
            pq_security_bits: config.min_pq_security_bits,
            created_at_height: height,
            expires_at_height: height.saturating_add(config.attestation_ttl_blocks),
        }
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure!(self.status.usable(), "attestation is not usable");
        ensure!(height <= self.expires_at_height, "attestation expired");
        ensure!(
            self.quorum_weight >= config.quote_quorum,
            "attestation quorum below quote quorum"
        );
        ensure!(
            self.pq_security_bits >= config.min_pq_security_bits,
            "attestation pq security below floor"
        );
        Ok(())
    }

    pub fn use_once(&mut self) {
        self.status = AttestationStatus::Used;
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityGuardrail {
    pub guardrail_id: String,
    pub pool_id: String,
    pub kind: GuardrailKind,
    pub status: GuardrailStatus,
    pub observed_value_bps: i64,
    pub limit_value_bps: i64,
    pub liquidity_units: u128,
    pub open_interest_units: u128,
    pub insurance_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub evidence_commitment: String,
    pub attestation_id: Option<String>,
    pub created_at_height: u64,
}

impl LiquidityGuardrail {
    pub fn for_pool(
        guardrail_id: impl Into<String>,
        pool: &ConfidentialPerpsPool,
        kind: GuardrailKind,
        observed_value_bps: i64,
        limit_value_bps: i64,
        height: u64,
    ) -> Self {
        let guardrail_id = guardrail_id.into();
        let status = if observed_value_bps.unsigned_abs() <= limit_value_bps.unsigned_abs() {
            GuardrailStatus::Passed
        } else {
            GuardrailStatus::Triggered
        };
        Self {
            evidence_commitment: commitment(
                "guardrail-evidence",
                &[&guardrail_id, &pool.pool_id, kind.as_str()],
            ),
            guardrail_id,
            pool_id: pool.pool_id.clone(),
            kind,
            status,
            observed_value_bps,
            limit_value_bps,
            liquidity_units: pool.liquidity_units,
            open_interest_units: pool.total_open_interest_units(),
            insurance_units: pool.insurance_fund_units,
            privacy_set_size: pool.privacy_set_size,
            pq_security_bits: pool.pq_security_bits,
            attestation_id: None,
            created_at_height: height,
        }
    }

    pub fn attach_attestation(&mut self, attestation_id: impl Into<String>) {
        self.attestation_id = Some(attestation_id.into());
        if !self.status.blocks_clearing() {
            self.status = GuardrailStatus::Passed;
        }
    }

    pub fn clamp(&mut self) {
        self.status = GuardrailStatus::Clamped;
    }

    pub fn release(&mut self) {
        self.status = GuardrailStatus::Released;
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateSettlement {
    pub rebate_id: String,
    pub pool_id: String,
    pub margin_note_id: String,
    pub intent_id: String,
    pub status: RebateStatus,
    pub rebate_units: u128,
    pub fee_credit_units_used: u128,
    pub settlement_commitment: String,
    pub voucher_commitment: String,
    pub recipient_commitment: String,
    pub attestation_id: Option<String>,
    pub created_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl RebateSettlement {
    pub fn new(
        rebate_id: impl Into<String>,
        pool_id: impl Into<String>,
        margin_note_id: impl Into<String>,
        intent_id: impl Into<String>,
        recipient_commitment: impl Into<String>,
        rebate_units: u128,
        fee_credit_units_used: u128,
        height: u64,
    ) -> Self {
        let rebate_id = rebate_id.into();
        let pool_id = pool_id.into();
        let margin_note_id = margin_note_id.into();
        let intent_id = intent_id.into();
        let recipient_commitment = recipient_commitment.into();
        Self {
            settlement_commitment: commitment("rebate-settlement", &[&rebate_id, &pool_id]),
            voucher_commitment: commitment("rebate-voucher", &[&rebate_id, &recipient_commitment]),
            rebate_id,
            pool_id,
            margin_note_id,
            intent_id,
            status: RebateStatus::Allocated,
            rebate_units,
            fee_credit_units_used,
            recipient_commitment,
            attestation_id: None,
            created_at_height: height,
            settled_at_height: None,
        }
    }

    pub fn attach_attestation(&mut self, attestation_id: impl Into<String>) {
        self.attestation_id = Some(attestation_id.into());
        self.status = RebateStatus::Voucherized;
    }

    pub fn settle(&mut self, height: u64) {
        self.status = RebateStatus::Settled;
        self.settled_at_height = Some(height);
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchClearing {
    pub batch_id: String,
    pub status: ClearingBatchStatus,
    pub pool_id: String,
    pub intent_ids: Vec<String>,
    pub margin_note_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub guardrail_ids: Vec<String>,
    pub rebate_ids: Vec<String>,
    pub aggregate_notional_units: u128,
    pub aggregate_margin_units: u128,
    pub aggregate_fee_credit_units: u128,
    pub aggregate_rebate_units: u128,
    pub protocol_fee_units: u128,
    pub lp_fee_units: u128,
    pub funding_rate_bps: i64,
    pub clearing_price_commitment: String,
    pub clearing_root: String,
    pub settlement_root: String,
    pub created_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl BatchClearing {
    pub fn new(batch_id: impl Into<String>, pool_id: impl Into<String>, height: u64) -> Self {
        let batch_id = batch_id.into();
        let pool_id = pool_id.into();
        Self {
            clearing_price_commitment: commitment("batch-clearing-price", &[&batch_id, &pool_id]),
            clearing_root: commitment("batch-clearing-root", &[&batch_id]),
            settlement_root: commitment("batch-settlement-root", &[&batch_id]),
            batch_id,
            status: ClearingBatchStatus::Proposed,
            pool_id,
            intent_ids: Vec::new(),
            margin_note_ids: Vec::new(),
            attestation_ids: Vec::new(),
            guardrail_ids: Vec::new(),
            rebate_ids: Vec::new(),
            aggregate_notional_units: 0,
            aggregate_margin_units: 0,
            aggregate_fee_credit_units: 0,
            aggregate_rebate_units: 0,
            protocol_fee_units: 0,
            lp_fee_units: 0,
            funding_rate_bps: 0,
            created_at_height: height,
            settled_at_height: None,
        }
    }

    pub fn add_intent(
        &mut self,
        intent: &FundingRateIntent,
        note: &FeeCreditMarginNote,
        attestation: &PqQuoteAttestation,
        config: &Config,
    ) -> Result<()> {
        ensure!(
            self.intent_ids.len() < config.max_batch_items,
            "batch exceeds configured maximum"
        );
        ensure!(intent.status.clearable(), "intent is not clearable");
        ensure!(note.status.clearable(), "margin note is not clearable");
        ensure!(attestation.status.usable(), "attestation is not usable");
        self.intent_ids.push(intent.intent_id.clone());
        self.margin_note_ids.push(note.note_id.clone());
        self.attestation_ids
            .push(attestation.attestation_id.clone());
        self.aggregate_notional_units = self
            .aggregate_notional_units
            .saturating_add(intent.notional_units);
        self.aggregate_margin_units = self
            .aggregate_margin_units
            .saturating_add(note.margin_commitment_units);
        self.aggregate_fee_credit_units = self
            .aggregate_fee_credit_units
            .saturating_add(intent.max_fee_credit_units);
        self.protocol_fee_units = self
            .protocol_fee_units
            .saturating_add(bps_amount(intent.notional_units, config.protocol_fee_bps));
        self.lp_fee_units = self
            .lp_fee_units
            .saturating_add(bps_amount(intent.notional_units, config.lp_fee_bps));
        self.status = ClearingBatchStatus::Attested;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_guardrail(&mut self, guardrail: &LiquidityGuardrail) {
        self.guardrail_ids.push(guardrail.guardrail_id.clone());
        if guardrail.status.blocks_clearing() {
            self.status = ClearingBatchStatus::Quarantined;
        } else if self.status == ClearingBatchStatus::Attested {
            self.status = ClearingBatchStatus::Guarded;
        }
        self.refresh_roots();
    }

    pub fn add_rebate(&mut self, rebate: &RebateSettlement) {
        self.rebate_ids.push(rebate.rebate_id.clone());
        self.aggregate_rebate_units = self
            .aggregate_rebate_units
            .saturating_add(rebate.rebate_units);
        self.refresh_roots();
    }

    pub fn settle(&mut self, funding_rate_bps: i64, height: u64) {
        self.funding_rate_bps = funding_rate_bps;
        self.status = ClearingBatchStatus::Settled;
        self.settled_at_height = Some(height);
        self.refresh_roots();
    }

    pub fn mark_rebated(&mut self) {
        self.status = ClearingBatchStatus::Rebated;
        self.refresh_roots();
    }

    pub fn refresh_roots(&mut self) {
        let clearing_payload = json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "intent_ids": self.intent_ids,
            "margin_note_ids": self.margin_note_ids,
            "attestation_ids": self.attestation_ids,
            "guardrail_ids": self.guardrail_ids,
        });
        let settlement_payload = json!({
            "batch_id": self.batch_id,
            "aggregate_notional_units": self.aggregate_notional_units.to_string(),
            "aggregate_margin_units": self.aggregate_margin_units.to_string(),
            "aggregate_fee_credit_units": self.aggregate_fee_credit_units.to_string(),
            "aggregate_rebate_units": self.aggregate_rebate_units.to_string(),
            "protocol_fee_units": self.protocol_fee_units.to_string(),
            "lp_fee_units": self.lp_fee_units.to_string(),
            "funding_rate_bps": self.funding_rate_bps,
        });
        self.clearing_root = domain_hash(
            "batch-clearing-root",
            &[HashPart::Json(&clearing_payload)],
            32,
        );
        self.settlement_root = domain_hash(
            "batch-settlement-root",
            &[HashPart::Json(&settlement_payload)],
            32,
        );
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub health: OperatorHealth,
    pub pool_ids: Vec<String>,
    pub batch_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub guardrail_ids: Vec<String>,
    pub aggregate_liquidity_units: u128,
    pub aggregate_open_interest_units: u128,
    pub aggregate_fee_credit_units: u128,
    pub aggregate_rebate_units: u128,
    pub average_fee_bps: u64,
    pub average_rebate_bps: u64,
    pub max_utilization_bps: u64,
    pub max_skew_bps: u64,
    pub privacy_set_floor: u64,
    pub pq_security_floor: u16,
    pub summary_root: String,
    pub created_at_height: u64,
}

impl OperatorSummary {
    pub fn new(
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
        pools: &[ConfidentialPerpsPool],
        batches: &[BatchClearing],
        config: &Config,
        height: u64,
    ) -> Self {
        let summary_id = summary_id.into();
        let operator_id = operator_id.into();
        let pool_ids = pools
            .iter()
            .map(|pool| pool.pool_id.clone())
            .collect::<Vec<_>>();
        let batch_ids = batches
            .iter()
            .map(|batch| batch.batch_id.clone())
            .collect::<Vec<_>>();
        let aggregate_liquidity_units = pools
            .iter()
            .fold(0_u128, |acc, pool| acc.saturating_add(pool.liquidity_units));
        let aggregate_open_interest_units = pools.iter().fold(0_u128, |acc, pool| {
            acc.saturating_add(pool.total_open_interest_units())
        });
        let aggregate_fee_credit_units = pools.iter().fold(0_u128, |acc, pool| {
            acc.saturating_add(pool.fee_credit_reserve_units)
        });
        let aggregate_rebate_units = batches.iter().fold(0_u128, |acc, batch| {
            acc.saturating_add(batch.aggregate_rebate_units)
        });
        let max_utilization_bps = pools
            .iter()
            .map(ConfidentialPerpsPool::utilization_bps)
            .max()
            .unwrap_or_default();
        let max_skew_bps = pools
            .iter()
            .map(ConfidentialPerpsPool::skew_bps)
            .max()
            .unwrap_or_default();
        let health = if max_utilization_bps > config.max_utilization_bps
            || max_skew_bps > config.max_skew_bps
        {
            OperatorHealth::Watch
        } else {
            OperatorHealth::Green
        };
        let mut summary = Self {
            summary_id,
            operator_id,
            health,
            pool_ids,
            batch_ids,
            attestation_ids: Vec::new(),
            guardrail_ids: pools
                .iter()
                .flat_map(|pool| pool.guardrail_ids.iter().cloned())
                .collect(),
            aggregate_liquidity_units,
            aggregate_open_interest_units,
            aggregate_fee_credit_units,
            aggregate_rebate_units,
            average_fee_bps: config.effective_trade_fee_bps(),
            average_rebate_bps: config.target_rebate_bps,
            max_utilization_bps,
            max_skew_bps,
            privacy_set_floor: pools
                .iter()
                .map(|pool| pool.privacy_set_size)
                .min()
                .unwrap_or(config.min_privacy_set_size),
            pq_security_floor: pools
                .iter()
                .map(|pool| pool.pq_security_bits)
                .min()
                .unwrap_or(config.min_pq_security_bits),
            summary_root: String::new(),
            created_at_height: height,
        };
        summary.summary_root = summary.compute_root();
        summary
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "operator-summary-root",
            &[
                HashPart::Str(&self.summary_id),
                HashPart::Json(&json!(self)),
            ],
            32,
        )
    }

    pub fn leaf(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub pools: BTreeMap<String, ConfidentialPerpsPool>,
    pub margin_notes: BTreeMap<String, FeeCreditMarginNote>,
    pub funding_intents: BTreeMap<String, FundingRateIntent>,
    pub pq_quote_attestations: BTreeMap<String, PqQuoteAttestation>,
    pub liquidity_guardrails: BTreeMap<String, LiquidityGuardrail>,
    pub rebate_settlements: BTreeMap<String, RebateSettlement>,
    pub batch_clearings: BTreeMap<String, BatchClearing>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
    pub counters: Counters,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        Self::new(
            Config::default(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
    }
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Self {
        Self {
            config,
            l2_height,
            monero_height,
            epoch,
            pools: BTreeMap::new(),
            margin_notes: BTreeMap::new(),
            funding_intents: BTreeMap::new(),
            pq_quote_attestations: BTreeMap::new(),
            liquidity_guardrails: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            batch_clearings: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            events: Vec::new(),
            counters: Counters::default(),
            roots: Roots::empty(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.config.validate().expect("devnet config is valid");
        state
            .register_pool(
                ConfidentialPerpsPool::new(
                    "pool-xmr-usd-low-fee-perps",
                    PerpsMarketKind::XmrUsd,
                    DEVNET_COLLATERAL_ASSET_ID,
                    DEVNET_QUOTE_ASSET_ID,
                    DEVNET_FEE_CREDIT_ASSET_ID,
                    12_500_000,
                    "operator-low-fee-perps-a",
                    DEVNET_L2_HEIGHT,
                )
                .activate(),
            )
            .expect("devnet pool registers");
        state
            .register_pool(
                ConfidentialPerpsPool::new(
                    "pool-btc-usd-low-fee-perps",
                    PerpsMarketKind::BtcUsd,
                    DEVNET_COLLATERAL_ASSET_ID,
                    DEVNET_QUOTE_ASSET_ID,
                    DEVNET_FEE_CREDIT_ASSET_ID,
                    8_750_000,
                    "operator-low-fee-perps-b",
                    DEVNET_L2_HEIGHT,
                )
                .activate(),
            )
            .expect("devnet pool registers");
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let pool_id = "pool-xmr-usd-low-fee-perps";
        let pool = state.pools.get(pool_id).expect("demo pool").clone();
        let mut note = FeeCreditMarginNote::new(
            "note-demo-maker-001",
            commitment("owner", &["maker-001"]),
            &pool,
            PositionSide::Long,
            125_000,
            32_500,
            220,
            &state.config,
            state.l2_height,
        );
        note.reserve_for_clearing().expect("demo reserve");
        state.register_margin_note(note).expect("demo note");
        let mut intent = FundingRateIntent::new(
            "intent-demo-maker-001",
            commitment("owner", &["maker-001"]),
            pool_id,
            "note-demo-maker-001",
            PositionSide::Long,
            125_000,
            &state.config,
            state.l2_height,
        );
        intent.mark_privacy_checked();
        let attestation = PqQuoteAttestation::new(
            "att-demo-maker-001",
            AttestationPurpose::Quote,
            pool_id,
            &intent.intent_id,
            &state.config,
            state.l2_height,
        );
        intent.attach_attestation(attestation.attestation_id.clone());
        state
            .register_attestation(attestation)
            .expect("demo attestation");
        state.register_funding_intent(intent).expect("demo intent");
        state
            .publish_guardrail(
                "guard-demo-utilization",
                pool_id,
                GuardrailKind::MaxUtilization,
            )
            .expect("demo guardrail");
        state
            .clear_batch(
                "batch-demo-low-fee-perps",
                pool_id,
                &["intent-demo-maker-001"],
            )
            .expect("demo batch");
        state
            .publish_operator_summary("summary-demo-low-fee-perps", "operator-low-fee-perps-a")
            .expect("demo summary");
        state.refresh_roots();
        state
    }

    pub fn register_pool(&mut self, pool: ConfidentialPerpsPool) -> Result<()> {
        ensure!(
            self.pools.len() < self.config.max_pools,
            "pool limit reached"
        );
        ensure!(
            !self.pools.contains_key(&pool.pool_id),
            "pool already exists"
        );
        ensure!(
            pool.liquidity_units >= self.config.min_liquidity_units,
            "pool liquidity below floor"
        );
        ensure!(
            pool.privacy_set_size >= self.config.min_privacy_set_size,
            "pool privacy set below floor"
        );
        ensure!(
            pool.pq_security_bits >= self.config.min_pq_security_bits,
            "pool pq bits below floor"
        );
        self.counters.record_pool();
        self.events.push(json!({
            "type": "confidential_perps_pool_registered",
            "pool_id": pool.pool_id,
            "market_kind": pool.market_kind.as_str(),
            "height": self.l2_height,
        }));
        self.pools.insert(pool.pool_id.clone(), pool);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_margin_note(&mut self, note: FeeCreditMarginNote) -> Result<()> {
        ensure!(
            self.margin_notes.len() < self.config.max_margin_notes,
            "margin note limit reached"
        );
        ensure!(
            !self.margin_notes.contains_key(&note.note_id),
            "margin note exists"
        );
        ensure!(
            !self.nullifiers.contains(&note.nullifier),
            "margin note nullifier reused"
        );
        ensure!(self.pools.contains_key(&note.pool_id), "unknown pool");
        note.validate(&self.config, self.l2_height)?;
        self.nullifiers.insert(note.nullifier.clone());
        self.counters.record_nullifier();
        self.counters.record_margin_note(&note);
        self.events.push(json!({
            "type": "fee_credit_margin_note_registered",
            "note_id": note.note_id,
            "pool_id": note.pool_id,
            "height": self.l2_height,
        }));
        self.margin_notes.insert(note.note_id.clone(), note);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_funding_intent(&mut self, intent: FundingRateIntent) -> Result<()> {
        ensure!(
            self.funding_intents.len() < self.config.max_funding_intents,
            "funding intent limit reached"
        );
        ensure!(
            !self.funding_intents.contains_key(&intent.intent_id),
            "funding intent exists"
        );
        ensure!(
            !self.nullifiers.contains(&intent.nullifier),
            "intent nullifier reused"
        );
        ensure!(self.pools.contains_key(&intent.pool_id), "unknown pool");
        ensure!(
            self.margin_notes.contains_key(&intent.margin_note_id),
            "unknown margin note"
        );
        intent.validate(&self.config, self.l2_height)?;
        let pool = self.pools.get(&intent.pool_id).expect("pool checked");
        pool.can_accept_trade(&self.config, intent.side, intent.notional_units)?;
        self.nullifiers.insert(intent.nullifier.clone());
        self.counters.record_nullifier();
        self.counters.record_funding_intent(&intent);
        self.events.push(json!({
            "type": "funding_rate_intent_registered",
            "intent_id": intent.intent_id,
            "pool_id": intent.pool_id,
            "height": self.l2_height,
        }));
        self.funding_intents
            .insert(intent.intent_id.clone(), intent);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_attestation(&mut self, attestation: PqQuoteAttestation) -> Result<()> {
        ensure!(
            self.pq_quote_attestations.len() < self.config.max_attestations,
            "attestation limit reached"
        );
        ensure!(
            !self
                .pq_quote_attestations
                .contains_key(&attestation.attestation_id),
            "attestation exists"
        );
        ensure!(
            self.pools.contains_key(&attestation.pool_id),
            "unknown pool"
        );
        attestation.validate(&self.config, self.l2_height)?;
        self.counters.record_attestation();
        self.events.push(json!({
            "type": "pq_quote_attestation_registered",
            "attestation_id": attestation.attestation_id,
            "pool_id": attestation.pool_id,
            "purpose": attestation.purpose.as_str(),
            "height": self.l2_height,
        }));
        self.pq_quote_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_guardrail(
        &mut self,
        guardrail_id: impl Into<String>,
        pool_id: impl AsRef<str>,
        kind: GuardrailKind,
    ) -> Result<String> {
        ensure!(
            self.liquidity_guardrails.len() < self.config.max_guardrails,
            "guardrail limit reached"
        );
        let pool_id = pool_id.as_ref();
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| format!("unknown pool {pool_id}"))?
            .clone();
        let observed = match kind {
            GuardrailKind::MinCoverage => pool.coverage_bps() as i64,
            GuardrailKind::MaxUtilization => pool.utilization_bps() as i64,
            GuardrailKind::MaxSkew => pool.skew_bps() as i64,
            GuardrailKind::MaxPriceImpact => 0,
            GuardrailKind::FundingClamp => pool.funding_index_bps,
            GuardrailKind::PrivacySetFloor => pool.privacy_set_size as i64,
            GuardrailKind::PqQuorum => pool.pq_security_bits as i64,
            GuardrailKind::LiquidationBackstop => {
                ratio_bps(pool.insurance_fund_units, pool.liquidity_units) as i64
            }
        };
        let limit = match kind {
            GuardrailKind::MinCoverage => self.config.min_vault_coverage_bps as i64,
            GuardrailKind::MaxUtilization => self.config.max_utilization_bps as i64,
            GuardrailKind::MaxSkew => self.config.max_skew_bps as i64,
            GuardrailKind::MaxPriceImpact => self.config.max_price_impact_bps as i64,
            GuardrailKind::FundingClamp => self.config.max_funding_rate_bps,
            GuardrailKind::PrivacySetFloor => self.config.min_privacy_set_size as i64,
            GuardrailKind::PqQuorum => self.config.min_pq_security_bits as i64,
            GuardrailKind::LiquidationBackstop => self.config.min_maintenance_margin_bps as i64,
        };
        let guardrail_id = guardrail_id.into();
        ensure!(
            !self.liquidity_guardrails.contains_key(&guardrail_id),
            "guardrail exists"
        );
        let guardrail = LiquidityGuardrail::for_pool(
            guardrail_id.clone(),
            &pool,
            kind,
            observed,
            limit,
            self.l2_height,
        );
        if let Some(pool) = self.pools.get_mut(pool_id) {
            pool.add_guardrail(guardrail_id.clone());
        }
        self.counters
            .record_guardrail(guardrail.status.blocks_clearing());
        self.events.push(json!({
            "type": "liquidity_guardrail_published",
            "guardrail_id": guardrail.guardrail_id,
            "pool_id": guardrail.pool_id,
            "kind": guardrail.kind.as_str(),
            "status": guardrail.status,
            "height": self.l2_height,
        }));
        self.liquidity_guardrails
            .insert(guardrail.guardrail_id.clone(), guardrail);
        self.refresh_roots();
        Ok(guardrail_id)
    }

    pub fn clear_batch(
        &mut self,
        batch_id: impl Into<String>,
        pool_id: impl AsRef<str>,
        intent_ids: &[&str],
    ) -> Result<String> {
        ensure!(
            self.batch_clearings.len() < self.config.max_batches,
            "batch limit reached"
        );
        let batch_id = batch_id.into();
        ensure!(
            !self.batch_clearings.contains_key(&batch_id),
            "batch exists"
        );
        let pool_id = pool_id.as_ref();
        ensure!(self.pools.contains_key(pool_id), "unknown pool");
        let mut batch = BatchClearing::new(batch_id.clone(), pool_id, self.l2_height);
        let mut rebates = Vec::new();
        for intent_id in intent_ids {
            let intent = self
                .funding_intents
                .get_mut(*intent_id)
                .ok_or_else(|| format!("unknown intent {intent_id}"))?;
            let note = self
                .margin_notes
                .get_mut(&intent.margin_note_id)
                .ok_or_else(|| format!("unknown margin note {}", intent.margin_note_id))?;
            let attestation_id = intent
                .quote_attestation_id
                .clone()
                .ok_or_else(|| format!("intent {} lacks attestation", intent.intent_id))?;
            let attestation = self
                .pq_quote_attestations
                .get_mut(&attestation_id)
                .ok_or_else(|| format!("unknown attestation {attestation_id}"))?;
            if note.status == MarginNoteStatus::Committed {
                note.reserve_for_clearing()?;
            }
            batch.add_intent(intent, note, attestation, &self.config)?;
            attestation.use_once();
            intent.mark_batched();
            let rebate_units = self
                .pools
                .get(pool_id)
                .expect("pool checked")
                .quote_rebate(&self.config, intent.notional_units);
            let rebate_id = format!("rebate-{}-{}", batch_id, intent.intent_id);
            let rebate = RebateSettlement::new(
                rebate_id,
                pool_id,
                &note.note_id,
                &intent.intent_id,
                &note.owner_commitment,
                rebate_units,
                intent.max_fee_credit_units,
                self.l2_height,
            );
            batch.add_rebate(&rebate);
            rebates.push(rebate);
        }
        for guardrail in self
            .liquidity_guardrails
            .values()
            .filter(|guardrail| guardrail.pool_id == pool_id)
        {
            batch.add_guardrail(guardrail);
        }
        let funding_rate_bps = self.compute_funding_rate_bps(pool_id)?;
        batch.settle(funding_rate_bps, self.l2_height);
        for intent_id in intent_ids {
            if let Some(intent) = self.funding_intents.get_mut(*intent_id) {
                intent.settle();
            }
        }
        for rebate in rebates {
            ensure!(
                self.rebate_settlements.len() < self.config.max_rebates,
                "rebate limit reached"
            );
            self.counters.record_rebate(&rebate);
            self.rebate_settlements
                .insert(rebate.rebate_id.clone(), rebate);
        }
        if let Some(pool) = self.pools.get_mut(pool_id) {
            for intent_id in intent_ids {
                if let Some(intent) = self.funding_intents.get(*intent_id) {
                    pool.apply_intent(intent, self.l2_height)?;
                }
            }
            pool.apply_funding(funding_rate_bps, self.l2_height);
        }
        batch.mark_rebated();
        self.counters.record_batch(&batch);
        self.events.push(json!({
            "type": "batch_cleared",
            "batch_id": batch.batch_id,
            "pool_id": batch.pool_id,
            "intent_count": batch.intent_ids.len(),
            "funding_rate_bps": funding_rate_bps,
            "height": self.l2_height,
        }));
        self.batch_clearings.insert(batch.batch_id.clone(), batch);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn settle_rebate(&mut self, rebate_id: impl AsRef<str>) -> Result<()> {
        let rebate_id = rebate_id.as_ref();
        let rebate = self
            .rebate_settlements
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate {rebate_id}"))?;
        rebate.settle(self.l2_height);
        if let Some(note) = self.margin_notes.get_mut(&rebate.margin_note_id) {
            note.rebate(rebate.rebate_units);
        }
        self.events.push(json!({
            "type": "rebate_settled",
            "rebate_id": rebate_id,
            "height": self.l2_height,
        }));
        self.refresh_roots();
        Ok(())
    }

    pub fn compute_funding_rate_bps(&self, pool_id: impl AsRef<str>) -> Result<i64> {
        let pool_id = pool_id.as_ref();
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| format!("unknown pool {pool_id}"))?;
        if pool.total_open_interest_units() == 0 {
            return Ok(0);
        }
        let skew_bps = ratio_bps(
            pool.skew_units().unsigned_abs(),
            pool.total_open_interest_units(),
        );
        let directional = if pool.skew_units() >= 0 { 1 } else { -1 };
        let raw = directional * (skew_bps as i64) / 20;
        Ok(raw.clamp(
            -self.config.max_funding_rate_bps,
            self.config.max_funding_rate_bps,
        ))
    }

    pub fn publish_operator_summary(
        &mut self,
        summary_id: impl Into<String>,
        operator_id: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary limit reached"
        );
        let summary_id = summary_id.into();
        ensure!(
            !self.operator_summaries.contains_key(&summary_id),
            "operator summary exists"
        );
        let operator_id = operator_id.into();
        let pools = self
            .pools
            .values()
            .filter(|pool| pool.operator_id == operator_id)
            .cloned()
            .collect::<Vec<_>>();
        let batches = self
            .batch_clearings
            .values()
            .filter(|batch| pools.iter().any(|pool| pool.pool_id == batch.pool_id))
            .cloned()
            .collect::<Vec<_>>();
        let summary = OperatorSummary::new(
            summary_id.clone(),
            operator_id,
            &pools,
            &batches,
            &self.config,
            self.l2_height,
        );
        self.counters.record_operator_summary();
        self.events.push(json!({
            "type": "operator_summary_published",
            "summary_id": summary.summary_id,
            "operator_id": summary.operator_id,
            "health": summary.health,
            "height": self.l2_height,
        }));
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn advance_height(&mut self, l2_delta: u64, monero_delta: u64) {
        self.l2_height = self.l2_height.saturating_add(l2_delta);
        self.monero_height = self.monero_height.saturating_add(monero_delta);
        if l2_delta > 0 {
            self.epoch = self.epoch.saturating_add(l2_delta / 360);
        }
        self.events.push(json!({
            "type": "height_advanced",
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
        }));
        self.refresh_roots();
    }

    pub fn refresh_roots(&mut self) {
        let pools = self
            .pools
            .values()
            .map(ConfidentialPerpsPool::leaf)
            .collect::<Vec<_>>();
        let margin_notes = self
            .margin_notes
            .values()
            .map(FeeCreditMarginNote::leaf)
            .collect::<Vec<_>>();
        let funding_intents = self
            .funding_intents
            .values()
            .map(FundingRateIntent::leaf)
            .collect::<Vec<_>>();
        let attestations = self
            .pq_quote_attestations
            .values()
            .map(PqQuoteAttestation::leaf)
            .collect::<Vec<_>>();
        let guardrails = self
            .liquidity_guardrails
            .values()
            .map(LiquidityGuardrail::leaf)
            .collect::<Vec<_>>();
        let rebates = self
            .rebate_settlements
            .values()
            .map(RebateSettlement::leaf)
            .collect::<Vec<_>>();
        let batches = self
            .batch_clearings
            .values()
            .map(BatchClearing::leaf)
            .collect::<Vec<_>>();
        let summaries = self
            .operator_summaries
            .values()
            .map(OperatorSummary::leaf)
            .collect::<Vec<_>>();
        let nullifiers = self
            .nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();
        self.roots = Roots {
            pools_root: merkle_root(CONFIDENTIAL_PERPS_POOL_SCHEME, &pools),
            margin_notes_root: merkle_root(FEE_CREDIT_MARGIN_NOTE_SCHEME, &margin_notes),
            funding_intents_root: merkle_root(FUNDING_RATE_INTENT_SCHEME, &funding_intents),
            pq_quote_attestations_root: merkle_root(PQ_QUOTE_ATTESTATION_SCHEME, &attestations),
            liquidity_guardrails_root: merkle_root(LIQUIDITY_GUARDRAIL_SCHEME, &guardrails),
            rebate_settlements_root: merkle_root(REBATE_SETTLEMENT_SCHEME, &rebates),
            batch_clearings_root: merkle_root(BATCH_CLEARING_SCHEME, &batches),
            operator_summaries_root: merkle_root(OPERATOR_SUMMARY_SCHEME, &summaries),
            nullifiers_root: merkle_root("fee-credit-perps-amm-nullifiers", &nullifiers),
            events_root: merkle_root("fee-credit-perps-amm-events", &self.events),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "protocol_version": state.config.protocol_version,
        "schema_version": state.config.schema_version,
        "chain_id": state.config.chain_id,
        "public_record_suite": PUBLIC_RECORD_SUITE,
        "l2_height": state.l2_height,
        "monero_height": state.monero_height,
        "epoch": state.epoch,
        "counters": state.counters,
        "roots": state.roots.public_record(),
        "low_fee_policy": {
            "effective_trade_fee_bps": state.config.effective_trade_fee_bps(),
            "max_user_fee_bps": state.config.max_user_fee_bps,
            "target_rebate_bps": state.config.target_rebate_bps,
            "rebate_cover_bps": state.config.rebate_cover_bps,
        },
        "privacy_policy": {
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "batch_privacy_set_size": state.config.batch_privacy_set_size,
            "min_pq_security_bits": state.config.min_pq_security_bits,
            "quote_quorum": state.config.quote_quorum,
            "funding_quorum": state.config.funding_quorum,
        },
    })
}

pub fn state_root(state: &State) -> String {
    let public = public_record(state);
    domain_hash(
        "private-l2-low-fee-pq-confidential-fee-credit-perps-amm-public-state-root",
        &[HashPart::Json(&public)],
        32,
    )
}

fn bps_amount(units: u128, bps: u64) -> u128 {
    units.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn ratio_bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(MAX_BPS as u128)
        .saturating_div(denominator) as u64
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let leaves = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    let payload = json!({
        "domain": domain,
        "parts": leaves,
    });
    domain_hash(
        "private-l2-low-fee-pq-confidential-fee-credit-perps-amm-commitment",
        &[HashPart::Json(&payload)],
        32,
    )
}
