use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialDefiCrossMarginRiskEngineRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialDefiCrossMarginRiskEngineRuntimeResult<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $message:expr $(,)?) => {
        ensure($condition, $message)
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_CROSS_MARGIN_RISK_ENGINE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-defi-cross-margin-risk-engine-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_CROSS_MARGIN_RISK_ENGINE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 2_048_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_ACCOUNT_ID: &str = "acct:confidential-cross-margin-demo";
pub const DEFAULT_COLLATERAL_ASSET_ID: &str = "asset:wxmr";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "asset:private-usd";
pub const DEFAULT_BRIDGE_ASSET_ID: &str = "asset:bridged-usdc-devnet";
pub const DEFAULT_AMM_POOL_ID: &str = "amm:wxmr-private-usd";
pub const DEFAULT_LENDING_MARKET_ID: &str = "lend:wxmr";
pub const DEFAULT_PERP_MARKET_ID: &str = "perp:xmr-usd-private";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-cross-margin-risk-v1";
pub const CONFIDENTIAL_ACCOUNTING_SUITE: &str =
    "RingCT-margin-note+range-proof+viewtag+root-only-risk-band-v1";
pub const ORACLE_GUARD_SUITE: &str =
    "pq-threshold-median-oracle+staleness-window+deviation-clamp-v1";
pub const TOKEN_COVENANT_SUITE: &str =
    "confidential-token-covenant+contract-hook+bridge-route-policy-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "recursive-low-fee-defi-risk-recompute+rebate-receipt-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_STALENESS_BLOCKS: u64 = 24;
pub const DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_COVENANT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_600;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 850;
pub const DEFAULT_LIQUIDATION_PENALTY_BPS: u64 = 350;
pub const DEFAULT_DELEVERAGE_MARGIN_BPS: u64 = 1_050;
pub const DEFAULT_INSOLVENCY_MARGIN_BPS: u64 = 250;
pub const DEFAULT_MAX_ORACLE_DEVIATION_BPS: u64 = 750;
pub const DEFAULT_COLLATERAL_PRIVACY_BUDGET: u64 = 2_000_000;
pub const DEFAULT_EXPOSURE_PRIVACY_BUDGET: u64 = 3_000_000;
pub const DEFAULT_MAX_ACCOUNTS: usize = 4_194_304;
pub const DEFAULT_MAX_ASSETS: usize = 524_288;
pub const DEFAULT_MAX_MARKETS: usize = 524_288;
pub const DEFAULT_MAX_POSITIONS: usize = 16_777_216;
pub const DEFAULT_MAX_SNAPSHOTS: usize = 8_388_608;
pub const DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_COVENANT_CHECKS: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_BUDGETS: usize = 8_388_608;
pub const DEFAULT_MAX_LIQUIDATION_CORRIDORS: usize = 2_097_152;
pub const DEFAULT_MAX_STRESS_SCENARIOS: usize = 262_144;
pub const DEFAULT_MAX_BRIDGE_HAIRCUT_OVERRIDES: usize = 262_144;
pub const DEFAULT_MAX_CONTRACT_RISK_ENVELOPES: usize = 1_048_576;
pub const DEFAULT_MAX_FEE_REBATES: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueKind {
    Amm,
    Lending,
    Perpetual,
    Vault,
    BridgeReserve,
    StableSwap,
    TokenCovenant,
    Insurance,
}

impl VenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perpetual => "perpetual",
            Self::Vault => "vault",
            Self::BridgeReserve => "bridge_reserve",
            Self::StableSwap => "stable_swap",
            Self::TokenCovenant => "token_covenant",
            Self::Insurance => "insurance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
    Supply,
    Borrow,
    Liquidity,
    Hedge,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::Supply => "supply",
            Self::Borrow => "borrow",
            Self::Liquidity => "liquidity",
            Self::Hedge => "hedge",
        }
    }

    pub fn sign(self) -> i128 {
        match self {
            Self::Long | Self::Supply | Self::Liquidity | Self::Hedge => 1,
            Self::Short | Self::Borrow => -1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    Prime,
    Standard,
    Watch,
    Deleverage,
    Liquidatable,
    Insolvent,
}

impl RiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prime => "prime",
            Self::Standard => "standard",
            Self::Watch => "watch",
            Self::Deleverage => "deleverage",
            Self::Liquidatable => "liquidatable",
            Self::Insolvent => "insolvent",
        }
    }

    pub fn liquidation_candidate(self) -> bool {
        matches!(self, Self::Liquidatable | Self::Insolvent)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Fresh,
    Stale,
    Deviating,
    Suspended,
}

impl OracleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Deviating => "deviating",
            Self::Suspended => "suspended",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantVerdict {
    Allowed,
    NeedsProof,
    RateLimited,
    RouteBlocked,
    AssetFrozen,
    Denied,
}

impl CovenantVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::NeedsProof => "needs_proof",
            Self::RateLimited => "rate_limited",
            Self::RouteBlocked => "route_blocked",
            Self::AssetFrozen => "asset_frozen",
            Self::Denied => "denied",
        }
    }

    pub fn permits_risk_credit(self) -> bool {
        matches!(self, Self::Allowed | Self::NeedsProof)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Recomputed,
    Rebated,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Recomputed => "recomputed",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_staleness_blocks: u64,
    pub snapshot_ttl_blocks: u64,
    pub covenant_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_user_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub deleverage_margin_bps: u64,
    pub insolvency_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub collateral_privacy_budget: u64,
    pub exposure_privacy_budget: u64,
    pub max_accounts: usize,
    pub max_assets: usize,
    pub max_markets: usize,
    pub max_positions: usize,
    pub max_snapshots: usize,
    pub max_batches: usize,
    pub max_covenant_checks: usize,
    pub max_privacy_budgets: usize,
    pub max_liquidation_corridors: usize,
    pub max_stress_scenarios: usize,
    pub max_bridge_haircut_overrides: usize,
    pub max_contract_risk_envelopes: usize,
    pub max_fee_rebates: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_staleness_blocks: DEFAULT_ORACLE_STALENESS_BLOCKS,
            snapshot_ttl_blocks: DEFAULT_SNAPSHOT_TTL_BLOCKS,
            covenant_ttl_blocks: DEFAULT_COVENANT_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            deleverage_margin_bps: DEFAULT_DELEVERAGE_MARGIN_BPS,
            insolvency_margin_bps: DEFAULT_INSOLVENCY_MARGIN_BPS,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            max_oracle_deviation_bps: DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            collateral_privacy_budget: DEFAULT_COLLATERAL_PRIVACY_BUDGET,
            exposure_privacy_budget: DEFAULT_EXPOSURE_PRIVACY_BUDGET,
            max_accounts: DEFAULT_MAX_ACCOUNTS,
            max_assets: DEFAULT_MAX_ASSETS,
            max_markets: DEFAULT_MAX_MARKETS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_snapshots: DEFAULT_MAX_SNAPSHOTS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_covenant_checks: DEFAULT_MAX_COVENANT_CHECKS,
            max_privacy_budgets: DEFAULT_MAX_PRIVACY_BUDGETS,
            max_liquidation_corridors: DEFAULT_MAX_LIQUIDATION_CORRIDORS,
            max_stress_scenarios: DEFAULT_MAX_STRESS_SCENARIOS,
            max_bridge_haircut_overrides: DEFAULT_MAX_BRIDGE_HAIRCUT_OVERRIDES,
            max_contract_risk_envelopes: DEFAULT_MAX_CONTRACT_RISK_ENVELOPES,
            max_fee_rebates: DEFAULT_MAX_FEE_REBATES,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub accounts_registered: u64,
    pub assets_registered: u64,
    pub markets_registered: u64,
    pub positions_recorded: u64,
    pub oracle_updates: u64,
    pub snapshots_signed: u64,
    pub liquidation_corridors_opened: u64,
    pub covenant_checks: u64,
    pub privacy_budget_events: u64,
    pub batch_recomputes: u64,
    pub stress_scenarios_recorded: u64,
    pub bridge_haircut_overrides_recorded: u64,
    pub contract_risk_envelopes_recorded: u64,
    pub fee_rebates_recorded: u64,
    pub rejected_requests: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub accounts_root: String,
    pub assets_root: String,
    pub markets_root: String,
    pub positions_root: String,
    pub exposures_root: String,
    pub oracle_root: String,
    pub snapshots_root: String,
    pub corridors_root: String,
    pub covenant_root: String,
    pub privacy_budget_root: String,
    pub batches_root: String,
    pub stress_scenarios_root: String,
    pub bridge_haircut_overrides_root: String,
    pub contract_risk_envelopes_root: String,
    pub fee_rebates_root: String,
    pub events_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountRecord {
    pub account_id: String,
    pub owner_commitment: String,
    pub view_tag_root: String,
    pub collateral_root: String,
    pub exposure_root: String,
    pub active: bool,
    pub opened_at_height: u64,
    pub last_risk_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssetRecord {
    pub asset_id: String,
    pub symbol_commitment: String,
    pub decimals: u8,
    pub collateral_factor_bps: u64,
    pub liability_factor_bps: u64,
    pub bridge_haircut_bps: u64,
    pub oracle_id: String,
    pub covenant_policy_id: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MarketRecord {
    pub market_id: String,
    pub venue: VenueKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub risk_weight_bps: u64,
    pub netting_group: String,
    pub covenant_policy_id: String,
    pub open_interest_cap: u128,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PositionRecord {
    pub position_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub venue: VenueKind,
    pub side: PositionSide,
    pub notional: u128,
    pub quantity_commitment: String,
    pub price_commitment: String,
    pub margin_commitment: String,
    pub privacy_nullifier: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExposureRecord {
    pub account_id: String,
    pub gross_collateral_value: u128,
    pub gross_liability_value: u128,
    pub amm_delta: i128,
    pub lending_delta: i128,
    pub perp_delta: i128,
    pub bridge_delta: i128,
    pub net_delta: i128,
    pub margin_ratio_bps: u64,
    pub risk_band: Option<RiskBand>,
    pub stale_oracle_count: u64,
    pub privacy_budget_remaining: u64,
    pub recomputed_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleRecord {
    pub oracle_id: String,
    pub asset_id: String,
    pub price_micro_units: u128,
    pub confidence_bps: u64,
    pub median_root: String,
    pub attestation_root: String,
    pub status: OracleStatus,
    pub updated_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskSnapshotRecord {
    pub snapshot_id: String,
    pub account_id: String,
    pub height: u64,
    pub risk_band: RiskBand,
    pub exposure_root: String,
    pub oracle_root: String,
    pub covenant_root: String,
    pub privacy_budget_root: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_root: String,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidationCorridorRecord {
    pub corridor_id: String,
    pub account_id: String,
    pub risk_band: RiskBand,
    pub min_close_bps: u64,
    pub max_close_bps: u64,
    pub penalty_bps: u64,
    pub keeper_fee_bps: u64,
    pub target_margin_bps: u64,
    pub route_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CovenantCheckRecord {
    pub check_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub market_id: String,
    pub policy_id: String,
    pub verdict: CovenantVerdict,
    pub proof_root: String,
    pub checked_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetRecord {
    pub budget_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub collateral_budget_remaining: u64,
    pub exposure_budget_remaining: u64,
    pub consumed_collateral_budget: u64,
    pub consumed_exposure_budget: u64,
    pub last_event_root: String,
    pub updated_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchRiskRecomputeRecord {
    pub batch_id: String,
    pub account_ids: Vec<String>,
    pub position_ids: Vec<String>,
    pub status: BatchStatus,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub before_root: String,
    pub after_root: String,
    pub proof_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StressScenarioRecord {
    pub scenario_id: String,
    pub account_id: String,
    pub price_shock_bps: u64,
    pub liquidity_haircut_bps: u64,
    pub funding_shock_bps: u64,
    pub bridge_delay_blocks: u64,
    pub stressed_margin_ratio_bps: u64,
    pub stressed_risk_band: RiskBand,
    pub scenario_root: String,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeHaircutOverrideRecord {
    pub override_id: String,
    pub asset_id: String,
    pub bridge_domain: String,
    pub haircut_bps: u64,
    pub reserve_root: String,
    pub attestation_root: String,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractRiskEnvelopeRecord {
    pub envelope_id: String,
    pub contract_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub max_notional: u128,
    pub max_slippage_bps: u64,
    pub max_callback_depth: u16,
    pub covenant_policy_id: String,
    pub code_commitment: String,
    pub witness_root: String,
    pub enabled: bool,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub batch_id: String,
    pub account_id: String,
    pub fee_paid_micro_units: u128,
    pub rebate_micro_units: u128,
    pub rebate_bps: u64,
    pub receipt_root: String,
    pub recorded_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterAccountRequest {
    pub account_id: String,
    pub owner_commitment: String,
    pub view_tag_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterAssetRequest {
    pub asset_id: String,
    pub symbol_commitment: String,
    pub decimals: u8,
    pub collateral_factor_bps: u64,
    pub liability_factor_bps: u64,
    pub bridge_haircut_bps: u64,
    pub oracle_id: String,
    pub covenant_policy_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterMarketRequest {
    pub market_id: String,
    pub venue: VenueKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub risk_weight_bps: u64,
    pub netting_group: String,
    pub covenant_policy_id: String,
    pub open_interest_cap: u128,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordOracleRequest {
    pub oracle_id: String,
    pub asset_id: String,
    pub price_micro_units: u128,
    pub confidence_bps: u64,
    pub median_root: String,
    pub attestation_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecordPositionRequest {
    pub position_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub side: PositionSide,
    pub notional: u128,
    pub quantity_commitment: String,
    pub price_commitment: String,
    pub margin_commitment: String,
    pub privacy_nullifier: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskSnapshotRequest {
    pub snapshot_id: String,
    pub account_id: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CovenantCheckRequest {
    pub check_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub market_id: String,
    pub policy_id: String,
    pub verdict: CovenantVerdict,
    pub proof_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyBudgetRequest {
    pub budget_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub consume_collateral_budget: u64,
    pub consume_exposure_budget: u64,
    pub event_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchRiskRecomputeRequest {
    pub batch_id: String,
    pub account_ids: Vec<String>,
    pub position_ids: Vec<String>,
    pub fee_bps: u64,
    pub proof_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StressScenarioRequest {
    pub scenario_id: String,
    pub account_id: String,
    pub price_shock_bps: u64,
    pub liquidity_haircut_bps: u64,
    pub funding_shock_bps: u64,
    pub bridge_delay_blocks: u64,
    pub scenario_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeHaircutOverrideRequest {
    pub override_id: String,
    pub asset_id: String,
    pub bridge_domain: String,
    pub haircut_bps: u64,
    pub reserve_root: String,
    pub attestation_root: String,
    pub active_from_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractRiskEnvelopeRequest {
    pub envelope_id: String,
    pub contract_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub max_notional: u128,
    pub max_slippage_bps: u64,
    pub max_callback_depth: u16,
    pub covenant_policy_id: String,
    pub code_commitment: String,
    pub witness_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateRequest {
    pub rebate_id: String,
    pub batch_id: String,
    pub account_id: String,
    pub fee_paid_micro_units: u128,
    pub receipt_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub accounts: BTreeMap<String, AccountRecord>,
    pub assets: BTreeMap<String, AssetRecord>,
    pub markets: BTreeMap<String, MarketRecord>,
    pub positions: BTreeMap<String, PositionRecord>,
    pub exposures: BTreeMap<String, ExposureRecord>,
    pub oracles: BTreeMap<String, OracleRecord>,
    pub snapshots: BTreeMap<String, RiskSnapshotRecord>,
    pub liquidation_corridors: BTreeMap<String, LiquidationCorridorRecord>,
    pub covenant_checks: BTreeMap<String, CovenantCheckRecord>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetRecord>,
    pub batches: BTreeMap<String, BatchRiskRecomputeRecord>,
    pub stress_scenarios: BTreeMap<String, StressScenarioRecord>,
    pub bridge_haircut_overrides: BTreeMap<String, BridgeHaircutOverrideRecord>,
    pub contract_risk_envelopes: BTreeMap<String, ContractRiskEnvelopeRecord>,
    pub fee_rebates: BTreeMap<String, FeeRebateRecord>,
    pub nullifiers: BTreeSet<String>,
    pub event_log: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            accounts: BTreeMap::new(),
            assets: BTreeMap::new(),
            markets: BTreeMap::new(),
            positions: BTreeMap::new(),
            exposures: BTreeMap::new(),
            oracles: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            liquidation_corridors: BTreeMap::new(),
            covenant_checks: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            batches: BTreeMap::new(),
            stress_scenarios: BTreeMap::new(),
            bridge_haircut_overrides: BTreeMap::new(),
            contract_risk_envelopes: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            event_log: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn register_account(&mut self, request: RegisterAccountRequest) -> Result<()> {
        ensure_non_empty("account_id", &request.account_id)?;
        ensure_non_empty("owner_commitment", &request.owner_commitment)?;
        ensure_non_empty("view_tag_root", &request.view_tag_root)?;
        ensure!(
            self.accounts.len() < self.config.max_accounts,
            "account capacity reached"
        )?;
        ensure!(
            !self.accounts.contains_key(&request.account_id),
            "account already exists"
        )?;

        let account = AccountRecord {
            account_id: request.account_id.clone(),
            owner_commitment: request.owner_commitment,
            view_tag_root: request.view_tag_root,
            collateral_root: empty_root("account_collateral"),
            exposure_root: empty_root("account_exposure"),
            active: true,
            opened_at_height: request.height,
            last_risk_height: request.height,
        };
        self.accounts.insert(request.account_id.clone(), account);
        self.exposures.insert(
            request.account_id.clone(),
            ExposureRecord {
                account_id: request.account_id.clone(),
                privacy_budget_remaining: self.config.exposure_privacy_budget,
                recomputed_at_height: request.height,
                ..ExposureRecord::default()
            },
        );
        self.counters.accounts_registered = self.counters.accounts_registered.saturating_add(1);
        self.push_event("account_registered", &request.account_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_asset(&mut self, request: RegisterAssetRequest) -> Result<()> {
        ensure_non_empty("asset_id", &request.asset_id)?;
        ensure_non_empty("oracle_id", &request.oracle_id)?;
        ensure_non_empty("covenant_policy_id", &request.covenant_policy_id)?;
        ensure_bps("collateral_factor_bps", request.collateral_factor_bps)?;
        ensure_bps("liability_factor_bps", request.liability_factor_bps)?;
        ensure_bps("bridge_haircut_bps", request.bridge_haircut_bps)?;
        ensure!(
            self.assets.len() < self.config.max_assets,
            "asset capacity reached"
        )?;
        ensure!(
            !self.assets.contains_key(&request.asset_id),
            "asset already exists"
        )?;

        self.assets.insert(
            request.asset_id.clone(),
            AssetRecord {
                asset_id: request.asset_id.clone(),
                symbol_commitment: request.symbol_commitment,
                decimals: request.decimals,
                collateral_factor_bps: request.collateral_factor_bps,
                liability_factor_bps: request.liability_factor_bps,
                bridge_haircut_bps: request.bridge_haircut_bps,
                oracle_id: request.oracle_id,
                covenant_policy_id: request.covenant_policy_id,
                enabled: true,
            },
        );
        self.counters.assets_registered = self.counters.assets_registered.saturating_add(1);
        self.push_event("asset_registered", &request.asset_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_market(&mut self, request: RegisterMarketRequest) -> Result<()> {
        ensure_non_empty("market_id", &request.market_id)?;
        ensure_known_asset(&self.assets, &request.base_asset_id)?;
        ensure_known_asset(&self.assets, &request.quote_asset_id)?;
        ensure_bps("risk_weight_bps", request.risk_weight_bps)?;
        ensure_non_empty("netting_group", &request.netting_group)?;
        ensure!(
            self.markets.len() < self.config.max_markets,
            "market capacity reached"
        )?;
        ensure!(
            !self.markets.contains_key(&request.market_id),
            "market already exists"
        )?;

        self.markets.insert(
            request.market_id.clone(),
            MarketRecord {
                market_id: request.market_id.clone(),
                venue: request.venue,
                base_asset_id: request.base_asset_id,
                quote_asset_id: request.quote_asset_id,
                risk_weight_bps: request.risk_weight_bps,
                netting_group: request.netting_group,
                covenant_policy_id: request.covenant_policy_id,
                open_interest_cap: request.open_interest_cap,
                enabled: true,
            },
        );
        self.counters.markets_registered = self.counters.markets_registered.saturating_add(1);
        self.push_event("market_registered", &request.market_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_oracle(&mut self, request: RecordOracleRequest) -> Result<()> {
        ensure_non_empty("oracle_id", &request.oracle_id)?;
        ensure_known_asset(&self.assets, &request.asset_id)?;
        ensure!(
            request.price_micro_units > 0,
            "oracle price must be positive"
        )?;
        ensure_bps("confidence_bps", request.confidence_bps)?;

        let status =
            self.oracle_status(&request.asset_id, request.price_micro_units, request.height);
        self.oracles.insert(
            request.oracle_id.clone(),
            OracleRecord {
                oracle_id: request.oracle_id.clone(),
                asset_id: request.asset_id,
                price_micro_units: request.price_micro_units,
                confidence_bps: request.confidence_bps,
                median_root: request.median_root,
                attestation_root: request.attestation_root,
                status,
                updated_at_height: request.height,
            },
        );
        self.counters.oracle_updates = self.counters.oracle_updates.saturating_add(1);
        self.push_event("oracle_recorded", &request.oracle_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_position(&mut self, request: RecordPositionRequest) -> Result<()> {
        ensure_non_empty("position_id", &request.position_id)?;
        ensure_non_empty("privacy_nullifier", &request.privacy_nullifier)?;
        ensure!(request.notional > 0, "position notional must be positive")?;
        ensure!(
            self.positions.len() < self.config.max_positions,
            "position capacity reached"
        )?;
        ensure!(
            !self.positions.contains_key(&request.position_id),
            "position already exists"
        )?;
        ensure!(
            !self.nullifiers.contains(&request.privacy_nullifier),
            "privacy nullifier already spent"
        )?;
        ensure_account_active(&self.accounts, &request.account_id)?;
        let market = match self.markets.get(&request.market_id) {
            Some(market) => market,
            None => return reject("unknown market"),
        };
        ensure!(market.enabled, "market disabled")?;
        ensure_known_asset(&self.assets, &request.asset_id)?;
        ensure_market_cap(self, market, request.notional)?;
        ensure_covenant_allows(
            self,
            &request.account_id,
            &request.asset_id,
            &request.market_id,
        )?;

        let position = PositionRecord {
            position_id: request.position_id.clone(),
            account_id: request.account_id.clone(),
            market_id: request.market_id.clone(),
            asset_id: request.asset_id,
            venue: market.venue,
            side: request.side,
            notional: request.notional,
            quantity_commitment: request.quantity_commitment,
            price_commitment: request.price_commitment,
            margin_commitment: request.margin_commitment,
            privacy_nullifier: request.privacy_nullifier.clone(),
            opened_at_height: request.height,
            updated_at_height: request.height,
            active: true,
        };
        self.positions.insert(request.position_id.clone(), position);
        self.nullifiers.insert(request.privacy_nullifier);
        self.counters.positions_recorded = self.counters.positions_recorded.saturating_add(1);
        self.recompute_account_risk(&request.account_id, request.height)?;
        self.push_event("position_recorded", &request.position_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_covenant_check(&mut self, request: CovenantCheckRequest) -> Result<()> {
        ensure_non_empty("check_id", &request.check_id)?;
        ensure_account_active(&self.accounts, &request.account_id)?;
        ensure_known_asset(&self.assets, &request.asset_id)?;
        ensure!(
            self.markets.contains_key(&request.market_id),
            "unknown market"
        )?;
        ensure!(
            self.covenant_checks.len() < self.config.max_covenant_checks,
            "covenant check capacity reached"
        )?;

        self.covenant_checks.insert(
            request.check_id.clone(),
            CovenantCheckRecord {
                check_id: request.check_id.clone(),
                account_id: request.account_id,
                asset_id: request.asset_id,
                market_id: request.market_id,
                policy_id: request.policy_id,
                verdict: request.verdict,
                proof_root: request.proof_root,
                checked_at_height: request.height,
                expires_at_height: request
                    .height
                    .saturating_add(self.config.covenant_ttl_blocks),
            },
        );
        self.counters.covenant_checks = self.counters.covenant_checks.saturating_add(1);
        self.push_event("covenant_check_recorded", &request.check_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn consume_privacy_budget(&mut self, request: PrivacyBudgetRequest) -> Result<()> {
        ensure_non_empty("budget_id", &request.budget_id)?;
        ensure_account_active(&self.accounts, &request.account_id)?;
        ensure_known_asset(&self.assets, &request.asset_id)?;
        ensure!(
            self.privacy_budgets.len() < self.config.max_privacy_budgets
                || self.privacy_budgets.contains_key(&request.budget_id),
            "privacy budget capacity reached"
        )?;

        let existing = match self.privacy_budgets.get(&request.budget_id) {
            Some(record) => record.clone(),
            None => PrivacyBudgetRecord {
                budget_id: request.budget_id.clone(),
                account_id: request.account_id.clone(),
                asset_id: request.asset_id.clone(),
                collateral_budget_remaining: self.config.collateral_privacy_budget,
                exposure_budget_remaining: self.config.exposure_privacy_budget,
                consumed_collateral_budget: 0,
                consumed_exposure_budget: 0,
                last_event_root: empty_root("privacy_budget_event"),
                updated_at_height: request.height,
            },
        };
        ensure!(
            existing.collateral_budget_remaining >= request.consume_collateral_budget,
            "collateral privacy budget exhausted"
        )?;
        ensure!(
            existing.exposure_budget_remaining >= request.consume_exposure_budget,
            "exposure privacy budget exhausted"
        )?;

        let updated = PrivacyBudgetRecord {
            collateral_budget_remaining: existing
                .collateral_budget_remaining
                .saturating_sub(request.consume_collateral_budget),
            exposure_budget_remaining: existing
                .exposure_budget_remaining
                .saturating_sub(request.consume_exposure_budget),
            consumed_collateral_budget: existing
                .consumed_collateral_budget
                .saturating_add(request.consume_collateral_budget),
            consumed_exposure_budget: existing
                .consumed_exposure_budget
                .saturating_add(request.consume_exposure_budget),
            last_event_root: request.event_root,
            updated_at_height: request.height,
            ..existing
        };
        self.privacy_budgets
            .insert(request.budget_id.clone(), updated);
        self.counters.privacy_budget_events = self.counters.privacy_budget_events.saturating_add(1);
        self.recompute_account_risk(&request.account_id, request.height)?;
        self.push_event("privacy_budget_consumed", &request.budget_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn sign_risk_snapshot(&mut self, request: RiskSnapshotRequest) -> Result<()> {
        ensure_non_empty("snapshot_id", &request.snapshot_id)?;
        ensure_non_empty(
            "pq_public_key_commitment",
            &request.pq_public_key_commitment,
        )?;
        ensure_non_empty("pq_signature_root", &request.pq_signature_root)?;
        ensure!(
            self.snapshots.len() < self.config.max_snapshots,
            "snapshot capacity reached"
        )?;
        self.recompute_account_risk(&request.account_id, request.height)?;
        let exposure = match self.exposures.get(&request.account_id) {
            Some(exposure) => exposure,
            None => return reject("missing account exposure"),
        };
        let risk_band = match exposure.risk_band {
            Some(risk_band) => risk_band,
            None => RiskBand::Insolvent,
        };
        let snapshot = RiskSnapshotRecord {
            snapshot_id: request.snapshot_id.clone(),
            account_id: request.account_id.clone(),
            height: request.height,
            risk_band,
            exposure_root: self.roots.exposures_root.clone(),
            oracle_root: self.roots.oracle_root.clone(),
            covenant_root: self.roots.covenant_root.clone(),
            privacy_budget_root: self.roots.privacy_budget_root.clone(),
            pq_public_key_commitment: request.pq_public_key_commitment,
            pq_signature_root: request.pq_signature_root,
            expires_at_height: request
                .height
                .saturating_add(self.config.snapshot_ttl_blocks),
        };
        self.snapshots.insert(request.snapshot_id.clone(), snapshot);
        self.counters.snapshots_signed = self.counters.snapshots_signed.saturating_add(1);
        if risk_band.liquidation_candidate() {
            self.open_liquidation_corridor(&request.account_id, risk_band, request.height)?;
        }
        self.push_event("risk_snapshot_signed", &request.snapshot_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn low_fee_batch_recompute(&mut self, request: BatchRiskRecomputeRequest) -> Result<()> {
        ensure_non_empty("batch_id", &request.batch_id)?;
        ensure!(
            self.batches.len() < self.config.max_batches,
            "batch capacity reached"
        )?;
        ensure_bps("fee_bps", request.fee_bps)?;
        ensure!(
            request.fee_bps <= self.config.max_user_fee_bps,
            "batch fee exceeds user fee cap"
        )?;
        ensure!(
            request.account_ids.len() as u64 >= self.config.min_privacy_set_size.min(1_024),
            "batch privacy set too small"
        )?;

        let before_root = self.state_root();
        for account_id in &request.account_ids {
            ensure_account_active(&self.accounts, account_id)?;
            self.recompute_account_risk(account_id, request.height)?;
        }
        let after_root = self.state_root();
        let batch = BatchRiskRecomputeRecord {
            batch_id: request.batch_id.clone(),
            account_ids: dedupe(request.account_ids),
            position_ids: dedupe(request.position_ids),
            status: BatchStatus::Recomputed,
            fee_bps: request.fee_bps,
            rebate_bps: self.config.batch_rebate_bps,
            before_root,
            after_root,
            proof_root: request.proof_root,
            opened_at_height: request.height,
            sealed_at_height: request
                .height
                .saturating_add(self.config.batch_window_blocks),
        };
        self.batches.insert(request.batch_id.clone(), batch);
        self.counters.batch_recomputes = self.counters.batch_recomputes.saturating_add(1);
        self.push_event("batch_risk_recomputed", &request.batch_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_stress_scenario(&mut self, request: StressScenarioRequest) -> Result<()> {
        ensure_non_empty("scenario_id", &request.scenario_id)?;
        ensure_account_active(&self.accounts, &request.account_id)?;
        ensure_bps("price_shock_bps", request.price_shock_bps)?;
        ensure_bps("liquidity_haircut_bps", request.liquidity_haircut_bps)?;
        ensure_bps("funding_shock_bps", request.funding_shock_bps)?;
        ensure!(
            self.stress_scenarios.len() < self.config.max_stress_scenarios,
            "stress scenario capacity reached"
        )?;
        self.recompute_account_risk(&request.account_id, request.height)?;
        let exposure = match self.exposures.get(&request.account_id) {
            Some(exposure) => exposure.clone(),
            None => return reject("missing account exposure"),
        };
        let collateral_after_price =
            reduce_by_bps(exposure.gross_collateral_value, request.price_shock_bps);
        let collateral_after_liquidity =
            reduce_by_bps(collateral_after_price, request.liquidity_haircut_bps);
        let liability_after_funding =
            increase_by_bps(exposure.gross_liability_value, request.funding_shock_bps);
        let stressed_margin_ratio_bps =
            margin_ratio_bps(collateral_after_liquidity, liability_after_funding);
        let stressed_exposure = ExposureRecord {
            gross_collateral_value: collateral_after_liquidity,
            gross_liability_value: liability_after_funding,
            margin_ratio_bps: stressed_margin_ratio_bps,
            stale_oracle_count: exposure.stale_oracle_count.saturating_add(
                if request.bridge_delay_blocks > self.config.oracle_staleness_blocks {
                    1
                } else {
                    0
                },
            ),
            ..exposure
        };
        let stressed_risk_band = self.classify_risk(&stressed_exposure);
        self.stress_scenarios.insert(
            request.scenario_id.clone(),
            StressScenarioRecord {
                scenario_id: request.scenario_id.clone(),
                account_id: request.account_id,
                price_shock_bps: request.price_shock_bps,
                liquidity_haircut_bps: request.liquidity_haircut_bps,
                funding_shock_bps: request.funding_shock_bps,
                bridge_delay_blocks: request.bridge_delay_blocks,
                stressed_margin_ratio_bps,
                stressed_risk_band,
                scenario_root: request.scenario_root,
                recorded_at_height: request.height,
            },
        );
        self.counters.stress_scenarios_recorded =
            self.counters.stress_scenarios_recorded.saturating_add(1);
        self.push_event("stress_scenario_recorded", &request.scenario_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_bridge_haircut_override(
        &mut self,
        request: BridgeHaircutOverrideRequest,
    ) -> Result<()> {
        ensure_non_empty("override_id", &request.override_id)?;
        ensure_known_asset(&self.assets, &request.asset_id)?;
        ensure_non_empty("bridge_domain", &request.bridge_domain)?;
        ensure_bps("haircut_bps", request.haircut_bps)?;
        ensure!(
            request.expires_at_height >= request.active_from_height,
            "haircut override expires before activation"
        )?;
        ensure!(
            self.bridge_haircut_overrides.len() < self.config.max_bridge_haircut_overrides,
            "bridge haircut override capacity reached"
        )?;
        self.bridge_haircut_overrides.insert(
            request.override_id.clone(),
            BridgeHaircutOverrideRecord {
                override_id: request.override_id.clone(),
                asset_id: request.asset_id,
                bridge_domain: request.bridge_domain,
                haircut_bps: request.haircut_bps,
                reserve_root: request.reserve_root,
                attestation_root: request.attestation_root,
                active_from_height: request.active_from_height,
                expires_at_height: request.expires_at_height,
                enabled: true,
            },
        );
        self.counters.bridge_haircut_overrides_recorded = self
            .counters
            .bridge_haircut_overrides_recorded
            .saturating_add(1);
        self.push_event("bridge_haircut_override_recorded", &request.override_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_contract_risk_envelope(
        &mut self,
        request: ContractRiskEnvelopeRequest,
    ) -> Result<()> {
        ensure_non_empty("envelope_id", &request.envelope_id)?;
        ensure_non_empty("contract_id", &request.contract_id)?;
        ensure!(
            self.markets.contains_key(&request.market_id),
            "unknown market"
        )?;
        ensure_known_asset(&self.assets, &request.asset_id)?;
        ensure!(
            request.max_notional > 0,
            "contract envelope max notional must be positive"
        )?;
        ensure_bps("max_slippage_bps", request.max_slippage_bps)?;
        ensure_non_empty("covenant_policy_id", &request.covenant_policy_id)?;
        ensure_non_empty("code_commitment", &request.code_commitment)?;
        ensure_non_empty("witness_root", &request.witness_root)?;
        ensure!(
            self.contract_risk_envelopes.len() < self.config.max_contract_risk_envelopes,
            "contract risk envelope capacity reached"
        )?;
        self.contract_risk_envelopes.insert(
            request.envelope_id.clone(),
            ContractRiskEnvelopeRecord {
                envelope_id: request.envelope_id.clone(),
                contract_id: request.contract_id,
                market_id: request.market_id,
                asset_id: request.asset_id,
                max_notional: request.max_notional,
                max_slippage_bps: request.max_slippage_bps,
                max_callback_depth: request.max_callback_depth,
                covenant_policy_id: request.covenant_policy_id,
                code_commitment: request.code_commitment,
                witness_root: request.witness_root,
                enabled: true,
                recorded_at_height: request.height,
            },
        );
        self.counters.contract_risk_envelopes_recorded = self
            .counters
            .contract_risk_envelopes_recorded
            .saturating_add(1);
        self.push_event("contract_risk_envelope_recorded", &request.envelope_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_fee_rebate(&mut self, request: FeeRebateRequest) -> Result<()> {
        ensure_non_empty("rebate_id", &request.rebate_id)?;
        ensure!(
            self.batches.contains_key(&request.batch_id),
            "unknown batch"
        )?;
        ensure_account_active(&self.accounts, &request.account_id)?;
        ensure!(
            self.fee_rebates.len() < self.config.max_fee_rebates,
            "fee rebate capacity reached"
        )?;
        let rebate_micro_units =
            apply_bps(request.fee_paid_micro_units, self.config.batch_rebate_bps);
        self.fee_rebates.insert(
            request.rebate_id.clone(),
            FeeRebateRecord {
                rebate_id: request.rebate_id.clone(),
                batch_id: request.batch_id,
                account_id: request.account_id,
                fee_paid_micro_units: request.fee_paid_micro_units,
                rebate_micro_units,
                rebate_bps: self.config.batch_rebate_bps,
                receipt_root: request.receipt_root,
                recorded_at_height: request.height,
            },
        );
        self.counters.fee_rebates_recorded = self.counters.fee_rebates_recorded.saturating_add(1);
        self.push_event("fee_rebate_recorded", &request.rebate_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "suites": {
                "hash": HASH_SUITE,
                "pq_signature": PQ_SIGNATURE_SUITE,
                "confidential_accounting": CONFIDENTIAL_ACCOUNTING_SUITE,
                "oracle_guard": ORACLE_GUARD_SUITE,
                "token_covenant": TOKEN_COVENANT_SUITE,
                "low_fee_batch": LOW_FEE_BATCH_SUITE
            },
            "counters": self.counters,
            "roots": self.roots,
            "risk_summary": self.risk_summary(),
            "defi_surfaces": {
                "stress_scenarios": self.stress_scenarios.len(),
                "bridge_haircut_overrides": self.bridge_haircut_overrides.len(),
                "contract_risk_envelopes": self.contract_risk_envelopes.len(),
                "fee_rebates": self.fee_rebates.len()
            },
            "limits": {
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "initial_margin_bps": self.config.initial_margin_bps,
                "maintenance_margin_bps": self.config.maintenance_margin_bps,
                "oracle_staleness_blocks": self.config.oracle_staleness_blocks,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "batch_privacy_set_size": self.config.batch_privacy_set_size
            }
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/state",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(&self.roots.accounts_root),
                HashPart::Str(&self.roots.assets_root),
                HashPart::Str(&self.roots.markets_root),
                HashPart::Str(&self.roots.positions_root),
                HashPart::Str(&self.roots.exposures_root),
                HashPart::Str(&self.roots.oracle_root),
                HashPart::Str(&self.roots.snapshots_root),
                HashPart::Str(&self.roots.corridors_root),
                HashPart::Str(&self.roots.covenant_root),
                HashPart::Str(&self.roots.privacy_budget_root),
                HashPart::Str(&self.roots.batches_root),
                HashPart::Str(&self.roots.stress_scenarios_root),
                HashPart::Str(&self.roots.bridge_haircut_overrides_root),
                HashPart::Str(&self.roots.contract_risk_envelopes_root),
                HashPart::Str(&self.roots.fee_rebates_root),
                HashPart::Str(&self.roots.events_root),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.accounts_root = map_root("accounts", &self.accounts);
        self.roots.assets_root = map_root("assets", &self.assets);
        self.roots.markets_root = map_root("markets", &self.markets);
        self.roots.positions_root = map_root("positions", &self.positions);
        self.roots.exposures_root = map_root("exposures", &self.exposures);
        self.roots.oracle_root = map_root("oracles", &self.oracles);
        self.roots.snapshots_root = map_root("snapshots", &self.snapshots);
        self.roots.corridors_root = map_root("liquidation_corridors", &self.liquidation_corridors);
        self.roots.covenant_root = map_root("covenant_checks", &self.covenant_checks);
        self.roots.privacy_budget_root = map_root("privacy_budgets", &self.privacy_budgets);
        self.roots.batches_root = map_root("batches", &self.batches);
        self.roots.stress_scenarios_root = map_root("stress_scenarios", &self.stress_scenarios);
        self.roots.bridge_haircut_overrides_root =
            map_root("bridge_haircut_overrides", &self.bridge_haircut_overrides);
        self.roots.contract_risk_envelopes_root =
            map_root("contract_risk_envelopes", &self.contract_risk_envelopes);
        self.roots.fee_rebates_root = map_root("fee_rebates", &self.fee_rebates);
        self.roots.events_root = list_root("events", &self.event_log);
        self.roots.state_root = self.state_root();
    }

    pub fn recompute_account_risk(&mut self, account_id: &str, height: u64) -> Result<()> {
        ensure_account_active(&self.accounts, account_id)?;
        let mut exposure = ExposureRecord {
            account_id: account_id.to_string(),
            privacy_budget_remaining: self.config.exposure_privacy_budget,
            recomputed_at_height: height,
            ..ExposureRecord::default()
        };

        for position in self.positions.values() {
            if position.account_id != account_id || !position.active {
                continue;
            }
            let asset = match self.assets.get(&position.asset_id) {
                Some(asset) => asset,
                None => continue,
            };
            let oracle = self.oracles.get(&asset.oracle_id);
            let stale = match oracle {
                Some(record) => {
                    height.saturating_sub(record.updated_at_height)
                        > self.config.oracle_staleness_blocks
                }
                None => true,
            };
            if stale {
                exposure.stale_oracle_count = exposure.stale_oracle_count.saturating_add(1);
            }
            let collateral_value = apply_bps(position.notional, asset.collateral_factor_bps);
            let liability_value = apply_bps(position.notional, asset.liability_factor_bps);
            match position.side {
                PositionSide::Long
                | PositionSide::Supply
                | PositionSide::Liquidity
                | PositionSide::Hedge => {
                    exposure.gross_collateral_value = exposure
                        .gross_collateral_value
                        .saturating_add(collateral_value);
                }
                PositionSide::Short | PositionSide::Borrow => {
                    exposure.gross_liability_value = exposure
                        .gross_liability_value
                        .saturating_add(liability_value);
                }
            }
            let signed = signed_notional(position.notional, position.side.sign());
            match position.venue {
                VenueKind::Amm | VenueKind::StableSwap => {
                    exposure.amm_delta = exposure.amm_delta.saturating_add(signed);
                }
                VenueKind::Lending | VenueKind::Vault => {
                    exposure.lending_delta = exposure.lending_delta.saturating_add(signed);
                }
                VenueKind::Perpetual => {
                    exposure.perp_delta = exposure.perp_delta.saturating_add(signed);
                }
                VenueKind::BridgeReserve => {
                    let haircut = apply_bps(position.notional, asset.bridge_haircut_bps);
                    exposure.bridge_delta = exposure
                        .bridge_delta
                        .saturating_add(signed_notional(haircut, position.side.sign()));
                }
                VenueKind::TokenCovenant | VenueKind::Insurance => {}
            }
        }

        let budget_remaining = match self
            .privacy_budgets
            .values()
            .filter(|budget| budget.account_id == account_id)
            .map(|budget| budget.exposure_budget_remaining)
            .min()
        {
            Some(value) => value,
            None => self.config.exposure_privacy_budget,
        };
        exposure.privacy_budget_remaining = budget_remaining;
        exposure.net_delta = exposure
            .amm_delta
            .saturating_add(exposure.lending_delta)
            .saturating_add(exposure.perp_delta)
            .saturating_add(exposure.bridge_delta);
        exposure.margin_ratio_bps = margin_ratio_bps(
            exposure.gross_collateral_value,
            exposure.gross_liability_value,
        );
        exposure.risk_band = Some(self.classify_risk(&exposure));
        self.exposures.insert(account_id.to_string(), exposure);
        if let Some(account) = self.accounts.get_mut(account_id) {
            account.last_risk_height = height;
            account.exposure_root = map_root("account_exposure", &self.exposures);
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn risk_summary(&self) -> Value {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for exposure in self.exposures.values() {
            let band = match exposure.risk_band {
                Some(risk_band) => risk_band,
                None => RiskBand::Insolvent,
            }
            .as_str()
            .to_string();
            let count = match counts.get(&band) {
                Some(value) => *value,
                None => 0,
            }
            .saturating_add(1);
            counts.insert(band, count);
        }
        json!({
            "accounts": self.accounts.len(),
            "positions": self.positions.len(),
            "snapshots": self.snapshots.len(),
            "liquidation_corridors": self.liquidation_corridors.len(),
            "risk_band_counts": counts,
        })
    }

    fn classify_risk(&self, exposure: &ExposureRecord) -> RiskBand {
        if exposure.stale_oracle_count > 0 || exposure.privacy_budget_remaining == 0 {
            return RiskBand::Watch;
        }
        if exposure.margin_ratio_bps <= self.config.insolvency_margin_bps {
            return RiskBand::Insolvent;
        }
        if exposure.margin_ratio_bps <= self.config.maintenance_margin_bps {
            return RiskBand::Liquidatable;
        }
        if exposure.margin_ratio_bps <= self.config.deleverage_margin_bps {
            return RiskBand::Deleverage;
        }
        if exposure.margin_ratio_bps <= self.config.initial_margin_bps {
            return RiskBand::Watch;
        }
        if exposure.margin_ratio_bps >= self.config.initial_margin_bps.saturating_mul(2) {
            RiskBand::Prime
        } else {
            RiskBand::Standard
        }
    }

    fn oracle_status(&self, asset_id: &str, price_micro_units: u128, height: u64) -> OracleStatus {
        let prior = self
            .oracles
            .values()
            .filter(|record| record.asset_id == asset_id)
            .max_by_key(|record| record.updated_at_height);
        match prior {
            Some(record)
                if height.saturating_sub(record.updated_at_height)
                    > self.config.oracle_staleness_blocks =>
            {
                OracleStatus::Stale
            }
            Some(record)
                if deviation_bps(record.price_micro_units, price_micro_units)
                    > self.config.max_oracle_deviation_bps =>
            {
                OracleStatus::Deviating
            }
            Some(_) | None => OracleStatus::Fresh,
        }
    }

    fn open_liquidation_corridor(
        &mut self,
        account_id: &str,
        risk_band: RiskBand,
        height: u64,
    ) -> Result<()> {
        ensure!(
            self.liquidation_corridors.len() < self.config.max_liquidation_corridors,
            "liquidation corridor capacity reached"
        )?;
        let corridor_id = domain_hash(
            "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/corridor_id",
            &[
                HashPart::Str(account_id),
                HashPart::Str(risk_band.as_str()),
                HashPart::U64(height),
                HashPart::Str(&self.roots.exposures_root),
            ],
            32,
        );
        if self.liquidation_corridors.contains_key(&corridor_id) {
            return Ok(());
        }
        let (min_close_bps, max_close_bps, target_margin_bps) = match risk_band {
            RiskBand::Insolvent => (2_500, MAX_BPS, self.config.initial_margin_bps),
            RiskBand::Liquidatable => (1_000, 5_000, self.config.deleverage_margin_bps),
            RiskBand::Deleverage => (500, 2_500, self.config.initial_margin_bps),
            RiskBand::Prime | RiskBand::Standard | RiskBand::Watch => {
                (0, 0, self.config.initial_margin_bps)
            }
        };
        let route_root = domain_hash(
            "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/liquidation_route",
            &[
                HashPart::Str(account_id),
                HashPart::Str(&self.roots.markets_root),
                HashPart::Str(&self.roots.oracle_root),
            ],
            32,
        );
        self.liquidation_corridors.insert(
            corridor_id.clone(),
            LiquidationCorridorRecord {
                corridor_id: corridor_id.clone(),
                account_id: account_id.to_string(),
                risk_band,
                min_close_bps,
                max_close_bps,
                penalty_bps: self.config.liquidation_penalty_bps,
                keeper_fee_bps: self.config.max_user_fee_bps,
                target_margin_bps,
                route_root,
                opened_at_height: height,
                expires_at_height: height.saturating_add(self.config.snapshot_ttl_blocks),
                active: true,
            },
        );
        self.counters.liquidation_corridors_opened =
            self.counters.liquidation_corridors_opened.saturating_add(1);
        self.push_event("liquidation_corridor_opened", &corridor_id);
        Ok(())
    }

    fn push_event(&mut self, kind: &str, id: &str) {
        let event = domain_hash(
            "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/event",
            &[
                HashPart::Str(kind),
                HashPart::Str(id),
                HashPart::U64(self.event_log.len() as u64),
            ],
            32,
        );
        self.event_log.push(event);
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    seed_devnet(&mut state);
    state.refresh_roots();
    state
}

pub fn demo() -> Value {
    devnet().public_record()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn seed_devnet(state: &mut State) {
    let _ = state.register_account(RegisterAccountRequest {
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        owner_commitment: "owner:demo-cross-margin-root".to_string(),
        view_tag_root: "viewtag:demo-cross-margin-root".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.register_asset(RegisterAssetRequest {
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        symbol_commitment: "symbol:wxmr".to_string(),
        decimals: 12,
        collateral_factor_bps: 8_500,
        liability_factor_bps: 10_500,
        bridge_haircut_bps: 600,
        oracle_id: "oracle:wxmr-usd".to_string(),
        covenant_policy_id: "policy:wxmr-private-defi".to_string(),
    });
    let _ = state.register_asset(RegisterAssetRequest {
        asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        symbol_commitment: "symbol:private-usd".to_string(),
        decimals: 6,
        collateral_factor_bps: 9_200,
        liability_factor_bps: 10_100,
        bridge_haircut_bps: 150,
        oracle_id: "oracle:private-usd".to_string(),
        covenant_policy_id: "policy:private-usd-defi".to_string(),
    });
    let _ = state.register_asset(RegisterAssetRequest {
        asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
        symbol_commitment: "symbol:bridged-usdc".to_string(),
        decimals: 6,
        collateral_factor_bps: 8_800,
        liability_factor_bps: 10_200,
        bridge_haircut_bps: 350,
        oracle_id: "oracle:bridged-usdc".to_string(),
        covenant_policy_id: "policy:bridge-usdc-route".to_string(),
    });
    let _ = state.register_market(RegisterMarketRequest {
        market_id: DEFAULT_AMM_POOL_ID.to_string(),
        venue: VenueKind::Amm,
        base_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        risk_weight_bps: 1_100,
        netting_group: "net:xmr-usd-spot".to_string(),
        covenant_policy_id: "policy:amm-private-route".to_string(),
        open_interest_cap: 50_000_000_000_000,
    });
    let _ = state.register_market(RegisterMarketRequest {
        market_id: DEFAULT_LENDING_MARKET_ID.to_string(),
        venue: VenueKind::Lending,
        base_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        risk_weight_bps: 1_300,
        netting_group: "net:xmr-credit".to_string(),
        covenant_policy_id: "policy:lending-private-route".to_string(),
        open_interest_cap: 30_000_000_000_000,
    });
    let _ = state.register_market(RegisterMarketRequest {
        market_id: DEFAULT_PERP_MARKET_ID.to_string(),
        venue: VenueKind::Perpetual,
        base_asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        risk_weight_bps: 1_700,
        netting_group: "net:xmr-usd-perp".to_string(),
        covenant_policy_id: "policy:perp-private-route".to_string(),
        open_interest_cap: 75_000_000_000_000,
    });
    let _ = state.record_oracle(RecordOracleRequest {
        oracle_id: "oracle:wxmr-usd".to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        price_micro_units: 175_000_000,
        confidence_bps: 30,
        median_root: "median:wxmr-usd-devnet".to_string(),
        attestation_root: "attest:wxmr-usd-pq-root".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.record_oracle(RecordOracleRequest {
        oracle_id: "oracle:private-usd".to_string(),
        asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
        price_micro_units: 1_000_000,
        confidence_bps: 5,
        median_root: "median:private-usd-devnet".to_string(),
        attestation_root: "attest:private-usd-pq-root".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.record_oracle(RecordOracleRequest {
        oracle_id: "oracle:bridged-usdc".to_string(),
        asset_id: DEFAULT_BRIDGE_ASSET_ID.to_string(),
        price_micro_units: 999_700,
        confidence_bps: 8,
        median_root: "median:bridged-usdc-devnet".to_string(),
        attestation_root: "attest:bridged-usdc-pq-root".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.record_covenant_check(CovenantCheckRequest {
        check_id: "check:demo-amm-wxmr".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        market_id: DEFAULT_AMM_POOL_ID.to_string(),
        policy_id: "policy:amm-private-route".to_string(),
        verdict: CovenantVerdict::Allowed,
        proof_root: "proof:covenant-amm-demo".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.record_covenant_check(CovenantCheckRequest {
        check_id: "check:demo-lending-wxmr".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        market_id: DEFAULT_LENDING_MARKET_ID.to_string(),
        policy_id: "policy:lending-private-route".to_string(),
        verdict: CovenantVerdict::Allowed,
        proof_root: "proof:covenant-lending-demo".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.record_covenant_check(CovenantCheckRequest {
        check_id: "check:demo-perp-wxmr".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        market_id: DEFAULT_PERP_MARKET_ID.to_string(),
        policy_id: "policy:perp-private-route".to_string(),
        verdict: CovenantVerdict::Allowed,
        proof_root: "proof:covenant-perp-demo".to_string(),
        height: DEVNET_HEIGHT,
    });
    let _ = state.record_position(RecordPositionRequest {
        position_id: "pos:demo-amm-lp".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        market_id: DEFAULT_AMM_POOL_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        side: PositionSide::Liquidity,
        notional: 9_000_000_000,
        quantity_commitment: "qty:amm-lp".to_string(),
        price_commitment: "price:amm-lp".to_string(),
        margin_commitment: "margin:amm-lp".to_string(),
        privacy_nullifier: "nullifier:amm-lp-demo".to_string(),
        height: DEVNET_HEIGHT + 1,
    });
    let _ = state.record_position(RecordPositionRequest {
        position_id: "pos:demo-lending-borrow".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        market_id: DEFAULT_LENDING_MARKET_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        side: PositionSide::Borrow,
        notional: 4_500_000_000,
        quantity_commitment: "qty:lending-borrow".to_string(),
        price_commitment: "price:lending-borrow".to_string(),
        margin_commitment: "margin:lending-borrow".to_string(),
        privacy_nullifier: "nullifier:lending-borrow-demo".to_string(),
        height: DEVNET_HEIGHT + 2,
    });
    let _ = state.record_position(RecordPositionRequest {
        position_id: "pos:demo-perp-short".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        market_id: DEFAULT_PERP_MARKET_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        side: PositionSide::Short,
        notional: 3_250_000_000,
        quantity_commitment: "qty:perp-short".to_string(),
        price_commitment: "price:perp-short".to_string(),
        margin_commitment: "margin:perp-short".to_string(),
        privacy_nullifier: "nullifier:perp-short-demo".to_string(),
        height: DEVNET_HEIGHT + 3,
    });
    let _ = state.consume_privacy_budget(PrivacyBudgetRequest {
        budget_id: "budget:demo-wxmr".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        asset_id: DEFAULT_COLLATERAL_ASSET_ID.to_string(),
        consume_collateral_budget: 12_000,
        consume_exposure_budget: 18_000,
        event_root: "budget-event:demo".to_string(),
        height: DEVNET_HEIGHT + 4,
    });
    let _ = state.sign_risk_snapshot(RiskSnapshotRequest {
        snapshot_id: "snapshot:demo-cross-margin".to_string(),
        account_id: DEFAULT_ACCOUNT_ID.to_string(),
        pq_public_key_commitment: "pq-pubkey:demo-risk-committee".to_string(),
        pq_signature_root: "pq-signature:demo-risk-snapshot".to_string(),
        height: DEVNET_HEIGHT + 5,
    });
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn reject<T>(message: &str) -> Result<T> {
    Err(message.to_string())
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{field} must be non-empty"),
    )
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    ensure(value <= MAX_BPS, &format!("{field} exceeds MAX_BPS"))
}

fn ensure_known_asset(assets: &BTreeMap<String, AssetRecord>, asset_id: &str) -> Result<()> {
    match assets.get(asset_id) {
        Some(asset) if asset.enabled => Ok(()),
        Some(_) => reject("asset disabled"),
        None => reject("unknown asset"),
    }
}

fn ensure_account_active(
    accounts: &BTreeMap<String, AccountRecord>,
    account_id: &str,
) -> Result<()> {
    match accounts.get(account_id) {
        Some(account) if account.active => Ok(()),
        Some(_) => reject("account disabled"),
        None => reject("unknown account"),
    }
}

fn ensure_market_cap(state: &State, market: &MarketRecord, next_notional: u128) -> Result<()> {
    let open_interest = state
        .positions
        .values()
        .filter(|position| position.market_id == market.market_id && position.active)
        .fold(0u128, |acc, position| acc.saturating_add(position.notional));
    ensure(
        open_interest.saturating_add(next_notional) <= market.open_interest_cap,
        "market open interest cap exceeded",
    )
}

fn ensure_covenant_allows(
    state: &State,
    account_id: &str,
    asset_id: &str,
    market_id: &str,
) -> Result<()> {
    let allowed = state.covenant_checks.values().any(|check| {
        check.account_id == account_id
            && check.asset_id == asset_id
            && check.market_id == market_id
            && check.verdict.permits_risk_credit()
    });
    ensure(allowed, "missing permitted token covenant check")
}

fn apply_bps(value: u128, bps: u64) -> u128 {
    value.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn reduce_by_bps(value: u128, bps: u64) -> u128 {
    value.saturating_sub(apply_bps(value, bps))
}

fn increase_by_bps(value: u128, bps: u64) -> u128 {
    value.saturating_add(apply_bps(value, bps))
}

fn signed_notional(value: u128, sign: i128) -> i128 {
    let capped = value.min(i128::MAX as u128) as i128;
    capped.saturating_mul(sign)
}

fn margin_ratio_bps(collateral: u128, liability: u128) -> u64 {
    if liability == 0 {
        return MAX_BPS.saturating_mul(10);
    }
    let ratio = collateral.saturating_mul(MAX_BPS as u128) / liability;
    ratio.min(u64::MAX as u128) as u64
}

fn deviation_bps(previous: u128, next: u128) -> u64 {
    if previous == 0 {
        return MAX_BPS;
    }
    let delta = previous.abs_diff(next);
    let bps = delta.saturating_mul(MAX_BPS as u128) / previous;
    bps.min(u64::MAX as u128) as u64
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/empty",
        &[HashPart::Str(domain)],
        32,
    )
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            let value_json = json!(value);
            domain_hash(
                "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/map_leaf",
                &[
                    HashPart::Str(domain),
                    HashPart::Str(key),
                    HashPart::Json(&value_json),
                ],
                32,
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/{domain}"),
        &leaves,
    )
}

fn list_root(domain: &str, list: &[String]) -> String {
    let leaves = list
        .iter()
        .enumerate()
        .map(|(index, value)| {
            domain_hash(
                "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/list_leaf",
                &[
                    HashPart::Str(domain),
                    HashPart::U64(index as u64),
                    HashPart::Str(value),
                ],
                32,
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime/{domain}"),
        &leaves,
    )
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
