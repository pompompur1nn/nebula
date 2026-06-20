use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedDerivativesClearingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-derivatives-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_HEIGHT: u64 =
    744_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_L2_NETWORK:
    &str = "nebula-private-l2-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_PQ_MARGIN_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-private-margin-settlement-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_PQ_ORDER_SCHEME: &str =
    "ml-kem-1024-sealed-order+ml-dsa-87-trader-authorization-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_ORACLE_SCHEME: &str =
    "ml-dsa-87+threshold-vrf-private-derivatives-oracle-guard-rail-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_COVENANT_SCHEME: &str =
    "zk-token-covenant-confidential-derivatives-transfer-hook-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_LIQUIDATION_SCHEME:
    &str = "zk-private-liquidation-netting-auction-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_BATCH_SCHEME: &str =
    "low-fee-confidential-derivatives-clearing-batch-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-derivatives-clearing-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_FEE_ASSET_ID:
    &str = "dnr-devnet-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID:
    &str = "dusd-private-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_BRIDGE_ID:
    &str = "monero-private-l2-bridge-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS:
    u64 = 1_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS:
    u64 = 900;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LIQUIDATION_MARGIN_BPS:
    u64 = 650;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAX_ORACLE_DEVIATION_BPS:
    u64 = 350;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAX_MARK_STALENESS_BLOCKS:
    u64 = 16;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LOW_FEE_BATCH_LIMIT:
    usize = 512;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LOW_FEE_NOTIONAL_CAP:
    u64 = 250_000_000_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_MARKETS: usize =
    131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_ACCOUNTS: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_POSITIONS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_SETTLEMENTS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BATCHES: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_ORACLE_MARKS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_COVENANTS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_LIQUIDATIONS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BRIDGE_HAIRCUTS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_NULLIFIERS: usize =
    2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentKind {
    TokenizedCallOption,
    TokenizedPutOption,
    PerpetualFuture,
    DatedFuture,
    VarianceSwap,
    StructuredNote,
    BarrierNote,
    CoveredYieldNote,
    LiquidationClaimToken,
    BridgeCollateralReceipt,
}

impl InstrumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenizedCallOption => "tokenized_call_option",
            Self::TokenizedPutOption => "tokenized_put_option",
            Self::PerpetualFuture => "perpetual_future",
            Self::DatedFuture => "dated_future",
            Self::VarianceSwap => "variance_swap",
            Self::StructuredNote => "structured_note",
            Self::BarrierNote => "barrier_note",
            Self::CoveredYieldNote => "covered_yield_note",
            Self::LiquidationClaimToken => "liquidation_claim_token",
            Self::BridgeCollateralReceipt => "bridge_collateral_receipt",
        }
    }

    pub fn is_option(self) -> bool {
        matches!(self, Self::TokenizedCallOption | Self::TokenizedPutOption)
    }

    pub fn is_perp(self) -> bool {
        matches!(self, Self::PerpetualFuture)
    }

    pub fn is_note(self) -> bool {
        matches!(
            self,
            Self::StructuredNote | Self::BarrierNote | Self::CoveredYieldNote
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Draft,
    Listed,
    Trading,
    ReduceOnly,
    OracleGuarded,
    Halted,
    Expired,
    Settled,
    Retired,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Listed => "listed",
            Self::Trading => "trading",
            Self::ReduceOnly => "reduce_only",
            Self::OracleGuarded => "oracle_guarded",
            Self::Halted => "halted",
            Self::Expired => "expired",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_new_risk(self) -> bool {
        matches!(self, Self::Trading | Self::OracleGuarded)
    }

    pub fn allows_reduce(self) -> bool {
        matches!(
            self,
            Self::Trading | Self::ReduceOnly | Self::OracleGuarded | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
    CoveredShort,
    MarketMakerInventory,
    DeltaHedge,
    LiquidationBackstop,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::CoveredShort => "covered_short",
            Self::MarketMakerInventory => "market_maker_inventory",
            Self::DeltaHedge => "delta_hedge",
            Self::LiquidationBackstop => "liquidation_backstop",
        }
    }

    pub fn is_short_risk(self) -> bool {
        matches!(
            self,
            Self::Short | Self::CoveredShort | Self::MarketMakerInventory
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    Open,
    MarginReserved,
    ReduceOnly,
    UnderMaintMargin,
    LiquidationQueued,
    Liquidating,
    Netted,
    Settled,
    Closed,
    Cancelled,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::MarginReserved => "margin_reserved",
            Self::ReduceOnly => "reduce_only",
            Self::UnderMaintMargin => "under_maint_margin",
            Self::LiquidationQueued => "liquidation_queued",
            Self::Liquidating => "liquidating",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Closed => "closed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn counts_open(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::MarginReserved
                | Self::ReduceOnly
                | Self::UnderMaintMargin
                | Self::LiquidationQueued
                | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    Premium,
    VariationMargin,
    Funding,
    Exercise,
    ExpiryCashSettle,
    StructuredCoupon,
    BarrierEvent,
    Liquidation,
    BridgeHaircut,
    CovenantRemediation,
    FeeRebate,
}

impl SettlementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Premium => "premium",
            Self::VariationMargin => "variation_margin",
            Self::Funding => "funding",
            Self::Exercise => "exercise",
            Self::ExpiryCashSettle => "expiry_cash_settle",
            Self::StructuredCoupon => "structured_coupon",
            Self::BarrierEvent => "barrier_event",
            Self::Liquidation => "liquidation",
            Self::BridgeHaircut => "bridge_haircut",
            Self::CovenantRemediation => "covenant_remediation",
            Self::FeeRebate => "fee_rebate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    GuardChecked,
    MarginChecked,
    CovenantChecked,
    Queued,
    Applied,
    Rejected,
    Reversed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::GuardChecked => "guard_checked",
            Self::MarginChecked => "margin_checked",
            Self::CovenantChecked => "covenant_checked",
            Self::Queued => "queued",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleGuardStatus {
    Pending,
    Accepted,
    DeviationLimited,
    Stale,
    QuorumFailed,
    CircuitBroken,
}

impl OracleGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::DeviationLimited => "deviation_limited",
            Self::Stale => "stale",
            Self::QuorumFailed => "quorum_failed",
            Self::CircuitBroken => "circuit_broken",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantStatus {
    Draft,
    Active,
    GracePeriod,
    Breached,
    Remediating,
    Paused,
    Retired,
}

impl CovenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::Breached => "breached",
            Self::Remediating => "remediating",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn transfer_allowed(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Proposed,
    Eligible,
    Netted,
    BackstopRouted,
    Settled,
    Rejected,
}

impl LiquidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Eligible => "eligible",
            Self::Netted => "netted",
            Self::BackstopRouted => "backstop_routed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub replay_domain: String,
    pub pq_margin_scheme: String,
    pub pq_order_scheme: String,
    pub oracle_scheme: String,
    pub covenant_scheme: String,
    pub liquidation_scheme: String,
    pub batch_scheme: String,
    pub fee_asset_id: String,
    pub default_collateral_asset_id: String,
    pub bridge_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_margin_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_mark_staleness_blocks: u64,
    pub low_fee_batch_limit: usize,
    pub low_fee_notional_cap: u64,
    pub max_markets: usize,
    pub max_accounts: usize,
    pub max_positions: usize,
    pub max_settlements: usize,
    pub max_batches: usize,
    pub max_oracle_marks: usize,
    pub max_covenants: usize,
    pub max_liquidations: usize,
    pub max_bridge_haircuts: usize,
    pub max_nullifiers: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_L2_NETWORK
                    .to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_SCHEMA_VERSION,
            replay_domain:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_REPLAY_DOMAIN
                    .to_string(),
            pq_margin_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_PQ_MARGIN_SCHEME
                    .to_string(),
            pq_order_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_PQ_ORDER_SCHEME
                    .to_string(),
            oracle_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_ORACLE_SCHEME
                    .to_string(),
            covenant_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_COVENANT_SCHEME
                    .to_string(),
            liquidation_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_LIQUIDATION_SCHEME
                    .to_string(),
            batch_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_BATCH_SCHEME
                    .to_string(),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            default_collateral_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            bridge_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_BRIDGE_ID
                    .to_string(),
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            initial_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LIQUIDATION_MARGIN_BPS,
            max_oracle_deviation_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAX_ORACLE_DEVIATION_BPS,
            max_mark_staleness_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAX_MARK_STALENESS_BLOCKS,
            low_fee_batch_limit:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LOW_FEE_BATCH_LIMIT,
            low_fee_notional_cap:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LOW_FEE_NOTIONAL_CAP,
            max_markets: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_MARKETS,
            max_accounts:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_ACCOUNTS,
            max_positions:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_POSITIONS,
            max_settlements:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_SETTLEMENTS,
            max_batches: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BATCHES,
            max_oracle_marks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_ORACLE_MARKS,
            max_covenants:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_COVENANTS,
            max_liquidations:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_LIQUIDATIONS,
            max_bridge_haircuts:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BRIDGE_HAIRCUTS,
            max_nullifiers:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_NULLIFIERS,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub markets_created: u64,
    pub accounts_registered: u64,
    pub covenants_registered: u64,
    pub positions_opened: u64,
    pub positions_reduced: u64,
    pub settlements_recorded: u64,
    pub settlements_applied: u64,
    pub oracle_marks_recorded: u64,
    pub oracle_guard_rejections: u64,
    pub margin_rejections: u64,
    pub covenant_rejections: u64,
    pub liquidations_proposed: u64,
    pub liquidations_netted: u64,
    pub bridge_haircuts_recorded: u64,
    pub low_fee_batches: u64,
    pub nullifiers_seen: u64,
    pub public_summaries_published: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub markets_root: String,
    pub accounts_root: String,
    pub covenants_root: String,
    pub positions_root: String,
    pub settlements_root: String,
    pub oracle_marks_root: String,
    pub liquidation_root: String,
    pub bridge_haircut_root: String,
    pub batch_root: String,
    pub nullifier_root: String,
    pub public_summary_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketRecord {
    pub market_id: String,
    pub instrument_kind: InstrumentKind,
    pub status: MarketStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub collateral_asset_id: String,
    pub oracle_feed_id: String,
    pub covenant_id: String,
    pub bridge_id: String,
    pub strike_price: u64,
    pub lot_size: u64,
    pub max_open_interest: u64,
    pub open_interest: u64,
    pub expiry_height: u64,
    pub funding_interval_blocks: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_margin_bps: u64,
    pub created_height: u64,
    pub last_mark_price: u64,
    pub last_mark_height: u64,
    pub metadata_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRecord {
    pub account_id: String,
    pub owner_commitment: String,
    pub view_tag: String,
    pub pq_public_key_commitment: String,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub reserved_margin: u64,
    pub realized_pnl: i128,
    pub unrealized_pnl: i128,
    pub nonce: u64,
    pub risk_bucket: String,
    pub active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CovenantRecord {
    pub covenant_id: String,
    pub status: CovenantStatus,
    pub asset_id: String,
    pub issuer_commitment: String,
    pub allowed_market_kinds: BTreeSet<InstrumentKind>,
    pub max_leverage_bps: u64,
    pub max_notional_per_account: u64,
    pub max_transfer_notional: u64,
    pub min_privacy_set_size: u64,
    pub requires_bridge_haircut: bool,
    pub allow_secondary_transfer: bool,
    pub remediation_fee_bps: u64,
    pub covenant_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PositionRecord {
    pub position_id: String,
    pub account_id: String,
    pub market_id: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub quantity: u64,
    pub entry_price: u64,
    pub mark_price: u64,
    pub notional: u64,
    pub margin_reserved: u64,
    pub liquidation_threshold: u64,
    pub token_commitment: String,
    pub order_nullifier: String,
    pub opened_height: u64,
    pub updated_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleMarkRecord {
    pub mark_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub mark_price: u64,
    pub index_price: u64,
    pub confidence_bps: u64,
    pub deviation_bps: u64,
    pub quorum_weight: u64,
    pub guard_status: OracleGuardStatus,
    pub attestation_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub settlement_kind: SettlementKind,
    pub status: SettlementStatus,
    pub market_id: String,
    pub position_id: String,
    pub account_id: String,
    pub counterparty_account_id: String,
    pub amount: i128,
    pub fee_amount: u64,
    pub margin_delta: i128,
    pub mark_price: u64,
    pub pq_signature_commitment: String,
    pub proof_commitment: String,
    pub nullifier: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationRecord {
    pub liquidation_id: String,
    pub position_id: String,
    pub account_id: String,
    pub market_id: String,
    pub status: LiquidationStatus,
    pub private_shortfall_commitment: String,
    pub netted_notional: u64,
    pub backstop_account_id: String,
    pub incentive_bps: u64,
    pub proof_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeHaircutRecord {
    pub haircut_id: String,
    pub bridge_id: String,
    pub collateral_asset_id: String,
    pub source_domain: String,
    pub haircut_bps: u64,
    pub liquidity_depth: u64,
    pub stress_score_bps: u64,
    pub attestation_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClearingBatchRecord {
    pub batch_id: String,
    pub status: SettlementStatus,
    pub settlement_ids: Vec<String>,
    pub total_notional: u64,
    pub fee_asset_id: String,
    pub aggregate_fee: u64,
    pub low_fee: bool,
    pub privacy_set_size: u64,
    pub proof_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicRiskSummaryRecord {
    pub summary_id: String,
    pub height: u64,
    pub markets: u64,
    pub open_positions: u64,
    pub total_open_interest: u64,
    pub total_reserved_margin: u64,
    pub liquidation_queue_notional: u64,
    pub max_oracle_deviation_bps: u64,
    pub bridge_haircut_bps: u64,
    pub low_fee_batches: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateMarketRequest {
    pub market_id: String,
    pub instrument_kind: InstrumentKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub collateral_asset_id: String,
    pub oracle_feed_id: String,
    pub covenant_id: String,
    pub bridge_id: String,
    pub strike_price: u64,
    pub lot_size: u64,
    pub max_open_interest: u64,
    pub expiry_height: u64,
    pub funding_interval_blocks: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_margin_bps: u64,
    pub created_height: u64,
    pub metadata_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterAccountRequest {
    pub account_id: String,
    pub owner_commitment: String,
    pub view_tag: String,
    pub pq_public_key_commitment: String,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub risk_bucket: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterCovenantRequest {
    pub covenant_id: String,
    pub asset_id: String,
    pub issuer_commitment: String,
    pub allowed_market_kinds: BTreeSet<InstrumentKind>,
    pub max_leverage_bps: u64,
    pub max_notional_per_account: u64,
    pub max_transfer_notional: u64,
    pub min_privacy_set_size: u64,
    pub requires_bridge_haircut: bool,
    pub allow_secondary_transfer: bool,
    pub remediation_fee_bps: u64,
    pub covenant_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenPositionRequest {
    pub position_id: String,
    pub account_id: String,
    pub market_id: String,
    pub side: PositionSide,
    pub quantity: u64,
    pub entry_price: u64,
    pub token_commitment: String,
    pub order_nullifier: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordOracleMarkRequest {
    pub mark_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub mark_price: u64,
    pub index_price: u64,
    pub confidence_bps: u64,
    pub quorum_weight: u64,
    pub attestation_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordSettlementRequest {
    pub settlement_id: String,
    pub settlement_kind: SettlementKind,
    pub market_id: String,
    pub position_id: String,
    pub account_id: String,
    pub counterparty_account_id: String,
    pub amount: i128,
    pub fee_amount: u64,
    pub margin_delta: i128,
    pub mark_price: u64,
    pub pq_signature_commitment: String,
    pub proof_commitment: String,
    pub nullifier: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeLiquidationRequest {
    pub liquidation_id: String,
    pub position_id: String,
    pub private_shortfall_commitment: String,
    pub backstop_account_id: String,
    pub incentive_bps: u64,
    pub proof_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordBridgeHaircutRequest {
    pub haircut_id: String,
    pub bridge_id: String,
    pub collateral_asset_id: String,
    pub source_domain: String,
    pub haircut_bps: u64,
    pub liquidity_depth: u64,
    pub stress_score_bps: u64,
    pub attestation_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApplyClearingBatchRequest {
    pub batch_id: String,
    pub settlement_ids: Vec<String>,
    pub privacy_set_size: u64,
    pub proof_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub markets: BTreeMap<String, MarketRecord>,
    pub accounts: BTreeMap<String, AccountRecord>,
    pub covenants: BTreeMap<String, CovenantRecord>,
    pub positions: BTreeMap<String, PositionRecord>,
    pub settlements: BTreeMap<String, SettlementRecord>,
    pub oracle_marks: BTreeMap<String, OracleMarkRecord>,
    pub liquidations: BTreeMap<String, LiquidationRecord>,
    pub bridge_haircuts: BTreeMap<String, BridgeHaircutRecord>,
    pub clearing_batches: BTreeMap<String, ClearingBatchRecord>,
    pub public_summaries: BTreeMap<String, PublicRiskSummaryRecord>,
    pub seen_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            markets: BTreeMap::new(),
            accounts: BTreeMap::new(),
            covenants: BTreeMap::new(),
            positions: BTreeMap::new(),
            settlements: BTreeMap::new(),
            oracle_marks: BTreeMap::new(),
            liquidations: BTreeMap::new(),
            bridge_haircuts: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
            seen_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn create_market(&mut self, request: CreateMarketRequest) -> Result<MarketRecord> {
        self.ensure_id("market_id", &request.market_id)?;
        self.ensure_capacity(self.markets.len(), self.config.max_markets, "markets")?;
        if self.markets.contains_key(&request.market_id) {
            return Err(format!("market already exists: {}", request.market_id));
        }
        if !self.covenants.contains_key(&request.covenant_id) {
            return Err(format!("unknown covenant: {}", request.covenant_id));
        }
        self.ensure_bps("maker_fee_bps", request.maker_fee_bps)?;
        self.ensure_bps("taker_fee_bps", request.taker_fee_bps)?;
        self.ensure_margin_ladder(
            request.initial_margin_bps,
            request.maintenance_margin_bps,
            request.liquidation_margin_bps,
        )?;
        if request.lot_size == 0 || request.max_open_interest == 0 {
            return Err("market lot size and max open interest must be positive".to_string());
        }
        let covenant = match self.covenants.get(&request.covenant_id) {
            Some(value) => value,
            None => return Err(format!("unknown covenant: {}", request.covenant_id)),
        };
        if !covenant
            .allowed_market_kinds
            .contains(&request.instrument_kind)
        {
            return Err("covenant does not allow requested instrument kind".to_string());
        }
        if covenant.status != CovenantStatus::Active {
            return Err("covenant is not active".to_string());
        }
        let record = MarketRecord {
            market_id: request.market_id.clone(),
            instrument_kind: request.instrument_kind,
            status: MarketStatus::Listed,
            base_asset_id: request.base_asset_id,
            quote_asset_id: request.quote_asset_id,
            collateral_asset_id: request.collateral_asset_id,
            oracle_feed_id: request.oracle_feed_id,
            covenant_id: request.covenant_id,
            bridge_id: request.bridge_id,
            strike_price: request.strike_price,
            lot_size: request.lot_size,
            max_open_interest: request.max_open_interest,
            open_interest: 0,
            expiry_height: request.expiry_height,
            funding_interval_blocks: request.funding_interval_blocks,
            maker_fee_bps: request.maker_fee_bps,
            taker_fee_bps: request.taker_fee_bps,
            initial_margin_bps: request.initial_margin_bps,
            maintenance_margin_bps: request.maintenance_margin_bps,
            liquidation_margin_bps: request.liquidation_margin_bps,
            created_height: request.created_height,
            last_mark_price: request.strike_price,
            last_mark_height: request.created_height,
            metadata_commitment: request.metadata_commitment,
        };
        self.markets.insert(request.market_id, record.clone());
        self.counters.markets_created = self.counters.markets_created.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_account(&mut self, request: RegisterAccountRequest) -> Result<AccountRecord> {
        self.ensure_id("account_id", &request.account_id)?;
        self.ensure_capacity(self.accounts.len(), self.config.max_accounts, "accounts")?;
        if self.accounts.contains_key(&request.account_id) {
            return Err(format!("account already exists: {}", request.account_id));
        }
        let record = AccountRecord {
            account_id: request.account_id.clone(),
            owner_commitment: request.owner_commitment,
            view_tag: request.view_tag,
            pq_public_key_commitment: request.pq_public_key_commitment,
            collateral_asset_id: request.collateral_asset_id,
            collateral_commitment: request.collateral_commitment,
            reserved_margin: 0,
            realized_pnl: 0,
            unrealized_pnl: 0,
            nonce: 0,
            risk_bucket: request.risk_bucket,
            active: true,
        };
        self.accounts.insert(request.account_id, record.clone());
        self.counters.accounts_registered = self.counters.accounts_registered.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn register_covenant(
        &mut self,
        request: RegisterCovenantRequest,
    ) -> Result<CovenantRecord> {
        self.ensure_id("covenant_id", &request.covenant_id)?;
        self.ensure_capacity(self.covenants.len(), self.config.max_covenants, "covenants")?;
        if self.covenants.contains_key(&request.covenant_id) {
            return Err(format!("covenant already exists: {}", request.covenant_id));
        }
        self.ensure_bps("max_leverage_bps", request.max_leverage_bps)?;
        self.ensure_bps("remediation_fee_bps", request.remediation_fee_bps)?;
        if request.allowed_market_kinds.is_empty() {
            return Err("covenant must allow at least one instrument kind".to_string());
        }
        if request.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("covenant privacy set is below runtime minimum".to_string());
        }
        let record = CovenantRecord {
            covenant_id: request.covenant_id.clone(),
            status: CovenantStatus::Active,
            asset_id: request.asset_id,
            issuer_commitment: request.issuer_commitment,
            allowed_market_kinds: request.allowed_market_kinds,
            max_leverage_bps: request.max_leverage_bps,
            max_notional_per_account: request.max_notional_per_account,
            max_transfer_notional: request.max_transfer_notional,
            min_privacy_set_size: request.min_privacy_set_size,
            requires_bridge_haircut: request.requires_bridge_haircut,
            allow_secondary_transfer: request.allow_secondary_transfer,
            remediation_fee_bps: request.remediation_fee_bps,
            covenant_root: request.covenant_root,
        };
        self.covenants.insert(request.covenant_id, record.clone());
        self.counters.covenants_registered = self.counters.covenants_registered.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_position(&mut self, request: OpenPositionRequest) -> Result<PositionRecord> {
        self.ensure_id("position_id", &request.position_id)?;
        self.ensure_capacity(self.positions.len(), self.config.max_positions, "positions")?;
        if self.positions.contains_key(&request.position_id) {
            return Err(format!("position already exists: {}", request.position_id));
        }
        if self.seen_nullifiers.contains(&request.order_nullifier) {
            return Err("order nullifier already used".to_string());
        }
        let market = match self.markets.get(&request.market_id) {
            Some(value) => value.clone(),
            None => return Err(format!("unknown market: {}", request.market_id)),
        };
        if !market.status.accepts_new_risk() && market.status != MarketStatus::Listed {
            return Err("market does not accept new risk".to_string());
        }
        let account = match self.accounts.get(&request.account_id) {
            Some(value) => value.clone(),
            None => return Err(format!("unknown account: {}", request.account_id)),
        };
        if !account.active {
            return Err("account is inactive".to_string());
        }
        self.check_token_covenant(
            &market.covenant_id,
            market.instrument_kind,
            request.quantity.saturating_mul(request.entry_price),
            true,
        )?;
        let quantity_notional = request.quantity.saturating_mul(request.entry_price);
        let bridge_haircut_bps = self.current_bridge_haircut_bps(&market.bridge_id);
        let adjusted_notional = apply_bps_up(
            quantity_notional,
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BPS
                .saturating_add(bridge_haircut_bps),
        );
        let margin_reserved = apply_bps_up(adjusted_notional, market.initial_margin_bps);
        let liquidation_threshold = apply_bps_up(adjusted_notional, market.liquidation_margin_bps);
        if market.open_interest.saturating_add(request.quantity) > market.max_open_interest {
            return Err("market open interest cap exceeded".to_string());
        }
        let record = PositionRecord {
            position_id: request.position_id.clone(),
            account_id: request.account_id.clone(),
            market_id: request.market_id.clone(),
            side: request.side,
            status: PositionStatus::MarginReserved,
            quantity: request.quantity,
            entry_price: request.entry_price,
            mark_price: market.last_mark_price,
            notional: quantity_notional,
            margin_reserved,
            liquidation_threshold,
            token_commitment: request.token_commitment,
            order_nullifier: request.order_nullifier.clone(),
            opened_height: request.height,
            updated_height: request.height,
        };
        self.positions.insert(request.position_id, record.clone());
        self.seen_nullifiers.insert(request.order_nullifier);
        if let Some(market_mut) = self.markets.get_mut(&request.market_id) {
            market_mut.status = MarketStatus::Trading;
            market_mut.open_interest = market_mut.open_interest.saturating_add(request.quantity);
        }
        if let Some(account_mut) = self.accounts.get_mut(&request.account_id) {
            account_mut.reserved_margin =
                account_mut.reserved_margin.saturating_add(margin_reserved);
            account_mut.nonce = account_mut.nonce.saturating_add(1);
        }
        self.counters.positions_opened = self.counters.positions_opened.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_oracle_mark(
        &mut self,
        request: RecordOracleMarkRequest,
    ) -> Result<OracleMarkRecord> {
        self.ensure_id("mark_id", &request.mark_id)?;
        self.ensure_capacity(
            self.oracle_marks.len(),
            self.config.max_oracle_marks,
            "oracle_marks",
        )?;
        if self.oracle_marks.contains_key(&request.mark_id) {
            return Err(format!("oracle mark already exists: {}", request.mark_id));
        }
        self.ensure_bps("confidence_bps", request.confidence_bps)?;
        let market = match self.markets.get(&request.market_id) {
            Some(value) => value.clone(),
            None => return Err(format!("unknown market: {}", request.market_id)),
        };
        if market.oracle_feed_id != request.feed_id {
            return Err("oracle feed does not match market".to_string());
        }
        let deviation_bps = deviation_bps(request.mark_price, request.index_price);
        let guard_status = if request.quorum_weight == 0 {
            OracleGuardStatus::QuorumFailed
        } else if request.height.saturating_sub(market.last_mark_height)
            > self.config.max_mark_staleness_blocks
            && market.last_mark_height != 0
        {
            OracleGuardStatus::Stale
        } else if deviation_bps > self.config.max_oracle_deviation_bps {
            OracleGuardStatus::DeviationLimited
        } else {
            OracleGuardStatus::Accepted
        };
        if guard_status != OracleGuardStatus::Accepted {
            self.counters.oracle_guard_rejections =
                self.counters.oracle_guard_rejections.saturating_add(1);
        }
        let record = OracleMarkRecord {
            mark_id: request.mark_id.clone(),
            market_id: request.market_id.clone(),
            feed_id: request.feed_id,
            mark_price: request.mark_price,
            index_price: request.index_price,
            confidence_bps: request.confidence_bps,
            deviation_bps,
            quorum_weight: request.quorum_weight,
            guard_status,
            attestation_root: request.attestation_root,
            height: request.height,
        };
        self.oracle_marks.insert(request.mark_id, record.clone());
        if guard_status == OracleGuardStatus::Accepted {
            if let Some(market_mut) = self.markets.get_mut(&request.market_id) {
                market_mut.last_mark_price = request.mark_price;
                market_mut.last_mark_height = request.height;
            }
            self.reprice_positions(&request.market_id, request.mark_price, request.height);
        } else if let Some(market_mut) = self.markets.get_mut(&request.market_id) {
            market_mut.status = MarketStatus::OracleGuarded;
        }
        self.counters.oracle_marks_recorded = self.counters.oracle_marks_recorded.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_settlement(
        &mut self,
        request: RecordSettlementRequest,
    ) -> Result<SettlementRecord> {
        self.ensure_id("settlement_id", &request.settlement_id)?;
        self.ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlements",
        )?;
        if self.settlements.contains_key(&request.settlement_id) {
            return Err(format!(
                "settlement already exists: {}",
                request.settlement_id
            ));
        }
        if self.seen_nullifiers.contains(&request.nullifier) {
            return Err("settlement nullifier already used".to_string());
        }
        let position = match self.positions.get(&request.position_id) {
            Some(value) => value.clone(),
            None => return Err(format!("unknown position: {}", request.position_id)),
        };
        if position.market_id != request.market_id || position.account_id != request.account_id {
            return Err("settlement does not match position ownership".to_string());
        }
        let market = match self.markets.get(&request.market_id) {
            Some(value) => value.clone(),
            None => return Err(format!("unknown market: {}", request.market_id)),
        };
        if !market.status.allows_reduce() && request.settlement_kind != SettlementKind::FeeRebate {
            return Err("market is not settleable".to_string());
        }
        self.check_oracle_guard(&market, request.mark_price, request.height)?;
        self.check_margin_delta(&position, request.margin_delta)?;
        self.check_token_covenant(
            &market.covenant_id,
            market.instrument_kind,
            position.notional,
            false,
        )?;
        let record = SettlementRecord {
            settlement_id: request.settlement_id.clone(),
            settlement_kind: request.settlement_kind,
            status: SettlementStatus::Queued,
            market_id: request.market_id,
            position_id: request.position_id,
            account_id: request.account_id,
            counterparty_account_id: request.counterparty_account_id,
            amount: request.amount,
            fee_amount: request.fee_amount,
            margin_delta: request.margin_delta,
            mark_price: request.mark_price,
            pq_signature_commitment: request.pq_signature_commitment,
            proof_commitment: request.proof_commitment,
            nullifier: request.nullifier.clone(),
            height: request.height,
        };
        self.settlements
            .insert(request.settlement_id, record.clone());
        self.seen_nullifiers.insert(request.nullifier);
        self.counters.settlements_recorded = self.counters.settlements_recorded.saturating_add(1);
        self.counters.nullifiers_seen = self.counters.nullifiers_seen.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn propose_liquidation(
        &mut self,
        request: ProposeLiquidationRequest,
    ) -> Result<LiquidationRecord> {
        self.ensure_id("liquidation_id", &request.liquidation_id)?;
        self.ensure_capacity(
            self.liquidations.len(),
            self.config.max_liquidations,
            "liquidations",
        )?;
        if self.liquidations.contains_key(&request.liquidation_id) {
            return Err(format!(
                "liquidation already exists: {}",
                request.liquidation_id
            ));
        }
        self.ensure_bps("incentive_bps", request.incentive_bps)?;
        let position = match self.positions.get(&request.position_id) {
            Some(value) => value.clone(),
            None => return Err(format!("unknown position: {}", request.position_id)),
        };
        let eligible = position.margin_reserved <= position.liquidation_threshold
            || position.status == PositionStatus::UnderMaintMargin;
        let status = if eligible {
            LiquidationStatus::Eligible
        } else {
            LiquidationStatus::Rejected
        };
        let netted_notional = self.nettable_liquidation_notional(&position);
        let record = LiquidationRecord {
            liquidation_id: request.liquidation_id.clone(),
            position_id: request.position_id.clone(),
            account_id: position.account_id.clone(),
            market_id: position.market_id.clone(),
            status,
            private_shortfall_commitment: request.private_shortfall_commitment,
            netted_notional,
            backstop_account_id: request.backstop_account_id,
            incentive_bps: request.incentive_bps,
            proof_commitment: request.proof_commitment,
            height: request.height,
        };
        self.liquidations
            .insert(request.liquidation_id, record.clone());
        if eligible {
            if let Some(position_mut) = self.positions.get_mut(&request.position_id) {
                position_mut.status = PositionStatus::LiquidationQueued;
                position_mut.updated_height = request.height;
            }
        }
        self.counters.liquidations_proposed = self.counters.liquidations_proposed.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_bridge_haircut(
        &mut self,
        request: RecordBridgeHaircutRequest,
    ) -> Result<BridgeHaircutRecord> {
        self.ensure_id("haircut_id", &request.haircut_id)?;
        self.ensure_capacity(
            self.bridge_haircuts.len(),
            self.config.max_bridge_haircuts,
            "bridge_haircuts",
        )?;
        if self.bridge_haircuts.contains_key(&request.haircut_id) {
            return Err(format!(
                "bridge haircut already exists: {}",
                request.haircut_id
            ));
        }
        self.ensure_bps("haircut_bps", request.haircut_bps)?;
        self.ensure_bps("stress_score_bps", request.stress_score_bps)?;
        let record = BridgeHaircutRecord {
            haircut_id: request.haircut_id.clone(),
            bridge_id: request.bridge_id,
            collateral_asset_id: request.collateral_asset_id,
            source_domain: request.source_domain,
            haircut_bps: request.haircut_bps,
            liquidity_depth: request.liquidity_depth,
            stress_score_bps: request.stress_score_bps,
            attestation_root: request.attestation_root,
            height: request.height,
        };
        self.bridge_haircuts
            .insert(request.haircut_id, record.clone());
        self.counters.bridge_haircuts_recorded =
            self.counters.bridge_haircuts_recorded.saturating_add(1);
        self.refresh_roots();
        Ok(record)
    }

    pub fn apply_clearing_batch(
        &mut self,
        request: ApplyClearingBatchRequest,
    ) -> Result<ClearingBatchRecord> {
        self.ensure_id("batch_id", &request.batch_id)?;
        self.ensure_capacity(
            self.clearing_batches.len(),
            self.config.max_batches,
            "clearing_batches",
        )?;
        if self.clearing_batches.contains_key(&request.batch_id) {
            return Err(format!(
                "clearing batch already exists: {}",
                request.batch_id
            ));
        }
        if request.settlement_ids.is_empty() {
            return Err("clearing batch requires settlements".to_string());
        }
        if request.settlement_ids.len() > self.config.low_fee_batch_limit {
            return Err("clearing batch exceeds configured settlement limit".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("clearing batch privacy set is below minimum".to_string());
        }
        let mut total_notional = 0_u64;
        let mut aggregate_fee = 0_u64;
        let mut touched_positions = BTreeSet::new();
        for settlement_id in &request.settlement_ids {
            let settlement = match self.settlements.get(settlement_id) {
                Some(value) => value,
                None => return Err(format!("unknown settlement: {}", settlement_id)),
            };
            if settlement.status != SettlementStatus::Queued {
                return Err(format!("settlement is not queued: {}", settlement_id));
            }
            let abs_amount = signed_abs_u64(settlement.amount);
            total_notional = total_notional.saturating_add(abs_amount);
            aggregate_fee = aggregate_fee.saturating_add(settlement.fee_amount);
            touched_positions.insert(settlement.position_id.clone());
        }
        let low_fee = total_notional <= self.config.low_fee_notional_cap
            && request.settlement_ids.len() <= self.config.low_fee_batch_limit;
        for settlement_id in &request.settlement_ids {
            let settlement = match self.settlements.get(settlement_id) {
                Some(value) => value.clone(),
                None => return Err(format!("unknown settlement: {}", settlement_id)),
            };
            self.apply_single_settlement(&settlement, request.height)?;
            if let Some(settlement_mut) = self.settlements.get_mut(settlement_id) {
                settlement_mut.status = SettlementStatus::Applied;
            }
        }
        for position_id in touched_positions {
            self.refresh_position_status(&position_id, request.height);
        }
        let record = ClearingBatchRecord {
            batch_id: request.batch_id.clone(),
            status: SettlementStatus::Applied,
            settlement_ids: request.settlement_ids,
            total_notional,
            fee_asset_id: self.config.fee_asset_id.clone(),
            aggregate_fee,
            low_fee,
            privacy_set_size: request.privacy_set_size,
            proof_root: request.proof_root,
            height: request.height,
        };
        self.clearing_batches
            .insert(request.batch_id, record.clone());
        self.counters.settlements_applied = self
            .counters
            .settlements_applied
            .saturating_add(record.settlement_ids.len() as u64);
        if low_fee {
            self.counters.low_fee_batches = self.counters.low_fee_batches.saturating_add(1);
        }
        self.net_private_liquidations(request.height);
        self.refresh_roots();
        Ok(record)
    }

    pub fn publish_public_risk_summary(
        &mut self,
        summary_id: String,
        height: u64,
    ) -> Result<Value> {
        self.ensure_id("summary_id", &summary_id)?;
        let open_positions = self
            .positions
            .values()
            .filter(|position| position.status.counts_open())
            .count() as u64;
        let total_open_interest = self.markets.values().fold(0_u64, |acc, market| {
            acc.saturating_add(market.open_interest)
        });
        let total_reserved_margin = self.accounts.values().fold(0_u64, |acc, account| {
            acc.saturating_add(account.reserved_margin)
        });
        let liquidation_queue_notional = self
            .liquidations
            .values()
            .filter(|liquidation| liquidation.status == LiquidationStatus::Eligible)
            .fold(0_u64, |acc, liquidation| {
                acc.saturating_add(liquidation.netted_notional)
            });
        let max_oracle_deviation_bps = self
            .oracle_marks
            .values()
            .map(|mark| mark.deviation_bps)
            .max()
            .unwrap_or(0);
        let bridge_haircut_bps = self
            .bridge_haircuts
            .values()
            .map(|haircut| haircut.haircut_bps)
            .max()
            .unwrap_or(0);
        let record = PublicRiskSummaryRecord {
            summary_id: summary_id.clone(),
            height,
            markets: self.markets.len() as u64,
            open_positions,
            total_open_interest,
            total_reserved_margin,
            liquidation_queue_notional,
            max_oracle_deviation_bps,
            bridge_haircut_bps,
            low_fee_batches: self.counters.low_fee_batches,
            state_root: self.state_root(),
        };
        self.public_summaries.insert(summary_id, record.clone());
        self.counters.public_summaries_published =
            self.counters.public_summaries_published.saturating_add(1);
        self.refresh_roots();
        Ok(public_record_from_summary(&record))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "markets": self.markets.len(),
            "accounts": self.accounts.len(),
            "covenants": self.covenants.len(),
            "positions": self.positions.len(),
            "settlements": self.settlements.len(),
            "clearing_batches": self.clearing_batches.len(),
            "oracle_marks": self.oracle_marks.len(),
            "liquidations": self.liquidations.len(),
            "bridge_haircuts": self.bridge_haircuts.len(),
            "counters": self.counters,
            "roots": self.roots,
            "public_risk": self.public_risk_snapshot(),
        })
    }

    pub fn state_root(&self) -> String {
        let parts = vec![
            HashPart::Str(&self.config.protocol_version),
            HashPart::Str(&self.roots.markets_root),
            HashPart::Str(&self.roots.accounts_root),
            HashPart::Str(&self.roots.covenants_root),
            HashPart::Str(&self.roots.positions_root),
            HashPart::Str(&self.roots.settlements_root),
            HashPart::Str(&self.roots.oracle_marks_root),
            HashPart::Str(&self.roots.liquidation_root),
            HashPart::Str(&self.roots.bridge_haircut_root),
            HashPart::Str(&self.roots.batch_root),
            HashPart::Str(&self.roots.nullifier_root),
            HashPart::Str(&self.roots.public_summary_root),
        ];
        domain_hash("private-l2-pq-confidential-derivatives-state", &parts, 32)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.markets_root = map_root("markets", &self.markets);
        self.roots.accounts_root = map_root("accounts", &self.accounts);
        self.roots.covenants_root = map_root("covenants", &self.covenants);
        self.roots.positions_root = map_root("positions", &self.positions);
        self.roots.settlements_root = map_root("settlements", &self.settlements);
        self.roots.oracle_marks_root = map_root("oracle_marks", &self.oracle_marks);
        self.roots.liquidation_root = map_root("liquidations", &self.liquidations);
        self.roots.bridge_haircut_root = map_root("bridge_haircuts", &self.bridge_haircuts);
        self.roots.batch_root = map_root("clearing_batches", &self.clearing_batches);
        self.roots.nullifier_root = set_root("nullifiers", &self.seen_nullifiers);
        self.roots.public_summary_root = map_root("public_summaries", &self.public_summaries);
        self.roots.state_root = self.state_root();
    }

    fn ensure_id(&self, label: &str, value: &str) -> Result<()> {
        if value.trim().is_empty() {
            return Err(format!("{} must not be empty", label));
        }
        Ok(())
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!("{} capacity exceeded", label));
        }
        Ok(())
    }

    fn ensure_bps(&self, label: &str, value: u64) -> Result<()> {
        if value > PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BPS {
            return Err(format!("{} exceeds max bps", label));
        }
        Ok(())
    }

    fn ensure_margin_ladder(&self, initial: u64, maintenance: u64, liquidation: u64) -> Result<()> {
        self.ensure_bps("initial_margin_bps", initial)?;
        self.ensure_bps("maintenance_margin_bps", maintenance)?;
        self.ensure_bps("liquidation_margin_bps", liquidation)?;
        if initial < maintenance || maintenance < liquidation {
            return Err("margin ladder must be initial >= maintenance >= liquidation".to_string());
        }
        Ok(())
    }

    fn check_oracle_guard(
        &mut self,
        market: &MarketRecord,
        mark_price: u64,
        height: u64,
    ) -> Result<()> {
        let stale =
            height.saturating_sub(market.last_mark_height) > self.config.max_mark_staleness_blocks;
        let deviation = deviation_bps(mark_price, market.last_mark_price);
        if stale {
            self.counters.oracle_guard_rejections =
                self.counters.oracle_guard_rejections.saturating_add(1);
            return Err("oracle mark is stale for settlement".to_string());
        }
        if deviation > self.config.max_oracle_deviation_bps {
            self.counters.oracle_guard_rejections =
                self.counters.oracle_guard_rejections.saturating_add(1);
            return Err("oracle deviation exceeds guard rail".to_string());
        }
        Ok(())
    }

    fn check_margin_delta(&mut self, position: &PositionRecord, margin_delta: i128) -> Result<()> {
        if margin_delta < 0 {
            let withdrawal = signed_abs_u64(margin_delta);
            let post_margin = position.margin_reserved.saturating_sub(withdrawal);
            if post_margin < position.liquidation_threshold {
                self.counters.margin_rejections = self.counters.margin_rejections.saturating_add(1);
                return Err("settlement would breach liquidation margin".to_string());
            }
        }
        Ok(())
    }

    fn check_token_covenant(
        &mut self,
        covenant_id: &str,
        instrument_kind: InstrumentKind,
        notional: u64,
        secondary_transfer: bool,
    ) -> Result<()> {
        let covenant = match self.covenants.get(covenant_id) {
            Some(value) => value,
            None => return Err(format!("unknown covenant: {}", covenant_id)),
        };
        if !covenant.status.transfer_allowed() {
            self.counters.covenant_rejections = self.counters.covenant_rejections.saturating_add(1);
            return Err("token covenant is not transferable".to_string());
        }
        if !covenant.allowed_market_kinds.contains(&instrument_kind) {
            self.counters.covenant_rejections = self.counters.covenant_rejections.saturating_add(1);
            return Err("token covenant blocks instrument kind".to_string());
        }
        if secondary_transfer && !covenant.allow_secondary_transfer {
            self.counters.covenant_rejections = self.counters.covenant_rejections.saturating_add(1);
            return Err("token covenant blocks secondary transfer".to_string());
        }
        if notional > covenant.max_transfer_notional || notional > covenant.max_notional_per_account
        {
            self.counters.covenant_rejections = self.counters.covenant_rejections.saturating_add(1);
            return Err("token covenant notional limit exceeded".to_string());
        }
        Ok(())
    }

    fn current_bridge_haircut_bps(&self, bridge_id: &str) -> u64 {
        self.bridge_haircuts
            .values()
            .filter(|record| record.bridge_id == bridge_id)
            .map(|record| record.haircut_bps)
            .max()
            .unwrap_or(0)
    }

    fn reprice_positions(&mut self, market_id: &str, mark_price: u64, height: u64) {
        let position_ids: Vec<String> = self
            .positions
            .values()
            .filter(|position| position.market_id == market_id && position.status.counts_open())
            .map(|position| position.position_id.clone())
            .collect();
        for position_id in position_ids {
            if let Some(position) = self.positions.get_mut(&position_id) {
                position.mark_price = mark_price;
                position.notional = position.quantity.saturating_mul(mark_price);
                position.updated_height = height;
                let pnl = if mark_price >= position.entry_price {
                    position
                        .quantity
                        .saturating_mul(mark_price.saturating_sub(position.entry_price))
                        as i128
                } else {
                    -((position
                        .quantity
                        .saturating_mul(position.entry_price.saturating_sub(mark_price)))
                        as i128)
                };
                if position.side.is_short_risk() {
                    position.status = if pnl < 0 && signed_abs_u64(pnl) >= position.margin_reserved
                    {
                        PositionStatus::UnderMaintMargin
                    } else {
                        position.status
                    };
                }
            }
        }
    }

    fn apply_single_settlement(
        &mut self,
        settlement: &SettlementRecord,
        height: u64,
    ) -> Result<()> {
        if let Some(account) = self.accounts.get_mut(&settlement.account_id) {
            account.realized_pnl = account.realized_pnl.saturating_add(settlement.amount);
            if settlement.margin_delta >= 0 {
                account.reserved_margin = account
                    .reserved_margin
                    .saturating_add(signed_abs_u64(settlement.margin_delta));
            } else {
                account.reserved_margin = account
                    .reserved_margin
                    .saturating_sub(signed_abs_u64(settlement.margin_delta));
            }
            account.nonce = account.nonce.saturating_add(1);
        }
        if let Some(position) = self.positions.get_mut(&settlement.position_id) {
            if settlement.margin_delta >= 0 {
                position.margin_reserved = position
                    .margin_reserved
                    .saturating_add(signed_abs_u64(settlement.margin_delta));
            } else {
                position.margin_reserved = position
                    .margin_reserved
                    .saturating_sub(signed_abs_u64(settlement.margin_delta));
            }
            position.mark_price = settlement.mark_price;
            position.updated_height = height;
            if matches!(
                settlement.settlement_kind,
                SettlementKind::Exercise
                    | SettlementKind::ExpiryCashSettle
                    | SettlementKind::Liquidation
            ) {
                position.status = PositionStatus::Settled;
            }
        }
        Ok(())
    }

    fn refresh_position_status(&mut self, position_id: &str, height: u64) {
        if let Some(position) = self.positions.get_mut(position_id) {
            if position.status == PositionStatus::Settled
                || position.status == PositionStatus::Closed
            {
                position.updated_height = height;
            } else if position.margin_reserved < position.liquidation_threshold {
                position.status = PositionStatus::UnderMaintMargin;
                position.updated_height = height;
            } else if position.margin_reserved == 0 {
                position.status = PositionStatus::Closed;
                position.updated_height = height;
            } else {
                position.status = PositionStatus::Open;
                position.updated_height = height;
            }
        }
    }

    fn nettable_liquidation_notional(&self, position: &PositionRecord) -> u64 {
        let opposite_notional = self
            .positions
            .values()
            .filter(|other| {
                other.market_id == position.market_id
                    && other.account_id != position.account_id
                    && other.status.counts_open()
                    && other.side != position.side
            })
            .fold(0_u64, |acc, other| acc.saturating_add(other.notional));
        if opposite_notional >= position.notional {
            0
        } else {
            position.notional.saturating_sub(opposite_notional)
        }
    }

    fn net_private_liquidations(&mut self, height: u64) {
        let liquidation_ids: Vec<String> = self
            .liquidations
            .values()
            .filter(|liquidation| liquidation.status == LiquidationStatus::Eligible)
            .map(|liquidation| liquidation.liquidation_id.clone())
            .collect();
        for liquidation_id in liquidation_ids {
            let position_id = match self.liquidations.get(&liquidation_id) {
                Some(record) => record.position_id.clone(),
                None => continue,
            };
            let position = match self.positions.get(&position_id) {
                Some(record) => record.clone(),
                None => continue,
            };
            let netted = self.nettable_liquidation_notional(&position);
            if let Some(liquidation) = self.liquidations.get_mut(&liquidation_id) {
                liquidation.netted_notional = netted;
                liquidation.height = height;
                liquidation.status = if netted == 0 {
                    LiquidationStatus::Netted
                } else {
                    LiquidationStatus::BackstopRouted
                };
            }
            if let Some(position_mut) = self.positions.get_mut(&position_id) {
                position_mut.status = if netted == 0 {
                    PositionStatus::Netted
                } else {
                    PositionStatus::Liquidating
                };
                position_mut.updated_height = height;
            }
            self.counters.liquidations_netted = self.counters.liquidations_netted.saturating_add(1);
        }
    }

    fn public_risk_snapshot(&self) -> Value {
        let open_positions = self
            .positions
            .values()
            .filter(|position| position.status.counts_open())
            .count();
        let total_reserved_margin = self.accounts.values().fold(0_u64, |acc, account| {
            acc.saturating_add(account.reserved_margin)
        });
        let total_open_interest = self.markets.values().fold(0_u64, |acc, market| {
            acc.saturating_add(market.open_interest)
        });
        json!({
            "open_positions": open_positions,
            "total_open_interest": total_open_interest,
            "total_reserved_margin": total_reserved_margin,
            "oracle_guard_rejections": self.counters.oracle_guard_rejections,
            "margin_rejections": self.counters.margin_rejections,
            "covenant_rejections": self.counters.covenant_rejections,
            "liquidations_proposed": self.counters.liquidations_proposed,
            "liquidations_netted": self.counters.liquidations_netted,
            "low_fee_batches": self.counters.low_fee_batches,
        })
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default());
    let mut allowed = BTreeSet::new();
    allowed.insert(InstrumentKind::TokenizedCallOption);
    allowed.insert(InstrumentKind::TokenizedPutOption);
    allowed.insert(InstrumentKind::PerpetualFuture);
    allowed.insert(InstrumentKind::StructuredNote);
    let covenant = RegisterCovenantRequest {
        covenant_id: "devnet-covenant-confidential-derivatives".to_string(),
        asset_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                .to_string(),
        issuer_commitment: "issuer:devnet:commitment".to_string(),
        allowed_market_kinds: allowed,
        max_leverage_bps: 5_000,
        max_notional_per_account: 50_000_000_000,
        max_transfer_notional: 25_000_000_000,
        min_privacy_set_size:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
        requires_bridge_haircut: true,
        allow_secondary_transfer: true,
        remediation_fee_bps: 25,
        covenant_root: "devnet-covenant-root".to_string(),
    };
    let _ = state.register_covenant(covenant);
    let _ = state.record_bridge_haircut(RecordBridgeHaircutRequest {
        haircut_id: "devnet-haircut-0001".to_string(),
        bridge_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_BRIDGE_ID
                .to_string(),
        collateral_asset_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                .to_string(),
        source_domain:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
        haircut_bps: 175,
        liquidity_depth: 5_000_000_000_000,
        stress_score_bps: 1_250,
        attestation_root: "devnet-bridge-haircut-attestation-root".to_string(),
        height: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_HEIGHT,
    });
    let _ = state.create_market(CreateMarketRequest {
        market_id: "xmr-dusd-private-perp".to_string(),
        instrument_kind: InstrumentKind::PerpetualFuture,
        base_asset_id: "xmr-private-devnet".to_string(),
        quote_asset_id: "dusd-private-devnet".to_string(),
        collateral_asset_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                .to_string(),
        oracle_feed_id: "oracle:xmr-usd:devnet".to_string(),
        covenant_id: "devnet-covenant-confidential-derivatives".to_string(),
        bridge_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_BRIDGE_ID
                .to_string(),
        strike_price: 18_000_000,
        lot_size: 1_000_000,
        max_open_interest: 1_000_000_000,
        expiry_height: 0,
        funding_interval_blocks: 20,
        maker_fee_bps: 2,
        taker_fee_bps: 5,
        initial_margin_bps:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS,
        maintenance_margin_bps:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS,
        liquidation_margin_bps:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_LIQUIDATION_MARGIN_BPS,
        created_height: PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_HEIGHT,
        metadata_commitment: "market-metadata:xmr-dusd-private-perp".to_string(),
    });
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let height =
        PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEVNET_HEIGHT + 4;
    let _ = state.register_account(RegisterAccountRequest {
        account_id: "acct:alice:shielded".to_string(),
        owner_commitment: "owner:alice:commitment".to_string(),
        view_tag: "view:alice:tag".to_string(),
        pq_public_key_commitment: "pqpk:alice:commitment".to_string(),
        collateral_asset_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                .to_string(),
        collateral_commitment: "collateral:alice:commitment".to_string(),
        risk_bucket: "market-maker-low-latency".to_string(),
    });
    let _ = state.register_account(RegisterAccountRequest {
        account_id: "acct:bob:shielded".to_string(),
        owner_commitment: "owner:bob:commitment".to_string(),
        view_tag: "view:bob:tag".to_string(),
        pq_public_key_commitment: "pqpk:bob:commitment".to_string(),
        collateral_asset_id:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                .to_string(),
        collateral_commitment: "collateral:bob:commitment".to_string(),
        risk_bucket: "structured-note-issuer".to_string(),
    });
    let _ = state.record_oracle_mark(RecordOracleMarkRequest {
        mark_id: "mark:xmr-dusd:0001".to_string(),
        market_id: "xmr-dusd-private-perp".to_string(),
        feed_id: "oracle:xmr-usd:devnet".to_string(),
        mark_price: 18_100_000,
        index_price: 18_090_000,
        confidence_bps: 35,
        quorum_weight: 7,
        attestation_root: "oracle-attestation-root:0001".to_string(),
        height,
    });
    let _ = state.open_position(OpenPositionRequest {
        position_id: "pos:alice:xmr-perp:long:0001".to_string(),
        account_id: "acct:alice:shielded".to_string(),
        market_id: "xmr-dusd-private-perp".to_string(),
        side: PositionSide::Long,
        quantity: 10,
        entry_price: 18_100_000,
        token_commitment: "tokenized-position:alice:0001".to_string(),
        order_nullifier: "nullifier:order:alice:0001".to_string(),
        height,
    });
    let _ = state.record_settlement(RecordSettlementRequest {
        settlement_id: "settlement:funding:0001".to_string(),
        settlement_kind: SettlementKind::Funding,
        market_id: "xmr-dusd-private-perp".to_string(),
        position_id: "pos:alice:xmr-perp:long:0001".to_string(),
        account_id: "acct:alice:shielded".to_string(),
        counterparty_account_id: "acct:bob:shielded".to_string(),
        amount: 125_000,
        fee_amount: 1_500,
        margin_delta: 25_000,
        mark_price: 18_100_000,
        pq_signature_commitment: "pq-sig:funding:0001".to_string(),
        proof_commitment: "proof:funding:0001".to_string(),
        nullifier: "nullifier:settlement:funding:0001".to_string(),
        height: height + 1,
    });
    let _ = state.apply_clearing_batch(ApplyClearingBatchRequest {
        batch_id: "batch:low-fee:0001".to_string(),
        settlement_ids: vec!["settlement:funding:0001".to_string()],
        privacy_set_size:
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
        proof_root: "batch-proof-root:0001".to_string(),
        height: height + 2,
    });
    let _ = state.publish_public_risk_summary("summary:devnet:0001".to_string(), height + 3);
    state
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn public_record_from_summary(record: &PublicRiskSummaryRecord) -> Value {
    json!({
        "summary_id": record.summary_id,
        "height": record.height,
        "markets": record.markets,
        "open_positions": record.open_positions,
        "total_open_interest": record.total_open_interest,
        "total_reserved_margin": record.total_reserved_margin,
        "liquidation_queue_notional": record.liquidation_queue_notional,
        "max_oracle_deviation_bps": record.max_oracle_deviation_bps,
        "bridge_haircut_bps": record.bridge_haircut_bps,
        "low_fee_batches": record.low_fee_batches,
        "state_root": record.state_root,
    })
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            let encoded = canonical_json(value);
            json!({
                "label": label,
                "key": key,
                "value": encoded,
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect();
    merkle_root(label, &leaves)
}

fn canonical_json<T: Serialize>(value: &T) -> String {
    match serde_json::to_string(value) {
        Ok(encoded) => encoded,
        Err(_) => "serialization_error".to_string(),
    }
}

fn apply_bps_up(amount: u64, bps: u64) -> u64 {
    let numerator = amount.saturating_mul(bps);
    numerator.saturating_add(
        PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BPS - 1,
    ) / PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BPS
}

fn deviation_bps(a: u64, b: u64) -> u64 {
    if a == b {
        return 0;
    }
    let high = if a > b { a } else { b };
    let low = if a > b { b } else { a };
    if high == 0 {
        return 0;
    }
    high.saturating_sub(low)
        .saturating_mul(PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_DERIVATIVES_CLEARING_RUNTIME_MAX_BPS)
        / high
}

fn signed_abs_u64(value: i128) -> u64 {
    if value >= 0 {
        if value > u64::MAX as i128 {
            u64::MAX
        } else {
            value as u64
        }
    } else {
        let positive = value.saturating_neg();
        if positive > u64::MAX as i128 {
            u64::MAX
        } else {
            positive as u64
        }
    }
}
