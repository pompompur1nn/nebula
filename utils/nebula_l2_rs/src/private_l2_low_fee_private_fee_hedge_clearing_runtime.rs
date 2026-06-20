use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePrivateFeeHedgeClearingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {{
        if !$condition {
            return Err(format!($($arg)+));
        }
        Ok::<(), String>(())
    }};
}

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-private-fee-hedge-clearing-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_SCHEMA_VERSION: u64 =
    SCHEMA_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_HASH_SUITE: &str = HASH_SUITE;
pub const PQ_AUTH_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-fee-hedge-auth-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_PQ_AUTH_SCHEME: &str =
    PQ_AUTH_SCHEME;
pub const PQ_SEALING_SCHEME: &str = "ml-kem-1024+xwing-sealed-private-fee-hedge-order-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_PQ_SEALING_SCHEME: &str =
    PQ_SEALING_SCHEME;
pub const HEDGE_BOOK_SCHEME: &str = "monero-l2-private-low-fee-hedge-book-root-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_HEDGE_BOOK_SCHEME: &str =
    HEDGE_BOOK_SCHEME;
pub const SPONSOR_MARGIN_SCHEME: &str = "roots-only-private-fee-hedge-sponsor-margin-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_SPONSOR_MARGIN_SCHEME: &str =
    SPONSOR_MARGIN_SCHEME;
pub const EXPOSURE_NETTING_SCHEME: &str = "zk-private-fee-hedge-exposure-netting-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_EXPOSURE_NETTING_SCHEME: &str =
    EXPOSURE_NETTING_SCHEME;
pub const CLEARING_PROOF_SCHEME: &str = "zk-pq-low-fee-future-cap-clearing-proof-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_CLEARING_PROOF_SCHEME: &str =
    CLEARING_PROOF_SCHEME;
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "zk-pq-private-fee-hedge-settlement-receipt-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_SETTLEMENT_RECEIPT_SCHEME: &str =
    SETTLEMENT_RECEIPT_SCHEME;
pub const REBATE_PROOF_SCHEME: &str = "roots-only-private-fee-hedge-rebate-proof-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_REBATE_PROOF_SCHEME: &str =
    REBATE_PROOF_SCHEME;
pub const PRIVACY_BUDGET_SCHEME: &str = "private-fee-hedge-privacy-budget-firewall-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_PRIVACY_BUDGET_SCHEME: &str =
    PRIVACY_BUDGET_SCHEME;
pub const SLASHING_EVIDENCE_SCHEME: &str = "private-fee-hedge-stale-leverage-slasher-v1";
pub const PRIVATE_L2_LOW_FEE_PRIVATE_FEE_HEDGE_CLEARING_RUNTIME_SLASHING_EVIDENCE_SCHEME: &str =
    SLASHING_EVIDENCE_SCHEME;
pub const DEVNET_HEIGHT: u64 = 927_440;
pub const DEVNET_EPOCH: u64 = 1_288;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_BOOK_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 40;
pub const DEFAULT_MARGIN_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_NETTING_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 6;
pub const DEFAULT_PRIVACY_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 18;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_CLEARING_FEE_BPS: u64 = 3;
pub const DEFAULT_CAP_PREMIUM_BPS: u64 = 24;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_MARGIN_BPS: u64 = 1_500;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 900;
pub const DEFAULT_SLASH_BPS: u64 = 2_000;
pub const DEFAULT_MAX_BOOKS: usize = 131_072;
pub const DEFAULT_MAX_ORDERS: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVATIONS: usize = 524_288;
pub const DEFAULT_MAX_NETTING_ROUNDS: usize = 262_144;
pub const DEFAULT_MAX_CLEARINGS: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const DEFAULT_MAX_REBATES: usize = 524_288;
pub const DEFAULT_MAX_PRIVACY_ACCOUNTS: usize = 262_144;
pub const DEFAULT_MAX_SLASHES: usize = 262_144;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeVenue {
    PrivateTransfer,
    ConfidentialToken,
    PrivateAmm,
    DefiSwap,
    LendingPool,
    PerpDex,
    ContractCall,
    BridgeExit,
    SponsorRelay,
    SequencerAuction,
}

impl HedgeVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialToken => "confidential_token",
            Self::PrivateAmm => "private_amm",
            Self::DefiSwap => "defi_swap",
            Self::LendingPool => "lending_pool",
            Self::PerpDex => "perp_dex",
            Self::ContractCall => "contract_call",
            Self::BridgeExit => "bridge_exit",
            Self::SponsorRelay => "sponsor_relay",
            Self::SequencerAuction => "sequencer_auction",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeInstrument {
    FeeFuture,
    FeeCap,
    FeeFloor,
    FeeCollar,
    SponsorRebateForward,
    PriorityInclusionFuture,
    VarianceSwap,
}

impl HedgeInstrument {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeFuture => "fee_future",
            Self::FeeCap => "fee_cap",
            Self::FeeFloor => "fee_floor",
            Self::FeeCollar => "fee_collar",
            Self::SponsorRebateForward => "sponsor_rebate_forward",
            Self::PriorityInclusionFuture => "priority_inclusion_future",
            Self::VarianceSwap => "variance_swap",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeSide {
    PayFixedFee,
    ReceiveFixedFee,
    BuyCap,
    SellCap,
    BuyFloor,
    SellFloor,
    SponsorShortFee,
    UserLongFee,
}

impl HedgeSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayFixedFee => "pay_fixed_fee",
            Self::ReceiveFixedFee => "receive_fixed_fee",
            Self::BuyCap => "buy_cap",
            Self::SellCap => "sell_cap",
            Self::BuyFloor => "buy_floor",
            Self::SellFloor => "sell_floor",
            Self::SponsorShortFee => "sponsor_short_fee",
            Self::UserLongFee => "user_long_fee",
        }
    }

    pub fn signed_notional(self, notional: u64) -> i128 {
        match self {
            Self::PayFixedFee | Self::BuyCap | Self::BuyFloor | Self::UserLongFee => {
                notional as i128
            }
            Self::ReceiveFixedFee | Self::SellCap | Self::SellFloor | Self::SponsorShortFee => {
                -(notional as i128)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookStatus {
    Proposed,
    Open,
    Sponsored,
    Netting,
    Clearing,
    Settling,
    Settled,
    Paused,
    Expired,
    Slashed,
}

impl BookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Sponsored => "sponsored",
            Self::Netting => "netting",
            Self::Clearing => "clearing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    Admitted,
    MarginReserved,
    Netted,
    Clearing,
    Cleared,
    Receipted,
    Rebated,
    Rejected,
    Expired,
    Slashed,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::MarginReserved => "margin_reserved",
            Self::Netted => "netted",
            Self::Clearing => "clearing",
            Self::Cleared => "cleared",
            Self::Receipted => "receipted",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn nettable(self) -> bool {
        matches!(self, Self::Sealed | Self::Admitted | Self::MarginReserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    PartiallyConsumed,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PartiallyConsumed => "partially_consumed",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Proposed,
    PrivacyChecked,
    ExposureMatched,
    ClearingQueued,
    Settled,
    Disputed,
    Expired,
}

impl NettingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PrivacyChecked => "privacy_checked",
            Self::ExposureMatched => "exposure_matched",
            Self::ClearingQueued => "clearing_queued",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingStatus {
    Proposed,
    MarginChecked,
    Cleared,
    Receipting,
    Settled,
    Rebated,
    Disputed,
    Expired,
}

impl ClearingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::MarginChecked => "margin_checked",
            Self::Cleared => "cleared",
            Self::Receipting => "receipting",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Revoked,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Issued,
    Claimed,
    Expired,
    Revoked,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Issued => "issued",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetStatus {
    Active,
    Throttled,
    Exhausted,
    Reset,
    Slashed,
}

impl PrivacyBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Reset => "reset",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    StaleOracle,
    StaleClearing,
    OverleveredMargin,
    PrivacyBudgetAbuse,
    InvalidReceipt,
    ReplayFenceViolation,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleOracle => "stale_oracle",
            Self::StaleClearing => "stale_clearing",
            Self::OverleveredMargin => "overlevered_margin",
            Self::PrivacyBudgetAbuse => "privacy_budget_abuse",
            Self::InvalidReceipt => "invalid_receipt",
            Self::ReplayFenceViolation => "replay_fence_violation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub pq_sealing_scheme: String,
    pub hedge_book_scheme: String,
    pub sponsor_margin_scheme: String,
    pub exposure_netting_scheme: String,
    pub clearing_proof_scheme: String,
    pub settlement_receipt_scheme: String,
    pub rebate_proof_scheme: String,
    pub privacy_budget_scheme: String,
    pub slashing_evidence_scheme: String,
    pub book_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub margin_ttl_blocks: u64,
    pub netting_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub privacy_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub clearing_fee_bps: u64,
    pub cap_premium_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub slash_bps: u64,
    pub max_books: usize,
    pub max_orders: usize,
    pub max_reservations: usize,
    pub max_netting_rounds: usize,
    pub max_clearings: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_privacy_accounts: usize,
    pub max_slashes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            pq_sealing_scheme: PQ_SEALING_SCHEME.to_string(),
            hedge_book_scheme: HEDGE_BOOK_SCHEME.to_string(),
            sponsor_margin_scheme: SPONSOR_MARGIN_SCHEME.to_string(),
            exposure_netting_scheme: EXPOSURE_NETTING_SCHEME.to_string(),
            clearing_proof_scheme: CLEARING_PROOF_SCHEME.to_string(),
            settlement_receipt_scheme: SETTLEMENT_RECEIPT_SCHEME.to_string(),
            rebate_proof_scheme: REBATE_PROOF_SCHEME.to_string(),
            privacy_budget_scheme: PRIVACY_BUDGET_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            book_ttl_blocks: DEFAULT_BOOK_TTL_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            margin_ttl_blocks: DEFAULT_MARGIN_TTL_BLOCKS,
            netting_ttl_blocks: DEFAULT_NETTING_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            privacy_epoch_blocks: DEFAULT_PRIVACY_EPOCH_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            clearing_fee_bps: DEFAULT_CLEARING_FEE_BPS,
            cap_premium_bps: DEFAULT_CAP_PREMIUM_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            initial_margin_bps: DEFAULT_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            max_books: DEFAULT_MAX_BOOKS,
            max_orders: DEFAULT_MAX_ORDERS,
            max_reservations: DEFAULT_MAX_RESERVATIONS,
            max_netting_rounds: DEFAULT_MAX_NETTING_ROUNDS,
            max_clearings: DEFAULT_MAX_CLEARINGS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_privacy_accounts: DEFAULT_MAX_PRIVACY_ACCOUNTS,
            max_slashes: DEFAULT_MAX_SLASHES,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub books_opened: u64,
    pub sealed_orders_posted: u64,
    pub sponsor_margins_reserved: u64,
    pub exposure_rounds_netted: u64,
    pub clearings_completed: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub privacy_budget_updates: u64,
    pub hedgers_slashed: u64,
    pub total_notional_micro_units: u64,
    pub total_margin_reserved_micro_units: u64,
    pub total_fee_savings_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_slash_micro_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub books_root: String,
    pub orders_root: String,
    pub reservations_root: String,
    pub netting_rounds_root: String,
    pub clearings_root: String,
    pub receipts_root: String,
    pub rebates_root: String,
    pub privacy_budgets_root: String,
    pub slashes_root: String,
    pub replay_fences_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            books_root: empty_root("books"),
            orders_root: empty_root("orders"),
            reservations_root: empty_root("reservations"),
            netting_rounds_root: empty_root("netting_rounds"),
            clearings_root: empty_root("clearings"),
            receipts_root: empty_root("receipts"),
            rebates_root: empty_root("rebates"),
            privacy_budgets_root: empty_root("privacy_budgets"),
            slashes_root: empty_root("slashes"),
            replay_fences_root: empty_root("replay_fences"),
            state_root: empty_root("state"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeBook {
    pub book_id: String,
    pub venue: HedgeVenue,
    pub instrument: HedgeInstrument,
    pub status: BookStatus,
    pub operator_commitment: String,
    pub oracle_root: String,
    pub sponsor_pool_id: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub min_notional_micro_units: u64,
    pub max_notional_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub maturity_height: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub pq_security_bits: u16,
    pub metadata_hash: String,
    pub order_ids: BTreeSet<String>,
    pub reservation_ids: BTreeSet<String>,
    pub netting_round_ids: BTreeSet<String>,
    pub clearing_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedHedgeOrder {
    pub order_id: String,
    pub book_id: String,
    pub hedger_commitment: String,
    pub sealed_payload_hash: String,
    pub nullifier_hash: String,
    pub side: HedgeSide,
    pub notional_micro_units: u64,
    pub max_fee_bps: u64,
    pub limit_fee_bps: u64,
    pub premium_micro_units: u64,
    pub margin_commitment: String,
    pub privacy_account_id: String,
    pub decoy_root: String,
    pub status: OrderStatus,
    pub posted_height: u64,
    pub expires_height: u64,
    pub pq_security_bits: u16,
    pub reservation_id: Option<String>,
    pub netting_round_id: Option<String>,
    pub clearing_id: Option<String>,
    pub receipt_id: Option<String>,
    pub rebate_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorMarginReservation {
    pub reservation_id: String,
    pub book_id: String,
    pub sponsor_id: String,
    pub order_ids: BTreeSet<String>,
    pub margin_root: String,
    pub reserved_micro_units: u64,
    pub consumed_micro_units: u64,
    pub cover_bps: u64,
    pub status: ReservationStatus,
    pub reserved_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureNettingRound {
    pub netting_round_id: String,
    pub book_id: String,
    pub order_ids: BTreeSet<String>,
    pub exposure_root: String,
    pub netted_exposure_micro_units: i128,
    pub long_notional_micro_units: u64,
    pub short_notional_micro_units: u64,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub status: NettingStatus,
    pub proposed_height: u64,
    pub expires_height: u64,
    pub clearing_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeHedgeClearing {
    pub clearing_id: String,
    pub book_id: String,
    pub netting_round_id: String,
    pub order_ids: BTreeSet<String>,
    pub clearing_price_bps: u64,
    pub cap_strike_bps: Option<u64>,
    pub settlement_root: String,
    pub proof_root: String,
    pub gross_notional_micro_units: u64,
    pub net_exposure_micro_units: i128,
    pub clearing_fee_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub user_paid_micro_units: u64,
    pub fee_savings_micro_units: u64,
    pub status: ClearingStatus,
    pub cleared_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementReceipt {
    pub receipt_id: String,
    pub clearing_id: String,
    pub book_id: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub encrypted_memo_hash: String,
    pub settled_order_count: u64,
    pub settled_notional_micro_units: u64,
    pub final_fee_bps: u64,
    pub status: ReceiptStatus,
    pub published_height: u64,
    pub finalizes_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub clearing_id: String,
    pub book_id: String,
    pub beneficiary_commitment: String,
    pub rebate_root: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub issued_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub privacy_account_id: String,
    pub epoch: u64,
    pub status: PrivacyBudgetStatus,
    pub spent_weight: u64,
    pub max_weight: u64,
    pub min_remaining_decoys: u64,
    pub last_update_height: u64,
    pub order_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashRecord {
    pub slash_id: String,
    pub subject_id: String,
    pub book_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub slashed_micro_units: u64,
    pub status: ReservationStatus,
    pub slashed_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenHedgeBookRequest {
    pub venue: HedgeVenue,
    pub instrument: HedgeInstrument,
    pub operator_commitment: String,
    pub oracle_root: String,
    pub sponsor_pool_id: String,
    pub min_notional_micro_units: u64,
    pub max_notional_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub maturity_height: u64,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub pq_security_bits: u16,
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostSealedHedgeOrderRequest {
    pub book_id: String,
    pub hedger_commitment: String,
    pub sealed_payload: Value,
    pub nullifier_hash: String,
    pub side: HedgeSide,
    pub notional_micro_units: u64,
    pub max_fee_bps: u64,
    pub limit_fee_bps: u64,
    pub premium_micro_units: u64,
    pub margin_commitment: String,
    pub privacy_account_id: String,
    pub decoy_root: String,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorMarginRequest {
    pub book_id: String,
    pub sponsor_id: String,
    pub order_ids: Vec<String>,
    pub margin_root: String,
    pub reserved_micro_units: u64,
    pub cover_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetHedgeExposureRequest {
    pub book_id: String,
    pub order_ids: Vec<String>,
    pub exposure_witness_root: String,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClearFeeHedgesRequest {
    pub book_id: String,
    pub netting_round_id: String,
    pub clearing_price_bps: u64,
    pub cap_strike_bps: Option<u64>,
    pub settlement_witness_root: String,
    pub proof_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishSettlementReceiptRequest {
    pub clearing_id: String,
    pub receipt_root: String,
    pub nullifier_root: String,
    pub encrypted_memo: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRebateRequest {
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_root: String,
    pub rebate_bps: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackPrivacyBudgetRequest {
    pub privacy_account_id: String,
    pub epoch: u64,
    pub spend_weight: u64,
    pub max_weight: u64,
    pub min_remaining_decoys: u64,
    pub order_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashHedgerRequest {
    pub subject_id: String,
    pub book_id: String,
    pub reason: SlashReason,
    pub evidence: Value,
    pub slash_base_micro_units: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeReceiptRequest {
    pub receipt_id: String,
    pub finality_witness_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRebateRequest {
    pub rebate_id: String,
    pub claim_nullifier: String,
    pub claim_witness_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseMarginRequest {
    pub reservation_id: String,
    pub release_witness_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeBookSummary {
    pub book_id: String,
    pub venue: HedgeVenue,
    pub instrument: HedgeInstrument,
    pub status: BookStatus,
    pub order_count: u64,
    pub reservation_count: u64,
    pub netting_round_count: u64,
    pub clearing_count: u64,
    pub max_user_fee_bps: u64,
    pub maturity_height: u64,
    pub expires_height: u64,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeExposureSummary {
    pub book_id: String,
    pub open_long_notional_micro_units: u64,
    pub open_short_notional_micro_units: u64,
    pub cleared_notional_micro_units: u64,
    pub sponsored_margin_micro_units: u64,
    pub pending_receipts: u64,
    pub issued_rebates_micro_units: u64,
    pub active_privacy_accounts: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub books: BTreeMap<String, HedgeBook>,
    pub orders: BTreeMap<String, SealedHedgeOrder>,
    pub reservations: BTreeMap<String, SponsorMarginReservation>,
    pub netting_rounds: BTreeMap<String, ExposureNettingRound>,
    pub clearings: BTreeMap<String, FeeHedgeClearing>,
    pub receipts: BTreeMap<String, PrivateSettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub slashes: BTreeMap<String, SlashRecord>,
    pub replay_fences: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            counters: Counters::default(),
            roots: Roots::default(),
            books: BTreeMap::new(),
            orders: BTreeMap::new(),
            reservations: BTreeMap::new(),
            netting_rounds: BTreeMap::new(),
            clearings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            slashes: BTreeMap::new(),
            replay_fences: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn state_root(&self) -> String {
        let roots = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "epoch": self.epoch,
            "books_root": self.roots.books_root,
            "orders_root": self.roots.orders_root,
            "reservations_root": self.roots.reservations_root,
            "netting_rounds_root": self.roots.netting_rounds_root,
            "clearings_root": self.roots.clearings_root,
            "receipts_root": self.roots.receipts_root,
            "rebates_root": self.roots.rebates_root,
            "privacy_budgets_root": self.roots.privacy_budgets_root,
            "slashes_root": self.roots.slashes_root,
            "replay_fences_root": self.roots.replay_fences_root,
            "counters": self.counters,
        });
        hash_json("state-root", &roots)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "epoch": self.epoch,
            "hash_suite": self.config.hash_suite,
            "pq_auth_scheme": self.config.pq_auth_scheme,
            "pq_sealing_scheme": self.config.pq_sealing_scheme,
            "hedge_book_scheme": self.config.hedge_book_scheme,
            "sponsor_margin_scheme": self.config.sponsor_margin_scheme,
            "exposure_netting_scheme": self.config.exposure_netting_scheme,
            "clearing_proof_scheme": self.config.clearing_proof_scheme,
            "settlement_receipt_scheme": self.config.settlement_receipt_scheme,
            "rebate_proof_scheme": self.config.rebate_proof_scheme,
            "privacy_budget_scheme": self.config.privacy_budget_scheme,
            "slashing_evidence_scheme": self.config.slashing_evidence_scheme,
            "roots": self.roots,
            "counters": self.counters,
            "limits": {
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "clearing_fee_bps": self.config.clearing_fee_bps,
                "sponsor_cover_bps": self.config.sponsor_cover_bps,
                "rebate_bps": self.config.rebate_bps,
                "initial_margin_bps": self.config.initial_margin_bps,
                "maintenance_margin_bps": self.config.maintenance_margin_bps,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_decoy_set_size": self.config.min_decoy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
            },
        })
    }

    pub fn open_confidential_fee_hedge_book(
        &mut self,
        request: OpenHedgeBookRequest,
    ) -> Result<HedgeBook> {
        ensure_capacity("books", self.books.len(), self.config.max_books)?;
        ensure_nonempty("operator_commitment", &request.operator_commitment)?;
        ensure_nonempty("oracle_root", &request.oracle_root)?;
        ensure_nonempty("sponsor_pool_id", &request.sponsor_pool_id)?;
        ensure!(
            request.min_notional_micro_units > 0,
            "min_notional_micro_units must be positive"
        )?;
        ensure!(
            request.max_notional_micro_units >= request.min_notional_micro_units,
            "max_notional_micro_units must cover min_notional_micro_units"
        )?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        ensure!(
            request.max_user_fee_bps <= self.config.max_user_fee_bps,
            "book max user fee exceeds runtime low-fee ceiling"
        )?;
        ensure!(
            request.maturity_height > self.height,
            "maturity_height must be in the future"
        )?;
        ensure!(
            request.min_privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below runtime minimum"
        )?;
        ensure!(
            request.min_decoy_set_size >= self.config.min_decoy_set_size,
            "decoy set below runtime minimum"
        )?;
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "post-quantum security bits below runtime minimum"
        )?;

        let metadata_hash = hash_json("book-metadata", &request.metadata);
        let book_id = derive_book_id(self.counters.books_opened + 1, &request, &metadata_hash);
        ensure!(!self.books.contains_key(&book_id), "book already exists");

        let book = HedgeBook {
            book_id: book_id.clone(),
            venue: request.venue,
            instrument: request.instrument,
            status: BookStatus::Open,
            operator_commitment: request.operator_commitment,
            oracle_root: request.oracle_root,
            sponsor_pool_id: request.sponsor_pool_id,
            fee_asset_id: self.config.fee_asset_id.clone(),
            collateral_asset_id: self.config.collateral_asset_id.clone(),
            min_notional_micro_units: request.min_notional_micro_units,
            max_notional_micro_units: request.max_notional_micro_units,
            max_user_fee_bps: request.max_user_fee_bps,
            maturity_height: request.maturity_height,
            opened_height: self.height,
            expires_height: self.height + self.config.book_ttl_blocks,
            min_privacy_set_size: request.min_privacy_set_size,
            min_decoy_set_size: request.min_decoy_set_size,
            pq_security_bits: request.pq_security_bits,
            metadata_hash,
            order_ids: BTreeSet::new(),
            reservation_ids: BTreeSet::new(),
            netting_round_ids: BTreeSet::new(),
            clearing_ids: BTreeSet::new(),
        };

        self.books.insert(book_id, book.clone());
        self.counters.books_opened += 1;
        self.refresh_roots();
        Ok(book)
    }

    pub fn post_sealed_hedge_order(
        &mut self,
        request: PostSealedHedgeOrderRequest,
    ) -> Result<SealedHedgeOrder> {
        ensure_capacity("orders", self.orders.len(), self.config.max_orders)?;
        ensure_nonempty("hedger_commitment", &request.hedger_commitment)?;
        ensure_nonempty("nullifier_hash", &request.nullifier_hash)?;
        ensure_nonempty("margin_commitment", &request.margin_commitment)?;
        ensure_nonempty("privacy_account_id", &request.privacy_account_id)?;
        ensure_nonempty("decoy_root", &request.decoy_root)?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        ensure_bps("limit_fee_bps", request.limit_fee_bps)?;
        ensure!(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "order max fee exceeds runtime ceiling"
        )?;
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "post-quantum security bits below runtime minimum"
        )?;

        let book = self
            .books
            .get(&request.book_id)
            .ok_or_else(|| format!("unknown book {}", request.book_id))?;
        ensure!(book.status.accepts_orders(), "book does not accept orders");
        ensure!(
            self.height <= book.expires_height && self.height < book.maturity_height,
            "book expired or matured"
        )?;
        ensure!(
            request.notional_micro_units >= book.min_notional_micro_units,
            "notional below book minimum"
        )?;
        ensure!(
            request.notional_micro_units <= book.max_notional_micro_units,
            "notional above book maximum"
        )?;
        ensure!(
            request.max_fee_bps <= book.max_user_fee_bps,
            "order fee exceeds book ceiling"
        )?;

        let sealed_payload_hash = hash_json("sealed-order-payload", &request.sealed_payload);
        let replay_key = format!("order-nullifier:{}", request.nullifier_hash);
        ensure!(
            !self.replay_fences.contains(&replay_key),
            "order nullifier replay"
        )?;
        let order_id = derive_order_id(
            self.counters.sealed_orders_posted + 1,
            &request.book_id,
            &request.hedger_commitment,
            &sealed_payload_hash,
            &request.nullifier_hash,
        );

        let order = SealedHedgeOrder {
            order_id: order_id.clone(),
            book_id: request.book_id.clone(),
            hedger_commitment: request.hedger_commitment,
            sealed_payload_hash,
            nullifier_hash: request.nullifier_hash,
            side: request.side,
            notional_micro_units: request.notional_micro_units,
            max_fee_bps: request.max_fee_bps,
            limit_fee_bps: request.limit_fee_bps,
            premium_micro_units: request.premium_micro_units,
            margin_commitment: request.margin_commitment,
            privacy_account_id: request.privacy_account_id,
            decoy_root: request.decoy_root,
            status: OrderStatus::Sealed,
            posted_height: self.height,
            expires_height: self.height + self.config.order_ttl_blocks,
            pq_security_bits: request.pq_security_bits,
            reservation_id: None,
            netting_round_id: None,
            clearing_id: None,
            receipt_id: None,
            rebate_id: None,
        };

        self.orders.insert(order_id.clone(), order.clone());
        self.replay_fences.insert(replay_key);
        self.books
            .get_mut(&request.book_id)
            .expect("book checked above")
            .order_ids
            .insert(order_id);
        self.counters.sealed_orders_posted += 1;
        self.counters.total_notional_micro_units = self
            .counters
            .total_notional_micro_units
            .saturating_add(order.notional_micro_units);
        self.refresh_roots();
        Ok(order)
    }

    pub fn reserve_sponsor_margin(
        &mut self,
        request: ReserveSponsorMarginRequest,
    ) -> Result<SponsorMarginReservation> {
        ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("margin_root", &request.margin_root)?;
        ensure_bps("cover_bps", request.cover_bps)?;
        ensure!(
            request.cover_bps >= self.config.sponsor_cover_bps,
            "sponsor cover below runtime target"
        )?;
        ensure!(
            request.reserved_micro_units > 0,
            "reserved_micro_units must be positive"
        )?;
        ensure!(!request.order_ids.is_empty(), "order_ids must not be empty");

        let book = self
            .books
            .get(&request.book_id)
            .ok_or_else(|| format!("unknown book {}", request.book_id))?;
        ensure!(book.status.accepts_orders(), "book cannot reserve margin");

        let mut unique_orders = BTreeSet::new();
        let mut required_margin = 0_u64;
        for order_id in &request.order_ids {
            ensure!(unique_orders.insert(order_id.clone()), "duplicate order id");
            let order = self
                .orders
                .get(order_id)
                .ok_or_else(|| format!("unknown order {order_id}"))?;
            ensure!(
                order.book_id == request.book_id,
                "order belongs to another book"
            );
            ensure!(order.status.nettable(), "order is not margin-reservable");
            ensure!(self.height <= order.expires_height, "order expired");
            required_margin = required_margin.saturating_add(bps_amount(
                order.notional_micro_units,
                self.config.initial_margin_bps,
            ));
        }
        ensure!(
            request.reserved_micro_units >= required_margin,
            "reserved margin below required initial margin"
        )?;

        let reservation_id = derive_reservation_id(
            self.counters.sponsor_margins_reserved + 1,
            &request.book_id,
            &request.sponsor_id,
            &request.margin_root,
            request.reserved_micro_units,
        );
        let reservation = SponsorMarginReservation {
            reservation_id: reservation_id.clone(),
            book_id: request.book_id.clone(),
            sponsor_id: request.sponsor_id,
            order_ids: unique_orders.clone(),
            margin_root: request.margin_root,
            reserved_micro_units: request.reserved_micro_units,
            consumed_micro_units: 0,
            cover_bps: request.cover_bps,
            status: ReservationStatus::Reserved,
            reserved_height: self.height,
            expires_height: self.height + self.config.margin_ttl_blocks,
        };

        self.reservations
            .insert(reservation_id.clone(), reservation.clone());
        let book = self
            .books
            .get_mut(&request.book_id)
            .expect("book checked above");
        book.status = BookStatus::Sponsored;
        book.reservation_ids.insert(reservation_id.clone());
        for order_id in unique_orders {
            let order = self.orders.get_mut(&order_id).expect("order checked above");
            order.status = OrderStatus::MarginReserved;
            order.reservation_id = Some(reservation_id.clone());
        }
        self.counters.sponsor_margins_reserved += 1;
        self.counters.total_margin_reserved_micro_units = self
            .counters
            .total_margin_reserved_micro_units
            .saturating_add(reservation.reserved_micro_units);
        self.refresh_roots();
        Ok(reservation)
    }

    pub fn net_hedge_exposures(
        &mut self,
        request: NetHedgeExposureRequest,
    ) -> Result<ExposureNettingRound> {
        ensure_capacity(
            "netting_rounds",
            self.netting_rounds.len(),
            self.config.max_netting_rounds,
        )?;
        ensure_nonempty("exposure_witness_root", &request.exposure_witness_root)?;
        ensure!(!request.order_ids.is_empty(), "order_ids must not be empty");
        let book = self
            .books
            .get(&request.book_id)
            .ok_or_else(|| format!("unknown book {}", request.book_id))?;
        ensure!(
            request.privacy_set_size >= book.min_privacy_set_size,
            "privacy set below book minimum"
        )?;
        ensure!(
            request.decoy_set_size >= book.min_decoy_set_size,
            "decoy set below book minimum"
        )?;

        let mut order_ids = BTreeSet::new();
        let mut long_notional = 0_u64;
        let mut short_notional = 0_u64;
        let mut net_exposure = 0_i128;
        for order_id in &request.order_ids {
            ensure!(order_ids.insert(order_id.clone()), "duplicate order id");
            let order = self
                .orders
                .get(order_id)
                .ok_or_else(|| format!("unknown order {order_id}"))?;
            ensure!(
                order.book_id == request.book_id,
                "order belongs to another book"
            );
            ensure!(order.status.nettable(), "order is not nettable");
            ensure!(self.height <= order.expires_height, "order expired");
            let signed = order.side.signed_notional(order.notional_micro_units);
            net_exposure += signed;
            if signed >= 0 {
                long_notional = long_notional.saturating_add(order.notional_micro_units);
            } else {
                short_notional = short_notional.saturating_add(order.notional_micro_units);
            }
        }
        ensure!(
            long_notional > 0 && short_notional > 0,
            "netting requires both long and short fee exposure"
        )?;

        let netting_round_id = derive_netting_round_id(
            self.counters.exposure_rounds_netted + 1,
            &request.book_id,
            &request.exposure_witness_root,
            net_exposure,
        );
        let round = ExposureNettingRound {
            netting_round_id: netting_round_id.clone(),
            book_id: request.book_id.clone(),
            order_ids: order_ids.clone(),
            exposure_root: derive_exposure_root(
                &request.book_id,
                &order_ids,
                &request.exposure_witness_root,
                net_exposure,
            ),
            netted_exposure_micro_units: net_exposure,
            long_notional_micro_units: long_notional,
            short_notional_micro_units: short_notional,
            privacy_set_size: request.privacy_set_size,
            decoy_set_size: request.decoy_set_size,
            status: NettingStatus::ExposureMatched,
            proposed_height: self.height,
            expires_height: self.height + self.config.netting_ttl_blocks,
            clearing_id: None,
        };

        self.netting_rounds
            .insert(netting_round_id.clone(), round.clone());
        let book = self
            .books
            .get_mut(&request.book_id)
            .expect("book checked above");
        book.status = BookStatus::Netting;
        book.netting_round_ids.insert(netting_round_id.clone());
        for order_id in order_ids {
            let order = self.orders.get_mut(&order_id).expect("order checked above");
            order.status = OrderStatus::Netted;
            order.netting_round_id = Some(netting_round_id.clone());
        }
        self.counters.exposure_rounds_netted += 1;
        self.refresh_roots();
        Ok(round)
    }

    pub fn clear_low_fee_fee_futures_and_caps(
        &mut self,
        request: ClearFeeHedgesRequest,
    ) -> Result<FeeHedgeClearing> {
        ensure_capacity("clearings", self.clearings.len(), self.config.max_clearings)?;
        ensure_nonempty("settlement_witness_root", &request.settlement_witness_root)?;
        ensure_nonempty("proof_root", &request.proof_root)?;
        ensure_bps("clearing_price_bps", request.clearing_price_bps)?;
        if let Some(cap_strike_bps) = request.cap_strike_bps {
            ensure_bps("cap_strike_bps", cap_strike_bps)?;
        }
        let round = self
            .netting_rounds
            .get(&request.netting_round_id)
            .ok_or_else(|| format!("unknown netting round {}", request.netting_round_id))?;
        ensure!(
            round.book_id == request.book_id,
            "round belongs to another book"
        );
        ensure!(
            matches!(
                round.status,
                NettingStatus::ExposureMatched | NettingStatus::ClearingQueued
            ),
            "round is not clearable"
        )?;
        ensure!(self.height <= round.expires_height, "netting round expired");

        let gross_notional = round
            .long_notional_micro_units
            .saturating_add(round.short_notional_micro_units);
        let clearing_fee = bps_amount(gross_notional, self.config.clearing_fee_bps);
        let cap_premium = if request.cap_strike_bps.is_some() {
            bps_amount(gross_notional, self.config.cap_premium_bps)
        } else {
            0
        };
        let sponsor_paid = bps_amount(
            clearing_fee.saturating_add(cap_premium),
            self.config.sponsor_cover_bps,
        );
        let user_paid = clearing_fee
            .saturating_add(cap_premium)
            .saturating_sub(sponsor_paid);
        let baseline_fee = bps_amount(gross_notional, self.config.max_user_fee_bps);
        let fee_savings = baseline_fee.saturating_sub(user_paid);
        let clearing_id = derive_clearing_id(
            self.counters.clearings_completed + 1,
            &request.book_id,
            &request.netting_round_id,
            request.clearing_price_bps,
            &request.proof_root,
        );
        let clearing = FeeHedgeClearing {
            clearing_id: clearing_id.clone(),
            book_id: request.book_id.clone(),
            netting_round_id: request.netting_round_id.clone(),
            order_ids: round.order_ids.clone(),
            clearing_price_bps: request.clearing_price_bps,
            cap_strike_bps: request.cap_strike_bps,
            settlement_root: derive_settlement_root(
                &request.book_id,
                &request.netting_round_id,
                &request.settlement_witness_root,
                request.clearing_price_bps,
            ),
            proof_root: request.proof_root,
            gross_notional_micro_units: gross_notional,
            net_exposure_micro_units: round.netted_exposure_micro_units,
            clearing_fee_micro_units: clearing_fee,
            sponsor_paid_micro_units: sponsor_paid,
            user_paid_micro_units: user_paid,
            fee_savings_micro_units: fee_savings,
            status: ClearingStatus::Cleared,
            cleared_height: self.height,
            expires_height: self.height + self.config.clearing_ttl_blocks,
        };

        self.clearings.insert(clearing_id.clone(), clearing.clone());
        let round = self
            .netting_rounds
            .get_mut(&request.netting_round_id)
            .expect("round checked above");
        round.status = NettingStatus::ClearingQueued;
        round.clearing_id = Some(clearing_id.clone());
        let book = self
            .books
            .get_mut(&request.book_id)
            .expect("book checked through round");
        book.status = BookStatus::Clearing;
        book.clearing_ids.insert(clearing_id.clone());
        for order_id in &clearing.order_ids {
            let order = self
                .orders
                .get_mut(order_id)
                .expect("order checked by round");
            order.status = OrderStatus::Cleared;
            order.clearing_id = Some(clearing_id.clone());
        }
        self.consume_reservations_for_clearing(&clearing);
        self.counters.clearings_completed += 1;
        self.counters.total_fee_savings_micro_units = self
            .counters
            .total_fee_savings_micro_units
            .saturating_add(clearing.fee_savings_micro_units);
        self.refresh_roots();
        Ok(clearing)
    }

    pub fn publish_private_settlement_receipt(
        &mut self,
        request: PublishSettlementReceiptRequest,
    ) -> Result<PrivateSettlementReceipt> {
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        ensure_nonempty("receipt_root", &request.receipt_root)?;
        ensure_nonempty("nullifier_root", &request.nullifier_root)?;
        let clearing = self
            .clearings
            .get(&request.clearing_id)
            .ok_or_else(|| format!("unknown clearing {}", request.clearing_id))?;
        ensure!(
            matches!(
                clearing.status,
                ClearingStatus::Cleared | ClearingStatus::Receipting
            ),
            "clearing is not receiptable"
        )?;
        ensure!(self.height <= clearing.expires_height, "clearing expired");
        let encrypted_memo_hash = hash_json("settlement-receipt-memo", &request.encrypted_memo);
        let replay_key = format!("receipt-nullifier-root:{}", request.nullifier_root);
        ensure!(
            !self.replay_fences.contains(&replay_key),
            "receipt nullifier root replay"
        )?;

        let receipt_id = derive_receipt_id(
            self.counters.receipts_published + 1,
            &request.clearing_id,
            &request.receipt_root,
            &request.nullifier_root,
        );
        let receipt = PrivateSettlementReceipt {
            receipt_id: receipt_id.clone(),
            clearing_id: request.clearing_id.clone(),
            book_id: clearing.book_id.clone(),
            receipt_root: request.receipt_root,
            nullifier_root: request.nullifier_root,
            encrypted_memo_hash,
            settled_order_count: clearing.order_ids.len() as u64,
            settled_notional_micro_units: clearing.gross_notional_micro_units,
            final_fee_bps: clearing.clearing_price_bps,
            status: ReceiptStatus::Published,
            published_height: self.height,
            finalizes_height: self.height + self.config.receipt_finality_blocks,
        };

        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.replay_fences.insert(replay_key);
        let clearing = self
            .clearings
            .get_mut(&request.clearing_id)
            .expect("clearing checked above");
        clearing.status = ClearingStatus::Receipting;
        for order_id in &clearing.order_ids {
            let order = self
                .orders
                .get_mut(order_id)
                .expect("order checked by clearing");
            order.status = OrderStatus::Receipted;
            order.receipt_id = Some(receipt_id.clone());
        }
        self.counters.receipts_published += 1;
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        ensure_nonempty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_nonempty("rebate_root", &request.rebate_root)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        ensure!(
            request.rebate_bps <= self.config.rebate_bps,
            "rebate exceeds runtime rebate ceiling"
        )?;
        ensure!(
            request.expires_height > self.height,
            "rebate expiry must be in the future"
        )?;
        let receipt = self
            .receipts
            .get(&request.receipt_id)
            .ok_or_else(|| format!("unknown receipt {}", request.receipt_id))?;
        ensure!(
            matches!(
                receipt.status,
                ReceiptStatus::Published | ReceiptStatus::Finalized
            ),
            "receipt is not rebate eligible"
        )?;
        let clearing = self
            .clearings
            .get(&receipt.clearing_id)
            .ok_or_else(|| format!("unknown clearing {}", receipt.clearing_id))?;
        let amount = bps_amount(clearing.fee_savings_micro_units, request.rebate_bps);
        ensure!(amount > 0, "rebate amount is zero");

        let rebate_id = derive_rebate_id(
            self.counters.rebates_issued + 1,
            &request.receipt_id,
            &request.beneficiary_commitment,
            &request.rebate_root,
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            receipt_id: request.receipt_id.clone(),
            clearing_id: receipt.clearing_id.clone(),
            book_id: receipt.book_id.clone(),
            beneficiary_commitment: request.beneficiary_commitment,
            rebate_root: request.rebate_root,
            amount_micro_units: amount,
            rebate_bps: request.rebate_bps,
            status: RebateStatus::Issued,
            issued_height: self.height,
            expires_height: request.expires_height,
        };

        self.rebates.insert(rebate_id.clone(), rebate.clone());
        let clearing = self
            .clearings
            .get_mut(&receipt.clearing_id)
            .expect("clearing checked above");
        clearing.status = ClearingStatus::Rebated;
        for order_id in &clearing.order_ids {
            let order = self
                .orders
                .get_mut(order_id)
                .expect("order checked by clearing");
            order.status = OrderStatus::Rebated;
            order.rebate_id = Some(rebate_id.clone());
        }
        self.counters.rebates_issued += 1;
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(amount);
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn finalize_private_settlement_receipt(
        &mut self,
        request: FinalizeReceiptRequest,
    ) -> Result<PrivateSettlementReceipt> {
        ensure_nonempty("finality_witness_root", &request.finality_witness_root)?;
        let receipt_view = self
            .receipts
            .get(&request.receipt_id)
            .ok_or_else(|| format!("unknown receipt {}", request.receipt_id))?;
        ensure!(
            matches!(receipt_view.status, ReceiptStatus::Published),
            "receipt is not finalizable"
        );
        ensure!(
            self.height >= receipt_view.finalizes_height,
            "receipt finality height has not been reached"
        );
        let finality_key = derive_finality_key(
            &request.receipt_id,
            &request.finality_witness_root,
            receipt_view.finalizes_height,
        );
        ensure!(
            !self.replay_fences.contains(&finality_key),
            "receipt finality replay"
        );
        let receipt = self
            .receipts
            .get_mut(&request.receipt_id)
            .ok_or_else(|| format!("unknown receipt {}", request.receipt_id))?;
        receipt.status = ReceiptStatus::Finalized;
        self.replay_fences.insert(finality_key);
        if let Some(clearing) = self.clearings.get_mut(&receipt.clearing_id) {
            if matches!(clearing.status, ClearingStatus::Receipting) {
                clearing.status = ClearingStatus::Settled;
            }
        }
        if let Some(book) = self.books.get_mut(&receipt.book_id) {
            if matches!(book.status, BookStatus::Settling | BookStatus::Clearing) {
                book.status = BookStatus::Settling;
            }
        }
        let finalized = receipt.clone();
        self.refresh_roots();
        Ok(finalized)
    }

    pub fn claim_rebate(&mut self, request: ClaimRebateRequest) -> Result<FeeRebate> {
        ensure_nonempty("claim_nullifier", &request.claim_nullifier)?;
        ensure_nonempty("claim_witness_root", &request.claim_witness_root)?;
        let replay_key = derive_claim_key(
            &request.rebate_id,
            &request.claim_nullifier,
            &request.claim_witness_root,
        );
        ensure!(
            !self.replay_fences.contains(&replay_key),
            "rebate claim replay"
        );
        let rebate = self
            .rebates
            .get_mut(&request.rebate_id)
            .ok_or_else(|| format!("unknown rebate {}", request.rebate_id))?;
        ensure!(
            matches!(rebate.status, RebateStatus::Issued),
            "rebate is not claimable"
        );
        ensure!(self.height <= rebate.expires_height, "rebate expired");
        rebate.status = RebateStatus::Claimed;
        self.replay_fences.insert(replay_key);
        let claimed = rebate.clone();
        self.refresh_roots();
        Ok(claimed)
    }

    pub fn release_sponsor_margin(
        &mut self,
        request: ReleaseMarginRequest,
    ) -> Result<SponsorMarginReservation> {
        ensure_nonempty("release_witness_root", &request.release_witness_root)?;
        let replay_key = derive_release_key(&request.reservation_id, &request.release_witness_root);
        ensure!(
            !self.replay_fences.contains(&replay_key),
            "margin release replay"
        );
        let reservation = self
            .reservations
            .get_mut(&request.reservation_id)
            .ok_or_else(|| format!("unknown reservation {}", request.reservation_id))?;
        ensure!(
            matches!(
                reservation.status,
                ReservationStatus::Reserved
                    | ReservationStatus::PartiallyConsumed
                    | ReservationStatus::Expired
            ),
            "reservation is not releasable"
        );
        let all_orders_terminal = reservation.order_ids.iter().all(|order_id| {
            self.orders.get(order_id).map_or(true, |order| {
                matches!(
                    order.status,
                    OrderStatus::Cleared
                        | OrderStatus::Receipted
                        | OrderStatus::Rebated
                        | OrderStatus::Expired
                        | OrderStatus::Rejected
                        | OrderStatus::Slashed
                )
            })
        });
        ensure!(
            all_orders_terminal || self.height > reservation.expires_height,
            "reservation still backs live orders"
        );
        reservation.status = ReservationStatus::Released;
        self.replay_fences.insert(replay_key);
        let released = reservation.clone();
        self.refresh_roots();
        Ok(released)
    }

    pub fn hedge_book_summary(&self, book_id: &str) -> Result<HedgeBookSummary> {
        let book = self
            .books
            .get(book_id)
            .ok_or_else(|| format!("unknown book {book_id}"))?;
        Ok(HedgeBookSummary {
            book_id: book.book_id.clone(),
            venue: book.venue,
            instrument: book.instrument,
            status: book.status,
            order_count: book.order_ids.len() as u64,
            reservation_count: book.reservation_ids.len() as u64,
            netting_round_count: book.netting_round_ids.len() as u64,
            clearing_count: book.clearing_ids.len() as u64,
            max_user_fee_bps: book.max_user_fee_bps,
            maturity_height: book.maturity_height,
            expires_height: book.expires_height,
            min_privacy_set_size: book.min_privacy_set_size,
            min_decoy_set_size: book.min_decoy_set_size,
        })
    }

    pub fn hedge_exposure_summary(&self, book_id: &str) -> Result<HedgeExposureSummary> {
        ensure!(self.books.contains_key(book_id), "unknown book {book_id}");
        let mut open_long = 0_u64;
        let mut open_short = 0_u64;
        let mut active_privacy_accounts = BTreeSet::new();
        for order in self
            .orders
            .values()
            .filter(|order| order.book_id == book_id)
        {
            if matches!(
                order.status,
                OrderStatus::Sealed
                    | OrderStatus::Admitted
                    | OrderStatus::MarginReserved
                    | OrderStatus::Netted
            ) {
                if order.side.signed_notional(order.notional_micro_units) >= 0 {
                    open_long = open_long.saturating_add(order.notional_micro_units);
                } else {
                    open_short = open_short.saturating_add(order.notional_micro_units);
                }
                active_privacy_accounts.insert(order.privacy_account_id.clone());
            }
        }
        let cleared_notional = self
            .clearings
            .values()
            .filter(|clearing| clearing.book_id == book_id)
            .map(|clearing| clearing.gross_notional_micro_units)
            .fold(0_u64, u64::saturating_add);
        let sponsored_margin = self
            .reservations
            .values()
            .filter(|reservation| reservation.book_id == book_id)
            .map(|reservation| reservation.reserved_micro_units)
            .fold(0_u64, u64::saturating_add);
        let pending_receipts = self
            .receipts
            .values()
            .filter(|receipt| {
                receipt.book_id == book_id && matches!(receipt.status, ReceiptStatus::Published)
            })
            .count() as u64;
        let issued_rebates = self
            .rebates
            .values()
            .filter(|rebate| rebate.book_id == book_id)
            .map(|rebate| rebate.amount_micro_units)
            .fold(0_u64, u64::saturating_add);
        Ok(HedgeExposureSummary {
            book_id: book_id.to_string(),
            open_long_notional_micro_units: open_long,
            open_short_notional_micro_units: open_short,
            cleared_notional_micro_units: cleared_notional,
            sponsored_margin_micro_units: sponsored_margin,
            pending_receipts,
            issued_rebates_micro_units: issued_rebates,
            active_privacy_accounts: active_privacy_accounts.len() as u64,
        })
    }

    pub fn track_privacy_budget(
        &mut self,
        request: TrackPrivacyBudgetRequest,
    ) -> Result<PrivacyBudget> {
        ensure_capacity(
            "privacy_budgets",
            self.privacy_budgets.len(),
            self.config.max_privacy_accounts,
        )?;
        ensure_nonempty("privacy_account_id", &request.privacy_account_id)?;
        ensure!(request.max_weight > 0, "max_weight must be positive");
        ensure!(
            request.min_remaining_decoys >= self.config.min_decoy_set_size,
            "remaining decoys below runtime minimum"
        )?;
        if let Some(order_id) = &request.order_id {
            ensure!(self.orders.contains_key(order_id), "unknown budget order");
        }
        let key = privacy_budget_key(&request.privacy_account_id, request.epoch);
        let mut budget = self.privacy_budgets.remove(&key).unwrap_or(PrivacyBudget {
            privacy_account_id: request.privacy_account_id.clone(),
            epoch: request.epoch,
            status: PrivacyBudgetStatus::Active,
            spent_weight: 0,
            max_weight: request.max_weight,
            min_remaining_decoys: request.min_remaining_decoys,
            last_update_height: self.height,
            order_ids: BTreeSet::new(),
        });
        ensure!(
            request.max_weight >= budget.spent_weight,
            "max_weight cannot drop below spent weight"
        )?;
        budget.max_weight = request.max_weight;
        budget.min_remaining_decoys = request.min_remaining_decoys;
        budget.spent_weight = budget.spent_weight.saturating_add(request.spend_weight);
        budget.last_update_height = self.height;
        if let Some(order_id) = request.order_id {
            budget.order_ids.insert(order_id);
        }
        budget.status = if budget.spent_weight >= budget.max_weight {
            PrivacyBudgetStatus::Exhausted
        } else if budget.spent_weight.saturating_mul(100) >= budget.max_weight.saturating_mul(80) {
            PrivacyBudgetStatus::Throttled
        } else {
            PrivacyBudgetStatus::Active
        };
        self.privacy_budgets.insert(key, budget.clone());
        self.counters.privacy_budget_updates += 1;
        self.refresh_roots();
        Ok(budget)
    }

    pub fn slash_stale_or_overlevered_hedger(
        &mut self,
        request: SlashHedgerRequest,
    ) -> Result<SlashRecord> {
        ensure_capacity("slashes", self.slashes.len(), self.config.max_slashes)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        let evidence_root = hash_json("slash-evidence", &request.evidence);
        ensure!(
            self.books.contains_key(&request.book_id),
            "unknown slashing book"
        )?;
        let slash_amount = bps_amount(request.slash_base_micro_units, self.config.slash_bps);
        ensure!(slash_amount > 0, "slash amount is zero");
        let slash_id = derive_slash_id(
            self.counters.hedgers_slashed + 1,
            &request.subject_id,
            &request.book_id,
            request.reason,
            &evidence_root,
        );
        let record = SlashRecord {
            slash_id: slash_id.clone(),
            subject_id: request.subject_id.clone(),
            book_id: request.book_id.clone(),
            reason: request.reason,
            evidence_root,
            slashed_micro_units: slash_amount,
            status: ReservationStatus::Slashed,
            slashed_height: self.height,
        };

        self.slashes.insert(slash_id, record.clone());
        if let Some(order) = self.orders.get_mut(&request.subject_id) {
            order.status = OrderStatus::Slashed;
        }
        if let Some(reservation) = self.reservations.get_mut(&request.subject_id) {
            reservation.status = ReservationStatus::Slashed;
        }
        if let Some(book) = self.books.get_mut(&request.book_id) {
            if matches!(
                request.reason,
                SlashReason::StaleOracle | SlashReason::StaleClearing
            ) {
                book.status = BookStatus::Slashed;
            }
        }
        let budget_key = self
            .privacy_budgets
            .iter()
            .find(|(_, budget)| budget.order_ids.contains(&request.subject_id))
            .map(|(key, _)| key.clone());
        if let Some(key) = budget_key {
            if let Some(budget) = self.privacy_budgets.get_mut(&key) {
                budget.status = PrivacyBudgetStatus::Slashed;
            }
        }
        self.counters.hedgers_slashed += 1;
        self.counters.total_slash_micro_units = self
            .counters
            .total_slash_micro_units
            .saturating_add(slash_amount);
        self.refresh_roots();
        Ok(record)
    }

    pub fn advance_height(&mut self, height: u64) {
        if height > self.height {
            self.height = height;
            self.epoch = height / self.config.privacy_epoch_blocks.max(1);
            self.expire_stale_records();
            self.refresh_roots();
        }
    }

    fn consume_reservations_for_clearing(&mut self, clearing: &FeeHedgeClearing) {
        let mut reservation_ids = BTreeSet::new();
        for order_id in &clearing.order_ids {
            if let Some(order) = self.orders.get(order_id) {
                if let Some(reservation_id) = &order.reservation_id {
                    reservation_ids.insert(reservation_id.clone());
                }
            }
        }
        let mut remaining = clearing.sponsor_paid_micro_units;
        for reservation_id in reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(&reservation_id) {
                if !matches!(reservation.status, ReservationStatus::Reserved) {
                    continue;
                }
                let available = reservation
                    .reserved_micro_units
                    .saturating_sub(reservation.consumed_micro_units);
                let consume = available.min(remaining);
                reservation.consumed_micro_units =
                    reservation.consumed_micro_units.saturating_add(consume);
                remaining = remaining.saturating_sub(consume);
                reservation.status =
                    if reservation.consumed_micro_units >= reservation.reserved_micro_units {
                        ReservationStatus::Consumed
                    } else {
                        ReservationStatus::PartiallyConsumed
                    };
                if remaining == 0 {
                    break;
                }
            }
        }
    }

    fn expire_stale_records(&mut self) {
        for book in self.books.values_mut() {
            if self.height > book.expires_height && !matches!(book.status, BookStatus::Settled) {
                book.status = BookStatus::Expired;
            }
        }
        for order in self.orders.values_mut() {
            if self.height > order.expires_height
                && matches!(
                    order.status,
                    OrderStatus::Sealed | OrderStatus::Admitted | OrderStatus::MarginReserved
                )
            {
                order.status = OrderStatus::Expired;
            }
        }
        for reservation in self.reservations.values_mut() {
            if self.height > reservation.expires_height
                && matches!(reservation.status, ReservationStatus::Reserved)
            {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for round in self.netting_rounds.values_mut() {
            if self.height > round.expires_height
                && !matches!(
                    round.status,
                    NettingStatus::Settled | NettingStatus::Disputed
                )
            {
                round.status = NettingStatus::Expired;
            }
        }
        for clearing in self.clearings.values_mut() {
            if self.height > clearing.expires_height
                && !matches!(
                    clearing.status,
                    ClearingStatus::Settled | ClearingStatus::Rebated
                )
            {
                clearing.status = ClearingStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if self.height > rebate.expires_height && matches!(rebate.status, RebateStatus::Issued)
            {
                rebate.status = RebateStatus::Expired;
            }
        }
    }

    fn refresh_roots(&mut self) {
        self.roots.books_root = map_root("books", &self.books);
        self.roots.orders_root = map_root("orders", &self.orders);
        self.roots.reservations_root = map_root("reservations", &self.reservations);
        self.roots.netting_rounds_root = map_root("netting_rounds", &self.netting_rounds);
        self.roots.clearings_root = map_root("clearings", &self.clearings);
        self.roots.receipts_root = map_root("receipts", &self.receipts);
        self.roots.rebates_root = map_root("rebates", &self.rebates);
        self.roots.privacy_budgets_root = map_root("privacy_budgets", &self.privacy_budgets);
        self.roots.slashes_root = map_root("slashes", &self.slashes);
        self.roots.replay_fences_root = set_root("replay_fences", &self.replay_fences);
        self.roots.state_root = self.state_root();
    }
}

fn derive_book_id(sequence: u64, request: &OpenHedgeBookRequest, metadata_hash: &str) -> String {
    domain_hash(
        "private-fee-hedge-book-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(request.venue.as_str()),
            HashPart::Str(request.instrument.as_str()),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.oracle_root),
            HashPart::Str(&request.sponsor_pool_id),
            HashPart::Str(metadata_hash),
        ],
        32,
    )
}

fn derive_order_id(
    sequence: u64,
    book_id: &str,
    hedger_commitment: &str,
    sealed_payload_hash: &str,
    nullifier_hash: &str,
) -> String {
    domain_hash(
        "private-fee-hedge-order-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(book_id),
            HashPart::Str(hedger_commitment),
            HashPart::Str(sealed_payload_hash),
            HashPart::Str(nullifier_hash),
        ],
        32,
    )
}

fn derive_reservation_id(
    sequence: u64,
    book_id: &str,
    sponsor_id: &str,
    margin_root: &str,
    reserved_micro_units: u64,
) -> String {
    domain_hash(
        "private-fee-hedge-reservation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(book_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(margin_root),
            HashPart::U64(reserved_micro_units),
        ],
        32,
    )
}

fn derive_netting_round_id(
    sequence: u64,
    book_id: &str,
    witness_root: &str,
    net_exposure: i128,
) -> String {
    domain_hash(
        "private-fee-hedge-netting-round-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(book_id),
            HashPart::Str(witness_root),
            HashPart::Int(net_exposure),
        ],
        32,
    )
}

fn derive_exposure_root(
    book_id: &str,
    order_ids: &BTreeSet<String>,
    witness_root: &str,
    net_exposure: i128,
) -> String {
    let leaves = order_ids
        .iter()
        .map(|order_id| json!({"order_id": order_id}))
        .collect::<Vec<_>>();
    let order_root = merkle_root("private-fee-hedge-exposure-orders", &leaves);
    domain_hash(
        "private-fee-hedge-exposure-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(book_id),
            HashPart::Str(&order_root),
            HashPart::Str(witness_root),
            HashPart::Int(net_exposure),
        ],
        32,
    )
}

fn derive_clearing_id(
    sequence: u64,
    book_id: &str,
    netting_round_id: &str,
    clearing_price_bps: u64,
    proof_root: &str,
) -> String {
    domain_hash(
        "private-fee-hedge-clearing-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(book_id),
            HashPart::Str(netting_round_id),
            HashPart::U64(clearing_price_bps),
            HashPart::Str(proof_root),
        ],
        32,
    )
}

fn derive_settlement_root(
    book_id: &str,
    netting_round_id: &str,
    settlement_witness_root: &str,
    clearing_price_bps: u64,
) -> String {
    domain_hash(
        "private-fee-hedge-settlement-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(book_id),
            HashPart::Str(netting_round_id),
            HashPart::Str(settlement_witness_root),
            HashPart::U64(clearing_price_bps),
        ],
        32,
    )
}

fn derive_receipt_id(
    sequence: u64,
    clearing_id: &str,
    receipt_root: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "private-fee-hedge-receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(clearing_id),
            HashPart::Str(receipt_root),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

fn derive_rebate_id(
    sequence: u64,
    receipt_id: &str,
    beneficiary_commitment: &str,
    rebate_root: &str,
) -> String {
    domain_hash(
        "private-fee-hedge-rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(rebate_root),
        ],
        32,
    )
}

fn derive_slash_id(
    sequence: u64,
    subject_id: &str,
    book_id: &str,
    reason: SlashReason,
    evidence_root: &str,
) -> String {
    domain_hash(
        "private-fee-hedge-slash-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(subject_id),
            HashPart::Str(book_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn derive_finality_key(
    receipt_id: &str,
    finality_witness_root: &str,
    finalizes_height: u64,
) -> String {
    domain_hash(
        "private-fee-hedge-receipt-finality-key",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(finality_witness_root),
            HashPart::U64(finalizes_height),
        ],
        32,
    )
}

fn derive_claim_key(rebate_id: &str, claim_nullifier: &str, claim_witness_root: &str) -> String {
    domain_hash(
        "private-fee-hedge-rebate-claim-key",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(rebate_id),
            HashPart::Str(claim_nullifier),
            HashPart::Str(claim_witness_root),
        ],
        32,
    )
}

fn derive_release_key(reservation_id: &str, release_witness_root: &str) -> String {
    domain_hash(
        "private-fee-hedge-margin-release-key",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(release_witness_root),
        ],
        32,
    )
}

fn privacy_budget_key(privacy_account_id: &str, epoch: u64) -> String {
    domain_hash(
        "private-fee-hedge-privacy-budget-key",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(privacy_account_id),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn empty_root(name: &str) -> String {
    merkle_root(&format!("private-fee-hedge-{name}"), &[])
}

fn map_root<T: Serialize>(name: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(&format!("private-fee-hedge-{name}"), &leaves)
}

fn set_root(name: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(&format!("private-fee-hedge-{name}"), &leaves)
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    ensure!(value <= MAX_BPS, "{name} exceeds MAX_BPS")
}

fn ensure_capacity(name: &str, len: usize, max: usize) -> Result<()> {
    ensure!(len < max, "{name} capacity exhausted")
}

fn ensure_nonempty(name: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{name} must not be empty")
}
