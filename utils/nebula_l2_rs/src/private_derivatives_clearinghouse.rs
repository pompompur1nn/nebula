use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateDerivativesClearinghouseResult<T> = Result<T, String>;

pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION: &str =
    "nebula-private-derivatives-clearinghouse-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MARGIN_COMMITMENT_SCHEME: &str =
    "shake256-confidential-cross-margin-account-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_POSITION_COMMITMENT_SCHEME: &str =
    "shake256-shielded-perp-option-position-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MARK_COMMITMENT_SCHEME: &str =
    "ml-kem-1024+shake256-encrypted-mark-price-commitment-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_FUNDING_EPOCH_SCHEME: &str =
    "deterministic-private-derivatives-funding-epoch-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_LIQUIDATION_QUEUE_SCHEME: &str =
    "private-priority-liquidation-queue-commitment-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_KEEPER_AUCTION_SCHEME: &str =
    "zk-sealed-keeper-derivatives-auction-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_REBATE_SCHEME: &str =
    "zk-low-fee-private-derivatives-rebate-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-derivatives-risk-attestation-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_PRIVACY_BUDGET_SCHEME: &str =
    "bucketed-selective-disclosure-derivatives-budget-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-private-derivatives-settlement-receipt-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-private-derivatives-public-record-v1";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_HEIGHT: u64 = 192;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_LOW_FEE_LANE: &str =
    "small-private-derivatives";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_BASE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_INSURANCE_ASSET_ID: &str =
    "pdch-insurance-devnet";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_ORACLE_FEED_ID: &str =
    "feed-wxmr-dusd-derivatives-devnet";
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_WXMR_PRICE: u64 =
    166 * PRIVATE_DERIVATIVES_CLEARINGHOUSE_PRICE_SCALE;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_FUNDING_EPOCH_BLOCKS: u64 = 24;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MARK_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_POSITION_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_LIQUIDATION_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_REBATE_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS: u64 = 21_600;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 160;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_INITIAL_MARGIN_BPS: u64 = 2_000;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 1_250;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_LIQUIDATION_PENALTY_BPS: u64 = 650;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MAX_LEVERAGE_BPS: u64 = 50_000;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_SMALL_NOTIONAL_UNITS: u64 = 50_000_000;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_SPONSORED_MAX_FEE_UNITS: u64 = 7_500;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_MARKETS: usize = 65_536;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_MARGIN_ACCOUNTS: usize = 262_144;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_POSITIONS: usize = 524_288;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_MARKS: usize = 262_144;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_LIQUIDATIONS: usize = 524_288;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_AUCTIONS: usize = 524_288;
pub const PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativesMarketKind {
    Perpetual,
    EuropeanOption,
    AmericanOption,
    PowerPerpetual,
    VolatilityPerpetual,
    StructuredOption,
}

impl DerivativesMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Perpetual => "perpetual",
            Self::EuropeanOption => "european_option",
            Self::AmericanOption => "american_option",
            Self::PowerPerpetual => "power_perpetual",
            Self::VolatilityPerpetual => "volatility_perpetual",
            Self::StructuredOption => "structured_option",
        }
    }

    pub fn uses_funding(self) -> bool {
        matches!(
            self,
            Self::Perpetual | Self::PowerPerpetual | Self::VolatilityPerpetual
        )
    }

    pub fn is_option(self) -> bool {
        matches!(
            self,
            Self::EuropeanOption | Self::AmericanOption | Self::StructuredOption
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativesMarketStatus {
    Draft,
    Active,
    ReduceOnly,
    LiquidationOnly,
    SettlementOnly,
    Paused,
    Retired,
}

impl DerivativesMarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::SettlementOnly => "settlement_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_new_positions(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(
            self,
            Self::Active | Self::ReduceOnly | Self::LiquidationOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginAccountStatus {
    Pending,
    Active,
    Frozen,
    MarginCall,
    Liquidating,
    Settling,
    Closed,
    Expired,
}

impl MarginAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::MarginCall => "margin_call",
            Self::Liquidating => "liquidating",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Active | Self::Frozen | Self::MarginCall | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionInstrument {
    PerpLong,
    PerpShort,
    CallLong,
    CallShort,
    PutLong,
    PutShort,
    Spread,
    VolatilitySwap,
}

impl PositionInstrument {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerpLong => "perp_long",
            Self::PerpShort => "perp_short",
            Self::CallLong => "call_long",
            Self::CallShort => "call_short",
            Self::PutLong => "put_long",
            Self::PutShort => "put_short",
            Self::Spread => "spread",
            Self::VolatilitySwap => "volatility_swap",
        }
    }

    pub fn is_short(self) -> bool {
        matches!(self, Self::PerpShort | Self::CallShort | Self::PutShort)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedPositionStatus {
    Pending,
    Open,
    ReduceOnly,
    FundingLocked,
    Exercisable,
    LiquidationQueued,
    Auctioning,
    Settling,
    Settled,
    Closed,
    Expired,
    Disputed,
}

impl ShieldedPositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::FundingLocked => "funding_locked",
            Self::Exercisable => "exercisable",
            Self::LiquidationQueued => "liquidation_queued",
            Self::Auctioning => "auctioning",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Open
                | Self::ReduceOnly
                | Self::FundingLocked
                | Self::Exercisable
                | Self::LiquidationQueued
                | Self::Auctioning
                | Self::Settling
        )
    }

    pub fn liquidatable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::ReduceOnly | Self::FundingLocked | Self::LiquidationQueued
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingEpochStatus {
    Scheduled,
    MarkCommitted,
    Locked,
    Applied,
    Challenged,
    Settled,
    Expired,
}

impl FundingEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::MarkCommitted => "mark_committed",
            Self::Locked => "locked",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::MarkCommitted | Self::Locked | Self::Applied
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarkCommitmentStatus {
    Submitted,
    Aggregated,
    ChallengeOpen,
    Accepted,
    Rejected,
    Expired,
}

impl MarkCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Aggregated => "aggregated",
            Self::ChallengeOpen => "challenge_open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationQueueStatus {
    Queued,
    ChallengeOpen,
    KeeperAuctionOpen,
    Executable,
    Executed,
    Cancelled,
    Expired,
}

impl LiquidationQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ChallengeOpen => "challenge_open",
            Self::KeeperAuctionOpen => "keeper_auction_open",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::ChallengeOpen | Self::KeeperAuctionOpen | Self::Executable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeeperAuctionStatus {
    CommitOpen,
    RevealOpen,
    Clearing,
    Awarded,
    Settled,
    Cancelled,
    Expired,
    Slashed,
}

impl KeeperAuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Clearing => "clearing",
            Self::Awarded => "awarded",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::CommitOpen | Self::RevealOpen | Self::Clearing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Posted,
    Reserved,
    Redeemable,
    Redeemed,
    Cancelled,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Reserved => "reserved",
            Self::Redeemable => "redeemable",
            Self::Redeemed => "redeemed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Posted | Self::Reserved | Self::Redeemable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRiskDecision {
    Approve,
    RaiseMargin,
    ReduceOnly,
    PauseMarket,
    LiquidationOnly,
    EmergencySettlement,
    Reject,
}

impl PqRiskDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::RaiseMargin => "raise_margin",
            Self::ReduceOnly => "reduce_only",
            Self::PauseMarket => "pause_market",
            Self::LiquidationOnly => "liquidation_only",
            Self::EmergencySettlement => "emergency_settlement",
            Self::Reject => "reject",
        }
    }

    pub fn permits_risk(self) -> bool {
        matches!(self, Self::Approve | Self::RaiseMargin | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetStatus {
    Active,
    Exhausted,
    Frozen,
    Rotating,
    Revoked,
    Expired,
}

impl PrivacyBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Submitted,
    Proven,
    Challenged,
    Accepted,
    Finalized,
    Rejected,
    Expired,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Proven => "proven",
            Self::Challenged => "challenged",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    MarketListed,
    MarginAccountCommitted,
    PositionCommitted,
    FundingEpochPosted,
    MarkCommitted,
    LiquidationQueued,
    KeeperAuctionPosted,
    RebatePosted,
    PqAttestationPosted,
    PrivacyBudgetPosted,
    SettlementReceiptPosted,
    StateCheckpoint,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketListed => "market_listed",
            Self::MarginAccountCommitted => "margin_account_committed",
            Self::PositionCommitted => "position_committed",
            Self::FundingEpochPosted => "funding_epoch_posted",
            Self::MarkCommitted => "mark_committed",
            Self::LiquidationQueued => "liquidation_queued",
            Self::KeeperAuctionPosted => "keeper_auction_posted",
            Self::RebatePosted => "rebate_posted",
            Self::PqAttestationPosted => "pq_attestation_posted",
            Self::PrivacyBudgetPosted => "privacy_budget_posted",
            Self::SettlementReceiptPosted => "settlement_receipt_posted",
            Self::StateCheckpoint => "state_checkpoint",
        }
    }
}

fn clearinghouse_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn clearinghouse_collection_root(domain: &str, records: &[Value]) -> String {
    clearinghouse_record_root(domain, &Value::Array(records.to_vec()))
}

fn clearinghouse_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn non_empty(field: &str, value: &str) -> PrivateDerivativesClearinghouseResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_bps(field: &str, value: u64) -> PrivateDerivativesClearinghouseResult<()> {
    if value > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn validate_positive(field: &str, value: u64) -> PrivateDerivativesClearinghouseResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn validate_window(
    starts_at_height: u64,
    expires_at_height: u64,
    label: &str,
) -> PrivateDerivativesClearinghouseResult<()> {
    if expires_at_height <= starts_at_height {
        Err(format!("{label} expiry must be after start"))
    } else {
        Ok(())
    }
}

fn validate_public_payload(
    field: &str,
    payload: &Value,
) -> PrivateDerivativesClearinghouseResult<()> {
    match payload {
        Value::Null => Err(format!("{field} must not be null")),
        _ => Ok(()),
    }
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for value in values {
        set.insert(value.clone());
    }
    set.into_iter().collect()
}

fn json_root(domain: &str, payload: &Value) -> String {
    clearinghouse_record_root(domain, payload)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDerivativesClearinghouseConfig {
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub insurance_asset_id: String,
    pub default_oracle_feed_id: String,
    pub margin_commitment_scheme: String,
    pub position_commitment_scheme: String,
    pub mark_commitment_scheme: String,
    pub funding_epoch_scheme: String,
    pub liquidation_queue_scheme: String,
    pub keeper_auction_scheme: String,
    pub rebate_scheme: String,
    pub pq_attestation_scheme: String,
    pub privacy_budget_scheme: String,
    pub settlement_receipt_scheme: String,
    pub public_record_scheme: String,
    pub default_low_fee_lane: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub funding_epoch_blocks: u64,
    pub mark_ttl_blocks: u64,
    pub position_ttl_blocks: u64,
    pub liquidation_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub privacy_budget_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub max_leverage_bps: u64,
    pub small_notional_units: u64,
    pub sponsored_max_fee_units: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
}

impl Default for PrivateDerivativesClearinghouseConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PrivateDerivativesClearinghouseConfig {
    pub fn devnet() -> Self {
        Self {
            base_asset_id: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_BASE_ASSET_ID.to_string(),
            quote_asset_id: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_QUOTE_ASSET_ID.to_string(),
            insurance_asset_id: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_INSURANCE_ASSET_ID
                .to_string(),
            default_oracle_feed_id: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_ORACLE_FEED_ID
                .to_string(),
            margin_commitment_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_MARGIN_COMMITMENT_SCHEME
                .to_string(),
            position_commitment_scheme:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_POSITION_COMMITMENT_SCHEME.to_string(),
            mark_commitment_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_MARK_COMMITMENT_SCHEME
                .to_string(),
            funding_epoch_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_FUNDING_EPOCH_SCHEME
                .to_string(),
            liquidation_queue_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_LIQUIDATION_QUEUE_SCHEME
                .to_string(),
            keeper_auction_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_KEEPER_AUCTION_SCHEME
                .to_string(),
            rebate_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_REBATE_SCHEME.to_string(),
            pq_attestation_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_PQ_ATTESTATION_SCHEME
                .to_string(),
            privacy_budget_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_PRIVACY_BUDGET_SCHEME
                .to_string(),
            settlement_receipt_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_SETTLEMENT_RECEIPT_SCHEME
                .to_string(),
            public_record_scheme: PRIVATE_DERIVATIVES_CLEARINGHOUSE_PUBLIC_RECORD_SCHEME
                .to_string(),
            default_low_fee_lane: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_LOW_FEE_LANE
                .to_string(),
            price_scale: PRIVATE_DERIVATIVES_CLEARINGHOUSE_PRICE_SCALE,
            index_scale: PRIVATE_DERIVATIVES_CLEARINGHOUSE_INDEX_SCALE,
            funding_epoch_blocks: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_FUNDING_EPOCH_BLOCKS,
            mark_ttl_blocks: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MARK_TTL_BLOCKS,
            position_ttl_blocks: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_POSITION_TTL_BLOCKS,
            liquidation_ttl_blocks:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_LIQUIDATION_TTL_BLOCKS,
            auction_ttl_blocks: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_AUCTION_TTL_BLOCKS,
            rebate_ttl_blocks: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_REBATE_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            privacy_budget_ttl_blocks:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_PRIVACY_BUDGET_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_RECEIPT_TTL_BLOCKS,
            initial_margin_bps: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_LIQUIDATION_PENALTY_BPS,
            max_leverage_bps: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MAX_LEVERAGE_BPS,
            small_notional_units: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_SMALL_NOTIONAL_UNITS,
            sponsored_max_fee_units:
                PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_SPONSORED_MAX_FEE_UNITS,
            min_privacy_set_size: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("base_asset_id", &self.base_asset_id)?;
        non_empty("quote_asset_id", &self.quote_asset_id)?;
        non_empty("insurance_asset_id", &self.insurance_asset_id)?;
        non_empty("default_oracle_feed_id", &self.default_oracle_feed_id)?;
        non_empty("margin_commitment_scheme", &self.margin_commitment_scheme)?;
        non_empty(
            "position_commitment_scheme",
            &self.position_commitment_scheme,
        )?;
        non_empty("mark_commitment_scheme", &self.mark_commitment_scheme)?;
        non_empty("funding_epoch_scheme", &self.funding_epoch_scheme)?;
        non_empty("liquidation_queue_scheme", &self.liquidation_queue_scheme)?;
        non_empty("keeper_auction_scheme", &self.keeper_auction_scheme)?;
        non_empty("rebate_scheme", &self.rebate_scheme)?;
        non_empty("pq_attestation_scheme", &self.pq_attestation_scheme)?;
        non_empty("privacy_budget_scheme", &self.privacy_budget_scheme)?;
        non_empty("settlement_receipt_scheme", &self.settlement_receipt_scheme)?;
        non_empty("public_record_scheme", &self.public_record_scheme)?;
        non_empty("default_low_fee_lane", &self.default_low_fee_lane)?;
        validate_positive("price_scale", self.price_scale)?;
        validate_positive("index_scale", self.index_scale)?;
        validate_positive("funding_epoch_blocks", self.funding_epoch_blocks)?;
        validate_positive("mark_ttl_blocks", self.mark_ttl_blocks)?;
        validate_positive("position_ttl_blocks", self.position_ttl_blocks)?;
        validate_positive("liquidation_ttl_blocks", self.liquidation_ttl_blocks)?;
        validate_positive("auction_ttl_blocks", self.auction_ttl_blocks)?;
        validate_positive("rebate_ttl_blocks", self.rebate_ttl_blocks)?;
        validate_positive("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        validate_positive("privacy_budget_ttl_blocks", self.privacy_budget_ttl_blocks)?;
        validate_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        validate_bps("initial_margin_bps", self.initial_margin_bps)?;
        validate_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        validate_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        if self.maintenance_margin_bps > self.initial_margin_bps {
            return Err("maintenance margin cannot exceed initial margin".to_string());
        }
        if self.max_leverage_bps < PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_BPS {
            return Err("max leverage must be at least 1x".to_string());
        }
        validate_positive("small_notional_units", self.small_notional_units)?;
        validate_positive("sponsored_max_fee_units", self.sponsored_max_fee_units)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        if self.min_pq_security_bits
            < PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS
        {
            return Err("minimum pq security bits below protocol floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_derivatives_clearinghouse_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "insurance_asset_id": self.insurance_asset_id,
            "default_oracle_feed_id": self.default_oracle_feed_id,
            "margin_commitment_scheme": self.margin_commitment_scheme,
            "position_commitment_scheme": self.position_commitment_scheme,
            "mark_commitment_scheme": self.mark_commitment_scheme,
            "funding_epoch_scheme": self.funding_epoch_scheme,
            "liquidation_queue_scheme": self.liquidation_queue_scheme,
            "keeper_auction_scheme": self.keeper_auction_scheme,
            "rebate_scheme": self.rebate_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "privacy_budget_scheme": self.privacy_budget_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "public_record_scheme": self.public_record_scheme,
            "default_low_fee_lane": self.default_low_fee_lane,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "funding_epoch_blocks": self.funding_epoch_blocks,
            "mark_ttl_blocks": self.mark_ttl_blocks,
            "position_ttl_blocks": self.position_ttl_blocks,
            "liquidation_ttl_blocks": self.liquidation_ttl_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "privacy_budget_ttl_blocks": self.privacy_budget_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "small_notional_units": self.small_notional_units,
            "sponsored_max_fee_units": self.sponsored_max_fee_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-CLEARINGHOUSE-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivativesMarket {
    pub market_id: String,
    pub name: String,
    pub kind: DerivativesMarketKind,
    pub status: DerivativesMarketStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub collateral_asset_id: String,
    pub oracle_feed_id: String,
    pub low_fee_lane: String,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub max_leverage_bps: u64,
    pub max_open_interest_units: u64,
    pub funding_interval_blocks: u64,
    pub listed_at_height: u64,
    pub expires_at_height: u64,
    pub risk_metadata: Value,
}

impl DerivativesMarket {
    pub fn new(
        name: &str,
        kind: DerivativesMarketKind,
        base_asset_id: &str,
        quote_asset_id: &str,
        collateral_asset_id: &str,
        oracle_feed_id: &str,
        low_fee_lane: &str,
        initial_margin_bps: u64,
        maintenance_margin_bps: u64,
        liquidation_penalty_bps: u64,
        max_leverage_bps: u64,
        max_open_interest_units: u64,
        funding_interval_blocks: u64,
        listed_at_height: u64,
        expires_at_height: u64,
        risk_metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let id_payload = json!({
            "name": name,
            "kind": kind.as_str(),
            "base_asset_id": base_asset_id,
            "quote_asset_id": quote_asset_id,
            "collateral_asset_id": collateral_asset_id,
            "oracle_feed_id": oracle_feed_id,
            "listed_at_height": listed_at_height,
        });
        let market_id = clearinghouse_record_root("PRIVATE-DERIVATIVES-MARKET-ID", &id_payload);
        let market = Self {
            market_id,
            name: name.to_string(),
            kind,
            status: DerivativesMarketStatus::Active,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            initial_margin_bps,
            maintenance_margin_bps,
            liquidation_penalty_bps,
            max_leverage_bps,
            max_open_interest_units,
            funding_interval_blocks,
            listed_at_height,
            expires_at_height,
            risk_metadata: risk_metadata.clone(),
        };
        market.validate()?;
        Ok(market)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("market_id", &self.market_id)?;
        non_empty("name", &self.name)?;
        non_empty("base_asset_id", &self.base_asset_id)?;
        non_empty("quote_asset_id", &self.quote_asset_id)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("oracle_feed_id", &self.oracle_feed_id)?;
        non_empty("low_fee_lane", &self.low_fee_lane)?;
        validate_bps("initial_margin_bps", self.initial_margin_bps)?;
        validate_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        validate_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        if self.maintenance_margin_bps > self.initial_margin_bps {
            return Err(format!(
                "market {} maintenance margin exceeds initial margin",
                self.market_id
            ));
        }
        if self.max_leverage_bps < PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_BPS {
            return Err(format!("market {} leverage below 1x", self.market_id));
        }
        validate_positive("max_open_interest_units", self.max_open_interest_units)?;
        validate_positive("funding_interval_blocks", self.funding_interval_blocks)?;
        validate_window(
            self.listed_at_height,
            self.expires_at_height,
            "market listing window",
        )?;
        validate_public_payload("risk_metadata", &self.risk_metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "derivatives_market",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "name": self.name,
            "market_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "low_fee_lane": self.low_fee_lane,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "max_open_interest_units": self.max_open_interest_units,
            "funding_interval_blocks": self.funding_interval_blocks,
            "listed_at_height": self.listed_at_height,
            "expires_at_height": self.expires_at_height,
            "risk_metadata": self.risk_metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-MARKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialMarginAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub margin_commitment: String,
    pub balance_upper_bound_units: u64,
    pub locked_margin_upper_bound_units: u64,
    pub health_bucket: String,
    pub status: MarginAccountStatus,
    pub privacy_budget_id: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub viewing_policy_root: String,
    pub range_proof: Value,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl ConfidentialMarginAccount {
    pub fn new(
        owner_commitment: &str,
        collateral_asset_id: &str,
        margin_commitment: &str,
        balance_upper_bound_units: u64,
        locked_margin_upper_bound_units: u64,
        health_bucket: &str,
        privacy_budget_id: &str,
        min_privacy_set_size: u64,
        pq_security_bits: u16,
        viewing_policy: &Value,
        range_proof: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let viewing_policy_root =
            json_root("PRIVATE-DERIVATIVES-MARGIN-VIEWING-POLICY", viewing_policy);
        let id_payload = json!({
            "owner_commitment": owner_commitment,
            "collateral_asset_id": collateral_asset_id,
            "margin_commitment": margin_commitment,
            "created_at_height": created_at_height,
        });
        let account_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-MARGIN-ACCOUNT-ID", &id_payload);
        let account = Self {
            account_id,
            owner_commitment: owner_commitment.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            margin_commitment: margin_commitment.to_string(),
            balance_upper_bound_units,
            locked_margin_upper_bound_units,
            health_bucket: health_bucket.to_string(),
            status: MarginAccountStatus::Active,
            privacy_budget_id: privacy_budget_id.to_string(),
            min_privacy_set_size,
            pq_security_bits,
            viewing_policy_root,
            range_proof: range_proof.clone(),
            created_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        account.validate()?;
        Ok(account)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("account_id", &self.account_id)?;
        non_empty("owner_commitment", &self.owner_commitment)?;
        non_empty("collateral_asset_id", &self.collateral_asset_id)?;
        non_empty("margin_commitment", &self.margin_commitment)?;
        non_empty("health_bucket", &self.health_bucket)?;
        non_empty("privacy_budget_id", &self.privacy_budget_id)?;
        non_empty("viewing_policy_root", &self.viewing_policy_root)?;
        validate_positive("balance_upper_bound_units", self.balance_upper_bound_units)?;
        if self.locked_margin_upper_bound_units > self.balance_upper_bound_units {
            return Err(format!(
                "margin account {} locked margin exceeds balance",
                self.account_id
            ));
        }
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        if self.pq_security_bits < PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err(format!(
                "margin account {} below pq security floor",
                self.account_id
            ));
        }
        validate_public_payload("range_proof", &self.range_proof)?;
        validate_public_payload("metadata", &self.metadata)?;
        validate_window(
            self.created_at_height,
            self.expires_at_height,
            "margin account window",
        )?;
        Ok(())
    }

    pub fn available_margin_upper_bound_units(&self) -> u64 {
        self.balance_upper_bound_units
            .saturating_sub(self.locked_margin_upper_bound_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_margin_account",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "margin_commitment": self.margin_commitment,
            "balance_upper_bound_units": self.balance_upper_bound_units,
            "locked_margin_upper_bound_units": self.locked_margin_upper_bound_units,
            "available_margin_upper_bound_units": self.available_margin_upper_bound_units(),
            "health_bucket": self.health_bucket,
            "status": self.status.as_str(),
            "privacy_budget_id": self.privacy_budget_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "viewing_policy_root": self.viewing_policy_root,
            "range_proof": self.range_proof,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-MARGIN-ACCOUNT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedDerivativePosition {
    pub position_id: String,
    pub market_id: String,
    pub margin_account_id: String,
    pub instrument: PositionInstrument,
    pub status: ShieldedPositionStatus,
    pub notional_bucket: String,
    pub notional_upper_bound_units: u64,
    pub collateral_requirement_upper_bound_units: u64,
    pub size_commitment: String,
    pub entry_price_commitment: String,
    pub payoff_commitment: String,
    pub maturity_height: u64,
    pub funding_epoch_id: String,
    pub privacy_budget_id: String,
    pub order_nullifier_root: String,
    pub range_proof: Value,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl ShieldedDerivativePosition {
    pub fn new(
        market_id: &str,
        margin_account_id: &str,
        instrument: PositionInstrument,
        notional_bucket: &str,
        notional_upper_bound_units: u64,
        collateral_requirement_upper_bound_units: u64,
        size_commitment: &str,
        entry_price_commitment: &str,
        payoff_commitment: &str,
        maturity_height: u64,
        funding_epoch_id: &str,
        privacy_budget_id: &str,
        order_nullifier_payload: &Value,
        range_proof: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let order_nullifier_root = json_root(
            "PRIVATE-DERIVATIVES-POSITION-ORDER-NULLIFIERS",
            order_nullifier_payload,
        );
        let id_payload = json!({
            "market_id": market_id,
            "margin_account_id": margin_account_id,
            "instrument": instrument.as_str(),
            "size_commitment": size_commitment,
            "entry_price_commitment": entry_price_commitment,
            "created_at_height": created_at_height,
        });
        let position_id = clearinghouse_record_root("PRIVATE-DERIVATIVES-POSITION-ID", &id_payload);
        let position = Self {
            position_id,
            market_id: market_id.to_string(),
            margin_account_id: margin_account_id.to_string(),
            instrument,
            status: ShieldedPositionStatus::Open,
            notional_bucket: notional_bucket.to_string(),
            notional_upper_bound_units,
            collateral_requirement_upper_bound_units,
            size_commitment: size_commitment.to_string(),
            entry_price_commitment: entry_price_commitment.to_string(),
            payoff_commitment: payoff_commitment.to_string(),
            maturity_height,
            funding_epoch_id: funding_epoch_id.to_string(),
            privacy_budget_id: privacy_budget_id.to_string(),
            order_nullifier_root,
            range_proof: range_proof.clone(),
            created_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        position.validate()?;
        Ok(position)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("position_id", &self.position_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("margin_account_id", &self.margin_account_id)?;
        non_empty("notional_bucket", &self.notional_bucket)?;
        non_empty("size_commitment", &self.size_commitment)?;
        non_empty("entry_price_commitment", &self.entry_price_commitment)?;
        non_empty("payoff_commitment", &self.payoff_commitment)?;
        non_empty("funding_epoch_id", &self.funding_epoch_id)?;
        non_empty("privacy_budget_id", &self.privacy_budget_id)?;
        non_empty("order_nullifier_root", &self.order_nullifier_root)?;
        validate_positive(
            "notional_upper_bound_units",
            self.notional_upper_bound_units,
        )?;
        validate_positive(
            "collateral_requirement_upper_bound_units",
            self.collateral_requirement_upper_bound_units,
        )?;
        if self.collateral_requirement_upper_bound_units > self.notional_upper_bound_units {
            return Err(format!(
                "position {} collateral requirement exceeds notional",
                self.position_id
            ));
        }
        if self.maturity_height <= self.created_at_height {
            return Err(format!(
                "position {} maturity not in future",
                self.position_id
            ));
        }
        validate_window(
            self.created_at_height,
            self.expires_at_height,
            "position ttl window",
        )?;
        validate_public_payload("range_proof", &self.range_proof)?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_derivative_position",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "position_id": self.position_id,
            "market_id": self.market_id,
            "margin_account_id": self.margin_account_id,
            "instrument": self.instrument.as_str(),
            "status": self.status.as_str(),
            "notional_bucket": self.notional_bucket,
            "notional_upper_bound_units": self.notional_upper_bound_units,
            "collateral_requirement_upper_bound_units": self.collateral_requirement_upper_bound_units,
            "size_commitment": self.size_commitment,
            "entry_price_commitment": self.entry_price_commitment,
            "payoff_commitment": self.payoff_commitment,
            "maturity_height": self.maturity_height,
            "funding_epoch_id": self.funding_epoch_id,
            "privacy_budget_id": self.privacy_budget_id,
            "order_nullifier_root": self.order_nullifier_root,
            "range_proof": self.range_proof,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-SHIELDED-POSITION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingEpoch {
    pub epoch_id: String,
    pub market_id: String,
    pub epoch_number: u64,
    pub status: FundingEpochStatus,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub premium_index_commitment: String,
    pub funding_rate_bps: i64,
    pub mark_commitment_root: String,
    pub net_payment_commitment: String,
    pub participant_set_root: String,
    pub metadata: Value,
}

impl FundingEpoch {
    pub fn new(
        market_id: &str,
        epoch_number: u64,
        starts_at_height: u64,
        ends_at_height: u64,
        premium_index_commitment: &str,
        funding_rate_bps: i64,
        mark_commitment_payload: &Value,
        net_payment_commitment: &str,
        participant_payload: &Value,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let mark_commitment_root = json_root(
            "PRIVATE-DERIVATIVES-FUNDING-MARK-COMMITMENTS",
            mark_commitment_payload,
        );
        let participant_set_root = json_root(
            "PRIVATE-DERIVATIVES-FUNDING-PARTICIPANTS",
            participant_payload,
        );
        let id_payload = json!({
            "market_id": market_id,
            "epoch_number": epoch_number,
            "starts_at_height": starts_at_height,
            "ends_at_height": ends_at_height,
        });
        let epoch_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-FUNDING-EPOCH-ID", &id_payload);
        let epoch = Self {
            epoch_id,
            market_id: market_id.to_string(),
            epoch_number,
            status: FundingEpochStatus::MarkCommitted,
            starts_at_height,
            ends_at_height,
            premium_index_commitment: premium_index_commitment.to_string(),
            funding_rate_bps,
            mark_commitment_root,
            net_payment_commitment: net_payment_commitment.to_string(),
            participant_set_root,
            metadata: metadata.clone(),
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("epoch_id", &self.epoch_id)?;
        non_empty("market_id", &self.market_id)?;
        validate_positive("epoch_number", self.epoch_number)?;
        non_empty("premium_index_commitment", &self.premium_index_commitment)?;
        non_empty("mark_commitment_root", &self.mark_commitment_root)?;
        non_empty("net_payment_commitment", &self.net_payment_commitment)?;
        non_empty("participant_set_root", &self.participant_set_root)?;
        validate_window(
            self.starts_at_height,
            self.ends_at_height,
            "funding epoch window",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "funding_epoch",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "market_id": self.market_id,
            "epoch_number": self.epoch_number,
            "status": self.status.as_str(),
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "premium_index_commitment": self.premium_index_commitment,
            "funding_rate_bps": self.funding_rate_bps,
            "mark_commitment_root": self.mark_commitment_root,
            "net_payment_commitment": self.net_payment_commitment,
            "participant_set_root": self.participant_set_root,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-FUNDING-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMarkPriceCommitment {
    pub mark_id: String,
    pub market_id: String,
    pub epoch_id: String,
    pub oracle_feed_id: String,
    pub status: MarkCommitmentStatus,
    pub encrypted_mark_price: Value,
    pub price_bucket: String,
    pub confidence_bps: u64,
    pub source_set_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl EncryptedMarkPriceCommitment {
    pub fn new(
        market_id: &str,
        epoch_id: &str,
        oracle_feed_id: &str,
        encrypted_mark_price: &Value,
        price_bucket: &str,
        confidence_bps: u64,
        source_payload: &Value,
        posted_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let source_set_root =
            json_root("PRIVATE-DERIVATIVES-MARK-PRICE-SOURCE-SET", source_payload);
        let id_payload = json!({
            "market_id": market_id,
            "epoch_id": epoch_id,
            "oracle_feed_id": oracle_feed_id,
            "encrypted_mark_price": encrypted_mark_price,
            "posted_at_height": posted_at_height,
        });
        let mark_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-MARK-COMMITMENT-ID", &id_payload);
        let mark = Self {
            mark_id,
            market_id: market_id.to_string(),
            epoch_id: epoch_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            status: MarkCommitmentStatus::Submitted,
            encrypted_mark_price: encrypted_mark_price.clone(),
            price_bucket: price_bucket.to_string(),
            confidence_bps,
            source_set_root,
            posted_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        mark.validate()?;
        Ok(mark)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("mark_id", &self.mark_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("epoch_id", &self.epoch_id)?;
        non_empty("oracle_feed_id", &self.oracle_feed_id)?;
        non_empty("price_bucket", &self.price_bucket)?;
        validate_bps("confidence_bps", self.confidence_bps)?;
        non_empty("source_set_root", &self.source_set_root)?;
        validate_public_payload("encrypted_mark_price", &self.encrypted_mark_price)?;
        validate_public_payload("metadata", &self.metadata)?;
        validate_window(
            self.posted_at_height,
            self.expires_at_height,
            "encrypted mark window",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_mark_price_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "mark_id": self.mark_id,
            "market_id": self.market_id,
            "epoch_id": self.epoch_id,
            "oracle_feed_id": self.oracle_feed_id,
            "status": self.status.as_str(),
            "encrypted_mark_price": self.encrypted_mark_price,
            "price_bucket": self.price_bucket,
            "confidence_bps": self.confidence_bps,
            "source_set_root": self.source_set_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-ENCRYPTED-MARK", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationQueueEntry {
    pub queue_id: String,
    pub market_id: String,
    pub margin_account_id: String,
    pub position_id: String,
    pub status: LiquidationQueueStatus,
    pub priority_bucket: String,
    pub health_bucket: String,
    pub encrypted_trigger: Value,
    pub keeper_set_root: String,
    pub penalty_bps: u64,
    pub queued_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl LiquidationQueueEntry {
    pub fn new(
        market_id: &str,
        margin_account_id: &str,
        position_id: &str,
        priority_bucket: &str,
        health_bucket: &str,
        encrypted_trigger: &Value,
        keeper_payload: &Value,
        penalty_bps: u64,
        queued_at_height: u64,
        executable_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let keeper_set_root =
            json_root("PRIVATE-DERIVATIVES-LIQUIDATION-KEEPER-SET", keeper_payload);
        let id_payload = json!({
            "market_id": market_id,
            "margin_account_id": margin_account_id,
            "position_id": position_id,
            "priority_bucket": priority_bucket,
            "queued_at_height": queued_at_height,
        });
        let queue_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-LIQUIDATION-QUEUE-ID", &id_payload);
        let entry = Self {
            queue_id,
            market_id: market_id.to_string(),
            margin_account_id: margin_account_id.to_string(),
            position_id: position_id.to_string(),
            status: LiquidationQueueStatus::KeeperAuctionOpen,
            priority_bucket: priority_bucket.to_string(),
            health_bucket: health_bucket.to_string(),
            encrypted_trigger: encrypted_trigger.clone(),
            keeper_set_root,
            penalty_bps,
            queued_at_height,
            executable_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("queue_id", &self.queue_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("margin_account_id", &self.margin_account_id)?;
        non_empty("position_id", &self.position_id)?;
        non_empty("priority_bucket", &self.priority_bucket)?;
        non_empty("health_bucket", &self.health_bucket)?;
        non_empty("keeper_set_root", &self.keeper_set_root)?;
        validate_bps("penalty_bps", self.penalty_bps)?;
        if self.executable_at_height < self.queued_at_height {
            return Err(format!("queue {} executable before queued", self.queue_id));
        }
        validate_window(
            self.queued_at_height,
            self.expires_at_height,
            "liquidation queue window",
        )?;
        validate_public_payload("encrypted_trigger", &self.encrypted_trigger)?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidation_queue_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "queue_id": self.queue_id,
            "market_id": self.market_id,
            "margin_account_id": self.margin_account_id,
            "position_id": self.position_id,
            "status": self.status.as_str(),
            "priority_bucket": self.priority_bucket,
            "health_bucket": self.health_bucket,
            "encrypted_trigger": self.encrypted_trigger,
            "keeper_set_root": self.keeper_set_root,
            "penalty_bps": self.penalty_bps,
            "queued_at_height": self.queued_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-LIQUIDATION-QUEUE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKeeperAuction {
    pub auction_id: String,
    pub queue_id: String,
    pub market_id: String,
    pub status: KeeperAuctionStatus,
    pub commit_root: String,
    pub encrypted_bid_book: Value,
    pub min_keeper_bond_units: u64,
    pub max_fee_bps: u64,
    pub winner_commitment: String,
    pub opens_at_height: u64,
    pub reveal_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl SealedKeeperAuction {
    pub fn new(
        queue_id: &str,
        market_id: &str,
        bid_payload: &Value,
        min_keeper_bond_units: u64,
        max_fee_bps: u64,
        winner_commitment: &str,
        opens_at_height: u64,
        reveal_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let commit_root = json_root("PRIVATE-DERIVATIVES-KEEPER-AUCTION-BIDS", bid_payload);
        let id_payload = json!({
            "queue_id": queue_id,
            "market_id": market_id,
            "commit_root": commit_root,
            "opens_at_height": opens_at_height,
        });
        let auction_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-KEEPER-AUCTION-ID", &id_payload);
        let auction = Self {
            auction_id,
            queue_id: queue_id.to_string(),
            market_id: market_id.to_string(),
            status: KeeperAuctionStatus::CommitOpen,
            commit_root,
            encrypted_bid_book: bid_payload.clone(),
            min_keeper_bond_units,
            max_fee_bps,
            winner_commitment: winner_commitment.to_string(),
            opens_at_height,
            reveal_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        auction.validate()?;
        Ok(auction)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("auction_id", &self.auction_id)?;
        non_empty("queue_id", &self.queue_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("commit_root", &self.commit_root)?;
        non_empty("winner_commitment", &self.winner_commitment)?;
        validate_positive("min_keeper_bond_units", self.min_keeper_bond_units)?;
        validate_bps("max_fee_bps", self.max_fee_bps)?;
        if self.reveal_at_height < self.opens_at_height {
            return Err(format!(
                "auction {} reveal height before open height",
                self.auction_id
            ));
        }
        validate_window(
            self.opens_at_height,
            self.expires_at_height,
            "keeper auction window",
        )?;
        validate_public_payload("encrypted_bid_book", &self.encrypted_bid_book)?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_keeper_auction",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "auction_id": self.auction_id,
            "queue_id": self.queue_id,
            "market_id": self.market_id,
            "status": self.status.as_str(),
            "commit_root": self.commit_root,
            "encrypted_bid_book": self.encrypted_bid_book,
            "min_keeper_bond_units": self.min_keeper_bond_units,
            "max_fee_bps": self.max_fee_bps,
            "winner_commitment": self.winner_commitment,
            "opens_at_height": self.opens_at_height,
            "reveal_at_height": self.reveal_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-KEEPER-AUCTION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub sponsor_commitment: String,
    pub market_id: String,
    pub beneficiary_commitment: String,
    pub low_fee_lane: String,
    pub status: RebateStatus,
    pub notional_bucket: String,
    pub max_fee_units: u64,
    pub remaining_fee_units: u64,
    pub min_privacy_set_size: u64,
    pub proof_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl LowFeeRebate {
    pub fn new(
        sponsor_commitment: &str,
        market_id: &str,
        beneficiary_commitment: &str,
        low_fee_lane: &str,
        notional_bucket: &str,
        max_fee_units: u64,
        remaining_fee_units: u64,
        min_privacy_set_size: u64,
        proof_payload: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let proof_root = json_root("PRIVATE-DERIVATIVES-LOW-FEE-REBATE-PROOF", proof_payload);
        let id_payload = json!({
            "sponsor_commitment": sponsor_commitment,
            "market_id": market_id,
            "beneficiary_commitment": beneficiary_commitment,
            "low_fee_lane": low_fee_lane,
            "starts_at_height": starts_at_height,
        });
        let rebate_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-LOW-FEE-REBATE-ID", &id_payload);
        let rebate = Self {
            rebate_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            market_id: market_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            status: RebateStatus::Posted,
            notional_bucket: notional_bucket.to_string(),
            max_fee_units,
            remaining_fee_units,
            min_privacy_set_size,
            proof_root,
            starts_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("rebate_id", &self.rebate_id)?;
        non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        non_empty("low_fee_lane", &self.low_fee_lane)?;
        non_empty("notional_bucket", &self.notional_bucket)?;
        validate_positive("max_fee_units", self.max_fee_units)?;
        if self.remaining_fee_units > self.max_fee_units {
            return Err(format!("rebate {} remaining exceeds max", self.rebate_id));
        }
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        non_empty("proof_root", &self.proof_root)?;
        validate_window(
            self.starts_at_height,
            self.expires_at_height,
            "rebate window",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "sponsor_commitment": self.sponsor_commitment,
            "market_id": self.market_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "low_fee_lane": self.low_fee_lane,
            "status": self.status.as_str(),
            "notional_bucket": self.notional_bucket,
            "max_fee_units": self.max_fee_units,
            "remaining_fee_units": self.remaining_fee_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "proof_root": self.proof_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-LOW-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskCommitteeAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub decision: PqRiskDecision,
    pub pq_security_bits: u16,
    pub signer_commitments: Vec<String>,
    pub threshold: u64,
    pub evidence_root: String,
    pub signature_bundle_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PqRiskCommitteeAttestation {
    pub fn new(
        committee_id: &str,
        subject_kind: &str,
        subject_id: &str,
        decision: PqRiskDecision,
        pq_security_bits: u16,
        signer_commitments: &[String],
        threshold: u64,
        evidence_payload: &Value,
        signature_bundle: &Value,
        issued_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let sorted_signers = sorted_strings(signer_commitments);
        let evidence_root = json_root(
            "PRIVATE-DERIVATIVES-PQ-RISK-ATTESTATION-EVIDENCE",
            evidence_payload,
        );
        let signature_bundle_root = json_root(
            "PRIVATE-DERIVATIVES-PQ-RISK-ATTESTATION-SIGNATURES",
            signature_bundle,
        );
        let id_payload = json!({
            "committee_id": committee_id,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "decision": decision.as_str(),
            "signers": sorted_signers,
            "issued_at_height": issued_at_height,
        });
        let attestation_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-PQ-RISK-ATTESTATION-ID", &id_payload);
        let attestation = Self {
            attestation_id,
            committee_id: committee_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            decision,
            pq_security_bits,
            signer_commitments: sorted_signers,
            threshold,
            evidence_root,
            signature_bundle_root,
            issued_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("attestation_id", &self.attestation_id)?;
        non_empty("committee_id", &self.committee_id)?;
        non_empty("subject_kind", &self.subject_kind)?;
        non_empty("subject_id", &self.subject_id)?;
        if self.pq_security_bits < PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err(format!(
                "attestation {} below pq security floor",
                self.attestation_id
            ));
        }
        validate_positive("threshold", self.threshold)?;
        if self.signer_commitments.len() < self.threshold as usize {
            return Err(format!(
                "attestation {} threshold exceeds signer count",
                self.attestation_id
            ));
        }
        for signer in &self.signer_commitments {
            non_empty("signer_commitment", signer)?;
        }
        non_empty("evidence_root", &self.evidence_root)?;
        non_empty("signature_bundle_root", &self.signature_bundle_root)?;
        validate_window(
            self.issued_at_height,
            self.expires_at_height,
            "pq attestation window",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_risk_committee_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "decision": self.decision.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "signer_commitments": self.signer_commitments,
            "threshold": self.threshold,
            "evidence_root": self.evidence_root,
            "signature_bundle_root": self.signature_bundle_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-PQ-RISK-ATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAccount {
    pub budget_id: String,
    pub owner_commitment: String,
    pub market_id: String,
    pub status: PrivacyBudgetStatus,
    pub disclosure_labels: Vec<String>,
    pub total_budget_units: u64,
    pub remaining_budget_units: u64,
    pub min_anonymity_set_size: u64,
    pub rotation_nonce: u64,
    pub policy_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivacyBudgetAccount {
    pub fn new(
        owner_commitment: &str,
        market_id: &str,
        disclosure_labels: &[String],
        total_budget_units: u64,
        remaining_budget_units: u64,
        min_anonymity_set_size: u64,
        rotation_nonce: u64,
        policy_payload: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let labels = sorted_strings(disclosure_labels);
        let policy_root = json_root("PRIVATE-DERIVATIVES-PRIVACY-BUDGET-POLICY", policy_payload);
        let id_payload = json!({
            "owner_commitment": owner_commitment,
            "market_id": market_id,
            "disclosure_labels": labels,
            "starts_at_height": starts_at_height,
            "rotation_nonce": rotation_nonce,
        });
        let budget_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-PRIVACY-BUDGET-ID", &id_payload);
        let budget = Self {
            budget_id,
            owner_commitment: owner_commitment.to_string(),
            market_id: market_id.to_string(),
            status: PrivacyBudgetStatus::Active,
            disclosure_labels: labels,
            total_budget_units,
            remaining_budget_units,
            min_anonymity_set_size,
            rotation_nonce,
            policy_root,
            starts_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("budget_id", &self.budget_id)?;
        non_empty("owner_commitment", &self.owner_commitment)?;
        non_empty("market_id", &self.market_id)?;
        validate_positive("total_budget_units", self.total_budget_units)?;
        if self.remaining_budget_units > self.total_budget_units {
            return Err(format!(
                "privacy budget {} remaining exceeds total",
                self.budget_id
            ));
        }
        validate_positive("min_anonymity_set_size", self.min_anonymity_set_size)?;
        if self.disclosure_labels.is_empty() {
            return Err(format!("privacy budget {} has no labels", self.budget_id));
        }
        for label in &self.disclosure_labels {
            non_empty("disclosure_label", label)?;
        }
        non_empty("policy_root", &self.policy_root)?;
        validate_window(
            self.starts_at_height,
            self.expires_at_height,
            "privacy budget window",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_account",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "market_id": self.market_id,
            "status": self.status.as_str(),
            "disclosure_labels": self.disclosure_labels,
            "total_budget_units": self.total_budget_units,
            "remaining_budget_units": self.remaining_budget_units,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "rotation_nonce": self.rotation_nonce,
            "policy_root": self.policy_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root("PRIVATE-DERIVATIVES-PRIVACY-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub market_id: String,
    pub margin_account_id: String,
    pub position_id: String,
    pub status: SettlementReceiptStatus,
    pub settlement_kind: String,
    pub settlement_amount_commitment: String,
    pub fee_commitment: String,
    pub proof_root: String,
    pub pq_attestation_id: String,
    pub privacy_budget_id: String,
    pub submitted_at_height: u64,
    pub finalized_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl SettlementReceipt {
    pub fn new(
        market_id: &str,
        margin_account_id: &str,
        position_id: &str,
        settlement_kind: &str,
        settlement_amount_commitment: &str,
        fee_commitment: &str,
        proof_payload: &Value,
        pq_attestation_id: &str,
        privacy_budget_id: &str,
        submitted_at_height: u64,
        finalized_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let proof_root = json_root(
            "PRIVATE-DERIVATIVES-SETTLEMENT-RECEIPT-PROOF",
            proof_payload,
        );
        let id_payload = json!({
            "market_id": market_id,
            "margin_account_id": margin_account_id,
            "position_id": position_id,
            "settlement_kind": settlement_kind,
            "proof_root": proof_root,
            "submitted_at_height": submitted_at_height,
        });
        let receipt_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-SETTLEMENT-RECEIPT-ID", &id_payload);
        let receipt = Self {
            receipt_id,
            market_id: market_id.to_string(),
            margin_account_id: margin_account_id.to_string(),
            position_id: position_id.to_string(),
            status: SettlementReceiptStatus::Proven,
            settlement_kind: settlement_kind.to_string(),
            settlement_amount_commitment: settlement_amount_commitment.to_string(),
            fee_commitment: fee_commitment.to_string(),
            proof_root,
            pq_attestation_id: pq_attestation_id.to_string(),
            privacy_budget_id: privacy_budget_id.to_string(),
            submitted_at_height,
            finalized_at_height,
            expires_at_height,
            metadata: metadata.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("receipt_id", &self.receipt_id)?;
        non_empty("market_id", &self.market_id)?;
        non_empty("margin_account_id", &self.margin_account_id)?;
        non_empty("position_id", &self.position_id)?;
        non_empty("settlement_kind", &self.settlement_kind)?;
        non_empty(
            "settlement_amount_commitment",
            &self.settlement_amount_commitment,
        )?;
        non_empty("fee_commitment", &self.fee_commitment)?;
        non_empty("proof_root", &self.proof_root)?;
        non_empty("pq_attestation_id", &self.pq_attestation_id)?;
        non_empty("privacy_budget_id", &self.privacy_budget_id)?;
        if self.finalized_at_height < self.submitted_at_height {
            return Err(format!(
                "receipt {} finalized before submitted",
                self.receipt_id
            ));
        }
        validate_window(
            self.submitted_at_height,
            self.expires_at_height,
            "settlement receipt window",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "market_id": self.market_id,
            "margin_account_id": self.margin_account_id,
            "position_id": self.position_id,
            "status": self.status.as_str(),
            "settlement_kind": self.settlement_kind,
            "settlement_amount_commitment": self.settlement_amount_commitment,
            "fee_commitment": self.fee_commitment,
            "proof_root": self.proof_root,
            "pq_attestation_id": self.pq_attestation_id,
            "privacy_budget_id": self.privacy_budget_id,
            "submitted_at_height": self.submitted_at_height,
            "finalized_at_height": self.finalized_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub subject_root: String,
    pub state_height: u64,
    pub sequence: u64,
    pub disclosure_root: String,
    pub metadata_root: String,
}

impl DeterministicPublicRecord {
    pub fn new(
        record_kind: PublicRecordKind,
        subject_id: &str,
        subject_root: &str,
        state_height: u64,
        sequence: u64,
        disclosure_payload: &Value,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        let disclosure_root = json_root(
            "PRIVATE-DERIVATIVES-PUBLIC-RECORD-DISCLOSURE",
            disclosure_payload,
        );
        let metadata_root = json_root("PRIVATE-DERIVATIVES-PUBLIC-RECORD-METADATA", metadata);
        let id_payload = json!({
            "record_kind": record_kind.as_str(),
            "subject_id": subject_id,
            "subject_root": subject_root,
            "state_height": state_height,
            "sequence": sequence,
        });
        let record_id =
            clearinghouse_record_root("PRIVATE-DERIVATIVES-PUBLIC-RECORD-ID", &id_payload);
        let record = Self {
            record_id,
            record_kind,
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            state_height,
            sequence,
            disclosure_root,
            metadata_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        non_empty("record_id", &self.record_id)?;
        non_empty("subject_id", &self.subject_id)?;
        non_empty("subject_root", &self.subject_root)?;
        non_empty("disclosure_root", &self.disclosure_root)?;
        non_empty("metadata_root", &self.metadata_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "state_height": self.state_height,
            "sequence": self.sequence,
            "disclosure_root": self.disclosure_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-DETERMINISTIC-PUBLIC-RECORD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDerivativesClearinghouseCounters {
    pub market_count: u64,
    pub active_market_count: u64,
    pub margin_account_count: u64,
    pub live_margin_account_count: u64,
    pub position_count: u64,
    pub live_position_count: u64,
    pub short_position_count: u64,
    pub funding_epoch_count: u64,
    pub live_funding_epoch_count: u64,
    pub mark_commitment_count: u64,
    pub accepted_mark_commitment_count: u64,
    pub liquidation_queue_count: u64,
    pub live_liquidation_queue_count: u64,
    pub keeper_auction_count: u64,
    pub live_keeper_auction_count: u64,
    pub low_fee_rebate_count: u64,
    pub spendable_rebate_count: u64,
    pub pq_attestation_count: u64,
    pub active_pq_attestation_count: u64,
    pub privacy_budget_count: u64,
    pub spendable_privacy_budget_count: u64,
    pub settlement_receipt_count: u64,
    pub public_record_count: u64,
    pub total_open_notional_upper_bound_units: u64,
    pub total_locked_margin_upper_bound_units: u64,
    pub aggregate_rebate_budget_units: u64,
    pub aggregate_remaining_rebate_units: u64,
    pub minimum_privacy_set_size: u64,
    pub minimum_pq_security_bits: u16,
}

impl PrivateDerivativesClearinghouseCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_derivatives_clearinghouse_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "market_count": self.market_count,
            "active_market_count": self.active_market_count,
            "margin_account_count": self.margin_account_count,
            "live_margin_account_count": self.live_margin_account_count,
            "position_count": self.position_count,
            "live_position_count": self.live_position_count,
            "short_position_count": self.short_position_count,
            "funding_epoch_count": self.funding_epoch_count,
            "live_funding_epoch_count": self.live_funding_epoch_count,
            "mark_commitment_count": self.mark_commitment_count,
            "accepted_mark_commitment_count": self.accepted_mark_commitment_count,
            "liquidation_queue_count": self.liquidation_queue_count,
            "live_liquidation_queue_count": self.live_liquidation_queue_count,
            "keeper_auction_count": self.keeper_auction_count,
            "live_keeper_auction_count": self.live_keeper_auction_count,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "spendable_rebate_count": self.spendable_rebate_count,
            "pq_attestation_count": self.pq_attestation_count,
            "active_pq_attestation_count": self.active_pq_attestation_count,
            "privacy_budget_count": self.privacy_budget_count,
            "spendable_privacy_budget_count": self.spendable_privacy_budget_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "public_record_count": self.public_record_count,
            "total_open_notional_upper_bound_units": self.total_open_notional_upper_bound_units,
            "total_locked_margin_upper_bound_units": self.total_locked_margin_upper_bound_units,
            "aggregate_rebate_budget_units": self.aggregate_rebate_budget_units,
            "aggregate_remaining_rebate_units": self.aggregate_remaining_rebate_units,
            "minimum_privacy_set_size": self.minimum_privacy_set_size,
            "minimum_pq_security_bits": self.minimum_pq_security_bits,
        })
    }

    pub fn root(&self) -> String {
        json_root(
            "PRIVATE-DERIVATIVES-CLEARINGHOUSE-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDerivativesClearinghouseRoots {
    pub config_root: String,
    pub market_root: String,
    pub margin_account_root: String,
    pub position_root: String,
    pub funding_epoch_root: String,
    pub mark_commitment_root: String,
    pub liquidation_queue_root: String,
    pub keeper_auction_root: String,
    pub low_fee_rebate_root: String,
    pub pq_attestation_root: String,
    pub privacy_budget_root: String,
    pub settlement_receipt_root: String,
    pub public_record_root: String,
    pub counters_root: String,
}

impl PrivateDerivativesClearinghouseRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_derivatives_clearinghouse_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "market_root": self.market_root,
            "margin_account_root": self.margin_account_root,
            "position_root": self.position_root,
            "funding_epoch_root": self.funding_epoch_root,
            "mark_commitment_root": self.mark_commitment_root,
            "liquidation_queue_root": self.liquidation_queue_root,
            "keeper_auction_root": self.keeper_auction_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_budget_root": self.privacy_budget_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_derivatives_clearinghouse_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDerivativesClearinghouseState {
    pub height: u64,
    pub nonce: u64,
    pub config: PrivateDerivativesClearinghouseConfig,
    pub markets: BTreeMap<String, DerivativesMarket>,
    pub margin_accounts: BTreeMap<String, ConfidentialMarginAccount>,
    pub positions: BTreeMap<String, ShieldedDerivativePosition>,
    pub funding_epochs: BTreeMap<String, FundingEpoch>,
    pub mark_commitments: BTreeMap<String, EncryptedMarkPriceCommitment>,
    pub liquidation_queue: BTreeMap<String, LiquidationQueueEntry>,
    pub keeper_auctions: BTreeMap<String, SealedKeeperAuction>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub pq_attestations: BTreeMap<String, PqRiskCommitteeAttestation>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetAccount>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl Default for PrivateDerivativesClearinghouseState {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateDerivativesClearinghouseState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: PrivateDerivativesClearinghouseConfig::default(),
            markets: BTreeMap::new(),
            margin_accounts: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_epochs: BTreeMap::new(),
            mark_commitments: BTreeMap::new(),
            liquidation_queue: BTreeMap::new(),
            keeper_auctions: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: PrivateDerivativesClearinghouseConfig,
    ) -> PrivateDerivativesClearinghouseResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> PrivateDerivativesClearinghouseResult<Self> {
        let mut state = Self::with_config(PrivateDerivativesClearinghouseConfig::devnet())?;
        state.set_height(PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_HEIGHT)?;

        let market = DerivativesMarket::new(
            "wXMR private derivatives clearinghouse devnet",
            DerivativesMarketKind::Perpetual,
            &state.config.base_asset_id,
            &state.config.quote_asset_id,
            &state.config.quote_asset_id,
            &state.config.default_oracle_feed_id,
            &state.config.default_low_fee_lane,
            state.config.initial_margin_bps,
            state.config.maintenance_margin_bps,
            state.config.liquidation_penalty_bps,
            state.config.max_leverage_bps,
            10_000_000_000_000,
            state.config.funding_epoch_blocks,
            state.height.saturating_sub(96),
            state.height.saturating_add(21_600),
            &json!({
                "mode": "devnet",
                "private_defi": "shielded perpetuals and option margins",
                "oracle": state.config.default_oracle_feed_id
            }),
        )?;
        let market_id = market.market_id.clone();
        state.insert_market(market)?;

        let option_market = DerivativesMarket::new(
            "wXMR confidential weekly calls devnet",
            DerivativesMarketKind::EuropeanOption,
            &state.config.base_asset_id,
            &state.config.quote_asset_id,
            &state.config.quote_asset_id,
            &state.config.default_oracle_feed_id,
            &state.config.default_low_fee_lane,
            3_000,
            1_500,
            state.config.liquidation_penalty_bps,
            20_000,
            2_000_000_000_000,
            state.config.funding_epoch_blocks,
            state.height.saturating_sub(72),
            state.height.saturating_add(7_200),
            &json!({
                "mode": "devnet",
                "exercise": "bucketed-european",
                "settlement": "private cash settled"
            }),
        )?;
        let option_market_id = option_market.market_id.clone();
        state.insert_market(option_market)?;

        let risk_attestation = PqRiskCommitteeAttestation::new(
            "devnet-derivatives-risk-committee",
            "market",
            &market_id,
            PqRiskDecision::Approve,
            state.config.min_pq_security_bits,
            &[
                "ml-dsa-derivatives-member-1".to_string(),
                "ml-dsa-derivatives-member-2".to_string(),
                "slh-dsa-derivatives-member-3".to_string(),
            ],
            2,
            &json!({
                "initial_margin_bps": state.config.initial_margin_bps,
                "maintenance_margin_bps": state.config.maintenance_margin_bps,
                "max_leverage_bps": state.config.max_leverage_bps,
                "feed": state.config.default_oracle_feed_id
            }),
            &json!({
                "threshold": "2-of-3",
                "scheme": state.config.pq_attestation_scheme
            }),
            state.height.saturating_sub(64),
            state
                .height
                .saturating_add(state.config.attestation_ttl_blocks),
            &json!({"purpose": "devnet launch envelope"}),
        )?;
        let risk_attestation_id = risk_attestation.attestation_id.clone();
        state.insert_pq_attestation(risk_attestation)?;

        let budget = PrivacyBudgetAccount::new(
            "devnet-alice-derivatives-owner",
            &market_id,
            &[
                "margin_health_bucket".to_string(),
                "position_notional_bucket".to_string(),
                "funding_epoch_participation".to_string(),
                "settlement_receipt".to_string(),
            ],
            16,
            13,
            state.config.min_privacy_set_size,
            1,
            &json!({
                "allowed": ["bucket", "root", "receipt_status"],
                "forbidden": ["exact_size", "exact_margin", "raw_owner_address"]
            }),
            state.height.saturating_sub(48),
            state
                .height
                .saturating_add(state.config.privacy_budget_ttl_blocks),
            &json!({"owner": "alice", "strategy": "private-perp-and-option-hedge"}),
        )?;
        let budget_id = budget.budget_id.clone();
        state.insert_privacy_budget(budget)?;

        let option_budget = PrivacyBudgetAccount::new(
            "devnet-bob-options-owner",
            &option_market_id,
            &[
                "option_moneyness_bucket".to_string(),
                "exercise_status".to_string(),
                "collateral_bucket".to_string(),
            ],
            10,
            8,
            state.config.min_privacy_set_size,
            1,
            &json!({
                "allowed": ["series_bucket", "exercise_receipt"],
                "forbidden": ["strike_exact", "premium_exact"]
            }),
            state.height.saturating_sub(42),
            state
                .height
                .saturating_add(state.config.privacy_budget_ttl_blocks),
            &json!({"owner": "bob", "strategy": "covered-call"}),
        )?;
        let option_budget_id = option_budget.budget_id.clone();
        state.insert_privacy_budget(option_budget)?;

        let margin_account = ConfidentialMarginAccount::new(
            "devnet-alice-derivatives-owner",
            &state.config.quote_asset_id,
            "alice-cross-margin-commitment-devnet",
            500_000_000,
            120_000_000,
            "healthy_200_300",
            &budget_id,
            state.config.min_privacy_set_size,
            state.config.min_pq_security_bits,
            &json!({
                "viewers": ["owner", "selective-auditor"],
                "session": "pq-view-key-root"
            }),
            &json!({
                "scheme": state.config.margin_commitment_scheme,
                "balance_bucket": "250m_500m",
                "locked_bucket": "100m_150m"
            }),
            state.height.saturating_sub(36),
            state
                .height
                .saturating_add(state.config.position_ttl_blocks),
            &json!({"role": "cross-margin", "fixture": "alice"}),
        )?;
        let margin_account_id = margin_account.account_id.clone();
        state.insert_margin_account(margin_account)?;

        let option_margin_account = ConfidentialMarginAccount::new(
            "devnet-bob-options-owner",
            &state.config.quote_asset_id,
            "bob-option-margin-commitment-devnet",
            220_000_000,
            40_000_000,
            "super_safe_300_500",
            &option_budget_id,
            state.config.min_privacy_set_size,
            state.config.min_pq_security_bits,
            &json!({
                "viewers": ["owner", "exercise-auditor"],
                "session": "pq-option-view-key-root"
            }),
            &json!({
                "scheme": state.config.margin_commitment_scheme,
                "balance_bucket": "200m_250m",
                "locked_bucket": "25m_50m"
            }),
            state.height.saturating_sub(34),
            state
                .height
                .saturating_add(state.config.position_ttl_blocks),
            &json!({"role": "option-margin", "fixture": "bob"}),
        )?;
        let option_margin_account_id = option_margin_account.account_id.clone();
        state.insert_margin_account(option_margin_account)?;

        let funding_epoch = FundingEpoch::new(
            &market_id,
            1,
            state
                .height
                .saturating_sub(state.config.funding_epoch_blocks),
            state.height,
            "premium-index-commitment-wxmr-devnet-001",
            18,
            &json!({
                "mark_root": "initial-mark-set",
                "oracle_feed": state.config.default_oracle_feed_id
            }),
            "net-funding-payment-commitment-devnet-001",
            &json!({
                "participants": "bucketed",
                "privacy_set_size": state.config.min_privacy_set_size
            }),
            &json!({"mode": "devnet", "funding": "positive-small"}),
        )?;
        let epoch_id = funding_epoch.epoch_id.clone();
        state.insert_funding_epoch(funding_epoch)?;

        let position = ShieldedDerivativePosition::new(
            &market_id,
            &margin_account_id,
            PositionInstrument::PerpLong,
            "small_25m_50m",
            40_000_000,
            10_000_000,
            "alice-perp-size-commitment-devnet",
            "alice-perp-entry-price-commitment-devnet",
            "alice-perp-payoff-commitment-devnet",
            state.height.saturating_add(7_200),
            &epoch_id,
            &budget_id,
            &json!({
                "order_nullifiers": ["alice-order-nullifier-1"],
                "matching": "sealed-batch"
            }),
            &json!({
                "scheme": state.config.position_commitment_scheme,
                "notional_bucket": "small",
                "direction": "long"
            }),
            state.height.saturating_sub(30),
            state
                .height
                .saturating_add(state.config.position_ttl_blocks),
            &json!({"fixture": "alice-long-perp", "strategy": "private directional"}),
        )?;
        let position_id = position.position_id.clone();
        state.insert_position(position)?;

        let option_position = ShieldedDerivativePosition::new(
            &option_market_id,
            &option_margin_account_id,
            PositionInstrument::CallShort,
            "covered_small_10m_25m",
            18_000_000,
            6_000_000,
            "bob-covered-call-size-commitment-devnet",
            "bob-covered-call-entry-price-commitment-devnet",
            "bob-covered-call-payoff-commitment-devnet",
            state.height.saturating_add(1_440),
            &epoch_id,
            &option_budget_id,
            &json!({
                "order_nullifiers": ["bob-option-order-nullifier-1"],
                "series": "weekly-call"
            }),
            &json!({
                "scheme": state.config.position_commitment_scheme,
                "strike_bucket": "170_180",
                "premium_bucket": "small"
            }),
            state.height.saturating_sub(28),
            state
                .height
                .saturating_add(state.config.position_ttl_blocks),
            &json!({"fixture": "bob-covered-call", "strategy": "private yield"}),
        )?;
        let option_position_id = option_position.position_id.clone();
        state.insert_position(option_position)?;

        let mark = EncryptedMarkPriceCommitment::new(
            &market_id,
            &epoch_id,
            &state.config.default_oracle_feed_id,
            &json!({
                "kem": state.config.mark_commitment_scheme,
                "ciphertext": "encrypted-wxmr-mark-price-devnet",
                "commitment": PRIVATE_DERIVATIVES_CLEARINGHOUSE_DEVNET_WXMR_PRICE
            }),
            "165_170",
            9_500,
            &json!({
                "sources": ["devnet-median-1", "devnet-median-2", "devnet-median-3"],
                "aggregation": "threshold-median"
            }),
            state.height.saturating_sub(4),
            state.height.saturating_add(state.config.mark_ttl_blocks),
            &json!({"fixture": "encrypted-mark", "visibility": "committee+settlement"}),
        )?;
        state.insert_mark_commitment(mark)?;

        let liquidation = LiquidationQueueEntry::new(
            &market_id,
            &margin_account_id,
            &position_id,
            "watch_maintenance_buffer",
            "watch_130_150",
            &json!({
                "ciphertext": "alice-liquidation-trigger-ciphertext",
                "condition": "maintenance-margin-watch",
                "oracle_bucket": "155_165"
            }),
            &json!({
                "keepers": ["devnet-keeper-set-root"],
                "eligibility": "bonded-pq-session"
            }),
            state.config.liquidation_penalty_bps,
            state.height.saturating_sub(2),
            state.height.saturating_add(2),
            state
                .height
                .saturating_add(state.config.liquidation_ttl_blocks),
            &json!({"fixture": "queued-but-not-executed"}),
        )?;
        let queue_id = liquidation.queue_id.clone();
        state.insert_liquidation_queue_entry(liquidation)?;

        let auction = SealedKeeperAuction::new(
            &queue_id,
            &market_id,
            &json!({
                "sealed_bids": ["keeper-bid-commitment-1", "keeper-bid-commitment-2"],
                "auction": "sealed-first-price-devnet"
            }),
            25_000,
            75,
            "pending-winner-commitment",
            state.height,
            state.height.saturating_add(6),
            state.height.saturating_add(state.config.auction_ttl_blocks),
            &json!({"fixture": "liquidation-keeper-auction"}),
        )?;
        state.insert_keeper_auction(auction)?;

        let rebate = LowFeeRebate::new(
            "devnet-foundation-derivatives-sponsor",
            &market_id,
            "devnet-alice-derivatives-owner",
            &state.config.default_low_fee_lane,
            "small_25m_50m",
            state.config.sponsored_max_fee_units,
            6_250,
            state.config.min_privacy_set_size,
            &json!({
                "scheme": state.config.rebate_scheme,
                "eligibility": "small-private-derivatives",
                "fee_cap": state.config.sponsored_max_fee_units
            }),
            state.height.saturating_sub(12),
            state.height.saturating_add(state.config.rebate_ttl_blocks),
            &json!({"campaign": "private-defi-low-fee-launch"}),
        )?;
        state.insert_low_fee_rebate(rebate)?;

        let receipt = SettlementReceipt::new(
            &market_id,
            &margin_account_id,
            &position_id,
            "funding_payment",
            "alice-funding-settlement-amount-commitment",
            "alice-funding-fee-commitment",
            &json!({
                "scheme": state.config.settlement_receipt_scheme,
                "epoch_id": epoch_id,
                "funding_rate_bps": 18,
                "result": "paid-small"
            }),
            &risk_attestation_id,
            &budget_id,
            state.height.saturating_sub(1),
            state.height,
            state.height.saturating_add(state.config.receipt_ttl_blocks),
            &json!({"fixture": "funding-settlement-receipt"}),
        )?;
        state.insert_settlement_receipt(receipt)?;

        let option_receipt = SettlementReceipt::new(
            &option_market_id,
            &option_margin_account_id,
            &option_position_id,
            "option_premium",
            "bob-option-premium-settlement-amount-commitment",
            "bob-option-fee-commitment",
            &json!({
                "scheme": state.config.settlement_receipt_scheme,
                "series": "weekly-call",
                "result": "premium-collected"
            }),
            &risk_attestation_id,
            &option_budget_id,
            state.height.saturating_sub(1),
            state.height,
            state.height.saturating_add(state.config.receipt_ttl_blocks),
            &json!({"fixture": "option-premium-receipt"}),
        )?;
        state.insert_settlement_receipt(option_receipt)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateDerivativesClearinghouseResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn next_nonce(&mut self) -> u64 {
        let nonce = self.nonce;
        self.nonce = self.nonce.saturating_add(1);
        nonce
    }

    pub fn insert_market(
        &mut self,
        market: DerivativesMarket,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        market.validate()?;
        if self.markets.contains_key(&market.market_id) {
            return Err(format!("market {} already exists", market.market_id));
        }
        self.add_public_record(
            PublicRecordKind::MarketListed,
            &market.market_id,
            &market.root(),
            &json!({"market_kind": market.kind.as_str(), "status": market.status.as_str()}),
            &json!({"source": "insert_market"}),
        )?;
        self.markets.insert(market.market_id.clone(), market);
        Ok(())
    }

    pub fn insert_margin_account(
        &mut self,
        account: ConfidentialMarginAccount,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        account.validate()?;
        if !self
            .privacy_budgets
            .contains_key(&account.privacy_budget_id)
        {
            return Err(format!(
                "margin account {} references missing privacy budget",
                account.account_id
            ));
        }
        if self.margin_accounts.contains_key(&account.account_id) {
            return Err(format!(
                "margin account {} already exists",
                account.account_id
            ));
        }
        self.add_public_record(
            PublicRecordKind::MarginAccountCommitted,
            &account.account_id,
            &account.root(),
            &json!({"status": account.status.as_str(), "health_bucket": account.health_bucket}),
            &json!({"source": "insert_margin_account"}),
        )?;
        self.margin_accounts
            .insert(account.account_id.clone(), account);
        Ok(())
    }

    pub fn insert_position(
        &mut self,
        position: ShieldedDerivativePosition,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        position.validate()?;
        if !self.markets.contains_key(&position.market_id) {
            return Err(format!(
                "position {} references missing market",
                position.position_id
            ));
        }
        if !self
            .margin_accounts
            .contains_key(&position.margin_account_id)
        {
            return Err(format!(
                "position {} references missing margin account",
                position.position_id
            ));
        }
        if !self.funding_epochs.contains_key(&position.funding_epoch_id) {
            return Err(format!(
                "position {} references missing funding epoch",
                position.position_id
            ));
        }
        if !self
            .privacy_budgets
            .contains_key(&position.privacy_budget_id)
        {
            return Err(format!(
                "position {} references missing privacy budget",
                position.position_id
            ));
        }
        if self.positions.contains_key(&position.position_id) {
            return Err(format!("position {} already exists", position.position_id));
        }
        self.add_public_record(
            PublicRecordKind::PositionCommitted,
            &position.position_id,
            &position.root(),
            &json!({
                "instrument": position.instrument.as_str(),
                "status": position.status.as_str(),
                "notional_bucket": position.notional_bucket
            }),
            &json!({"source": "insert_position"}),
        )?;
        self.positions
            .insert(position.position_id.clone(), position);
        Ok(())
    }

    pub fn insert_funding_epoch(
        &mut self,
        epoch: FundingEpoch,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        epoch.validate()?;
        if !self.markets.contains_key(&epoch.market_id) {
            return Err(format!(
                "funding epoch {} references missing market",
                epoch.epoch_id
            ));
        }
        if self.funding_epochs.contains_key(&epoch.epoch_id) {
            return Err(format!("funding epoch {} already exists", epoch.epoch_id));
        }
        self.add_public_record(
            PublicRecordKind::FundingEpochPosted,
            &epoch.epoch_id,
            &epoch.root(),
            &json!({"status": epoch.status.as_str(), "epoch_number": epoch.epoch_number}),
            &json!({"source": "insert_funding_epoch"}),
        )?;
        self.funding_epochs.insert(epoch.epoch_id.clone(), epoch);
        Ok(())
    }

    pub fn insert_mark_commitment(
        &mut self,
        mark: EncryptedMarkPriceCommitment,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        mark.validate()?;
        if !self.markets.contains_key(&mark.market_id) {
            return Err(format!("mark {} references missing market", mark.mark_id));
        }
        if !self.funding_epochs.contains_key(&mark.epoch_id) {
            return Err(format!(
                "mark {} references missing funding epoch",
                mark.mark_id
            ));
        }
        if self.mark_commitments.contains_key(&mark.mark_id) {
            return Err(format!("mark {} already exists", mark.mark_id));
        }
        self.add_public_record(
            PublicRecordKind::MarkCommitted,
            &mark.mark_id,
            &mark.root(),
            &json!({"status": mark.status.as_str(), "price_bucket": mark.price_bucket}),
            &json!({"source": "insert_mark_commitment"}),
        )?;
        self.mark_commitments.insert(mark.mark_id.clone(), mark);
        Ok(())
    }

    pub fn insert_liquidation_queue_entry(
        &mut self,
        entry: LiquidationQueueEntry,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        entry.validate()?;
        if !self.markets.contains_key(&entry.market_id) {
            return Err(format!(
                "queue {} references missing market",
                entry.queue_id
            ));
        }
        if !self.margin_accounts.contains_key(&entry.margin_account_id) {
            return Err(format!(
                "queue {} references missing margin account",
                entry.queue_id
            ));
        }
        if !self.positions.contains_key(&entry.position_id) {
            return Err(format!(
                "queue {} references missing position",
                entry.queue_id
            ));
        }
        if self.liquidation_queue.contains_key(&entry.queue_id) {
            return Err(format!("queue {} already exists", entry.queue_id));
        }
        self.add_public_record(
            PublicRecordKind::LiquidationQueued,
            &entry.queue_id,
            &entry.root(),
            &json!({
                "status": entry.status.as_str(),
                "priority_bucket": entry.priority_bucket,
                "health_bucket": entry.health_bucket
            }),
            &json!({"source": "insert_liquidation_queue_entry"}),
        )?;
        self.liquidation_queue.insert(entry.queue_id.clone(), entry);
        Ok(())
    }

    pub fn insert_keeper_auction(
        &mut self,
        auction: SealedKeeperAuction,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        auction.validate()?;
        if !self.markets.contains_key(&auction.market_id) {
            return Err(format!(
                "auction {} references missing market",
                auction.auction_id
            ));
        }
        if !self.liquidation_queue.contains_key(&auction.queue_id) {
            return Err(format!(
                "auction {} references missing queue",
                auction.auction_id
            ));
        }
        if self.keeper_auctions.contains_key(&auction.auction_id) {
            return Err(format!("auction {} already exists", auction.auction_id));
        }
        self.add_public_record(
            PublicRecordKind::KeeperAuctionPosted,
            &auction.auction_id,
            &auction.root(),
            &json!({"status": auction.status.as_str(), "max_fee_bps": auction.max_fee_bps}),
            &json!({"source": "insert_keeper_auction"}),
        )?;
        self.keeper_auctions
            .insert(auction.auction_id.clone(), auction);
        Ok(())
    }

    pub fn insert_low_fee_rebate(
        &mut self,
        rebate: LowFeeRebate,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        rebate.validate()?;
        if !self.markets.contains_key(&rebate.market_id) {
            return Err(format!(
                "rebate {} references missing market",
                rebate.rebate_id
            ));
        }
        if rebate.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "rebate {} below privacy set floor",
                rebate.rebate_id
            ));
        }
        if self.low_fee_rebates.contains_key(&rebate.rebate_id) {
            return Err(format!("rebate {} already exists", rebate.rebate_id));
        }
        self.add_public_record(
            PublicRecordKind::RebatePosted,
            &rebate.rebate_id,
            &rebate.root(),
            &json!({"status": rebate.status.as_str(), "lane": rebate.low_fee_lane}),
            &json!({"source": "insert_low_fee_rebate"}),
        )?;
        self.low_fee_rebates
            .insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqRiskCommitteeAttestation,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        attestation.validate()?;
        if attestation.pq_security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "attestation {} below configured pq floor",
                attestation.attestation_id
            ));
        }
        if self
            .pq_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err(format!(
                "attestation {} already exists",
                attestation.attestation_id
            ));
        }
        self.add_public_record(
            PublicRecordKind::PqAttestationPosted,
            &attestation.attestation_id,
            &attestation.root(),
            &json!({
                "decision": attestation.decision.as_str(),
                "subject_kind": attestation.subject_kind
            }),
            &json!({"source": "insert_pq_attestation"}),
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn insert_privacy_budget(
        &mut self,
        budget: PrivacyBudgetAccount,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        budget.validate()?;
        if !self.markets.contains_key(&budget.market_id) {
            return Err(format!(
                "privacy budget {} references missing market",
                budget.budget_id
            ));
        }
        if budget.min_anonymity_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "privacy budget {} below anonymity floor",
                budget.budget_id
            ));
        }
        if self.privacy_budgets.contains_key(&budget.budget_id) {
            return Err(format!(
                "privacy budget {} already exists",
                budget.budget_id
            ));
        }
        self.add_public_record(
            PublicRecordKind::PrivacyBudgetPosted,
            &budget.budget_id,
            &budget.root(),
            &json!({
                "status": budget.status.as_str(),
                "labels": budget.disclosure_labels
            }),
            &json!({"source": "insert_privacy_budget"}),
        )?;
        self.privacy_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn insert_settlement_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        receipt.validate()?;
        if !self.markets.contains_key(&receipt.market_id) {
            return Err(format!(
                "receipt {} references missing market",
                receipt.receipt_id
            ));
        }
        if !self
            .margin_accounts
            .contains_key(&receipt.margin_account_id)
        {
            return Err(format!(
                "receipt {} references missing margin account",
                receipt.receipt_id
            ));
        }
        if !self.positions.contains_key(&receipt.position_id) {
            return Err(format!(
                "receipt {} references missing position",
                receipt.receipt_id
            ));
        }
        if !self
            .pq_attestations
            .contains_key(&receipt.pq_attestation_id)
        {
            return Err(format!(
                "receipt {} references missing pq attestation",
                receipt.receipt_id
            ));
        }
        if !self
            .privacy_budgets
            .contains_key(&receipt.privacy_budget_id)
        {
            return Err(format!(
                "receipt {} references missing privacy budget",
                receipt.receipt_id
            ));
        }
        if self.settlement_receipts.contains_key(&receipt.receipt_id) {
            return Err(format!("receipt {} already exists", receipt.receipt_id));
        }
        self.add_public_record(
            PublicRecordKind::SettlementReceiptPosted,
            &receipt.receipt_id,
            &receipt.root(),
            &json!({
                "status": receipt.status.as_str(),
                "settlement_kind": receipt.settlement_kind
            }),
            &json!({"source": "insert_settlement_receipt"}),
        )?;
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    fn add_public_record(
        &mut self,
        record_kind: PublicRecordKind,
        subject_id: &str,
        subject_root: &str,
        disclosure_payload: &Value,
        metadata: &Value,
    ) -> PrivateDerivativesClearinghouseResult<()> {
        let sequence = self.next_nonce();
        let record = DeterministicPublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            self.height,
            sequence,
            disclosure_payload,
            metadata,
        )?;
        self.public_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    pub fn roots(&self) -> PrivateDerivativesClearinghouseRoots {
        let market_records = self
            .markets
            .values()
            .map(DerivativesMarket::public_record)
            .collect::<Vec<_>>();
        let margin_account_records = self
            .margin_accounts
            .values()
            .map(ConfidentialMarginAccount::public_record)
            .collect::<Vec<_>>();
        let position_records = self
            .positions
            .values()
            .map(ShieldedDerivativePosition::public_record)
            .collect::<Vec<_>>();
        let funding_epoch_records = self
            .funding_epochs
            .values()
            .map(FundingEpoch::public_record)
            .collect::<Vec<_>>();
        let mark_records = self
            .mark_commitments
            .values()
            .map(EncryptedMarkPriceCommitment::public_record)
            .collect::<Vec<_>>();
        let liquidation_records = self
            .liquidation_queue
            .values()
            .map(LiquidationQueueEntry::public_record)
            .collect::<Vec<_>>();
        let auction_records = self
            .keeper_auctions
            .values()
            .map(SealedKeeperAuction::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .low_fee_rebates
            .values()
            .map(LowFeeRebate::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .pq_attestations
            .values()
            .map(PqRiskCommitteeAttestation::public_record)
            .collect::<Vec<_>>();
        let budget_records = self
            .privacy_budgets
            .values()
            .map(PrivacyBudgetAccount::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .settlement_receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let public_records = self
            .public_records
            .values()
            .map(DeterministicPublicRecord::public_record)
            .collect::<Vec<_>>();
        let counters = self.counters();

        PrivateDerivativesClearinghouseRoots {
            config_root: self.config.root(),
            market_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-MARKETS",
                &market_records,
            ),
            margin_account_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-MARGIN-ACCOUNTS",
                &margin_account_records,
            ),
            position_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-POSITIONS",
                &position_records,
            ),
            funding_epoch_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-FUNDING-EPOCHS",
                &funding_epoch_records,
            ),
            mark_commitment_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-MARK-COMMITMENTS",
                &mark_records,
            ),
            liquidation_queue_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-LIQUIDATION-QUEUE",
                &liquidation_records,
            ),
            keeper_auction_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-KEEPER-AUCTIONS",
                &auction_records,
            ),
            low_fee_rebate_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-LOW-FEE-REBATES",
                &rebate_records,
            ),
            pq_attestation_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-PQ-ATTESTATIONS",
                &attestation_records,
            ),
            privacy_budget_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-PRIVACY-BUDGETS",
                &budget_records,
            ),
            settlement_receipt_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-SETTLEMENT-RECEIPTS",
                &receipt_records,
            ),
            public_record_root: clearinghouse_collection_root(
                "PRIVATE-DERIVATIVES-CLEARINGHOUSE-PUBLIC-RECORDS",
                &public_records,
            ),
            counters_root: counters.root(),
        }
    }

    pub fn counters(&self) -> PrivateDerivativesClearinghouseCounters {
        let market_count = self.markets.len() as u64;
        let active_market_count = self
            .markets
            .values()
            .filter(|market| market.status.accepts_new_positions())
            .count() as u64;
        let margin_account_count = self.margin_accounts.len() as u64;
        let live_margin_account_count = self
            .margin_accounts
            .values()
            .filter(|account| account.status.live())
            .count() as u64;
        let position_count = self.positions.len() as u64;
        let live_position_count = self
            .positions
            .values()
            .filter(|position| position.status.live())
            .count() as u64;
        let short_position_count = self
            .positions
            .values()
            .filter(|position| position.instrument.is_short())
            .count() as u64;
        let funding_epoch_count = self.funding_epochs.len() as u64;
        let live_funding_epoch_count = self
            .funding_epochs
            .values()
            .filter(|epoch| epoch.status.live())
            .count() as u64;
        let mark_commitment_count = self.mark_commitments.len() as u64;
        let accepted_mark_commitment_count = self
            .mark_commitments
            .values()
            .filter(|mark| mark.status == MarkCommitmentStatus::Accepted)
            .count() as u64;
        let liquidation_queue_count = self.liquidation_queue.len() as u64;
        let live_liquidation_queue_count = self
            .liquidation_queue
            .values()
            .filter(|entry| entry.status.live())
            .count() as u64;
        let keeper_auction_count = self.keeper_auctions.len() as u64;
        let live_keeper_auction_count = self
            .keeper_auctions
            .values()
            .filter(|auction| auction.status.live())
            .count() as u64;
        let low_fee_rebate_count = self.low_fee_rebates.len() as u64;
        let spendable_rebate_count = self
            .low_fee_rebates
            .values()
            .filter(|rebate| rebate.status.spendable())
            .count() as u64;
        let pq_attestation_count = self.pq_attestations.len() as u64;
        let active_pq_attestation_count = self
            .pq_attestations
            .values()
            .filter(|attestation| {
                attestation.decision.permits_risk() && attestation.expires_at_height >= self.height
            })
            .count() as u64;
        let privacy_budget_count = self.privacy_budgets.len() as u64;
        let spendable_privacy_budget_count = self
            .privacy_budgets
            .values()
            .filter(|budget| budget.status.spendable() && budget.remaining_budget_units > 0)
            .count() as u64;
        let settlement_receipt_count = self.settlement_receipts.len() as u64;
        let public_record_count = self.public_records.len() as u64;
        let total_open_notional_upper_bound_units = self
            .positions
            .values()
            .filter(|position| position.status.live())
            .map(|position| position.notional_upper_bound_units)
            .fold(0_u64, u64::saturating_add);
        let total_locked_margin_upper_bound_units = self
            .margin_accounts
            .values()
            .map(|account| account.locked_margin_upper_bound_units)
            .fold(0_u64, u64::saturating_add);
        let aggregate_rebate_budget_units = self
            .low_fee_rebates
            .values()
            .map(|rebate| rebate.max_fee_units)
            .fold(0_u64, u64::saturating_add);
        let aggregate_remaining_rebate_units = self
            .low_fee_rebates
            .values()
            .map(|rebate| rebate.remaining_fee_units)
            .fold(0_u64, u64::saturating_add);
        let minimum_privacy_set_size = match self
            .privacy_budgets
            .values()
            .map(|budget| budget.min_anonymity_set_size)
            .min()
        {
            Some(value) => value,
            None => self.config.min_privacy_set_size,
        };
        let minimum_pq_security_bits = match self
            .pq_attestations
            .values()
            .map(|attestation| attestation.pq_security_bits)
            .min()
        {
            Some(value) => value,
            None => self.config.min_pq_security_bits,
        };

        PrivateDerivativesClearinghouseCounters {
            market_count,
            active_market_count,
            margin_account_count,
            live_margin_account_count,
            position_count,
            live_position_count,
            short_position_count,
            funding_epoch_count,
            live_funding_epoch_count,
            mark_commitment_count,
            accepted_mark_commitment_count,
            liquidation_queue_count,
            live_liquidation_queue_count,
            keeper_auction_count,
            live_keeper_auction_count,
            low_fee_rebate_count,
            spendable_rebate_count,
            pq_attestation_count,
            active_pq_attestation_count,
            privacy_budget_count,
            spendable_privacy_budget_count,
            settlement_receipt_count,
            public_record_count,
            total_open_notional_upper_bound_units,
            total_locked_margin_upper_bound_units,
            aggregate_rebate_budget_units,
            aggregate_remaining_rebate_units,
            minimum_privacy_set_size,
            minimum_pq_security_bits,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_derivatives_clearinghouse_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_derivatives_clearinghouse_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateDerivativesClearinghouseResult<()> {
        self.config.validate()?;
        if self.markets.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_MARKETS {
            return Err("too many markets".to_string());
        }
        if self.margin_accounts.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_MARGIN_ACCOUNTS {
            return Err("too many margin accounts".to_string());
        }
        if self.positions.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_POSITIONS {
            return Err("too many positions".to_string());
        }
        if self.mark_commitments.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_MARKS {
            return Err("too many mark commitments".to_string());
        }
        if self.liquidation_queue.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_LIQUIDATIONS {
            return Err("too many liquidation queue entries".to_string());
        }
        if self.keeper_auctions.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_AUCTIONS {
            return Err("too many keeper auctions".to_string());
        }
        if self.public_records.len() > PRIVATE_DERIVATIVES_CLEARINGHOUSE_MAX_PUBLIC_RECORDS {
            return Err("too many public records".to_string());
        }

        for market in self.markets.values() {
            market.validate()?;
        }
        for budget in self.privacy_budgets.values() {
            budget.validate()?;
            if !self.markets.contains_key(&budget.market_id) {
                return Err(format!(
                    "privacy budget {} references missing market",
                    budget.budget_id
                ));
            }
            if budget.min_anonymity_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "privacy budget {} below configured anonymity floor",
                    budget.budget_id
                ));
            }
        }
        for account in self.margin_accounts.values() {
            account.validate()?;
            if !self
                .privacy_budgets
                .contains_key(&account.privacy_budget_id)
            {
                return Err(format!(
                    "account {} references missing privacy budget",
                    account.account_id
                ));
            }
            if account.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "account {} below configured privacy set floor",
                    account.account_id
                ));
            }
            if account.pq_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "account {} below configured pq floor",
                    account.account_id
                ));
            }
        }
        for epoch in self.funding_epochs.values() {
            epoch.validate()?;
            if !self.markets.contains_key(&epoch.market_id) {
                return Err(format!(
                    "funding epoch {} references missing market",
                    epoch.epoch_id
                ));
            }
        }
        for position in self.positions.values() {
            position.validate()?;
            if !self.markets.contains_key(&position.market_id) {
                return Err(format!(
                    "position {} references missing market",
                    position.position_id
                ));
            }
            if !self
                .margin_accounts
                .contains_key(&position.margin_account_id)
            {
                return Err(format!(
                    "position {} references missing margin account",
                    position.position_id
                ));
            }
            if !self.funding_epochs.contains_key(&position.funding_epoch_id) {
                return Err(format!(
                    "position {} references missing funding epoch",
                    position.position_id
                ));
            }
            if !self
                .privacy_budgets
                .contains_key(&position.privacy_budget_id)
            {
                return Err(format!(
                    "position {} references missing privacy budget",
                    position.position_id
                ));
            }
        }
        for mark in self.mark_commitments.values() {
            mark.validate()?;
            if !self.markets.contains_key(&mark.market_id) {
                return Err(format!("mark {} references missing market", mark.mark_id));
            }
            if !self.funding_epochs.contains_key(&mark.epoch_id) {
                return Err(format!(
                    "mark {} references missing funding epoch",
                    mark.mark_id
                ));
            }
        }
        for entry in self.liquidation_queue.values() {
            entry.validate()?;
            if !self.markets.contains_key(&entry.market_id) {
                return Err(format!(
                    "queue {} references missing market",
                    entry.queue_id
                ));
            }
            if !self.margin_accounts.contains_key(&entry.margin_account_id) {
                return Err(format!(
                    "queue {} references missing margin account",
                    entry.queue_id
                ));
            }
            if !self.positions.contains_key(&entry.position_id) {
                return Err(format!(
                    "queue {} references missing position",
                    entry.queue_id
                ));
            }
        }
        for auction in self.keeper_auctions.values() {
            auction.validate()?;
            if !self.markets.contains_key(&auction.market_id) {
                return Err(format!(
                    "auction {} references missing market",
                    auction.auction_id
                ));
            }
            if !self.liquidation_queue.contains_key(&auction.queue_id) {
                return Err(format!(
                    "auction {} references missing queue",
                    auction.auction_id
                ));
            }
        }
        for rebate in self.low_fee_rebates.values() {
            rebate.validate()?;
            if !self.markets.contains_key(&rebate.market_id) {
                return Err(format!(
                    "rebate {} references missing market",
                    rebate.rebate_id
                ));
            }
            if rebate.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "rebate {} below configured privacy set floor",
                    rebate.rebate_id
                ));
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            if attestation.pq_security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "attestation {} below configured pq floor",
                    attestation.attestation_id
                ));
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.markets.contains_key(&receipt.market_id) {
                return Err(format!(
                    "receipt {} references missing market",
                    receipt.receipt_id
                ));
            }
            if !self
                .margin_accounts
                .contains_key(&receipt.margin_account_id)
            {
                return Err(format!(
                    "receipt {} references missing margin account",
                    receipt.receipt_id
                ));
            }
            if !self.positions.contains_key(&receipt.position_id) {
                return Err(format!(
                    "receipt {} references missing position",
                    receipt.receipt_id
                ));
            }
            if !self
                .pq_attestations
                .contains_key(&receipt.pq_attestation_id)
            {
                return Err(format!(
                    "receipt {} references missing pq attestation",
                    receipt.receipt_id
                ));
            }
            if !self
                .privacy_budgets
                .contains_key(&receipt.privacy_budget_id)
            {
                return Err(format!(
                    "receipt {} references missing privacy budget",
                    receipt.receipt_id
                ));
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(())
    }
}

pub fn private_derivatives_clearinghouse_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-DERIVATIVES-CLEARINGHOUSE-STATE-ROOT",
        &[
            HashPart::Str(PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

#[allow(dead_code)]
fn _private_derivatives_clearinghouse_domain_separator() -> String {
    clearinghouse_string_root(
        "PRIVATE-DERIVATIVES-CLEARINGHOUSE-DOMAIN-SEPARATOR",
        PRIVATE_DERIVATIVES_CLEARINGHOUSE_PROTOCOL_VERSION,
    )
}
