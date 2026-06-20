use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePrivateLiquidityRouteCacheRuntimeResult<T> = Result<T>;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-private-liquidity-route-cache-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROUTE_HINT_SCHEME: &str = "roots-only-private-liquidity-route-hint-v1";
pub const ENCRYPTED_QUOTE_SCHEME: &str = "ml-kem-1024+zk-encrypted-route-quote-v1";
pub const SPONSOR_RESERVATION_SCHEME: &str = "low-fee-private-route-sponsor-reservation-v1";
pub const CACHE_LEASE_SCHEME: &str = "private-route-cache-lease-nullifier-v1";
pub const REFRESH_RECEIPT_SCHEME: &str = "batched-private-route-refresh-receipt-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "route-intent-nullifier-fence-v1";
pub const STALE_SLASHING_SCHEME: &str = "stale-private-route-cache-slashing-v1";
pub const REBATE_SCHEME: &str = "low-fee-private-route-cache-rebate-v1";
pub const DEVNET_HEIGHT: u64 = 539_000;
pub const DEFAULT_ROUTE_HINT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_CACHE_LEASE_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_REFRESH_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_SLASH_GRACE_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_ROUTE_HINTS: usize = 1_048_576;
pub const DEFAULT_MAX_QUOTES: usize = 2_097_152;
pub const DEFAULT_MAX_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_BATCH_REFRESHES: usize = 16_384;
pub const DEFAULT_MAX_SPONSOR_RESERVATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 768;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_MAX_ROUTE_FEE_BPS: u64 = 20;
pub const DEFAULT_MIN_REBATE_BPS: u64 = 3;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 14;
pub const DEFAULT_MIN_ROUTE_HEALTH_BPS: u64 = 7_200;
pub const DEFAULT_MAX_STALENESS_BPS: u64 = 650;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 240_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteVenueKind {
    ConfidentialAmm,
    PrivateRfq,
    LendingPool,
    BridgeExit,
    PaymentChannel,
    Darkpool,
    InternalNetting,
    SolverInventory,
}

impl RouteVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAmm => "confidential_amm",
            Self::PrivateRfq => "private_rfq",
            Self::LendingPool => "lending_pool",
            Self::BridgeExit => "bridge_exit",
            Self::PaymentChannel => "payment_channel",
            Self::Darkpool => "darkpool",
            Self::InternalNetting => "internal_netting",
            Self::SolverInventory => "solver_inventory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntentKind {
    SwapExactIn,
    SwapExactOut,
    RfqFill,
    LendingBorrow,
    LendingRepay,
    BridgeExit,
    ChannelPay,
    ChannelRebalance,
    CollateralMove,
    ArbitrageNetting,
}

impl RouteIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::RfqFill => "rfq_fill",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::BridgeExit => "bridge_exit",
            Self::ChannelPay => "channel_pay",
            Self::ChannelRebalance => "channel_rebalance",
            Self::CollateralMove => "collateral_move",
            Self::ArbitrageNetting => "arbitrage_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteHintStatus {
    Advertised,
    Quoted,
    Leased,
    Refreshing,
    Settled,
    Stale,
    Slashed,
    Expired,
}

impl RouteHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Quoted => "quoted",
            Self::Leased => "leased",
            Self::Refreshing => "refreshing",
            Self::Settled => "settled",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn quotable(self) -> bool {
        matches!(self, Self::Advertised | Self::Quoted | Self::Refreshing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Reserved,
    Leased,
    Refreshed,
    Consumed,
    Stale,
    Slashed,
    Expired,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Reserved => "reserved",
            Self::Leased => "leased",
            Self::Refreshed => "refreshed",
            Self::Consumed => "consumed",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn reservable(self) -> bool {
        matches!(self, Self::Posted | Self::Refreshed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Bound,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Extended,
    Consumed,
    Revoked,
    Expired,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Extended => "extended",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshStatus {
    Built,
    Accepted,
    Finalized,
    Rejected,
    Disputed,
}

impl RefreshStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Bound,
    Spent,
    Burned,
    Expired,
}

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bound => "bound",
            Self::Spent => "spent",
            Self::Burned => "burned",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashStatus {
    Filed,
    Proven,
    Applied,
    Rejected,
}

impl SlashStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::Proven => "proven",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Claimable,
    Reserved,
    Paid,
    Forfeited,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claimable => "claimable",
            Self::Reserved => "reserved",
            Self::Paid => "paid",
            Self::Forfeited => "forfeited",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub route_hint_scheme: String,
    pub encrypted_quote_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub cache_lease_scheme: String,
    pub refresh_receipt_scheme: String,
    pub privacy_fence_scheme: String,
    pub stale_slashing_scheme: String,
    pub rebate_scheme: String,
    pub route_hint_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub cache_lease_ttl_blocks: u64,
    pub refresh_window_blocks: u64,
    pub slash_grace_blocks: u64,
    pub max_route_hints: usize,
    pub max_quotes: usize,
    pub max_leases: usize,
    pub max_batch_refreshes: usize,
    pub max_sponsor_reservations: usize,
    pub max_privacy_fences: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_route_fee_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_route_health_bps: u64,
    pub max_staleness_bps: u64,
    pub sponsor_budget_micro_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            route_hint_scheme: ROUTE_HINT_SCHEME.to_string(),
            encrypted_quote_scheme: ENCRYPTED_QUOTE_SCHEME.to_string(),
            sponsor_reservation_scheme: SPONSOR_RESERVATION_SCHEME.to_string(),
            cache_lease_scheme: CACHE_LEASE_SCHEME.to_string(),
            refresh_receipt_scheme: REFRESH_RECEIPT_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            stale_slashing_scheme: STALE_SLASHING_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            route_hint_ttl_blocks: DEFAULT_ROUTE_HINT_TTL_BLOCKS,
            quote_ttl_blocks: DEFAULT_QUOTE_TTL_BLOCKS,
            cache_lease_ttl_blocks: DEFAULT_CACHE_LEASE_TTL_BLOCKS,
            refresh_window_blocks: DEFAULT_REFRESH_WINDOW_BLOCKS,
            slash_grace_blocks: DEFAULT_SLASH_GRACE_BLOCKS,
            max_route_hints: DEFAULT_MAX_ROUTE_HINTS,
            max_quotes: DEFAULT_MAX_QUOTES,
            max_leases: DEFAULT_MAX_LEASES,
            max_batch_refreshes: DEFAULT_MAX_BATCH_REFRESHES,
            max_sponsor_reservations: DEFAULT_MAX_SPONSOR_RESERVATIONS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_route_fee_bps: DEFAULT_MAX_ROUTE_FEE_BPS,
            min_rebate_bps: DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_route_health_bps: DEFAULT_MIN_ROUTE_HEALTH_BPS,
            max_staleness_bps: DEFAULT_MAX_STALENESS_BPS,
            sponsor_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_route_fee_bps", self.max_route_fee_bps)?;
        ensure_bps("min_rebate_bps", self.min_rebate_bps)?;
        ensure_bps("max_rebate_bps", self.max_rebate_bps)?;
        ensure_bps("min_route_health_bps", self.min_route_health_bps)?;
        ensure_bps("max_staleness_bps", self.max_staleness_bps)?;
        if self.min_rebate_bps > self.max_rebate_bps {
            return Err("min_rebate_bps exceeds max_rebate_bps".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("min_privacy_set_size must be non-zero".to_string());
        }
        if self.min_batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set below route privacy set".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub route_hints: u64,
    pub encrypted_quotes: u64,
    pub sponsor_reservations: u64,
    pub cache_leases: u64,
    pub refresh_receipts: u64,
    pub privacy_fences: u64,
    pub stale_slashes: u64,
    pub rebates: u64,
    pub consumed_quotes: u64,
    pub spent_nullifiers: u64,
    pub expired_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub route_hint_root: String,
    pub encrypted_quote_root: String,
    pub sponsor_reservation_root: String,
    pub cache_lease_root: String,
    pub refresh_receipt_root: String,
    pub privacy_fence_root: String,
    pub stale_slashing_root: String,
    pub rebate_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteHintRecord {
    pub route_hint_id: String,
    pub owner_commitment: String,
    pub venue_kind: RouteVenueKind,
    pub intent_kind: RouteIntentKind,
    pub asset_pair_root: String,
    pub route_commitment_root: String,
    pub liquidity_bucket_root: String,
    pub fee_hint_bps: u64,
    pub latency_hint_ms: u64,
    pub route_health_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: RouteHintStatus,
    pub metadata_root: String,
}

impl RouteHintRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "route_hint_id": self.route_hint_id,
            "owner_commitment": self.owner_commitment,
            "venue_kind": self.venue_kind.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "asset_pair_root": self.asset_pair_root,
            "route_commitment_root": self.route_commitment_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "fee_hint_bps": self.fee_hint_bps,
            "latency_hint_ms": self.latency_hint_ms,
            "route_health_bps": self.route_health_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedQuoteRecord {
    pub quote_id: String,
    pub route_hint_id: String,
    pub maker_commitment: String,
    pub quote_ciphertext_root: String,
    pub quote_nullifier_root: String,
    pub max_user_fee_bps: u64,
    pub route_fee_bps: u64,
    pub expected_rebate_bps: u64,
    pub liquidity_score_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuoteStatus,
}

impl EncryptedQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "route_hint_id": self.route_hint_id,
            "maker_commitment": self.maker_commitment,
            "quote_ciphertext_root": self.quote_ciphertext_root,
            "quote_nullifier_root": self.quote_nullifier_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "route_fee_bps": self.route_fee_bps,
            "expected_rebate_bps": self.expected_rebate_bps,
            "liquidity_score_bps": self.liquidity_score_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub quote_id: String,
    pub sponsor_commitment: String,
    pub budget_micro_units: u64,
    pub reserved_fee_bps: u64,
    pub rebate_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: ReservationStatus,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "quote_id": self.quote_id,
            "sponsor_commitment": self.sponsor_commitment,
            "budget_micro_units": self.budget_micro_units,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_bps": self.rebate_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheLeaseRecord {
    pub lease_id: String,
    pub quote_id: String,
    pub lessee_commitment: String,
    pub lease_nullifier: String,
    pub lease_weight: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: LeaseStatus,
}

impl CacheLeaseRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "quote_id": self.quote_id,
            "lessee_commitment": self.lessee_commitment,
            "lease_nullifier": self.lease_nullifier,
            "lease_weight": self.lease_weight,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchRefreshReceiptRecord {
    pub refresh_id: String,
    pub coordinator_commitment: String,
    pub route_hint_root_before: String,
    pub route_hint_root_after: String,
    pub quote_root_before: String,
    pub quote_root_after: String,
    pub refreshed_quote_count: u64,
    pub privacy_set_size: u64,
    pub fee_savings_bps: u64,
    pub created_at_height: u64,
    pub status: RefreshStatus,
}

impl BatchRefreshReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "refresh_id": self.refresh_id,
            "coordinator_commitment": self.coordinator_commitment,
            "route_hint_root_before": self.route_hint_root_before,
            "route_hint_root_after": self.route_hint_root_after,
            "quote_root_before": self.quote_root_before,
            "quote_root_after": self.quote_root_after,
            "refreshed_quote_count": self.refreshed_quote_count,
            "privacy_set_size": self.privacy_set_size,
            "fee_savings_bps": self.fee_savings_bps,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub route_hint_id: String,
    pub quote_id: String,
    pub intent_nullifier: String,
    pub fence_root: String,
    pub opened_at_height: u64,
    pub status: FenceStatus,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "route_hint_id": self.route_hint_id,
            "quote_id": self.quote_id,
            "intent_nullifier": self.intent_nullifier,
            "fence_root": self.fence_root,
            "opened_at_height": self.opened_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StaleRouteSlashingRecord {
    pub slash_id: String,
    pub route_hint_id: String,
    pub quote_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub stale_by_blocks: u64,
    pub slash_amount_micro_units: u64,
    pub created_at_height: u64,
    pub status: SlashStatus,
}

impl StaleRouteSlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "route_hint_id": self.route_hint_id,
            "quote_id": self.quote_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "stale_by_blocks": self.stale_by_blocks,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateRecord {
    pub rebate_id: String,
    pub reservation_id: String,
    pub quote_id: String,
    pub claimant_commitment: String,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub created_at_height: u64,
    pub status: RebateStatus,
}

impl RebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.reservation_id,
            "quote_id": self.quote_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_bps": self.rebate_bps,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvertiseRouteHintRequest {
    pub owner_commitment: String,
    pub venue_kind: RouteVenueKind,
    pub intent_kind: RouteIntentKind,
    pub asset_pair_root: String,
    pub route_commitment_root: String,
    pub liquidity_bucket_root: String,
    pub fee_hint_bps: u64,
    pub latency_hint_ms: u64,
    pub route_health_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub ttl_blocks: u64,
    pub metadata_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostEncryptedQuoteRequest {
    pub route_hint_id: String,
    pub maker_commitment: String,
    pub quote_ciphertext_root: String,
    pub quote_nullifier_root: String,
    pub max_user_fee_bps: u64,
    pub route_fee_bps: u64,
    pub expected_rebate_bps: u64,
    pub liquidity_score_bps: u64,
    pub ttl_blocks: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveSponsorRequest {
    pub quote_id: String,
    pub sponsor_commitment: String,
    pub budget_micro_units: u64,
    pub reserved_fee_bps: u64,
    pub rebate_bps: u64,
    pub ttl_blocks: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseCacheRequest {
    pub quote_id: String,
    pub lessee_commitment: String,
    pub lease_nullifier: String,
    pub lease_weight: u64,
    pub ttl_blocks: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchRefreshRequest {
    pub coordinator_commitment: String,
    pub quote_ids: Vec<String>,
    pub route_hint_root_after: String,
    pub quote_root_after: String,
    pub privacy_set_size: u64,
    pub fee_savings_bps: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenPrivacyFenceRequest {
    pub route_hint_id: String,
    pub quote_id: String,
    pub intent_nullifier: String,
    pub fence_root: String,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashStaleRouteRequest {
    pub route_hint_id: String,
    pub quote_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub stale_by_blocks: u64,
    pub slash_amount_micro_units: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRebateRequest {
    pub reservation_id: String,
    pub quote_id: String,
    pub claimant_commitment: String,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub route_hints: BTreeMap<String, RouteHintRecord>,
    pub encrypted_quotes: BTreeMap<String, EncryptedQuoteRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub cache_leases: BTreeMap<String, CacheLeaseRecord>,
    pub refresh_receipts: BTreeMap<String, BatchRefreshReceiptRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub stale_slashes: BTreeMap<String, StaleRouteSlashingRecord>,
    pub rebates: BTreeMap<String, RebateRecord>,
    pub spent_nullifiers: BTreeSet<String>,
    pub consumed_quote_ids: BTreeSet<String>,
    pub current_height: u64,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            route_hints: BTreeMap::new(),
            encrypted_quotes: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            refresh_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            stale_slashes: BTreeMap::new(),
            rebates: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            consumed_quote_ids: BTreeSet::new(),
            current_height,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            route_hints: self.route_hints.len() as u64,
            encrypted_quotes: self.encrypted_quotes.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            cache_leases: self.cache_leases.len() as u64,
            refresh_receipts: self.refresh_receipts.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            stale_slashes: self.stale_slashes.len() as u64,
            rebates: self.rebates.len() as u64,
            consumed_quotes: self.consumed_quote_ids.len() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            expired_records: self.expired_route_hint_count() + self.expired_quote_count(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: public_record_root(&self.config.public_record()),
            route_hint_root: root_from_records(
                "route_hints",
                self.route_hints
                    .values()
                    .map(RouteHintRecord::public_record)
                    .collect(),
            ),
            encrypted_quote_root: root_from_records(
                "encrypted_quotes",
                self.encrypted_quotes
                    .values()
                    .map(EncryptedQuoteRecord::public_record)
                    .collect(),
            ),
            sponsor_reservation_root: root_from_records(
                "sponsor_reservations",
                self.sponsor_reservations
                    .values()
                    .map(SponsorReservationRecord::public_record)
                    .collect(),
            ),
            cache_lease_root: root_from_records(
                "cache_leases",
                self.cache_leases
                    .values()
                    .map(CacheLeaseRecord::public_record)
                    .collect(),
            ),
            refresh_receipt_root: root_from_records(
                "refresh_receipts",
                self.refresh_receipts
                    .values()
                    .map(BatchRefreshReceiptRecord::public_record)
                    .collect(),
            ),
            privacy_fence_root: root_from_records(
                "privacy_fences",
                self.privacy_fences
                    .values()
                    .map(PrivacyFenceRecord::public_record)
                    .collect(),
            ),
            stale_slashing_root: root_from_records(
                "stale_slashes",
                self.stale_slashes
                    .values()
                    .map(StaleRouteSlashingRecord::public_record)
                    .collect(),
            ),
            rebate_root: root_from_records(
                "rebates",
                self.rebates
                    .values()
                    .map(RebateRecord::public_record)
                    .collect(),
            ),
            counters_root: public_record_root(&self.counters().public_record()),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(
            "route_hints",
            self.route_hints.len(),
            self.config.max_route_hints,
        )?;
        ensure_capacity(
            "encrypted_quotes",
            self.encrypted_quotes.len(),
            self.config.max_quotes,
        )?;
        ensure_capacity(
            "cache_leases",
            self.cache_leases.len(),
            self.config.max_leases,
        )?;
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )?;
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        Ok(())
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_height {
            return Err("height cannot move backwards".to_string());
        }
        self.current_height = height;
        Ok(())
    }

    pub fn expired_route_hint_count(&self) -> u64 {
        self.route_hints
            .values()
            .filter(|route| route.expires_at_height <= self.current_height)
            .count() as u64
    }

    pub fn expired_quote_count(&self) -> u64 {
        self.encrypted_quotes
            .values()
            .filter(|quote| quote.expires_at_height <= self.current_height)
            .count() as u64
    }

    pub fn advertise_route_hint(
        &mut self,
        request: AdvertiseRouteHintRequest,
    ) -> Result<RouteHintRecord> {
        self.validate_route_hint_request(&request)?;
        ensure_capacity(
            "route_hints",
            self.route_hints.len() + 1,
            self.config.max_route_hints,
        )?;
        let route_hint_id = route_hint_id(
            &request.owner_commitment,
            request.venue_kind,
            request.intent_kind,
            &request.route_commitment_root,
            request.nonce,
        );
        if self.route_hints.contains_key(&route_hint_id) {
            return Err("route hint already exists".to_string());
        }
        let ttl_blocks = self.route_hint_ttl(request.ttl_blocks);
        let record = RouteHintRecord {
            route_hint_id: route_hint_id.clone(),
            owner_commitment: request.owner_commitment,
            venue_kind: request.venue_kind,
            intent_kind: request.intent_kind,
            asset_pair_root: request.asset_pair_root,
            route_commitment_root: request.route_commitment_root,
            liquidity_bucket_root: request.liquidity_bucket_root,
            fee_hint_bps: request.fee_hint_bps,
            latency_hint_ms: request.latency_hint_ms,
            route_health_bps: request.route_health_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            created_at_height: self.current_height,
            expires_at_height: self.current_height + ttl_blocks,
            status: RouteHintStatus::Advertised,
            metadata_root: request.metadata_root,
        };
        self.route_hints.insert(route_hint_id, record.clone());
        Ok(record)
    }

    pub fn post_encrypted_quote(
        &mut self,
        request: PostEncryptedQuoteRequest,
    ) -> Result<EncryptedQuoteRecord> {
        self.validate_quote_request(&request)?;
        ensure_capacity(
            "encrypted_quotes",
            self.encrypted_quotes.len() + 1,
            self.config.max_quotes,
        )?;
        let route_hint = self
            .route_hints
            .get_mut(&request.route_hint_id)
            .ok_or_else(|| "route hint not found".to_string())?;
        if !route_hint.status.quotable() {
            return Err("route hint is not quotable".to_string());
        }
        if route_hint.expires_at_height <= self.current_height {
            return Err("route hint expired".to_string());
        }
        let quote_id = quote_id(
            &request.route_hint_id,
            &request.maker_commitment,
            &request.quote_nullifier_root,
            request.nonce,
        );
        if self.encrypted_quotes.contains_key(&quote_id) {
            return Err("quote already exists".to_string());
        }
        route_hint.status = RouteHintStatus::Quoted;
        let ttl_blocks = self.quote_ttl(request.ttl_blocks);
        let record = EncryptedQuoteRecord {
            quote_id: quote_id.clone(),
            route_hint_id: request.route_hint_id,
            maker_commitment: request.maker_commitment,
            quote_ciphertext_root: request.quote_ciphertext_root,
            quote_nullifier_root: request.quote_nullifier_root,
            max_user_fee_bps: request.max_user_fee_bps,
            route_fee_bps: request.route_fee_bps,
            expected_rebate_bps: request.expected_rebate_bps,
            liquidity_score_bps: request.liquidity_score_bps,
            created_at_height: self.current_height,
            expires_at_height: self.current_height + ttl_blocks,
            status: QuoteStatus::Posted,
        };
        self.encrypted_quotes.insert(quote_id, record.clone());
        Ok(record)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> Result<SponsorReservationRecord> {
        self.validate_reservation_request(&request)?;
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len() + 1,
            self.config.max_sponsor_reservations,
        )?;
        let quote = self
            .encrypted_quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?;
        if !quote.status.reservable() {
            return Err("quote is not reservable".to_string());
        }
        if quote.expires_at_height <= self.current_height {
            return Err("quote expired".to_string());
        }
        let reservation_id = reservation_id(
            &request.quote_id,
            &request.sponsor_commitment,
            request.nonce,
        );
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err("reservation already exists".to_string());
        }
        quote.status = QuoteStatus::Reserved;
        let ttl_blocks = self.quote_ttl(request.ttl_blocks);
        let record = SponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            quote_id: request.quote_id,
            sponsor_commitment: request.sponsor_commitment,
            budget_micro_units: request.budget_micro_units,
            reserved_fee_bps: request.reserved_fee_bps,
            rebate_bps: request.rebate_bps,
            created_at_height: self.current_height,
            expires_at_height: self.current_height + ttl_blocks,
            status: ReservationStatus::Reserved,
        };
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn lease_cache(&mut self, request: LeaseCacheRequest) -> Result<CacheLeaseRecord> {
        self.validate_lease_request(&request)?;
        ensure_capacity(
            "cache_leases",
            self.cache_leases.len() + 1,
            self.config.max_leases,
        )?;
        if self.spent_nullifiers.contains(&request.lease_nullifier) {
            return Err("lease nullifier already spent".to_string());
        }
        let quote = self
            .encrypted_quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?;
        if quote.expires_at_height <= self.current_height {
            return Err("quote expired".to_string());
        }
        let lease_id = lease_id(
            &request.quote_id,
            &request.lessee_commitment,
            &request.lease_nullifier,
            request.nonce,
        );
        if self.cache_leases.contains_key(&lease_id) {
            return Err("lease already exists".to_string());
        }
        quote.status = QuoteStatus::Leased;
        self.spent_nullifiers
            .insert(request.lease_nullifier.clone());
        let ttl_blocks = self.lease_ttl(request.ttl_blocks);
        let record = CacheLeaseRecord {
            lease_id: lease_id.clone(),
            quote_id: request.quote_id,
            lessee_commitment: request.lessee_commitment,
            lease_nullifier: request.lease_nullifier,
            lease_weight: request.lease_weight,
            created_at_height: self.current_height,
            expires_at_height: self.current_height + ttl_blocks,
            status: LeaseStatus::Active,
        };
        self.cache_leases.insert(lease_id, record.clone());
        Ok(record)
    }

    pub fn batch_refresh(
        &mut self,
        request: BatchRefreshRequest,
    ) -> Result<BatchRefreshReceiptRecord> {
        self.validate_batch_refresh_request(&request)?;
        ensure_capacity(
            "refresh_receipts",
            self.refresh_receipts.len() + 1,
            self.config.max_batch_refreshes,
        )?;
        let roots_before = self.roots();
        for quote_id in &request.quote_ids {
            let quote = self
                .encrypted_quotes
                .get_mut(quote_id)
                .ok_or_else(|| format!("quote {quote_id} not found"))?;
            quote.status = QuoteStatus::Refreshed;
            quote.expires_at_height = self.current_height + self.config.quote_ttl_blocks;
            if let Some(route_hint) = self.route_hints.get_mut(&quote.route_hint_id) {
                route_hint.status = RouteHintStatus::Refreshing;
                route_hint.expires_at_height =
                    self.current_height + self.config.route_hint_ttl_blocks;
            }
        }
        let refresh_id = refresh_id(
            &request.coordinator_commitment,
            &roots_before.encrypted_quote_root,
            &request.quote_root_after,
            request.nonce,
        );
        let record = BatchRefreshReceiptRecord {
            refresh_id: refresh_id.clone(),
            coordinator_commitment: request.coordinator_commitment,
            route_hint_root_before: roots_before.route_hint_root,
            route_hint_root_after: request.route_hint_root_after,
            quote_root_before: roots_before.encrypted_quote_root,
            quote_root_after: request.quote_root_after,
            refreshed_quote_count: request.quote_ids.len() as u64,
            privacy_set_size: request.privacy_set_size,
            fee_savings_bps: request.fee_savings_bps,
            created_at_height: self.current_height,
            status: RefreshStatus::Accepted,
        };
        self.refresh_receipts.insert(refresh_id, record.clone());
        Ok(record)
    }

    pub fn open_privacy_fence(
        &mut self,
        request: OpenPrivacyFenceRequest,
    ) -> Result<PrivacyFenceRecord> {
        self.validate_privacy_fence_request(&request)?;
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len() + 1,
            self.config.max_privacy_fences,
        )?;
        if self.spent_nullifiers.contains(&request.intent_nullifier) {
            return Err("intent nullifier already spent".to_string());
        }
        if !self.route_hints.contains_key(&request.route_hint_id) {
            return Err("route hint not found".to_string());
        }
        if !self.encrypted_quotes.contains_key(&request.quote_id) {
            return Err("quote not found".to_string());
        }
        let fence_id = privacy_fence_id(
            &request.route_hint_id,
            &request.quote_id,
            &request.intent_nullifier,
            request.nonce,
        );
        if self.privacy_fences.contains_key(&fence_id) {
            return Err("privacy fence already exists".to_string());
        }
        self.spent_nullifiers
            .insert(request.intent_nullifier.clone());
        let record = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            route_hint_id: request.route_hint_id,
            quote_id: request.quote_id,
            intent_nullifier: request.intent_nullifier,
            fence_root: request.fence_root,
            opened_at_height: self.current_height,
            status: FenceStatus::Open,
        };
        self.privacy_fences.insert(fence_id, record.clone());
        Ok(record)
    }

    pub fn slash_stale_route(
        &mut self,
        request: SlashStaleRouteRequest,
    ) -> Result<StaleRouteSlashingRecord> {
        self.validate_slash_request(&request)?;
        let quote = self
            .encrypted_quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "quote not found".to_string())?;
        if quote.route_hint_id != request.route_hint_id {
            return Err("quote route hint mismatch".to_string());
        }
        if quote.expires_at_height + self.config.slash_grace_blocks > self.current_height {
            return Err("quote is still within stale grace window".to_string());
        }
        quote.status = QuoteStatus::Slashed;
        if let Some(route_hint) = self.route_hints.get_mut(&request.route_hint_id) {
            route_hint.status = RouteHintStatus::Slashed;
        }
        let slash_id = slash_id(
            &request.route_hint_id,
            &request.quote_id,
            &request.evidence_root,
            request.nonce,
        );
        let record = StaleRouteSlashingRecord {
            slash_id: slash_id.clone(),
            route_hint_id: request.route_hint_id,
            quote_id: request.quote_id,
            reporter_commitment: request.reporter_commitment,
            evidence_root: request.evidence_root,
            stale_by_blocks: request.stale_by_blocks,
            slash_amount_micro_units: request.slash_amount_micro_units,
            created_at_height: self.current_height,
            status: SlashStatus::Filed,
        };
        self.stale_slashes.insert(slash_id, record.clone());
        Ok(record)
    }

    pub fn claim_rebate(&mut self, request: ClaimRebateRequest) -> Result<RebateRecord> {
        self.validate_rebate_request(&request)?;
        let reservation = self
            .sponsor_reservations
            .get_mut(&request.reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?;
        if reservation.quote_id != request.quote_id {
            return Err("reservation quote mismatch".to_string());
        }
        reservation.status = ReservationStatus::Consumed;
        self.consumed_quote_ids.insert(request.quote_id.clone());
        let rebate_id = rebate_id(
            &request.reservation_id,
            &request.quote_id,
            &request.claimant_commitment,
            request.nonce,
        );
        let record = RebateRecord {
            rebate_id: rebate_id.clone(),
            reservation_id: request.reservation_id,
            quote_id: request.quote_id,
            claimant_commitment: request.claimant_commitment,
            rebate_micro_units: request.rebate_micro_units,
            rebate_bps: request.rebate_bps,
            created_at_height: self.current_height,
            status: RebateStatus::Claimable,
        };
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    fn route_hint_ttl(&self, ttl_blocks: u64) -> u64 {
        ttl_blocks.max(1).min(self.config.route_hint_ttl_blocks)
    }

    fn quote_ttl(&self, ttl_blocks: u64) -> u64 {
        ttl_blocks.max(1).min(self.config.quote_ttl_blocks)
    }

    fn lease_ttl(&self, ttl_blocks: u64) -> u64 {
        ttl_blocks.max(1).min(self.config.cache_lease_ttl_blocks)
    }

    fn validate_route_hint_request(&self, request: &AdvertiseRouteHintRequest) -> Result<()> {
        ensure_non_empty("owner_commitment", &request.owner_commitment)?;
        ensure_root("asset_pair_root", &request.asset_pair_root)?;
        ensure_root("route_commitment_root", &request.route_commitment_root)?;
        ensure_root("liquidity_bucket_root", &request.liquidity_bucket_root)?;
        ensure_root("metadata_root", &request.metadata_root)?;
        ensure_bps("fee_hint_bps", request.fee_hint_bps)?;
        ensure_bps("route_health_bps", request.route_health_bps)?;
        if request.fee_hint_bps > self.config.max_route_fee_bps {
            return Err("route fee hint exceeds cap".to_string());
        }
        if request.route_health_bps < self.config.min_route_health_bps {
            return Err("route health below floor".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set too small".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security bits below floor".to_string());
        }
        Ok(())
    }

    fn validate_quote_request(&self, request: &PostEncryptedQuoteRequest) -> Result<()> {
        ensure_non_empty("route_hint_id", &request.route_hint_id)?;
        ensure_non_empty("maker_commitment", &request.maker_commitment)?;
        ensure_root("quote_ciphertext_root", &request.quote_ciphertext_root)?;
        ensure_root("quote_nullifier_root", &request.quote_nullifier_root)?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        ensure_bps("route_fee_bps", request.route_fee_bps)?;
        ensure_bps("expected_rebate_bps", request.expected_rebate_bps)?;
        ensure_bps("liquidity_score_bps", request.liquidity_score_bps)?;
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("user fee exceeds cap".to_string());
        }
        if request.route_fee_bps > self.config.max_route_fee_bps {
            return Err("route fee exceeds cap".to_string());
        }
        if request.expected_rebate_bps < self.config.min_rebate_bps
            || request.expected_rebate_bps > self.config.max_rebate_bps
        {
            return Err("rebate outside configured band".to_string());
        }
        Ok(())
    }

    fn validate_reservation_request(&self, request: &ReserveSponsorRequest) -> Result<()> {
        ensure_non_empty("quote_id", &request.quote_id)?;
        ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        ensure_bps("reserved_fee_bps", request.reserved_fee_bps)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.budget_micro_units == 0 {
            return Err("budget must be non-zero".to_string());
        }
        if request.budget_micro_units > self.config.sponsor_budget_micro_units {
            return Err("budget exceeds sponsor cap".to_string());
        }
        if request.rebate_bps < self.config.min_rebate_bps
            || request.rebate_bps > self.config.max_rebate_bps
        {
            return Err("reservation rebate outside configured band".to_string());
        }
        Ok(())
    }

    fn validate_lease_request(&self, request: &LeaseCacheRequest) -> Result<()> {
        ensure_non_empty("quote_id", &request.quote_id)?;
        ensure_non_empty("lessee_commitment", &request.lessee_commitment)?;
        ensure_non_empty("lease_nullifier", &request.lease_nullifier)?;
        if request.lease_weight == 0 {
            return Err("lease weight must be non-zero".to_string());
        }
        Ok(())
    }

    fn validate_batch_refresh_request(&self, request: &BatchRefreshRequest) -> Result<()> {
        ensure_non_empty("coordinator_commitment", &request.coordinator_commitment)?;
        ensure_root("route_hint_root_after", &request.route_hint_root_after)?;
        ensure_root("quote_root_after", &request.quote_root_after)?;
        ensure_bps("fee_savings_bps", request.fee_savings_bps)?;
        if request.quote_ids.is_empty() {
            return Err("batch refresh requires quotes".to_string());
        }
        if request.privacy_set_size < self.config.min_batch_privacy_set_size {
            return Err("batch privacy set too small".to_string());
        }
        Ok(())
    }

    fn validate_privacy_fence_request(&self, request: &OpenPrivacyFenceRequest) -> Result<()> {
        ensure_non_empty("route_hint_id", &request.route_hint_id)?;
        ensure_non_empty("quote_id", &request.quote_id)?;
        ensure_non_empty("intent_nullifier", &request.intent_nullifier)?;
        ensure_root("fence_root", &request.fence_root)?;
        Ok(())
    }

    fn validate_slash_request(&self, request: &SlashStaleRouteRequest) -> Result<()> {
        ensure_non_empty("route_hint_id", &request.route_hint_id)?;
        ensure_non_empty("quote_id", &request.quote_id)?;
        ensure_non_empty("reporter_commitment", &request.reporter_commitment)?;
        ensure_root("evidence_root", &request.evidence_root)?;
        if request.stale_by_blocks == 0 {
            return Err("stale_by_blocks must be non-zero".to_string());
        }
        if request.slash_amount_micro_units == 0 {
            return Err("slash amount must be non-zero".to_string());
        }
        Ok(())
    }

    fn validate_rebate_request(&self, request: &ClaimRebateRequest) -> Result<()> {
        ensure_non_empty("reservation_id", &request.reservation_id)?;
        ensure_non_empty("quote_id", &request.quote_id)?;
        ensure_non_empty("claimant_commitment", &request.claimant_commitment)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.rebate_micro_units == 0 {
            return Err("rebate amount must be non-zero".to_string());
        }
        Ok(())
    }
}

pub fn root_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("{PROTOCOL_VERSION}:{domain}"), &records)
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "private-liquidity-route-cache:public-record",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "private-liquidity-route-cache:state-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("private-liquidity-route-cache:{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn route_hint_id(
    owner: &str,
    venue: RouteVenueKind,
    intent: RouteIntentKind,
    route_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "private-liquidity-route-cache:route-hint-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner),
            HashPart::Str(venue.as_str()),
            HashPart::Str(intent.as_str()),
            HashPart::Str(route_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn quote_id(route_hint_id: &str, maker: &str, nullifier_root: &str, nonce: u64) -> String {
    domain_hash(
        "private-liquidity-route-cache:quote-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_hint_id),
            HashPart::Str(maker),
            HashPart::Str(nullifier_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn reservation_id(quote_id: &str, sponsor: &str, nonce: u64) -> String {
    domain_hash(
        "private-liquidity-route-cache:reservation-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(sponsor),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn lease_id(quote_id: &str, lessee: &str, nullifier: &str, nonce: u64) -> String {
    domain_hash(
        "private-liquidity-route-cache:lease-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quote_id),
            HashPart::Str(lessee),
            HashPart::Str(nullifier),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn refresh_id(coordinator: &str, before: &str, after: &str, nonce: u64) -> String {
    domain_hash(
        "private-liquidity-route-cache:refresh-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(coordinator),
            HashPart::Str(before),
            HashPart::Str(after),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    route_hint_id: &str,
    quote_id: &str,
    nullifier: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "private-liquidity-route-cache:privacy-fence-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_hint_id),
            HashPart::Str(quote_id),
            HashPart::Str(nullifier),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn slash_id(route_hint_id: &str, quote_id: &str, evidence_root: &str, nonce: u64) -> String {
    domain_hash(
        "private-liquidity-route-cache:slash-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_hint_id),
            HashPart::Str(quote_id),
            HashPart::Str(evidence_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn rebate_id(reservation_id: &str, quote_id: &str, claimant: &str, nonce: u64) -> String {
    domain_hash(
        "private-liquidity-route-cache:rebate-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(quote_id),
            HashPart::Str(claimant),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_root(field: &str, value: &str) -> Result<()> {
    ensure_non_empty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

pub fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds MAX_BPS"))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(field: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        Err(format!("{field} capacity exceeded"))
    } else {
        Ok(())
    }
}

macro_rules! field_digest_helpers {
    ($validator:ident, $digest:ident, $record:ident, $field:literal) => {
        pub fn $validator(value: &str) -> Result<()> {
            ensure_non_empty($field, value)
        }

        pub fn $digest(value: &str) -> String {
            domain_hash(
                concat!("private-liquidity-route-cache:field:", $field),
                &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
                32,
            )
        }

        pub fn $record(value: &str) -> Value {
            json!({
                "field": $field,
                "value": value,
                "digest": $digest(value),
            })
        }
    };
}

field_digest_helpers!(
    validate_route_hint_id_field,
    route_hint_id_field_digest,
    route_hint_id_field_record,
    "route_hint_id"
);
field_digest_helpers!(
    validate_owner_commitment_field,
    owner_commitment_field_digest,
    owner_commitment_field_record,
    "owner_commitment"
);
field_digest_helpers!(
    validate_venue_kind_field,
    venue_kind_field_digest,
    venue_kind_field_record,
    "venue_kind"
);
field_digest_helpers!(
    validate_intent_kind_field,
    intent_kind_field_digest,
    intent_kind_field_record,
    "intent_kind"
);
field_digest_helpers!(
    validate_asset_pair_root_field,
    asset_pair_root_field_digest,
    asset_pair_root_field_record,
    "asset_pair_root"
);
field_digest_helpers!(
    validate_route_commitment_root_field,
    route_commitment_root_field_digest,
    route_commitment_root_field_record,
    "route_commitment_root"
);
field_digest_helpers!(
    validate_liquidity_bucket_root_field,
    liquidity_bucket_root_field_digest,
    liquidity_bucket_root_field_record,
    "liquidity_bucket_root"
);
field_digest_helpers!(
    validate_fee_hint_bps_field,
    fee_hint_bps_field_digest,
    fee_hint_bps_field_record,
    "fee_hint_bps"
);
field_digest_helpers!(
    validate_latency_hint_ms_field,
    latency_hint_ms_field_digest,
    latency_hint_ms_field_record,
    "latency_hint_ms"
);
field_digest_helpers!(
    validate_route_health_bps_field,
    route_health_bps_field_digest,
    route_health_bps_field_record,
    "route_health_bps"
);
field_digest_helpers!(
    validate_privacy_set_size_field,
    privacy_set_size_field_digest,
    privacy_set_size_field_record,
    "privacy_set_size"
);
field_digest_helpers!(
    validate_pq_security_bits_field,
    pq_security_bits_field_digest,
    pq_security_bits_field_record,
    "pq_security_bits"
);
field_digest_helpers!(
    validate_created_at_height_field,
    created_at_height_field_digest,
    created_at_height_field_record,
    "created_at_height"
);
field_digest_helpers!(
    validate_expires_at_height_field,
    expires_at_height_field_digest,
    expires_at_height_field_record,
    "expires_at_height"
);
field_digest_helpers!(
    validate_metadata_root_field,
    metadata_root_field_digest,
    metadata_root_field_record,
    "metadata_root"
);
field_digest_helpers!(
    validate_quote_id_field,
    quote_id_field_digest,
    quote_id_field_record,
    "quote_id"
);
field_digest_helpers!(
    validate_maker_commitment_field,
    maker_commitment_field_digest,
    maker_commitment_field_record,
    "maker_commitment"
);
field_digest_helpers!(
    validate_quote_ciphertext_root_field,
    quote_ciphertext_root_field_digest,
    quote_ciphertext_root_field_record,
    "quote_ciphertext_root"
);
field_digest_helpers!(
    validate_quote_nullifier_root_field,
    quote_nullifier_root_field_digest,
    quote_nullifier_root_field_record,
    "quote_nullifier_root"
);
field_digest_helpers!(
    validate_max_user_fee_bps_field,
    max_user_fee_bps_field_digest,
    max_user_fee_bps_field_record,
    "max_user_fee_bps"
);
field_digest_helpers!(
    validate_route_fee_bps_field,
    route_fee_bps_field_digest,
    route_fee_bps_field_record,
    "route_fee_bps"
);
field_digest_helpers!(
    validate_expected_rebate_bps_field,
    expected_rebate_bps_field_digest,
    expected_rebate_bps_field_record,
    "expected_rebate_bps"
);
field_digest_helpers!(
    validate_liquidity_score_bps_field,
    liquidity_score_bps_field_digest,
    liquidity_score_bps_field_record,
    "liquidity_score_bps"
);
field_digest_helpers!(
    validate_reservation_id_field,
    reservation_id_field_digest,
    reservation_id_field_record,
    "reservation_id"
);
field_digest_helpers!(
    validate_sponsor_commitment_field,
    sponsor_commitment_field_digest,
    sponsor_commitment_field_record,
    "sponsor_commitment"
);
field_digest_helpers!(
    validate_budget_micro_units_field,
    budget_micro_units_field_digest,
    budget_micro_units_field_record,
    "budget_micro_units"
);
field_digest_helpers!(
    validate_reserved_fee_bps_field,
    reserved_fee_bps_field_digest,
    reserved_fee_bps_field_record,
    "reserved_fee_bps"
);
field_digest_helpers!(
    validate_rebate_bps_field,
    rebate_bps_field_digest,
    rebate_bps_field_record,
    "rebate_bps"
);
field_digest_helpers!(
    validate_lease_id_field,
    lease_id_field_digest,
    lease_id_field_record,
    "lease_id"
);
field_digest_helpers!(
    validate_lessee_commitment_field,
    lessee_commitment_field_digest,
    lessee_commitment_field_record,
    "lessee_commitment"
);
field_digest_helpers!(
    validate_lease_nullifier_field,
    lease_nullifier_field_digest,
    lease_nullifier_field_record,
    "lease_nullifier"
);
field_digest_helpers!(
    validate_lease_weight_field,
    lease_weight_field_digest,
    lease_weight_field_record,
    "lease_weight"
);
field_digest_helpers!(
    validate_refresh_id_field,
    refresh_id_field_digest,
    refresh_id_field_record,
    "refresh_id"
);
field_digest_helpers!(
    validate_coordinator_commitment_field,
    coordinator_commitment_field_digest,
    coordinator_commitment_field_record,
    "coordinator_commitment"
);
field_digest_helpers!(
    validate_route_hint_root_before_field,
    route_hint_root_before_field_digest,
    route_hint_root_before_field_record,
    "route_hint_root_before"
);
field_digest_helpers!(
    validate_route_hint_root_after_field,
    route_hint_root_after_field_digest,
    route_hint_root_after_field_record,
    "route_hint_root_after"
);
field_digest_helpers!(
    validate_quote_root_before_field,
    quote_root_before_field_digest,
    quote_root_before_field_record,
    "quote_root_before"
);
field_digest_helpers!(
    validate_quote_root_after_field,
    quote_root_after_field_digest,
    quote_root_after_field_record,
    "quote_root_after"
);
field_digest_helpers!(
    validate_refreshed_quote_count_field,
    refreshed_quote_count_field_digest,
    refreshed_quote_count_field_record,
    "refreshed_quote_count"
);
field_digest_helpers!(
    validate_fee_savings_bps_field,
    fee_savings_bps_field_digest,
    fee_savings_bps_field_record,
    "fee_savings_bps"
);
field_digest_helpers!(
    validate_fence_id_field,
    fence_id_field_digest,
    fence_id_field_record,
    "fence_id"
);
field_digest_helpers!(
    validate_intent_nullifier_field,
    intent_nullifier_field_digest,
    intent_nullifier_field_record,
    "intent_nullifier"
);
field_digest_helpers!(
    validate_fence_root_field,
    fence_root_field_digest,
    fence_root_field_record,
    "fence_root"
);
field_digest_helpers!(
    validate_slash_id_field,
    slash_id_field_digest,
    slash_id_field_record,
    "slash_id"
);
field_digest_helpers!(
    validate_reporter_commitment_field,
    reporter_commitment_field_digest,
    reporter_commitment_field_record,
    "reporter_commitment"
);
field_digest_helpers!(
    validate_evidence_root_field,
    evidence_root_field_digest,
    evidence_root_field_record,
    "evidence_root"
);
field_digest_helpers!(
    validate_stale_by_blocks_field,
    stale_by_blocks_field_digest,
    stale_by_blocks_field_record,
    "stale_by_blocks"
);
field_digest_helpers!(
    validate_slash_amount_micro_units_field,
    slash_amount_micro_units_field_digest,
    slash_amount_micro_units_field_record,
    "slash_amount_micro_units"
);
field_digest_helpers!(
    validate_rebate_id_field,
    rebate_id_field_digest,
    rebate_id_field_record,
    "rebate_id"
);
field_digest_helpers!(
    validate_claimant_commitment_field,
    claimant_commitment_field_digest,
    claimant_commitment_field_record,
    "claimant_commitment"
);
field_digest_helpers!(
    validate_rebate_micro_units_field,
    rebate_micro_units_field_digest,
    rebate_micro_units_field_record,
    "rebate_micro_units"
);
field_digest_helpers!(
    validate_cache_lease_scheme_field,
    cache_lease_scheme_field_digest,
    cache_lease_scheme_field_record,
    "cache_lease_scheme"
);
field_digest_helpers!(
    validate_refresh_receipt_scheme_field,
    refresh_receipt_scheme_field_digest,
    refresh_receipt_scheme_field_record,
    "refresh_receipt_scheme"
);
field_digest_helpers!(
    validate_privacy_fence_scheme_field,
    privacy_fence_scheme_field_digest,
    privacy_fence_scheme_field_record,
    "privacy_fence_scheme"
);
field_digest_helpers!(
    validate_stale_slashing_scheme_field,
    stale_slashing_scheme_field_digest,
    stale_slashing_scheme_field_record,
    "stale_slashing_scheme"
);
field_digest_helpers!(
    validate_route_hint_scheme_field,
    route_hint_scheme_field_digest,
    route_hint_scheme_field_record,
    "route_hint_scheme"
);
field_digest_helpers!(
    validate_encrypted_quote_scheme_field,
    encrypted_quote_scheme_field_digest,
    encrypted_quote_scheme_field_record,
    "encrypted_quote_scheme"
);
