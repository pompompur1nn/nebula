use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqPrivatePaymentChannelHubRuntimeResult<T> = Result<T>;

pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-private-payment-channel-hub-runtime-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_CHANNEL_SCHEME: &str =
    "ml-kem-1024-private-payment-channel-root-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_ROUTE_SCHEME: &str =
    "privacy-fenced-channel-route-commitment-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_LIQUIDITY_SCHEME: &str =
    "low-fee-channel-liquidity-lease-root-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_SETTLEMENT_SCHEME: &str =
    "recursive-zk-channel-settlement-batch-root-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_RECEIPT_SCHEME: &str =
    "private-payment-channel-settlement-receipt-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_REBATE_SCHEME: &str =
    "sponsored-channel-fee-rebate-root-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_WATCHER_SCHEME: &str =
    "pq-channel-watcher-attestation-root-v1";
pub const PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_DEVNET_HEIGHT: u64 = 566_400;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_CHANNEL_PRIVACY_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 2_048;
pub const DEFAULT_CHANNEL_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_UPDATE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_MAX_ROUTER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 20;
pub const DEFAULT_MAX_CHANNELS: usize = 2_097_152;
pub const DEFAULT_MAX_UPDATES: usize = 16_777_216;
pub const DEFAULT_MAX_ROUTES: usize = 4_194_304;
pub const DEFAULT_MAX_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_WATCHER_ATTESTATIONS: usize = 4_194_304;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    UserToUser,
    Merchant,
    ContractEscrow,
    DexSettlement,
    MoneroBridgeExit,
    LiquidityProvider,
    PaymasterSponsored,
}

impl ChannelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserToUser => "user_to_user",
            Self::Merchant => "merchant",
            Self::ContractEscrow => "contract_escrow",
            Self::DexSettlement => "dex_settlement",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::LiquidityProvider => "liquidity_provider",
            Self::PaymasterSponsored => "paymaster_sponsored",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Opening,
    Active,
    Draining,
    Settling,
    Closed,
    Disputed,
    Quarantined,
}

impl ChannelStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Disputed => "disputed",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Proposed,
    CoSigned,
    Routed,
    Settled,
    Expired,
    Disputed,
}

impl UpdateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::CoSigned => "co_signed",
            Self::Routed => "routed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Quoted,
    Reserved,
    Locked,
    Filled,
    Failed,
    Expired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Locked => "locked",
            Self::Filled => "filled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Open,
    BoundToChannel,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::BoundToChannel => "bound_to_channel",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Building,
    Sealed,
    Proving,
    Settled,
    PartialFailure,
    Disputed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Settled => "settled",
            Self::PartialFailure => "partial_failure",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ChannelOpen,
    OffchainUpdate,
    RouteFill,
    LeaseSettlement,
    ChannelClose,
    RebateClaim,
    WatcherSlash,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChannelOpen => "channel_open",
            Self::OffchainUpdate => "offchain_update",
            Self::RouteFill => "route_fill",
            Self::LeaseSettlement => "lease_settlement",
            Self::ChannelClose => "channel_close",
            Self::RebateClaim => "rebate_claim",
            Self::WatcherSlash => "watcher_slash",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    Donated,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Donated => "donated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Reserved,
    Spent,
    Expired,
    Quarantined,
}

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherVerdict {
    Healthy,
    LateUpdate,
    InvalidSignature,
    StaleState,
    DoubleSpendAttempt,
    RouteTimeout,
}

impl WatcherVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::LateUpdate => "late_update",
            Self::InvalidSignature => "invalid_signature",
            Self::StaleState => "stale_state",
            Self::DoubleSpendAttempt => "double_spend_attempt",
            Self::RouteTimeout => "route_timeout",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub min_pq_security_bits: u16,
    pub min_channel_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub channel_ttl_blocks: u64,
    pub update_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_router_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub max_channels: usize,
    pub max_updates: usize,
    pub max_routes: usize,
    pub max_leases: usize,
    pub max_batch_items: usize,
    pub max_watcher_attestations: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_channel_privacy_set_size: DEFAULT_MIN_CHANNEL_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            channel_ttl_blocks: DEFAULT_CHANNEL_TTL_BLOCKS,
            update_ttl_blocks: DEFAULT_UPDATE_TTL_BLOCKS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_router_fee_bps: DEFAULT_MAX_ROUTER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            max_channels: DEFAULT_MAX_CHANNELS,
            max_updates: DEFAULT_MAX_UPDATES,
            max_routes: DEFAULT_MAX_ROUTES,
            max_leases: DEFAULT_MAX_LEASES,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_watcher_attestations: DEFAULT_MAX_WATCHER_ATTESTATIONS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security must be at least 192 bits".to_string());
        }
        if self.min_channel_privacy_set_size < 2 {
            return Err("channel privacy set must be at least 2".to_string());
        }
        if self.min_batch_privacy_set_size < self.min_channel_privacy_set_size {
            return Err("batch privacy set must cover channel privacy set".to_string());
        }
        if self.channel_ttl_blocks == 0
            || self.update_ttl_blocks == 0
            || self.route_ttl_blocks == 0
            || self.lease_ttl_blocks == 0
            || self.settlement_window_blocks == 0
        {
            return Err("timing windows must be non-zero".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.max_router_fee_bps > MAX_BPS
            || self.target_rebate_bps > MAX_BPS
            || self.max_rebate_bps > MAX_BPS
        {
            return Err("bps caps must fit within MAX_BPS".to_string());
        }
        if self.target_rebate_bps > self.max_rebate_bps {
            return Err("target rebate exceeds max rebate".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_channel_privacy_set_size": self.min_channel_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "channel_ttl_blocks": self.channel_ttl_blocks,
            "update_ttl_blocks": self.update_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "lease_ttl_blocks": self.lease_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_router_fee_bps": self.max_router_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "max_channels": self.max_channels,
            "max_updates": self.max_updates,
            "max_routes": self.max_routes,
            "max_leases": self.max_leases,
            "max_batch_items": self.max_batch_items,
            "max_watcher_attestations": self.max_watcher_attestations,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub channels: u64,
    pub participants: u64,
    pub updates: u64,
    pub routes: u64,
    pub leases: u64,
    pub batches: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub fences: u64,
    pub watcher_attestations: u64,
    pub spent_nullifiers: u64,
    pub events: u64,
    pub active_channels: u64,
    pub settled_updates: u64,
    pub filled_routes: u64,
    pub total_capacity_micro_units: u64,
    pub total_fee_micro_units: u64,
    pub total_rebate_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "channels": self.channels,
            "participants": self.participants,
            "updates": self.updates,
            "routes": self.routes,
            "leases": self.leases,
            "batches": self.batches,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "fences": self.fences,
            "watcher_attestations": self.watcher_attestations,
            "spent_nullifiers": self.spent_nullifiers,
            "events": self.events,
            "active_channels": self.active_channels,
            "settled_updates": self.settled_updates,
            "filled_routes": self.filled_routes,
            "total_capacity_micro_units": self.total_capacity_micro_units,
            "total_fee_micro_units": self.total_fee_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub channel_root: String,
    pub participant_root: String,
    pub update_root: String,
    pub route_root: String,
    pub lease_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub fence_root: String,
    pub watcher_root: String,
    pub nullifier_root: String,
    pub event_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            channel_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-CHANNEL-EMPTY", &[]),
            participant_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-PARTICIPANT-EMPTY", &[]),
            update_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-UPDATE-EMPTY", &[]),
            route_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-ROUTE-EMPTY", &[]),
            lease_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-LEASE-EMPTY", &[]),
            batch_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-EMPTY", &[]),
            receipt_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-RECEIPT-EMPTY", &[]),
            rebate_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-REBATE-EMPTY", &[]),
            fence_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-FENCE-EMPTY", &[]),
            watcher_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-WATCHER-EMPTY", &[]),
            nullifier_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-NULLIFIER-EMPTY", &[]),
            event_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-EVENT-EMPTY", &[]),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_root": self.channel_root,
            "participant_root": self.participant_root,
            "update_root": self.update_root,
            "route_root": self.route_root,
            "lease_root": self.lease_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "fence_root": self.fence_root,
            "watcher_root": self.watcher_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelParticipant {
    pub participant_id: String,
    pub channel_id: String,
    pub participant_commitment: String,
    pub pq_key_commitment: String,
    pub view_tag_root: String,
    pub weight: u16,
    pub joined_at_height: u64,
}

impl ChannelParticipant {
    pub fn public_record(&self) -> Value {
        json!({
            "participant_id": self.participant_id,
            "channel_id": self.channel_id,
            "participant_commitment": self.participant_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "view_tag_root": self.view_tag_root,
            "weight": self.weight,
            "joined_at_height": self.joined_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentChannel {
    pub channel_id: String,
    pub kind: ChannelKind,
    pub status: ChannelStatus,
    pub asset_root: String,
    pub participant_root: String,
    pub funding_commitment: String,
    pub capacity_commitment: String,
    pub reserve_commitment: String,
    pub latest_update_root: String,
    pub privacy_fence_id: String,
    pub opening_nullifier: String,
    pub capacity_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PaymentChannel {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.channel_id.is_empty()
            || self.asset_root.is_empty()
            || self.participant_root.is_empty()
            || self.opening_nullifier.is_empty()
        {
            return Err("payment channel missing required roots".to_string());
        }
        if self.capacity_micro_units == 0 {
            return Err("payment channel capacity must be non-zero".to_string());
        }
        if self.min_privacy_set_size < config.min_channel_privacy_set_size {
            return Err("payment channel privacy set below minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("payment channel PQ security below minimum".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("payment channel expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "channel_id": self.channel_id,
            "kind": self.kind,
            "status": self.status,
            "asset_root": self.asset_root,
            "participant_root": self.participant_root,
            "funding_commitment": self.funding_commitment,
            "capacity_commitment": self.capacity_commitment,
            "reserve_commitment": self.reserve_commitment,
            "latest_update_root": self.latest_update_root,
            "privacy_fence_id": self.privacy_fence_id,
            "opening_nullifier": self.opening_nullifier,
            "capacity_micro_units": self.capacity_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelUpdate {
    pub update_id: String,
    pub channel_id: String,
    pub status: UpdateStatus,
    pub sequence: u64,
    pub balance_delta_root: String,
    pub encrypted_memo_root: String,
    pub co_signature_root: String,
    pub route_id: Option<String>,
    pub update_nullifier: String,
    pub fee_micro_units: u64,
    pub proposed_at_height: u64,
    pub expires_at_height: u64,
}

impl ChannelUpdate {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.update_id.is_empty()
            || self.channel_id.is_empty()
            || self.balance_delta_root.is_empty()
            || self.update_nullifier.is_empty()
        {
            return Err("channel update missing required roots".to_string());
        }
        if self.expires_at_height <= self.proposed_at_height {
            return Err("channel update expiry must be after proposal height".to_string());
        }
        if self.fee_micro_units == 0 {
            return Err("channel update fee must be non-zero".to_string());
        }
        if self.expires_at_height > self.proposed_at_height + config.update_ttl_blocks * 4 {
            return Err("channel update expiry exceeds bounded ttl".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "update_id": self.update_id,
            "channel_id": self.channel_id,
            "status": self.status,
            "sequence": self.sequence,
            "balance_delta_root": self.balance_delta_root,
            "encrypted_memo_root": self.encrypted_memo_root,
            "co_signature_root": self.co_signature_root,
            "route_id": self.route_id,
            "update_nullifier": self.update_nullifier,
            "fee_micro_units": self.fee_micro_units,
            "proposed_at_height": self.proposed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteCommitment {
    pub route_id: String,
    pub source_channel_id: String,
    pub target_commitment: String,
    pub status: RouteStatus,
    pub router_commitment: String,
    pub liquidity_lease_id: Option<String>,
    pub amount_commitment: String,
    pub fee_quote_micro_units: u64,
    pub privacy_set_size: u64,
    pub route_fence_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl RouteCommitment {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.route_id.is_empty()
            || self.source_channel_id.is_empty()
            || self.target_commitment.is_empty()
            || self.route_fence_id.is_empty()
        {
            return Err("route commitment missing required roots".to_string());
        }
        if self.privacy_set_size < config.min_channel_privacy_set_size {
            return Err("route commitment privacy set too small".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("route commitment expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "source_channel_id": self.source_channel_id,
            "target_commitment": self.target_commitment,
            "status": self.status,
            "router_commitment": self.router_commitment,
            "liquidity_lease_id": self.liquidity_lease_id,
            "amount_commitment": self.amount_commitment,
            "fee_quote_micro_units": self.fee_quote_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "route_fence_id": self.route_fence_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidityLease {
    pub lease_id: String,
    pub lessor_commitment: String,
    pub channel_id: Option<String>,
    pub status: LeaseStatus,
    pub asset_root: String,
    pub capacity_commitment: String,
    pub capacity_micro_units: u64,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityLease {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.lease_id.is_empty()
            || self.lessor_commitment.is_empty()
            || self.asset_root.is_empty()
            || self.capacity_commitment.is_empty()
        {
            return Err("liquidity lease missing required roots".to_string());
        }
        if self.capacity_micro_units == 0 {
            return Err("liquidity lease capacity must be non-zero".to_string());
        }
        if self.max_fee_bps > config.max_router_fee_bps || self.rebate_bps > config.max_rebate_bps {
            return Err("liquidity lease fee values exceed caps".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("liquidity lease expiry must be after creation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "lessor_commitment": self.lessor_commitment,
            "channel_id": self.channel_id,
            "status": self.status,
            "asset_root": self.asset_root,
            "capacity_commitment": self.capacity_commitment,
            "capacity_micro_units": self.capacity_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub channel_root: String,
    pub update_root: String,
    pub route_root: String,
    pub lease_root: String,
    pub receipt_root: String,
    pub recursive_proof_root: String,
    pub batch_size: u64,
    pub settled_update_count: u64,
    pub filled_route_count: u64,
    pub total_fee_micro_units: u64,
    pub sealed_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl SettlementBatch {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.batch_id.is_empty()
            || self.channel_root.is_empty()
            || self.update_root.is_empty()
            || self.recursive_proof_root.is_empty()
        {
            return Err("settlement batch missing required roots".to_string());
        }
        if self.batch_size == 0 || self.batch_size > config.max_batch_items as u64 {
            return Err("settlement batch size invalid".to_string());
        }
        if self.settled_update_count > self.batch_size || self.filled_route_count > self.batch_size
        {
            return Err("settlement batch counters exceed batch size".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status,
            "channel_root": self.channel_root,
            "update_root": self.update_root,
            "route_root": self.route_root,
            "lease_root": self.lease_root,
            "receipt_root": self.receipt_root,
            "recursive_proof_root": self.recursive_proof_root,
            "batch_size": self.batch_size,
            "settled_update_count": self.settled_update_count,
            "filled_route_count": self.filled_route_count,
            "total_fee_micro_units": self.total_fee_micro_units,
            "sealed_at_height": self.sealed_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub subject_id: String,
    pub kind: ReceiptKind,
    pub status_root: String,
    pub fee_paid_micro_units: u64,
    pub rebate_id: Option<String>,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.receipt_id.is_empty() || self.batch_id.is_empty() || self.subject_id.is_empty() {
            return Err("settlement receipt missing required ids".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "subject_id": self.subject_id,
            "kind": self.kind,
            "status_root": self.status_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_id": self.rebate_id,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub status: RebateStatus,
    pub amount_micro_units: u64,
    pub claim_nullifier: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.rebate_id.is_empty()
            || self.receipt_id.is_empty()
            || self.beneficiary_commitment.is_empty()
            || self.claim_nullifier.is_empty()
        {
            return Err("fee rebate missing required roots".to_string());
        }
        if self.amount_micro_units == 0 {
            return Err("fee rebate amount must be non-zero".to_string());
        }
        if self.privacy_set_size < config.min_channel_privacy_set_size {
            return Err("fee rebate privacy set too small".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("fee rebate expiry must be after creation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status,
            "amount_micro_units": self.amount_micro_units,
            "claim_nullifier": self.claim_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub subject_id: String,
    pub status: FenceStatus,
    pub nullifier: String,
    pub ring_root: String,
    pub view_tag_root: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.fence_id.is_empty()
            || self.subject_id.is_empty()
            || self.nullifier.is_empty()
            || self.ring_root.is_empty()
        {
            return Err("privacy fence missing required roots".to_string());
        }
        if self.privacy_set_size < config.min_channel_privacy_set_size {
            return Err("privacy fence privacy set too small".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("privacy fence expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "subject_id": self.subject_id,
            "status": self.status,
            "nullifier": self.nullifier,
            "ring_root": self.ring_root,
            "view_tag_root": self.view_tag_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub channel_id: String,
    pub watcher_commitment: String,
    pub verdict: WatcherVerdict,
    pub evidence_root: String,
    pub signature_root: String,
    pub latency_ms: u64,
    pub issued_at_height: u64,
}

impl WatcherAttestation {
    pub fn validate(&self) -> Result<()> {
        if self.attestation_id.is_empty()
            || self.channel_id.is_empty()
            || self.evidence_root.is_empty()
            || self.signature_root.is_empty()
        {
            return Err("watcher attestation missing required roots".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "channel_id": self.channel_id,
            "watcher_commitment": self.watcher_commitment,
            "verdict": self.verdict,
            "evidence_root": self.evidence_root,
            "signature_root": self.signature_root,
            "latency_ms": self.latency_ms,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub channels: BTreeMap<String, PaymentChannel>,
    pub participants: BTreeMap<String, ChannelParticipant>,
    pub updates: BTreeMap<String, ChannelUpdate>,
    pub routes: BTreeMap<String, RouteCommitment>,
    pub leases: BTreeMap<String, LiquidityLease>,
    pub batches: BTreeMap<String, SettlementBatch>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub spent_nullifiers: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            current_height: 0,
            channels: BTreeMap::new(),
            participants: BTreeMap::new(),
            updates: BTreeMap::new(),
            routes: BTreeMap::new(),
            leases: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            current_height,
            ..Self::default()
        };
        state.recompute_counters();
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self {
            current_height: PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_DEVNET_HEIGHT,
            ..Self::default()
        };
        let height = state.current_height;
        let channel_nullifier = nullifier("devnet-channel", "alice-bob-merchant-0001");
        let channel_id_value =
            payment_channel_id(ChannelKind::Merchant, &channel_nullifier, height - 64);
        let participant_a = ChannelParticipant {
            participant_id: participant_id(&channel_id_value, "alice", 0),
            channel_id: channel_id_value.clone(),
            participant_commitment: commitment("participant", "alice"),
            pq_key_commitment: commitment("pq-key", "alice-ml-dsa-87"),
            view_tag_root: payload_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-VIEW-TAG",
                &json!(["alice-viewtag"]),
            ),
            weight: 1,
            joined_at_height: height - 64,
        };
        let participant_b = ChannelParticipant {
            participant_id: participant_id(&channel_id_value, "merchant", 1),
            channel_id: channel_id_value.clone(),
            participant_commitment: commitment("participant", "merchant"),
            pq_key_commitment: commitment("pq-key", "merchant-ml-dsa-87"),
            view_tag_root: payload_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-VIEW-TAG",
                &json!(["merchant-viewtag"]),
            ),
            weight: 1,
            joined_at_height: height - 64,
        };
        state
            .participants
            .insert(participant_a.participant_id.clone(), participant_a);
        state
            .participants
            .insert(participant_b.participant_id.clone(), participant_b);
        let participant_root = map_root(
            "PRIVATE-L2-PQ-PAYMENT-HUB-DEVNET-PARTICIPANTS",
            &state.participants,
            |participant| participant.public_record(),
        );
        let fence_id_value = privacy_fence_id(&channel_id_value, &channel_nullifier);
        let channel = PaymentChannel {
            channel_id: channel_id_value.clone(),
            kind: ChannelKind::Merchant,
            status: ChannelStatus::Active,
            asset_root: payload_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-ASSET",
                &json!(["wxmr", "private-usd"]),
            ),
            participant_root,
            funding_commitment: commitment("funding", "devnet-merchant-channel"),
            capacity_commitment: commitment("capacity", "hidden-capacity"),
            reserve_commitment: commitment("reserve", "hidden-reserve"),
            latest_update_root: merkle_root("PRIVATE-L2-PQ-PAYMENT-HUB-LATEST-UPDATE-EMPTY", &[]),
            privacy_fence_id: fence_id_value.clone(),
            opening_nullifier: channel_nullifier.clone(),
            capacity_micro_units: 250_000_000,
            min_privacy_set_size: state.config.min_channel_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            opened_at_height: height - 64,
            expires_at_height: height + state.config.channel_ttl_blocks,
        };
        state.open_channel(channel).expect("devnet channel");
        state
            .open_privacy_fence(PrivacyFence {
                fence_id: fence_id_value.clone(),
                subject_id: channel_id_value.clone(),
                status: FenceStatus::Spent,
                nullifier: channel_nullifier.clone(),
                ring_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-RING",
                    &json!(["merchant-channel-ring-a", "merchant-channel-ring-b"]),
                ),
                view_tag_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-FENCE-VIEW-TAG",
                    &json!(["viewtag-a", "viewtag-b"]),
                ),
                privacy_set_size: state.config.min_channel_privacy_set_size,
                opened_at_height: height - 64,
                expires_at_height: height + state.config.channel_ttl_blocks,
            })
            .expect("devnet fence");
        state
            .spend_nullifier(&channel_nullifier)
            .expect("devnet channel nullifier");

        let lease_id_value = liquidity_lease_id("lp-a", "wxmr", height - 32);
        state
            .reserve_liquidity(LiquidityLease {
                lease_id: lease_id_value.clone(),
                lessor_commitment: commitment("lessor", "lp-a"),
                channel_id: Some(channel_id_value.clone()),
                status: LeaseStatus::BoundToChannel,
                asset_root: payload_root("PRIVATE-L2-PQ-PAYMENT-HUB-LEASE-ASSET", &json!(["wxmr"])),
                capacity_commitment: commitment("lease-capacity", "hidden-liquidity"),
                capacity_micro_units: 100_000_000,
                max_fee_bps: 9,
                rebate_bps: state.config.target_rebate_bps,
                created_at_height: height - 32,
                expires_at_height: height + state.config.lease_ttl_blocks,
            })
            .expect("devnet lease");

        let route_nullifier = nullifier("devnet-route", "alice-to-merchant-route-0001");
        let route_id_value = route_id(&channel_id_value, &route_nullifier, height - 4);
        let route_fence_id = privacy_fence_id(&route_id_value, &route_nullifier);
        state
            .commit_route(RouteCommitment {
                route_id: route_id_value.clone(),
                source_channel_id: channel_id_value.clone(),
                target_commitment: commitment("target", "merchant-invoice-0001"),
                status: RouteStatus::Filled,
                router_commitment: commitment("router", "low-fee-router-a"),
                liquidity_lease_id: Some(lease_id_value.clone()),
                amount_commitment: commitment("amount", "hidden-payment"),
                fee_quote_micro_units: 4_200,
                privacy_set_size: state.config.min_channel_privacy_set_size,
                route_fence_id: route_fence_id.clone(),
                opened_at_height: height - 4,
                expires_at_height: height + state.config.route_ttl_blocks,
            })
            .expect("devnet route");

        let update_nullifier = nullifier("devnet-update", "payment-update-0001");
        let update_id_value = channel_update_id(&channel_id_value, 1, &update_nullifier);
        state
            .record_update(ChannelUpdate {
                update_id: update_id_value.clone(),
                channel_id: channel_id_value.clone(),
                status: UpdateStatus::Settled,
                sequence: 1,
                balance_delta_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BALANCE-DELTA",
                    &json!({"delta": "hidden", "asset": "wxmr"}),
                ),
                encrypted_memo_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-ENCRYPTED-MEMO",
                    &json!({"memo": "encrypted merchant invoice"}),
                ),
                co_signature_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-CO-SIGNATURE",
                    &json!(["alice-ml-dsa-87", "merchant-ml-dsa-87"]),
                ),
                route_id: Some(route_id_value.clone()),
                update_nullifier: update_nullifier.clone(),
                fee_micro_units: 4_200,
                proposed_at_height: height - 3,
                expires_at_height: height + state.config.update_ttl_blocks,
            })
            .expect("devnet update");
        state
            .spend_nullifier(&update_nullifier)
            .expect("devnet update nullifier");

        state
            .record_watcher_attestation(WatcherAttestation {
                attestation_id: watcher_attestation_id(&channel_id_value, "watcher-a", height - 1),
                channel_id: channel_id_value.clone(),
                watcher_commitment: commitment("watcher", "watcher-a"),
                verdict: WatcherVerdict::Healthy,
                evidence_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-WATCHER-EVIDENCE",
                    &json!({"latency_ms": 95, "state": "fresh"}),
                ),
                signature_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-WATCHER-SIGNATURE",
                    &json!(["watcher-a-ml-dsa-87", "watcher-b-slh-dsa"]),
                ),
                latency_ms: 95,
                issued_at_height: height - 1,
            })
            .expect("devnet watcher");

        let batch_id_value = settlement_batch_id(height, 0);
        let receipt_id_value = settlement_receipt_id(&batch_id_value, &update_id_value);
        let rebate_id_value = rebate_id(&receipt_id_value, "alice");
        state
            .issue_receipt(SettlementReceipt {
                receipt_id: receipt_id_value.clone(),
                batch_id: batch_id_value.clone(),
                subject_id: update_id_value.clone(),
                kind: ReceiptKind::OffchainUpdate,
                status_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-RECEIPT-STATUS",
                    &json!({"status": "settled"}),
                ),
                fee_paid_micro_units: 4_200,
                rebate_id: Some(rebate_id_value.clone()),
                settled_at_height: height,
            })
            .expect("devnet receipt");
        state
            .issue_rebate(FeeRebate {
                rebate_id: rebate_id_value,
                receipt_id: receipt_id_value.clone(),
                beneficiary_commitment: commitment("beneficiary", "alice"),
                status: RebateStatus::Claimable,
                amount_micro_units: 252,
                claim_nullifier: nullifier("rebate", "payment-channel-hub-alice-0001"),
                privacy_set_size: state.config.min_channel_privacy_set_size,
                created_at_height: height,
                expires_at_height: height + state.config.rebate_ttl_blocks,
            })
            .expect("devnet rebate");
        state
            .settle_batch(SettlementBatch {
                batch_id: batch_id_value.clone(),
                status: BatchStatus::Settled,
                channel_root: map_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-CHANNEL",
                    &state.channels,
                    |channel| channel.public_record(),
                ),
                update_root: map_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-UPDATE",
                    &state.updates,
                    |update| update.public_record(),
                ),
                route_root: map_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-ROUTE",
                    &state.routes,
                    |route| route.public_record(),
                ),
                lease_root: map_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-LEASE",
                    &state.leases,
                    |lease| lease.public_record(),
                ),
                receipt_root: map_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-RECEIPT",
                    &state.receipts,
                    |receipt| receipt.public_record(),
                ),
                recursive_proof_root: payload_root(
                    "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-PROOF",
                    &json!({"recursive": true, "suite": "shake256"}),
                ),
                batch_size: 1,
                settled_update_count: 1,
                filled_route_count: 1,
                total_fee_micro_units: 4_200,
                sealed_at_height: height - 1,
                settled_at_height: Some(height),
            })
            .expect("devnet batch");
        state.emit_event(
            "channel_opened",
            &channel_id_value,
            &json!({"kind": ChannelKind::Merchant.as_str()}),
            height - 64,
        );
        state.emit_event(
            "route_filled",
            &route_id_value,
            &json!({"fee_micro_units": 4_200_u64}),
            height,
        );
        state.emit_event(
            "batch_settled",
            &batch_id_value,
            &json!({"updates": 1_u64}),
            height,
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn open_channel(&mut self, channel: PaymentChannel) -> Result<()> {
        if self.channels.len() >= self.config.max_channels {
            return Err("payment channel capacity exceeded".to_string());
        }
        channel.validate(&self.config)?;
        if self.spent_nullifiers.contains(&channel.opening_nullifier) {
            return Err("channel opening nullifier already spent".to_string());
        }
        self.channels.insert(channel.channel_id.clone(), channel);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_update(&mut self, update: ChannelUpdate) -> Result<()> {
        if self.updates.len() >= self.config.max_updates {
            return Err("channel update capacity exceeded".to_string());
        }
        update.validate(&self.config)?;
        if !self.channels.contains_key(&update.channel_id) {
            return Err("update references unknown channel".to_string());
        }
        if self.spent_nullifiers.contains(&update.update_nullifier) {
            return Err("channel update nullifier already spent".to_string());
        }
        self.updates.insert(update.update_id.clone(), update);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn commit_route(&mut self, route: RouteCommitment) -> Result<()> {
        if self.routes.len() >= self.config.max_routes {
            return Err("route capacity exceeded".to_string());
        }
        route.validate(&self.config)?;
        if !self.channels.contains_key(&route.source_channel_id) {
            return Err("route references unknown channel".to_string());
        }
        self.routes.insert(route.route_id.clone(), route);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn reserve_liquidity(&mut self, lease: LiquidityLease) -> Result<()> {
        if self.leases.len() >= self.config.max_leases {
            return Err("liquidity lease capacity exceeded".to_string());
        }
        lease.validate(&self.config)?;
        self.leases.insert(lease.lease_id.clone(), lease);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn settle_batch(&mut self, batch: SettlementBatch) -> Result<()> {
        batch.validate(&self.config)?;
        self.batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_receipt(&mut self, receipt: SettlementReceipt) -> Result<()> {
        receipt.validate()?;
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        rebate.validate(&self.config)?;
        if !self.receipts.contains_key(&rebate.receipt_id) {
            return Err("rebate references unknown receipt".to_string());
        }
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn open_privacy_fence(&mut self, fence: PrivacyFence) -> Result<()> {
        fence.validate(&self.config)?;
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_watcher_attestation(&mut self, attestation: WatcherAttestation) -> Result<()> {
        if self.watcher_attestations.len() >= self.config.max_watcher_attestations {
            return Err("watcher attestation capacity exceeded".to_string());
        }
        attestation.validate()?;
        if !self.channels.contains_key(&attestation.channel_id) {
            return Err("watcher attestation references unknown channel".to_string());
        }
        self.watcher_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn spend_nullifier(&mut self, nullifier_value: &str) -> Result<()> {
        if !self.spent_nullifiers.insert(nullifier_value.to_string()) {
            return Err("nullifier already spent".to_string());
        }
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn emit_event(&mut self, event_kind: &str, subject_id: &str, payload: &Value, height: u64) {
        self.events.push(RuntimeEvent {
            event_id: runtime_event_id(event_kind, subject_id, height),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: payload_root("PRIVATE-L2-PQ-PAYMENT-HUB-EVENT-PAYLOAD", payload),
            emitted_at_height: height,
        });
        self.recompute_counters();
        self.recompute_roots();
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            channels: self.channels.len() as u64,
            participants: self.participants.len() as u64,
            updates: self.updates.len() as u64,
            routes: self.routes.len() as u64,
            leases: self.leases.len() as u64,
            batches: self.batches.len() as u64,
            receipts: self.receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            fences: self.privacy_fences.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
            events: self.events.len() as u64,
            active_channels: self
                .channels
                .values()
                .filter(|channel| channel.status == ChannelStatus::Active)
                .count() as u64,
            settled_updates: self
                .updates
                .values()
                .filter(|update| update.status == UpdateStatus::Settled)
                .count() as u64,
            filled_routes: self
                .routes
                .values()
                .filter(|route| route.status == RouteStatus::Filled)
                .count() as u64,
            total_capacity_micro_units: self
                .channels
                .values()
                .map(|channel| channel.capacity_micro_units)
                .sum(),
            total_fee_micro_units: self
                .receipts
                .values()
                .map(|receipt| receipt.fee_paid_micro_units)
                .sum(),
            total_rebate_micro_units: self
                .rebates
                .values()
                .map(|rebate| rebate.amount_micro_units)
                .sum(),
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            channel_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-CHANNELS",
                &self.channels,
                |channel| channel.public_record(),
            ),
            participant_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-PARTICIPANTS",
                &self.participants,
                |participant| participant.public_record(),
            ),
            update_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-UPDATES",
                &self.updates,
                |update| update.public_record(),
            ),
            route_root: map_root("PRIVATE-L2-PQ-PAYMENT-HUB-ROUTES", &self.routes, |route| {
                route.public_record()
            }),
            lease_root: map_root("PRIVATE-L2-PQ-PAYMENT-HUB-LEASES", &self.leases, |lease| {
                lease.public_record()
            }),
            batch_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-BATCHES",
                &self.batches,
                |batch| batch.public_record(),
            ),
            receipt_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-RECEIPTS",
                &self.receipts,
                |receipt| receipt.public_record(),
            ),
            rebate_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-REBATES",
                &self.rebates,
                |rebate| rebate.public_record(),
            ),
            fence_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-FENCES",
                &self.privacy_fences,
                |fence| fence.public_record(),
            ),
            watcher_root: map_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-WATCHERS",
                &self.watcher_attestations,
                |attestation| attestation.public_record(),
            ),
            nullifier_root: set_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-NULLIFIERS",
                &self.spent_nullifiers,
            ),
            event_root: vec_root(
                "PRIVATE-L2-PQ-PAYMENT-HUB-EVENTS",
                &self
                    .events
                    .iter()
                    .map(RuntimeEvent::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_HASH_SUITE,
            "channel_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_CHANNEL_SCHEME,
            "route_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_ROUTE_SCHEME,
            "liquidity_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_LIQUIDITY_SCHEME,
            "settlement_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_SETTLEMENT_SCHEME,
            "receipt_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_RECEIPT_SCHEME,
            "rebate_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_REBATE_SCHEME,
            "watcher_scheme": PRIVATE_L2_PQ_PRIVATE_PAYMENT_CHANNEL_HUB_RUNTIME_WATCHER_SCHEME,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_private_payment_channel_hub_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn private_l2_pq_private_payment_channel_hub_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn payment_channel_id(kind: ChannelKind, opening_nullifier: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-CHANNEL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(opening_nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn participant_id(channel_id: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-PARTICIPANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn channel_update_id(channel_id: &str, sequence: u64, update_nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-UPDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::U64(sequence),
            HashPart::Str(update_nullifier),
        ],
        32,
    )
}

pub fn route_id(channel_id: &str, route_nullifier: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(route_nullifier),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn liquidity_lease_id(lessor_label: &str, asset_label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lessor_label),
            HashPart::Str(asset_label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn settlement_batch_id(height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, subject_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(subject_id),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, beneficiary_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_label),
        ],
        32,
    )
}

pub fn privacy_fence_id(subject_id: &str, nullifier_value: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_value),
        ],
        32,
    )
}

pub fn watcher_attestation_id(channel_id: &str, watcher_label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-WATCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(channel_id),
            HashPart::Str(watcher_label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn runtime_event_id(event_kind: &str, subject_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn nullifier(scope_id: &str, secret_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(secret_label),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-PAYMENT-HUB-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-PAYMENT-HUB-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-PAYMENT-HUB-STATE", record)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, project: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| {
            json!(root_from_record(
                domain,
                &json!({"id": id, "record": project(value)})
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!(domain_hash(
                domain,
                &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
                32
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn vec_root(domain: &str, values: &[Value]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!(root_from_record(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
