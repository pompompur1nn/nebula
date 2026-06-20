use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateDexLiquidityMigrationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_DEX_LIQUIDITY_MIGRATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-dex-liquidity-migration-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_DEX_LIQUIDITY_MIGRATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 713_000;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const DEVNET_ROUTER_ID: &str = "monero-l2-pq-private-dex-liquidity-migration-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_INTENT_SCHEME: &str =
    "ml-kem-1024-sealed-private-dex-liquidity-migration-intent-v1";
pub const POOL_MIRROR_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-private-pool-mirror-root-v1";
pub const LP_NOTE_CONVERSION_SCHEME: &str = "zk-pq-private-lp-note-conversion-nullifier-root-v1";
pub const BATCH_AUCTION_SCHEME: &str =
    "sealed-private-low-fee-l2-dex-liquidity-migration-auction-v1";
pub const SLIPPAGE_GUARD_SCHEME: &str = "private-route-slippage-guard-commitment-root-v1";
pub const BRIDGE_RESERVE_PROOF_SCHEME: &str =
    "pq-private-monero-l2-dex-bridge-reserve-proof-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "private-dex-liquidity-migration-nullifier-fence-root-v1";
pub const FEE_SPONSOR_COUPON_SCHEME: &str =
    "low-fee-private-dex-liquidity-migration-sponsor-coupon-root-v1";
pub const REORG_ANCHOR_SCHEME: &str =
    "monero-reorg-safe-private-dex-liquidity-migration-anchor-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "private-dex-liquidity-migration-misbehavior-slashing-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_POOL_MIRROR_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_CONVERSION_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_RESERVE_PROOF_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_REORG_ANCHOR_DEPTH: u64 = 12;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 28;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_500;
pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 45;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_MAX_INTENTS: usize = 1_048_576;
pub const DEFAULT_MAX_POOL_MIRRORS: usize = 524_288;
pub const DEFAULT_MAX_CONVERSIONS: usize = 1_048_576;
pub const DEFAULT_MAX_AUCTIONS: usize = 262_144;
pub const DEFAULT_MAX_BIDS: usize = 1_048_576;
pub const DEFAULT_MAX_SLIPPAGE_GUARDS: usize = 1_048_576;
pub const DEFAULT_MAX_RESERVE_PROOFS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIER_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_SPONSOR_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_REORG_ANCHORS: usize = 524_288;
pub const DEFAULT_MAX_SLASHES: usize = 524_288;
pub const DEFAULT_MAX_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyVenueKind {
    ConstantProductPool,
    StableSwapPool,
    ConcentratedLiquidityPosition,
    RoutedLpBasket,
    BridgeBackedPool,
    TokenIncentiveFarm,
}
impl LegacyVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProductPool => "constant_product_pool",
            Self::StableSwapPool => "stable_swap_pool",
            Self::ConcentratedLiquidityPosition => "concentrated_liquidity_position",
            Self::RoutedLpBasket => "routed_lp_basket",
            Self::BridgeBackedPool => "bridge_backed_pool",
            Self::TokenIncentiveFarm => "token_incentive_farm",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationLane {
    SponsoredLowFee,
    FastExit,
    PoolRebalance,
    TokenLaunch,
    DefiRoute,
    EmergencyUnwind,
}
impl MigrationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::FastExit => "fast_exit",
            Self::PoolRebalance => "pool_rebalance",
            Self::TokenLaunch => "token_launch",
            Self::DefiRoute => "defi_route",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 1_000,
            Self::FastExit => 940,
            Self::SponsoredLowFee => 880,
            Self::TokenLaunch => 820,
            Self::DefiRoute => 780,
            Self::PoolRebalance => 720,
        }
    }
    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::PoolRebalance => config.max_user_fee_bps / 2,
            Self::TokenLaunch | Self::DefiRoute => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::FastExit | Self::EmergencyUnwind => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Fenced,
    Mirrored,
    Guarded,
    Auctioned,
    Converting,
    Converted,
    Settled,
    Expired,
    Slashed,
}
impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Fenced => "fenced",
            Self::Mirrored => "mirrored",
            Self::Guarded => "guarded",
            Self::Auctioned => "auctioned",
            Self::Converting => "converting",
            Self::Converted => "converted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    Active,
    Superseded,
    Expired,
    Challenged,
    Slashed,
}
impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionStatus {
    Committed,
    ReserveChecked,
    Nullified,
    Minted,
    Settled,
    Refunded,
    Expired,
    Slashed,
}
impl ConversionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::ReserveChecked => "reserve_checked",
            Self::Nullified => "nullified",
            Self::Minted => "minted",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Sponsored,
    Clearing,
    Settling,
    Settled,
    Cancelled,
    Expired,
}
impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Sponsored => "sponsored",
            Self::Clearing => "clearing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Revealed,
    Eligible,
    Selected,
    Filled,
    Rejected,
    Expired,
    Slashed,
}
impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Filled => "filled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    LegacyLpNullifier,
    RouteNullifier,
    KeyImage,
    ViewTag,
    CouponSerial,
    ReserveNonce,
}
impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegacyLpNullifier => "legacy_lp_nullifier",
            Self::RouteNullifier => "route_nullifier",
            Self::KeyImage => "key_image",
            Self::ViewTag => "view_tag",
            Self::CouponSerial => "coupon_serial",
            Self::ReserveNonce => "reserve_nonce",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DoubleMigration,
    StalePoolMirror,
    ReserveShortfall,
    SlippageViolation,
    CouponOveruse,
    ReorgAnchorFraud,
    AuctionCensorship,
}
impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleMigration => "double_migration",
            Self::StalePoolMirror => "stale_pool_mirror",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::SlippageViolation => "slippage_violation",
            Self::CouponOveruse => "coupon_overuse",
            Self::ReorgAnchorFraud => "reorg_anchor_fraud",
            Self::AuctionCensorship => "auction_censorship",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub router_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub hash_suite: String,
    pub encrypted_intent_scheme: String,
    pub pool_mirror_attestation_scheme: String,
    pub lp_note_conversion_scheme: String,
    pub batch_auction_scheme: String,
    pub slippage_guard_scheme: String,
    pub bridge_reserve_proof_scheme: String,
    pub nullifier_fence_scheme: String,
    pub fee_sponsor_coupon_scheme: String,
    pub reorg_anchor_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub pool_mirror_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub conversion_ttl_blocks: u64,
    pub reserve_proof_ttl_blocks: u64,
    pub reorg_anchor_depth: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_slippage_bps: u64,
    pub max_slash_bps: u64,
    pub max_intents: usize,
    pub max_pool_mirrors: usize,
    pub max_conversions: usize,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_slippage_guards: usize,
    pub max_reserve_proofs: usize,
    pub max_nullifier_fences: usize,
    pub max_sponsor_coupons: usize,
    pub max_reorg_anchors: usize,
    pub max_slashes: usize,
    pub max_events: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            stable_asset_id: DEVNET_STABLE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            encrypted_intent_scheme: ENCRYPTED_INTENT_SCHEME.to_string(),
            pool_mirror_attestation_scheme: POOL_MIRROR_ATTESTATION_SCHEME.to_string(),
            lp_note_conversion_scheme: LP_NOTE_CONVERSION_SCHEME.to_string(),
            batch_auction_scheme: BATCH_AUCTION_SCHEME.to_string(),
            slippage_guard_scheme: SLIPPAGE_GUARD_SCHEME.to_string(),
            bridge_reserve_proof_scheme: BRIDGE_RESERVE_PROOF_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            fee_sponsor_coupon_scheme: FEE_SPONSOR_COUPON_SCHEME.to_string(),
            reorg_anchor_scheme: REORG_ANCHOR_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size: DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            pool_mirror_ttl_blocks: DEFAULT_POOL_MIRROR_TTL_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            conversion_ttl_blocks: DEFAULT_CONVERSION_TTL_BLOCKS,
            reserve_proof_ttl_blocks: DEFAULT_RESERVE_PROOF_TTL_BLOCKS,
            reorg_anchor_depth: DEFAULT_REORG_ANCHOR_DEPTH,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
            max_intents: DEFAULT_MAX_INTENTS,
            max_pool_mirrors: DEFAULT_MAX_POOL_MIRRORS,
            max_conversions: DEFAULT_MAX_CONVERSIONS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_bids: DEFAULT_MAX_BIDS,
            max_slippage_guards: DEFAULT_MAX_SLIPPAGE_GUARDS,
            max_reserve_proofs: DEFAULT_MAX_RESERVE_PROOFS,
            max_nullifier_fences: DEFAULT_MAX_NULLIFIER_FENCES,
            max_sponsor_coupons: DEFAULT_MAX_SPONSOR_COUPONS,
            max_reorg_anchors: DEFAULT_MAX_REORG_ANCHORS,
            max_slashes: DEFAULT_MAX_SLASHES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure(!self.router_id.is_empty(), "router id required")?;
        ensure(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(self.min_pq_security_bits >= 192, "pq security too low")?;
        ensure(
            self.low_fee_bps <= self.max_user_fee_bps,
            "low fee exceeds max user fee",
        )?;
        ensure(
            self.max_user_fee_bps <= self.max_solver_fee_bps,
            "solver fee cap too low",
        )?;
        ensure(
            self.max_solver_fee_bps <= MAX_BPS,
            "solver fee cap exceeds bps",
        )?;
        ensure(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover exceeds bps",
        )?;
        ensure(self.max_slippage_bps <= MAX_BPS, "slippage exceeds bps")?;
        ensure(self.max_slash_bps <= MAX_BPS, "slash exceeds bps")?;
        ensure(self.intent_ttl_blocks > 0, "intent ttl required")?;
        ensure(self.auction_ttl_blocks > 0, "auction ttl required")?;
        ensure(self.reorg_anchor_depth > 0, "reorg anchor depth required")?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "router_id": self.router_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "hash_suite": self.hash_suite,
            "encrypted_intent_scheme": self.encrypted_intent_scheme,
            "pool_mirror_attestation_scheme": self.pool_mirror_attestation_scheme,
            "lp_note_conversion_scheme": self.lp_note_conversion_scheme,
            "batch_auction_scheme": self.batch_auction_scheme,
            "slippage_guard_scheme": self.slippage_guard_scheme,
            "bridge_reserve_proof_scheme": self.bridge_reserve_proof_scheme,
            "nullifier_fence_scheme": self.nullifier_fence_scheme,
            "fee_sponsor_coupon_scheme": self.fee_sponsor_coupon_scheme,
            "reorg_anchor_scheme": self.reorg_anchor_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "privacy": {
                "min_privacy_set_size": self.min_privacy_set_size,
                "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
                "min_pq_security_bits": self.min_pq_security_bits
            },
            "fees": {
                "low_fee_bps": self.low_fee_bps,
                "max_user_fee_bps": self.max_user_fee_bps,
                "max_solver_fee_bps": self.max_solver_fee_bps,
                "sponsor_cover_bps": self.sponsor_cover_bps,
                "max_slippage_bps": self.max_slippage_bps,
                "max_slash_bps": self.max_slash_bps
            },
            "ttls": {
                "intent_ttl_blocks": self.intent_ttl_blocks,
                "pool_mirror_ttl_blocks": self.pool_mirror_ttl_blocks,
                "auction_ttl_blocks": self.auction_ttl_blocks,
                "conversion_ttl_blocks": self.conversion_ttl_blocks,
                "reserve_proof_ttl_blocks": self.reserve_proof_ttl_blocks,
                "reorg_anchor_depth": self.reorg_anchor_depth
            },
            "capacity": {
                "max_intents": self.max_intents,
                "max_pool_mirrors": self.max_pool_mirrors,
                "max_conversions": self.max_conversions,
                "max_auctions": self.max_auctions,
                "max_bids": self.max_bids,
                "max_slippage_guards": self.max_slippage_guards,
                "max_reserve_proofs": self.max_reserve_proofs,
                "max_nullifier_fences": self.max_nullifier_fences,
                "max_sponsor_coupons": self.max_sponsor_coupons,
                "max_reorg_anchors": self.max_reorg_anchors,
                "max_slashes": self.max_slashes,
                "max_events": self.max_events
            }
        })
    }
}
impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub intents: u64,
    pub pool_mirrors: u64,
    pub conversions: u64,
    pub auctions: u64,
    pub bids: u64,
    pub slippage_guards: u64,
    pub reserve_proofs: u64,
    pub nullifier_fences: u64,
    pub sponsor_coupons: u64,
    pub reorg_anchors: u64,
    pub slashes: u64,
    pub events: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub intent_root: String,
    pub pool_mirror_root: String,
    pub conversion_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub slippage_guard_root: String,
    pub reserve_proof_root: String,
    pub nullifier_fence_root: String,
    pub sponsor_coupon_root: String,
    pub reorg_anchor_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn empty() -> Self {
        Self {
            intent_root: empty_root("intents"),
            pool_mirror_root: empty_root("pool-mirrors"),
            conversion_root: empty_root("conversions"),
            auction_root: empty_root("auctions"),
            bid_root: empty_root("bids"),
            slippage_guard_root: empty_root("slippage-guards"),
            reserve_proof_root: empty_root("reserve-proofs"),
            nullifier_fence_root: empty_root("nullifier-fences"),
            sponsor_coupon_root: empty_root("sponsor-coupons"),
            reorg_anchor_root: empty_root("reorg-anchors"),
            slashing_evidence_root: empty_root("slashing-evidence"),
            event_root: empty_root("events"),
            public_record_root: empty_root("public-record"),
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedMigrationIntent {
    pub intent_id: String,
    pub lane: MigrationLane,
    pub legacy_venue_kind: LegacyVenueKind,
    pub legacy_pool_commitment: String,
    pub target_pool_commitment: String,
    pub encrypted_payload_root: String,
    pub route_hint_root: String,
    pub input_lp_note_root: String,
    pub output_lp_note_root: String,
    pub owner_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub coupon_id: Option<String>,
    pub reorg_anchor_id: Option<String>,
    pub status: IntentStatus,
    pub created_height: u64,
    pub expires_height: u64,
}
impl EncryptedMigrationIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: MigrationLane,
        legacy_venue_kind: LegacyVenueKind,
        legacy_pool_commitment: impl Into<String>,
        target_pool_commitment: impl Into<String>,
        encrypted_payload_root: impl Into<String>,
        route_hint_root: impl Into<String>,
        input_lp_note_root: impl Into<String>,
        output_lp_note_root: impl Into<String>,
        owner_commitment: impl Into<String>,
        privacy_set_size: u64,
        pq_security_bits: u16,
        max_user_fee_bps: u64,
        max_slippage_bps: u64,
        coupon_id: Option<String>,
        reorg_anchor_id: Option<String>,
        created_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let legacy_pool_commitment = legacy_pool_commitment.into();
        let target_pool_commitment = target_pool_commitment.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let route_hint_root = route_hint_root.into();
        let input_lp_note_root = input_lp_note_root.into();
        let output_lp_note_root = output_lp_note_root.into();
        let owner_commitment = owner_commitment.into();
        let intent_id = migration_intent_id(
            lane,
            &legacy_pool_commitment,
            &target_pool_commitment,
            &encrypted_payload_root,
            created_height,
        );
        Self {
            intent_id,
            lane,
            legacy_venue_kind,
            legacy_pool_commitment,
            target_pool_commitment,
            encrypted_payload_root,
            route_hint_root,
            input_lp_note_root,
            output_lp_note_root,
            owner_commitment,
            privacy_set_size,
            pq_security_bits,
            max_user_fee_bps,
            max_slippage_bps,
            coupon_id,
            reorg_anchor_id,
            status: IntentStatus::Sealed,
            created_height,
            expires_height: created_height.saturating_add(ttl_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane": self.lane.as_str(),
            "legacy_venue_kind": self.legacy_venue_kind.as_str(),
            "legacy_pool_commitment": self.legacy_pool_commitment,
            "target_pool_commitment": self.target_pool_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "route_hint_root": self.route_hint_root,
            "input_lp_note_root": self.input_lp_note_root,
            "output_lp_note_root": self.output_lp_note_root,
            "owner_commitment": self.owner_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "coupon_id": self.coupon_id,
            "reorg_anchor_id": self.reorg_anchor_id,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PoolMirrorAttestation {
    pub attestation_id: String,
    pub legacy_pool_commitment: String,
    pub target_pool_commitment: String,
    pub asset_pair_root: String,
    pub reserve_ratio_root: String,
    pub fee_curve_root: String,
    pub oracle_price_root: String,
    pub liquidity_depth_root: String,
    pub attester_set_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
    pub posted_height: u64,
    pub expires_height: u64,
}
impl PoolMirrorAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        legacy_pool_commitment: impl Into<String>,
        target_pool_commitment: impl Into<String>,
        asset_pair_root: impl Into<String>,
        reserve_ratio_root: impl Into<String>,
        fee_curve_root: impl Into<String>,
        oracle_price_root: impl Into<String>,
        liquidity_depth_root: impl Into<String>,
        attester_set_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        privacy_set_size: u64,
        pq_security_bits: u16,
        posted_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let legacy_pool_commitment = legacy_pool_commitment.into();
        let target_pool_commitment = target_pool_commitment.into();
        let asset_pair_root = asset_pair_root.into();
        let reserve_ratio_root = reserve_ratio_root.into();
        let fee_curve_root = fee_curve_root.into();
        let oracle_price_root = oracle_price_root.into();
        let liquidity_depth_root = liquidity_depth_root.into();
        let attester_set_root = attester_set_root.into();
        let pq_signature_root = pq_signature_root.into();
        let attestation_id = pool_mirror_attestation_id(
            &legacy_pool_commitment,
            &target_pool_commitment,
            &reserve_ratio_root,
            posted_height,
        );
        Self {
            attestation_id,
            legacy_pool_commitment,
            target_pool_commitment,
            asset_pair_root,
            reserve_ratio_root,
            fee_curve_root,
            oracle_price_root,
            liquidity_depth_root,
            attester_set_root,
            pq_signature_root,
            privacy_set_size,
            pq_security_bits,
            status: AttestationStatus::Posted,
            posted_height,
            expires_height: posted_height.saturating_add(ttl_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "legacy_pool_commitment": self.legacy_pool_commitment,
            "target_pool_commitment": self.target_pool_commitment,
            "asset_pair_root": self.asset_pair_root,
            "reserve_ratio_root": self.reserve_ratio_root,
            "fee_curve_root": self.fee_curve_root,
            "oracle_price_root": self.oracle_price_root,
            "liquidity_depth_root": self.liquidity_depth_root,
            "attester_set_root": self.attester_set_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "posted_height": self.posted_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LpNoteConversion {
    pub conversion_id: String,
    pub intent_id: String,
    pub mirror_attestation_id: String,
    pub legacy_lp_nullifier_root: String,
    pub legacy_lp_note_root: String,
    pub target_lp_note_root: String,
    pub migration_receipt_root: String,
    pub reserve_proof_id: String,
    pub slippage_guard_id: String,
    pub fee_paid_commitment: String,
    pub minted_liquidity_commitment: String,
    pub privacy_set_size: u64,
    pub status: ConversionStatus,
    pub created_height: u64,
    pub expires_height: u64,
}
impl LpNoteConversion {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: impl Into<String>,
        mirror_attestation_id: impl Into<String>,
        legacy_lp_nullifier_root: impl Into<String>,
        legacy_lp_note_root: impl Into<String>,
        target_lp_note_root: impl Into<String>,
        migration_receipt_root: impl Into<String>,
        reserve_proof_id: impl Into<String>,
        slippage_guard_id: impl Into<String>,
        fee_paid_commitment: impl Into<String>,
        minted_liquidity_commitment: impl Into<String>,
        privacy_set_size: u64,
        created_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let intent_id = intent_id.into();
        let mirror_attestation_id = mirror_attestation_id.into();
        let legacy_lp_nullifier_root = legacy_lp_nullifier_root.into();
        let legacy_lp_note_root = legacy_lp_note_root.into();
        let target_lp_note_root = target_lp_note_root.into();
        let migration_receipt_root = migration_receipt_root.into();
        let reserve_proof_id = reserve_proof_id.into();
        let slippage_guard_id = slippage_guard_id.into();
        let fee_paid_commitment = fee_paid_commitment.into();
        let minted_liquidity_commitment = minted_liquidity_commitment.into();
        let conversion_id = lp_note_conversion_id(
            &intent_id,
            &legacy_lp_nullifier_root,
            &target_lp_note_root,
            created_height,
        );
        Self {
            conversion_id,
            intent_id,
            mirror_attestation_id,
            legacy_lp_nullifier_root,
            legacy_lp_note_root,
            target_lp_note_root,
            migration_receipt_root,
            reserve_proof_id,
            slippage_guard_id,
            fee_paid_commitment,
            minted_liquidity_commitment,
            privacy_set_size,
            status: ConversionStatus::Committed,
            created_height,
            expires_height: created_height.saturating_add(ttl_blocks),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "conversion_id": self.conversion_id,
            "intent_id": self.intent_id,
            "mirror_attestation_id": self.mirror_attestation_id,
            "legacy_lp_nullifier_root": self.legacy_lp_nullifier_root,
            "legacy_lp_note_root": self.legacy_lp_note_root,
            "target_lp_note_root": self.target_lp_note_root,
            "migration_receipt_root": self.migration_receipt_root,
            "reserve_proof_id": self.reserve_proof_id,
            "slippage_guard_id": self.slippage_guard_id,
            "fee_paid_commitment": self.fee_paid_commitment,
            "minted_liquidity_commitment": self.minted_liquidity_commitment,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BatchMigrationAuction {
    pub auction_id: String,
    pub lane: MigrationLane,
    pub encrypted_intent_set_root: String,
    pub target_pool_set_root: String,
    pub clearing_price_root: String,
    pub solver_set_root: String,
    pub sponsor_set_root: String,
    pub reserve_proof_root: String,
    pub slippage_guard_root: String,
    pub min_privacy_set_size: u64,
    pub max_solver_fee_bps: u64,
    pub status: AuctionStatus,
    pub opened_height: u64,
    pub closes_height: u64,
    pub selected_bid_ids: BTreeSet<String>,
}
impl BatchMigrationAuction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: MigrationLane,
        encrypted_intent_set_root: impl Into<String>,
        target_pool_set_root: impl Into<String>,
        clearing_price_root: impl Into<String>,
        solver_set_root: impl Into<String>,
        sponsor_set_root: impl Into<String>,
        reserve_proof_root: impl Into<String>,
        slippage_guard_root: impl Into<String>,
        min_privacy_set_size: u64,
        max_solver_fee_bps: u64,
        opened_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let encrypted_intent_set_root = encrypted_intent_set_root.into();
        let target_pool_set_root = target_pool_set_root.into();
        let clearing_price_root = clearing_price_root.into();
        let solver_set_root = solver_set_root.into();
        let sponsor_set_root = sponsor_set_root.into();
        let reserve_proof_root = reserve_proof_root.into();
        let slippage_guard_root = slippage_guard_root.into();
        let auction_id = batch_migration_auction_id(
            lane,
            &encrypted_intent_set_root,
            &target_pool_set_root,
            opened_height,
        );
        Self {
            auction_id,
            lane,
            encrypted_intent_set_root,
            target_pool_set_root,
            clearing_price_root,
            solver_set_root,
            sponsor_set_root,
            reserve_proof_root,
            slippage_guard_root,
            min_privacy_set_size,
            max_solver_fee_bps,
            status: AuctionStatus::Open,
            opened_height,
            closes_height: opened_height.saturating_add(ttl_blocks),
            selected_bid_ids: BTreeSet::new(),
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "encrypted_intent_set_root": self.encrypted_intent_set_root,
            "target_pool_set_root": self.target_pool_set_root,
            "clearing_price_root": self.clearing_price_root,
            "solver_set_root": self.solver_set_root,
            "sponsor_set_root": self.sponsor_set_root,
            "reserve_proof_root": self.reserve_proof_root,
            "slippage_guard_root": self.slippage_guard_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "closes_height": self.closes_height,
            "selected_bid_ids": self.selected_bid_ids
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationBid {
    pub bid_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub encrypted_bid_root: String,
    pub bid_commitment_root: String,
    pub route_execution_root: String,
    pub target_pool_liquidity_root: String,
    pub sponsored_fee_coupon_root: String,
    pub pq_signature_root: String,
    pub fee_bps: u64,
    pub expected_fill_bps: u64,
    pub status: BidStatus,
    pub posted_height: u64,
}
impl MigrationBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: impl Into<String>,
        solver_commitment: impl Into<String>,
        encrypted_bid_root: impl Into<String>,
        bid_commitment_root: impl Into<String>,
        route_execution_root: impl Into<String>,
        target_pool_liquidity_root: impl Into<String>,
        sponsored_fee_coupon_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        fee_bps: u64,
        expected_fill_bps: u64,
        posted_height: u64,
    ) -> Self {
        let auction_id = auction_id.into();
        let solver_commitment = solver_commitment.into();
        let encrypted_bid_root = encrypted_bid_root.into();
        let bid_commitment_root = bid_commitment_root.into();
        let route_execution_root = route_execution_root.into();
        let target_pool_liquidity_root = target_pool_liquidity_root.into();
        let sponsored_fee_coupon_root = sponsored_fee_coupon_root.into();
        let pq_signature_root = pq_signature_root.into();
        let bid_id = migration_bid_id(&auction_id, &solver_commitment, &bid_commitment_root);
        Self {
            bid_id,
            auction_id,
            solver_commitment,
            encrypted_bid_root,
            bid_commitment_root,
            route_execution_root,
            target_pool_liquidity_root,
            sponsored_fee_coupon_root,
            pq_signature_root,
            fee_bps,
            expected_fill_bps,
            status: BidStatus::Committed,
            posted_height,
        }
    }
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "encrypted_bid_root": self.encrypted_bid_root,
            "bid_commitment_root": self.bid_commitment_root,
            "route_execution_root": self.route_execution_root,
            "target_pool_liquidity_root": self.target_pool_liquidity_root,
            "sponsored_fee_coupon_root": self.sponsored_fee_coupon_root,
            "pq_signature_root": self.pq_signature_root,
            "fee_bps": self.fee_bps,
            "expected_fill_bps": self.expected_fill_bps,
            "status": self.status.as_str(),
            "posted_height": self.posted_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlippageGuard {
    pub guard_id: String,
    pub intent_id: String,
    pub quoted_price_root: String,
    pub min_output_note_root: String,
    pub max_slippage_bps: u64,
    pub deadline_height: u64,
    pub guard_commitment_root: String,
    pub status: String,
}
impl SlippageGuard {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeReserveProof {
    pub proof_id: String,
    pub target_pool_commitment: String,
    pub monero_reserve_root: String,
    pub l2_reserve_root: String,
    pub liability_root: String,
    pub reserve_delta_root: String,
    pub witness_set_root: String,
    pub pq_signature_root: String,
    pub coverage_bps: u64,
    pub posted_height: u64,
    pub expires_height: u64,
}
impl BridgeReserveProof {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierPrivacyFence {
    pub fence_id: String,
    pub fence_kind: FenceKind,
    pub nullifier_root: String,
    pub owner_commitment: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub first_seen_height: u64,
}
impl NullifierPrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "fence_kind": self.fence_kind.as_str(),
            "nullifier_root": self.nullifier_root,
            "owner_commitment": self.owner_commitment,
            "replay_domain": self.replay_domain,
            "privacy_set_size": self.privacy_set_size,
            "first_seen_height": self.first_seen_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeSponsorCoupon {
    pub coupon_id: String,
    pub sponsor_commitment: String,
    pub coupon_serial_root: String,
    pub eligible_lane: MigrationLane,
    pub covered_fee_bps: u64,
    pub spend_limit_commitment: String,
    pub privacy_policy_root: String,
    pub pq_signature_root: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub spent: bool,
}
impl FeeSponsorCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "sponsor_commitment": self.sponsor_commitment,
            "coupon_serial_root": self.coupon_serial_root,
            "eligible_lane": self.eligible_lane.as_str(),
            "covered_fee_bps": self.covered_fee_bps,
            "spend_limit_commitment": self.spend_limit_commitment,
            "privacy_policy_root": self.privacy_policy_root,
            "pq_signature_root": self.pq_signature_root,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "spent": self.spent
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReorgAnchor {
    pub anchor_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub monero_block_hash: String,
    pub l2_state_root: String,
    pub migration_root: String,
    pub witness_set_root: String,
    pub pq_signature_root: String,
}
impl ReorgAnchor {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub reason: SlashingReason,
    pub accused_commitment: String,
    pub affected_object_id: String,
    pub evidence_root: String,
    pub penalty_bps: u64,
    pub reporter_commitment: String,
    pub posted_height: u64,
    pub resolved: bool,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "reason": self.reason.as_str(),
            "accused_commitment": self.accused_commitment,
            "affected_object_id": self.affected_object_id,
            "evidence_root": self.evidence_root,
            "penalty_bps": self.penalty_bps,
            "reporter_commitment": self.reporter_commitment,
            "posted_height": self.posted_height,
            "resolved": self.resolved
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: String,
    pub object_id: String,
    pub height: u64,
    pub record_root: String,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub intents: BTreeMap<String, EncryptedMigrationIntent>,
    pub pool_mirrors: BTreeMap<String, PoolMirrorAttestation>,
    pub conversions: BTreeMap<String, LpNoteConversion>,
    pub auctions: BTreeMap<String, BatchMigrationAuction>,
    pub bids: BTreeMap<String, MigrationBid>,
    pub slippage_guards: BTreeMap<String, SlippageGuard>,
    pub reserve_proofs: BTreeMap<String, BridgeReserveProof>,
    pub nullifier_fences: BTreeMap<String, NullifierPrivacyFence>,
    pub sponsor_coupons: BTreeMap<String, FeeSponsorCoupon>,
    pub reorg_anchors: BTreeMap<String, ReorgAnchor>,
    pub slashes: BTreeMap<String, SlashingEvidence>,
    pub events: Vec<RuntimeEvent>,
}
impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
    }
}
impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        Self {
            config,
            current_height,
            intents: BTreeMap::new(),
            pool_mirrors: BTreeMap::new(),
            conversions: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            slippage_guards: BTreeMap::new(),
            reserve_proofs: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            sponsor_coupons: BTreeMap::new(),
            reorg_anchors: BTreeMap::new(),
            slashes: BTreeMap::new(),
            events: Vec::new(),
        }
    }
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = state.current_height;
        let anchor = ReorgAnchor {
            anchor_id: reorg_anchor_id(height - 12, height, &tagged_root("devnet-migration-root")),
            monero_height: height - 12,
            l2_height: height,
            monero_block_hash: tagged_root("devnet-monero-block"),
            l2_state_root: tagged_root("devnet-pre-migration-state"),
            migration_root: tagged_root("devnet-migration-root"),
            witness_set_root: tagged_root("devnet-anchor-watchers"),
            pq_signature_root: tagged_root("devnet-anchor-pq-signature"),
        };
        let anchor_id = anchor.anchor_id.clone();
        state.insert_reorg_anchor(anchor).expect("devnet anchor");
        let coupon = FeeSponsorCoupon {
            coupon_id: fee_sponsor_coupon_id(
                "devnet-sponsor",
                &tagged_root("devnet-coupon-serial"),
                height,
            ),
            sponsor_commitment: "devnet-sponsor".to_string(),
            coupon_serial_root: tagged_root("devnet-coupon-serial"),
            eligible_lane: MigrationLane::SponsoredLowFee,
            covered_fee_bps: DEFAULT_SPONSOR_COVER_BPS,
            spend_limit_commitment: tagged_root("devnet-coupon-limit"),
            privacy_policy_root: tagged_root("devnet-coupon-policy"),
            pq_signature_root: tagged_root("devnet-coupon-pq-signature"),
            issued_height: height,
            expires_height: height + 96,
            spent: false,
        };
        let coupon_id = coupon.coupon_id.clone();
        state
            .insert_fee_sponsor_coupon(coupon)
            .expect("devnet coupon");
        let fence = NullifierPrivacyFence {
            fence_id: nullifier_fence_id(
                FenceKind::LegacyLpNullifier,
                &tagged_root("devnet-lp-nullifier"),
                "devnet-owner",
            ),
            fence_kind: FenceKind::LegacyLpNullifier,
            nullifier_root: tagged_root("devnet-lp-nullifier"),
            owner_commitment: "devnet-owner".to_string(),
            replay_domain: DEVNET_ROUTER_ID.to_string(),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            first_seen_height: height,
        };
        state.insert_nullifier_fence(fence).expect("devnet fence");
        let intent = EncryptedMigrationIntent::new(
            MigrationLane::SponsoredLowFee,
            LegacyVenueKind::ConstantProductPool,
            tagged_root("devnet-legacy-pool"),
            tagged_root("devnet-target-private-pool"),
            tagged_root("devnet-encrypted-intent"),
            tagged_root("devnet-route-hint"),
            tagged_root("devnet-input-lp-note"),
            tagged_root("devnet-output-lp-note"),
            "devnet-owner",
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEFAULT_MAX_USER_FEE_BPS,
            DEFAULT_MAX_SLIPPAGE_BPS,
            Some(coupon_id),
            Some(anchor_id),
            height,
            state.config.intent_ttl_blocks,
        );
        let intent_id = intent.intent_id.clone();
        state.insert_intent(intent).expect("devnet intent");
        let mirror = PoolMirrorAttestation::new(
            tagged_root("devnet-legacy-pool"),
            tagged_root("devnet-target-private-pool"),
            tagged_root("devnet-asset-pair"),
            tagged_root("devnet-reserve-ratio"),
            tagged_root("devnet-fee-curve"),
            tagged_root("devnet-oracle-price"),
            tagged_root("devnet-liquidity-depth"),
            tagged_root("devnet-attesters"),
            tagged_root("devnet-mirror-pq-signature"),
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            height,
            state.config.pool_mirror_ttl_blocks,
        );
        let mirror_id = mirror.attestation_id.clone();
        state.insert_pool_mirror(mirror).expect("devnet mirror");
        let reserve = BridgeReserveProof {
            proof_id: bridge_reserve_proof_id(
                &tagged_root("devnet-target-private-pool"),
                &tagged_root("devnet-monero-reserve"),
                height,
            ),
            target_pool_commitment: tagged_root("devnet-target-private-pool"),
            monero_reserve_root: tagged_root("devnet-monero-reserve"),
            l2_reserve_root: tagged_root("devnet-l2-reserve"),
            liability_root: tagged_root("devnet-liability"),
            reserve_delta_root: tagged_root("devnet-reserve-delta"),
            witness_set_root: tagged_root("devnet-reserve-watchers"),
            pq_signature_root: tagged_root("devnet-reserve-pq-signature"),
            coverage_bps: 12_500,
            posted_height: height,
            expires_height: height + state.config.reserve_proof_ttl_blocks,
        };
        let reserve_id = reserve.proof_id.clone();
        state
            .insert_bridge_reserve_proof(reserve)
            .expect("devnet reserve");
        let guard = SlippageGuard {
            guard_id: slippage_guard_id(&intent_id, &tagged_root("devnet-quoted-price"), height),
            intent_id: intent_id.clone(),
            quoted_price_root: tagged_root("devnet-quoted-price"),
            min_output_note_root: tagged_root("devnet-min-output-note"),
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            deadline_height: height + state.config.auction_ttl_blocks,
            guard_commitment_root: tagged_root("devnet-slippage-guard"),
            status: "active".to_string(),
        };
        let guard_id = guard.guard_id.clone();
        state.insert_slippage_guard(guard).expect("devnet guard");
        let auction = BatchMigrationAuction::new(
            MigrationLane::SponsoredLowFee,
            tagged_root("devnet-intent-set"),
            tagged_root("devnet-target-pool-set"),
            tagged_root("devnet-clearing-price"),
            tagged_root("devnet-solvers"),
            tagged_root("devnet-sponsors"),
            tagged_root("devnet-reserve-proof-set"),
            tagged_root("devnet-slippage-guard-set"),
            DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            DEFAULT_MAX_SOLVER_FEE_BPS,
            height,
            state.config.auction_ttl_blocks,
        );
        let auction_id = auction.auction_id.clone();
        state.insert_auction(auction).expect("devnet auction");
        let bid = MigrationBid::new(
            auction_id,
            "devnet-solver",
            tagged_root("devnet-encrypted-bid"),
            tagged_root("devnet-bid-commitment"),
            tagged_root("devnet-route-execution"),
            tagged_root("devnet-target-liquidity"),
            tagged_root("devnet-sponsored-fee"),
            tagged_root("devnet-bid-pq-signature"),
            DEFAULT_LOW_FEE_BPS,
            9_950,
            height,
        );
        state.insert_bid(bid).expect("devnet bid");
        let conversion = LpNoteConversion::new(
            intent_id,
            mirror_id,
            tagged_root("devnet-lp-nullifier"),
            tagged_root("devnet-input-lp-note"),
            tagged_root("devnet-output-lp-note"),
            tagged_root("devnet-migration-receipt"),
            reserve_id,
            guard_id,
            tagged_root("devnet-fee-paid"),
            tagged_root("devnet-minted-liquidity"),
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            height + 1,
            state.config.conversion_ttl_blocks,
        );
        state
            .insert_conversion(conversion)
            .expect("devnet conversion");
        state.push_event("devnet_private_liquidity_migration_ready", "devnet", height);
        state
    }
    pub fn counters(&self) -> Counters {
        Counters {
            intents: self.intents.len() as u64,
            pool_mirrors: self.pool_mirrors.len() as u64,
            conversions: self.conversions.len() as u64,
            auctions: self.auctions.len() as u64,
            bids: self.bids.len() as u64,
            slippage_guards: self.slippage_guards.len() as u64,
            reserve_proofs: self.reserve_proofs.len() as u64,
            nullifier_fences: self.nullifier_fences.len() as u64,
            sponsor_coupons: self.sponsor_coupons.len() as u64,
            reorg_anchors: self.reorg_anchors.len() as u64,
            slashes: self.slashes.len() as u64,
            events: self.events.len() as u64,
        }
    }
    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            intent_root: map_root("intents", &self.intents),
            pool_mirror_root: map_root("pool-mirrors", &self.pool_mirrors),
            conversion_root: map_root("conversions", &self.conversions),
            auction_root: map_root("auctions", &self.auctions),
            bid_root: map_root("bids", &self.bids),
            slippage_guard_root: map_root("slippage-guards", &self.slippage_guards),
            reserve_proof_root: map_root("reserve-proofs", &self.reserve_proofs),
            nullifier_fence_root: map_root("nullifier-fences", &self.nullifier_fences),
            sponsor_coupon_root: map_root("sponsor-coupons", &self.sponsor_coupons),
            reorg_anchor_root: map_root("reorg-anchors", &self.reorg_anchors),
            slashing_evidence_root: map_root("slashing-evidence", &self.slashes),
            event_root: vec_root("events", &self.events),
            public_record_root: String::new(),
        };
        roots.public_record_root = state_root_from_record(&json!({
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "counters": self.counters().public_record(),
            "roots": {
                "intent_root": roots.intent_root,
                "pool_mirror_root": roots.pool_mirror_root,
                "conversion_root": roots.conversion_root,
                "auction_root": roots.auction_root,
                "bid_root": roots.bid_root,
                "slippage_guard_root": roots.slippage_guard_root,
                "reserve_proof_root": roots.reserve_proof_root,
                "nullifier_fence_root": roots.nullifier_fence_root,
                "sponsor_coupon_root": roots.sponsor_coupon_root,
                "reorg_anchor_root": roots.reorg_anchor_root,
                "slashing_evidence_root": roots.slashing_evidence_root,
                "event_root": roots.event_root
            }
        }));
        roots
    }
    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": self.state_root()
        })
    }
    pub fn state_root(&self) -> String {
        let roots = self.roots();
        state_root_from_record(&json!({
            "protocol": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "current_height": self.current_height,
            "counters": self.counters().public_record(),
            "roots": roots.public_record()
        }))
    }
    pub fn insert_intent(&mut self, intent: EncryptedMigrationIntent) -> Result<()> {
        self.config.validate()?;
        ensure_capacity(self.intents.len(), self.config.max_intents, "intents")?;
        ensure(
            intent.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small",
        )?;
        ensure(
            intent.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security too low",
        )?;
        ensure(
            intent.max_user_fee_bps <= self.config.max_user_fee_bps,
            "user fee too high",
        )?;
        ensure(
            intent.max_slippage_bps <= self.config.max_slippage_bps,
            "slippage too high",
        )?;
        ensure(
            intent.expires_height > self.current_height,
            "intent expired",
        )?;
        self.intents.insert(intent.intent_id.clone(), intent);
        Ok(())
    }
    pub fn insert_pool_mirror(&mut self, mirror: PoolMirrorAttestation) -> Result<()> {
        ensure_capacity(
            self.pool_mirrors.len(),
            self.config.max_pool_mirrors,
            "pool mirrors",
        )?;
        ensure(
            mirror.privacy_set_size >= self.config.min_privacy_set_size,
            "mirror privacy too small",
        )?;
        ensure(
            mirror.pq_security_bits >= self.config.min_pq_security_bits,
            "mirror pq too low",
        )?;
        self.pool_mirrors
            .insert(mirror.attestation_id.clone(), mirror);
        Ok(())
    }
    pub fn insert_conversion(&mut self, conversion: LpNoteConversion) -> Result<()> {
        ensure_capacity(
            self.conversions.len(),
            self.config.max_conversions,
            "conversions",
        )?;
        ensure(
            self.intents.contains_key(&conversion.intent_id),
            "missing intent",
        )?;
        ensure(
            self.pool_mirrors
                .contains_key(&conversion.mirror_attestation_id),
            "missing mirror",
        )?;
        ensure(
            self.reserve_proofs
                .contains_key(&conversion.reserve_proof_id),
            "missing reserve proof",
        )?;
        ensure(
            self.slippage_guards
                .contains_key(&conversion.slippage_guard_id),
            "missing slippage guard",
        )?;
        self.conversions
            .insert(conversion.conversion_id.clone(), conversion);
        Ok(())
    }
    pub fn insert_auction(&mut self, auction: BatchMigrationAuction) -> Result<()> {
        ensure_capacity(self.auctions.len(), self.config.max_auctions, "auctions")?;
        ensure(
            auction.min_privacy_set_size >= self.config.min_batch_privacy_set_size,
            "auction privacy too small",
        )?;
        ensure(
            auction.max_solver_fee_bps <= self.config.max_solver_fee_bps,
            "solver fee too high",
        )?;
        self.auctions.insert(auction.auction_id.clone(), auction);
        Ok(())
    }
    pub fn insert_bid(&mut self, bid: MigrationBid) -> Result<()> {
        ensure_capacity(self.bids.len(), self.config.max_bids, "bids")?;
        ensure(
            self.auctions.contains_key(&bid.auction_id),
            "missing auction",
        )?;
        ensure(
            bid.fee_bps <= self.config.max_solver_fee_bps,
            "bid fee too high",
        )?;
        ensure(bid.expected_fill_bps <= MAX_BPS, "fill bps too high")?;
        self.bids.insert(bid.bid_id.clone(), bid);
        Ok(())
    }
    pub fn insert_slippage_guard(&mut self, guard: SlippageGuard) -> Result<()> {
        ensure_capacity(
            self.slippage_guards.len(),
            self.config.max_slippage_guards,
            "slippage guards",
        )?;
        ensure(
            guard.max_slippage_bps <= self.config.max_slippage_bps,
            "guard slippage too high",
        )?;
        self.slippage_guards.insert(guard.guard_id.clone(), guard);
        Ok(())
    }
    pub fn insert_bridge_reserve_proof(&mut self, proof: BridgeReserveProof) -> Result<()> {
        ensure_capacity(
            self.reserve_proofs.len(),
            self.config.max_reserve_proofs,
            "reserve proofs",
        )?;
        ensure(
            proof.coverage_bps >= MAX_BPS,
            "reserve proof under-collateralized",
        )?;
        self.reserve_proofs.insert(proof.proof_id.clone(), proof);
        Ok(())
    }
    pub fn insert_nullifier_fence(&mut self, fence: NullifierPrivacyFence) -> Result<()> {
        ensure_capacity(
            self.nullifier_fences.len(),
            self.config.max_nullifier_fences,
            "nullifier fences",
        )?;
        ensure(
            fence.privacy_set_size >= self.config.min_privacy_set_size,
            "fence privacy too small",
        )?;
        ensure(
            !self.nullifier_fences.contains_key(&fence.fence_id),
            "duplicate nullifier fence",
        )?;
        self.nullifier_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }
    pub fn insert_fee_sponsor_coupon(&mut self, coupon: FeeSponsorCoupon) -> Result<()> {
        ensure_capacity(
            self.sponsor_coupons.len(),
            self.config.max_sponsor_coupons,
            "sponsor coupons",
        )?;
        ensure(
            coupon.covered_fee_bps <= self.config.sponsor_cover_bps,
            "coupon cover too high",
        )?;
        self.sponsor_coupons
            .insert(coupon.coupon_id.clone(), coupon);
        Ok(())
    }
    pub fn insert_reorg_anchor(&mut self, anchor: ReorgAnchor) -> Result<()> {
        ensure_capacity(
            self.reorg_anchors.len(),
            self.config.max_reorg_anchors,
            "reorg anchors",
        )?;
        ensure(
            anchor.l2_height >= anchor.monero_height,
            "anchor height inversion",
        )?;
        self.reorg_anchors.insert(anchor.anchor_id.clone(), anchor);
        Ok(())
    }
    pub fn insert_slashing_evidence(&mut self, evidence: SlashingEvidence) -> Result<()> {
        ensure_capacity(
            self.slashes.len(),
            self.config.max_slashes,
            "slashing evidence",
        )?;
        ensure(
            evidence.penalty_bps <= self.config.max_slash_bps,
            "penalty too high",
        )?;
        self.slashes.insert(evidence.evidence_id.clone(), evidence);
        Ok(())
    }
    pub fn push_event(&mut self, kind: &str, object_id: &str, height: u64) {
        if self.events.len() >= self.config.max_events {
            return;
        }
        let record_root = domain_hash(
            "monero-l2-pq-private-dex-liquidity-migration:event-record",
            &[
                HashPart::Str(kind),
                HashPart::Str(object_id),
                HashPart::U64(height),
            ],
            32,
        );
        let event_id = domain_hash(
            "monero-l2-pq-private-dex-liquidity-migration:event-id",
            &[
                HashPart::Str(kind),
                HashPart::Str(object_id),
                HashPart::U64(height),
                HashPart::U64(self.events.len() as u64),
            ],
            32,
        );
        self.events.push(RuntimeEvent {
            event_id,
            kind: kind.to_string(),
            object_id: object_id.to_string(),
            height,
            record_root,
        });
    }
    pub fn expire_at_height(&mut self, height: u64) {
        self.current_height = height;
        for intent in self.intents.values_mut() {
            if intent.expires_height <= height
                && !matches!(intent.status, IntentStatus::Settled | IntentStatus::Slashed)
            {
                intent.status = IntentStatus::Expired;
            }
        }
        for mirror in self.pool_mirrors.values_mut() {
            if mirror.expires_height <= height
                && !matches!(mirror.status, AttestationStatus::Slashed)
            {
                mirror.status = AttestationStatus::Expired;
            }
        }
        for auction in self.auctions.values_mut() {
            if auction.closes_height <= height
                && matches!(
                    auction.status,
                    AuctionStatus::Open | AuctionStatus::Sealed | AuctionStatus::Sponsored
                )
            {
                auction.status = AuctionStatus::Expired;
            }
        }
        for conversion in self.conversions.values_mut() {
            if conversion.expires_height <= height
                && !matches!(
                    conversion.status,
                    ConversionStatus::Settled | ConversionStatus::Slashed
                )
            {
                conversion.status = ConversionStatus::Expired;
            }
        }
    }
    pub fn apply_coupon_to_intent(&mut self, intent_id: &str, coupon_id: &str) -> Result<()> {
        let intent = self
            .intents
            .get_mut(intent_id)
            .ok_or_else(|| "missing intent".to_string())?;
        let coupon = self
            .sponsor_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| "missing coupon".to_string())?;
        ensure(!coupon.spent, "coupon already spent")?;
        ensure(
            coupon.expires_height > self.current_height,
            "coupon expired",
        )?;
        ensure(coupon.eligible_lane == intent.lane, "coupon lane mismatch")?;
        intent.coupon_id = Some(coupon_id.to_string());
        coupon.spent = true;
        self.push_event("coupon_applied", intent_id, self.current_height);
        Ok(())
    }
    pub fn select_bid(&mut self, auction_id: &str, bid_id: &str) -> Result<()> {
        let bid = self
            .bids
            .get_mut(bid_id)
            .ok_or_else(|| "missing bid".to_string())?;
        ensure(bid.auction_id == auction_id, "bid auction mismatch")?;
        ensure(
            bid.fee_bps <= self.config.max_solver_fee_bps,
            "bid fee too high",
        )?;
        bid.status = BidStatus::Selected;
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| "missing auction".to_string())?;
        auction.status = AuctionStatus::Clearing;
        auction.selected_bid_ids.insert(bid_id.to_string());
        self.push_event("bid_selected", bid_id, self.current_height);
        Ok(())
    }
    pub fn privacy_audit_record(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "height": self.current_height,
            "minimums": {
                "intent_privacy_set_size": self.min_intent_privacy_set_size(),
                "pool_mirror_privacy_set_size": self.min_pool_mirror_privacy_set_size(),
                "conversion_privacy_set_size": self.min_conversion_privacy_set_size(),
                "nullifier_fence_privacy_set_size": self.min_fence_privacy_set_size(),
                "pq_security_bits": self.min_observed_pq_security_bits()
            },
            "roots": self.roots().public_record(),
            "private_payload_policy": "roots_only"
        })
    }
    pub fn defi_liquidity_record(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "height": self.current_height,
            "lanes": self.lane_counts(),
            "target_pool_root": merkle_root(
                "monero-l2-pq-private-dex-liquidity-migration:target-pools",
                &self.intents
                    .values()
                    .map(|intent| Value::String(intent.target_pool_commitment.clone()))
                    .collect::<Vec<_>>()
            ),
            "legacy_pool_root": merkle_root(
                "monero-l2-pq-private-dex-liquidity-migration:legacy-pools",
                &self.intents
                    .values()
                    .map(|intent| Value::String(intent.legacy_pool_commitment.clone()))
                    .collect::<Vec<_>>()
            ),
            "low_fee_bps": self.config.low_fee_bps,
            "max_user_fee_bps": self.config.max_user_fee_bps
        })
    }
    pub fn lane_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::new();
        for intent in self.intents.values() {
            *counts.entry(intent.lane.as_str().to_string()).or_insert(0) += 1;
        }
        counts
    }
    pub fn min_intent_privacy_set_size(&self) -> u64 {
        self.intents
            .values()
            .map(|intent| intent.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size)
    }
    pub fn min_pool_mirror_privacy_set_size(&self) -> u64 {
        self.pool_mirrors
            .values()
            .map(|mirror| mirror.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size)
    }
    pub fn min_conversion_privacy_set_size(&self) -> u64 {
        self.conversions
            .values()
            .map(|conversion| conversion.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size)
    }
    pub fn min_fence_privacy_set_size(&self) -> u64 {
        self.nullifier_fences
            .values()
            .map(|fence| fence.privacy_set_size)
            .min()
            .unwrap_or(self.config.min_privacy_set_size)
    }
    pub fn min_observed_pq_security_bits(&self) -> u16 {
        let intent_bits = self
            .intents
            .values()
            .map(|intent| intent.pq_security_bits)
            .min()
            .unwrap_or(self.config.min_pq_security_bits);
        let mirror_bits = self
            .pool_mirrors
            .values()
            .map(|mirror| mirror.pq_security_bits)
            .min()
            .unwrap_or(self.config.min_pq_security_bits);
        intent_bits.min(mirror_bits)
    }
    pub fn active_intent_ids(&self) -> Vec<String> {
        self.intents
            .values()
            .filter(|intent| {
                matches!(
                    intent.status,
                    IntentStatus::Sealed
                        | IntentStatus::Fenced
                        | IntentStatus::Mirrored
                        | IntentStatus::Guarded
                        | IntentStatus::Auctioned
                        | IntentStatus::Converting
                )
            })
            .map(|intent| intent.intent_id.clone())
            .collect()
    }
    pub fn active_auction_ids(&self) -> Vec<String> {
        self.auctions
            .values()
            .filter(|auction| {
                matches!(
                    auction.status,
                    AuctionStatus::Open
                        | AuctionStatus::Sealed
                        | AuctionStatus::Sponsored
                        | AuctionStatus::Clearing
                        | AuctionStatus::Settling
                )
            })
            .map(|auction| auction.auction_id.clone())
            .collect()
    }
    pub fn selected_bid_ids(&self) -> Vec<String> {
        self.bids
            .values()
            .filter(|bid| matches!(bid.status, BidStatus::Selected | BidStatus::Filled))
            .map(|bid| bid.bid_id.clone())
            .collect()
    }
    pub fn reserve_coverage_floor_bps(&self) -> u64 {
        self.reserve_proofs
            .values()
            .map(|proof| proof.coverage_bps)
            .min()
            .unwrap_or(MAX_BPS)
    }
    pub fn unexpired_coupon_ids(&self) -> Vec<String> {
        self.sponsor_coupons
            .values()
            .filter(|coupon| !coupon.spent && coupon.expires_height > self.current_height)
            .map(|coupon| coupon.coupon_id.clone())
            .collect()
    }
    pub fn unexpired_anchor_ids(&self) -> Vec<String> {
        self.reorg_anchors
            .values()
            .filter(|anchor| {
                anchor
                    .l2_height
                    .saturating_add(self.config.reorg_anchor_depth)
                    >= self.current_height
            })
            .map(|anchor| anchor.anchor_id.clone())
            .collect()
    }
    pub fn validate_privacy_invariants(&self) -> Result<()> {
        ensure(
            self.min_intent_privacy_set_size() >= self.config.min_privacy_set_size,
            "intent privacy invariant failed",
        )?;
        ensure(
            self.min_pool_mirror_privacy_set_size() >= self.config.min_privacy_set_size,
            "pool mirror privacy invariant failed",
        )?;
        ensure(
            self.min_conversion_privacy_set_size() >= self.config.min_privacy_set_size,
            "conversion privacy invariant failed",
        )?;
        ensure(
            self.min_fence_privacy_set_size() >= self.config.min_privacy_set_size,
            "fence privacy invariant failed",
        )?;
        ensure(
            self.min_observed_pq_security_bits() >= self.config.min_pq_security_bits,
            "pq security invariant failed",
        )?;
        Ok(())
    }
    pub fn validate_fee_invariants(&self) -> Result<()> {
        ensure(
            self.config.low_fee_bps <= self.config.max_user_fee_bps,
            "low fee invariant failed",
        )?;
        ensure(
            self.config.max_user_fee_bps <= self.config.max_solver_fee_bps,
            "solver fee invariant failed",
        )?;
        for intent in self.intents.values() {
            ensure(
                intent.max_user_fee_bps <= self.config.max_user_fee_bps,
                "intent fee invariant failed",
            )?;
            ensure(
                intent.max_slippage_bps <= self.config.max_slippage_bps,
                "intent slippage invariant failed",
            )?;
        }
        for bid in self.bids.values() {
            ensure(
                bid.fee_bps <= self.config.max_solver_fee_bps,
                "bid fee invariant failed",
            )?;
        }
        Ok(())
    }
    pub fn validate_linkage_invariants(&self) -> Result<()> {
        for conversion in self.conversions.values() {
            ensure(
                self.intents.contains_key(&conversion.intent_id),
                "conversion intent link failed",
            )?;
            ensure(
                self.pool_mirrors
                    .contains_key(&conversion.mirror_attestation_id),
                "conversion mirror link failed",
            )?;
            ensure(
                self.reserve_proofs
                    .contains_key(&conversion.reserve_proof_id),
                "conversion reserve link failed",
            )?;
            ensure(
                self.slippage_guards
                    .contains_key(&conversion.slippage_guard_id),
                "conversion guard link failed",
            )?;
        }
        for bid in self.bids.values() {
            ensure(
                self.auctions.contains_key(&bid.auction_id),
                "bid auction link failed",
            )?;
        }
        Ok(())
    }
    pub fn validate_runtime_invariants(&self) -> Result<()> {
        self.config.validate()?;
        self.validate_privacy_invariants()?;
        self.validate_fee_invariants()?;
        self.validate_linkage_invariants()?;
        ensure(
            self.intents.len() <= self.config.max_intents,
            "intent capacity invariant failed",
        )?;
        ensure(
            self.pool_mirrors.len() <= self.config.max_pool_mirrors,
            "mirror capacity invariant failed",
        )?;
        ensure(
            self.conversions.len() <= self.config.max_conversions,
            "conversion capacity invariant failed",
        )?;
        ensure(
            self.auctions.len() <= self.config.max_auctions,
            "auction capacity invariant failed",
        )?;
        ensure(
            self.bids.len() <= self.config.max_bids,
            "bid capacity invariant failed",
        )?;
        ensure(
            self.events.len() <= self.config.max_events,
            "event capacity invariant failed",
        )?;
        Ok(())
    }
}

pub fn migration_intent_id(
    lane: MigrationLane,
    legacy_pool_commitment: &str,
    target_pool_commitment: &str,
    encrypted_payload_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:intent-id",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(legacy_pool_commitment),
            HashPart::Str(target_pool_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn pool_mirror_attestation_id(
    legacy_pool_commitment: &str,
    target_pool_commitment: &str,
    reserve_ratio_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:pool-mirror-id",
        &[
            HashPart::Str(legacy_pool_commitment),
            HashPart::Str(target_pool_commitment),
            HashPart::Str(reserve_ratio_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn lp_note_conversion_id(
    intent_id: &str,
    legacy_lp_nullifier_root: &str,
    target_lp_note_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:conversion-id",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(legacy_lp_nullifier_root),
            HashPart::Str(target_lp_note_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn batch_migration_auction_id(
    lane: MigrationLane,
    encrypted_intent_set_root: &str,
    target_pool_set_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:auction-id",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(encrypted_intent_set_root),
            HashPart::Str(target_pool_set_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn migration_bid_id(
    auction_id: &str,
    solver_commitment: &str,
    bid_commitment_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:bid-id",
        &[
            HashPart::Str(auction_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(bid_commitment_root),
        ],
        32,
    )
}
pub fn slippage_guard_id(intent_id: &str, quoted_price_root: &str, height: u64) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:slippage-guard-id",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(quoted_price_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn bridge_reserve_proof_id(
    target_pool_commitment: &str,
    monero_reserve_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:reserve-proof-id",
        &[
            HashPart::Str(target_pool_commitment),
            HashPart::Str(monero_reserve_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn nullifier_fence_id(kind: FenceKind, nullifier_root: &str, owner_commitment: &str) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:nullifier-fence-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(nullifier_root),
            HashPart::Str(owner_commitment),
        ],
        32,
    )
}
pub fn fee_sponsor_coupon_id(
    sponsor_commitment: &str,
    coupon_serial_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:fee-coupon-id",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(coupon_serial_root),
            HashPart::U64(height),
        ],
        32,
    )
}
pub fn reorg_anchor_id(monero_height: u64, l2_height: u64, migration_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:reorg-anchor-id",
        &[
            HashPart::U64(monero_height),
            HashPart::U64(l2_height),
            HashPart::Str(migration_root),
        ],
        32,
    )
}
pub fn slashing_evidence_id(
    reason: SlashingReason,
    accused_commitment: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:slashing-id",
        &[
            HashPart::Str(reason.as_str()),
            HashPart::Str(accused_commitment),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}
pub fn tagged_root(tag: &str) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:tagged-root",
        &[HashPart::Str(tag)],
        32,
    )
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-private-dex-liquidity-migration:state-root",
        &[HashPart::Json(record)],
        32,
    )
}
fn empty_root(label: &str) -> String {
    merkle_root(
        &format!("monero-l2-pq-private-dex-liquidity-migration:{label}"),
        &[],
    )
}
fn map_root<T>(label: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .values()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-dex-liquidity-migration:{label}"),
        &leaves,
    )
}
fn vec_root<T>(label: &str, values: &[T]) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .iter()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-private-dex-liquidity-migration:{label}"),
        &leaves,
    )
}
fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current < max {
        Ok(())
    } else {
        Err(format!("{label} capacity exceeded"))
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}
impl PublicRecord for EncryptedMigrationIntent {
    fn public_record(&self) -> Value {
        EncryptedMigrationIntent::public_record(self)
    }
}
impl PublicRecord for PoolMirrorAttestation {
    fn public_record(&self) -> Value {
        PoolMirrorAttestation::public_record(self)
    }
}
impl PublicRecord for LpNoteConversion {
    fn public_record(&self) -> Value {
        LpNoteConversion::public_record(self)
    }
}
impl PublicRecord for BatchMigrationAuction {
    fn public_record(&self) -> Value {
        BatchMigrationAuction::public_record(self)
    }
}
impl PublicRecord for MigrationBid {
    fn public_record(&self) -> Value {
        MigrationBid::public_record(self)
    }
}
impl PublicRecord for SlippageGuard {
    fn public_record(&self) -> Value {
        SlippageGuard::public_record(self)
    }
}
impl PublicRecord for BridgeReserveProof {
    fn public_record(&self) -> Value {
        BridgeReserveProof::public_record(self)
    }
}
impl PublicRecord for NullifierPrivacyFence {
    fn public_record(&self) -> Value {
        NullifierPrivacyFence::public_record(self)
    }
}
impl PublicRecord for FeeSponsorCoupon {
    fn public_record(&self) -> Value {
        FeeSponsorCoupon::public_record(self)
    }
}
impl PublicRecord for ReorgAnchor {
    fn public_record(&self) -> Value {
        ReorgAnchor::public_record(self)
    }
}
impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}
impl PublicRecord for RuntimeEvent {
    fn public_record(&self) -> Value {
        RuntimeEvent::public_record(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_has_stable_root() {
        let state = State::devnet();
        assert_eq!(state.config.protocol_version, PROTOCOL_VERSION);
        assert!(!state.state_root().is_empty());
        assert_eq!(state.counters().intents, 1);
    }
}
