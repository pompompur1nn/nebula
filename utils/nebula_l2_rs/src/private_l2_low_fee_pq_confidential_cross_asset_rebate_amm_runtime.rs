use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialCrossAssetRebateAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-cross-asset-rebate-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_HEIGHT: u64 =
    912_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_LOW_FEE_BPS:
    u64 = 3;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 16;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS:
    u64 = 2;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_LP_FEE_BPS:
    u64 = 4;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_REBATE_BPS:
    u64 = 8;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_REBATE_COVER_BPS:
    u64 = 9_250;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE:
    u64 = 131_072;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 192;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS:
    u64 = 32;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS:
    u64 = 48;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_BUCKET_TTL_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS:
    u64 = 6;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_ROUTE_HOPS:
    u8 = 6;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_BATCH_ITEMS:
    usize = 512;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MIN_LIQUIDITY_UNITS:
    u128 = 10_000;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_POOL_SKEW_BPS:
    u64 = 6_500;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_PRICE_IMPACT_BPS:
    u64 = 85;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_POOLS: usize =
    262_144;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_ROUTES: usize =
    524_288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_INTENTS: usize =
    1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BUCKETS: usize =
    524_288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_GUARDRAILS: usize =
    524_288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BATCHES: usize =
    524_288;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_NULLIFIERS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_EVENTS: usize =
    2_097_152;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID:
    &str = "wxmr-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID:
    &str = "private-usd-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID:
    &str = "nebula-fee-credit-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_FEE_ASSET_ID:
    &str = "piconero-devnet";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_POOL_SCHEME: &str =
    "confidential-cross-asset-constant-product-pool-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_ROUTE_SCHEME: &str =
    "privacy-preserving-cross-asset-rebate-route-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_INTENT_SCHEME: &str =
    "shielded-low-fee-swap-intent-nullifier-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_BUCKET_SCHEME: &str =
    "cross-asset-fee-credit-bucket-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_PQ_ATTESTATION_SCHEME:
    &str = "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f-confidential-amm-route-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_GUARDRAIL_SCHEME: &str =
    "confidential-amm-liquidity-guardrail-root-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_BATCH_SCHEME: &str =
    "low-fee-private-cross-asset-amm-batch-settlement-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_REPLAY_DOMAIN: &str =
    "private-l2-low-fee-pq-confidential-cross-asset-rebate-amm-devnet";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Active,
    Warmup,
    Paused,
    Degraded,
    Draining,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Warmup => "warmup",
            Self::Paused => "paused",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_swaps(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Active | Self::Warmup | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolCurve {
    ConstantProduct,
    Stable,
    Weighted,
    Concentrated,
}

impl PoolCurve {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::Stable => "stable",
            Self::Weighted => "weighted",
            Self::Concentrated => "concentrated",
        }
    }

    pub fn base_weight_bps(self) -> u64 {
        match self {
            Self::ConstantProduct | Self::Stable => 5_000,
            Self::Weighted => 6_000,
            Self::Concentrated => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    DirectAmm,
    TriangularAmm,
    RebateSweep,
    FeeCreditNetting,
    StablePeg,
    PrivacyRebalance,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectAmm => "direct_amm",
            Self::TriangularAmm => "triangular_amm",
            Self::RebateSweep => "rebate_sweep",
            Self::FeeCreditNetting => "fee_credit_netting",
            Self::StablePeg => "stable_peg",
            Self::PrivacyRebalance => "privacy_rebalance",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::RebateSweep => 960,
            Self::FeeCreditNetting => 920,
            Self::StablePeg => 860,
            Self::DirectAmm => 820,
            Self::TriangularAmm => 760,
            Self::PrivacyRebalance => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    PrivacyChecked,
    Routed,
    Attested,
    Batched,
    Settling,
    Settled,
    RebateCredited,
    Expired,
    Rejected,
    Cancelled,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PrivacyChecked => "privacy_checked",
            Self::Routed => "routed",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::RebateCredited => "rebate_credited",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::PrivacyChecked
                | Self::Routed
                | Self::Attested
                | Self::Batched
                | Self::Settling
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::RebateCredited | Self::Expired | Self::Rejected | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateLane {
    SponsoredLowFee,
    MakerRefresh,
    PrivacyBoost,
    CrossAssetSweep,
    StablePeg,
    EmergencyExit,
}

impl RebateLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::MakerRefresh => "maker_refresh",
            Self::PrivacyBoost => "privacy_boost",
            Self::CrossAssetSweep => "cross_asset_sweep",
            Self::StablePeg => "stable_peg",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee | Self::PrivacyBoost => config.low_fee_bps,
            Self::MakerRefresh => config.low_fee_bps.saturating_add(1),
            Self::CrossAssetSweep | Self::StablePeg => config.max_user_fee_bps / 2,
            Self::EmergencyExit => config.max_user_fee_bps,
        }
    }

    pub fn rebate_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.default_rebate_bps,
            Self::MakerRefresh => config.default_rebate_bps.saturating_add(2),
            Self::PrivacyBoost => config.default_rebate_bps.saturating_add(3),
            Self::CrossAssetSweep | Self::StablePeg => config.default_rebate_bps,
            Self::EmergencyExit => config.default_rebate_bps.saturating_mul(2),
        }
        .min(config.max_user_fee_bps)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Reserved,
    Crediting,
    Draining,
    Settled,
    Exhausted,
    Paused,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Crediting => "crediting",
            Self::Draining => "draining",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Crediting)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Verified,
    Bound,
    Consumed,
    Challenged,
    Expired,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Verified => "verified",
            Self::Bound => "bound",
            Self::Consumed => "consumed",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_bind(self) -> bool {
        matches!(self, Self::Proposed | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailStatus {
    Enforced,
    Warning,
    Degraded,
    Paused,
    Breached,
}

impl GuardrailStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Warning => "warning",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Breached => "breached",
        }
    }

    pub fn permits_settlement(self) -> bool {
        matches!(self, Self::Enforced | Self::Warning | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Attested,
    Executing,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub default_rebate_bps: u64,
    pub rebate_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub dispute_window_blocks: u64,
    pub max_route_hops: u8,
    pub max_batch_items: usize,
    pub min_liquidity_units: u128,
    pub max_pool_skew_bps: u64,
    pub max_price_impact_bps: u64,
    pub hash_suite: String,
    pub pq_attestation_scheme: String,
    pub replay_domain: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_SCHEMA_VERSION,
            devnet_height:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_HEIGHT,
            low_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            protocol_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_LP_FEE_BPS,
            default_rebate_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_REBATE_BPS,
            rebate_cover_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_REBATE_COVER_BPS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            intent_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            bucket_ttl_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_BUCKET_TTL_BLOCKS,
            settlement_window_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            dispute_window_blocks:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            max_route_hops:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_ROUTE_HOPS,
            max_batch_items:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_liquidity_units:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MIN_LIQUIDITY_UNITS,
            max_pool_skew_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_POOL_SKEW_BPS,
            max_price_impact_bps:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEFAULT_MAX_PRICE_IMPACT_BPS,
            hash_suite:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_HASH_SUITE
                    .to_string(),
            pq_attestation_scheme:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_PQ_ATTESTATION_SCHEME
                    .to_string(),
            replay_domain:
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_REPLAY_DOMAIN
                    .to_string(),
        }
    }
}

impl Config {
    pub fn low_fee_total_bps(&self) -> u64 {
        self.low_fee_bps
            .saturating_add(self.protocol_fee_bps)
            .saturating_add(self.lp_fee_bps)
            .min(self.max_user_fee_bps)
    }

    pub fn validate(&self) -> Result<()> {
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("low fee bps exceeds max user fee bps".to_string());
        }
        if self.max_user_fee_bps
            > PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BPS
        {
            return Err("max user fee bps exceeds bps denominator".to_string());
        }
        if self.rebate_cover_bps
            > PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BPS
        {
            return Err("rebate cover bps exceeds bps denominator".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_privacy_set_size > self.target_privacy_set_size
        {
            return Err("invalid privacy set thresholds".to_string());
        }
        if self.min_pq_security_bits == 0
            || self.min_pq_security_bits > self.target_pq_security_bits
        {
            return Err("invalid pq security thresholds".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub pools: u64,
    pub routes: u64,
    pub intents: u64,
    pub buckets: u64,
    pub attestations: u64,
    pub guardrails: u64,
    pub batches: u64,
    pub settled_swaps: u64,
    pub rebate_credits: u64,
    pub replay_fences: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "pools": self.pools,
            "routes": self.routes,
            "intents": self.intents,
            "buckets": self.buckets,
            "attestations": self.attestations,
            "guardrails": self.guardrails,
            "batches": self.batches,
            "settled_swaps": self.settled_swaps,
            "rebate_credits": self.rebate_credits,
            "replay_fences": self.replay_fences,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub pools_root: String,
    pub routes_root: String,
    pub intents_root: String,
    pub buckets_root: String,
    pub attestations_root: String,
    pub guardrails_root: String,
    pub batches_root: String,
    pub replay_fences_root: String,
    pub event_root: String,
    pub operator_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "pools_root": self.pools_root,
            "routes_root": self.routes_root,
            "intents_root": self.intents_root,
            "buckets_root": self.buckets_root,
            "attestations_root": self.attestations_root,
            "guardrails_root": self.guardrails_root,
            "batches_root": self.batches_root,
            "replay_fences_root": self.replay_fences_root,
            "event_root": self.event_root,
            "operator_root": self.operator_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ConfidentialAmmPool {
    pub pool_id: String,
    pub asset_a: String,
    pub asset_b: String,
    pub encrypted_reserve_a_commitment: String,
    pub encrypted_reserve_b_commitment: String,
    pub reserve_a_units: u128,
    pub reserve_b_units: u128,
    pub lp_supply_commitment: String,
    pub curve: PoolCurve,
    pub status: PoolStatus,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub rebate_lane: RebateLane,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub last_reprice_height: u64,
    pub cumulative_volume_units: u128,
}

impl ConfidentialAmmPool {
    pub fn new(
        pool_id: impl Into<String>,
        asset_a: impl Into<String>,
        asset_b: impl Into<String>,
        reserve_a_units: u128,
        reserve_b_units: u128,
        curve: PoolCurve,
        config: &Config,
    ) -> Self {
        let pool_id = pool_id.into();
        let asset_a = asset_a.into();
        let asset_b = asset_b.into();
        Self {
            encrypted_reserve_a_commitment: commitment(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_POOL_SCHEME,
                &[&pool_id, &asset_a, "reserve-a"],
            ),
            encrypted_reserve_b_commitment: commitment(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_POOL_SCHEME,
                &[&pool_id, &asset_b, "reserve-b"],
            ),
            lp_supply_commitment: commitment(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_POOL_SCHEME,
                &[&pool_id, "lp-supply"],
            ),
            pool_id,
            asset_a,
            asset_b,
            reserve_a_units,
            reserve_b_units,
            curve,
            status: PoolStatus::Active,
            fee_bps: config.low_fee_total_bps(),
            protocol_fee_bps: config.protocol_fee_bps,
            rebate_lane: RebateLane::SponsoredLowFee,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.target_pq_security_bits,
            last_reprice_height: config.devnet_height,
            cumulative_volume_units: 0,
        }
    }

    pub fn contains_asset(&self, asset_id: &str) -> bool {
        self.asset_a == asset_id || self.asset_b == asset_id
    }

    pub fn other_asset(&self, asset_id: &str) -> Option<&str> {
        if self.asset_a == asset_id {
            Some(&self.asset_b)
        } else if self.asset_b == asset_id {
            Some(&self.asset_a)
        } else {
            None
        }
    }

    pub fn reserve_for(&self, asset_id: &str) -> Option<u128> {
        if self.asset_a == asset_id {
            Some(self.reserve_a_units)
        } else if self.asset_b == asset_id {
            Some(self.reserve_b_units)
        } else {
            None
        }
    }

    pub fn notional_liquidity(&self) -> u128 {
        self.reserve_a_units.saturating_add(self.reserve_b_units)
    }

    pub fn invariant(&self) -> u128 {
        self.reserve_a_units.saturating_mul(self.reserve_b_units)
    }

    pub fn pool_skew_bps(&self) -> u64 {
        let total = self.notional_liquidity();
        if total == 0 {
            return 0;
        }
        let larger = self.reserve_a_units.max(self.reserve_b_units);
        ((larger.saturating_mul(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BPS as u128,
        )) / total) as u64
    }

    pub fn estimated_out(&self, input_asset: &str, input_units: u128) -> Option<u128> {
        if input_units == 0 || !self.status.accepts_swaps() {
            return None;
        }
        let (reserve_in, reserve_out) = if self.asset_a == input_asset {
            (self.reserve_a_units, self.reserve_b_units)
        } else if self.asset_b == input_asset {
            (self.reserve_b_units, self.reserve_a_units)
        } else {
            return None;
        };
        let fee_denom =
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BPS as u128;
        let effective_input =
            input_units.saturating_mul(fee_denom.saturating_sub(self.fee_bps as u128)) / fee_denom;
        let numerator = effective_input.saturating_mul(reserve_out);
        let denominator = reserve_in.saturating_add(effective_input);
        if denominator == 0 {
            None
        } else {
            Some(numerator / denominator)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "asset_a": self.asset_a,
            "asset_b": self.asset_b,
            "reserve_a_commitment": self.encrypted_reserve_a_commitment,
            "reserve_b_commitment": self.encrypted_reserve_b_commitment,
            "lp_supply_commitment": self.lp_supply_commitment,
            "curve": self.curve.as_str(),
            "status": self.status.as_str(),
            "fee_bps": self.fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "rebate_lane": self.rebate_lane.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "last_reprice_height": self.last_reprice_height,
            "liquidity_commitment": commitment("pool-public-liquidity", &[&self.pool_id]),
            "volume_commitment": commitment("pool-public-volume", &[&self.pool_id]),
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_POOL_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RouteHop {
    pub pool_id: String,
    pub input_asset: String,
    pub output_asset: String,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
}

impl RouteHop {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "input_asset": self.input_asset,
            "output_asset": self.output_asset,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CrossAssetRebateRoute {
    pub route_id: String,
    pub route_kind: RouteKind,
    pub source_asset: String,
    pub target_asset: String,
    pub rebate_asset: String,
    pub hops: Vec<RouteHop>,
    pub privacy_floor: u64,
    pub total_fee_bps: u64,
    pub total_rebate_bps: u64,
    pub route_commitment: String,
    pub fee_credit_bucket_id: String,
    pub route_nullifier_domain: String,
    pub priority_weight: u64,
    pub enabled: bool,
}

impl CrossAssetRebateRoute {
    pub fn new(
        route_id: impl Into<String>,
        route_kind: RouteKind,
        source_asset: impl Into<String>,
        target_asset: impl Into<String>,
        rebate_asset: impl Into<String>,
        hops: Vec<RouteHop>,
        bucket_id: impl Into<String>,
        config: &Config,
    ) -> Self {
        let route_id = route_id.into();
        let source_asset = source_asset.into();
        let target_asset = target_asset.into();
        let rebate_asset = rebate_asset.into();
        let total_fee_bps = hops
            .iter()
            .fold(0u64, |acc, hop| acc.saturating_add(hop.max_fee_bps))
            .min(config.max_user_fee_bps);
        let total_rebate_bps = hops
            .iter()
            .fold(0u64, |acc, hop| acc.saturating_add(hop.rebate_bps))
            .min(config.max_user_fee_bps);
        Self {
            route_commitment: commitment(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_ROUTE_SCHEME,
                &[&route_id, &source_asset, &target_asset, &rebate_asset],
            ),
            fee_credit_bucket_id: bucket_id.into(),
            route_nullifier_domain: commitment("route-nullifier-domain", &[&route_id]),
            privacy_floor: config.min_privacy_set_size,
            priority_weight: route_kind.priority_weight(),
            route_id,
            route_kind,
            source_asset,
            target_asset,
            rebate_asset,
            hops,
            total_fee_bps,
            total_rebate_bps,
            enabled: true,
        }
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn is_low_fee(&self, config: &Config) -> bool {
        self.total_fee_bps <= config.max_user_fee_bps / 2
    }

    pub fn validates_assets(&self) -> bool {
        if self.hops.is_empty() {
            return false;
        }
        let mut expected = self.source_asset.as_str();
        for hop in &self.hops {
            if hop.input_asset != expected {
                return false;
            }
            expected = &hop.output_asset;
        }
        expected == self.target_asset
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "route_kind": self.route_kind.as_str(),
            "source_asset": self.source_asset,
            "target_asset": self.target_asset,
            "rebate_asset": self.rebate_asset,
            "hops": self.hops.iter().map(RouteHop::public_record).collect::<Vec<_>>(),
            "privacy_floor": self.privacy_floor,
            "total_fee_bps": self.total_fee_bps,
            "total_rebate_bps": self.total_rebate_bps,
            "route_commitment": self.route_commitment,
            "fee_credit_bucket_id": self.fee_credit_bucket_id,
            "route_nullifier_domain": self.route_nullifier_domain,
            "priority_weight": self.priority_weight,
            "enabled": self.enabled,
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_ROUTE_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SwapIntent {
    pub intent_id: String,
    pub route_id: String,
    pub input_asset: String,
    pub output_asset: String,
    pub rebate_asset: String,
    pub input_note_commitment: String,
    pub min_output_note_commitment: String,
    pub owner_view_tag_commitment: String,
    pub amount_in_commitment: String,
    pub min_amount_out_commitment: String,
    pub max_fee_bps: u64,
    pub max_price_impact_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: IntentStatus,
    pub nullifier: String,
    pub replay_fence: String,
}

impl SwapIntent {
    pub fn new(
        intent_id: impl Into<String>,
        route: &CrossAssetRebateRoute,
        config: &Config,
    ) -> Self {
        let intent_id = intent_id.into();
        Self {
            input_note_commitment: commitment("intent-input-note", &[&intent_id]),
            min_output_note_commitment: commitment("intent-min-output-note", &[&intent_id]),
            owner_view_tag_commitment: commitment("intent-owner-view-tag", &[&intent_id]),
            amount_in_commitment: commitment("intent-amount-in", &[&intent_id]),
            min_amount_out_commitment: commitment("intent-min-amount-out", &[&intent_id]),
            nullifier: commitment("intent-nullifier", &[&intent_id, &route.route_id]),
            replay_fence: commitment("intent-replay-fence", &[&intent_id, &config.replay_domain]),
            route_id: route.route_id.clone(),
            input_asset: route.source_asset.clone(),
            output_asset: route.target_asset.clone(),
            rebate_asset: route.rebate_asset.clone(),
            max_fee_bps: route.total_fee_bps,
            max_price_impact_bps: config.max_price_impact_bps,
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.target_pq_security_bits,
            submitted_height: config.devnet_height,
            expires_height: config.devnet_height + config.intent_ttl_blocks,
            status: IntentStatus::Submitted,
            intent_id,
        }
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "route_id": self.route_id,
            "input_asset": self.input_asset,
            "output_asset": self.output_asset,
            "rebate_asset": self.rebate_asset,
            "input_note_commitment": self.input_note_commitment,
            "min_output_note_commitment": self.min_output_note_commitment,
            "owner_view_tag_commitment": self.owner_view_tag_commitment,
            "amount_in_commitment": self.amount_in_commitment,
            "min_amount_out_commitment": self.min_amount_out_commitment,
            "max_fee_bps": self.max_fee_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "nullifier": self.nullifier,
            "replay_fence": self.replay_fence,
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_INTENT_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FeeCreditBucket {
    pub bucket_id: String,
    pub asset_id: String,
    pub rebate_lane: RebateLane,
    pub sponsor_commitment: String,
    pub available_credit_units: u128,
    pub reserved_credit_units: u128,
    pub credited_units: u128,
    pub status: BucketStatus,
    pub opened_height: u64,
    pub expires_height: u64,
    pub min_privacy_set_size: u64,
    pub bucket_root_commitment: String,
}

impl FeeCreditBucket {
    pub fn new(
        bucket_id: impl Into<String>,
        asset_id: impl Into<String>,
        lane: RebateLane,
        available_credit_units: u128,
        config: &Config,
    ) -> Self {
        let bucket_id = bucket_id.into();
        let asset_id = asset_id.into();
        Self {
            sponsor_commitment: commitment("fee-credit-sponsor", &[&bucket_id, &asset_id]),
            bucket_root_commitment: commitment(
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_BUCKET_SCHEME,
                &[&bucket_id, &asset_id],
            ),
            bucket_id,
            asset_id,
            rebate_lane: lane,
            available_credit_units,
            reserved_credit_units: 0,
            credited_units: 0,
            status: BucketStatus::Open,
            opened_height: config.devnet_height,
            expires_height: config.devnet_height + config.bucket_ttl_blocks,
            min_privacy_set_size: config.min_privacy_set_size,
        }
    }

    pub fn reserve(&mut self, units: u128) -> Result<()> {
        if !self.status.usable() {
            return Err("fee credit bucket is not usable".to_string());
        }
        if self.available_credit_units < units {
            return Err("insufficient fee credit bucket balance".to_string());
        }
        self.available_credit_units = self.available_credit_units.saturating_sub(units);
        self.reserved_credit_units = self.reserved_credit_units.saturating_add(units);
        self.status = BucketStatus::Reserved;
        Ok(())
    }

    pub fn credit(&mut self, units: u128) -> Result<()> {
        if self.reserved_credit_units < units {
            return Err("reserved credit below requested credit".to_string());
        }
        self.reserved_credit_units = self.reserved_credit_units.saturating_sub(units);
        self.credited_units = self.credited_units.saturating_add(units);
        self.status = if self.available_credit_units == 0 && self.reserved_credit_units == 0 {
            BucketStatus::Exhausted
        } else {
            BucketStatus::Crediting
        };
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "asset_id": self.asset_id,
            "rebate_lane": self.rebate_lane.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "available_credit_commitment": commitment("fee-credit-available", &[&self.bucket_id]),
            "reserved_credit_commitment": commitment("fee-credit-reserved", &[&self.bucket_id]),
            "credited_commitment": commitment("fee-credit-credited", &[&self.bucket_id]),
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "bucket_root_commitment": self.bucket_root_commitment,
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_BUCKET_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PqRouteAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub intent_id: String,
    pub operator_id: String,
    pub pq_scheme: String,
    pub ml_kem_ciphertext_commitment: String,
    pub ml_dsa_signature_commitment: String,
    pub slh_dsa_signature_commitment: String,
    pub route_transcript_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl PqRouteAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        route_id: impl Into<String>,
        intent_id: impl Into<String>,
        operator_id: impl Into<String>,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let route_id = route_id.into();
        let intent_id = intent_id.into();
        let operator_id = operator_id.into();
        Self {
            ml_kem_ciphertext_commitment: commitment(
                "attestation-ml-kem",
                &[&attestation_id, &route_id],
            ),
            ml_dsa_signature_commitment: commitment(
                "attestation-ml-dsa",
                &[&attestation_id, &operator_id],
            ),
            slh_dsa_signature_commitment: commitment(
                "attestation-slh-dsa",
                &[&attestation_id, &operator_id],
            ),
            route_transcript_root: commitment(
                "attestation-route-transcript",
                &[&attestation_id, &intent_id],
            ),
            pq_scheme: config.pq_attestation_scheme.clone(),
            privacy_set_size: config.target_privacy_set_size,
            pq_security_bits: config.target_pq_security_bits,
            status: AttestationStatus::Verified,
            issued_height: config.devnet_height,
            expires_height: config.devnet_height + config.attestation_ttl_blocks,
            attestation_id,
            route_id,
            intent_id,
            operator_id,
        }
    }

    pub fn satisfies(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_privacy_set_size
            && self.pq_security_bits >= config.min_pq_security_bits
            && matches!(
                self.status,
                AttestationStatus::Verified | AttestationStatus::Bound
            )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "operator_id": self.operator_id,
            "pq_scheme": self.pq_scheme,
            "ml_kem_ciphertext_commitment": self.ml_kem_ciphertext_commitment,
            "ml_dsa_signature_commitment": self.ml_dsa_signature_commitment,
            "slh_dsa_signature_commitment": self.slh_dsa_signature_commitment,
            "route_transcript_root": self.route_transcript_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_PQ_ATTESTATION_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct LiquidityGuardrail {
    pub guardrail_id: String,
    pub pool_id: String,
    pub min_liquidity_units: u128,
    pub max_pool_skew_bps: u64,
    pub max_price_impact_bps: u64,
    pub observed_liquidity_commitment: String,
    pub observed_skew_bps: u64,
    pub observed_price_impact_bps: u64,
    pub status: GuardrailStatus,
    pub last_checked_height: u64,
}

impl LiquidityGuardrail {
    pub fn for_pool(
        guardrail_id: impl Into<String>,
        pool: &ConfidentialAmmPool,
        config: &Config,
    ) -> Self {
        let guardrail_id = guardrail_id.into();
        let observed_skew_bps = pool.pool_skew_bps();
        let observed_price_impact_bps = if pool.notional_liquidity() < config.min_liquidity_units {
            config.max_price_impact_bps.saturating_add(1)
        } else {
            config.max_price_impact_bps / 2
        };
        let status = if pool.notional_liquidity() < config.min_liquidity_units {
            GuardrailStatus::Breached
        } else if observed_skew_bps > config.max_pool_skew_bps {
            GuardrailStatus::Warning
        } else {
            GuardrailStatus::Enforced
        };
        Self {
            observed_liquidity_commitment: commitment(
                "guardrail-observed-liquidity",
                &[&guardrail_id, &pool.pool_id],
            ),
            guardrail_id,
            pool_id: pool.pool_id.clone(),
            min_liquidity_units: config.min_liquidity_units,
            max_pool_skew_bps: config.max_pool_skew_bps,
            max_price_impact_bps: config.max_price_impact_bps,
            observed_skew_bps,
            observed_price_impact_bps,
            status,
            last_checked_height: config.devnet_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guardrail_id": self.guardrail_id,
            "pool_id": self.pool_id,
            "min_liquidity_commitment": commitment("guardrail-min-liquidity", &[&self.guardrail_id]),
            "max_pool_skew_bps": self.max_pool_skew_bps,
            "max_price_impact_bps": self.max_price_impact_bps,
            "observed_liquidity_commitment": self.observed_liquidity_commitment,
            "observed_skew_bps": self.observed_skew_bps,
            "observed_price_impact_bps": self.observed_price_impact_bps,
            "status": self.status.as_str(),
            "last_checked_height": self.last_checked_height,
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_GUARDRAIL_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BatchSettlement {
    pub batch_id: String,
    pub route_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub bucket_ids: Vec<String>,
    pub batch_transcript_root: String,
    pub encrypted_netting_root: String,
    pub rebate_credit_root: String,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub settlement_height: u64,
    pub total_fee_bps: u64,
    pub total_rebate_bps: u64,
}

impl BatchSettlement {
    pub fn new(
        batch_id: impl Into<String>,
        route_ids: Vec<String>,
        intent_ids: Vec<String>,
        attestation_ids: Vec<String>,
        bucket_ids: Vec<String>,
        config: &Config,
    ) -> Self {
        let batch_id = batch_id.into();
        Self {
            batch_transcript_root: commitment("batch-transcript", &[&batch_id]),
            encrypted_netting_root: commitment("batch-encrypted-netting", &[&batch_id]),
            rebate_credit_root: commitment("batch-rebate-credit", &[&batch_id]),
            batch_id,
            route_ids,
            intent_ids,
            attestation_ids,
            bucket_ids,
            status: BatchStatus::Sealed,
            opened_height: config.devnet_height,
            settlement_height: config.devnet_height + config.settlement_window_blocks,
            total_fee_bps: config.low_fee_total_bps(),
            total_rebate_bps: config.default_rebate_bps,
        }
    }

    pub fn item_count(&self) -> usize {
        self.intent_ids.len()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "route_ids": self.route_ids,
            "intent_ids": self.intent_ids,
            "attestation_ids": self.attestation_ids,
            "bucket_ids": self.bucket_ids,
            "batch_transcript_root": self.batch_transcript_root,
            "encrypted_netting_root": self.encrypted_netting_root,
            "rebate_credit_root": self.rebate_credit_root,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "settlement_height": self.settlement_height,
            "total_fee_bps": self.total_fee_bps,
            "total_rebate_bps": self.total_rebate_bps,
            "item_count": self.item_count(),
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json(
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_BATCH_SCHEME,
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub pq_key_commitment: String,
    pub route_count: u64,
    pub attestation_count: u64,
    pub settled_batch_count: u64,
    pub total_rebate_units_commitment: String,
    pub low_fee_score: u64,
    pub privacy_score: u64,
    pub active: bool,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>) -> Self {
        let operator_id = operator_id.into();
        Self {
            pq_key_commitment: commitment("operator-pq-key", &[&operator_id]),
            total_rebate_units_commitment: commitment("operator-rebate-units", &[&operator_id]),
            operator_id,
            route_count: 0,
            attestation_count: 0,
            settled_batch_count: 0,
            low_fee_score: 1_000,
            privacy_score: 1_000,
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "pq_key_commitment": self.pq_key_commitment,
            "route_count": self.route_count,
            "attestation_count": self.attestation_count,
            "settled_batch_count": self.settled_batch_count,
            "total_rebate_units_commitment": self.total_rebate_units_commitment,
            "low_fee_score": self.low_fee_score,
            "privacy_score": self.privacy_score,
            "active": self.active,
        })
    }

    pub fn root_leaf(&self) -> String {
        hash_json("operator-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, ConfidentialAmmPool>,
    pub routes: BTreeMap<String, CrossAssetRebateRoute>,
    pub intents: BTreeMap<String, SwapIntent>,
    pub fee_credit_buckets: BTreeMap<String, FeeCreditBucket>,
    pub pq_route_attestations: BTreeMap<String, PqRouteAttestation>,
    pub liquidity_guardrails: BTreeMap<String, LiquidityGuardrail>,
    pub batch_settlements: BTreeMap<String, BatchSettlement>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub replay_fences: BTreeSet<String>,
    pub public_events: Vec<String>,
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
            pools: BTreeMap::new(),
            routes: BTreeMap::new(),
            intents: BTreeMap::new(),
            fee_credit_buckets: BTreeMap::new(),
            pq_route_attestations: BTreeMap::new(),
            liquidity_guardrails: BTreeMap::new(),
            batch_settlements: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            replay_fences: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::default());
        state.install_devnet_fixtures();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let route_ids = state.routes.keys().cloned().collect::<Vec<_>>();
        for (index, route_id) in route_ids.iter().enumerate() {
            if let Some(route) = state.routes.get(route_id).cloned() {
                let intent_id = format!("demo-intent-{index:02}");
                let mut intent = SwapIntent::new(intent_id.clone(), &route, &state.config);
                intent.status = if index % 2 == 0 {
                    IntentStatus::Attested
                } else {
                    IntentStatus::Routed
                };
                let _ = state.insert_intent(intent);
                let attestation = PqRouteAttestation::new(
                    format!("demo-attestation-{index:02}"),
                    route.route_id,
                    intent_id,
                    "operator-devnet-01",
                    &state.config,
                );
                let _ = state.insert_attestation(attestation);
            }
        }
        let batch = BatchSettlement::new(
            "demo-batch-00",
            state.routes.keys().take(2).cloned().collect(),
            state.intents.keys().take(2).cloned().collect(),
            state
                .pq_route_attestations
                .keys()
                .take(2)
                .cloned()
                .collect(),
            state.fee_credit_buckets.keys().take(2).cloned().collect(),
            &state.config,
        );
        let _ = state.insert_batch(batch);
        state
            .public_events
            .push("demo settlement batch sealed with roots-only rebate credits".to_string());
        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn insert_pool(&mut self, pool: ConfidentialAmmPool) -> Result<()> {
        ensure_capacity(
            self.pools.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_POOLS,
            "pools",
        )?;
        if pool.reserve_a_units < self.config.min_liquidity_units
            || pool.reserve_b_units < self.config.min_liquidity_units
        {
            return Err("pool reserve below minimum liquidity units".to_string());
        }
        self.pools.insert(pool.pool_id.clone(), pool);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_route(&mut self, route: CrossAssetRebateRoute) -> Result<()> {
        ensure_capacity(
            self.routes.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_ROUTES,
            "routes",
        )?;
        if route.hop_count() == 0 || route.hop_count() > self.config.max_route_hops as usize {
            return Err("route hop count outside configured bounds".to_string());
        }
        if !route.validates_assets() {
            return Err("route hop assets do not connect source to target".to_string());
        }
        self.routes.insert(route.route_id.clone(), route);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_intent(&mut self, intent: SwapIntent) -> Result<()> {
        ensure_capacity(
            self.intents.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_INTENTS,
            "intents",
        )?;
        if self.replay_fences.contains(&intent.replay_fence) {
            return Err("duplicate swap intent replay fence".to_string());
        }
        if intent.privacy_set_size < self.config.min_privacy_set_size {
            return Err("intent privacy set below configured minimum".to_string());
        }
        if intent.pq_security_bits < self.config.min_pq_security_bits {
            return Err("intent pq security bits below configured minimum".to_string());
        }
        self.replay_fences.insert(intent.replay_fence.clone());
        self.intents.insert(intent.intent_id.clone(), intent);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_fee_credit_bucket(&mut self, bucket: FeeCreditBucket) -> Result<()> {
        ensure_capacity(
            self.fee_credit_buckets.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BUCKETS,
            "fee credit buckets",
        )?;
        self.fee_credit_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_attestation(&mut self, attestation: PqRouteAttestation) -> Result<()> {
        ensure_capacity(
            self.pq_route_attestations.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_ATTESTATIONS,
            "pq route attestations",
        )?;
        if !attestation.satisfies(&self.config) {
            return Err("pq route attestation below privacy or pq threshold".to_string());
        }
        self.pq_route_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_guardrail(&mut self, guardrail: LiquidityGuardrail) -> Result<()> {
        ensure_capacity(
            self.liquidity_guardrails.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_GUARDRAILS,
            "liquidity guardrails",
        )?;
        self.liquidity_guardrails
            .insert(guardrail.guardrail_id.clone(), guardrail);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_batch(&mut self, batch: BatchSettlement) -> Result<()> {
        ensure_capacity(
            self.batch_settlements.len(),
            PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_MAX_BATCHES,
            "batch settlements",
        )?;
        if batch.item_count() > self.config.max_batch_items {
            return Err("batch item count exceeds configured maximum".to_string());
        }
        self.batch_settlements.insert(batch.batch_id.clone(), batch);
        self.refresh_counters();
        self.refresh_roots();
        Ok(())
    }

    pub fn quote_swap(&self, pool_id: &str, input_asset: &str, input_units: u128) -> Result<u128> {
        let pool = self
            .pools
            .get(pool_id)
            .ok_or_else(|| "unknown pool for quote".to_string())?;
        pool.estimated_out(input_asset, input_units)
            .ok_or_else(|| "unable to quote swap for pool and input asset".to_string())
    }

    pub fn route_score(&self, route_id: &str) -> Result<u64> {
        let route = self
            .routes
            .get(route_id)
            .ok_or_else(|| "unknown route for score".to_string())?;
        let low_fee_bonus = if route.is_low_fee(&self.config) {
            200
        } else {
            0
        };
        let privacy_bonus = route
            .privacy_floor
            .saturating_mul(100)
            .checked_div(self.config.target_privacy_set_size.max(1))
            .unwrap_or(0);
        Ok(route
            .priority_weight
            .saturating_add(low_fee_bonus)
            .saturating_add(privacy_bonus)
            .saturating_sub(route.total_fee_bps))
    }

    pub fn operator_summary(&self, operator_id: &str) -> Option<OperatorSummary> {
        self.operator_summaries
            .get(operator_id)
            .cloned()
            .map(|mut summary| {
                summary.attestation_count = self
                    .pq_route_attestations
                    .values()
                    .filter(|attestation| attestation.operator_id == operator_id)
                    .count() as u64;
                summary.settled_batch_count = self
                    .batch_settlements
                    .values()
                    .filter(|batch| matches!(batch.status, BatchStatus::Settled))
                    .count() as u64;
                summary
            })
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn refresh_counters(&mut self) {
        self.counters = Counters {
            pools: self.pools.len() as u64,
            routes: self.routes.len() as u64,
            intents: self.intents.len() as u64,
            buckets: self.fee_credit_buckets.len() as u64,
            attestations: self.pq_route_attestations.len() as u64,
            guardrails: self.liquidity_guardrails.len() as u64,
            batches: self.batch_settlements.len() as u64,
            settled_swaps: self
                .intents
                .values()
                .filter(|intent| {
                    matches!(
                        intent.status,
                        IntentStatus::Settled | IntentStatus::RebateCredited
                    )
                })
                .count() as u64,
            rebate_credits: self
                .fee_credit_buckets
                .values()
                .map(|bucket| bucket.credited_units > 0)
                .filter(|credited| *credited)
                .count() as u64,
            replay_fences: self.replay_fences.len() as u64,
            events: self.public_events.len() as u64,
        };
    }

    pub fn refresh_roots(&mut self) {
        self.roots.pools_root =
            merkle_root_from(self.pools.values().map(ConfidentialAmmPool::root_leaf));
        self.roots.routes_root =
            merkle_root_from(self.routes.values().map(CrossAssetRebateRoute::root_leaf));
        self.roots.intents_root =
            merkle_root_from(self.intents.values().map(SwapIntent::root_leaf));
        self.roots.buckets_root = merkle_root_from(
            self.fee_credit_buckets
                .values()
                .map(FeeCreditBucket::root_leaf),
        );
        self.roots.attestations_root = merkle_root_from(
            self.pq_route_attestations
                .values()
                .map(PqRouteAttestation::root_leaf),
        );
        self.roots.guardrails_root = merkle_root_from(
            self.liquidity_guardrails
                .values()
                .map(LiquidityGuardrail::root_leaf),
        );
        self.roots.batches_root = merkle_root_from(
            self.batch_settlements
                .values()
                .map(BatchSettlement::root_leaf),
        );
        self.roots.replay_fences_root = merkle_root_from(self.replay_fences.iter().cloned());
        self.roots.event_root = merkle_root_from(self.public_events.iter().cloned());
        self.roots.operator_root = merkle_root_from(
            self.operator_summaries
                .values()
                .map(OperatorSummary::root_leaf),
        );
        self.roots.state_root = hash_json(
            "private-l2-low-fee-pq-confidential-cross-asset-rebate-amm-state-root",
            &json!({
                "protocol_version": self.config.protocol_version,
                "pools_root": self.roots.pools_root,
                "routes_root": self.roots.routes_root,
                "intents_root": self.roots.intents_root,
                "buckets_root": self.roots.buckets_root,
                "attestations_root": self.roots.attestations_root,
                "guardrails_root": self.roots.guardrails_root,
                "batches_root": self.roots.batches_root,
                "replay_fences_root": self.roots.replay_fences_root,
                "event_root": self.roots.event_root,
                "operator_root": self.roots.operator_root,
            }),
        );
    }

    fn install_devnet_fixtures(&mut self) {
        let config = self.config.clone();
        let pools = vec![
            ConfidentialAmmPool::new(
                "pool-wxmr-private-usd",
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID,
                4_000_000_000_000,
                640_000_000_000,
                PoolCurve::ConstantProduct,
                &config,
            ),
            ConfidentialAmmPool::new(
                "pool-private-usd-fee-credit",
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                720_000_000_000,
                720_000_000_000,
                PoolCurve::Stable,
                &config,
            ),
            ConfidentialAmmPool::new(
                "pool-wxmr-fee-credit",
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                3_200_000_000_000,
                600_000_000_000,
                PoolCurve::Weighted,
                &config,
            ),
        ];
        for pool in pools {
            let guardrail =
                LiquidityGuardrail::for_pool(format!("guardrail-{}", pool.pool_id), &pool, &config);
            let _ = self.insert_pool(pool);
            let _ = self.insert_guardrail(guardrail);
        }

        let buckets = vec![
            FeeCreditBucket::new(
                "bucket-sponsored-low-fee-wxmr",
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID,
                RebateLane::SponsoredLowFee,
                2_000_000_000,
                &config,
            ),
            FeeCreditBucket::new(
                "bucket-cross-asset-sweep-usd",
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID,
                RebateLane::CrossAssetSweep,
                3_500_000_000,
                &config,
            ),
            FeeCreditBucket::new(
                "bucket-privacy-boost-credit",
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                RebateLane::PrivacyBoost,
                5_000_000_000,
                &config,
            ),
        ];
        for bucket in buckets {
            let _ = self.insert_fee_credit_bucket(bucket);
        }

        let routes = vec![
            CrossAssetRebateRoute::new(
                "route-wxmr-to-private-usd-sponsored",
                RouteKind::DirectAmm,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                vec![RouteHop {
                    pool_id: "pool-wxmr-private-usd".to_string(),
                    input_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID.to_string(),
                    output_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID.to_string(),
                    max_fee_bps: config.low_fee_bps,
                    rebate_bps: RebateLane::SponsoredLowFee.rebate_bps(&config),
                }],
                "bucket-sponsored-low-fee-wxmr",
                &config,
            ),
            CrossAssetRebateRoute::new(
                "route-private-usd-to-fee-credit-sweep",
                RouteKind::RebateSweep,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                vec![RouteHop {
                    pool_id: "pool-private-usd-fee-credit".to_string(),
                    input_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID.to_string(),
                    output_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID.to_string(),
                    max_fee_bps: config.low_fee_bps,
                    rebate_bps: RebateLane::CrossAssetSweep.rebate_bps(&config),
                }],
                "bucket-cross-asset-sweep-usd",
                &config,
            ),
            CrossAssetRebateRoute::new(
                "route-wxmr-to-fee-credit-triangular",
                RouteKind::TriangularAmm,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID,
                vec![
                    RouteHop {
                        pool_id: "pool-wxmr-private-usd".to_string(),
                        input_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_BASE_ASSET_ID.to_string(),
                        output_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID.to_string(),
                        max_fee_bps: config.low_fee_bps,
                        rebate_bps: RebateLane::PrivacyBoost.rebate_bps(&config),
                    },
                    RouteHop {
                        pool_id: "pool-private-usd-fee-credit".to_string(),
                        input_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_QUOTE_ASSET_ID.to_string(),
                        output_asset: PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_DEVNET_REBATE_ASSET_ID.to_string(),
                        max_fee_bps: config.low_fee_bps,
                        rebate_bps: RebateLane::PrivacyBoost.rebate_bps(&config),
                    },
                ],
                "bucket-privacy-boost-credit",
                &config,
            ),
        ];
        for route in routes {
            let _ = self.insert_route(route);
        }

        let mut operator = OperatorSummary::new("operator-devnet-01");
        operator.route_count = self.routes.len() as u64;
        self.operator_summaries
            .insert(operator.operator_id.clone(), operator);
        self.public_events.push(
            "devnet low-fee confidential cross-asset rebate AMM fixtures installed".to_string(),
        );
        self.refresh_counters();
        self.refresh_roots();
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
        "devnet_height": state.config.devnet_height,
        "fee_policy": {
            "low_fee_bps": state.config.low_fee_bps,
            "max_user_fee_bps": state.config.max_user_fee_bps,
            "protocol_fee_bps": state.config.protocol_fee_bps,
            "lp_fee_bps": state.config.lp_fee_bps,
            "default_rebate_bps": state.config.default_rebate_bps,
            "rebate_cover_bps": state.config.rebate_cover_bps,
        },
        "privacy_policy": {
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "target_privacy_set_size": state.config.target_privacy_set_size,
            "min_pq_security_bits": state.config.min_pq_security_bits,
            "target_pq_security_bits": state.config.target_pq_security_bits,
            "pq_attestation_scheme": state.config.pq_attestation_scheme,
        },
        "roots": state.roots.public_record(),
        "counters": state.counters.public_record(),
        "pools": state.pools.values().map(ConfidentialAmmPool::public_record).collect::<Vec<_>>(),
        "routes": state.routes.values().map(CrossAssetRebateRoute::public_record).collect::<Vec<_>>(),
        "intents": state.intents.values().map(SwapIntent::public_record).collect::<Vec<_>>(),
        "fee_credit_buckets": state.fee_credit_buckets.values().map(FeeCreditBucket::public_record).collect::<Vec<_>>(),
        "pq_route_attestations": state.pq_route_attestations.values().map(PqRouteAttestation::public_record).collect::<Vec<_>>(),
        "liquidity_guardrails": state.liquidity_guardrails.values().map(LiquidityGuardrail::public_record).collect::<Vec<_>>(),
        "batch_settlements": state.batch_settlements.values().map(BatchSettlement::public_record).collect::<Vec<_>>(),
        "operator_summaries": state.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
        "replay_fences_root": state.roots.replay_fences_root,
        "event_root": state.roots.event_root,
    })
}

pub fn state_root(state: &State) -> String {
    hash_json(
        "private-l2-low-fee-pq-confidential-cross-asset-rebate-amm-public-state-root",
        &public_record(state),
    )
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let mut hash_parts = Vec::with_capacity(parts.len() + 1);
    hash_parts.push(HashPart::Str(domain));
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(domain, &hash_parts, 32)
}

fn hash_json(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Str(domain), HashPart::Json(value)], 32)
}

fn merkle_root_from<I>(leaves: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = leaves.into_iter().collect::<Vec<_>>();
    if leaves.is_empty() {
        domain_hash(
            "empty-private-l2-low-fee-pq-confidential-cross-asset-rebate-amm-root",
            &[HashPart::Str("empty")],
            32,
        )
    } else {
        let leaves = leaves.into_iter().map(Value::String).collect::<Vec<_>>();
        merkle_root(
            "private-l2-low-fee-pq-confidential-cross-asset-rebate-amm-merkle-root",
            &leaves,
        )
    }
}

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_CROSS_ASSET_REBATE_AMM_RUNTIME_GENERATED_NOTES:
    &[&str] = &[
    "000: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "001: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "002: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "003: generated policy note: confidential reserves publish commitments instead of balances",
    "004: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "005: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "006: generated policy note: liquidity guardrails cap price impact before route selection",
    "007: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "008: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "009: generated policy note: operator summaries expose service quality without route secrets",
    "010: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "011: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "012: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "013: generated policy note: confidential reserves publish commitments instead of balances",
    "014: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "015: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "016: generated policy note: liquidity guardrails cap price impact before route selection",
    "017: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "018: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "019: generated policy note: operator summaries expose service quality without route secrets",
    "020: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "021: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "022: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "023: generated policy note: confidential reserves publish commitments instead of balances",
    "024: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "025: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "026: generated policy note: liquidity guardrails cap price impact before route selection",
    "027: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "028: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "029: generated policy note: operator summaries expose service quality without route secrets",
    "030: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "031: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "032: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "033: generated policy note: confidential reserves publish commitments instead of balances",
    "034: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "035: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "036: generated policy note: liquidity guardrails cap price impact before route selection",
    "037: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "038: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "039: generated policy note: operator summaries expose service quality without route secrets",
    "040: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "041: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "042: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "043: generated policy note: confidential reserves publish commitments instead of balances",
    "044: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "045: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "046: generated policy note: liquidity guardrails cap price impact before route selection",
    "047: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "048: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "049: generated policy note: operator summaries expose service quality without route secrets",
    "050: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "051: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "052: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "053: generated policy note: confidential reserves publish commitments instead of balances",
    "054: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "055: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "056: generated policy note: liquidity guardrails cap price impact before route selection",
    "057: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "058: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "059: generated policy note: operator summaries expose service quality without route secrets",
    "060: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "061: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "062: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "063: generated policy note: confidential reserves publish commitments instead of balances",
    "064: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "065: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "066: generated policy note: liquidity guardrails cap price impact before route selection",
    "067: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "068: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "069: generated policy note: operator summaries expose service quality without route secrets",
    "070: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "071: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "072: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "073: generated policy note: confidential reserves publish commitments instead of balances",
    "074: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "075: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "076: generated policy note: liquidity guardrails cap price impact before route selection",
    "077: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "078: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "079: generated policy note: operator summaries expose service quality without route secrets",
    "080: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "081: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "082: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "083: generated policy note: confidential reserves publish commitments instead of balances",
    "084: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "085: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "086: generated policy note: liquidity guardrails cap price impact before route selection",
    "087: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "088: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "089: generated policy note: operator summaries expose service quality without route secrets",
    "090: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "091: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "092: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "093: generated policy note: confidential reserves publish commitments instead of balances",
    "094: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "095: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "096: generated policy note: liquidity guardrails cap price impact before route selection",
    "097: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "098: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "099: generated policy note: operator summaries expose service quality without route secrets",
    "100: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "101: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "102: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "103: generated policy note: confidential reserves publish commitments instead of balances",
    "104: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "105: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "106: generated policy note: liquidity guardrails cap price impact before route selection",
    "107: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "108: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "109: generated policy note: operator summaries expose service quality without route secrets",
    "110: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "111: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "112: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "113: generated policy note: confidential reserves publish commitments instead of balances",
    "114: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "115: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "116: generated policy note: liquidity guardrails cap price impact before route selection",
    "117: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "118: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "119: generated policy note: operator summaries expose service quality without route secrets",
    "120: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "121: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "122: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "123: generated policy note: confidential reserves publish commitments instead of balances",
    "124: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "125: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "126: generated policy note: liquidity guardrails cap price impact before route selection",
    "127: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "128: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "129: generated policy note: operator summaries expose service quality without route secrets",
    "130: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "131: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "132: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "133: generated policy note: confidential reserves publish commitments instead of balances",
    "134: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "135: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "136: generated policy note: liquidity guardrails cap price impact before route selection",
    "137: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "138: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "139: generated policy note: operator summaries expose service quality without route secrets",
    "140: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "141: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "142: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "143: generated policy note: confidential reserves publish commitments instead of balances",
    "144: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "145: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "146: generated policy note: liquidity guardrails cap price impact before route selection",
    "147: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "148: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "149: generated policy note: operator summaries expose service quality without route secrets",
    "150: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "151: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "152: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "153: generated policy note: confidential reserves publish commitments instead of balances",
    "154: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "155: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "156: generated policy note: liquidity guardrails cap price impact before route selection",
    "157: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "158: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "159: generated policy note: operator summaries expose service quality without route secrets",
    "160: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "161: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "162: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "163: generated policy note: confidential reserves publish commitments instead of balances",
    "164: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "165: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "166: generated policy note: liquidity guardrails cap price impact before route selection",
    "167: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "168: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "169: generated policy note: operator summaries expose service quality without route secrets",
    "170: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "171: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "172: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "173: generated policy note: confidential reserves publish commitments instead of balances",
    "174: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "175: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "176: generated policy note: liquidity guardrails cap price impact before route selection",
    "177: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "178: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "179: generated policy note: operator summaries expose service quality without route secrets",
    "180: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "181: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "182: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "183: generated policy note: confidential reserves publish commitments instead of balances",
    "184: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "185: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "186: generated policy note: liquidity guardrails cap price impact before route selection",
    "187: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "188: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "189: generated policy note: operator summaries expose service quality without route secrets",
    "190: generated policy note: low fee AMM routing keeps amounts shielded and exports roots only",
    "191: generated policy note: fee credit buckets rebate users without revealing swap notional",
    "192: generated policy note: PQ attestations bind route transcripts before batch settlement",
    "193: generated policy note: confidential reserves publish commitments instead of balances",
    "194: generated policy note: cross-asset rebates can settle in a separate shielded asset",
    "195: generated policy note: replay fences are rooted so operators can reject duplicate intents",
    "196: generated policy note: liquidity guardrails cap price impact before route selection",
    "197: generated policy note: batch roots separate netting, route, and rebate credit transcripts",
    "198: generated policy note: low fee lanes prioritize sponsored swaps with privacy floors",
    "199: generated policy note: operator summaries expose service quality without route secrets",
];
