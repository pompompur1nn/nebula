use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PqPrivateLiquidityMirrorRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-liquidity-mirror-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_HEIGHT: u64 = 742_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_POOL_SCHEME: &str =
    "roots-only-monero-l2-pq-private-liquidity-mirror-pool-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_RESERVE_SCHEME: &str =
    "ml-kem-1024-sealed-private-monero-reserve-snapshot-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_CUSTODIAN_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-pq-custodian-liquidity-attestation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_INTENT_SCHEME: &str =
    "ml-kem-1024-encrypted-private-liquidity-intent-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_SPONSOR_SCHEME: &str =
    "low-fee-private-liquidity-sponsor-reservation-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_REBALANCE_SCHEME: &str =
    "fast-private-monero-liquidity-mirror-rebalance-batch-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_RECEIPT_SCHEME: &str =
    "defi-private-liquidity-mirror-receipt-rebate-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-private-liquidity-mirror-nullifier-fence-root-v1";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-liquidity-mirror-devnet";
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_POOL_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 12;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_REBALANCE_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS: u64 = 144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 =
    10_800;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 =
    13_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_CUSTODIAN_COUNT: u64 = 3;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_CUSTODIAN_QUORUM_BPS: u64 = 6_700;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_LP_FEE_BPS: u64 = 9;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_REBATE_BPS: u64 = 7;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 1_024;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_POOLS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_SNAPSHOTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_INTENTS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_SPONSOR_RESERVATIONS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_BATCHES: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_RECEIPTS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_REBATES: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_FENCES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorLane {
    SponsoredLowFee,
    Standard,
    Fast,
    Defi,
    Rebalance,
    ReserveAudit,
    Emergency,
}

impl MirrorLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Rebalance => "rebalance",
            Self::ReserveAudit => "reserve_audit",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee | Self::ReserveAudit => config.low_fee_bps,
            Self::Rebalance => config.max_user_fee_bps / 2,
            Self::Defi => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::Standard => config.max_user_fee_bps.saturating_mul(3) / 4,
            Self::Fast | Self::Emergency => config.max_user_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::SponsoredLowFee => 900,
            Self::Defi => 830,
            Self::Rebalance => 780,
            Self::Standard => 640,
            Self::ReserveAudit => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ConstantProduct,
    StableSwap,
    WeightedBasket,
    ExitReserve,
    IntentDarkpool,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::StableSwap => "stable_swap",
            Self::WeightedBasket => "weighted_basket",
            Self::ExitReserve => "exit_reserve",
            Self::IntentDarkpool => "intent_darkpool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Active,
    Degraded,
    Rebalancing,
    Paused,
    Draining,
    Slashed,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Rebalancing => "rebalancing",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Submitted,
    CustodianAttested,
    QuorumAttested,
    Mirrored,
    Expired,
    Disputed,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::CustodianAttested => "custodian_attested",
            Self::QuorumAttested => "quorum_attested",
            Self::Mirrored => "mirrored",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    AddLiquidity,
    RemoveLiquidity,
    Swap,
    PrivateExit,
    PrivateEntry,
    Rebalance,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Swap => "swap",
            Self::PrivateExit => "private_exit",
            Self::PrivateEntry => "private_entry",
            Self::Rebalance => "rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Reserved,
    Matched,
    Batched,
    Settled,
    Expired,
    Cancelled,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Encrypted | Self::Reserved | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceStatus {
    Open,
    Sealed,
    Submitted,
    Settled,
    Disputed,
    Expired,
}

impl RebalanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Final,
    RebateIssued,
    Disputed,
    Reversed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Final => "final",
            Self::RebateIssued => "rebate_issued",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub mirrored_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pool_scheme: String,
    pub reserve_scheme: String,
    pub custodian_scheme: String,
    pub intent_scheme: String,
    pub sponsor_scheme: String,
    pub rebalance_scheme: String,
    pub receipt_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub pool_ttl_blocks: u64,
    pub snapshot_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub rebalance_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub min_custodian_count: u64,
    pub custodian_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_batch_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            mirrored_asset_id: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_ASSET_ID
                .to_string(),
            fee_asset_id: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_HASH_SUITE.to_string(),
            pool_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_POOL_SCHEME.to_string(),
            reserve_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_RESERVE_SCHEME
                .to_string(),
            custodian_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_CUSTODIAN_SCHEME
                .to_string(),
            intent_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_INTENT_SCHEME.to_string(),
            sponsor_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            rebalance_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_REBALANCE_SCHEME
                .to_string(),
            receipt_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            nullifier_scheme: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_REPLAY_DOMAIN.to_string(),
            pool_ttl_blocks: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_POOL_TTL_BLOCKS,
            snapshot_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS,
            intent_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            sponsor_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_SPONSOR_TTL_BLOCKS,
            rebalance_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_REBALANCE_TTL_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            min_custodian_count:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_CUSTODIAN_COUNT,
            custodian_quorum_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_CUSTODIAN_QUORUM_BPS,
            strong_quorum_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_STRONG_QUORUM_BPS,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            lp_fee_bps: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_LP_FEE_BPS,
            rebate_bps: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_REBATE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_batch_items: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub pools: u64,
    pub snapshots: u64,
    pub attestations: u64,
    pub intents: u64,
    pub sponsor_reservations: u64,
    pub rebalance_batches: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub fences: u64,
    pub public_records: u64,
    pub events: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub pool_root: String,
    pub active_pool_root: String,
    pub reserve_snapshot_root: String,
    pub custodian_attestation_root: String,
    pub encrypted_intent_root: String,
    pub open_intent_root: String,
    pub sponsor_reservation_root: String,
    pub rebalance_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            pool_root: merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-POOLS", &[]),
            active_pool_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-ACTIVE-POOLS",
                &[],
            ),
            reserve_snapshot_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-RESERVE-SNAPSHOTS",
                &[],
            ),
            custodian_attestation_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-CUSTODIAN-ATTESTATIONS",
                &[],
            ),
            encrypted_intent_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-ENCRYPTED-INTENTS",
                &[],
            ),
            open_intent_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-OPEN-INTENTS",
                &[],
            ),
            sponsor_reservation_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-SPONSOR-RESERVATIONS",
                &[],
            ),
            rebalance_batch_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-REBALANCE-BATCHES",
                &[],
            ),
            receipt_root: merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-RECEIPTS", &[]),
            rebate_root: merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-REBATES", &[]),
            privacy_fence_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVACY-FENCES",
                &[],
            ),
            nullifier_root: merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-NULLIFIERS", &[]),
            event_root: merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-EVENTS", &[]),
            public_record_root: domain_hash(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PUBLIC-RECORD-ROOT",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&json!({ "empty": true })),
                ],
                32,
            ),
            state_root: domain_hash(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-STATE-ROOT",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Json(&json!({ "empty": true })),
                ],
                32,
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirroredLiquidityPool {
    pub pool_id: String,
    pub pool_kind: PoolKind,
    pub status: PoolStatus,
    pub lane: MirrorLane,
    pub monero_reserve_commitment: String,
    pub l2_mirror_commitment: String,
    pub lp_commitment_root: String,
    pub fee_commitment_root: String,
    pub encrypted_parameter_root: String,
    pub privacy_set_size: u64,
    pub reserve_coverage_bps: u64,
    pub pq_security_bits: u16,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl MirroredLiquidityPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "pool_kind": self.pool_kind.as_str(),
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "monero_reserve_commitment": self.monero_reserve_commitment,
            "l2_mirror_commitment": self.l2_mirror_commitment,
            "lp_commitment_root": self.lp_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "encrypted_parameter_root": self.encrypted_parameter_root,
            "privacy_set_size": self.privacy_set_size,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "pq_security_bits": self.pq_security_bits,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateReserveSnapshot {
    pub snapshot_id: String,
    pub pool_id: String,
    pub status: SnapshotStatus,
    pub reserve_commitment_root: String,
    pub view_tag_root: String,
    pub output_membership_root: String,
    pub encrypted_balance_root: String,
    pub coverage_bps: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl PrivateReserveSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "reserve_commitment_root": self.reserve_commitment_root,
            "view_tag_root": self.view_tag_root,
            "output_membership_root": self.output_membership_root,
            "encrypted_balance_root": self.encrypted_balance_root,
            "coverage_bps": self.coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCustodianAttestation {
    pub attestation_id: String,
    pub snapshot_id: String,
    pub custodian_id: String,
    pub custodian_weight: u64,
    pub pq_signature_root: String,
    pub verification_key_root: String,
    pub reserve_claim_root: String,
    pub audited_height: u64,
    pub pq_security_bits: u16,
    pub accepted: bool,
}

impl PqCustodianAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "snapshot_id": self.snapshot_id,
            "custodian_id": self.custodian_id,
            "custodian_weight": self.custodian_weight,
            "pq_signature_root": self.pq_signature_root,
            "verification_key_root": self.verification_key_root,
            "reserve_claim_root": self.reserve_claim_root,
            "audited_height": self.audited_height,
            "pq_security_bits": self.pq_security_bits,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedLiquidityIntent {
    pub intent_id: String,
    pub pool_id: String,
    pub intent_kind: IntentKind,
    pub status: IntentStatus,
    pub lane: MirrorLane,
    pub sender_nullifier: String,
    pub amount_commitment: String,
    pub min_output_commitment: String,
    pub encrypted_route_root: String,
    pub kem_ciphertext_hash: String,
    pub sponsor_hint_root: String,
    pub fee_bps: u64,
    pub priority_weight: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl EncryptedLiquidityIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "pool_id": self.pool_id,
            "intent_kind": self.intent_kind.as_str(),
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "sender_nullifier": self.sender_nullifier,
            "amount_commitment": self.amount_commitment,
            "min_output_commitment": self.min_output_commitment,
            "encrypted_route_root": self.encrypted_route_root,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "sponsor_hint_root": self.sponsor_hint_root,
            "fee_bps": self.fee_bps,
            "priority_weight": self.priority_weight,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub intent_id: String,
    pub sponsor_id: String,
    pub status: ReservationStatus,
    pub reserved_fee_units: u64,
    pub cover_bps: u64,
    pub credential_nullifier: String,
    pub sponsor_commitment_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "intent_id": self.intent_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "reserved_fee_units": self.reserved_fee_units,
            "cover_bps": self.cover_bps,
            "credential_nullifier": self.credential_nullifier,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorRebalanceBatch {
    pub batch_id: String,
    pub status: RebalanceStatus,
    pub lane: MirrorLane,
    pub pool_root: String,
    pub intent_root: String,
    pub snapshot_root: String,
    pub sponsor_root: String,
    pub settlement_commitment_root: String,
    pub solver_commitment: String,
    pub item_count: usize,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl MirrorRebalanceBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "pool_root": self.pool_root,
            "intent_root": self.intent_root,
            "snapshot_root": self.snapshot_root,
            "sponsor_root": self.sponsor_root,
            "settlement_commitment_root": self.settlement_commitment_root,
            "solver_commitment": self.solver_commitment,
            "item_count": self.item_count,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub pool_id: String,
    pub status: ReceiptStatus,
    pub fill_commitment: String,
    pub paid_fee_commitment: String,
    pub rebate_commitment: String,
    pub settlement_root: String,
    pub finalized_at_height: u64,
    pub sequence: u64,
}

impl MirrorReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "fill_commitment": self.fill_commitment,
            "paid_fee_commitment": self.paid_fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "settlement_root": self.settlement_root,
            "finalized_at_height": self.finalized_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub sponsor_id: String,
    pub rebate_commitment: String,
    pub claim_nullifier: String,
    pub expires_at_height: u64,
    pub sequence: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "sponsor_id": self.sponsor_id,
            "rebate_commitment": self.rebate_commitment,
            "claim_nullifier": self.claim_nullifier,
            "expires_at_height": self.expires_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub nullifier: String,
    pub domain: String,
    pub anchor_root: String,
    pub opened_at_height: u64,
    pub sequence: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "domain": self.domain,
            "anchor_root": self.anchor_root,
            "opened_at_height": self.opened_at_height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityMirrorSummary {
    pub chain_id: String,
    pub protocol_version: String,
    pub height: u64,
    pub pool_count: usize,
    pub active_pool_count: usize,
    pub snapshot_count: usize,
    pub attestation_count: usize,
    pub open_intent_count: usize,
    pub sponsor_reservation_count: usize,
    pub rebalance_batch_count: usize,
    pub receipt_count: usize,
    pub rebate_count: usize,
    pub nullifier_count: usize,
    pub aggregate_privacy_set_size: u64,
    pub min_observed_reserve_coverage_bps: u64,
    pub max_fee_bps: u64,
    pub roots: Roots,
}

impl LiquidityMirrorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "height": self.height,
            "pool_count": self.pool_count,
            "active_pool_count": self.active_pool_count,
            "snapshot_count": self.snapshot_count,
            "attestation_count": self.attestation_count,
            "open_intent_count": self.open_intent_count,
            "sponsor_reservation_count": self.sponsor_reservation_count,
            "rebalance_batch_count": self.rebalance_batch_count,
            "receipt_count": self.receipt_count,
            "rebate_count": self.rebate_count,
            "nullifier_count": self.nullifier_count,
            "aggregate_privacy_set_size": self.aggregate_privacy_set_size,
            "min_observed_reserve_coverage_bps": self.min_observed_reserve_coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "roots": self.roots,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveHealth {
    pub pool_id: String,
    pub status: PoolStatus,
    pub latest_snapshot_id: Option<String>,
    pub latest_snapshot_height: Option<u64>,
    pub accepted_attestation_weight: u64,
    pub accepted_attestation_count: u64,
    pub coverage_bps: u64,
    pub privacy_set_size: u64,
    pub quorum_met: bool,
    pub strong_quorum_met: bool,
    pub pq_ready: bool,
}

impl ReserveHealth {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "status": self.status.as_str(),
            "latest_snapshot_id": self.latest_snapshot_id,
            "latest_snapshot_height": self.latest_snapshot_height,
            "accepted_attestation_weight": self.accepted_attestation_weight,
            "accepted_attestation_count": self.accepted_attestation_count,
            "coverage_bps": self.coverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "quorum_met": self.quorum_met,
            "strong_quorum_met": self.strong_quorum_met,
            "pq_ready": self.pq_ready,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentFeeQuote {
    pub quote_id: String,
    pub lane: MirrorLane,
    pub intent_kind: IntentKind,
    pub amount_commitment: String,
    pub user_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub priority_weight: u64,
    pub expires_at_height: u64,
}

impl IntentFeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "lane": self.lane.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "amount_commitment": self.amount_commitment,
            "user_fee_bps": self.user_fee_bps,
            "lp_fee_bps": self.lp_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "priority_weight": self.priority_weight,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicLedgerView {
    pub config_root: String,
    pub counter_root: String,
    pub root_root: String,
    pub pool_root: String,
    pub reserve_health_root: String,
    pub private_flow_root: String,
    pub fee_flow_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PublicLedgerView {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "root_root": self.root_root,
            "pool_root": self.pool_root,
            "reserve_health_root": self.reserve_health_root,
            "private_flow_root": self.private_flow_root,
            "fee_flow_root": self.fee_flow_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub pools: BTreeMap<String, MirroredLiquidityPool>,
    pub reserve_snapshots: BTreeMap<String, PrivateReserveSnapshot>,
    pub custodian_attestations: BTreeMap<String, PqCustodianAttestation>,
    pub encrypted_intents: BTreeMap<String, EncryptedLiquidityIntent>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub rebalance_batches: BTreeMap<String, MirrorRebalanceBatch>,
    pub receipts: BTreeMap<String, MirrorReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: Vec<Value>,
    pub events: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            height: MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_DEVNET_HEIGHT,
            pools: BTreeMap::new(),
            reserve_snapshots: BTreeMap::new(),
            custodian_attestations: BTreeMap::new(),
            encrypted_intents: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            rebalance_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: Vec::new(),
            events: Vec::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let h = state.height;
        let pool_a = state.sample_pool(
            "devnet-xmr-usdc",
            PoolKind::StableSwap,
            MirrorLane::Defi,
            h,
            1,
        );
        let pool_b = state.sample_pool(
            "devnet-xmr-fast-exit",
            PoolKind::ExitReserve,
            MirrorLane::SponsoredLowFee,
            h,
            2,
        );
        state.insert_pool(pool_a);
        state.insert_pool(pool_b);

        let pool_ids: Vec<String> = state.pools.keys().cloned().collect();
        for (idx, pool_id) in pool_ids.iter().enumerate() {
            let sequence = (idx as u64) + 1;
            let snapshot = state.sample_snapshot(pool_id, h + sequence, sequence);
            state.insert_snapshot(snapshot.clone());
            for custodian_index in 0..3 {
                let attestation = state.sample_attestation(
                    &snapshot.snapshot_id,
                    &format!("devnet-custodian-{}", custodian_index + 1),
                    h + sequence + custodian_index,
                    sequence + custodian_index,
                );
                state.insert_attestation(attestation);
            }
        }

        let intent_a = state.sample_intent(
            &pool_ids[0],
            IntentKind::Swap,
            MirrorLane::Defi,
            "devnet-swap-note-a",
            h + 8,
            1,
        );
        let intent_b = state.sample_intent(
            &pool_ids[1],
            IntentKind::PrivateExit,
            MirrorLane::SponsoredLowFee,
            "devnet-exit-note-b",
            h + 9,
            2,
        );
        state.insert_intent(intent_a.clone());
        state.insert_intent(intent_b.clone());

        let reservation =
            state.sample_reservation(&intent_b.intent_id, "devnet-sponsor-1", h + 10, 1);
        state.insert_sponsor_reservation(reservation.clone());

        let batch_intent_ids = vec![intent_a.intent_id, intent_b.intent_id];
        let batch = state.sample_rebalance_batch(&pool_ids, &batch_intent_ids, h + 12, 1);
        state.insert_rebalance_batch(batch.clone());

        for (idx, intent_id) in batch_intent_ids.iter().enumerate() {
            if let Some(intent) = state.encrypted_intents.get(intent_id).cloned() {
                let receipt = state.sample_receipt(
                    &batch.batch_id,
                    &intent,
                    h + 16 + idx as u64,
                    idx as u64 + 1,
                );
                state.insert_receipt(receipt.clone());
                let rebate = state.sample_rebate(
                    &receipt.receipt_id,
                    "devnet-sponsor-1",
                    h + 16,
                    idx as u64 + 1,
                );
                state.insert_rebate(rebate);
            }
        }

        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.config.schema_version,
            "height": self.height,
            "config": self.config,
            "counters": self.counters,
            "roots": {
                "pool_root": self.roots.pool_root,
                "active_pool_root": self.roots.active_pool_root,
                "reserve_snapshot_root": self.roots.reserve_snapshot_root,
                "custodian_attestation_root": self.roots.custodian_attestation_root,
                "encrypted_intent_root": self.roots.encrypted_intent_root,
                "open_intent_root": self.roots.open_intent_root,
                "sponsor_reservation_root": self.roots.sponsor_reservation_root,
                "rebalance_batch_root": self.roots.rebalance_batch_root,
                "receipt_root": self.roots.receipt_root,
                "rebate_root": self.roots.rebate_root,
                "privacy_fence_root": self.roots.privacy_fence_root,
                "nullifier_root": self.roots.nullifier_root,
                "event_root": self.roots.event_root,
                "public_record_root": self.roots.public_record_root,
            },
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn validate_config(&self) -> MoneroL2PqPrivateLiquidityMirrorRuntimeResult<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("config chain_id does not match crate CHAIN_ID".to_string());
        }
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("config protocol_version does not match runtime protocol".to_string());
        }
        if self.config.schema_version
            != MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_SCHEMA_VERSION
        {
            return Err("config schema_version does not match runtime schema".to_string());
        }
        if self.config.low_fee_bps > self.config.max_user_fee_bps {
            return Err("low_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.config.max_user_fee_bps > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_BPS {
            return Err("max_user_fee_bps exceeds max bps".to_string());
        }
        if self.config.lp_fee_bps > self.config.max_user_fee_bps {
            return Err("lp_fee_bps exceeds max_user_fee_bps".to_string());
        }
        if self.config.rebate_bps > self.config.max_user_fee_bps {
            return Err("rebate_bps exceeds max_user_fee_bps".to_string());
        }
        if self.config.sponsor_cover_bps > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_BPS {
            return Err("sponsor_cover_bps exceeds max bps".to_string());
        }
        if self.config.min_reserve_coverage_bps > self.config.target_reserve_coverage_bps {
            return Err("min_reserve_coverage_bps exceeds target".to_string());
        }
        if self.config.min_pq_security_bits > self.config.target_pq_security_bits {
            return Err("min_pq_security_bits exceeds target_pq_security_bits".to_string());
        }
        if self.config.min_custodian_count == 0 {
            return Err("min_custodian_count must be nonzero".to_string());
        }
        if self.config.max_batch_items == 0 {
            return Err("max_batch_items must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn validate_runtime_shape(&self) -> MoneroL2PqPrivateLiquidityMirrorRuntimeResult<()> {
        self.validate_config()?;
        if self.pools.len() > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_POOLS {
            return Err("pool capacity exceeded".to_string());
        }
        if self.reserve_snapshots.len()
            > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_SNAPSHOTS
        {
            return Err("reserve snapshot capacity exceeded".to_string());
        }
        if self.custodian_attestations.len()
            > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_ATTESTATIONS
        {
            return Err("custodian attestation capacity exceeded".to_string());
        }
        if self.encrypted_intents.len() > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_INTENTS
        {
            return Err("encrypted intent capacity exceeded".to_string());
        }
        if self.sponsor_reservations.len()
            > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_SPONSOR_RESERVATIONS
        {
            return Err("sponsor reservation capacity exceeded".to_string());
        }
        if self.rebalance_batches.len() > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_BATCHES
        {
            return Err("rebalance batch capacity exceeded".to_string());
        }
        if self.receipts.len() > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_RECEIPTS {
            return Err("receipt capacity exceeded".to_string());
        }
        if self.rebates.len() > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_REBATES {
            return Err("rebate capacity exceeded".to_string());
        }
        if self.privacy_fences.len() > MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_FENCES {
            return Err("privacy fence capacity exceeded".to_string());
        }
        Ok(())
    }

    pub fn validate_references(&self) -> MoneroL2PqPrivateLiquidityMirrorRuntimeResult<()> {
        for snapshot in self.reserve_snapshots.values() {
            if !self.pools.contains_key(&snapshot.pool_id) {
                return Err(format!(
                    "snapshot references unknown pool {}",
                    snapshot.pool_id
                ));
            }
        }
        for attestation in self.custodian_attestations.values() {
            if !self
                .reserve_snapshots
                .contains_key(&attestation.snapshot_id)
            {
                return Err(format!(
                    "attestation references unknown snapshot {}",
                    attestation.snapshot_id
                ));
            }
        }
        for intent in self.encrypted_intents.values() {
            if !self.pools.contains_key(&intent.pool_id) {
                return Err(format!("intent references unknown pool {}", intent.pool_id));
            }
        }
        for reservation in self.sponsor_reservations.values() {
            if !self.encrypted_intents.contains_key(&reservation.intent_id) {
                return Err(format!(
                    "sponsor reservation references unknown intent {}",
                    reservation.intent_id
                ));
            }
        }
        for receipt in self.receipts.values() {
            if !self.rebalance_batches.contains_key(&receipt.batch_id) {
                return Err(format!(
                    "receipt references unknown batch {}",
                    receipt.batch_id
                ));
            }
            if !self.encrypted_intents.contains_key(&receipt.intent_id) {
                return Err(format!(
                    "receipt references unknown intent {}",
                    receipt.intent_id
                ));
            }
            if !self.pools.contains_key(&receipt.pool_id) {
                return Err(format!(
                    "receipt references unknown pool {}",
                    receipt.pool_id
                ));
            }
        }
        for rebate in self.rebates.values() {
            if !self.receipts.contains_key(&rebate.receipt_id) {
                return Err(format!(
                    "rebate references unknown receipt {}",
                    rebate.receipt_id
                ));
            }
        }
        Ok(())
    }

    pub fn validate_privacy_fences(&self) -> MoneroL2PqPrivateLiquidityMirrorRuntimeResult<()> {
        for intent in self.encrypted_intents.values() {
            if !self.nullifiers.contains(&intent.sender_nullifier) {
                return Err(format!(
                    "intent nullifier missing from fence set {}",
                    intent.sender_nullifier
                ));
            }
        }
        for reservation in self.sponsor_reservations.values() {
            if !self.nullifiers.contains(&reservation.credential_nullifier) {
                return Err(format!(
                    "reservation nullifier missing from fence set {}",
                    reservation.credential_nullifier
                ));
            }
        }
        for rebate in self.rebates.values() {
            if !self.nullifiers.contains(&rebate.claim_nullifier) {
                return Err(format!(
                    "rebate nullifier missing from fence set {}",
                    rebate.claim_nullifier
                ));
            }
        }
        Ok(())
    }

    pub fn validate_roots(&self) -> MoneroL2PqPrivateLiquidityMirrorRuntimeResult<()> {
        let mut shadow = self.clone();
        shadow.recompute_roots();
        if self.roots.pool_root != shadow.roots.pool_root {
            return Err("pool_root mismatch".to_string());
        }
        if self.roots.active_pool_root != shadow.roots.active_pool_root {
            return Err("active_pool_root mismatch".to_string());
        }
        if self.roots.reserve_snapshot_root != shadow.roots.reserve_snapshot_root {
            return Err("reserve_snapshot_root mismatch".to_string());
        }
        if self.roots.custodian_attestation_root != shadow.roots.custodian_attestation_root {
            return Err("custodian_attestation_root mismatch".to_string());
        }
        if self.roots.encrypted_intent_root != shadow.roots.encrypted_intent_root {
            return Err("encrypted_intent_root mismatch".to_string());
        }
        if self.roots.open_intent_root != shadow.roots.open_intent_root {
            return Err("open_intent_root mismatch".to_string());
        }
        if self.roots.sponsor_reservation_root != shadow.roots.sponsor_reservation_root {
            return Err("sponsor_reservation_root mismatch".to_string());
        }
        if self.roots.rebalance_batch_root != shadow.roots.rebalance_batch_root {
            return Err("rebalance_batch_root mismatch".to_string());
        }
        if self.roots.receipt_root != shadow.roots.receipt_root {
            return Err("receipt_root mismatch".to_string());
        }
        if self.roots.rebate_root != shadow.roots.rebate_root {
            return Err("rebate_root mismatch".to_string());
        }
        if self.roots.privacy_fence_root != shadow.roots.privacy_fence_root {
            return Err("privacy_fence_root mismatch".to_string());
        }
        if self.roots.nullifier_root != shadow.roots.nullifier_root {
            return Err("nullifier_root mismatch".to_string());
        }
        if self.roots.public_record_root != shadow.roots.public_record_root {
            return Err("public_record_root mismatch".to_string());
        }
        Ok(())
    }

    pub fn validate(&self) -> MoneroL2PqPrivateLiquidityMirrorRuntimeResult<()> {
        self.validate_runtime_shape()?;
        self.validate_references()?;
        self.validate_privacy_fences()?;
        self.validate_roots()?;
        Ok(())
    }

    pub fn summary(&self) -> LiquidityMirrorSummary {
        let active_pool_count = self
            .pools
            .values()
            .filter(|pool| pool.status.usable())
            .count();
        let open_intent_count = self
            .encrypted_intents
            .values()
            .filter(|intent| intent.status.live())
            .count();
        let aggregate_privacy_set_size = self
            .pools
            .values()
            .map(|pool| pool.privacy_set_size)
            .fold(0_u64, u64::saturating_add);
        let min_observed_reserve_coverage_bps = self
            .pools
            .values()
            .map(|pool| pool.reserve_coverage_bps)
            .min()
            .unwrap_or(0);
        let max_fee_bps = self
            .encrypted_intents
            .values()
            .map(|intent| intent.fee_bps)
            .max()
            .unwrap_or(self.config.low_fee_bps);
        LiquidityMirrorSummary {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            height: self.height,
            pool_count: self.pools.len(),
            active_pool_count,
            snapshot_count: self.reserve_snapshots.len(),
            attestation_count: self.custodian_attestations.len(),
            open_intent_count,
            sponsor_reservation_count: self.sponsor_reservations.len(),
            rebalance_batch_count: self.rebalance_batches.len(),
            receipt_count: self.receipts.len(),
            rebate_count: self.rebates.len(),
            nullifier_count: self.nullifiers.len(),
            aggregate_privacy_set_size,
            min_observed_reserve_coverage_bps,
            max_fee_bps,
            roots: self.roots.clone(),
        }
    }

    pub fn reserve_health(&self, pool_id: &str) -> Option<ReserveHealth> {
        let pool = self.pools.get(pool_id)?;
        let latest_snapshot = self
            .reserve_snapshots
            .values()
            .filter(|snapshot| snapshot.pool_id == pool_id)
            .max_by_key(|snapshot| (snapshot.opened_at_height, snapshot.sequence));
        let (snapshot_id, snapshot_height, coverage_bps, privacy_set_size) =
            if let Some(snapshot) = latest_snapshot {
                (
                    Some(snapshot.snapshot_id.clone()),
                    Some(snapshot.opened_at_height),
                    snapshot.coverage_bps,
                    snapshot.privacy_set_size,
                )
            } else {
                (None, None, pool.reserve_coverage_bps, pool.privacy_set_size)
            };
        let accepted_attestations: Vec<&PqCustodianAttestation> = self
            .custodian_attestations
            .values()
            .filter(|attestation| {
                attestation.accepted
                    && snapshot_id
                        .as_ref()
                        .map(|id| id == &attestation.snapshot_id)
                        .unwrap_or(false)
            })
            .collect();
        let accepted_attestation_weight = accepted_attestations
            .iter()
            .map(|attestation| attestation.custodian_weight)
            .fold(0_u64, u64::saturating_add);
        let accepted_attestation_count = accepted_attestations.len() as u64;
        let quorum_basis = self
            .config
            .min_custodian_count
            .max(accepted_attestation_weight);
        let quorum_bps = if quorum_basis == 0 {
            0
        } else {
            accepted_attestation_weight
                .saturating_mul(MONERO_L2_PQ_PRIVATE_LIQUIDITY_MIRROR_RUNTIME_MAX_BPS)
                / quorum_basis
        };
        let pq_ready = accepted_attestations
            .iter()
            .all(|attestation| attestation.pq_security_bits >= self.config.min_pq_security_bits)
            && pool.pq_security_bits >= self.config.min_pq_security_bits;
        Some(ReserveHealth {
            pool_id: pool_id.to_string(),
            status: pool.status,
            latest_snapshot_id: snapshot_id,
            latest_snapshot_height: snapshot_height,
            accepted_attestation_weight,
            accepted_attestation_count,
            coverage_bps,
            privacy_set_size,
            quorum_met: quorum_bps >= self.config.custodian_quorum_bps,
            strong_quorum_met: quorum_bps >= self.config.strong_quorum_bps,
            pq_ready,
        })
    }

    pub fn reserve_health_records(&self) -> Vec<Value> {
        self.pools
            .keys()
            .filter_map(|pool_id| self.reserve_health(pool_id))
            .map(|health| health.public_record())
            .collect()
    }

    pub fn quote_intent_fee(
        &self,
        lane: MirrorLane,
        intent_kind: IntentKind,
        amount_commitment: &str,
    ) -> IntentFeeQuote {
        IntentFeeQuote {
            quote_id: quote_id(lane, intent_kind, amount_commitment, self.height),
            lane,
            intent_kind,
            amount_commitment: amount_commitment.to_string(),
            user_fee_bps: lane.fee_bps(&self.config),
            lp_fee_bps: self.config.lp_fee_bps,
            sponsor_cover_bps: if lane == MirrorLane::SponsoredLowFee {
                self.config.sponsor_cover_bps
            } else {
                0
            },
            rebate_bps: self.config.rebate_bps,
            priority_weight: lane.priority_weight(),
            expires_at_height: self.height + self.config.intent_ttl_blocks,
        }
    }

    pub fn public_ledger_view(&self) -> PublicLedgerView {
        let config_record = json!({ "config": self.config });
        let counter_record = json!({ "counters": self.counters });
        let root_record = json!({ "roots": self.roots });
        let reserve_health_records = self.reserve_health_records();
        let private_flow_records = private_flow_records(
            &self.encrypted_intents,
            &self.rebalance_batches,
            &self.receipts,
        );
        let fee_flow_records =
            fee_flow_records(&self.sponsor_reservations, &self.receipts, &self.rebates);
        PublicLedgerView {
            config_root: root_from_record(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-CONFIG-ROOT",
                &config_record,
            ),
            counter_root: root_from_record(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-COUNTER-ROOT",
                &counter_record,
            ),
            root_root: root_from_record(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-ROOTS-ROOT",
                &root_record,
            ),
            pool_root: self.roots.pool_root.clone(),
            reserve_health_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-RESERVE-HEALTH",
                &reserve_health_records,
            ),
            private_flow_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVATE-FLOWS",
                &private_flow_records,
            ),
            fee_flow_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-FEE-FLOWS",
                &fee_flow_records,
            ),
            nullifier_root: self.roots.nullifier_root.clone(),
            public_record_root: self.roots.public_record_root.clone(),
            state_root: self.roots.state_root.clone(),
        }
    }

    pub fn export_public_records(&self) -> Vec<Value> {
        let mut records = self.public_records.clone();
        let summary = self.summary().public_record();
        let ledger = self.public_ledger_view().public_record();
        records.push(json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "record_type": "liquidity_mirror_summary",
            "payload_root": payload_root(&summary),
            "payload": summary,
        }));
        records.push(json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "record_type": "public_ledger_view",
            "payload_root": payload_root(&ledger),
            "payload": ledger,
        }));
        records
    }

    pub fn advance_height(&mut self, height: u64) {
        self.height = self.height.max(height);
        self.expire_stale_records();
        self.recompute_roots();
    }

    pub fn expire_stale_records(&mut self) {
        for pool in self.pools.values_mut() {
            if pool.expires_at_height <= self.height && pool.status.usable() {
                pool.status = PoolStatus::Draining;
            }
        }
        for snapshot in self.reserve_snapshots.values_mut() {
            if snapshot.expires_at_height <= self.height
                && matches!(
                    snapshot.status,
                    SnapshotStatus::Submitted
                        | SnapshotStatus::CustodianAttested
                        | SnapshotStatus::QuorumAttested
                )
            {
                snapshot.status = SnapshotStatus::Expired;
            }
        }
        for intent in self.encrypted_intents.values_mut() {
            if intent.expires_at_height <= self.height && intent.status.live() {
                intent.status = IntentStatus::Expired;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.expires_at_height <= self.height
                && reservation.status == ReservationStatus::Reserved
            {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for batch in self.rebalance_batches.values_mut() {
            if batch.expires_at_height <= self.height
                && matches!(
                    batch.status,
                    RebalanceStatus::Open | RebalanceStatus::Sealed | RebalanceStatus::Submitted
                )
            {
                batch.status = RebalanceStatus::Expired;
            }
        }
    }

    pub fn insert_pool(&mut self, pool: MirroredLiquidityPool) {
        self.counters.pools = self.counters.pools.max(pool.sequence);
        self.emit_public_record("pool", pool.public_record());
        self.pools.insert(pool.pool_id.clone(), pool);
    }

    pub fn insert_snapshot(&mut self, snapshot: PrivateReserveSnapshot) {
        self.counters.snapshots = self.counters.snapshots.max(snapshot.sequence);
        self.emit_public_record("reserve_snapshot", snapshot.public_record());
        self.reserve_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
    }

    pub fn insert_attestation(&mut self, attestation: PqCustodianAttestation) {
        self.counters.attestations = self.counters.attestations.saturating_add(1);
        self.emit_public_record("pq_custodian_attestation", attestation.public_record());
        self.custodian_attestations
            .insert(attestation.attestation_id.clone(), attestation);
    }

    pub fn insert_intent(&mut self, intent: EncryptedLiquidityIntent) {
        self.counters.intents = self.counters.intents.max(intent.sequence);
        self.add_privacy_fence(
            &intent.sender_nullifier,
            &intent.intent_id,
            intent.submitted_at_height,
        );
        self.emit_public_record("encrypted_liquidity_intent", intent.public_record());
        self.encrypted_intents
            .insert(intent.intent_id.clone(), intent);
    }

    pub fn insert_sponsor_reservation(&mut self, reservation: SponsorReservation) {
        self.counters.sponsor_reservations =
            self.counters.sponsor_reservations.max(reservation.sequence);
        self.add_privacy_fence(
            &reservation.credential_nullifier,
            &reservation.reservation_id,
            reservation.opened_at_height,
        );
        self.emit_public_record("sponsor_reservation", reservation.public_record());
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation);
    }

    pub fn insert_rebalance_batch(&mut self, batch: MirrorRebalanceBatch) {
        self.counters.rebalance_batches = self.counters.rebalance_batches.max(batch.sequence);
        self.emit_public_record("mirror_rebalance_batch", batch.public_record());
        self.rebalance_batches.insert(batch.batch_id.clone(), batch);
    }

    pub fn insert_receipt(&mut self, receipt: MirrorReceipt) {
        self.counters.receipts = self.counters.receipts.max(receipt.sequence);
        self.emit_public_record("mirror_receipt", receipt.public_record());
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
    }

    pub fn insert_rebate(&mut self, rebate: FeeRebate) {
        self.counters.rebates = self.counters.rebates.max(rebate.sequence);
        self.add_privacy_fence(&rebate.claim_nullifier, &rebate.rebate_id, self.height);
        self.emit_public_record("fee_rebate", rebate.public_record());
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
    }

    pub fn recompute_roots(&mut self) {
        let pool_records = records_from_map(&self.pools, MirroredLiquidityPool::public_record);
        let active_pool_records: Vec<Value> = self
            .pools
            .values()
            .filter(|pool| pool.status.usable())
            .map(MirroredLiquidityPool::public_record)
            .collect();
        let snapshot_records = records_from_map(
            &self.reserve_snapshots,
            PrivateReserveSnapshot::public_record,
        );
        let attestation_records = records_from_map(
            &self.custodian_attestations,
            PqCustodianAttestation::public_record,
        );
        let intent_records = records_from_map(
            &self.encrypted_intents,
            EncryptedLiquidityIntent::public_record,
        );
        let open_intent_records: Vec<Value> = self
            .encrypted_intents
            .values()
            .filter(|intent| intent.status.live())
            .map(EncryptedLiquidityIntent::public_record)
            .collect();
        let sponsor_records = records_from_map(
            &self.sponsor_reservations,
            SponsorReservation::public_record,
        );
        let batch_records =
            records_from_map(&self.rebalance_batches, MirrorRebalanceBatch::public_record);
        let receipt_records = records_from_map(&self.receipts, MirrorReceipt::public_record);
        let rebate_records = records_from_map(&self.rebates, FeeRebate::public_record);
        let fence_records = records_from_map(&self.privacy_fences, PrivacyFence::public_record);
        let nullifier_records: Vec<Value> = self
            .nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect();

        self.roots.pool_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-POOLS", &pool_records);
        self.roots.active_pool_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-ACTIVE-POOLS",
            &active_pool_records,
        );
        self.roots.reserve_snapshot_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-RESERVE-SNAPSHOTS",
            &snapshot_records,
        );
        self.roots.custodian_attestation_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-CUSTODIAN-ATTESTATIONS",
            &attestation_records,
        );
        self.roots.encrypted_intent_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-ENCRYPTED-INTENTS",
            &intent_records,
        );
        self.roots.open_intent_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-OPEN-INTENTS",
            &open_intent_records,
        );
        self.roots.sponsor_reservation_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-SPONSOR-RESERVATIONS",
            &sponsor_records,
        );
        self.roots.rebalance_batch_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-REBALANCE-BATCHES",
            &batch_records,
        );
        self.roots.receipt_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-RECEIPTS",
            &receipt_records,
        );
        self.roots.rebate_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-REBATES",
            &rebate_records,
        );
        self.roots.privacy_fence_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVACY-FENCES",
            &fence_records,
        );
        self.roots.nullifier_root = merkle_root(
            "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-NULLIFIERS",
            &nullifier_records,
        );
        self.roots.event_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-EVENTS", &self.events);
        self.roots.public_record_root = public_record_root(&self.public_records);
        self.roots.state_root = self.state_root();
    }

    fn emit_public_record(&mut self, record_type: &str, payload: Value) {
        let record = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "record_type": record_type,
            "payload_root": payload_root(&payload),
            "payload": payload,
        });
        self.public_records.push(record);
        self.counters.public_records = self.public_records.len() as u64;
    }

    fn add_privacy_fence(&mut self, nullifier: &str, anchor: &str, height: u64) {
        if self.nullifiers.insert(nullifier.to_string()) {
            let sequence = self.counters.fences.saturating_add(1);
            let fence = PrivacyFence {
                fence_id: privacy_fence_id(nullifier, anchor, sequence),
                nullifier: nullifier.to_string(),
                domain: self.config.replay_domain.clone(),
                anchor_root: domain_hash(
                    "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVACY-FENCE-ANCHOR",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(PROTOCOL_VERSION),
                        HashPart::Str(anchor),
                    ],
                    32,
                ),
                opened_at_height: height,
                sequence,
            };
            self.counters.fences = sequence;
            self.privacy_fences.insert(fence.fence_id.clone(), fence);
        }
    }

    fn sample_pool(
        &self,
        label: &str,
        pool_kind: PoolKind,
        lane: MirrorLane,
        height: u64,
        sequence: u64,
    ) -> MirroredLiquidityPool {
        let monero_reserve_commitment = commitment_id("MONERO-RESERVE", label, sequence);
        let l2_mirror_commitment = commitment_id("L2-MIRROR", label, sequence);
        MirroredLiquidityPool {
            pool_id: pool_id(label, sequence),
            pool_kind,
            status: PoolStatus::Active,
            lane,
            monero_reserve_commitment,
            l2_mirror_commitment,
            lp_commitment_root: commitment_id("LP-COMMITMENT-ROOT", label, sequence),
            fee_commitment_root: commitment_id("FEE-COMMITMENT-ROOT", label, sequence),
            encrypted_parameter_root: commitment_id("ENCRYPTED-PARAMETER-ROOT", label, sequence),
            privacy_set_size: self.config.min_privacy_set_size + sequence * 8_192,
            reserve_coverage_bps: self.config.target_reserve_coverage_bps + sequence * 25,
            pq_security_bits: self.config.target_pq_security_bits,
            created_at_height: height,
            expires_at_height: height + self.config.pool_ttl_blocks,
            sequence,
        }
    }

    fn sample_snapshot(&self, pool_id: &str, height: u64, sequence: u64) -> PrivateReserveSnapshot {
        PrivateReserveSnapshot {
            snapshot_id: snapshot_id(pool_id, height, sequence),
            pool_id: pool_id.to_string(),
            status: SnapshotStatus::QuorumAttested,
            reserve_commitment_root: commitment_id("RESERVE-SNAPSHOT", pool_id, sequence),
            view_tag_root: commitment_id("VIEW-TAG", pool_id, sequence),
            output_membership_root: commitment_id("OUTPUT-MEMBERSHIP", pool_id, sequence),
            encrypted_balance_root: commitment_id("ENCRYPTED-BALANCE", pool_id, sequence),
            coverage_bps: self.config.target_reserve_coverage_bps,
            privacy_set_size: self.config.min_privacy_set_size + sequence * 4_096,
            opened_at_height: height,
            expires_at_height: height + self.config.snapshot_ttl_blocks,
            sequence,
        }
    }

    fn sample_attestation(
        &self,
        snapshot_id: &str,
        custodian_id: &str,
        height: u64,
        sequence: u64,
    ) -> PqCustodianAttestation {
        PqCustodianAttestation {
            attestation_id: attestation_id(snapshot_id, custodian_id, sequence),
            snapshot_id: snapshot_id.to_string(),
            custodian_id: custodian_id.to_string(),
            custodian_weight: 1,
            pq_signature_root: commitment_id("PQ-SIGNATURE", custodian_id, sequence),
            verification_key_root: commitment_id("PQ-VERIFYING-KEY", custodian_id, sequence),
            reserve_claim_root: commitment_id("RESERVE-CLAIM", snapshot_id, sequence),
            audited_height: height,
            pq_security_bits: self.config.target_pq_security_bits,
            accepted: true,
        }
    }

    fn sample_intent(
        &self,
        pool_id: &str,
        intent_kind: IntentKind,
        lane: MirrorLane,
        note: &str,
        height: u64,
        sequence: u64,
    ) -> EncryptedLiquidityIntent {
        EncryptedLiquidityIntent {
            intent_id: intent_id(pool_id, note, sequence),
            pool_id: pool_id.to_string(),
            intent_kind,
            status: IntentStatus::Matched,
            lane,
            sender_nullifier: nullifier_id("INTENT", note, sequence),
            amount_commitment: commitment_id("AMOUNT", note, sequence),
            min_output_commitment: commitment_id("MIN-OUTPUT", note, sequence),
            encrypted_route_root: commitment_id("ENCRYPTED-ROUTE", note, sequence),
            kem_ciphertext_hash: commitment_id("ML-KEM-CIPHERTEXT", note, sequence),
            sponsor_hint_root: commitment_id("SPONSOR-HINT", note, sequence),
            fee_bps: lane.fee_bps(&self.config),
            priority_weight: lane.priority_weight(),
            submitted_at_height: height,
            expires_at_height: height + self.config.intent_ttl_blocks,
            sequence,
        }
    }

    fn sample_reservation(
        &self,
        intent_id: &str,
        sponsor_id: &str,
        height: u64,
        sequence: u64,
    ) -> SponsorReservation {
        SponsorReservation {
            reservation_id: sponsor_reservation_id(intent_id, sponsor_id, sequence),
            intent_id: intent_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            status: ReservationStatus::Reserved,
            reserved_fee_units: 24_000 + sequence * 1_000,
            cover_bps: self.config.sponsor_cover_bps,
            credential_nullifier: nullifier_id("SPONSOR", sponsor_id, sequence),
            sponsor_commitment_root: commitment_id("SPONSOR-COMMITMENT", sponsor_id, sequence),
            opened_at_height: height,
            expires_at_height: height + self.config.sponsor_ttl_blocks,
            sequence,
        }
    }

    fn sample_rebalance_batch(
        &self,
        pool_ids: &[String],
        intent_ids: &[String],
        height: u64,
        sequence: u64,
    ) -> MirrorRebalanceBatch {
        let pool_refs: Vec<Value> = pool_ids
            .iter()
            .map(|pool_id| json!({ "pool_id": pool_id }))
            .collect();
        let intent_refs: Vec<Value> = intent_ids
            .iter()
            .map(|intent_id| json!({ "intent_id": intent_id }))
            .collect();
        MirrorRebalanceBatch {
            batch_id: rebalance_batch_id(
                &merkle_root("DEVNET-POOL-REFS", &pool_refs),
                height,
                sequence,
            ),
            status: RebalanceStatus::Submitted,
            lane: MirrorLane::Rebalance,
            pool_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-BATCH-POOLS",
                &pool_refs,
            ),
            intent_root: merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-BATCH-INTENTS",
                &intent_refs,
            ),
            snapshot_root: self.roots.reserve_snapshot_root.clone(),
            sponsor_root: self.roots.sponsor_reservation_root.clone(),
            settlement_commitment_root: commitment_id("BATCH-SETTLEMENT", "devnet", sequence),
            solver_commitment: commitment_id("SOLVER", "devnet-solver", sequence),
            item_count: intent_ids.len(),
            opened_at_height: height,
            expires_at_height: height + self.config.rebalance_ttl_blocks,
            sequence,
        }
    }

    fn sample_receipt(
        &self,
        batch_id: &str,
        intent: &EncryptedLiquidityIntent,
        height: u64,
        sequence: u64,
    ) -> MirrorReceipt {
        MirrorReceipt {
            receipt_id: receipt_id(batch_id, &intent.intent_id, sequence),
            batch_id: batch_id.to_string(),
            intent_id: intent.intent_id.clone(),
            pool_id: intent.pool_id.clone(),
            status: ReceiptStatus::Final,
            fill_commitment: commitment_id("FILL", &intent.intent_id, sequence),
            paid_fee_commitment: commitment_id("PAID-FEE", &intent.intent_id, sequence),
            rebate_commitment: commitment_id("REBATE-COMMITMENT", &intent.intent_id, sequence),
            settlement_root: commitment_id("SETTLEMENT", batch_id, sequence),
            finalized_at_height: height,
            sequence,
        }
    }

    fn sample_rebate(
        &self,
        receipt_id: &str,
        sponsor_id: &str,
        height: u64,
        sequence: u64,
    ) -> FeeRebate {
        FeeRebate {
            rebate_id: rebate_id(receipt_id, sponsor_id, sequence),
            receipt_id: receipt_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            rebate_commitment: commitment_id("REBATE", receipt_id, sequence),
            claim_nullifier: nullifier_id("REBATE-CLAIM", receipt_id, sequence),
            expires_at_height: height + self.config.rebate_ttl_blocks,
            sequence,
        }
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PAYLOAD-ROOT",
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

pub fn public_record_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PUBLIC-RECORDS",
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-STATE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn pool_id(label: &str, sequence: u64) -> String {
    deterministic_id(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-POOL-ID",
        label,
        sequence,
    )
}

pub fn snapshot_id(pool_id: &str, height: u64, sequence: u64) -> String {
    let height_s = height.to_string();
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(pool_id),
            HashPart::Str(&height_s),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn attestation_id(snapshot_id: &str, custodian_id: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(snapshot_id),
            HashPart::Str(custodian_id),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn intent_id(pool_id: &str, note: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(pool_id),
            HashPart::Str(note),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(intent_id: &str, sponsor_id: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(intent_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn rebalance_batch_id(pool_root: &str, height: u64, sequence: u64) -> String {
    let height_s = height.to_string();
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-REBALANCE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(pool_root),
            HashPart::Str(&height_s),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn receipt_id(batch_id: &str, intent_id: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(intent_id),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, sponsor_id: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn privacy_fence_id(nullifier: &str, anchor: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(nullifier),
            HashPart::Str(anchor),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn quote_id(
    lane: MirrorLane,
    intent_kind: IntentKind,
    amount_commitment: &str,
    height: u64,
) -> String {
    let height_s = height.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(intent_kind.as_str()),
            HashPart::Str(amount_commitment),
            HashPart::Str(&height_s),
        ],
        32,
    )
}

pub fn nullifier_id(domain: &str, label: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn commitment_id(domain: &str, label: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, label: &str, sequence: u64) -> String {
    let sequence_s = sequence.to_string();
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(&sequence_s),
        ],
        32,
    )
}

fn records_from_map<T, F>(map: &BTreeMap<String, T>, record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(record).collect()
}

fn private_flow_records(
    intents: &BTreeMap<String, EncryptedLiquidityIntent>,
    batches: &BTreeMap<String, MirrorRebalanceBatch>,
    receipts: &BTreeMap<String, MirrorReceipt>,
) -> Vec<Value> {
    let intent_records = records_from_map(intents, EncryptedLiquidityIntent::public_record);
    let batch_records = records_from_map(batches, MirrorRebalanceBatch::public_record);
    let receipt_records = records_from_map(receipts, MirrorReceipt::public_record);
    vec![
        json!({
            "flow": "encrypted_intents",
            "root": merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVATE-FLOW-INTENTS",
                &intent_records,
            ),
            "count": intent_records.len(),
        }),
        json!({
            "flow": "rebalance_batches",
            "root": merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVATE-FLOW-BATCHES",
                &batch_records,
            ),
            "count": batch_records.len(),
        }),
        json!({
            "flow": "receipts",
            "root": merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-PRIVATE-FLOW-RECEIPTS",
                &receipt_records,
            ),
            "count": receipt_records.len(),
        }),
    ]
}

fn fee_flow_records(
    reservations: &BTreeMap<String, SponsorReservation>,
    receipts: &BTreeMap<String, MirrorReceipt>,
    rebates: &BTreeMap<String, FeeRebate>,
) -> Vec<Value> {
    let reservation_records = records_from_map(reservations, SponsorReservation::public_record);
    let receipt_records = records_from_map(receipts, MirrorReceipt::public_record);
    let rebate_records = records_from_map(rebates, FeeRebate::public_record);
    vec![
        json!({
            "flow": "sponsor_reservations",
            "root": merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-FEE-FLOW-SPONSORS",
                &reservation_records,
            ),
            "count": reservation_records.len(),
        }),
        json!({
            "flow": "receipts",
            "root": merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-FEE-FLOW-RECEIPTS",
                &receipt_records,
            ),
            "count": receipt_records.len(),
        }),
        json!({
            "flow": "rebates",
            "root": merkle_root(
                "MONERO-L2-PQ-PRIVATE-LIQUIDITY-MIRROR-FEE-FLOW-REBATES",
                &rebate_records,
            ),
            "count": rebate_records.len(),
        }),
    ]
}
