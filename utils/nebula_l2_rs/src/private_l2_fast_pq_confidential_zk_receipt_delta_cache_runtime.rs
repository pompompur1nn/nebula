use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = PrivateL2FastPqConfidentialZkReceiptDeltaCacheRuntimeResult<T>;
pub type PrivateL2FastPqConfidentialZkReceiptDeltaCacheRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZK_RECEIPT_DELTA_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-zk-receipt-delta-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZK_RECEIPT_DELTA_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_RECEIPT_DELTA_SUITE: &str =
    "ml-kem-1024+xwing-confidential-zk-receipt-delta-cache-v1";
pub const PQ_CACHE_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-receipt-delta-cache-attestation-v1";
pub const PREFETCH_LANE_SUITE: &str = "fast-private-zk-receipt-delta-prefetch-lane-v1";
pub const CACHE_LEASE_SUITE: &str = "confidential-receipt-delta-cache-lease-v1";
pub const INVALIDATION_FENCE_SUITE: &str =
    "private-l2-confidential-zk-receipt-delta-invalidation-fence-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-zk-receipt-delta-cache-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "receipt-delta-cache-privacy-redaction-budget-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "operator-safe-confidential-zk-receipt-delta-cache-public-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_040_000;
pub const DEVNET_EPOCH: u64 = 14_336;
pub const DEFAULT_SHARD_COUNT: u16 = 16;
pub const DEFAULT_PREFETCH_LANES: u16 = 8;
pub const DEFAULT_TARGET_HIT_LATENCY_US: u64 = 35_000;
pub const DEFAULT_HARD_HIT_LATENCY_US: u64 = 160_000;
pub const DEFAULT_DELTA_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 512;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 64;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;

const D_STATE: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:ROOTS";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:SHARDS";
const D_DELTAS: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:DELTAS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:ATTESTATIONS";
const D_PREFETCH: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:PREFETCH";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:LEASES";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:FENCES";
const D_LATENCY: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:LATENCY";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:REBATES";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:REDACTIONS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:PUBLIC";

macro_rules! status_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
    };
}

status_enum!(ShardStatus {
    Cold => "cold",
    Warming => "warming",
    Hot => "hot",
    Saturated => "saturated",
    Fenced => "fenced",
    Draining => "draining",
});
status_enum!(DeltaStatus {
    Encrypted => "encrypted",
    Prefetched => "prefetched",
    Leased => "leased",
    Hit => "hit",
    Flushed => "flushed",
    Invalidated => "invalidated",
    Expired => "expired",
});
status_enum!(AttestationStatus {
    Draft => "draft",
    Published => "published",
    Verified => "verified",
    QuorumAccepted => "quorum_accepted",
    Rejected => "rejected",
    Expired => "expired",
});
status_enum!(PrefetchLaneStatus {
    Open => "open",
    Filling => "filling",
    Warmed => "warmed",
    Throttled => "throttled",
    Paused => "paused",
});
status_enum!(CacheLeaseStatus {
    Offered => "offered",
    Reserved => "reserved",
    Active => "active",
    Released => "released",
    Slashed => "slashed",
    Expired => "expired",
});
status_enum!(InvalidationFenceStatus {
    Active => "active",
    Matched => "matched",
    Frozen => "frozen",
    Released => "released",
    Expired => "expired",
});
status_enum!(LowFeeRebateStatus {
    Reserved => "reserved",
    Applied => "applied",
    Settled => "settled",
    Reclaimed => "reclaimed",
    Challenged => "challenged",
    Expired => "expired",
});
status_enum!(RedactionBudgetStatus {
    Open => "open",
    Debited => "debited",
    Exhausted => "exhausted",
    Frozen => "frozen",
    Closed => "closed",
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaClass {
    ReceiptHeader,
    ZkProofHint,
    NullifierWindow,
    ContractEvent,
    BridgeExit,
    DefiSettlement,
    WalletSync,
    LowFeeBulk,
}

impl DeltaClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptHeader => "receipt_header",
            Self::ZkProofHint => "zk_proof_hint",
            Self::NullifierWindow => "nullifier_window",
            Self::ContractEvent => "contract_event",
            Self::BridgeExit => "bridge_exit",
            Self::DefiSettlement => "defi_settlement",
            Self::WalletSync => "wallet_sync",
            Self::LowFeeBulk => "low_fee_bulk",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 990,
            Self::DefiSettlement => 930,
            Self::NullifierWindow => 900,
            Self::ContractEvent => 860,
            Self::ReceiptHeader => 820,
            Self::ZkProofHint => 780,
            Self::WalletSync => 620,
            Self::LowFeeBulk => 480,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub shard_count: u16,
    pub prefetch_lanes: u16,
    pub target_hit_latency_us: u64,
    pub hard_hit_latency_us: u64,
    pub delta_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub enable_low_fee_rebates: bool,
    pub enable_privacy_redaction_budgets: bool,
    pub enable_operator_safe_public_records: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            shard_count: DEFAULT_SHARD_COUNT,
            prefetch_lanes: DEFAULT_PREFETCH_LANES,
            target_hit_latency_us: DEFAULT_TARGET_HIT_LATENCY_US,
            hard_hit_latency_us: DEFAULT_HARD_HIT_LATENCY_US,
            delta_ttl_blocks: DEFAULT_DELTA_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            enable_low_fee_rebates: true,
            enable_privacy_redaction_budgets: true,
            enable_operator_safe_public_records: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "shard_count": self.shard_count,
            "prefetch_lanes": self.prefetch_lanes,
            "target_hit_latency_us": self.target_hit_latency_us,
            "hard_hit_latency_us": self.hard_hit_latency_us,
            "delta_ttl_blocks": self.delta_ttl_blocks,
            "lease_ttl_blocks": self.lease_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
            "enable_privacy_redaction_budgets": self.enable_privacy_redaction_budgets,
            "enable_operator_safe_public_records": self.enable_operator_safe_public_records,
        })
    }

    pub fn root(&self) -> String {
        hash_json(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub encrypted_delta_count: u64,
    pub delta_hit_count: u64,
    pub delta_miss_count: u64,
    pub pq_attestation_count: u64,
    pub prefetch_lane_count: u64,
    pub cache_lease_count: u64,
    pub invalidation_fence_count: u64,
    pub low_fee_rebate_count: u64,
    pub redaction_budget_count: u64,
    pub latency_bucket_count: u64,
    pub total_rebate_micros: u64,
    pub redacted_field_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        hash_json(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub shard_root: String,
    pub encrypted_delta_root: String,
    pub pq_attestation_root: String,
    pub prefetch_lane_root: String,
    pub cache_lease_root: String,
    pub invalidation_fence_root: String,
    pub latency_bucket_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub spent_nullifier_root: String,
    pub deterministic_state_root: String,
}

impl Roots {
    pub fn without_state_root(&self) -> Self {
        let mut roots = self.clone();
        roots.deterministic_state_root.clear();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        hash_json(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheShard {
    pub shard_id: String,
    pub status: ShardStatus,
    pub lane_affinity: u16,
    pub hot_delta_count: u64,
    pub max_delta_count: u64,
    pub occupancy_bps: u64,
    pub shard_commitment: String,
    pub latest_receipt_root: String,
}

impl CacheShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "lane_affinity": self.lane_affinity,
            "hot_delta_count": self.hot_delta_count,
            "max_delta_count": self.max_delta_count,
            "occupancy_bps": self.occupancy_bps,
            "shard_commitment": self.shard_commitment,
            "latest_receipt_root": self.latest_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptDelta {
    pub delta_id: String,
    pub shard_id: String,
    pub delta_class: DeltaClass,
    pub status: DeltaStatus,
    pub receipt_commitment: String,
    pub encrypted_delta_commitment: String,
    pub zk_delta_root: String,
    pub nullifier_window_root: String,
    pub inserted_l2_height: u64,
    pub expires_l2_height: u64,
    pub fee_micros: u64,
    pub privacy_set_size: u64,
}

impl EncryptedReceiptDelta {
    pub fn public_record(&self) -> Value {
        json!({
            "delta_id": self.delta_id,
            "shard_id": self.shard_id,
            "delta_class": self.delta_class.as_str(),
            "status": self.status.as_str(),
            "receipt_commitment": self.receipt_commitment,
            "encrypted_delta_commitment": self.encrypted_delta_commitment,
            "zk_delta_root": self.zk_delta_root,
            "nullifier_window_root": self.nullifier_window_root,
            "inserted_l2_height": self.inserted_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "fee_micros": self.fee_micros,
            "privacy_set_size": self.privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestation {
    pub attestation_id: String,
    pub operator_id: String,
    pub shard_id: String,
    pub status: AttestationStatus,
    pub attested_delta_root: String,
    pub cache_hit_rate_bps: u64,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub signature_commitment: String,
    pub expires_l2_height: u64,
}

impl PqCacheAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "attested_delta_root": self.attested_delta_root,
            "cache_hit_rate_bps": self.cache_hit_rate_bps,
            "quorum_weight_bps": self.quorum_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "signature_commitment": self.signature_commitment,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchLane {
    pub lane_id: String,
    pub shard_id: String,
    pub status: PrefetchLaneStatus,
    pub delta_class: DeltaClass,
    pub target_latency_us: u64,
    pub queued_delta_count: u64,
    pub warmed_delta_count: u64,
    pub lane_credit_micros: u64,
}

impl PrefetchLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "delta_class": self.delta_class.as_str(),
            "target_latency_us": self.target_latency_us,
            "queued_delta_count": self.queued_delta_count,
            "warmed_delta_count": self.warmed_delta_count,
            "lane_credit_micros": self.lane_credit_micros,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub delta_id: String,
    pub lessee_commitment: String,
    pub status: CacheLeaseStatus,
    pub reserved_l2_height: u64,
    pub expires_l2_height: u64,
    pub lease_fee_micros: u64,
}

impl CacheLease {
    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "delta_id": self.delta_id,
            "lessee_commitment": self.lessee_commitment,
            "status": self.status.as_str(),
            "reserved_l2_height": self.reserved_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "lease_fee_micros": self.lease_fee_micros,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub shard_id: String,
    pub status: InvalidationFenceStatus,
    pub fence_root: String,
    pub invalidates_before_height: u64,
    pub expires_l2_height: u64,
    pub reason_code: String,
}

impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "fence_root": self.fence_root,
            "invalidates_before_height": self.invalidates_before_height,
            "expires_l2_height": self.expires_l2_height,
            "reason_code": self.reason_code,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub bucket_id: String,
    pub upper_bound_us: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub rebate_eligible_count: u64,
}

impl LatencyBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheRebate {
    pub rebate_id: String,
    pub delta_id: String,
    pub status: LowFeeRebateStatus,
    pub fee_asset_id: String,
    pub rebate_micros: u64,
    pub fee_bps: u64,
    pub settlement_commitment: String,
    pub expires_l2_height: u64,
}

impl LowFeeCacheRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "delta_id": self.delta_id,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "rebate_micros": self.rebate_micros,
            "fee_bps": self.fee_bps,
            "settlement_commitment": self.settlement_commitment,
            "expires_l2_height": self.expires_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub subject_commitment: String,
    pub status: RedactionBudgetStatus,
    pub epoch: u64,
    pub allowed_fields: u16,
    pub spent_fields: u16,
    pub redaction_root: String,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_commitment": self.subject_commitment,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "allowed_fields": self.allowed_fields,
            "spent_fields": self.spent_fields,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub shards: BTreeMap<String, CacheShard>,
    pub encrypted_deltas: BTreeMap<String, EncryptedReceiptDelta>,
    pub pq_attestations: BTreeMap<String, PqCacheAttestation>,
    pub prefetch_lanes: BTreeMap<String, PrefetchLane>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub low_fee_rebates: BTreeMap<String, LowFeeCacheRebate>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            shards: BTreeMap::new(),
            encrypted_deltas: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            prefetch_lanes: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.install_devnet_fixtures();
        state.recompute();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_zk_receipt_delta_cache_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.without_state_root().public_record(),
            "shards": public_values(&self.shards),
            "encrypted_deltas": public_values(&self.encrypted_deltas),
            "pq_attestations": public_values(&self.pq_attestations),
            "prefetch_lanes": public_values(&self.prefetch_lanes),
            "cache_leases": public_values(&self.cache_leases),
            "invalidation_fences": public_values(&self.invalidation_fences),
            "latency_buckets": public_values(&self.latency_buckets),
            "low_fee_rebates": public_values(&self.low_fee_rebates),
            "redaction_budgets": public_values(&self.redaction_budgets),
        })
    }

    pub fn state_root(&self) -> String {
        hash_json(D_STATE, &self.public_record())
    }

    pub fn recompute(&mut self) {
        self.counters = Counters {
            encrypted_delta_count: self.encrypted_deltas.len() as u64,
            delta_hit_count: self
                .encrypted_deltas
                .values()
                .filter(|delta| delta.status == DeltaStatus::Hit)
                .count() as u64,
            delta_miss_count: self
                .latency_buckets
                .values()
                .map(|bucket| bucket.miss_count)
                .sum(),
            pq_attestation_count: self.pq_attestations.len() as u64,
            prefetch_lane_count: self.prefetch_lanes.len() as u64,
            cache_lease_count: self.cache_leases.len() as u64,
            invalidation_fence_count: self.invalidation_fences.len() as u64,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            latency_bucket_count: self.latency_buckets.len() as u64,
            total_rebate_micros: self
                .low_fee_rebates
                .values()
                .map(|rebate| rebate.rebate_micros)
                .sum(),
            redacted_field_count: self
                .redaction_budgets
                .values()
                .map(|budget| u64::from(budget.spent_fields))
                .sum(),
        };
        self.roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            shard_root: merkle_json(D_SHARDS, public_values(&self.shards)),
            encrypted_delta_root: merkle_json(D_DELTAS, public_values(&self.encrypted_deltas)),
            pq_attestation_root: merkle_json(D_ATTESTATIONS, public_values(&self.pq_attestations)),
            prefetch_lane_root: merkle_json(D_PREFETCH, public_values(&self.prefetch_lanes)),
            cache_lease_root: merkle_json(D_LEASES, public_values(&self.cache_leases)),
            invalidation_fence_root: merkle_json(
                D_FENCES,
                public_values(&self.invalidation_fences),
            ),
            latency_bucket_root: merkle_json(D_LATENCY, public_values(&self.latency_buckets)),
            low_fee_rebate_root: merkle_json(D_REBATES, public_values(&self.low_fee_rebates)),
            redaction_budget_root: merkle_json(
                D_REDACTIONS,
                public_values(&self.redaction_budgets),
            ),
            spent_nullifier_root: merkle_root(
                "PL2-FAST-PQ-CONF-ZK-RECEIPT-DELTA-CACHE:SPENT-NULLIFIERS",
                &self
                    .spent_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect::<Vec<_>>(),
            ),
            deterministic_state_root: String::new(),
        };
        self.roots.deterministic_state_root = self.state_root();
    }

    fn install_devnet_fixtures(&mut self) {
        self.shards.insert(
            "delta-shard-0000".to_string(),
            CacheShard {
                shard_id: "delta-shard-0000".to_string(),
                status: ShardStatus::Hot,
                lane_affinity: 0,
                hot_delta_count: 3,
                max_delta_count: 65_536,
                occupancy_bps: 412,
                shard_commitment: fixture_hash(D_SHARDS, "delta-shard-0000"),
                latest_receipt_root: fixture_hash(D_DELTAS, "receipt-root-0000"),
            },
        );
        self.shards.insert(
            "delta-shard-0001".to_string(),
            CacheShard {
                shard_id: "delta-shard-0001".to_string(),
                status: ShardStatus::Warming,
                lane_affinity: 1,
                hot_delta_count: 2,
                max_delta_count: 65_536,
                occupancy_bps: 276,
                shard_commitment: fixture_hash(D_SHARDS, "delta-shard-0001"),
                latest_receipt_root: fixture_hash(D_DELTAS, "receipt-root-0001"),
            },
        );
        self.encrypted_deltas.insert(
            "delta-devnet-0001".to_string(),
            EncryptedReceiptDelta {
                delta_id: "delta-devnet-0001".to_string(),
                shard_id: "delta-shard-0000".to_string(),
                delta_class: DeltaClass::BridgeExit,
                status: DeltaStatus::Hit,
                receipt_commitment: fixture_hash(D_DELTAS, "receipt-commitment-0001"),
                encrypted_delta_commitment: fixture_hash(D_DELTAS, "encrypted-delta-0001"),
                zk_delta_root: fixture_hash(D_DELTAS, "zk-delta-root-0001"),
                nullifier_window_root: fixture_hash(D_DELTAS, "nullifier-window-0001"),
                inserted_l2_height: DEVNET_L2_HEIGHT,
                expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_DELTA_TTL_BLOCKS,
                fee_micros: 8,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            },
        );
        self.encrypted_deltas.insert(
            "delta-devnet-0002".to_string(),
            EncryptedReceiptDelta {
                delta_id: "delta-devnet-0002".to_string(),
                shard_id: "delta-shard-0001".to_string(),
                delta_class: DeltaClass::LowFeeBulk,
                status: DeltaStatus::Prefetched,
                receipt_commitment: fixture_hash(D_DELTAS, "receipt-commitment-0002"),
                encrypted_delta_commitment: fixture_hash(D_DELTAS, "encrypted-delta-0002"),
                zk_delta_root: fixture_hash(D_DELTAS, "zk-delta-root-0002"),
                nullifier_window_root: fixture_hash(D_DELTAS, "nullifier-window-0002"),
                inserted_l2_height: DEVNET_L2_HEIGHT + 1,
                expires_l2_height: DEVNET_L2_HEIGHT + 1 + DEFAULT_DELTA_TTL_BLOCKS,
                fee_micros: 2,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
            },
        );
        self.pq_attestations.insert(
            "attest-devnet-0001".to_string(),
            PqCacheAttestation {
                attestation_id: "attest-devnet-0001".to_string(),
                operator_id: "operator-devnet-fast-cache-0".to_string(),
                shard_id: "delta-shard-0000".to_string(),
                status: AttestationStatus::QuorumAccepted,
                attested_delta_root: fixture_hash(D_ATTESTATIONS, "attested-deltas-0001"),
                cache_hit_rate_bps: 9_240,
                quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                signature_commitment: fixture_hash(D_ATTESTATIONS, "pq-signature-0001"),
                expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
            },
        );
        self.prefetch_lanes.insert(
            "prefetch-lane-bridge-exit".to_string(),
            PrefetchLane {
                lane_id: "prefetch-lane-bridge-exit".to_string(),
                shard_id: "delta-shard-0000".to_string(),
                status: PrefetchLaneStatus::Warmed,
                delta_class: DeltaClass::BridgeExit,
                target_latency_us: 28_000,
                queued_delta_count: 18,
                warmed_delta_count: 16,
                lane_credit_micros: 2_400,
            },
        );
        self.cache_leases.insert(
            "lease-devnet-0001".to_string(),
            CacheLease {
                lease_id: "lease-devnet-0001".to_string(),
                delta_id: "delta-devnet-0001".to_string(),
                lessee_commitment: fixture_hash(D_LEASES, "lessee-commitment-0001"),
                status: CacheLeaseStatus::Active,
                reserved_l2_height: DEVNET_L2_HEIGHT + 2,
                expires_l2_height: DEVNET_L2_HEIGHT + 2 + DEFAULT_LEASE_TTL_BLOCKS,
                lease_fee_micros: 4,
            },
        );
        self.invalidation_fences.insert(
            "fence-devnet-epoch".to_string(),
            InvalidationFence {
                fence_id: "fence-devnet-epoch".to_string(),
                shard_id: "delta-shard-0001".to_string(),
                status: InvalidationFenceStatus::Active,
                fence_root: fixture_hash(D_FENCES, "epoch-fence-root"),
                invalidates_before_height: DEVNET_L2_HEIGHT.saturating_sub(8),
                expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_FENCE_TTL_BLOCKS,
                reason_code: "devnet_epoch_delta_rollover".to_string(),
            },
        );
        self.latency_buckets.insert(
            "hit-lt-50ms".to_string(),
            LatencyBucket {
                bucket_id: "hit-lt-50ms".to_string(),
                upper_bound_us: 50_000,
                hit_count: 41_920,
                miss_count: 144,
                rebate_eligible_count: 72,
            },
        );
        self.low_fee_rebates.insert(
            "rebate-devnet-0001".to_string(),
            LowFeeCacheRebate {
                rebate_id: "rebate-devnet-0001".to_string(),
                delta_id: "delta-devnet-0002".to_string(),
                status: LowFeeRebateStatus::Applied,
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                rebate_micros: 2,
                fee_bps: DEFAULT_TARGET_REBATE_BPS,
                settlement_commitment: fixture_hash(D_REBATES, "settlement-0001"),
                expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_REBATE_TTL_BLOCKS,
            },
        );
        self.redaction_budgets.insert(
            "redaction-budget-devnet-0001".to_string(),
            PrivacyRedactionBudget {
                budget_id: "redaction-budget-devnet-0001".to_string(),
                subject_commitment: fixture_hash(D_REDACTIONS, "subject-0001"),
                status: RedactionBudgetStatus::Debited,
                epoch: DEVNET_EPOCH,
                allowed_fields: 12,
                spent_fields: 3,
                redaction_root: fixture_hash(D_REDACTIONS, "redaction-root-0001"),
            },
        );
        self.spent_nullifiers
            .insert(fixture_hash(D_STATE, "spent-nullifier-0001"));
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for CacheShard {
    fn public_record(&self) -> Value {
        CacheShard::public_record(self)
    }
}

impl PublicRecord for EncryptedReceiptDelta {
    fn public_record(&self) -> Value {
        EncryptedReceiptDelta::public_record(self)
    }
}

impl PublicRecord for PqCacheAttestation {
    fn public_record(&self) -> Value {
        PqCacheAttestation::public_record(self)
    }
}

impl PublicRecord for PrefetchLane {
    fn public_record(&self) -> Value {
        PrefetchLane::public_record(self)
    }
}

impl PublicRecord for CacheLease {
    fn public_record(&self) -> Value {
        CacheLease::public_record(self)
    }
}

impl PublicRecord for InvalidationFence {
    fn public_record(&self) -> Value {
        InvalidationFence::public_record(self)
    }
}

impl PublicRecord for LatencyBucket {
    fn public_record(&self) -> Value {
        LatencyBucket::public_record(self)
    }
}

impl PublicRecord for LowFeeCacheRebate {
    fn public_record(&self) -> Value {
        LowFeeCacheRebate::public_record(self)
    }
}

impl PublicRecord for PrivacyRedactionBudget {
    fn public_record(&self) -> Value {
        PrivacyRedactionBudget::public_record(self)
    }
}

fn public_values<T: PublicRecord>(items: &BTreeMap<String, T>) -> Vec<Value> {
    items.values().map(PublicRecord::public_record).collect()
}

fn hash_json(domain: &'static str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Str(&value.to_string()),
        ],
    )
}

fn merkle_json(domain: &'static str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn fixture_hash(domain: &'static str, label: &'static str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str("devnet-fixture"),
            HashPart::Str(label),
        ],
    )
}
