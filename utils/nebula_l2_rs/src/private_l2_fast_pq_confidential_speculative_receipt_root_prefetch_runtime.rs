use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialSpeculativeReceiptRootPrefetchRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SPECULATIVE_RECEIPT_ROOT_PREFETCH_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-speculative-receipt-root-prefetch-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_SPECULATIVE_RECEIPT_ROOT_PREFETCH_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prefetch-attestation-v1";
pub const RECEIPT_ROOT_SCHEME: &str = "speculative-confidential-receipt-root-v1";
pub const PREFETCH_LANE_SCHEME: &str = "private-l2-prefetch-lane-root-v1";
pub const ENCRYPTED_HINT_SCHEME: &str = "encrypted-receipt-root-hint-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-prefetch-attestation-root-v1";
pub const CACHE_LEASE_SCHEME: &str = "receipt-root-cache-lease-root-v1";
pub const INVALIDATION_FENCE_SCHEME: &str = "receipt-root-invalidation-fence-root-v1";
pub const LATENCY_BUCKET_SCHEME: &str = "receipt-root-prefetch-latency-bucket-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "receipt-root-prefetch-low-fee-rebate-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "confidential-prefetch-redaction-budget-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str = "private-l2-prefetch-operator-summary-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_872_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_PREFETCH_COORDINATOR: &str = "devnet-private-l2-prefetch-coordinator";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_LANES: usize = 256;
pub const DEFAULT_MAX_SPECULATIVE_ROOTS: usize = 4_194_304;
pub const DEFAULT_MAX_ENCRYPTED_HINTS: usize = 4_194_304;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_CACHE_LEASES: usize = 2_097_152;
pub const DEFAULT_MAX_INVALIDATION_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_LATENCY_BUCKETS: usize = 65_536;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 95;
pub const DEFAULT_TARGET_ROOT_BUILD_MS: u64 = 220;
pub const DEFAULT_ROOT_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_CACHE_LEASE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 4;
pub const DEFAULT_REBATE_BPS: u64 = 3;
pub const DEFAULT_PREFETCH_HIT_REBATE_MICRO_UNITS: u64 = 75;
pub const DEFAULT_PREFETCH_MISS_PENALTY_MICRO_UNITS: u64 = 25;
pub const DEFAULT_MAX_HINT_BYTES: u64 = 384;
pub const DEFAULT_MAX_REDACTED_FIELDS_PER_HINT: u16 = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchLaneKind {
    UltraFastReceiptRoot,
    LowFeeReceiptRoot,
    BridgeSettlement,
    DexSwap,
    LendingLiquidation,
    PerpSettlement,
    AccountAbstraction,
    VaultStrategy,
    OracleCallback,
    MoneroExit,
    RecursiveProof,
    BackgroundWarmup,
    EmergencyEscape,
}

impl PrefetchLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFastReceiptRoot => "ultra_fast_receipt_root",
            Self::LowFeeReceiptRoot => "low_fee_receipt_root",
            Self::BridgeSettlement => "bridge_settlement",
            Self::DexSwap => "dex_swap",
            Self::LendingLiquidation => "lending_liquidation",
            Self::PerpSettlement => "perp_settlement",
            Self::AccountAbstraction => "account_abstraction",
            Self::VaultStrategy => "vault_strategy",
            Self::OracleCallback => "oracle_callback",
            Self::MoneroExit => "monero_exit",
            Self::RecursiveProof => "recursive_proof",
            Self::BackgroundWarmup => "background_warmup",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::BridgeSettlement => 9_700,
            Self::MoneroExit => 9_500,
            Self::PerpSettlement => 9_200,
            Self::DexSwap => 8_900,
            Self::UltraFastReceiptRoot => 8_800,
            Self::LendingLiquidation => 8_600,
            Self::OracleCallback => 8_300,
            Self::RecursiveProof => 8_100,
            Self::AccountAbstraction => 7_800,
            Self::VaultStrategy => 7_400,
            Self::LowFeeReceiptRoot => 7_200,
            Self::BackgroundWarmup => 4_500,
        }
    }

    pub fn latency_critical(self) -> bool {
        matches!(
            self,
            Self::UltraFastReceiptRoot
                | Self::BridgeSettlement
                | Self::DexSwap
                | Self::PerpSettlement
                | Self::MoneroExit
                | Self::EmergencyEscape
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    WarmOnly,
    Congested,
    SponsorOnly,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_prefetch(self) -> bool {
        matches!(
            self,
            Self::Open | Self::WarmOnly | Self::Congested | Self::SponsorOnly
        )
    }

    pub fn public_label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::WarmOnly => "warm_only",
            Self::Congested => "congested",
            Self::SponsorOnly => "sponsor_only",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptRootStatus {
    Predicted,
    Prefetched,
    Attested,
    Leased,
    Hit,
    Miss,
    Invalidated,
    Finalized,
    Expired,
}

impl ReceiptRootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Predicted => "predicted",
            Self::Prefetched => "prefetched",
            Self::Attested => "attested",
            Self::Leased => "leased",
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Invalidated => "invalidated",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Predicted | Self::Prefetched | Self::Attested | Self::Leased
        )
    }

    pub fn cacheable(self) -> bool {
        matches!(
            self,
            Self::Prefetched | Self::Attested | Self::Leased | Self::Hit
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintPrivacyTier {
    Shielded,
    Redacted,
    AggregateOnly,
    OperatorBlind,
    EmergencyReveal,
}

impl HintPrivacyTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shielded => "shielded",
            Self::Redacted => "redacted",
            Self::AggregateOnly => "aggregate_only",
            Self::OperatorBlind => "operator_blind",
            Self::EmergencyReveal => "emergency_reveal",
        }
    }

    pub fn requires_budget(self) -> bool {
        matches!(self, Self::Redacted | Self::EmergencyReveal)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Verified,
    Quarantined,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLeaseStatus {
    Reserved,
    Active,
    Released,
    Invalidated,
    Expired,
}

impl CacheLeaseStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Reserved | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    Reorg,
    ConflictingReceipt,
    PrivacyBudgetExceeded,
    OperatorQuarantine,
    CachePoisoning,
    PqAttestationFailure,
    ManualEmergency,
}

impl FenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::ConflictingReceipt => "conflicting_receipt",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::OperatorQuarantine => "operator_quarantine",
            Self::CachePoisoning => "cache_poisoning",
            Self::PqAttestationFailure => "pq_attestation_failure",
            Self::ManualEmergency => "manual_emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    P50,
    P75,
    P90,
    P95,
    P99,
    Max,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::P50 => "p50",
            Self::P75 => "p75",
            Self::P90 => "p90",
            Self::P95 => "p95",
            Self::P99 => "p99",
            Self::Max => "max",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub coordinator: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub receipt_root_scheme: String,
    pub prefetch_lane_scheme: String,
    pub encrypted_hint_scheme: String,
    pub pq_attestation_scheme: String,
    pub cache_lease_scheme: String,
    pub invalidation_fence_scheme: String,
    pub latency_bucket_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub redaction_budget_scheme: String,
    pub operator_summary_scheme: String,
    pub genesis_height: u64,
    pub max_lanes: usize,
    pub max_speculative_roots: usize,
    pub max_encrypted_hints: usize,
    pub max_attestations: usize,
    pub max_cache_leases: usize,
    pub max_invalidation_fences: usize,
    pub max_latency_buckets: usize,
    pub max_rebates: usize,
    pub max_redaction_budgets: usize,
    pub min_pq_security_bits: u16,
    pub target_prefetch_ms: u64,
    pub target_root_build_ms: u64,
    pub root_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub cache_lease_ttl_blocks: u64,
    pub invalidation_fence_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub prefetch_hit_rebate_micro_units: u64,
    pub prefetch_miss_penalty_micro_units: u64,
    pub max_hint_bytes: u64,
    pub max_redacted_fields_per_hint: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            coordinator: DEVNET_PREFETCH_COORDINATOR.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            receipt_root_scheme: RECEIPT_ROOT_SCHEME.to_string(),
            prefetch_lane_scheme: PREFETCH_LANE_SCHEME.to_string(),
            encrypted_hint_scheme: ENCRYPTED_HINT_SCHEME.to_string(),
            pq_attestation_scheme: PQ_ATTESTATION_SCHEME.to_string(),
            cache_lease_scheme: CACHE_LEASE_SCHEME.to_string(),
            invalidation_fence_scheme: INVALIDATION_FENCE_SCHEME.to_string(),
            latency_bucket_scheme: LATENCY_BUCKET_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            genesis_height: DEVNET_HEIGHT,
            max_lanes: DEFAULT_MAX_LANES,
            max_speculative_roots: DEFAULT_MAX_SPECULATIVE_ROOTS,
            max_encrypted_hints: DEFAULT_MAX_ENCRYPTED_HINTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_cache_leases: DEFAULT_MAX_CACHE_LEASES,
            max_invalidation_fences: DEFAULT_MAX_INVALIDATION_FENCES,
            max_latency_buckets: DEFAULT_MAX_LATENCY_BUCKETS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            target_root_build_ms: DEFAULT_TARGET_ROOT_BUILD_MS,
            root_ttl_blocks: DEFAULT_ROOT_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            cache_lease_ttl_blocks: DEFAULT_CACHE_LEASE_TTL_BLOCKS,
            invalidation_fence_ttl_blocks: DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            prefetch_hit_rebate_micro_units: DEFAULT_PREFETCH_HIT_REBATE_MICRO_UNITS,
            prefetch_miss_penalty_micro_units: DEFAULT_PREFETCH_MISS_PENALTY_MICRO_UNITS,
            max_hint_bytes: DEFAULT_MAX_HINT_BYTES,
            max_redacted_fields_per_hint: DEFAULT_MAX_REDACTED_FIELDS_PER_HINT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum PQ security below 192 bits".to_string());
        }
        if self.min_privacy_set_size < 4_096 {
            return Err("privacy set size below private L2 floor".to_string());
        }
        if self.target_user_fee_bps > self.max_user_fee_bps {
            return Err("target fee exceeds configured fee ceiling".to_string());
        }
        if self.rebate_bps > self.max_user_fee_bps {
            return Err("rebate basis points exceed user fee ceiling".to_string());
        }
        if self.max_hint_bytes == 0 {
            return Err("encrypted hint byte ceiling must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "coordinator": self.coordinator,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "receipt_root_scheme": self.receipt_root_scheme,
            "prefetch_lane_scheme": self.prefetch_lane_scheme,
            "encrypted_hint_scheme": self.encrypted_hint_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "cache_lease_scheme": self.cache_lease_scheme,
            "invalidation_fence_scheme": self.invalidation_fence_scheme,
            "latency_bucket_scheme": self.latency_bucket_scheme,
            "low_fee_rebate_scheme": self.low_fee_rebate_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "operator_summary_scheme": self.operator_summary_scheme,
            "genesis_height": self.genesis_height,
            "max_lanes": self.max_lanes,
            "max_speculative_roots": self.max_speculative_roots,
            "max_encrypted_hints": self.max_encrypted_hints,
            "max_attestations": self.max_attestations,
            "max_cache_leases": self.max_cache_leases,
            "max_invalidation_fences": self.max_invalidation_fences,
            "max_latency_buckets": self.max_latency_buckets,
            "max_rebates": self.max_rebates,
            "max_redaction_budgets": self.max_redaction_budgets,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_prefetch_ms": self.target_prefetch_ms,
            "target_root_build_ms": self.target_root_build_ms,
            "root_ttl_blocks": self.root_ttl_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "cache_lease_ttl_blocks": self.cache_lease_ttl_blocks,
            "invalidation_fence_ttl_blocks": self.invalidation_fence_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "prefetch_hit_rebate_micro_units": self.prefetch_hit_rebate_micro_units,
            "prefetch_miss_penalty_micro_units": self.prefetch_miss_penalty_micro_units,
            "max_hint_bytes": self.max_hint_bytes,
            "max_redacted_fields_per_hint": self.max_redacted_fields_per_hint
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.config",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes_opened: u64,
    pub speculative_roots_registered: u64,
    pub roots_prefetched: u64,
    pub roots_attested: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub roots_invalidated: u64,
    pub hints_encrypted: u64,
    pub hints_consumed: u64,
    pub pq_attestations_verified: u64,
    pub cache_leases_issued: u64,
    pub cache_leases_released: u64,
    pub invalidation_fences_raised: u64,
    pub redaction_budget_spent: u64,
    pub low_fee_rebates_issued: u64,
    pub total_rebate_micro_units: u64,
    pub total_penalty_micro_units: u64,
    pub total_prefetch_latency_ms: u64,
    pub total_root_build_latency_ms: u64,
}

impl Counters {
    pub fn hit_rate_bps(&self) -> u64 {
        let total = self.cache_hits.saturating_add(self.cache_misses);
        if total == 0 {
            0
        } else {
            self.cache_hits.saturating_mul(MAX_BPS) / total
        }
    }

    pub fn average_prefetch_latency_ms(&self) -> u64 {
        if self.roots_prefetched == 0 {
            0
        } else {
            self.total_prefetch_latency_ms / self.roots_prefetched
        }
    }

    pub fn average_root_build_latency_ms(&self) -> u64 {
        if self.speculative_roots_registered == 0 {
            0
        } else {
            self.total_root_build_latency_ms / self.speculative_roots_registered
        }
    }

    pub fn net_rebate_micro_units(&self) -> i128 {
        self.total_rebate_micro_units as i128 - self.total_penalty_micro_units as i128
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lanes_opened": self.lanes_opened,
            "speculative_roots_registered": self.speculative_roots_registered,
            "roots_prefetched": self.roots_prefetched,
            "roots_attested": self.roots_attested,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "roots_invalidated": self.roots_invalidated,
            "hints_encrypted": self.hints_encrypted,
            "hints_consumed": self.hints_consumed,
            "pq_attestations_verified": self.pq_attestations_verified,
            "cache_leases_issued": self.cache_leases_issued,
            "cache_leases_released": self.cache_leases_released,
            "invalidation_fences_raised": self.invalidation_fences_raised,
            "redaction_budget_spent": self.redaction_budget_spent,
            "low_fee_rebates_issued": self.low_fee_rebates_issued,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "total_penalty_micro_units": self.total_penalty_micro_units,
            "total_prefetch_latency_ms": self.total_prefetch_latency_ms,
            "total_root_build_latency_ms": self.total_root_build_latency_ms,
            "hit_rate_bps": self.hit_rate_bps(),
            "average_prefetch_latency_ms": self.average_prefetch_latency_ms(),
            "average_root_build_latency_ms": self.average_root_build_latency_ms(),
            "net_rebate_micro_units": self.net_rebate_micro_units()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.counters",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub prefetch_lanes_root: String,
    pub speculative_receipt_roots_root: String,
    pub encrypted_receipt_hints_root: String,
    pub pq_prefetch_attestations_root: String,
    pub cache_leases_root: String,
    pub invalidation_fences_root: String,
    pub latency_buckets_root: String,
    pub low_fee_rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "prefetch_lanes_root": self.prefetch_lanes_root,
            "speculative_receipt_roots_root": self.speculative_receipt_roots_root,
            "encrypted_receipt_hints_root": self.encrypted_receipt_hints_root,
            "pq_prefetch_attestations_root": self.pq_prefetch_attestations_root,
            "cache_leases_root": self.cache_leases_root,
            "invalidation_fences_root": self.invalidation_fences_root,
            "latency_buckets_root": self.latency_buckets_root,
            "low_fee_rebates_root": self.low_fee_rebates_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "operator_summaries_root": self.operator_summaries_root,
            "public_record_root": self.public_record_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchLane {
    pub lane_id: String,
    pub kind: PrefetchLaneKind,
    pub status: LaneStatus,
    pub operator_id: String,
    pub privacy_domain: String,
    pub priority: u64,
    pub capacity_per_block: u64,
    pub target_latency_ms: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub last_prefetch_height: u64,
    pub active_roots: u64,
    pub cache_pressure_bps: u64,
    pub accepts_redacted_hints: bool,
}

impl PrefetchLane {
    pub fn new(
        lane_id: impl Into<String>,
        kind: PrefetchLaneKind,
        operator_id: impl Into<String>,
        height: u64,
    ) -> Self {
        Self {
            lane_id: lane_id.into(),
            kind,
            status: LaneStatus::Open,
            operator_id: operator_id.into(),
            privacy_domain: format!("privacy-domain-{}", kind.as_str()),
            priority: kind.default_priority(),
            capacity_per_block: if kind.latency_critical() {
                8_192
            } else {
                2_048
            },
            target_latency_ms: if kind.latency_critical() { 80 } else { 180 },
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: 8_500,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            opened_at_height: height,
            last_prefetch_height: height,
            active_roots: 0,
            cache_pressure_bps: 0,
            accepts_redacted_hints: !matches!(kind, PrefetchLaneKind::EmergencyEscape),
        }
    }

    pub fn with_capacity(mut self, capacity_per_block: u64) -> Self {
        self.capacity_per_block = capacity_per_block;
        self
    }

    pub fn with_target_latency(mut self, target_latency_ms: u64) -> Self {
        self.target_latency_ms = target_latency_ms;
        self
    }

    pub fn can_prefetch(&self) -> bool {
        self.status.accepts_prefetch()
            && self.pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS
            && self.min_privacy_set_size >= DEFAULT_MIN_PRIVACY_SET_SIZE
    }

    pub fn available_capacity(&self) -> u64 {
        self.capacity_per_block.saturating_sub(self.active_roots)
    }

    pub fn pressure_adjusted_priority(&self) -> u64 {
        self.priority
            .saturating_mul(MAX_BPS.saturating_sub(self.cache_pressure_bps.min(MAX_BPS)))
            / MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.public_label(),
            "operator_id": self.operator_id,
            "privacy_domain": self.privacy_domain,
            "priority": self.priority,
            "pressure_adjusted_priority": self.pressure_adjusted_priority(),
            "capacity_per_block": self.capacity_per_block,
            "available_capacity": self.available_capacity(),
            "target_latency_ms": self.target_latency_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "last_prefetch_height": self.last_prefetch_height,
            "active_roots": self.active_roots,
            "cache_pressure_bps": self.cache_pressure_bps,
            "accepts_redacted_hints": self.accepts_redacted_hints,
            "can_prefetch": self.can_prefetch()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.lane",
            &[
                HashPart::Str(PREFETCH_LANE_SCHEME),
                HashPart::Str(&self.lane_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpeculativeReceiptRoot {
    pub root_id: String,
    pub lane_id: String,
    pub predicted_receipt_root: String,
    pub parent_state_root: String,
    pub execution_commitment_root: String,
    pub nullifier_root: String,
    pub encrypted_hint_root: String,
    pub status: ReceiptRootStatus,
    pub predicted_at_height: u64,
    pub expires_at_height: u64,
    pub root_build_latency_ms: u64,
    pub prefetch_latency_ms: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_ceiling_micro_units: u64,
    pub rebate_micro_units: u64,
    pub invalidation_fence_id: Option<String>,
    pub cache_lease_id: Option<String>,
    pub attestation_id: Option<String>,
}

impl SpeculativeReceiptRoot {
    pub fn new(
        root_id: impl Into<String>,
        lane_id: impl Into<String>,
        parent_state_root: impl Into<String>,
        execution_commitment_root: impl Into<String>,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let root_id = root_id.into();
        let lane_id = lane_id.into();
        let parent_state_root = parent_state_root.into();
        let execution_commitment_root = execution_commitment_root.into();
        let predicted_receipt_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.predicted_root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&root_id),
                HashPart::Str(&lane_id),
                HashPart::Str(&parent_state_root),
                HashPart::Str(&execution_commitment_root),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let nullifier_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.nullifier_root",
            &[
                HashPart::Str(&root_id),
                HashPart::Str(&predicted_receipt_root),
            ],
            32,
        );
        let encrypted_hint_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.hint_root",
            &[HashPart::Str(&root_id), HashPart::Str(&lane_id)],
        );
        Self {
            root_id,
            lane_id,
            predicted_receipt_root,
            parent_state_root,
            execution_commitment_root,
            nullifier_root,
            encrypted_hint_root,
            status: ReceiptRootStatus::Predicted,
            predicted_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            root_build_latency_ms: DEFAULT_TARGET_ROOT_BUILD_MS,
            prefetch_latency_ms: DEFAULT_TARGET_PREFETCH_MS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            fee_ceiling_micro_units: 450,
            rebate_micro_units: DEFAULT_PREFETCH_HIT_REBATE_MICRO_UNITS,
            invalidation_fence_id: None,
            cache_lease_id: None,
            attestation_id: None,
        }
    }

    pub fn mark_prefetched(mut self, latency_ms: u64) -> Self {
        self.status = ReceiptRootStatus::Prefetched;
        self.prefetch_latency_ms = latency_ms;
        self
    }

    pub fn mark_attested(mut self, attestation_id: impl Into<String>) -> Self {
        self.status = ReceiptRootStatus::Attested;
        self.attestation_id = Some(attestation_id.into());
        self
    }

    pub fn attach_cache_lease(mut self, lease_id: impl Into<String>) -> Self {
        self.status = ReceiptRootStatus::Leased;
        self.cache_lease_id = Some(lease_id.into());
        self
    }

    pub fn attach_fence(mut self, fence_id: impl Into<String>) -> Self {
        self.status = ReceiptRootStatus::Invalidated;
        self.invalidation_fence_id = Some(fence_id.into());
        self
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height && self.status.live()
    }

    pub fn eligible_for_rebate(&self) -> bool {
        matches!(
            self.status,
            ReceiptRootStatus::Prefetched
                | ReceiptRootStatus::Attested
                | ReceiptRootStatus::Leased
                | ReceiptRootStatus::Hit
        ) && self.prefetch_latency_ms <= DEFAULT_TARGET_PREFETCH_MS.saturating_mul(2)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "lane_id": self.lane_id,
            "predicted_receipt_root": self.predicted_receipt_root,
            "parent_state_root": self.parent_state_root,
            "execution_commitment_root": self.execution_commitment_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "status": self.status.as_str(),
            "predicted_at_height": self.predicted_at_height,
            "expires_at_height": self.expires_at_height,
            "root_build_latency_ms": self.root_build_latency_ms,
            "prefetch_latency_ms": self.prefetch_latency_ms,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "fee_ceiling_micro_units": self.fee_ceiling_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "invalidation_fence_id": self.invalidation_fence_id,
            "cache_lease_id": self.cache_lease_id,
            "attestation_id": self.attestation_id,
            "eligible_for_rebate": self.eligible_for_rebate()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.speculative_root",
            &[
                HashPart::Str(RECEIPT_ROOT_SCHEME),
                HashPart::Str(&self.root_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptHint {
    pub hint_id: String,
    pub root_id: String,
    pub lane_id: String,
    pub privacy_tier: HintPrivacyTier,
    pub ciphertext_commitment: String,
    pub ephemeral_pq_key_commitment: String,
    pub redaction_commitment: String,
    pub access_nullifier: String,
    pub byte_len: u64,
    pub redacted_fields: u16,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl EncryptedReceiptHint {
    pub fn new(
        hint_id: impl Into<String>,
        root_id: impl Into<String>,
        lane_id: impl Into<String>,
        privacy_tier: HintPrivacyTier,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let hint_id = hint_id.into();
        let root_id = root_id.into();
        let lane_id = lane_id.into();
        let ciphertext_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.hint_ciphertext",
            &[HashPart::Str(&hint_id), HashPart::Str(&root_id)],
        );
        let ephemeral_pq_key_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.hint_pq_key",
            &[HashPart::Str(&hint_id), HashPart::Str(PQ_AUTH_SUITE)],
        );
        let redaction_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.hint_redaction",
            &[
                HashPart::Str(&hint_id),
                HashPart::Str(privacy_tier.as_str()),
            ],
            32,
        );
        let access_nullifier = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.hint_access_nullifier",
            &[HashPart::Str(&hint_id), HashPart::Str(&lane_id)],
        );
        Self {
            hint_id,
            root_id,
            lane_id,
            privacy_tier,
            ciphertext_commitment,
            ephemeral_pq_key_commitment,
            redaction_commitment,
            access_nullifier,
            byte_len: DEFAULT_MAX_HINT_BYTES / 2,
            redacted_fields: if privacy_tier.requires_budget() { 4 } else { 0 },
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            created_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            consumed: false,
        }
    }

    pub fn consume(mut self) -> Self {
        self.consumed = true;
        self
    }

    pub fn valid_for_config(&self, config: &Config) -> bool {
        self.byte_len <= config.max_hint_bytes
            && self.redacted_fields <= config.max_redacted_fields_per_hint
            && self.privacy_set_size >= config.min_privacy_set_size
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "root_id": self.root_id,
            "lane_id": self.lane_id,
            "privacy_tier": self.privacy_tier.as_str(),
            "ciphertext_commitment": self.ciphertext_commitment,
            "ephemeral_pq_key_commitment": self.ephemeral_pq_key_commitment,
            "redaction_commitment": self.redaction_commitment,
            "access_nullifier": self.access_nullifier,
            "byte_len": self.byte_len,
            "redacted_fields": self.redacted_fields,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.encrypted_hint",
            &[
                HashPart::Str(ENCRYPTED_HINT_SCHEME),
                HashPart::Str(&self.hint_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPrefetchAttestation {
    pub attestation_id: String,
    pub root_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub pq_suite: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub status: AttestationStatus,
    pub security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_blocks: u64,
}

impl PqPrefetchAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        root_id: impl Into<String>,
        operator_id: impl Into<String>,
        lane_id: impl Into<String>,
        height: u64,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let root_id = root_id.into();
        let operator_id = operator_id.into();
        let lane_id = lane_id.into();
        let signature_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.attestation_signature",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(&root_id),
                HashPart::Str(&operator_id),
            ],
            32,
        );
        let transcript_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.attestation_transcript",
            &[
                HashPart::Str(&attestation_id),
                HashPart::Str(&lane_id),
                HashPart::Str(PQ_AUTH_SUITE),
            ],
            32,
        );
        Self {
            attestation_id,
            root_id,
            operator_id,
            lane_id,
            pq_suite: PQ_AUTH_SUITE.to_string(),
            signature_commitment,
            transcript_root,
            status: AttestationStatus::Pending,
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attested_at_height: height,
            expires_at_height: height.saturating_add(DEFAULT_ROOT_TTL_BLOCKS),
            challenge_window_blocks: 4,
        }
    }

    pub fn verify(mut self) -> Self {
        self.status = AttestationStatus::Verified;
        self
    }

    pub fn quarantine(mut self) -> Self {
        self.status = AttestationStatus::Quarantined;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "root_id": self.root_id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "pq_suite": self.pq_suite,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "status": self.status,
            "security_bits": self.security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "verified": self.status.verified()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.pq_attestation",
            &[
                HashPart::Str(PQ_ATTESTATION_SCHEME),
                HashPart::Str(&self.attestation_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLease {
    pub lease_id: String,
    pub root_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub status: CacheLeaseStatus,
    pub reserved_bytes: u64,
    pub priority: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub fee_ceiling_micro_units: u64,
    pub rebate_micro_units: u64,
}

impl CacheLease {
    pub fn new(
        lease_id: impl Into<String>,
        root_id: impl Into<String>,
        lane_id: impl Into<String>,
        operator_id: impl Into<String>,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        Self {
            lease_id: lease_id.into(),
            root_id: root_id.into(),
            lane_id: lane_id.into(),
            operator_id: operator_id.into(),
            status: CacheLeaseStatus::Reserved,
            reserved_bytes: 4096,
            priority: 8_000,
            issued_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
            fee_ceiling_micro_units: 425,
            rebate_micro_units: DEFAULT_PREFETCH_HIT_REBATE_MICRO_UNITS,
        }
    }

    pub fn activate(mut self) -> Self {
        self.status = CacheLeaseStatus::Active;
        self
    }

    pub fn release(mut self) -> Self {
        self.status = CacheLeaseStatus::Released;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "root_id": self.root_id,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "reserved_bytes": self.reserved_bytes,
            "priority": self.priority,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "fee_ceiling_micro_units": self.fee_ceiling_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "usable": self.status.usable()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.cache_lease",
            &[
                HashPart::Str(CACHE_LEASE_SCHEME),
                HashPart::Str(&self.lease_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub lane_id: String,
    pub root_id: Option<String>,
    pub reason: FenceReason,
    pub fence_root: String,
    pub raised_by_operator_id: String,
    pub raised_at_height: u64,
    pub expires_at_height: u64,
    pub affected_roots: u64,
    pub public_severity: u8,
}

impl InvalidationFence {
    pub fn new(
        fence_id: impl Into<String>,
        lane_id: impl Into<String>,
        root_id: Option<String>,
        reason: FenceReason,
        operator_id: impl Into<String>,
        height: u64,
    ) -> Self {
        let fence_id = fence_id.into();
        let lane_id = lane_id.into();
        let raised_by_operator_id = operator_id.into();
        let root_part = root_id.as_deref().unwrap_or("lane-wide");
        let fence_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.fence_root",
            &[
                HashPart::Str(&fence_id),
                HashPart::Str(&lane_id),
                HashPart::Str(root_part),
                HashPart::Str(reason.as_str()),
            ],
            32,
        );
        Self {
            fence_id,
            lane_id,
            root_id,
            reason,
            fence_root,
            raised_by_operator_id,
            raised_at_height: height,
            expires_at_height: height.saturating_add(DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS),
            affected_roots: 1,
            public_severity: if matches!(
                reason,
                FenceReason::CachePoisoning | FenceReason::PqAttestationFailure
            ) {
                3
            } else {
                1
            },
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "root_id": self.root_id,
            "reason": self.reason.as_str(),
            "fence_root": self.fence_root,
            "raised_by_operator_id": self.raised_by_operator_id,
            "raised_at_height": self.raised_at_height,
            "expires_at_height": self.expires_at_height,
            "affected_roots": self.affected_roots,
            "public_severity": self.public_severity
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.invalidation_fence",
            &[
                HashPart::Str(INVALIDATION_FENCE_SCHEME),
                HashPart::Str(&self.fence_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub class: LatencyClass,
    pub lower_bound_ms: u64,
    pub upper_bound_ms: u64,
    pub samples: u64,
    pub hits: u64,
    pub misses: u64,
    pub rebates_micro_units: u64,
    pub penalties_micro_units: u64,
}

impl LatencyBucket {
    pub fn new(
        bucket_id: impl Into<String>,
        lane_id: impl Into<String>,
        class: LatencyClass,
        lower_bound_ms: u64,
        upper_bound_ms: u64,
    ) -> Self {
        Self {
            bucket_id: bucket_id.into(),
            lane_id: lane_id.into(),
            class,
            lower_bound_ms,
            upper_bound_ms,
            samples: 0,
            hits: 0,
            misses: 0,
            rebates_micro_units: 0,
            penalties_micro_units: 0,
        }
    }

    pub fn record_hit(&mut self, rebate_micro_units: u64) {
        self.samples = self.samples.saturating_add(1);
        self.hits = self.hits.saturating_add(1);
        self.rebates_micro_units = self.rebates_micro_units.saturating_add(rebate_micro_units);
    }

    pub fn record_miss(&mut self, penalty_micro_units: u64) {
        self.samples = self.samples.saturating_add(1);
        self.misses = self.misses.saturating_add(1);
        self.penalties_micro_units = self
            .penalties_micro_units
            .saturating_add(penalty_micro_units);
    }

    pub fn hit_rate_bps(&self) -> u64 {
        if self.samples == 0 {
            0
        } else {
            self.hits.saturating_mul(MAX_BPS) / self.samples
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "class": self.class.as_str(),
            "lower_bound_ms": self.lower_bound_ms,
            "upper_bound_ms": self.upper_bound_ms,
            "samples": self.samples,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate_bps": self.hit_rate_bps(),
            "rebates_micro_units": self.rebates_micro_units,
            "penalties_micro_units": self.penalties_micro_units
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.latency_bucket",
            &[
                HashPart::Str(LATENCY_BUCKET_SCHEME),
                HashPart::Str(&self.bucket_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub root_id: String,
    pub lane_id: String,
    pub recipient_commitment: String,
    pub amount_micro_units: u64,
    pub fee_paid_micro_units: u64,
    pub effective_fee_bps: u64,
    pub issued_at_height: u64,
    pub settlement_root: String,
    pub claimed: bool,
}

impl LowFeeRebate {
    pub fn new(
        rebate_id: impl Into<String>,
        root_id: impl Into<String>,
        lane_id: impl Into<String>,
        amount_micro_units: u64,
        height: u64,
    ) -> Self {
        let rebate_id = rebate_id.into();
        let root_id = root_id.into();
        let lane_id = lane_id.into();
        let recipient_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.rebate_recipient",
            &[HashPart::Str(&rebate_id), HashPart::Str(&root_id)],
        );
        let settlement_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.rebate_settlement",
            &[HashPart::Str(&rebate_id), HashPart::Str(&lane_id)],
        );
        Self {
            rebate_id,
            root_id,
            lane_id,
            recipient_commitment,
            amount_micro_units,
            fee_paid_micro_units: 400,
            effective_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            issued_at_height: height,
            settlement_root,
            claimed: false,
        }
    }

    pub fn claim(mut self) -> Self {
        self.claimed = true;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "root_id": self.root_id,
            "lane_id": self.lane_id,
            "recipient_commitment": self.recipient_commitment,
            "amount_micro_units": self.amount_micro_units,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "effective_fee_bps": self.effective_fee_bps,
            "issued_at_height": self.issued_at_height,
            "settlement_root": self.settlement_root,
            "claimed": self.claimed
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.low_fee_rebate",
            &[
                HashPart::Str(LOW_FEE_REBATE_SCHEME),
                HashPart::Str(&self.rebate_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub max_redacted_fields: u64,
    pub spent_redacted_fields: u64,
    pub max_emergency_reveals: u64,
    pub spent_emergency_reveals: u64,
    pub privacy_set_floor: u64,
    pub budget_root: String,
}

impl RedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        lane_id: impl Into<String>,
        operator_id: impl Into<String>,
        epoch: u64,
    ) -> Self {
        let budget_id = budget_id.into();
        let lane_id = lane_id.into();
        let operator_id = operator_id.into();
        let budget_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.redaction_budget",
            &[
                HashPart::Str(&budget_id),
                HashPart::Str(&lane_id),
                HashPart::Str(&operator_id),
                HashPart::Int(epoch as i128),
            ],
            32,
        );
        Self {
            budget_id,
            lane_id,
            operator_id,
            epoch,
            max_redacted_fields: 65_536,
            spent_redacted_fields: 0,
            max_emergency_reveals: 4,
            spent_emergency_reveals: 0,
            privacy_set_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
            budget_root,
        }
    }

    pub fn spend(&mut self, redacted_fields: u64, emergency_reveals: u64) -> Result<()> {
        if self.spent_redacted_fields.saturating_add(redacted_fields) > self.max_redacted_fields {
            return Err("redaction field budget exhausted".to_string());
        }
        if self
            .spent_emergency_reveals
            .saturating_add(emergency_reveals)
            > self.max_emergency_reveals
        {
            return Err("emergency reveal budget exhausted".to_string());
        }
        self.spent_redacted_fields = self.spent_redacted_fields.saturating_add(redacted_fields);
        self.spent_emergency_reveals = self
            .spent_emergency_reveals
            .saturating_add(emergency_reveals);
        Ok(())
    }

    pub fn remaining_redacted_fields(&self) -> u64 {
        self.max_redacted_fields
            .saturating_sub(self.spent_redacted_fields)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "max_redacted_fields": self.max_redacted_fields,
            "spent_redacted_fields": self.spent_redacted_fields,
            "remaining_redacted_fields": self.remaining_redacted_fields(),
            "max_emergency_reveals": self.max_emergency_reveals,
            "spent_emergency_reveals": self.spent_emergency_reveals,
            "privacy_set_floor": self.privacy_set_floor,
            "budget_root": self.budget_root
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.redaction_budget_record",
            &[
                HashPart::Str(REDACTION_BUDGET_SCHEME),
                HashPart::Str(&self.budget_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub lane_ids: BTreeSet<String>,
    pub public_key_commitment: String,
    pub pq_key_commitment: String,
    pub total_prefetches: u64,
    pub verified_attestations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub invalidations: u64,
    pub rebates_micro_units: u64,
    pub penalties_micro_units: u64,
    pub median_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub privacy_score_bps: u64,
    pub fee_score_bps: u64,
    pub quarantined: bool,
}

impl OperatorSummary {
    pub fn new(operator_id: impl Into<String>, lane_ids: BTreeSet<String>) -> Self {
        let operator_id = operator_id.into();
        let public_key_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.operator_public_key",
            &[HashPart::Str(&operator_id)],
        );
        let pq_key_commitment = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.operator_pq_key",
            &[HashPart::Str(&operator_id), HashPart::Str(PQ_AUTH_SUITE)],
        );
        Self {
            operator_id,
            lane_ids,
            public_key_commitment,
            pq_key_commitment,
            total_prefetches: 0,
            verified_attestations: 0,
            cache_hits: 0,
            cache_misses: 0,
            invalidations: 0,
            rebates_micro_units: 0,
            penalties_micro_units: 0,
            median_latency_ms: DEFAULT_TARGET_PREFETCH_MS,
            p99_latency_ms: DEFAULT_TARGET_PREFETCH_MS.saturating_mul(3),
            privacy_score_bps: 9_800,
            fee_score_bps: 9_600,
            quarantined: false,
        }
    }

    pub fn hit_rate_bps(&self) -> u64 {
        let total = self.cache_hits.saturating_add(self.cache_misses);
        if total == 0 {
            0
        } else {
            self.cache_hits.saturating_mul(MAX_BPS) / total
        }
    }

    pub fn net_rebate_micro_units(&self) -> i128 {
        self.rebates_micro_units as i128 - self.penalties_micro_units as i128
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "lane_ids": self.lane_ids,
            "public_key_commitment": self.public_key_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "total_prefetches": self.total_prefetches,
            "verified_attestations": self.verified_attestations,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_bps": self.hit_rate_bps(),
            "invalidations": self.invalidations,
            "rebates_micro_units": self.rebates_micro_units,
            "penalties_micro_units": self.penalties_micro_units,
            "net_rebate_micro_units": self.net_rebate_micro_units(),
            "median_latency_ms": self.median_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "privacy_score_bps": self.privacy_score_bps,
            "fee_score_bps": self.fee_score_bps,
            "quarantined": self.quarantined
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.operator_summary",
            &[
                HashPart::Str(OPERATOR_SUMMARY_SCHEME),
                HashPart::Str(&self.operator_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub prefetch_lanes: BTreeMap<String, PrefetchLane>,
    pub speculative_receipt_roots: BTreeMap<String, SpeculativeReceiptRoot>,
    pub encrypted_receipt_hints: BTreeMap<String, EncryptedReceiptHint>,
    pub pq_prefetch_attestations: BTreeMap<String, PqPrefetchAttestation>,
    pub cache_leases: BTreeMap<String, CacheLease>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub active_lane_index: BTreeMap<String, BTreeSet<String>>,
    pub height: u64,
    pub epoch: u64,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            counters: Counters::default(),
            roots: Roots::default(),
            prefetch_lanes: BTreeMap::new(),
            speculative_receipt_roots: BTreeMap::new(),
            encrypted_receipt_hints: BTreeMap::new(),
            pq_prefetch_attestations: BTreeMap::new(),
            cache_leases: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            active_lane_index: BTreeMap::new(),
            height: DEVNET_HEIGHT,
            epoch: 0,
            config,
        };
        state.install_devnet_lanes();
        state.install_devnet_roots();
        state.install_devnet_latency_buckets();
        state.refresh_operator_summaries();
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let fence = InvalidationFence::new(
            "fence-demo-reorg-0001",
            "lane-bridge-settlement",
            Some("root-bridge-settlement-0002".to_string()),
            FenceReason::Reorg,
            "operator-fast-pq-alpha",
            state.height.saturating_add(2),
        );
        let fenced_root = state
            .speculative_receipt_roots
            .get("root-bridge-settlement-0002")
            .cloned()
            .map(|root| root.attach_fence(fence.fence_id.clone()));
        if let Some(root) = fenced_root {
            state
                .speculative_receipt_roots
                .insert(root.root_id.clone(), root);
        }
        state
            .invalidation_fences
            .insert(fence.fence_id.clone(), fence);
        state.counters.invalidation_fences_raised =
            state.counters.invalidation_fences_raised.saturating_add(1);
        state.counters.roots_invalidated = state.counters.roots_invalidated.saturating_add(1);
        state.refresh_operator_summaries();
        state.recompute_roots();
        state
    }

    fn install_devnet_lanes(&mut self) {
        let lanes = [
            PrefetchLane::new(
                "lane-ultra-fast-receipts",
                PrefetchLaneKind::UltraFastReceiptRoot,
                "operator-fast-pq-alpha",
                self.height,
            )
            .with_capacity(16_384)
            .with_target_latency(65),
            PrefetchLane::new(
                "lane-bridge-settlement",
                PrefetchLaneKind::BridgeSettlement,
                "operator-fast-pq-alpha",
                self.height,
            )
            .with_capacity(12_288)
            .with_target_latency(85),
            PrefetchLane::new(
                "lane-low-fee-receipts",
                PrefetchLaneKind::LowFeeReceiptRoot,
                "operator-low-fee-beta",
                self.height,
            )
            .with_capacity(24_576)
            .with_target_latency(150),
            PrefetchLane::new(
                "lane-background-warmup",
                PrefetchLaneKind::BackgroundWarmup,
                "operator-low-fee-beta",
                self.height,
            )
            .with_capacity(32_768)
            .with_target_latency(250),
        ];
        for lane in lanes {
            self.counters.lanes_opened = self.counters.lanes_opened.saturating_add(1);
            self.active_lane_index
                .entry(lane.operator_id.clone())
                .or_default()
                .insert(lane.lane_id.clone());
            self.prefetch_lanes.insert(lane.lane_id.clone(), lane);
        }
    }

    fn install_devnet_roots(&mut self) {
        let specs = [
            (
                "root-ultra-fast-0001",
                "lane-ultra-fast-receipts",
                "parent-state-alpha",
                "execution-commitment-alpha",
                63,
                true,
            ),
            (
                "root-bridge-settlement-0002",
                "lane-bridge-settlement",
                "parent-state-beta",
                "execution-commitment-beta",
                92,
                true,
            ),
            (
                "root-low-fee-0003",
                "lane-low-fee-receipts",
                "parent-state-gamma",
                "execution-commitment-gamma",
                128,
                false,
            ),
            (
                "root-background-0004",
                "lane-background-warmup",
                "parent-state-delta",
                "execution-commitment-delta",
                210,
                false,
            ),
        ];
        for (idx, (root_id, lane_id, parent, commitment, latency, attested)) in
            specs.into_iter().enumerate()
        {
            let mut root = SpeculativeReceiptRoot::new(
                root_id,
                lane_id,
                parent,
                commitment,
                self.height.saturating_add(idx as u64),
                self.config.root_ttl_blocks,
            )
            .mark_prefetched(latency);
            let hint = EncryptedReceiptHint::new(
                format!("hint-{root_id}"),
                root_id,
                lane_id,
                if attested {
                    HintPrivacyTier::OperatorBlind
                } else {
                    HintPrivacyTier::AggregateOnly
                },
                self.height.saturating_add(idx as u64),
                self.config.hint_ttl_blocks,
            );
            let lease = CacheLease::new(
                format!("lease-{root_id}"),
                root_id,
                lane_id,
                if lane_id.contains("low-fee") || lane_id.contains("background") {
                    "operator-low-fee-beta"
                } else {
                    "operator-fast-pq-alpha"
                },
                self.height.saturating_add(idx as u64),
                self.config.cache_lease_ttl_blocks,
            )
            .activate();
            root = root.attach_cache_lease(lease.lease_id.clone());
            if attested {
                let attestation = PqPrefetchAttestation::new(
                    format!("attestation-{root_id}"),
                    root_id,
                    lease.operator_id.clone(),
                    lane_id,
                    self.height.saturating_add(idx as u64),
                )
                .verify();
                root = root.mark_attested(attestation.attestation_id.clone());
                self.counters.roots_attested = self.counters.roots_attested.saturating_add(1);
                self.counters.pq_attestations_verified =
                    self.counters.pq_attestations_verified.saturating_add(1);
                self.pq_prefetch_attestations
                    .insert(attestation.attestation_id.clone(), attestation);
            }
            if root.eligible_for_rebate() {
                let rebate = LowFeeRebate::new(
                    format!("rebate-{root_id}"),
                    root_id,
                    lane_id,
                    self.config.prefetch_hit_rebate_micro_units,
                    self.height.saturating_add(idx as u64),
                );
                self.counters.low_fee_rebates_issued =
                    self.counters.low_fee_rebates_issued.saturating_add(1);
                self.counters.total_rebate_micro_units = self
                    .counters
                    .total_rebate_micro_units
                    .saturating_add(rebate.amount_micro_units);
                self.low_fee_rebates
                    .insert(rebate.rebate_id.clone(), rebate);
            }
            self.counters.speculative_roots_registered =
                self.counters.speculative_roots_registered.saturating_add(1);
            self.counters.roots_prefetched = self.counters.roots_prefetched.saturating_add(1);
            self.counters.cache_leases_issued = self.counters.cache_leases_issued.saturating_add(1);
            self.counters.hints_encrypted = self.counters.hints_encrypted.saturating_add(1);
            self.counters.total_prefetch_latency_ms = self
                .counters
                .total_prefetch_latency_ms
                .saturating_add(root.prefetch_latency_ms);
            self.counters.total_root_build_latency_ms = self
                .counters
                .total_root_build_latency_ms
                .saturating_add(root.root_build_latency_ms);
            if latency <= self.config.target_prefetch_ms {
                self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
            } else {
                self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
                self.counters.total_penalty_micro_units = self
                    .counters
                    .total_penalty_micro_units
                    .saturating_add(self.config.prefetch_miss_penalty_micro_units);
            }
            self.encrypted_receipt_hints
                .insert(hint.hint_id.clone(), hint);
            self.cache_leases.insert(lease.lease_id.clone(), lease);
            self.speculative_receipt_roots
                .insert(root.root_id.clone(), root);
        }
        for lane_id in self.prefetch_lanes.keys().cloned().collect::<Vec<_>>() {
            let active_roots = self
                .speculative_receipt_roots
                .values()
                .filter(|root| root.lane_id == lane_id && root.status.live())
                .count() as u64;
            if let Some(lane) = self.prefetch_lanes.get_mut(&lane_id) {
                lane.active_roots = active_roots;
                lane.cache_pressure_bps =
                    active_roots.saturating_mul(MAX_BPS) / lane.capacity_per_block.max(1);
                lane.last_prefetch_height = self.height.saturating_add(active_roots);
            }
        }
        let mut alpha_budget = RedactionBudget::new(
            "redaction-budget-alpha-epoch-0",
            "lane-ultra-fast-receipts",
            "operator-fast-pq-alpha",
            self.epoch,
        );
        let _ = alpha_budget.spend(8, 0);
        let mut beta_budget = RedactionBudget::new(
            "redaction-budget-beta-epoch-0",
            "lane-low-fee-receipts",
            "operator-low-fee-beta",
            self.epoch,
        );
        let _ = beta_budget.spend(4, 0);
        self.counters.redaction_budget_spent = 12;
        self.redaction_budgets
            .insert(alpha_budget.budget_id.clone(), alpha_budget);
        self.redaction_budgets
            .insert(beta_budget.budget_id.clone(), beta_budget);
    }

    fn install_devnet_latency_buckets(&mut self) {
        let mut p50 = LatencyBucket::new(
            "bucket-ultra-fast-p50",
            "lane-ultra-fast-receipts",
            LatencyClass::P50,
            0,
            75,
        );
        p50.record_hit(self.config.prefetch_hit_rebate_micro_units);
        p50.record_hit(self.config.prefetch_hit_rebate_micro_units);
        let mut p95 = LatencyBucket::new(
            "bucket-bridge-p95",
            "lane-bridge-settlement",
            LatencyClass::P95,
            76,
            150,
        );
        p95.record_hit(self.config.prefetch_hit_rebate_micro_units);
        let mut p99 = LatencyBucket::new(
            "bucket-low-fee-p99",
            "lane-low-fee-receipts",
            LatencyClass::P99,
            151,
            250,
        );
        p99.record_miss(self.config.prefetch_miss_penalty_micro_units);
        for bucket in [p50, p95, p99] {
            self.latency_buckets
                .insert(bucket.bucket_id.clone(), bucket);
        }
    }

    pub fn register_speculative_root(&mut self, root: SpeculativeReceiptRoot) -> Result<String> {
        self.config.validate()?;
        if self.speculative_receipt_roots.len() >= self.config.max_speculative_roots {
            return Err("speculative receipt root capacity exceeded".to_string());
        }
        let lane = self
            .prefetch_lanes
            .get_mut(&root.lane_id)
            .ok_or_else(|| "prefetch lane not found".to_string())?;
        if !lane.can_prefetch() {
            return Err("prefetch lane cannot accept speculative roots".to_string());
        }
        lane.active_roots = lane.active_roots.saturating_add(1);
        lane.last_prefetch_height = self.height;
        self.counters.speculative_roots_registered =
            self.counters.speculative_roots_registered.saturating_add(1);
        self.counters.total_root_build_latency_ms = self
            .counters
            .total_root_build_latency_ms
            .saturating_add(root.root_build_latency_ms);
        let root_id = root.root_id.clone();
        self.speculative_receipt_roots.insert(root_id.clone(), root);
        self.recompute_roots();
        Ok(root_id)
    }

    pub fn register_encrypted_hint(&mut self, hint: EncryptedReceiptHint) -> Result<String> {
        if self.encrypted_receipt_hints.len() >= self.config.max_encrypted_hints {
            return Err("encrypted receipt hint capacity exceeded".to_string());
        }
        if !hint.valid_for_config(&self.config) {
            return Err("encrypted receipt hint violates privacy or byte limits".to_string());
        }
        if !self.speculative_receipt_roots.contains_key(&hint.root_id) {
            return Err("encrypted receipt hint references unknown root".to_string());
        }
        self.counters.hints_encrypted = self.counters.hints_encrypted.saturating_add(1);
        let hint_id = hint.hint_id.clone();
        self.encrypted_receipt_hints.insert(hint_id.clone(), hint);
        self.recompute_roots();
        Ok(hint_id)
    }

    pub fn verify_attestation(&mut self, attestation_id: &str) -> Result<()> {
        let attestation = self
            .pq_prefetch_attestations
            .get_mut(attestation_id)
            .ok_or_else(|| "attestation not found".to_string())?;
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("attestation PQ security below runtime minimum".to_string());
        }
        attestation.status = AttestationStatus::Verified;
        if let Some(root) = self.speculative_receipt_roots.get_mut(&attestation.root_id) {
            root.status = ReceiptRootStatus::Attested;
            root.attestation_id = Some(attestation_id.to_string());
        }
        self.counters.pq_attestations_verified =
            self.counters.pq_attestations_verified.saturating_add(1);
        self.counters.roots_attested = self.counters.roots_attested.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn issue_cache_lease(&mut self, lease: CacheLease) -> Result<String> {
        if self.cache_leases.len() >= self.config.max_cache_leases {
            return Err("cache lease capacity exceeded".to_string());
        }
        if !self.speculative_receipt_roots.contains_key(&lease.root_id) {
            return Err("cache lease references unknown speculative root".to_string());
        }
        let lease_id = lease.lease_id.clone();
        if let Some(root) = self.speculative_receipt_roots.get_mut(&lease.root_id) {
            root.cache_lease_id = Some(lease_id.clone());
            root.status = ReceiptRootStatus::Leased;
        }
        self.counters.cache_leases_issued = self.counters.cache_leases_issued.saturating_add(1);
        self.cache_leases.insert(lease_id.clone(), lease);
        self.recompute_roots();
        Ok(lease_id)
    }

    pub fn raise_invalidation_fence(&mut self, fence: InvalidationFence) -> Result<String> {
        if self.invalidation_fences.len() >= self.config.max_invalidation_fences {
            return Err("invalidation fence capacity exceeded".to_string());
        }
        if let Some(root_id) = &fence.root_id {
            let root = self
                .speculative_receipt_roots
                .get_mut(root_id)
                .ok_or_else(|| "invalidation fence references unknown root".to_string())?;
            root.status = ReceiptRootStatus::Invalidated;
            root.invalidation_fence_id = Some(fence.fence_id.clone());
            self.counters.roots_invalidated = self.counters.roots_invalidated.saturating_add(1);
        }
        self.counters.invalidation_fences_raised =
            self.counters.invalidation_fences_raised.saturating_add(1);
        let fence_id = fence.fence_id.clone();
        self.invalidation_fences.insert(fence_id.clone(), fence);
        self.recompute_roots();
        Ok(fence_id)
    }

    pub fn record_cache_hit(&mut self, root_id: &str, latency_ms: u64) -> Result<()> {
        let root = self
            .speculative_receipt_roots
            .get_mut(root_id)
            .ok_or_else(|| "speculative root not found".to_string())?;
        root.status = ReceiptRootStatus::Hit;
        root.prefetch_latency_ms = latency_ms;
        self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
        self.counters.total_prefetch_latency_ms = self
            .counters
            .total_prefetch_latency_ms
            .saturating_add(latency_ms);
        if root.eligible_for_rebate() {
            let rebate = LowFeeRebate::new(
                format!("rebate-{root_id}-{}", self.counters.low_fee_rebates_issued),
                root_id,
                root.lane_id.clone(),
                self.config.prefetch_hit_rebate_micro_units,
                self.height,
            );
            self.counters.low_fee_rebates_issued =
                self.counters.low_fee_rebates_issued.saturating_add(1);
            self.counters.total_rebate_micro_units = self
                .counters
                .total_rebate_micro_units
                .saturating_add(rebate.amount_micro_units);
            self.low_fee_rebates
                .insert(rebate.rebate_id.clone(), rebate);
        }
        self.recompute_roots();
        Ok(())
    }

    pub fn record_cache_miss(&mut self, root_id: &str, latency_ms: u64) -> Result<()> {
        let root = self
            .speculative_receipt_roots
            .get_mut(root_id)
            .ok_or_else(|| "speculative root not found".to_string())?;
        root.status = ReceiptRootStatus::Miss;
        root.prefetch_latency_ms = latency_ms;
        self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
        self.counters.total_prefetch_latency_ms = self
            .counters
            .total_prefetch_latency_ms
            .saturating_add(latency_ms);
        self.counters.total_penalty_micro_units = self
            .counters
            .total_penalty_micro_units
            .saturating_add(self.config.prefetch_miss_penalty_micro_units);
        self.recompute_roots();
        Ok(())
    }

    pub fn expire_at_height(&mut self, height: u64) {
        self.height = height;
        for root in self.speculative_receipt_roots.values_mut() {
            if root.expired_at(height) {
                root.status = ReceiptRootStatus::Expired;
            }
        }
        for lease in self.cache_leases.values_mut() {
            if height > lease.expires_at_height && lease.status.usable() {
                lease.status = CacheLeaseStatus::Expired;
            }
        }
        for attestation in self.pq_prefetch_attestations.values_mut() {
            if height > attestation.expires_at_height && !attestation.status.verified() {
                attestation.status = AttestationStatus::Expired;
            }
        }
        self.recompute_roots();
    }

    pub fn refresh_operator_summaries(&mut self) {
        self.operator_summaries.clear();
        for (operator_id, lane_ids) in &self.active_lane_index {
            let mut summary = OperatorSummary::new(operator_id.clone(), lane_ids.clone());
            for root in self.speculative_receipt_roots.values() {
                if lane_ids.contains(&root.lane_id) {
                    summary.total_prefetches = summary.total_prefetches.saturating_add(1);
                    if root.status == ReceiptRootStatus::Hit || root.eligible_for_rebate() {
                        summary.cache_hits = summary.cache_hits.saturating_add(1);
                    }
                    if root.status == ReceiptRootStatus::Miss {
                        summary.cache_misses = summary.cache_misses.saturating_add(1);
                    }
                    if root.status == ReceiptRootStatus::Invalidated {
                        summary.invalidations = summary.invalidations.saturating_add(1);
                    }
                    summary.median_latency_ms =
                        summary.median_latency_ms.min(root.prefetch_latency_ms);
                    summary.p99_latency_ms = summary.p99_latency_ms.max(root.prefetch_latency_ms);
                }
            }
            for attestation in self.pq_prefetch_attestations.values() {
                if attestation.operator_id == *operator_id && attestation.status.verified() {
                    summary.verified_attestations = summary.verified_attestations.saturating_add(1);
                }
            }
            for rebate in self.low_fee_rebates.values() {
                if lane_ids.contains(&rebate.lane_id) {
                    summary.rebates_micro_units = summary
                        .rebates_micro_units
                        .saturating_add(rebate.amount_micro_units);
                }
            }
            summary.penalties_micro_units = self
                .config
                .prefetch_miss_penalty_micro_units
                .saturating_mul(summary.cache_misses);
            summary.privacy_score_bps = DEFAULT_MIN_PRIVACY_SET_SIZE
                .saturating_mul(MAX_BPS)
                .checked_div(
                    self.config
                        .min_privacy_set_size
                        .saturating_add(summary.invalidations.saturating_mul(1024))
                        .max(1),
                )
                .unwrap_or(0)
                .min(MAX_BPS);
            summary.fee_score_bps = MAX_BPS.saturating_sub(
                summary
                    .cache_misses
                    .saturating_mul(self.config.max_user_fee_bps)
                    .min(MAX_BPS),
            );
            self.operator_summaries
                .insert(summary.operator_id.clone(), summary);
        }
    }

    pub fn recompute_roots(&mut self) {
        self.roots.config_root = self.config.state_root();
        self.roots.counters_root = self.counters.state_root();
        self.roots.prefetch_lanes_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.prefetch_lanes",
            self.prefetch_lanes
                .values()
                .map(PrefetchLane::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.speculative_receipt_roots_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.speculative_roots",
            self.speculative_receipt_roots
                .values()
                .map(SpeculativeReceiptRoot::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.encrypted_receipt_hints_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.encrypted_hints",
            self.encrypted_receipt_hints
                .values()
                .map(EncryptedReceiptHint::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.pq_prefetch_attestations_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.attestations",
            self.pq_prefetch_attestations
                .values()
                .map(PqPrefetchAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.cache_leases_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.cache_leases",
            self.cache_leases
                .values()
                .map(CacheLease::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.invalidation_fences_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.invalidation_fences",
            self.invalidation_fences
                .values()
                .map(InvalidationFence::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.latency_buckets_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.latency_buckets",
            self.latency_buckets
                .values()
                .map(LatencyBucket::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.low_fee_rebates_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.low_fee_rebates",
            self.low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.redaction_budgets_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.redaction_budgets",
            self.redaction_budgets
                .values()
                .map(RedactionBudget::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.operator_summaries_root = merkle_root(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.operator_summaries",
            self.operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.public_record_root = domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.public_record_root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.prefetch_lanes_root),
                HashPart::Str(&self.roots.speculative_receipt_roots_root),
                HashPart::Str(&self.roots.encrypted_receipt_hints_root),
                HashPart::Str(&self.roots.pq_prefetch_attestations_root),
                HashPart::Str(&self.roots.cache_leases_root),
                HashPart::Str(&self.roots.invalidation_fences_root),
                HashPart::Str(&self.roots.latency_buckets_root),
                HashPart::Str(&self.roots.low_fee_rebates_root),
                HashPart::Str(&self.roots.redaction_budgets_root),
                HashPart::Str(&self.roots.operator_summaries_root),
            ],
            32,
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "prefetch_lanes": self.prefetch_lanes.values().map(PrefetchLane::public_record).collect::<Vec<_>>(),
            "speculative_receipt_roots": self.speculative_receipt_roots.values().map(SpeculativeReceiptRoot::public_record).collect::<Vec<_>>(),
            "encrypted_receipt_hints": self.encrypted_receipt_hints.values().map(EncryptedReceiptHint::public_record).collect::<Vec<_>>(),
            "pq_prefetch_attestations": self.pq_prefetch_attestations.values().map(PqPrefetchAttestation::public_record).collect::<Vec<_>>(),
            "cache_leases": self.cache_leases.values().map(CacheLease::public_record).collect::<Vec<_>>(),
            "invalidation_fences": self.invalidation_fences.values().map(InvalidationFence::public_record).collect::<Vec<_>>(),
            "latency_buckets": self.latency_buckets.values().map(LatencyBucket::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>()
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private_l2_fast_pq_confidential_speculative_receipt_root_prefetch.state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch as i128),
                HashPart::Str(&self.roots.public_record_root),
                HashPart::Json(&self.roots.public_record()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
