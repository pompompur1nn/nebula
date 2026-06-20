#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessPrefetchCreditLaneRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_PREFETCH_CREDIT_LANE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-witness-prefetch-credit-lane-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_PREFETCH_CREDIT_LANE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PREFETCH_LANE_SUITE: &str = "confidential-witness-prefetch-credit-lane-v1";
pub const PQ_CACHE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-prefetch-cache-v1";
pub const WITNESS_CREDIT_SUITE: &str = "private-l2-confidential-witness-credit-note-v1";
pub const SHARD_QUEUE_SUITE: &str = "private-l2-confidential-prefetch-shard-queue-v1";
pub const LATENCY_BUCKET_SUITE: &str = "prefetch-credit-lane-latency-bucket-v1";
pub const FEE_CREDIT_SUITE: &str = "monero-private-l2-low-fee-prefetch-credit-v1";
pub const BACKPRESSURE_QUARANTINE_SUITE: &str =
    "confidential-witness-prefetch-backpressure-quarantine-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "budgeted-prefetch-witness-redaction-root-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-prefetch-credit-lane-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_720_064;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_704_512;
pub const DEVNET_EPOCH: u64 = 18_432;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PREFETCH_MS: u64 = 9;
pub const DEFAULT_MAX_PREFETCH_MS: u64 = 64;
pub const DEFAULT_TARGET_CACHE_HIT_BPS: u64 = 9_450;
pub const DEFAULT_MAX_BACKPRESSURE_BPS: u64 = 7_800;
pub const DEFAULT_PRIVACY_REDACTION_BUDGET_BPS: u64 = 340;
pub const DEFAULT_FEE_CREDIT_REBATE_BPS: u64 = 9;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_900;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_QUEUE_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_FEE_CREDIT_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_MAX_PREFETCH_LANES: usize = 131_072;
pub const DEFAULT_MAX_SHARD_QUEUES: usize = 524_288;
pub const DEFAULT_MAX_WITNESS_CREDITS: usize = 8_388_608;
pub const DEFAULT_MAX_CACHE_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_LATENCY_BUCKETS: usize = 2_097_152;
pub const DEFAULT_MAX_FEE_CREDITS: usize = 4_194_304;
pub const DEFAULT_MAX_QUARANTINES: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 2_097_152;
pub const DEFAULT_MAX_DETERMINISTIC_ROOTS: usize = 2_097_152;
pub const DEFAULT_MAX_DEVNET_FIXTURES: usize = 1_024;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchLaneKind {
    HotAccountWitness,
    ContractStorageWitness,
    MoneroBridgeOutputWitness,
    DefiNettingWitness,
    CrossShardReceiptWitness,
    RecursiveProofWitness,
    FeeCreditWitness,
    EscapeHatchWitness,
}

impl PrefetchLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotAccountWitness => "hot_account_witness",
            Self::ContractStorageWitness => "contract_storage_witness",
            Self::MoneroBridgeOutputWitness => "monero_bridge_output_witness",
            Self::DefiNettingWitness => "defi_netting_witness",
            Self::CrossShardReceiptWitness => "cross_shard_receipt_witness",
            Self::RecursiveProofWitness => "recursive_proof_witness",
            Self::FeeCreditWitness => "fee_credit_witness",
            Self::EscapeHatchWitness => "escape_hatch_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Priming,
    Hot,
    Backpressured,
    Quarantined,
    Draining,
    Suspended,
    Retired,
}

impl LaneStatus {
    pub fn accepts_prefetch(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Priming | Self::Hot | Self::Backpressured
        )
    }

    pub fn is_operator_safe(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Priming | Self::Hot | Self::Draining
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Priming => "priming",
            Self::Hot => "hot",
            Self::Backpressured => "backpressured",
            Self::Quarantined => "quarantined",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Accepting,
    PreferLocal,
    Spillover,
    Backpressured,
    Quarantined,
    Closed,
}

impl QueueStatus {
    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Accepting | Self::PreferLocal | Self::Spillover)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepting => "accepting",
            Self::PreferLocal => "prefer_local",
            Self::Spillover => "spillover",
            Self::Backpressured => "backpressured",
            Self::Quarantined => "quarantined",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Reserved,
    Prefetched,
    Consumed,
    Refunded,
    Expired,
    Challenged,
    Quarantined,
}

impl CreditStatus {
    pub fn is_live(self) -> bool {
        matches!(self, Self::Reserved | Self::Prefetched)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Prefetched => "prefetched",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    CacheHit,
    CacheMiss,
    Hold,
    Reject,
    Slash,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CacheHit => "cache_hit",
            Self::CacheMiss => "cache_miss",
            Self::Hold => "hold",
            Self::Reject => "reject",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    SubFiveMs,
    SubTenMs,
    SubTwentyFiveMs,
    SubFiftyMs,
    SlowPath,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubFiveMs => "sub_five_ms",
            Self::SubTenMs => "sub_ten_ms",
            Self::SubTwentyFiveMs => "sub_twenty_five_ms",
            Self::SubFiftyMs => "sub_fifty_ms",
            Self::SlowPath => "slow_path",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    BackpressureSpike,
    InvalidPqCacheAttestation,
    PrivacyBudgetExceeded,
    WitnessCreditReplay,
    QueueRootDivergence,
    LatencySloBreach,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackpressureSpike => "backpressure_spike",
            Self::InvalidPqCacheAttestation => "invalid_pq_cache_attestation",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::WitnessCreditReplay => "witness_credit_replay",
            Self::QueueRootDivergence => "queue_root_divergence",
            Self::LatencySloBreach => "latency_slo_breach",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub mode: RuntimeMode,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_prefetch_ms: u64,
    pub max_prefetch_ms: u64,
    pub target_cache_hit_bps: u64,
    pub max_backpressure_bps: u64,
    pub privacy_redaction_budget_bps: u64,
    pub fee_credit_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub lane_ttl_blocks: u64,
    pub queue_ttl_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fee_credit_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub max_prefetch_lanes: usize,
    pub max_shard_queues: usize,
    pub max_witness_credits: usize,
    pub max_cache_attestations: usize,
    pub max_latency_buckets: usize,
    pub max_fee_credits: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_deterministic_roots: usize,
    pub max_devnet_fixtures: usize,
    pub max_operator_summaries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            mode: RuntimeMode::Devnet,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_prefetch_ms: DEFAULT_TARGET_PREFETCH_MS,
            max_prefetch_ms: DEFAULT_MAX_PREFETCH_MS,
            target_cache_hit_bps: DEFAULT_TARGET_CACHE_HIT_BPS,
            max_backpressure_bps: DEFAULT_MAX_BACKPRESSURE_BPS,
            privacy_redaction_budget_bps: DEFAULT_PRIVACY_REDACTION_BUDGET_BPS,
            fee_credit_rebate_bps: DEFAULT_FEE_CREDIT_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            queue_ttl_blocks: DEFAULT_QUEUE_TTL_BLOCKS,
            credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fee_credit_ttl_blocks: DEFAULT_FEE_CREDIT_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            max_prefetch_lanes: DEFAULT_MAX_PREFETCH_LANES,
            max_shard_queues: DEFAULT_MAX_SHARD_QUEUES,
            max_witness_credits: DEFAULT_MAX_WITNESS_CREDITS,
            max_cache_attestations: DEFAULT_MAX_CACHE_ATTESTATIONS,
            max_latency_buckets: DEFAULT_MAX_LATENCY_BUCKETS,
            max_fee_credits: DEFAULT_MAX_FEE_CREDITS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_deterministic_roots: DEFAULT_MAX_DETERMINISTIC_ROOTS,
            max_devnet_fixtures: DEFAULT_MAX_DEVNET_FIXTURES,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode.as_str(),
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_prefetch_ms": self.target_prefetch_ms,
            "max_prefetch_ms": self.max_prefetch_ms,
            "target_cache_hit_bps": self.target_cache_hit_bps,
            "max_backpressure_bps": self.max_backpressure_bps,
            "privacy_redaction_budget_bps": self.privacy_redaction_budget_bps,
            "fee_credit_rebate_bps": self.fee_credit_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "lane_ttl_blocks": self.lane_ttl_blocks,
            "queue_ttl_blocks": self.queue_ttl_blocks,
            "credit_ttl_blocks": self.credit_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fee_credit_ttl_blocks": self.fee_credit_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub prefetch_lane_count: u64,
    pub open_lane_count: u64,
    pub shard_queue_count: u64,
    pub accepting_queue_count: u64,
    pub witness_credit_count: u64,
    pub live_witness_credit_count: u64,
    pub pq_cache_attestation_count: u64,
    pub cache_hit_attestation_count: u64,
    pub latency_bucket_count: u64,
    pub fee_credit_count: u64,
    pub quarantine_count: u64,
    pub active_quarantine_count: u64,
    pub redaction_budget_count: u64,
    pub deterministic_root_count: u64,
    pub devnet_fixture_count: u64,
    pub operator_summary_count: u64,
    pub total_reserved_witness_bytes: u64,
    pub total_prefetched_witness_bytes: u64,
    pub total_fee_micro_units: u64,
    pub total_fee_credit_micro_units: u64,
    pub average_prefetch_ms: u64,
    pub average_cache_hit_bps: u64,
    pub average_backpressure_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub prefetch_lane_root: String,
    pub shard_queue_root: String,
    pub witness_credit_root: String,
    pub pq_cache_attestation_root: String,
    pub latency_bucket_root: String,
    pub fee_credit_root: String,
    pub backpressure_quarantine_root: String,
    pub privacy_redaction_budget_root: String,
    pub deterministic_root_root: String,
    pub devnet_fixture_root: String,
    pub operator_summary_root: String,
    pub operator_safe_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty =
            empty_root("private-l2-fast-pq-confidential-witness-prefetch-credit-lane:empty");
        Self {
            prefetch_lane_root: empty.clone(),
            shard_queue_root: empty.clone(),
            witness_credit_root: empty.clone(),
            pq_cache_attestation_root: empty.clone(),
            latency_bucket_root: empty.clone(),
            fee_credit_root: empty.clone(),
            backpressure_quarantine_root: empty.clone(),
            privacy_redaction_budget_root: empty.clone(),
            deterministic_root_root: empty.clone(),
            devnet_fixture_root: empty.clone(),
            operator_summary_root: empty.clone(),
            operator_safe_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchLane {
    pub lane_id: String,
    pub shard_id: String,
    pub operator_id: String,
    pub kind: PrefetchLaneKind,
    pub status: LaneStatus,
    pub priority_weight: u64,
    pub capacity_witness_bytes: u64,
    pub reserved_witness_bytes: u64,
    pub prefetched_witness_bytes: u64,
    pub cache_hit_bps: u64,
    pub backpressure_bps: u64,
    pub average_prefetch_ms: u64,
    pub pq_attestation_key_commitment: String,
    pub privacy_fence_root: String,
    pub queue_commitment_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl PrefetchLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "priority_weight": self.priority_weight,
            "capacity_witness_bytes": self.capacity_witness_bytes,
            "reserved_witness_bytes": self.reserved_witness_bytes,
            "prefetched_witness_bytes": self.prefetched_witness_bytes,
            "cache_hit_bps": self.cache_hit_bps,
            "backpressure_bps": self.backpressure_bps,
            "average_prefetch_ms": self.average_prefetch_ms,
            "pq_attestation_key_commitment": self.pq_attestation_key_commitment,
            "privacy_fence_root": self.privacy_fence_root,
            "queue_commitment_root": self.queue_commitment_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardQueue {
    pub queue_id: String,
    pub shard_id: String,
    pub lane_ids: BTreeSet<String>,
    pub status: QueueStatus,
    pub encrypted_queue_root: String,
    pub pending_credit_count: u64,
    pub pending_witness_bytes: u64,
    pub local_hit_bps: u64,
    pub spillover_bps: u64,
    pub max_depth: u64,
    pub updated_at_height: u64,
}

impl ShardQueue {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "shard_id": self.shard_id,
            "lane_ids": self.lane_ids,
            "status": self.status.as_str(),
            "encrypted_queue_root": self.encrypted_queue_root,
            "pending_credit_count": self.pending_credit_count,
            "pending_witness_bytes": self.pending_witness_bytes,
            "local_hit_bps": self.local_hit_bps,
            "spillover_bps": self.spillover_bps,
            "max_depth": self.max_depth,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCredit {
    pub credit_id: String,
    pub lane_id: String,
    pub queue_id: String,
    pub shard_id: String,
    pub account_hint_tag: String,
    pub contract_id: String,
    pub status: CreditStatus,
    pub encrypted_witness_root: String,
    pub nullifier_commitment: String,
    pub witness_bytes: u64,
    pub fee_micro_units: u64,
    pub priority_score: u64,
    pub privacy_set_size: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl WitnessCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "lane_id": self.lane_id,
            "queue_id": self.queue_id,
            "shard_id": self.shard_id,
            "account_hint_tag": self.account_hint_tag,
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "encrypted_witness_root": self.encrypted_witness_root,
            "nullifier_commitment": self.nullifier_commitment,
            "witness_bytes": self.witness_bytes,
            "fee_micro_units": self.fee_micro_units,
            "priority_score": self.priority_score,
            "privacy_set_size": self.privacy_set_size,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCreditRequest {
    pub lane_id: String,
    pub queue_id: String,
    pub shard_id: String,
    pub account_hint_tag: String,
    pub contract_id: String,
    pub witness_bytes: u64,
    pub fee_micro_units: u64,
    pub priority_score: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestation {
    pub attestation_id: String,
    pub credit_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub verdict: AttestationVerdict,
    pub pq_signature_root: String,
    pub cache_leaf_root: String,
    pub transcript_root: String,
    pub measured_prefetch_ms: u64,
    pub cache_hit_bps: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqCacheAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "credit_id": self.credit_id,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "verdict": self.verdict.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "cache_leaf_root": self.cache_leaf_root,
            "transcript_root": self.transcript_root,
            "measured_prefetch_ms": self.measured_prefetch_ms,
            "cache_hit_bps": self.cache_hit_bps,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub shard_id: String,
    pub class: LatencyClass,
    pub sample_count: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub cache_hit_bps: u64,
    pub fee_credit_bps: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
}

impl LatencyBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "shard_id": self.shard_id,
            "class": self.class.as_str(),
            "sample_count": self.sample_count,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "cache_hit_bps": self.cache_hit_bps,
            "fee_credit_bps": self.fee_credit_bps,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCredit {
    pub fee_credit_id: String,
    pub credit_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub rebate_micro_units: u64,
    pub user_fee_cap_micro_units: u64,
    pub sponsor_cover_bps: u64,
    pub low_fee_receipt_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_credit_id": self.fee_credit_id,
            "credit_id": self.credit_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "rebate_micro_units": self.rebate_micro_units,
            "user_fee_cap_micro_units": self.user_fee_cap_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureQuarantine {
    pub quarantine_id: String,
    pub lane_id: String,
    pub queue_id: String,
    pub reason: QuarantineReason,
    pub encrypted_evidence_root: String,
    pub public_reason_code: String,
    pub backpressure_bps: u64,
    pub affected_credit_count: u64,
    pub opened_at_height: u64,
    pub releases_at_height: u64,
    pub active: bool,
}

impl BackpressureQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "lane_id": self.lane_id,
            "queue_id": self.queue_id,
            "reason": self.reason.as_str(),
            "encrypted_evidence_root": self.encrypted_evidence_root,
            "public_reason_code": self.public_reason_code,
            "backpressure_bps": self.backpressure_bps,
            "affected_credit_count": self.affected_credit_count,
            "opened_at_height": self.opened_at_height,
            "releases_at_height": self.releases_at_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane_id: String,
    pub queue_id: String,
    pub redacted_witness_root: String,
    pub privacy_set_size: u64,
    pub redaction_budget_bps: u64,
    pub disclosed_field_count: u64,
    pub withheld_field_count: u64,
    pub applied_at_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane_id": self.lane_id,
            "queue_id": self.queue_id,
            "redacted_witness_root": self.redacted_witness_root,
            "privacy_set_size": self.privacy_set_size,
            "redaction_budget_bps": self.redaction_budget_bps,
            "disclosed_field_count": self.disclosed_field_count,
            "withheld_field_count": self.withheld_field_count,
            "applied_at_height": self.applied_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRootRecord {
    pub root_id: String,
    pub domain: String,
    pub lane_id: String,
    pub queue_id: String,
    pub root: String,
    pub leaf_count: u64,
    pub computed_at_height: u64,
}

impl DeterministicRootRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub lane_id: String,
    pub queue_id: String,
    pub credit_id: String,
    pub expected_state_root: String,
    pub note: String,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub cache_hit_bps: u64,
    pub average_prefetch_ms: u64,
    pub fee_credit_micro_units: u64,
    pub active_quarantine_count: u64,
    pub operator_safe_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub prefetch_lanes: BTreeMap<String, PrefetchLane>,
    pub shard_queues: BTreeMap<String, ShardQueue>,
    pub witness_credits: BTreeMap<String, WitnessCredit>,
    pub pq_cache_attestations: BTreeMap<String, PqCacheAttestation>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub fee_credits: BTreeMap<String, FeeCredit>,
    pub backpressure_quarantines: BTreeMap<String, BackpressureQuarantine>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub deterministic_roots: BTreeMap<String, DeterministicRootRecord>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub credit_index_by_lane: BTreeMap<String, BTreeSet<String>>,
    pub credit_index_by_queue: BTreeMap<String, BTreeSet<String>>,
    pub quarantine_index_by_lane: BTreeMap<String, BTreeSet<String>>,
    pub counters: Counters,
    pub roots: Roots,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            prefetch_lanes: BTreeMap::new(),
            shard_queues: BTreeMap::new(),
            witness_credits: BTreeMap::new(),
            pq_cache_attestations: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            fee_credits: BTreeMap::new(),
            backpressure_quarantines: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            deterministic_roots: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            credit_index_by_lane: BTreeMap::new(),
            credit_index_by_queue: BTreeMap::new(),
            quarantine_index_by_lane: BTreeMap::new(),
            counters: Counters::default(),
            roots: Roots::default(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn with_config(config: Config) -> Self {
        let mut state = Self {
            config,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn insert_prefetch_lane(&mut self, lane: PrefetchLane) -> Result<()> {
        ensure!(
            self.prefetch_lanes.len() < self.config.max_prefetch_lanes
                || self.prefetch_lanes.contains_key(&lane.lane_id),
            "prefetch lane capacity exceeded"
        );
        ensure!(
            lane.cache_hit_bps <= MAX_BPS,
            "lane {} cache hit bps exceeds max",
            lane.lane_id
        );
        ensure!(
            lane.backpressure_bps <= MAX_BPS,
            "lane {} backpressure bps exceeds max",
            lane.lane_id
        );
        ensure!(
            lane.reserved_witness_bytes <= lane.capacity_witness_bytes,
            "lane {} reserve exceeds capacity",
            lane.lane_id
        );
        self.prefetch_lanes.insert(lane.lane_id.clone(), lane);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_shard_queue(&mut self, queue: ShardQueue) -> Result<()> {
        ensure!(
            self.shard_queues.len() < self.config.max_shard_queues
                || self.shard_queues.contains_key(&queue.queue_id),
            "shard queue capacity exceeded"
        );
        for lane_id in &queue.lane_ids {
            ensure!(
                self.prefetch_lanes.contains_key(lane_id),
                "queue {} references unknown lane {}",
                queue.queue_id,
                lane_id
            );
        }
        self.shard_queues.insert(queue.queue_id.clone(), queue);
        self.refresh_roots();
        Ok(())
    }

    pub fn reserve_witness_credit(&mut self, request: WitnessCreditRequest) -> Result<String> {
        ensure!(
            self.witness_credits.len() < self.config.max_witness_credits,
            "witness credit capacity exceeded"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small for witness credit"
        );
        {
            let lane = self
                .prefetch_lanes
                .get(&request.lane_id)
                .ok_or_else(|| format!("unknown prefetch lane {}", request.lane_id))?;
            ensure!(
                lane.status.accepts_prefetch(),
                "prefetch lane {} does not accept credits",
                request.lane_id
            );
            ensure!(
                lane.reserved_witness_bytes + request.witness_bytes <= lane.capacity_witness_bytes,
                "prefetch lane {} capacity exceeded",
                request.lane_id
            );
        }
        {
            let queue = self
                .shard_queues
                .get(&request.queue_id)
                .ok_or_else(|| format!("unknown shard queue {}", request.queue_id))?;
            ensure!(
                queue.status.accepts_writes(),
                "queue {} does not accept credits",
                request.queue_id
            );
            ensure!(
                queue.lane_ids.contains(&request.lane_id),
                "queue {} is not bound to lane {}",
                request.queue_id,
                request.lane_id
            );
        }

        let credit_id = credit_id(&request, self.l2_height, self.witness_credits.len() as u64);
        let encrypted_witness_root = domain_hash(
            WITNESS_CREDIT_SUITE,
            &[
                HashPart::Str(&credit_id),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.account_hint_tag),
                HashPart::U64(request.witness_bytes),
            ],
            32,
        );
        let nullifier_commitment = domain_hash(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:nullifier",
            &[
                HashPart::Str(&credit_id),
                HashPart::Str(&request.shard_id),
                HashPart::U64(self.epoch),
            ],
            32,
        );
        let credit = WitnessCredit {
            credit_id: credit_id.clone(),
            lane_id: request.lane_id.clone(),
            queue_id: request.queue_id.clone(),
            shard_id: request.shard_id,
            account_hint_tag: request.account_hint_tag,
            contract_id: request.contract_id,
            status: CreditStatus::Reserved,
            encrypted_witness_root,
            nullifier_commitment,
            witness_bytes: request.witness_bytes,
            fee_micro_units: request.fee_micro_units,
            priority_score: request.priority_score,
            privacy_set_size: request.privacy_set_size,
            reserved_at_height: self.l2_height,
            expires_at_height: self.l2_height + self.config.credit_ttl_blocks,
        };

        if let Some(lane) = self.prefetch_lanes.get_mut(&request.lane_id) {
            lane.reserved_witness_bytes += request.witness_bytes;
            lane.updated_at_height = self.l2_height;
        }
        if let Some(queue) = self.shard_queues.get_mut(&request.queue_id) {
            queue.pending_credit_count += 1;
            queue.pending_witness_bytes += request.witness_bytes;
            queue.updated_at_height = self.l2_height;
        }
        self.credit_index_by_lane
            .entry(request.lane_id)
            .or_default()
            .insert(credit_id.clone());
        self.credit_index_by_queue
            .entry(request.queue_id)
            .or_default()
            .insert(credit_id.clone());
        self.witness_credits.insert(credit_id.clone(), credit);
        self.refresh_roots();
        Ok(credit_id)
    }

    pub fn mark_prefetched(&mut self, credit_id: &str, measured_prefetch_ms: u64) -> Result<()> {
        let credit = self
            .witness_credits
            .get_mut(credit_id)
            .ok_or_else(|| format!("unknown witness credit {}", credit_id))?;
        ensure!(
            credit.status == CreditStatus::Reserved,
            "credit {} is not reservable",
            credit_id
        );
        credit.status = CreditStatus::Prefetched;
        if let Some(lane) = self.prefetch_lanes.get_mut(&credit.lane_id) {
            lane.prefetched_witness_bytes += credit.witness_bytes;
            lane.average_prefetch_ms =
                rolling_average(lane.average_prefetch_ms, measured_prefetch_ms);
            lane.updated_at_height = self.l2_height;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn consume_credit(&mut self, credit_id: &str) -> Result<()> {
        let credit = self
            .witness_credits
            .get_mut(credit_id)
            .ok_or_else(|| format!("unknown witness credit {}", credit_id))?;
        ensure!(credit.status.is_live(), "credit {} is not live", credit_id);
        credit.status = CreditStatus::Consumed;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_pq_cache_attestation(&mut self, attestation: PqCacheAttestation) -> Result<()> {
        ensure!(
            self.pq_cache_attestations.len() < self.config.max_cache_attestations
                || self
                    .pq_cache_attestations
                    .contains_key(&attestation.attestation_id),
            "pq cache attestation capacity exceeded"
        );
        ensure!(
            self.witness_credits.contains_key(&attestation.credit_id),
            "attestation references unknown credit {}",
            attestation.credit_id
        );
        ensure!(
            self.prefetch_lanes.contains_key(&attestation.lane_id),
            "attestation references unknown lane {}",
            attestation.lane_id
        );
        if let Some(credit) = self.witness_credits.get_mut(&attestation.credit_id) {
            if attestation.verdict == AttestationVerdict::CacheHit {
                credit.status = CreditStatus::Prefetched;
            } else if matches!(
                attestation.verdict,
                AttestationVerdict::Reject | AttestationVerdict::Slash
            ) {
                credit.status = CreditStatus::Challenged;
            }
        }
        if let Some(lane) = self.prefetch_lanes.get_mut(&attestation.lane_id) {
            lane.cache_hit_bps = rolling_average(lane.cache_hit_bps, attestation.cache_hit_bps);
            lane.average_prefetch_ms =
                rolling_average(lane.average_prefetch_ms, attestation.measured_prefetch_ms);
            lane.updated_at_height = self.l2_height;
        }
        self.pq_cache_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_latency_bucket(&mut self, bucket: LatencyBucket) -> Result<()> {
        ensure!(
            self.latency_buckets.len() < self.config.max_latency_buckets
                || self.latency_buckets.contains_key(&bucket.bucket_id),
            "latency bucket capacity exceeded"
        );
        ensure!(
            self.prefetch_lanes.contains_key(&bucket.lane_id),
            "latency bucket references unknown lane {}",
            bucket.lane_id
        );
        self.latency_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_fee_credit(&mut self, fee_credit: FeeCredit) -> Result<()> {
        ensure!(
            self.fee_credits.len() < self.config.max_fee_credits
                || self.fee_credits.contains_key(&fee_credit.fee_credit_id),
            "fee credit capacity exceeded"
        );
        ensure!(
            fee_credit.sponsor_cover_bps <= MAX_BPS,
            "fee credit sponsor cover exceeds max"
        );
        ensure!(
            self.witness_credits.contains_key(&fee_credit.credit_id),
            "fee credit references unknown witness credit {}",
            fee_credit.credit_id
        );
        self.fee_credits
            .insert(fee_credit.fee_credit_id.clone(), fee_credit);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_backpressure(&mut self, quarantine: BackpressureQuarantine) -> Result<()> {
        ensure!(
            self.backpressure_quarantines.len() < self.config.max_quarantines
                || self
                    .backpressure_quarantines
                    .contains_key(&quarantine.quarantine_id),
            "backpressure quarantine capacity exceeded"
        );
        ensure!(
            self.prefetch_lanes.contains_key(&quarantine.lane_id),
            "quarantine references unknown lane {}",
            quarantine.lane_id
        );
        ensure!(
            self.shard_queues.contains_key(&quarantine.queue_id),
            "quarantine references unknown queue {}",
            quarantine.queue_id
        );
        if let Some(lane) = self.prefetch_lanes.get_mut(&quarantine.lane_id) {
            lane.status = LaneStatus::Quarantined;
            lane.backpressure_bps = quarantine.backpressure_bps;
            lane.updated_at_height = self.l2_height;
        }
        if let Some(queue) = self.shard_queues.get_mut(&quarantine.queue_id) {
            queue.status = QueueStatus::Quarantined;
            queue.updated_at_height = self.l2_height;
        }
        self.quarantine_index_by_lane
            .entry(quarantine.lane_id.clone())
            .or_default()
            .insert(quarantine.quarantine_id.clone());
        self.backpressure_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_privacy_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<()> {
        ensure!(
            self.privacy_redaction_budgets.len() < self.config.max_redaction_budgets
                || self
                    .privacy_redaction_budgets
                    .contains_key(&budget.budget_id),
            "privacy redaction budget capacity exceeded"
        );
        ensure!(
            budget.privacy_set_size >= self.config.min_privacy_set_size,
            "redaction budget privacy set too small"
        );
        ensure!(
            budget.redaction_budget_bps <= self.config.privacy_redaction_budget_bps,
            "redaction budget exceeds configured budget"
        );
        self.privacy_redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_deterministic_root(&mut self, record: DeterministicRootRecord) -> Result<()> {
        ensure!(
            self.deterministic_roots.len() < self.config.max_deterministic_roots
                || self.deterministic_roots.contains_key(&record.root_id),
            "deterministic root capacity exceeded"
        );
        self.deterministic_roots
            .insert(record.root_id.clone(), record);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_devnet_fixture(&mut self, fixture: DevnetFixture) -> Result<()> {
        ensure!(
            self.devnet_fixtures.len() < self.config.max_devnet_fixtures
                || self.devnet_fixtures.contains_key(&fixture.fixture_id),
            "devnet fixture capacity exceeded"
        );
        self.devnet_fixtures
            .insert(fixture.fixture_id.clone(), fixture);
        self.refresh_roots();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries
                || self.operator_summaries.contains_key(&summary.summary_id),
            "operator summary capacity exceeded"
        );
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "prefetch_lane_suite": PREFETCH_LANE_SUITE,
            "pq_cache_attestation_suite": PQ_CACHE_ATTESTATION_SUITE,
            "witness_credit_suite": WITNESS_CREDIT_SUITE,
            "shard_queue_suite": SHARD_QUEUE_SUITE,
            "latency_bucket_suite": LATENCY_BUCKET_SUITE,
            "fee_credit_suite": FEE_CREDIT_SUITE,
            "backpressure_quarantine_suite": BACKPRESSURE_QUARANTINE_SUITE,
            "privacy_redaction_suite": PRIVACY_REDACTION_SUITE,
            "operator_summary_suite": OPERATOR_SUMMARY_SUITE,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "mode": self.config.mode.as_str(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "prefetch_lanes": self
                .prefetch_lanes
                .values()
                .map(PrefetchLane::public_record)
                .collect::<Vec<_>>(),
            "shard_queues": self
                .shard_queues
                .values()
                .map(ShardQueue::public_record)
                .collect::<Vec<_>>(),
            "operator_summaries": self
                .operator_summaries
                .values()
                .map(OperatorSummary::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = json!({
            "backpressure_quarantine_root": self.roots.backpressure_quarantine_root,
            "deterministic_root_root": self.roots.deterministic_root_root,
            "devnet_fixture_root": self.roots.devnet_fixture_root,
            "fee_credit_root": self.roots.fee_credit_root,
            "latency_bucket_root": self.roots.latency_bucket_root,
            "operator_safe_root": self.roots.operator_safe_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "pq_cache_attestation_root": self.roots.pq_cache_attestation_root,
            "prefetch_lane_root": self.roots.prefetch_lane_root,
            "privacy_redaction_budget_root": self.roots.privacy_redaction_budget_root,
            "shard_queue_root": self.roots.shard_queue_root,
            "witness_credit_root": self.roots.witness_credit_root,
        });
        domain_hash(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.l2_network),
                HashPart::Str(&self.config.monero_network),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
                HashPart::Json(&roots),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots.prefetch_lane_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:prefetch-lanes",
            self.prefetch_lanes
                .values()
                .map(PrefetchLane::public_record),
        );
        self.roots.shard_queue_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:shard-queues",
            self.shard_queues.values().map(ShardQueue::public_record),
        );
        self.roots.witness_credit_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:witness-credits",
            self.witness_credits
                .values()
                .map(WitnessCredit::public_record),
        );
        self.roots.pq_cache_attestation_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:pq-cache-attestations",
            self.pq_cache_attestations
                .values()
                .map(PqCacheAttestation::public_record),
        );
        self.roots.latency_bucket_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:latency-buckets",
            self.latency_buckets
                .values()
                .map(LatencyBucket::public_record),
        );
        self.roots.fee_credit_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:fee-credits",
            self.fee_credits.values().map(FeeCredit::public_record),
        );
        self.roots.backpressure_quarantine_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:quarantines",
            self.backpressure_quarantines
                .values()
                .map(BackpressureQuarantine::public_record),
        );
        self.roots.privacy_redaction_budget_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:redaction-budgets",
            self.privacy_redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record),
        );
        self.roots.deterministic_root_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:deterministic-roots",
            self.deterministic_roots
                .values()
                .map(DeterministicRootRecord::public_record),
        );
        self.roots.devnet_fixture_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:devnet-fixtures",
            self.devnet_fixtures
                .values()
                .map(DevnetFixture::public_record),
        );
        self.roots.operator_summary_root = root_from_public_records(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:operator-summaries",
            self.operator_summaries
                .values()
                .map(OperatorSummary::public_record),
        );
        self.roots.operator_safe_root = domain_hash(
            "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:operator-safe-root",
            &[
                HashPart::Str(&self.roots.operator_summary_root),
                HashPart::U64(self.counters.live_witness_credit_count),
                HashPart::U64(self.counters.total_fee_credit_micro_units),
                HashPart::U64(self.counters.average_prefetch_ms),
            ],
            32,
        );
        self.roots.state_root = self.state_root();
    }

    fn derive_counters(&self) -> Counters {
        let open_lane_count = self
            .prefetch_lanes
            .values()
            .filter(|lane| lane.status.is_operator_safe())
            .count() as u64;
        let accepting_queue_count = self
            .shard_queues
            .values()
            .filter(|queue| queue.status.accepts_writes())
            .count() as u64;
        let live_witness_credit_count = self
            .witness_credits
            .values()
            .filter(|credit| credit.status.is_live())
            .count() as u64;
        let cache_hit_attestation_count = self
            .pq_cache_attestations
            .values()
            .filter(|attestation| attestation.verdict == AttestationVerdict::CacheHit)
            .count() as u64;
        let active_quarantine_count = self
            .backpressure_quarantines
            .values()
            .filter(|quarantine| quarantine.active)
            .count() as u64;
        let total_reserved_witness_bytes = self
            .prefetch_lanes
            .values()
            .map(|lane| lane.reserved_witness_bytes)
            .sum();
        let total_prefetched_witness_bytes = self
            .prefetch_lanes
            .values()
            .map(|lane| lane.prefetched_witness_bytes)
            .sum();
        let total_fee_micro_units = self
            .witness_credits
            .values()
            .map(|credit| credit.fee_micro_units)
            .sum();
        let total_fee_credit_micro_units = self
            .fee_credits
            .values()
            .map(|credit| credit.rebate_micro_units)
            .sum();
        let average_prefetch_ms = average_u64(
            self.prefetch_lanes
                .values()
                .map(|lane| lane.average_prefetch_ms),
        );
        let average_cache_hit_bps =
            average_u64(self.prefetch_lanes.values().map(|lane| lane.cache_hit_bps));
        let average_backpressure_bps = average_u64(
            self.prefetch_lanes
                .values()
                .map(|lane| lane.backpressure_bps),
        );

        Counters {
            prefetch_lane_count: self.prefetch_lanes.len() as u64,
            open_lane_count,
            shard_queue_count: self.shard_queues.len() as u64,
            accepting_queue_count,
            witness_credit_count: self.witness_credits.len() as u64,
            live_witness_credit_count,
            pq_cache_attestation_count: self.pq_cache_attestations.len() as u64,
            cache_hit_attestation_count,
            latency_bucket_count: self.latency_buckets.len() as u64,
            fee_credit_count: self.fee_credits.len() as u64,
            quarantine_count: self.backpressure_quarantines.len() as u64,
            active_quarantine_count,
            redaction_budget_count: self.privacy_redaction_budgets.len() as u64,
            deterministic_root_count: self.deterministic_roots.len() as u64,
            devnet_fixture_count: self.devnet_fixtures.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            total_reserved_witness_bytes,
            total_prefetched_witness_bytes,
            total_fee_micro_units,
            total_fee_credit_micro_units,
            average_prefetch_ms,
            average_cache_hit_bps,
            average_backpressure_bps,
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let lane_a = sample_lane(
        "prefetch-hot-accounts-a",
        "shard-0007",
        "operator-prefetch-alpha",
        PrefetchLaneKind::HotAccountWitness,
        LaneStatus::Hot,
        67_108_864,
        9_620,
        6,
    );
    let lane_b = sample_lane(
        "prefetch-contract-storage-b",
        "shard-0011",
        "operator-prefetch-beta",
        PrefetchLaneKind::ContractStorageWitness,
        LaneStatus::Open,
        134_217_728,
        9_410,
        8,
    );
    let lane_c = sample_lane(
        "prefetch-monero-bridge-c",
        "shard-bridge-03",
        "operator-prefetch-gamma",
        PrefetchLaneKind::MoneroBridgeOutputWitness,
        LaneStatus::Hot,
        50_331_648,
        9_530,
        7,
    );
    state.insert_prefetch_lane(lane_a).expect("sample lane a");
    state.insert_prefetch_lane(lane_b).expect("sample lane b");
    state.insert_prefetch_lane(lane_c).expect("sample lane c");

    state
        .insert_shard_queue(sample_queue(
            "queue-hot-accounts-0007",
            "shard-0007",
            ["prefetch-hot-accounts-a"],
            QueueStatus::Accepting,
            9_700,
        ))
        .expect("sample queue a");
    state
        .insert_shard_queue(sample_queue(
            "queue-contract-storage-0011",
            "shard-0011",
            ["prefetch-contract-storage-b"],
            QueueStatus::PreferLocal,
            9_420,
        ))
        .expect("sample queue b");
    state
        .insert_shard_queue(sample_queue(
            "queue-monero-bridge-03",
            "shard-bridge-03",
            ["prefetch-monero-bridge-c"],
            QueueStatus::Accepting,
            9_520,
        ))
        .expect("sample queue c");

    let credit_0 = state
        .reserve_witness_credit(sample_credit_request(
            "prefetch-hot-accounts-a",
            "queue-hot-accounts-0007",
            "shard-0007",
            "private-swap-router-v4",
            "acct-hint-vtag-7f21",
            24_576,
            360,
            1_000,
        ))
        .expect("sample credit 0");
    let credit_1 = state
        .reserve_witness_credit(sample_credit_request(
            "prefetch-contract-storage-b",
            "queue-contract-storage-0011",
            "shard-0011",
            "confidential-lending-pool-v3",
            "acct-hint-vtag-42ac",
            65_536,
            610,
            940,
        ))
        .expect("sample credit 1");
    let credit_2 = state
        .reserve_witness_credit(sample_credit_request(
            "prefetch-monero-bridge-c",
            "queue-monero-bridge-03",
            "shard-bridge-03",
            "monero-exit-router-v2",
            "bridge-output-vtag-2d09",
            18_432,
            330,
            920,
        ))
        .expect("sample credit 2");
    state
        .mark_prefetched(&credit_0, 5)
        .expect("prefetch credit 0");
    state
        .mark_prefetched(&credit_2, 7)
        .expect("prefetch credit 2");

    state
        .add_pq_cache_attestation(sample_attestation(
            "attest-prefetch-alpha-0001",
            &credit_0,
            "prefetch-hot-accounts-a",
            "operator-prefetch-alpha",
            AttestationVerdict::CacheHit,
            5,
            9_660,
        ))
        .expect("sample attestation 0");
    state
        .add_pq_cache_attestation(sample_attestation(
            "attest-prefetch-beta-0001",
            &credit_1,
            "prefetch-contract-storage-b",
            "operator-prefetch-beta",
            AttestationVerdict::Hold,
            11,
            9_210,
        ))
        .expect("sample attestation 1");
    state
        .add_latency_bucket(sample_latency_bucket(
            "latency-hot-accounts-sub10",
            "prefetch-hot-accounts-a",
            "shard-0007",
            LatencyClass::SubTenMs,
            12_880,
            5,
            8,
            12,
        ))
        .expect("sample latency 0");
    state
        .add_latency_bucket(sample_latency_bucket(
            "latency-bridge-sub10",
            "prefetch-monero-bridge-c",
            "shard-bridge-03",
            LatencyClass::SubTenMs,
            6_420,
            6,
            10,
            18,
        ))
        .expect("sample latency 1");
    state
        .add_fee_credit(sample_fee_credit(
            "fee-credit-swap-0",
            &credit_0,
            "fee-sponsor-mesh-02",
            "prefetch-hot-accounts-a",
            24,
            360,
        ))
        .expect("sample fee credit 0");
    state
        .add_fee_credit(sample_fee_credit(
            "fee-credit-bridge-0",
            &credit_2,
            "bridge-rebate-vault-01",
            "prefetch-monero-bridge-c",
            18,
            330,
        ))
        .expect("sample fee credit 1");
    state
        .add_privacy_redaction_budget(sample_redaction_budget(
            "redaction-prefetch-swap-0",
            "prefetch-hot-accounts-a",
            "queue-hot-accounts-0007",
            220,
            DEFAULT_MIN_PRIVACY_SET_SIZE,
        ))
        .expect("sample redaction 0");
    state
        .add_privacy_redaction_budget(sample_redaction_budget(
            "redaction-prefetch-bridge-0",
            "prefetch-monero-bridge-c",
            "queue-monero-bridge-03",
            260,
            DEFAULT_MIN_PRIVACY_SET_SIZE * 2,
        ))
        .expect("sample redaction 1");
    state
        .quarantine_backpressure(sample_quarantine(
            "quarantine-contract-storage-0",
            "prefetch-contract-storage-b",
            "queue-contract-storage-0011",
            QuarantineReason::LatencySloBreach,
            8_120,
            1,
        ))
        .expect("sample quarantine");
    state
        .add_operator_summary(sample_summary(
            "summary-alpha-prefetch-18432",
            "operator-prefetch-alpha",
            "prefetch-hot-accounts-a",
            9_640,
            5,
            24,
            0,
        ))
        .expect("sample summary 0");
    state
        .add_operator_summary(sample_summary(
            "summary-gamma-prefetch-18432",
            "operator-prefetch-gamma",
            "prefetch-monero-bridge-c",
            9_530,
            7,
            18,
            0,
        ))
        .expect("sample summary 1");

    let deterministic_root = deterministic_fixture_root(&state, "devnet-speed-low-fee-root");
    state
        .add_deterministic_root(DeterministicRootRecord {
            root_id: "deterministic-root-devnet-0".to_string(),
            domain: "devnet-speed-low-fee-root".to_string(),
            lane_id: "prefetch-hot-accounts-a".to_string(),
            queue_id: "queue-hot-accounts-0007".to_string(),
            root: deterministic_root,
            leaf_count: 3,
            computed_at_height: state.l2_height,
        })
        .expect("sample deterministic root");
    state.refresh_roots();
    let expected_state_root = state.roots.state_root.clone();
    state
        .add_devnet_fixture(DevnetFixture {
            fixture_id: "fixture-prefetch-credit-lane-devnet-0".to_string(),
            label: "speed-low-fee-confidential-witness-prefetch".to_string(),
            lane_id: "prefetch-hot-accounts-a".to_string(),
            queue_id: "queue-hot-accounts-0007".to_string(),
            credit_id: credit_0,
            expected_state_root,
            note: "deterministic devnet fixture for Monero/private L2 prefetch credit lanes"
                .to_string(),
        })
        .expect("sample fixture");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn sample_lane(
    lane_id: &str,
    shard_id: &str,
    operator_id: &str,
    kind: PrefetchLaneKind,
    status: LaneStatus,
    capacity_witness_bytes: u64,
    cache_hit_bps: u64,
    average_prefetch_ms: u64,
) -> PrefetchLane {
    PrefetchLane {
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        operator_id: operator_id.to_string(),
        kind,
        status,
        priority_weight: 1_000,
        capacity_witness_bytes,
        reserved_witness_bytes: 0,
        prefetched_witness_bytes: 0,
        cache_hit_bps,
        backpressure_bps: 180,
        average_prefetch_ms,
        pq_attestation_key_commitment: sample_root("pq-key", lane_id),
        privacy_fence_root: sample_root("privacy-fence", shard_id),
        queue_commitment_root: sample_root("queue-commitment", lane_id),
        opened_at_height: DEVNET_L2_HEIGHT - 96,
        updated_at_height: DEVNET_L2_HEIGHT,
    }
}

fn sample_queue<const N: usize>(
    queue_id: &str,
    shard_id: &str,
    lane_ids: [&str; N],
    status: QueueStatus,
    local_hit_bps: u64,
) -> ShardQueue {
    ShardQueue {
        queue_id: queue_id.to_string(),
        shard_id: shard_id.to_string(),
        lane_ids: lane_ids
            .iter()
            .map(|lane_id| (*lane_id).to_string())
            .collect(),
        status,
        encrypted_queue_root: sample_root("encrypted-queue", queue_id),
        pending_credit_count: 0,
        pending_witness_bytes: 0,
        local_hit_bps,
        spillover_bps: MAX_BPS - local_hit_bps,
        max_depth: 65_536,
        updated_at_height: DEVNET_L2_HEIGHT,
    }
}

fn sample_credit_request(
    lane_id: &str,
    queue_id: &str,
    shard_id: &str,
    contract_id: &str,
    account_hint_tag: &str,
    witness_bytes: u64,
    fee_micro_units: u64,
    priority_score: u64,
) -> WitnessCreditRequest {
    WitnessCreditRequest {
        lane_id: lane_id.to_string(),
        queue_id: queue_id.to_string(),
        shard_id: shard_id.to_string(),
        account_hint_tag: account_hint_tag.to_string(),
        contract_id: contract_id.to_string(),
        witness_bytes,
        fee_micro_units,
        priority_score,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
    }
}

fn sample_attestation(
    attestation_id: &str,
    credit_id: &str,
    lane_id: &str,
    operator_id: &str,
    verdict: AttestationVerdict,
    measured_prefetch_ms: u64,
    cache_hit_bps: u64,
) -> PqCacheAttestation {
    PqCacheAttestation {
        attestation_id: attestation_id.to_string(),
        credit_id: credit_id.to_string(),
        lane_id: lane_id.to_string(),
        operator_id: operator_id.to_string(),
        verdict,
        pq_signature_root: sample_root("pq-signature", attestation_id),
        cache_leaf_root: sample_root("cache-leaf", credit_id),
        transcript_root: sample_root("cache-transcript", attestation_id),
        measured_prefetch_ms,
        cache_hit_bps,
        attested_at_height: DEVNET_L2_HEIGHT,
        expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_ATTESTATION_TTL_BLOCKS,
    }
}

fn sample_latency_bucket(
    bucket_id: &str,
    lane_id: &str,
    shard_id: &str,
    class: LatencyClass,
    sample_count: u64,
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
) -> LatencyBucket {
    LatencyBucket {
        bucket_id: bucket_id.to_string(),
        lane_id: lane_id.to_string(),
        shard_id: shard_id.to_string(),
        class,
        sample_count,
        p50_ms,
        p95_ms,
        p99_ms,
        cache_hit_bps: 9_520,
        fee_credit_bps: DEFAULT_FEE_CREDIT_REBATE_BPS,
        window_start_height: DEVNET_L2_HEIGHT - 64,
        window_end_height: DEVNET_L2_HEIGHT,
    }
}

fn sample_fee_credit(
    fee_credit_id: &str,
    credit_id: &str,
    sponsor_id: &str,
    lane_id: &str,
    rebate_micro_units: u64,
    user_fee_cap_micro_units: u64,
) -> FeeCredit {
    FeeCredit {
        fee_credit_id: fee_credit_id.to_string(),
        credit_id: credit_id.to_string(),
        sponsor_id: sponsor_id.to_string(),
        lane_id: lane_id.to_string(),
        rebate_micro_units,
        user_fee_cap_micro_units,
        sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
        low_fee_receipt_root: sample_root("low-fee-receipt", fee_credit_id),
        issued_at_height: DEVNET_L2_HEIGHT,
        expires_at_height: DEVNET_L2_HEIGHT + DEFAULT_FEE_CREDIT_TTL_BLOCKS,
    }
}

fn sample_quarantine(
    quarantine_id: &str,
    lane_id: &str,
    queue_id: &str,
    reason: QuarantineReason,
    backpressure_bps: u64,
    affected_credit_count: u64,
) -> BackpressureQuarantine {
    BackpressureQuarantine {
        quarantine_id: quarantine_id.to_string(),
        lane_id: lane_id.to_string(),
        queue_id: queue_id.to_string(),
        reason,
        encrypted_evidence_root: sample_root("quarantine-evidence", quarantine_id),
        public_reason_code: reason.as_str().to_string(),
        backpressure_bps,
        affected_credit_count,
        opened_at_height: DEVNET_L2_HEIGHT,
        releases_at_height: DEVNET_L2_HEIGHT + DEFAULT_QUARANTINE_TTL_BLOCKS,
        active: true,
    }
}

fn sample_redaction_budget(
    budget_id: &str,
    lane_id: &str,
    queue_id: &str,
    redaction_budget_bps: u64,
    privacy_set_size: u64,
) -> PrivacyRedactionBudget {
    PrivacyRedactionBudget {
        budget_id: budget_id.to_string(),
        lane_id: lane_id.to_string(),
        queue_id: queue_id.to_string(),
        redacted_witness_root: sample_root("redacted-witness", budget_id),
        privacy_set_size,
        redaction_budget_bps,
        disclosed_field_count: 3,
        withheld_field_count: 19,
        applied_at_height: DEVNET_L2_HEIGHT,
    }
}

fn sample_summary(
    summary_id: &str,
    operator_id: &str,
    lane_id: &str,
    cache_hit_bps: u64,
    average_prefetch_ms: u64,
    fee_credit_micro_units: u64,
    active_quarantine_count: u64,
) -> OperatorSummary {
    OperatorSummary {
        summary_id: summary_id.to_string(),
        operator_id: operator_id.to_string(),
        lane_id: lane_id.to_string(),
        epoch: DEVNET_EPOCH,
        cache_hit_bps,
        average_prefetch_ms,
        fee_credit_micro_units,
        active_quarantine_count,
        operator_safe_root: sample_root("operator-safe-summary", summary_id),
    }
}

fn deterministic_fixture_root(state: &State, domain: &str) -> String {
    let leaves = vec![
        state.roots.prefetch_lane_root.clone(),
        state.roots.shard_queue_root.clone(),
        state.roots.witness_credit_root.clone(),
    ]
    .into_iter()
    .map(Value::String)
    .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn credit_id(request: &WitnessCreditRequest, height: u64, nonce: u64) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-witness-prefetch-credit-lane:credit-id",
        &[
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.queue_id),
            HashPart::Str(&request.contract_id),
            HashPart::Str(&request.account_hint_tag),
            HashPart::U64(request.witness_bytes),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn root_from_public_records<I>(domain: &str, values: I) -> String
where
    I: Iterator<Item = Value>,
{
    let leaves = values.collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &Vec::<Value>::new())
}

fn sample_root(domain: &str, id: &str) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(id)],
        32,
    )
}

fn average_u64<I>(values: I) -> u64
where
    I: Iterator<Item = u64>,
{
    let mut sum = 0u64;
    let mut count = 0u64;
    for value in values {
        sum = sum.saturating_add(value);
        count += 1;
    }
    if count == 0 {
        0
    } else {
        sum / count
    }
}

fn rolling_average(previous: u64, next: u64) -> u64 {
    if previous == 0 {
        next
    } else {
        (previous + next) / 2
    }
}
