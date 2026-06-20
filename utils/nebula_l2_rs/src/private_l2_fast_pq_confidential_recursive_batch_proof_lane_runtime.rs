use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialRecursiveBatchProofLaneRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2FastPqConfidentialRecursiveBatchProofLaneRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_BATCH_PROOF_LANE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-recursive-batch-proof-lane-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_BATCH_PROOF_LANE_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_BATCH_PROOF_LANE_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_RECURSIVE_BATCH_PROOF_LANE_RUNTIME_SCHEMA_VERSION;

pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_PROVER_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-recursive-batch-proof-lane-v1";
pub const PRIVACY_SCHEME: &str =
    "viewtag-stealth-nullifier-confidential-witness-redaction-proof-lane-v1";
pub const RECURSION_SCHEME: &str = "folded-recursive-stark-snark-aggregation-low-latency-lane-v1";
pub const LOW_FEE_SCHEME: &str = "sponsor-credit-low-fee-recursive-batch-rebate-v1";
pub const BACKPRESSURE_SCHEME: &str =
    "deterministic-capacity-fence-latency-bucket-priority-queue-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-private-l2-fast-pq-confidential-recursive-batch-proof-lane-public-record-v1";

pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_OPERATOR_SET_ID: &str = "operator-set:recursive-proof-lane-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_REBATE_ASSET_ID: &str = "asset:l2-fee-credit-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_880_400;
pub const DEVNET_EPOCH: u64 = 42;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_LANE_COUNT: usize = 64;
pub const DEFAULT_MAX_WINDOW_COUNT: usize = 256;
pub const DEFAULT_MAX_WITNESS_COUNT: usize = 16_384;
pub const DEFAULT_MAX_ATTESTATION_COUNT: usize = 8_192;
pub const DEFAULT_MAX_FENCE_COUNT: usize = 1_024;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 3;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const DEFAULT_BATCH_TARGET_MS: u64 = 850;
pub const DEFAULT_PROOF_TARGET_MS: u64 = 2_400;
pub const DEFAULT_RECURSION_DEPTH: u8 = 8;
pub const DEFAULT_MAX_WINDOW_BATCHES: u32 = 128;
pub const DEFAULT_MIN_OPERATOR_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_QUORUM_WEIGHT: u64 = 67;
pub const DEFAULT_MAX_BACKPRESSURE_BPS: u64 = 8_500;
pub const DEFAULT_FENCE_COOLDOWN_MS: u64 = 4_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LanePriority {
    CriticalSettlement,
    FastRetail,
    BulkBridge,
    LiquidityMaintenance,
    ArchiveCompression,
}

impl LanePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CriticalSettlement => "critical_settlement",
            Self::FastRetail => "fast_retail",
            Self::BulkBridge => "bulk_bridge",
            Self::LiquidityMaintenance => "liquidity_maintenance",
            Self::ArchiveCompression => "archive_compression",
        }
    }

    pub fn scheduler_weight(self) -> u64 {
        match self {
            Self::CriticalSettlement => 100,
            Self::FastRetail => 80,
            Self::LiquidityMaintenance => 65,
            Self::BulkBridge => 48,
            Self::ArchiveCompression => 24,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Warmup,
    Active,
    Throttled,
    Backpressured,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Backpressured => "backpressured",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Warmup | Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Sealed,
    Recursing,
    Attested,
    Settled,
    Challenged,
    Expired,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Recursing => "recursing",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    Transfer,
    BridgeDeposit,
    BridgeWithdrawal,
    SwapSettlement,
    FeeSponsor,
    StateCompression,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::SwapSettlement => "swap_settlement",
            Self::FeeSponsor => "fee_sponsor",
            Self::StateCompression => "state_compression",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    QuorumReady,
    Accepted,
    Challenged,
    Revoked,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumReady => "quorum_ready",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    SubSecond,
    OneToThreeSeconds,
    ThreeToTenSeconds,
    TenToThirtySeconds,
    SlowPath,
}

impl LatencyClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubSecond => "sub_second",
            Self::OneToThreeSeconds => "one_to_three_seconds",
            Self::ThreeToTenSeconds => "three_to_ten_seconds",
            Self::TenToThirtySeconds => "ten_to_thirty_seconds",
            Self::SlowPath => "slow_path",
        }
    }

    pub fn from_millis(latency_ms: u64) -> Self {
        if latency_ms < 1_000 {
            Self::SubSecond
        } else if latency_ms < 3_000 {
            Self::OneToThreeSeconds
        } else if latency_ms < 10_000 {
            Self::ThreeToTenSeconds
        } else if latency_ms < 30_000 {
            Self::TenToThirtySeconds
        } else {
            Self::SlowPath
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceSeverity {
    Advisory,
    Soft,
    Hard,
    Emergency,
}

impl FenceSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Soft => "soft",
            Self::Hard => "hard",
            Self::Emergency => "emergency",
        }
    }

    pub fn blocks_admission(self) -> bool {
        matches!(self, Self::Hard | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    OperatorSummary,
    PublicRecord,
    AuditorView,
    FullWitness,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorSummary => "operator_summary",
            Self::PublicRecord => "public_record",
            Self::AuditorView => "auditor_view",
            Self::FullWitness => "full_witness",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub operator_set_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub l2_height: u64,
    pub epoch: u64,
    pub hash_suite: String,
    pub pq_prover_attestation_suite: String,
    pub privacy_scheme: String,
    pub recursion_scheme: String,
    pub low_fee_scheme: String,
    pub backpressure_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_lane_count: usize,
    pub max_window_count: usize,
    pub max_witness_count: usize,
    pub max_attestation_count: usize,
    pub max_fence_count: usize,
    pub max_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub batch_target_ms: u64,
    pub proof_target_ms: u64,
    pub max_recursion_depth: u8,
    pub max_window_batches: u32,
    pub min_operator_weight: u64,
    pub min_quorum_weight: u64,
    pub max_backpressure_bps: u64,
    pub fence_cooldown_ms: u64,
    pub public_record_redaction: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "operator_set_id": self.operator_set_id,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "l2_height": self.l2_height,
            "epoch": self.epoch,
            "hash_suite": self.hash_suite,
            "pq_prover_attestation_suite": self.pq_prover_attestation_suite,
            "privacy_scheme": self.privacy_scheme,
            "recursion_scheme": self.recursion_scheme,
            "low_fee_scheme": self.low_fee_scheme,
            "backpressure_scheme": self.backpressure_scheme,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_lane_count": self.max_lane_count,
            "max_window_count": self.max_window_count,
            "max_witness_count": self.max_witness_count,
            "max_attestation_count": self.max_attestation_count,
            "max_fence_count": self.max_fence_count,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "batch_target_ms": self.batch_target_ms,
            "proof_target_ms": self.proof_target_ms,
            "max_recursion_depth": self.max_recursion_depth,
            "max_window_batches": self.max_window_batches,
            "min_operator_weight": self.min_operator_weight,
            "min_quorum_weight": self.min_quorum_weight,
            "max_backpressure_bps": self.max_backpressure_bps,
            "fence_cooldown_ms": self.fence_cooldown_ms,
            "public_record_redaction": self.public_record_redaction,
        })
    }

    pub fn root(&self) -> String {
        record_root("RECURSIVE-BATCH-PROOF-LANE-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(self.schema_version == SCHEMA_VERSION, "schema mismatch")?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below configured floor",
        )?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.max_lane_count > 0, "lane limit must be non-zero")?;
        require(self.max_window_count > 0, "window limit must be non-zero")?;
        require(self.max_witness_count > 0, "witness limit must be non-zero")?;
        require(
            self.target_user_fee_bps <= self.max_user_fee_bps,
            "target fee exceeds max user fee",
        )?;
        require(self.max_user_fee_bps <= MAX_BPS, "max fee exceeds bps max")?;
        require(self.rebate_bps <= MAX_BPS, "rebate exceeds bps max")?;
        require(
            self.max_backpressure_bps <= MAX_BPS,
            "backpressure exceeds bps max",
        )?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            operator_set_id: DEVNET_OPERATOR_SET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            epoch: DEVNET_EPOCH,
            hash_suite: HASH_SUITE.to_string(),
            pq_prover_attestation_suite: PQ_PROVER_ATTESTATION_SUITE.to_string(),
            privacy_scheme: PRIVACY_SCHEME.to_string(),
            recursion_scheme: RECURSION_SCHEME.to_string(),
            low_fee_scheme: LOW_FEE_SCHEME.to_string(),
            backpressure_scheme: BACKPRESSURE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_lane_count: DEFAULT_MAX_LANE_COUNT,
            max_window_count: DEFAULT_MAX_WINDOW_COUNT,
            max_witness_count: DEFAULT_MAX_WITNESS_COUNT,
            max_attestation_count: DEFAULT_MAX_ATTESTATION_COUNT,
            max_fence_count: DEFAULT_MAX_FENCE_COUNT,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            batch_target_ms: DEFAULT_BATCH_TARGET_MS,
            proof_target_ms: DEFAULT_PROOF_TARGET_MS,
            max_recursion_depth: DEFAULT_RECURSION_DEPTH,
            max_window_batches: DEFAULT_MAX_WINDOW_BATCHES,
            min_operator_weight: DEFAULT_MIN_OPERATOR_WEIGHT,
            min_quorum_weight: DEFAULT_MIN_QUORUM_WEIGHT,
            max_backpressure_bps: DEFAULT_MAX_BACKPRESSURE_BPS,
            fence_cooldown_ms: DEFAULT_FENCE_COOLDOWN_MS,
            public_record_redaction: "roots-only-with-operator-safe-metrics".to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lanes: u64,
    pub active_lanes: u64,
    pub windows: u64,
    pub open_windows: u64,
    pub sealed_windows: u64,
    pub settled_windows: u64,
    pub witness_commitments: u64,
    pub accepted_witnesses: u64,
    pub rejected_witnesses: u64,
    pub pq_attestations: u64,
    pub accepted_attestations: u64,
    pub latency_buckets: u64,
    pub rebates: u64,
    pub total_rebate_amount: u64,
    pub backpressure_fences: u64,
    pub active_fences: u64,
    pub privacy_redactions: u64,
    pub operator_summaries: u64,
    pub public_records: u64,
    pub consumed_nullifiers: u64,
    pub total_batches: u64,
    pub total_transactions: u64,
    pub total_witness_bytes: u64,
    pub total_proof_bytes: u64,
    pub total_fee_charged: u64,
    pub total_fee_target: u64,
    pub next_lane_index: u64,
    pub next_window_index: u64,
    pub next_witness_index: u64,
    pub next_attestation_index: u64,
    pub next_latency_bucket_index: u64,
    pub next_rebate_index: u64,
    pub next_fence_index: u64,
    pub next_redaction_index: u64,
    pub next_operator_summary_index: u64,
    pub next_public_record_index: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "active_lanes": self.active_lanes,
            "windows": self.windows,
            "open_windows": self.open_windows,
            "sealed_windows": self.sealed_windows,
            "settled_windows": self.settled_windows,
            "witness_commitments": self.witness_commitments,
            "accepted_witnesses": self.accepted_witnesses,
            "rejected_witnesses": self.rejected_witnesses,
            "pq_attestations": self.pq_attestations,
            "accepted_attestations": self.accepted_attestations,
            "latency_buckets": self.latency_buckets,
            "rebates": self.rebates,
            "total_rebate_amount": self.total_rebate_amount,
            "backpressure_fences": self.backpressure_fences,
            "active_fences": self.active_fences,
            "privacy_redactions": self.privacy_redactions,
            "operator_summaries": self.operator_summaries,
            "public_records": self.public_records,
            "consumed_nullifiers": self.consumed_nullifiers,
            "total_batches": self.total_batches,
            "total_transactions": self.total_transactions,
            "total_witness_bytes": self.total_witness_bytes,
            "total_proof_bytes": self.total_proof_bytes,
            "total_fee_charged": self.total_fee_charged,
            "total_fee_target": self.total_fee_target,
        })
    }

    pub fn root(&self) -> String {
        record_root("RECURSIVE-BATCH-PROOF-LANE-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub proof_lane_root: String,
    pub recursive_batch_window_root: String,
    pub witness_commitment_root: String,
    pub pq_prover_attestation_root: String,
    pub latency_bucket_root: String,
    pub low_fee_rebate_root: String,
    pub backpressure_fence_root: String,
    pub privacy_redaction_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = empty_root("RECURSIVE-BATCH-PROOF-LANE-EMPTY");
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            proof_lane_root: empty.clone(),
            recursive_batch_window_root: empty.clone(),
            witness_commitment_root: empty.clone(),
            pq_prover_attestation_root: empty.clone(),
            latency_bucket_root: empty.clone(),
            low_fee_rebate_root: empty.clone(),
            backpressure_fence_root: empty.clone(),
            privacy_redaction_root: empty.clone(),
            operator_summary_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "proof_lane_root": self.proof_lane_root,
            "recursive_batch_window_root": self.recursive_batch_window_root,
            "witness_commitment_root": self.witness_commitment_root,
            "pq_prover_attestation_root": self.pq_prover_attestation_root,
            "latency_bucket_root": self.latency_bucket_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "backpressure_fence_root": self.backpressure_fence_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "proof_lane_root": self.proof_lane_root,
            "recursive_batch_window_root": self.recursive_batch_window_root,
            "witness_commitment_root": self.witness_commitment_root,
            "pq_prover_attestation_root": self.pq_prover_attestation_root,
            "latency_bucket_root": self.latency_bucket_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "backpressure_fence_root": self.backpressure_fence_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofLane {
    pub lane_id: String,
    pub lane_label: String,
    pub priority: LanePriority,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub scheduler_commitment: String,
    pub fee_asset_id: String,
    pub max_batch_count: u32,
    pub max_transactions_per_batch: u32,
    pub target_batch_ms: u64,
    pub target_proof_ms: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_budget_commitment: String,
    pub privacy_set_size: u64,
    pub pending_witnesses: u64,
    pub in_flight_windows: u64,
    pub last_committed_l2_height: u64,
    pub metadata_root: String,
}

impl ProofLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_label": self.lane_label,
            "priority": self.priority.as_str(),
            "priority_weight": self.priority.scheduler_weight(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "scheduler_commitment": self.scheduler_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_batch_count": self.max_batch_count,
            "max_transactions_per_batch": self.max_transactions_per_batch,
            "target_batch_ms": self.target_batch_ms,
            "target_proof_ms": self.target_proof_ms,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_budget_commitment": self.sponsor_budget_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pending_witnesses": self.pending_witnesses,
            "in_flight_windows": self.in_flight_windows,
            "last_committed_l2_height": self.last_committed_l2_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("RECURSIVE-BATCH-PROOF-LANE", &self.public_record())
    }

    pub fn accepts_window(&self, config: &Config) -> bool {
        self.status.accepts_batches()
            && self.max_user_fee_bps <= config.max_user_fee_bps
            && self.privacy_set_size >= config.min_privacy_set_size
            && self.in_flight_windows < u64::from(config.max_window_batches)
    }

    pub fn projected_capacity(&self) -> u64 {
        u64::from(self.max_batch_count).saturating_mul(u64::from(self.max_transactions_per_batch))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveBatchWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: WindowStatus,
    pub open_l2_height: u64,
    pub close_l2_height: u64,
    pub batch_count: u32,
    pub transaction_count: u64,
    pub recursion_depth: u8,
    pub parent_window_ids: Vec<String>,
    pub witness_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub folded_proof_root: String,
    pub fee_commitment_root: String,
    pub privacy_pool_root: String,
    pub latency_bucket_id: Option<String>,
}

impl RecursiveBatchWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "open_l2_height": self.open_l2_height,
            "close_l2_height": self.close_l2_height,
            "batch_count": self.batch_count,
            "transaction_count": self.transaction_count,
            "recursion_depth": self.recursion_depth,
            "parent_window_ids": self.parent_window_ids,
            "witness_root": self.witness_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "folded_proof_root": self.folded_proof_root,
            "fee_commitment_root": self.fee_commitment_root,
            "privacy_pool_root": self.privacy_pool_root,
            "latency_bucket_id": self.latency_bucket_id,
        })
    }

    pub fn root(&self) -> String {
        record_root("RECURSIVE-BATCH-WINDOW", &self.public_record())
    }

    pub fn window_span(&self) -> u64 {
        self.close_l2_height.saturating_sub(self.open_l2_height)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            WindowStatus::Settled | WindowStatus::Challenged | WindowStatus::Expired
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCommitment {
    pub witness_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub kind: WitnessKind,
    pub nullifier: String,
    pub note_commitment: String,
    pub encrypted_witness_root: String,
    pub public_input_root: String,
    pub fee_commitment: String,
    pub witness_bytes: u64,
    pub transaction_count: u64,
    pub max_fee_bps: u64,
    pub accepted: bool,
    pub submitted_at_l2_height: u64,
}

impl WitnessCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "kind": self.kind.as_str(),
            "nullifier_root": record_root("WITNESS-NULLIFIER-REDACTED", &json!({ "nullifier": self.nullifier })),
            "note_commitment": self.note_commitment,
            "encrypted_witness_root": self.encrypted_witness_root,
            "public_input_root": self.public_input_root,
            "fee_commitment": self.fee_commitment,
            "witness_bytes": self.witness_bytes,
            "transaction_count": self.transaction_count,
            "max_fee_bps": self.max_fee_bps,
            "accepted": self.accepted,
            "submitted_at_l2_height": self.submitted_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("WITNESS-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqProverAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub prover_commitment: String,
    pub aggregation_key_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight: u64,
    pub proof_bytes: u64,
    pub recursion_depth: u8,
    pub attested_state_root: String,
    pub status: AttestationStatus,
    pub attested_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl PqProverAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "prover_commitment": self.prover_commitment,
            "aggregation_key_root": self.aggregation_key_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_weight": self.quorum_weight,
            "proof_bytes": self.proof_bytes,
            "recursion_depth": self.recursion_depth,
            "attested_state_root": self.attested_state_root,
            "status": self.status.as_str(),
            "attested_at_l2_height": self.attested_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("PQ-PROVER-ATTESTATION", &self.public_record())
    }

    pub fn is_accepted(&self) -> bool {
        matches!(
            self.status,
            AttestationStatus::QuorumReady | AttestationStatus::Accepted
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
    pub sample_count: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub max_ms: u64,
    pub fee_pressure_bps: u64,
    pub backpressure_bps: u64,
}

impl LatencyBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "class": self.class.as_str(),
            "lower_bound_ms": self.lower_bound_ms,
            "upper_bound_ms": self.upper_bound_ms,
            "sample_count": self.sample_count,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "fee_pressure_bps": self.fee_pressure_bps,
            "backpressure_bps": self.backpressure_bps,
        })
    }

    pub fn root(&self) -> String {
        record_root("LATENCY-BUCKET", &self.public_record())
    }

    pub fn from_sample(bucket_id: String, lane_id: String, latency_ms: u64) -> Self {
        let class = LatencyClass::from_millis(latency_ms);
        let (lower_bound_ms, upper_bound_ms) = match class {
            LatencyClass::SubSecond => (0, 999),
            LatencyClass::OneToThreeSeconds => (1_000, 2_999),
            LatencyClass::ThreeToTenSeconds => (3_000, 9_999),
            LatencyClass::TenToThirtySeconds => (10_000, 29_999),
            LatencyClass::SlowPath => (30_000, u64::MAX),
        };
        Self {
            bucket_id,
            lane_id,
            class,
            lower_bound_ms,
            upper_bound_ms,
            sample_count: 1,
            p50_ms: latency_ms,
            p95_ms: latency_ms,
            p99_ms: latency_ms,
            max_ms: latency_ms,
            fee_pressure_bps: 0,
            backpressure_bps: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub witness_id: String,
    pub recipient_commitment: String,
    pub charged_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_amount: u64,
    pub rebate_asset_id: String,
    pub sponsor_commitment: String,
    pub settled_at_l2_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "witness_id": self.witness_id,
            "recipient_commitment": self.recipient_commitment,
            "charged_fee_bps": self.charged_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_bps": self.rebate_bps,
            "rebate_amount": self.rebate_amount,
            "rebate_asset_id": self.rebate_asset_id,
            "sponsor_commitment": self.sponsor_commitment,
            "settled_at_l2_height": self.settled_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("LOW-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureFence {
    pub fence_id: String,
    pub lane_id: String,
    pub severity: FenceSeverity,
    pub reason_code: String,
    pub trigger_latency_ms: u64,
    pub trigger_backpressure_bps: u64,
    pub max_admission_bps: u64,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub active: bool,
    pub mitigation_root: String,
}

impl BackpressureFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "lane_id": self.lane_id,
            "severity": self.severity.as_str(),
            "reason_code": self.reason_code,
            "trigger_latency_ms": self.trigger_latency_ms,
            "trigger_backpressure_bps": self.trigger_backpressure_bps,
            "max_admission_bps": self.max_admission_bps,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "active": self.active,
            "mitigation_root": self.mitigation_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("BACKPRESSURE-FENCE", &self.public_record())
    }

    pub fn blocks_admission(&self) -> bool {
        self.active && self.severity.blocks_admission()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub scope: RedactionScope,
    pub redacted_payload_root: String,
    pub disclosure_policy_root: String,
    pub auditor_commitment: Option<String>,
    pub revealed_field_count: u16,
    pub hidden_field_count: u16,
    pub created_at_l2_height: u64,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "scope": self.scope.as_str(),
            "redacted_payload_root": self.redacted_payload_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "auditor_commitment": self.auditor_commitment,
            "revealed_field_count": self.revealed_field_count,
            "hidden_field_count": self.hidden_field_count,
            "created_at_l2_height": self.created_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVACY-REDACTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub lane_ids: Vec<String>,
    pub window_count: u64,
    pub settled_window_count: u64,
    pub accepted_witness_count: u64,
    pub proof_success_bps: u64,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub average_fee_bps: u64,
    pub rebate_amount: u64,
    pub backpressure_events: u64,
    pub privacy_budget_root: String,
    pub period_start_l2_height: u64,
    pub period_end_l2_height: u64,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "lane_ids": self.lane_ids,
            "window_count": self.window_count,
            "settled_window_count": self.settled_window_count,
            "accepted_witness_count": self.accepted_witness_count,
            "proof_success_bps": self.proof_success_bps,
            "median_latency_ms": self.median_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "average_fee_bps": self.average_fee_bps,
            "rebate_amount": self.rebate_amount,
            "backpressure_events": self.backpressure_events,
            "privacy_budget_root": self.privacy_budget_root,
            "period_start_l2_height": self.period_start_l2_height,
            "period_end_l2_height": self.period_end_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("OPERATOR-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub public_payload: Value,
    pub payload_root: String,
    pub emitted_at_l2_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "public_payload": self.public_payload,
            "payload_root": self.payload_root,
            "emitted_at_l2_height": self.emitted_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("DETERMINISTIC-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub proof_lanes: BTreeMap<String, ProofLane>,
    pub recursive_batch_windows: BTreeMap<String, RecursiveBatchWindow>,
    pub witness_commitments: BTreeMap<String, WitnessCommitment>,
    pub pq_prover_attestations: BTreeMap<String, PqProverAttestation>,
    pub latency_buckets: BTreeMap<String, LatencyBucket>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub backpressure_fences: BTreeMap<String, BackpressureFence>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::new(),
            roots: Roots::default(),
            proof_lanes: BTreeMap::new(),
            recursive_batch_windows: BTreeMap::new(),
            witness_commitments: BTreeMap::new(),
            pq_prover_attestations: BTreeMap::new(),
            latency_buckets: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            backpressure_fences: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "l2_network": self.config.l2_network,
            "l2_height": self.config.l2_height,
            "epoch": self.config.epoch,
            "hash_suite": HASH_SUITE,
            "pq_prover_attestation_suite": PQ_PROVER_ATTESTATION_SUITE,
            "privacy_scheme": PRIVACY_SCHEME,
            "recursion_scheme": RECURSION_SCHEME,
            "low_fee_scheme": LOW_FEE_SCHEME,
            "backpressure_scheme": BACKPRESSURE_SCHEME,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "active_lanes": self.proof_lanes.values().filter(|lane| lane.status == LaneStatus::Active).count(),
            "open_windows": self.recursive_batch_windows.values().filter(|window| window.status == WindowStatus::Open).count(),
            "accepted_attestations": self.pq_prover_attestations.values().filter(|attestation| attestation.is_accepted()).count(),
            "blocking_fences": self.backpressure_fences.values().filter(|fence| fence.blocks_admission()).count(),
            "operator_safe_public_records": self.public_records.values().map(DeterministicPublicRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn register_lane(&mut self, mut lane: ProofLane) -> Result<String> {
        self.config.validate()?;
        require(
            self.proof_lanes.len() < self.config.max_lane_count,
            "lane limit reached",
        )?;
        require_non_empty("lane_label", &lane.lane_label)?;
        require_root("operator_commitment", &lane.operator_commitment)?;
        require_root("scheduler_commitment", &lane.scheduler_commitment)?;
        require_root("sponsor_budget_commitment", &lane.sponsor_budget_commitment)?;
        require_root("metadata_root", &lane.metadata_root)?;
        require(
            lane.max_batch_count > 0,
            "lane batch capacity must be non-zero",
        )?;
        require(
            lane.max_transactions_per_batch > 0,
            "lane transaction capacity must be non-zero",
        )?;
        require(
            lane.max_user_fee_bps <= self.config.max_user_fee_bps,
            "lane fee exceeds configured maximum",
        )?;
        require(
            lane.privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set below minimum",
        )?;
        if lane.lane_id.trim().is_empty() {
            lane.lane_id = deterministic_id(
                "proof-lane",
                &[
                    HashPart::Str(&lane.lane_label),
                    HashPart::Str(lane.priority.as_str()),
                    HashPart::U64(self.counters.next_lane_index),
                ],
            );
        }
        let lane_id = lane.lane_id.clone();
        require(!self.proof_lanes.contains_key(&lane_id), "duplicate lane")?;
        if lane.status == LaneStatus::Active {
            self.counters.active_lanes = self.counters.active_lanes.saturating_add(1);
        }
        self.counters.lanes = self.counters.lanes.saturating_add(1);
        self.counters.next_lane_index = self.counters.next_lane_index.saturating_add(1);
        self.proof_lanes.insert(lane_id.clone(), lane.clone());
        self.emit_public_record("proof_lane", &lane_id, lane.public_record());
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_batch_window(&mut self, mut window: RecursiveBatchWindow) -> Result<String> {
        require(
            self.recursive_batch_windows.len() < self.config.max_window_count,
            "window limit reached",
        )?;
        let lane = self
            .proof_lanes
            .get(&window.lane_id)
            .ok_or_else(|| "unknown lane".to_string())?;
        require(
            lane.accepts_window(&self.config),
            "lane is not accepting windows",
        )?;
        require(
            window.batch_count <= self.config.max_window_batches,
            "batch count exceeds window maximum",
        )?;
        require(
            window.recursion_depth <= self.config.max_recursion_depth,
            "recursion depth exceeds configured maximum",
        )?;
        require(
            window.close_l2_height >= window.open_l2_height,
            "window close height before open height",
        )?;
        require_root("witness_root", &window.witness_root)?;
        require_root("pre_state_root", &window.pre_state_root)?;
        require_root("post_state_root", &window.post_state_root)?;
        require_root("folded_proof_root", &window.folded_proof_root)?;
        require_root("fee_commitment_root", &window.fee_commitment_root)?;
        require_root("privacy_pool_root", &window.privacy_pool_root)?;
        require(
            unique_strings(&window.parent_window_ids),
            "parent windows must be unique",
        )?;
        for parent_id in &window.parent_window_ids {
            require(
                self.recursive_batch_windows.contains_key(parent_id),
                "unknown parent window",
            )?;
        }
        if window.window_id.trim().is_empty() {
            window.window_id = deterministic_id(
                "recursive-window",
                &[
                    HashPart::Str(&window.lane_id),
                    HashPart::U64(window.open_l2_height),
                    HashPart::U64(self.counters.next_window_index),
                ],
            );
        }
        let window_id = window.window_id.clone();
        require(
            !self.recursive_batch_windows.contains_key(&window_id),
            "duplicate window",
        )?;
        self.counters.windows = self.counters.windows.saturating_add(1);
        self.counters.total_batches = self
            .counters
            .total_batches
            .saturating_add(u64::from(window.batch_count));
        self.counters.total_transactions = self
            .counters
            .total_transactions
            .saturating_add(window.transaction_count);
        self.counters.next_window_index = self.counters.next_window_index.saturating_add(1);
        if window.status == WindowStatus::Open {
            self.counters.open_windows = self.counters.open_windows.saturating_add(1);
        }
        if window.status == WindowStatus::Sealed {
            self.counters.sealed_windows = self.counters.sealed_windows.saturating_add(1);
        }
        if window.status == WindowStatus::Settled {
            self.counters.settled_windows = self.counters.settled_windows.saturating_add(1);
        }
        if let Some(lane) = self.proof_lanes.get_mut(&window.lane_id) {
            lane.in_flight_windows = lane.in_flight_windows.saturating_add(1);
            lane.last_committed_l2_height =
                lane.last_committed_l2_height.max(window.open_l2_height);
        }
        self.recursive_batch_windows
            .insert(window_id.clone(), window.clone());
        self.emit_public_record("recursive_batch_window", &window_id, window.public_record());
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn commit_witness(&mut self, mut witness: WitnessCommitment) -> Result<String> {
        require(
            self.witness_commitments.len() < self.config.max_witness_count,
            "witness limit reached",
        )?;
        require(
            self.proof_lanes.contains_key(&witness.lane_id),
            "unknown lane",
        )?;
        require(
            self.recursive_batch_windows
                .contains_key(&witness.window_id),
            "unknown window",
        )?;
        require_root("nullifier", &witness.nullifier)?;
        require_root("note_commitment", &witness.note_commitment)?;
        require_root("encrypted_witness_root", &witness.encrypted_witness_root)?;
        require_root("public_input_root", &witness.public_input_root)?;
        require_root("fee_commitment", &witness.fee_commitment)?;
        require(witness.witness_bytes > 0, "witness bytes must be non-zero")?;
        require(
            witness.transaction_count > 0,
            "transaction count must be non-zero",
        )?;
        require(
            witness.max_fee_bps <= self.config.max_user_fee_bps,
            "witness fee exceeds maximum",
        )?;
        require(
            !self.consumed_nullifiers.contains(&witness.nullifier),
            "duplicate witness nullifier",
        )?;
        if witness.witness_id.trim().is_empty() {
            witness.witness_id = deterministic_id(
                "witness",
                &[
                    HashPart::Str(&witness.window_id),
                    HashPart::Str(witness.kind.as_str()),
                    HashPart::Str(&witness.nullifier),
                    HashPart::U64(self.counters.next_witness_index),
                ],
            );
        }
        let witness_id = witness.witness_id.clone();
        require(
            !self.witness_commitments.contains_key(&witness_id),
            "duplicate witness",
        )?;
        self.consumed_nullifiers.insert(witness.nullifier.clone());
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        self.counters.witness_commitments = self.counters.witness_commitments.saturating_add(1);
        self.counters.total_witness_bytes = self
            .counters
            .total_witness_bytes
            .saturating_add(witness.witness_bytes);
        self.counters.total_fee_charged = self
            .counters
            .total_fee_charged
            .saturating_add(witness.max_fee_bps);
        self.counters.total_fee_target = self
            .counters
            .total_fee_target
            .saturating_add(self.config.target_user_fee_bps);
        if witness.accepted {
            self.counters.accepted_witnesses = self.counters.accepted_witnesses.saturating_add(1);
        } else {
            self.counters.rejected_witnesses = self.counters.rejected_witnesses.saturating_add(1);
        }
        self.counters.next_witness_index = self.counters.next_witness_index.saturating_add(1);
        if let Some(lane) = self.proof_lanes.get_mut(&witness.lane_id) {
            lane.pending_witnesses = lane.pending_witnesses.saturating_add(1);
        }
        self.witness_commitments
            .insert(witness_id.clone(), witness.clone());
        self.emit_public_record("witness_commitment", &witness_id, witness.public_record());
        self.refresh_roots();
        Ok(witness_id)
    }

    pub fn attest_pq_prover(&mut self, mut attestation: PqProverAttestation) -> Result<String> {
        require(
            self.pq_prover_attestations.len() < self.config.max_attestation_count,
            "attestation limit reached",
        )?;
        require(
            self.proof_lanes.contains_key(&attestation.lane_id),
            "unknown lane",
        )?;
        require(
            self.recursive_batch_windows
                .contains_key(&attestation.window_id),
            "unknown window",
        )?;
        require_root("prover_commitment", &attestation.prover_commitment)?;
        require_root("aggregation_key_root", &attestation.aggregation_key_root)?;
        require_root("signature_root", &attestation.signature_root)?;
        require_root("attested_state_root", &attestation.attested_state_root)?;
        require(
            attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security below configured minimum",
        )?;
        require(
            attestation.quorum_weight >= self.config.min_quorum_weight,
            "prover quorum below configured minimum",
        )?;
        require(attestation.proof_bytes > 0, "proof bytes must be non-zero")?;
        require(
            attestation.recursion_depth <= self.config.max_recursion_depth,
            "attestation recursion depth too high",
        )?;
        require(
            attestation.expires_at_l2_height > attestation.attested_at_l2_height,
            "attestation expiry must be after attestation height",
        )?;
        if attestation.attestation_id.trim().is_empty() {
            attestation.attestation_id = deterministic_id(
                "pq-prover-attestation",
                &[
                    HashPart::Str(&attestation.window_id),
                    HashPart::Str(&attestation.prover_commitment),
                    HashPart::U64(self.counters.next_attestation_index),
                ],
            );
        }
        let attestation_id = attestation.attestation_id.clone();
        require(
            !self.pq_prover_attestations.contains_key(&attestation_id),
            "duplicate attestation",
        )?;
        if attestation.is_accepted() {
            self.counters.accepted_attestations =
                self.counters.accepted_attestations.saturating_add(1);
        }
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.counters.total_proof_bytes = self
            .counters
            .total_proof_bytes
            .saturating_add(attestation.proof_bytes);
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.pq_prover_attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.emit_public_record(
            "pq_prover_attestation",
            &attestation_id,
            attestation.public_record(),
        );
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn record_latency_sample(&mut self, lane_id: &str, latency_ms: u64) -> Result<String> {
        require(self.proof_lanes.contains_key(lane_id), "unknown lane")?;
        let bucket_id = deterministic_id(
            "latency-bucket",
            &[
                HashPart::Str(lane_id),
                HashPart::Str(LatencyClass::from_millis(latency_ms).as_str()),
                HashPart::U64(self.counters.next_latency_bucket_index),
            ],
        );
        let mut bucket =
            LatencyBucket::from_sample(bucket_id.clone(), lane_id.to_string(), latency_ms);
        bucket.fee_pressure_bps = fee_pressure_bps(latency_ms, self.config.batch_target_ms);
        bucket.backpressure_bps = backpressure_bps(latency_ms, self.config.proof_target_ms);
        require(
            bucket.backpressure_bps <= self.config.max_backpressure_bps,
            "latency sample exceeds max backpressure",
        )?;
        self.counters.latency_buckets = self.counters.latency_buckets.saturating_add(1);
        self.counters.next_latency_bucket_index =
            self.counters.next_latency_bucket_index.saturating_add(1);
        self.latency_buckets
            .insert(bucket_id.clone(), bucket.clone());
        self.emit_public_record("latency_bucket", &bucket_id, bucket.public_record());
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn issue_low_fee_rebate(&mut self, mut rebate: LowFeeRebate) -> Result<String> {
        require(
            self.low_fee_rebates.len() < self.config.max_witness_count,
            "rebate limit reached",
        )?;
        require(
            self.proof_lanes.contains_key(&rebate.lane_id),
            "unknown lane",
        )?;
        require(
            self.recursive_batch_windows.contains_key(&rebate.window_id),
            "unknown window",
        )?;
        require(
            self.witness_commitments.contains_key(&rebate.witness_id),
            "unknown witness",
        )?;
        require_root("recipient_commitment", &rebate.recipient_commitment)?;
        require_root("sponsor_commitment", &rebate.sponsor_commitment)?;
        require(
            rebate.charged_fee_bps <= self.config.max_user_fee_bps,
            "charged fee exceeds maximum",
        )?;
        require(
            rebate.target_fee_bps <= self.config.target_user_fee_bps,
            "target fee exceeds configured target",
        )?;
        require(
            rebate.target_fee_bps <= rebate.charged_fee_bps,
            "target fee exceeds charged fee",
        )?;
        require(
            rebate.rebate_bps <= self.config.rebate_bps,
            "rebate bps exceeds configured maximum",
        )?;
        if rebate.rebate_id.trim().is_empty() {
            rebate.rebate_id = deterministic_id(
                "low-fee-rebate",
                &[
                    HashPart::Str(&rebate.witness_id),
                    HashPart::Str(&rebate.recipient_commitment),
                    HashPart::U64(self.counters.next_rebate_index),
                ],
            );
        }
        let rebate_id = rebate.rebate_id.clone();
        require(
            !self.low_fee_rebates.contains_key(&rebate_id),
            "duplicate rebate",
        )?;
        self.counters.rebates = self.counters.rebates.saturating_add(1);
        self.counters.total_rebate_amount = self
            .counters
            .total_rebate_amount
            .saturating_add(rebate.rebate_amount);
        self.counters.next_rebate_index = self.counters.next_rebate_index.saturating_add(1);
        self.low_fee_rebates
            .insert(rebate_id.clone(), rebate.clone());
        self.emit_public_record("low_fee_rebate", &rebate_id, rebate.public_record());
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn open_backpressure_fence(&mut self, mut fence: BackpressureFence) -> Result<String> {
        require(
            self.backpressure_fences.len() < self.config.max_fence_count,
            "fence limit reached",
        )?;
        require(
            self.proof_lanes.contains_key(&fence.lane_id),
            "unknown lane",
        )?;
        require_non_empty("reason_code", &fence.reason_code)?;
        require_root("mitigation_root", &fence.mitigation_root)?;
        require(
            fence.trigger_backpressure_bps <= MAX_BPS,
            "trigger backpressure exceeds bps max",
        )?;
        require(
            fence.max_admission_bps <= MAX_BPS,
            "max admission exceeds bps max",
        )?;
        require(
            fence.expires_at_l2_height > fence.opened_at_l2_height,
            "fence expiry must be after open height",
        )?;
        if fence.fence_id.trim().is_empty() {
            fence.fence_id = deterministic_id(
                "backpressure-fence",
                &[
                    HashPart::Str(&fence.lane_id),
                    HashPart::Str(fence.severity.as_str()),
                    HashPart::U64(self.counters.next_fence_index),
                ],
            );
        }
        let fence_id = fence.fence_id.clone();
        require(
            !self.backpressure_fences.contains_key(&fence_id),
            "duplicate fence",
        )?;
        if fence.active {
            self.counters.active_fences = self.counters.active_fences.saturating_add(1);
        }
        self.counters.backpressure_fences = self.counters.backpressure_fences.saturating_add(1);
        self.counters.next_fence_index = self.counters.next_fence_index.saturating_add(1);
        if fence.blocks_admission() {
            if let Some(lane) = self.proof_lanes.get_mut(&fence.lane_id) {
                lane.status = LaneStatus::Backpressured;
            }
        }
        self.backpressure_fences
            .insert(fence_id.clone(), fence.clone());
        self.emit_public_record("backpressure_fence", &fence_id, fence.public_record());
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn add_privacy_redaction(&mut self, mut redaction: PrivacyRedaction) -> Result<String> {
        require_non_empty("subject_kind", &redaction.subject_kind)?;
        require_non_empty("subject_id", &redaction.subject_id)?;
        require_root("redacted_payload_root", &redaction.redacted_payload_root)?;
        require_root("disclosure_policy_root", &redaction.disclosure_policy_root)?;
        require(
            redaction.hidden_field_count > 0,
            "redaction must hide at least one field",
        )?;
        if redaction.redaction_id.trim().is_empty() {
            redaction.redaction_id = deterministic_id(
                "privacy-redaction",
                &[
                    HashPart::Str(&redaction.subject_kind),
                    HashPart::Str(&redaction.subject_id),
                    HashPart::Str(redaction.scope.as_str()),
                    HashPart::U64(self.counters.next_redaction_index),
                ],
            );
        }
        let redaction_id = redaction.redaction_id.clone();
        require(
            !self.privacy_redactions.contains_key(&redaction_id),
            "duplicate redaction",
        )?;
        self.counters.privacy_redactions = self.counters.privacy_redactions.saturating_add(1);
        self.counters.next_redaction_index = self.counters.next_redaction_index.saturating_add(1);
        self.privacy_redactions
            .insert(redaction_id.clone(), redaction.clone());
        self.emit_public_record(
            "privacy_redaction",
            &redaction_id,
            redaction.public_record(),
        );
        self.refresh_roots();
        Ok(redaction_id)
    }

    pub fn upsert_operator_summary(&mut self, mut summary: OperatorSummary) -> Result<String> {
        require_root("operator_commitment", &summary.operator_commitment)?;
        require(!summary.lane_ids.is_empty(), "summary requires lanes")?;
        require(
            unique_strings(&summary.lane_ids),
            "summary lanes must be unique",
        )?;
        for lane_id in &summary.lane_ids {
            require(
                self.proof_lanes.contains_key(lane_id),
                "summary has unknown lane",
            )?;
        }
        require(
            summary.proof_success_bps <= MAX_BPS,
            "proof success exceeds bps max",
        )?;
        require(
            summary.average_fee_bps <= self.config.max_user_fee_bps,
            "summary fee exceeds max user fee",
        )?;
        require_root("privacy_budget_root", &summary.privacy_budget_root)?;
        require(
            summary.period_end_l2_height >= summary.period_start_l2_height,
            "summary period end before start",
        )?;
        if summary.summary_id.trim().is_empty() {
            summary.summary_id = deterministic_id(
                "operator-summary",
                &[
                    HashPart::Str(&summary.operator_commitment),
                    HashPart::U64(summary.period_start_l2_height),
                    HashPart::U64(summary.period_end_l2_height),
                    HashPart::U64(self.counters.next_operator_summary_index),
                ],
            );
        }
        let summary_id = summary.summary_id.clone();
        let is_new = !self.operator_summaries.contains_key(&summary_id);
        self.operator_summaries
            .insert(summary_id.clone(), summary.clone());
        if is_new {
            self.counters.operator_summaries = self.counters.operator_summaries.saturating_add(1);
            self.counters.next_operator_summary_index =
                self.counters.next_operator_summary_index.saturating_add(1);
        }
        self.emit_public_record("operator_summary", &summary_id, summary.public_record());
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn settle_window(
        &mut self,
        window_id: &str,
        latency_bucket_id: Option<String>,
    ) -> Result<()> {
        let window = self
            .recursive_batch_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown window".to_string())?;
        require(!window.is_terminal(), "window already terminal")?;
        if let Some(bucket_id) = &latency_bucket_id {
            require(
                self.latency_buckets.contains_key(bucket_id),
                "unknown latency bucket",
            )?;
        }
        window.status = WindowStatus::Settled;
        window.latency_bucket_id = latency_bucket_id;
        self.counters.settled_windows = self.counters.settled_windows.saturating_add(1);
        if let Some(lane) = self.proof_lanes.get_mut(&window.lane_id) {
            lane.in_flight_windows = lane.in_flight_windows.saturating_sub(1);
            lane.pending_witnesses = lane
                .pending_witnesses
                .saturating_sub(window.transaction_count);
        }
        let payload = window.public_record();
        self.emit_public_record("window_settled", window_id, payload);
        self.refresh_roots();
        Ok(())
    }

    pub fn lane_backpressure_bps(&self, lane_id: &str) -> u64 {
        self.backpressure_fences
            .values()
            .filter(|fence| fence.lane_id == lane_id && fence.active)
            .map(|fence| fence.trigger_backpressure_bps)
            .max()
            .unwrap_or(0)
    }

    pub fn operator_safe_summary(&self, operator_commitment: &str) -> Value {
        let lane_ids = self
            .proof_lanes
            .values()
            .filter(|lane| lane.operator_commitment == operator_commitment)
            .map(|lane| lane.lane_id.clone())
            .collect::<Vec<_>>();
        let lane_set = lane_ids.iter().cloned().collect::<BTreeSet<_>>();
        let windows = self
            .recursive_batch_windows
            .values()
            .filter(|window| lane_set.contains(&window.lane_id))
            .collect::<Vec<_>>();
        let witnesses = self
            .witness_commitments
            .values()
            .filter(|witness| lane_set.contains(&witness.lane_id) && witness.accepted)
            .count();
        json!({
            "operator_commitment": operator_commitment,
            "lane_ids": lane_ids,
            "window_count": windows.len(),
            "settled_window_count": windows.iter().filter(|window| window.status == WindowStatus::Settled).count(),
            "accepted_witness_count": witnesses,
            "blocking_fences": self.backpressure_fences.values().filter(|fence| lane_set.contains(&fence.lane_id) && fence.blocks_admission()).count(),
            "public_roots": self.roots.public_record(),
        })
    }

    fn emit_public_record(&mut self, record_kind: &str, subject_id: &str, public_payload: Value) {
        let record_id = deterministic_id(
            "public-record",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.counters.next_public_record_index),
            ],
        );
        let payload_root = record_root("PUBLIC-RECORD-PAYLOAD", &public_payload);
        let record = DeterministicPublicRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            public_payload,
            payload_root,
            emitted_at_l2_height: self.config.l2_height,
        };
        self.public_records.insert(record_id, record);
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        self.counters.next_public_record_index =
            self.counters.next_public_record_index.saturating_add(1);
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.proof_lane_root = collection_root(
            "RECURSIVE-BATCH-PROOF-LANES",
            self.proof_lanes.values().map(ProofLane::public_record),
        );
        self.roots.recursive_batch_window_root = collection_root(
            "RECURSIVE-BATCH-WINDOWS",
            self.recursive_batch_windows
                .values()
                .map(RecursiveBatchWindow::public_record),
        );
        self.roots.witness_commitment_root = collection_root(
            "WITNESS-COMMITMENTS",
            self.witness_commitments
                .values()
                .map(WitnessCommitment::public_record),
        );
        self.roots.pq_prover_attestation_root = collection_root(
            "PQ-PROVER-ATTESTATIONS",
            self.pq_prover_attestations
                .values()
                .map(PqProverAttestation::public_record),
        );
        self.roots.latency_bucket_root = collection_root(
            "LATENCY-BUCKETS",
            self.latency_buckets
                .values()
                .map(LatencyBucket::public_record),
        );
        self.roots.low_fee_rebate_root = collection_root(
            "LOW-FEE-REBATES",
            self.low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record),
        );
        self.roots.backpressure_fence_root = collection_root(
            "BACKPRESSURE-FENCES",
            self.backpressure_fences
                .values()
                .map(BackpressureFence::public_record),
        );
        self.roots.privacy_redaction_root = collection_root(
            "PRIVACY-REDACTIONS",
            self.privacy_redactions
                .values()
                .map(PrivacyRedaction::public_record),
        );
        self.roots.operator_summary_root = collection_root(
            "OPERATOR-SUMMARIES",
            self.operator_summaries
                .values()
                .map(OperatorSummary::public_record),
        );
        self.roots.nullifier_root = collection_root(
            "CONSUMED-WITNESS-NULLIFIERS",
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier_root": record_root("NULLIFIER-REDACTED", &json!({ "nullifier": nullifier })) })),
        );
        self.roots.public_record_root = collection_root(
            "DETERMINISTIC-PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(DeterministicPublicRecord::public_record),
        );
        self.roots.state_root = domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-RECURSIVE-BATCH-PROOF-LANE-STATE-ROOT",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.epoch),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&self.roots.without_state_root()),
            ],
            32,
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let lane_id = state
        .register_lane(ProofLane {
            lane_id: String::new(),
            lane_label: "fast-retail-recursive-lane-a".to_string(),
            priority: LanePriority::FastRetail,
            status: LaneStatus::Active,
            operator_commitment: hex_root("operator", 1),
            scheduler_commitment: hex_root("scheduler", 1),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            max_batch_count: 48,
            max_transactions_per_batch: 1_024,
            target_batch_ms: 750,
            target_proof_ms: 2_100,
            max_user_fee_bps: 6,
            sponsor_budget_commitment: hex_root("sponsor-budget", 1),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pending_witnesses: 0,
            in_flight_windows: 0,
            last_committed_l2_height: DEVNET_L2_HEIGHT,
            metadata_root: hex_root("lane-metadata", 1),
        })
        .expect("demo lane");
    let window_id = state
        .open_batch_window(RecursiveBatchWindow {
            window_id: String::new(),
            lane_id: lane_id.clone(),
            status: WindowStatus::Sealed,
            open_l2_height: DEVNET_L2_HEIGHT + 1,
            close_l2_height: DEVNET_L2_HEIGHT + 2,
            batch_count: 32,
            transaction_count: 18_944,
            recursion_depth: 5,
            parent_window_ids: vec![],
            witness_root: hex_root("witness-root", 1),
            pre_state_root: hex_root("pre-state", 1),
            post_state_root: hex_root("post-state", 1),
            folded_proof_root: hex_root("folded-proof", 1),
            fee_commitment_root: hex_root("fee-root", 1),
            privacy_pool_root: hex_root("privacy-pool", 1),
            latency_bucket_id: None,
        })
        .expect("demo window");
    let witness_id = state
        .commit_witness(WitnessCommitment {
            witness_id: String::new(),
            lane_id: lane_id.clone(),
            window_id: window_id.clone(),
            kind: WitnessKind::Transfer,
            nullifier: hex_root("nullifier", 1),
            note_commitment: hex_root("note", 1),
            encrypted_witness_root: hex_root("encrypted-witness", 1),
            public_input_root: hex_root("public-input", 1),
            fee_commitment: hex_root("fee-commitment", 1),
            witness_bytes: 96_512,
            transaction_count: 512,
            max_fee_bps: 6,
            accepted: true,
            submitted_at_l2_height: DEVNET_L2_HEIGHT + 1,
        })
        .expect("demo witness");
    state
        .attest_pq_prover(PqProverAttestation {
            attestation_id: String::new(),
            lane_id: lane_id.clone(),
            window_id: window_id.clone(),
            prover_commitment: hex_root("prover", 1),
            aggregation_key_root: hex_root("aggregation-key", 1),
            signature_root: hex_root("pq-signature", 1),
            pq_security_bits: 256,
            quorum_weight: 74,
            proof_bytes: 42_240,
            recursion_depth: 5,
            attested_state_root: hex_root("attested-state", 1),
            status: AttestationStatus::Accepted,
            attested_at_l2_height: DEVNET_L2_HEIGHT + 2,
            expires_at_l2_height: DEVNET_L2_HEIGHT + 82,
        })
        .expect("demo attestation");
    let bucket_id = state
        .record_latency_sample(&lane_id, 812)
        .expect("demo latency bucket");
    state
        .issue_low_fee_rebate(LowFeeRebate {
            rebate_id: String::new(),
            lane_id: lane_id.clone(),
            window_id: window_id.clone(),
            witness_id: witness_id.clone(),
            recipient_commitment: hex_root("rebate-recipient", 1),
            charged_fee_bps: 6,
            target_fee_bps: 3,
            rebate_bps: 3,
            rebate_amount: 1_250,
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            sponsor_commitment: hex_root("rebate-sponsor", 1),
            settled_at_l2_height: DEVNET_L2_HEIGHT + 3,
        })
        .expect("demo rebate");
    state
        .open_backpressure_fence(BackpressureFence {
            fence_id: String::new(),
            lane_id: lane_id.clone(),
            severity: FenceSeverity::Advisory,
            reason_code: "latency-watch".to_string(),
            trigger_latency_ms: 812,
            trigger_backpressure_bps: 0,
            max_admission_bps: 9_500,
            opened_at_l2_height: DEVNET_L2_HEIGHT + 3,
            expires_at_l2_height: DEVNET_L2_HEIGHT + 12,
            active: true,
            mitigation_root: hex_root("fence-mitigation", 1),
        })
        .expect("demo fence");
    state
        .add_privacy_redaction(PrivacyRedaction {
            redaction_id: String::new(),
            subject_kind: "witness_commitment".to_string(),
            subject_id: witness_id.clone(),
            scope: RedactionScope::PublicRecord,
            redacted_payload_root: hex_root("redacted-witness", 1),
            disclosure_policy_root: hex_root("redaction-policy", 1),
            auditor_commitment: Some(hex_root("auditor", 1)),
            revealed_field_count: 9,
            hidden_field_count: 4,
            created_at_l2_height: DEVNET_L2_HEIGHT + 3,
        })
        .expect("demo redaction");
    state
        .upsert_operator_summary(OperatorSummary {
            summary_id: String::new(),
            operator_commitment: hex_root("operator", 1),
            lane_ids: vec![lane_id.clone()],
            window_count: 1,
            settled_window_count: 0,
            accepted_witness_count: 1,
            proof_success_bps: 10_000,
            median_latency_ms: 812,
            p95_latency_ms: 812,
            average_fee_bps: 6,
            rebate_amount: 1_250,
            backpressure_events: 1,
            privacy_budget_root: hex_root("privacy-budget", 1),
            period_start_l2_height: DEVNET_L2_HEIGHT,
            period_end_l2_height: DEVNET_L2_HEIGHT + 16,
        })
        .expect("demo operator summary");
    state
        .settle_window(&window_id, Some(bucket_id))
        .expect("demo settle window");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet_state_root() -> String {
    devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    devnet().public_record()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{field} must be non-empty"),
    )
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    require(
        value.len() >= 16,
        &format!("{field} must look like a commitment root"),
    )
}

fn unique_strings(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

fn deterministic_id(prefix: &str, parts: &[HashPart<'_>]) -> String {
    format!("{prefix}:{}", domain_hash(prefix, parts, 16))
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn empty_root(domain: &str) -> String {
    domain_hash(domain, &[HashPart::Str("empty")], 32)
}

fn collection_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &values.into_iter().collect::<Vec<_>>())
}

fn fee_pressure_bps(latency_ms: u64, target_ms: u64) -> u64 {
    if target_ms == 0 || latency_ms <= target_ms {
        0
    } else {
        latency_ms
            .saturating_sub(target_ms)
            .saturating_mul(MAX_BPS)
            .checked_div(target_ms)
            .unwrap_or(MAX_BPS)
            .min(MAX_BPS)
    }
}

fn backpressure_bps(latency_ms: u64, target_ms: u64) -> u64 {
    if target_ms == 0 || latency_ms <= target_ms {
        0
    } else {
        latency_ms
            .saturating_sub(target_ms)
            .saturating_mul(MAX_BPS)
            .checked_div(target_ms.saturating_mul(2).max(1))
            .unwrap_or(MAX_BPS)
            .min(MAX_BPS)
    }
}

fn hex_root(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-RECURSIVE-BATCH-PROOF-LANE-DEVNET-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}
