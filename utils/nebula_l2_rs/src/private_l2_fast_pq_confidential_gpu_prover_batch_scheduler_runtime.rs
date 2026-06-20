use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<T> = Result<T, String>;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-gpu-prover-batch-scheduler-v1";
pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_GPU_PROVER_BATCH_SCHEDULER_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const PQ_AUTH_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f";
pub const CONFIDENTIAL_PROOF_SYSTEM: &str = "zk-confidential-l2-batch-pq-gpu-v1";
pub const WITNESS_PACKING_SCHEME: &str = "deterministic-columnar-witness-pack-v1";
pub const TELEMETRY_ROOT_DOMAIN: &str = "nebula.private_l2.gpu_prover.telemetry";
pub const DEFAULT_EPOCH: u64 = 1;
pub const DEFAULT_TARGET_PRECONF_MS: u64 = 250;
pub const DEFAULT_SOFT_PRECONF_MS: u64 = 700;
pub const DEFAULT_BATCH_MAX_WEIGHT: u64 = 8_000_000;
pub const DEFAULT_GPU_MEMORY_LIMIT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const DEFAULT_WITNESS_PACK_BYTES: u64 = 32 * 1024 * 1024;
pub const DEFAULT_QUEUE_DEPTH: u64 = 65_536;
pub const DEFAULT_LOW_FEE_BPS: u64 = 1_500;
pub const DEFAULT_FAIR_SHARE_QUANTA: u64 = 16;
pub const DEFAULT_HOT_CACHE_HINT_TTL_SLOTS: u64 = 32;
pub const DEFAULT_SAFE_MODE_SEVERITY: u8 = 2;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_BUCKETS: usize = 32;
pub const MAX_QUEUES: usize = 64;
pub const MAX_JOBS: usize = 65_536;
pub const MAX_BATCHES: usize = 8_192;
pub const MAX_GPU_POOLS: usize = 64;
pub const MAX_CONTRACT_HINTS: usize = 16_384;
pub const MAX_EVENTS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    Transfer,
    Swap,
    ContractCall,
    BridgeIn,
    BridgeOut,
    RecursiveAggregation,
    StateTransition,
    Withdrawal,
    WalletRecovery,
    AuditDisclosure,
}

impl ProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Swap => "swap",
            Self::ContractCall => "contract_call",
            Self::BridgeIn => "bridge_in",
            Self::BridgeOut => "bridge_out",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::StateTransition => "state_transition",
            Self::Withdrawal => "withdrawal",
            Self::WalletRecovery => "wallet_recovery",
            Self::AuditDisclosure => "audit_disclosure",
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::Transfer => 900,
            Self::Swap => 1_400,
            Self::ContractCall => 2_400,
            Self::BridgeIn => 1_800,
            Self::BridgeOut => 2_200,
            Self::RecursiveAggregation => 5_200,
            Self::StateTransition => 3_200,
            Self::Withdrawal => 1_700,
            Self::WalletRecovery => 2_800,
            Self::AuditDisclosure => 1_100,
        }
    }

    pub fn prefers_hot_contract_cache(self) -> bool {
        matches!(
            self,
            Self::ContractCall | Self::Swap | Self::StateTransition
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Submitted,
    Admitted,
    Deferred,
    Queued,
    Packed,
    Scheduled,
    Proving,
    Proved,
    Published,
    Rejected,
    Cancelled,
    Expired,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Admitted => "admitted",
            Self::Deferred => "deferred",
            Self::Queued => "queued",
            Self::Packed => "packed",
            Self::Scheduled => "scheduled",
            Self::Proving => "proving",
            Self::Proved => "proved",
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Admitted
                | Self::Deferred
                | Self::Queued
                | Self::Packed
                | Self::Scheduled
                | Self::Proving
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Packed,
    Assigned,
    Proving,
    Proved,
    Published,
    Failed,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Packed => "packed",
            Self::Assigned => "assigned",
            Self::Proving => "proving",
            Self::Proved => "proved",
            Self::Published => "published",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaClass {
    Instant,
    Fast,
    Standard,
    Economy,
    Maintenance,
}

impl SlaClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Economy => "economy",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn target_ms(self) -> u64 {
        match self {
            Self::Instant => 180,
            Self::Fast => 350,
            Self::Standard => 900,
            Self::Economy => 2_500,
            Self::Maintenance => 8_000,
        }
    }

    pub fn fairness_weight(self) -> u64 {
        match self {
            Self::Instant => 32,
            Self::Fast => 24,
            Self::Standard => 16,
            Self::Economy => 8,
            Self::Maintenance => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueLane {
    Critical,
    FastFee,
    Normal,
    LowFee,
    Recursive,
    Maintenance,
    SafeModeDrain,
}

impl QueueLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::FastFee => "fast_fee",
            Self::Normal => "normal",
            Self::LowFee => "low_fee",
            Self::Recursive => "recursive",
            Self::Maintenance => "maintenance",
            Self::SafeModeDrain => "safe_mode_drain",
        }
    }

    pub fn default_sla(self) -> SlaClass {
        match self {
            Self::Critical => SlaClass::Instant,
            Self::FastFee => SlaClass::Fast,
            Self::Normal => SlaClass::Standard,
            Self::LowFee => SlaClass::Economy,
            Self::Recursive => SlaClass::Standard,
            Self::Maintenance => SlaClass::Maintenance,
            Self::SafeModeDrain => SlaClass::Fast,
        }
    }

    pub fn admits_low_fee(self) -> bool {
        matches!(self, Self::LowFee | Self::Maintenance)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuClass {
    Any,
    Consumer,
    DataCenter,
    ConfidentialCompute,
    HighMemory,
}

impl GpuClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Consumer => "consumer",
            Self::DataCenter => "data_center",
            Self::ConfidentialCompute => "confidential_compute",
            Self::HighMemory => "high_memory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureMode {
    Open,
    PreferFastFee,
    LowFeeThrottle,
    PackOnly,
    CriticalOnly,
    SafeMode,
}

impl BackpressureMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PreferFastFee => "prefer_fast_fee",
            Self::LowFeeThrottle => "low_fee_throttle",
            Self::PackOnly => "pack_only",
            Self::CriticalOnly => "critical_only",
            Self::SafeMode => "safe_mode",
        }
    }

    pub fn admits(self, lane: QueueLane) -> bool {
        match self {
            Self::Open => true,
            Self::PreferFastFee => !matches!(lane, QueueLane::Maintenance),
            Self::LowFeeThrottle => !matches!(lane, QueueLane::LowFee | QueueLane::Maintenance),
            Self::PackOnly => matches!(lane, QueueLane::Critical | QueueLane::SafeModeDrain),
            Self::CriticalOnly => matches!(lane, QueueLane::Critical),
            Self::SafeMode => matches!(lane, QueueLane::Critical | QueueLane::SafeModeDrain),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admit,
    AdmitLowFee,
    Defer,
    Reject,
    Shed,
}

impl AdmissionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::AdmitLowFee => "admit_low_fee",
            Self::Defer => "defer",
            Self::Reject => "reject",
            Self::Shed => "shed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeModeActionKind {
    EnterSafeMode,
    ExitSafeMode,
    PauseLowFee,
    ResumeLowFee,
    DrainCritical,
    FreezeGpuPool,
    UnfreezeGpuPool,
    RaiseMinFee,
    LowerMinFee,
    DisableContract,
    EnableContract,
    RotateOperatorKey,
}

impl SafeModeActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnterSafeMode => "enter_safe_mode",
            Self::ExitSafeMode => "exit_safe_mode",
            Self::PauseLowFee => "pause_low_fee",
            Self::ResumeLowFee => "resume_low_fee",
            Self::DrainCritical => "drain_critical",
            Self::FreezeGpuPool => "freeze_gpu_pool",
            Self::UnfreezeGpuPool => "unfreeze_gpu_pool",
            Self::RaiseMinFee => "raise_min_fee",
            Self::LowerMinFee => "lower_min_fee",
            Self::DisableContract => "disable_contract",
            Self::EnableContract => "enable_contract",
            Self::RotateOperatorKey => "rotate_operator_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Configured,
    GpuPoolRegistered,
    JobSubmitted,
    JobAdmitted,
    JobDeferred,
    JobRejected,
    WitnessPacked,
    BatchOpened,
    BatchSealed,
    BatchAssigned,
    BatchProved,
    BatchPublished,
    BackpressureChanged,
    CacheHintRecorded,
    SafeModeAction,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::GpuPoolRegistered => "gpu_pool_registered",
            Self::JobSubmitted => "job_submitted",
            Self::JobAdmitted => "job_admitted",
            Self::JobDeferred => "job_deferred",
            Self::JobRejected => "job_rejected",
            Self::WitnessPacked => "witness_packed",
            Self::BatchOpened => "batch_opened",
            Self::BatchSealed => "batch_sealed",
            Self::BatchAssigned => "batch_assigned",
            Self::BatchProved => "batch_proved",
            Self::BatchPublished => "batch_published",
            Self::BackpressureChanged => "backpressure_changed",
            Self::CacheHintRecorded => "cache_hint_recorded",
            Self::SafeModeAction => "safe_mode_action",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub epoch: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_preconfirmation_ms: u64,
    pub max_batch_weight: u64,
    pub max_queue_depth: u64,
    pub gpu_memory_limit_bytes: u64,
    pub witness_pack_bytes: u64,
    pub low_fee_threshold_bps: u64,
    pub fair_share_quanta: u64,
    pub hot_cache_hint_ttl_slots: u64,
    pub safe_mode_min_severity: u8,
    pub require_pq_auth: bool,
    pub require_confidential_payload_roots: bool,
    pub enable_low_fee_lane: bool,
    pub enable_hot_contract_cache: bool,
    pub enable_operator_safe_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            epoch: DEFAULT_EPOCH,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONF_MS,
            soft_preconfirmation_ms: DEFAULT_SOFT_PRECONF_MS,
            max_batch_weight: DEFAULT_BATCH_MAX_WEIGHT,
            max_queue_depth: DEFAULT_QUEUE_DEPTH,
            gpu_memory_limit_bytes: DEFAULT_GPU_MEMORY_LIMIT_BYTES,
            witness_pack_bytes: DEFAULT_WITNESS_PACK_BYTES,
            low_fee_threshold_bps: DEFAULT_LOW_FEE_BPS,
            fair_share_quanta: DEFAULT_FAIR_SHARE_QUANTA,
            hot_cache_hint_ttl_slots: DEFAULT_HOT_CACHE_HINT_TTL_SLOTS,
            safe_mode_min_severity: DEFAULT_SAFE_MODE_SEVERITY,
            require_pq_auth: true,
            require_confidential_payload_roots: true,
            enable_low_fee_lane: true,
            enable_hot_contract_cache: true,
            enable_operator_safe_mode: true,
        };
        config.config_id = config_id(&config.identity_record());
        config
    }
}

impl Config {
    pub fn devnet() -> Self {
        let mut config = Self::default();
        config.epoch = 7;
        config.max_queue_depth = 8_192;
        config.max_batch_weight = 2_000_000;
        config.gpu_memory_limit_bytes = 8 * 1024 * 1024 * 1024;
        config.witness_pack_bytes = 8 * 1024 * 1024;
        config.config_id = config_id(&config.identity_record());
        config
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config_id": self.config_id,
            "epoch": self.epoch,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "soft_preconfirmation_ms": self.soft_preconfirmation_ms,
            "max_batch_weight": self.max_batch_weight,
            "max_queue_depth": self.max_queue_depth,
            "gpu_memory_limit_bytes": self.gpu_memory_limit_bytes,
            "witness_pack_bytes": self.witness_pack_bytes,
            "low_fee_threshold_bps": self.low_fee_threshold_bps,
            "fair_share_quanta": self.fair_share_quanta,
            "hot_cache_hint_ttl_slots": self.hot_cache_hint_ttl_slots,
            "safe_mode_min_severity": self.safe_mode_min_severity,
            "require_pq_auth": self.require_pq_auth,
            "require_confidential_payload_roots": self.require_confidential_payload_roots,
            "enable_low_fee_lane": self.enable_low_fee_lane,
            "enable_hot_contract_cache": self.enable_hot_contract_cache,
            "enable_operator_safe_mode": self.enable_operator_safe_mode,
            "pq_auth_scheme": PQ_AUTH_SCHEME,
            "proof_system": CONFIDENTIAL_PROOF_SYSTEM,
            "witness_packing_scheme": WITNESS_PACKING_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub submitted_jobs: u64,
    pub admitted_jobs: u64,
    pub deferred_jobs: u64,
    pub rejected_jobs: u64,
    pub shed_jobs: u64,
    pub low_fee_jobs: u64,
    pub packed_jobs: u64,
    pub scheduled_jobs: u64,
    pub proved_jobs: u64,
    pub published_jobs: u64,
    pub opened_batches: u64,
    pub sealed_batches: u64,
    pub assigned_batches: u64,
    pub failed_batches: u64,
    pub witness_bytes_packed: u64,
    pub gpu_cycles_reserved: u64,
    pub preconfirmations_issued: u64,
    pub preconfirmation_sla_misses: u64,
    pub backpressure_transitions: u64,
    pub safe_mode_actions: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl Counters {
    pub fn record_decision(&mut self, decision: AdmissionDecision) {
        match decision {
            AdmissionDecision::Admit => {
                self.admitted_jobs = self.admitted_jobs.saturating_add(1);
            }
            AdmissionDecision::AdmitLowFee => {
                self.admitted_jobs = self.admitted_jobs.saturating_add(1);
                self.low_fee_jobs = self.low_fee_jobs.saturating_add(1);
            }
            AdmissionDecision::Defer => {
                self.deferred_jobs = self.deferred_jobs.saturating_add(1);
            }
            AdmissionDecision::Reject => {
                self.rejected_jobs = self.rejected_jobs.saturating_add(1);
            }
            AdmissionDecision::Shed => {
                self.shed_jobs = self.shed_jobs.saturating_add(1);
            }
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "submitted_jobs": self.submitted_jobs,
            "admitted_jobs": self.admitted_jobs,
            "deferred_jobs": self.deferred_jobs,
            "rejected_jobs": self.rejected_jobs,
            "shed_jobs": self.shed_jobs,
            "low_fee_jobs": self.low_fee_jobs,
            "packed_jobs": self.packed_jobs,
            "scheduled_jobs": self.scheduled_jobs,
            "proved_jobs": self.proved_jobs,
            "published_jobs": self.published_jobs,
            "opened_batches": self.opened_batches,
            "sealed_batches": self.sealed_batches,
            "assigned_batches": self.assigned_batches,
            "failed_batches": self.failed_batches,
            "witness_bytes_packed": self.witness_bytes_packed,
            "gpu_cycles_reserved": self.gpu_cycles_reserved,
            "preconfirmations_issued": self.preconfirmations_issued,
            "preconfirmation_sla_misses": self.preconfirmation_sla_misses,
            "backpressure_transitions": self.backpressure_transitions,
            "safe_mode_actions": self.safe_mode_actions,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub gpu_pool_root: String,
    pub queue_root: String,
    pub job_root: String,
    pub batch_root: String,
    pub witness_root: String,
    pub preconfirmation_root: String,
    pub cache_hint_root: String,
    pub backpressure_root: String,
    pub safe_mode_root: String,
    pub counters_root: String,
    pub event_root: String,
    pub telemetry_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "gpu_pool_root": self.gpu_pool_root,
            "queue_root": self.queue_root,
            "job_root": self.job_root,
            "batch_root": self.batch_root,
            "witness_root": self.witness_root,
            "preconfirmation_root": self.preconfirmation_root,
            "cache_hint_root": self.cache_hint_root,
            "backpressure_root": self.backpressure_root,
            "safe_mode_root": self.safe_mode_root,
            "counters_root": self.counters_root,
            "event_root": self.event_root,
            "telemetry_root": self.telemetry_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuPoolRecord {
    pub pool_id: String,
    pub operator_id: String,
    pub gpu_class: GpuClass,
    pub device_count: u64,
    pub memory_bytes: u64,
    pub proving_cycles_per_slot: u64,
    pub confidential_compute: bool,
    pub pq_attestation_root: String,
    pub active: bool,
    pub frozen: bool,
    pub assigned_weight: u64,
}

impl GpuPoolRecord {
    pub fn capacity_weight(&self) -> u64 {
        if self.active && !self.frozen {
            self.device_count
                .saturating_mul(self.proving_cycles_per_slot)
        } else {
            0
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "operator_id": self.operator_id,
            "gpu_class": self.gpu_class.as_str(),
            "device_count": self.device_count,
            "memory_bytes": self.memory_bytes,
            "proving_cycles_per_slot": self.proving_cycles_per_slot,
            "confidential_compute": self.confidential_compute,
            "pq_attestation_root": self.pq_attestation_root,
            "active": self.active,
            "frozen": self.frozen,
            "assigned_weight": self.assigned_weight,
            "capacity_weight": self.capacity_weight(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobRequest {
    pub job_id: String,
    pub account_id: String,
    pub contract_id: String,
    pub proof_kind: ProofKind,
    pub lane: QueueLane,
    pub sla_class: SlaClass,
    pub fee_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub witness_bytes: u64,
    pub witness_columns: u64,
    pub witness_rows: u64,
    pub estimated_weight: u64,
    pub required_gpu_class: GpuClass,
    pub payload_root: String,
    pub witness_commitment_root: String,
    pub nullifier_root: String,
    pub pq_authorization_root: String,
    pub cache_hint_contracts: Vec<String>,
    pub submitted_slot: u64,
    pub expiry_slot: u64,
    pub privacy_budget: u64,
}

impl ProofJobRequest {
    pub fn normalized_weight(&self) -> u64 {
        let explicit = self.estimated_weight.max(self.proof_kind.base_weight());
        explicit.saturating_add(self.witness_bytes / 4096)
    }

    pub fn low_fee(&self, config: &Config) -> bool {
        if self.max_fee_micro_units == 0 {
            true
        } else {
            self.fee_micro_units.saturating_mul(MAX_BPS)
                <= self
                    .max_fee_micro_units
                    .saturating_mul(config.low_fee_threshold_bps)
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "account_id": self.account_id,
            "contract_id": self.contract_id,
            "proof_kind": self.proof_kind.as_str(),
            "lane": self.lane.as_str(),
            "sla_class": self.sla_class.as_str(),
            "fee_micro_units": self.fee_micro_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "witness_bytes": self.witness_bytes,
            "witness_columns": self.witness_columns,
            "witness_rows": self.witness_rows,
            "estimated_weight": self.estimated_weight,
            "normalized_weight": self.normalized_weight(),
            "required_gpu_class": self.required_gpu_class.as_str(),
            "payload_root": self.payload_root,
            "witness_commitment_root": self.witness_commitment_root,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "cache_hint_contracts": self.cache_hint_contracts,
            "submitted_slot": self.submitted_slot,
            "expiry_slot": self.expiry_slot,
            "privacy_budget": self.privacy_budget,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobRecord {
    pub request: ProofJobRequest,
    pub status: JobStatus,
    pub decision: AdmissionDecision,
    pub queue_id: String,
    pub batch_id: String,
    pub pack_id: String,
    pub assigned_pool_id: String,
    pub admission_reason: String,
    pub admitted_slot: u64,
    pub scheduled_slot: u64,
    pub proved_slot: u64,
    pub published_slot: u64,
    pub queue_rank: u64,
    pub fairness_credit: u64,
    pub low_fee_lane: bool,
}

impl ProofJobRecord {
    pub fn active(&self) -> bool {
        self.status.active()
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "request": self.request.identity_record(),
            "status": self.status.as_str(),
            "decision": self.decision.as_str(),
            "queue_id": self.queue_id,
            "batch_id": self.batch_id,
            "pack_id": self.pack_id,
            "assigned_pool_id": self.assigned_pool_id,
            "admission_reason": self.admission_reason,
            "admitted_slot": self.admitted_slot,
            "scheduled_slot": self.scheduled_slot,
            "proved_slot": self.proved_slot,
            "published_slot": self.published_slot,
            "queue_rank": self.queue_rank,
            "fairness_credit": self.fairness_credit,
            "low_fee_lane": self.low_fee_lane,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueRecord {
    pub queue_id: String,
    pub lane: QueueLane,
    pub sla_class: SlaClass,
    pub max_depth: u64,
    pub admitted_weight: u64,
    pub queued_weight: u64,
    pub proved_weight: u64,
    pub fairness_credit: u64,
    pub paused: bool,
    pub job_ids: VecDeque<String>,
}

impl QueueRecord {
    pub fn new(queue_id: String, lane: QueueLane, max_depth: u64, fair_share_quanta: u64) -> Self {
        Self {
            queue_id,
            lane,
            sla_class: lane.default_sla(),
            max_depth,
            admitted_weight: 0,
            queued_weight: 0,
            proved_weight: 0,
            fairness_credit: lane
                .default_sla()
                .fairness_weight()
                .saturating_mul(fair_share_quanta),
            paused: false,
            job_ids: VecDeque::new(),
        }
    }

    pub fn depth(&self) -> u64 {
        self.job_ids.len() as u64
    }

    pub fn has_capacity(&self) -> bool {
        !self.paused && self.depth() < self.max_depth
    }

    pub fn identity_record(&self) -> Value {
        let job_ids: Vec<String> = self.job_ids.iter().cloned().collect();
        json!({
            "queue_id": self.queue_id,
            "lane": self.lane.as_str(),
            "sla_class": self.sla_class.as_str(),
            "max_depth": self.max_depth,
            "depth": self.depth(),
            "admitted_weight": self.admitted_weight,
            "queued_weight": self.queued_weight,
            "proved_weight": self.proved_weight,
            "fairness_credit": self.fairness_credit,
            "paused": self.paused,
            "job_ids": job_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessPackRecord {
    pub pack_id: String,
    pub batch_id: String,
    pub job_ids: Vec<String>,
    pub total_witness_bytes: u64,
    pub total_columns: u64,
    pub total_rows: u64,
    pub packed_root: String,
    pub layout_root: String,
    pub compression_ratio_bps: u64,
    pub gpu_memory_bytes: u64,
    pub created_slot: u64,
}

impl WitnessPackRecord {
    pub fn identity_record(&self) -> Value {
        json!({
            "pack_id": self.pack_id,
            "batch_id": self.batch_id,
            "job_ids": self.job_ids,
            "total_witness_bytes": self.total_witness_bytes,
            "total_columns": self.total_columns,
            "total_rows": self.total_rows,
            "packed_root": self.packed_root,
            "layout_root": self.layout_root,
            "compression_ratio_bps": self.compression_ratio_bps,
            "gpu_memory_bytes": self.gpu_memory_bytes,
            "created_slot": self.created_slot,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    pub batch_id: String,
    pub status: BatchStatus,
    pub lane: QueueLane,
    pub sla_class: SlaClass,
    pub job_ids: Vec<String>,
    pub pack_id: String,
    pub assigned_pool_id: String,
    pub total_weight: u64,
    pub total_fee_micro_units: u64,
    pub witness_bytes: u64,
    pub expected_cycles: u64,
    pub opened_slot: u64,
    pub sealed_slot: u64,
    pub assigned_slot: u64,
    pub proved_slot: u64,
    pub published_slot: u64,
    pub proof_root: String,
    pub telemetry_root: String,
}

impl BatchRecord {
    pub fn identity_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "sla_class": self.sla_class.as_str(),
            "job_ids": self.job_ids,
            "pack_id": self.pack_id,
            "assigned_pool_id": self.assigned_pool_id,
            "total_weight": self.total_weight,
            "total_fee_micro_units": self.total_fee_micro_units,
            "witness_bytes": self.witness_bytes,
            "expected_cycles": self.expected_cycles,
            "opened_slot": self.opened_slot,
            "sealed_slot": self.sealed_slot,
            "assigned_slot": self.assigned_slot,
            "proved_slot": self.proved_slot,
            "published_slot": self.published_slot,
            "proof_root": self.proof_root,
            "telemetry_root": self.telemetry_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationBucketRecord {
    pub bucket_id: String,
    pub sla_class: SlaClass,
    pub target_ms: u64,
    pub max_weight: u64,
    pub pending_weight: u64,
    pub issued_count: u64,
    pub missed_count: u64,
    pub job_ids: BTreeSet<String>,
}

impl PreconfirmationBucketRecord {
    pub fn identity_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "sla_class": self.sla_class.as_str(),
            "target_ms": self.target_ms,
            "max_weight": self.max_weight,
            "pending_weight": self.pending_weight,
            "issued_count": self.issued_count,
            "missed_count": self.missed_count,
            "job_ids": self.job_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotContractCacheHintRecord {
    pub contract_id: String,
    pub hint_root: String,
    pub access_weight: u64,
    pub last_slot: u64,
    pub ttl_slots: u64,
    pub preferred_gpu_class: GpuClass,
    pub disabled: bool,
}

impl HotContractCacheHintRecord {
    pub fn active_at(&self, slot: u64) -> bool {
        !self.disabled && slot <= self.last_slot.saturating_add(self.ttl_slots)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "hint_root": self.hint_root,
            "access_weight": self.access_weight,
            "last_slot": self.last_slot,
            "ttl_slots": self.ttl_slots,
            "preferred_gpu_class": self.preferred_gpu_class.as_str(),
            "disabled": self.disabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureRecord {
    pub mode: BackpressureMode,
    pub reason: String,
    pub queue_depth: u64,
    pub queue_weight: u64,
    pub gpu_capacity_weight: u64,
    pub memory_pressure_bps: u64,
    pub low_fee_paused: bool,
    pub effective_min_fee_micro_units: u64,
    pub changed_slot: u64,
}

impl Default for BackpressureRecord {
    fn default() -> Self {
        Self {
            mode: BackpressureMode::Open,
            reason: String::from("genesis"),
            queue_depth: 0,
            queue_weight: 0,
            gpu_capacity_weight: 0,
            memory_pressure_bps: 0,
            low_fee_paused: false,
            effective_min_fee_micro_units: 0,
            changed_slot: 0,
        }
    }
}

impl BackpressureRecord {
    pub fn identity_record(&self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "reason": self.reason,
            "queue_depth": self.queue_depth,
            "queue_weight": self.queue_weight,
            "gpu_capacity_weight": self.gpu_capacity_weight,
            "memory_pressure_bps": self.memory_pressure_bps,
            "low_fee_paused": self.low_fee_paused,
            "effective_min_fee_micro_units": self.effective_min_fee_micro_units,
            "changed_slot": self.changed_slot,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeActionRecord {
    pub action_id: String,
    pub operator_id: String,
    pub kind: SafeModeActionKind,
    pub severity: u8,
    pub reason: String,
    pub target_id: String,
    pub previous_value: String,
    pub new_value: String,
    pub pq_approval_root: String,
    pub slot: u64,
    pub applied: bool,
}

impl SafeModeActionRecord {
    pub fn identity_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "severity": self.severity,
            "reason": self.reason,
            "target_id": self.target_id,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "pq_approval_root": self.pq_approval_root,
            "slot": self.slot,
            "applied": self.applied,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub slot: u64,
    pub record_root: String,
    pub detail: String,
}

impl EventRecord {
    pub fn identity_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "slot": self.slot,
            "record_root": self.record_root,
            "detail": self.detail,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRecord {
    pub job_id: String,
    pub decision: AdmissionDecision,
    pub lane: QueueLane,
    pub queue_id: String,
    pub reason: String,
    pub queue_depth_after: u64,
    pub effective_fee_micro_units: u64,
    pub fairness_credit_after: u64,
    pub slot: u64,
}

impl AdmissionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "decision": self.decision.as_str(),
            "lane": self.lane.as_str(),
            "queue_id": self.queue_id,
            "reason": self.reason,
            "queue_depth_after": self.queue_depth_after,
            "effective_fee_micro_units": self.effective_fee_micro_units,
            "fairness_credit_after": self.fairness_credit_after,
            "slot": self.slot,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleRecord {
    pub batch_id: String,
    pub assigned_pool_id: String,
    pub job_ids: Vec<String>,
    pub total_weight: u64,
    pub witness_bytes: u64,
    pub expected_cycles: u64,
    pub slot: u64,
    pub telemetry_root: String,
}

impl ScheduleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "assigned_pool_id": self.assigned_pool_id,
            "job_ids": self.job_ids,
            "total_weight": self.total_weight,
            "witness_bytes": self.witness_bytes,
            "expected_cycles": self.expected_cycles,
            "slot": self.slot,
            "telemetry_root": self.telemetry_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_slot: u64,
    pub queues: BTreeMap<String, QueueRecord>,
    pub jobs: BTreeMap<String, ProofJobRecord>,
    pub batches: BTreeMap<String, BatchRecord>,
    pub witness_packs: BTreeMap<String, WitnessPackRecord>,
    pub gpu_pools: BTreeMap<String, GpuPoolRecord>,
    pub preconfirmation_buckets: BTreeMap<String, PreconfirmationBucketRecord>,
    pub hot_contract_cache_hints: BTreeMap<String, HotContractCacheHintRecord>,
    pub safe_mode_actions: BTreeMap<String, SafeModeActionRecord>,
    pub events: BTreeMap<String, EventRecord>,
    pub backpressure: BackpressureRecord,
    pub counters: Counters,
    pub roots: Roots,
    pub safe_mode_active: bool,
}

pub type Runtime = State;

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            current_slot: 0,
            queues: BTreeMap::new(),
            jobs: BTreeMap::new(),
            batches: BTreeMap::new(),
            witness_packs: BTreeMap::new(),
            gpu_pools: BTreeMap::new(),
            preconfirmation_buckets: BTreeMap::new(),
            hot_contract_cache_hints: BTreeMap::new(),
            safe_mode_actions: BTreeMap::new(),
            events: BTreeMap::new(),
            backpressure: BackpressureRecord::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            safe_mode_active: false,
        };
        state.install_default_queues();
        state.install_default_buckets();
        state.record_event(
            EventKind::Configured,
            state.config.config_id.clone(),
            "config installed",
        );
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let pool = GpuPoolRecord {
            pool_id: String::from("devnet-gpu-pool-0"),
            operator_id: String::from("operator-devnet"),
            gpu_class: GpuClass::ConfidentialCompute,
            device_count: 4,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            proving_cycles_per_slot: 1_250_000,
            confidential_compute: true,
            pq_attestation_root: String::from("devnet-pq-attestation-root"),
            active: true,
            frozen: false,
            assigned_weight: 0,
        };
        let _ = state.register_gpu_pool(pool);
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let requests = vec![
            ProofJobRequest {
                job_id: String::from("demo-transfer-0"),
                account_id: String::from("acct-a"),
                contract_id: String::from("native-transfer"),
                proof_kind: ProofKind::Transfer,
                lane: QueueLane::FastFee,
                sla_class: SlaClass::Fast,
                fee_micro_units: 420,
                max_fee_micro_units: 900,
                witness_bytes: 90_112,
                witness_columns: 24,
                witness_rows: 512,
                estimated_weight: 1_200,
                required_gpu_class: GpuClass::Any,
                payload_root: String::from("payload-demo-transfer"),
                witness_commitment_root: String::from("witness-demo-transfer"),
                nullifier_root: String::from("nullifier-demo-transfer"),
                pq_authorization_root: String::from("pq-auth-demo-transfer"),
                cache_hint_contracts: vec![String::from("native-transfer")],
                submitted_slot: 1,
                expiry_slot: 16,
                privacy_budget: 64,
            },
            ProofJobRequest {
                job_id: String::from("demo-contract-0"),
                account_id: String::from("acct-b"),
                contract_id: String::from("amm-private-v1"),
                proof_kind: ProofKind::ContractCall,
                lane: QueueLane::FastFee,
                sla_class: SlaClass::Fast,
                fee_micro_units: 1_600,
                max_fee_micro_units: 2_000,
                witness_bytes: 440_320,
                witness_columns: 96,
                witness_rows: 2048,
                estimated_weight: 3_400,
                required_gpu_class: GpuClass::ConfidentialCompute,
                payload_root: String::from("payload-demo-contract"),
                witness_commitment_root: String::from("witness-demo-contract"),
                nullifier_root: String::from("nullifier-demo-contract"),
                pq_authorization_root: String::from("pq-auth-demo-contract"),
                cache_hint_contracts: vec![String::from("amm-private-v1")],
                submitted_slot: 1,
                expiry_slot: 20,
                privacy_budget: 128,
            },
            ProofJobRequest {
                job_id: String::from("demo-low-fee-0"),
                account_id: String::from("acct-c"),
                contract_id: String::from("wallet-transfer"),
                proof_kind: ProofKind::Transfer,
                lane: QueueLane::LowFee,
                sla_class: SlaClass::Economy,
                fee_micro_units: 20,
                max_fee_micro_units: 1_000,
                witness_bytes: 64_000,
                witness_columns: 16,
                witness_rows: 384,
                estimated_weight: 900,
                required_gpu_class: GpuClass::Any,
                payload_root: String::from("payload-demo-low-fee"),
                witness_commitment_root: String::from("witness-demo-low-fee"),
                nullifier_root: String::from("nullifier-demo-low-fee"),
                pq_authorization_root: String::from("pq-auth-demo-low-fee"),
                cache_hint_contracts: vec![String::from("wallet-transfer")],
                submitted_slot: 1,
                expiry_slot: 80,
                privacy_budget: 32,
            },
        ];
        for request in requests {
            let _ = state.submit_job(request);
        }
        let _ = state.pack_next_batch(1);
        let _ = state.assign_next_batch(2);
        state.refresh_roots();
        state
    }

    pub fn install_default_queues(&mut self) {
        let lanes = [
            QueueLane::Critical,
            QueueLane::FastFee,
            QueueLane::Normal,
            QueueLane::LowFee,
            QueueLane::Recursive,
            QueueLane::Maintenance,
            QueueLane::SafeModeDrain,
        ];
        for lane in lanes {
            let queue_id = queue_id_for_lane(lane);
            if !self.queues.contains_key(&queue_id) && self.queues.len() < MAX_QUEUES {
                self.queues.insert(
                    queue_id.clone(),
                    QueueRecord::new(
                        queue_id,
                        lane,
                        self.config.max_queue_depth,
                        self.config.fair_share_quanta,
                    ),
                );
            }
        }
    }

    pub fn install_default_buckets(&mut self) {
        let classes = [
            SlaClass::Instant,
            SlaClass::Fast,
            SlaClass::Standard,
            SlaClass::Economy,
            SlaClass::Maintenance,
        ];
        for class in classes {
            if self.preconfirmation_buckets.len() < MAX_BUCKETS {
                let bucket_id = format!("preconfirm-{}", class.as_str());
                self.preconfirmation_buckets
                    .entry(bucket_id.clone())
                    .or_insert(PreconfirmationBucketRecord {
                        bucket_id,
                        sla_class: class,
                        target_ms: class.target_ms(),
                        max_weight: self.config.max_batch_weight,
                        pending_weight: 0,
                        issued_count: 0,
                        missed_count: 0,
                        job_ids: BTreeSet::new(),
                    });
            }
        }
    }

    pub fn register_gpu_pool(
        &mut self,
        pool: GpuPoolRecord,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<String> {
        if pool.pool_id.is_empty() {
            return Err(String::from("gpu pool id is required"));
        }
        if self.gpu_pools.len() >= MAX_GPU_POOLS && !self.gpu_pools.contains_key(&pool.pool_id) {
            return Err(String::from("gpu pool registry is full"));
        }
        let pool_id = pool.pool_id.clone();
        self.gpu_pools.insert(pool_id.clone(), pool);
        self.record_event(
            EventKind::GpuPoolRegistered,
            pool_id.clone(),
            "gpu pool registered",
        );
        self.refresh_backpressure(String::from("gpu_pool_registered"));
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn submit_job(
        &mut self,
        request: ProofJobRequest,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<AdmissionRecord> {
        self.current_slot = self.current_slot.max(request.submitted_slot);
        self.counters.submitted_jobs = self.counters.submitted_jobs.saturating_add(1);
        if request.job_id.is_empty() {
            return Err(String::from("job id is required"));
        }
        if self.jobs.contains_key(&request.job_id) {
            return Err(String::from("job id already exists"));
        }
        if self.jobs.len() >= MAX_JOBS {
            return Err(String::from("job registry is full"));
        }
        self.record_cache_hints(&request);
        self.record_event(
            EventKind::JobSubmitted,
            request.job_id.clone(),
            "job submitted",
        );
        let admission = self.admit_job(request);
        self.refresh_backpressure(String::from("job_submitted"));
        self.refresh_roots();
        admission
    }

    pub fn admit_job(
        &mut self,
        request: ProofJobRequest,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<AdmissionRecord> {
        let low_fee = request.low_fee(&self.config) || request.lane.admits_low_fee();
        let lane = if low_fee && self.config.enable_low_fee_lane {
            QueueLane::LowFee
        } else {
            request.lane
        };
        let queue_id = queue_id_for_lane(lane);
        let queue_depth = self.total_queue_depth();
        let queue_weight = self.total_queue_weight();
        let decision = self.decide_admission(&request, lane, queue_depth, queue_weight);
        self.counters.record_decision(decision);
        let mut reason = admission_reason(decision, self.backpressure.mode, lane);
        let mut status = JobStatus::Deferred;
        let mut queue_rank = 0;
        let mut fairness_credit_after = 0;
        let mut queue_depth_after = 0;
        if matches!(
            decision,
            AdmissionDecision::Admit | AdmissionDecision::AdmitLowFee
        ) {
            if let Some(queue) = self.queues.get_mut(&queue_id) {
                let weight = request.normalized_weight();
                queue.job_ids.push_back(request.job_id.clone());
                queue.admitted_weight = queue.admitted_weight.saturating_add(weight);
                queue.queued_weight = queue.queued_weight.saturating_add(weight);
                queue.fairness_credit = queue
                    .fairness_credit
                    .saturating_add(request.sla_class.fairness_weight());
                queue_rank = queue.depth();
                queue_depth_after = queue.depth();
                fairness_credit_after = queue.fairness_credit;
                status = JobStatus::Queued;
                reason = String::from("admitted to deterministic queue");
                self.update_preconfirmation_bucket(&request, weight, false);
            } else {
                return Err(String::from("queue is missing"));
            }
        } else if matches!(
            decision,
            AdmissionDecision::Reject | AdmissionDecision::Shed
        ) {
            status = JobStatus::Rejected;
        }
        let record = ProofJobRecord {
            request: request.clone(),
            status,
            decision,
            queue_id: queue_id.clone(),
            batch_id: String::new(),
            pack_id: String::new(),
            assigned_pool_id: String::new(),
            admission_reason: reason.clone(),
            admitted_slot: self.current_slot,
            scheduled_slot: 0,
            proved_slot: 0,
            published_slot: 0,
            queue_rank,
            fairness_credit: fairness_credit_after,
            low_fee_lane: low_fee,
        };
        self.jobs.insert(request.job_id.clone(), record);
        self.record_event(
            event_for_decision(decision),
            request.job_id.clone(),
            reason.as_str(),
        );
        Ok(AdmissionRecord {
            job_id: request.job_id,
            decision,
            lane,
            queue_id,
            reason,
            queue_depth_after,
            effective_fee_micro_units: self.backpressure.effective_min_fee_micro_units,
            fairness_credit_after,
            slot: self.current_slot,
        })
    }

    pub fn pack_next_batch(
        &mut self,
        slot: u64,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<ScheduleRecord> {
        self.current_slot = self.current_slot.max(slot);
        let lane = self.next_lane_for_packing();
        let queue_id = queue_id_for_lane(lane);
        let selected = self.select_jobs_for_batch(&queue_id);
        if selected.is_empty() {
            return Err(String::from("no jobs available for packing"));
        }
        let batch_id = format!(
            "batch-{}-{}",
            self.current_slot,
            self.counters.opened_batches.saturating_add(1)
        );
        let pack_id = format!(
            "pack-{}-{}",
            self.current_slot,
            self.counters.opened_batches.saturating_add(1)
        );
        let mut total_weight = 0_u64;
        let mut total_fee = 0_u64;
        let mut witness_bytes = 0_u64;
        let mut total_columns = 0_u64;
        let mut total_rows = 0_u64;
        for job_id in &selected {
            if let Some(job) = self.jobs.get_mut(job_id) {
                total_weight = total_weight.saturating_add(job.request.normalized_weight());
                total_fee = total_fee.saturating_add(job.request.fee_micro_units);
                witness_bytes = witness_bytes.saturating_add(job.request.witness_bytes);
                total_columns = total_columns.saturating_add(job.request.witness_columns);
                total_rows = total_rows.saturating_add(job.request.witness_rows);
                job.status = JobStatus::Packed;
                job.batch_id = batch_id.clone();
                job.pack_id = pack_id.clone();
                self.counters.packed_jobs = self.counters.packed_jobs.saturating_add(1);
            }
        }
        let pack_root = deterministic_root(
            "witness_pack_payload",
            &json!({
                "pack_id": pack_id,
                "batch_id": batch_id,
                "job_ids": selected,
                "witness_bytes": witness_bytes,
                "columns": total_columns,
                "rows": total_rows,
            }),
        );
        let layout_root = deterministic_root(
            "witness_pack_layout",
            &json!({
                "pack_id": pack_id,
                "scheme": WITNESS_PACKING_SCHEME,
                "columns": total_columns,
                "rows": total_rows,
                "gpu_memory_bytes": witness_bytes,
            }),
        );
        let pack = WitnessPackRecord {
            pack_id: pack_id.clone(),
            batch_id: batch_id.clone(),
            job_ids: selected.clone(),
            total_witness_bytes: witness_bytes,
            total_columns,
            total_rows,
            packed_root: pack_root,
            layout_root,
            compression_ratio_bps: compression_ratio_bps(
                witness_bytes,
                self.config.witness_pack_bytes,
            ),
            gpu_memory_bytes: witness_bytes.min(self.config.gpu_memory_limit_bytes),
            created_slot: self.current_slot,
        };
        let telemetry_root = deterministic_root(
            TELEMETRY_ROOT_DOMAIN,
            &json!({
                "batch_id": batch_id,
                "pack_id": pack_id,
                "slot": self.current_slot,
                "total_weight": total_weight,
                "witness_bytes": witness_bytes,
                "job_count": selected.len(),
            }),
        );
        let batch = BatchRecord {
            batch_id: batch_id.clone(),
            status: BatchStatus::Packed,
            lane,
            sla_class: lane.default_sla(),
            job_ids: selected.clone(),
            pack_id: pack_id.clone(),
            assigned_pool_id: String::new(),
            total_weight,
            total_fee_micro_units: total_fee,
            witness_bytes,
            expected_cycles: total_weight.saturating_mul(8),
            opened_slot: self.current_slot,
            sealed_slot: self.current_slot,
            assigned_slot: 0,
            proved_slot: 0,
            published_slot: 0,
            proof_root: String::new(),
            telemetry_root: telemetry_root.clone(),
        };
        self.witness_packs.insert(pack_id, pack);
        self.batches.insert(batch_id.clone(), batch);
        self.counters.opened_batches = self.counters.opened_batches.saturating_add(1);
        self.counters.sealed_batches = self.counters.sealed_batches.saturating_add(1);
        self.counters.witness_bytes_packed = self
            .counters
            .witness_bytes_packed
            .saturating_add(witness_bytes);
        self.record_event(
            EventKind::WitnessPacked,
            batch_id.clone(),
            "witness pack created",
        );
        self.record_event(
            EventKind::BatchSealed,
            batch_id.clone(),
            "batch sealed for gpu assignment",
        );
        self.refresh_backpressure(String::from("batch_packed"));
        self.refresh_roots();
        Ok(ScheduleRecord {
            batch_id,
            assigned_pool_id: String::new(),
            job_ids: selected,
            total_weight,
            witness_bytes,
            expected_cycles: total_weight.saturating_mul(8),
            slot: self.current_slot,
            telemetry_root,
        })
    }

    pub fn assign_next_batch(
        &mut self,
        slot: u64,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<ScheduleRecord> {
        self.current_slot = self.current_slot.max(slot);
        let batch_id = match self
            .batches
            .iter()
            .find(|(_, batch)| batch.status == BatchStatus::Packed)
            .map(|(batch_id, _)| batch_id.clone())
        {
            Some(batch_id) => batch_id,
            None => return Err(String::from("no packed batch available")),
        };
        let pool_id = match self.best_gpu_pool_for_batch(&batch_id) {
            Some(pool_id) => pool_id,
            None => return Err(String::from("no active gpu pool available")),
        };
        let mut job_ids = Vec::new();
        let mut total_weight = 0_u64;
        let mut witness_bytes = 0_u64;
        let mut expected_cycles = 0_u64;
        let mut telemetry_root = String::new();
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            batch.status = BatchStatus::Assigned;
            batch.assigned_pool_id = pool_id.clone();
            batch.assigned_slot = self.current_slot;
            job_ids = batch.job_ids.clone();
            total_weight = batch.total_weight;
            witness_bytes = batch.witness_bytes;
            expected_cycles = batch.expected_cycles;
            telemetry_root = batch.telemetry_root.clone();
        }
        for job_id in &job_ids {
            if let Some(job) = self.jobs.get_mut(job_id) {
                job.status = JobStatus::Scheduled;
                job.assigned_pool_id = pool_id.clone();
                job.scheduled_slot = self.current_slot;
                self.counters.scheduled_jobs = self.counters.scheduled_jobs.saturating_add(1);
            }
        }
        if let Some(pool) = self.gpu_pools.get_mut(&pool_id) {
            pool.assigned_weight = pool.assigned_weight.saturating_add(total_weight);
        }
        self.counters.assigned_batches = self.counters.assigned_batches.saturating_add(1);
        self.counters.gpu_cycles_reserved = self
            .counters
            .gpu_cycles_reserved
            .saturating_add(expected_cycles);
        self.record_event(
            EventKind::BatchAssigned,
            batch_id.clone(),
            "batch assigned to gpu pool",
        );
        self.refresh_backpressure(String::from("batch_assigned"));
        self.refresh_roots();
        Ok(ScheduleRecord {
            batch_id,
            assigned_pool_id: pool_id,
            job_ids,
            total_weight,
            witness_bytes,
            expected_cycles,
            slot: self.current_slot,
            telemetry_root,
        })
    }

    pub fn mark_batch_proved(
        &mut self,
        batch_id: &str,
        proof_root: String,
        slot: u64,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<()> {
        self.current_slot = self.current_slot.max(slot);
        let mut job_ids = Vec::new();
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Proved;
            batch.proved_slot = self.current_slot;
            batch.proof_root = proof_root;
            job_ids = batch.job_ids.clone();
        } else {
            return Err(String::from("batch not found"));
        }
        for job_id in job_ids {
            let mut bucket_update: Option<(ProofJobRequest, u64)> = None;
            if let Some(job) = self.jobs.get_mut(&job_id) {
                job.status = JobStatus::Proved;
                job.proved_slot = self.current_slot;
                bucket_update = Some((job.request.clone(), job.request.normalized_weight()));
                self.counters.proved_jobs = self.counters.proved_jobs.saturating_add(1);
            }
            if let Some((request, weight)) = bucket_update {
                self.update_preconfirmation_bucket(&request, weight, true);
            }
        }
        self.record_event(
            EventKind::BatchProved,
            String::from(batch_id),
            "batch proof completed",
        );
        self.refresh_backpressure(String::from("batch_proved"));
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_batch(
        &mut self,
        batch_id: &str,
        slot: u64,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<()> {
        self.current_slot = self.current_slot.max(slot);
        let mut job_ids = Vec::new();
        if let Some(batch) = self.batches.get_mut(batch_id) {
            batch.status = BatchStatus::Published;
            batch.published_slot = self.current_slot;
            job_ids = batch.job_ids.clone();
        } else {
            return Err(String::from("batch not found"));
        }
        for job_id in job_ids {
            if let Some(job) = self.jobs.get_mut(&job_id) {
                job.status = JobStatus::Published;
                job.published_slot = self.current_slot;
                self.counters.published_jobs = self.counters.published_jobs.saturating_add(1);
            }
        }
        self.record_event(
            EventKind::BatchPublished,
            String::from(batch_id),
            "batch published",
        );
        self.refresh_roots();
        Ok(())
    }

    pub fn apply_safe_mode_action(
        &mut self,
        mut action: SafeModeActionRecord,
    ) -> PrivateL2FastPqConfidentialGpuProverBatchSchedulerResult<()> {
        if !self.config.enable_operator_safe_mode {
            return Err(String::from("operator safe mode is disabled"));
        }
        if action.action_id.is_empty() {
            return Err(String::from("safe mode action id is required"));
        }
        if action.severity < self.config.safe_mode_min_severity {
            return Err(String::from("safe mode action severity is below threshold"));
        }
        self.current_slot = self.current_slot.max(action.slot);
        let previous = self.backpressure.clone();
        match action.kind {
            SafeModeActionKind::EnterSafeMode => {
                self.safe_mode_active = true;
                self.backpressure.mode = BackpressureMode::SafeMode;
                self.backpressure.reason = action.reason.clone();
            }
            SafeModeActionKind::ExitSafeMode => {
                self.safe_mode_active = false;
                self.backpressure.mode = BackpressureMode::Open;
                self.backpressure.reason = action.reason.clone();
            }
            SafeModeActionKind::PauseLowFee => {
                if let Some(queue) = self.queues.get_mut(&queue_id_for_lane(QueueLane::LowFee)) {
                    queue.paused = true;
                }
                self.backpressure.low_fee_paused = true;
            }
            SafeModeActionKind::ResumeLowFee => {
                if let Some(queue) = self.queues.get_mut(&queue_id_for_lane(QueueLane::LowFee)) {
                    queue.paused = false;
                }
                self.backpressure.low_fee_paused = false;
            }
            SafeModeActionKind::DrainCritical => {
                self.backpressure.mode = BackpressureMode::CriticalOnly;
                self.backpressure.reason = action.reason.clone();
            }
            SafeModeActionKind::FreezeGpuPool => {
                if let Some(pool) = self.gpu_pools.get_mut(&action.target_id) {
                    pool.frozen = true;
                }
            }
            SafeModeActionKind::UnfreezeGpuPool => {
                if let Some(pool) = self.gpu_pools.get_mut(&action.target_id) {
                    pool.frozen = false;
                }
            }
            SafeModeActionKind::RaiseMinFee => {
                self.backpressure.effective_min_fee_micro_units =
                    parse_u64_or_zero(&action.new_value)
                        .max(self.backpressure.effective_min_fee_micro_units);
            }
            SafeModeActionKind::LowerMinFee => {
                self.backpressure.effective_min_fee_micro_units =
                    parse_u64_or_zero(&action.new_value);
            }
            SafeModeActionKind::DisableContract => {
                if let Some(hint) = self.hot_contract_cache_hints.get_mut(&action.target_id) {
                    hint.disabled = true;
                }
            }
            SafeModeActionKind::EnableContract => {
                if let Some(hint) = self.hot_contract_cache_hints.get_mut(&action.target_id) {
                    hint.disabled = false;
                }
            }
            SafeModeActionKind::RotateOperatorKey => {}
        }
        self.backpressure.changed_slot = self.current_slot;
        action.previous_value = deterministic_root(
            "safe_mode_previous_backpressure",
            &previous.identity_record(),
        );
        action.applied = true;
        self.safe_mode_actions
            .insert(action.action_id.clone(), action.clone());
        self.counters.safe_mode_actions = self.counters.safe_mode_actions.saturating_add(1);
        self.record_event(
            EventKind::SafeModeAction,
            action.action_id,
            "safe mode action applied",
        );
        self.refresh_backpressure(String::from("safe_mode_action"));
        self.refresh_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_protocol_version": PRIVATE_L2_FAST_PQ_CONFIDENTIAL_GPU_PROVER_BATCH_SCHEDULER_PROTOCOL_VERSION,
            "config": self.config.identity_record(),
            "current_slot": self.current_slot,
            "queue_count": self.queues.len(),
            "job_count": self.jobs.len(),
            "batch_count": self.batches.len(),
            "witness_pack_count": self.witness_packs.len(),
            "gpu_pool_count": self.gpu_pools.len(),
            "preconfirmation_bucket_count": self.preconfirmation_buckets.len(),
            "hot_contract_cache_hint_count": self.hot_contract_cache_hints.len(),
            "safe_mode_action_count": self.safe_mode_actions.len(),
            "event_count": self.events.len(),
            "safe_mode_active": self.safe_mode_active,
            "backpressure": self.backpressure.identity_record(),
            "counters": self.counters.identity_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        let config_root = deterministic_root("config", &self.config.identity_record());
        let gpu_pool_root = root_for_records(
            "gpu_pools",
            self.gpu_pools
                .values()
                .map(GpuPoolRecord::identity_record)
                .collect(),
        );
        let queue_root = root_for_records(
            "queues",
            self.queues
                .values()
                .map(QueueRecord::identity_record)
                .collect(),
        );
        let job_root = root_for_records(
            "jobs",
            self.jobs
                .values()
                .map(ProofJobRecord::identity_record)
                .collect(),
        );
        let batch_root = root_for_records(
            "batches",
            self.batches
                .values()
                .map(BatchRecord::identity_record)
                .collect(),
        );
        let witness_root = root_for_records(
            "witness_packs",
            self.witness_packs
                .values()
                .map(WitnessPackRecord::identity_record)
                .collect(),
        );
        let preconfirmation_root = root_for_records(
            "preconfirmation_buckets",
            self.preconfirmation_buckets
                .values()
                .map(PreconfirmationBucketRecord::identity_record)
                .collect(),
        );
        let cache_hint_root = root_for_records(
            "hot_contract_cache_hints",
            self.hot_contract_cache_hints
                .values()
                .map(HotContractCacheHintRecord::identity_record)
                .collect(),
        );
        let backpressure_root =
            deterministic_root("backpressure", &self.backpressure.identity_record());
        let safe_mode_root = root_for_records(
            "safe_mode_actions",
            self.safe_mode_actions
                .values()
                .map(SafeModeActionRecord::identity_record)
                .collect(),
        );
        let counters_root = deterministic_root("counters", &self.counters.identity_record());
        let event_root = root_for_records(
            "events",
            self.events
                .values()
                .map(EventRecord::identity_record)
                .collect(),
        );
        let telemetry_root = deterministic_root(
            TELEMETRY_ROOT_DOMAIN,
            &json!({
                "config_root": config_root,
                "gpu_pool_root": gpu_pool_root,
                "queue_root": queue_root,
                "job_root": job_root,
                "batch_root": batch_root,
                "witness_root": witness_root,
                "preconfirmation_root": preconfirmation_root,
                "cache_hint_root": cache_hint_root,
                "backpressure_root": backpressure_root,
                "safe_mode_root": safe_mode_root,
                "counters_root": counters_root,
                "event_root": event_root,
            }),
        );
        let state_root = deterministic_root(
            "state",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "config_root": config_root,
                "gpu_pool_root": gpu_pool_root,
                "queue_root": queue_root,
                "job_root": job_root,
                "batch_root": batch_root,
                "witness_root": witness_root,
                "preconfirmation_root": preconfirmation_root,
                "cache_hint_root": cache_hint_root,
                "backpressure_root": backpressure_root,
                "safe_mode_root": safe_mode_root,
                "counters_root": counters_root,
                "event_root": event_root,
                "telemetry_root": telemetry_root,
                "current_slot": self.current_slot,
                "safe_mode_active": self.safe_mode_active,
            }),
        );
        self.roots = Roots {
            config_root,
            gpu_pool_root,
            queue_root,
            job_root,
            batch_root,
            witness_root,
            preconfirmation_root,
            cache_hint_root,
            backpressure_root,
            safe_mode_root,
            counters_root,
            event_root,
            telemetry_root,
            state_root,
        };
    }

    fn decide_admission(
        &self,
        request: &ProofJobRequest,
        lane: QueueLane,
        queue_depth: u64,
        queue_weight: u64,
    ) -> AdmissionDecision {
        if self.config.require_pq_auth && request.pq_authorization_root.is_empty() {
            return AdmissionDecision::Reject;
        }
        if self.config.require_confidential_payload_roots
            && (request.payload_root.is_empty()
                || request.witness_commitment_root.is_empty()
                || request.nullifier_root.is_empty())
        {
            return AdmissionDecision::Reject;
        }
        if request.expiry_slot != 0 && request.expiry_slot <= self.current_slot {
            return AdmissionDecision::Reject;
        }
        if !self.backpressure.mode.admits(lane) {
            return if self.safe_mode_active {
                AdmissionDecision::Shed
            } else {
                AdmissionDecision::Defer
            };
        }
        if queue_depth >= self.config.max_queue_depth {
            return AdmissionDecision::Shed;
        }
        if queue_weight >= self.config.max_batch_weight.saturating_mul(8) {
            return AdmissionDecision::Defer;
        }
        if request.fee_micro_units < self.backpressure.effective_min_fee_micro_units {
            return AdmissionDecision::Defer;
        }
        if request.low_fee(&self.config) || lane == QueueLane::LowFee {
            if self.backpressure.low_fee_paused || !self.config.enable_low_fee_lane {
                AdmissionDecision::Defer
            } else {
                AdmissionDecision::AdmitLowFee
            }
        } else {
            AdmissionDecision::Admit
        }
    }

    fn select_jobs_for_batch(&mut self, queue_id: &str) -> Vec<String> {
        let mut selected = Vec::new();
        let mut selected_weight = 0_u64;
        let mut selected_witness_bytes = 0_u64;
        if let Some(queue) = self.queues.get_mut(queue_id) {
            while let Some(job_id) = queue.job_ids.pop_front() {
                let mut include = false;
                let mut weight = 0_u64;
                let mut witness_bytes = 0_u64;
                if let Some(job) = self.jobs.get(&job_id) {
                    weight = job.request.normalized_weight();
                    witness_bytes = job.request.witness_bytes;
                    include = selected_weight.saturating_add(weight)
                        <= self.config.max_batch_weight
                        && selected_witness_bytes.saturating_add(witness_bytes)
                            <= self.config.witness_pack_bytes;
                }
                if include {
                    selected_weight = selected_weight.saturating_add(weight);
                    selected_witness_bytes = selected_witness_bytes.saturating_add(witness_bytes);
                    selected.push(job_id);
                } else {
                    queue.job_ids.push_front(job_id);
                    break;
                }
            }
            queue.queued_weight = queue.queued_weight.saturating_sub(selected_weight);
            queue.fairness_credit = queue.fairness_credit.saturating_sub(selected.len() as u64);
        }
        selected
    }

    fn next_lane_for_packing(&self) -> QueueLane {
        let mut best_lane = QueueLane::Maintenance;
        let mut best_score = 0_u64;
        for queue in self.queues.values() {
            if queue.paused || queue.job_ids.is_empty() {
                continue;
            }
            let score = queue.fairness_credit.saturating_add(
                queue
                    .sla_class
                    .fairness_weight()
                    .saturating_mul(queue.depth()),
            );
            if score > best_score {
                best_lane = queue.lane;
                best_score = score;
            }
        }
        best_lane
    }

    fn best_gpu_pool_for_batch(&self, batch_id: &str) -> Option<String> {
        let batch = self.batches.get(batch_id)?;
        let required = self.required_gpu_class_for_batch(batch);
        let mut best: Option<(String, u64)> = None;
        for (pool_id, pool) in &self.gpu_pools {
            if !gpu_class_matches(pool.gpu_class, required) {
                continue;
            }
            if pool.memory_bytes < batch.witness_bytes {
                continue;
            }
            let score = pool.capacity_weight().saturating_sub(pool.assigned_weight);
            match &best {
                Some((_, best_score)) if score <= *best_score => {}
                _ => best = Some((pool_id.clone(), score)),
            }
        }
        best.map(|(pool_id, _)| pool_id)
    }

    fn required_gpu_class_for_batch(&self, batch: &BatchRecord) -> GpuClass {
        let mut required = GpuClass::Any;
        for job_id in &batch.job_ids {
            if let Some(job) = self.jobs.get(job_id) {
                required = stronger_gpu_class(required, job.request.required_gpu_class);
            }
        }
        required
    }

    fn update_preconfirmation_bucket(
        &mut self,
        request: &ProofJobRequest,
        weight: u64,
        proved: bool,
    ) {
        let bucket_id = format!("preconfirm-{}", request.sla_class.as_str());
        if let Some(bucket) = self.preconfirmation_buckets.get_mut(&bucket_id) {
            if proved {
                bucket.pending_weight = bucket.pending_weight.saturating_sub(weight);
                bucket.issued_count = bucket.issued_count.saturating_add(1);
                bucket.job_ids.remove(&request.job_id);
                self.counters.preconfirmations_issued =
                    self.counters.preconfirmations_issued.saturating_add(1);
                if self
                    .current_slot
                    .saturating_sub(request.submitted_slot)
                    .saturating_mul(100)
                    > bucket.target_ms
                {
                    bucket.missed_count = bucket.missed_count.saturating_add(1);
                    self.counters.preconfirmation_sla_misses =
                        self.counters.preconfirmation_sla_misses.saturating_add(1);
                }
            } else {
                bucket.pending_weight = bucket.pending_weight.saturating_add(weight);
                bucket.job_ids.insert(request.job_id.clone());
            }
        }
    }

    fn record_cache_hints(&mut self, request: &ProofJobRequest) {
        if !self.config.enable_hot_contract_cache {
            return;
        }
        let mut contracts = BTreeSet::new();
        if request.proof_kind.prefers_hot_contract_cache() && !request.contract_id.is_empty() {
            contracts.insert(request.contract_id.clone());
        }
        for contract_id in &request.cache_hint_contracts {
            if !contract_id.is_empty() {
                contracts.insert(contract_id.clone());
            }
        }
        for contract_id in contracts {
            if self.hot_contract_cache_hints.len() >= MAX_CONTRACT_HINTS
                && !self.hot_contract_cache_hints.contains_key(&contract_id)
            {
                continue;
            }
            let hint_root = deterministic_root(
                "hot_contract_cache_hint",
                &json!({
                    "contract_id": contract_id,
                    "job_id": request.job_id,
                    "slot": self.current_slot,
                    "proof_kind": request.proof_kind.as_str(),
                }),
            );
            {
                let entry = self
                    .hot_contract_cache_hints
                    .entry(contract_id.clone())
                    .or_insert(HotContractCacheHintRecord {
                        contract_id: contract_id.clone(),
                        hint_root: hint_root.clone(),
                        access_weight: 0,
                        last_slot: self.current_slot,
                        ttl_slots: self.config.hot_cache_hint_ttl_slots,
                        preferred_gpu_class: request.required_gpu_class,
                        disabled: false,
                    });
                if entry.active_at(self.current_slot) {
                    self.counters.cache_hits = self.counters.cache_hits.saturating_add(1);
                } else {
                    self.counters.cache_misses = self.counters.cache_misses.saturating_add(1);
                }
                entry.hint_root = hint_root;
                entry.access_weight = entry
                    .access_weight
                    .saturating_add(request.normalized_weight());
                entry.last_slot = self.current_slot;
                entry.ttl_slots = self.config.hot_cache_hint_ttl_slots;
                entry.preferred_gpu_class =
                    stronger_gpu_class(entry.preferred_gpu_class, request.required_gpu_class);
            }
            self.record_event(
                EventKind::CacheHintRecorded,
                contract_id,
                "hot contract cache hint recorded",
            );
        }
    }

    fn refresh_backpressure(&mut self, reason: String) {
        let queue_depth = self.total_queue_depth();
        let queue_weight = self.total_queue_weight();
        let gpu_capacity_weight = self.total_gpu_capacity_weight();
        let memory_pressure_bps = if self.config.gpu_memory_limit_bytes == 0 {
            MAX_BPS
        } else {
            self.total_witness_bytes()
                .saturating_mul(MAX_BPS)
                .checked_div(self.config.gpu_memory_limit_bytes)
                .unwrap_or(0)
                .min(MAX_BPS)
        };
        let next_mode = if self.safe_mode_active {
            BackpressureMode::SafeMode
        } else if queue_depth >= self.config.max_queue_depth {
            BackpressureMode::CriticalOnly
        } else if queue_weight >= self.config.max_batch_weight.saturating_mul(12) {
            BackpressureMode::PackOnly
        } else if memory_pressure_bps >= 8_000 {
            BackpressureMode::LowFeeThrottle
        } else if gpu_capacity_weight < queue_weight / 2 && queue_weight > 0 {
            BackpressureMode::PreferFastFee
        } else {
            BackpressureMode::Open
        };
        if next_mode != self.backpressure.mode {
            self.counters.backpressure_transitions =
                self.counters.backpressure_transitions.saturating_add(1);
            self.record_event(
                EventKind::BackpressureChanged,
                next_mode.as_str().to_string(),
                reason.as_str(),
            );
        }
        self.backpressure.mode = next_mode;
        self.backpressure.reason = reason;
        self.backpressure.queue_depth = queue_depth;
        self.backpressure.queue_weight = queue_weight;
        self.backpressure.gpu_capacity_weight = gpu_capacity_weight;
        self.backpressure.memory_pressure_bps = memory_pressure_bps;
        self.backpressure.low_fee_paused = matches!(
            next_mode,
            BackpressureMode::LowFeeThrottle
                | BackpressureMode::CriticalOnly
                | BackpressureMode::SafeMode
        );
        self.backpressure.changed_slot = self.current_slot;
    }

    fn total_queue_depth(&self) -> u64 {
        self.queues.values().map(QueueRecord::depth).sum()
    }

    fn total_queue_weight(&self) -> u64 {
        self.queues.values().map(|queue| queue.queued_weight).sum()
    }

    fn total_gpu_capacity_weight(&self) -> u64 {
        self.gpu_pools
            .values()
            .map(GpuPoolRecord::capacity_weight)
            .sum()
    }

    fn total_witness_bytes(&self) -> u64 {
        self.jobs
            .values()
            .filter(|job| job.active())
            .map(|job| job.request.witness_bytes)
            .sum()
    }

    fn record_event(&mut self, kind: EventKind, subject_id: String, detail: &str) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = format!(
            "event-{}-{}",
            self.current_slot,
            self.events.len().saturating_add(1)
        );
        let record_root = deterministic_root(
            "event_subject",
            &json!({
                "kind": kind.as_str(),
                "subject_id": subject_id,
                "detail": detail,
                "slot": self.current_slot,
            }),
        );
        self.events.insert(
            event_id.clone(),
            EventRecord {
                event_id,
                kind,
                subject_id,
                slot: self.current_slot,
                record_root,
                detail: String::from(detail),
            },
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    State::demo().public_record()
}

pub fn state_root() -> String {
    let mut state = State::demo();
    state.refresh_roots();
    state.state_root()
}

pub fn config_id(record: &Value) -> String {
    deterministic_root("config_id", record)
}

pub fn queue_id_for_lane(lane: QueueLane) -> String {
    format!("queue-{}", lane.as_str())
}

pub fn deterministic_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn root_for_records(domain: &str, records: Vec<Value>) -> String {
    let leaves: Vec<Value> = records
        .iter()
        .map(|record| Value::String(deterministic_root(domain, record)))
        .collect();
    merkle_root(domain, &leaves)
}

pub fn gpu_class_matches(pool: GpuClass, required: GpuClass) -> bool {
    matches!(required, GpuClass::Any)
        || pool == required
        || matches!(
            (pool, required),
            (GpuClass::ConfidentialCompute, GpuClass::DataCenter)
                | (GpuClass::ConfidentialCompute, GpuClass::Consumer)
                | (GpuClass::ConfidentialCompute, GpuClass::Any)
                | (GpuClass::HighMemory, GpuClass::DataCenter)
                | (GpuClass::HighMemory, GpuClass::Consumer)
                | (GpuClass::DataCenter, GpuClass::Consumer)
        )
}

pub fn stronger_gpu_class(left: GpuClass, right: GpuClass) -> GpuClass {
    let left_rank = gpu_class_rank(left);
    let right_rank = gpu_class_rank(right);
    if right_rank > left_rank {
        right
    } else {
        left
    }
}

pub fn gpu_class_rank(class: GpuClass) -> u64 {
    match class {
        GpuClass::Any => 0,
        GpuClass::Consumer => 1,
        GpuClass::DataCenter => 2,
        GpuClass::HighMemory => 3,
        GpuClass::ConfidentialCompute => 4,
    }
}

pub fn compression_ratio_bps(witness_bytes: u64, pack_bytes: u64) -> u64 {
    if witness_bytes == 0 {
        MAX_BPS
    } else {
        pack_bytes
            .min(witness_bytes)
            .saturating_mul(MAX_BPS)
            .checked_div(witness_bytes)
            .unwrap_or(MAX_BPS)
    }
}

pub fn event_for_decision(decision: AdmissionDecision) -> EventKind {
    match decision {
        AdmissionDecision::Admit | AdmissionDecision::AdmitLowFee => EventKind::JobAdmitted,
        AdmissionDecision::Defer => EventKind::JobDeferred,
        AdmissionDecision::Reject | AdmissionDecision::Shed => EventKind::JobRejected,
    }
}

pub fn admission_reason(
    decision: AdmissionDecision,
    mode: BackpressureMode,
    lane: QueueLane,
) -> String {
    format!(
        "{} under {} backpressure for {}",
        decision.as_str(),
        mode.as_str(),
        lane.as_str()
    )
}

pub fn parse_u64_or_zero(value: &str) -> u64 {
    let mut parsed = 0_u64;
    for byte in value.bytes() {
        if byte < b'0' || byte > b'9' {
            return 0;
        }
        parsed = parsed
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'));
    }
    parsed
}
