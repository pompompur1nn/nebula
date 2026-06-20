use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ParallelContractExecutionSchedulerRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-parallel-contract-execution-scheduler-runtime-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PQ_WORKER_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-parallel-contract-worker-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_TASK_SCHEME: &str =
    "private-l2-parallel-contract-task-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEPENDENCY_SCHEME: &str =
    "private-l2-contract-dependency-edge-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_ATTESTATION_SCHEME: &str =
    "pq-parallel-contract-worker-attestation-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_RESERVATION_SCHEME: &str =
    "low-fee-parallel-execution-lane-reservation-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_BATCH_SCHEME: &str =
    "parallel-private-contract-execution-batch-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_RECEIPT_SCHEME: &str =
    "parallel-private-contract-settlement-receipt-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_REBATE_SCHEME: &str =
    "parallel-private-contract-low-fee-rebate-root-v1";
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEVNET_HEIGHT: u64 = 620_000;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_TASKS: usize =
    4_194_304;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_DEPENDENCIES: usize =
    8_388_608;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    2_097_152;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_BATCHES: usize =
    524_288;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_RECEIPTS: usize =
    1_048_576;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_BATCH_TASKS: usize =
    16_384;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_TARGET_BATCH_MS: u64 =
    450;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_TASK_TTL_BLOCKS: u64 =
    18;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 =
    10;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 512;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 16_384;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    18;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_WORKER_FEE_BPS: u64 =
    20;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 =
    7;
pub const PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractTaskKind {
    PrivateCall,
    ConfidentialTransfer,
    TokenMint,
    TokenBurn,
    DefiSwap,
    LendingUpdate,
    MarginUpdate,
    GovernanceAction,
    OracleCallback,
    MoneroBridgeSettlement,
}

impl ContractTaskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::DefiSwap => "defi_swap",
            Self::LendingUpdate => "lending_update",
            Self::MarginUpdate => "margin_update",
            Self::GovernanceAction => "governance_action",
            Self::OracleCallback => "oracle_callback",
            Self::MoneroBridgeSettlement => "monero_bridge_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLane {
    UltraFast,
    LowFeeBatch,
    DefiNetting,
    TokenRuntime,
    Governance,
    BridgeCritical,
    BackgroundCompression,
}

impl ExecutionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UltraFast => "ultra_fast",
            Self::LowFeeBatch => "low_fee_batch",
            Self::DefiNetting => "defi_netting",
            Self::TokenRuntime => "token_runtime",
            Self::Governance => "governance",
            Self::BridgeCritical => "bridge_critical",
            Self::BackgroundCompression => "background_compression",
        }
    }

    pub fn latency_sensitive(self) -> bool {
        matches!(
            self,
            Self::UltraFast | Self::DefiNetting | Self::BridgeCritical
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulingStrategy {
    LowestFee,
    FastestFinality,
    MaxParallelism,
    PreservePrivacySet,
    BridgeSafetyFirst,
}

impl SchedulingStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowestFee => "lowest_fee",
            Self::FastestFinality => "fastest_finality",
            Self::MaxParallelism => "max_parallelism",
            Self::PreservePrivacySet => "preserve_privacy_set",
            Self::BridgeSafetyFirst => "bridge_safety_first",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CachePolicy {
    None,
    WitnessOnly,
    StateReadSet,
    FullPrivateTrace,
    ReusableProofHints,
}

impl CachePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WitnessOnly => "witness_only",
            Self::StateReadSet => "state_read_set",
            Self::FullPrivateTrace => "full_private_trace",
            Self::ReusableProofHints => "reusable_proof_hints",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    DependencyLocked,
    Ready,
    Reserved,
    Batched,
    Executed,
    Settled,
    Expired,
    Rejected,
}

impl TaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::DependencyLocked => "dependency_locked",
            Self::Ready => "ready",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStatus {
    Open,
    Satisfied,
    Conflict,
    BypassedByProof,
    Expired,
}

impl DependencyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Satisfied => "satisfied",
            Self::Conflict => "conflict",
            Self::BypassedByProof => "bypassed_by_proof",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerAttestationStatus {
    Recorded,
    Verified,
    Slashed,
    Revoked,
}

impl WorkerAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Verified => "verified",
            Self::Slashed => "slashed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Rebated,
    Expired,
    Cancelled,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    WorkerAssigned,
    Executed,
    ProofQueued,
    Settled,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::WorkerAssigned => "worker_assigned",
            Self::Executed => "executed",
            Self::ProofQueued => "proof_queued",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    Rebated,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rebated => "rebated",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub scheduler_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub worker_auth_suite: String,
    pub hash_suite: String,
    pub max_tasks: usize,
    pub max_dependencies: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_batch_tasks: usize,
    pub target_batch_ms: u64,
    pub task_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_worker_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub current_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            chain_id: CHAIN_ID.to_string(),
            scheduler_id: "devnet-parallel-contract-execution-scheduler".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            worker_auth_suite:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PQ_WORKER_AUTH_SUITE
                    .to_string(),
            hash_suite: PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_HASH_SUITE
                .to_string(),
            max_tasks: PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_TASKS,
            max_dependencies:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_DEPENDENCIES,
            max_attestations:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_tasks:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_BATCH_TASKS,
            target_batch_ms:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_TARGET_BATCH_MS,
            task_ttl_blocks:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_TASK_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_worker_fee_bps:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MAX_WORKER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            current_height: PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require(
            self.protocol_version
                == PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            "unsupported parallel contract execution scheduler protocol version",
        )?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("scheduler_id", &self.scheduler_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("worker_auth_suite", &self.worker_auth_suite)?;
        require(
            self.min_pq_security_bits
                >= PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "parallel contract execution scheduler requires at least 256-bit PQ security",
        )?;
        require(self.max_tasks > 0, "max_tasks must be positive")?;
        require(
            self.max_dependencies >= self.max_tasks,
            "max_dependencies must cover at least max_tasks",
        )?;
        require(
            self.max_attestations > 0,
            "max_attestations must be positive",
        )?;
        require(
            self.max_reservations > 0,
            "max_reservations must be positive",
        )?;
        require(self.max_batches > 0, "max_batches must be positive")?;
        require(self.max_receipts > 0, "max_receipts must be positive")?;
        require(self.max_batch_tasks > 0, "max_batch_tasks must be positive")?;
        require(self.target_batch_ms > 0, "target_batch_ms must be positive")?;
        require(self.task_ttl_blocks > 0, "task_ttl_blocks must be positive")?;
        require(
            self.batch_ttl_blocks > 0,
            "batch_ttl_blocks must be positive",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "min_privacy_set_size must be positive",
        )?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must cover the per-task minimum privacy set",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("max_worker_fee_bps", self.max_worker_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "target rebate cannot exceed max user fee",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "scheduler_id": self.scheduler_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "worker_auth_suite": self.worker_auth_suite,
            "hash_suite": self.hash_suite,
            "max_tasks": self.max_tasks,
            "max_dependencies": self.max_dependencies,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_batch_tasks": self.max_batch_tasks,
            "target_batch_ms": self.target_batch_ms,
            "task_ttl_blocks": self.task_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_worker_fee_bps": self.max_worker_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "current_height": self.current_height,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub next_task: u64,
    pub next_dependency: u64,
    pub next_attestation: u64,
    pub next_reservation: u64,
    pub next_batch: u64,
    pub next_receipt: u64,
    pub next_rebate: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_task": self.next_task,
            "next_dependency": self.next_dependency,
            "next_attestation": self.next_attestation,
            "next_reservation": self.next_reservation,
            "next_batch": self.next_batch,
            "next_receipt": self.next_receipt,
            "next_rebate": self.next_rebate,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitContractTaskRequest {
    pub task_kind: ContractTaskKind,
    pub lane: ExecutionLane,
    pub strategy: SchedulingStrategy,
    pub caller_commitment: String,
    pub contract_address_commitment: String,
    pub function_selector_commitment: String,
    pub encrypted_calldata_root: String,
    pub private_witness_root: String,
    pub state_read_set_root: String,
    pub state_write_set_commitment: String,
    pub nullifier_root: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub cache_policy: CachePolicy,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl SubmitContractTaskRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require_non_empty("caller_commitment", &self.caller_commitment)?;
        require_non_empty(
            "contract_address_commitment",
            &self.contract_address_commitment,
        )?;
        require_non_empty(
            "function_selector_commitment",
            &self.function_selector_commitment,
        )?;
        require_root("encrypted_calldata_root", &self.encrypted_calldata_root)?;
        require_root("private_witness_root", &self.private_witness_root)?;
        require_root("state_read_set_root", &self.state_read_set_root)?;
        require_root(
            "state_write_set_commitment",
            &self.state_write_set_commitment,
        )?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "contract task fee exceeds low-fee cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "contract task privacy set is too small",
        )?;
        require_root("pq_authorization_root", &self.pq_authorization_root)?;
        require(
            self.expires_at_height > config.current_height,
            "contract task must expire in the future",
        )?;
        require_root("metadata_root", &self.metadata_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "task_kind": self.task_kind.as_str(),
            "lane": self.lane.as_str(),
            "strategy": self.strategy.as_str(),
            "caller_commitment": self.caller_commitment,
            "contract_address_commitment": self.contract_address_commitment,
            "function_selector_commitment": self.function_selector_commitment,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "private_witness_root": self.private_witness_root,
            "state_read_set_root": self.state_read_set_root,
            "state_write_set_commitment": self.state_write_set_commitment,
            "nullifier_root": self.nullifier_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "cache_policy": self.cache_policy.as_str(),
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkTaskDependencyRequest {
    pub parent_task_id: String,
    pub child_task_id: String,
    pub dependency_kind: String,
    pub read_write_conflict_root: String,
    pub witness_ordering_root: String,
    pub privacy_guard_root: String,
    pub proof_override_root: Option<String>,
    pub expires_at_height: u64,
}

impl LinkTaskDependencyRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require_non_empty("parent_task_id", &self.parent_task_id)?;
        require_non_empty("child_task_id", &self.child_task_id)?;
        require(
            self.parent_task_id != self.child_task_id,
            "task dependency cannot point to itself",
        )?;
        require_non_empty("dependency_kind", &self.dependency_kind)?;
        require_root("read_write_conflict_root", &self.read_write_conflict_root)?;
        require_root("witness_ordering_root", &self.witness_ordering_root)?;
        require_root("privacy_guard_root", &self.privacy_guard_root)?;
        if let Some(root) = &self.proof_override_root {
            require_root("proof_override_root", root)?;
        }
        require(
            self.expires_at_height > config.current_height,
            "dependency must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "parent_task_id": self.parent_task_id,
            "child_task_id": self.child_task_id,
            "dependency_kind": self.dependency_kind,
            "read_write_conflict_root": self.read_write_conflict_root,
            "witness_ordering_root": self.witness_ordering_root,
            "privacy_guard_root": self.privacy_guard_root,
            "proof_override_root": self.proof_override_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordWorkerAttestationRequest {
    pub worker_committee_id: String,
    pub worker_key_root: String,
    pub supported_lane: ExecutionLane,
    pub task_root: String,
    pub dependency_root: String,
    pub witness_cache_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub max_worker_fee_bps: u64,
    pub available_parallelism: u64,
    pub expires_at_height: u64,
}

impl RecordWorkerAttestationRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require_non_empty("worker_committee_id", &self.worker_committee_id)?;
        require_root("worker_key_root", &self.worker_key_root)?;
        require_root("task_root", &self.task_root)?;
        require_root("dependency_root", &self.dependency_root)?;
        require_root("witness_cache_root", &self.witness_cache_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "worker attestation does not meet PQ security floor",
        )?;
        require_bps("max_worker_fee_bps", self.max_worker_fee_bps)?;
        require(
            self.max_worker_fee_bps <= config.max_worker_fee_bps,
            "worker fee exceeds low-fee cap",
        )?;
        require(
            self.available_parallelism > 0,
            "available_parallelism must be positive",
        )?;
        require(
            self.expires_at_height > config.current_height,
            "worker attestation must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "worker_committee_id": self.worker_committee_id,
            "worker_key_root": self.worker_key_root,
            "supported_lane": self.supported_lane.as_str(),
            "task_root": self.task_root,
            "dependency_root": self.dependency_root,
            "witness_cache_root": self.witness_cache_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "max_worker_fee_bps": self.max_worker_fee_bps,
            "available_parallelism": self.available_parallelism,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveExecutionLaneRequest {
    pub task_id: String,
    pub worker_attestation_id: String,
    pub lane: ExecutionLane,
    pub reservation_nullifier: String,
    pub fee_sponsor_commitment: String,
    pub reserved_fee_bps: u64,
    pub rebate_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveExecutionLaneRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require_non_empty("task_id", &self.task_id)?;
        require_non_empty("worker_attestation_id", &self.worker_attestation_id)?;
        require_root("reservation_nullifier", &self.reservation_nullifier)?;
        require_non_empty("fee_sponsor_commitment", &self.fee_sponsor_commitment)?;
        require_bps("reserved_fee_bps", self.reserved_fee_bps)?;
        require(
            self.reserved_fee_bps <= config.max_user_fee_bps,
            "reserved execution fee exceeds low-fee cap",
        )?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= self.reserved_fee_bps,
            "rebate cannot exceed reserved fee",
        )?;
        require(
            self.reserved_at_height >= config.current_height,
            "reservation height cannot be behind current scheduler height",
        )?;
        require(
            self.expires_at_height > self.reserved_at_height,
            "reservation must expire after it is created",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "task_id": self.task_id,
            "worker_attestation_id": self.worker_attestation_id,
            "lane": self.lane.as_str(),
            "reservation_nullifier": self.reservation_nullifier,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_bps": self.rebate_bps,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildExecutionBatchRequest {
    pub lane: ExecutionLane,
    pub strategy: SchedulingStrategy,
    pub task_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub worker_attestation_ids: Vec<String>,
    pub dependency_root: String,
    pub read_set_root: String,
    pub write_set_commitment: String,
    pub nullifier_root: String,
    pub witness_bundle_root: String,
    pub expected_state_delta_root: String,
    pub batch_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub target_batch_ms: u64,
    pub expires_at_height: u64,
}

impl BuildExecutionBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require(!self.task_ids.is_empty(), "batch must include tasks")?;
        require(
            self.task_ids.len() <= config.max_batch_tasks,
            "batch includes too many tasks",
        )?;
        require_unique("task_ids", &self.task_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_unique("worker_attestation_ids", &self.worker_attestation_ids)?;
        require_root("dependency_root", &self.dependency_root)?;
        require_root("read_set_root", &self.read_set_root)?;
        require_root("write_set_commitment", &self.write_set_commitment)?;
        require_root("nullifier_root", &self.nullifier_root)?;
        require_root("witness_bundle_root", &self.witness_bundle_root)?;
        require_root("expected_state_delta_root", &self.expected_state_delta_root)?;
        require(
            self.batch_privacy_set_size >= config.batch_privacy_set_size,
            "batch privacy set is too small",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require(
            self.max_user_fee_bps <= config.max_user_fee_bps,
            "batch fee exceeds low-fee cap",
        )?;
        require(self.target_batch_ms > 0, "target_batch_ms must be positive")?;
        require(
            self.target_batch_ms <= config.target_batch_ms.saturating_mul(2),
            "batch latency target is too slow for fast runtime",
        )?;
        require(
            self.expires_at_height > config.current_height,
            "batch must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "strategy": self.strategy.as_str(),
            "task_ids": self.task_ids,
            "reservation_ids": self.reservation_ids,
            "worker_attestation_ids": self.worker_attestation_ids,
            "dependency_root": self.dependency_root,
            "read_set_root": self.read_set_root,
            "write_set_commitment": self.write_set_commitment,
            "nullifier_root": self.nullifier_root,
            "witness_bundle_root": self.witness_bundle_root,
            "expected_state_delta_root": self.expected_state_delta_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_batch_ms": self.target_batch_ms,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleExecutionBatchRequest {
    pub batch_id: String,
    pub execution_trace_root: String,
    pub new_private_state_root: String,
    pub emitted_event_root: String,
    pub recursive_proof_root: String,
    pub pq_worker_signature_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
    pub proof_latency_ms: u64,
}

impl SettleExecutionBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("execution_trace_root", &self.execution_trace_root)?;
        require_root("new_private_state_root", &self.new_private_state_root)?;
        require_root("emitted_event_root", &self.emitted_event_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_root("pq_worker_signature_root", &self.pq_worker_signature_root)?;
        require_bps("settled_fee_bps", self.settled_fee_bps)?;
        require(
            self.settled_fee_bps <= config.max_user_fee_bps,
            "settled fee exceeds low-fee cap",
        )?;
        require(
            self.settled_at_height >= config.current_height,
            "settlement height cannot be behind current scheduler height",
        )?;
        require(
            self.proof_latency_ms > 0,
            "proof_latency_ms must be positive",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "execution_trace_root": self.execution_trace_root,
            "new_private_state_root": self.new_private_state_root,
            "emitted_event_root": self.emitted_event_root,
            "recursive_proof_root": self.recursive_proof_root,
            "pq_worker_signature_root": self.pq_worker_signature_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
            "proof_latency_ms": self.proof_latency_ms,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishExecutionRebateRequest {
    pub receipt_id: String,
    pub reservation_ids: Vec<String>,
    pub rebate_pool_root: String,
    pub rebate_nullifier_root: String,
    pub rebate_bps: u64,
    pub published_at_height: u64,
}

impl PublishExecutionRebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require(
            !self.reservation_ids.is_empty(),
            "rebate needs reservations",
        )?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("rebate_pool_root", &self.rebate_pool_root)?;
        require_root("rebate_nullifier_root", &self.rebate_nullifier_root)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= config.max_user_fee_bps,
            "rebate exceeds fee cap",
        )?;
        require(
            self.published_at_height >= config.current_height,
            "rebate height cannot be behind current scheduler height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_ids": self.reservation_ids,
            "rebate_pool_root": self.rebate_pool_root,
            "rebate_nullifier_root": self.rebate_nullifier_root,
            "rebate_bps": self.rebate_bps,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractTaskRecord {
    pub task_id: String,
    pub request: SubmitContractTaskRequest,
    pub status: TaskStatus,
    pub accepted_at_height: u64,
    pub task_root: String,
}

impl ContractTaskRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "task_id": self.task_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "accepted_at_height": self.accepted_at_height,
            "task_root": self.task_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDependencyRecord {
    pub dependency_id: String,
    pub request: LinkTaskDependencyRequest,
    pub status: DependencyStatus,
    pub registered_at_height: u64,
    pub dependency_root: String,
}

impl TaskDependencyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "dependency_id": self.dependency_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
            "dependency_root": self.dependency_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerAttestationRecord {
    pub attestation_id: String,
    pub request: RecordWorkerAttestationRequest,
    pub status: WorkerAttestationStatus,
    pub recorded_at_height: u64,
    pub attestation_root: String,
}

impl WorkerAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "recorded_at_height": self.recorded_at_height,
            "attestation_root": self.attestation_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionLaneReservationRecord {
    pub reservation_id: String,
    pub request: ReserveExecutionLaneRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
}

impl ExecutionLaneReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelExecutionBatchRecord {
    pub batch_id: String,
    pub request: BuildExecutionBatchRequest,
    pub status: BatchStatus,
    pub built_at_height: u64,
    pub batch_root: String,
    pub ready_task_count: usize,
    pub latency_sensitive: bool,
}

impl ParallelExecutionBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "batch_root": self.batch_root,
            "ready_task_count": self.ready_task_count,
            "latency_sensitive": self.latency_sensitive,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionSettlementReceipt {
    pub receipt_id: String,
    pub request: SettleExecutionBatchRequest,
    pub status: ReceiptStatus,
    pub receipt_root: String,
    pub settled_task_ids: Vec<String>,
    pub settled_reservation_ids: Vec<String>,
}

impl ExecutionSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "receipt_root": self.receipt_root,
            "settled_task_ids": self.settled_task_ids,
            "settled_reservation_ids": self.settled_reservation_ids,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionRebateReceipt {
    pub rebate_id: String,
    pub request: PublishExecutionRebateRequest,
    pub status: ReceiptStatus,
    pub rebate_root: String,
}

impl ExecutionRebateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub task_root: String,
    pub dependency_root: String,
    pub worker_attestation_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "task_root": self.task_root,
            "dependency_root": self.dependency_root,
            "worker_attestation_root": self.worker_attestation_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub tasks: BTreeMap<String, ContractTaskRecord>,
    pub dependencies: BTreeMap<String, TaskDependencyRecord>,
    pub worker_attestations: BTreeMap<String, WorkerAttestationRecord>,
    pub reservations: BTreeMap<String, ExecutionLaneReservationRecord>,
    pub batches: BTreeMap<String, ParallelExecutionBatchRecord>,
    pub receipts: BTreeMap<String, ExecutionSettlementReceipt>,
    pub rebates: BTreeMap<String, ExecutionRebateReceipt>,
}

impl State {
    pub fn devnet() -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<Self> {
        Self::with_config(Config::devnet())
    }

    pub fn with_config(
        config: Config,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            tasks: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            worker_attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
        })
    }

    pub fn submit_contract_task(
        &mut self,
        request: SubmitContractTaskRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<ContractTaskRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        require(
            self.tasks.len() < self.config.max_tasks,
            "parallel contract task capacity exhausted",
        )?;

        let sequence = self.counters.next_task;
        self.counters.next_task = self.counters.next_task.saturating_add(1);
        let task_id = contract_task_id(&request, sequence);
        require(
            !self.tasks.contains_key(&task_id),
            "duplicate parallel contract task",
        )?;
        let task_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_TASK_SCHEME,
            &json!({
                "task_id": task_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let status = if request.lane.latency_sensitive() {
            TaskStatus::Ready
        } else {
            TaskStatus::Queued
        };
        let record = ContractTaskRecord {
            task_id: task_id.clone(),
            request,
            status,
            accepted_at_height: self.config.current_height,
            task_root,
        };
        self.tasks.insert(task_id, record.clone());
        Ok(record)
    }

    pub fn link_task_dependency(
        &mut self,
        request: LinkTaskDependencyRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<TaskDependencyRecord> {
        request.validate(&self.config)?;
        require(
            self.dependencies.len() < self.config.max_dependencies,
            "parallel contract dependency capacity exhausted",
        )?;
        require(
            self.tasks.contains_key(&request.parent_task_id),
            "parent task is unknown",
        )?;
        require(
            self.tasks.contains_key(&request.child_task_id),
            "child task is unknown",
        )?;

        let sequence = self.counters.next_dependency;
        self.counters.next_dependency = self.counters.next_dependency.saturating_add(1);
        let dependency_id = task_dependency_id(&request, sequence);
        require(
            !self.dependencies.contains_key(&dependency_id),
            "duplicate contract task dependency",
        )?;
        let dependency_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEPENDENCY_SCHEME,
            &json!({
                "dependency_id": dependency_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let record = TaskDependencyRecord {
            dependency_id: dependency_id.clone(),
            request: request.clone(),
            status: DependencyStatus::Open,
            registered_at_height: self.config.current_height,
            dependency_root,
        };
        if let Some(child) = self.tasks.get_mut(&request.child_task_id) {
            child.status = TaskStatus::DependencyLocked;
        }
        self.dependencies.insert(dependency_id, record.clone());
        Ok(record)
    }

    pub fn record_worker_attestation(
        &mut self,
        request: RecordWorkerAttestationRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<WorkerAttestationRecord> {
        request.validate(&self.config)?;
        require(
            self.worker_attestations.len() < self.config.max_attestations,
            "parallel contract worker attestation capacity exhausted",
        )?;

        let sequence = self.counters.next_attestation;
        self.counters.next_attestation = self.counters.next_attestation.saturating_add(1);
        let attestation_id = worker_attestation_id(&request, sequence);
        require(
            !self.worker_attestations.contains_key(&attestation_id),
            "duplicate worker attestation",
        )?;
        let attestation_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_ATTESTATION_SCHEME,
            &json!({
                "attestation_id": attestation_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        let record = WorkerAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            status: WorkerAttestationStatus::Verified,
            recorded_at_height: self.config.current_height,
            attestation_root,
        };
        self.worker_attestations
            .insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_execution_lane(
        &mut self,
        request: ReserveExecutionLaneRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<ExecutionLaneReservationRecord>
    {
        request.validate(&self.config)?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "parallel contract reservation capacity exhausted",
        )?;
        let task = self
            .tasks
            .get(&request.task_id)
            .ok_or_else(|| "reservation references unknown task".to_string())?;
        require(
            task.request.lane == request.lane,
            "reservation lane does not match task lane",
        )?;
        let attestation = self
            .worker_attestations
            .get(&request.worker_attestation_id)
            .ok_or_else(|| "reservation references unknown worker attestation".to_string())?;
        require(
            attestation.request.supported_lane == request.lane,
            "worker attestation does not support reserved lane",
        )?;

        let sequence = self.counters.next_reservation;
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        let reservation_id = execution_lane_reservation_id(&request, sequence);
        require(
            !self.reservations.contains_key(&reservation_id),
            "duplicate execution lane reservation",
        )?;
        let reservation_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_RESERVATION_SCHEME,
            &json!({
                "reservation_id": reservation_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        if let Some(task) = self.tasks.get_mut(&request.task_id) {
            task.status = TaskStatus::Reserved;
        }
        let record = ExecutionLaneReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
            reservation_root,
        };
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_execution_batch(
        &mut self,
        request: BuildExecutionBatchRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<ParallelExecutionBatchRecord>
    {
        request.validate(&self.config)?;
        require(
            self.batches.len() < self.config.max_batches,
            "parallel execution batch capacity exhausted",
        )?;
        for task_id in &request.task_ids {
            let task = self
                .tasks
                .get(task_id)
                .ok_or_else(|| format!("batch references unknown task: {task_id}"))?;
            require(
                task.request.lane == request.lane,
                "batch lane mismatch for task",
            )?;
            require(
                matches!(
                    task.status,
                    TaskStatus::Ready | TaskStatus::Queued | TaskStatus::Reserved
                ),
                "batch task is not schedulable",
            )?;
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .reservations
                .get(reservation_id)
                .ok_or_else(|| format!("batch references unknown reservation: {reservation_id}"))?;
            require(
                reservation.request.lane == request.lane,
                "batch lane mismatch for reservation",
            )?;
        }
        for attestation_id in &request.worker_attestation_ids {
            let attestation = self
                .worker_attestations
                .get(attestation_id)
                .ok_or_else(|| {
                    format!("batch references unknown worker attestation: {attestation_id}")
                })?;
            require(
                attestation.request.supported_lane == request.lane,
                "batch lane mismatch for worker attestation",
            )?;
        }

        let sequence = self.counters.next_batch;
        self.counters.next_batch = self.counters.next_batch.saturating_add(1);
        let batch_id = parallel_execution_batch_id(&request, sequence);
        require(
            !self.batches.contains_key(&batch_id),
            "duplicate parallel execution batch",
        )?;
        let batch_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_BATCH_SCHEME,
            &json!({
                "batch_id": batch_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        for task_id in &request.task_ids {
            if let Some(task) = self.tasks.get_mut(task_id) {
                task.status = TaskStatus::Batched;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Matched;
            }
        }
        let record = ParallelExecutionBatchRecord {
            batch_id: batch_id.clone(),
            ready_task_count: request.task_ids.len(),
            latency_sensitive: request.lane.latency_sensitive(),
            request,
            status: BatchStatus::Built,
            built_at_height: self.config.current_height,
            batch_root,
        };
        self.batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn settle_execution_batch(
        &mut self,
        request: SettleExecutionBatchRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<ExecutionSettlementReceipt> {
        request.validate(&self.config)?;
        require(
            self.receipts.len() < self.config.max_receipts,
            "parallel execution receipt capacity exhausted",
        )?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "settlement references unknown execution batch".to_string())?;
        require(
            matches!(
                batch.status,
                BatchStatus::Built | BatchStatus::WorkerAssigned | BatchStatus::Executed
            ),
            "execution batch is not settlement ready",
        )?;

        let settled_task_ids = batch.request.task_ids.clone();
        let settled_reservation_ids = batch.request.reservation_ids.clone();
        let sequence = self.counters.next_receipt;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        let receipt_id = execution_settlement_receipt_id(&request, sequence);
        require(
            !self.receipts.contains_key(&receipt_id),
            "duplicate execution settlement receipt",
        )?;
        let receipt_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_RECEIPT_SCHEME,
            &json!({
                "receipt_id": receipt_id,
                "sequence": sequence,
                "request": request.public_record(),
                "settled_task_ids": settled_task_ids,
                "settled_reservation_ids": settled_reservation_ids,
            }),
        );
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Settled;
        }
        for task_id in &settled_task_ids {
            if let Some(task) = self.tasks.get_mut(task_id) {
                task.status = TaskStatus::Settled;
            }
        }
        for reservation_id in &settled_reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let record = ExecutionSettlementReceipt {
            receipt_id: receipt_id.clone(),
            request,
            status: ReceiptStatus::Accepted,
            receipt_root,
            settled_task_ids,
            settled_reservation_ids,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_execution_rebate(
        &mut self,
        request: PublishExecutionRebateRequest,
    ) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<ExecutionRebateReceipt> {
        request.validate(&self.config)?;
        require(
            self.rebates.len() < self.config.max_receipts,
            "parallel execution rebate capacity exhausted",
        )?;
        require(
            self.receipts.contains_key(&request.receipt_id),
            "rebate references unknown receipt",
        )?;
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "rebate references unknown reservation",
            )?;
        }

        let sequence = self.counters.next_rebate;
        self.counters.next_rebate = self.counters.next_rebate.saturating_add(1);
        let rebate_id = execution_rebate_id(&request, sequence);
        require(
            !self.rebates.contains_key(&rebate_id),
            "duplicate execution rebate",
        )?;
        let rebate_root = payload_root(
            PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_REBATE_SCHEME,
            &json!({
                "rebate_id": rebate_id,
                "sequence": sequence,
                "request": request.public_record(),
            }),
        );
        if let Some(receipt) = self.receipts.get_mut(&request.receipt_id) {
            receipt.status = ReceiptStatus::Rebated;
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Rebated;
            }
        }
        let record = ExecutionRebateReceipt {
            rebate_id: rebate_id.clone(),
            request,
            status: ReceiptStatus::Accepted,
            rebate_root,
        };
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let task_records = self
            .tasks
            .values()
            .map(ContractTaskRecord::public_record)
            .collect::<Vec<_>>();
        let dependency_records = self
            .dependencies
            .values()
            .map(TaskDependencyRecord::public_record)
            .collect::<Vec<_>>();
        let worker_attestation_records = self
            .worker_attestations
            .values()
            .map(WorkerAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .reservations
            .values()
            .map(ExecutionLaneReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(ParallelExecutionBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(ExecutionSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let rebate_records = self
            .rebates
            .values()
            .map(ExecutionRebateReceipt::public_record)
            .collect::<Vec<_>>();
        Roots {
            task_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_TASK_SCHEME,
                &task_records,
            ),
            dependency_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_DEPENDENCY_SCHEME,
                &dependency_records,
            ),
            worker_attestation_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_ATTESTATION_SCHEME,
                &worker_attestation_records,
            ),
            reservation_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_RESERVATION_SCHEME,
                &reservation_records,
            ),
            batch_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_BATCH_SCHEME,
                &batch_records,
            ),
            receipt_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_RECEIPT_SCHEME,
                &receipt_records,
            ),
            rebate_root: root_from_records(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_REBATE_SCHEME,
                &rebate_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "task_count": self.tasks.len(),
            "dependency_count": self.dependencies.len(),
            "worker_attestation_count": self.worker_attestations.len(),
            "reservation_count": self.reservations.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }
}

pub fn contract_task_id(request: &SubmitContractTaskRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-TASK-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(request.task_kind.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.contract_address_commitment),
            HashPart::Str(&request.encrypted_calldata_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn task_dependency_id(request: &LinkTaskDependencyRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-DEPENDENCY-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(&request.parent_task_id),
            HashPart::Str(&request.child_task_id),
            HashPart::Str(&request.dependency_kind),
            HashPart::Str(&request.read_write_conflict_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn worker_attestation_id(request: &RecordWorkerAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-WORKER-ATTESTATION-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(&request.worker_committee_id),
            HashPart::Str(request.supported_lane.as_str()),
            HashPart::Str(&request.task_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn execution_lane_reservation_id(
    request: &ReserveExecutionLaneRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-EXECUTION-RESERVATION-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(&request.task_id),
            HashPart::Str(&request.worker_attestation_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.reservation_nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn parallel_execution_batch_id(request: &BuildExecutionBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-EXECUTION-BATCH-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(request.strategy.as_str()),
            HashPart::Json(&json!(request.task_ids)),
            HashPart::Str(&request.dependency_root),
            HashPart::Str(&request.expected_state_delta_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn execution_settlement_receipt_id(
    request: &SettleExecutionBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-EXECUTION-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.execution_trace_root),
            HashPart::Str(&request.new_private_state_root),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn execution_rebate_id(request: &PublishExecutionRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-EXECUTION-REBATE-ID",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(&request.receipt_id),
            HashPart::Json(&json!(request.reservation_ids)),
            HashPart::Str(&request.rebate_pool_root),
            HashPart::Str(&request.rebate_nullifier_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-EXECUTION-SCHEDULER-RECORD-ROOT",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PARALLEL-CONTRACT-EXECUTION-SCHEDULER-STATE-ROOT",
        &[
            HashPart::Str(
                PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn root_from_records(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(
    label: &str,
    value: &str,
) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a commitment/root"),
    )
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_PARALLEL_CONTRACT_EXECUTION_SCHEDULER_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_unique(
    label: &str,
    values: &[String],
) -> PrivateL2ParallelContractExecutionSchedulerRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}
