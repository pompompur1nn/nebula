use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkPrivateSmartContractParallelExecutorResult<T> = Result<T, String>;

pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROTOCOL_VERSION: &str =
    "nebula-l2-zk-private-smart-contract-parallel-executor-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_SCHEMA_VERSION: &str =
    "zk-private-smart-contract-parallel-executor-state-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT: u64 = 2_731;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+XChaCha20-Poly1305+sealed-private-contract-calldata-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_WITNESS_SUITE: &str =
    "zk-private-contract-witness-lanes-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROOF_SUITE: &str =
    "recursive-private-contract-execution-proof-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DIFF_SUITE: &str =
    "state-diff-commitment-vector-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_RECEIPT_SUITE: &str =
    "contract-call-receipt-commitment-v1";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_NAMESPACE: &str =
    "nebula.devnet.zk_private_smart_contract_parallel_executor";
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_SHARDS: u64 = 16;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_WITNESS_LANES: u64 = 8;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 3;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_PROOF_QUEUE_DEPTH: u64 = 512;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_MAX_CALLS_PER_SHARD: u64 = 128;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_MAX_DIFF_BYTES: u64 = 4_194_304;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_HEALTH_SLO_MS: u64 = 1_250;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_DEPENDENCY_NODES: usize = 32_768;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_WITNESS_LANES: usize = 512;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_EXECUTION_SHARDS: usize = 1_024;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_PROOF_QUEUE_ITEMS: usize = 65_536;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_RECEIPTS: usize = 65_536;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_SPONSOR_BATCHES: usize = 16_384;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_STATE_DIFFS: usize = 65_536;
pub const ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_HEALTH_SAMPLES: usize = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyNodeKind {
    ContractCall,
    StorageRead,
    StorageWrite,
    NullifierCheck,
    NoteSpend,
    NoteMint,
    OracleRead,
    FeeDebit,
    SponsorCredit,
    ProofArtifact,
}

impl DependencyNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::StorageRead => "storage_read",
            Self::StorageWrite => "storage_write",
            Self::NullifierCheck => "nullifier_check",
            Self::NoteSpend => "note_spend",
            Self::NoteMint => "note_mint",
            Self::OracleRead => "oracle_read",
            Self::FeeDebit => "fee_debit",
            Self::SponsorCredit => "sponsor_credit",
            Self::ProofArtifact => "proof_artifact",
        }
    }

    pub fn writes_state(self) -> bool {
        matches!(
            self,
            Self::StorageWrite
                | Self::NoteSpend
                | Self::NoteMint
                | Self::FeeDebit
                | Self::SponsorCredit
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyVisibility {
    PublicCommitment,
    EncryptedHint,
    SealedPath,
    WitnessOnly,
}

impl DependencyVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicCommitment => "public_commitment",
            Self::EncryptedHint => "encrypted_hint",
            Self::SealedPath => "sealed_path",
            Self::WitnessOnly => "witness_only",
        }
    }

    pub fn private(self) -> bool {
        !matches!(self, Self::PublicCommitment)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessLaneStatus {
    Open,
    Sampling,
    Locked,
    Proving,
    Draining,
    Paused,
}

impl WitnessLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sampling => "sampling",
            Self::Locked => "locked",
            Self::Proving => "proving",
            Self::Draining => "draining",
            Self::Paused => "paused",
        }
    }

    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Open | Self::Sampling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionShardStatus {
    Available,
    Reserved,
    Executing,
    Sealed,
    Committed,
    Retrying,
    Quarantined,
}

impl ExecutionShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Sealed => "sealed",
            Self::Committed => "committed",
            Self::Retrying => "retrying",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        !matches!(self, Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofQueueStatus {
    Queued,
    Assigned,
    Proving,
    Aggregating,
    Ready,
    Submitted,
    Failed,
}

impl ProofQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Assigned => "assigned",
            Self::Proving => "proving",
            Self::Aggregating => "aggregating",
            Self::Ready => "ready",
            Self::Submitted => "submitted",
            Self::Failed => "failed",
        }
    }

    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Assigned | Self::Proving | Self::Aggregating | Self::Ready
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractReceiptStatus {
    Accepted,
    Executed,
    Reverted,
    Proved,
    Settled,
}

impl ContractReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Executed => "executed",
            Self::Reverted => "reverted",
            Self::Proved => "proved",
            Self::Settled => "settled",
        }
    }

    pub fn successful(self) -> bool {
        matches!(self, Self::Executed | Self::Proved | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorBatchStatus {
    Open,
    Reserved,
    Debited,
    Reconciled,
    Refunded,
    Frozen,
}

impl FeeSponsorBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Debited => "debited",
            Self::Reconciled => "reconciled",
            Self::Refunded => "refunded",
            Self::Frozen => "frozen",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Debited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateDiffStatus {
    Proposed,
    Witnessed,
    Proven,
    Applied,
    Superseded,
    Rejected,
}

impl StateDiffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Witnessed => "witnessed",
            Self::Proven => "proven",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub fn final_state(self) -> bool {
        matches!(self, Self::Applied | Self::Superseded | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorHealthLevel {
    Healthy,
    Degraded,
    Backpressured,
    Recovering,
    Halted,
}

impl ExecutorHealthLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Backpressured => "backpressured",
            Self::Recovering => "recovering",
            Self::Halted => "halted",
        }
    }

    pub fn ok(self) -> bool {
        matches!(self, Self::Healthy | Self::Recovering)
    }
}

pub trait ExecutorRecord {
    fn public_record(&self) -> Value;

    fn root(&self, domain: &str) -> String {
        domain_hash(domain, &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub namespace: String,
    pub encryption_suite: String,
    pub witness_suite: String,
    pub proof_suite: String,
    pub state_diff_suite: String,
    pub receipt_suite: String,
    pub execution_shards: u64,
    pub witness_lanes: u64,
    pub batch_window_blocks: u64,
    pub proof_queue_depth: u64,
    pub max_calls_per_shard: u64,
    pub max_diff_bytes: u64,
    pub health_slo_ms: u64,
    pub allow_fee_sponsors: bool,
    pub require_conflict_free_shards: bool,
    pub deterministic_scheduler: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            config_id: executor_id("config", "devnet"),
            protocol_version: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROTOCOL_VERSION
                .to_string(),
            schema_version: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_SCHEMA_VERSION.to_string(),
            namespace: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_NAMESPACE.to_string(),
            encryption_suite: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_ENCRYPTION_SUITE
                .to_string(),
            witness_suite: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_WITNESS_SUITE.to_string(),
            proof_suite: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROOF_SUITE.to_string(),
            state_diff_suite: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DIFF_SUITE.to_string(),
            receipt_suite: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_RECEIPT_SUITE.to_string(),
            execution_shards: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_SHARDS,
            witness_lanes: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_WITNESS_LANES,
            batch_window_blocks:
                ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_BATCH_WINDOW_BLOCKS,
            proof_queue_depth:
                ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_PROOF_QUEUE_DEPTH,
            max_calls_per_shard:
                ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_MAX_CALLS_PER_SHARD,
            max_diff_bytes: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_MAX_DIFF_BYTES,
            health_slo_ms: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEFAULT_HEALTH_SLO_MS,
            allow_fee_sponsors: true,
            require_conflict_free_shards: true,
            deterministic_scheduler: true,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("config.config_id", &self.config_id)?;
        ensure_non_empty("config.protocol_version", &self.protocol_version)?;
        ensure_non_empty("config.schema_version", &self.schema_version)?;
        ensure_non_empty("config.namespace", &self.namespace)?;
        ensure_non_empty("config.encryption_suite", &self.encryption_suite)?;
        ensure_non_empty("config.witness_suite", &self.witness_suite)?;
        ensure_non_empty("config.proof_suite", &self.proof_suite)?;
        ensure_non_empty("config.state_diff_suite", &self.state_diff_suite)?;
        ensure_non_empty("config.receipt_suite", &self.receipt_suite)?;
        ensure_positive("config.execution_shards", self.execution_shards)?;
        ensure_positive("config.witness_lanes", self.witness_lanes)?;
        ensure_positive("config.batch_window_blocks", self.batch_window_blocks)?;
        ensure_positive("config.proof_queue_depth", self.proof_queue_depth)?;
        ensure_positive("config.max_calls_per_shard", self.max_calls_per_shard)?;
        ensure_positive("config.max_diff_bytes", self.max_diff_bytes)?;
        ensure_positive("config.health_slo_ms", self.health_slo_ms)?;
        ensure_capacity_u64(
            "config.execution_shards",
            self.execution_shards,
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_EXECUTION_SHARDS,
        )?;
        ensure_capacity_u64(
            "config.witness_lanes",
            self.witness_lanes,
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_WITNESS_LANES,
        )?;
        if self.protocol_version != ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROTOCOL_VERSION {
            return Err("config.protocol_version mismatch".to_string());
        }
        Ok(())
    }
}

impl ExecutorRecord for Config {
    fn public_record(&self) -> Value {
        json!({
            "allow_fee_sponsors": self.allow_fee_sponsors,
            "batch_window_blocks": self.batch_window_blocks,
            "config_id": self.config_id,
            "deterministic_scheduler": self.deterministic_scheduler,
            "encryption_suite": self.encryption_suite,
            "execution_shards": self.execution_shards,
            "health_slo_ms": self.health_slo_ms,
            "max_calls_per_shard": self.max_calls_per_shard,
            "max_diff_bytes": self.max_diff_bytes,
            "namespace": self.namespace,
            "proof_queue_depth": self.proof_queue_depth,
            "proof_suite": self.proof_suite,
            "protocol_version": self.protocol_version,
            "receipt_suite": self.receipt_suite,
            "require_conflict_free_shards": self.require_conflict_free_shards,
            "schema_version": self.schema_version,
            "state_diff_suite": self.state_diff_suite,
            "witness_lanes": self.witness_lanes,
            "witness_suite": self.witness_suite,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDependencyNode {
    pub node_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub shard_id: String,
    pub kind: DependencyNodeKind,
    pub visibility: DependencyVisibility,
    pub encrypted_path_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_root: String,
    pub predecessor_ids: BTreeSet<String>,
    pub successor_ids: BTreeSet<String>,
    pub declared_weight: u64,
    pub sequence: u64,
}

impl EncryptedDependencyNode {
    pub fn new(
        sequence: u64,
        call_id: impl Into<String>,
        contract_id: impl Into<String>,
        shard_id: impl Into<String>,
        kind: DependencyNodeKind,
        visibility: DependencyVisibility,
        predecessor_ids: BTreeSet<String>,
    ) -> Self {
        let call_id = call_id.into();
        let contract_id = contract_id.into();
        let shard_id = shard_id.into();
        let node_id = dependency_node_id(sequence, &call_id, &contract_id, kind);
        let encrypted_path_root = fixture_root("dependency_path", &node_id);
        let read_set_root = fixture_root("dependency_read_set", &node_id);
        let write_set_root = if kind.writes_state() {
            fixture_root("dependency_write_set", &node_id)
        } else {
            empty_root("dependency_write_set")
        };
        let nullifier_root = fixture_root("dependency_nullifiers", &node_id);
        Self {
            node_id,
            call_id,
            contract_id,
            shard_id,
            kind,
            visibility,
            encrypted_path_root,
            read_set_root,
            write_set_root,
            nullifier_root,
            predecessor_ids,
            successor_ids: BTreeSet::new(),
            declared_weight: 10_000 + sequence.saturating_mul(1_250),
            sequence,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("dependency.node_id", &self.node_id)?;
        ensure_non_empty("dependency.call_id", &self.call_id)?;
        ensure_non_empty("dependency.contract_id", &self.contract_id)?;
        ensure_non_empty("dependency.shard_id", &self.shard_id)?;
        ensure_non_empty("dependency.encrypted_path_root", &self.encrypted_path_root)?;
        ensure_non_empty("dependency.read_set_root", &self.read_set_root)?;
        ensure_non_empty("dependency.write_set_root", &self.write_set_root)?;
        ensure_non_empty("dependency.nullifier_root", &self.nullifier_root)?;
        ensure_positive("dependency.declared_weight", self.declared_weight)?;
        if self.predecessor_ids.contains(&self.node_id)
            || self.successor_ids.contains(&self.node_id)
        {
            return Err(format!("dependency {} self references", self.node_id));
        }
        Ok(())
    }
}

impl ExecutorRecord for EncryptedDependencyNode {
    fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "declared_weight": self.declared_weight,
            "encrypted_path_root": self.encrypted_path_root,
            "kind": self.kind.as_str(),
            "node_id": self.node_id,
            "nullifier_root": self.nullifier_root,
            "predecessor_ids": self.predecessor_ids.iter().cloned().collect::<Vec<_>>(),
            "read_set_root": self.read_set_root,
            "sequence": self.sequence,
            "shard_id": self.shard_id,
            "successor_ids": self.successor_ids.iter().cloned().collect::<Vec<_>>(),
            "visibility": self.visibility.as_str(),
            "write_set_root": self.write_set_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessLane {
    pub lane_id: String,
    pub status: WitnessLaneStatus,
    pub assigned_shard_ids: BTreeSet<String>,
    pub transcript_root: String,
    pub sample_commitment_root: String,
    pub witness_count: u64,
    pub pending_bytes: u64,
    pub high_watermark_height: u64,
    pub lane_priority: u64,
}

impl WitnessLane {
    pub fn new(index: u64, shard_ids: BTreeSet<String>, status: WitnessLaneStatus) -> Self {
        let lane_id = lane_id(index);
        let transcript_root = fixture_root("witness_lane_transcript", &lane_id);
        let sample_commitment_root = fixture_root("witness_lane_samples", &lane_id);
        Self {
            lane_id,
            status,
            assigned_shard_ids: shard_ids,
            transcript_root,
            sample_commitment_root,
            witness_count: 24 + index.saturating_mul(7),
            pending_bytes: 32_768 + index.saturating_mul(4_096),
            high_watermark_height: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT
                .saturating_sub(index),
            lane_priority: 100_000_u64.saturating_sub(index.saturating_mul(1_000)),
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("witness_lane.lane_id", &self.lane_id)?;
        ensure_non_empty("witness_lane.transcript_root", &self.transcript_root)?;
        ensure_non_empty(
            "witness_lane.sample_commitment_root",
            &self.sample_commitment_root,
        )?;
        ensure_positive("witness_lane.lane_priority", self.lane_priority)?;
        if self.assigned_shard_ids.is_empty() {
            return Err(format!(
                "witness lane {} has no assigned shards",
                self.lane_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for WitnessLane {
    fn public_record(&self) -> Value {
        json!({
            "assigned_shard_ids": self.assigned_shard_ids.iter().cloned().collect::<Vec<_>>(),
            "high_watermark_height": self.high_watermark_height,
            "lane_id": self.lane_id,
            "lane_priority": self.lane_priority,
            "pending_bytes": self.pending_bytes,
            "sample_commitment_root": self.sample_commitment_root,
            "status": self.status.as_str(),
            "transcript_root": self.transcript_root,
            "witness_count": self.witness_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionShard {
    pub shard_id: String,
    pub status: ExecutionShardStatus,
    pub worker_group: String,
    pub lane_id: String,
    pub contract_ids: BTreeSet<String>,
    pub dependency_node_ids: BTreeSet<String>,
    pub read_region_root: String,
    pub write_region_root: String,
    pub conflict_fence_root: String,
    pub sealed_plan_root: String,
    pub max_parallel_calls: u64,
    pub scheduled_calls: u64,
    pub executed_calls: u64,
    pub retry_count: u64,
}

impl ExecutionShard {
    pub fn new(
        index: u64,
        lane_id: impl Into<String>,
        contract_ids: BTreeSet<String>,
        dependency_node_ids: BTreeSet<String>,
        status: ExecutionShardStatus,
    ) -> Self {
        let shard_id = shard_id(index);
        let worker_group = format!("zk-exec-workers-{:02}", index % 4);
        let read_region_root = fixture_root("execution_shard_read_region", &shard_id);
        let write_region_root = fixture_root("execution_shard_write_region", &shard_id);
        let conflict_fence_root = fixture_root("execution_shard_conflict_fence", &shard_id);
        let sealed_plan_root = fixture_root("execution_shard_plan", &shard_id);
        let scheduled_calls = dependency_node_ids.len() as u64;
        let executed_calls = if matches!(
            status,
            ExecutionShardStatus::Committed | ExecutionShardStatus::Sealed
        ) {
            scheduled_calls
        } else {
            scheduled_calls.saturating_sub(1)
        };
        Self {
            shard_id,
            status,
            worker_group,
            lane_id: lane_id.into(),
            contract_ids,
            dependency_node_ids,
            read_region_root,
            write_region_root,
            conflict_fence_root,
            sealed_plan_root,
            max_parallel_calls: 128,
            scheduled_calls,
            executed_calls,
            retry_count: if matches!(status, ExecutionShardStatus::Retrying) {
                1
            } else {
                0
            },
        }
    }

    pub fn conflict_free(&self) -> bool {
        self.status.live() && self.executed_calls <= self.scheduled_calls && self.retry_count <= 2
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("execution_shard.shard_id", &self.shard_id)?;
        ensure_non_empty("execution_shard.worker_group", &self.worker_group)?;
        ensure_non_empty("execution_shard.lane_id", &self.lane_id)?;
        ensure_non_empty("execution_shard.read_region_root", &self.read_region_root)?;
        ensure_non_empty("execution_shard.write_region_root", &self.write_region_root)?;
        ensure_non_empty(
            "execution_shard.conflict_fence_root",
            &self.conflict_fence_root,
        )?;
        ensure_non_empty("execution_shard.sealed_plan_root", &self.sealed_plan_root)?;
        ensure_positive(
            "execution_shard.max_parallel_calls",
            self.max_parallel_calls,
        )?;
        if self.contract_ids.is_empty() {
            return Err(format!(
                "execution shard {} has no contracts",
                self.shard_id
            ));
        }
        if self.dependency_node_ids.is_empty() {
            return Err(format!(
                "execution shard {} has no dependency nodes",
                self.shard_id
            ));
        }
        if self.executed_calls > self.scheduled_calls {
            return Err(format!(
                "execution shard {} executed more calls than scheduled",
                self.shard_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for ExecutionShard {
    fn public_record(&self) -> Value {
        json!({
            "conflict_fence_root": self.conflict_fence_root,
            "contract_ids": self.contract_ids.iter().cloned().collect::<Vec<_>>(),
            "dependency_node_ids": self.dependency_node_ids.iter().cloned().collect::<Vec<_>>(),
            "executed_calls": self.executed_calls,
            "lane_id": self.lane_id,
            "max_parallel_calls": self.max_parallel_calls,
            "read_region_root": self.read_region_root,
            "retry_count": self.retry_count,
            "scheduled_calls": self.scheduled_calls,
            "sealed_plan_root": self.sealed_plan_root,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "worker_group": self.worker_group,
            "write_region_root": self.write_region_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofQueueItem {
    pub proof_id: String,
    pub status: ProofQueueStatus,
    pub shard_id: String,
    pub lane_id: String,
    pub dependency_root: String,
    pub witness_root: String,
    pub receipt_root: String,
    pub prover_id: String,
    pub priority: u64,
    pub enqueued_at_height: u64,
    pub deadline_height: u64,
    pub attempt: u64,
}

impl ProofQueueItem {
    pub fn new(
        index: u64,
        shard_id: impl Into<String>,
        lane_id: impl Into<String>,
        status: ProofQueueStatus,
    ) -> Self {
        let shard_id = shard_id.into();
        let lane_id = lane_id.into();
        let proof_id = proof_queue_id(index, &shard_id);
        Self {
            dependency_root: fixture_root("proof_dependency", &proof_id),
            witness_root: fixture_root("proof_witness", &proof_id),
            receipt_root: fixture_root("proof_receipt", &proof_id),
            prover_id: format!("devnet-prover-{:02}", index % 5),
            priority: 900_000_u64.saturating_sub(index.saturating_mul(10_000)),
            enqueued_at_height: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT,
            deadline_height: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT
                .saturating_add(12)
                .saturating_add(index),
            attempt: if matches!(status, ProofQueueStatus::Failed) {
                2
            } else {
                1
            },
            proof_id,
            status,
            shard_id,
            lane_id,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("proof_queue.proof_id", &self.proof_id)?;
        ensure_non_empty("proof_queue.shard_id", &self.shard_id)?;
        ensure_non_empty("proof_queue.lane_id", &self.lane_id)?;
        ensure_non_empty("proof_queue.dependency_root", &self.dependency_root)?;
        ensure_non_empty("proof_queue.witness_root", &self.witness_root)?;
        ensure_non_empty("proof_queue.receipt_root", &self.receipt_root)?;
        ensure_non_empty("proof_queue.prover_id", &self.prover_id)?;
        ensure_positive("proof_queue.priority", self.priority)?;
        ensure_positive("proof_queue.attempt", self.attempt)?;
        if self.deadline_height <= self.enqueued_at_height {
            return Err(format!(
                "proof queue {} deadline is not in the future",
                self.proof_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for ProofQueueItem {
    fn public_record(&self) -> Value {
        json!({
            "attempt": self.attempt,
            "deadline_height": self.deadline_height,
            "dependency_root": self.dependency_root,
            "enqueued_at_height": self.enqueued_at_height,
            "lane_id": self.lane_id,
            "priority": self.priority,
            "proof_id": self.proof_id,
            "prover_id": self.prover_id,
            "receipt_root": self.receipt_root,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "witness_root": self.witness_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCallReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub shard_id: String,
    pub status: ContractReceiptStatus,
    pub calldata_commitment: String,
    pub return_data_commitment: String,
    pub event_root: String,
    pub nullifier_root: String,
    pub gas_charged: u64,
    pub sponsor_batch_id: Option<String>,
    pub emitted_at_height: u64,
}

impl ContractCallReceipt {
    pub fn new(
        index: u64,
        call_id: impl Into<String>,
        contract_id: impl Into<String>,
        shard_id: impl Into<String>,
        status: ContractReceiptStatus,
        sponsor_batch_id: Option<String>,
    ) -> Self {
        let call_id = call_id.into();
        let contract_id = contract_id.into();
        let shard_id = shard_id.into();
        let receipt_id = receipt_id(index, &call_id);
        Self {
            calldata_commitment: fixture_root("receipt_calldata", &receipt_id),
            return_data_commitment: fixture_root("receipt_return_data", &receipt_id),
            event_root: fixture_root("receipt_events", &receipt_id),
            nullifier_root: fixture_root("receipt_nullifiers", &receipt_id),
            gas_charged: 21_000 + index.saturating_mul(4_200),
            emitted_at_height: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT
                .saturating_add(index % 3),
            receipt_id,
            call_id,
            contract_id,
            shard_id,
            status,
            sponsor_batch_id,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("receipt.receipt_id", &self.receipt_id)?;
        ensure_non_empty("receipt.call_id", &self.call_id)?;
        ensure_non_empty("receipt.contract_id", &self.contract_id)?;
        ensure_non_empty("receipt.shard_id", &self.shard_id)?;
        ensure_non_empty("receipt.calldata_commitment", &self.calldata_commitment)?;
        ensure_non_empty(
            "receipt.return_data_commitment",
            &self.return_data_commitment,
        )?;
        ensure_non_empty("receipt.event_root", &self.event_root)?;
        ensure_non_empty("receipt.nullifier_root", &self.nullifier_root)?;
        ensure_positive("receipt.gas_charged", self.gas_charged)?;
        if self.status.successful()
            && self.return_data_commitment == empty_root("receipt_return_data")
        {
            return Err(format!(
                "receipt {} is successful with empty return data",
                self.receipt_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for ContractCallReceipt {
    fn public_record(&self) -> Value {
        json!({
            "calldata_commitment": self.calldata_commitment,
            "call_id": self.call_id,
            "contract_id": self.contract_id,
            "emitted_at_height": self.emitted_at_height,
            "event_root": self.event_root,
            "gas_charged": self.gas_charged,
            "nullifier_root": self.nullifier_root,
            "receipt_id": self.receipt_id,
            "return_data_commitment": self.return_data_commitment,
            "shard_id": self.shard_id,
            "sponsor_batch_id": self.sponsor_batch_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorBatch {
    pub sponsor_batch_id: String,
    pub status: FeeSponsorBatchStatus,
    pub sponsor_account_commitment: String,
    pub covered_receipt_ids: BTreeSet<String>,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub consumed_fee_units: u64,
    pub rebate_commitment_root: String,
    pub reconciliation_root: String,
    pub opened_at_height: u64,
}

impl FeeSponsorBatch {
    pub fn new(
        index: u64,
        covered_receipt_ids: BTreeSet<String>,
        status: FeeSponsorBatchStatus,
    ) -> Self {
        let sponsor_batch_id = sponsor_batch_id(index);
        let max_fee_units = 500_000 + index.saturating_mul(100_000);
        let reserved_fee_units = max_fee_units.saturating_sub(75_000);
        let consumed_fee_units = if status.active() {
            reserved_fee_units.saturating_sub(120_000)
        } else {
            reserved_fee_units.saturating_sub(80_000)
        };
        Self {
            sponsor_account_commitment: fixture_root("fee_sponsor_account", &sponsor_batch_id),
            fee_asset_id: format!("pNEBULA-fee-asset-{:02}", index),
            rebate_commitment_root: fixture_root("fee_sponsor_rebate", &sponsor_batch_id),
            reconciliation_root: fixture_root("fee_sponsor_reconciliation", &sponsor_batch_id),
            opened_at_height: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT
                .saturating_sub(2)
                .saturating_add(index),
            sponsor_batch_id,
            status,
            covered_receipt_ids,
            max_fee_units,
            reserved_fee_units,
            consumed_fee_units,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("fee_sponsor.sponsor_batch_id", &self.sponsor_batch_id)?;
        ensure_non_empty(
            "fee_sponsor.sponsor_account_commitment",
            &self.sponsor_account_commitment,
        )?;
        ensure_non_empty("fee_sponsor.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty(
            "fee_sponsor.rebate_commitment_root",
            &self.rebate_commitment_root,
        )?;
        ensure_non_empty("fee_sponsor.reconciliation_root", &self.reconciliation_root)?;
        ensure_positive("fee_sponsor.max_fee_units", self.max_fee_units)?;
        if self.covered_receipt_ids.is_empty() {
            return Err(format!(
                "fee sponsor batch {} has no covered receipts",
                self.sponsor_batch_id
            ));
        }
        if self.consumed_fee_units > self.reserved_fee_units {
            return Err(format!(
                "fee sponsor batch {} consumed more than reserved",
                self.sponsor_batch_id
            ));
        }
        if self.reserved_fee_units > self.max_fee_units {
            return Err(format!(
                "fee sponsor batch {} reserved more than max",
                self.sponsor_batch_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for FeeSponsorBatch {
    fn public_record(&self) -> Value {
        json!({
            "consumed_fee_units": self.consumed_fee_units,
            "covered_receipt_ids": self.covered_receipt_ids.iter().cloned().collect::<Vec<_>>(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "opened_at_height": self.opened_at_height,
            "rebate_commitment_root": self.rebate_commitment_root,
            "reconciliation_root": self.reconciliation_root,
            "reserved_fee_units": self.reserved_fee_units,
            "sponsor_account_commitment": self.sponsor_account_commitment,
            "sponsor_batch_id": self.sponsor_batch_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDiffCommitment {
    pub diff_id: String,
    pub status: StateDiffStatus,
    pub shard_id: String,
    pub previous_state_root: String,
    pub next_state_root: String,
    pub diff_commitment_root: String,
    pub touched_contract_root: String,
    pub touched_storage_root: String,
    pub receipt_root: String,
    pub proof_id: String,
    pub diff_bytes: u64,
    pub applied_at_height: Option<u64>,
}

impl StateDiffCommitment {
    pub fn new(
        index: u64,
        shard_id: impl Into<String>,
        proof_id: impl Into<String>,
        status: StateDiffStatus,
    ) -> Self {
        let shard_id = shard_id.into();
        let proof_id = proof_id.into();
        let diff_id = state_diff_id(index, &shard_id);
        let applied_at_height = if matches!(status, StateDiffStatus::Applied) {
            Some(ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT.saturating_add(index))
        } else {
            None
        };
        Self {
            previous_state_root: fixture_root("state_diff_previous", &diff_id),
            next_state_root: fixture_root("state_diff_next", &diff_id),
            diff_commitment_root: fixture_root("state_diff_commitment", &diff_id),
            touched_contract_root: fixture_root("state_diff_contracts", &diff_id),
            touched_storage_root: fixture_root("state_diff_storage", &diff_id),
            receipt_root: fixture_root("state_diff_receipts", &diff_id),
            diff_bytes: 64_000 + index.saturating_mul(8_000),
            diff_id,
            status,
            shard_id,
            proof_id,
            applied_at_height,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("state_diff.diff_id", &self.diff_id)?;
        ensure_non_empty("state_diff.shard_id", &self.shard_id)?;
        ensure_non_empty("state_diff.previous_state_root", &self.previous_state_root)?;
        ensure_non_empty("state_diff.next_state_root", &self.next_state_root)?;
        ensure_non_empty(
            "state_diff.diff_commitment_root",
            &self.diff_commitment_root,
        )?;
        ensure_non_empty(
            "state_diff.touched_contract_root",
            &self.touched_contract_root,
        )?;
        ensure_non_empty(
            "state_diff.touched_storage_root",
            &self.touched_storage_root,
        )?;
        ensure_non_empty("state_diff.receipt_root", &self.receipt_root)?;
        ensure_non_empty("state_diff.proof_id", &self.proof_id)?;
        ensure_positive("state_diff.diff_bytes", self.diff_bytes)?;
        if matches!(self.status, StateDiffStatus::Applied) && self.applied_at_height.is_none() {
            return Err(format!(
                "state diff {} applied without height",
                self.diff_id
            ));
        }
        if self.status.final_state()
            && matches!(self.status, StateDiffStatus::Rejected)
            && self.applied_at_height.is_some()
        {
            return Err(format!(
                "state diff {} rejected with applied height",
                self.diff_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for StateDiffCommitment {
    fn public_record(&self) -> Value {
        json!({
            "applied_at_height": self.applied_at_height,
            "diff_bytes": self.diff_bytes,
            "diff_commitment_root": self.diff_commitment_root,
            "diff_id": self.diff_id,
            "next_state_root": self.next_state_root,
            "previous_state_root": self.previous_state_root,
            "proof_id": self.proof_id,
            "receipt_root": self.receipt_root,
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "touched_contract_root": self.touched_contract_root,
            "touched_storage_root": self.touched_storage_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorHealthSample {
    pub sample_id: String,
    pub level: ExecutorHealthLevel,
    pub measured_at_height: u64,
    pub active_shards: u64,
    pub queued_proofs: u64,
    pub pending_witness_bytes: u64,
    pub avg_execution_latency_ms: u64,
    pub p95_execution_latency_ms: u64,
    pub conflict_rate_ppm: u64,
    pub backpressure_root: String,
}

impl ExecutorHealthSample {
    pub fn new(
        index: u64,
        level: ExecutorHealthLevel,
        active_shards: u64,
        queued_proofs: u64,
        pending_witness_bytes: u64,
    ) -> Self {
        let sample_id = health_sample_id(index);
        Self {
            measured_at_height: ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT
                .saturating_add(index),
            avg_execution_latency_ms: 210 + index.saturating_mul(17),
            p95_execution_latency_ms: 600 + index.saturating_mul(43),
            conflict_rate_ppm: 2_400 + index.saturating_mul(110),
            backpressure_root: fixture_root("executor_health_backpressure", &sample_id),
            sample_id,
            level,
            active_shards,
            queued_proofs,
            pending_witness_bytes,
        }
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        ensure_non_empty("health.sample_id", &self.sample_id)?;
        ensure_non_empty("health.backpressure_root", &self.backpressure_root)?;
        if self.p95_execution_latency_ms < self.avg_execution_latency_ms {
            return Err(format!(
                "health sample {} p95 below average",
                self.sample_id
            ));
        }
        Ok(())
    }
}

impl ExecutorRecord for ExecutorHealthSample {
    fn public_record(&self) -> Value {
        json!({
            "active_shards": self.active_shards,
            "avg_execution_latency_ms": self.avg_execution_latency_ms,
            "backpressure_root": self.backpressure_root,
            "conflict_rate_ppm": self.conflict_rate_ppm,
            "level": self.level.as_str(),
            "measured_at_height": self.measured_at_height,
            "p95_execution_latency_ms": self.p95_execution_latency_ms,
            "pending_witness_bytes": self.pending_witness_bytes,
            "queued_proofs": self.queued_proofs,
            "sample_id": self.sample_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub encrypted_dependency_graph_root: String,
    pub witness_lane_root: String,
    pub execution_shard_root: String,
    pub proof_queue_root: String,
    pub contract_call_receipt_root: String,
    pub fee_sponsor_batch_root: String,
    pub state_diff_commitment_root: String,
    pub health_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "contract_call_receipt_root": self.contract_call_receipt_root,
            "encrypted_dependency_graph_root": self.encrypted_dependency_graph_root,
            "execution_shard_root": self.execution_shard_root,
            "fee_sponsor_batch_root": self.fee_sponsor_batch_root,
            "health_root": self.health_root,
            "proof_queue_root": self.proof_queue_root,
            "state_diff_commitment_root": self.state_diff_commitment_root,
            "state_root": self.state_root,
            "witness_lane_root": self.witness_lane_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub encrypted_dependency_nodes: u64,
    pub private_dependency_nodes: u64,
    pub state_writing_dependency_nodes: u64,
    pub witness_lanes: u64,
    pub active_witness_lanes: u64,
    pub execution_shards: u64,
    pub conflict_free_shards: u64,
    pub proof_queue_items: u64,
    pub pending_proofs: u64,
    pub contract_call_receipts: u64,
    pub successful_receipts: u64,
    pub fee_sponsor_batches: u64,
    pub active_fee_sponsor_batches: u64,
    pub state_diff_commitments: u64,
    pub applied_state_diffs: u64,
    pub health_samples: u64,
    pub healthy_samples: u64,
    pub total_reserved_fee_units: u64,
    pub total_consumed_fee_units: u64,
    pub total_diff_bytes: u64,
    pub total_pending_witness_bytes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "active_fee_sponsor_batches": self.active_fee_sponsor_batches,
            "active_witness_lanes": self.active_witness_lanes,
            "applied_state_diffs": self.applied_state_diffs,
            "conflict_free_shards": self.conflict_free_shards,
            "contract_call_receipts": self.contract_call_receipts,
            "encrypted_dependency_nodes": self.encrypted_dependency_nodes,
            "execution_shards": self.execution_shards,
            "fee_sponsor_batches": self.fee_sponsor_batches,
            "health_samples": self.health_samples,
            "healthy_samples": self.healthy_samples,
            "pending_proofs": self.pending_proofs,
            "private_dependency_nodes": self.private_dependency_nodes,
            "proof_queue_items": self.proof_queue_items,
            "state_diff_commitments": self.state_diff_commitments,
            "state_writing_dependency_nodes": self.state_writing_dependency_nodes,
            "successful_receipts": self.successful_receipts,
            "total_consumed_fee_units": self.total_consumed_fee_units,
            "total_diff_bytes": self.total_diff_bytes,
            "total_pending_witness_bytes": self.total_pending_witness_bytes,
            "total_reserved_fee_units": self.total_reserved_fee_units,
            "witness_lanes": self.witness_lanes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub encrypted_dependency_graph: BTreeMap<String, EncryptedDependencyNode>,
    pub witness_lanes: BTreeMap<String, WitnessLane>,
    pub execution_shards: BTreeMap<String, ExecutionShard>,
    pub proof_queue: BTreeMap<String, ProofQueueItem>,
    pub contract_call_receipts: BTreeMap<String, ContractCallReceipt>,
    pub fee_sponsor_batches: BTreeMap<String, FeeSponsorBatch>,
    pub state_diff_commitments: BTreeMap<String, StateDiffCommitment>,
    pub health: BTreeMap<String, ExecutorHealthSample>,
}

impl State {
    pub fn new(height: u64, config: Config) -> Self {
        Self {
            height,
            config,
            encrypted_dependency_graph: BTreeMap::new(),
            witness_lanes: BTreeMap::new(),
            execution_shards: BTreeMap::new(),
            proof_queue: BTreeMap::new(),
            contract_call_receipts: BTreeMap::new(),
            fee_sponsor_batches: BTreeMap::new(),
            state_diff_commitments: BTreeMap::new(),
            health: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ZkPrivateSmartContractParallelExecutorResult<Self> {
        let config = Config::devnet();
        let mut state = Self::new(
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_DEVNET_HEIGHT,
            config,
        );

        let contract_ids = [
            "private-amm-vault",
            "private-lending-pool",
            "private-perps-margin",
            "private-stable-swap",
            "private-governance-timelock",
            "private-oracle-router",
        ];

        for index in 0..12_u64 {
            let call_id = contract_call_id(index);
            let contract_id = contract_ids[(index as usize) % contract_ids.len()].to_string();
            let shard_id = shard_id(index % 6);
            let kind = match index % 6 {
                0 => DependencyNodeKind::ContractCall,
                1 => DependencyNodeKind::StorageRead,
                2 => DependencyNodeKind::StorageWrite,
                3 => DependencyNodeKind::NullifierCheck,
                4 => DependencyNodeKind::FeeDebit,
                _ => DependencyNodeKind::ProofArtifact,
            };
            let visibility = match index % 4 {
                0 => DependencyVisibility::PublicCommitment,
                1 => DependencyVisibility::EncryptedHint,
                2 => DependencyVisibility::SealedPath,
                _ => DependencyVisibility::WitnessOnly,
            };
            let predecessor_ids = if index == 0 {
                BTreeSet::new()
            } else if index % 3 == 0 {
                BTreeSet::from([dependency_node_id(
                    index.saturating_sub(1),
                    &contract_call_id(index.saturating_sub(1)),
                    contract_ids[((index.saturating_sub(1)) as usize) % contract_ids.len()],
                    match (index.saturating_sub(1)) % 6 {
                        0 => DependencyNodeKind::ContractCall,
                        1 => DependencyNodeKind::StorageRead,
                        2 => DependencyNodeKind::StorageWrite,
                        3 => DependencyNodeKind::NullifierCheck,
                        4 => DependencyNodeKind::FeeDebit,
                        _ => DependencyNodeKind::ProofArtifact,
                    },
                )])
            } else {
                BTreeSet::new()
            };
            state.insert_dependency_node(EncryptedDependencyNode::new(
                index,
                call_id,
                contract_id,
                shard_id,
                kind,
                visibility,
                predecessor_ids,
            ))?;
        }
        state.rebuild_dependency_successors();

        for index in 0..4_u64 {
            let mut assigned_shards = BTreeSet::new();
            assigned_shards.insert(shard_id(index));
            assigned_shards.insert(shard_id(index + 4));
            let status = match index {
                0 => WitnessLaneStatus::Sampling,
                1 => WitnessLaneStatus::Open,
                2 => WitnessLaneStatus::Proving,
                _ => WitnessLaneStatus::Draining,
            };
            state.insert_witness_lane(WitnessLane::new(index, assigned_shards, status))?;
        }

        for index in 0..6_u64 {
            let shard = shard_id(index);
            let lane = lane_id(index % 4);
            let mut shard_contracts = BTreeSet::new();
            let mut shard_nodes = BTreeSet::new();
            for node in state.encrypted_dependency_graph.values() {
                if node.shard_id == shard {
                    shard_contracts.insert(node.contract_id.clone());
                    shard_nodes.insert(node.node_id.clone());
                }
            }
            let status = match index {
                0 | 1 => ExecutionShardStatus::Committed,
                2 => ExecutionShardStatus::Sealed,
                3 => ExecutionShardStatus::Executing,
                4 => ExecutionShardStatus::Reserved,
                _ => ExecutionShardStatus::Retrying,
            };
            state.insert_execution_shard(ExecutionShard::new(
                index,
                lane,
                shard_contracts,
                shard_nodes,
                status,
            ))?;
        }

        for index in 0..6_u64 {
            let status = match index {
                0 => ProofQueueStatus::Submitted,
                1 => ProofQueueStatus::Ready,
                2 => ProofQueueStatus::Aggregating,
                3 => ProofQueueStatus::Proving,
                4 => ProofQueueStatus::Assigned,
                _ => ProofQueueStatus::Queued,
            };
            state.insert_proof_queue_item(ProofQueueItem::new(
                index,
                shard_id(index),
                lane_id(index % 4),
                status,
            ))?;
        }

        for index in 0..10_u64 {
            let sponsor_batch_id = if index % 3 == 0 {
                Some(sponsor_batch_id(index % 3))
            } else {
                None
            };
            let status = match index % 5 {
                0 => ContractReceiptStatus::Settled,
                1 => ContractReceiptStatus::Proved,
                2 => ContractReceiptStatus::Executed,
                3 => ContractReceiptStatus::Accepted,
                _ => ContractReceiptStatus::Reverted,
            };
            state.insert_contract_call_receipt(ContractCallReceipt::new(
                index,
                contract_call_id(index),
                contract_ids[(index as usize) % contract_ids.len()],
                shard_id(index % 6),
                status,
                sponsor_batch_id,
            ))?;
        }

        for index in 0..3_u64 {
            let mut covered_receipts = BTreeSet::new();
            for receipt in state.contract_call_receipts.values() {
                if receipt.sponsor_batch_id.as_deref() == Some(sponsor_batch_id(index).as_str()) {
                    covered_receipts.insert(receipt.receipt_id.clone());
                }
            }
            let status = match index {
                0 => FeeSponsorBatchStatus::Reconciled,
                1 => FeeSponsorBatchStatus::Debited,
                _ => FeeSponsorBatchStatus::Reserved,
            };
            state.insert_fee_sponsor_batch(FeeSponsorBatch::new(
                index,
                covered_receipts,
                status,
            ))?;
        }

        for index in 0..6_u64 {
            let status = match index {
                0 | 1 => StateDiffStatus::Applied,
                2 => StateDiffStatus::Proven,
                3 => StateDiffStatus::Witnessed,
                4 => StateDiffStatus::Proposed,
                _ => StateDiffStatus::Superseded,
            };
            state.insert_state_diff_commitment(StateDiffCommitment::new(
                index,
                shard_id(index),
                proof_queue_id(index, &shard_id(index)),
                status,
            ))?;
        }

        for index in 0..5_u64 {
            let level = match index {
                0 | 1 => ExecutorHealthLevel::Healthy,
                2 => ExecutorHealthLevel::Recovering,
                3 => ExecutorHealthLevel::Degraded,
                _ => ExecutorHealthLevel::Backpressured,
            };
            let active_shards = state
                .execution_shards
                .values()
                .filter(|shard| shard.status.live())
                .count() as u64;
            let queued_proofs = state
                .proof_queue
                .values()
                .filter(|item| item.status.pending())
                .count() as u64;
            let pending_witness_bytes = state
                .witness_lanes
                .values()
                .map(|lane| lane.pending_bytes)
                .sum();
            state.insert_health_sample(ExecutorHealthSample::new(
                index,
                level,
                active_shards,
                queued_proofs,
                pending_witness_bytes,
            ))?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        self.config.validate()?;
        ensure_capacity(
            "encrypted_dependency_graph",
            self.encrypted_dependency_graph.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_DEPENDENCY_NODES,
        )?;
        ensure_capacity(
            "witness_lanes",
            self.witness_lanes.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_WITNESS_LANES,
        )?;
        ensure_capacity(
            "execution_shards",
            self.execution_shards.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_EXECUTION_SHARDS,
        )?;
        ensure_capacity(
            "proof_queue",
            self.proof_queue.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_PROOF_QUEUE_ITEMS,
        )?;
        ensure_capacity(
            "contract_call_receipts",
            self.contract_call_receipts.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_RECEIPTS,
        )?;
        ensure_capacity(
            "fee_sponsor_batches",
            self.fee_sponsor_batches.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_SPONSOR_BATCHES,
        )?;
        ensure_capacity(
            "state_diff_commitments",
            self.state_diff_commitments.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_STATE_DIFFS,
        )?;
        ensure_capacity(
            "health",
            self.health.len(),
            ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_MAX_HEALTH_SAMPLES,
        )?;

        for (id, node) in &self.encrypted_dependency_graph {
            if id != &node.node_id {
                return Err(format!(
                    "dependency graph key {} does not match node id",
                    id
                ));
            }
            node.validate()?;
            for predecessor_id in &node.predecessor_ids {
                if !self.encrypted_dependency_graph.contains_key(predecessor_id) {
                    return Err(format!(
                        "dependency node {} missing predecessor {}",
                        node.node_id, predecessor_id
                    ));
                }
            }
            for successor_id in &node.successor_ids {
                if !self.encrypted_dependency_graph.contains_key(successor_id) {
                    return Err(format!(
                        "dependency node {} missing successor {}",
                        node.node_id, successor_id
                    ));
                }
            }
        }

        for (id, lane) in &self.witness_lanes {
            if id != &lane.lane_id {
                return Err(format!("witness lane key {} does not match lane id", id));
            }
            lane.validate()?;
            for shard_id in &lane.assigned_shard_ids {
                if !self.execution_shards.contains_key(shard_id) {
                    return Err(format!(
                        "witness lane {} references missing shard {}",
                        lane.lane_id, shard_id
                    ));
                }
            }
        }

        for (id, shard) in &self.execution_shards {
            if id != &shard.shard_id {
                return Err(format!(
                    "execution shard key {} does not match shard id",
                    id
                ));
            }
            shard.validate()?;
            if !self.witness_lanes.contains_key(&shard.lane_id) {
                return Err(format!(
                    "execution shard {} references missing lane {}",
                    shard.shard_id, shard.lane_id
                ));
            }
            for node_id in &shard.dependency_node_ids {
                if !self.encrypted_dependency_graph.contains_key(node_id) {
                    return Err(format!(
                        "execution shard {} references missing dependency {}",
                        shard.shard_id, node_id
                    ));
                }
            }
        }

        for (id, item) in &self.proof_queue {
            if id != &item.proof_id {
                return Err(format!("proof queue key {} does not match proof id", id));
            }
            item.validate()?;
            if !self.execution_shards.contains_key(&item.shard_id) {
                return Err(format!(
                    "proof queue {} references missing shard {}",
                    item.proof_id, item.shard_id
                ));
            }
            if !self.witness_lanes.contains_key(&item.lane_id) {
                return Err(format!(
                    "proof queue {} references missing lane {}",
                    item.proof_id, item.lane_id
                ));
            }
        }

        for (id, receipt) in &self.contract_call_receipts {
            if id != &receipt.receipt_id {
                return Err(format!("receipt key {} does not match receipt id", id));
            }
            receipt.validate()?;
            if !self.execution_shards.contains_key(&receipt.shard_id) {
                return Err(format!(
                    "receipt {} references missing shard {}",
                    receipt.receipt_id, receipt.shard_id
                ));
            }
            if let Some(sponsor_batch_id) = &receipt.sponsor_batch_id {
                if !self.fee_sponsor_batches.contains_key(sponsor_batch_id) {
                    return Err(format!(
                        "receipt {} references missing sponsor batch {}",
                        receipt.receipt_id, sponsor_batch_id
                    ));
                }
            }
        }

        for (id, batch) in &self.fee_sponsor_batches {
            if id != &batch.sponsor_batch_id {
                return Err(format!("sponsor batch key {} does not match batch id", id));
            }
            batch.validate()?;
            for receipt_id in &batch.covered_receipt_ids {
                match self.contract_call_receipts.get(receipt_id) {
                    Some(receipt) if receipt.sponsor_batch_id.as_ref() == Some(id) => {}
                    Some(_) => {
                        return Err(format!(
                            "sponsor batch {} receipt {} does not link back",
                            id, receipt_id
                        ));
                    }
                    None => {
                        return Err(format!(
                            "sponsor batch {} references missing receipt {}",
                            id, receipt_id
                        ));
                    }
                }
            }
        }

        for (id, diff) in &self.state_diff_commitments {
            if id != &diff.diff_id {
                return Err(format!("state diff key {} does not match diff id", id));
            }
            diff.validate()?;
            if !self.execution_shards.contains_key(&diff.shard_id) {
                return Err(format!(
                    "state diff {} references missing shard {}",
                    diff.diff_id, diff.shard_id
                ));
            }
            if !self.proof_queue.contains_key(&diff.proof_id) {
                return Err(format!(
                    "state diff {} references missing proof {}",
                    diff.diff_id, diff.proof_id
                ));
            }
            if diff.diff_bytes > self.config.max_diff_bytes {
                return Err(format!(
                    "state diff {} exceeds max diff bytes",
                    diff.diff_id
                ));
            }
        }

        for (id, sample) in &self.health {
            if id != &sample.sample_id {
                return Err(format!("health key {} does not match sample id", id));
            }
            sample.validate()?;
        }

        if self.config.require_conflict_free_shards {
            let conflicted = self
                .execution_shards
                .values()
                .filter(|shard| !shard.conflict_free())
                .map(|shard| shard.shard_id.clone())
                .collect::<Vec<_>>();
            if !conflicted.is_empty() {
                return Err(format!(
                    "conflicted execution shards: {}",
                    conflicted.join(",")
                ));
            }
        }

        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(
        &mut self,
        delta: u64,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        self.height = self
            .height
            .checked_add(delta)
            .ok_or_else(|| "height overflow".to_string())?;
        self.validate()
    }

    pub fn insert_dependency_node(
        &mut self,
        node: EncryptedDependencyNode,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        node.validate()?;
        if self.encrypted_dependency_graph.contains_key(&node.node_id) {
            return Err(format!("duplicate dependency node {}", node.node_id));
        }
        self.encrypted_dependency_graph
            .insert(node.node_id.clone(), node);
        Ok(())
    }

    pub fn insert_witness_lane(
        &mut self,
        lane: WitnessLane,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        lane.validate()?;
        if self.witness_lanes.contains_key(&lane.lane_id) {
            return Err(format!("duplicate witness lane {}", lane.lane_id));
        }
        self.witness_lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_execution_shard(
        &mut self,
        shard: ExecutionShard,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        shard.validate()?;
        if self.execution_shards.contains_key(&shard.shard_id) {
            return Err(format!("duplicate execution shard {}", shard.shard_id));
        }
        self.execution_shards.insert(shard.shard_id.clone(), shard);
        Ok(())
    }

    pub fn insert_proof_queue_item(
        &mut self,
        item: ProofQueueItem,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        item.validate()?;
        if self.proof_queue.contains_key(&item.proof_id) {
            return Err(format!("duplicate proof queue item {}", item.proof_id));
        }
        self.proof_queue.insert(item.proof_id.clone(), item);
        Ok(())
    }

    pub fn insert_contract_call_receipt(
        &mut self,
        receipt: ContractCallReceipt,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        receipt.validate()?;
        if self
            .contract_call_receipts
            .contains_key(&receipt.receipt_id)
        {
            return Err(format!(
                "duplicate contract call receipt {}",
                receipt.receipt_id
            ));
        }
        self.contract_call_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn insert_fee_sponsor_batch(
        &mut self,
        batch: FeeSponsorBatch,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        batch.validate()?;
        if self
            .fee_sponsor_batches
            .contains_key(&batch.sponsor_batch_id)
        {
            return Err(format!(
                "duplicate fee sponsor batch {}",
                batch.sponsor_batch_id
            ));
        }
        self.fee_sponsor_batches
            .insert(batch.sponsor_batch_id.clone(), batch);
        Ok(())
    }

    pub fn insert_state_diff_commitment(
        &mut self,
        diff: StateDiffCommitment,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        diff.validate()?;
        if self.state_diff_commitments.contains_key(&diff.diff_id) {
            return Err(format!("duplicate state diff {}", diff.diff_id));
        }
        self.state_diff_commitments
            .insert(diff.diff_id.clone(), diff);
        Ok(())
    }

    pub fn insert_health_sample(
        &mut self,
        sample: ExecutorHealthSample,
    ) -> ZkPrivateSmartContractParallelExecutorResult<()> {
        sample.validate()?;
        if self.health.contains_key(&sample.sample_id) {
            return Err(format!("duplicate health sample {}", sample.sample_id));
        }
        self.health.insert(sample.sample_id.clone(), sample);
        Ok(())
    }

    pub fn rebuild_dependency_successors(&mut self) {
        for node in self.encrypted_dependency_graph.values_mut() {
            node.successor_ids.clear();
        }
        let edges = self
            .encrypted_dependency_graph
            .values()
            .flat_map(|node| {
                node.predecessor_ids
                    .iter()
                    .map(|predecessor_id| (predecessor_id.clone(), node.node_id.clone()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for (predecessor_id, successor_id) in edges {
            if let Some(predecessor) = self.encrypted_dependency_graph.get_mut(&predecessor_id) {
                predecessor.successor_ids.insert(successor_id);
            }
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = self
            .config
            .root("ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:CONFIG");
        let encrypted_dependency_graph_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:DEPENDENCY-GRAPH",
            &self.encrypted_dependency_graph,
        );
        let witness_lane_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:WITNESS-LANES",
            &self.witness_lanes,
        );
        let execution_shard_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:EXECUTION-SHARDS",
            &self.execution_shards,
        );
        let proof_queue_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:PROOF-QUEUE",
            &self.proof_queue,
        );
        let contract_call_receipt_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:CALL-RECEIPTS",
            &self.contract_call_receipts,
        );
        let fee_sponsor_batch_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:FEE-SPONSOR-BATCHES",
            &self.fee_sponsor_batches,
        );
        let state_diff_commitment_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:STATE-DIFFS",
            &self.state_diff_commitments,
        );
        let health_root = map_root(
            "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:HEALTH",
            &self.health,
        );
        let counters = self.counters();
        let state_record = json!({
            "chain_id": CHAIN_ID,
            "config_root": config_root,
            "contract_call_receipt_root": contract_call_receipt_root,
            "counters": counters.public_record(),
            "encrypted_dependency_graph_root": encrypted_dependency_graph_root,
            "execution_shard_root": execution_shard_root,
            "fee_sponsor_batch_root": fee_sponsor_batch_root,
            "health_root": health_root,
            "height": self.height,
            "proof_queue_root": proof_queue_root,
            "protocol_version": ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "state_diff_commitment_root": state_diff_commitment_root,
            "witness_lane_root": witness_lane_root,
        });
        let state_root = root_from_record(&state_record);
        Roots {
            config_root,
            encrypted_dependency_graph_root,
            witness_lane_root,
            execution_shard_root,
            proof_queue_root,
            contract_call_receipt_root,
            fee_sponsor_batch_root,
            state_diff_commitment_root,
            health_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            encrypted_dependency_nodes: self.encrypted_dependency_graph.len() as u64,
            private_dependency_nodes: self
                .encrypted_dependency_graph
                .values()
                .filter(|node| node.visibility.private())
                .count() as u64,
            state_writing_dependency_nodes: self
                .encrypted_dependency_graph
                .values()
                .filter(|node| node.kind.writes_state())
                .count() as u64,
            witness_lanes: self.witness_lanes.len() as u64,
            active_witness_lanes: self
                .witness_lanes
                .values()
                .filter(|lane| lane.status.accepts_work())
                .count() as u64,
            execution_shards: self.execution_shards.len() as u64,
            conflict_free_shards: self
                .execution_shards
                .values()
                .filter(|shard| shard.conflict_free())
                .count() as u64,
            proof_queue_items: self.proof_queue.len() as u64,
            pending_proofs: self
                .proof_queue
                .values()
                .filter(|item| item.status.pending())
                .count() as u64,
            contract_call_receipts: self.contract_call_receipts.len() as u64,
            successful_receipts: self
                .contract_call_receipts
                .values()
                .filter(|receipt| receipt.status.successful())
                .count() as u64,
            fee_sponsor_batches: self.fee_sponsor_batches.len() as u64,
            active_fee_sponsor_batches: self
                .fee_sponsor_batches
                .values()
                .filter(|batch| batch.status.active())
                .count() as u64,
            state_diff_commitments: self.state_diff_commitments.len() as u64,
            applied_state_diffs: self
                .state_diff_commitments
                .values()
                .filter(|diff| matches!(diff.status, StateDiffStatus::Applied))
                .count() as u64,
            health_samples: self.health.len() as u64,
            healthy_samples: self
                .health
                .values()
                .filter(|sample| sample.level.ok())
                .count() as u64,
            total_reserved_fee_units: self
                .fee_sponsor_batches
                .values()
                .map(|batch| batch.reserved_fee_units)
                .sum(),
            total_consumed_fee_units: self
                .fee_sponsor_batches
                .values()
                .map(|batch| batch.consumed_fee_units)
                .sum(),
            total_diff_bytes: self
                .state_diff_commitments
                .values()
                .map(|diff| diff.diff_bytes)
                .sum(),
            total_pending_witness_bytes: self
                .witness_lanes
                .values()
                .map(|lane| lane.pending_bytes)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "contract_call_receipts": self.contract_call_receipts.iter().map(|(id, receipt)| {
                json!({"id": id, "record": receipt.public_record()})
            }).collect::<Vec<_>>(),
            "counters": counters.public_record(),
            "encrypted_dependency_graph": self.encrypted_dependency_graph.iter().map(|(id, node)| {
                json!({"id": id, "record": node.public_record()})
            }).collect::<Vec<_>>(),
            "execution_shards": self.execution_shards.iter().map(|(id, shard)| {
                json!({"id": id, "record": shard.public_record()})
            }).collect::<Vec<_>>(),
            "fee_sponsor_batches": self.fee_sponsor_batches.iter().map(|(id, batch)| {
                json!({"id": id, "record": batch.public_record()})
            }).collect::<Vec<_>>(),
            "health": self.health.iter().map(|(id, sample)| {
                json!({"id": id, "record": sample.public_record()})
            }).collect::<Vec<_>>(),
            "height": self.height,
            "proof_queue": self.proof_queue.iter().map(|(id, item)| {
                json!({"id": id, "record": item.public_record()})
            }).collect::<Vec<_>>(),
            "protocol_version": ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROTOCOL_VERSION,
            "roots": roots.public_record(),
            "state_diff_commitments": self.state_diff_commitments.iter().map(|(id, diff)| {
                json!({"id": id, "record": diff.public_record()})
            }).collect::<Vec<_>>(),
            "witness_lanes": self.witness_lanes.iter().map(|(id, lane)| {
                json!({"id": id, "record": lane.public_record()})
            }).collect::<Vec<_>>(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ZK_PRIVATE_SMART_CONTRACT_PARALLEL_EXECUTOR_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> ZkPrivateSmartContractParallelExecutorResult<State> {
    State::devnet()
}

fn map_root<T: ExecutorRecord>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn executor_id(kind: &str, label: &str) -> String {
    domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        16,
    )
}

fn fixture_root(kind: &str, label: &str) -> String {
    domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn empty_root(kind: &str) -> String {
    merkle_root(
        &format!("ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:{kind}:EMPTY"),
        &[],
    )
}

fn contract_call_id(index: u64) -> String {
    format!("zk-private-call-{:04}", index)
}

fn shard_id(index: u64) -> String {
    format!("zk-private-exec-shard-{:02}", index)
}

fn lane_id(index: u64) -> String {
    format!("zk-private-witness-lane-{:02}", index)
}

fn sponsor_batch_id(index: u64) -> String {
    format!("zk-private-fee-sponsor-batch-{:02}", index)
}

fn dependency_node_id(
    sequence: u64,
    call_id: &str,
    contract_id: &str,
    kind: DependencyNodeKind,
) -> String {
    let digest = domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:DEPENDENCY-NODE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(call_id),
            HashPart::Str(contract_id),
            HashPart::Str(kind.as_str()),
        ],
        12,
    );
    format!("zk-private-dependency-{sequence:04}-{digest}")
}

fn proof_queue_id(index: u64, shard_id: &str) -> String {
    let digest = domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:PROOF-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(index as i128),
            HashPart::Str(shard_id),
        ],
        10,
    );
    format!("zk-private-proof-{index:04}-{digest}")
}

fn receipt_id(index: u64, call_id: &str) -> String {
    let digest = domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(index as i128),
            HashPart::Str(call_id),
        ],
        10,
    );
    format!("zk-private-receipt-{index:04}-{digest}")
}

fn state_diff_id(index: u64, shard_id: &str) -> String {
    let digest = domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:STATE-DIFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(index as i128),
            HashPart::Str(shard_id),
        ],
        10,
    );
    format!("zk-private-state-diff-{index:04}-{digest}")
}

fn health_sample_id(index: u64) -> String {
    let digest = domain_hash(
        "ZK-PRIVATE-SMART-CONTRACT-PARALLEL-EXECUTOR:HEALTH-SAMPLE-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Int(index as i128)],
        10,
    );
    format!("zk-private-executor-health-{index:04}-{digest}")
}

fn ensure_non_empty(field: &str, value: &str) -> ZkPrivateSmartContractParallelExecutorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(field: &str, value: u64) -> ZkPrivateSmartContractParallelExecutorResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_capacity(
    field: &str,
    actual: usize,
    max: usize,
) -> ZkPrivateSmartContractParallelExecutorResult<()> {
    if actual > max {
        return Err(format!("{field} exceeds capacity {actual}/{max}"));
    }
    Ok(())
}

fn ensure_capacity_u64(
    field: &str,
    actual: u64,
    max: usize,
) -> ZkPrivateSmartContractParallelExecutorResult<()> {
    if actual > max as u64 {
        return Err(format!("{field} exceeds capacity {actual}/{max}"));
    }
    Ok(())
}
