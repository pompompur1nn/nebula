use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type StateShardingResult<T> = Result<T, String>;
pub type ShardId = String;
pub type PartitionId = String;
pub type RoutingTableId = String;
pub type RoutingRuleId = String;
pub type AtomicBundleId = String;
pub type LockLeaseId = String;
pub type HandoffReceiptId = String;
pub type AssignmentId = String;
pub type PqAttestationId = String;
pub type ReplayManifestId = String;

pub const STATE_SHARDING_PROTOCOL_VERSION: &str = "nebula-state-sharding-v1";
pub const STATE_SHARDING_PRIVACY_SCHEME: &str =
    "bucketed-key-telemetry-with-blinded-state-witnesses-v1";
pub const STATE_SHARDING_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-65+slh-dsa-shake-128s-shard-attestation-devnet";
pub const STATE_SHARDING_DA_SCHEME: &str = "erasure-rooted-state-shard-da-v1";
pub const STATE_SHARDING_REPLAY_SCHEME: &str = "deterministic-shard-replay-manifest-v1";
pub const STATE_SHARDING_CACHE_SCHEME: &str = "lease-aware-hot-state-cache-v1";
pub const STATE_SHARDING_DEFAULT_SHARD_COUNT: u64 = 8;
pub const STATE_SHARDING_DEFAULT_HOT_PARTITIONS: u64 = 16;
pub const STATE_SHARDING_DEFAULT_REPLICATION_FACTOR: u64 = 3;
pub const STATE_SHARDING_DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 720;
pub const STATE_SHARDING_DEFAULT_LOCK_LEASE_BLOCKS: u64 = 6;
pub const STATE_SHARDING_DEFAULT_HANDOFF_WINDOW_BLOCKS: u64 = 12;
pub const STATE_SHARDING_DEFAULT_DA_RETENTION_BLOCKS: u64 = 14_400;
pub const STATE_SHARDING_DEFAULT_CACHE_TTL_BLOCKS: u64 = 32;
pub const STATE_SHARDING_DEFAULT_CACHE_ENTRIES: u64 = 131_072;
pub const STATE_SHARDING_DEFAULT_CACHE_BYTES: u64 = 256 * 1024 * 1024;
pub const STATE_SHARDING_DEFAULT_WALLET_FEE_UNITS: u64 = 1;
pub const STATE_SHARDING_DEFAULT_BRIDGE_FEE_UNITS: u64 = 2;
pub const STATE_SHARDING_MAX_BPS: u64 = 10_000;
pub const STATE_SHARDING_STATUS_ACTIVE: &str = "active";
pub const STATE_SHARDING_STATUS_PENDING: &str = "pending";
pub const STATE_SHARDING_STATUS_PREPARED: &str = "prepared";
pub const STATE_SHARDING_STATUS_COMMITTED: &str = "committed";
pub const STATE_SHARDING_STATUS_ROLLED_BACK: &str = "rolled_back";
pub const STATE_SHARDING_STATUS_EXPIRED: &str = "expired";
pub const STATE_SHARDING_STATUS_RETIRED: &str = "retired";
pub const STATE_SHARDING_STATUS_PAUSED: &str = "paused";
pub const STATE_SHARDING_STATUS_QUARANTINED: &str = "quarantined";
pub const STATE_SHARDING_LOW_FEE_WALLET_LANE: &str = "wallet_private_transfer";
pub const STATE_SHARDING_LOW_FEE_BRIDGE_LANE: &str = "monero_bridge_settlement";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ShardPartitionKind {
    AccountRange,
    ContractBucket,
    DefiPool,
    PrivacyNullifier,
    BridgeQueue,
    TokenLedger,
    HotCache,
    DataAvailability,
    WalletLane,
    System,
    Custom(String),
}

impl ShardPartitionKind {
    pub fn label(&self) -> String {
        match self {
            Self::AccountRange => "account_range".to_string(),
            Self::ContractBucket => "contract_bucket".to_string(),
            Self::DefiPool => "defi_pool".to_string(),
            Self::PrivacyNullifier => "privacy_nullifier".to_string(),
            Self::BridgeQueue => "bridge_queue".to_string(),
            Self::TokenLedger => "token_ledger".to_string(),
            Self::HotCache => "hot_cache".to_string(),
            Self::DataAvailability => "data_availability".to_string(),
            Self::WalletLane => "wallet_lane".to_string(),
            Self::System => "system".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shard_partition_kind",
            "chain_id": CHAIN_ID,
            "label": self.label(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ShardAccessClass {
    PublicRead,
    PrivateBalance,
    PrivateContract,
    DefiHotPath,
    BridgeControl,
    SequencerSystem,
    DataAvailabilityReplay,
    WalletLowFee,
    ValidatorOnly,
    Custom(String),
}

impl ShardAccessClass {
    pub fn label(&self) -> String {
        match self {
            Self::PublicRead => "public_read".to_string(),
            Self::PrivateBalance => "private_balance".to_string(),
            Self::PrivateContract => "private_contract".to_string(),
            Self::DefiHotPath => "defi_hot_path".to_string(),
            Self::BridgeControl => "bridge_control".to_string(),
            Self::SequencerSystem => "sequencer_system".to_string(),
            Self::DataAvailabilityReplay => "data_availability_replay".to_string(),
            Self::WalletLowFee => "wallet_low_fee".to_string(),
            Self::ValidatorOnly => "validator_only".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn privacy_sensitive(&self) -> bool {
        match self {
            Self::PrivateBalance
            | Self::PrivateContract
            | Self::BridgeControl
            | Self::WalletLowFee
            | Self::ValidatorOnly => true,
            Self::PublicRead
            | Self::DefiHotPath
            | Self::SequencerSystem
            | Self::DataAvailabilityReplay
            | Self::Custom(_) => false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shard_access_class",
            "chain_id": CHAIN_ID,
            "label": self.label(),
            "privacy_sensitive": self.privacy_sensitive(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ShardTrafficClass {
    Wallet,
    Bridge,
    Defi,
    Contract,
    Token,
    Proof,
    Replay,
    Bulk,
    System,
    Custom(String),
}

impl ShardTrafficClass {
    pub fn label(&self) -> String {
        match self {
            Self::Wallet => "wallet".to_string(),
            Self::Bridge => "bridge".to_string(),
            Self::Defi => "defi".to_string(),
            Self::Contract => "contract".to_string(),
            Self::Token => "token".to_string(),
            Self::Proof => "proof".to_string(),
            Self::Replay => "replay".to_string(),
            Self::Bulk => "bulk".to_string(),
            Self::System => "system".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LockLeaseMode {
    Read,
    Write,
    Atomic,
    Handoff,
    Rollback,
}

impl LockLeaseMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Atomic => "atomic",
            Self::Handoff => "handoff",
            Self::Rollback => "rollback",
        }
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        !(self == &Self::Read && other == &Self::Read)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ShardAssignmentRole {
    Sequencer,
    Validator,
    Prover,
    Watchtower,
    DataAvailability,
    CacheWarmer,
}

impl ShardAssignmentRole {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Validator => "validator",
            Self::Prover => "prover",
            Self::Watchtower => "watchtower",
            Self::DataAvailability => "data_availability",
            Self::CacheWarmer => "cache_warmer",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CacheEvictionKind {
    Lru,
    Lfu,
    LeaseAware,
    FeeAware,
    DaPinned,
    HotnessDecay,
}

impl CacheEvictionKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Lru => "lru",
            Self::Lfu => "lfu",
            Self::LeaseAware => "lease_aware",
            Self::FeeAware => "fee_aware",
            Self::DaPinned => "da_pinned",
            Self::HotnessDecay => "hotness_decay",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardTopologyConfig {
    pub topology_id: String,
    pub epoch: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub shard_count: u64,
    pub hot_partition_count: u64,
    pub replication_factor: u64,
    pub lock_lease_blocks: u64,
    pub handoff_window_blocks: u64,
    pub da_retention_blocks: u64,
    pub pq_attestations_required: bool,
    pub privacy_witness_required: bool,
    pub low_fee_lanes_enabled: bool,
    pub access_policy_root: String,
    pub routing_table_root: String,
    pub status: String,
}

impl ShardTopologyConfig {
    pub fn new(epoch: u64, epoch_start_height: u64, epoch_end_height: u64) -> Self {
        let access_policy_root = merkle_root("STATE-SHARDING-ACCESS-POLICY", &[]);
        let routing_table_root = merkle_root("STATE-SHARDING-ROUTING-TABLE", &[]);
        let topology_id = shard_topology_id(
            epoch,
            epoch_start_height,
            epoch_end_height,
            STATE_SHARDING_DEFAULT_SHARD_COUNT,
            STATE_SHARDING_DEFAULT_HOT_PARTITIONS,
            &routing_table_root,
        );
        Self {
            topology_id,
            epoch,
            epoch_start_height,
            epoch_end_height,
            shard_count: STATE_SHARDING_DEFAULT_SHARD_COUNT,
            hot_partition_count: STATE_SHARDING_DEFAULT_HOT_PARTITIONS,
            replication_factor: STATE_SHARDING_DEFAULT_REPLICATION_FACTOR,
            lock_lease_blocks: STATE_SHARDING_DEFAULT_LOCK_LEASE_BLOCKS,
            handoff_window_blocks: STATE_SHARDING_DEFAULT_HANDOFF_WINDOW_BLOCKS,
            da_retention_blocks: STATE_SHARDING_DEFAULT_DA_RETENTION_BLOCKS,
            pq_attestations_required: true,
            privacy_witness_required: true,
            low_fee_lanes_enabled: true,
            access_policy_root,
            routing_table_root,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn with_roots(
        mut self,
        access_policy_root: impl Into<String>,
        routing_table_root: impl Into<String>,
    ) -> Self {
        self.access_policy_root = access_policy_root.into();
        self.routing_table_root = routing_table_root.into();
        self.topology_id = shard_topology_id(
            self.epoch,
            self.epoch_start_height,
            self.epoch_end_height,
            self.shard_count,
            self.hot_partition_count,
            &self.routing_table_root,
        );
        self
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.epoch_start_height && height <= self.epoch_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shard_topology_config",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "topology_id": self.topology_id,
            "epoch": self.epoch,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "shard_count": self.shard_count,
            "hot_partition_count": self.hot_partition_count,
            "replication_factor": self.replication_factor,
            "lock_lease_blocks": self.lock_lease_blocks,
            "handoff_window_blocks": self.handoff_window_blocks,
            "da_retention_blocks": self.da_retention_blocks,
            "pq_attestations_required": self.pq_attestations_required,
            "privacy_witness_required": self.privacy_witness_required,
            "low_fee_lanes_enabled": self.low_fee_lanes_enabled,
            "access_policy_root": self.access_policy_root,
            "routing_table_root": self.routing_table_root,
            "status": self.status,
        })
    }

    pub fn config_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-TOPOLOGY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.topology_id, "topology id")?;
        ensure_positive(self.shard_count, "topology shard count")?;
        ensure_positive(self.hot_partition_count, "topology hot partition count")?;
        ensure_positive(self.replication_factor, "topology replication factor")?;
        ensure_positive(self.lock_lease_blocks, "topology lock lease blocks")?;
        ensure_positive(self.handoff_window_blocks, "topology handoff window blocks")?;
        ensure_positive(self.da_retention_blocks, "topology DA retention blocks")?;
        if self.epoch_end_height < self.epoch_start_height {
            return Err("topology epoch end precedes start".to_string());
        }
        if self.replication_factor > self.shard_count {
            return Err("topology replication factor exceeds shard count".to_string());
        }
        ensure_non_empty(&self.access_policy_root, "topology access policy root")?;
        ensure_non_empty(&self.routing_table_root, "topology routing table root")?;
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "topology status",
        )?;
        let expected = shard_topology_id(
            self.epoch,
            self.epoch_start_height,
            self.epoch_end_height,
            self.shard_count,
            self.hot_partition_count,
            &self.routing_table_root,
        );
        if self.topology_id != expected {
            return Err("topology id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateShard {
    pub shard_id: ShardId,
    pub topology_id: String,
    pub shard_index: u64,
    pub partition_kind: ShardPartitionKind,
    pub access_classes: Vec<ShardAccessClass>,
    pub keyspace_start_root: String,
    pub keyspace_end_root: String,
    pub replica_set: Vec<String>,
    pub primary_operator_id: String,
    pub current_state_root: String,
    pub hot_state_root: String,
    pub data_availability_root: String,
    pub routing_hint_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl StateShard {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        topology_id: impl Into<String>,
        shard_index: u64,
        partition_kind: ShardPartitionKind,
        access_classes: Vec<ShardAccessClass>,
        replica_set: Vec<String>,
        primary_operator_id: impl Into<String>,
        created_at_height: u64,
    ) -> StateShardingResult<Self> {
        let topology_id = topology_id.into();
        let primary_operator_id = primary_operator_id.into();
        ensure_non_empty(&topology_id, "state shard topology id")?;
        ensure_non_empty(&primary_operator_id, "state shard primary operator id")?;
        if access_classes.is_empty() {
            return Err("state shard requires at least one access class".to_string());
        }
        if replica_set.is_empty() {
            return Err("state shard requires at least one replica".to_string());
        }
        let keyspace_start_root = shard_keyspace_boundary_root(&topology_id, shard_index, "start");
        let keyspace_end_root = shard_keyspace_boundary_root(&topology_id, shard_index, "end");
        let shard_id = state_shard_id(&topology_id, shard_index, &partition_kind);
        Ok(Self {
            shard_id,
            topology_id,
            shard_index,
            partition_kind,
            access_classes,
            keyspace_start_root,
            keyspace_end_root,
            replica_set,
            primary_operator_id,
            current_state_root: merkle_root("STATE-SHARD-CURRENT", &[]),
            hot_state_root: merkle_root("STATE-SHARD-HOT", &[]),
            data_availability_root: merkle_root("STATE-SHARD-DA", &[]),
            routing_hint_root: merkle_root("STATE-SHARD-ROUTING-HINT", &[]),
            created_at_height,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn accepts(&self, access_class: &ShardAccessClass) -> bool {
        self.access_classes
            .iter()
            .any(|class| class == access_class)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_shard",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "shard_id": self.shard_id,
            "topology_id": self.topology_id,
            "shard_index": self.shard_index,
            "partition_kind": self.partition_kind.label(),
            "access_classes": self.access_classes.iter().map(ShardAccessClass::label).collect::<Vec<_>>(),
            "keyspace_start_root": self.keyspace_start_root,
            "keyspace_end_root": self.keyspace_end_root,
            "replica_set": self.replica_set,
            "primary_operator_id": self.primary_operator_id,
            "current_state_root": self.current_state_root,
            "hot_state_root": self.hot_state_root,
            "data_availability_root": self.data_availability_root,
            "routing_hint_root": self.routing_hint_root,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn shard_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARD", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.shard_id, "state shard id")?;
        ensure_non_empty(&self.topology_id, "state shard topology id")?;
        ensure_non_empty(&self.primary_operator_id, "state shard primary operator id")?;
        ensure_non_empty(&self.keyspace_start_root, "state shard keyspace start root")?;
        ensure_non_empty(&self.keyspace_end_root, "state shard keyspace end root")?;
        ensure_non_empty(&self.current_state_root, "state shard current state root")?;
        ensure_non_empty(&self.hot_state_root, "state shard hot state root")?;
        ensure_non_empty(
            &self.data_availability_root,
            "state shard data availability root",
        )?;
        if self.access_classes.is_empty() {
            return Err("state shard access classes cannot be empty".to_string());
        }
        ensure_unique_strings(
            self.access_classes
                .iter()
                .map(ShardAccessClass::label)
                .collect::<Vec<_>>(),
            "state shard access classes",
        )?;
        ensure_unique_strings(self.replica_set.clone(), "state shard replica set")?;
        if !self.replica_set.contains(&self.primary_operator_id) {
            return Err("state shard primary operator must be in replica set".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
                STATE_SHARDING_STATUS_QUARANTINED,
            ],
            "state shard status",
        )?;
        let expected = state_shard_id(&self.topology_id, self.shard_index, &self.partition_kind);
        if self.shard_id != expected {
            return Err("state shard id mismatch".to_string());
        }
        Ok(self.shard_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotStatePartition {
    pub partition_id: PartitionId,
    pub shard_id: ShardId,
    pub bucket_index: u64,
    pub partition_kind: ShardPartitionKind,
    pub access_class: ShardAccessClass,
    pub key_bucket_commitment: String,
    pub hot_key_telemetry_root: String,
    pub privacy_witness_root: String,
    pub cache_policy_id: String,
    pub low_fee_lane_id: String,
    pub target_latency_ms: u64,
    pub max_parallel_reads: u64,
    pub max_parallel_writes: u64,
    pub created_at_height: u64,
    pub status: String,
}

impl HotStatePartition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: impl Into<String>,
        bucket_index: u64,
        partition_kind: ShardPartitionKind,
        access_class: ShardAccessClass,
        cache_policy_id: impl Into<String>,
        low_fee_lane_id: impl Into<String>,
        created_at_height: u64,
    ) -> StateShardingResult<Self> {
        let shard_id = shard_id.into();
        let cache_policy_id = cache_policy_id.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        ensure_non_empty(&shard_id, "hot partition shard id")?;
        ensure_non_empty(&cache_policy_id, "hot partition cache policy id")?;
        let key_bucket_commitment =
            hot_key_bucket_commitment(&shard_id, bucket_index, &access_class, "devnet-bucket");
        let partition_id = hot_state_partition_id(&shard_id, bucket_index, &access_class);
        Ok(Self {
            partition_id,
            shard_id,
            bucket_index,
            partition_kind,
            access_class,
            key_bucket_commitment,
            hot_key_telemetry_root: merkle_root("STATE-SHARDING-HOT-KEY-TELEMETRY", &[]),
            privacy_witness_root: merkle_root("STATE-SHARDING-PRIVACY-WITNESS", &[]),
            cache_policy_id,
            low_fee_lane_id,
            target_latency_ms: 250,
            max_parallel_reads: 8_192,
            max_parallel_writes: 2_048,
            created_at_height,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "hot_state_partition",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "partition_id": self.partition_id,
            "shard_id": self.shard_id,
            "bucket_index": self.bucket_index,
            "partition_kind": self.partition_kind.label(),
            "access_class": self.access_class.label(),
            "key_bucket_commitment": self.key_bucket_commitment,
            "hot_key_telemetry_root": self.hot_key_telemetry_root,
            "privacy_witness_root": self.privacy_witness_root,
            "cache_policy_id": self.cache_policy_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "target_latency_ms": self.target_latency_ms,
            "max_parallel_reads": self.max_parallel_reads,
            "max_parallel_writes": self.max_parallel_writes,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn partition_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-HOT-PARTITION", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.partition_id, "hot partition id")?;
        ensure_non_empty(&self.shard_id, "hot partition shard id")?;
        ensure_non_empty(
            &self.key_bucket_commitment,
            "hot partition key bucket commitment",
        )?;
        ensure_non_empty(&self.hot_key_telemetry_root, "hot partition telemetry root")?;
        ensure_non_empty(&self.privacy_witness_root, "hot partition witness root")?;
        ensure_non_empty(&self.cache_policy_id, "hot partition cache policy id")?;
        ensure_positive(self.target_latency_ms, "hot partition target latency")?;
        ensure_positive(self.max_parallel_reads, "hot partition max parallel reads")?;
        ensure_positive(
            self.max_parallel_writes,
            "hot partition max parallel writes",
        )?;
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "hot partition status",
        )?;
        let expected =
            hot_state_partition_id(&self.shard_id, self.bucket_index, &self.access_class);
        if self.partition_id != expected {
            return Err("hot partition id mismatch".to_string());
        }
        Ok(self.partition_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingRule {
    pub rule_id: RoutingRuleId,
    pub table_id: RoutingTableId,
    pub key_prefix_commitment: String,
    pub partition_kind: ShardPartitionKind,
    pub access_class: ShardAccessClass,
    pub primary_shard_id: ShardId,
    pub fallback_shard_ids: Vec<ShardId>,
    pub low_fee_lane_id: String,
    pub da_lane_id: String,
    pub priority: u64,
    pub privacy_witness_required: bool,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl RoutingRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        table_id: impl Into<String>,
        key_prefix_label: impl Into<String>,
        partition_kind: ShardPartitionKind,
        access_class: ShardAccessClass,
        primary_shard_id: impl Into<String>,
        fallback_shard_ids: Vec<ShardId>,
        low_fee_lane_id: impl Into<String>,
        da_lane_id: impl Into<String>,
        priority: u64,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> StateShardingResult<Self> {
        let table_id = table_id.into();
        let key_prefix_label = key_prefix_label.into();
        let primary_shard_id = primary_shard_id.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        let da_lane_id = da_lane_id.into();
        ensure_non_empty(&table_id, "routing rule table id")?;
        ensure_non_empty(&key_prefix_label, "routing rule key prefix")?;
        ensure_non_empty(&primary_shard_id, "routing rule primary shard id")?;
        let key_prefix_commitment = state_sharding_string_root(
            "STATE-SHARDING-KEY-PREFIX",
            &format!("{table_id}:{key_prefix_label}"),
        );
        let rule_id = routing_rule_id(
            &table_id,
            &key_prefix_commitment,
            &partition_kind,
            &access_class,
            &primary_shard_id,
            priority,
        );
        Ok(Self {
            rule_id,
            table_id,
            key_prefix_commitment,
            partition_kind,
            access_class: access_class.clone(),
            primary_shard_id,
            fallback_shard_ids,
            low_fee_lane_id,
            da_lane_id,
            priority,
            privacy_witness_required: access_class.privacy_sensitive(),
            valid_from_height,
            expires_at_height,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == STATE_SHARDING_STATUS_ACTIVE
            && height >= self.valid_from_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_sharding_routing_rule",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "rule_id": self.rule_id,
            "table_id": self.table_id,
            "key_prefix_commitment": self.key_prefix_commitment,
            "partition_kind": self.partition_kind.label(),
            "access_class": self.access_class.label(),
            "primary_shard_id": self.primary_shard_id,
            "fallback_shard_ids": self.fallback_shard_ids,
            "low_fee_lane_id": self.low_fee_lane_id,
            "da_lane_id": self.da_lane_id,
            "priority": self.priority,
            "privacy_witness_required": self.privacy_witness_required,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn rule_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-ROUTING-RULE", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.rule_id, "routing rule id")?;
        ensure_non_empty(&self.table_id, "routing rule table id")?;
        ensure_non_empty(
            &self.key_prefix_commitment,
            "routing rule key prefix commitment",
        )?;
        ensure_non_empty(&self.primary_shard_id, "routing rule primary shard id")?;
        ensure_unique_strings(
            self.fallback_shard_ids.clone(),
            "routing rule fallback shard ids",
        )?;
        if self.expires_at_height > 0 && self.expires_at_height < self.valid_from_height {
            return Err("routing rule expires before it becomes valid".to_string());
        }
        if self.privacy_witness_required && !self.access_class.privacy_sensitive() {
            return Err(
                "routing rule requires privacy witness for non-sensitive class".to_string(),
            );
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "routing rule status",
        )?;
        let expected = routing_rule_id(
            &self.table_id,
            &self.key_prefix_commitment,
            &self.partition_kind,
            &self.access_class,
            &self.primary_shard_id,
            self.priority,
        );
        if self.rule_id != expected {
            return Err("routing rule id mismatch".to_string());
        }
        Ok(self.rule_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingTable {
    pub table_id: RoutingTableId,
    pub topology_id: String,
    pub epoch: u64,
    pub height: u64,
    pub rules: Vec<RoutingRule>,
    pub fallback_shard_id: ShardId,
    pub table_commitment: String,
    pub status: String,
}

impl RoutingTable {
    pub fn new(
        topology_id: impl Into<String>,
        epoch: u64,
        height: u64,
        fallback_shard_id: impl Into<String>,
        rules: Vec<RoutingRule>,
    ) -> StateShardingResult<Self> {
        let topology_id = topology_id.into();
        let fallback_shard_id = fallback_shard_id.into();
        ensure_non_empty(&topology_id, "routing table topology id")?;
        ensure_non_empty(&fallback_shard_id, "routing table fallback shard id")?;
        let table_id = routing_table_id(&topology_id, epoch, height);
        let table_commitment = routing_rule_root(&rules);
        Ok(Self {
            table_id,
            topology_id,
            epoch,
            height,
            rules,
            fallback_shard_id,
            table_commitment,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn route_for_key(
        &self,
        access_class: &ShardAccessClass,
        key_material: &str,
        height: u64,
    ) -> Option<&RoutingRule> {
        self.rules
            .iter()
            .filter(|rule| rule.is_active_at(height) && rule.access_class == *access_class)
            .min_by(|left, right| {
                let left_score = routing_score(&self.table_id, &left.rule_id, key_material);
                let right_score = routing_score(&self.table_id, &right.rule_id, key_material);
                left_score
                    .cmp(&right_score)
                    .then_with(|| right.priority.cmp(&left.priority))
                    .then_with(|| left.rule_id.cmp(&right.rule_id))
            })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_sharding_routing_table",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "table_id": self.table_id,
            "topology_id": self.topology_id,
            "epoch": self.epoch,
            "height": self.height,
            "rules": self.rules.iter().map(RoutingRule::public_record).collect::<Vec<_>>(),
            "fallback_shard_id": self.fallback_shard_id,
            "table_commitment": self.table_commitment,
            "status": self.status,
        })
    }

    pub fn table_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-ROUTING-TABLE", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.table_id, "routing table id")?;
        ensure_non_empty(&self.topology_id, "routing table topology id")?;
        ensure_non_empty(&self.fallback_shard_id, "routing table fallback shard id")?;
        ensure_non_empty(&self.table_commitment, "routing table commitment")?;
        let mut rule_ids = BTreeSet::new();
        for rule in &self.rules {
            if rule.table_id != self.table_id {
                return Err("routing table contains rule for another table".to_string());
            }
            rule.validate()?;
            if !rule_ids.insert(rule.rule_id.clone()) {
                return Err("routing table contains duplicate rule id".to_string());
            }
        }
        let expected_table_id = routing_table_id(&self.topology_id, self.epoch, self.height);
        if self.table_id != expected_table_id {
            return Err("routing table id mismatch".to_string());
        }
        let expected_commitment = routing_rule_root(&self.rules);
        if self.table_commitment != expected_commitment {
            return Err("routing table commitment mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "routing table status",
        )?;
        Ok(self.table_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyWitnessCommitment {
    pub witness_id: String,
    pub shard_id: ShardId,
    pub access_class: ShardAccessClass,
    pub blinded_key_root: String,
    pub old_state_root: String,
    pub new_state_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub nullifier_bucket_root: String,
    pub transcript_root: String,
    pub proof_system: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyWitnessCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: impl Into<String>,
        access_class: ShardAccessClass,
        blinded_key_root: impl Into<String>,
        old_state_root: impl Into<String>,
        new_state_root: impl Into<String>,
        read_set_root: impl Into<String>,
        write_set_root: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> StateShardingResult<Self> {
        let shard_id = shard_id.into();
        let blinded_key_root = blinded_key_root.into();
        let old_state_root = old_state_root.into();
        let new_state_root = new_state_root.into();
        let read_set_root = read_set_root.into();
        let write_set_root = write_set_root.into();
        ensure_non_empty(&shard_id, "privacy witness shard id")?;
        ensure_non_empty(&blinded_key_root, "privacy witness blinded key root")?;
        let nullifier_bucket_root = privacy_nullifier_bucket_root(&shard_id, &blinded_key_root);
        let transcript_root = privacy_witness_transcript_root(
            &shard_id,
            &access_class,
            &blinded_key_root,
            &old_state_root,
            &new_state_root,
            &read_set_root,
            &write_set_root,
            created_at_height,
        );
        let witness_id = privacy_witness_id(
            &shard_id,
            &access_class,
            &blinded_key_root,
            &old_state_root,
            &new_state_root,
            created_at_height,
        );
        Ok(Self {
            witness_id,
            shard_id,
            access_class,
            blinded_key_root,
            old_state_root,
            new_state_root,
            read_set_root,
            write_set_root,
            nullifier_bucket_root,
            transcript_root,
            proof_system: STATE_SHARDING_PRIVACY_SCHEME.to_string(),
            created_at_height,
            expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_safe_state_witness_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "witness_id": self.witness_id,
            "shard_id": self.shard_id,
            "access_class": self.access_class.label(),
            "blinded_key_root": self.blinded_key_root,
            "old_state_root": self.old_state_root,
            "new_state_root": self.new_state_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "nullifier_bucket_root": self.nullifier_bucket_root,
            "transcript_root": self.transcript_root,
            "proof_system": self.proof_system,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn witness_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-PRIVACY-WITNESS", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.witness_id, "privacy witness id")?;
        ensure_non_empty(&self.shard_id, "privacy witness shard id")?;
        ensure_non_empty(&self.blinded_key_root, "privacy witness blinded key root")?;
        ensure_non_empty(&self.old_state_root, "privacy witness old state root")?;
        ensure_non_empty(&self.new_state_root, "privacy witness new state root")?;
        ensure_non_empty(&self.read_set_root, "privacy witness read set root")?;
        ensure_non_empty(&self.write_set_root, "privacy witness write set root")?;
        ensure_non_empty(
            &self.nullifier_bucket_root,
            "privacy witness nullifier bucket root",
        )?;
        ensure_non_empty(&self.transcript_root, "privacy witness transcript root")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("privacy witness expiry must exceed creation height".to_string());
        }
        if !self.access_class.privacy_sensitive() {
            return Err("privacy witness must use a privacy-sensitive access class".to_string());
        }
        let expected = privacy_witness_id(
            &self.shard_id,
            &self.access_class,
            &self.blinded_key_root,
            &self.old_state_root,
            &self.new_state_root,
            self.created_at_height,
        );
        if self.witness_id != expected {
            return Err("privacy witness id mismatch".to_string());
        }
        Ok(self.witness_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotKeyTelemetryBucket {
    pub telemetry_id: String,
    pub shard_id: ShardId,
    pub partition_id: PartitionId,
    pub epoch: u64,
    pub bucket_index: u64,
    pub key_bucket_commitment: String,
    pub read_count_bucket: u64,
    pub write_count_bucket: u64,
    pub contention_score_bucket: u64,
    pub fee_pressure_bucket: u64,
    pub sample_count: u64,
    pub telemetry_root: String,
    pub created_at_height: u64,
}

impl HotKeyTelemetryBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: impl Into<String>,
        partition_id: impl Into<String>,
        epoch: u64,
        bucket_index: u64,
        bucket_label: impl Into<String>,
        read_count: u64,
        write_count: u64,
        fee_pressure_bps: u64,
        created_at_height: u64,
    ) -> StateShardingResult<Self> {
        let shard_id = shard_id.into();
        let partition_id = partition_id.into();
        let bucket_label = bucket_label.into();
        ensure_non_empty(&shard_id, "hot telemetry shard id")?;
        ensure_non_empty(&partition_id, "hot telemetry partition id")?;
        ensure_non_empty(&bucket_label, "hot telemetry bucket label")?;
        ensure_bps(fee_pressure_bps, "hot telemetry fee pressure")?;
        let read_count_bucket = bucket_count(read_count);
        let write_count_bucket = bucket_count(write_count);
        let contention_score_bucket = bucket_count(read_count.saturating_add(write_count));
        let fee_pressure_bucket = bucket_bps(fee_pressure_bps);
        let key_bucket_commitment = hot_key_bucket_commitment(
            &shard_id,
            bucket_index,
            &ShardAccessClass::PublicRead,
            &bucket_label,
        );
        let telemetry_id = hot_key_telemetry_id(&shard_id, &partition_id, epoch, bucket_index);
        let telemetry_root = telemetry_bucket_root_from_parts(
            &shard_id,
            &partition_id,
            epoch,
            bucket_index,
            &key_bucket_commitment,
            read_count_bucket,
            write_count_bucket,
            contention_score_bucket,
            fee_pressure_bucket,
        );
        Ok(Self {
            telemetry_id,
            shard_id,
            partition_id,
            epoch,
            bucket_index,
            key_bucket_commitment,
            read_count_bucket,
            write_count_bucket,
            contention_score_bucket,
            fee_pressure_bucket,
            sample_count: read_count.saturating_add(write_count),
            telemetry_root,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bucketed_hot_key_telemetry",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "privacy_scheme": STATE_SHARDING_PRIVACY_SCHEME,
            "telemetry_id": self.telemetry_id,
            "shard_id": self.shard_id,
            "partition_id": self.partition_id,
            "epoch": self.epoch,
            "bucket_index": self.bucket_index,
            "key_bucket_commitment": self.key_bucket_commitment,
            "read_count_bucket": self.read_count_bucket,
            "write_count_bucket": self.write_count_bucket,
            "contention_score_bucket": self.contention_score_bucket,
            "fee_pressure_bucket": self.fee_pressure_bucket,
            "sample_count": self.sample_count,
            "telemetry_root": self.telemetry_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.telemetry_id, "hot telemetry id")?;
        ensure_non_empty(&self.shard_id, "hot telemetry shard id")?;
        ensure_non_empty(&self.partition_id, "hot telemetry partition id")?;
        ensure_non_empty(
            &self.key_bucket_commitment,
            "hot telemetry bucket commitment",
        )?;
        ensure_non_empty(&self.telemetry_root, "hot telemetry root")?;
        ensure_bps(
            self.fee_pressure_bucket,
            "hot telemetry fee pressure bucket",
        )?;
        let expected_id = hot_key_telemetry_id(
            &self.shard_id,
            &self.partition_id,
            self.epoch,
            self.bucket_index,
        );
        if self.telemetry_id != expected_id {
            return Err("hot telemetry id mismatch".to_string());
        }
        let expected_root = telemetry_bucket_root_from_parts(
            &self.shard_id,
            &self.partition_id,
            self.epoch,
            self.bucket_index,
            &self.key_bucket_commitment,
            self.read_count_bucket,
            self.write_count_bucket,
            self.contention_score_bucket,
            self.fee_pressure_bucket,
        );
        if self.telemetry_root != expected_root {
            return Err("hot telemetry root mismatch".to_string());
        }
        Ok(state_sharding_payload_root(
            "STATE-SHARDING-HOT-KEY-TELEMETRY-RECORD",
            &self.public_record(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRoot {
    pub rollback_id: String,
    pub bundle_id: AtomicBundleId,
    pub shard_id: ShardId,
    pub pre_state_root: String,
    pub inverse_delta_root: String,
    pub witness_root: String,
    pub reason_code: String,
    pub created_at_height: u64,
}

impl RollbackRoot {
    pub fn new(
        bundle_id: impl Into<String>,
        shard_id: impl Into<String>,
        pre_state_root: impl Into<String>,
        inverse_delta_root: impl Into<String>,
        witness_root: impl Into<String>,
        reason_code: impl Into<String>,
        created_at_height: u64,
    ) -> StateShardingResult<Self> {
        let bundle_id = bundle_id.into();
        let shard_id = shard_id.into();
        let pre_state_root = pre_state_root.into();
        let inverse_delta_root = inverse_delta_root.into();
        let witness_root = witness_root.into();
        let reason_code = reason_code.into();
        ensure_non_empty(&bundle_id, "rollback bundle id")?;
        ensure_non_empty(&shard_id, "rollback shard id")?;
        ensure_non_empty(&pre_state_root, "rollback pre-state root")?;
        ensure_non_empty(&inverse_delta_root, "rollback inverse delta root")?;
        ensure_non_empty(&witness_root, "rollback witness root")?;
        ensure_non_empty(&reason_code, "rollback reason code")?;
        let rollback_id = rollback_root_id(
            &bundle_id,
            &shard_id,
            &pre_state_root,
            &inverse_delta_root,
            created_at_height,
        );
        Ok(Self {
            rollback_id,
            bundle_id,
            shard_id,
            pre_state_root,
            inverse_delta_root,
            witness_root,
            reason_code,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_sharding_rollback_root",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "rollback_id": self.rollback_id,
            "bundle_id": self.bundle_id,
            "shard_id": self.shard_id,
            "pre_state_root": self.pre_state_root,
            "inverse_delta_root": self.inverse_delta_root,
            "witness_root": self.witness_root,
            "reason_code": self.reason_code,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn rollback_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-ROLLBACK-ROOT", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.rollback_id, "rollback id")?;
        ensure_non_empty(&self.bundle_id, "rollback bundle id")?;
        ensure_non_empty(&self.shard_id, "rollback shard id")?;
        ensure_non_empty(&self.pre_state_root, "rollback pre-state root")?;
        ensure_non_empty(&self.inverse_delta_root, "rollback inverse delta root")?;
        ensure_non_empty(&self.witness_root, "rollback witness root")?;
        ensure_non_empty(&self.reason_code, "rollback reason code")?;
        let expected = rollback_root_id(
            &self.bundle_id,
            &self.shard_id,
            &self.pre_state_root,
            &self.inverse_delta_root,
            self.created_at_height,
        );
        if self.rollback_id != expected {
            return Err("rollback id mismatch".to_string());
        }
        Ok(self.rollback_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicShardLockLease {
    pub lease_id: LockLeaseId,
    pub bundle_id: AtomicBundleId,
    pub shard_id: ShardId,
    pub lock_mode: LockLeaseMode,
    pub owner_commitment: String,
    pub resource_root: String,
    pub rollback_root: String,
    pub acquired_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl AtomicShardLockLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        shard_id: impl Into<String>,
        lock_mode: LockLeaseMode,
        owner_commitment: impl Into<String>,
        resource_root: impl Into<String>,
        rollback_root: impl Into<String>,
        acquired_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> StateShardingResult<Self> {
        let bundle_id = bundle_id.into();
        let shard_id = shard_id.into();
        let owner_commitment = owner_commitment.into();
        let resource_root = resource_root.into();
        let rollback_root = rollback_root.into();
        ensure_non_empty(&bundle_id, "lock lease bundle id")?;
        ensure_non_empty(&shard_id, "lock lease shard id")?;
        ensure_non_empty(&owner_commitment, "lock lease owner commitment")?;
        ensure_non_empty(&resource_root, "lock lease resource root")?;
        if expires_at_height <= acquired_at_height {
            return Err("lock lease expiry must exceed acquisition height".to_string());
        }
        let lease_id = lock_lease_id(
            &bundle_id,
            &shard_id,
            &lock_mode,
            &owner_commitment,
            acquired_at_height,
            nonce,
        );
        Ok(Self {
            lease_id,
            bundle_id,
            shard_id,
            lock_mode,
            owner_commitment,
            resource_root,
            rollback_root,
            acquired_at_height,
            expires_at_height,
            nonce,
            status: STATE_SHARDING_STATUS_PREPARED.to_string(),
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        (self.status == STATE_SHARDING_STATUS_ACTIVE
            || self.status == STATE_SHARDING_STATUS_PREPARED)
            && height >= self.acquired_at_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "atomic_shard_lock_lease",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "lease_id": self.lease_id,
            "bundle_id": self.bundle_id,
            "shard_id": self.shard_id,
            "lock_mode": self.lock_mode.label(),
            "owner_commitment": self.owner_commitment,
            "resource_root": self.resource_root,
            "rollback_root": self.rollback_root,
            "acquired_at_height": self.acquired_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn lease_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-LOCK-LEASE", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.lease_id, "lock lease id")?;
        ensure_non_empty(&self.bundle_id, "lock lease bundle id")?;
        ensure_non_empty(&self.shard_id, "lock lease shard id")?;
        ensure_non_empty(&self.owner_commitment, "lock lease owner commitment")?;
        ensure_non_empty(&self.resource_root, "lock lease resource root")?;
        ensure_non_empty(&self.rollback_root, "lock lease rollback root")?;
        if self.expires_at_height <= self.acquired_at_height {
            return Err("lock lease expiry must exceed acquisition height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PREPARED,
                STATE_SHARDING_STATUS_COMMITTED,
                STATE_SHARDING_STATUS_ROLLED_BACK,
                STATE_SHARDING_STATUS_EXPIRED,
            ],
            "lock lease status",
        )?;
        let expected = lock_lease_id(
            &self.bundle_id,
            &self.shard_id,
            &self.lock_mode,
            &self.owner_commitment,
            self.acquired_at_height,
            self.nonce,
        );
        if self.lease_id != expected {
            return Err("lock lease id mismatch".to_string());
        }
        Ok(self.lease_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardHandoffReceipt {
    pub receipt_id: HandoffReceiptId,
    pub bundle_id: AtomicBundleId,
    pub from_shard_id: ShardId,
    pub to_shard_id: ShardId,
    pub state_delta_root: String,
    pub witness_root: String,
    pub data_availability_root: String,
    pub lock_release_root: String,
    pub pq_attestation_root: String,
    pub accepted_at_height: u64,
    pub status: String,
}

impl ShardHandoffReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bundle_id: impl Into<String>,
        from_shard_id: impl Into<String>,
        to_shard_id: impl Into<String>,
        state_delta_root: impl Into<String>,
        witness_root: impl Into<String>,
        data_availability_root: impl Into<String>,
        lock_release_root: impl Into<String>,
        pq_attestation_root: impl Into<String>,
        accepted_at_height: u64,
    ) -> StateShardingResult<Self> {
        let bundle_id = bundle_id.into();
        let from_shard_id = from_shard_id.into();
        let to_shard_id = to_shard_id.into();
        let state_delta_root = state_delta_root.into();
        let witness_root = witness_root.into();
        let data_availability_root = data_availability_root.into();
        let lock_release_root = lock_release_root.into();
        let pq_attestation_root = pq_attestation_root.into();
        ensure_non_empty(&bundle_id, "handoff bundle id")?;
        ensure_non_empty(&from_shard_id, "handoff from shard id")?;
        ensure_non_empty(&to_shard_id, "handoff to shard id")?;
        if from_shard_id == to_shard_id {
            return Err("handoff receipt cannot target the same shard".to_string());
        }
        let receipt_id = handoff_receipt_id(
            &bundle_id,
            &from_shard_id,
            &to_shard_id,
            &state_delta_root,
            accepted_at_height,
        );
        Ok(Self {
            receipt_id,
            bundle_id,
            from_shard_id,
            to_shard_id,
            state_delta_root,
            witness_root,
            data_availability_root,
            lock_release_root,
            pq_attestation_root,
            accepted_at_height,
            status: STATE_SHARDING_STATUS_COMMITTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_shard_handoff_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "from_shard_id": self.from_shard_id,
            "to_shard_id": self.to_shard_id,
            "state_delta_root": self.state_delta_root,
            "witness_root": self.witness_root,
            "data_availability_root": self.data_availability_root,
            "lock_release_root": self.lock_release_root,
            "pq_attestation_root": self.pq_attestation_root,
            "accepted_at_height": self.accepted_at_height,
            "status": self.status,
        })
    }

    pub fn receipt_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-HANDOFF-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.receipt_id, "handoff receipt id")?;
        ensure_non_empty(&self.bundle_id, "handoff bundle id")?;
        ensure_non_empty(&self.from_shard_id, "handoff from shard id")?;
        ensure_non_empty(&self.to_shard_id, "handoff to shard id")?;
        ensure_non_empty(&self.state_delta_root, "handoff state delta root")?;
        ensure_non_empty(&self.witness_root, "handoff witness root")?;
        ensure_non_empty(&self.data_availability_root, "handoff DA root")?;
        ensure_non_empty(&self.lock_release_root, "handoff lock release root")?;
        ensure_non_empty(&self.pq_attestation_root, "handoff PQ attestation root")?;
        if self.from_shard_id == self.to_shard_id {
            return Err("handoff receipt has identical source and destination".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_PREPARED,
                STATE_SHARDING_STATUS_COMMITTED,
                STATE_SHARDING_STATUS_ROLLED_BACK,
            ],
            "handoff receipt status",
        )?;
        let expected = handoff_receipt_id(
            &self.bundle_id,
            &self.from_shard_id,
            &self.to_shard_id,
            &self.state_delta_root,
            self.accepted_at_height,
        );
        if self.receipt_id != expected {
            return Err("handoff receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossShardAtomicBundle {
    pub bundle_id: AtomicBundleId,
    pub coordinator_shard_id: ShardId,
    pub participant_shard_ids: Vec<ShardId>,
    pub read_set_root: String,
    pub write_set_root: String,
    pub lock_lease_root: String,
    pub handoff_receipt_root: String,
    pub rollback_root: String,
    pub fee_lane_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl CrossShardAtomicBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinator_shard_id: impl Into<String>,
        participant_shard_ids: Vec<ShardId>,
        read_set_root: impl Into<String>,
        write_set_root: impl Into<String>,
        fee_lane_id: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> StateShardingResult<Self> {
        let coordinator_shard_id = coordinator_shard_id.into();
        let read_set_root = read_set_root.into();
        let write_set_root = write_set_root.into();
        let fee_lane_id = fee_lane_id.into();
        ensure_non_empty(&coordinator_shard_id, "atomic bundle coordinator shard id")?;
        ensure_non_empty(&read_set_root, "atomic bundle read set root")?;
        ensure_non_empty(&write_set_root, "atomic bundle write set root")?;
        if participant_shard_ids.is_empty() {
            return Err("atomic bundle requires participant shards".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("atomic bundle expiry must exceed creation height".to_string());
        }
        ensure_unique_strings(
            participant_shard_ids.clone(),
            "atomic bundle participant shards",
        )?;
        let bundle_id = cross_shard_atomic_bundle_id(
            &coordinator_shard_id,
            &participant_shard_ids,
            &read_set_root,
            &write_set_root,
            created_at_height,
        );
        Ok(Self {
            bundle_id,
            coordinator_shard_id,
            participant_shard_ids,
            read_set_root,
            write_set_root,
            lock_lease_root: merkle_root("STATE-SHARDING-LOCK-LEASE", &[]),
            handoff_receipt_root: merkle_root("STATE-SHARDING-HANDOFF-RECEIPT", &[]),
            rollback_root: merkle_root("STATE-SHARDING-ROLLBACK-ROOT", &[]),
            fee_lane_id,
            created_at_height,
            expires_at_height,
            status: STATE_SHARDING_STATUS_PREPARED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_shard_atomic_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "coordinator_shard_id": self.coordinator_shard_id,
            "participant_shard_ids": self.participant_shard_ids,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "lock_lease_root": self.lock_lease_root,
            "handoff_receipt_root": self.handoff_receipt_root,
            "rollback_root": self.rollback_root,
            "fee_lane_id": self.fee_lane_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn bundle_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-ATOMIC-BUNDLE", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.bundle_id, "atomic bundle id")?;
        ensure_non_empty(
            &self.coordinator_shard_id,
            "atomic bundle coordinator shard id",
        )?;
        ensure_non_empty(&self.read_set_root, "atomic bundle read set root")?;
        ensure_non_empty(&self.write_set_root, "atomic bundle write set root")?;
        ensure_non_empty(&self.lock_lease_root, "atomic bundle lock lease root")?;
        ensure_non_empty(
            &self.handoff_receipt_root,
            "atomic bundle handoff receipt root",
        )?;
        ensure_non_empty(&self.rollback_root, "atomic bundle rollback root")?;
        if self.participant_shard_ids.is_empty() {
            return Err("atomic bundle participant shards cannot be empty".to_string());
        }
        ensure_unique_strings(
            self.participant_shard_ids.clone(),
            "atomic bundle participant shards",
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("atomic bundle expiry must exceed creation height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_PREPARED,
                STATE_SHARDING_STATUS_COMMITTED,
                STATE_SHARDING_STATUS_ROLLED_BACK,
                STATE_SHARDING_STATUS_EXPIRED,
            ],
            "atomic bundle status",
        )?;
        let expected = cross_shard_atomic_bundle_id(
            &self.coordinator_shard_id,
            &self.participant_shard_ids,
            &self.read_set_root,
            &self.write_set_root,
            self.created_at_height,
        );
        if self.bundle_id != expected {
            return Err("atomic bundle id mismatch".to_string());
        }
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardAssignment {
    pub assignment_id: AssignmentId,
    pub epoch: u64,
    pub shard_id: ShardId,
    pub operator_id: String,
    pub role: ShardAssignmentRole,
    pub stake_weight: u64,
    pub capacity_units: u64,
    pub pq_key_commitment_root: String,
    pub lane_permissions: Vec<String>,
    pub duty_start_height: u64,
    pub duty_end_height: u64,
    pub status: String,
}

impl ShardAssignment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        shard_id: impl Into<String>,
        operator_id: impl Into<String>,
        role: ShardAssignmentRole,
        stake_weight: u64,
        capacity_units: u64,
        duty_start_height: u64,
        duty_end_height: u64,
        lane_permissions: Vec<String>,
    ) -> StateShardingResult<Self> {
        let shard_id = shard_id.into();
        let operator_id = operator_id.into();
        ensure_non_empty(&shard_id, "shard assignment shard id")?;
        ensure_non_empty(&operator_id, "shard assignment operator id")?;
        ensure_positive(stake_weight, "shard assignment stake weight")?;
        ensure_positive(capacity_units, "shard assignment capacity units")?;
        if duty_end_height < duty_start_height {
            return Err("shard assignment duty end precedes start".to_string());
        }
        let pq_key_commitment_root = pq_operator_key_commitment_root(&operator_id, &role);
        let assignment_id =
            shard_assignment_id(epoch, &shard_id, &operator_id, &role, duty_start_height);
        Ok(Self {
            assignment_id,
            epoch,
            shard_id,
            operator_id,
            role,
            stake_weight,
            capacity_units,
            pq_key_commitment_root,
            lane_permissions,
            duty_start_height,
            duty_end_height,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == STATE_SHARDING_STATUS_ACTIVE
            && height >= self.duty_start_height
            && height <= self.duty_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sequencer_validator_shard_assignment",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "assignment_id": self.assignment_id,
            "epoch": self.epoch,
            "shard_id": self.shard_id,
            "operator_id": self.operator_id,
            "role": self.role.label(),
            "stake_weight": self.stake_weight,
            "capacity_units": self.capacity_units,
            "pq_key_commitment_root": self.pq_key_commitment_root,
            "lane_permissions": self.lane_permissions,
            "duty_start_height": self.duty_start_height,
            "duty_end_height": self.duty_end_height,
            "status": self.status,
        })
    }

    pub fn assignment_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-ASSIGNMENT", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.assignment_id, "shard assignment id")?;
        ensure_non_empty(&self.shard_id, "shard assignment shard id")?;
        ensure_non_empty(&self.operator_id, "shard assignment operator id")?;
        ensure_positive(self.stake_weight, "shard assignment stake weight")?;
        ensure_positive(self.capacity_units, "shard assignment capacity units")?;
        ensure_non_empty(
            &self.pq_key_commitment_root,
            "shard assignment PQ key commitment root",
        )?;
        ensure_unique_strings(
            self.lane_permissions.clone(),
            "shard assignment lane permissions",
        )?;
        if self.duty_end_height < self.duty_start_height {
            return Err("shard assignment duty end precedes start".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "shard assignment status",
        )?;
        let expected = shard_assignment_id(
            self.epoch,
            &self.shard_id,
            &self.operator_id,
            &self.role,
            self.duty_start_height,
        );
        if self.assignment_id != expected {
            return Err("shard assignment id mismatch".to_string());
        }
        Ok(self.assignment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqShardAttestation {
    pub attestation_id: PqAttestationId,
    pub shard_id: ShardId,
    pub operator_id: String,
    pub assignment_id: AssignmentId,
    pub attestation_scheme: String,
    pub public_key_commitment_root: String,
    pub signed_payload_root: String,
    pub transcript_root: String,
    pub signature_commitment_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqShardAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: impl Into<String>,
        operator_id: impl Into<String>,
        assignment_id: impl Into<String>,
        public_key_commitment_root: impl Into<String>,
        signed_payload_root: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> StateShardingResult<Self> {
        let shard_id = shard_id.into();
        let operator_id = operator_id.into();
        let assignment_id = assignment_id.into();
        let public_key_commitment_root = public_key_commitment_root.into();
        let signed_payload_root = signed_payload_root.into();
        ensure_non_empty(&shard_id, "PQ shard attestation shard id")?;
        ensure_non_empty(&operator_id, "PQ shard attestation operator id")?;
        ensure_non_empty(&assignment_id, "PQ shard attestation assignment id")?;
        ensure_non_empty(
            &public_key_commitment_root,
            "PQ shard attestation key commitment root",
        )?;
        ensure_non_empty(
            &signed_payload_root,
            "PQ shard attestation signed payload root",
        )?;
        if expires_at_height <= created_at_height {
            return Err("PQ shard attestation expiry must exceed creation height".to_string());
        }
        let transcript_root = pq_shard_attestation_transcript_root(
            &shard_id,
            &operator_id,
            &assignment_id,
            &public_key_commitment_root,
            &signed_payload_root,
            created_at_height,
        );
        let signature_commitment_root = pq_signature_commitment_root(
            &operator_id,
            &transcript_root,
            STATE_SHARDING_PQ_ATTESTATION_SCHEME,
        );
        let attestation_id = pq_shard_attestation_id(
            &shard_id,
            &operator_id,
            &assignment_id,
            &transcript_root,
            created_at_height,
        );
        Ok(Self {
            attestation_id,
            shard_id,
            operator_id,
            assignment_id,
            attestation_scheme: STATE_SHARDING_PQ_ATTESTATION_SCHEME.to_string(),
            public_key_commitment_root,
            signed_payload_root,
            transcript_root,
            signature_commitment_root,
            created_at_height,
            expires_at_height,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_shard_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "shard_id": self.shard_id,
            "operator_id": self.operator_id,
            "assignment_id": self.assignment_id,
            "attestation_scheme": self.attestation_scheme,
            "public_key_commitment_root": self.public_key_commitment_root,
            "signed_payload_root": self.signed_payload_root,
            "transcript_root": self.transcript_root,
            "signature_commitment_root": self.signature_commitment_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn attestation_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-PQ-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.attestation_id, "PQ shard attestation id")?;
        ensure_non_empty(&self.shard_id, "PQ shard attestation shard id")?;
        ensure_non_empty(&self.operator_id, "PQ shard attestation operator id")?;
        ensure_non_empty(&self.assignment_id, "PQ shard attestation assignment id")?;
        ensure_non_empty(
            &self.public_key_commitment_root,
            "PQ shard attestation key commitment root",
        )?;
        ensure_non_empty(
            &self.signed_payload_root,
            "PQ shard attestation signed payload root",
        )?;
        ensure_non_empty(
            &self.transcript_root,
            "PQ shard attestation transcript root",
        )?;
        ensure_non_empty(
            &self.signature_commitment_root,
            "PQ shard attestation signature commitment root",
        )?;
        if self.attestation_scheme != STATE_SHARDING_PQ_ATTESTATION_SCHEME {
            return Err("PQ shard attestation scheme mismatch".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("PQ shard attestation expiry must exceed creation height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_EXPIRED,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_QUARANTINED,
            ],
            "PQ shard attestation status",
        )?;
        let expected_transcript = pq_shard_attestation_transcript_root(
            &self.shard_id,
            &self.operator_id,
            &self.assignment_id,
            &self.public_key_commitment_root,
            &self.signed_payload_root,
            self.created_at_height,
        );
        if self.transcript_root != expected_transcript {
            return Err("PQ shard attestation transcript mismatch".to_string());
        }
        let expected = pq_shard_attestation_id(
            &self.shard_id,
            &self.operator_id,
            &self.assignment_id,
            &self.transcript_root,
            self.created_at_height,
        );
        if self.attestation_id != expected {
            return Err("PQ shard attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCachePolicy {
    pub policy_id: String,
    pub label: String,
    pub eviction_kind: CacheEvictionKind,
    pub max_entries: u64,
    pub max_bytes: u64,
    pub ttl_blocks: u64,
    pub hot_pin_bps: u64,
    pub lease_aware: bool,
    pub da_pinned: bool,
    pub privacy_preserving_misses: bool,
    pub status: String,
}

impl StateCachePolicy {
    pub fn new(
        label: impl Into<String>,
        eviction_kind: CacheEvictionKind,
        max_entries: u64,
        max_bytes: u64,
        ttl_blocks: u64,
        hot_pin_bps: u64,
    ) -> StateShardingResult<Self> {
        let label = label.into();
        ensure_non_empty(&label, "cache policy label")?;
        ensure_positive(max_entries, "cache policy max entries")?;
        ensure_positive(max_bytes, "cache policy max bytes")?;
        ensure_positive(ttl_blocks, "cache policy ttl blocks")?;
        ensure_bps(hot_pin_bps, "cache policy hot pin bps")?;
        let policy_id =
            state_cache_policy_id(&label, &eviction_kind, max_entries, max_bytes, ttl_blocks);
        let lease_aware = eviction_kind == CacheEvictionKind::LeaseAware;
        let da_pinned = eviction_kind == CacheEvictionKind::DaPinned;
        Ok(Self {
            policy_id,
            label,
            eviction_kind,
            max_entries,
            max_bytes,
            ttl_blocks,
            hot_pin_bps,
            lease_aware,
            da_pinned,
            privacy_preserving_misses: true,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn devnet_hot() -> Self {
        Self::new(
            "devnet-hot-state",
            CacheEvictionKind::LeaseAware,
            STATE_SHARDING_DEFAULT_CACHE_ENTRIES,
            STATE_SHARDING_DEFAULT_CACHE_BYTES,
            STATE_SHARDING_DEFAULT_CACHE_TTL_BLOCKS,
            3_000,
        )
        .expect("devnet cache policy")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_state_cache_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "cache_scheme": STATE_SHARDING_CACHE_SCHEME,
            "policy_id": self.policy_id,
            "label": self.label,
            "eviction_kind": self.eviction_kind.label(),
            "max_entries": self.max_entries,
            "max_bytes": self.max_bytes,
            "ttl_blocks": self.ttl_blocks,
            "hot_pin_bps": self.hot_pin_bps,
            "lease_aware": self.lease_aware,
            "da_pinned": self.da_pinned,
            "privacy_preserving_misses": self.privacy_preserving_misses,
            "status": self.status,
        })
    }

    pub fn policy_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-CACHE-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.policy_id, "cache policy id")?;
        ensure_non_empty(&self.label, "cache policy label")?;
        ensure_positive(self.max_entries, "cache policy max entries")?;
        ensure_positive(self.max_bytes, "cache policy max bytes")?;
        ensure_positive(self.ttl_blocks, "cache policy ttl blocks")?;
        ensure_bps(self.hot_pin_bps, "cache policy hot pin bps")?;
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "cache policy status",
        )?;
        let expected = state_cache_policy_id(
            &self.label,
            &self.eviction_kind,
            self.max_entries,
            self.max_bytes,
            self.ttl_blocks,
        );
        if self.policy_id != expected {
            return Err("cache policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEvictionProof {
    pub proof_id: String,
    pub policy_id: String,
    pub shard_id: ShardId,
    pub evicted_key_bucket_root: String,
    pub evicted_value_root: String,
    pub before_cache_root: String,
    pub after_cache_root: String,
    pub lease_exclusion_root: String,
    pub hotness_bucket: u64,
    pub reason: String,
    pub created_at_height: u64,
}

impl CacheEvictionProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        shard_id: impl Into<String>,
        evicted_key_bucket_root: impl Into<String>,
        evicted_value_root: impl Into<String>,
        before_cache_root: impl Into<String>,
        after_cache_root: impl Into<String>,
        lease_exclusion_root: impl Into<String>,
        hotness_count: u64,
        reason: impl Into<String>,
        created_at_height: u64,
    ) -> StateShardingResult<Self> {
        let policy_id = policy_id.into();
        let shard_id = shard_id.into();
        let evicted_key_bucket_root = evicted_key_bucket_root.into();
        let evicted_value_root = evicted_value_root.into();
        let before_cache_root = before_cache_root.into();
        let after_cache_root = after_cache_root.into();
        let lease_exclusion_root = lease_exclusion_root.into();
        let reason = reason.into();
        ensure_non_empty(&policy_id, "cache eviction proof policy id")?;
        ensure_non_empty(&shard_id, "cache eviction proof shard id")?;
        ensure_non_empty(
            &evicted_key_bucket_root,
            "cache eviction proof key bucket root",
        )?;
        ensure_non_empty(&evicted_value_root, "cache eviction proof value root")?;
        ensure_non_empty(&before_cache_root, "cache eviction proof before root")?;
        ensure_non_empty(&after_cache_root, "cache eviction proof after root")?;
        ensure_non_empty(
            &lease_exclusion_root,
            "cache eviction proof lease exclusion root",
        )?;
        ensure_non_empty(&reason, "cache eviction proof reason")?;
        let hotness_bucket = bucket_count(hotness_count);
        let proof_id = cache_eviction_proof_id(
            &policy_id,
            &shard_id,
            &evicted_key_bucket_root,
            &before_cache_root,
            &after_cache_root,
            created_at_height,
        );
        Ok(Self {
            proof_id,
            policy_id,
            shard_id,
            evicted_key_bucket_root,
            evicted_value_root,
            before_cache_root,
            after_cache_root,
            lease_exclusion_root,
            hotness_bucket,
            reason,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_state_cache_eviction_proof",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "proof_id": self.proof_id,
            "policy_id": self.policy_id,
            "shard_id": self.shard_id,
            "evicted_key_bucket_root": self.evicted_key_bucket_root,
            "evicted_value_root": self.evicted_value_root,
            "before_cache_root": self.before_cache_root,
            "after_cache_root": self.after_cache_root,
            "lease_exclusion_root": self.lease_exclusion_root,
            "hotness_bucket": self.hotness_bucket,
            "reason": self.reason,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn proof_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-CACHE-EVICTION-PROOF", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.proof_id, "cache eviction proof id")?;
        ensure_non_empty(&self.policy_id, "cache eviction proof policy id")?;
        ensure_non_empty(&self.shard_id, "cache eviction proof shard id")?;
        ensure_non_empty(
            &self.evicted_key_bucket_root,
            "cache eviction proof key bucket root",
        )?;
        ensure_non_empty(&self.evicted_value_root, "cache eviction proof value root")?;
        ensure_non_empty(&self.before_cache_root, "cache eviction proof before root")?;
        ensure_non_empty(&self.after_cache_root, "cache eviction proof after root")?;
        ensure_non_empty(
            &self.lease_exclusion_root,
            "cache eviction proof lease exclusion root",
        )?;
        ensure_non_empty(&self.reason, "cache eviction proof reason")?;
        let expected = cache_eviction_proof_id(
            &self.policy_id,
            &self.shard_id,
            &self.evicted_key_bucket_root,
            &self.before_cache_root,
            &self.after_cache_root,
            self.created_at_height,
        );
        if self.proof_id != expected {
            return Err("cache eviction proof id mismatch".to_string());
        }
        Ok(self.proof_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeShardLane {
    pub lane_id: String,
    pub label: String,
    pub traffic_class: ShardTrafficClass,
    pub shard_ids: Vec<ShardId>,
    pub min_fee_units: u64,
    pub rebate_bps: u64,
    pub quota_per_block: u64,
    pub sponsor_root: String,
    pub wallet_hint_commitment_root: String,
    pub bridge_hint_commitment_root: String,
    pub privacy_witness_required: bool,
    pub status: String,
}

impl LowFeeShardLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        traffic_class: ShardTrafficClass,
        shard_ids: Vec<ShardId>,
        min_fee_units: u64,
        rebate_bps: u64,
        quota_per_block: u64,
        sponsor_root: impl Into<String>,
    ) -> StateShardingResult<Self> {
        let label = label.into();
        let sponsor_root = sponsor_root.into();
        ensure_non_empty(&label, "low fee shard lane label")?;
        ensure_bps(rebate_bps, "low fee shard lane rebate bps")?;
        ensure_positive(quota_per_block, "low fee shard lane quota")?;
        ensure_non_empty(&sponsor_root, "low fee shard lane sponsor root")?;
        if shard_ids.is_empty() {
            return Err("low fee shard lane requires shard ids".to_string());
        }
        ensure_unique_strings(shard_ids.clone(), "low fee shard lane shards")?;
        let lane_id = low_fee_shard_lane_id(&label, &traffic_class, &shard_ids, min_fee_units);
        Ok(Self {
            lane_id,
            label,
            traffic_class,
            shard_ids,
            min_fee_units,
            rebate_bps,
            quota_per_block,
            sponsor_root,
            wallet_hint_commitment_root: merkle_root("STATE-SHARDING-WALLET-LANE-HINT", &[]),
            bridge_hint_commitment_root: merkle_root("STATE-SHARDING-BRIDGE-LANE-HINT", &[]),
            privacy_witness_required: true,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_shard_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "label": self.label,
            "traffic_class": self.traffic_class.label(),
            "shard_ids": self.shard_ids,
            "min_fee_units": self.min_fee_units,
            "rebate_bps": self.rebate_bps,
            "quota_per_block": self.quota_per_block,
            "sponsor_root": self.sponsor_root,
            "wallet_hint_commitment_root": self.wallet_hint_commitment_root,
            "bridge_hint_commitment_root": self.bridge_hint_commitment_root,
            "privacy_witness_required": self.privacy_witness_required,
            "status": self.status,
        })
    }

    pub fn lane_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-LOW-FEE-LANE", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.lane_id, "low fee shard lane id")?;
        ensure_non_empty(&self.label, "low fee shard lane label")?;
        ensure_bps(self.rebate_bps, "low fee shard lane rebate bps")?;
        ensure_positive(self.quota_per_block, "low fee shard lane quota")?;
        ensure_non_empty(&self.sponsor_root, "low fee shard lane sponsor root")?;
        ensure_non_empty(
            &self.wallet_hint_commitment_root,
            "low fee shard lane wallet hint root",
        )?;
        ensure_non_empty(
            &self.bridge_hint_commitment_root,
            "low fee shard lane bridge hint root",
        )?;
        if self.shard_ids.is_empty() {
            return Err("low fee shard lane shards cannot be empty".to_string());
        }
        ensure_unique_strings(self.shard_ids.clone(), "low fee shard lane shards")?;
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "low fee shard lane status",
        )?;
        let expected = low_fee_shard_lane_id(
            &self.label,
            &self.traffic_class,
            &self.shard_ids,
            self.min_fee_units,
        );
        if self.lane_id != expected {
            return Err("low fee shard lane id mismatch".to_string());
        }
        Ok(self.lane_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAvailabilityShardRoot {
    pub da_root_id: String,
    pub shard_id: ShardId,
    pub da_epoch: u64,
    pub block_height: u64,
    pub blob_root: String,
    pub erasure_root: String,
    pub sample_root: String,
    pub replay_manifest_id: ReplayManifestId,
    pub low_fee_lane_id: String,
    pub retention_until_height: u64,
    pub status: String,
}

impl DataAvailabilityShardRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_id: impl Into<String>,
        da_epoch: u64,
        block_height: u64,
        blob_root: impl Into<String>,
        erasure_root: impl Into<String>,
        sample_root: impl Into<String>,
        replay_manifest_id: impl Into<String>,
        low_fee_lane_id: impl Into<String>,
        retention_until_height: u64,
    ) -> StateShardingResult<Self> {
        let shard_id = shard_id.into();
        let blob_root = blob_root.into();
        let erasure_root = erasure_root.into();
        let sample_root = sample_root.into();
        let replay_manifest_id = replay_manifest_id.into();
        let low_fee_lane_id = low_fee_lane_id.into();
        ensure_non_empty(&shard_id, "DA shard root shard id")?;
        ensure_non_empty(&blob_root, "DA shard root blob root")?;
        ensure_non_empty(&erasure_root, "DA shard root erasure root")?;
        ensure_non_empty(&sample_root, "DA shard root sample root")?;
        ensure_non_empty(&replay_manifest_id, "DA shard root replay manifest id")?;
        if retention_until_height <= block_height {
            return Err("DA shard retention must exceed block height".to_string());
        }
        let da_root_id =
            da_shard_root_id(&shard_id, da_epoch, block_height, &blob_root, &erasure_root);
        Ok(Self {
            da_root_id,
            shard_id,
            da_epoch,
            block_height,
            blob_root,
            erasure_root,
            sample_root,
            replay_manifest_id,
            low_fee_lane_id,
            retention_until_height,
            status: STATE_SHARDING_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "data_availability_shard_root",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "da_scheme": STATE_SHARDING_DA_SCHEME,
            "da_root_id": self.da_root_id,
            "shard_id": self.shard_id,
            "da_epoch": self.da_epoch,
            "block_height": self.block_height,
            "blob_root": self.blob_root,
            "erasure_root": self.erasure_root,
            "sample_root": self.sample_root,
            "replay_manifest_id": self.replay_manifest_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "retention_until_height": self.retention_until_height,
            "status": self.status,
        })
    }

    pub fn da_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-DA-SHARD-ROOT", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.da_root_id, "DA shard root id")?;
        ensure_non_empty(&self.shard_id, "DA shard root shard id")?;
        ensure_non_empty(&self.blob_root, "DA shard root blob root")?;
        ensure_non_empty(&self.erasure_root, "DA shard root erasure root")?;
        ensure_non_empty(&self.sample_root, "DA shard root sample root")?;
        ensure_non_empty(&self.replay_manifest_id, "DA shard root replay manifest id")?;
        if self.retention_until_height <= self.block_height {
            return Err("DA shard retention must exceed block height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                STATE_SHARDING_STATUS_ACTIVE,
                STATE_SHARDING_STATUS_PENDING,
                STATE_SHARDING_STATUS_RETIRED,
                STATE_SHARDING_STATUS_PAUSED,
            ],
            "DA shard root status",
        )?;
        let expected = da_shard_root_id(
            &self.shard_id,
            self.da_epoch,
            self.block_height,
            &self.blob_root,
            &self.erasure_root,
        );
        if self.da_root_id != expected {
            return Err("DA shard root id mismatch".to_string());
        }
        Ok(self.da_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub manifest_id: ReplayManifestId,
    pub from_height: u64,
    pub to_height: u64,
    pub shard_state_roots: BTreeMap<ShardId, String>,
    pub da_root_ids: Vec<String>,
    pub bundle_root: String,
    pub handoff_root: String,
    pub routing_table_root: String,
    pub previous_manifest_root: String,
    pub created_at_height: u64,
}

impl ReplayManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_height: u64,
        to_height: u64,
        shard_state_roots: BTreeMap<ShardId, String>,
        da_root_ids: Vec<String>,
        bundle_root: impl Into<String>,
        handoff_root: impl Into<String>,
        routing_table_root: impl Into<String>,
        previous_manifest_root: impl Into<String>,
        created_at_height: u64,
    ) -> StateShardingResult<Self> {
        let bundle_root = bundle_root.into();
        let handoff_root = handoff_root.into();
        let routing_table_root = routing_table_root.into();
        let previous_manifest_root = previous_manifest_root.into();
        if to_height < from_height {
            return Err("replay manifest height range is inverted".to_string());
        }
        if shard_state_roots.is_empty() {
            return Err("replay manifest requires shard state roots".to_string());
        }
        ensure_non_empty(&bundle_root, "replay manifest bundle root")?;
        ensure_non_empty(&handoff_root, "replay manifest handoff root")?;
        ensure_non_empty(&routing_table_root, "replay manifest routing table root")?;
        ensure_unique_strings(da_root_ids.clone(), "replay manifest DA roots")?;
        let manifest_id = replay_manifest_id(
            from_height,
            to_height,
            &shard_state_roots,
            &bundle_root,
            &routing_table_root,
        );
        Ok(Self {
            manifest_id,
            from_height,
            to_height,
            shard_state_roots,
            da_root_ids,
            bundle_root,
            handoff_root,
            routing_table_root,
            previous_manifest_root,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_sharding_replay_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "replay_scheme": STATE_SHARDING_REPLAY_SCHEME,
            "manifest_id": self.manifest_id,
            "from_height": self.from_height,
            "to_height": self.to_height,
            "shard_state_roots": self.shard_state_roots,
            "da_root_ids": self.da_root_ids,
            "bundle_root": self.bundle_root,
            "handoff_root": self.handoff_root,
            "routing_table_root": self.routing_table_root,
            "previous_manifest_root": self.previous_manifest_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn manifest_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-REPLAY-MANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.manifest_id, "replay manifest id")?;
        if self.to_height < self.from_height {
            return Err("replay manifest height range is inverted".to_string());
        }
        if self.shard_state_roots.is_empty() {
            return Err("replay manifest shard roots cannot be empty".to_string());
        }
        for (shard_id, root) in &self.shard_state_roots {
            ensure_non_empty(shard_id, "replay manifest shard id")?;
            ensure_non_empty(root, "replay manifest shard root")?;
        }
        ensure_unique_strings(self.da_root_ids.clone(), "replay manifest DA roots")?;
        ensure_non_empty(&self.bundle_root, "replay manifest bundle root")?;
        ensure_non_empty(&self.handoff_root, "replay manifest handoff root")?;
        ensure_non_empty(
            &self.routing_table_root,
            "replay manifest routing table root",
        )?;
        ensure_non_empty(
            &self.previous_manifest_root,
            "replay manifest previous root",
        )?;
        let expected = replay_manifest_id(
            self.from_height,
            self.to_height,
            &self.shard_state_roots,
            &self.bundle_root,
            &self.routing_table_root,
        );
        if self.manifest_id != expected {
            return Err("replay manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateShardingPublicRecord {
    pub record_id: String,
    pub height: u64,
    pub scope: String,
    pub label: String,
    pub payload_root: String,
    pub payload: Value,
}

impl StateShardingPublicRecord {
    pub fn new(
        height: u64,
        scope: impl Into<String>,
        label: impl Into<String>,
        payload: Value,
    ) -> StateShardingResult<Self> {
        let scope = scope.into();
        let label = label.into();
        ensure_non_empty(&scope, "public record scope")?;
        ensure_non_empty(&label, "public record label")?;
        let payload_root = state_sharding_payload_root("STATE-SHARDING-PUBLIC-PAYLOAD", &payload);
        let record_id = state_sharding_public_record_id(height, &scope, &label, &payload_root);
        Ok(Self {
            record_id,
            height,
            scope,
            label,
            payload_root,
            payload,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "state_sharding_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "height": self.height,
            "scope": self.scope,
            "label": self.label,
            "payload_root": self.payload_root,
            "payload": self.payload,
        })
    }

    pub fn record_root(&self) -> String {
        state_sharding_payload_root("STATE-SHARDING-PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        ensure_non_empty(&self.record_id, "public record id")?;
        ensure_non_empty(&self.scope, "public record scope")?;
        ensure_non_empty(&self.label, "public record label")?;
        ensure_non_empty(&self.payload_root, "public record payload root")?;
        let expected_payload =
            state_sharding_payload_root("STATE-SHARDING-PUBLIC-PAYLOAD", &self.payload);
        if self.payload_root != expected_payload {
            return Err("public record payload root mismatch".to_string());
        }
        let expected = state_sharding_public_record_id(
            self.height,
            &self.scope,
            &self.label,
            &self.payload_root,
        );
        if self.record_id != expected {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.record_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateShardingDevnet {
    pub height: u64,
    pub topology: ShardTopologyConfig,
    pub shards: BTreeMap<ShardId, StateShard>,
    pub hot_partitions: BTreeMap<PartitionId, HotStatePartition>,
    pub routing_tables: BTreeMap<RoutingTableId, RoutingTable>,
    pub privacy_witnesses: BTreeMap<String, PrivacyWitnessCommitment>,
    pub hot_key_telemetry: BTreeMap<String, HotKeyTelemetryBucket>,
    pub atomic_bundles: BTreeMap<AtomicBundleId, CrossShardAtomicBundle>,
    pub lock_leases: BTreeMap<LockLeaseId, AtomicShardLockLease>,
    pub handoff_receipts: BTreeMap<HandoffReceiptId, ShardHandoffReceipt>,
    pub rollback_roots: BTreeMap<String, RollbackRoot>,
    pub shard_assignments: BTreeMap<AssignmentId, ShardAssignment>,
    pub pq_attestations: BTreeMap<PqAttestationId, PqShardAttestation>,
    pub cache_policies: BTreeMap<String, StateCachePolicy>,
    pub eviction_proofs: BTreeMap<String, CacheEvictionProof>,
    pub low_fee_lanes: BTreeMap<String, LowFeeShardLane>,
    pub da_shard_roots: BTreeMap<String, DataAvailabilityShardRoot>,
    pub replay_manifests: BTreeMap<ReplayManifestId, ReplayManifest>,
    pub public_records: BTreeMap<String, StateShardingPublicRecord>,
}

impl StateShardingDevnet {
    pub fn devnet() -> StateShardingResult<Self> {
        let height = 128;
        let epoch = 0;
        let epoch_start = 0;
        let epoch_end = STATE_SHARDING_DEFAULT_EPOCH_LENGTH_BLOCKS - 1;
        let mut topology = ShardTopologyConfig::new(epoch, epoch_start, epoch_end);
        let cache_policy = StateCachePolicy::devnet_hot();
        let cache_policy_id = cache_policy.policy_id.clone();
        let operators = [
            "sequencer-alpha",
            "validator-bravo",
            "validator-charlie",
            "validator-delta",
        ];

        let mut shards = BTreeMap::new();
        for index in 0..STATE_SHARDING_DEFAULT_SHARD_COUNT {
            let partition_kind = match index {
                0 => ShardPartitionKind::AccountRange,
                1 => ShardPartitionKind::PrivacyNullifier,
                2 => ShardPartitionKind::DefiPool,
                3 => ShardPartitionKind::ContractBucket,
                4 => ShardPartitionKind::BridgeQueue,
                5 => ShardPartitionKind::TokenLedger,
                6 => ShardPartitionKind::DataAvailability,
                _ => ShardPartitionKind::System,
            };
            let access_classes = match index {
                0 => vec![ShardAccessClass::PublicRead, ShardAccessClass::WalletLowFee],
                1 => vec![
                    ShardAccessClass::PrivateBalance,
                    ShardAccessClass::WalletLowFee,
                ],
                2 => vec![
                    ShardAccessClass::DefiHotPath,
                    ShardAccessClass::PrivateContract,
                ],
                3 => vec![
                    ShardAccessClass::PrivateContract,
                    ShardAccessClass::PublicRead,
                ],
                4 => vec![
                    ShardAccessClass::BridgeControl,
                    ShardAccessClass::WalletLowFee,
                ],
                5 => vec![ShardAccessClass::PublicRead, ShardAccessClass::DefiHotPath],
                6 => vec![ShardAccessClass::DataAvailabilityReplay],
                _ => vec![
                    ShardAccessClass::SequencerSystem,
                    ShardAccessClass::ValidatorOnly,
                ],
            };
            let replica_set = deterministic_replica_set(&operators, index as usize, 3);
            let primary_operator_id = replica_set[0].clone();
            let shard = StateShard::new(
                topology.topology_id.clone(),
                index,
                partition_kind,
                access_classes,
                replica_set,
                primary_operator_id,
                height,
            )?;
            shards.insert(shard.shard_id.clone(), shard);
        }

        let shard_ids = shards.keys().cloned().collect::<Vec<_>>();
        let sponsor_root = state_sharding_string_root("STATE-SHARDING-DEVNET-SPONSOR", "devnet");
        let wallet_lane = LowFeeShardLane::new(
            STATE_SHARDING_LOW_FEE_WALLET_LANE,
            ShardTrafficClass::Wallet,
            shard_ids.iter().take(2).cloned().collect::<Vec<_>>(),
            STATE_SHARDING_DEFAULT_WALLET_FEE_UNITS,
            8_500,
            25_000,
            sponsor_root.clone(),
        )?;
        let bridge_lane = LowFeeShardLane::new(
            STATE_SHARDING_LOW_FEE_BRIDGE_LANE,
            ShardTrafficClass::Bridge,
            shard_ids
                .iter()
                .skip(4)
                .take(2)
                .cloned()
                .collect::<Vec<_>>(),
            STATE_SHARDING_DEFAULT_BRIDGE_FEE_UNITS,
            7_500,
            10_000,
            sponsor_root,
        )?;
        let wallet_lane_id = wallet_lane.lane_id.clone();
        let bridge_lane_id = bridge_lane.lane_id.clone();

        let mut low_fee_lanes = BTreeMap::new();
        low_fee_lanes.insert(wallet_lane.lane_id.clone(), wallet_lane);
        low_fee_lanes.insert(bridge_lane.lane_id.clone(), bridge_lane);

        let mut cache_policies = BTreeMap::new();
        cache_policies.insert(cache_policy.policy_id.clone(), cache_policy);

        let mut hot_partitions = BTreeMap::new();
        for (offset, shard) in shards.values().enumerate() {
            let access_class = shard
                .access_classes
                .first()
                .cloned()
                .unwrap_or(ShardAccessClass::PublicRead);
            let lane_id = if access_class == ShardAccessClass::BridgeControl {
                bridge_lane_id.clone()
            } else {
                wallet_lane_id.clone()
            };
            let partition = HotStatePartition::new(
                shard.shard_id.clone(),
                offset as u64,
                ShardPartitionKind::HotCache,
                access_class,
                cache_policy_id.clone(),
                lane_id,
                height,
            )?;
            hot_partitions.insert(partition.partition_id.clone(), partition);
        }

        let table_id = routing_table_id(&topology.topology_id, epoch, height);
        let routing_rules = shards
            .values()
            .enumerate()
            .map(|(index, shard)| {
                let access_class = shard
                    .access_classes
                    .first()
                    .cloned()
                    .unwrap_or(ShardAccessClass::PublicRead);
                let lane_id = if access_class == ShardAccessClass::BridgeControl {
                    bridge_lane_id.clone()
                } else {
                    wallet_lane_id.clone()
                };
                RoutingRule::new(
                    table_id.clone(),
                    format!("devnet-route-{index}"),
                    shard.partition_kind.clone(),
                    access_class,
                    shard.shard_id.clone(),
                    shard_ids
                        .iter()
                        .filter(|candidate| *candidate != &shard.shard_id)
                        .take(2)
                        .cloned()
                        .collect::<Vec<_>>(),
                    lane_id,
                    "devnet-da-lane",
                    1_000_u64.saturating_sub(index as u64),
                    epoch_start,
                    0,
                )
            })
            .collect::<StateShardingResult<Vec<_>>>()?;
        let fallback_shard_id = shard_ids
            .first()
            .cloned()
            .ok_or_else(|| "devnet requires at least one shard".to_string())?;
        let routing_table = RoutingTable::new(
            topology.topology_id.clone(),
            epoch,
            height,
            fallback_shard_id,
            routing_rules,
        )?;
        let mut routing_tables = BTreeMap::new();
        routing_tables.insert(routing_table.table_id.clone(), routing_table);
        topology = topology.with_roots(
            access_class_root(&shards),
            routing_table_record_root(&routing_tables),
        );

        let shard_a = shard_ids[0].clone();
        let shard_b = shard_ids[1].clone();
        let read_root = state_sharding_string_root("STATE-SHARDING-DEVNET-READSET", "wallet-read");
        let write_root =
            state_sharding_string_root("STATE-SHARDING-DEVNET-WRITESET", "wallet-write");
        let mut bundle = CrossShardAtomicBundle::new(
            shard_a.clone(),
            vec![shard_a.clone(), shard_b.clone()],
            read_root.clone(),
            write_root.clone(),
            wallet_lane_id.clone(),
            height,
            height + STATE_SHARDING_DEFAULT_LOCK_LEASE_BLOCKS,
        )?;
        let owner_commitment =
            state_sharding_string_root("STATE-SHARDING-DEVNET-BUNDLE-OWNER", "wallet-batch");
        let rollback = RollbackRoot::new(
            bundle.bundle_id.clone(),
            shard_a.clone(),
            merkle_root("STATE-SHARDING-DEVNET-PRE-STATE", &[]),
            merkle_root("STATE-SHARDING-DEVNET-INVERSE-DELTA", &[]),
            merkle_root("STATE-SHARDING-DEVNET-ROLLBACK-WITNESS", &[]),
            "devnet_preconfirm_reorg",
            height,
        )?;
        let lease = AtomicShardLockLease::new(
            bundle.bundle_id.clone(),
            shard_a.clone(),
            LockLeaseMode::Atomic,
            owner_commitment,
            state_sharding_string_root("STATE-SHARDING-DEVNET-LEASE-RESOURCE", "wallet-state"),
            rollback.rollback_root(),
            height,
            height + STATE_SHARDING_DEFAULT_LOCK_LEASE_BLOCKS,
            0,
        )?;
        let handoff = ShardHandoffReceipt::new(
            bundle.bundle_id.clone(),
            shard_a.clone(),
            shard_b.clone(),
            state_sharding_string_root("STATE-SHARDING-DEVNET-DELTA", "wallet-bucket-handoff"),
            merkle_root("STATE-SHARDING-DEVNET-HANDOFF-WITNESS", &[]),
            merkle_root("STATE-SHARDING-DEVNET-HANDOFF-DA", &[]),
            lease.lease_root(),
            merkle_root("STATE-SHARDING-DEVNET-HANDOFF-PQ", &[]),
            height + 1,
        )?;
        bundle.lock_lease_root = merkle_root("STATE-SHARDING-LOCK-LEASE", &[lease.public_record()]);
        bundle.handoff_receipt_root =
            merkle_root("STATE-SHARDING-HANDOFF-RECEIPT", &[handoff.public_record()]);
        bundle.rollback_root =
            merkle_root("STATE-SHARDING-ROLLBACK-ROOT", &[rollback.public_record()]);

        let witness = PrivacyWitnessCommitment::new(
            shard_b.clone(),
            ShardAccessClass::PrivateBalance,
            state_sharding_string_root("STATE-SHARDING-DEVNET-BLINDED-KEY", "alice-wallet"),
            merkle_root("STATE-SHARDING-DEVNET-OLD-STATE", &[]),
            merkle_root("STATE-SHARDING-DEVNET-NEW-STATE", &[]),
            read_root,
            write_root,
            height,
            height + 24,
        )?;

        let telemetry_partition = hot_partitions
            .values()
            .next()
            .ok_or_else(|| "devnet requires a hot partition".to_string())?;
        let telemetry = HotKeyTelemetryBucket::new(
            telemetry_partition.shard_id.clone(),
            telemetry_partition.partition_id.clone(),
            epoch,
            0,
            "wallet-bucket-0",
            42_000,
            9_000,
            2_100,
            height,
        )?;

        let mut shard_assignments = BTreeMap::new();
        let mut pq_attestations = BTreeMap::new();
        for (index, shard) in shards.values().enumerate() {
            let operator_id = operators[index % operators.len()].to_string();
            let role = if index == 0 {
                ShardAssignmentRole::Sequencer
            } else if index == 6 {
                ShardAssignmentRole::DataAvailability
            } else {
                ShardAssignmentRole::Validator
            };
            let assignment = ShardAssignment::new(
                epoch,
                shard.shard_id.clone(),
                operator_id.clone(),
                role,
                1_000 + index as u64,
                10_000,
                epoch_start,
                epoch_end,
                vec![wallet_lane_id.clone(), bridge_lane_id.clone()],
            )?;
            let attestation = PqShardAttestation::new(
                shard.shard_id.clone(),
                operator_id,
                assignment.assignment_id.clone(),
                assignment.pq_key_commitment_root.clone(),
                assignment.assignment_root(),
                height,
                height + 144,
            )?;
            shard_assignments.insert(assignment.assignment_id.clone(), assignment);
            pq_attestations.insert(attestation.attestation_id.clone(), attestation);
        }

        let eviction = CacheEvictionProof::new(
            cache_policy_id,
            shard_a.clone(),
            state_sharding_string_root("STATE-SHARDING-DEVNET-EVICTED-KEY", "old-hot-key"),
            state_sharding_string_root("STATE-SHARDING-DEVNET-EVICTED-VALUE", "old-value"),
            merkle_root("STATE-SHARDING-DEVNET-CACHE-BEFORE", &[]),
            merkle_root("STATE-SHARDING-DEVNET-CACHE-AFTER", &[]),
            merkle_root("STATE-SHARDING-DEVNET-LEASE-EXCLUSION", &[]),
            2,
            "lease_aware_lru",
            height,
        )?;

        let mut shard_state_roots = BTreeMap::new();
        for shard in shards.values() {
            shard_state_roots.insert(shard.shard_id.clone(), shard.current_state_root.clone());
        }
        let manifest = ReplayManifest::new(
            epoch_start,
            height,
            shard_state_roots,
            Vec::new(),
            bundle.bundle_root(),
            handoff.receipt_root(),
            topology.routing_table_root.clone(),
            merkle_root("STATE-SHARDING-PREVIOUS-REPLAY-MANIFEST", &[]),
            height,
        )?;
        let da_root = DataAvailabilityShardRoot::new(
            shard_a.clone(),
            epoch,
            height,
            state_sharding_string_root("STATE-SHARDING-DEVNET-BLOB", "blob-0"),
            state_sharding_string_root("STATE-SHARDING-DEVNET-ERASURE", "erasure-0"),
            state_sharding_string_root("STATE-SHARDING-DEVNET-SAMPLE", "sample-0"),
            manifest.manifest_id.clone(),
            wallet_lane_id,
            height + STATE_SHARDING_DEFAULT_DA_RETENTION_BLOCKS,
        )?;

        let mut privacy_witnesses = BTreeMap::new();
        privacy_witnesses.insert(witness.witness_id.clone(), witness);
        let mut hot_key_telemetry = BTreeMap::new();
        hot_key_telemetry.insert(telemetry.telemetry_id.clone(), telemetry);
        let mut atomic_bundles = BTreeMap::new();
        atomic_bundles.insert(bundle.bundle_id.clone(), bundle);
        let mut lock_leases = BTreeMap::new();
        lock_leases.insert(lease.lease_id.clone(), lease);
        let mut handoff_receipts = BTreeMap::new();
        handoff_receipts.insert(handoff.receipt_id.clone(), handoff);
        let mut rollback_roots = BTreeMap::new();
        rollback_roots.insert(rollback.rollback_id.clone(), rollback);
        let mut eviction_proofs = BTreeMap::new();
        eviction_proofs.insert(eviction.proof_id.clone(), eviction);
        let mut replay_manifests = BTreeMap::new();
        replay_manifests.insert(manifest.manifest_id.clone(), manifest);
        let mut da_shard_roots = BTreeMap::new();
        da_shard_roots.insert(da_root.da_root_id.clone(), da_root);

        let mut state = Self {
            height,
            topology,
            shards,
            hot_partitions,
            routing_tables,
            privacy_witnesses,
            hot_key_telemetry,
            atomic_bundles,
            lock_leases,
            handoff_receipts,
            rollback_roots,
            shard_assignments,
            pq_attestations,
            cache_policies,
            eviction_proofs,
            low_fee_lanes,
            da_shard_roots,
            replay_manifests,
            public_records: BTreeMap::new(),
        };
        let snapshot = state.public_record_without_root();
        state.publish_public_record(height, "state_sharding_devnet", "bootstrap", snapshot)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> StateShardingResult<String> {
        if height < self.height {
            return Err("state sharding height cannot move backwards".to_string());
        }
        self.height = height;
        Ok(self.state_root())
    }

    pub fn publish_public_record(
        &mut self,
        height: u64,
        scope: impl Into<String>,
        label: impl Into<String>,
        payload: Value,
    ) -> StateShardingResult<String> {
        let record = StateShardingPublicRecord::new(height, scope, label, payload)?;
        let record_root = record.record_root();
        self.public_records.insert(record.record_id.clone(), record);
        Ok(record_root)
    }

    pub fn route_key(
        &self,
        access_class: &ShardAccessClass,
        key_material: &str,
    ) -> Option<&RoutingRule> {
        self.routing_tables
            .values()
            .filter(|table| table.status == STATE_SHARDING_STATUS_ACTIVE)
            .max_by_key(|table| (table.epoch, table.height))
            .and_then(|table| table.route_for_key(access_class, key_material, self.height))
    }

    pub fn shard_root(&self) -> String {
        state_shard_record_root(&self.shards)
    }

    pub fn hot_partition_root(&self) -> String {
        hot_partition_record_root(&self.hot_partitions)
    }

    pub fn routing_table_root(&self) -> String {
        routing_table_record_root(&self.routing_tables)
    }

    pub fn privacy_witness_root(&self) -> String {
        privacy_witness_record_root(&self.privacy_witnesses)
    }

    pub fn hot_key_telemetry_root(&self) -> String {
        hot_key_telemetry_record_root(&self.hot_key_telemetry)
    }

    pub fn atomic_bundle_root(&self) -> String {
        atomic_bundle_record_root(&self.atomic_bundles)
    }

    pub fn lock_lease_root(&self) -> String {
        lock_lease_record_root(&self.lock_leases)
    }

    pub fn handoff_receipt_root(&self) -> String {
        handoff_receipt_record_root(&self.handoff_receipts)
    }

    pub fn rollback_root(&self) -> String {
        rollback_record_root(&self.rollback_roots)
    }

    pub fn shard_assignment_root(&self) -> String {
        shard_assignment_record_root(&self.shard_assignments)
    }

    pub fn pq_attestation_root(&self) -> String {
        pq_attestation_record_root(&self.pq_attestations)
    }

    pub fn cache_policy_root(&self) -> String {
        cache_policy_record_root(&self.cache_policies)
    }

    pub fn eviction_proof_root(&self) -> String {
        eviction_proof_record_root(&self.eviction_proofs)
    }

    pub fn low_fee_lane_root(&self) -> String {
        low_fee_lane_record_root(&self.low_fee_lanes)
    }

    pub fn da_shard_root(&self) -> String {
        da_shard_record_root(&self.da_shard_roots)
    }

    pub fn replay_manifest_root(&self) -> String {
        replay_manifest_record_root(&self.replay_manifests)
    }

    pub fn public_record_root(&self) -> String {
        state_sharding_public_record_root(&self.public_records)
    }

    pub fn state_root(&self) -> String {
        state_sharding_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "state_sharding_devnet",
            "chain_id": CHAIN_ID,
            "protocol_version": STATE_SHARDING_PROTOCOL_VERSION,
            "height": self.height,
            "topology": self.topology.public_record(),
            "topology_root": self.topology.config_root(),
            "shard_count": self.shards.len() as u64,
            "hot_partition_count": self.hot_partitions.len() as u64,
            "routing_table_count": self.routing_tables.len() as u64,
            "privacy_witness_count": self.privacy_witnesses.len() as u64,
            "hot_key_telemetry_count": self.hot_key_telemetry.len() as u64,
            "atomic_bundle_count": self.atomic_bundles.len() as u64,
            "lock_lease_count": self.lock_leases.len() as u64,
            "handoff_receipt_count": self.handoff_receipts.len() as u64,
            "rollback_root_count": self.rollback_roots.len() as u64,
            "assignment_count": self.shard_assignments.len() as u64,
            "pq_attestation_count": self.pq_attestations.len() as u64,
            "cache_policy_count": self.cache_policies.len() as u64,
            "eviction_proof_count": self.eviction_proofs.len() as u64,
            "low_fee_lane_count": self.low_fee_lanes.len() as u64,
            "da_shard_root_count": self.da_shard_roots.len() as u64,
            "replay_manifest_count": self.replay_manifests.len() as u64,
            "public_record_count": self.public_records.len() as u64,
            "shard_root": self.shard_root(),
            "hot_partition_root": self.hot_partition_root(),
            "routing_table_root": self.routing_table_root(),
            "privacy_witness_root": self.privacy_witness_root(),
            "hot_key_telemetry_root": self.hot_key_telemetry_root(),
            "atomic_bundle_root": self.atomic_bundle_root(),
            "lock_lease_root": self.lock_lease_root(),
            "handoff_receipt_root": self.handoff_receipt_root(),
            "rollback_root": self.rollback_root(),
            "shard_assignment_root": self.shard_assignment_root(),
            "pq_attestation_root": self.pq_attestation_root(),
            "cache_policy_root": self.cache_policy_root(),
            "eviction_proof_root": self.eviction_proof_root(),
            "low_fee_lane_root": self.low_fee_lane_root(),
            "da_shard_root": self.da_shard_root(),
            "replay_manifest_root": self.replay_manifest_root(),
            "public_record_root": self.public_record_root(),
        })
    }

    pub fn validate(&self) -> StateShardingResult<String> {
        self.topology.validate()?;
        if self.height < self.topology.epoch_start_height {
            return Err("state sharding height is before topology start".to_string());
        }
        if self.shards.len() as u64 != self.topology.shard_count {
            return Err("state sharding shard count does not match topology".to_string());
        }
        validate_map_keys(
            &self.shards,
            |record| record.shard_id.clone(),
            "state shard map",
        )?;
        for shard in self.shards.values() {
            shard.validate()?;
            if shard.topology_id != self.topology.topology_id {
                return Err("state shard topology id mismatch".to_string());
            }
        }
        validate_map_keys(
            &self.hot_partitions,
            |record| record.partition_id.clone(),
            "hot partition map",
        )?;
        for partition in self.hot_partitions.values() {
            partition.validate()?;
            ensure_known_key(
                &self.shards,
                &partition.shard_id,
                "hot partition references unknown shard",
            )?;
            ensure_known_key(
                &self.cache_policies,
                &partition.cache_policy_id,
                "hot partition references unknown cache policy",
            )?;
            if !partition.low_fee_lane_id.is_empty() {
                ensure_known_key(
                    &self.low_fee_lanes,
                    &partition.low_fee_lane_id,
                    "hot partition references unknown low fee lane",
                )?;
            }
        }
        validate_map_keys(
            &self.routing_tables,
            |record| record.table_id.clone(),
            "routing table map",
        )?;
        for table in self.routing_tables.values() {
            table.validate()?;
            if table.topology_id != self.topology.topology_id {
                return Err("routing table topology id mismatch".to_string());
            }
            ensure_known_key(
                &self.shards,
                &table.fallback_shard_id,
                "routing table references unknown fallback shard",
            )?;
            for rule in &table.rules {
                ensure_known_key(
                    &self.shards,
                    &rule.primary_shard_id,
                    "routing rule references unknown shard",
                )?;
                for fallback in &rule.fallback_shard_ids {
                    ensure_known_key(
                        &self.shards,
                        fallback,
                        "routing rule references unknown fallback shard",
                    )?;
                }
                if !rule.low_fee_lane_id.is_empty() {
                    ensure_known_key(
                        &self.low_fee_lanes,
                        &rule.low_fee_lane_id,
                        "routing rule references unknown low fee lane",
                    )?;
                }
            }
        }
        validate_map_keys(
            &self.privacy_witnesses,
            |record| record.witness_id.clone(),
            "privacy witness map",
        )?;
        for witness in self.privacy_witnesses.values() {
            witness.validate()?;
            ensure_known_key(
                &self.shards,
                &witness.shard_id,
                "privacy witness references unknown shard",
            )?;
        }
        validate_map_keys(
            &self.hot_key_telemetry,
            |record| record.telemetry_id.clone(),
            "hot key telemetry map",
        )?;
        for telemetry in self.hot_key_telemetry.values() {
            telemetry.validate()?;
            ensure_known_key(
                &self.shards,
                &telemetry.shard_id,
                "hot telemetry references unknown shard",
            )?;
            ensure_known_key(
                &self.hot_partitions,
                &telemetry.partition_id,
                "hot telemetry references unknown partition",
            )?;
        }
        validate_map_keys(
            &self.atomic_bundles,
            |record| record.bundle_id.clone(),
            "atomic bundle map",
        )?;
        for bundle in self.atomic_bundles.values() {
            bundle.validate()?;
            ensure_known_key(
                &self.shards,
                &bundle.coordinator_shard_id,
                "atomic bundle references unknown coordinator shard",
            )?;
            for participant in &bundle.participant_shard_ids {
                ensure_known_key(
                    &self.shards,
                    participant,
                    "atomic bundle references unknown participant shard",
                )?;
            }
            if !bundle.fee_lane_id.is_empty() {
                ensure_known_key(
                    &self.low_fee_lanes,
                    &bundle.fee_lane_id,
                    "atomic bundle references unknown fee lane",
                )?;
            }
        }
        validate_map_keys(
            &self.lock_leases,
            |record| record.lease_id.clone(),
            "lock lease map",
        )?;
        for lease in self.lock_leases.values() {
            lease.validate()?;
            ensure_known_key(
                &self.atomic_bundles,
                &lease.bundle_id,
                "lock lease references unknown bundle",
            )?;
            ensure_known_key(
                &self.shards,
                &lease.shard_id,
                "lock lease references unknown shard",
            )?;
        }
        validate_map_keys(
            &self.handoff_receipts,
            |record| record.receipt_id.clone(),
            "handoff receipt map",
        )?;
        for receipt in self.handoff_receipts.values() {
            receipt.validate()?;
            ensure_known_key(
                &self.atomic_bundles,
                &receipt.bundle_id,
                "handoff receipt references unknown bundle",
            )?;
            ensure_known_key(
                &self.shards,
                &receipt.from_shard_id,
                "handoff receipt references unknown source shard",
            )?;
            ensure_known_key(
                &self.shards,
                &receipt.to_shard_id,
                "handoff receipt references unknown target shard",
            )?;
        }
        validate_map_keys(
            &self.rollback_roots,
            |record| record.rollback_id.clone(),
            "rollback root map",
        )?;
        for rollback in self.rollback_roots.values() {
            rollback.validate()?;
            ensure_known_key(
                &self.atomic_bundles,
                &rollback.bundle_id,
                "rollback root references unknown bundle",
            )?;
            ensure_known_key(
                &self.shards,
                &rollback.shard_id,
                "rollback root references unknown shard",
            )?;
        }
        validate_map_keys(
            &self.shard_assignments,
            |record| record.assignment_id.clone(),
            "shard assignment map",
        )?;
        for assignment in self.shard_assignments.values() {
            assignment.validate()?;
            ensure_known_key(
                &self.shards,
                &assignment.shard_id,
                "shard assignment references unknown shard",
            )?;
        }
        validate_map_keys(
            &self.pq_attestations,
            |record| record.attestation_id.clone(),
            "PQ attestation map",
        )?;
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            ensure_known_key(
                &self.shards,
                &attestation.shard_id,
                "PQ attestation references unknown shard",
            )?;
            ensure_known_key(
                &self.shard_assignments,
                &attestation.assignment_id,
                "PQ attestation references unknown assignment",
            )?;
        }
        validate_map_keys(
            &self.cache_policies,
            |record| record.policy_id.clone(),
            "cache policy map",
        )?;
        for policy in self.cache_policies.values() {
            policy.validate()?;
        }
        validate_map_keys(
            &self.eviction_proofs,
            |record| record.proof_id.clone(),
            "cache eviction proof map",
        )?;
        for proof in self.eviction_proofs.values() {
            proof.validate()?;
            ensure_known_key(
                &self.cache_policies,
                &proof.policy_id,
                "cache eviction proof references unknown policy",
            )?;
            ensure_known_key(
                &self.shards,
                &proof.shard_id,
                "cache eviction proof references unknown shard",
            )?;
        }
        validate_map_keys(
            &self.low_fee_lanes,
            |record| record.lane_id.clone(),
            "low fee lane map",
        )?;
        for lane in self.low_fee_lanes.values() {
            lane.validate()?;
            for shard_id in &lane.shard_ids {
                ensure_known_key(
                    &self.shards,
                    shard_id,
                    "low fee lane references unknown shard",
                )?;
            }
        }
        validate_map_keys(
            &self.da_shard_roots,
            |record| record.da_root_id.clone(),
            "DA shard root map",
        )?;
        for root in self.da_shard_roots.values() {
            root.validate()?;
            ensure_known_key(
                &self.shards,
                &root.shard_id,
                "DA shard root references unknown shard",
            )?;
            ensure_known_key(
                &self.replay_manifests,
                &root.replay_manifest_id,
                "DA shard root references unknown replay manifest",
            )?;
            if !root.low_fee_lane_id.is_empty() {
                ensure_known_key(
                    &self.low_fee_lanes,
                    &root.low_fee_lane_id,
                    "DA shard root references unknown low fee lane",
                )?;
            }
        }
        validate_map_keys(
            &self.replay_manifests,
            |record| record.manifest_id.clone(),
            "replay manifest map",
        )?;
        for manifest in self.replay_manifests.values() {
            manifest.validate()?;
            for shard_id in manifest.shard_state_roots.keys() {
                ensure_known_key(
                    &self.shards,
                    shard_id,
                    "replay manifest references unknown shard",
                )?;
            }
        }
        validate_map_keys(
            &self.public_records,
            |record| record.record_id.clone(),
            "state sharding public record map",
        )?;
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn shard_topology_id(
    epoch: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    shard_count: u64,
    hot_partition_count: u64,
    _routing_table_root: &str,
) -> String {
    domain_hash(
        "STATE-SHARDING-TOPOLOGY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(STATE_SHARDING_PROTOCOL_VERSION),
            HashPart::Int(epoch as i128),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
            HashPart::Int(shard_count as i128),
            HashPart::Int(hot_partition_count as i128),
        ],
        32,
    )
}

pub fn state_shard_id(
    topology_id: &str,
    shard_index: u64,
    partition_kind: &ShardPartitionKind,
) -> String {
    domain_hash(
        "STATE-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(topology_id),
            HashPart::Int(shard_index as i128),
            HashPart::Str(&partition_kind.label()),
        ],
        32,
    )
}

pub fn hot_state_partition_id(
    shard_id: &str,
    bucket_index: u64,
    access_class: &ShardAccessClass,
) -> String {
    domain_hash(
        "STATE-SHARDING-HOT-PARTITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Int(bucket_index as i128),
            HashPart::Str(&access_class.label()),
        ],
        32,
    )
}

pub fn routing_table_id(topology_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "STATE-SHARDING-ROUTING-TABLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(topology_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn routing_rule_id(
    table_id: &str,
    key_prefix_commitment: &str,
    partition_kind: &ShardPartitionKind,
    access_class: &ShardAccessClass,
    primary_shard_id: &str,
    priority: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-ROUTING-RULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(table_id),
            HashPart::Str(key_prefix_commitment),
            HashPart::Str(&partition_kind.label()),
            HashPart::Str(&access_class.label()),
            HashPart::Str(primary_shard_id),
            HashPart::Int(priority as i128),
        ],
        32,
    )
}

pub fn privacy_witness_id(
    shard_id: &str,
    access_class: &ShardAccessClass,
    blinded_key_root: &str,
    old_state_root: &str,
    new_state_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-PRIVACY-WITNESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(&access_class.label()),
            HashPart::Str(blinded_key_root),
            HashPart::Str(old_state_root),
            HashPart::Str(new_state_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn hot_key_telemetry_id(
    shard_id: &str,
    partition_id: &str,
    epoch: u64,
    bucket_index: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-HOT-KEY-TELEMETRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(partition_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(bucket_index as i128),
        ],
        32,
    )
}

pub fn cross_shard_atomic_bundle_id(
    coordinator_shard_id: &str,
    participant_shard_ids: &[ShardId],
    read_set_root: &str,
    write_set_root: &str,
    created_at_height: u64,
) -> String {
    let participants = json!(participant_shard_ids);
    domain_hash(
        "STATE-SHARDING-ATOMIC-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(coordinator_shard_id),
            HashPart::Json(&participants),
            HashPart::Str(read_set_root),
            HashPart::Str(write_set_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn lock_lease_id(
    bundle_id: &str,
    shard_id: &str,
    lock_mode: &LockLeaseMode,
    owner_commitment: &str,
    acquired_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-LOCK-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(shard_id),
            HashPart::Str(lock_mode.label()),
            HashPart::Str(owner_commitment),
            HashPart::Int(acquired_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn handoff_receipt_id(
    bundle_id: &str,
    from_shard_id: &str,
    to_shard_id: &str,
    state_delta_root: &str,
    accepted_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-HANDOFF-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(from_shard_id),
            HashPart::Str(to_shard_id),
            HashPart::Str(state_delta_root),
            HashPart::Int(accepted_at_height as i128),
        ],
        32,
    )
}

pub fn rollback_root_id(
    bundle_id: &str,
    shard_id: &str,
    pre_state_root: &str,
    inverse_delta_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-ROLLBACK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bundle_id),
            HashPart::Str(shard_id),
            HashPart::Str(pre_state_root),
            HashPart::Str(inverse_delta_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn shard_assignment_id(
    epoch: u64,
    shard_id: &str,
    operator_id: &str,
    role: &ShardAssignmentRole,
    duty_start_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-ASSIGNMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(shard_id),
            HashPart::Str(operator_id),
            HashPart::Str(role.label()),
            HashPart::Int(duty_start_height as i128),
        ],
        32,
    )
}

pub fn pq_shard_attestation_id(
    shard_id: &str,
    operator_id: &str,
    assignment_id: &str,
    transcript_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(operator_id),
            HashPart::Str(assignment_id),
            HashPart::Str(transcript_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn state_cache_policy_id(
    label: &str,
    eviction_kind: &CacheEvictionKind,
    max_entries: u64,
    max_bytes: u64,
    ttl_blocks: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-CACHE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(eviction_kind.label()),
            HashPart::Int(max_entries as i128),
            HashPart::Int(max_bytes as i128),
            HashPart::Int(ttl_blocks as i128),
        ],
        32,
    )
}

pub fn cache_eviction_proof_id(
    policy_id: &str,
    shard_id: &str,
    evicted_key_bucket_root: &str,
    before_cache_root: &str,
    after_cache_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-CACHE-EVICTION-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(shard_id),
            HashPart::Str(evicted_key_bucket_root),
            HashPart::Str(before_cache_root),
            HashPart::Str(after_cache_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_shard_lane_id(
    label: &str,
    traffic_class: &ShardTrafficClass,
    shard_ids: &[ShardId],
    min_fee_units: u64,
) -> String {
    let shards = json!(shard_ids);
    domain_hash(
        "STATE-SHARDING-LOW-FEE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(&traffic_class.label()),
            HashPart::Json(&shards),
            HashPart::Int(min_fee_units as i128),
        ],
        32,
    )
}

pub fn da_shard_root_id(
    shard_id: &str,
    da_epoch: u64,
    block_height: u64,
    blob_root: &str,
    erasure_root: &str,
) -> String {
    domain_hash(
        "STATE-SHARDING-DA-SHARD-ROOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Int(da_epoch as i128),
            HashPart::Int(block_height as i128),
            HashPart::Str(blob_root),
            HashPart::Str(erasure_root),
        ],
        32,
    )
}

pub fn replay_manifest_id(
    from_height: u64,
    to_height: u64,
    shard_state_roots: &BTreeMap<ShardId, String>,
    bundle_root: &str,
    routing_table_root: &str,
) -> String {
    let roots = json!(shard_state_roots);
    domain_hash(
        "STATE-SHARDING-REPLAY-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(from_height as i128),
            HashPart::Int(to_height as i128),
            HashPart::Json(&roots),
            HashPart::Str(bundle_root),
            HashPart::Str(routing_table_root),
        ],
        32,
    )
}

pub fn state_sharding_public_record_id(
    height: u64,
    scope: &str,
    label: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "STATE-SHARDING-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(scope),
            HashPart::Str(label),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn state_sharding_state_root_from_record(record: &Value) -> String {
    state_sharding_payload_root("STATE-SHARDING-STATE-ROOT", record)
}

pub fn state_sharding_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn state_sharding_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn state_sharding_bytes_root(domain: &str, value: &[u8]) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Bytes(value)],
        32,
    )
}

pub fn state_shard_record_root(records: &BTreeMap<ShardId, StateShard>) -> String {
    let leaves = records
        .values()
        .map(StateShard::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-SHARD", &leaves)
}

pub fn hot_partition_record_root(records: &BTreeMap<PartitionId, HotStatePartition>) -> String {
    let leaves = records
        .values()
        .map(HotStatePartition::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-HOT-PARTITION", &leaves)
}

pub fn routing_table_record_root(records: &BTreeMap<RoutingTableId, RoutingTable>) -> String {
    let leaves = records
        .values()
        .map(RoutingTable::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-ROUTING-TABLE", &leaves)
}

pub fn routing_rule_root(records: &[RoutingRule]) -> String {
    let leaves = records
        .iter()
        .map(RoutingRule::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-ROUTING-RULE", &leaves)
}

pub fn privacy_witness_record_root(records: &BTreeMap<String, PrivacyWitnessCommitment>) -> String {
    let leaves = records
        .values()
        .map(PrivacyWitnessCommitment::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-PRIVACY-WITNESS", &leaves)
}

pub fn hot_key_telemetry_record_root(records: &BTreeMap<String, HotKeyTelemetryBucket>) -> String {
    let leaves = records
        .values()
        .map(HotKeyTelemetryBucket::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-HOT-KEY-TELEMETRY", &leaves)
}

pub fn atomic_bundle_record_root(
    records: &BTreeMap<AtomicBundleId, CrossShardAtomicBundle>,
) -> String {
    let leaves = records
        .values()
        .map(CrossShardAtomicBundle::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-ATOMIC-BUNDLE", &leaves)
}

pub fn lock_lease_record_root(records: &BTreeMap<LockLeaseId, AtomicShardLockLease>) -> String {
    let leaves = records
        .values()
        .map(AtomicShardLockLease::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-LOCK-LEASE", &leaves)
}

pub fn handoff_receipt_record_root(
    records: &BTreeMap<HandoffReceiptId, ShardHandoffReceipt>,
) -> String {
    let leaves = records
        .values()
        .map(ShardHandoffReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-HANDOFF-RECEIPT", &leaves)
}

pub fn rollback_record_root(records: &BTreeMap<String, RollbackRoot>) -> String {
    let leaves = records
        .values()
        .map(RollbackRoot::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-ROLLBACK-ROOT", &leaves)
}

pub fn shard_assignment_record_root(records: &BTreeMap<AssignmentId, ShardAssignment>) -> String {
    let leaves = records
        .values()
        .map(ShardAssignment::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-ASSIGNMENT", &leaves)
}

pub fn pq_attestation_record_root(
    records: &BTreeMap<PqAttestationId, PqShardAttestation>,
) -> String {
    let leaves = records
        .values()
        .map(PqShardAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-PQ-ATTESTATION", &leaves)
}

pub fn cache_policy_record_root(records: &BTreeMap<String, StateCachePolicy>) -> String {
    let leaves = records
        .values()
        .map(StateCachePolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-CACHE-POLICY", &leaves)
}

pub fn eviction_proof_record_root(records: &BTreeMap<String, CacheEvictionProof>) -> String {
    let leaves = records
        .values()
        .map(CacheEvictionProof::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-CACHE-EVICTION-PROOF", &leaves)
}

pub fn low_fee_lane_record_root(records: &BTreeMap<String, LowFeeShardLane>) -> String {
    let leaves = records
        .values()
        .map(LowFeeShardLane::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-LOW-FEE-LANE", &leaves)
}

pub fn da_shard_record_root(records: &BTreeMap<String, DataAvailabilityShardRoot>) -> String {
    let leaves = records
        .values()
        .map(DataAvailabilityShardRoot::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-DA-SHARD-ROOT", &leaves)
}

pub fn replay_manifest_record_root(records: &BTreeMap<ReplayManifestId, ReplayManifest>) -> String {
    let leaves = records
        .values()
        .map(ReplayManifest::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-REPLAY-MANIFEST", &leaves)
}

pub fn state_sharding_public_record_root(
    records: &BTreeMap<String, StateShardingPublicRecord>,
) -> String {
    let leaves = records
        .values()
        .map(StateShardingPublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-PUBLIC-RECORD", &leaves)
}

pub fn shard_keyspace_boundary_root(topology_id: &str, shard_index: u64, boundary: &str) -> String {
    domain_hash(
        "STATE-SHARDING-KEYSPACE-BOUNDARY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(topology_id),
            HashPart::Int(shard_index as i128),
            HashPart::Str(boundary),
        ],
        32,
    )
}

pub fn hot_key_bucket_commitment(
    shard_id: &str,
    bucket_index: u64,
    access_class: &ShardAccessClass,
    bucket_label: &str,
) -> String {
    domain_hash(
        "STATE-SHARDING-HOT-KEY-BUCKET-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Int(bucket_index as i128),
            HashPart::Str(&access_class.label()),
            HashPart::Str(bucket_label),
        ],
        32,
    )
}

pub fn privacy_nullifier_bucket_root(shard_id: &str, blinded_key_root: &str) -> String {
    domain_hash(
        "STATE-SHARDING-PRIVACY-NULLIFIER-BUCKET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(blinded_key_root),
        ],
        32,
    )
}

pub fn privacy_witness_transcript_root(
    shard_id: &str,
    access_class: &ShardAccessClass,
    blinded_key_root: &str,
    old_state_root: &str,
    new_state_root: &str,
    read_set_root: &str,
    write_set_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-PRIVACY-WITNESS-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(&access_class.label()),
            HashPart::Str(blinded_key_root),
            HashPart::Str(old_state_root),
            HashPart::Str(new_state_root),
            HashPart::Str(read_set_root),
            HashPart::Str(write_set_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn telemetry_bucket_root_from_parts(
    shard_id: &str,
    partition_id: &str,
    epoch: u64,
    bucket_index: u64,
    key_bucket_commitment: &str,
    read_count_bucket: u64,
    write_count_bucket: u64,
    contention_score_bucket: u64,
    fee_pressure_bucket: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-HOT-KEY-TELEMETRY-BUCKET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(partition_id),
            HashPart::Int(epoch as i128),
            HashPart::Int(bucket_index as i128),
            HashPart::Str(key_bucket_commitment),
            HashPart::Int(read_count_bucket as i128),
            HashPart::Int(write_count_bucket as i128),
            HashPart::Int(contention_score_bucket as i128),
            HashPart::Int(fee_pressure_bucket as i128),
        ],
        32,
    )
}

pub fn pq_operator_key_commitment_root(operator_id: &str, role: &ShardAssignmentRole) -> String {
    domain_hash(
        "STATE-SHARDING-PQ-OPERATOR-KEY-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(role.label()),
            HashPart::Str(STATE_SHARDING_PQ_ATTESTATION_SCHEME),
        ],
        32,
    )
}

pub fn pq_shard_attestation_transcript_root(
    shard_id: &str,
    operator_id: &str,
    assignment_id: &str,
    public_key_commitment_root: &str,
    signed_payload_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "STATE-SHARDING-PQ-ATTESTATION-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id),
            HashPart::Str(operator_id),
            HashPart::Str(assignment_id),
            HashPart::Str(public_key_commitment_root),
            HashPart::Str(signed_payload_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn pq_signature_commitment_root(
    operator_id: &str,
    transcript_root: &str,
    scheme: &str,
) -> String {
    domain_hash(
        "STATE-SHARDING-PQ-SIGNATURE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(transcript_root),
            HashPart::Str(scheme),
        ],
        32,
    )
}

fn access_class_root(shards: &BTreeMap<ShardId, StateShard>) -> String {
    let leaves = shards
        .values()
        .map(|shard| {
            json!({
                "shard_id": shard.shard_id,
                "access_classes": shard.access_classes.iter().map(ShardAccessClass::label).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("STATE-SHARDING-ACCESS-CLASS", &leaves)
}

fn routing_score(table_id: &str, rule_id: &str, key_material: &str) -> u64 {
    let score = domain_hash(
        "STATE-SHARDING-ROUTING-SCORE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(table_id),
            HashPart::Str(rule_id),
            HashPart::Str(key_material),
        ],
        8,
    );
    u64::from_str_radix(&score, 16).unwrap_or(u64::MAX)
}

fn bucket_count(value: u64) -> u64 {
    if value == 0 {
        return 0;
    }
    let mut bucket = 1_u64;
    while bucket < value && bucket < (1_u64 << 62) {
        bucket <<= 1;
    }
    bucket
}

fn bucket_bps(value: u64) -> u64 {
    ((value.saturating_add(99)) / 100) * 100
}

fn deterministic_replica_set(labels: &[&str], offset: usize, count: usize) -> Vec<String> {
    (0..count)
        .map(|step| labels[(offset + step) % labels.len()].to_string())
        .collect::<Vec<_>>()
}

fn ensure_non_empty(value: &str, label: &str) -> StateShardingResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> StateShardingResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> StateShardingResult<()> {
    if value > STATE_SHARDING_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> StateShardingResult<()> {
    if !allowed.iter().any(|status| status == &value) {
        return Err(format!("{label} has unsupported value {value}"));
    }
    Ok(())
}

fn ensure_unique_strings(values: Vec<String>, label: &str) -> StateShardingResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(&value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate entries"));
        }
    }
    Ok(())
}

fn ensure_known_key<T>(
    map: &BTreeMap<String, T>,
    key: &str,
    message: &str,
) -> StateShardingResult<()> {
    if !map.contains_key(key) {
        return Err(message.to_string());
    }
    Ok(())
}

fn validate_map_keys<T, F>(
    map: &BTreeMap<String, T>,
    id_fn: F,
    label: &str,
) -> StateShardingResult<()>
where
    F: Fn(&T) -> String,
{
    for (key, value) in map {
        let expected = id_fn(value);
        if key != &expected {
            return Err(format!("{label} key mismatch"));
        }
    }
    Ok(())
}
