use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ZkContractParallelStateCacheResult<T> = Result<T, String>;

pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_PROTOCOL_VERSION: &str =
    "nebula-l2-zk-contract-parallel-state-cache-v1";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_SCHEMA_VERSION: &str =
    "zk-contract-parallel-state-cache-state-v1";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_DEVNET_HEIGHT: u64 = 2_409;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_ENCRYPTION_SUITE: &str =
    "ML-KEM-768+XChaCha20-Poly1305-encrypted-state-shards";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_WITNESS_SUITE: &str =
    "read-write-witness-pq-transcript-v1";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_LEASE_SUITE: &str = "cache-lease-commitment-v1";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_CONFLICT_SUITE: &str = "parallel-conflict-proof-v1";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_EVICTION_SUITE: &str =
    "deterministic-eviction-receipt-v1";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_NAMESPACE: &str =
    "nebula.devnet.zk_contract_parallel_state_cache";
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_SHARD_TTL_BLOCKS: u64 = 96;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_LEASE_TTL_BLOCKS: u64 = 8;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 3;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_SHARDS: usize = 16_384;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_WITNESSES: usize = 32_768;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_LEASES: usize = 32_768;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_CONFLICT_PROOFS: usize = 16_384;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_EXECUTION_LANES: usize = 128;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_PROOF_BATCHES: usize = 16_384;
pub const ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_EVICTION_RECEIPTS: usize = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardClass {
    Account,
    ContractStorage,
    ContractCode,
    PrivatePool,
    LiquidityPosition,
    OracleCache,
    BridgeBuffer,
    ProofScratch,
}

impl ShardClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::ContractStorage => "contract_storage",
            Self::ContractCode => "contract_code",
            Self::PrivatePool => "private_pool",
            Self::LiquidityPosition => "liquidity_position",
            Self::OracleCache => "oracle_cache",
            Self::BridgeBuffer => "bridge_buffer",
            Self::ProofScratch => "proof_scratch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Hot,
    Warm,
    Pinned,
    WriteLocked,
    EvictionCandidate,
    Evicted,
    Quarantined,
}

impl ShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hot => "hot",
            Self::Warm => "warm",
            Self::Pinned => "pinned",
            Self::WriteLocked => "write_locked",
            Self::EvictionCandidate => "eviction_candidate",
            Self::Evicted => "evicted",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(self) -> bool {
        !matches!(self, Self::Evicted | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessKind {
    Read,
    Write,
    ReadWrite,
    Snapshot,
    Eviction,
}

impl WitnessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
            Self::Snapshot => "snapshot",
            Self::Eviction => "eviction",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseMode {
    SharedRead,
    ExclusiveWrite,
    SpeculativeWrite,
    ProofOnly,
}

impl LeaseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SharedRead => "shared_read",
            Self::ExclusiveWrite => "exclusive_write",
            Self::SpeculativeWrite => "speculative_write",
            Self::ProofOnly => "proof_only",
        }
    }

    pub fn writes(self) -> bool {
        matches!(self, Self::ExclusiveWrite | Self::SpeculativeWrite)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanePriority {
    Realtime,
    Fast,
    Batch,
    Background,
}

impl LanePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Realtime => "realtime",
            Self::Fast => "fast",
            Self::Batch => "batch",
            Self::Background => "background",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBatchStatus {
    Open,
    Sealed,
    Proving,
    Proven,
    Failed,
}

impl ProofBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Proven => "proven",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    ReadAfterWrite,
    WriteAfterRead,
    WriteAfterWrite,
    LeaseExpired,
    StaleWitness,
    LaneFenceViolation,
}

impl ConflictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadAfterWrite => "read_after_write",
            Self::WriteAfterRead => "write_after_read",
            Self::WriteAfterWrite => "write_after_write",
            Self::LeaseExpired => "lease_expired",
            Self::StaleWitness => "stale_witness",
            Self::LaneFenceViolation => "lane_fence_violation",
        }
    }
}

pub trait CacheRecord {
    fn public_record(&self) -> Value;

    fn root(&self, domain: &str) -> String {
        domain_hash(domain, &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub namespace: String,
    pub encryption_suite: String,
    pub witness_suite: String,
    pub lease_suite: String,
    pub conflict_suite: String,
    pub eviction_suite: String,
    pub shard_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub proof_batch_window_blocks: u64,
    pub max_parallel_lanes: u64,
    pub max_shards_per_lane: u64,
    pub deterministic_eviction_seed: String,
    pub privacy_policy_root: String,
}

impl Config {
    pub fn devnet() -> ZkContractParallelStateCacheResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            protocol_version: ZK_CONTRACT_PARALLEL_STATE_CACHE_PROTOCOL_VERSION.to_string(),
            schema_version: ZK_CONTRACT_PARALLEL_STATE_CACHE_SCHEMA_VERSION.to_string(),
            namespace: ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_NAMESPACE.to_string(),
            encryption_suite: ZK_CONTRACT_PARALLEL_STATE_CACHE_ENCRYPTION_SUITE.to_string(),
            witness_suite: ZK_CONTRACT_PARALLEL_STATE_CACHE_WITNESS_SUITE.to_string(),
            lease_suite: ZK_CONTRACT_PARALLEL_STATE_CACHE_LEASE_SUITE.to_string(),
            conflict_suite: ZK_CONTRACT_PARALLEL_STATE_CACHE_CONFLICT_SUITE.to_string(),
            eviction_suite: ZK_CONTRACT_PARALLEL_STATE_CACHE_EVICTION_SUITE.to_string(),
            shard_ttl_blocks: ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_SHARD_TTL_BLOCKS,
            lease_ttl_blocks: ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_LEASE_TTL_BLOCKS,
            proof_batch_window_blocks: ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_BATCH_WINDOW_BLOCKS,
            max_parallel_lanes: 12,
            max_shards_per_lane: 256,
            deterministic_eviction_seed: string_root(
                "ZK-CONTRACT-PARALLEL-CACHE-EVICTION-SEED",
                "devnet-low-latency-cache",
            ),
            privacy_policy_root: string_root(
                "ZK-CONTRACT-PARALLEL-CACHE-PRIVACY",
                "encrypted-shard-roots-witness-commitments-only",
            ),
        };
        config.config_id = config_id(&config);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.config_id, "config id")?;
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.schema_version, "schema version")?;
        ensure_non_empty(&self.namespace, "namespace")?;
        ensure_non_empty(&self.encryption_suite, "encryption suite")?;
        ensure_non_empty(&self.witness_suite, "witness suite")?;
        ensure_non_empty(&self.lease_suite, "lease suite")?;
        ensure_non_empty(&self.conflict_suite, "conflict suite")?;
        ensure_non_empty(&self.eviction_suite, "eviction suite")?;
        ensure_positive(self.shard_ttl_blocks, "shard ttl blocks")?;
        ensure_positive(self.lease_ttl_blocks, "lease ttl blocks")?;
        ensure_positive(self.proof_batch_window_blocks, "proof batch window blocks")?;
        ensure_positive(self.max_parallel_lanes, "max parallel lanes")?;
        ensure_positive(self.max_shards_per_lane, "max shards per lane")?;
        ensure_non_empty(
            &self.deterministic_eviction_seed,
            "deterministic eviction seed",
        )?;
        ensure_non_empty(&self.privacy_policy_root, "privacy policy root")?;
        if self.protocol_version != ZK_CONTRACT_PARALLEL_STATE_CACHE_PROTOCOL_VERSION {
            return Err(format!(
                "unsupported zk contract parallel state cache version {}",
                self.protocol_version
            ));
        }
        let required = config_id(self);
        if self.config_id != required {
            return Err(format!(
                "config id mismatch required {required} got {}",
                self.config_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_id": self.config_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "namespace": self.namespace,
            "encryption_suite": self.encryption_suite,
            "witness_suite": self.witness_suite,
            "lease_suite": self.lease_suite,
            "conflict_suite": self.conflict_suite,
            "eviction_suite": self.eviction_suite,
            "shard_ttl_blocks": self.shard_ttl_blocks,
            "lease_ttl_blocks": self.lease_ttl_blocks,
            "proof_batch_window_blocks": self.proof_batch_window_blocks,
            "max_parallel_lanes": self.max_parallel_lanes,
            "max_shards_per_lane": self.max_shards_per_lane,
            "deterministic_eviction_seed": self.deterministic_eviction_seed,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateShard {
    pub shard_id: String,
    pub contract_id: String,
    pub shard_class: ShardClass,
    pub namespace: String,
    pub key_commitment: String,
    pub ciphertext_commitment: String,
    pub nonce_commitment: String,
    pub state_slot_root: String,
    pub previous_shard_root: String,
    pub version: u64,
    pub size_bytes: u64,
    pub created_at_height: u64,
    pub last_access_height: u64,
    pub expires_at_height: u64,
    pub status: ShardStatus,
    pub lane_affinity: String,
    pub tags: BTreeSet<String>,
}

impl EncryptedStateShard {
    pub fn new(
        contract_id: &str,
        shard_class: ShardClass,
        namespace: &str,
        version: u64,
        created_at_height: u64,
        lane_affinity: &str,
        tags: BTreeSet<String>,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(contract_id, "contract id")?;
        ensure_non_empty(namespace, "shard namespace")?;
        ensure_non_empty(lane_affinity, "lane affinity")?;
        ensure_positive(version, "shard version")?;
        let state_slot_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-SLOT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(contract_id),
                HashPart::Str(shard_class.as_str()),
                HashPart::Str(namespace),
                HashPart::Int(version as i128),
            ],
            32,
        );
        let previous_shard_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-PREVIOUS-SHARD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(contract_id),
                HashPart::Str(namespace),
                HashPart::Int((version.saturating_sub(1)) as i128),
            ],
            32,
        );
        let key_commitment = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-SHARD-KEY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(contract_id),
                HashPart::Str(namespace),
                HashPart::Int(version as i128),
            ],
            32,
        );
        let ciphertext_commitment = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-SHARD-CIPHERTEXT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&state_slot_root),
                HashPart::Str(&key_commitment),
            ],
            32,
        );
        let nonce_commitment = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-SHARD-NONCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(contract_id),
                HashPart::Str(namespace),
                HashPart::Str(lane_affinity),
            ],
            32,
        );
        let shard_id = shard_id(
            contract_id,
            shard_class,
            namespace,
            version,
            &ciphertext_commitment,
        );
        let shard = Self {
            shard_id,
            contract_id: contract_id.to_string(),
            shard_class,
            namespace: namespace.to_string(),
            key_commitment,
            ciphertext_commitment,
            nonce_commitment,
            state_slot_root,
            previous_shard_root,
            version,
            size_bytes: 16_384 + (version * 256),
            created_at_height,
            last_access_height: created_at_height,
            expires_at_height: created_at_height
                + ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_SHARD_TTL_BLOCKS,
            status: ShardStatus::Hot,
            lane_affinity: lane_affinity.to_string(),
            tags,
        };
        shard.validate()?;
        Ok(shard)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.shard_id, "shard id")?;
        ensure_non_empty(&self.contract_id, "shard contract id")?;
        ensure_non_empty(&self.namespace, "shard namespace")?;
        ensure_non_empty(&self.key_commitment, "shard key commitment")?;
        ensure_non_empty(&self.ciphertext_commitment, "shard ciphertext commitment")?;
        ensure_non_empty(&self.nonce_commitment, "shard nonce commitment")?;
        ensure_non_empty(&self.state_slot_root, "shard state slot root")?;
        ensure_non_empty(&self.previous_shard_root, "previous shard root")?;
        ensure_positive(self.version, "shard version")?;
        ensure_positive(self.size_bytes, "shard size bytes")?;
        ensure_non_empty(&self.lane_affinity, "shard lane affinity")?;
        if self.expires_at_height < self.created_at_height {
            return Err(format!("shard {} expires before creation", self.shard_id));
        }
        if self.last_access_height < self.created_at_height {
            return Err(format!(
                "shard {} last access before creation",
                self.shard_id
            ));
        }
        let required = shard_id(
            &self.contract_id,
            self.shard_class,
            &self.namespace,
            self.version,
            &self.ciphertext_commitment,
        );
        if self.shard_id != required {
            return Err(format!(
                "shard id mismatch required {required} got {}",
                self.shard_id
            ));
        }
        Ok(())
    }
}

impl CacheRecord for EncryptedStateShard {
    fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "contract_id": self.contract_id,
            "shard_class": self.shard_class.as_str(),
            "namespace": self.namespace,
            "key_commitment": self.key_commitment,
            "ciphertext_commitment": self.ciphertext_commitment,
            "nonce_commitment": self.nonce_commitment,
            "state_slot_root": self.state_slot_root,
            "previous_shard_root": self.previous_shard_root,
            "version": self.version,
            "size_bytes": self.size_bytes,
            "created_at_height": self.created_at_height,
            "last_access_height": self.last_access_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "lane_affinity": self.lane_affinity,
            "tags": self.tags.iter().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadWriteWitness {
    pub witness_id: String,
    pub transaction_id: String,
    pub contract_id: String,
    pub kind: WitnessKind,
    pub lane_id: String,
    pub read_set: BTreeSet<String>,
    pub write_set: BTreeSet<String>,
    pub read_root: String,
    pub write_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub witness_commitment: String,
    pub nullifier_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl ReadWriteWitness {
    pub fn new(
        transaction_id: &str,
        contract_id: &str,
        kind: WitnessKind,
        lane_id: &str,
        read_set: BTreeSet<String>,
        write_set: BTreeSet<String>,
        pre_state_root: &str,
        opened_at_height: u64,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(transaction_id, "transaction id")?;
        ensure_non_empty(contract_id, "witness contract id")?;
        ensure_non_empty(lane_id, "witness lane id")?;
        ensure_non_empty(pre_state_root, "pre state root")?;
        let read_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-WITNESS-READ", &read_set);
        let write_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-WITNESS-WRITE", &write_set);
        let post_state_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-WITNESS-POST-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(pre_state_root),
                HashPart::Str(&read_root),
                HashPart::Str(&write_root),
                HashPart::Str(transaction_id),
            ],
            32,
        );
        let witness_commitment = witness_commitment(
            transaction_id,
            contract_id,
            kind,
            lane_id,
            &read_root,
            &write_root,
            pre_state_root,
            &post_state_root,
        );
        let nullifier_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-WITNESS-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(transaction_id),
                HashPart::Str(&witness_commitment),
            ],
            32,
        );
        let witness_id = witness_id(transaction_id, &witness_commitment);
        let witness = Self {
            witness_id,
            transaction_id: transaction_id.to_string(),
            contract_id: contract_id.to_string(),
            kind,
            lane_id: lane_id.to_string(),
            read_set,
            write_set,
            read_root,
            write_root,
            pre_state_root: pre_state_root.to_string(),
            post_state_root,
            witness_commitment,
            nullifier_root,
            opened_at_height,
            closes_at_height: opened_at_height
                + ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_LEASE_TTL_BLOCKS,
        };
        witness.validate()?;
        Ok(witness)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.witness_id, "witness id")?;
        ensure_non_empty(&self.transaction_id, "witness transaction id")?;
        ensure_non_empty(&self.contract_id, "witness contract id")?;
        ensure_non_empty(&self.lane_id, "witness lane id")?;
        ensure_non_empty(&self.read_root, "witness read root")?;
        ensure_non_empty(&self.write_root, "witness write root")?;
        ensure_non_empty(&self.pre_state_root, "witness pre state root")?;
        ensure_non_empty(&self.post_state_root, "witness post state root")?;
        ensure_non_empty(&self.witness_commitment, "witness commitment")?;
        ensure_non_empty(&self.nullifier_root, "witness nullifier root")?;
        if self.closes_at_height < self.opened_at_height {
            return Err(format!("witness {} closes before open", self.witness_id));
        }
        let required_read = set_root("ZK-CONTRACT-PARALLEL-CACHE-WITNESS-READ", &self.read_set);
        let required_write = set_root("ZK-CONTRACT-PARALLEL-CACHE-WITNESS-WRITE", &self.write_set);
        if self.read_root != required_read {
            return Err(format!("witness {} read root mismatch", self.witness_id));
        }
        if self.write_root != required_write {
            return Err(format!("witness {} write root mismatch", self.witness_id));
        }
        let required_commitment = witness_commitment(
            &self.transaction_id,
            &self.contract_id,
            self.kind,
            &self.lane_id,
            &self.read_root,
            &self.write_root,
            &self.pre_state_root,
            &self.post_state_root,
        );
        if self.witness_commitment != required_commitment {
            return Err(format!(
                "witness commitment mismatch for {}",
                self.witness_id
            ));
        }
        let required_id = witness_id(&self.transaction_id, &self.witness_commitment);
        if self.witness_id != required_id {
            return Err(format!("witness id mismatch required {required_id}"));
        }
        Ok(())
    }
}

impl CacheRecord for ReadWriteWitness {
    fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "transaction_id": self.transaction_id,
            "contract_id": self.contract_id,
            "kind": self.kind.as_str(),
            "lane_id": self.lane_id,
            "read_set": self.read_set.iter().cloned().collect::<Vec<_>>(),
            "write_set": self.write_set.iter().cloned().collect::<Vec<_>>(),
            "read_root": self.read_root,
            "write_root": self.write_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "witness_commitment": self.witness_commitment,
            "nullifier_root": self.nullifier_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheLeaseCommitment {
    pub lease_id: String,
    pub holder_id: String,
    pub transaction_id: String,
    pub lane_id: String,
    pub mode: LeaseMode,
    pub shard_ids: BTreeSet<String>,
    pub shard_root: String,
    pub witness_id: String,
    pub commitment: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub released_at_height: Option<u64>,
}

impl CacheLeaseCommitment {
    pub fn new(
        holder_id: &str,
        transaction_id: &str,
        lane_id: &str,
        mode: LeaseMode,
        shard_ids: BTreeSet<String>,
        witness_id: &str,
        opened_at_height: u64,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(holder_id, "lease holder id")?;
        ensure_non_empty(transaction_id, "lease transaction id")?;
        ensure_non_empty(lane_id, "lease lane id")?;
        ensure_non_empty(witness_id, "lease witness id")?;
        ensure_not_empty_set(&shard_ids, "lease shards")?;
        let shard_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-LEASE-SHARDS", &shard_ids);
        let commitment = lease_commitment(
            holder_id,
            transaction_id,
            lane_id,
            mode,
            &shard_root,
            witness_id,
            opened_at_height,
        );
        let lease_id = lease_id(holder_id, transaction_id, &commitment);
        let lease = Self {
            lease_id,
            holder_id: holder_id.to_string(),
            transaction_id: transaction_id.to_string(),
            lane_id: lane_id.to_string(),
            mode,
            shard_ids,
            shard_root,
            witness_id: witness_id.to_string(),
            commitment,
            opened_at_height,
            expires_at_height: opened_at_height
                + ZK_CONTRACT_PARALLEL_STATE_CACHE_DEFAULT_LEASE_TTL_BLOCKS,
            released_at_height: None,
        };
        lease.validate()?;
        Ok(lease)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.lease_id, "lease id")?;
        ensure_non_empty(&self.holder_id, "lease holder id")?;
        ensure_non_empty(&self.transaction_id, "lease transaction id")?;
        ensure_non_empty(&self.lane_id, "lease lane id")?;
        ensure_not_empty_set(&self.shard_ids, "lease shard ids")?;
        ensure_non_empty(&self.shard_root, "lease shard root")?;
        ensure_non_empty(&self.witness_id, "lease witness id")?;
        ensure_non_empty(&self.commitment, "lease commitment")?;
        if self.expires_at_height < self.opened_at_height {
            return Err(format!("lease {} expires before open", self.lease_id));
        }
        if let Some(released) = self.released_at_height {
            if released < self.opened_at_height {
                return Err(format!("lease {} released before open", self.lease_id));
            }
        }
        let required_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-LEASE-SHARDS", &self.shard_ids);
        if self.shard_root != required_root {
            return Err(format!("lease {} shard root mismatch", self.lease_id));
        }
        let required_commitment = lease_commitment(
            &self.holder_id,
            &self.transaction_id,
            &self.lane_id,
            self.mode,
            &self.shard_root,
            &self.witness_id,
            self.opened_at_height,
        );
        if self.commitment != required_commitment {
            return Err(format!("lease {} commitment mismatch", self.lease_id));
        }
        let required_id = lease_id(&self.holder_id, &self.transaction_id, &self.commitment);
        if self.lease_id != required_id {
            return Err(format!("lease id mismatch required {required_id}"));
        }
        Ok(())
    }
}

impl CacheRecord for CacheLeaseCommitment {
    fn public_record(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "holder_id": self.holder_id,
            "transaction_id": self.transaction_id,
            "lane_id": self.lane_id,
            "mode": self.mode.as_str(),
            "writes": self.mode.writes(),
            "shard_ids": self.shard_ids.iter().cloned().collect::<Vec<_>>(),
            "shard_root": self.shard_root,
            "witness_id": self.witness_id,
            "commitment": self.commitment,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "released_at_height": self.released_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConflictProof {
    pub conflict_id: String,
    pub kind: ConflictKind,
    pub left_transaction_id: String,
    pub right_transaction_id: String,
    pub left_witness_id: String,
    pub right_witness_id: String,
    pub lease_id: String,
    pub lane_id: String,
    pub shard_ids: BTreeSet<String>,
    pub shard_root: String,
    pub evidence_root: String,
    pub detected_at_height: u64,
    pub resolved: bool,
}

impl ConflictProof {
    pub fn new(
        kind: ConflictKind,
        left_transaction_id: &str,
        right_transaction_id: &str,
        left_witness_id: &str,
        right_witness_id: &str,
        lease_id: &str,
        lane_id: &str,
        shard_ids: BTreeSet<String>,
        detected_at_height: u64,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(left_transaction_id, "left transaction id")?;
        ensure_non_empty(right_transaction_id, "right transaction id")?;
        ensure_non_empty(left_witness_id, "left witness id")?;
        ensure_non_empty(right_witness_id, "right witness id")?;
        ensure_non_empty(lease_id, "conflict lease id")?;
        ensure_non_empty(lane_id, "conflict lane id")?;
        ensure_not_empty_set(&shard_ids, "conflict shard ids")?;
        let shard_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-CONFLICT-SHARDS", &shard_ids);
        let evidence_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-CONFLICT-EVIDENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(left_witness_id),
                HashPart::Str(right_witness_id),
                HashPart::Str(&shard_root),
                HashPart::Str(lease_id),
            ],
            32,
        );
        let conflict_id = conflict_id(
            kind,
            left_transaction_id,
            right_transaction_id,
            &evidence_root,
        );
        let proof = Self {
            conflict_id,
            kind,
            left_transaction_id: left_transaction_id.to_string(),
            right_transaction_id: right_transaction_id.to_string(),
            left_witness_id: left_witness_id.to_string(),
            right_witness_id: right_witness_id.to_string(),
            lease_id: lease_id.to_string(),
            lane_id: lane_id.to_string(),
            shard_ids,
            shard_root,
            evidence_root,
            detected_at_height,
            resolved: false,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.conflict_id, "conflict id")?;
        ensure_non_empty(&self.left_transaction_id, "left transaction id")?;
        ensure_non_empty(&self.right_transaction_id, "right transaction id")?;
        ensure_non_empty(&self.left_witness_id, "left witness id")?;
        ensure_non_empty(&self.right_witness_id, "right witness id")?;
        ensure_non_empty(&self.lease_id, "conflict lease id")?;
        ensure_non_empty(&self.lane_id, "conflict lane id")?;
        ensure_not_empty_set(&self.shard_ids, "conflict shard ids")?;
        ensure_non_empty(&self.shard_root, "conflict shard root")?;
        ensure_non_empty(&self.evidence_root, "conflict evidence root")?;
        let required_root = set_root(
            "ZK-CONTRACT-PARALLEL-CACHE-CONFLICT-SHARDS",
            &self.shard_ids,
        );
        if self.shard_root != required_root {
            return Err(format!("conflict {} shard root mismatch", self.conflict_id));
        }
        let required_evidence = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-CONFLICT-EVIDENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(self.kind.as_str()),
                HashPart::Str(&self.left_witness_id),
                HashPart::Str(&self.right_witness_id),
                HashPart::Str(&self.shard_root),
                HashPart::Str(&self.lease_id),
            ],
            32,
        );
        if self.evidence_root != required_evidence {
            return Err(format!(
                "conflict {} evidence root mismatch",
                self.conflict_id
            ));
        }
        let required_id = conflict_id(
            self.kind,
            &self.left_transaction_id,
            &self.right_transaction_id,
            &self.evidence_root,
        );
        if self.conflict_id != required_id {
            return Err(format!("conflict id mismatch required {required_id}"));
        }
        Ok(())
    }
}

impl CacheRecord for ConflictProof {
    fn public_record(&self) -> Value {
        json!({
            "conflict_id": self.conflict_id,
            "kind": self.kind.as_str(),
            "left_transaction_id": self.left_transaction_id,
            "right_transaction_id": self.right_transaction_id,
            "left_witness_id": self.left_witness_id,
            "right_witness_id": self.right_witness_id,
            "lease_id": self.lease_id,
            "lane_id": self.lane_id,
            "shard_ids": self.shard_ids.iter().cloned().collect::<Vec<_>>(),
            "shard_root": self.shard_root,
            "evidence_root": self.evidence_root,
            "detected_at_height": self.detected_at_height,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionLane {
    pub lane_id: String,
    pub label: String,
    pub priority: LanePriority,
    pub max_inflight: u64,
    pub latency_budget_ms: u64,
    pub assigned_contracts: BTreeSet<String>,
    pub pinned_shards: BTreeSet<String>,
    pub fence_root: String,
    pub last_committed_height: u64,
    pub backlog_weight: u64,
}

impl ExecutionLane {
    pub fn new(
        label: &str,
        priority: LanePriority,
        max_inflight: u64,
        latency_budget_ms: u64,
        contracts: BTreeSet<String>,
        pinned_shards: BTreeSet<String>,
        last_committed_height: u64,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(label, "lane label")?;
        ensure_positive(max_inflight, "lane max inflight")?;
        ensure_positive(latency_budget_ms, "lane latency budget ms")?;
        ensure_not_empty_set(&contracts, "lane contracts")?;
        let contract_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-LANE-CONTRACTS", &contracts);
        let pinned_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-LANE-PINNED", &pinned_shards);
        let fence_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-LANE-FENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(priority.as_str()),
                HashPart::Str(&contract_root),
                HashPart::Str(&pinned_root),
            ],
            32,
        );
        let lane_id = lane_id(label, priority, &fence_root);
        let lane = Self {
            lane_id,
            label: label.to_string(),
            priority,
            max_inflight,
            latency_budget_ms,
            assigned_contracts: contracts,
            pinned_shards,
            fence_root,
            last_committed_height,
            backlog_weight: 0,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.lane_id, "lane id")?;
        ensure_non_empty(&self.label, "lane label")?;
        ensure_positive(self.max_inflight, "lane max inflight")?;
        ensure_positive(self.latency_budget_ms, "lane latency budget ms")?;
        ensure_not_empty_set(&self.assigned_contracts, "lane assigned contracts")?;
        ensure_non_empty(&self.fence_root, "lane fence root")?;
        let contract_root = set_root(
            "ZK-CONTRACT-PARALLEL-CACHE-LANE-CONTRACTS",
            &self.assigned_contracts,
        );
        let pinned_root = set_root(
            "ZK-CONTRACT-PARALLEL-CACHE-LANE-PINNED",
            &self.pinned_shards,
        );
        let required_fence = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-LANE-FENCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.label),
                HashPart::Str(self.priority.as_str()),
                HashPart::Str(&contract_root),
                HashPart::Str(&pinned_root),
            ],
            32,
        );
        if self.fence_root != required_fence {
            return Err(format!("lane {} fence root mismatch", self.lane_id));
        }
        let required_id = lane_id(&self.label, self.priority, &self.fence_root);
        if self.lane_id != required_id {
            return Err(format!("lane id mismatch required {required_id}"));
        }
        Ok(())
    }
}

impl CacheRecord for ExecutionLane {
    fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "label": self.label,
            "priority": self.priority.as_str(),
            "max_inflight": self.max_inflight,
            "latency_budget_ms": self.latency_budget_ms,
            "assigned_contracts": self.assigned_contracts.iter().cloned().collect::<Vec<_>>(),
            "pinned_shards": self.pinned_shards.iter().cloned().collect::<Vec<_>>(),
            "fence_root": self.fence_root,
            "last_committed_height": self.last_committed_height,
            "backlog_weight": self.backlog_weight,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofJobBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub status: ProofBatchStatus,
    pub job_ids: BTreeSet<String>,
    pub witness_ids: BTreeSet<String>,
    pub shard_ids: BTreeSet<String>,
    pub job_root: String,
    pub witness_root: String,
    pub shard_root: String,
    pub aggregate_input_root: String,
    pub proof_commitment: String,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub fee_micro_xmr: u64,
}

impl ProofJobBatch {
    pub fn new(
        lane_id: &str,
        job_ids: BTreeSet<String>,
        witness_ids: BTreeSet<String>,
        shard_ids: BTreeSet<String>,
        opened_at_height: u64,
        fee_micro_xmr: u64,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(lane_id, "proof batch lane id")?;
        ensure_not_empty_set(&job_ids, "proof batch jobs")?;
        ensure_not_empty_set(&witness_ids, "proof batch witnesses")?;
        ensure_not_empty_set(&shard_ids, "proof batch shards")?;
        ensure_positive(fee_micro_xmr, "proof batch fee")?;
        let job_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-PROOF-JOBS", &job_ids);
        let witness_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-PROOF-WITNESSES", &witness_ids);
        let shard_root = set_root("ZK-CONTRACT-PARALLEL-CACHE-PROOF-SHARDS", &shard_ids);
        let aggregate_input_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-PROOF-AGGREGATE-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_id),
                HashPart::Str(&job_root),
                HashPart::Str(&witness_root),
                HashPart::Str(&shard_root),
            ],
            32,
        );
        let proof_commitment = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-PROOF-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&aggregate_input_root),
                HashPart::Int(opened_at_height as i128),
            ],
            32,
        );
        let batch_id = proof_batch_id(lane_id, &aggregate_input_root, opened_at_height);
        let batch = Self {
            batch_id,
            lane_id: lane_id.to_string(),
            status: ProofBatchStatus::Open,
            job_ids,
            witness_ids,
            shard_ids,
            job_root,
            witness_root,
            shard_root,
            aggregate_input_root,
            proof_commitment,
            opened_at_height,
            sealed_at_height: None,
            fee_micro_xmr,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.batch_id, "proof batch id")?;
        ensure_non_empty(&self.lane_id, "proof batch lane id")?;
        ensure_not_empty_set(&self.job_ids, "proof batch job ids")?;
        ensure_not_empty_set(&self.witness_ids, "proof batch witness ids")?;
        ensure_not_empty_set(&self.shard_ids, "proof batch shard ids")?;
        ensure_non_empty(&self.job_root, "proof batch job root")?;
        ensure_non_empty(&self.witness_root, "proof batch witness root")?;
        ensure_non_empty(&self.shard_root, "proof batch shard root")?;
        ensure_non_empty(
            &self.aggregate_input_root,
            "proof batch aggregate input root",
        )?;
        ensure_non_empty(&self.proof_commitment, "proof batch proof commitment")?;
        ensure_positive(self.fee_micro_xmr, "proof batch fee")?;
        if let Some(sealed) = self.sealed_at_height {
            if sealed < self.opened_at_height {
                return Err(format!("proof batch {} sealed before open", self.batch_id));
            }
        }
        let required_job = set_root("ZK-CONTRACT-PARALLEL-CACHE-PROOF-JOBS", &self.job_ids);
        let required_witness = set_root(
            "ZK-CONTRACT-PARALLEL-CACHE-PROOF-WITNESSES",
            &self.witness_ids,
        );
        let required_shard = set_root("ZK-CONTRACT-PARALLEL-CACHE-PROOF-SHARDS", &self.shard_ids);
        if self.job_root != required_job
            || self.witness_root != required_witness
            || self.shard_root != required_shard
        {
            return Err(format!("proof batch {} set root mismatch", self.batch_id));
        }
        let required_input = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-PROOF-AGGREGATE-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.lane_id),
                HashPart::Str(&self.job_root),
                HashPart::Str(&self.witness_root),
                HashPart::Str(&self.shard_root),
            ],
            32,
        );
        if self.aggregate_input_root != required_input {
            return Err(format!(
                "proof batch {} aggregate input mismatch",
                self.batch_id
            ));
        }
        let required_id = proof_batch_id(
            &self.lane_id,
            &self.aggregate_input_root,
            self.opened_at_height,
        );
        if self.batch_id != required_id {
            return Err(format!("proof batch id mismatch required {required_id}"));
        }
        Ok(())
    }
}

impl CacheRecord for ProofJobBatch {
    fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "job_ids": self.job_ids.iter().cloned().collect::<Vec<_>>(),
            "witness_ids": self.witness_ids.iter().cloned().collect::<Vec<_>>(),
            "shard_ids": self.shard_ids.iter().cloned().collect::<Vec<_>>(),
            "job_root": self.job_root,
            "witness_root": self.witness_root,
            "shard_root": self.shard_root,
            "aggregate_input_root": self.aggregate_input_root,
            "proof_commitment": self.proof_commitment,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "fee_micro_xmr": self.fee_micro_xmr,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvictionReceipt {
    pub receipt_id: String,
    pub shard_id: String,
    pub lane_id: String,
    pub reason: String,
    pub previous_shard_root: String,
    pub eviction_root: String,
    pub deterministic_order: u64,
    pub evicted_at_height: u64,
    pub retained_witness_root: String,
}

impl EvictionReceipt {
    pub fn new(
        shard_id_value: &str,
        lane_id: &str,
        reason: &str,
        previous_shard_root: &str,
        deterministic_order: u64,
        evicted_at_height: u64,
        retained_witness_root: &str,
    ) -> ZkContractParallelStateCacheResult<Self> {
        ensure_non_empty(shard_id_value, "eviction shard id")?;
        ensure_non_empty(lane_id, "eviction lane id")?;
        ensure_non_empty(reason, "eviction reason")?;
        ensure_non_empty(previous_shard_root, "eviction previous shard root")?;
        ensure_non_empty(retained_witness_root, "eviction retained witness root")?;
        let eviction_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-EVICTION-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(shard_id_value),
                HashPart::Str(lane_id),
                HashPart::Str(reason),
                HashPart::Str(previous_shard_root),
                HashPart::Int(deterministic_order as i128),
                HashPart::Str(retained_witness_root),
            ],
            32,
        );
        let receipt_id = eviction_receipt_id(shard_id_value, lane_id, &eviction_root);
        let receipt = Self {
            receipt_id,
            shard_id: shard_id_value.to_string(),
            lane_id: lane_id.to_string(),
            reason: reason.to_string(),
            previous_shard_root: previous_shard_root.to_string(),
            eviction_root,
            deterministic_order,
            evicted_at_height,
            retained_witness_root: retained_witness_root.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        ensure_non_empty(&self.receipt_id, "eviction receipt id")?;
        ensure_non_empty(&self.shard_id, "eviction shard id")?;
        ensure_non_empty(&self.lane_id, "eviction lane id")?;
        ensure_non_empty(&self.reason, "eviction reason")?;
        ensure_non_empty(&self.previous_shard_root, "eviction previous shard root")?;
        ensure_non_empty(&self.eviction_root, "eviction root")?;
        ensure_non_empty(&self.retained_witness_root, "retained witness root")?;
        let required_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-EVICTION-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.shard_id),
                HashPart::Str(&self.lane_id),
                HashPart::Str(&self.reason),
                HashPart::Str(&self.previous_shard_root),
                HashPart::Int(self.deterministic_order as i128),
                HashPart::Str(&self.retained_witness_root),
            ],
            32,
        );
        if self.eviction_root != required_root {
            return Err(format!(
                "eviction receipt {} root mismatch",
                self.receipt_id
            ));
        }
        let required_id = eviction_receipt_id(&self.shard_id, &self.lane_id, &self.eviction_root);
        if self.receipt_id != required_id {
            return Err(format!(
                "eviction receipt id mismatch required {required_id}"
            ));
        }
        Ok(())
    }
}

impl CacheRecord for EvictionReceipt {
    fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "shard_id": self.shard_id,
            "lane_id": self.lane_id,
            "reason": self.reason,
            "previous_shard_root": self.previous_shard_root,
            "eviction_root": self.eviction_root,
            "deterministic_order": self.deterministic_order,
            "evicted_at_height": self.evicted_at_height,
            "retained_witness_root": self.retained_witness_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub shard_root: String,
    pub witness_root: String,
    pub lease_root: String,
    pub conflict_root: String,
    pub lane_root: String,
    pub proof_batch_root: String,
    pub eviction_root: String,
    pub active_contract_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "shard_root": self.shard_root,
            "witness_root": self.witness_root,
            "lease_root": self.lease_root,
            "conflict_root": self.conflict_root,
            "lane_root": self.lane_root,
            "proof_batch_root": self.proof_batch_root,
            "eviction_root": self.eviction_root,
            "active_contract_root": self.active_contract_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub shard_count: u64,
    pub live_shard_count: u64,
    pub witness_count: u64,
    pub lease_count: u64,
    pub active_lease_count: u64,
    pub conflict_count: u64,
    pub unresolved_conflict_count: u64,
    pub lane_count: u64,
    pub proof_batch_count: u64,
    pub open_proof_batch_count: u64,
    pub eviction_receipt_count: u64,
    pub total_cached_bytes: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_count": self.shard_count,
            "live_shard_count": self.live_shard_count,
            "witness_count": self.witness_count,
            "lease_count": self.lease_count,
            "active_lease_count": self.active_lease_count,
            "conflict_count": self.conflict_count,
            "unresolved_conflict_count": self.unresolved_conflict_count,
            "lane_count": self.lane_count,
            "proof_batch_count": self.proof_batch_count,
            "open_proof_batch_count": self.open_proof_batch_count,
            "eviction_receipt_count": self.eviction_receipt_count,
            "total_cached_bytes": self.total_cached_bytes,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub active_contracts: BTreeSet<String>,
    pub encrypted_state_shards: BTreeMap<String, EncryptedStateShard>,
    pub read_write_witnesses: BTreeMap<String, ReadWriteWitness>,
    pub cache_leases: BTreeMap<String, CacheLeaseCommitment>,
    pub conflict_proofs: BTreeMap<String, ConflictProof>,
    pub execution_lanes: BTreeMap<String, ExecutionLane>,
    pub proof_job_batches: BTreeMap<String, ProofJobBatch>,
    pub eviction_receipts: BTreeMap<String, EvictionReceipt>,
    pub audit_tags: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> ZkContractParallelStateCacheResult<State> {
        let config = Config::devnet()?;
        let height = ZK_CONTRACT_PARALLEL_STATE_CACHE_DEVNET_HEIGHT;
        let mut active_contracts = BTreeSet::new();
        active_contracts.insert("zkdex.pool.wxmr-usdc".to_string());
        active_contracts.insert("zkperps.market.xmr-usd".to_string());
        active_contracts.insert("zkbridge.monero.fast-exit".to_string());
        active_contracts.insert("zkpaymaster.private-session".to_string());

        let mut settlement_contracts = BTreeSet::new();
        settlement_contracts.insert("zkdex.pool.wxmr-usdc".to_string());
        settlement_contracts.insert("zkpaymaster.private-session".to_string());
        let mut perps_contracts = BTreeSet::new();
        perps_contracts.insert("zkperps.market.xmr-usd".to_string());
        let mut bridge_contracts = BTreeSet::new();
        bridge_contracts.insert("zkbridge.monero.fast-exit".to_string());

        let mut settlement_pinned = BTreeSet::new();
        settlement_pinned.insert("bootstrap".to_string());
        let mut perps_pinned = BTreeSet::new();
        perps_pinned.insert("funding-cache".to_string());
        let mut bridge_pinned = BTreeSet::new();
        bridge_pinned.insert("exit-covenant".to_string());

        let lane_a = ExecutionLane::new(
            "settlement-fast-lane",
            LanePriority::Realtime,
            96,
            75,
            settlement_contracts,
            settlement_pinned,
            height.saturating_sub(2),
        )?;
        let lane_b = ExecutionLane::new(
            "perps-risk-lane",
            LanePriority::Fast,
            64,
            120,
            perps_contracts,
            perps_pinned,
            height.saturating_sub(3),
        )?;
        let lane_c = ExecutionLane::new(
            "monero-bridge-lane",
            LanePriority::Fast,
            48,
            150,
            bridge_contracts,
            bridge_pinned,
            height.saturating_sub(1),
        )?;

        let mut execution_lanes = BTreeMap::new();
        execution_lanes.insert(lane_a.lane_id.clone(), lane_a.clone());
        execution_lanes.insert(lane_b.lane_id.clone(), lane_b.clone());
        execution_lanes.insert(lane_c.lane_id.clone(), lane_c.clone());

        let mut encrypted_state_shards = BTreeMap::new();
        for shard in [
            EncryptedStateShard::new(
                "zkdex.pool.wxmr-usdc",
                ShardClass::PrivatePool,
                "liquidity.active.bin.0001",
                7,
                height.saturating_sub(20),
                &lane_a.lane_id,
                tag_set(&["amm", "hot", "low_fee"]),
            )?,
            EncryptedStateShard::new(
                "zkdex.pool.wxmr-usdc",
                ShardClass::LiquidityPosition,
                "positions.range.private",
                3,
                height.saturating_sub(18),
                &lane_a.lane_id,
                tag_set(&["positions", "write_heavy"]),
            )?,
            EncryptedStateShard::new(
                "zkperps.market.xmr-usd",
                ShardClass::ContractStorage,
                "margin.accounts.active",
                11,
                height.saturating_sub(16),
                &lane_b.lane_id,
                tag_set(&["perps", "risk"]),
            )?,
            EncryptedStateShard::new(
                "zkbridge.monero.fast-exit",
                ShardClass::BridgeBuffer,
                "exit.queue.fast",
                5,
                height.saturating_sub(10),
                &lane_c.lane_id,
                tag_set(&["bridge", "monero"]),
            )?,
            EncryptedStateShard::new(
                "zkpaymaster.private-session",
                ShardClass::Account,
                "sponsor.credits.session",
                4,
                height.saturating_sub(12),
                &lane_a.lane_id,
                tag_set(&["paymaster", "fee_credit"]),
            )?,
        ] {
            encrypted_state_shards.insert(shard.shard_id.clone(), shard);
        }

        let shard_ids = encrypted_state_shards.keys().cloned().collect::<Vec<_>>();
        let first_shard = get_vec_item(&shard_ids, 0, "devnet first shard")?;
        let second_shard = get_vec_item(&shard_ids, 1, "devnet second shard")?;
        let third_shard = get_vec_item(&shard_ids, 2, "devnet third shard")?;
        let fourth_shard = get_vec_item(&shard_ids, 3, "devnet fourth shard")?;
        let fifth_shard = get_vec_item(&shard_ids, 4, "devnet fifth shard")?;

        let pre_state_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-DEVNET-PRE-STATE",
            encrypted_state_shards.values(),
        );

        let witness_a = ReadWriteWitness::new(
            "tx.zkcache.devnet.swap.0001",
            "zkdex.pool.wxmr-usdc",
            WitnessKind::ReadWrite,
            &lane_a.lane_id,
            set_from_vec(&[first_shard.clone(), fifth_shard.clone()]),
            set_from_vec(&[second_shard.clone()]),
            &pre_state_root,
            height.saturating_sub(2),
        )?;
        let witness_b = ReadWriteWitness::new(
            "tx.zkcache.devnet.perps.0002",
            "zkperps.market.xmr-usd",
            WitnessKind::ReadWrite,
            &lane_b.lane_id,
            set_from_vec(&[third_shard.clone()]),
            set_from_vec(&[third_shard.clone()]),
            &witness_a.post_state_root,
            height.saturating_sub(1),
        )?;
        let witness_c = ReadWriteWitness::new(
            "tx.zkcache.devnet.exit.0003",
            "zkbridge.monero.fast-exit",
            WitnessKind::Read,
            &lane_c.lane_id,
            set_from_vec(&[fourth_shard.clone()]),
            BTreeSet::new(),
            &witness_b.post_state_root,
            height,
        )?;

        let mut read_write_witnesses = BTreeMap::new();
        read_write_witnesses.insert(witness_a.witness_id.clone(), witness_a.clone());
        read_write_witnesses.insert(witness_b.witness_id.clone(), witness_b.clone());
        read_write_witnesses.insert(witness_c.witness_id.clone(), witness_c.clone());

        let lease_a = CacheLeaseCommitment::new(
            "sequencer.devnet.01",
            &witness_a.transaction_id,
            &lane_a.lane_id,
            LeaseMode::ExclusiveWrite,
            set_from_vec(&[
                first_shard.clone(),
                second_shard.clone(),
                fifth_shard.clone(),
            ]),
            &witness_a.witness_id,
            height.saturating_sub(2),
        )?;
        let lease_b = CacheLeaseCommitment::new(
            "sequencer.devnet.02",
            &witness_b.transaction_id,
            &lane_b.lane_id,
            LeaseMode::SpeculativeWrite,
            set_from_vec(&[third_shard.clone()]),
            &witness_b.witness_id,
            height.saturating_sub(1),
        )?;
        let lease_c = CacheLeaseCommitment::new(
            "sequencer.devnet.03",
            &witness_c.transaction_id,
            &lane_c.lane_id,
            LeaseMode::SharedRead,
            set_from_vec(&[fourth_shard.clone()]),
            &witness_c.witness_id,
            height,
        )?;

        let mut cache_leases = BTreeMap::new();
        cache_leases.insert(lease_a.lease_id.clone(), lease_a.clone());
        cache_leases.insert(lease_b.lease_id.clone(), lease_b.clone());
        cache_leases.insert(lease_c.lease_id.clone(), lease_c.clone());

        let conflict = ConflictProof::new(
            ConflictKind::WriteAfterRead,
            &witness_a.transaction_id,
            &witness_b.transaction_id,
            &witness_a.witness_id,
            &witness_b.witness_id,
            &lease_b.lease_id,
            &lane_b.lane_id,
            set_from_vec(&[third_shard.clone()]),
            height,
        )?;
        let mut conflict_proofs = BTreeMap::new();
        conflict_proofs.insert(conflict.conflict_id.clone(), conflict);

        let proof_batch_a = ProofJobBatch::new(
            &lane_a.lane_id,
            set_from_vec(&[
                "proof-job.swap-routing.0001".to_string(),
                "proof-job.paymaster-credit.0002".to_string(),
            ]),
            set_from_vec(&[witness_a.witness_id.clone()]),
            set_from_vec(&[
                first_shard.clone(),
                second_shard.clone(),
                fifth_shard.clone(),
            ]),
            height.saturating_sub(1),
            2_400,
        )?;
        let proof_batch_b = ProofJobBatch::new(
            &lane_c.lane_id,
            set_from_vec(&["proof-job.monero-exit.0003".to_string()]),
            set_from_vec(&[witness_c.witness_id.clone()]),
            set_from_vec(&[fourth_shard.clone()]),
            height,
            3_200,
        )?;
        let mut proof_job_batches = BTreeMap::new();
        proof_job_batches.insert(proof_batch_a.batch_id.clone(), proof_batch_a);
        proof_job_batches.insert(proof_batch_b.batch_id.clone(), proof_batch_b);

        let retained_witness_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-DEVNET-RETAINED-WITNESS",
            read_write_witnesses.values(),
        );
        let stale_shard = encrypted_state_shards
            .get(&second_shard)
            .ok_or_else(|| "missing devnet eviction shard".to_string())?;
        let eviction_receipt = EvictionReceipt::new(
            &stale_shard.shard_id,
            &lane_a.lane_id,
            "deterministic-capacity-trim",
            &stale_shard.previous_shard_root,
            1,
            height,
            &retained_witness_root,
        )?;
        let mut eviction_receipts = BTreeMap::new();
        eviction_receipts.insert(eviction_receipt.receipt_id.clone(), eviction_receipt);

        let mut audit_tags = BTreeSet::new();
        audit_tags.insert("devnet".to_string());
        audit_tags.insert("parallel-cache".to_string());
        audit_tags.insert("encrypted-shards".to_string());
        audit_tags.insert("deterministic-roots".to_string());

        let state = State {
            config,
            height,
            epoch: height / 720,
            active_contracts,
            encrypted_state_shards,
            read_write_witnesses,
            cache_leases,
            conflict_proofs,
            execution_lanes,
            proof_job_batches,
            eviction_receipts,
            audit_tags,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> ZkContractParallelStateCacheResult<()> {
        self.config.validate()?;
        if self.epoch != self.height / 720 {
            return Err(format!(
                "epoch mismatch required {} got {}",
                self.height / 720,
                self.epoch
            ));
        }
        ensure_max_len(
            self.encrypted_state_shards.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_SHARDS,
            "encrypted state shards",
        )?;
        ensure_max_len(
            self.read_write_witnesses.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_WITNESSES,
            "read write witnesses",
        )?;
        ensure_max_len(
            self.cache_leases.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_LEASES,
            "cache leases",
        )?;
        ensure_max_len(
            self.conflict_proofs.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_CONFLICT_PROOFS,
            "conflict proofs",
        )?;
        ensure_max_len(
            self.execution_lanes.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_EXECUTION_LANES,
            "execution lanes",
        )?;
        ensure_max_len(
            self.proof_job_batches.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_PROOF_BATCHES,
            "proof job batches",
        )?;
        ensure_max_len(
            self.eviction_receipts.len(),
            ZK_CONTRACT_PARALLEL_STATE_CACHE_MAX_EVICTION_RECEIPTS,
            "eviction receipts",
        )?;

        for (id, shard) in &self.encrypted_state_shards {
            if id != &shard.shard_id {
                return Err(format!("shard map key mismatch {id}"));
            }
            shard.validate()?;
            if !self.execution_lanes.contains_key(&shard.lane_affinity) {
                return Err(format!("shard {} references missing lane", shard.shard_id));
            }
        }
        for (id, witness) in &self.read_write_witnesses {
            if id != &witness.witness_id {
                return Err(format!("witness map key mismatch {id}"));
            }
            witness.validate()?;
            if !self.execution_lanes.contains_key(&witness.lane_id) {
                return Err(format!(
                    "witness {} references missing lane",
                    witness.witness_id
                ));
            }
            ensure_known_shards(
                &witness.read_set,
                &self.encrypted_state_shards,
                "witness read",
            )?;
            ensure_known_shards(
                &witness.write_set,
                &self.encrypted_state_shards,
                "witness write",
            )?;
        }
        for (id, lease) in &self.cache_leases {
            if id != &lease.lease_id {
                return Err(format!("lease map key mismatch {id}"));
            }
            lease.validate()?;
            if !self.execution_lanes.contains_key(&lease.lane_id) {
                return Err(format!("lease {} references missing lane", lease.lease_id));
            }
            if !self.read_write_witnesses.contains_key(&lease.witness_id) {
                return Err(format!(
                    "lease {} references missing witness",
                    lease.lease_id
                ));
            }
            ensure_known_shards(&lease.shard_ids, &self.encrypted_state_shards, "lease")?;
        }
        for (id, proof) in &self.conflict_proofs {
            if id != &proof.conflict_id {
                return Err(format!("conflict map key mismatch {id}"));
            }
            proof.validate()?;
            if !self.execution_lanes.contains_key(&proof.lane_id) {
                return Err(format!(
                    "conflict {} references missing lane",
                    proof.conflict_id
                ));
            }
            if !self.cache_leases.contains_key(&proof.lease_id) {
                return Err(format!(
                    "conflict {} references missing lease",
                    proof.conflict_id
                ));
            }
            if !self
                .read_write_witnesses
                .contains_key(&proof.left_witness_id)
                || !self
                    .read_write_witnesses
                    .contains_key(&proof.right_witness_id)
            {
                return Err(format!(
                    "conflict {} references missing witness",
                    proof.conflict_id
                ));
            }
            ensure_known_shards(&proof.shard_ids, &self.encrypted_state_shards, "conflict")?;
        }
        for (id, lane) in &self.execution_lanes {
            if id != &lane.lane_id {
                return Err(format!("lane map key mismatch {id}"));
            }
            lane.validate()?;
        }
        for (id, batch) in &self.proof_job_batches {
            if id != &batch.batch_id {
                return Err(format!("proof batch map key mismatch {id}"));
            }
            batch.validate()?;
            if !self.execution_lanes.contains_key(&batch.lane_id) {
                return Err(format!(
                    "proof batch {} references missing lane",
                    batch.batch_id
                ));
            }
            ensure_known_witnesses(
                &batch.witness_ids,
                &self.read_write_witnesses,
                "proof batch",
            )?;
            ensure_known_shards(
                &batch.shard_ids,
                &self.encrypted_state_shards,
                "proof batch",
            )?;
        }
        for (id, receipt) in &self.eviction_receipts {
            if id != &receipt.receipt_id {
                return Err(format!("eviction receipt map key mismatch {id}"));
            }
            receipt.validate()?;
            if !self.execution_lanes.contains_key(&receipt.lane_id) {
                return Err(format!(
                    "eviction receipt {} references missing lane",
                    receipt.receipt_id
                ));
            }
            if !self.encrypted_state_shards.contains_key(&receipt.shard_id) {
                return Err(format!(
                    "eviction receipt {} references missing shard",
                    receipt.receipt_id
                ));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> ZkContractParallelStateCacheResult<()> {
        self.height = height;
        self.epoch = height / 720;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> ZkContractParallelStateCacheResult<()> {
        if height < self.height {
            return Err(format!(
                "cannot decrease parallel state cache height from {} to {height}",
                self.height
            ));
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let shard_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-SHARDS",
            self.encrypted_state_shards.values(),
        );
        let witness_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-WITNESSES",
            self.read_write_witnesses.values(),
        );
        let lease_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-LEASES",
            self.cache_leases.values(),
        );
        let conflict_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-CONFLICTS",
            self.conflict_proofs.values(),
        );
        let lane_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-LANES",
            self.execution_lanes.values(),
        );
        let proof_batch_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-PROOF-BATCHES",
            self.proof_job_batches.values(),
        );
        let eviction_root = merkle_for_records(
            "ZK-CONTRACT-PARALLEL-CACHE-EVICTIONS",
            self.eviction_receipts.values(),
        );
        let active_contract_root = set_root(
            "ZK-CONTRACT-PARALLEL-CACHE-ACTIVE-CONTRACTS",
            &self.active_contracts,
        );
        let state_root = domain_hash(
            "ZK-CONTRACT-PARALLEL-CACHE-ROOTS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config_root),
                HashPart::Str(&shard_root),
                HashPart::Str(&witness_root),
                HashPart::Str(&lease_root),
                HashPart::Str(&conflict_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&proof_batch_root),
                HashPart::Str(&eviction_root),
                HashPart::Str(&active_contract_root),
                HashPart::Int(self.height as i128),
                HashPart::Int(self.epoch as i128),
            ],
            32,
        );
        Roots {
            config_root,
            shard_root,
            witness_root,
            lease_root,
            conflict_root,
            lane_root,
            proof_batch_root,
            eviction_root,
            active_contract_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let live_shard_count = self
            .encrypted_state_shards
            .values()
            .filter(|shard| shard.status.live())
            .count() as u64;
        let active_lease_count = self
            .cache_leases
            .values()
            .filter(|lease| {
                lease.released_at_height.is_none() && lease.expires_at_height >= self.height
            })
            .count() as u64;
        let unresolved_conflict_count = self
            .conflict_proofs
            .values()
            .filter(|proof| !proof.resolved)
            .count() as u64;
        let open_proof_batch_count = self
            .proof_job_batches
            .values()
            .filter(|batch| {
                matches!(
                    batch.status,
                    ProofBatchStatus::Open | ProofBatchStatus::Sealed | ProofBatchStatus::Proving
                )
            })
            .count() as u64;
        let total_cached_bytes = self
            .encrypted_state_shards
            .values()
            .map(|shard| shard.size_bytes)
            .fold(0_u64, u64::saturating_add);
        Counters {
            shard_count: self.encrypted_state_shards.len() as u64,
            live_shard_count,
            witness_count: self.read_write_witnesses.len() as u64,
            lease_count: self.cache_leases.len() as u64,
            active_lease_count,
            conflict_count: self.conflict_proofs.len() as u64,
            unresolved_conflict_count,
            lane_count: self.execution_lanes.len() as u64,
            proof_batch_count: self.proof_job_batches.len() as u64,
            open_proof_batch_count,
            eviction_receipt_count: self.eviction_receipts.len() as u64,
            total_cached_bytes,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": ZK_CONTRACT_PARALLEL_STATE_CACHE_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_contracts": self.active_contracts.iter().cloned().collect::<Vec<_>>(),
            "encrypted_state_shards": self.encrypted_state_shards.values().map(EncryptedStateShard::public_record).collect::<Vec<_>>(),
            "read_write_witnesses": self.read_write_witnesses.values().map(ReadWriteWitness::public_record).collect::<Vec<_>>(),
            "cache_leases": self.cache_leases.values().map(CacheLeaseCommitment::public_record).collect::<Vec<_>>(),
            "conflict_proofs": self.conflict_proofs.values().map(ConflictProof::public_record).collect::<Vec<_>>(),
            "execution_lanes": self.execution_lanes.values().map(ExecutionLane::public_record).collect::<Vec<_>>(),
            "proof_job_batches": self.proof_job_batches.values().map(ProofJobBatch::public_record).collect::<Vec<_>>(),
            "eviction_receipts": self.eviction_receipts.values().map(EvictionReceipt::public_record).collect::<Vec<_>>(),
            "audit_tags": self.audit_tags.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> ZkContractParallelStateCacheResult<State> {
    State::devnet()
}

fn config_id(config: &Config) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.protocol_version),
            HashPart::Str(&config.schema_version),
            HashPart::Str(&config.namespace),
            HashPart::Str(&config.encryption_suite),
            HashPart::Str(&config.witness_suite),
            HashPart::Str(&config.lease_suite),
            HashPart::Str(&config.conflict_suite),
            HashPart::Str(&config.eviction_suite),
            HashPart::Int(config.shard_ttl_blocks as i128),
            HashPart::Int(config.lease_ttl_blocks as i128),
            HashPart::Int(config.proof_batch_window_blocks as i128),
            HashPart::Int(config.max_parallel_lanes as i128),
            HashPart::Int(config.max_shards_per_lane as i128),
            HashPart::Str(&config.deterministic_eviction_seed),
            HashPart::Str(&config.privacy_policy_root),
        ],
        32,
    )
}

fn shard_id(
    contract_id: &str,
    shard_class: ShardClass,
    namespace: &str,
    version: u64,
    ciphertext_commitment: &str,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(shard_class.as_str()),
            HashPart::Str(namespace),
            HashPart::Int(version as i128),
            HashPart::Str(ciphertext_commitment),
        ],
        32,
    )
}

fn witness_commitment(
    transaction_id: &str,
    contract_id: &str,
    kind: WitnessKind,
    lane_id: &str,
    read_root: &str,
    write_root: &str,
    pre_state_root: &str,
    post_state_root: &str,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-WITNESS-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transaction_id),
            HashPart::Str(contract_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane_id),
            HashPart::Str(read_root),
            HashPart::Str(write_root),
            HashPart::Str(pre_state_root),
            HashPart::Str(post_state_root),
        ],
        32,
    )
}

fn witness_id(transaction_id: &str, commitment: &str) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-WITNESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transaction_id),
            HashPart::Str(commitment),
        ],
        32,
    )
}

fn lease_commitment(
    holder_id: &str,
    transaction_id: &str,
    lane_id: &str,
    mode: LeaseMode,
    shard_root: &str,
    witness_id_value: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-LEASE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(holder_id),
            HashPart::Str(transaction_id),
            HashPart::Str(lane_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(shard_root),
            HashPart::Str(witness_id_value),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn lease_id(holder_id: &str, transaction_id: &str, commitment: &str) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(holder_id),
            HashPart::Str(transaction_id),
            HashPart::Str(commitment),
        ],
        32,
    )
}

fn conflict_id(
    kind: ConflictKind,
    left_transaction_id: &str,
    right_transaction_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-CONFLICT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(left_transaction_id),
            HashPart::Str(right_transaction_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn lane_id(label: &str, priority: LanePriority, fence_root: &str) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(priority.as_str()),
            HashPart::Str(fence_root),
        ],
        32,
    )
}

fn proof_batch_id(
    lane_id_value: &str,
    aggregate_input_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-PROOF-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id_value),
            HashPart::Str(aggregate_input_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn eviction_receipt_id(shard_id_value: &str, lane_id_value: &str, eviction_root: &str) -> String {
    domain_hash(
        "ZK-CONTRACT-PARALLEL-CACHE-EVICTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(shard_id_value),
            HashPart::Str(lane_id_value),
            HashPart::Str(eviction_root),
        ],
        32,
    )
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let records = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_from_vec(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn tag_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn get_vec_item(
    values: &[String],
    index: usize,
    label: &str,
) -> ZkContractParallelStateCacheResult<String> {
    values
        .get(index)
        .cloned()
        .ok_or_else(|| format!("missing {label} at index {index}"))
}

fn merkle_for_records<'a, T, I>(domain: &str, values: I) -> String
where
    T: CacheRecord + 'a,
    I: Iterator<Item = &'a T>,
{
    let records = values.map(CacheRecord::public_record).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn ensure_non_empty(value: &str, label: &str) -> ZkContractParallelStateCacheResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> ZkContractParallelStateCacheResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_not_empty_set(
    values: &BTreeSet<String>,
    label: &str,
) -> ZkContractParallelStateCacheResult<()> {
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    for value in values {
        ensure_non_empty(value, label)?;
    }
    Ok(())
}

fn ensure_max_len(
    actual: usize,
    max: usize,
    label: &str,
) -> ZkContractParallelStateCacheResult<()> {
    if actual > max {
        return Err(format!("{label} length {actual} exceeds max {max}"));
    }
    Ok(())
}

fn ensure_known_shards(
    values: &BTreeSet<String>,
    shards: &BTreeMap<String, EncryptedStateShard>,
    label: &str,
) -> ZkContractParallelStateCacheResult<()> {
    for value in values {
        if !shards.contains_key(value) {
            return Err(format!("{label} references unknown shard {value}"));
        }
    }
    Ok(())
}

fn ensure_known_witnesses(
    values: &BTreeSet<String>,
    witnesses: &BTreeMap<String, ReadWriteWitness>,
    label: &str,
) -> ZkContractParallelStateCacheResult<()> {
    for value in values {
        if !witnesses.contains_key(value) {
            return Err(format!("{label} references unknown witness {value}"));
        }
    }
    Ok(())
}
