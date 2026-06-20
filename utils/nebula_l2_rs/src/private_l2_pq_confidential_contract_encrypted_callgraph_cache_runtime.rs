use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractEncryptedCallgraphCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_CALLGRAPH_CACHE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-encrypted-callgraph-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ENCRYPTED_CALLGRAPH_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_CALLGRAPH_SUITE: &str =
    "ML-KEM-1024+XWing-confidential-contract-callgraph-envelope-v1";
pub const PQ_CONTRACT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-contract-callgraph-v1";
pub const CACHE_SHARD_SUITE: &str = "private-l2-pq-confidential-contract-callgraph-cache-shard-v1";
pub const DEPENDENCY_HINT_SUITE: &str = "redacted-confidential-contract-dependency-hint-v1";
pub const INVALIDATION_PROOF_SUITE: &str = "pq-callgraph-cache-invalidation-proof-v1";
pub const COMPRESSION_REBATE_SUITE: &str = "low-fee-callgraph-cache-compression-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "privacy-budgeted-callgraph-cache-redaction-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-encrypted-callgraph-cache-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_680_000;
pub const DEVNET_EPOCH: u64 = 14_400;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_TARGET_CACHE_HIT_BPS: u64 = 8_700;
pub const DEFAULT_TARGET_LATENCY_MICROS: u64 = 1_800;
pub const DEFAULT_MAX_CALL_FEE_BPS: u64 = 8;
pub const DEFAULT_COMPRESSION_REBATE_BPS: u64 = 2_400;
pub const DEFAULT_SHARD_TTL_BLOCKS: u64 = 4_096;
pub const DEFAULT_NODE_TTL_BLOCKS: u64 = 2_048;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 8_192;
pub const DEFAULT_INVALIDATION_WINDOW_BLOCKS: u64 = 288;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_SHARDS: usize = 262_144;
pub const DEFAULT_MAX_NODES: usize = 8_388_608;
pub const DEFAULT_MAX_DEPENDENCY_HINTS: usize = 16_777_216;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_INVALIDATION_PROOFS: usize = 2_097_152;
pub const DEFAULT_MAX_COMPRESSION_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 524_288;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

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
pub enum ContractClass {
    AccountAbstraction,
    DefiRouter,
    BridgeAdapter,
    OracleAdapter,
    GovernanceModule,
    PrivacyPool,
    FheApplication,
    PaymentChannel,
    Custom,
}

impl ContractClass {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeAdapter => 10_000,
            Self::DefiRouter => 9_600,
            Self::AccountAbstraction => 9_200,
            Self::PaymentChannel => 8_900,
            Self::FheApplication => 8_600,
            Self::OracleAdapter => 8_300,
            Self::PrivacyPool => 8_000,
            Self::GovernanceModule => 7_500,
            Self::Custom => 7_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheShardStatus {
    Opening,
    Warm,
    Hot,
    Congested,
    Sealing,
    Invalidating,
    Paused,
    Retired,
}

impl CacheShardStatus {
    pub fn accepts_nodes(self) -> bool {
        matches!(
            self,
            Self::Opening | Self::Warm | Self::Hot | Self::Congested
        )
    }

    pub fn accepts_hints(self) -> bool {
        matches!(self, Self::Warm | Self::Hot | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallgraphNodeKind {
    EntryPoint,
    InternalCall,
    DelegateCall,
    StaticCall,
    FheGate,
    StorageRead,
    StorageWrite,
    EventEmission,
    CrossContractCallback,
    ExitCommitment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallgraphNodeStatus {
    Encrypted,
    Attested,
    Cacheable,
    Warmed,
    Hot,
    DependencyPending,
    Invalidating,
    Invalidated,
    Expired,
    Slashed,
}

impl CallgraphNodeStatus {
    pub fn can_hint(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::Cacheable | Self::Warmed | Self::Hot
        )
    }

    pub fn can_invalidate(self) -> bool {
        !matches!(self, Self::Invalidated | Self::Expired | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyHintKind {
    ReadAfterWrite,
    WriteAfterRead,
    DelegateTarget,
    FheCiphertext,
    StoragePrefix,
    EventTopic,
    CallbackEdge,
    FeeSponsor,
    RebateDictionary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintDisclosureLevel {
    FullyRedacted,
    ContractClassOnly,
    ShardLocal,
    OperatorSafe,
    AuditorOpening,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ContractCodeHash,
    PqSignature,
    CallgraphOpening,
    DeterministicTrace,
    FheCircuitBinding,
    CacheSafety,
    FeeMetering,
    PrivacyBudget,
    EmergencyRevocation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    TtlExpired,
    ContractUpgrade,
    AttestationRevoked,
    DependencyChanged,
    PrivacyBudgetExceeded,
    CachePoisoning,
    SequencerFault,
    EmergencyPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToShard,
    Denied,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub runtime_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub protocol_version: String,
    pub mode: RuntimeMode,
    pub hash_suite: String,
    pub encrypted_callgraph_suite: String,
    pub pq_attestation_suite: String,
    pub cache_shard_suite: String,
    pub dependency_hint_suite: String,
    pub invalidation_proof_suite: String,
    pub compression_rebate_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub target_cache_hit_bps: u64,
    pub target_latency_micros: u64,
    pub max_call_fee_bps: u64,
    pub compression_rebate_bps: u64,
    pub shard_ttl_blocks: u64,
    pub node_ttl_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub invalidation_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_shards: usize,
    pub max_nodes: usize,
    pub max_dependency_hints: usize,
    pub max_attestations: usize,
    pub max_invalidation_proofs: usize,
    pub max_compression_rebates: usize,
    pub max_redaction_budgets: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            runtime_id: "private-l2-pq-confidential-contract-encrypted-callgraph-cache".to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            mode: RuntimeMode::Devnet,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_callgraph_suite: ENCRYPTED_CALLGRAPH_SUITE.to_string(),
            pq_attestation_suite: PQ_CONTRACT_ATTESTATION_SUITE.to_string(),
            cache_shard_suite: CACHE_SHARD_SUITE.to_string(),
            dependency_hint_suite: DEPENDENCY_HINT_SUITE.to_string(),
            invalidation_proof_suite: INVALIDATION_PROOF_SUITE.to_string(),
            compression_rebate_suite: COMPRESSION_REBATE_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            target_cache_hit_bps: DEFAULT_TARGET_CACHE_HIT_BPS,
            target_latency_micros: DEFAULT_TARGET_LATENCY_MICROS,
            max_call_fee_bps: DEFAULT_MAX_CALL_FEE_BPS,
            compression_rebate_bps: DEFAULT_COMPRESSION_REBATE_BPS,
            shard_ttl_blocks: DEFAULT_SHARD_TTL_BLOCKS,
            node_ttl_blocks: DEFAULT_NODE_TTL_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            invalidation_window_blocks: DEFAULT_INVALIDATION_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_shards: DEFAULT_MAX_SHARDS,
            max_nodes: DEFAULT_MAX_NODES,
            max_dependency_hints: DEFAULT_MAX_DEPENDENCY_HINTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_invalidation_proofs: DEFAULT_MAX_INVALIDATION_PROOFS,
            max_compression_rebates: DEFAULT_MAX_COMPRESSION_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        required("chain_id", &self.chain_id)?;
        required("runtime_id", &self.runtime_id)?;
        required("l2_network", &self.l2_network)?;
        required("fee_asset_id", &self.fee_asset_id)?;
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version {}",
            self.protocol_version
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "min_pq_security_bits below 256"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum"
        );
        ensure_bps("target_cache_hit_bps", self.target_cache_hit_bps)?;
        ensure_bps("max_call_fee_bps", self.max_call_fee_bps)?;
        ensure_bps("compression_rebate_bps", self.compression_rebate_bps)?;
        ensure_nonzero("shard_ttl_blocks", self.shard_ttl_blocks)?;
        ensure_nonzero("node_ttl_blocks", self.node_ttl_blocks)?;
        ensure_nonzero("hint_ttl_blocks", self.hint_ttl_blocks)?;
        ensure_nonzero("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        ensure_nonzero("redaction_epoch_blocks", self.redaction_epoch_blocks)?;
        ensure_capacity("max_shards", self.max_shards)?;
        ensure_capacity("max_nodes", self.max_nodes)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "runtime_id": self.runtime_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "mode": self.mode.as_str(),
            "hash_suite": self.hash_suite,
            "encrypted_callgraph_suite": self.encrypted_callgraph_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "cache_shard_suite": self.cache_shard_suite,
            "dependency_hint_suite": self.dependency_hint_suite,
            "invalidation_proof_suite": self.invalidation_proof_suite,
            "compression_rebate_suite": self.compression_rebate_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "target_cache_hit_bps": self.target_cache_hit_bps,
            "target_latency_micros": self.target_latency_micros,
            "max_call_fee_bps": self.max_call_fee_bps,
            "compression_rebate_bps": self.compression_rebate_bps,
            "shard_ttl_blocks": self.shard_ttl_blocks,
            "node_ttl_blocks": self.node_ttl_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "invalidation_window_blocks": self.invalidation_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedCallgraphNode {
    pub node_id: String,
    pub shard_id: String,
    pub contract_commitment: String,
    pub caller_commitment: String,
    pub callee_commitment: String,
    pub node_kind: CallgraphNodeKind,
    pub status: CallgraphNodeStatus,
    pub contract_class: ContractClass,
    pub encrypted_payload_root: String,
    pub ciphertext_commitment: String,
    pub pq_key_commitment: String,
    pub dependency_root: String,
    pub call_depth: u16,
    pub fanout: u16,
    pub estimated_gas: u64,
    pub measured_latency_micros: u64,
    pub compressed_bytes: u64,
    pub uncompressed_bytes: u64,
    pub privacy_set_size: u64,
    pub fee_paid: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub access_count: u64,
    pub last_access_height: u64,
    pub redaction_tag: String,
}

impl EncryptedCallgraphNode {
    pub fn new(
        shard_id: impl Into<String>,
        contract_commitment: impl Into<String>,
        node_kind: CallgraphNodeKind,
        contract_class: ContractClass,
        encrypted_payload_root: impl Into<String>,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let shard_id = shard_id.into();
        let contract_commitment = contract_commitment.into();
        let encrypted_payload_root = encrypted_payload_root.into();
        let node_seed = domain_hash(
            "CALLGRAPH-NODE-ID",
            &[
                HashPart::Str(&shard_id),
                HashPart::Str(&contract_commitment),
                HashPart::Str(&encrypted_payload_root),
                HashPart::U64(created_height),
            ],
            16,
        );
        let ciphertext_commitment = short_commitment(
            "CALLGRAPH-CIPHERTEXT",
            &encrypted_payload_root,
            created_height,
        );
        let pq_key_commitment =
            short_commitment("CALLGRAPH-PQ-KEY", &contract_commitment, created_height);
        let dependency_root = domain_hash(
            "CALLGRAPH-EMPTY-DEPENDENCIES",
            &[HashPart::Str(&node_seed)],
            32,
        );
        Self {
            node_id: format!("cg-node-{node_seed}"),
            shard_id,
            contract_commitment,
            caller_commitment: "redacted-caller".to_string(),
            callee_commitment: "redacted-callee".to_string(),
            node_kind,
            status: CallgraphNodeStatus::Encrypted,
            contract_class,
            encrypted_payload_root,
            ciphertext_commitment,
            pq_key_commitment,
            dependency_root,
            call_depth: 0,
            fanout: 0,
            estimated_gas: 0,
            measured_latency_micros: config.target_latency_micros,
            compressed_bytes: 0,
            uncompressed_bytes: 0,
            privacy_set_size: config.min_privacy_set_size,
            fee_paid: 0,
            created_height,
            expires_height: created_height + config.node_ttl_blocks,
            access_count: 0,
            last_access_height: created_height,
            redaction_tag: "operator-safe".to_string(),
        }
    }

    pub fn with_metrics(
        mut self,
        estimated_gas: u64,
        latency_micros: u64,
        uncompressed_bytes: u64,
        compressed_bytes: u64,
        fee_paid: u64,
    ) -> Self {
        self.estimated_gas = estimated_gas;
        self.measured_latency_micros = latency_micros;
        self.uncompressed_bytes = uncompressed_bytes;
        self.compressed_bytes = compressed_bytes;
        self.fee_paid = fee_paid;
        self
    }

    pub fn with_edges(
        mut self,
        caller_commitment: impl Into<String>,
        callee_commitment: impl Into<String>,
        call_depth: u16,
        fanout: u16,
    ) -> Self {
        self.caller_commitment = caller_commitment.into();
        self.callee_commitment = callee_commitment.into();
        self.call_depth = call_depth;
        self.fanout = fanout;
        self
    }

    pub fn attest(mut self) -> Self {
        self.status = CallgraphNodeStatus::Attested;
        self
    }

    pub fn warm(mut self, height: u64) -> Self {
        self.status = CallgraphNodeStatus::Warmed;
        self.access_count = self.access_count.saturating_add(1);
        self.last_access_height = height;
        self
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.uncompressed_bytes == 0 {
            return 0;
        }
        self.compressed_bytes.saturating_mul(MAX_BPS) / self.uncompressed_bytes
    }

    pub fn cache_score(&self) -> u64 {
        let priority = self.contract_class.priority_weight();
        let speed_score = DEFAULT_TARGET_LATENCY_MICROS
            .saturating_mul(MAX_BPS)
            .checked_div(self.measured_latency_micros.max(1))
            .unwrap_or(MAX_BPS)
            .min(MAX_BPS);
        let privacy_score = (self.privacy_set_size.min(DEFAULT_TARGET_PRIVACY_SET_SIZE))
            .saturating_mul(MAX_BPS)
            / DEFAULT_TARGET_PRIVACY_SET_SIZE;
        let compression_score = MAX_BPS.saturating_sub(self.compression_ratio_bps());
        (priority + speed_score + privacy_score + compression_score) / 4
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        required("node_id", &self.node_id)?;
        required("shard_id", &self.shard_id)?;
        required("contract_commitment", &self.contract_commitment)?;
        required("encrypted_payload_root", &self.encrypted_payload_root)?;
        required("ciphertext_commitment", &self.ciphertext_commitment)?;
        required("pq_key_commitment", &self.pq_key_commitment)?;
        required("dependency_root", &self.dependency_root)?;
        ensure!(
            self.expires_height > self.created_height,
            "node {} expires before creation",
            self.node_id
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "node {} privacy set below minimum",
            self.node_id
        );
        ensure!(
            self.compressed_bytes <= self.uncompressed_bytes || self.uncompressed_bytes == 0,
            "node {} compressed bytes exceed source bytes",
            self.node_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "node_id": self.node_id,
            "shard_id": self.shard_id,
            "contract_commitment": self.contract_commitment,
            "caller_commitment": self.caller_commitment,
            "callee_commitment": self.callee_commitment,
            "node_kind": self.node_kind,
            "status": self.status,
            "contract_class": self.contract_class,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_commitment": self.ciphertext_commitment,
            "pq_key_commitment": self.pq_key_commitment,
            "dependency_root": self.dependency_root,
            "call_depth": self.call_depth,
            "fanout": self.fanout,
            "estimated_gas": self.estimated_gas,
            "measured_latency_micros": self.measured_latency_micros,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "compression_ratio_bps": self.compression_ratio_bps(),
            "privacy_set_size": self.privacy_set_size,
            "fee_paid": self.fee_paid,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "access_count": self.access_count,
            "last_access_height": self.last_access_height,
            "cache_score": self.cache_score(),
            "redaction_tag": self.redaction_tag,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "ENCRYPTED-CALLGRAPH-NODE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CacheShard {
    pub shard_id: String,
    pub operator_commitment: String,
    pub region_commitment: String,
    pub status: CacheShardStatus,
    pub contract_classes: BTreeSet<ContractClass>,
    pub node_root: String,
    pub hint_root: String,
    pub attestation_root: String,
    pub max_nodes: usize,
    pub warm_nodes: u64,
    pub hot_nodes: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_fee_collected: u64,
    pub compression_rebate_pool: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl CacheShard {
    pub fn new(
        shard_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        status: CacheShardStatus,
        created_height: u64,
        config: &Config,
    ) -> Self {
        Self {
            shard_id: shard_id.into(),
            operator_commitment: operator_commitment.into(),
            region_commitment: "redacted-region".to_string(),
            status,
            contract_classes: BTreeSet::new(),
            node_root: empty_root("CACHE-SHARD-NODES"),
            hint_root: empty_root("CACHE-SHARD-HINTS"),
            attestation_root: empty_root("CACHE-SHARD-ATTESTATIONS"),
            max_nodes: config.max_nodes / config.max_shards.max(1),
            warm_nodes: 0,
            hot_nodes: 0,
            cache_hits: 0,
            cache_misses: 0,
            total_fee_collected: 0,
            compression_rebate_pool: 0,
            created_height,
            expires_height: created_height + config.shard_ttl_blocks,
        }
    }

    pub fn add_contract_class(mut self, class: ContractClass) -> Self {
        let _ = self.contract_classes.insert(class);
        self
    }

    pub fn record_hit(&mut self, fee: u64) {
        self.cache_hits = self.cache_hits.saturating_add(1);
        self.total_fee_collected = self.total_fee_collected.saturating_add(fee);
    }

    pub fn record_miss(&mut self) {
        self.cache_misses = self.cache_misses.saturating_add(1);
    }

    pub fn hit_rate_bps(&self) -> u64 {
        let total = self.cache_hits.saturating_add(self.cache_misses);
        if total == 0 {
            return 0;
        }
        self.cache_hits.saturating_mul(MAX_BPS) / total
    }

    pub fn validate(&self) -> Result<()> {
        required("shard_id", &self.shard_id)?;
        required("operator_commitment", &self.operator_commitment)?;
        ensure!(
            self.max_nodes > 0,
            "shard {} has zero capacity",
            self.shard_id
        );
        ensure!(
            self.expires_height > self.created_height,
            "shard {} expires before creation",
            self.shard_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "operator_commitment": self.operator_commitment,
            "region_commitment": self.region_commitment,
            "status": self.status,
            "contract_classes": self.contract_classes,
            "node_root": self.node_root,
            "hint_root": self.hint_root,
            "attestation_root": self.attestation_root,
            "max_nodes": self.max_nodes,
            "warm_nodes": self.warm_nodes,
            "hot_nodes": self.hot_nodes,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_bps": self.hit_rate_bps(),
            "total_fee_collected": self.total_fee_collected,
            "compression_rebate_pool": self.compression_rebate_pool,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash("CACHE-SHARD", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DependencyHint {
    pub hint_id: String,
    pub shard_id: String,
    pub from_node_id: String,
    pub to_node_commitment: String,
    pub hint_kind: DependencyHintKind,
    pub disclosure_level: HintDisclosureLevel,
    pub encrypted_hint_root: String,
    pub nullifier: String,
    pub edge_weight_bps: u64,
    pub privacy_set_size: u64,
    pub predicted_latency_savings_micros: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl DependencyHint {
    pub fn new(
        shard_id: impl Into<String>,
        from_node_id: impl Into<String>,
        to_node_commitment: impl Into<String>,
        hint_kind: DependencyHintKind,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let shard_id = shard_id.into();
        let from_node_id = from_node_id.into();
        let to_node_commitment = to_node_commitment.into();
        let hint_seed = domain_hash(
            "DEPENDENCY-HINT-ID",
            &[
                HashPart::Str(&shard_id),
                HashPart::Str(&from_node_id),
                HashPart::Str(&to_node_commitment),
                HashPart::U64(created_height),
            ],
            16,
        );
        Self {
            hint_id: format!("dep-hint-{hint_seed}"),
            shard_id,
            from_node_id,
            to_node_commitment,
            hint_kind,
            disclosure_level: HintDisclosureLevel::OperatorSafe,
            encrypted_hint_root: domain_hash(
                "DEPENDENCY-HINT-CIPHERTEXT",
                &[HashPart::Str(&hint_seed)],
                32,
            ),
            nullifier: domain_hash(
                "DEPENDENCY-HINT-NULLIFIER",
                &[HashPart::Str(&hint_seed)],
                32,
            ),
            edge_weight_bps: 5_000,
            privacy_set_size: config.min_privacy_set_size,
            predicted_latency_savings_micros: config.target_latency_micros / 3,
            created_height,
            expires_height: created_height + config.hint_ttl_blocks,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        required("hint_id", &self.hint_id)?;
        required("shard_id", &self.shard_id)?;
        required("from_node_id", &self.from_node_id)?;
        required("to_node_commitment", &self.to_node_commitment)?;
        ensure_bps("edge_weight_bps", self.edge_weight_bps)?;
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "hint {} privacy set below minimum",
            self.hint_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "shard_id": self.shard_id,
            "from_node_id": self.from_node_id,
            "to_node_commitment": self.to_node_commitment,
            "hint_kind": self.hint_kind,
            "disclosure_level": self.disclosure_level,
            "encrypted_hint_root": self.encrypted_hint_root,
            "nullifier": self.nullifier,
            "edge_weight_bps": self.edge_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "predicted_latency_savings_micros": self.predicted_latency_savings_micros,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "DEPENDENCY-HINT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqContractAttestation {
    pub attestation_id: String,
    pub shard_id: String,
    pub node_id: String,
    pub contract_commitment: String,
    pub attester_commitment: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub pq_signature_root: String,
    pub statement_root: String,
    pub evidence_root: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl PqContractAttestation {
    pub fn new(
        node: &EncryptedCallgraphNode,
        attester_commitment: impl Into<String>,
        kind: AttestationKind,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let attester_commitment = attester_commitment.into();
        let seed = domain_hash(
            "PQ-CONTRACT-ATTESTATION-ID",
            &[
                HashPart::Str(&node.node_id),
                HashPart::Str(&attester_commitment),
                HashPart::U64(created_height),
            ],
            16,
        );
        Self {
            attestation_id: format!("pq-attest-{seed}"),
            shard_id: node.shard_id.clone(),
            node_id: node.node_id.clone(),
            contract_commitment: node.contract_commitment.clone(),
            attester_commitment,
            kind,
            status: AttestationStatus::Submitted,
            pq_signature_root: domain_hash(
                "PQ-CONTRACT-ATTESTATION-SIGNATURE",
                &[HashPart::Str(&seed)],
                32,
            ),
            statement_root: node.root(),
            evidence_root: domain_hash(
                "PQ-CONTRACT-ATTESTATION-EVIDENCE",
                &[HashPart::Str(&seed)],
                32,
            ),
            security_bits: config.min_pq_security_bits,
            privacy_set_size: config.target_privacy_set_size,
            created_height,
            expires_height: created_height + config.attestation_ttl_blocks,
        }
    }

    pub fn accept(mut self) -> Self {
        self.status = AttestationStatus::Accepted;
        self
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        required("attestation_id", &self.attestation_id)?;
        required("node_id", &self.node_id)?;
        required("contract_commitment", &self.contract_commitment)?;
        required("attester_commitment", &self.attester_commitment)?;
        ensure!(
            self.security_bits >= config.min_pq_security_bits,
            "attestation {} security below configured minimum",
            self.attestation_id
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "attestation {} privacy set below minimum",
            self.attestation_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "shard_id": self.shard_id,
            "node_id": self.node_id,
            "contract_commitment": self.contract_commitment,
            "attester_commitment": self.attester_commitment,
            "kind": self.kind,
            "status": self.status,
            "pq_signature_root": self.pq_signature_root,
            "statement_root": self.statement_root,
            "evidence_root": self.evidence_root,
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-CONTRACT-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvalidationProof {
    pub proof_id: String,
    pub shard_id: String,
    pub node_id: String,
    pub reason: InvalidationReason,
    pub stale_root: String,
    pub replacement_root: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub settlement_height: u64,
}

impl InvalidationProof {
    pub fn new(
        node: &EncryptedCallgraphNode,
        reason: InvalidationReason,
        challenger_commitment: impl Into<String>,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let challenger_commitment = challenger_commitment.into();
        let seed = domain_hash(
            "INVALIDATION-PROOF-ID",
            &[
                HashPart::Str(&node.node_id),
                HashPart::Str(&challenger_commitment),
                HashPart::U64(created_height),
            ],
            16,
        );
        Self {
            proof_id: format!("invalidate-{seed}"),
            shard_id: node.shard_id.clone(),
            node_id: node.node_id.clone(),
            reason,
            stale_root: node.root(),
            replacement_root: empty_root("INVALIDATION-REPLACEMENT"),
            evidence_root: domain_hash("INVALIDATION-EVIDENCE", &[HashPart::Str(&seed)], 32),
            challenger_commitment,
            privacy_set_size: config.min_privacy_set_size,
            created_height,
            settlement_height: created_height + config.invalidation_window_blocks,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        required("proof_id", &self.proof_id)?;
        required("node_id", &self.node_id)?;
        required("stale_root", &self.stale_root)?;
        required("evidence_root", &self.evidence_root)?;
        ensure!(
            self.settlement_height > self.created_height,
            "proof {} settlement must be after creation",
            self.proof_id
        );
        ensure!(
            self.privacy_set_size >= config.min_privacy_set_size,
            "proof {} privacy set below minimum",
            self.proof_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "shard_id": self.shard_id,
            "node_id": self.node_id,
            "reason": self.reason,
            "stale_root": self.stale_root,
            "replacement_root": self.replacement_root,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "settlement_height": self.settlement_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "INVALIDATION-PROOF",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompressionRebate {
    pub rebate_id: String,
    pub shard_id: String,
    pub node_id: String,
    pub beneficiary_commitment: String,
    pub original_fee: u64,
    pub compressed_bytes_saved: u64,
    pub rebate_amount: u64,
    pub status: RebateStatus,
    pub claim_nullifier: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl CompressionRebate {
    pub fn for_node(
        node: &EncryptedCallgraphNode,
        beneficiary_commitment: impl Into<String>,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let beneficiary_commitment = beneficiary_commitment.into();
        let saved = node
            .uncompressed_bytes
            .saturating_sub(node.compressed_bytes);
        let rebate_amount = node.fee_paid.saturating_mul(config.compression_rebate_bps) / MAX_BPS;
        let seed = domain_hash(
            "COMPRESSION-REBATE-ID",
            &[
                HashPart::Str(&node.node_id),
                HashPart::Str(&beneficiary_commitment),
                HashPart::U64(created_height),
            ],
            16,
        );
        Self {
            rebate_id: format!("callgraph-rebate-{seed}"),
            shard_id: node.shard_id.clone(),
            node_id: node.node_id.clone(),
            beneficiary_commitment,
            original_fee: node.fee_paid,
            compressed_bytes_saved: saved,
            rebate_amount,
            status: RebateStatus::Pending,
            claim_nullifier: domain_hash(
                "COMPRESSION-REBATE-NULLIFIER",
                &[HashPart::Str(&seed)],
                32,
            ),
            created_height,
            expires_height: created_height + config.rebate_ttl_blocks,
        }
    }

    pub fn claimable(mut self) -> Self {
        self.status = RebateStatus::Claimable;
        self
    }

    pub fn validate(&self) -> Result<()> {
        required("rebate_id", &self.rebate_id)?;
        required("node_id", &self.node_id)?;
        required("beneficiary_commitment", &self.beneficiary_commitment)?;
        required("claim_nullifier", &self.claim_nullifier)?;
        ensure!(
            self.expires_height > self.created_height,
            "rebate {} expires before creation",
            self.rebate_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "shard_id": self.shard_id,
            "node_id": self.node_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "original_fee": self.original_fee,
            "compressed_bytes_saved": self.compressed_bytes_saved,
            "rebate_amount": self.rebate_amount,
            "status": self.status,
            "claim_nullifier": self.claim_nullifier,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "COMPRESSION-REBATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_commitment: String,
    pub shard_id: String,
    pub epoch: u64,
    pub max_public_nodes: u64,
    pub max_public_edges: u64,
    pub max_operator_summaries: u64,
    pub spent_public_nodes: u64,
    pub spent_public_edges: u64,
    pub spent_operator_summaries: u64,
    pub privacy_floor: u64,
    pub created_height: u64,
}

impl RedactionBudget {
    pub fn new(
        shard_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        epoch: u64,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let shard_id = shard_id.into();
        let operator_commitment = operator_commitment.into();
        let seed = domain_hash(
            "REDACTION-BUDGET-ID",
            &[
                HashPart::Str(&shard_id),
                HashPart::Str(&operator_commitment),
                HashPart::U64(epoch),
            ],
            16,
        );
        Self {
            budget_id: format!("redaction-budget-{seed}"),
            operator_commitment,
            shard_id,
            epoch,
            max_public_nodes: 64,
            max_public_edges: 128,
            max_operator_summaries: 16,
            spent_public_nodes: 0,
            spent_public_edges: 0,
            spent_operator_summaries: 0,
            privacy_floor: config.min_privacy_set_size,
            created_height,
        }
    }

    pub fn spend(&mut self, public_nodes: u64, public_edges: u64, summaries: u64) -> Result<()> {
        ensure!(
            self.spent_public_nodes.saturating_add(public_nodes) <= self.max_public_nodes,
            "redaction node budget exceeded"
        );
        ensure!(
            self.spent_public_edges.saturating_add(public_edges) <= self.max_public_edges,
            "redaction edge budget exceeded"
        );
        ensure!(
            self.spent_operator_summaries.saturating_add(summaries) <= self.max_operator_summaries,
            "redaction summary budget exceeded"
        );
        self.spent_public_nodes = self.spent_public_nodes.saturating_add(public_nodes);
        self.spent_public_edges = self.spent_public_edges.saturating_add(public_edges);
        self.spent_operator_summaries = self.spent_operator_summaries.saturating_add(summaries);
        Ok(())
    }

    pub fn remaining_nodes(&self) -> u64 {
        self.max_public_nodes
            .saturating_sub(self.spent_public_nodes)
    }

    pub fn validate(&self) -> Result<()> {
        required("budget_id", &self.budget_id)?;
        required("operator_commitment", &self.operator_commitment)?;
        ensure!(
            self.spent_public_nodes <= self.max_public_nodes,
            "redaction budget {} overspent nodes",
            self.budget_id
        );
        ensure!(
            self.spent_public_edges <= self.max_public_edges,
            "redaction budget {} overspent edges",
            self.budget_id
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_commitment": self.operator_commitment,
            "shard_id": self.shard_id,
            "epoch": self.epoch,
            "max_public_nodes": self.max_public_nodes,
            "max_public_edges": self.max_public_edges,
            "max_operator_summaries": self.max_operator_summaries,
            "spent_public_nodes": self.spent_public_nodes,
            "spent_public_edges": self.spent_public_edges,
            "spent_operator_summaries": self.spent_operator_summaries,
            "remaining_public_nodes": self.remaining_nodes(),
            "privacy_floor": self.privacy_floor,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "REDACTION-BUDGET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub shard_ids: Vec<String>,
    pub epoch: u64,
    pub node_count: u64,
    pub hint_count: u64,
    pub attestation_count: u64,
    pub invalidation_count: u64,
    pub cache_hit_bps: u64,
    pub median_latency_micros: u64,
    pub fee_collected: u64,
    pub rebate_claimable: u64,
    pub redacted_callgraph_root: String,
    pub created_height: u64,
}

impl OperatorSummary {
    pub fn from_state(
        operator_commitment: impl Into<String>,
        epoch: u64,
        state: &State,
        created_height: u64,
    ) -> Self {
        let operator_commitment = operator_commitment.into();
        let shard_ids = state
            .shards
            .values()
            .filter(|shard| shard.operator_commitment == operator_commitment)
            .map(|shard| shard.shard_id.clone())
            .collect::<Vec<_>>();
        let fee_collected = state
            .shards
            .values()
            .filter(|shard| shard.operator_commitment == operator_commitment)
            .map(|shard| shard.total_fee_collected)
            .sum();
        let total_hits: u64 = state.shards.values().map(|shard| shard.cache_hits).sum();
        let total_misses: u64 = state.shards.values().map(|shard| shard.cache_misses).sum();
        let total_access = total_hits.saturating_add(total_misses);
        let cache_hit_bps = if total_access == 0 {
            0
        } else {
            total_hits.saturating_mul(MAX_BPS) / total_access
        };
        let median_latency_micros = median_latency(state.nodes.values());
        let rebate_claimable = state
            .compression_rebates
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Claimable)
            .map(|rebate| rebate.rebate_amount)
            .sum();
        let redacted_callgraph_root = merkle_root(
            "OPERATOR-REDACTED-CALLGRAPH",
            &state
                .nodes
                .values()
                .map(|node| {
                    json!({
                        "node_id": node.node_id,
                        "shard_id": node.shard_id,
                        "status": node.status,
                        "contract_class": node.contract_class,
                        "cache_score": node.cache_score(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let seed = domain_hash(
            "OPERATOR-SUMMARY-ID",
            &[
                HashPart::Str(&operator_commitment),
                HashPart::U64(epoch),
                HashPart::Str(&redacted_callgraph_root),
            ],
            16,
        );
        Self {
            summary_id: format!("operator-summary-{seed}"),
            operator_commitment,
            shard_ids,
            epoch,
            node_count: state.nodes.len() as u64,
            hint_count: state.dependency_hints.len() as u64,
            attestation_count: state.pq_attestations.len() as u64,
            invalidation_count: state.invalidation_proofs.len() as u64,
            cache_hit_bps,
            median_latency_micros,
            fee_collected,
            rebate_claimable,
            redacted_callgraph_root,
            created_height,
        }
    }

    pub fn validate(&self) -> Result<()> {
        required("summary_id", &self.summary_id)?;
        required("operator_commitment", &self.operator_commitment)?;
        required("redacted_callgraph_root", &self.redacted_callgraph_root)?;
        ensure_bps("cache_hit_bps", self.cache_hit_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "shard_ids": self.shard_ids,
            "epoch": self.epoch,
            "node_count": self.node_count,
            "hint_count": self.hint_count,
            "attestation_count": self.attestation_count,
            "invalidation_count": self.invalidation_count,
            "cache_hit_bps": self.cache_hit_bps,
            "median_latency_micros": self.median_latency_micros,
            "fee_collected": self.fee_collected,
            "rebate_claimable": self.rebate_claimable,
            "redacted_callgraph_root": self.redacted_callgraph_root,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "OPERATOR-SUMMARY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub shard_count: u64,
    pub node_count: u64,
    pub dependency_hint_count: u64,
    pub pq_attestation_count: u64,
    pub invalidation_proof_count: u64,
    pub compression_rebate_count: u64,
    pub redaction_budget_count: u64,
    pub operator_summary_count: u64,
    pub warm_node_count: u64,
    pub hot_node_count: u64,
    pub total_cache_hits: u64,
    pub total_cache_misses: u64,
    pub total_fee_collected: u64,
    pub total_rebate_claimable: u64,
    pub average_cache_score: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_count": self.shard_count,
            "node_count": self.node_count,
            "dependency_hint_count": self.dependency_hint_count,
            "pq_attestation_count": self.pq_attestation_count,
            "invalidation_proof_count": self.invalidation_proof_count,
            "compression_rebate_count": self.compression_rebate_count,
            "redaction_budget_count": self.redaction_budget_count,
            "operator_summary_count": self.operator_summary_count,
            "warm_node_count": self.warm_node_count,
            "hot_node_count": self.hot_node_count,
            "total_cache_hits": self.total_cache_hits,
            "total_cache_misses": self.total_cache_misses,
            "total_fee_collected": self.total_fee_collected,
            "total_rebate_claimable": self.total_rebate_claimable,
            "average_cache_score": self.average_cache_score,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub shard_root: String,
    pub node_root: String,
    pub dependency_hint_root: String,
    pub pq_attestation_root: String,
    pub invalidation_proof_root: String,
    pub compression_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub counter_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_root": self.shard_root,
            "node_root": self.node_root,
            "dependency_hint_root": self.dependency_hint_root,
            "pq_attestation_root": self.pq_attestation_root,
            "invalidation_proof_root": self.invalidation_proof_root,
            "compression_rebate_root": self.compression_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "CALLGRAPH-CACHE-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub epoch: u64,
    pub shards: BTreeMap<String, CacheShard>,
    pub nodes: BTreeMap<String, EncryptedCallgraphNode>,
    pub dependency_hints: BTreeMap<String, DependencyHint>,
    pub pq_attestations: BTreeMap<String, PqContractAttestation>,
    pub invalidation_proofs: BTreeMap<String, InvalidationProof>,
    pub compression_rebates: BTreeMap<String, CompressionRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            l2_height,
            epoch,
            shards: BTreeMap::new(),
            nodes: BTreeMap::new(),
            dependency_hints: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            invalidation_proofs: BTreeMap::new(),
            compression_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        build_demo().expect("devnet encrypted callgraph cache")
    }

    pub fn add_shard(&mut self, shard: CacheShard) -> Result<String> {
        ensure!(
            self.shards.len() < self.config.max_shards,
            "cache shard capacity exceeded"
        );
        shard.validate()?;
        let shard_id = shard.shard_id.clone();
        let _ = self.shards.insert(shard_id.clone(), shard);
        Ok(shard_id)
    }

    pub fn add_node(&mut self, node: EncryptedCallgraphNode) -> Result<String> {
        ensure!(
            self.nodes.len() < self.config.max_nodes,
            "callgraph node capacity exceeded"
        );
        node.validate(&self.config)?;
        let shard = self
            .shards
            .get_mut(&node.shard_id)
            .ok_or_else(|| format!("missing shard {}", node.shard_id))?;
        ensure!(
            shard.status.accepts_nodes(),
            "shard {} does not accept nodes",
            node.shard_id
        );
        if matches!(node.status, CallgraphNodeStatus::Warmed) {
            shard.warm_nodes = shard.warm_nodes.saturating_add(1);
        }
        if matches!(node.status, CallgraphNodeStatus::Hot) {
            shard.hot_nodes = shard.hot_nodes.saturating_add(1);
        }
        shard.total_fee_collected = shard.total_fee_collected.saturating_add(node.fee_paid);
        let _ = shard.contract_classes.insert(node.contract_class);
        let node_id = node.node_id.clone();
        let _ = self.nodes.insert(node_id.clone(), node);
        self.refresh_shard_roots();
        Ok(node_id)
    }

    pub fn add_dependency_hint(&mut self, hint: DependencyHint) -> Result<String> {
        ensure!(
            self.dependency_hints.len() < self.config.max_dependency_hints,
            "dependency hint capacity exceeded"
        );
        hint.validate(&self.config)?;
        let shard = self
            .shards
            .get(&hint.shard_id)
            .ok_or_else(|| format!("missing shard {}", hint.shard_id))?;
        ensure!(
            shard.status.accepts_hints(),
            "shard {} does not accept dependency hints",
            hint.shard_id
        );
        let node = self
            .nodes
            .get(&hint.from_node_id)
            .ok_or_else(|| format!("missing source node {}", hint.from_node_id))?;
        ensure!(
            node.status.can_hint(),
            "node {} is not hintable",
            hint.from_node_id
        );
        let hint_id = hint.hint_id.clone();
        let _ = self.dependency_hints.insert(hint_id.clone(), hint);
        self.refresh_shard_roots();
        Ok(hint_id)
    }

    pub fn add_pq_attestation(&mut self, attestation: PqContractAttestation) -> Result<String> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations,
            "pq attestation capacity exceeded"
        );
        attestation.validate(&self.config)?;
        ensure!(
            self.nodes.contains_key(&attestation.node_id),
            "attestation references missing node {}",
            attestation.node_id
        );
        let attestation_id = attestation.attestation_id.clone();
        let _ = self
            .pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.refresh_shard_roots();
        Ok(attestation_id)
    }

    pub fn add_invalidation_proof(&mut self, proof: InvalidationProof) -> Result<String> {
        ensure!(
            self.invalidation_proofs.len() < self.config.max_invalidation_proofs,
            "invalidation proof capacity exceeded"
        );
        proof.validate(&self.config)?;
        let node = self
            .nodes
            .get_mut(&proof.node_id)
            .ok_or_else(|| format!("missing invalidated node {}", proof.node_id))?;
        ensure!(
            node.status.can_invalidate(),
            "node {} already finalized",
            proof.node_id
        );
        node.status = CallgraphNodeStatus::Invalidating;
        let proof_id = proof.proof_id.clone();
        let _ = self.invalidation_proofs.insert(proof_id.clone(), proof);
        Ok(proof_id)
    }

    pub fn add_compression_rebate(&mut self, rebate: CompressionRebate) -> Result<String> {
        ensure!(
            self.compression_rebates.len() < self.config.max_compression_rebates,
            "compression rebate capacity exceeded"
        );
        rebate.validate()?;
        ensure!(
            self.nodes.contains_key(&rebate.node_id),
            "rebate references missing node {}",
            rebate.node_id
        );
        let rebate_id = rebate.rebate_id.clone();
        let _ = self.compression_rebates.insert(rebate_id.clone(), rebate);
        Ok(rebate_id)
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exceeded"
        );
        budget.validate()?;
        let budget_id = budget.budget_id.clone();
        let _ = self.redaction_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<String> {
        ensure!(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity exceeded"
        );
        summary.validate()?;
        let summary_id = summary.summary_id.clone();
        let _ = self.operator_summaries.insert(summary_id.clone(), summary);
        Ok(summary_id)
    }

    pub fn record_cache_access(&mut self, node_id: &str, hit: bool, fee: u64) -> Result<()> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| format!("missing node {node_id}"))?;
        node.access_count = node.access_count.saturating_add(1);
        node.last_access_height = self.l2_height;
        if hit
            && matches!(
                node.status,
                CallgraphNodeStatus::Warmed | CallgraphNodeStatus::Hot
            )
        {
            node.status = CallgraphNodeStatus::Hot;
        }
        let shard = self
            .shards
            .get_mut(&node.shard_id)
            .ok_or_else(|| format!("missing shard {}", node.shard_id))?;
        if hit {
            shard.record_hit(fee);
        } else {
            shard.record_miss();
        }
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let warm_node_count = self
            .nodes
            .values()
            .filter(|node| node.status == CallgraphNodeStatus::Warmed)
            .count() as u64;
        let hot_node_count = self
            .nodes
            .values()
            .filter(|node| node.status == CallgraphNodeStatus::Hot)
            .count() as u64;
        let total_cache_hits = self.shards.values().map(|shard| shard.cache_hits).sum();
        let total_cache_misses = self.shards.values().map(|shard| shard.cache_misses).sum();
        let total_fee_collected = self
            .shards
            .values()
            .map(|shard| shard.total_fee_collected)
            .sum();
        let total_rebate_claimable = self
            .compression_rebates
            .values()
            .filter(|rebate| rebate.status == RebateStatus::Claimable)
            .map(|rebate| rebate.rebate_amount)
            .sum();
        let total_score: u64 = self
            .nodes
            .values()
            .map(EncryptedCallgraphNode::cache_score)
            .sum();
        let average_cache_score = if self.nodes.is_empty() {
            0
        } else {
            total_score / self.nodes.len() as u64
        };
        Counters {
            shard_count: self.shards.len() as u64,
            node_count: self.nodes.len() as u64,
            dependency_hint_count: self.dependency_hints.len() as u64,
            pq_attestation_count: self.pq_attestations.len() as u64,
            invalidation_proof_count: self.invalidation_proofs.len() as u64,
            compression_rebate_count: self.compression_rebates.len() as u64,
            redaction_budget_count: self.redaction_budgets.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            warm_node_count,
            hot_node_count,
            total_cache_hits,
            total_cache_misses,
            total_fee_collected,
            total_rebate_claimable,
            average_cache_score,
        }
    }

    pub fn roots(&self) -> Roots {
        let counter_record = self.counters().public_record();
        Roots {
            shard_root: collection_root(
                "CALLGRAPH-CACHE-SHARDS",
                self.shards.values().map(CacheShard::public_record),
            ),
            node_root: collection_root(
                "CALLGRAPH-CACHE-NODES",
                self.nodes
                    .values()
                    .map(EncryptedCallgraphNode::public_record),
            ),
            dependency_hint_root: collection_root(
                "CALLGRAPH-CACHE-HINTS",
                self.dependency_hints
                    .values()
                    .map(DependencyHint::public_record),
            ),
            pq_attestation_root: collection_root(
                "CALLGRAPH-CACHE-ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqContractAttestation::public_record),
            ),
            invalidation_proof_root: collection_root(
                "CALLGRAPH-CACHE-INVALIDATIONS",
                self.invalidation_proofs
                    .values()
                    .map(InvalidationProof::public_record),
            ),
            compression_rebate_root: collection_root(
                "CALLGRAPH-CACHE-REBATES",
                self.compression_rebates
                    .values()
                    .map(CompressionRebate::public_record),
            ),
            redaction_budget_root: collection_root(
                "CALLGRAPH-CACHE-REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            operator_summary_root: collection_root(
                "CALLGRAPH-CACHE-OPERATOR-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSummary::public_record),
            ),
            counter_root: domain_hash(
                "CALLGRAPH-CACHE-COUNTERS",
                &[HashPart::Json(&counter_record)],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "l2_height": self.l2_height,
            "epoch": self.epoch,
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ENCRYPTED-CALLGRAPH-CACHE-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.epoch),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }

    pub fn validate(&self) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.shards.len() <= self.config.max_shards,
            "too many shards"
        );
        ensure!(self.nodes.len() <= self.config.max_nodes, "too many nodes");
        ensure!(
            self.dependency_hints.len() <= self.config.max_dependency_hints,
            "too many dependency hints"
        );
        for shard in self.shards.values() {
            shard.validate()?;
        }
        for node in self.nodes.values() {
            node.validate(&self.config)?;
            ensure!(
                self.shards.contains_key(&node.shard_id),
                "node {} references missing shard {}",
                node.node_id,
                node.shard_id
            );
        }
        for hint in self.dependency_hints.values() {
            hint.validate(&self.config)?;
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate(&self.config)?;
        }
        for proof in self.invalidation_proofs.values() {
            proof.validate(&self.config)?;
        }
        for rebate in self.compression_rebates.values() {
            rebate.validate()?;
        }
        for budget in self.redaction_budgets.values() {
            budget.validate()?;
        }
        for summary in self.operator_summaries.values() {
            summary.validate()?;
        }
        Ok(self.state_root())
    }

    fn refresh_shard_roots(&mut self) {
        for shard in self.shards.values_mut() {
            let shard_id = shard.shard_id.clone();
            shard.node_root = collection_root(
                "CACHE-SHARD-NODE-ROOT",
                self.nodes
                    .values()
                    .filter(|node| node.shard_id == shard_id)
                    .map(EncryptedCallgraphNode::public_record),
            );
            shard.hint_root = collection_root(
                "CACHE-SHARD-HINT-ROOT",
                self.dependency_hints
                    .values()
                    .filter(|hint| hint.shard_id == shard_id)
                    .map(DependencyHint::public_record),
            );
            shard.attestation_root = collection_root(
                "CACHE-SHARD-ATTESTATION-ROOT",
                self.pq_attestations
                    .values()
                    .filter(|attestation| attestation.shard_id == shard_id)
                    .map(PqContractAttestation::public_record),
            );
        }
    }
}

fn build_devnet() -> Result<State> {
    build_demo()
}

fn build_demo() -> Result<State> {
    let config = Config::devnet();
    let mut state = State::new(config.clone(), DEVNET_L2_HEIGHT, DEVNET_EPOCH)?;

    let shard_a = CacheShard::new(
        "cg-shard-aa-defi-hot",
        "operator-pq-commitment-aa01",
        CacheShardStatus::Hot,
        DEVNET_L2_HEIGHT - 1_024,
        &config,
    )
    .add_contract_class(ContractClass::DefiRouter)
    .add_contract_class(ContractClass::AccountAbstraction)
    .add_contract_class(ContractClass::BridgeAdapter);
    let shard_b = CacheShard::new(
        "cg-shard-fhe-oracle-warm",
        "operator-pq-commitment-bb02",
        CacheShardStatus::Warm,
        DEVNET_L2_HEIGHT - 768,
        &config,
    )
    .add_contract_class(ContractClass::FheApplication)
    .add_contract_class(ContractClass::OracleAdapter);
    state.add_shard(shard_a)?;
    state.add_shard(shard_b)?;

    let node_a = EncryptedCallgraphNode::new(
        "cg-shard-aa-defi-hot",
        "contract-commitment-private-router-v4",
        CallgraphNodeKind::EntryPoint,
        ContractClass::DefiRouter,
        "encrypted-callgraph-root-router-swap",
        DEVNET_L2_HEIGHT - 512,
        &config,
    )
    .with_edges(
        "caller-commitment-wallet-aa",
        "callee-commitment-pool-router",
        0,
        4,
    )
    .with_metrics(61_000, 920, 12_288, 2_944, 2_100)
    .attest()
    .warm(DEVNET_L2_HEIGHT - 24);
    let node_b = EncryptedCallgraphNode::new(
        "cg-shard-aa-defi-hot",
        "contract-commitment-private-bridge-adapter-v2",
        CallgraphNodeKind::CrossContractCallback,
        ContractClass::BridgeAdapter,
        "encrypted-callgraph-root-bridge-callback",
        DEVNET_L2_HEIGHT - 448,
        &config,
    )
    .with_edges(
        "caller-commitment-router",
        "callee-commitment-bridge-adapter",
        1,
        2,
    )
    .with_metrics(89_000, 1_240, 16_384, 3_712, 2_800)
    .attest()
    .warm(DEVNET_L2_HEIGHT - 12);
    let node_c = EncryptedCallgraphNode::new(
        "cg-shard-fhe-oracle-warm",
        "contract-commitment-fhe-oracle-settlement-v1",
        CallgraphNodeKind::FheGate,
        ContractClass::FheApplication,
        "encrypted-callgraph-root-fhe-oracle",
        DEVNET_L2_HEIGHT - 320,
        &config,
    )
    .with_edges(
        "caller-commitment-oracle-client",
        "callee-commitment-fhe-gate",
        2,
        1,
    )
    .with_metrics(134_000, 1_740, 24_576, 6_144, 3_200)
    .attest();

    let node_a_id = state.add_node(node_a)?;
    let node_b_id = state.add_node(node_b)?;
    let node_c_id = state.add_node(node_c)?;

    let hint_ab = DependencyHint::new(
        "cg-shard-aa-defi-hot",
        node_a_id.clone(),
        "callee-commitment-bridge-adapter",
        DependencyHintKind::CallbackEdge,
        DEVNET_L2_HEIGHT - 300,
        &config,
    );
    let hint_ac = DependencyHint::new(
        "cg-shard-aa-defi-hot",
        node_a_id.clone(),
        "storage-prefix-redacted-liquidity",
        DependencyHintKind::StoragePrefix,
        DEVNET_L2_HEIGHT - 288,
        &config,
    );
    state.add_dependency_hint(hint_ab)?;
    state.add_dependency_hint(hint_ac)?;

    let attest_a = PqContractAttestation::new(
        state.nodes.get(&node_a_id).expect("demo node exists"),
        "attester-pq-committee-alpha",
        AttestationKind::DeterministicTrace,
        DEVNET_L2_HEIGHT - 256,
        &config,
    )
    .accept();
    let attest_b = PqContractAttestation::new(
        state.nodes.get(&node_b_id).expect("demo node exists"),
        "attester-pq-committee-alpha",
        AttestationKind::CacheSafety,
        DEVNET_L2_HEIGHT - 240,
        &config,
    )
    .accept();
    state.add_pq_attestation(attest_a)?;
    state.add_pq_attestation(attest_b)?;

    let rebate_a = CompressionRebate::for_node(
        state.nodes.get(&node_a_id).expect("demo node exists"),
        "beneficiary-commitment-wallet-aa",
        DEVNET_L2_HEIGHT - 120,
        &config,
    )
    .claimable();
    let rebate_b = CompressionRebate::for_node(
        state.nodes.get(&node_b_id).expect("demo node exists"),
        "beneficiary-commitment-bridge-user",
        DEVNET_L2_HEIGHT - 118,
        &config,
    )
    .claimable();
    state.add_compression_rebate(rebate_a)?;
    state.add_compression_rebate(rebate_b)?;

    let proof = InvalidationProof::new(
        state.nodes.get(&node_c_id).expect("demo node exists"),
        InvalidationReason::DependencyChanged,
        "challenger-commitment-watchtower-17",
        DEVNET_L2_HEIGHT - 64,
        &config,
    );
    state.add_invalidation_proof(proof)?;

    let mut budget_a = RedactionBudget::new(
        "cg-shard-aa-defi-hot",
        "operator-pq-commitment-aa01",
        DEVNET_EPOCH,
        DEVNET_L2_HEIGHT - 48,
        &config,
    );
    budget_a.spend(3, 5, 1)?;
    state.add_redaction_budget(budget_a)?;

    state.record_cache_access(&node_a_id, true, 24)?;
    state.record_cache_access(&node_b_id, true, 31)?;
    state.record_cache_access(&node_c_id, false, 0)?;

    let summary = OperatorSummary::from_state(
        "operator-pq-commitment-aa01",
        DEVNET_EPOCH,
        &state,
        DEVNET_L2_HEIGHT,
    );
    state.add_operator_summary(summary)?;
    state.refresh_shard_roots();
    state.validate()?;
    Ok(state)
}

pub fn devnet() -> State {
    build_devnet().expect("devnet encrypted callgraph cache")
}

pub fn demo() -> State {
    build_demo().expect("demo encrypted callgraph cache")
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn required(field: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} is required");
    Ok(())
}

fn ensure_nonzero(field: &str, value: u64) -> Result<()> {
    ensure!(value > 0, "{field} must be nonzero");
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    ensure!(value <= MAX_BPS, "{field} must be <= {MAX_BPS}");
    Ok(())
}

fn ensure_capacity(field: &str, value: usize) -> Result<()> {
    ensure!(value > 0, "{field} capacity must be nonzero");
    Ok(())
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn collection_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn short_commitment(domain: &str, label: &str, height: u64) -> String {
    domain_hash(domain, &[HashPart::Str(label), HashPart::U64(height)], 32)
}

fn median_latency<'a, I>(nodes: I) -> u64
where
    I: IntoIterator<Item = &'a EncryptedCallgraphNode>,
{
    let mut latencies = nodes
        .into_iter()
        .map(|node| node.measured_latency_micros)
        .collect::<Vec<_>>();
    if latencies.is_empty() {
        return 0;
    }
    latencies.sort_unstable();
    latencies[latencies.len() / 2]
}
