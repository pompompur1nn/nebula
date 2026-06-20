use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqDaRecoveryOracleResult<T> = Result<T, String>;

pub const PQ_DA_RECOVERY_ORACLE_PROTOCOL_VERSION: u64 = 1;
pub const PQ_DA_RECOVERY_ORACLE_PROTOCOL_ID: &str = "nebula-l2-pq-da-recovery-oracle-v1";
pub const PQ_DA_RECOVERY_ORACLE_SCHEMA_VERSION: u64 = 1;
pub const PQ_DA_RECOVERY_ORACLE_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_DA_RECOVERY_ORACLE_PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-192f";
pub const PQ_DA_RECOVERY_ORACLE_KEM_SUITE: &str = "ML-KEM-1024";
pub const PQ_DA_RECOVERY_ORACLE_ERASURE_SUITE: &str = "rs-16-16-shake256-commitment-v1";
pub const PQ_DA_RECOVERY_ORACLE_RECURSION_SCHEME: &str = "nebula-recursive-da-repair-proof-v1";
pub const PQ_DA_RECOVERY_ORACLE_MONERO_BRIDGE_SCHEME: &str =
    "monero-view-tag-bridge-proof-recovery-v1";
pub const PQ_DA_RECOVERY_ORACLE_DEVNET_HEIGHT: u64 = 2_048;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_MIN_SECURITY_BITS: u16 = 256;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_ORIGINAL_SHARDS: u16 = 16;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_PARITY_SHARDS: u16 = 16;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_SHARD_SIZE_BYTES: u64 = 1_024;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_REPAIR_TTL_BLOCKS: u64 = 144;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_RETENTION_BLOCKS: u64 = 14_400;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_LOW_FEE_CREDIT_UNITS: u64 = 250_000;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_REPAIR_BOUNTY_UNITS: u64 = 1_500_000;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_CHALLENGE_BOND_UNITS: u64 = 500_000;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_RETRIEVAL_FEE_MICROUNITS: u64 = 4;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_SLASH_BPS: u64 = 3_000;
pub const PQ_DA_RECOVERY_ORACLE_MAX_BPS: u64 = 10_000;
pub const PQ_DA_RECOVERY_ORACLE_MAX_BATCHES: usize = 262_144;
pub const PQ_DA_RECOVERY_ORACLE_MAX_SHARDS: usize = 8_388_608;
pub const PQ_DA_RECOVERY_ORACLE_MAX_WATCHERS: usize = 65_536;
pub const PQ_DA_RECOVERY_ORACLE_MAX_ATTESTATIONS: usize = 2_097_152;
pub const PQ_DA_RECOVERY_ORACLE_MAX_BOUNTIES: usize = 262_144;
pub const PQ_DA_RECOVERY_ORACLE_MAX_RETRIEVAL_CREDITS: usize = 524_288;
pub const PQ_DA_RECOVERY_ORACLE_MAX_CHALLENGES: usize = 524_288;
pub const PQ_DA_RECOVERY_ORACLE_MAX_REPAIR_ROOTS: usize = 524_288;
pub const PQ_DA_RECOVERY_ORACLE_MAX_PUBLIC_EVENTS: usize = 1_048_576;
pub const PQ_DA_RECOVERY_ORACLE_DEFAULT_ASSET_ID: &str = "dxmr";
pub const PQ_DA_RECOVERY_ORACLE_LOW_FEE_LANE_ID: &str = "low-fee-private-da-retrieval";
pub const PQ_DA_RECOVERY_ORACLE_MONERO_LANE_ID: &str = "monero-bridge-proof-recovery";
pub const PQ_DA_RECOVERY_ORACLE_PRIVATE_BATCH_LANE_ID: &str = "private-batch-repair";
pub const PQ_DA_RECOVERY_ORACLE_DEVNET_OPERATOR_ID: &str = "pq-da-recovery-oracle-operator-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLane {
    PrivateBatch,
    MoneroBridgeProof,
    TokenDefi,
    ContractCall,
    RecursiveProof,
    ForcedInclusion,
    EmergencyReplay,
}

impl RecoveryLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateBatch => "private_batch",
            Self::MoneroBridgeProof => "monero_bridge_proof",
            Self::TokenDefi => "token_defi",
            Self::ContractCall => "contract_call",
            Self::RecursiveProof => "recursive_proof",
            Self::ForcedInclusion => "forced_inclusion",
            Self::EmergencyReplay => "emergency_replay",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyReplay => 10_000,
            Self::MoneroBridgeProof => 9_500,
            Self::ForcedInclusion => 9_000,
            Self::PrivateBatch => 8_200,
            Self::RecursiveProof => 7_400,
            Self::ContractCall => 6_800,
            Self::TokenDefi => 6_400,
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::PrivateBatch
                | Self::MoneroBridgeProof
                | Self::TokenDefi
                | Self::ContractCall
                | Self::RecursiveProof
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchAvailabilityStatus {
    Posted,
    Sampling,
    Attested,
    Degraded,
    RepairRequested,
    Repairing,
    Recovered,
    Challenged,
    Slashed,
    Expired,
    Finalized,
}

impl BatchAvailabilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Sampling => "sampling",
            Self::Attested => "attested",
            Self::Degraded => "degraded",
            Self::RepairRequested => "repair_requested",
            Self::Repairing => "repairing",
            Self::Recovered => "recovered",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Finalized => "finalized",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Posted
                | Self::Sampling
                | Self::Attested
                | Self::Degraded
                | Self::RepairRequested
                | Self::Repairing
                | Self::Recovered
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardRole {
    Original,
    Parity,
    Repair,
    RecursiveRepair,
}

impl ShardRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Parity => "parity",
            Self::Repair => "repair",
            Self::RecursiveRepair => "recursive_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardAvailabilityStatus {
    Committed,
    Sampled,
    Missing,
    Repaired,
    Withheld,
    Invalid,
    Expired,
}

impl ShardAvailabilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Sampled => "sampled",
            Self::Missing => "missing",
            Self::Repaired => "repaired",
            Self::Withheld => "withheld",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Committed | Self::Sampled | Self::Repaired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherRole {
    Sequencer,
    Watchtower,
    ArchiveProvider,
    MoneroObserver,
    RepairProvider,
    Challenger,
    EmergencyCouncil,
}

impl WatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Watchtower => "watchtower",
            Self::ArchiveProvider => "archive_provider",
            Self::MoneroObserver => "monero_observer",
            Self::RepairProvider => "repair_provider",
            Self::Challenger => "challenger",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherStatus {
    Pending,
    Active,
    Degraded,
    Jailed,
    Retired,
}

impl WatcherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Custody,
    Retrieval,
    Repair,
    MoneroBridgeObservation,
    RecursiveProofRepair,
    ChallengeSupport,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Custody => "custody",
            Self::Retrieval => "retrieval",
            Self::Repair => "repair",
            Self::MoneroBridgeObservation => "monero_bridge_observation",
            Self::RecursiveProofRepair => "recursive_proof_repair",
            Self::ChallengeSupport => "challenge_support",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BountyStatus {
    Open,
    Assigned,
    Claimed,
    Verified,
    Paid,
    Slashed,
    Expired,
}

impl BountyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::Claimed => "claimed",
            Self::Verified => "verified",
            Self::Paid => "paid",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalCreditStatus {
    Funded,
    Reserved,
    Spent,
    Refunded,
    Expired,
}

impl RetrievalCreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funded => "funded",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    MissingShard,
    InvalidShard,
    FalseCustody,
    FalseRepair,
    MoneroBridgeMismatch,
    RecursiveRootMismatch,
    FeeCreditAbuse,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingShard => "missing_shard",
            Self::InvalidShard => "invalid_shard",
            Self::FalseCustody => "false_custody",
            Self::FalseRepair => "false_repair",
            Self::MoneroBridgeMismatch => "monero_bridge_mismatch",
            Self::RecursiveRootMismatch => "recursive_root_mismatch",
            Self::FeeCreditAbuse => "fee_credit_abuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Resolved,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Resolved => "resolved",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveRepairStatus {
    Pending,
    Proving,
    Posted,
    Verified,
    Rejected,
    Superseded,
}

impl RecursiveRepairStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Proving => "proving",
            Self::Posted => "posted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDaRecoveryOracleConfig {
    pub protocol_version: u64,
    pub protocol_id: String,
    pub schema_version: u64,
    pub min_security_bits: u16,
    pub original_shards: u16,
    pub parity_shards: u16,
    pub shard_size_bytes: u64,
    pub min_watcher_weight: u64,
    pub challenge_window_blocks: u64,
    pub repair_ttl_blocks: u64,
    pub retention_blocks: u64,
    pub default_low_fee_credit_units: u64,
    pub default_repair_bounty_units: u64,
    pub default_challenge_bond_units: u64,
    pub default_retrieval_fee_microunits: u64,
    pub slash_bps: u64,
    pub fee_asset_id: String,
}

impl PqDaRecoveryOracleConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PQ_DA_RECOVERY_ORACLE_PROTOCOL_VERSION,
            protocol_id: PQ_DA_RECOVERY_ORACLE_PROTOCOL_ID.to_string(),
            schema_version: PQ_DA_RECOVERY_ORACLE_SCHEMA_VERSION,
            min_security_bits: PQ_DA_RECOVERY_ORACLE_DEFAULT_MIN_SECURITY_BITS,
            original_shards: PQ_DA_RECOVERY_ORACLE_DEFAULT_ORIGINAL_SHARDS,
            parity_shards: PQ_DA_RECOVERY_ORACLE_DEFAULT_PARITY_SHARDS,
            shard_size_bytes: PQ_DA_RECOVERY_ORACLE_DEFAULT_SHARD_SIZE_BYTES,
            min_watcher_weight: PQ_DA_RECOVERY_ORACLE_DEFAULT_MIN_WATCHER_WEIGHT,
            challenge_window_blocks: PQ_DA_RECOVERY_ORACLE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            repair_ttl_blocks: PQ_DA_RECOVERY_ORACLE_DEFAULT_REPAIR_TTL_BLOCKS,
            retention_blocks: PQ_DA_RECOVERY_ORACLE_DEFAULT_RETENTION_BLOCKS,
            default_low_fee_credit_units: PQ_DA_RECOVERY_ORACLE_DEFAULT_LOW_FEE_CREDIT_UNITS,
            default_repair_bounty_units: PQ_DA_RECOVERY_ORACLE_DEFAULT_REPAIR_BOUNTY_UNITS,
            default_challenge_bond_units: PQ_DA_RECOVERY_ORACLE_DEFAULT_CHALLENGE_BOND_UNITS,
            default_retrieval_fee_microunits:
                PQ_DA_RECOVERY_ORACLE_DEFAULT_RETRIEVAL_FEE_MICROUNITS,
            slash_bps: PQ_DA_RECOVERY_ORACLE_DEFAULT_SLASH_BPS,
            fee_asset_id: PQ_DA_RECOVERY_ORACLE_DEFAULT_ASSET_ID.to_string(),
        }
    }

    pub fn total_shards(&self) -> u64 {
        self.original_shards as u64 + self.parity_shards as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "protocol_id": self.protocol_id,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "hash_suite": PQ_DA_RECOVERY_ORACLE_HASH_SUITE,
            "pq_signature_suite": PQ_DA_RECOVERY_ORACLE_PQ_SIGNATURE_SUITE,
            "kem_suite": PQ_DA_RECOVERY_ORACLE_KEM_SUITE,
            "erasure_suite": PQ_DA_RECOVERY_ORACLE_ERASURE_SUITE,
            "recursion_scheme": PQ_DA_RECOVERY_ORACLE_RECURSION_SCHEME,
            "monero_bridge_scheme": PQ_DA_RECOVERY_ORACLE_MONERO_BRIDGE_SCHEME,
            "min_security_bits": self.min_security_bits,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "total_shards": self.total_shards(),
            "shard_size_bytes": self.shard_size_bytes,
            "min_watcher_weight": self.min_watcher_weight,
            "challenge_window_blocks": self.challenge_window_blocks,
            "repair_ttl_blocks": self.repair_ttl_blocks,
            "retention_blocks": self.retention_blocks,
            "default_low_fee_credit_units": self.default_low_fee_credit_units,
            "default_repair_bounty_units": self.default_repair_bounty_units,
            "default_challenge_bond_units": self.default_challenge_bond_units,
            "default_retrieval_fee_microunits": self.default_retrieval_fee_microunits,
            "slash_bps": self.slash_bps,
            "fee_asset_id": self.fee_asset_id,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        if self.protocol_version != PQ_DA_RECOVERY_ORACLE_PROTOCOL_VERSION {
            return Err("unsupported pq da recovery oracle protocol version".to_string());
        }
        if self.protocol_id != PQ_DA_RECOVERY_ORACLE_PROTOCOL_ID {
            return Err("unexpected pq da recovery oracle protocol id".to_string());
        }
        if self.min_security_bits < 192 {
            return Err(
                "pq da recovery oracle security bits below post-quantum policy".to_string(),
            );
        }
        if self.original_shards == 0 || self.parity_shards == 0 {
            return Err("pq da recovery oracle requires original and parity shards".to_string());
        }
        if self.parity_shards > self.original_shards.saturating_mul(4) {
            return Err("pq da recovery oracle parity fanout is excessive".to_string());
        }
        if self.shard_size_bytes == 0 {
            return Err("pq da recovery oracle shard size must be non-zero".to_string());
        }
        if self.min_watcher_weight == 0 {
            return Err("pq da recovery oracle watcher quorum must be non-zero".to_string());
        }
        if self.challenge_window_blocks == 0 || self.repair_ttl_blocks == 0 {
            return Err("pq da recovery oracle windows must be non-zero".to_string());
        }
        if self.retention_blocks < self.challenge_window_blocks + self.repair_ttl_blocks {
            return Err(
                "pq da recovery oracle retention must cover challenge and repair windows"
                    .to_string(),
            );
        }
        if self.default_retrieval_fee_microunits == 0 {
            return Err("pq da recovery oracle retrieval fee must be non-zero".to_string());
        }
        if self.slash_bps > PQ_DA_RECOVERY_ORACLE_MAX_BPS {
            return Err("pq da recovery oracle slash bps exceeds maximum".to_string());
        }
        require_non_empty("fee_asset_id", &self.fee_asset_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWatcher {
    pub watcher_id: String,
    pub role: WatcherRole,
    pub status: WatcherStatus,
    pub weight: u64,
    pub pq_identity_key_commitment: String,
    pub retrieval_endpoint_commitment: String,
    pub bond_asset_id: String,
    pub bond_amount: u64,
    pub joined_at_height: u64,
    pub last_attested_height: u64,
}

impl RecoveryWatcher {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "weight": self.weight,
            "pq_identity_key_commitment": self.pq_identity_key_commitment,
            "retrieval_endpoint_commitment": self.retrieval_endpoint_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_amount": self.bond_amount,
            "joined_at_height": self.joined_at_height,
            "last_attested_height": self.last_attested_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("watcher_id", &self.watcher_id)?;
        require_non_empty(
            "pq_identity_key_commitment",
            &self.pq_identity_key_commitment,
        )?;
        require_non_empty(
            "retrieval_endpoint_commitment",
            &self.retrieval_endpoint_commitment,
        )?;
        require_non_empty("bond_asset_id", &self.bond_asset_id)?;
        if self.weight == 0 {
            return Err(format!(
                "watcher {} has zero quorum weight",
                self.watcher_id
            ));
        }
        if self.status.can_attest() && self.bond_amount == 0 {
            return Err(format!("active watcher {} has zero bond", self.watcher_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureShardCommitment {
    pub shard_id: String,
    pub batch_id: String,
    pub shard_index: u32,
    pub role: ShardRole,
    pub status: ShardAvailabilityStatus,
    pub size_bytes: u64,
    pub shard_commitment: String,
    pub polynomial_commitment: String,
    pub encrypted_payload_hash: String,
    pub repair_hint_commitment: String,
    pub custody_watcher_ids: Vec<String>,
    pub posted_at_height: u64,
}

impl ErasureShardCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "batch_id": self.batch_id,
            "shard_index": self.shard_index,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "size_bytes": self.size_bytes,
            "shard_commitment": self.shard_commitment,
            "polynomial_commitment": self.polynomial_commitment,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "repair_hint_commitment": self.repair_hint_commitment,
            "custody_watcher_ids": self.custody_watcher_ids,
            "posted_at_height": self.posted_at_height,
        })
    }

    pub fn validate(&self, config: &PqDaRecoveryOracleConfig) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("shard_id", &self.shard_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("shard_commitment", &self.shard_commitment)?;
        require_non_empty("polynomial_commitment", &self.polynomial_commitment)?;
        require_non_empty("encrypted_payload_hash", &self.encrypted_payload_hash)?;
        require_non_empty("repair_hint_commitment", &self.repair_hint_commitment)?;
        if self.shard_index as u64 >= config.total_shards().saturating_add(4_096) {
            return Err(format!(
                "shard {} index exceeds configured recovery fanout",
                self.shard_id
            ));
        }
        if self.size_bytes == 0 || self.size_bytes > config.shard_size_bytes.saturating_mul(4) {
            return Err(format!("shard {} size is outside policy", self.shard_id));
        }
        if self.custody_watcher_ids.is_empty() {
            return Err(format!("shard {} has no custody watchers", self.shard_id));
        }
        require_unique("custody_watcher_ids", &self.custody_watcher_ids)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchRecoveryRecord {
    pub batch_id: String,
    pub lane: RecoveryLane,
    pub status: BatchAvailabilityStatus,
    pub sequencer_commitment: String,
    pub private_batch_payload_hash: String,
    pub encrypted_metadata_root: String,
    pub shard_commitment_root: String,
    pub original_shards: u16,
    pub parity_shards: u16,
    pub required_repair_shards: u16,
    pub watcher_quorum_weight: u64,
    pub low_fee_lane_id: String,
    pub posted_at_height: u64,
    pub challenge_deadline_height: u64,
    pub repair_deadline_height: u64,
    pub recursive_repair_root_id: Option<String>,
}

impl PrivateBatchRecoveryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "private_batch_payload_hash": self.private_batch_payload_hash,
            "encrypted_metadata_root": self.encrypted_metadata_root,
            "shard_commitment_root": self.shard_commitment_root,
            "original_shards": self.original_shards,
            "parity_shards": self.parity_shards,
            "required_repair_shards": self.required_repair_shards,
            "watcher_quorum_weight": self.watcher_quorum_weight,
            "low_fee_lane_id": self.low_fee_lane_id,
            "posted_at_height": self.posted_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "repair_deadline_height": self.repair_deadline_height,
            "recursive_repair_root_id": self.recursive_repair_root_id,
        })
    }

    pub fn validate(&self, config: &PqDaRecoveryOracleConfig) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("sequencer_commitment", &self.sequencer_commitment)?;
        require_non_empty(
            "private_batch_payload_hash",
            &self.private_batch_payload_hash,
        )?;
        require_non_empty("encrypted_metadata_root", &self.encrypted_metadata_root)?;
        require_non_empty("shard_commitment_root", &self.shard_commitment_root)?;
        require_non_empty("low_fee_lane_id", &self.low_fee_lane_id)?;
        if self.original_shards == 0 || self.parity_shards == 0 {
            return Err(format!(
                "batch {} must include original and parity shards",
                self.batch_id
            ));
        }
        if self.required_repair_shards > self.original_shards + self.parity_shards {
            return Err(format!(
                "batch {} repair threshold exceeds shard count",
                self.batch_id
            ));
        }
        if self.watcher_quorum_weight < config.min_watcher_weight {
            return Err(format!(
                "batch {} has insufficient watcher quorum weight",
                self.batch_id
            ));
        }
        if self.challenge_deadline_height <= self.posted_at_height {
            return Err(format!(
                "batch {} challenge deadline is not after post height",
                self.batch_id
            ));
        }
        if self.repair_deadline_height <= self.challenge_deadline_height {
            return Err(format!(
                "batch {} repair deadline is not after challenge deadline",
                self.batch_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeProofRecoveryRecord {
    pub bridge_proof_id: String,
    pub batch_id: String,
    pub monero_network: String,
    pub txid_hash: String,
    pub output_set_root: String,
    pub view_tag_root: String,
    pub reserve_event_root: String,
    pub ring_member_commitment_root: String,
    pub bridge_amount_piconero_commitment: String,
    pub recipient_subaddress_commitment: String,
    pub proof_payload_hash: String,
    pub recovery_shard_root: String,
    pub observed_at_height: u64,
    pub min_monero_confirmations: u64,
}

impl MoneroBridgeProofRecoveryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "bridge_proof_id": self.bridge_proof_id,
            "batch_id": self.batch_id,
            "monero_network": self.monero_network,
            "txid_hash": self.txid_hash,
            "output_set_root": self.output_set_root,
            "view_tag_root": self.view_tag_root,
            "reserve_event_root": self.reserve_event_root,
            "ring_member_commitment_root": self.ring_member_commitment_root,
            "bridge_amount_piconero_commitment": self.bridge_amount_piconero_commitment,
            "recipient_subaddress_commitment": self.recipient_subaddress_commitment,
            "proof_payload_hash": self.proof_payload_hash,
            "recovery_shard_root": self.recovery_shard_root,
            "observed_at_height": self.observed_at_height,
            "min_monero_confirmations": self.min_monero_confirmations,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("bridge_proof_id", &self.bridge_proof_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("txid_hash", &self.txid_hash)?;
        require_non_empty("output_set_root", &self.output_set_root)?;
        require_non_empty("view_tag_root", &self.view_tag_root)?;
        require_non_empty("reserve_event_root", &self.reserve_event_root)?;
        require_non_empty(
            "ring_member_commitment_root",
            &self.ring_member_commitment_root,
        )?;
        require_non_empty(
            "bridge_amount_piconero_commitment",
            &self.bridge_amount_piconero_commitment,
        )?;
        require_non_empty(
            "recipient_subaddress_commitment",
            &self.recipient_subaddress_commitment,
        )?;
        require_non_empty("proof_payload_hash", &self.proof_payload_hash)?;
        require_non_empty("recovery_shard_root", &self.recovery_shard_root)?;
        if self.min_monero_confirmations == 0 {
            return Err(format!(
                "monero bridge proof {} requires confirmations",
                self.bridge_proof_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub batch_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub shard_ids: Vec<String>,
    pub claimed_available_root: String,
    pub missing_shard_root: String,
    pub repair_payload_root: String,
    pub latency_millis: u64,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "batch_id": self.batch_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "shard_ids": self.shard_ids,
            "claimed_available_root": self.claimed_available_root,
            "missing_shard_root": self.missing_shard_root,
            "repair_payload_root": self.repair_payload_root,
            "latency_millis": self.latency_millis,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("watcher_id", &self.watcher_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("claimed_available_root", &self.claimed_available_root)?;
        require_non_empty("missing_shard_root", &self.missing_shard_root)?;
        require_non_empty("repair_payload_root", &self.repair_payload_root)?;
        require_non_empty("pq_signature_root", &self.pq_signature_root)?;
        if self.shard_ids.is_empty() {
            return Err(format!(
                "attestation {} references no shards",
                self.attestation_id
            ));
        }
        require_unique("attestation shard_ids", &self.shard_ids)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairBounty {
    pub bounty_id: String,
    pub batch_id: String,
    pub lane: RecoveryLane,
    pub status: BountyStatus,
    pub payer_commitment: String,
    pub assigned_provider_id: Option<String>,
    pub asset_id: String,
    pub bounty_amount: u64,
    pub min_repaired_shards: u16,
    pub repair_deadline_height: u64,
    pub verification_root: String,
    pub opened_at_height: u64,
}

impl RepairBounty {
    pub fn public_record(&self) -> Value {
        json!({
            "bounty_id": self.bounty_id,
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "payer_commitment": self.payer_commitment,
            "assigned_provider_id": self.assigned_provider_id,
            "asset_id": self.asset_id,
            "bounty_amount": self.bounty_amount,
            "min_repaired_shards": self.min_repaired_shards,
            "repair_deadline_height": self.repair_deadline_height,
            "verification_root": self.verification_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("bounty_id", &self.bounty_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("payer_commitment", &self.payer_commitment)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("verification_root", &self.verification_root)?;
        if self.bounty_amount == 0 {
            return Err(format!("repair bounty {} has zero amount", self.bounty_id));
        }
        if self.min_repaired_shards == 0 {
            return Err(format!(
                "repair bounty {} has zero repair threshold",
                self.bounty_id
            ));
        }
        if self.repair_deadline_height <= self.opened_at_height {
            return Err(format!(
                "repair bounty {} deadline is not after opening",
                self.bounty_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRetrievalCredit {
    pub credit_id: String,
    pub owner_commitment: String,
    pub lane_id: String,
    pub status: RetrievalCreditStatus,
    pub asset_id: String,
    pub funded_units: u64,
    pub spent_units: u64,
    pub retrieval_fee_microunits: u64,
    pub batch_allowlist_root: String,
    pub nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRetrievalCredit {
    pub fn remaining_units(&self) -> u64 {
        self.funded_units.saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "owner_commitment": self.owner_commitment,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "funded_units": self.funded_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "retrieval_fee_microunits": self.retrieval_fee_microunits,
            "batch_allowlist_root": self.batch_allowlist_root,
            "nullifier_root": self.nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("credit_id", &self.credit_id)?;
        require_non_empty("owner_commitment", &self.owner_commitment)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("batch_allowlist_root", &self.batch_allowlist_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        if self.funded_units == 0 {
            return Err(format!(
                "retrieval credit {} has zero funding",
                self.credit_id
            ));
        }
        if self.spent_units > self.funded_units {
            return Err(format!("retrieval credit {} is overspent", self.credit_id));
        }
        if self.retrieval_fee_microunits == 0 {
            return Err(format!(
                "retrieval credit {} has zero retrieval fee",
                self.credit_id
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "retrieval credit {} expires before opening",
                self.credit_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub challenger_commitment: String,
    pub challenged_watcher_id: Option<String>,
    pub batch_id: String,
    pub shard_id: Option<String>,
    pub evidence_payload_root: String,
    pub transcript_root: String,
    pub bond_asset_id: String,
    pub bond_amount: u64,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl ChallengeEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "challenged_watcher_id": self.challenged_watcher_id,
            "batch_id": self.batch_id,
            "shard_id": self.shard_id,
            "evidence_payload_root": self.evidence_payload_root,
            "transcript_root": self.transcript_root,
            "bond_asset_id": self.bond_asset_id,
            "bond_amount": self.bond_amount,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("challenge_id", &self.challenge_id)?;
        require_non_empty("challenger_commitment", &self.challenger_commitment)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("evidence_payload_root", &self.evidence_payload_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        require_non_empty("bond_asset_id", &self.bond_asset_id)?;
        if self.bond_amount == 0 {
            return Err(format!("challenge {} has zero bond", self.challenge_id));
        }
        if self.response_deadline_height <= self.opened_at_height {
            return Err(format!(
                "challenge {} response deadline is not after opening",
                self.challenge_id
            ));
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err(format!(
                    "challenge {} resolved before opening",
                    self.challenge_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofRepairRoot {
    pub repair_root_id: String,
    pub batch_id: String,
    pub status: RecursiveRepairStatus,
    pub prior_recursive_root: String,
    pub repaired_da_root: String,
    pub repaired_bridge_root: String,
    pub repaired_shard_root: String,
    pub aggregation_transcript_root: String,
    pub proof_commitment: String,
    pub verifier_key_commitment: String,
    pub posted_at_height: u64,
    pub verified_at_height: Option<u64>,
}

impl RecursiveProofRepairRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "repair_root_id": self.repair_root_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "prior_recursive_root": self.prior_recursive_root,
            "repaired_da_root": self.repaired_da_root,
            "repaired_bridge_root": self.repaired_bridge_root,
            "repaired_shard_root": self.repaired_shard_root,
            "aggregation_transcript_root": self.aggregation_transcript_root,
            "proof_commitment": self.proof_commitment,
            "verifier_key_commitment": self.verifier_key_commitment,
            "posted_at_height": self.posted_at_height,
            "verified_at_height": self.verified_at_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("repair_root_id", &self.repair_root_id)?;
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("prior_recursive_root", &self.prior_recursive_root)?;
        require_non_empty("repaired_da_root", &self.repaired_da_root)?;
        require_non_empty("repaired_bridge_root", &self.repaired_bridge_root)?;
        require_non_empty("repaired_shard_root", &self.repaired_shard_root)?;
        require_non_empty(
            "aggregation_transcript_root",
            &self.aggregation_transcript_root,
        )?;
        require_non_empty("proof_commitment", &self.proof_commitment)?;
        require_non_empty("verifier_key_commitment", &self.verifier_key_commitment)?;
        if let Some(verified_at_height) = self.verified_at_height {
            if verified_at_height < self.posted_at_height {
                return Err(format!(
                    "recursive repair {} verified before posting",
                    self.repair_root_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryOracleEvent {
    pub event_id: String,
    pub subject_id: String,
    pub event_kind: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl RecoveryOracleEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "subject_id": self.subject_id,
            "event_kind": self.event_kind,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        require_non_empty("event_id", &self.event_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("event_kind", &self.event_kind)?;
        require_non_empty("payload_root", &self.payload_root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDaRecoveryOracleRoots {
    pub watcher_root: String,
    pub batch_root: String,
    pub shard_root: String,
    pub bridge_proof_root: String,
    pub attestation_root: String,
    pub bounty_root: String,
    pub retrieval_credit_root: String,
    pub challenge_root: String,
    pub recursive_repair_root: String,
    pub event_root: String,
}

impl PqDaRecoveryOracleRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_root": self.watcher_root,
            "batch_root": self.batch_root,
            "shard_root": self.shard_root,
            "bridge_proof_root": self.bridge_proof_root,
            "attestation_root": self.attestation_root,
            "bounty_root": self.bounty_root,
            "retrieval_credit_root": self.retrieval_credit_root,
            "challenge_root": self.challenge_root,
            "recursive_repair_root": self.recursive_repair_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_da_recovery_oracle_payload_root("PQ-DA-RECOVERY-ORACLE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDaRecoveryOracleCounters {
    pub watchers: usize,
    pub active_watchers: usize,
    pub batches: usize,
    pub live_batches: usize,
    pub shards: usize,
    pub usable_shards: usize,
    pub monero_bridge_proofs: usize,
    pub attestations: usize,
    pub quorum_attestations: usize,
    pub repair_bounties: usize,
    pub open_bounties: usize,
    pub retrieval_credits: usize,
    pub funded_retrieval_units: u64,
    pub spent_retrieval_units: u64,
    pub challenges: usize,
    pub open_challenges: usize,
    pub recursive_repair_roots: usize,
    pub verified_recursive_repairs: usize,
    pub events: usize,
}

impl PqDaRecoveryOracleCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "watchers": self.watchers,
            "active_watchers": self.active_watchers,
            "batches": self.batches,
            "live_batches": self.live_batches,
            "shards": self.shards,
            "usable_shards": self.usable_shards,
            "monero_bridge_proofs": self.monero_bridge_proofs,
            "attestations": self.attestations,
            "quorum_attestations": self.quorum_attestations,
            "repair_bounties": self.repair_bounties,
            "open_bounties": self.open_bounties,
            "retrieval_credits": self.retrieval_credits,
            "funded_retrieval_units": self.funded_retrieval_units,
            "spent_retrieval_units": self.spent_retrieval_units,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "recursive_repair_roots": self.recursive_repair_roots,
            "verified_recursive_repairs": self.verified_recursive_repairs,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDaRecoveryOracleState {
    pub height: u64,
    pub config: PqDaRecoveryOracleConfig,
    pub operator_id: String,
    pub watchers: BTreeMap<String, RecoveryWatcher>,
    pub batches: BTreeMap<String, PrivateBatchRecoveryRecord>,
    pub shards: BTreeMap<String, ErasureShardCommitment>,
    pub monero_bridge_proofs: BTreeMap<String, MoneroBridgeProofRecoveryRecord>,
    pub attestations: BTreeMap<String, WatcherAttestation>,
    pub repair_bounties: BTreeMap<String, RepairBounty>,
    pub retrieval_credits: BTreeMap<String, LowFeeRetrievalCredit>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub recursive_repair_roots: BTreeMap<String, RecursiveProofRepairRoot>,
    pub events: BTreeMap<String, RecoveryOracleEvent>,
}

impl PqDaRecoveryOracleState {
    pub fn devnet() -> PqDaRecoveryOracleResult<Self> {
        let config = PqDaRecoveryOracleConfig::devnet();
        let height = PQ_DA_RECOVERY_ORACLE_DEVNET_HEIGHT;
        let watcher_a = RecoveryWatcher {
            watcher_id: "pq-da-watchtower-alpha".to_string(),
            role: WatcherRole::Watchtower,
            status: WatcherStatus::Active,
            weight: 3,
            pq_identity_key_commitment: sample_id("WATCHER-KEY", "alpha"),
            retrieval_endpoint_commitment: sample_id("WATCHER-ENDPOINT", "alpha"),
            bond_asset_id: config.fee_asset_id.clone(),
            bond_amount: 5_000_000,
            joined_at_height: height - 256,
            last_attested_height: height - 1,
        };
        let watcher_b = RecoveryWatcher {
            watcher_id: "pq-da-archive-beta".to_string(),
            role: WatcherRole::ArchiveProvider,
            status: WatcherStatus::Active,
            weight: 2,
            pq_identity_key_commitment: sample_id("WATCHER-KEY", "beta"),
            retrieval_endpoint_commitment: sample_id("WATCHER-ENDPOINT", "beta"),
            bond_asset_id: config.fee_asset_id.clone(),
            bond_amount: 4_000_000,
            joined_at_height: height - 192,
            last_attested_height: height - 2,
        };
        let watcher_c = RecoveryWatcher {
            watcher_id: "monero-observer-gamma".to_string(),
            role: WatcherRole::MoneroObserver,
            status: WatcherStatus::Active,
            weight: 2,
            pq_identity_key_commitment: sample_id("WATCHER-KEY", "gamma"),
            retrieval_endpoint_commitment: sample_id("WATCHER-ENDPOINT", "gamma"),
            bond_asset_id: config.fee_asset_id.clone(),
            bond_amount: 4_500_000,
            joined_at_height: height - 160,
            last_attested_height: height - 1,
        };

        let batch_id = sample_id("BATCH", "private-monero-defi-0");
        let shard_ids = (0..config.total_shards())
            .map(|index| sample_id("SHARD", &format!("{batch_id}:{index}")))
            .collect::<Vec<_>>();
        let shard_leaves = shard_ids
            .iter()
            .enumerate()
            .map(|(index, shard_id)| {
                json!({
                    "shard_id": shard_id,
                    "index": index,
                    "commitment": sample_id("SHARD-COMMITMENT", shard_id),
                })
            })
            .collect::<Vec<_>>();
        let shard_commitment_root = merkle_root("PQ-DA-RECOVERY-DEVNET-SHARDS", &shard_leaves);
        let batch = PrivateBatchRecoveryRecord {
            batch_id: batch_id.clone(),
            lane: RecoveryLane::MoneroBridgeProof,
            status: BatchAvailabilityStatus::RepairRequested,
            sequencer_commitment: sample_id("SEQUENCER", "devnet"),
            private_batch_payload_hash: sample_id("PRIVATE-BATCH-PAYLOAD", &batch_id),
            encrypted_metadata_root: sample_id("ENCRYPTED-METADATA", &batch_id),
            shard_commitment_root: shard_commitment_root.clone(),
            original_shards: config.original_shards,
            parity_shards: config.parity_shards,
            required_repair_shards: 4,
            watcher_quorum_weight: 7,
            low_fee_lane_id: PQ_DA_RECOVERY_ORACLE_MONERO_LANE_ID.to_string(),
            posted_at_height: height - 12,
            challenge_deadline_height: height + config.challenge_window_blocks,
            repair_deadline_height: height
                + config.challenge_window_blocks
                + config.repair_ttl_blocks,
            recursive_repair_root_id: Some(sample_id("RECURSIVE-REPAIR", &batch_id)),
        };

        let mut shards = BTreeMap::new();
        for (index, shard_id) in shard_ids.iter().enumerate() {
            let role = if index < config.original_shards as usize {
                ShardRole::Original
            } else {
                ShardRole::Parity
            };
            let status = if index == 3 {
                ShardAvailabilityStatus::Missing
            } else if index == 9 {
                ShardAvailabilityStatus::Repaired
            } else {
                ShardAvailabilityStatus::Committed
            };
            shards.insert(
                shard_id.clone(),
                ErasureShardCommitment {
                    shard_id: shard_id.clone(),
                    batch_id: batch_id.clone(),
                    shard_index: index as u32,
                    role,
                    status,
                    size_bytes: config.shard_size_bytes,
                    shard_commitment: sample_id("SHARD-COMMITMENT", shard_id),
                    polynomial_commitment: sample_id("POLY-COMMITMENT", shard_id),
                    encrypted_payload_hash: sample_id("SHARD-CIPHERTEXT", shard_id),
                    repair_hint_commitment: sample_id("REPAIR-HINT", shard_id),
                    custody_watcher_ids: vec![
                        watcher_a.watcher_id.clone(),
                        watcher_b.watcher_id.clone(),
                    ],
                    posted_at_height: height - 12,
                },
            );
        }

        let bridge_proof_id = sample_id("MONERO-BRIDGE-PROOF", &batch_id);
        let bridge_proof = MoneroBridgeProofRecoveryRecord {
            bridge_proof_id: bridge_proof_id.clone(),
            batch_id: batch_id.clone(),
            monero_network: "monero-devnet".to_string(),
            txid_hash: sample_id("MONERO-TXID", "devnet-bridge-release-0"),
            output_set_root: sample_id("MONERO-OUTPUT-SET", "devnet-bridge-release-0"),
            view_tag_root: sample_id("MONERO-VIEW-TAG", "devnet-bridge-release-0"),
            reserve_event_root: sample_id("MONERO-RESERVE-EVENT", "devnet-bridge-release-0"),
            ring_member_commitment_root: sample_id("MONERO-RING", "devnet-bridge-release-0"),
            bridge_amount_piconero_commitment: sample_id(
                "MONERO-AMOUNT",
                "devnet-bridge-release-0",
            ),
            recipient_subaddress_commitment: sample_id(
                "MONERO-SUBADDRESS",
                "devnet-bridge-release-0",
            ),
            proof_payload_hash: sample_id("MONERO-BRIDGE-PAYLOAD", &bridge_proof_id),
            recovery_shard_root: shard_commitment_root,
            observed_at_height: height - 10,
            min_monero_confirmations: 12,
        };

        let attestation_a = WatcherAttestation {
            attestation_id: sample_id("ATTESTATION", "alpha-custody"),
            watcher_id: watcher_a.watcher_id.clone(),
            batch_id: batch_id.clone(),
            kind: AttestationKind::Custody,
            status: AttestationStatus::Accepted,
            shard_ids: shard_ids.iter().take(16).cloned().collect(),
            claimed_available_root: sample_id("AVAILABLE-ROOT", "alpha"),
            missing_shard_root: sample_id("MISSING-ROOT", "alpha-none"),
            repair_payload_root: sample_id("REPAIR-PAYLOAD", "alpha-empty"),
            latency_millis: 180,
            pq_signature_root: sample_id("PQ-SIGNATURE", "alpha-custody"),
            submitted_at_height: height - 8,
        };
        let attestation_b = WatcherAttestation {
            attestation_id: sample_id("ATTESTATION", "beta-repair"),
            watcher_id: watcher_b.watcher_id.clone(),
            batch_id: batch_id.clone(),
            kind: AttestationKind::Repair,
            status: AttestationStatus::Submitted,
            shard_ids: shard_ids.iter().skip(16).take(16).cloned().collect(),
            claimed_available_root: sample_id("AVAILABLE-ROOT", "beta"),
            missing_shard_root: sample_id("MISSING-ROOT", "beta-shard-3"),
            repair_payload_root: sample_id("REPAIR-PAYLOAD", "beta-shard-3"),
            latency_millis: 260,
            pq_signature_root: sample_id("PQ-SIGNATURE", "beta-repair"),
            submitted_at_height: height - 6,
        };
        let attestation_c = WatcherAttestation {
            attestation_id: sample_id("ATTESTATION", "gamma-monero"),
            watcher_id: watcher_c.watcher_id.clone(),
            batch_id: batch_id.clone(),
            kind: AttestationKind::MoneroBridgeObservation,
            status: AttestationStatus::Accepted,
            shard_ids: shard_ids.iter().take(8).cloned().collect(),
            claimed_available_root: sample_id("AVAILABLE-ROOT", "gamma"),
            missing_shard_root: sample_id("MISSING-ROOT", "gamma-none"),
            repair_payload_root: bridge_proof.proof_payload_hash.clone(),
            latency_millis: 440,
            pq_signature_root: sample_id("PQ-SIGNATURE", "gamma-monero"),
            submitted_at_height: height - 5,
        };

        let bounty = RepairBounty {
            bounty_id: sample_id("REPAIR-BOUNTY", &batch_id),
            batch_id: batch_id.clone(),
            lane: RecoveryLane::MoneroBridgeProof,
            status: BountyStatus::Open,
            payer_commitment: sample_id("BOUNTY-PAYER", "devnet-sponsor"),
            assigned_provider_id: Some(watcher_b.watcher_id.clone()),
            asset_id: config.fee_asset_id.clone(),
            bounty_amount: config.default_repair_bounty_units,
            min_repaired_shards: 4,
            repair_deadline_height: height + config.repair_ttl_blocks,
            verification_root: sample_id("BOUNTY-VERIFY", &batch_id),
            opened_at_height: height - 4,
        };
        let credit = LowFeeRetrievalCredit {
            credit_id: sample_id("RETRIEVAL-CREDIT", "devnet-wallet"),
            owner_commitment: sample_id("WALLET", "devnet-wallet"),
            lane_id: PQ_DA_RECOVERY_ORACLE_LOW_FEE_LANE_ID.to_string(),
            status: RetrievalCreditStatus::Funded,
            asset_id: config.fee_asset_id.clone(),
            funded_units: config.default_low_fee_credit_units,
            spent_units: 16,
            retrieval_fee_microunits: config.default_retrieval_fee_microunits,
            batch_allowlist_root: sample_id("ALLOWLIST", &batch_id),
            nullifier_root: sample_id("RETRIEVAL-NULLIFIER", "devnet-wallet"),
            opened_at_height: height - 20,
            expires_at_height: height + config.retention_blocks,
        };
        let challenge = ChallengeEvidence {
            challenge_id: sample_id("CHALLENGE", "missing-shard-3"),
            kind: ChallengeKind::MissingShard,
            status: ChallengeStatus::EvidenceSubmitted,
            challenger_commitment: sample_id("CHALLENGER", "wallet-devnet"),
            challenged_watcher_id: Some(watcher_a.watcher_id.clone()),
            batch_id: batch_id.clone(),
            shard_id: shard_ids.get(3).cloned(),
            evidence_payload_root: sample_id("CHALLENGE-EVIDENCE", "missing-shard-3"),
            transcript_root: sample_id("CHALLENGE-TRANSCRIPT", "missing-shard-3"),
            bond_asset_id: config.fee_asset_id.clone(),
            bond_amount: config.default_challenge_bond_units,
            opened_at_height: height - 3,
            response_deadline_height: height + config.challenge_window_blocks,
            resolved_at_height: None,
        };
        let repair_root_id = batch
            .recursive_repair_root_id
            .clone()
            .ok_or_else(|| "devnet batch missing recursive repair root".to_string())?;
        let recursive = RecursiveProofRepairRoot {
            repair_root_id,
            batch_id: batch_id.clone(),
            status: RecursiveRepairStatus::Posted,
            prior_recursive_root: sample_id("PRIOR-RECURSIVE", &batch_id),
            repaired_da_root: sample_id("REPAIRED-DA", &batch_id),
            repaired_bridge_root: bridge_proof.proof_payload_hash.clone(),
            repaired_shard_root: sample_id("REPAIRED-SHARDS", &batch_id),
            aggregation_transcript_root: sample_id("REPAIR-AGGREGATION", &batch_id),
            proof_commitment: sample_id("REPAIR-PROOF", &batch_id),
            verifier_key_commitment: sample_id("REPAIR-VK", "devnet"),
            posted_at_height: height - 1,
            verified_at_height: None,
        };
        let event = RecoveryOracleEvent {
            event_id: sample_id("EVENT", "repair-opened"),
            subject_id: batch_id.clone(),
            event_kind: "repair_bounty_opened".to_string(),
            payload_root: bounty.verification_root.clone(),
            emitted_at_height: height - 4,
        };

        let mut state = Self {
            height,
            config,
            operator_id: PQ_DA_RECOVERY_ORACLE_DEVNET_OPERATOR_ID.to_string(),
            watchers: BTreeMap::new(),
            batches: BTreeMap::new(),
            shards,
            monero_bridge_proofs: BTreeMap::new(),
            attestations: BTreeMap::new(),
            repair_bounties: BTreeMap::new(),
            retrieval_credits: BTreeMap::new(),
            challenges: BTreeMap::new(),
            recursive_repair_roots: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state
            .watchers
            .insert(watcher_a.watcher_id.clone(), watcher_a);
        state
            .watchers
            .insert(watcher_b.watcher_id.clone(), watcher_b);
        state
            .watchers
            .insert(watcher_c.watcher_id.clone(), watcher_c);
        state.batches.insert(batch.batch_id.clone(), batch);
        state
            .monero_bridge_proofs
            .insert(bridge_proof.bridge_proof_id.clone(), bridge_proof);
        state
            .attestations
            .insert(attestation_a.attestation_id.clone(), attestation_a);
        state
            .attestations
            .insert(attestation_b.attestation_id.clone(), attestation_b);
        state
            .attestations
            .insert(attestation_c.attestation_id.clone(), attestation_c);
        state
            .repair_bounties
            .insert(bounty.bounty_id.clone(), bounty);
        state
            .retrieval_credits
            .insert(credit.credit_id.clone(), credit);
        state
            .challenges
            .insert(challenge.challenge_id.clone(), challenge);
        state
            .recursive_repair_roots
            .insert(recursive.repair_root_id.clone(), recursive);
        state.events.insert(event.event_id.clone(), event);
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqDaRecoveryOracleResult<()> {
        if height < self.height {
            return Err("pq da recovery oracle height cannot move backwards".to_string());
        }
        self.height = height;
        self.validate()
    }

    pub fn roots(&self) -> PqDaRecoveryOracleRoots {
        PqDaRecoveryOracleRoots {
            watcher_root: map_root("PQ-DA-RECOVERY-WATCHERS", &self.watchers),
            batch_root: map_root("PQ-DA-RECOVERY-BATCHES", &self.batches),
            shard_root: map_root("PQ-DA-RECOVERY-SHARDS", &self.shards),
            bridge_proof_root: map_root(
                "PQ-DA-RECOVERY-MONERO-BRIDGE-PROOFS",
                &self.monero_bridge_proofs,
            ),
            attestation_root: map_root("PQ-DA-RECOVERY-ATTESTATIONS", &self.attestations),
            bounty_root: map_root("PQ-DA-RECOVERY-BOUNTIES", &self.repair_bounties),
            retrieval_credit_root: map_root("PQ-DA-RECOVERY-CREDITS", &self.retrieval_credits),
            challenge_root: map_root("PQ-DA-RECOVERY-CHALLENGES", &self.challenges),
            recursive_repair_root: map_root(
                "PQ-DA-RECOVERY-RECURSIVE-REPAIRS",
                &self.recursive_repair_roots,
            ),
            event_root: map_root("PQ-DA-RECOVERY-EVENTS", &self.events),
        }
    }

    pub fn counters(&self) -> PqDaRecoveryOracleCounters {
        PqDaRecoveryOracleCounters {
            watchers: self.watchers.len(),
            active_watchers: self
                .watchers
                .values()
                .filter(|watcher| watcher.status.can_attest())
                .count(),
            batches: self.batches.len(),
            live_batches: self
                .batches
                .values()
                .filter(|batch| batch.status.live())
                .count(),
            shards: self.shards.len(),
            usable_shards: self
                .shards
                .values()
                .filter(|shard| shard.status.usable())
                .count(),
            monero_bridge_proofs: self.monero_bridge_proofs.len(),
            attestations: self.attestations.len(),
            quorum_attestations: self
                .attestations
                .values()
                .filter(|attestation| attestation.status.counts_for_quorum())
                .count(),
            repair_bounties: self.repair_bounties.len(),
            open_bounties: self
                .repair_bounties
                .values()
                .filter(|bounty| {
                    matches!(bounty.status, BountyStatus::Open | BountyStatus::Assigned)
                })
                .count(),
            retrieval_credits: self.retrieval_credits.len(),
            funded_retrieval_units: self
                .retrieval_credits
                .values()
                .map(|credit| credit.funded_units)
                .sum(),
            spent_retrieval_units: self
                .retrieval_credits
                .values()
                .map(|credit| credit.spent_units)
                .sum(),
            challenges: self.challenges.len(),
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| {
                    matches!(
                        challenge.status,
                        ChallengeStatus::Open
                            | ChallengeStatus::EvidenceSubmitted
                            | ChallengeStatus::Accepted
                    )
                })
                .count(),
            recursive_repair_roots: self.recursive_repair_roots.len(),
            verified_recursive_repairs: self
                .recursive_repair_roots
                .values()
                .filter(|root| root.status == RecursiveRepairStatus::Verified)
                .count(),
            events: self.events.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "height": self.height,
            "operator_id": self.operator_id,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "root_commitment": self.roots().state_root(),
            "counters": self.counters().public_record(),
            "low_fee_lane_id": PQ_DA_RECOVERY_ORACLE_LOW_FEE_LANE_ID,
            "monero_lane_id": PQ_DA_RECOVERY_ORACLE_MONERO_LANE_ID,
            "private_batch_lane_id": PQ_DA_RECOVERY_ORACLE_PRIVATE_BATCH_LANE_ID,
        })
    }

    pub fn state_root(&self) -> String {
        pq_da_recovery_oracle_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqDaRecoveryOracleResult<()> {
        self.config.validate()?;
        require_non_empty("operator_id", &self.operator_id)?;
        enforce_limit(
            "watchers",
            self.watchers.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_WATCHERS,
        )?;
        enforce_limit(
            "batches",
            self.batches.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_BATCHES,
        )?;
        enforce_limit(
            "shards",
            self.shards.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_SHARDS,
        )?;
        enforce_limit(
            "attestations",
            self.attestations.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_ATTESTATIONS,
        )?;
        enforce_limit(
            "repair_bounties",
            self.repair_bounties.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_BOUNTIES,
        )?;
        enforce_limit(
            "retrieval_credits",
            self.retrieval_credits.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_RETRIEVAL_CREDITS,
        )?;
        enforce_limit(
            "challenges",
            self.challenges.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_CHALLENGES,
        )?;
        enforce_limit(
            "recursive_repair_roots",
            self.recursive_repair_roots.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_REPAIR_ROOTS,
        )?;
        enforce_limit(
            "events",
            self.events.len(),
            PQ_DA_RECOVERY_ORACLE_MAX_PUBLIC_EVENTS,
        )?;

        for (id, watcher) in &self.watchers {
            require_key_match("watcher", id, &watcher.watcher_id)?;
            watcher.validate()?;
        }
        let active_weight = self
            .watchers
            .values()
            .filter(|watcher| watcher.status.can_attest())
            .map(|watcher| watcher.weight)
            .sum::<u64>();
        if active_weight < self.config.min_watcher_weight {
            return Err("pq da recovery oracle active watcher weight below quorum".to_string());
        }
        for (id, shard) in &self.shards {
            require_key_match("shard", id, &shard.shard_id)?;
            shard.validate(&self.config)?;
            require_known_batch(&self.batches, &shard.batch_id)?;
            for watcher_id in &shard.custody_watcher_ids {
                require_known_watcher(&self.watchers, watcher_id)?;
            }
        }
        for (id, batch) in &self.batches {
            require_key_match("batch", id, &batch.batch_id)?;
            batch.validate(&self.config)?;
            let shard_count = self
                .shards
                .values()
                .filter(|shard| shard.batch_id == batch.batch_id)
                .count();
            if shard_count < batch.original_shards as usize {
                return Err(format!(
                    "batch {} has fewer committed shards than original shard count",
                    batch.batch_id
                ));
            }
            if let Some(root_id) = &batch.recursive_repair_root_id {
                if !self.recursive_repair_roots.contains_key(root_id) {
                    return Err(format!(
                        "batch {} references unknown recursive repair root {}",
                        batch.batch_id, root_id
                    ));
                }
            }
        }
        for (id, bridge_proof) in &self.monero_bridge_proofs {
            require_key_match("monero bridge proof", id, &bridge_proof.bridge_proof_id)?;
            bridge_proof.validate()?;
            require_known_batch(&self.batches, &bridge_proof.batch_id)?;
        }
        for (id, attestation) in &self.attestations {
            require_key_match("attestation", id, &attestation.attestation_id)?;
            attestation.validate()?;
            require_known_watcher(&self.watchers, &attestation.watcher_id)?;
            require_known_batch(&self.batches, &attestation.batch_id)?;
            for shard_id in &attestation.shard_ids {
                require_known_shard(&self.shards, shard_id)?;
            }
        }
        for (id, bounty) in &self.repair_bounties {
            require_key_match("repair bounty", id, &bounty.bounty_id)?;
            bounty.validate()?;
            require_known_batch(&self.batches, &bounty.batch_id)?;
            if let Some(provider_id) = &bounty.assigned_provider_id {
                require_known_watcher(&self.watchers, provider_id)?;
            }
        }
        for (id, credit) in &self.retrieval_credits {
            require_key_match("retrieval credit", id, &credit.credit_id)?;
            credit.validate()?;
        }
        for (id, challenge) in &self.challenges {
            require_key_match("challenge", id, &challenge.challenge_id)?;
            challenge.validate()?;
            require_known_batch(&self.batches, &challenge.batch_id)?;
            if let Some(watcher_id) = &challenge.challenged_watcher_id {
                require_known_watcher(&self.watchers, watcher_id)?;
            }
            if let Some(shard_id) = &challenge.shard_id {
                require_known_shard(&self.shards, shard_id)?;
            }
        }
        for (id, root) in &self.recursive_repair_roots {
            require_key_match("recursive repair root", id, &root.repair_root_id)?;
            root.validate()?;
            require_known_batch(&self.batches, &root.batch_id)?;
        }
        for (id, event) in &self.events {
            require_key_match("event", id, &event.event_id)?;
            event.validate()?;
        }
        Ok(())
    }
}

pub fn pq_da_recovery_oracle_state_root_from_record(record: &Value) -> String {
    pq_da_recovery_oracle_payload_root("PQ-DA-RECOVERY-ORACLE-STATE", record)
}

pub fn pq_da_recovery_oracle_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn pq_da_recovery_oracle_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn erasure_shard_commitment_id(batch_id: &str, shard_index: u32, role: ShardRole) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-ERASURE-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Int(shard_index as i128),
            HashPart::Str(role.as_str()),
        ],
        32,
    )
}

pub fn private_batch_recovery_id(
    lane: RecoveryLane,
    sequencer_commitment: &str,
    payload_hash: &str,
    posted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-PRIVATE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sequencer_commitment),
            HashPart::Str(payload_hash),
            HashPart::Int(posted_at_height as i128),
        ],
        32,
    )
}

pub fn monero_bridge_proof_recovery_id(
    batch_id: &str,
    txid_hash: &str,
    output_set_root: &str,
) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-MONERO-BRIDGE-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(txid_hash),
            HashPart::Str(output_set_root),
        ],
        32,
    )
}

pub fn watcher_attestation_id(
    watcher_id: &str,
    batch_id: &str,
    kind: AttestationKind,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-WATCHER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(batch_id),
            HashPart::Str(kind.as_str()),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn repair_bounty_id(batch_id: &str, payer_commitment: &str, opened_at_height: u64) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-REPAIR-BOUNTY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(payer_commitment),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_retrieval_credit_id(
    owner_commitment: &str,
    lane_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-LOW-FEE-RETRIEVAL-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn challenge_evidence_id(
    kind: ChallengeKind,
    batch_id: &str,
    challenger_commitment: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-CHALLENGE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(batch_id),
            HashPart::Str(challenger_commitment),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_proof_repair_root_id(
    batch_id: &str,
    prior_recursive_root: &str,
    repaired_da_root: &str,
) -> String {
    domain_hash(
        "PQ-DA-RECOVERY-RECURSIVE-PROOF-REPAIR-ROOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(prior_recursive_root),
            HashPart::Str(repaired_da_root),
        ],
        32,
    )
}

fn map_root<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for RecoveryWatcher {
    fn public_record(&self) -> Value {
        RecoveryWatcher::public_record(self)
    }
}

impl PublicRecord for PrivateBatchRecoveryRecord {
    fn public_record(&self) -> Value {
        PrivateBatchRecoveryRecord::public_record(self)
    }
}

impl PublicRecord for ErasureShardCommitment {
    fn public_record(&self) -> Value {
        ErasureShardCommitment::public_record(self)
    }
}

impl PublicRecord for MoneroBridgeProofRecoveryRecord {
    fn public_record(&self) -> Value {
        MoneroBridgeProofRecoveryRecord::public_record(self)
    }
}

impl PublicRecord for WatcherAttestation {
    fn public_record(&self) -> Value {
        WatcherAttestation::public_record(self)
    }
}

impl PublicRecord for RepairBounty {
    fn public_record(&self) -> Value {
        RepairBounty::public_record(self)
    }
}

impl PublicRecord for LowFeeRetrievalCredit {
    fn public_record(&self) -> Value {
        LowFeeRetrievalCredit::public_record(self)
    }
}

impl PublicRecord for ChallengeEvidence {
    fn public_record(&self) -> Value {
        ChallengeEvidence::public_record(self)
    }
}

impl PublicRecord for RecursiveProofRepairRoot {
    fn public_record(&self) -> Value {
        RecursiveProofRepairRoot::public_record(self)
    }
}

impl PublicRecord for RecoveryOracleEvent {
    fn public_record(&self) -> Value {
        RecoveryOracleEvent::public_record(self)
    }
}

fn require_non_empty(label: &str, value: &str) -> PqDaRecoveryOracleResult<()> {
    if value.trim().is_empty() {
        Err(format!("pq da recovery oracle {label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_unique(label: &str, values: &[String]) -> PqDaRecoveryOracleResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!(
                "pq da recovery oracle {label} contains duplicate {value}"
            ));
        }
    }
    Ok(())
}

fn require_key_match(kind: &str, key: &str, id: &str) -> PqDaRecoveryOracleResult<()> {
    if key != id {
        Err(format!(
            "pq da recovery oracle {kind} key {key} does not match id {id}"
        ))
    } else {
        Ok(())
    }
}

fn enforce_limit(label: &str, len: usize, limit: usize) -> PqDaRecoveryOracleResult<()> {
    if len > limit {
        Err(format!(
            "pq da recovery oracle {label} count {len} exceeds limit {limit}"
        ))
    } else {
        Ok(())
    }
}

fn require_known_watcher(
    watchers: &BTreeMap<String, RecoveryWatcher>,
    watcher_id: &str,
) -> PqDaRecoveryOracleResult<()> {
    if watchers.contains_key(watcher_id) {
        Ok(())
    } else {
        Err(format!(
            "pq da recovery oracle references unknown watcher {watcher_id}"
        ))
    }
}

fn require_known_batch(
    batches: &BTreeMap<String, PrivateBatchRecoveryRecord>,
    batch_id: &str,
) -> PqDaRecoveryOracleResult<()> {
    if batches.contains_key(batch_id) {
        Ok(())
    } else {
        Err(format!(
            "pq da recovery oracle references unknown batch {batch_id}"
        ))
    }
}

fn require_known_shard(
    shards: &BTreeMap<String, ErasureShardCommitment>,
    shard_id: &str,
) -> PqDaRecoveryOracleResult<()> {
    if shards.contains_key(shard_id) {
        Ok(())
    } else {
        Err(format!(
            "pq da recovery oracle references unknown shard {shard_id}"
        ))
    }
}

fn sample_id(domain: &str, seed: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(seed)], 32)
}
