use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialParallelWitnessAvailabilityRelayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_WITNESS_AVAILABILITY_RELAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-witness-availability-relay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_WITNESS_AVAILABILITY_RELAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 846_720;
pub const MONERO_NETWORK: &str = "monero-devnet";
pub const L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SCHEME: &str = "ML-DSA-87+SLH-DSA-SHAKE-192f-parallel-witness-lane-v1";
pub const WITNESS_CHUNK_SCHEME: &str = "roots-only-erasure-coded-private-witness-chunk-v1";
pub const PRECONFIRMATION_RECEIPT_SCHEME: &str =
    "pq-confidential-preconfirmation-availability-receipt-v1";
pub const QUORUM_HEALTH_SCHEME: &str = "parallel-relay-quorum-health-root-v1";
pub const FEE_REBATE_SCHEME: &str = "bandwidth-latency-low-fee-rebate-root-v1";
pub const REPAIR_WINDOW_SCHEME: &str = "erasure-repair-window-roots-only-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "roots-only-public-witness-availability-record-v1";
pub const DEFAULT_LANE_COUNT: u16 = 16;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 180;
pub const DEFAULT_TARGET_RELAY_LATENCY_MS: u64 = 420;
pub const DEFAULT_MAX_CHUNK_BYTES: u64 = 96 * 1024;
pub const DEFAULT_DATA_SHARDS: u16 = 16;
pub const DEFAULT_PARITY_SHARDS: u16 = 8;
pub const DEFAULT_REPAIR_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_QUORUM_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_RELAY_WEIGHT: u64 = 67;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_REBATE_POOL_MICRO_UNITS: u64 = 500_000_000;
pub const DEFAULT_LATENCY_REBATE_BPS: u64 = 3_000;
pub const DEFAULT_BANDWIDTH_REBATE_BPS: u64 = 2_500;
pub const DEFAULT_PRIVACY_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 6_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_LANES: usize = 256;
pub const MAX_CHUNK_COMMITMENTS: usize = 2_097_152;
pub const MAX_LANE_ATTESTATIONS: usize = 2_097_152;
pub const MAX_QUORUM_REPORTS: usize = 524_288;
pub const MAX_PRECONFIRMATION_RECEIPTS: usize = 1_048_576;
pub const MAX_FEE_REBATES: usize = 1_048_576;
pub const MAX_REPAIR_WINDOWS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 1_048_576;
pub const MAX_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneRole {
    Sequencer,
    Builder,
    DataRelay,
    RepairRelay,
    Watchtower,
    FeeSponsor,
}

impl LaneRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sequencer => "sequencer",
            Self::Builder => "builder",
            Self::DataRelay => "data_relay",
            Self::RepairRelay => "repair_relay",
            Self::Watchtower => "watchtower",
            Self::FeeSponsor => "fee_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Candidate,
    Active,
    Degraded,
    RepairOnly,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::RepairOnly => "repair_only",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::RepairOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkClass {
    ExecutionWitness,
    StateDiff,
    NullifierSet,
    RangeProofCache,
    DecoyTranscript,
    RepairParity,
}

impl ChunkClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionWitness => "execution_witness",
            Self::StateDiff => "state_diff",
            Self::NullifierSet => "nullifier_set",
            Self::RangeProofCache => "range_proof_cache",
            Self::DecoyTranscript => "decoy_transcript",
            Self::RepairParity => "repair_parity",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::ExecutionWitness => 100,
            Self::StateDiff => 90,
            Self::NullifierSet => 95,
            Self::RangeProofCache => 60,
            Self::DecoyTranscript => 85,
            Self::RepairParity => 70,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Committed,
    Relayed,
    QuorumAvailable,
    Preconfirmed,
    RepairNeeded,
    Repaired,
    Expired,
    Slashed,
}

impl ChunkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Relayed => "relayed",
            Self::QuorumAvailable => "quorum_available",
            Self::Preconfirmed => "preconfirmed",
            Self::RepairNeeded => "repair_needed",
            Self::Repaired => "repaired",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    LaneJoin,
    ChunkAvailable,
    ShardCustodied,
    Preconfirmation,
    RepairComplete,
    LatencySample,
    PrivacyFence,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LaneJoin => "lane_join",
            Self::ChunkAvailable => "chunk_available",
            Self::ShardCustodied => "shard_custodied",
            Self::Preconfirmation => "preconfirmation",
            Self::RepairComplete => "repair_complete",
            Self::LatencySample => "latency_sample",
            Self::PrivacyFence => "privacy_fence",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumStatus {
    Unknown,
    Healthy,
    Degraded,
    Repairing,
    Unsafe,
    Halted,
}

impl QuorumStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Repairing => "repairing",
            Self::Unsafe => "unsafe",
            Self::Halted => "halted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Open,
    QuorumSigned,
    Published,
    Repaired,
    Settled,
    Expired,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::QuorumSigned => "quorum_signed",
            Self::Published => "published",
            Self::Repaired => "repaired",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateKind {
    LowLatency,
    HighBandwidth,
    PrivacyPreserving,
    RepairContribution,
    SponsorSubsidy,
}

impl RebateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowLatency => "low_latency",
            Self::HighBandwidth => "high_bandwidth",
            Self::PrivacyPreserving => "privacy_preserving",
            Self::RepairContribution => "repair_contribution",
            Self::SponsorSubsidy => "sponsor_subsidy",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairStatus {
    Open,
    Sampling,
    Repairing,
    Recovered,
    Failed,
    Expired,
}

impl RepairStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sampling => "sampling",
            Self::Repairing => "repairing",
            Self::Recovered => "recovered",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub config_id: String,
    pub lane_count: u16,
    pub min_pq_security_bits: u16,
    pub target_preconfirmation_ms: u64,
    pub target_relay_latency_ms: u64,
    pub max_chunk_bytes: u64,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub repair_window_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub quorum_window_blocks: u64,
    pub min_relay_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub rebate_pool_micro_units: u64,
    pub latency_rebate_bps: u64,
    pub bandwidth_rebate_bps: u64,
    pub privacy_rebate_bps: u64,
    pub max_user_fee_micro_units: u64,
    pub min_privacy_set_size: u64,
    pub require_roots_only_publication: bool,
    pub require_pq_lane_attestations: bool,
    pub enable_parallel_preconfirmation: bool,
    pub enable_erasure_repair: bool,
    pub enable_low_fee_rebates: bool,
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            lane_count: DEFAULT_LANE_COUNT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            target_relay_latency_ms: DEFAULT_TARGET_RELAY_LATENCY_MS,
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
            repair_window_blocks: DEFAULT_REPAIR_WINDOW_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            quorum_window_blocks: DEFAULT_QUORUM_WINDOW_BLOCKS,
            min_relay_weight: DEFAULT_MIN_RELAY_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            rebate_pool_micro_units: DEFAULT_REBATE_POOL_MICRO_UNITS,
            latency_rebate_bps: DEFAULT_LATENCY_REBATE_BPS,
            bandwidth_rebate_bps: DEFAULT_BANDWIDTH_REBATE_BPS,
            privacy_rebate_bps: DEFAULT_PRIVACY_REBATE_BPS,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            require_roots_only_publication: true,
            require_pq_lane_attestations: true,
            enable_parallel_preconfirmation: true,
            enable_erasure_repair: true,
            enable_low_fee_rebates: true,
        };
        config.config_id = config_id(&config.identity_record());
        config
    }
}

impl Config {
    pub fn identity_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "monero_network": MONERO_NETWORK,
            "l2_network": L2_NETWORK,
            "hash_suite": HASH_SUITE,
            "pq_attestation_scheme": PQ_ATTESTATION_SCHEME,
            "witness_chunk_scheme": WITNESS_CHUNK_SCHEME,
            "preconfirmation_receipt_scheme": PRECONFIRMATION_RECEIPT_SCHEME,
            "quorum_health_scheme": QUORUM_HEALTH_SCHEME,
            "fee_rebate_scheme": FEE_REBATE_SCHEME,
            "repair_window_scheme": REPAIR_WINDOW_SCHEME,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "lane_count": self.lane_count,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "target_relay_latency_ms": self.target_relay_latency_ms,
            "max_chunk_bytes": self.max_chunk_bytes,
            "data_shards": self.data_shards,
            "parity_shards": self.parity_shards,
            "repair_window_blocks": self.repair_window_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "quorum_window_blocks": self.quorum_window_blocks,
            "min_relay_weight": self.min_relay_weight,
            "quorum_bps": self.quorum_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "latency_rebate_bps": self.latency_rebate_bps,
            "bandwidth_rebate_bps": self.bandwidth_rebate_bps,
            "privacy_rebate_bps": self.privacy_rebate_bps,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "min_privacy_set_size": self.min_privacy_set_size,
            "require_roots_only_publication": self.require_roots_only_publication,
            "require_pq_lane_attestations": self.require_pq_lane_attestations,
            "enable_parallel_preconfirmation": self.enable_parallel_preconfirmation,
            "enable_erasure_repair": self.enable_erasure_repair,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        if let Value::Object(fields) = &mut record {
            fields.insert(
                "config_id".to_string(),
                Value::String(self.config_id.clone()),
            );
        }
        record
    }

    pub fn validate(&self) -> Result<()> {
        if self.lane_count == 0 || usize::from(self.lane_count) > MAX_LANES {
            return Err("lane_count out of range".to_string());
        }
        if self.data_shards == 0 || self.parity_shards == 0 {
            return Err("erasure shard counts must be non-zero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits below runtime floor".to_string());
        }
        require_bps("quorum_bps", self.quorum_bps)?;
        require_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        require_bps("latency_rebate_bps", self.latency_rebate_bps)?;
        require_bps("bandwidth_rebate_bps", self.bandwidth_rebate_bps)?;
        require_bps("privacy_rebate_bps", self.privacy_rebate_bps)?;
        if self.strong_quorum_bps < self.quorum_bps {
            return Err("strong_quorum_bps must be at least quorum_bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lanes_registered: u64,
    pub lanes_active: u64,
    pub chunk_commitments: u64,
    pub chunk_bytes_committed: u64,
    pub lane_attestations: u64,
    pub quorum_reports: u64,
    pub preconfirmation_receipts: u64,
    pub fee_rebates: u64,
    pub rebate_micro_units_reserved: u64,
    pub rebate_micro_units_paid: u64,
    pub repair_windows: u64,
    pub repaired_chunks: u64,
    pub public_records: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes_registered": self.lanes_registered,
            "lanes_active": self.lanes_active,
            "chunk_commitments": self.chunk_commitments,
            "chunk_bytes_committed": self.chunk_bytes_committed,
            "lane_attestations": self.lane_attestations,
            "quorum_reports": self.quorum_reports,
            "preconfirmation_receipts": self.preconfirmation_receipts,
            "fee_rebates": self.fee_rebates,
            "rebate_micro_units_reserved": self.rebate_micro_units_reserved,
            "rebate_micro_units_paid": self.rebate_micro_units_paid,
            "repair_windows": self.repair_windows,
            "repaired_chunks": self.repaired_chunks,
            "public_records": self.public_records,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub state_root: String,
    pub config_root: String,
    pub lanes_root: String,
    pub chunk_commitments_root: String,
    pub lane_attestations_root: String,
    pub quorum_reports_root: String,
    pub preconfirmation_receipts_root: String,
    pub fee_rebates_root: String,
    pub repair_windows_root: String,
    pub public_records_root: String,
    pub counters_root: String,
    pub events_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "config_root": self.config_root,
            "lanes_root": self.lanes_root,
            "chunk_commitments_root": self.chunk_commitments_root,
            "lane_attestations_root": self.lane_attestations_root,
            "quorum_reports_root": self.quorum_reports_root,
            "preconfirmation_receipts_root": self.preconfirmation_receipts_root,
            "fee_rebates_root": self.fee_rebates_root,
            "repair_windows_root": self.repair_windows_root,
            "public_records_root": self.public_records_root,
            "counters_root": self.counters_root,
            "events_root": self.events_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRegistration {
    pub lane_id: String,
    pub role: LaneRole,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub stake_commitment_root: String,
    pub region_commitment: String,
    pub bandwidth_floor_bytes_per_sec: u64,
    pub target_latency_ms: u64,
    pub relay_weight: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub registered_at_height: u64,
    pub status: LaneStatus,
}

impl LaneRegistration {
    pub fn new(input: LaneRegistrationInput) -> Result<Self> {
        input.validate()?;
        let lane_id = lane_id(
            input.role,
            &input.operator_commitment,
            &input.pq_identity_root,
            input.registered_at_height,
        );
        Ok(Self {
            lane_id,
            role: input.role,
            operator_commitment: input.operator_commitment,
            pq_identity_root: input.pq_identity_root,
            stake_commitment_root: input.stake_commitment_root,
            region_commitment: input.region_commitment,
            bandwidth_floor_bytes_per_sec: input.bandwidth_floor_bytes_per_sec,
            target_latency_ms: input.target_latency_ms,
            relay_weight: input.relay_weight,
            pq_security_bits: input.pq_security_bits,
            privacy_set_size: input.privacy_set_size,
            registered_at_height: input.registered_at_height,
            status: LaneStatus::Candidate,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "role": self.role.as_str(),
            "operator_commitment": self.operator_commitment,
            "pq_identity_root": self.pq_identity_root,
            "stake_commitment_root": self.stake_commitment_root,
            "region_commitment": self.region_commitment,
            "bandwidth_floor_bytes_per_sec": self.bandwidth_floor_bytes_per_sec,
            "target_latency_ms": self.target_latency_ms,
            "relay_weight": self.relay_weight,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "registered_at_height": self.registered_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-WITNESS-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRegistrationInput {
    pub role: LaneRole,
    pub operator_commitment: String,
    pub pq_identity_root: String,
    pub stake_commitment_root: String,
    pub region_commitment: String,
    pub bandwidth_floor_bytes_per_sec: u64,
    pub target_latency_ms: u64,
    pub relay_weight: u64,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub registered_at_height: u64,
}

impl LaneRegistrationInput {
    pub fn validate(&self) -> Result<()> {
        require_root("operator_commitment", &self.operator_commitment)?;
        require_root("pq_identity_root", &self.pq_identity_root)?;
        require_root("stake_commitment_root", &self.stake_commitment_root)?;
        require_non_empty("region_commitment", &self.region_commitment)?;
        if self.bandwidth_floor_bytes_per_sec == 0 {
            return Err("bandwidth_floor_bytes_per_sec must be non-zero".to_string());
        }
        if self.target_latency_ms == 0 {
            return Err("target_latency_ms must be non-zero".to_string());
        }
        if self.relay_weight == 0 {
            return Err("relay_weight must be non-zero".to_string());
        }
        if self.pq_security_bits < 128 {
            return Err("pq_security_bits below runtime floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessChunkCommitment {
    pub chunk_id: String,
    pub execution_id: String,
    pub class: ChunkClass,
    pub lane_id: String,
    pub chunk_index: u32,
    pub shard_index: u16,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub chunk_bytes: u64,
    pub witness_root: String,
    pub erasure_root: String,
    pub encrypted_payload_root: String,
    pub privacy_fence_root: String,
    pub fee_commitment_root: String,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
    pub status: ChunkStatus,
}

impl WitnessChunkCommitment {
    pub fn new(input: WitnessChunkCommitmentInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let chunk_id = witness_chunk_id(
            &input.execution_id,
            input.class,
            &input.lane_id,
            input.chunk_index,
            input.shard_index,
            &input.witness_root,
            input.committed_at_height,
        );
        Ok(Self {
            chunk_id,
            execution_id: input.execution_id,
            class: input.class,
            lane_id: input.lane_id,
            chunk_index: input.chunk_index,
            shard_index: input.shard_index,
            data_shards: input.data_shards,
            parity_shards: input.parity_shards,
            chunk_bytes: input.chunk_bytes,
            witness_root: input.witness_root,
            erasure_root: input.erasure_root,
            encrypted_payload_root: input.encrypted_payload_root,
            privacy_fence_root: input.privacy_fence_root,
            fee_commitment_root: input.fee_commitment_root,
            committed_at_height: input.committed_at_height,
            expires_at_height: input.expires_at_height,
            status: ChunkStatus::Committed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chunk_id": self.chunk_id,
            "execution_id": self.execution_id,
            "class": self.class.as_str(),
            "lane_id": self.lane_id,
            "chunk_index": self.chunk_index,
            "shard_index": self.shard_index,
            "data_shards": self.data_shards,
            "parity_shards": self.parity_shards,
            "chunk_bytes": self.chunk_bytes,
            "witness_root": self.witness_root,
            "erasure_root": self.erasure_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "privacy_fence_root": self.privacy_fence_root,
            "fee_commitment_root": self.fee_commitment_root,
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-WITNESS-CHUNK-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessChunkCommitmentInput {
    pub execution_id: String,
    pub class: ChunkClass,
    pub lane_id: String,
    pub chunk_index: u32,
    pub shard_index: u16,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub chunk_bytes: u64,
    pub witness_root: String,
    pub erasure_root: String,
    pub encrypted_payload_root: String,
    pub privacy_fence_root: String,
    pub fee_commitment_root: String,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
}

impl WitnessChunkCommitmentInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("execution_id", &self.execution_id)?;
        require_root("lane_id", &self.lane_id)?;
        require_root("witness_root", &self.witness_root)?;
        require_root("erasure_root", &self.erasure_root)?;
        require_root("encrypted_payload_root", &self.encrypted_payload_root)?;
        require_root("privacy_fence_root", &self.privacy_fence_root)?;
        require_root("fee_commitment_root", &self.fee_commitment_root)?;
        if self.chunk_bytes == 0 || self.chunk_bytes > config.max_chunk_bytes {
            return Err("chunk_bytes out of range".to_string());
        }
        if self.data_shards == 0 || self.parity_shards == 0 {
            return Err("shard counts must be non-zero".to_string());
        }
        if self.shard_index >= self.data_shards + self.parity_shards {
            return Err("shard_index outside erasure set".to_string());
        }
        if self.expires_at_height <= self.committed_at_height {
            return Err("expires_at_height must be after committed_at_height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub lane_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub aggregate_weight: u64,
    pub latency_ms: u64,
    pub bandwidth_bytes_per_sec: u64,
    pub pq_security_bits: u16,
    pub signed_at_height: u64,
}

impl PqLaneAttestation {
    pub fn new(input: PqLaneAttestationInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let attestation_id = pq_lane_attestation_id(
            input.kind,
            &input.lane_id,
            &input.subject_id,
            &input.subject_root,
            input.signed_at_height,
        );
        Ok(Self {
            attestation_id,
            kind: input.kind,
            lane_id: input.lane_id,
            subject_id: input.subject_id,
            subject_root: input.subject_root,
            pq_signature_root: input.pq_signature_root,
            transcript_root: input.transcript_root,
            aggregate_weight: input.aggregate_weight,
            latency_ms: input.latency_ms,
            bandwidth_bytes_per_sec: input.bandwidth_bytes_per_sec,
            pq_security_bits: input.pq_security_bits,
            signed_at_height: input.signed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "aggregate_weight": self.aggregate_weight,
            "latency_ms": self.latency_ms,
            "bandwidth_bytes_per_sec": self.bandwidth_bytes_per_sec,
            "pq_security_bits": self.pq_security_bits,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-PQ-LANE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqLaneAttestationInput {
    pub kind: AttestationKind,
    pub lane_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub aggregate_weight: u64,
    pub latency_ms: u64,
    pub bandwidth_bytes_per_sec: u64,
    pub pq_security_bits: u16,
    pub signed_at_height: u64,
}

impl PqLaneAttestationInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("lane_id", &self.lane_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_root("subject_root", &self.subject_root)?;
        require_root("pq_signature_root", &self.pq_signature_root)?;
        require_root("transcript_root", &self.transcript_root)?;
        if self.aggregate_weight == 0 {
            return Err("aggregate_weight must be non-zero".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below configured floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayQuorumHealth {
    pub report_id: String,
    pub quorum_id: String,
    pub chunk_root: String,
    pub available_weight: u64,
    pub total_weight: u64,
    pub available_lanes: u16,
    pub degraded_lanes: u16,
    pub missing_shards: u16,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub aggregate_bandwidth_bytes_per_sec: u64,
    pub status: QuorumStatus,
    pub reported_at_height: u64,
}

impl RelayQuorumHealth {
    pub fn new(input: RelayQuorumHealthInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let status = quorum_status(
            input.available_weight,
            input.total_weight,
            input.missing_shards,
            input.p95_latency_ms,
            config,
        );
        let report_id = quorum_report_id(
            &input.quorum_id,
            &input.chunk_root,
            input.available_weight,
            input.reported_at_height,
        );
        Ok(Self {
            report_id,
            quorum_id: input.quorum_id,
            chunk_root: input.chunk_root,
            available_weight: input.available_weight,
            total_weight: input.total_weight,
            available_lanes: input.available_lanes,
            degraded_lanes: input.degraded_lanes,
            missing_shards: input.missing_shards,
            median_latency_ms: input.median_latency_ms,
            p95_latency_ms: input.p95_latency_ms,
            aggregate_bandwidth_bytes_per_sec: input.aggregate_bandwidth_bytes_per_sec,
            status,
            reported_at_height: input.reported_at_height,
        })
    }

    pub fn quorum_bps(&self) -> u64 {
        if self.total_weight == 0 {
            0
        } else {
            self.available_weight.saturating_mul(MAX_BPS) / self.total_weight
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "quorum_id": self.quorum_id,
            "chunk_root": self.chunk_root,
            "available_weight": self.available_weight,
            "total_weight": self.total_weight,
            "quorum_bps": self.quorum_bps(),
            "available_lanes": self.available_lanes,
            "degraded_lanes": self.degraded_lanes,
            "missing_shards": self.missing_shards,
            "median_latency_ms": self.median_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "aggregate_bandwidth_bytes_per_sec": self.aggregate_bandwidth_bytes_per_sec,
            "status": self.status.as_str(),
            "reported_at_height": self.reported_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-L2-RELAY-QUORUM-HEALTH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayQuorumHealthInput {
    pub quorum_id: String,
    pub chunk_root: String,
    pub available_weight: u64,
    pub total_weight: u64,
    pub available_lanes: u16,
    pub degraded_lanes: u16,
    pub missing_shards: u16,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub aggregate_bandwidth_bytes_per_sec: u64,
    pub reported_at_height: u64,
}

impl RelayQuorumHealthInput {
    pub fn validate(&self, _config: &Config) -> Result<()> {
        require_non_empty("quorum_id", &self.quorum_id)?;
        require_root("chunk_root", &self.chunk_root)?;
        if self.total_weight == 0 || self.available_weight > self.total_weight {
            return Err("invalid quorum weight".to_string());
        }
        if self.p95_latency_ms < self.median_latency_ms {
            return Err("p95_latency_ms must be at least median_latency_ms".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationAvailabilityReceipt {
    pub receipt_id: String,
    pub execution_id: String,
    pub chunk_root: String,
    pub quorum_report_id: String,
    pub receipt_root: String,
    pub lane_attestation_root: String,
    pub preconfirmed_weight: u64,
    pub latency_ms: u64,
    pub fee_micro_units: u64,
    pub expires_at_height: u64,
    pub issued_at_height: u64,
    pub status: ReceiptStatus,
}

impl PreconfirmationAvailabilityReceipt {
    pub fn new(input: PreconfirmationAvailabilityReceiptInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let receipt_id = preconfirmation_receipt_id(
            &input.execution_id,
            &input.chunk_root,
            &input.quorum_report_id,
            input.issued_at_height,
        );
        let receipt_root = payload_root(
            "PRIVATE-L2-PRECONFIRMATION-AVAILABILITY-RECEIPT-DRAFT",
            &json!({
                "receipt_id": receipt_id,
                "execution_id": input.execution_id,
                "chunk_root": input.chunk_root,
                "quorum_report_id": input.quorum_report_id,
                "lane_attestation_root": input.lane_attestation_root,
                "preconfirmed_weight": input.preconfirmed_weight,
                "latency_ms": input.latency_ms,
                "fee_micro_units": input.fee_micro_units,
                "expires_at_height": input.expires_at_height,
                "issued_at_height": input.issued_at_height,
            }),
        );
        Ok(Self {
            receipt_id,
            execution_id: input.execution_id,
            chunk_root: input.chunk_root,
            quorum_report_id: input.quorum_report_id,
            receipt_root,
            lane_attestation_root: input.lane_attestation_root,
            preconfirmed_weight: input.preconfirmed_weight,
            latency_ms: input.latency_ms,
            fee_micro_units: input.fee_micro_units,
            expires_at_height: input.expires_at_height,
            issued_at_height: input.issued_at_height,
            status: ReceiptStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "execution_id": self.execution_id,
            "chunk_root": self.chunk_root,
            "quorum_report_id": self.quorum_report_id,
            "receipt_root": self.receipt_root,
            "lane_attestation_root": self.lane_attestation_root,
            "preconfirmed_weight": self.preconfirmed_weight,
            "latency_ms": self.latency_ms,
            "fee_micro_units": self.fee_micro_units,
            "expires_at_height": self.expires_at_height,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreconfirmationAvailabilityReceiptInput {
    pub execution_id: String,
    pub chunk_root: String,
    pub quorum_report_id: String,
    pub lane_attestation_root: String,
    pub preconfirmed_weight: u64,
    pub latency_ms: u64,
    pub fee_micro_units: u64,
    pub expires_at_height: u64,
    pub issued_at_height: u64,
}

impl PreconfirmationAvailabilityReceiptInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("execution_id", &self.execution_id)?;
        require_root("chunk_root", &self.chunk_root)?;
        require_root("quorum_report_id", &self.quorum_report_id)?;
        require_root("lane_attestation_root", &self.lane_attestation_root)?;
        if self.preconfirmed_weight < config.min_relay_weight {
            return Err("preconfirmed_weight below configured minimum".to_string());
        }
        if self.fee_micro_units > config.max_user_fee_micro_units {
            return Err("fee_micro_units exceeds configured low-fee ceiling".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("expires_at_height must be after issued_at_height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthLatencyFeeRebate {
    pub rebate_id: String,
    pub kind: RebateKind,
    pub receipt_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub baseline_fee_micro_units: u64,
    pub paid_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub latency_ms: u64,
    pub bandwidth_bytes_per_sec: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub settled: bool,
}

impl BandwidthLatencyFeeRebate {
    pub fn new(input: BandwidthLatencyFeeRebateInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let rebate_micro_units = compute_rebate_micro_units(
            input.kind,
            input.baseline_fee_micro_units,
            input.paid_fee_micro_units,
            input.latency_ms,
            input.bandwidth_bytes_per_sec,
            input.privacy_set_size,
            config,
        );
        let rebate_id = fee_rebate_id(
            input.kind,
            &input.receipt_id,
            &input.lane_id,
            &input.account_commitment,
            input.issued_at_height,
        );
        Ok(Self {
            rebate_id,
            kind: input.kind,
            receipt_id: input.receipt_id,
            lane_id: input.lane_id,
            account_commitment: input.account_commitment,
            baseline_fee_micro_units: input.baseline_fee_micro_units,
            paid_fee_micro_units: input.paid_fee_micro_units,
            rebate_micro_units,
            latency_ms: input.latency_ms,
            bandwidth_bytes_per_sec: input.bandwidth_bytes_per_sec,
            privacy_set_size: input.privacy_set_size,
            issued_at_height: input.issued_at_height,
            settled: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "kind": self.kind.as_str(),
            "receipt_id": self.receipt_id,
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "baseline_fee_micro_units": self.baseline_fee_micro_units,
            "paid_fee_micro_units": self.paid_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "latency_ms": self.latency_ms,
            "bandwidth_bytes_per_sec": self.bandwidth_bytes_per_sec,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "settled": self.settled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthLatencyFeeRebateInput {
    pub kind: RebateKind,
    pub receipt_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub baseline_fee_micro_units: u64,
    pub paid_fee_micro_units: u64,
    pub latency_ms: u64,
    pub bandwidth_bytes_per_sec: u64,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
}

impl BandwidthLatencyFeeRebateInput {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("receipt_id", &self.receipt_id)?;
        require_root("lane_id", &self.lane_id)?;
        require_root("account_commitment", &self.account_commitment)?;
        if self.paid_fee_micro_units > self.baseline_fee_micro_units {
            return Err("paid_fee_micro_units exceeds baseline_fee_micro_units".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy_set_size below configured minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureRepairWindow {
    pub repair_id: String,
    pub execution_id: String,
    pub chunk_root: String,
    pub missing_shard_root: String,
    pub repair_lane_root: String,
    pub recovered_chunk_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub repaired_at_height: Option<u64>,
    pub status: RepairStatus,
}

impl ErasureRepairWindow {
    pub fn new(input: ErasureRepairWindowInput, config: &Config) -> Result<Self> {
        input.validate(config)?;
        let repair_id = repair_window_id(
            &input.execution_id,
            &input.chunk_root,
            &input.missing_shard_root,
            input.opened_at_height,
        );
        Ok(Self {
            repair_id,
            execution_id: input.execution_id,
            chunk_root: input.chunk_root,
            missing_shard_root: input.missing_shard_root,
            repair_lane_root: input.repair_lane_root,
            recovered_chunk_root: input.recovered_chunk_root,
            opened_at_height: input.opened_at_height,
            closes_at_height: input.closes_at_height,
            repaired_at_height: None,
            status: RepairStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "repair_id": self.repair_id,
            "execution_id": self.execution_id,
            "chunk_root": self.chunk_root,
            "missing_shard_root": self.missing_shard_root,
            "repair_lane_root": self.repair_lane_root,
            "recovered_chunk_root": self.recovered_chunk_root,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "repaired_at_height": self.repaired_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureRepairWindowInput {
    pub execution_id: String,
    pub chunk_root: String,
    pub missing_shard_root: String,
    pub repair_lane_root: String,
    pub recovered_chunk_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl ErasureRepairWindowInput {
    pub fn validate(&self, _config: &Config) -> Result<()> {
        require_non_empty("execution_id", &self.execution_id)?;
        require_root("chunk_root", &self.chunk_root)?;
        require_root("missing_shard_root", &self.missing_shard_root)?;
        require_root("repair_lane_root", &self.repair_lane_root)?;
        require_root("recovered_chunk_root", &self.recovered_chunk_root)?;
        if self.closes_at_height <= self.opened_at_height {
            return Err("closes_at_height must be after opened_at_height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub subject_root: String,
    pub state_root: String,
    pub published_at_height: u64,
    pub roots_only: bool,
}

impl PublicRecord {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        state_root: &str,
        height: u64,
    ) -> Result<Self> {
        require_non_empty("subject_kind", subject_kind)?;
        require_non_empty("subject_id", subject_id)?;
        require_root("subject_root", subject_root)?;
        require_root("state_root", state_root)?;
        let record_id = public_record_id(subject_kind, subject_id, subject_root, height);
        Ok(Self {
            record_id,
            subject_id: subject_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_root: subject_root.to_string(),
            state_root: state_root.to_string(),
            published_at_height: height,
            roots_only: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "subject_root": self.subject_root,
            "state_root": self.state_root,
            "published_at_height": self.published_at_height,
            "roots_only": self.roots_only,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
        sequence: u64,
    ) -> Self {
        Self {
            event_id: runtime_event_id(event_kind, subject_id, subject_root, height, sequence),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            height,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub lanes: BTreeMap<String, LaneRegistration>,
    pub chunk_commitments: BTreeMap<String, WitnessChunkCommitment>,
    pub lane_attestations: BTreeMap<String, PqLaneAttestation>,
    pub quorum_reports: BTreeMap<String, RelayQuorumHealth>,
    pub preconfirmation_receipts: BTreeMap<String, PreconfirmationAvailabilityReceipt>,
    pub fee_rebates: BTreeMap<String, BandwidthLatencyFeeRebate>,
    pub repair_windows: BTreeMap<String, ErasureRepairWindow>,
    pub public_records: BTreeMap<String, PublicRecord>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            lanes: BTreeMap::new(),
            chunk_commitments: BTreeMap::new(),
            lane_attestations: BTreeMap::new(),
            quorum_reports: BTreeMap::new(),
            preconfirmation_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            repair_windows: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
            counters: Counters::default(),
        }
    }

    pub fn register_lane(&mut self, input: LaneRegistrationInput) -> Result<String> {
        self.config.validate()?;
        require_capacity("lanes", self.lanes.len(), MAX_LANES)?;
        let mut lane = LaneRegistration::new(input)?;
        if lane.pq_security_bits < self.config.min_pq_security_bits {
            return Err("lane pq_security_bits below configured floor".to_string());
        }
        if lane.privacy_set_size < self.config.min_privacy_set_size {
            return Err("lane privacy_set_size below configured minimum".to_string());
        }
        lane.status = LaneStatus::Active;
        let lane_id = lane.lane_id.clone();
        let lane_root = lane.root();
        self.lanes.insert(lane_id.clone(), lane);
        self.counters.lanes_registered = self.counters.lanes_registered.saturating_add(1);
        self.counters.lanes_active = self
            .lanes
            .values()
            .filter(|lane| lane.status.live())
            .count() as u64;
        self.push_event("lane_registered", &lane_id, &lane_root, DEVNET_HEIGHT)?;
        Ok(lane_id)
    }

    pub fn commit_witness_chunk(&mut self, input: WitnessChunkCommitmentInput) -> Result<String> {
        require_capacity(
            "chunk_commitments",
            self.chunk_commitments.len(),
            MAX_CHUNK_COMMITMENTS,
        )?;
        self.require_lane(&input.lane_id)?;
        let chunk = WitnessChunkCommitment::new(input, &self.config)?;
        let chunk_id = chunk.chunk_id.clone();
        let chunk_root = chunk.root();
        self.counters.chunk_commitments = self.counters.chunk_commitments.saturating_add(1);
        self.counters.chunk_bytes_committed = self
            .counters
            .chunk_bytes_committed
            .saturating_add(chunk.chunk_bytes);
        self.chunk_commitments.insert(chunk_id.clone(), chunk);
        self.push_event(
            "witness_chunk_committed",
            &chunk_id,
            &chunk_root,
            DEVNET_HEIGHT,
        )?;
        Ok(chunk_id)
    }

    pub fn attest_lane(&mut self, input: PqLaneAttestationInput) -> Result<String> {
        require_capacity(
            "lane_attestations",
            self.lane_attestations.len(),
            MAX_LANE_ATTESTATIONS,
        )?;
        self.require_lane(&input.lane_id)?;
        let attestation = PqLaneAttestation::new(input, &self.config)?;
        let attestation_id = attestation.attestation_id.clone();
        let attestation_root = attestation.root();
        self.lane_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.lane_attestations = self.counters.lane_attestations.saturating_add(1);
        self.push_event(
            "pq_lane_attested",
            &attestation_id,
            &attestation_root,
            DEVNET_HEIGHT,
        )?;
        Ok(attestation_id)
    }

    pub fn report_quorum_health(&mut self, input: RelayQuorumHealthInput) -> Result<String> {
        require_capacity(
            "quorum_reports",
            self.quorum_reports.len(),
            MAX_QUORUM_REPORTS,
        )?;
        let report = RelayQuorumHealth::new(input, &self.config)?;
        let report_id = report.report_id.clone();
        let report_root = report.root();
        self.quorum_reports.insert(report_id.clone(), report);
        self.counters.quorum_reports = self.counters.quorum_reports.saturating_add(1);
        self.push_event(
            "quorum_health_reported",
            &report_id,
            &report_root,
            DEVNET_HEIGHT,
        )?;
        Ok(report_id)
    }

    pub fn issue_preconfirmation_receipt(
        &mut self,
        input: PreconfirmationAvailabilityReceiptInput,
    ) -> Result<String> {
        require_capacity(
            "preconfirmation_receipts",
            self.preconfirmation_receipts.len(),
            MAX_PRECONFIRMATION_RECEIPTS,
        )?;
        self.require_quorum_report(&input.quorum_report_id)?;
        let receipt = PreconfirmationAvailabilityReceipt::new(input, &self.config)?;
        let receipt_id = receipt.receipt_id.clone();
        let receipt_root = receipt.receipt_root.clone();
        self.preconfirmation_receipts
            .insert(receipt_id.clone(), receipt);
        self.counters.preconfirmation_receipts =
            self.counters.preconfirmation_receipts.saturating_add(1);
        self.push_event(
            "preconfirmation_receipt_issued",
            &receipt_id,
            &receipt_root,
            DEVNET_HEIGHT,
        )?;
        Ok(receipt_id)
    }

    pub fn reserve_fee_rebate(&mut self, input: BandwidthLatencyFeeRebateInput) -> Result<String> {
        require_capacity("fee_rebates", self.fee_rebates.len(), MAX_FEE_REBATES)?;
        self.require_lane(&input.lane_id)?;
        self.require_receipt(&input.receipt_id)?;
        let rebate = BandwidthLatencyFeeRebate::new(input, &self.config)?;
        if self
            .counters
            .rebate_micro_units_reserved
            .saturating_add(rebate.rebate_micro_units)
            > self.config.rebate_pool_micro_units
        {
            return Err("rebate pool exhausted".to_string());
        }
        let rebate_id = rebate.rebate_id.clone();
        let rebate_root = payload_root("PRIVATE-L2-FEE-REBATE", &rebate.public_record());
        self.counters.rebate_micro_units_reserved = self
            .counters
            .rebate_micro_units_reserved
            .saturating_add(rebate.rebate_micro_units);
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        self.counters.fee_rebates = self.counters.fee_rebates.saturating_add(1);
        self.push_event(
            "fee_rebate_reserved",
            &rebate_id,
            &rebate_root,
            DEVNET_HEIGHT,
        )?;
        Ok(rebate_id)
    }

    pub fn settle_fee_rebate(&mut self, rebate_id: &str) -> Result<String> {
        let (rebate_root, paid) = {
            let rebate = self
                .fee_rebates
                .get_mut(rebate_id)
                .ok_or_else(|| "unknown fee rebate".to_string())?;
            if rebate.settled {
                return Err("fee rebate already settled".to_string());
            }
            rebate.settled = true;
            (
                payload_root("PRIVATE-L2-FEE-REBATE-SETTLED", &rebate.public_record()),
                rebate.rebate_micro_units,
            )
        };
        self.counters.rebate_micro_units_paid =
            self.counters.rebate_micro_units_paid.saturating_add(paid);
        self.push_event("fee_rebate_settled", rebate_id, &rebate_root, DEVNET_HEIGHT)?;
        Ok(rebate_root)
    }

    pub fn open_repair_window(&mut self, input: ErasureRepairWindowInput) -> Result<String> {
        require_capacity(
            "repair_windows",
            self.repair_windows.len(),
            MAX_REPAIR_WINDOWS,
        )?;
        let repair = ErasureRepairWindow::new(input, &self.config)?;
        let repair_id = repair.repair_id.clone();
        let repair_root = payload_root("PRIVATE-L2-ERASURE-REPAIR-WINDOW", &repair.public_record());
        self.repair_windows.insert(repair_id.clone(), repair);
        self.counters.repair_windows = self.counters.repair_windows.saturating_add(1);
        self.push_event(
            "repair_window_opened",
            &repair_id,
            &repair_root,
            DEVNET_HEIGHT,
        )?;
        Ok(repair_id)
    }

    pub fn mark_repair_recovered(
        &mut self,
        repair_id: &str,
        repaired_at_height: u64,
    ) -> Result<String> {
        let repair_root = {
            let repair = self
                .repair_windows
                .get_mut(repair_id)
                .ok_or_else(|| "unknown repair window".to_string())?;
            if repaired_at_height > repair.closes_at_height {
                return Err("repair completed after window close".to_string());
            }
            repair.status = RepairStatus::Recovered;
            repair.repaired_at_height = Some(repaired_at_height);
            payload_root(
                "PRIVATE-L2-ERASURE-REPAIR-RECOVERED",
                &repair.public_record(),
            )
        };
        self.counters.repaired_chunks = self.counters.repaired_chunks.saturating_add(1);
        self.push_event(
            "repair_window_recovered",
            repair_id,
            &repair_root,
            repaired_at_height,
        )?;
        Ok(repair_root)
    }

    pub fn publish_public_record(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
    ) -> Result<String> {
        require_capacity(
            "public_records",
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
        )?;
        let state_root = self.state_root();
        let record =
            PublicRecord::new(subject_kind, subject_id, subject_root, &state_root, height)?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        self.counters.public_records = self.counters.public_records.saturating_add(1);
        Ok(record_id)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            state_root: String::new(),
            config_root: payload_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-CONFIG",
                &self.config.public_record(),
            ),
            lanes_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-LANES",
                self.lanes
                    .values()
                    .map(|lane| lane.public_record())
                    .collect(),
            ),
            chunk_commitments_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-CHUNKS",
                self.chunk_commitments
                    .values()
                    .map(|chunk| chunk.public_record())
                    .collect(),
            ),
            lane_attestations_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-ATTESTATIONS",
                self.lane_attestations
                    .values()
                    .map(|attestation| attestation.public_record())
                    .collect(),
            ),
            quorum_reports_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-QUORUM-REPORTS",
                self.quorum_reports
                    .values()
                    .map(|report| report.public_record())
                    .collect(),
            ),
            preconfirmation_receipts_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-PRECONFIRMATION-RECEIPTS",
                self.preconfirmation_receipts
                    .values()
                    .map(|receipt| receipt.public_record())
                    .collect(),
            ),
            fee_rebates_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-FEE-REBATES",
                self.fee_rebates
                    .values()
                    .map(|rebate| rebate.public_record())
                    .collect(),
            ),
            repair_windows_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-REPAIR-WINDOWS",
                self.repair_windows
                    .values()
                    .map(|repair| repair.public_record())
                    .collect(),
            ),
            public_records_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-PUBLIC-RECORDS",
                self.public_records
                    .values()
                    .map(|record| record.public_record())
                    .collect(),
            ),
            counters_root: payload_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-COUNTERS",
                &self.counters.public_record(),
            ),
            events_root: collection_root(
                "PRIVATE-L2-WITNESS-AVAILABILITY-EVENTS",
                self.events
                    .values()
                    .map(|event| event.public_record())
                    .collect(),
            ),
        };
        roots.state_root = state_root_from_record(&self.public_record_without_state_root(&roots));
        roots
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        roots.state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root(&roots);
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    pub fn public_record_without_state_root(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "monero_network": MONERO_NETWORK,
            "l2_network": L2_NETWORK,
            "roots_only": true,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    fn require_lane(&self, lane_id: &str) -> Result<()> {
        match self.lanes.get(lane_id) {
            Some(lane) if lane.status.live() => Ok(()),
            Some(_) => Err("lane is not live".to_string()),
            None => Err("unknown lane".to_string()),
        }
    }

    fn require_quorum_report(&self, report_id: &str) -> Result<()> {
        if self.quorum_reports.contains_key(report_id) {
            Ok(())
        } else {
            Err("unknown quorum report".to_string())
        }
    }

    fn require_receipt(&self, receipt_id: &str) -> Result<()> {
        if self.preconfirmation_receipts.contains_key(receipt_id) {
            Ok(())
        } else {
            Err("unknown preconfirmation receipt".to_string())
        }
    }

    fn push_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
    ) -> Result<()> {
        require_capacity("events", self.events.len(), MAX_EVENTS)?;
        let sequence = self.counters.events.saturating_add(1);
        let event = RuntimeEvent::new(event_kind, subject_id, subject_root, height, sequence);
        self.events.insert(event.event_id.clone(), event);
        self.counters.events = sequence;
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let config = state.config.clone();
    for index in 0..config.lane_count {
        let role = match index % 6 {
            0 => LaneRole::Sequencer,
            1 => LaneRole::Builder,
            2 => LaneRole::DataRelay,
            3 => LaneRole::RepairRelay,
            4 => LaneRole::Watchtower,
            _ => LaneRole::FeeSponsor,
        };
        let operator = commitment(&format!("devnet-lane-operator-{index}"));
        let pq_identity = commitment(&format!("devnet-lane-pq-identity-{index}"));
        let stake = commitment(&format!("devnet-lane-stake-{index}"));
        let lane_id = state
            .register_lane(LaneRegistrationInput {
                role,
                operator_commitment: operator,
                pq_identity_root: pq_identity,
                stake_commitment_root: stake,
                region_commitment: format!("region-{}", index % 4),
                bandwidth_floor_bytes_per_sec: 25_000_000 + u64::from(index) * 1_000_000,
                target_latency_ms: DEFAULT_TARGET_RELAY_LATENCY_MS,
                relay_weight: 10,
                pq_security_bits: 256,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE + 1_024,
                registered_at_height: DEVNET_HEIGHT,
            })
            .expect("devnet lane registration");
        let subject_root = commitment(&format!("devnet-lane-attestation-subject-{index}"));
        state
            .attest_lane(PqLaneAttestationInput {
                kind: AttestationKind::LaneJoin,
                lane_id,
                subject_id: format!("devnet-lane-join-{index}"),
                subject_root,
                pq_signature_root: commitment(&format!("devnet-lane-signature-{index}")),
                transcript_root: commitment(&format!("devnet-lane-transcript-{index}")),
                aggregate_weight: 10,
                latency_ms: DEFAULT_TARGET_RELAY_LATENCY_MS,
                bandwidth_bytes_per_sec: 25_000_000 + u64::from(index) * 1_000_000,
                pq_security_bits: 256,
                signed_at_height: DEVNET_HEIGHT + 1,
            })
            .expect("devnet lane attestation");
    }

    let lane_ids: Vec<String> = state.lanes.keys().cloned().collect();
    for chunk_index in 0..12_u32 {
        let lane_id = lane_ids[chunk_index as usize % lane_ids.len()].clone();
        let chunk_id = state
            .commit_witness_chunk(WitnessChunkCommitmentInput {
                execution_id: "devnet-private-fast-execution-0".to_string(),
                class: match chunk_index % 5 {
                    0 => ChunkClass::ExecutionWitness,
                    1 => ChunkClass::StateDiff,
                    2 => ChunkClass::NullifierSet,
                    3 => ChunkClass::RangeProofCache,
                    _ => ChunkClass::DecoyTranscript,
                },
                lane_id: lane_id.clone(),
                chunk_index,
                shard_index: chunk_index as u16,
                data_shards: DEFAULT_DATA_SHARDS,
                parity_shards: DEFAULT_PARITY_SHARDS,
                chunk_bytes: 64 * 1024,
                witness_root: commitment(&format!("devnet-witness-root-{chunk_index}")),
                erasure_root: commitment(&format!("devnet-erasure-root-{chunk_index}")),
                encrypted_payload_root: commitment(&format!(
                    "devnet-encrypted-payload-{chunk_index}"
                )),
                privacy_fence_root: commitment(&format!("devnet-privacy-fence-{chunk_index}")),
                fee_commitment_root: commitment(&format!("devnet-fee-commitment-{chunk_index}")),
                committed_at_height: DEVNET_HEIGHT + 2,
                expires_at_height: DEVNET_HEIGHT + 2 + DEFAULT_RECEIPT_TTL_BLOCKS,
            })
            .expect("devnet chunk commitment");
        let chunk_root = state
            .chunk_commitments
            .get(&chunk_id)
            .expect("chunk")
            .root();
        let report_id = state
            .report_quorum_health(RelayQuorumHealthInput {
                quorum_id: "devnet-witness-quorum-0".to_string(),
                chunk_root: chunk_root.clone(),
                available_weight: 120,
                total_weight: 160,
                available_lanes: 12,
                degraded_lanes: 1,
                missing_shards: 0,
                median_latency_ms: 150,
                p95_latency_ms: 260,
                aggregate_bandwidth_bytes_per_sec: 420_000_000,
                reported_at_height: DEVNET_HEIGHT + 3,
            })
            .expect("devnet quorum health");
        let attestation_root = collection_root(
            "PRIVATE-L2-DEVNET-LANE-ATTESTATION-ROOT",
            state
                .lane_attestations
                .values()
                .take(8)
                .map(|attestation| attestation.public_record())
                .collect(),
        );
        let receipt_id = state
            .issue_preconfirmation_receipt(PreconfirmationAvailabilityReceiptInput {
                execution_id: "devnet-private-fast-execution-0".to_string(),
                chunk_root: chunk_root.clone(),
                quorum_report_id: report_id,
                lane_attestation_root: attestation_root,
                preconfirmed_weight: 120,
                latency_ms: 175,
                fee_micro_units: 2_000,
                expires_at_height: DEVNET_HEIGHT + 40,
                issued_at_height: DEVNET_HEIGHT + 4,
            })
            .expect("devnet preconfirmation receipt");
        state
            .reserve_fee_rebate(BandwidthLatencyFeeRebateInput {
                kind: RebateKind::LowLatency,
                receipt_id,
                lane_id,
                account_commitment: commitment(&format!("devnet-rebate-account-{chunk_index}")),
                baseline_fee_micro_units: 4_000,
                paid_fee_micro_units: 2_000,
                latency_ms: 175,
                bandwidth_bytes_per_sec: 36_000_000,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE + 2_048,
                issued_at_height: DEVNET_HEIGHT + 5,
            })
            .expect("devnet fee rebate");
        state
            .publish_public_record("witness_chunk", &chunk_id, &chunk_root, DEVNET_HEIGHT + 6)
            .expect("devnet public record");
    }
    state
}

pub fn config_id(record: &Value) -> String {
    payload_root("PRIVATE-L2-WITNESS-AVAILABILITY-CONFIG-ID", record)
}

pub fn lane_id(
    role: LaneRole,
    operator_commitment: &str,
    pq_identity_root: &str,
    registered_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_identity_root),
            HashPart::U64(registered_at_height),
        ],
        32,
    )
}

pub fn witness_chunk_id(
    execution_id: &str,
    class: ChunkClass,
    lane_id: &str,
    chunk_index: u32,
    shard_index: u16,
    witness_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-CHUNK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(execution_id),
            HashPart::Str(class.as_str()),
            HashPart::Str(lane_id),
            HashPart::U64(u64::from(chunk_index)),
            HashPart::U64(u64::from(shard_index)),
            HashPart::Str(witness_root),
            HashPart::U64(committed_at_height),
        ],
        32,
    )
}

pub fn pq_lane_attestation_id(
    kind: AttestationKind,
    lane_id: &str,
    subject_id: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(signed_at_height),
        ],
        32,
    )
}

pub fn quorum_report_id(
    quorum_id: &str,
    chunk_root: &str,
    available_weight: u64,
    reported_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-QUORUM-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(quorum_id),
            HashPart::Str(chunk_root),
            HashPart::U64(available_weight),
            HashPart::U64(reported_at_height),
        ],
        32,
    )
}

pub fn preconfirmation_receipt_id(
    execution_id: &str,
    chunk_root: &str,
    quorum_report_id: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-PRECONFIRMATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(execution_id),
            HashPart::Str(chunk_root),
            HashPart::Str(quorum_report_id),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn fee_rebate_id(
    kind: RebateKind,
    receipt_id: &str,
    lane_id: &str,
    account_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(receipt_id),
            HashPart::Str(lane_id),
            HashPart::Str(account_commitment),
            HashPart::U64(issued_at_height),
        ],
        32,
    )
}

pub fn repair_window_id(
    execution_id: &str,
    chunk_root: &str,
    missing_shard_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-REPAIR-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(execution_id),
            HashPart::Str(chunk_root),
            HashPart::Str(missing_shard_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn public_record_id(
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(published_at_height),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-WITNESS-AVAILABILITY-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn quorum_status(
    available_weight: u64,
    total_weight: u64,
    missing_shards: u16,
    p95_latency_ms: u64,
    config: &Config,
) -> QuorumStatus {
    if total_weight == 0 {
        return QuorumStatus::Unknown;
    }
    let bps = available_weight.saturating_mul(MAX_BPS) / total_weight;
    if bps < config.quorum_bps {
        return QuorumStatus::Unsafe;
    }
    if missing_shards > config.parity_shards {
        return QuorumStatus::Repairing;
    }
    if p95_latency_ms > config.target_relay_latency_ms.saturating_mul(2) {
        return QuorumStatus::Degraded;
    }
    if bps >= config.strong_quorum_bps && missing_shards == 0 {
        QuorumStatus::Healthy
    } else {
        QuorumStatus::Degraded
    }
}

pub fn compute_rebate_micro_units(
    kind: RebateKind,
    baseline_fee_micro_units: u64,
    paid_fee_micro_units: u64,
    latency_ms: u64,
    bandwidth_bytes_per_sec: u64,
    privacy_set_size: u64,
    config: &Config,
) -> u64 {
    let fee_delta = baseline_fee_micro_units.saturating_sub(paid_fee_micro_units);
    let kind_bps = match kind {
        RebateKind::LowLatency => {
            if latency_ms <= config.target_preconfirmation_ms {
                config.latency_rebate_bps
            } else {
                config.latency_rebate_bps / 2
            }
        }
        RebateKind::HighBandwidth => {
            if bandwidth_bytes_per_sec >= 25_000_000 {
                config.bandwidth_rebate_bps
            } else {
                config.bandwidth_rebate_bps / 2
            }
        }
        RebateKind::PrivacyPreserving => {
            if privacy_set_size >= config.min_privacy_set_size.saturating_mul(2) {
                config.privacy_rebate_bps
            } else {
                config.privacy_rebate_bps / 2
            }
        }
        RebateKind::RepairContribution => config.bandwidth_rebate_bps / 2,
        RebateKind::SponsorSubsidy => {
            (config.latency_rebate_bps + config.bandwidth_rebate_bps + config.privacy_rebate_bps)
                / 3
        }
    };
    fee_delta.saturating_mul(kind_bps) / MAX_BPS
}

pub fn roots_only_record(subject_kind: &str, subject_id: &str, subject_root: &str) -> Value {
    json!({
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "subject_root": subject_root,
        "roots_only": true,
        "scheme": PUBLIC_RECORD_SCHEME,
    })
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    if value.len() < 32 {
        return Err(format!("{label} must be a commitment root"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn require_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn unique_lane_count<'a>(lane_ids: impl Iterator<Item = &'a String>) -> usize {
    lane_ids.collect::<BTreeSet<_>>().len()
}
