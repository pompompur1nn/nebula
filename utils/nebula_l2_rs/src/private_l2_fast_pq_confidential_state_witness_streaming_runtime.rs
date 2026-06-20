use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_STREAMING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-state-witness-streaming-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_STATE_WITNESS_STREAMING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_BROADCASTER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-witness-stream-broadcaster-v1";
pub const PQ_ENCRYPTED_CHUNK_SUITE: &str =
    "ML-KEM-1024-confidential-state-witness-stream-chunk-envelope-v1";
pub const LOW_FEE_STREAMING_CREDIT_SUITE: &str = "low-fee-confidential-witness-streaming-credit-v1";
pub const STALE_CHUNK_QUARANTINE_SUITE: &str = "deterministic-stale-witness-chunk-quarantine-v1";
pub const DEVNET_L2_HEIGHT: u64 = 2_280_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_440_000;
pub const DEVNET_EPOCH: u64 = 8_448;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_CHUNK_BYTES: u64 = 32_768;
pub const DEFAULT_MAX_CHUNK_BYTES: u64 = 131_072;
pub const DEFAULT_LEASE_TTL_SLOTS: u64 = 64;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 96;
pub const DEFAULT_STALE_AFTER_SLOTS: u64 = 48;
pub const DEFAULT_QUARANTINE_TTL_SLOTS: u64 = 512;
pub const DEFAULT_LOW_FEE_CREDIT_TTL_SLOTS: u64 = 256;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 75;
pub const DEFAULT_MAX_LATENCY_MS: u64 = 250;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_LOW_FEE_DISCOUNT_BPS: u64 = 4_500;
pub const DEFAULT_MIN_BROADCASTER_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_MIN_LANE_BOND_MICRO_UNITS: u64 = 20_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_STREAM_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_CHUNK_COMMITMENTS: usize = 4_194_304;
pub const DEFAULT_MAX_BROADCASTER_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_QOS_LANES: usize = 16_384;
pub const DEFAULT_MAX_LOW_FEE_CREDITS: usize = 1_048_576;
pub const DEFAULT_MAX_QUARANTINE_ENTRIES: usize = 524_288;
pub const DEFAULT_MAX_STREAM_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 4_194_304;

const D_STATE: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:ROOTS";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:LEASES";
const D_CHUNKS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:CHUNKS";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:ATTESTATIONS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:LANES";
const D_CREDITS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:CREDITS";
const D_QUARANTINE: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:QUARANTINE";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:RECEIPTS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:PUBLIC";
const D_NULLIFIERS: &str = "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:NULLIFIERS";

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
pub enum LeaseStatus {
    Requested,
    Active,
    Streaming,
    Draining,
    Completed,
    Expired,
    Slashed,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Streaming => "streaming",
            Self::Draining => "draining",
            Self::Completed => "completed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::Active | Self::Streaming | Self::Draining
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Committed,
    Available,
    Delivered,
    Stale,
    Quarantined,
    Replaced,
}

impl ChunkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Available => "available",
            Self::Delivered => "delivered",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Replaced => "replaced",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    Instant,
    Fast,
    LowFee,
    Backfill,
    Watchtower,
    Operator,
}

impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instant => "instant",
            Self::Fast => "fast",
            Self::LowFee => "low_fee",
            Self::Backfill => "backfill",
            Self::Watchtower => "watchtower",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    SheddingLowFee,
    Draining,
    Suspended,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Congested => "congested",
            Self::SheddingLowFee => "shedding_low_fee",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_leases(self) -> bool {
        matches!(self, Self::Open | Self::Congested | Self::SheddingLowFee)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Include,
    Hold,
    Quarantine,
    Reject,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Hold => "hold",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleHeight,
    MissingPredecessor,
    BadCommitment,
    PqAttestationMissing,
    LaneSlaMiss,
    DuplicateNullifier,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleHeight => "stale_height",
            Self::MissingPredecessor => "missing_predecessor",
            Self::BadCommitment => "bad_commitment",
            Self::PqAttestationMissing => "pq_attestation_missing",
            Self::LaneSlaMiss => "lane_sla_miss",
            Self::DuplicateNullifier => "duplicate_nullifier",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub mode: RuntimeMode,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub target_chunk_bytes: u64,
    pub max_chunk_bytes: u64,
    pub lease_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub stale_after_slots: u64,
    pub quarantine_ttl_slots: u64,
    pub low_fee_credit_ttl_slots: u64,
    pub target_latency_ms: u64,
    pub max_latency_ms: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub supermajority_weight_bps: u64,
    pub max_user_fee_bps: u64,
    pub low_fee_discount_bps: u64,
    pub min_broadcaster_bond_micro_units: u64,
    pub min_lane_bond_micro_units: u64,
    pub slash_bps: u64,
    pub enable_low_fee_credits: bool,
    pub enable_stale_chunk_quarantine: bool,
    pub enable_watchtower_lane: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            mode: RuntimeMode::Devnet,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_chunk_bytes: DEFAULT_TARGET_CHUNK_BYTES,
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            lease_ttl_slots: DEFAULT_LEASE_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            stale_after_slots: DEFAULT_STALE_AFTER_SLOTS,
            quarantine_ttl_slots: DEFAULT_QUARANTINE_TTL_SLOTS,
            low_fee_credit_ttl_slots: DEFAULT_LOW_FEE_CREDIT_TTL_SLOTS,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            max_latency_ms: DEFAULT_MAX_LATENCY_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            quorum_weight_bps: DEFAULT_QUORUM_WEIGHT_BPS,
            supermajority_weight_bps: DEFAULT_SUPERMAJORITY_WEIGHT_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            low_fee_discount_bps: DEFAULT_LOW_FEE_DISCOUNT_BPS,
            min_broadcaster_bond_micro_units: DEFAULT_MIN_BROADCASTER_BOND_MICRO_UNITS,
            min_lane_bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            enable_low_fee_credits: true,
            enable_stale_chunk_quarantine: true,
            enable_watchtower_lane: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_streaming_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "mode": self.mode.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_chunk_bytes": self.target_chunk_bytes,
            "max_chunk_bytes": self.max_chunk_bytes,
            "lease_ttl_slots": self.lease_ttl_slots,
            "attestation_ttl_slots": self.attestation_ttl_slots,
            "stale_after_slots": self.stale_after_slots,
            "quarantine_ttl_slots": self.quarantine_ttl_slots,
            "low_fee_credit_ttl_slots": self.low_fee_credit_ttl_slots,
            "target_latency_ms": self.target_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "quorum_weight_bps": self.quorum_weight_bps,
            "supermajority_weight_bps": self.supermajority_weight_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_discount_bps": self.low_fee_discount_bps,
            "min_broadcaster_bond_micro_units": self.min_broadcaster_bond_micro_units,
            "min_lane_bond_micro_units": self.min_lane_bond_micro_units,
            "slash_bps": self.slash_bps,
            "enable_low_fee_credits": self.enable_low_fee_credits,
            "enable_stale_chunk_quarantine": self.enable_stale_chunk_quarantine,
            "enable_watchtower_lane": self.enable_watchtower_lane,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub witness_stream_leases: u64,
    pub encrypted_chunk_commitments: u64,
    pub pq_broadcaster_attestations: u64,
    pub prefetch_qos_lanes: u64,
    pub low_fee_streaming_credits: u64,
    pub stale_chunk_quarantine_entries: u64,
    pub stream_receipts: u64,
    pub public_records: u64,
    pub active_leases: u64,
    pub quarantined_chunks: u64,
    pub delivered_chunks: u64,
    pub total_committed_bytes: u64,
    pub total_delivered_bytes: u64,
    pub total_credit_micro_units: u64,
    pub total_slashed_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub witness_stream_leases_root: String,
    pub encrypted_chunk_commitments_root: String,
    pub pq_broadcaster_attestations_root: String,
    pub prefetch_qos_lanes_root: String,
    pub low_fee_streaming_credits_root: String,
    pub stale_chunk_quarantine_root: String,
    pub stream_receipts_root: String,
    pub public_record_root: String,
    pub consumed_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_streaming_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "witness_stream_leases_root": self.witness_stream_leases_root,
            "encrypted_chunk_commitments_root": self.encrypted_chunk_commitments_root,
            "pq_broadcaster_attestations_root": self.pq_broadcaster_attestations_root,
            "prefetch_qos_lanes_root": self.prefetch_qos_lanes_root,
            "low_fee_streaming_credits_root": self.low_fee_streaming_credits_root,
            "stale_chunk_quarantine_root": self.stale_chunk_quarantine_root,
            "stream_receipts_root": self.stream_receipts_root,
            "public_record_root": self.public_record_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessStreamLease {
    pub lease_id: String,
    pub tenant_commitment: String,
    pub witness_root: String,
    pub stream_key_root: String,
    pub lane_id: String,
    pub lane_class: LaneClass,
    pub max_chunk_count: u64,
    pub reserved_bytes: u64,
    pub fee_cap_micro_units: u64,
    pub low_fee_credit_id: String,
    pub status: LeaseStatus,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
}

impl WitnessStreamLease {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "witness_stream_lease",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "lease_id": self.lease_id,
            "tenant_commitment": self.tenant_commitment,
            "witness_root": self.witness_root,
            "stream_key_root": self.stream_key_root,
            "lane_id": self.lane_id,
            "lane_class": self.lane_class.as_str(),
            "max_chunk_count": self.max_chunk_count,
            "reserved_bytes": self.reserved_bytes,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "low_fee_credit_id": self.low_fee_credit_id,
            "status": self.status.as_str(),
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WITNESS-STREAM-LEASE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("witness_stream_lease", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedChunkCommitment {
    pub chunk_id: String,
    pub lease_id: String,
    pub chunk_index: u64,
    pub encrypted_chunk_root: String,
    pub chunk_ciphertext_commitment: String,
    pub predecessor_chunk_root: String,
    pub witness_delta_root: String,
    pub availability_root: String,
    pub chunk_bytes: u64,
    pub status: ChunkStatus,
    pub committed_at_slot: u64,
    pub delivered_at_slot: u64,
    pub sequence: u64,
}

impl EncryptedChunkCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_chunk_commitment",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "chunk_id": self.chunk_id,
            "lease_id": self.lease_id,
            "chunk_index": self.chunk_index,
            "encrypted_chunk_root": self.encrypted_chunk_root,
            "chunk_ciphertext_commitment": self.chunk_ciphertext_commitment,
            "predecessor_chunk_root": self.predecessor_chunk_root,
            "witness_delta_root": self.witness_delta_root,
            "availability_root": self.availability_root,
            "chunk_bytes": self.chunk_bytes,
            "status": self.status.as_str(),
            "committed_at_slot": self.committed_at_slot,
            "delivered_at_slot": self.delivered_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ENCRYPTED-CHUNK-COMMITMENT", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("encrypted_chunk_commitment", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqBroadcasterAttestation {
    pub attestation_id: String,
    pub broadcaster_id: String,
    pub lease_id: String,
    pub chunk_id: String,
    pub attested_chunk_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub attester_weight_bps: u64,
    pub verdict: AttestationVerdict,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub sequence: u64,
}

impl PqBroadcasterAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_broadcaster_attestation",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "broadcaster_id": self.broadcaster_id,
            "lease_id": self.lease_id,
            "chunk_id": self.chunk_id,
            "attested_chunk_root": self.attested_chunk_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "attester_weight_bps": self.attester_weight_bps,
            "verdict": self.verdict.as_str(),
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PQ-BROADCASTER-ATTESTATION", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("pq_broadcaster_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchQosLane {
    pub lane_id: String,
    pub lane_class: LaneClass,
    pub operator_commitment: String,
    pub bandwidth_share_bps: u64,
    pub target_latency_ms: u64,
    pub max_queue_depth: u64,
    pub bonded_micro_units: u64,
    pub status: LaneStatus,
    pub opened_at_slot: u64,
    pub sequence: u64,
}

impl PrefetchQosLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "prefetch_qos_lane",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "lane_id": self.lane_id,
            "lane_class": self.lane_class.as_str(),
            "operator_commitment": self.operator_commitment,
            "bandwidth_share_bps": self.bandwidth_share_bps,
            "target_latency_ms": self.target_latency_ms,
            "max_queue_depth": self.max_queue_depth,
            "bonded_micro_units": self.bonded_micro_units,
            "status": self.status.as_str(),
            "opened_at_slot": self.opened_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PREFETCH-QOS-LANE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("prefetch_qos_lane", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeStreamingCredit {
    pub credit_id: String,
    pub owner_commitment: String,
    pub lane_id: String,
    pub credit_micro_units: u64,
    pub discount_bps: u64,
    pub spent_micro_units: u64,
    pub created_at_slot: u64,
    pub expires_at_slot: u64,
    pub nullifier: String,
    pub sequence: u64,
}

impl LowFeeStreamingCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_streaming_credit",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "credit_id": self.credit_id,
            "owner_commitment": self.owner_commitment,
            "lane_id": self.lane_id,
            "credit_micro_units": self.credit_micro_units,
            "discount_bps": self.discount_bps,
            "spent_micro_units": self.spent_micro_units,
            "created_at_slot": self.created_at_slot,
            "expires_at_slot": self.expires_at_slot,
            "nullifier": self.nullifier,
            "sequence": self.sequence,
        })
    }

    pub fn remaining_micro_units(&self) -> u64 {
        self.credit_micro_units
            .saturating_sub(self.spent_micro_units)
    }

    pub fn state_root(&self) -> String {
        record_root("LOW-FEE-STREAMING-CREDIT", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("low_fee_streaming_credit", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleChunkQuarantine {
    pub quarantine_id: String,
    pub chunk_id: String,
    pub lease_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub replacement_chunk_root: String,
    pub slashed_broadcaster_id: String,
    pub slashed_micro_units: u64,
    pub quarantined_at_slot: u64,
    pub releases_at_slot: u64,
    pub sequence: u64,
}

impl StaleChunkQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stale_chunk_quarantine",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "quarantine_id": self.quarantine_id,
            "chunk_id": self.chunk_id,
            "lease_id": self.lease_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "replacement_chunk_root": self.replacement_chunk_root,
            "slashed_broadcaster_id": self.slashed_broadcaster_id,
            "slashed_micro_units": self.slashed_micro_units,
            "quarantined_at_slot": self.quarantined_at_slot,
            "releases_at_slot": self.releases_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STALE-CHUNK-QUARANTINE", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("stale_chunk_quarantine", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StreamReceipt {
    pub receipt_id: String,
    pub lease_id: String,
    pub chunk_id: String,
    pub lane_id: String,
    pub delivered_bytes: u64,
    pub latency_ms: u64,
    pub fee_charged_micro_units: u64,
    pub credit_applied_micro_units: u64,
    pub public_record_root: String,
    pub emitted_at_slot: u64,
    pub sequence: u64,
}

impl StreamReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stream_receipt",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "lease_id": self.lease_id,
            "chunk_id": self.chunk_id,
            "lane_id": self.lane_id,
            "delivered_bytes": self.delivered_bytes,
            "latency_ms": self.latency_ms,
            "fee_charged_micro_units": self.fee_charged_micro_units,
            "credit_applied_micro_units": self.credit_applied_micro_units,
            "public_record_root": self.public_record_root,
            "emitted_at_slot": self.emitted_at_slot,
            "sequence": self.sequence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("STREAM-RECEIPT", &self.public_record())
    }

    pub fn stable_id(&self) -> String {
        stable_id("stream_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub current_slot: u64,
    pub witness_stream_leases: BTreeMap<String, WitnessStreamLease>,
    pub encrypted_chunk_commitments: BTreeMap<String, EncryptedChunkCommitment>,
    pub pq_broadcaster_attestations: BTreeMap<String, PqBroadcasterAttestation>,
    pub prefetch_qos_lanes: BTreeMap<String, PrefetchQosLane>,
    pub low_fee_streaming_credits: BTreeMap<String, LowFeeStreamingCredit>,
    pub stale_chunk_quarantine: BTreeMap<String, StaleChunkQuarantine>,
    pub stream_receipts: BTreeMap<String, StreamReceipt>,
    pub public_records: BTreeMap<String, Value>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            current_slot: DEVNET_EPOCH * 64,
            witness_stream_leases: BTreeMap::new(),
            encrypted_chunk_commitments: BTreeMap::new(),
            pq_broadcaster_attestations: BTreeMap::new(),
            prefetch_qos_lanes: BTreeMap::new(),
            low_fee_streaming_credits: BTreeMap::new(),
            stale_chunk_quarantine: BTreeMap::new(),
            stream_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };
        state.seed_devnet_records();
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            witness_stream_leases: self.witness_stream_leases.len() as u64,
            encrypted_chunk_commitments: self.encrypted_chunk_commitments.len() as u64,
            pq_broadcaster_attestations: self.pq_broadcaster_attestations.len() as u64,
            prefetch_qos_lanes: self.prefetch_qos_lanes.len() as u64,
            low_fee_streaming_credits: self.low_fee_streaming_credits.len() as u64,
            stale_chunk_quarantine_entries: self.stale_chunk_quarantine.len() as u64,
            stream_receipts: self.stream_receipts.len() as u64,
            public_records: self.public_records.len() as u64,
            active_leases: self
                .witness_stream_leases
                .values()
                .filter(|lease| lease.status.live())
                .count() as u64,
            quarantined_chunks: self
                .encrypted_chunk_commitments
                .values()
                .filter(|chunk| chunk.status == ChunkStatus::Quarantined)
                .count() as u64,
            delivered_chunks: self
                .encrypted_chunk_commitments
                .values()
                .filter(|chunk| chunk.status == ChunkStatus::Delivered)
                .count() as u64,
            total_committed_bytes: self
                .encrypted_chunk_commitments
                .values()
                .map(|chunk| chunk.chunk_bytes)
                .sum(),
            total_delivered_bytes: self
                .stream_receipts
                .values()
                .map(|receipt| receipt.delivered_bytes)
                .sum(),
            total_credit_micro_units: self
                .low_fee_streaming_credits
                .values()
                .map(|credit| credit.credit_micro_units)
                .sum(),
            total_slashed_micro_units: self
                .stale_chunk_quarantine
                .values()
                .map(|entry| entry.slashed_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters().state_root(),
            witness_stream_leases_root: values_root(D_LEASES, &self.witness_stream_leases),
            encrypted_chunk_commitments_root: values_root(
                D_CHUNKS,
                &self.encrypted_chunk_commitments,
            ),
            pq_broadcaster_attestations_root: values_root(
                D_ATTESTATIONS,
                &self.pq_broadcaster_attestations,
            ),
            prefetch_qos_lanes_root: values_root(D_LANES, &self.prefetch_qos_lanes),
            low_fee_streaming_credits_root: values_root(D_CREDITS, &self.low_fee_streaming_credits),
            stale_chunk_quarantine_root: values_root(D_QUARANTINE, &self.stale_chunk_quarantine),
            stream_receipts_root: values_root(D_RECEIPTS, &self.stream_receipts),
            public_record_root: value_map_root(D_PUBLIC, &self.public_records),
            consumed_nullifier_root: string_set_root(D_NULLIFIERS, &self.consumed_nullifiers),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_fast_pq_confidential_state_witness_streaming_state",
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_broadcaster_attestation_suite": PQ_BROADCASTER_ATTESTATION_SUITE,
            "pq_encrypted_chunk_suite": PQ_ENCRYPTED_CHUNK_SUITE,
            "low_fee_streaming_credit_suite": LOW_FEE_STREAMING_CREDIT_SUITE,
            "stale_chunk_quarantine_suite": STALE_CHUNK_QUARANTINE_SUITE,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "current_slot": self.current_slot,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn insert_witness_stream_lease(
        &mut self,
        mut record: WitnessStreamLease,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.witness_stream_leases.len() >= DEFAULT_MAX_STREAM_LEASES {
            return Err("witness_stream_lease capacity exceeded".to_string());
        }
        if record.lease_id.is_empty() {
            record.lease_id = record.stable_id();
        }
        let id = record.lease_id.clone();
        self.record_public(format!("witness_stream_lease:{id}"), record.public_record())?;
        self.witness_stream_leases.insert(id.clone(), record);
        Ok(id)
    }

    pub fn insert_encrypted_chunk_commitment(
        &mut self,
        mut record: EncryptedChunkCommitment,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.encrypted_chunk_commitments.len() >= DEFAULT_MAX_CHUNK_COMMITMENTS {
            return Err("encrypted_chunk_commitment capacity exceeded".to_string());
        }
        if record.chunk_bytes > self.config.max_chunk_bytes {
            return Err(format!(
                "chunk_bytes {} exceeds max_chunk_bytes {}",
                record.chunk_bytes, self.config.max_chunk_bytes
            ));
        }
        if record.chunk_id.is_empty() {
            record.chunk_id = record.stable_id();
        }
        let id = record.chunk_id.clone();
        self.record_public(
            format!("encrypted_chunk_commitment:{id}"),
            record.public_record(),
        )?;
        self.encrypted_chunk_commitments.insert(id.clone(), record);
        Ok(id)
    }

    pub fn insert_pq_broadcaster_attestation(
        &mut self,
        mut record: PqBroadcasterAttestation,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.pq_broadcaster_attestations.len() >= DEFAULT_MAX_BROADCASTER_ATTESTATIONS {
            return Err("pq_broadcaster_attestation capacity exceeded".to_string());
        }
        if record.attestation_id.is_empty() {
            record.attestation_id = record.stable_id();
        }
        let id = record.attestation_id.clone();
        self.record_public(
            format!("pq_broadcaster_attestation:{id}"),
            record.public_record(),
        )?;
        self.pq_broadcaster_attestations.insert(id.clone(), record);
        Ok(id)
    }

    pub fn insert_prefetch_qos_lane(
        &mut self,
        mut record: PrefetchQosLane,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.prefetch_qos_lanes.len() >= DEFAULT_MAX_QOS_LANES {
            return Err("prefetch_qos_lane capacity exceeded".to_string());
        }
        if !record.status.accepts_leases() && record.lane_class == LaneClass::LowFee {
            return Err("low_fee lane must accept leases when inserted".to_string());
        }
        if record.lane_id.is_empty() {
            record.lane_id = record.stable_id();
        }
        let id = record.lane_id.clone();
        self.record_public(format!("prefetch_qos_lane:{id}"), record.public_record())?;
        self.prefetch_qos_lanes.insert(id.clone(), record);
        Ok(id)
    }

    pub fn insert_low_fee_streaming_credit(
        &mut self,
        mut record: LowFeeStreamingCredit,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.low_fee_streaming_credits.len() >= DEFAULT_MAX_LOW_FEE_CREDITS {
            return Err("low_fee_streaming_credit capacity exceeded".to_string());
        }
        if !record.nullifier.is_empty() && self.consumed_nullifiers.contains(&record.nullifier) {
            return Err("low_fee_streaming_credit nullifier already consumed".to_string());
        }
        if record.credit_id.is_empty() {
            record.credit_id = record.stable_id();
        }
        let id = record.credit_id.clone();
        if !record.nullifier.is_empty() {
            self.consumed_nullifiers.insert(record.nullifier.clone());
        }
        self.record_public(
            format!("low_fee_streaming_credit:{id}"),
            record.public_record(),
        )?;
        self.low_fee_streaming_credits.insert(id.clone(), record);
        Ok(id)
    }

    pub fn insert_stale_chunk_quarantine(
        &mut self,
        mut record: StaleChunkQuarantine,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.stale_chunk_quarantine.len() >= DEFAULT_MAX_QUARANTINE_ENTRIES {
            return Err("stale_chunk_quarantine capacity exceeded".to_string());
        }
        if record.quarantine_id.is_empty() {
            record.quarantine_id = record.stable_id();
        }
        let id = record.quarantine_id.clone();
        if let Some(chunk) = self.encrypted_chunk_commitments.get_mut(&record.chunk_id) {
            chunk.status = ChunkStatus::Quarantined;
        }
        self.record_public(
            format!("stale_chunk_quarantine:{id}"),
            record.public_record(),
        )?;
        self.stale_chunk_quarantine.insert(id.clone(), record);
        Ok(id)
    }

    pub fn insert_stream_receipt(
        &mut self,
        mut record: StreamReceipt,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<String> {
        if self.stream_receipts.len() >= DEFAULT_MAX_STREAM_RECEIPTS {
            return Err("stream_receipt capacity exceeded".to_string());
        }
        if record.receipt_id.is_empty() {
            record.receipt_id = record.stable_id();
        }
        let id = record.receipt_id.clone();
        if let Some(chunk) = self.encrypted_chunk_commitments.get_mut(&record.chunk_id) {
            chunk.status = ChunkStatus::Delivered;
            chunk.delivered_at_slot = record.emitted_at_slot;
        }
        self.record_public(format!("stream_receipt:{id}"), record.public_record())?;
        self.stream_receipts.insert(id.clone(), record);
        Ok(id)
    }

    pub fn get_witness_stream_lease(&self, id: &str) -> Option<&WitnessStreamLease> {
        self.witness_stream_leases.get(id)
    }

    pub fn get_encrypted_chunk_commitment(&self, id: &str) -> Option<&EncryptedChunkCommitment> {
        self.encrypted_chunk_commitments.get(id)
    }

    pub fn get_pq_broadcaster_attestation(&self, id: &str) -> Option<&PqBroadcasterAttestation> {
        self.pq_broadcaster_attestations.get(id)
    }

    pub fn get_prefetch_qos_lane(&self, id: &str) -> Option<&PrefetchQosLane> {
        self.prefetch_qos_lanes.get(id)
    }

    pub fn get_low_fee_streaming_credit(&self, id: &str) -> Option<&LowFeeStreamingCredit> {
        self.low_fee_streaming_credits.get(id)
    }

    pub fn get_stale_chunk_quarantine(&self, id: &str) -> Option<&StaleChunkQuarantine> {
        self.stale_chunk_quarantine.get(id)
    }

    pub fn get_stream_receipt(&self, id: &str) -> Option<&StreamReceipt> {
        self.stream_receipts.get(id)
    }

    pub fn quarantine_stale_chunks(
        &mut self,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<Vec<String>> {
        let stale_after = self.config.stale_after_slots;
        let chunk_ids = self
            .encrypted_chunk_commitments
            .values()
            .filter(|chunk| {
                matches!(
                    chunk.status,
                    ChunkStatus::Committed | ChunkStatus::Available
                ) && self.current_slot.saturating_sub(chunk.committed_at_slot) > stale_after
            })
            .map(|chunk| chunk.chunk_id.clone())
            .collect::<Vec<_>>();
        let mut quarantine_ids = Vec::new();
        for (offset, chunk_id) in chunk_ids.into_iter().enumerate() {
            let chunk = self
                .encrypted_chunk_commitments
                .get(&chunk_id)
                .cloned()
                .ok_or_else(|| format!("chunk {chunk_id} disappeared before quarantine"))?;
            let entry = StaleChunkQuarantine {
                quarantine_id: String::new(),
                chunk_id: chunk.chunk_id.clone(),
                lease_id: chunk.lease_id.clone(),
                reason: QuarantineReason::StaleHeight,
                evidence_root: chunk.state_root(),
                replacement_chunk_root: deterministic_label_root(
                    "replacement_chunk_root",
                    &chunk.chunk_id,
                    offset as u64,
                ),
                slashed_broadcaster_id: "pending-broadcaster-resolution".to_string(),
                slashed_micro_units: 0,
                quarantined_at_slot: self.current_slot,
                releases_at_slot: self.current_slot + self.config.quarantine_ttl_slots,
                sequence: self.next_sequence(),
            };
            quarantine_ids.push(self.insert_stale_chunk_quarantine(entry)?);
        }
        Ok(quarantine_ids)
    }

    pub fn advance_slot(&mut self, slots: u64) {
        self.current_slot = self.current_slot.saturating_add(slots);
    }

    fn record_public(
        &mut self,
        key: String,
        record: Value,
    ) -> PrivateL2FastPqConfidentialStateWitnessStreamingRuntimeResult<()> {
        if self.public_records.len() >= DEFAULT_MAX_PUBLIC_RECORDS {
            return Err("public_records capacity exceeded".to_string());
        }
        self.public_records.insert(key, record);
        Ok(())
    }

    fn next_sequence(&self) -> u64 {
        self.public_records.len() as u64 + 1
    }

    fn seed_devnet_records(&mut self) {
        let instant_lane = PrefetchQosLane {
            lane_id: "devnet-instant-witness-lane".to_string(),
            lane_class: LaneClass::Instant,
            operator_commitment: deterministic_label_root("operator", "instant", 0),
            bandwidth_share_bps: 4_000,
            target_latency_ms: 45,
            max_queue_depth: 8_192,
            bonded_micro_units: self.config.min_lane_bond_micro_units * 2,
            status: LaneStatus::Open,
            opened_at_slot: self.current_slot,
            sequence: 1,
        };
        let low_fee_lane = PrefetchQosLane {
            lane_id: "devnet-low-fee-witness-lane".to_string(),
            lane_class: LaneClass::LowFee,
            operator_commitment: deterministic_label_root("operator", "low_fee", 1),
            bandwidth_share_bps: 2_500,
            target_latency_ms: 140,
            max_queue_depth: 32_768,
            bonded_micro_units: self.config.min_lane_bond_micro_units,
            status: LaneStatus::Open,
            opened_at_slot: self.current_slot,
            sequence: 2,
        };
        let watchtower_lane = PrefetchQosLane {
            lane_id: "devnet-watchtower-witness-lane".to_string(),
            lane_class: LaneClass::Watchtower,
            operator_commitment: deterministic_label_root("operator", "watchtower", 2),
            bandwidth_share_bps: 1_500,
            target_latency_ms: 90,
            max_queue_depth: 16_384,
            bonded_micro_units: self.config.min_lane_bond_micro_units * 3,
            status: LaneStatus::Open,
            opened_at_slot: self.current_slot,
            sequence: 3,
        };
        self.insert_prefetch_qos_lane(instant_lane)
            .expect("seed instant lane");
        self.insert_prefetch_qos_lane(low_fee_lane)
            .expect("seed low fee lane");
        self.insert_prefetch_qos_lane(watchtower_lane)
            .expect("seed watchtower lane");

        let credit = LowFeeStreamingCredit {
            credit_id: "devnet-low-fee-credit-0".to_string(),
            owner_commitment: deterministic_label_root("owner", "wallet-cohort-a", 0),
            lane_id: "devnet-low-fee-witness-lane".to_string(),
            credit_micro_units: 250_000,
            discount_bps: self.config.low_fee_discount_bps,
            spent_micro_units: 25_000,
            created_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.low_fee_credit_ttl_slots,
            nullifier: deterministic_label_root("credit-nullifier", "wallet-cohort-a", 0),
            sequence: 4,
        };
        self.insert_low_fee_streaming_credit(credit)
            .expect("seed low fee credit");

        let lease = WitnessStreamLease {
            lease_id: "devnet-witness-stream-lease-0".to_string(),
            tenant_commitment: deterministic_label_root("tenant", "contract-batch-a", 0),
            witness_root: deterministic_label_root("witness-root", "contract-batch-a", 0),
            stream_key_root: deterministic_label_root("stream-key", "contract-batch-a", 0),
            lane_id: "devnet-low-fee-witness-lane".to_string(),
            lane_class: LaneClass::LowFee,
            max_chunk_count: 64,
            reserved_bytes: self.config.target_chunk_bytes * 8,
            fee_cap_micro_units: 100_000,
            low_fee_credit_id: "devnet-low-fee-credit-0".to_string(),
            status: LeaseStatus::Streaming,
            created_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.lease_ttl_slots,
            sequence: 5,
        };
        self.insert_witness_stream_lease(lease)
            .expect("seed witness stream lease");

        let chunk = EncryptedChunkCommitment {
            chunk_id: "devnet-encrypted-witness-chunk-0".to_string(),
            lease_id: "devnet-witness-stream-lease-0".to_string(),
            chunk_index: 0,
            encrypted_chunk_root: deterministic_label_root(
                "encrypted-chunk",
                "contract-batch-a",
                0,
            ),
            chunk_ciphertext_commitment: deterministic_label_root(
                "chunk-ciphertext",
                "contract-batch-a",
                0,
            ),
            predecessor_chunk_root: deterministic_label_root("genesis-predecessor", "stream", 0),
            witness_delta_root: deterministic_label_root("witness-delta", "contract-batch-a", 0),
            availability_root: deterministic_label_root("availability", "contract-batch-a", 0),
            chunk_bytes: self.config.target_chunk_bytes,
            status: ChunkStatus::Available,
            committed_at_slot: self.current_slot,
            delivered_at_slot: 0,
            sequence: 6,
        };
        self.insert_encrypted_chunk_commitment(chunk)
            .expect("seed encrypted chunk");

        let attestation = PqBroadcasterAttestation {
            attestation_id: "devnet-pq-broadcaster-attestation-0".to_string(),
            broadcaster_id: "devnet-broadcaster-0".to_string(),
            lease_id: "devnet-witness-stream-lease-0".to_string(),
            chunk_id: "devnet-encrypted-witness-chunk-0".to_string(),
            attested_chunk_root: deterministic_label_root("attested-chunk", "contract-batch-a", 0),
            pq_public_key_root: deterministic_label_root("pq-public-key", "broadcaster-0", 0),
            pq_signature_root: deterministic_label_root("pq-signature", "broadcaster-0", 0),
            attester_weight_bps: self.config.quorum_weight_bps,
            verdict: AttestationVerdict::Include,
            created_at_slot: self.current_slot,
            expires_at_slot: self.current_slot + self.config.attestation_ttl_slots,
            sequence: 7,
        };
        self.insert_pq_broadcaster_attestation(attestation)
            .expect("seed pq broadcaster attestation");

        let receipt = StreamReceipt {
            receipt_id: "devnet-stream-receipt-0".to_string(),
            lease_id: "devnet-witness-stream-lease-0".to_string(),
            chunk_id: "devnet-encrypted-witness-chunk-0".to_string(),
            lane_id: "devnet-low-fee-witness-lane".to_string(),
            delivered_bytes: self.config.target_chunk_bytes,
            latency_ms: 68,
            fee_charged_micro_units: 750,
            credit_applied_micro_units: 325,
            public_record_root: deterministic_label_root("receipt-public-record", "stream", 0),
            emitted_at_slot: self.current_slot + 1,
            sequence: 8,
        };
        self.insert_stream_receipt(receipt)
            .expect("seed stream receipt");

        let stale_chunk = EncryptedChunkCommitment {
            chunk_id: "devnet-stale-witness-chunk-0".to_string(),
            lease_id: "devnet-witness-stream-lease-0".to_string(),
            chunk_index: 1,
            encrypted_chunk_root: deterministic_label_root(
                "encrypted-chunk",
                "contract-batch-a",
                1,
            ),
            chunk_ciphertext_commitment: deterministic_label_root(
                "chunk-ciphertext",
                "contract-batch-a",
                1,
            ),
            predecessor_chunk_root: deterministic_label_root(
                "encrypted-chunk",
                "contract-batch-a",
                0,
            ),
            witness_delta_root: deterministic_label_root("witness-delta", "contract-batch-a", 1),
            availability_root: deterministic_label_root("availability", "contract-batch-a", 1),
            chunk_bytes: self.config.target_chunk_bytes,
            status: ChunkStatus::Quarantined,
            committed_at_slot: self.current_slot - self.config.stale_after_slots - 1,
            delivered_at_slot: 0,
            sequence: 9,
        };
        self.insert_encrypted_chunk_commitment(stale_chunk)
            .expect("seed stale chunk");

        let quarantine = StaleChunkQuarantine {
            quarantine_id: "devnet-stale-chunk-quarantine-0".to_string(),
            chunk_id: "devnet-stale-witness-chunk-0".to_string(),
            lease_id: "devnet-witness-stream-lease-0".to_string(),
            reason: QuarantineReason::StaleHeight,
            evidence_root: deterministic_label_root("stale-evidence", "contract-batch-a", 1),
            replacement_chunk_root: deterministic_label_root("replacement", "contract-batch-a", 1),
            slashed_broadcaster_id: "devnet-broadcaster-1".to_string(),
            slashed_micro_units: 15_000,
            quarantined_at_slot: self.current_slot,
            releases_at_slot: self.current_slot + self.config.quarantine_ttl_slots,
            sequence: 10,
        };
        self.insert_stale_chunk_quarantine(quarantine)
            .expect("seed stale chunk quarantine");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    if let Value::Object(object) = record {
        object.insert(key.to_string(), value);
    }
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn state_root_from_public_record(record: &Value) -> String {
    record_root(D_STATE, record)
}

fn stable_id(kind: &str, record: &Value) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:STABLE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        20,
    )
}

fn deterministic_label_root(label: &str, value: &str, sequence: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-STATE-WITNESS-STREAMING:DETERMINISTIC-LABEL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn values_root<T>(domain: &str, values: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn value_map_root(domain: &str, values: &BTreeMap<String, Value>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for WitnessStreamLease {
    fn public_record(&self) -> Value {
        WitnessStreamLease::public_record(self)
    }
}

impl PublicRecord for EncryptedChunkCommitment {
    fn public_record(&self) -> Value {
        EncryptedChunkCommitment::public_record(self)
    }
}

impl PublicRecord for PqBroadcasterAttestation {
    fn public_record(&self) -> Value {
        PqBroadcasterAttestation::public_record(self)
    }
}

impl PublicRecord for PrefetchQosLane {
    fn public_record(&self) -> Value {
        PrefetchQosLane::public_record(self)
    }
}

impl PublicRecord for LowFeeStreamingCredit {
    fn public_record(&self) -> Value {
        LowFeeStreamingCredit::public_record(self)
    }
}

impl PublicRecord for StaleChunkQuarantine {
    fn public_record(&self) -> Value {
        StaleChunkQuarantine::public_record(self)
    }
}

impl PublicRecord for StreamReceipt {
    fn public_record(&self) -> Value {
        StreamReceipt::public_record(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_root_is_deterministic() {
        let state = State::devnet();
        assert_eq!(state.state_root(), State::devnet().state_root());
    }

    #[test]
    fn public_record_contains_state_root() {
        let state = State::devnet();
        assert_eq!(
            state.public_record()["state_root"].as_str(),
            Some(state.state_root().as_str())
        );
    }
}
