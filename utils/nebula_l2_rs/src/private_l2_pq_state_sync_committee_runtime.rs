use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqStateSyncCommitteeRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-state-sync-committee-runtime-v1";
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_ENCRYPTED_SYNC_SUITE: &str =
    "threshold-ml-kem-encrypted-fast-state-sync-v1";
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_LOW_FEE_RELAY_SCHEME: &str =
    "batched-low-fee-private-state-sync-relay-v1";
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEVNET_HEIGHT: u64 = 524_000;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS: u64 = 6_700;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_FAST_QUORUM_BPS: u64 = 7_500;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_COMMITTEES: usize = 65_536;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_SNAPSHOTS: usize = 524_288;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 524_288;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_CHUNKS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_CHALLENGES: usize = 524_288;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_MANIFESTS: usize = 524_288;
pub const PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncLane {
    PrivateContractState,
    ConfidentialTokenState,
    PrivateDefiState,
    MoneroBridgeState,
    ProofDataAvailability,
    EmergencyRecovery,
}

impl SyncLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractState => "private_contract_state",
            Self::ConfidentialTokenState => "confidential_token_state",
            Self::PrivateDefiState => "private_defi_state",
            Self::MoneroBridgeState => "monero_bridge_state",
            Self::ProofDataAvailability => "proof_data_availability",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn priority_score(self) -> u64 {
        match self {
            Self::EmergencyRecovery => 10_000,
            Self::MoneroBridgeState => 9_500,
            Self::PrivateDefiState => 9_100,
            Self::PrivateContractState => 8_800,
            Self::ConfidentialTokenState => 8_300,
            Self::ProofDataAvailability => 7_600,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Paused,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_sync(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Encrypted,
    RelayReserved,
    Chunked,
    Attested,
    ManifestReady,
    Finalized,
    Challenged,
    Expired,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::RelayReserved => "relay_reserved",
            Self::Chunked => "chunked",
            Self::Attested => "attested",
            Self::ManifestReady => "manifest_ready",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::RelayReserved
                | Self::Chunked
                | Self::Attested
                | Self::ManifestReady
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approve,
    Reject,
    Abstain,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayReservationStatus {
    Reserved,
    Published,
    Settled,
    Cancelled,
    Expired,
}

impl RelayReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeVerdict {
    Pending,
    SnapshotValid,
    SnapshotInvalid,
    DataUnavailable,
}

impl ChallengeVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SnapshotValid => "snapshot_valid",
            Self::SnapshotInvalid => "snapshot_invalid",
            Self::DataUnavailable => "data_unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub fast_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub snapshot_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub max_committees: usize,
    pub max_snapshots: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_chunks: usize,
    pub max_challenges: usize,
    pub max_manifests: usize,
    pub require_roots_only: bool,
    pub require_low_fee_relay: bool,
    pub require_pq_attestation: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight_bps: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS,
            fast_quorum_bps: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_FAST_QUORUM_BPS,
            max_user_fee_bps: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            snapshot_ttl_blocks:
                PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            max_committees: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_COMMITTEES,
            max_snapshots: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_SNAPSHOTS,
            max_attestations: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_reservations: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_chunks: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_CHUNKS,
            max_challenges: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_CHALLENGES,
            max_manifests: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEFAULT_MAX_MANIFESTS,
            require_roots_only: true,
            require_low_fee_relay: true,
            require_pq_attestation: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("PQ state sync chain id mismatch".to_string());
        }
        if !self.require_roots_only {
            return Err("PQ state sync requires roots-only private records".to_string());
        }
        if self.min_privacy_set_size == 0 || self.min_pq_security_bits < 192 {
            return Err("PQ state sync privacy/PQ floor is invalid".to_string());
        }
        if self.quorum_weight_bps == 0
            || self.quorum_weight_bps > PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS
            || self.fast_quorum_bps < self.quorum_weight_bps
            || self.fast_quorum_bps > PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS
            || self.max_user_fee_bps > PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS
        {
            return Err("PQ state sync BPS policy is invalid".to_string());
        }
        if self.snapshot_ttl_blocks == 0 || self.reservation_ttl_blocks == 0 {
            return Err("PQ state sync TTL windows must be positive".to_string());
        }
        if self.max_committees == 0
            || self.max_snapshots == 0
            || self.max_attestations == 0
            || self.max_reservations == 0
            || self.max_chunks == 0
            || self.max_challenges == 0
            || self.max_manifests == 0
        {
            return Err("PQ state sync capacities must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_state_sync_committee_config",
            "chain_id": self.chain_id,
            "protocol_version": PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PROTOCOL_VERSION,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "snapshot_ttl_blocks": self.snapshot_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "max_committees": self.max_committees,
            "max_snapshots": self.max_snapshots,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_chunks": self.max_chunks,
            "max_challenges": self.max_challenges,
            "max_manifests": self.max_manifests,
            "require_roots_only": self.require_roots_only,
            "require_low_fee_relay": self.require_low_fee_relay,
            "require_pq_attestation": self.require_pq_attestation,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub committee_count: u64,
    pub snapshot_count: u64,
    pub attestation_count: u64,
    pub reservation_count: u64,
    pub chunk_count: u64,
    pub challenge_count: u64,
    pub manifest_count: u64,
    pub consumed_nullifier_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_state_sync_committee_counters",
            "committee_count": self.committee_count,
            "snapshot_count": self.snapshot_count,
            "attestation_count": self.attestation_count,
            "reservation_count": self.reservation_count,
            "chunk_count": self.chunk_count,
            "challenge_count": self.challenge_count,
            "manifest_count": self.manifest_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterStateSyncCommitteeRequest {
    pub lane: SyncLane,
    pub operator_set_root: String,
    pub threshold_key_root: String,
    pub pq_public_key_root: String,
    pub stake_weight_root: String,
    pub low_fee_policy_root: String,
    pub privacy_proof_root: String,
    pub epoch: u64,
    pub member_set_size: u64,
    pub committee_weight_bps: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
}

impl RegisterStateSyncCommitteeRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("operator_set_root", &self.operator_set_root)?;
        required("threshold_key_root", &self.threshold_key_root)?;
        required("pq_public_key_root", &self.pq_public_key_root)?;
        required("stake_weight_root", &self.stake_weight_root)?;
        required("low_fee_policy_root", &self.low_fee_policy_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        validate_privacy_and_pq(self.member_set_size, self.pq_security_bits, config)?;
        if self.committee_weight_bps < config.quorum_weight_bps
            || self.committee_weight_bps > PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS
        {
            return Err("PQ state sync committee weight outside quorum policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "operator_set_root": self.operator_set_root,
            "threshold_key_root": self.threshold_key_root,
            "pq_public_key_root": self.pq_public_key_root,
            "stake_weight_root": self.stake_weight_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "privacy_proof_root": self.privacy_proof_root,
            "epoch": self.epoch,
            "member_set_size": self.member_set_size,
            "committee_weight_bps": self.committee_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishEncryptedFastSyncSnapshotRequest {
    pub committee_id: String,
    pub lane: SyncLane,
    pub source_state_root: String,
    pub target_state_root: String,
    pub encrypted_snapshot_root: String,
    pub chunk_set_root: String,
    pub state_diff_commitment_root: String,
    pub access_policy_root: String,
    pub pq_encryption_root: String,
    pub privacy_proof_root: String,
    pub snapshot_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub published_at_height: u64,
}

impl PublishEncryptedFastSyncSnapshotRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("committee_id", &self.committee_id)?;
        required("source_state_root", &self.source_state_root)?;
        required("target_state_root", &self.target_state_root)?;
        required("encrypted_snapshot_root", &self.encrypted_snapshot_root)?;
        required("chunk_set_root", &self.chunk_set_root)?;
        required(
            "state_diff_commitment_root",
            &self.state_diff_commitment_root,
        )?;
        required("access_policy_root", &self.access_policy_root)?;
        required("pq_encryption_root", &self.pq_encryption_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("snapshot_nullifier", &self.snapshot_nullifier)?;
        validate_privacy_and_pq(self.privacy_set_size, self.pq_security_bits, config)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("PQ state sync snapshot fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "lane": self.lane.as_str(),
            "source_state_root": self.source_state_root,
            "target_state_root": self.target_state_root,
            "encrypted_snapshot_root": self.encrypted_snapshot_root,
            "chunk_set_root": self.chunk_set_root,
            "state_diff_commitment_root": self.state_diff_commitment_root,
            "access_policy_root": self.access_policy_root,
            "pq_encryption_root": self.pq_encryption_root,
            "privacy_proof_root": self.privacy_proof_root,
            "snapshot_nullifier": self.snapshot_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitCommitteeAttestationRequest {
    pub snapshot_id: String,
    pub committee_id: String,
    pub attester_commitment: String,
    pub verdict: AttestationVerdict,
    pub attestation_weight_bps: u64,
    pub availability_root: String,
    pub state_transition_check_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl SubmitCommitteeAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("snapshot_id", &self.snapshot_id)?;
        required("committee_id", &self.committee_id)?;
        required("attester_commitment", &self.attester_commitment)?;
        required("availability_root", &self.availability_root)?;
        required(
            "state_transition_check_root",
            &self.state_transition_check_root,
        )?;
        required("pq_signature_root", &self.pq_signature_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("attestation_nullifier", &self.attestation_nullifier)?;
        validate_privacy_and_pq(self.privacy_set_size, self.pq_security_bits, config)?;
        if self.attestation_weight_bps > PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS {
            return Err("PQ state sync attestation weight exceeds BPS range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "committee_id": self.committee_id,
            "attester_commitment": self.attester_commitment,
            "verdict": self.verdict.as_str(),
            "attestation_weight_bps": self.attestation_weight_bps,
            "availability_root": self.availability_root,
            "state_transition_check_root": self.state_transition_check_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeSnapshotRelayRequest {
    pub snapshot_id: String,
    pub relayer_commitment: String,
    pub relay_window_root: String,
    pub bandwidth_commitment_root: String,
    pub low_fee_sponsor_root: String,
    pub fee_receipt_root: String,
    pub pq_relayer_signature_root: String,
    pub relay_nullifier: String,
    pub max_fee_bps: u64,
    pub reserved_at_height: u64,
}

impl ReserveLowFeeSnapshotRelayRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("snapshot_id", &self.snapshot_id)?;
        required("relayer_commitment", &self.relayer_commitment)?;
        required("relay_window_root", &self.relay_window_root)?;
        required("bandwidth_commitment_root", &self.bandwidth_commitment_root)?;
        if config.require_low_fee_relay {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_relayer_signature_root", &self.pq_relayer_signature_root)?;
        required("relay_nullifier", &self.relay_nullifier)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("PQ state sync relay reservation fee exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "relayer_commitment": self.relayer_commitment,
            "relay_window_root": self.relay_window_root,
            "bandwidth_commitment_root": self.bandwidth_commitment_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "fee_receipt_root": self.fee_receipt_root,
            "pq_relayer_signature_root": self.pq_relayer_signature_root,
            "relay_nullifier": self.relay_nullifier,
            "max_fee_bps": self.max_fee_bps,
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitStateChunkRequest {
    pub snapshot_id: String,
    pub chunk_index: u64,
    pub chunk_count: u64,
    pub encrypted_chunk_root: String,
    pub chunk_commitment_root: String,
    pub erasure_coding_root: String,
    pub availability_sample_root: String,
    pub pq_chunk_signature_root: String,
    pub committed_at_height: u64,
}

impl CommitStateChunkRequest {
    pub fn validate(&self) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("snapshot_id", &self.snapshot_id)?;
        required("encrypted_chunk_root", &self.encrypted_chunk_root)?;
        required("chunk_commitment_root", &self.chunk_commitment_root)?;
        required("erasure_coding_root", &self.erasure_coding_root)?;
        required("availability_sample_root", &self.availability_sample_root)?;
        required("pq_chunk_signature_root", &self.pq_chunk_signature_root)?;
        if self.chunk_count == 0 || self.chunk_index >= self.chunk_count {
            return Err("PQ state sync chunk index/count is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "chunk_index": self.chunk_index,
            "chunk_count": self.chunk_count,
            "encrypted_chunk_root": self.encrypted_chunk_root,
            "chunk_commitment_root": self.chunk_commitment_root,
            "erasure_coding_root": self.erasure_coding_root,
            "availability_sample_root": self.availability_sample_root,
            "pq_chunk_signature_root": self.pq_chunk_signature_root,
            "committed_at_height": self.committed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitChallengeReceiptRequest {
    pub snapshot_id: String,
    pub challenger_commitment: String,
    pub challenged_chunk_root: String,
    pub challenge_claim_root: String,
    pub response_root: String,
    pub pq_challenge_signature_root: String,
    pub privacy_proof_root: String,
    pub challenge_nullifier: String,
    pub verdict: ChallengeVerdict,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub challenged_at_height: u64,
}

impl SubmitChallengeReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("snapshot_id", &self.snapshot_id)?;
        required("challenger_commitment", &self.challenger_commitment)?;
        required("challenged_chunk_root", &self.challenged_chunk_root)?;
        required("challenge_claim_root", &self.challenge_claim_root)?;
        required("response_root", &self.response_root)?;
        required(
            "pq_challenge_signature_root",
            &self.pq_challenge_signature_root,
        )?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("challenge_nullifier", &self.challenge_nullifier)?;
        validate_privacy_and_pq(self.privacy_set_size, self.pq_security_bits, config)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "challenger_commitment": self.challenger_commitment,
            "challenged_chunk_root": self.challenged_chunk_root,
            "challenge_claim_root": self.challenge_claim_root,
            "response_root": self.response_root,
            "pq_challenge_signature_root": self.pq_challenge_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "challenge_nullifier": self.challenge_nullifier,
            "verdict": self.verdict.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "challenged_at_height": self.challenged_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeSyncManifestRequest {
    pub snapshot_id: String,
    pub reservation_id: String,
    pub manifest_root: String,
    pub finalized_state_root: String,
    pub aggregate_attestation_root: String,
    pub aggregate_chunk_root: String,
    pub relay_receipt_root: String,
    pub challenge_receipt_root: String,
    pub low_fee_settlement_root: String,
    pub pq_manifest_signature_root: String,
    pub final_quorum_weight_bps: u64,
    pub final_fee_bps: u64,
    pub finalized_at_height: u64,
}

impl FinalizeSyncManifestRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        required("snapshot_id", &self.snapshot_id)?;
        required("reservation_id", &self.reservation_id)?;
        required("manifest_root", &self.manifest_root)?;
        required("finalized_state_root", &self.finalized_state_root)?;
        required(
            "aggregate_attestation_root",
            &self.aggregate_attestation_root,
        )?;
        required("aggregate_chunk_root", &self.aggregate_chunk_root)?;
        required("relay_receipt_root", &self.relay_receipt_root)?;
        required("challenge_receipt_root", &self.challenge_receipt_root)?;
        required("low_fee_settlement_root", &self.low_fee_settlement_root)?;
        required(
            "pq_manifest_signature_root",
            &self.pq_manifest_signature_root,
        )?;
        if self.final_quorum_weight_bps < config.fast_quorum_bps {
            return Err("PQ state sync manifest below fast quorum".to_string());
        }
        if self.final_fee_bps > config.max_user_fee_bps {
            return Err("PQ state sync manifest fee exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "reservation_id": self.reservation_id,
            "manifest_root": self.manifest_root,
            "finalized_state_root": self.finalized_state_root,
            "aggregate_attestation_root": self.aggregate_attestation_root,
            "aggregate_chunk_root": self.aggregate_chunk_root,
            "relay_receipt_root": self.relay_receipt_root,
            "challenge_receipt_root": self.challenge_receipt_root,
            "low_fee_settlement_root": self.low_fee_settlement_root,
            "pq_manifest_signature_root": self.pq_manifest_signature_root,
            "final_quorum_weight_bps": self.final_quorum_weight_bps,
            "final_fee_bps": self.final_fee_bps,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSyncCommitteeRecord {
    pub committee_id: String,
    pub request: RegisterStateSyncCommitteeRequest,
    pub status: CommitteeStatus,
}

impl StateSyncCommitteeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFastSyncSnapshotRecord {
    pub snapshot_id: String,
    pub request: PublishEncryptedFastSyncSnapshotRequest,
    pub approved_weight_bps: u64,
    pub rejected_weight_bps: u64,
    pub status: SnapshotStatus,
    pub expires_at_height: u64,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub chunk_ids: Vec<String>,
    pub challenge_ids: Vec<String>,
}

impl EncryptedFastSyncSnapshotRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "request": self.request.public_record(),
            "approved_weight_bps": self.approved_weight_bps,
            "rejected_weight_bps": self.rejected_weight_bps,
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
            "attestation_ids": self.attestation_ids,
            "reservation_ids": self.reservation_ids,
            "chunk_ids": self.chunk_ids,
            "challenge_ids": self.challenge_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeAttestationRecord {
    pub attestation_id: String,
    pub request: SubmitCommitteeAttestationRequest,
}

impl CommitteeAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSnapshotRelayReservationRecord {
    pub reservation_id: String,
    pub request: ReserveLowFeeSnapshotRelayRequest,
    pub status: RelayReservationStatus,
    pub expires_at_height: u64,
}

impl LowFeeSnapshotRelayReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateChunkCommitmentRecord {
    pub chunk_id: String,
    pub request: CommitStateChunkRequest,
}

impl StateChunkCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "chunk_id": self.chunk_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeReceiptRecord {
    pub challenge_id: String,
    pub request: SubmitChallengeReceiptRequest,
}

impl ChallengeReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedSyncManifestRecord {
    pub manifest_id: String,
    pub request: FinalizeSyncManifestRequest,
}

impl FinalizedSyncManifestRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub committee_root: String,
    pub snapshot_root: String,
    pub attestation_root: String,
    pub reservation_root: String,
    pub chunk_root: String,
    pub challenge_root: String,
    pub manifest_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "committee_root": self.committee_root,
            "snapshot_root": self.snapshot_root,
            "attestation_root": self.attestation_root,
            "reservation_root": self.reservation_root,
            "chunk_root": self.chunk_root,
            "challenge_root": self.challenge_root,
            "manifest_root": self.manifest_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub protocol_version: String,
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub committees: BTreeMap<String, StateSyncCommitteeRecord>,
    pub snapshots: BTreeMap<String, EncryptedFastSyncSnapshotRecord>,
    pub attestations: BTreeMap<String, CommitteeAttestationRecord>,
    pub reservations: BTreeMap<String, LowFeeSnapshotRelayReservationRecord>,
    pub chunks: BTreeMap<String, StateChunkCommitmentRecord>,
    pub challenges: BTreeMap<String, ChallengeReceiptRecord>,
    pub manifests: BTreeMap<String, FinalizedSyncManifestRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqStateSyncCommitteeRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        Ok(Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_DEVNET_HEIGHT,
            committees: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            chunks: BTreeMap::new(),
            challenges: BTreeMap::new(),
            manifests: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            chain_id: config.chain_id.clone(),
            protocol_version: PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            config,
            counters: Counters::default(),
            current_height,
            committees: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            chunks: BTreeMap::new(),
            challenges: BTreeMap::new(),
            manifests: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_committee(
        &mut self,
        request: RegisterStateSyncCommitteeRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<StateSyncCommitteeRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.committees.len() >= self.config.max_committees {
            return Err("PQ state sync committee capacity exhausted".to_string());
        }
        self.counters.committee_count = self.counters.committee_count.saturating_add(1);
        self.current_height = self.current_height.max(request.registered_at_height);
        let committee_id = state_sync_committee_id(&request, self.counters.committee_count);
        let record = StateSyncCommitteeRecord {
            committee_id: committee_id.clone(),
            request,
            status: CommitteeStatus::Active,
        };
        self.committees.insert(committee_id, record.clone());
        Ok(record)
    }

    pub fn publish_encrypted_fast_sync_snapshot(
        &mut self,
        request: PublishEncryptedFastSyncSnapshotRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<EncryptedFastSyncSnapshotRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.snapshots.len() >= self.config.max_snapshots {
            return Err("PQ state sync snapshot capacity exhausted".to_string());
        }
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "PQ state sync committee not found".to_string())?;
        if !committee.status.can_sync() || committee.request.lane != request.lane {
            return Err("PQ state sync committee cannot publish this snapshot".to_string());
        }
        self.insert_nullifier(&request.snapshot_nullifier)?;
        self.counters.snapshot_count = self.counters.snapshot_count.saturating_add(1);
        self.current_height = self.current_height.max(request.published_at_height);
        let snapshot_id = fast_sync_snapshot_id(&request, self.counters.snapshot_count);
        let record = EncryptedFastSyncSnapshotRecord {
            snapshot_id: snapshot_id.clone(),
            expires_at_height: request
                .published_at_height
                .saturating_add(self.config.snapshot_ttl_blocks),
            request,
            approved_weight_bps: 0,
            rejected_weight_bps: 0,
            status: SnapshotStatus::Encrypted,
            attestation_ids: Vec::new(),
            reservation_ids: Vec::new(),
            chunk_ids: Vec::new(),
            challenge_ids: Vec::new(),
        };
        self.snapshots.insert(snapshot_id, record.clone());
        Ok(record)
    }

    pub fn submit_committee_attestation(
        &mut self,
        request: SubmitCommitteeAttestationRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<CommitteeAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.attestations.len() >= self.config.max_attestations {
            return Err("PQ state sync attestation capacity exhausted".to_string());
        }
        {
            let snapshot = self
                .snapshots
                .get(&request.snapshot_id)
                .ok_or_else(|| "PQ state sync snapshot not found for attestation".to_string())?;
            if !snapshot.status.live() || request.attested_at_height >= snapshot.expires_at_height {
                return Err("PQ state sync snapshot cannot receive attestation".to_string());
            }
            if snapshot.request.committee_id != request.committee_id {
                return Err("PQ state sync attestation committee mismatch".to_string());
            }
        }
        self.insert_nullifier(&request.attestation_nullifier)?;
        self.counters.attestation_count = self.counters.attestation_count.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let attestation_id = committee_attestation_id(&request, self.counters.attestation_count);
        let record = CommitteeAttestationRecord {
            attestation_id: attestation_id.clone(),
            request: request.clone(),
        };
        if let Some(snapshot) = self.snapshots.get_mut(&request.snapshot_id) {
            match request.verdict {
                AttestationVerdict::Approve => {
                    snapshot.approved_weight_bps = snapshot
                        .approved_weight_bps
                        .saturating_add(request.attestation_weight_bps)
                        .min(PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS);
                }
                AttestationVerdict::Reject => {
                    snapshot.rejected_weight_bps = snapshot
                        .rejected_weight_bps
                        .saturating_add(request.attestation_weight_bps)
                        .min(PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_MAX_BPS);
                }
                AttestationVerdict::Abstain => {}
            }
            snapshot.attestation_ids.push(attestation_id.clone());
            if snapshot.approved_weight_bps >= self.config.fast_quorum_bps {
                snapshot.status = SnapshotStatus::Attested;
            } else if snapshot.rejected_weight_bps >= self.config.quorum_weight_bps {
                snapshot.status = SnapshotStatus::Challenged;
            }
        }
        self.attestations.insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_low_fee_snapshot_relay(
        &mut self,
        request: ReserveLowFeeSnapshotRelayRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<LowFeeSnapshotRelayReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.reservations.len() >= self.config.max_reservations {
            return Err("PQ state sync reservation capacity exhausted".to_string());
        }
        {
            let snapshot = self.snapshots.get(&request.snapshot_id).ok_or_else(|| {
                "PQ state sync snapshot not found for relay reservation".to_string()
            })?;
            if !snapshot.status.live() || request.reserved_at_height >= snapshot.expires_at_height {
                return Err("PQ state sync snapshot cannot reserve relay".to_string());
            }
        }
        self.insert_nullifier(&request.relay_nullifier)?;
        self.counters.reservation_count = self.counters.reservation_count.saturating_add(1);
        self.current_height = self.current_height.max(request.reserved_at_height);
        let reservation_id =
            low_fee_snapshot_relay_reservation_id(&request, self.counters.reservation_count);
        let record = LowFeeSnapshotRelayReservationRecord {
            reservation_id: reservation_id.clone(),
            expires_at_height: request
                .reserved_at_height
                .saturating_add(self.config.reservation_ttl_blocks),
            request: request.clone(),
            status: RelayReservationStatus::Reserved,
        };
        if let Some(snapshot) = self.snapshots.get_mut(&request.snapshot_id) {
            snapshot.status = SnapshotStatus::RelayReserved;
            snapshot.reservation_ids.push(reservation_id.clone());
        }
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn commit_state_chunk(
        &mut self,
        request: CommitStateChunkRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<StateChunkCommitmentRecord> {
        self.config.validate()?;
        request.validate()?;
        if self.chunks.len() >= self.config.max_chunks {
            return Err("PQ state sync chunk capacity exhausted".to_string());
        }
        {
            let snapshot = self
                .snapshots
                .get(&request.snapshot_id)
                .ok_or_else(|| "PQ state sync snapshot not found for chunk".to_string())?;
            if !snapshot.status.live() || request.committed_at_height >= snapshot.expires_at_height
            {
                return Err("PQ state sync snapshot cannot receive chunks".to_string());
            }
        }
        self.counters.chunk_count = self.counters.chunk_count.saturating_add(1);
        self.current_height = self.current_height.max(request.committed_at_height);
        let chunk_id = state_chunk_commitment_id(&request, self.counters.chunk_count);
        let record = StateChunkCommitmentRecord {
            chunk_id: chunk_id.clone(),
            request: request.clone(),
        };
        if let Some(snapshot) = self.snapshots.get_mut(&request.snapshot_id) {
            snapshot.status = SnapshotStatus::Chunked;
            snapshot.chunk_ids.push(chunk_id.clone());
        }
        self.chunks.insert(chunk_id, record.clone());
        Ok(record)
    }

    pub fn submit_challenge_receipt(
        &mut self,
        request: SubmitChallengeReceiptRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<ChallengeReceiptRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.challenges.len() >= self.config.max_challenges {
            return Err("PQ state sync challenge capacity exhausted".to_string());
        }
        {
            let snapshot = self
                .snapshots
                .get(&request.snapshot_id)
                .ok_or_else(|| "PQ state sync snapshot not found for challenge".to_string())?;
            if !snapshot.status.live() || request.challenged_at_height >= snapshot.expires_at_height
            {
                return Err("PQ state sync snapshot cannot receive challenge".to_string());
            }
        }
        self.insert_nullifier(&request.challenge_nullifier)?;
        self.counters.challenge_count = self.counters.challenge_count.saturating_add(1);
        self.current_height = self.current_height.max(request.challenged_at_height);
        let challenge_id = challenge_receipt_id(&request, self.counters.challenge_count);
        let record = ChallengeReceiptRecord {
            challenge_id: challenge_id.clone(),
            request: request.clone(),
        };
        if let Some(snapshot) = self.snapshots.get_mut(&request.snapshot_id) {
            if matches!(
                request.verdict,
                ChallengeVerdict::SnapshotInvalid | ChallengeVerdict::DataUnavailable
            ) {
                snapshot.status = SnapshotStatus::Challenged;
            }
            snapshot.challenge_ids.push(challenge_id.clone());
        }
        self.challenges.insert(challenge_id, record.clone());
        Ok(record)
    }

    pub fn finalize_sync_manifest(
        &mut self,
        request: FinalizeSyncManifestRequest,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<FinalizedSyncManifestRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.manifests.len() >= self.config.max_manifests {
            return Err("PQ state sync manifest capacity exhausted".to_string());
        }
        {
            let snapshot = self
                .snapshots
                .get(&request.snapshot_id)
                .ok_or_else(|| "PQ state sync snapshot not found for manifest".to_string())?;
            if request.finalized_at_height >= snapshot.expires_at_height {
                return Err("PQ state sync snapshot expired before manifest".to_string());
            }
            if snapshot.approved_weight_bps < self.config.fast_quorum_bps {
                return Err("PQ state sync snapshot lacks fast quorum".to_string());
            }
            if matches!(
                snapshot.status,
                SnapshotStatus::Challenged | SnapshotStatus::Finalized
            ) {
                return Err("PQ state sync snapshot cannot finalize".to_string());
            }
        }
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "PQ state sync reservation not found for manifest".to_string())?;
        if reservation.request.snapshot_id != request.snapshot_id {
            return Err("PQ state sync manifest reservation mismatch".to_string());
        }
        if request.finalized_at_height >= reservation.expires_at_height {
            return Err("PQ state sync relay reservation expired before manifest".to_string());
        }
        self.counters.manifest_count = self.counters.manifest_count.saturating_add(1);
        self.current_height = self.current_height.max(request.finalized_at_height);
        let manifest_id = finalized_sync_manifest_id(&request, self.counters.manifest_count);
        let record = FinalizedSyncManifestRecord {
            manifest_id: manifest_id.clone(),
            request: request.clone(),
        };
        if let Some(snapshot) = self.snapshots.get_mut(&request.snapshot_id) {
            snapshot.status = SnapshotStatus::Finalized;
        }
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = RelayReservationStatus::Settled;
        }
        self.manifests.insert(manifest_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-STATE-SYNC-COMMITTEE-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = root_from_record(
            "PRIVATE-L2-PQ-STATE-SYNC-COMMITTEE-COUNTERS",
            &self.counters.public_record(),
        );
        let committee_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-COMMITTEES",
            &self
                .committees
                .values()
                .map(StateSyncCommitteeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let snapshot_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-SNAPSHOTS",
            &self
                .snapshots
                .values()
                .map(EncryptedFastSyncSnapshotRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-ATTESTATIONS",
            &self
                .attestations
                .values()
                .map(CommitteeAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let reservation_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-RELAY-RESERVATIONS",
            &self
                .reservations
                .values()
                .map(LowFeeSnapshotRelayReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let chunk_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-CHUNKS",
            &self
                .chunks
                .values()
                .map(StateChunkCommitmentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let challenge_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-CHALLENGES",
            &self
                .challenges
                .values()
                .map(ChallengeReceiptRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let manifest_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-MANIFESTS",
            &self
                .manifests
                .values()
                .map(FinalizedSyncManifestRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-STATE-SYNC-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-STATE-SYNC-COMMITTEE-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "config_root": config_root,
                "counter_root": counter_root,
                "committee_root": committee_root,
                "snapshot_root": snapshot_root,
                "attestation_root": attestation_root,
                "reservation_root": reservation_root,
                "chunk_root": chunk_root,
                "challenge_root": challenge_root,
                "manifest_root": manifest_root,
                "nullifier_root": nullifier_root,
            }),
        );
        Roots {
            config_root,
            counter_root,
            committee_root,
            snapshot_root,
            attestation_root,
            reservation_root,
            chunk_root,
            challenge_root,
            manifest_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_state_sync_committee_runtime",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PQ_SUITE,
            "encrypted_sync_suite": PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_ENCRYPTED_SYNC_SUITE,
            "low_fee_relay_scheme": PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_LOW_FEE_RELAY_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "committee_ids": self.committees.keys().cloned().collect::<Vec<_>>(),
            "snapshot_ids": self.snapshots.keys().cloned().collect::<Vec<_>>(),
            "attestation_ids": self.attestations.keys().cloned().collect::<Vec<_>>(),
            "reservation_ids": self.reservations.keys().cloned().collect::<Vec<_>>(),
            "chunk_ids": self.chunks.keys().cloned().collect::<Vec<_>>(),
            "challenge_ids": self.challenges.keys().cloned().collect::<Vec<_>>(),
            "manifest_ids": self.manifests.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn insert_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
        let nullifier_root = root_from_record(
            "PRIVATE-L2-PQ-STATE-SYNC-NULLIFIER",
            &json!({ "nullifier": nullifier }),
        );
        if !self.consumed_nullifiers.insert(nullifier_root) {
            return Err("PQ state sync nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_count =
            self.counters.consumed_nullifier_count.saturating_add(1);
        Ok(())
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_STATE_SYNC_COMMITTEE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-PQ-STATE-SYNC-PAYLOAD-{domain}"),
        payload,
    )
}

pub fn private_l2_pq_state_sync_committee_state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet() -> PrivateL2PqStateSyncCommitteeRuntimeResult<State> {
    State::devnet()
}

pub fn state_sync_committee_id(
    request: &RegisterStateSyncCommitteeRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-COMMITTEE-ID",
        &json!({
            "counter": counter,
            "lane": request.lane.as_str(),
            "operator_set_root": request.operator_set_root,
            "threshold_key_root": request.threshold_key_root,
            "epoch": request.epoch,
        }),
    )
}

pub fn fast_sync_snapshot_id(
    request: &PublishEncryptedFastSyncSnapshotRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-SNAPSHOT-ID",
        &json!({
            "counter": counter,
            "committee_id": request.committee_id,
            "lane": request.lane.as_str(),
            "source_state_root": request.source_state_root,
            "target_state_root": request.target_state_root,
            "encrypted_snapshot_root": request.encrypted_snapshot_root,
            "snapshot_nullifier": request.snapshot_nullifier,
        }),
    )
}

pub fn committee_attestation_id(
    request: &SubmitCommitteeAttestationRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "snapshot_id": request.snapshot_id,
            "committee_id": request.committee_id,
            "attester_commitment": request.attester_commitment,
            "verdict": request.verdict.as_str(),
            "attestation_nullifier": request.attestation_nullifier,
        }),
    )
}

pub fn low_fee_snapshot_relay_reservation_id(
    request: &ReserveLowFeeSnapshotRelayRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-RELAY-RESERVATION-ID",
        &json!({
            "counter": counter,
            "snapshot_id": request.snapshot_id,
            "relayer_commitment": request.relayer_commitment,
            "relay_window_root": request.relay_window_root,
            "relay_nullifier": request.relay_nullifier,
        }),
    )
}

pub fn state_chunk_commitment_id(request: &CommitStateChunkRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-CHUNK-ID",
        &json!({
            "counter": counter,
            "snapshot_id": request.snapshot_id,
            "chunk_index": request.chunk_index,
            "chunk_count": request.chunk_count,
            "chunk_commitment_root": request.chunk_commitment_root,
        }),
    )
}

pub fn challenge_receipt_id(request: &SubmitChallengeReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-CHALLENGE-ID",
        &json!({
            "counter": counter,
            "snapshot_id": request.snapshot_id,
            "challenger_commitment": request.challenger_commitment,
            "challenged_chunk_root": request.challenged_chunk_root,
            "challenge_nullifier": request.challenge_nullifier,
            "verdict": request.verdict.as_str(),
        }),
    )
}

pub fn finalized_sync_manifest_id(request: &FinalizeSyncManifestRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-STATE-SYNC-MANIFEST-ID",
        &json!({
            "counter": counter,
            "snapshot_id": request.snapshot_id,
            "reservation_id": request.reservation_id,
            "manifest_root": request.manifest_root,
            "finalized_state_root": request.finalized_state_root,
            "finalized_at_height": request.finalized_at_height,
        }),
    )
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    config: &Config,
) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
    if privacy_set_size < config.min_privacy_set_size {
        return Err("PQ state sync privacy set below minimum".to_string());
    }
    if pq_security_bits < config.min_pq_security_bits {
        return Err("PQ state sync PQ security bits below minimum".to_string());
    }
    Ok(())
}

fn required(field: &str, value: &str) -> PrivateL2PqStateSyncCommitteeRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("PQ state sync field {field} is required"));
    }
    Ok(())
}
