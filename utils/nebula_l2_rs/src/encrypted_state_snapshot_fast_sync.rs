use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type EncryptedStateSnapshotFastSyncResult<T> = Result<T, String>;

pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_PROTOCOL_VERSION: &str =
    "nebula-encrypted-state-snapshot-fast-sync-v1";
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_SCHEMA_VERSION: u64 = 1;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MANIFEST_CIPHER_SUITE: &str =
    "xchacha20-poly1305-ml-kem-1024-sealed-manifest-v1";
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_PQ_ATTESTATION_SUITE: &str =
    "ml-dsa-87-slh-dsa-shake256-snapshot-committee-v1";
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_ERASURE_SUITE: &str =
    "reed-solomon-kzg-sampling-private-shards-v1";
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_REPAIR_PROOF_SUITE: &str =
    "zk-repair-receipt-availability-delta-v1";
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_TARGET_LATENCY_MS: u64 = 450;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_MAX_MANIFEST_BYTES: u64 = 262_144;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_MAX_SHARDS_PER_MANIFEST: u32 = 4_096;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 1_500;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_PRIVACY_BUDGET_BPS: u64 = 1_200;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_BPS: u64 = 10_000;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_LANES: usize = 64;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_MANIFESTS: usize = 16_384;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SHARDS: usize = 524_288;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_ATTESTATIONS: usize = 131_072;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SAMPLING_RECEIPTS: usize = 1_048_576;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SPONSORS: usize = 65_536;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_TICKETS: usize = 262_144;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_REPAIRS: usize = 262_144;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_CHALLENGES: usize = 65_536;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SLASHING_EVIDENCE: usize = 65_536;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_CHECKPOINTS: usize = 65_536;
pub const ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_PUBLIC_RECORDS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotLaneKind {
    MoneroWalletSync,
    PrivateDefi,
    SmartContractStorage,
    LowFeeTransfer,
    BridgeExit,
    EmergencyRepair,
}

impl SnapshotLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroWalletSync => "monero_wallet_sync",
            Self::PrivateDefi => "private_defi",
            Self::SmartContractStorage => "smart_contract_storage",
            Self::LowFeeTransfer => "low_fee_transfer",
            Self::BridgeExit => "bridge_exit",
            Self::EmergencyRepair => "emergency_repair",
        }
    }

    pub fn private_state_heavy(self) -> bool {
        matches!(
            self,
            Self::MoneroWalletSync | Self::PrivateDefi | Self::SmartContractStorage
        )
    }

    pub fn latency_critical(self) -> bool {
        matches!(
            self,
            Self::LowFeeTransfer | Self::BridgeExit | Self::EmergencyRepair
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudClaimKind {
    InvalidManifestRoot,
    WithheldShard,
    BadErasureCoding,
    InsufficientPqWeight,
    SponsorOvercharge,
    RepairPoisoning,
}

impl FraudClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidManifestRoot => "invalid_manifest_root",
            Self::WithheldShard => "withheld_shard",
            Self::BadErasureCoding => "bad_erasure_coding",
            Self::InsufficientPqWeight => "insufficient_pq_weight",
            Self::SponsorOvercharge => "sponsor_overcharge",
            Self::RepairPoisoning => "repair_poisoning",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffenseKind {
    EquivocatedManifest,
    FalseAvailabilityVote,
    InvalidRepair,
    FeeTheft,
    PrivacyBudgetLeak,
    ChallengeNonResponse,
}

impl OffenseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EquivocatedManifest => "equivocated_manifest",
            Self::FalseAvailabilityVote => "false_availability_vote",
            Self::InvalidRepair => "invalid_repair",
            Self::FeeTheft => "fee_theft",
            Self::PrivacyBudgetLeak => "privacy_budget_leak",
            Self::ChallengeNonResponse => "challenge_non_response",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateSnapshotFastSyncConfig {
    pub chain_id: String,
    pub protocol_version: String,
    pub min_pq_security_bits: u16,
    pub challenge_window_blocks: u64,
    pub target_latency_ms: u64,
    pub max_manifest_bytes: u64,
    pub max_shards_per_manifest: u32,
    pub low_fee_cap_micro_units: u64,
    pub privacy_budget_bps: u64,
    pub erasure_data_shards: u16,
    pub erasure_parity_shards: u16,
    pub min_sampling_receipts_per_shard: u16,
    pub max_lanes: usize,
    pub max_manifests: usize,
    pub max_shards: usize,
    pub max_attestations: usize,
    pub max_sampling_receipts: usize,
    pub max_sponsors: usize,
    pub max_tickets: usize,
    pub max_repairs: usize,
    pub max_challenges: usize,
    pub max_slashing_evidence: usize,
    pub max_checkpoints: usize,
    pub max_public_records: usize,
}

pub type Config = EncryptedStateSnapshotFastSyncConfig;

impl Default for EncryptedStateSnapshotFastSyncConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl EncryptedStateSnapshotFastSyncConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_PROTOCOL_VERSION.to_string(),
            min_pq_security_bits: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_MIN_PQ_SECURITY_BITS,
            challenge_window_blocks:
                ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            target_latency_ms: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_TARGET_LATENCY_MS,
            max_manifest_bytes: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_MAX_MANIFEST_BYTES,
            max_shards_per_manifest:
                ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_MAX_SHARDS_PER_MANIFEST,
            low_fee_cap_micro_units:
                ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            privacy_budget_bps: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_DEFAULT_PRIVACY_BUDGET_BPS,
            erasure_data_shards: 16,
            erasure_parity_shards: 8,
            min_sampling_receipts_per_shard: 3,
            max_lanes: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_LANES,
            max_manifests: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_MANIFESTS,
            max_shards: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SHARDS,
            max_attestations: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_ATTESTATIONS,
            max_sampling_receipts: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SAMPLING_RECEIPTS,
            max_sponsors: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SPONSORS,
            max_tickets: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_TICKETS,
            max_repairs: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_REPAIRS,
            max_challenges: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_CHALLENGES,
            max_slashing_evidence: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_SLASHING_EVIDENCE,
            max_checkpoints: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_CHECKPOINTS,
            max_public_records: ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_at_least(
            "min_pq_security_bits",
            self.min_pq_security_bits as u64,
            128,
        )?;
        ensure_at_least("challenge_window_blocks", self.challenge_window_blocks, 1)?;
        ensure_at_least("target_latency_ms", self.target_latency_ms, 1)?;
        ensure_at_least("max_manifest_bytes", self.max_manifest_bytes, 1024)?;
        ensure_at_least(
            "max_shards_per_manifest",
            self.max_shards_per_manifest as u64,
            1,
        )?;
        ensure_at_most(
            "privacy_budget_bps",
            self.privacy_budget_bps,
            ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_BPS,
        )?;
        ensure_at_least("erasure_data_shards", self.erasure_data_shards as u64, 1)?;
        ensure_at_least(
            "erasure_parity_shards",
            self.erasure_parity_shards as u64,
            1,
        )?;
        ensure_at_least(
            "min_sampling_receipts_per_shard",
            self.min_sampling_receipts_per_shard as u64,
            1,
        )?;
        ensure_capacity_current(
            "max_lanes",
            self.max_lanes,
            ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MAX_LANES,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_SCHEMA_VERSION,
            "hash_suite": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_HASH_SUITE,
            "manifest_cipher_suite": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_MANIFEST_CIPHER_SUITE,
            "pq_attestation_suite": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_PQ_ATTESTATION_SUITE,
            "erasure_suite": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_ERASURE_SUITE,
            "repair_proof_suite": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_REPAIR_PROOF_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "challenge_window_blocks": self.challenge_window_blocks,
            "target_latency_ms": self.target_latency_ms,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_shards_per_manifest": self.max_shards_per_manifest,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "privacy_budget_bps": self.privacy_budget_bps,
            "erasure_data_shards": self.erasure_data_shards,
            "erasure_parity_shards": self.erasure_parity_shards,
            "min_sampling_receipts_per_shard": self.min_sampling_receipts_per_shard,
            "max_lanes": self.max_lanes,
            "max_manifests": self.max_manifests,
            "max_shards": self.max_shards,
            "max_attestations": self.max_attestations,
            "max_sampling_receipts": self.max_sampling_receipts,
            "max_sponsors": self.max_sponsors,
            "max_tickets": self.max_tickets,
            "max_repairs": self.max_repairs,
            "max_challenges": self.max_challenges,
            "max_slashing_evidence": self.max_slashing_evidence,
            "max_checkpoints": self.max_checkpoints,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotLane {
    pub lane_id: String,
    pub lane_kind: SnapshotLaneKind,
    pub operator_committee_id: String,
    pub min_pq_security_bits: u16,
    pub target_latency_ms: u64,
    pub max_manifest_bytes: u64,
    pub max_shards_per_manifest: u32,
    pub low_fee_cap_micro_units: u64,
    pub privacy_budget_bps: u64,
    pub enabled: bool,
}

impl SnapshotLane {
    pub fn deterministic_id(
        lane_kind: SnapshotLaneKind,
        operator_committee_id: &str,
        min_pq_security_bits: u16,
        target_latency_ms: u64,
        max_manifest_bytes: u64,
        max_shards_per_manifest: u32,
        low_fee_cap_micro_units: u64,
        privacy_budget_bps: u64,
        enabled: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SNAPSHOTLANE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_kind.as_str()),
                HashPart::Str(operator_committee_id),
                HashPart::Int(min_pq_security_bits as i128),
                HashPart::Int(target_latency_ms as i128),
                HashPart::Int(max_manifest_bytes as i128),
                HashPart::Int(max_shards_per_manifest as i128),
                HashPart::Int(low_fee_cap_micro_units as i128),
                HashPart::Int(privacy_budget_bps as i128),
                HashPart::Str(if enabled { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "operator_committee_id": self.operator_committee_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_latency_ms": self.target_latency_ms,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_shards_per_manifest": self.max_shards_per_manifest,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "privacy_budget_bps": self.privacy_budget_bps,
            "enabled": self.enabled,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SNAPSHOTLANE", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_non_empty("operator_committee_id", &self.operator_committee_id)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedManifest {
    pub manifest_id: String,
    pub lane_id: String,
    pub epoch: u64,
    pub snapshot_height: u64,
    pub parent_state_root: String,
    pub encrypted_header_root: String,
    pub shard_commitment_root: String,
    pub erasure_metadata_root: String,
    pub sampling_plan_root: String,
    pub fee_sponsor_id: String,
    pub challenge_deadline_height: u64,
    pub manifest_size_bytes: u64,
    pub shard_count: u32,
    pub cipher_suite: String,
}

impl EncryptedManifest {
    pub fn deterministic_id(
        lane_id: &str,
        epoch: u64,
        snapshot_height: u64,
        parent_state_root: &str,
        encrypted_header_root: &str,
        shard_commitment_root: &str,
        erasure_metadata_root: &str,
        sampling_plan_root: &str,
        fee_sponsor_id: &str,
        challenge_deadline_height: u64,
        manifest_size_bytes: u64,
        shard_count: u32,
        cipher_suite: &str,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-ENCRYPTEDMANIFEST-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane_id),
                HashPart::Int(epoch as i128),
                HashPart::Int(snapshot_height as i128),
                HashPart::Str(parent_state_root),
                HashPart::Str(encrypted_header_root),
                HashPart::Str(shard_commitment_root),
                HashPart::Str(erasure_metadata_root),
                HashPart::Str(sampling_plan_root),
                HashPart::Str(fee_sponsor_id),
                HashPart::Int(challenge_deadline_height as i128),
                HashPart::Int(manifest_size_bytes as i128),
                HashPart::Int(shard_count as i128),
                HashPart::Str(cipher_suite),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "lane_id": self.lane_id,
            "epoch": self.epoch,
            "snapshot_height": self.snapshot_height,
            "parent_state_root": self.parent_state_root,
            "encrypted_header_root": self.encrypted_header_root,
            "shard_commitment_root": self.shard_commitment_root,
            "erasure_metadata_root": self.erasure_metadata_root,
            "sampling_plan_root": self.sampling_plan_root,
            "fee_sponsor_id": self.fee_sponsor_id,
            "challenge_deadline_height": self.challenge_deadline_height,
            "manifest_size_bytes": self.manifest_size_bytes,
            "shard_count": self.shard_count,
            "cipher_suite": self.cipher_suite,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("ENCRYPTEDMANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_non_empty("parent_state_root", &self.parent_state_root)?;
        ensure_non_empty("encrypted_header_root", &self.encrypted_header_root)?;
        ensure_non_empty("shard_commitment_root", &self.shard_commitment_root)?;
        ensure_non_empty("erasure_metadata_root", &self.erasure_metadata_root)?;
        ensure_non_empty("sampling_plan_root", &self.sampling_plan_root)?;
        ensure_non_empty("fee_sponsor_id", &self.fee_sponsor_id)?;
        ensure_non_empty("cipher_suite", &self.cipher_suite)?;
        ensure_at_least("shard_count", self.shard_count as u64, 1)?;
        ensure_at_least("manifest_size_bytes", self.manifest_size_bytes, 1)?;
        ensure_at_least(
            "challenge_deadline_height",
            self.challenge_deadline_height,
            self.snapshot_height.saturating_add(1),
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShardCommitment {
    pub shard_id: String,
    pub manifest_id: String,
    pub shard_index: u32,
    pub encrypted_payload_root: String,
    pub state_key_range_commitment: String,
    pub nullifier_range_commitment: String,
    pub contract_storage_commitment: String,
    pub monero_view_tag_hint_root: String,
    pub byte_len: u64,
    pub erasure_group: u32,
    pub required_samples: u16,
}

impl ShardCommitment {
    pub fn deterministic_id(
        manifest_id: &str,
        shard_index: u32,
        encrypted_payload_root: &str,
        state_key_range_commitment: &str,
        nullifier_range_commitment: &str,
        contract_storage_commitment: &str,
        monero_view_tag_hint_root: &str,
        byte_len: u64,
        erasure_group: u32,
        required_samples: u16,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SHARDCOMMITMENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(manifest_id),
                HashPart::Int(shard_index as i128),
                HashPart::Str(encrypted_payload_root),
                HashPart::Str(state_key_range_commitment),
                HashPart::Str(nullifier_range_commitment),
                HashPart::Str(contract_storage_commitment),
                HashPart::Str(monero_view_tag_hint_root),
                HashPart::Int(byte_len as i128),
                HashPart::Int(erasure_group as i128),
                HashPart::Int(required_samples as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "manifest_id": self.manifest_id,
            "shard_index": self.shard_index,
            "encrypted_payload_root": self.encrypted_payload_root,
            "state_key_range_commitment": self.state_key_range_commitment,
            "nullifier_range_commitment": self.nullifier_range_commitment,
            "contract_storage_commitment": self.contract_storage_commitment,
            "monero_view_tag_hint_root": self.monero_view_tag_hint_root,
            "byte_len": self.byte_len,
            "erasure_group": self.erasure_group,
            "required_samples": self.required_samples,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SHARDCOMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("shard_id", &self.shard_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("encrypted_payload_root", &self.encrypted_payload_root)?;
        ensure_non_empty(
            "state_key_range_commitment",
            &self.state_key_range_commitment,
        )?;
        ensure_non_empty(
            "nullifier_range_commitment",
            &self.nullifier_range_commitment,
        )?;
        ensure_non_empty(
            "contract_storage_commitment",
            &self.contract_storage_commitment,
        )?;
        ensure_non_empty("monero_view_tag_hint_root", &self.monero_view_tag_hint_root)?;
        ensure_at_least("byte_len", self.byte_len, 1)?;
        ensure_at_least("required_samples", self.required_samples as u64, 1)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSnapshotAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub manifest_id: String,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub signed_state_root: String,
    pub security_bits: u16,
    pub signer_weight: u64,
    pub threshold_weight: u64,
    pub height: u64,
}

impl PqSnapshotAttestation {
    pub fn deterministic_id(
        committee_id: &str,
        manifest_id: &str,
        signer_set_root: &str,
        pq_signature_root: &str,
        transcript_root: &str,
        signed_state_root: &str,
        security_bits: u16,
        signer_weight: u64,
        threshold_weight: u64,
        height: u64,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-PQSNAPSHOTATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(committee_id),
                HashPart::Str(manifest_id),
                HashPart::Str(signer_set_root),
                HashPart::Str(pq_signature_root),
                HashPart::Str(transcript_root),
                HashPart::Str(signed_state_root),
                HashPart::Int(security_bits as i128),
                HashPart::Int(signer_weight as i128),
                HashPart::Int(threshold_weight as i128),
                HashPart::Int(height as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "manifest_id": self.manifest_id,
            "signer_set_root": self.signer_set_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "signed_state_root": self.signed_state_root,
            "security_bits": self.security_bits,
            "signer_weight": self.signer_weight,
            "threshold_weight": self.threshold_weight,
            "height": self.height,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("PQSNAPSHOTATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("attestation_id", &self.attestation_id)?;
        ensure_non_empty("committee_id", &self.committee_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("signer_set_root", &self.signer_set_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("transcript_root", &self.transcript_root)?;
        ensure_non_empty("signed_state_root", &self.signed_state_root)?;
        ensure_at_least("security_bits", self.security_bits as u64, 128)?;
        ensure_at_least("threshold_weight", self.threshold_weight, 1)?;
        ensure_at_least("signer_weight", self.signer_weight, self.threshold_weight)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SamplingReceipt {
    pub receipt_id: String,
    pub manifest_id: String,
    pub shard_id: String,
    pub sampler_id: String,
    pub sample_index: u32,
    pub sample_commitment: String,
    pub availability_response_root: String,
    pub latency_ms: u64,
    pub fee_micro_units: u64,
    pub height: u64,
    pub accepted: bool,
}

impl SamplingReceipt {
    pub fn deterministic_id(
        manifest_id: &str,
        shard_id: &str,
        sampler_id: &str,
        sample_index: u32,
        sample_commitment: &str,
        availability_response_root: &str,
        latency_ms: u64,
        fee_micro_units: u64,
        height: u64,
        accepted: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SAMPLINGRECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(manifest_id),
                HashPart::Str(shard_id),
                HashPart::Str(sampler_id),
                HashPart::Int(sample_index as i128),
                HashPart::Str(sample_commitment),
                HashPart::Str(availability_response_root),
                HashPart::Int(latency_ms as i128),
                HashPart::Int(fee_micro_units as i128),
                HashPart::Int(height as i128),
                HashPart::Str(if accepted { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "manifest_id": self.manifest_id,
            "shard_id": self.shard_id,
            "sampler_id": self.sampler_id,
            "sample_index": self.sample_index,
            "sample_commitment": self.sample_commitment,
            "availability_response_root": self.availability_response_root,
            "latency_ms": self.latency_ms,
            "fee_micro_units": self.fee_micro_units,
            "height": self.height,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SAMPLINGRECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("shard_id", &self.shard_id)?;
        ensure_non_empty("sampler_id", &self.sampler_id)?;
        ensure_non_empty("sample_commitment", &self.sample_commitment)?;
        ensure_non_empty(
            "availability_response_root",
            &self.availability_response_root,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub balance_micro_units: u64,
    pub reserved_micro_units: u64,
    pub max_fee_per_snapshot_micro_units: u64,
    pub privacy_pool_root: String,
    pub credential_root: String,
    pub nonce: u64,
    pub active: bool,
}

impl SponsorAccount {
    pub fn deterministic_id(
        owner_commitment: &str,
        asset_id: &str,
        balance_micro_units: u64,
        reserved_micro_units: u64,
        max_fee_per_snapshot_micro_units: u64,
        privacy_pool_root: &str,
        credential_root: &str,
        nonce: u64,
        active: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SPONSORACCOUNT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(owner_commitment),
                HashPart::Str(asset_id),
                HashPart::Int(balance_micro_units as i128),
                HashPart::Int(reserved_micro_units as i128),
                HashPart::Int(max_fee_per_snapshot_micro_units as i128),
                HashPart::Str(privacy_pool_root),
                HashPart::Str(credential_root),
                HashPart::Int(nonce as i128),
                HashPart::Str(if active { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "balance_micro_units": self.balance_micro_units,
            "reserved_micro_units": self.reserved_micro_units,
            "max_fee_per_snapshot_micro_units": self.max_fee_per_snapshot_micro_units,
            "privacy_pool_root": self.privacy_pool_root,
            "credential_root": self.credential_root,
            "nonce": self.nonce,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SPONSORACCOUNT", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("privacy_pool_root", &self.privacy_pool_root)?;
        ensure_non_empty("credential_root", &self.credential_root)?;
        if self.reserved_micro_units > self.balance_micro_units {
            return Err("reserved sponsor balance exceeds available balance".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorshipTicket {
    pub ticket_id: String,
    pub sponsor_id: String,
    pub manifest_id: String,
    pub max_fee_micro_units: u64,
    pub charged_fee_micro_units: u64,
    pub rebate_commitment: String,
    pub anonymous_budget_nullifier: String,
    pub issued_height: u64,
    pub settled: bool,
}

impl SponsorshipTicket {
    pub fn deterministic_id(
        sponsor_id: &str,
        manifest_id: &str,
        max_fee_micro_units: u64,
        charged_fee_micro_units: u64,
        rebate_commitment: &str,
        anonymous_budget_nullifier: &str,
        issued_height: u64,
        settled: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SPONSORSHIPTICKET-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(sponsor_id),
                HashPart::Str(manifest_id),
                HashPart::Int(max_fee_micro_units as i128),
                HashPart::Int(charged_fee_micro_units as i128),
                HashPart::Str(rebate_commitment),
                HashPart::Str(anonymous_budget_nullifier),
                HashPart::Int(issued_height as i128),
                HashPart::Str(if settled { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "sponsor_id": self.sponsor_id,
            "manifest_id": self.manifest_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "rebate_commitment": self.rebate_commitment,
            "anonymous_budget_nullifier": self.anonymous_budget_nullifier,
            "issued_height": self.issued_height,
            "settled": self.settled,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SPONSORSHIPTICKET", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("ticket_id", &self.ticket_id)?;
        ensure_non_empty("sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("rebate_commitment", &self.rebate_commitment)?;
        ensure_non_empty(
            "anonymous_budget_nullifier",
            &self.anonymous_budget_nullifier,
        )?;
        if self.charged_fee_micro_units > self.max_fee_micro_units {
            return Err("charged snapshot sponsorship fee exceeds ticket cap".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepairReceipt {
    pub repair_id: String,
    pub manifest_id: String,
    pub shard_id: String,
    pub provider_id: String,
    pub repair_payload_root: String,
    pub repair_proof_root: String,
    pub before_availability_root: String,
    pub after_availability_root: String,
    pub fee_micro_units: u64,
    pub height: u64,
    pub accepted: bool,
}

impl RepairReceipt {
    pub fn deterministic_id(
        manifest_id: &str,
        shard_id: &str,
        provider_id: &str,
        repair_payload_root: &str,
        repair_proof_root: &str,
        before_availability_root: &str,
        after_availability_root: &str,
        fee_micro_units: u64,
        height: u64,
        accepted: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-REPAIRRECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(manifest_id),
                HashPart::Str(shard_id),
                HashPart::Str(provider_id),
                HashPart::Str(repair_payload_root),
                HashPart::Str(repair_proof_root),
                HashPart::Str(before_availability_root),
                HashPart::Str(after_availability_root),
                HashPart::Int(fee_micro_units as i128),
                HashPart::Int(height as i128),
                HashPart::Str(if accepted { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "repair_id": self.repair_id,
            "manifest_id": self.manifest_id,
            "shard_id": self.shard_id,
            "provider_id": self.provider_id,
            "repair_payload_root": self.repair_payload_root,
            "repair_proof_root": self.repair_proof_root,
            "before_availability_root": self.before_availability_root,
            "after_availability_root": self.after_availability_root,
            "fee_micro_units": self.fee_micro_units,
            "height": self.height,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("REPAIRRECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("repair_id", &self.repair_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("shard_id", &self.shard_id)?;
        ensure_non_empty("provider_id", &self.provider_id)?;
        ensure_non_empty("repair_payload_root", &self.repair_payload_root)?;
        ensure_non_empty("repair_proof_root", &self.repair_proof_root)?;
        ensure_non_empty("before_availability_root", &self.before_availability_root)?;
        ensure_non_empty("after_availability_root", &self.after_availability_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudChallenge {
    pub challenge_id: String,
    pub manifest_id: String,
    pub challenger_id: String,
    pub claim_kind: FraudClaimKind,
    pub evidence_root: String,
    pub bond_micro_units: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub resolved: bool,
}

impl FraudChallenge {
    pub fn deterministic_id(
        manifest_id: &str,
        challenger_id: &str,
        claim_kind: FraudClaimKind,
        evidence_root: &str,
        bond_micro_units: u64,
        opened_height: u64,
        deadline_height: u64,
        resolved: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-FRAUDCHALLENGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(manifest_id),
                HashPart::Str(challenger_id),
                HashPart::Str(claim_kind.as_str()),
                HashPart::Str(evidence_root),
                HashPart::Int(bond_micro_units as i128),
                HashPart::Int(opened_height as i128),
                HashPart::Int(deadline_height as i128),
                HashPart::Str(if resolved { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "manifest_id": self.manifest_id,
            "challenger_id": self.challenger_id,
            "claim_kind": self.claim_kind.as_str(),
            "evidence_root": self.evidence_root,
            "bond_micro_units": self.bond_micro_units,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "resolved": self.resolved,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("FRAUDCHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("challenge_id", &self.challenge_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("challenger_id", &self.challenger_id)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_at_least(
            "deadline_height",
            self.deadline_height,
            self.opened_height.saturating_add(1),
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub challenge_id: String,
    pub offender_id: String,
    pub offense_kind: OffenseKind,
    pub conflicting_root: String,
    pub witness_root: String,
    pub slash_amount_micro_units: u64,
    pub height: u64,
    pub executed: bool,
}

impl SlashingEvidence {
    pub fn deterministic_id(
        challenge_id: &str,
        offender_id: &str,
        offense_kind: OffenseKind,
        conflicting_root: &str,
        witness_root: &str,
        slash_amount_micro_units: u64,
        height: u64,
        executed: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SLASHINGEVIDENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(challenge_id),
                HashPart::Str(offender_id),
                HashPart::Str(offense_kind.as_str()),
                HashPart::Str(conflicting_root),
                HashPart::Str(witness_root),
                HashPart::Int(slash_amount_micro_units as i128),
                HashPart::Int(height as i128),
                HashPart::Str(if executed { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "challenge_id": self.challenge_id,
            "offender_id": self.offender_id,
            "offense_kind": self.offense_kind.as_str(),
            "conflicting_root": self.conflicting_root,
            "witness_root": self.witness_root,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "height": self.height,
            "executed": self.executed,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SLASHINGEVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("evidence_id", &self.evidence_id)?;
        ensure_non_empty("challenge_id", &self.challenge_id)?;
        ensure_non_empty("offender_id", &self.offender_id)?;
        ensure_non_empty("conflicting_root", &self.conflicting_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotCheckpoint {
    pub checkpoint_id: String,
    pub manifest_id: String,
    pub state_root: String,
    pub attestation_root: String,
    pub sampling_root: String,
    pub repair_root: String,
    pub sponsor_root: String,
    pub height: u64,
    pub finalized: bool,
}

impl SnapshotCheckpoint {
    pub fn deterministic_id(
        manifest_id: &str,
        state_root: &str,
        attestation_root: &str,
        sampling_root: &str,
        repair_root: &str,
        sponsor_root: &str,
        height: u64,
        finalized: bool,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-SNAPSHOTCHECKPOINT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(manifest_id),
                HashPart::Str(state_root),
                HashPart::Str(attestation_root),
                HashPart::Str(sampling_root),
                HashPart::Str(repair_root),
                HashPart::Str(sponsor_root),
                HashPart::Int(height as i128),
                HashPart::Str(if finalized { "true" } else { "false" }),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "manifest_id": self.manifest_id,
            "state_root": self.state_root,
            "attestation_root": self.attestation_root,
            "sampling_root": self.sampling_root,
            "repair_root": self.repair_root,
            "sponsor_root": self.sponsor_root,
            "height": self.height,
            "finalized": self.finalized,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("SNAPSHOTCHECKPOINT", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("checkpoint_id", &self.checkpoint_id)?;
        ensure_non_empty("manifest_id", &self.manifest_id)?;
        ensure_non_empty("state_root", &self.state_root)?;
        ensure_non_empty("attestation_root", &self.attestation_root)?;
        ensure_non_empty("sampling_root", &self.sampling_root)?;
        ensure_non_empty("repair_root", &self.repair_root)?;
        ensure_non_empty("sponsor_root", &self.sponsor_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicAuditRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root_after: String,
    pub height: u64,
    pub redaction_root: String,
}

impl PublicAuditRecord {
    pub fn deterministic_id(
        record_kind: &str,
        subject_id: &str,
        payload_root: &str,
        state_root_after: &str,
        height: u64,
        redaction_root: &str,
    ) -> String {
        domain_hash(
            "ENCRYPTED-SNAPSHOT-PUBLICAUDITRECORD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(payload_root),
                HashPart::Str(state_root_after),
                HashPart::Int(height as i128),
                HashPart::Str(redaction_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root_after": self.state_root_after,
            "height": self.height,
            "redaction_root": self.redaction_root,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("PUBLICAUDITRECORD", &self.public_record())
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_non_empty("record_id", &self.record_id)?;
        ensure_non_empty("record_kind", &self.record_kind)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("payload_root", &self.payload_root)?;
        ensure_non_empty("state_root_after", &self.state_root_after)?;
        ensure_non_empty("redaction_root", &self.redaction_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateSnapshotFastSyncRoots {
    pub config_root: String,
    pub lane_root: String,
    pub manifest_root: String,
    pub shard_root: String,
    pub attestation_root: String,
    pub sampling_receipt_root: String,
    pub sponsor_root: String,
    pub sponsorship_ticket_root: String,
    pub repair_receipt_root: String,
    pub fraud_challenge_root: String,
    pub slashing_evidence_root: String,
    pub checkpoint_root: String,
    pub public_audit_record_root: String,
}

pub type Roots = EncryptedStateSnapshotFastSyncRoots;

impl EncryptedStateSnapshotFastSyncRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "manifest_root": self.manifest_root,
            "shard_root": self.shard_root,
            "attestation_root": self.attestation_root,
            "sampling_receipt_root": self.sampling_receipt_root,
            "sponsor_root": self.sponsor_root,
            "sponsorship_ticket_root": self.sponsorship_ticket_root,
            "repair_receipt_root": self.repair_receipt_root,
            "fraud_challenge_root": self.fraud_challenge_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "checkpoint_root": self.checkpoint_root,
            "public_audit_record_root": self.public_audit_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EncryptedStateSnapshotFastSyncCounters {
    pub lanes: usize,
    pub manifests: usize,
    pub shards: usize,
    pub attestations: usize,
    pub sampling_receipts: usize,
    pub sponsors: usize,
    pub sponsorship_tickets: usize,
    pub repair_receipts: usize,
    pub fraud_challenges: usize,
    pub slashing_evidence: usize,
    pub checkpoints: usize,
    pub public_records: usize,
    pub finalized_checkpoints: usize,
    pub unresolved_challenges: usize,
    pub accepted_repairs: usize,
    pub accepted_samples: usize,
}

pub type Counters = EncryptedStateSnapshotFastSyncCounters;

impl EncryptedStateSnapshotFastSyncCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "manifests": self.manifests,
            "shards": self.shards,
            "attestations": self.attestations,
            "sampling_receipts": self.sampling_receipts,
            "sponsors": self.sponsors,
            "sponsorship_tickets": self.sponsorship_tickets,
            "repair_receipts": self.repair_receipts,
            "fraud_challenges": self.fraud_challenges,
            "slashing_evidence": self.slashing_evidence,
            "checkpoints": self.checkpoints,
            "public_records": self.public_records,
            "finalized_checkpoints": self.finalized_checkpoints,
            "unresolved_challenges": self.unresolved_challenges,
            "accepted_repairs": self.accepted_repairs,
            "accepted_samples": self.accepted_samples,
        })
    }

    pub fn state_root(&self) -> String {
        snapshot_record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedStateSnapshotFastSyncState {
    pub height: u64,
    pub config: EncryptedStateSnapshotFastSyncConfig,
    pub lanes: BTreeMap<String, SnapshotLane>,
    pub manifests: BTreeMap<String, EncryptedManifest>,
    pub shard_commitments: BTreeMap<String, ShardCommitment>,
    pub attestations: BTreeMap<String, PqSnapshotAttestation>,
    pub sampling_receipts: BTreeMap<String, SamplingReceipt>,
    pub sponsors: BTreeMap<String, SponsorAccount>,
    pub sponsorship_tickets: BTreeMap<String, SponsorshipTicket>,
    pub repair_receipts: BTreeMap<String, RepairReceipt>,
    pub fraud_challenges: BTreeMap<String, FraudChallenge>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub checkpoints: BTreeMap<String, SnapshotCheckpoint>,
    pub public_records: BTreeMap<String, PublicAuditRecord>,
    pub manifest_shards: BTreeMap<String, BTreeSet<String>>,
    pub manifest_attestations: BTreeMap<String, BTreeSet<String>>,
    pub manifest_samples: BTreeMap<String, BTreeSet<String>>,
    pub manifest_repairs: BTreeMap<String, BTreeSet<String>>,
}

pub type State = EncryptedStateSnapshotFastSyncState;

impl Default for EncryptedStateSnapshotFastSyncState {
    fn default() -> Self {
        Self::devnet()
    }
}

impl EncryptedStateSnapshotFastSyncState {
    pub fn new(height: u64, config: EncryptedStateSnapshotFastSyncConfig) -> Self {
        Self {
            height,
            config,
            lanes: BTreeMap::new(),
            manifests: BTreeMap::new(),
            shard_commitments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sampling_receipts: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            sponsorship_tickets: BTreeMap::new(),
            repair_receipts: BTreeMap::new(),
            fraud_challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            public_records: BTreeMap::new(),
            manifest_shards: BTreeMap::new(),
            manifest_attestations: BTreeMap::new(),
            manifest_samples: BTreeMap::new(),
            manifest_repairs: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = EncryptedStateSnapshotFastSyncConfig::devnet();
        let mut state = Self::new(1, config);
        let privacy_root = empty_root("DEVNET-SPONSOR-PRIVACY");
        let credential_root = empty_root("DEVNET-SPONSOR-CREDENTIAL");
        let lane = SnapshotLane {
            lane_id: SnapshotLane::deterministic_id(
                SnapshotLaneKind::MoneroWalletSync,
                "devnet-pq-fast-sync-committee",
                256,
                420,
                131_072,
                512,
                900,
                900,
                true,
            ),
            lane_kind: SnapshotLaneKind::MoneroWalletSync,
            operator_committee_id: "devnet-pq-fast-sync-committee".to_string(),
            min_pq_security_bits: 256,
            target_latency_ms: 420,
            max_manifest_bytes: 131_072,
            max_shards_per_manifest: 512,
            low_fee_cap_micro_units: 900,
            privacy_budget_bps: 900,
            enabled: true,
        };
        let sponsor = SponsorAccount {
            sponsor_id: SponsorAccount::deterministic_id(
                "devnet-snapshot-sponsor",
                "dxmr",
                5_000_000,
                0,
                900,
                &privacy_root,
                &credential_root,
                0,
                true,
            ),
            owner_commitment: "devnet-snapshot-sponsor".to_string(),
            asset_id: "dxmr".to_string(),
            balance_micro_units: 5_000_000,
            reserved_micro_units: 0,
            max_fee_per_snapshot_micro_units: 900,
            privacy_pool_root: privacy_root,
            credential_root,
            nonce: 0,
            active: true,
        };
        let _result = state.register_lane(lane);
        let _result = state.register_sponsor(sponsor);
        let _result = state.emit_public_record(
            "devnet_bootstrap",
            "devnet",
            "bootstrap-redacted",
            &json!({"bootstrapped_height": state.height}),
        );
        state
    }

    pub fn update_height(&mut self, height: u64) -> EncryptedStateSnapshotFastSyncResult<()> {
        ensure_monotonic_height(self.height, height)?;
        self.height = height;
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> EncryptedStateSnapshotFastSyncResult<()> {
        self.update_height(height)
    }

    pub fn register_lane(
        &mut self,
        lane: SnapshotLane,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        lane.validate()?;
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        if lane.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("snapshot lane PQ security is below config minimum".to_string());
        }
        if lane.max_manifest_bytes > self.config.max_manifest_bytes {
            return Err("snapshot lane manifest size exceeds config cap".to_string());
        }
        if lane.max_shards_per_manifest > self.config.max_shards_per_manifest {
            return Err("snapshot lane shard cap exceeds config cap".to_string());
        }
        let id = lane.lane_id.clone();
        insert_unique(&mut self.lanes, id.clone(), lane, "snapshot lane")?;
        Ok(id)
    }

    pub fn register_sponsor(
        &mut self,
        sponsor: SponsorAccount,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        sponsor.validate()?;
        ensure_capacity("sponsors", self.sponsors.len(), self.config.max_sponsors)?;
        let id = sponsor.sponsor_id.clone();
        insert_unique(&mut self.sponsors, id.clone(), sponsor, "sponsor account")?;
        Ok(id)
    }

    pub fn publish_manifest(
        &mut self,
        manifest: EncryptedManifest,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        manifest.validate()?;
        ensure_capacity("manifests", self.manifests.len(), self.config.max_manifests)?;
        let lane = self
            .lanes
            .get(&manifest.lane_id)
            .ok_or_else(|| format!("unknown snapshot lane {}", manifest.lane_id))?;
        if !lane.enabled {
            return Err("snapshot lane is disabled".to_string());
        }
        if manifest.snapshot_height > self.height {
            return Err("manifest height is ahead of state height".to_string());
        }
        if manifest.challenge_deadline_height
            < manifest
                .snapshot_height
                .saturating_add(self.config.challenge_window_blocks)
        {
            return Err("manifest challenge window is too short".to_string());
        }
        if manifest.manifest_size_bytes > lane.max_manifest_bytes {
            return Err("manifest exceeds lane byte cap".to_string());
        }
        if manifest.shard_count > lane.max_shards_per_manifest {
            return Err("manifest exceeds lane shard cap".to_string());
        }
        if !self.sponsors.contains_key(&manifest.fee_sponsor_id) {
            return Err("manifest references unknown fee sponsor".to_string());
        }
        let id = manifest.manifest_id.clone();
        insert_unique(
            &mut self.manifests,
            id.clone(),
            manifest,
            "encrypted manifest",
        )?;
        self.manifest_shards.entry(id.clone()).or_default();
        self.manifest_attestations.entry(id.clone()).or_default();
        self.manifest_samples.entry(id.clone()).or_default();
        self.manifest_repairs.entry(id.clone()).or_default();
        Ok(id)
    }

    pub fn commit_shard(
        &mut self,
        shard: ShardCommitment,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        shard.validate()?;
        ensure_capacity(
            "shards",
            self.shard_commitments.len(),
            self.config.max_shards,
        )?;
        let manifest = self
            .manifests
            .get(&shard.manifest_id)
            .ok_or_else(|| format!("unknown manifest {}", shard.manifest_id))?;
        if shard.shard_index >= manifest.shard_count {
            return Err("shard index exceeds manifest shard count".to_string());
        }
        let id = shard.shard_id.clone();
        let manifest_id = shard.manifest_id.clone();
        insert_unique(
            &mut self.shard_commitments,
            id.clone(),
            shard,
            "shard commitment",
        )?;
        self.manifest_shards
            .entry(manifest_id)
            .or_default()
            .insert(id.clone());
        Ok(id)
    }

    pub fn attest_snapshot(
        &mut self,
        attestation: PqSnapshotAttestation,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        attestation.validate()?;
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        if !self.manifests.contains_key(&attestation.manifest_id) {
            return Err("attestation references unknown manifest".to_string());
        }
        if attestation.height > self.height {
            return Err("attestation height is ahead of state height".to_string());
        }
        if attestation.security_bits < self.config.min_pq_security_bits {
            return Err("attestation PQ security is below config minimum".to_string());
        }
        let id = attestation.attestation_id.clone();
        let manifest_id = attestation.manifest_id.clone();
        insert_unique(
            &mut self.attestations,
            id.clone(),
            attestation,
            "PQ snapshot attestation",
        )?;
        self.manifest_attestations
            .entry(manifest_id)
            .or_default()
            .insert(id.clone());
        Ok(id)
    }

    pub fn record_sample(
        &mut self,
        receipt: SamplingReceipt,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        receipt.validate()?;
        ensure_capacity(
            "sampling_receipts",
            self.sampling_receipts.len(),
            self.config.max_sampling_receipts,
        )?;
        if !self.manifests.contains_key(&receipt.manifest_id) {
            return Err("sample references unknown manifest".to_string());
        }
        if !self.shard_commitments.contains_key(&receipt.shard_id) {
            return Err("sample references unknown shard".to_string());
        }
        if receipt.height > self.height {
            return Err("sample receipt height is ahead of state height".to_string());
        }
        let id = receipt.receipt_id.clone();
        let manifest_id = receipt.manifest_id.clone();
        insert_unique(
            &mut self.sampling_receipts,
            id.clone(),
            receipt,
            "sampling receipt",
        )?;
        self.manifest_samples
            .entry(manifest_id)
            .or_default()
            .insert(id.clone());
        Ok(id)
    }

    pub fn issue_sponsorship_ticket(
        &mut self,
        ticket: SponsorshipTicket,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        ticket.validate()?;
        ensure_capacity(
            "sponsorship_tickets",
            self.sponsorship_tickets.len(),
            self.config.max_tickets,
        )?;
        let sponsor = self
            .sponsors
            .get(&ticket.sponsor_id)
            .ok_or_else(|| format!("unknown sponsor {}", ticket.sponsor_id))?;
        if !sponsor.active {
            return Err("sponsor account is inactive".to_string());
        }
        if !self.manifests.contains_key(&ticket.manifest_id) {
            return Err("ticket references unknown manifest".to_string());
        }
        if ticket.max_fee_micro_units > sponsor.max_fee_per_snapshot_micro_units {
            return Err("ticket fee cap exceeds sponsor policy".to_string());
        }
        let id = ticket.ticket_id.clone();
        insert_unique(
            &mut self.sponsorship_tickets,
            id.clone(),
            ticket,
            "sponsorship ticket",
        )?;
        Ok(id)
    }

    pub fn record_repair(
        &mut self,
        repair: RepairReceipt,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        repair.validate()?;
        ensure_capacity(
            "repair_receipts",
            self.repair_receipts.len(),
            self.config.max_repairs,
        )?;
        if !self.manifests.contains_key(&repair.manifest_id) {
            return Err("repair references unknown manifest".to_string());
        }
        if !self.shard_commitments.contains_key(&repair.shard_id) {
            return Err("repair references unknown shard".to_string());
        }
        if repair.height > self.height {
            return Err("repair height is ahead of state height".to_string());
        }
        let id = repair.repair_id.clone();
        let manifest_id = repair.manifest_id.clone();
        insert_unique(
            &mut self.repair_receipts,
            id.clone(),
            repair,
            "repair receipt",
        )?;
        self.manifest_repairs
            .entry(manifest_id)
            .or_default()
            .insert(id.clone());
        Ok(id)
    }

    pub fn open_fraud_challenge(
        &mut self,
        challenge: FraudChallenge,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        challenge.validate()?;
        ensure_capacity(
            "fraud_challenges",
            self.fraud_challenges.len(),
            self.config.max_challenges,
        )?;
        if !self.manifests.contains_key(&challenge.manifest_id) {
            return Err("challenge references unknown manifest".to_string());
        }
        if challenge.opened_height > self.height {
            return Err("challenge height is ahead of state height".to_string());
        }
        if challenge.deadline_height
            < challenge
                .opened_height
                .saturating_add(self.config.challenge_window_blocks)
        {
            return Err("fraud challenge deadline is too short".to_string());
        }
        let id = challenge.challenge_id.clone();
        insert_unique(
            &mut self.fraud_challenges,
            id.clone(),
            challenge,
            "fraud challenge",
        )?;
        Ok(id)
    }

    pub fn record_slashing_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        evidence.validate()?;
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        if !self.fraud_challenges.contains_key(&evidence.challenge_id) {
            return Err("slashing evidence references unknown challenge".to_string());
        }
        if evidence.height > self.height {
            return Err("slashing evidence height is ahead of state height".to_string());
        }
        let id = evidence.evidence_id.clone();
        insert_unique(
            &mut self.slashing_evidence,
            id.clone(),
            evidence,
            "slashing evidence",
        )?;
        Ok(id)
    }

    pub fn add_checkpoint(
        &mut self,
        checkpoint: SnapshotCheckpoint,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        checkpoint.validate()?;
        ensure_capacity(
            "checkpoints",
            self.checkpoints.len(),
            self.config.max_checkpoints,
        )?;
        if !self.manifests.contains_key(&checkpoint.manifest_id) {
            return Err("checkpoint references unknown manifest".to_string());
        }
        if checkpoint.height > self.height {
            return Err("checkpoint height is ahead of state height".to_string());
        }
        let id = checkpoint.checkpoint_id.clone();
        insert_unique(
            &mut self.checkpoints,
            id.clone(),
            checkpoint,
            "snapshot checkpoint",
        )?;
        Ok(id)
    }

    pub fn emit_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        redaction_label: &str,
        payload: &Value,
    ) -> EncryptedStateSnapshotFastSyncResult<String> {
        ensure_capacity(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        let payload_root = snapshot_record_root("PUBLIC-AUDIT-PAYLOAD", payload);
        let redaction_root = snapshot_label_root("PUBLIC-AUDIT-REDACTION", redaction_label);
        let state_root_after = self.state_root();
        let record_id = PublicAuditRecord::deterministic_id(
            record_kind,
            subject_id,
            &payload_root,
            &state_root_after,
            self.height,
            &redaction_root,
        );
        let record = PublicAuditRecord {
            record_id: record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            state_root_after,
            height: self.height,
            redaction_root,
        };
        insert_unique(
            &mut self.public_records,
            record_id.clone(),
            record,
            "public audit record",
        )?;
        Ok(record_id)
    }

    pub fn validate(&self) -> EncryptedStateSnapshotFastSyncResult<()> {
        self.config.validate()?;
        ensure_capacity_current("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_capacity_current("manifests", self.manifests.len(), self.config.max_manifests)?;
        ensure_capacity_current(
            "shards",
            self.shard_commitments.len(),
            self.config.max_shards,
        )?;
        ensure_capacity_current(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_capacity_current(
            "sampling_receipts",
            self.sampling_receipts.len(),
            self.config.max_sampling_receipts,
        )?;
        ensure_capacity_current("sponsors", self.sponsors.len(), self.config.max_sponsors)?;
        ensure_capacity_current(
            "sponsorship_tickets",
            self.sponsorship_tickets.len(),
            self.config.max_tickets,
        )?;
        ensure_capacity_current(
            "repair_receipts",
            self.repair_receipts.len(),
            self.config.max_repairs,
        )?;
        ensure_capacity_current(
            "fraud_challenges",
            self.fraud_challenges.len(),
            self.config.max_challenges,
        )?;
        ensure_capacity_current(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        ensure_capacity_current(
            "checkpoints",
            self.checkpoints.len(),
            self.config.max_checkpoints,
        )?;
        ensure_capacity_current(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        for manifest in self.manifests.values() {
            manifest.validate()?;
            if !self.lanes.contains_key(&manifest.lane_id) {
                return Err("manifest references missing lane".to_string());
            }
            if !self.sponsors.contains_key(&manifest.fee_sponsor_id) {
                return Err("manifest references missing sponsor".to_string());
            }
        }
        for shard in self.shard_commitments.values() {
            shard.validate()?;
            let manifest = self
                .manifests
                .get(&shard.manifest_id)
                .ok_or_else(|| "shard references missing manifest".to_string())?;
            if shard.shard_index >= manifest.shard_count {
                return Err("stored shard index exceeds manifest shard count".to_string());
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.manifests.contains_key(&attestation.manifest_id) {
                return Err("attestation references missing manifest".to_string());
            }
        }
        for receipt in self.sampling_receipts.values() {
            receipt.validate()?;
            if !self.manifests.contains_key(&receipt.manifest_id)
                || !self.shard_commitments.contains_key(&receipt.shard_id)
            {
                return Err("sampling receipt references missing object".to_string());
            }
        }
        for ticket in self.sponsorship_tickets.values() {
            ticket.validate()?;
            if !self.sponsors.contains_key(&ticket.sponsor_id)
                || !self.manifests.contains_key(&ticket.manifest_id)
            {
                return Err("ticket references missing object".to_string());
            }
        }
        for repair in self.repair_receipts.values() {
            repair.validate()?;
            if !self.manifests.contains_key(&repair.manifest_id)
                || !self.shard_commitments.contains_key(&repair.shard_id)
            {
                return Err("repair references missing object".to_string());
            }
        }
        for challenge in self.fraud_challenges.values() {
            challenge.validate()?;
            if !self.manifests.contains_key(&challenge.manifest_id) {
                return Err("challenge references missing manifest".to_string());
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            if !self.fraud_challenges.contains_key(&evidence.challenge_id) {
                return Err("slashing evidence references missing challenge".to_string());
            }
        }
        for checkpoint in self.checkpoints.values() {
            checkpoint.validate()?;
            if !self.manifests.contains_key(&checkpoint.manifest_id) {
                return Err("checkpoint references missing manifest".to_string());
            }
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(())
    }

    pub fn roots(&self) -> EncryptedStateSnapshotFastSyncRoots {
        EncryptedStateSnapshotFastSyncRoots {
            config_root: self.config.state_root(),
            lane_root: map_root("LANE", &self.lanes),
            manifest_root: map_root("MANIFEST", &self.manifests),
            shard_root: map_root("SHARD", &self.shard_commitments),
            attestation_root: map_root("ATTESTATION", &self.attestations),
            sampling_receipt_root: map_root("SAMPLING-RECEIPT", &self.sampling_receipts),
            sponsor_root: map_root("SPONSOR", &self.sponsors),
            sponsorship_ticket_root: map_root("SPONSORSHIP-TICKET", &self.sponsorship_tickets),
            repair_receipt_root: map_root("REPAIR-RECEIPT", &self.repair_receipts),
            fraud_challenge_root: map_root("FRAUD-CHALLENGE", &self.fraud_challenges),
            slashing_evidence_root: map_root("SLASHING-EVIDENCE", &self.slashing_evidence),
            checkpoint_root: map_root("CHECKPOINT", &self.checkpoints),
            public_audit_record_root: map_root("PUBLIC-AUDIT-RECORD", &self.public_records),
        }
    }

    pub fn counters(&self) -> EncryptedStateSnapshotFastSyncCounters {
        EncryptedStateSnapshotFastSyncCounters {
            lanes: self.lanes.len(),
            manifests: self.manifests.len(),
            shards: self.shard_commitments.len(),
            attestations: self.attestations.len(),
            sampling_receipts: self.sampling_receipts.len(),
            sponsors: self.sponsors.len(),
            sponsorship_tickets: self.sponsorship_tickets.len(),
            repair_receipts: self.repair_receipts.len(),
            fraud_challenges: self.fraud_challenges.len(),
            slashing_evidence: self.slashing_evidence.len(),
            checkpoints: self.checkpoints.len(),
            public_records: self.public_records.len(),
            finalized_checkpoints: self
                .checkpoints
                .values()
                .filter(|checkpoint| checkpoint.finalized)
                .count(),
            unresolved_challenges: self
                .fraud_challenges
                .values()
                .filter(|challenge| !challenge.resolved)
                .count(),
            accepted_repairs: self
                .repair_receipts
                .values()
                .filter(|repair| repair.accepted)
                .count(),
            accepted_samples: self
                .sampling_receipts
                .values()
                .filter(|receipt| receipt.accepted)
                .count(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": ENCRYPTED_STATE_SNAPSHOT_FAST_SYNC_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
            "manifest_indexes": {
                "manifest_shards_root": index_root("MANIFEST-SHARDS", &self.manifest_shards),
                "manifest_attestations_root": index_root("MANIFEST-ATTESTATIONS", &self.manifest_attestations),
                "manifest_samples_root": index_root("MANIFEST-SAMPLES", &self.manifest_samples),
                "manifest_repairs_root": index_root("MANIFEST-REPAIRS", &self.manifest_repairs),
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        encrypted_state_snapshot_fast_sync_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn manifest_sample_coverage(
        &self,
        manifest_id: &str,
    ) -> EncryptedStateSnapshotFastSyncResult<Value> {
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| format!("unknown manifest {manifest_id}"))?;
        let shard_ids = match self.manifest_shards.get(manifest_id) {
            Some(ids) => ids.clone(),
            None => BTreeSet::new(),
        };
        let sample_ids = match self.manifest_samples.get(manifest_id) {
            Some(ids) => ids.clone(),
            None => BTreeSet::new(),
        };
        let accepted_samples = sample_ids
            .iter()
            .filter_map(|id| self.sampling_receipts.get(id))
            .filter(|receipt| receipt.accepted)
            .count();
        Ok(json!({
            "manifest_id": manifest_id,
            "declared_shards": manifest.shard_count,
            "committed_shards": shard_ids.len(),
            "sampling_receipts": sample_ids.len(),
            "accepted_samples": accepted_samples,
            "min_required_per_shard": self.config.min_sampling_receipts_per_shard,
            "coverage_root": snapshot_record_root("MANIFEST-SAMPLE-COVERAGE", &json!({"manifest_id": manifest_id, "shards": shard_ids, "samples": sample_ids})),
        }))
    }

    pub fn manifest_security_summary(
        &self,
        manifest_id: &str,
    ) -> EncryptedStateSnapshotFastSyncResult<Value> {
        if !self.manifests.contains_key(manifest_id) {
            return Err(format!("unknown manifest {manifest_id}"));
        }
        let attestation_ids = match self.manifest_attestations.get(manifest_id) {
            Some(ids) => ids.clone(),
            None => BTreeSet::new(),
        };
        let mut total_weight = 0_u64;
        let mut threshold_weight = 0_u64;
        let mut minimum_security_bits = u16::MAX;
        for id in &attestation_ids {
            if let Some(attestation) = self.attestations.get(id) {
                total_weight = total_weight.saturating_add(attestation.signer_weight);
                threshold_weight = threshold_weight.max(attestation.threshold_weight);
                minimum_security_bits = minimum_security_bits.min(attestation.security_bits);
            }
        }
        if minimum_security_bits == u16::MAX {
            minimum_security_bits = 0;
        }
        Ok(json!({
            "manifest_id": manifest_id,
            "attestation_count": attestation_ids.len(),
            "signer_weight": total_weight,
            "max_threshold_weight": threshold_weight,
            "minimum_security_bits": minimum_security_bits,
            "meets_pq_floor": minimum_security_bits >= self.config.min_pq_security_bits,
        }))
    }

    pub fn sponsor_available_balance(
        &self,
        sponsor_id: &str,
    ) -> EncryptedStateSnapshotFastSyncResult<u64> {
        let sponsor = self
            .sponsors
            .get(sponsor_id)
            .ok_or_else(|| format!("unknown sponsor {sponsor_id}"))?;
        Ok(sponsor
            .balance_micro_units
            .saturating_sub(sponsor.reserved_micro_units))
    }

    pub fn active_challenge_ids_for_manifest(&self, manifest_id: &str) -> Vec<String> {
        self.fraud_challenges
            .values()
            .filter(|challenge| challenge.manifest_id == manifest_id && !challenge.resolved)
            .map(|challenge| challenge.challenge_id.clone())
            .collect()
    }

    pub fn repair_ids_for_shard(&self, shard_id: &str) -> Vec<String> {
        self.repair_receipts
            .values()
            .filter(|repair| repair.shard_id == shard_id)
            .map(|repair| repair.repair_id.clone())
            .collect()
    }
}

pub trait SnapshotFastSyncPublicRecord {
    fn public_record(&self) -> Value;
}

impl SnapshotFastSyncPublicRecord for SnapshotLane {
    fn public_record(&self) -> Value {
        SnapshotLane::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for EncryptedManifest {
    fn public_record(&self) -> Value {
        EncryptedManifest::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for ShardCommitment {
    fn public_record(&self) -> Value {
        ShardCommitment::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for PqSnapshotAttestation {
    fn public_record(&self) -> Value {
        PqSnapshotAttestation::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for SamplingReceipt {
    fn public_record(&self) -> Value {
        SamplingReceipt::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for SponsorAccount {
    fn public_record(&self) -> Value {
        SponsorAccount::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for SponsorshipTicket {
    fn public_record(&self) -> Value {
        SponsorshipTicket::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for RepairReceipt {
    fn public_record(&self) -> Value {
        RepairReceipt::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for FraudChallenge {
    fn public_record(&self) -> Value {
        FraudChallenge::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for SnapshotCheckpoint {
    fn public_record(&self) -> Value {
        SnapshotCheckpoint::public_record(self)
    }
}

impl SnapshotFastSyncPublicRecord for PublicAuditRecord {
    fn public_record(&self) -> Value {
        PublicAuditRecord::public_record(self)
    }
}

pub fn devnet() -> EncryptedStateSnapshotFastSyncState {
    EncryptedStateSnapshotFastSyncState::devnet()
}

pub fn encrypted_state_snapshot_fast_sync_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "ENCRYPTED-STATE-SNAPSHOT-FAST-SYNC-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn snapshot_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("ENCRYPTED-STATE-SNAPSHOT-FAST-SYNC-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn snapshot_label_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("ENCRYPTED-STATE-SNAPSHOT-FAST-SYNC-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(&format!("ENCRYPTED-STATE-SNAPSHOT-FAST-SYNC-{domain}"), &[])
}

fn map_root<T: SnapshotFastSyncPublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(id, record)| json!({ "id": id, "record": record.public_record() }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("ENCRYPTED-STATE-SNAPSHOT-FAST-SYNC-{domain}"),
        &leaves,
    )
}

fn index_root(domain: &str, map: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = map
        .iter()
        .map(|(id, children)| json!({ "id": id, "children": children.iter().cloned().collect::<Vec<_>>() }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("ENCRYPTED-STATE-SNAPSHOT-FAST-SYNC-{domain}"),
        &leaves,
    )
}

fn ensure_non_empty(field: &str, value: &str) -> EncryptedStateSnapshotFastSyncResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_at_least(
    field: &str,
    value: u64,
    minimum: u64,
) -> EncryptedStateSnapshotFastSyncResult<()> {
    if value < minimum {
        Err(format!("{field} must be at least {minimum}"))
    } else {
        Ok(())
    }
}

fn ensure_at_most(
    field: &str,
    value: u64,
    maximum: u64,
) -> EncryptedStateSnapshotFastSyncResult<()> {
    if value > maximum {
        Err(format!("{field} must be at most {maximum}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    field: &str,
    current: usize,
    maximum: usize,
) -> EncryptedStateSnapshotFastSyncResult<()> {
    if current >= maximum {
        Err(format!("{field} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_capacity_current(
    field: &str,
    current: usize,
    maximum: usize,
) -> EncryptedStateSnapshotFastSyncResult<()> {
    if current > maximum {
        Err(format!("{field} exceeds configured capacity"))
    } else {
        Ok(())
    }
}

fn ensure_monotonic_height(current: u64, next: u64) -> EncryptedStateSnapshotFastSyncResult<()> {
    if next < current {
        Err("height cannot move backwards".to_string())
    } else {
        Ok(())
    }
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    value: T,
    label: &str,
) -> EncryptedStateSnapshotFastSyncResult<()> {
    if map.contains_key(&id) {
        Err(format!("duplicate {label} id {id}"))
    } else {
        map.insert(id, value);
        Ok(())
    }
}
