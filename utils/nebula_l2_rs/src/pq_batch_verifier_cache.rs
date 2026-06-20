use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, HashPart},
    CHAIN_ID,
};

pub type PqBatchVerifierCacheResult<T> = Result<T, String>;

pub const PQ_BATCH_VERIFIER_CACHE_PROTOCOL_VERSION: u32 = 1;
pub const PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL: &str = "nebula-l2-pq-batch-verifier-cache-v1";
pub const PQ_BATCH_VERIFIER_CACHE_SCHEMA_VERSION: u64 = 1;
pub const PQ_BATCH_VERIFIER_CACHE_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_BATCH_VERIFIER_CACHE_PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-65+ML-DSA-87+SLH-DSA-SHAKE-128s-devnet";
pub const PQ_BATCH_VERIFIER_CACHE_RECURSIVE_PROOF_SCHEME: &str =
    "recursive-pq-proof-aggregation-cache-v1";
pub const PQ_BATCH_VERIFIER_CACHE_DA_SAMPLE_SCHEME: &str = "private-da-sample-proof-cache-v1";
pub const PQ_BATCH_VERIFIER_CACHE_ACCOUNT_RECOVERY_SCHEME: &str =
    "shielded-account-recovery-proof-cache-v1";
pub const PQ_BATCH_VERIFIER_CACHE_BRIDGE_FINALITY_SCHEME: &str =
    "bridge-finality-attestation-cache-v1";
pub const PQ_BATCH_VERIFIER_CACHE_PRIVACY_TAG_SCHEME: &str =
    "bucketed-privacy-preserving-cache-tags-v1";
pub const PQ_BATCH_VERIFIER_CACHE_DEVNET_HEIGHT: u64 = 900;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_JOB_TTL_BLOCKS: u64 = 120;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_RECURSIVE_TTL_BLOCKS: u64 = 2_880;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_DA_SAMPLE_TTL_BLOCKS: u64 = 360;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_RECOVERY_TTL_BLOCKS: u64 = 7_200;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_BRIDGE_FINALITY_TTL_BLOCKS: u64 = 1_440;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_PRIVACY_TAG_TTL_BLOCKS: u64 = 21_600;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 900;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_MAX_BATCH_WEIGHT: u64 = 1_000_000;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_MAX_BATCH_BYTES: u64 = 4_000_000;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PQ_BATCH_VERIFIER_CACHE_DEFAULT_MAX_REUSE_PER_TAG: u64 = 64;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_BPS: u64 = 10_000;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_JOBS: usize = 262_144;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_VERIFIER_KEYS: usize = 16_384;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_RECURSIVE_ENTRIES: usize = 524_288;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_DA_SAMPLE_ENTRIES: usize = 524_288;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_ACCOUNT_RECOVERY_ENTRIES: usize = 262_144;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_BRIDGE_FINALITY_ENTRIES: usize = 262_144;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_INVALIDATION_EPOCHS: usize = 16_384;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_LOW_FEE_LANES: usize = 128;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_PRIVACY_TAGS: usize = 1_048_576;
pub const PQ_BATCH_VERIFIER_CACHE_MAX_PUBLIC_RECORDS: usize = 1_048_576;

const STATE_STATUS_ACTIVE: &str = "active";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierWorkKind {
    PqSignature,
    ZkValidityProof,
    RecursiveRollupProof,
    DaSampleProof,
    AccountRecoveryProof,
    BridgeFinalityAttestation,
    SequencerFastPathAttestation,
    PrivacyTagRefresh,
}

impl PqVerifierWorkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignature => "pq_signature",
            Self::ZkValidityProof => "zk_validity_proof",
            Self::RecursiveRollupProof => "recursive_rollup_proof",
            Self::DaSampleProof => "da_sample_proof",
            Self::AccountRecoveryProof => "account_recovery_proof",
            Self::BridgeFinalityAttestation => "bridge_finality_attestation",
            Self::SequencerFastPathAttestation => "sequencer_fast_path_attestation",
            Self::PrivacyTagRefresh => "privacy_tag_refresh",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::PqSignature => 1_200,
            Self::ZkValidityProof => 11_000,
            Self::RecursiveRollupProof => 48_000,
            Self::DaSampleProof => 4_000,
            Self::AccountRecoveryProof => 7_500,
            Self::BridgeFinalityAttestation => 9_000,
            Self::SequencerFastPathAttestation => 2_500,
            Self::PrivacyTagRefresh => 800,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierLaneKind {
    Emergency,
    Bridge,
    PrivateTransfer,
    Defi,
    AccountRecovery,
    DaSampling,
    SequencerFastPath,
    LowFeePublicGood,
    Maintenance,
}

impl PqVerifierLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Bridge => "bridge",
            Self::PrivateTransfer => "private_transfer",
            Self::Defi => "defi",
            Self::AccountRecovery => "account_recovery",
            Self::DaSampling => "da_sampling",
            Self::SequencerFastPath => "sequencer_fast_path",
            Self::LowFeePublicGood => "low_fee_public_good",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn low_fee(self) -> bool {
        matches!(
            self,
            Self::AccountRecovery | Self::DaSampling | Self::LowFeePublicGood
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqBatchJobStatus {
    Queued,
    Sampling,
    Verifying,
    Cached,
    Reused,
    Finalized,
    Invalidated,
    Expired,
    Rejected,
}

impl PqBatchJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sampling => "sampling",
            Self::Verifying => "verifying",
            Self::Cached => "cached",
            Self::Reused => "reused",
            Self::Finalized => "finalized",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Sampling | Self::Verifying | Self::Cached | Self::Reused
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Invalidated | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Draft,
    Active,
    Rotating,
    Deprecated,
    Revoked,
}

impl VerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEntryStatus {
    Warm,
    Hot,
    Pinned,
    Consumed,
    Invalidated,
    Expired,
}

impl CacheEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warm => "warm",
            Self::Hot => "hot",
            Self::Pinned => "pinned",
            Self::Consumed => "consumed",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
        }
    }

    pub fn reusable(self) -> bool {
        matches!(self, Self::Warm | Self::Hot | Self::Pinned)
    }
}

fn ensure_non_empty(field: &str, value: &str) -> PqBatchVerifierCacheResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_hex_root(field: &str, value: &str) -> PqBatchVerifierCacheResult<()> {
    ensure_non_empty(field, value)?;
    if value.len() < 32 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        Err(format!("{field} must be a deterministic hex root"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(field: &str, value: usize) -> PqBatchVerifierCacheResult<()> {
    if value == 0 {
        Err(format!("{field} must be greater than zero"))
    } else {
        Ok(())
    }
}

fn ensure_at_most(field: &str, value: usize, max: usize) -> PqBatchVerifierCacheResult<()> {
    if value > max {
        Err(format!("{field} exceeds configured capacity {max}"))
    } else {
        Ok(())
    }
}

fn ensure_height_order(
    field: &str,
    start_height: u64,
    expiry_height: u64,
) -> PqBatchVerifierCacheResult<()> {
    if expiry_height <= start_height {
        Err(format!("{field} expiry height must be after start height"))
    } else {
        Ok(())
    }
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL),
            HashPart::Int(PQ_BATCH_VERIFIER_CACHE_PROTOCOL_VERSION as i128),
            HashPart::Json(record),
        ],
        32,
    )
}

fn collection_root(domain: &str, records: Vec<Value>) -> String {
    if records.is_empty() {
        return payload_root(&format!("{domain}:empty"), &json!([]));
    }

    let mut leaves = records
        .iter()
        .map(|record| payload_root(&format!("{domain}:leaf"), record))
        .collect::<Vec<_>>();

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for chunk in leaves.chunks(2) {
            let left = chunk[0].as_str();
            let right = match chunk.get(1) {
                Some(value) => value.as_str(),
                None => left,
            };
            next.push(domain_hash(
                &format!("{domain}:node"),
                &[
                    HashPart::Str(PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL),
                    HashPart::Str(left),
                    HashPart::Str(right),
                ],
                32,
            ));
        }
        leaves = next;
    }

    match leaves.first() {
        Some(root) => root.clone(),
        None => payload_root(&format!("{domain}:empty"), &json!([])),
    }
}

fn sorted_values<T>(map: &BTreeMap<String, T>, map_value: fn(&T) -> Value) -> Vec<Value> {
    map.values().map(map_value).collect::<Vec<_>>()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqBatchVerifierCacheConfig {
    pub chain_id: String,
    pub epoch_blocks: u64,
    pub job_ttl_blocks: u64,
    pub recursive_entry_ttl_blocks: u64,
    pub da_sample_ttl_blocks: u64,
    pub account_recovery_ttl_blocks: u64,
    pub bridge_finality_ttl_blocks: u64,
    pub privacy_tag_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_cap_micro_units: u64,
    pub max_batch_weight: u64,
    pub max_batch_bytes: u64,
    pub min_privacy_set_size: u64,
    pub max_reuse_per_tag: u64,
    pub max_jobs: usize,
    pub max_verifier_keys: usize,
    pub max_recursive_entries: usize,
    pub max_da_sample_entries: usize,
    pub max_account_recovery_entries: usize,
    pub max_bridge_finality_entries: usize,
    pub max_invalidation_epochs: usize,
    pub max_low_fee_lanes: usize,
    pub max_privacy_tags: usize,
    pub max_public_records: usize,
}

impl PqBatchVerifierCacheConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            epoch_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_EPOCH_BLOCKS,
            job_ttl_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_JOB_TTL_BLOCKS,
            recursive_entry_ttl_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_RECURSIVE_TTL_BLOCKS,
            da_sample_ttl_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_DA_SAMPLE_TTL_BLOCKS,
            account_recovery_ttl_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_RECOVERY_TTL_BLOCKS,
            bridge_finality_ttl_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_BRIDGE_FINALITY_TTL_BLOCKS,
            privacy_tag_ttl_blocks: PQ_BATCH_VERIFIER_CACHE_DEFAULT_PRIVACY_TAG_TTL_BLOCKS,
            min_pq_security_bits: PQ_BATCH_VERIFIER_CACHE_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_cap_micro_units: PQ_BATCH_VERIFIER_CACHE_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            max_batch_weight: PQ_BATCH_VERIFIER_CACHE_DEFAULT_MAX_BATCH_WEIGHT,
            max_batch_bytes: PQ_BATCH_VERIFIER_CACHE_DEFAULT_MAX_BATCH_BYTES,
            min_privacy_set_size: PQ_BATCH_VERIFIER_CACHE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_reuse_per_tag: PQ_BATCH_VERIFIER_CACHE_DEFAULT_MAX_REUSE_PER_TAG,
            max_jobs: PQ_BATCH_VERIFIER_CACHE_MAX_JOBS,
            max_verifier_keys: PQ_BATCH_VERIFIER_CACHE_MAX_VERIFIER_KEYS,
            max_recursive_entries: PQ_BATCH_VERIFIER_CACHE_MAX_RECURSIVE_ENTRIES,
            max_da_sample_entries: PQ_BATCH_VERIFIER_CACHE_MAX_DA_SAMPLE_ENTRIES,
            max_account_recovery_entries: PQ_BATCH_VERIFIER_CACHE_MAX_ACCOUNT_RECOVERY_ENTRIES,
            max_bridge_finality_entries: PQ_BATCH_VERIFIER_CACHE_MAX_BRIDGE_FINALITY_ENTRIES,
            max_invalidation_epochs: PQ_BATCH_VERIFIER_CACHE_MAX_INVALIDATION_EPOCHS,
            max_low_fee_lanes: PQ_BATCH_VERIFIER_CACHE_MAX_LOW_FEE_LANES,
            max_privacy_tags: PQ_BATCH_VERIFIER_CACHE_MAX_PRIVACY_TAGS,
            max_public_records: PQ_BATCH_VERIFIER_CACHE_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<()> {
        if self.chain_id.as_str() != CHAIN_ID {
            return Err("config.chain_id must match crate chain id".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err("config.epoch_blocks must be greater than zero".to_string());
        }
        if self.job_ttl_blocks == 0 {
            return Err("config.job_ttl_blocks must be greater than zero".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("config.min_pq_security_bits must be at least 192".to_string());
        }
        if self.low_fee_cap_micro_units == 0 {
            return Err("config.low_fee_cap_micro_units must be greater than zero".to_string());
        }
        if self.max_batch_weight == 0 || self.max_batch_bytes == 0 {
            return Err("config batch limits must be greater than zero".to_string());
        }
        if self.min_privacy_set_size < 16 {
            return Err("config.min_privacy_set_size must be at least 16".to_string());
        }
        if self.max_reuse_per_tag == 0 {
            return Err("config.max_reuse_per_tag must be greater than zero".to_string());
        }

        ensure_capacity("config.max_jobs", self.max_jobs)?;
        ensure_capacity("config.max_verifier_keys", self.max_verifier_keys)?;
        ensure_capacity("config.max_recursive_entries", self.max_recursive_entries)?;
        ensure_capacity("config.max_da_sample_entries", self.max_da_sample_entries)?;
        ensure_capacity(
            "config.max_account_recovery_entries",
            self.max_account_recovery_entries,
        )?;
        ensure_capacity(
            "config.max_bridge_finality_entries",
            self.max_bridge_finality_entries,
        )?;
        ensure_capacity(
            "config.max_invalidation_epochs",
            self.max_invalidation_epochs,
        )?;
        ensure_capacity("config.max_low_fee_lanes", self.max_low_fee_lanes)?;
        ensure_capacity("config.max_privacy_tags", self.max_privacy_tags)?;
        ensure_capacity("config.max_public_records", self.max_public_records)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_batch_verifier_cache_config",
            "protocol": PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL,
            "protocol_version": PQ_BATCH_VERIFIER_CACHE_PROTOCOL_VERSION,
            "schema_version": PQ_BATCH_VERIFIER_CACHE_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "hash_suite": PQ_BATCH_VERIFIER_CACHE_HASH_SUITE,
            "pq_signature_suite": PQ_BATCH_VERIFIER_CACHE_PQ_SIGNATURE_SUITE,
            "recursive_proof_scheme": PQ_BATCH_VERIFIER_CACHE_RECURSIVE_PROOF_SCHEME,
            "da_sample_scheme": PQ_BATCH_VERIFIER_CACHE_DA_SAMPLE_SCHEME,
            "account_recovery_scheme": PQ_BATCH_VERIFIER_CACHE_ACCOUNT_RECOVERY_SCHEME,
            "bridge_finality_scheme": PQ_BATCH_VERIFIER_CACHE_BRIDGE_FINALITY_SCHEME,
            "privacy_tag_scheme": PQ_BATCH_VERIFIER_CACHE_PRIVACY_TAG_SCHEME,
            "epoch_blocks": self.epoch_blocks,
            "job_ttl_blocks": self.job_ttl_blocks,
            "recursive_entry_ttl_blocks": self.recursive_entry_ttl_blocks,
            "da_sample_ttl_blocks": self.da_sample_ttl_blocks,
            "account_recovery_ttl_blocks": self.account_recovery_ttl_blocks,
            "bridge_finality_ttl_blocks": self.bridge_finality_ttl_blocks,
            "privacy_tag_ttl_blocks": self.privacy_tag_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "max_batch_weight": self.max_batch_weight,
            "max_batch_bytes": self.max_batch_bytes,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_reuse_per_tag": self.max_reuse_per_tag,
            "max_jobs": self.max_jobs as u64,
            "max_verifier_keys": self.max_verifier_keys as u64,
            "max_recursive_entries": self.max_recursive_entries as u64,
            "max_da_sample_entries": self.max_da_sample_entries as u64,
            "max_account_recovery_entries": self.max_account_recovery_entries as u64,
            "max_bridge_finality_entries": self.max_bridge_finality_entries as u64,
            "max_invalidation_epochs": self.max_invalidation_epochs as u64,
            "max_low_fee_lanes": self.max_low_fee_lanes as u64,
            "max_privacy_tags": self.max_privacy_tags as u64,
            "max_public_records": self.max_public_records as u64,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-BATCH-VERIFIER-CACHE-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifierKeyCatalogEntry {
    pub key_id: String,
    pub work_kind: PqVerifierWorkKind,
    pub scheme: String,
    pub verification_domain: String,
    pub key_commitment: String,
    pub parameter_root: String,
    pub activated_height: u64,
    pub retired_height: Option<u64>,
    pub pq_security_bits: u16,
    pub status: VerifierKeyStatus,
}

impl VerifierKeyCatalogEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_key_catalog_entry",
            "key_id": self.key_id,
            "work_kind": self.work_kind.as_str(),
            "scheme": self.scheme,
            "verification_domain": self.verification_domain,
            "key_commitment": self.key_commitment,
            "parameter_root": self.parameter_root,
            "activated_height": self.activated_height,
            "retired_height": self.retired_height,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-VERIFIER-KEY",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &PqBatchVerifierCacheConfig) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("verifier_key.key_id", &self.key_id)?;
        ensure_non_empty("verifier_key.scheme", &self.scheme)?;
        ensure_non_empty(
            "verifier_key.verification_domain",
            &self.verification_domain,
        )?;
        ensure_hex_root("verifier_key.key_commitment", &self.key_commitment)?;
        ensure_hex_root("verifier_key.parameter_root", &self.parameter_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "verifier_key {} has insufficient pq security bits",
                self.key_id
            ));
        }
        if let Some(retired_height) = self.retired_height {
            if retired_height <= self.activated_height {
                return Err(format!(
                    "verifier_key {} retired_height must be after activation",
                    self.key_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSignatureProofBatchJob {
    pub job_id: String,
    pub lane_id: String,
    pub work_kind: PqVerifierWorkKind,
    pub verifier_key_id: String,
    pub input_commitment: String,
    pub batch_transcript_root: String,
    pub privacy_tag_id: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub proof_count: u64,
    pub byte_size: u64,
    pub batch_weight: u64,
    pub sponsor_fee_micro_units: u64,
    pub cache_hit_count: u64,
    pub status: PqBatchJobStatus,
}

impl PqSignatureProofBatchJob {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_signature_proof_batch_job",
            "job_id": self.job_id,
            "lane_id": self.lane_id,
            "work_kind": self.work_kind.as_str(),
            "verifier_key_id": self.verifier_key_id,
            "input_commitment": self.input_commitment,
            "batch_transcript_root": self.batch_transcript_root,
            "privacy_tag_id": self.privacy_tag_id,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "proof_count": self.proof_count,
            "byte_size": self.byte_size,
            "batch_weight": self.batch_weight,
            "sponsor_fee_micro_units": self.sponsor_fee_micro_units,
            "cache_hit_count": self.cache_hit_count,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-BATCH-VERIFIER-CACHE-JOB", &self.public_record())
    }

    pub fn validate(&self, config: &PqBatchVerifierCacheConfig) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("job.job_id", &self.job_id)?;
        ensure_non_empty("job.lane_id", &self.lane_id)?;
        ensure_non_empty("job.verifier_key_id", &self.verifier_key_id)?;
        ensure_non_empty("job.privacy_tag_id", &self.privacy_tag_id)?;
        ensure_hex_root("job.input_commitment", &self.input_commitment)?;
        ensure_hex_root("job.batch_transcript_root", &self.batch_transcript_root)?;
        ensure_height_order("job", self.submitted_height, self.expires_height)?;
        if self.proof_count == 0 {
            return Err(format!(
                "job {} must include at least one proof",
                self.job_id
            ));
        }
        if self.byte_size > config.max_batch_bytes {
            return Err(format!("job {} exceeds max batch bytes", self.job_id));
        }
        if self.batch_weight > config.max_batch_weight {
            return Err(format!("job {} exceeds max batch weight", self.job_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProofCacheEntry {
    pub entry_id: String,
    pub job_id: String,
    pub verifier_key_id: String,
    pub recursion_layer: u32,
    pub input_root: String,
    pub output_root: String,
    pub accumulator_root: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub reuse_count: u64,
    pub status: CacheEntryStatus,
}

impl RecursiveProofCacheEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_cache_entry",
            "entry_id": self.entry_id,
            "job_id": self.job_id,
            "verifier_key_id": self.verifier_key_id,
            "recursion_layer": self.recursion_layer,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "accumulator_root": self.accumulator_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "reuse_count": self.reuse_count,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-RECURSIVE-ENTRY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("recursive.entry_id", &self.entry_id)?;
        ensure_non_empty("recursive.job_id", &self.job_id)?;
        ensure_non_empty("recursive.verifier_key_id", &self.verifier_key_id)?;
        ensure_hex_root("recursive.input_root", &self.input_root)?;
        ensure_hex_root("recursive.output_root", &self.output_root)?;
        ensure_hex_root("recursive.accumulator_root", &self.accumulator_root)?;
        ensure_height_order("recursive", self.created_height, self.expires_height)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaSampleProofCacheEntry {
    pub sample_id: String,
    pub job_id: String,
    pub shard_id: String,
    pub erasure_commitment: String,
    pub sample_proof_root: String,
    pub availability_window_start: u64,
    pub availability_window_end: u64,
    pub sample_count: u64,
    pub withheld_sample_count: u64,
    pub status: CacheEntryStatus,
}

impl DaSampleProofCacheEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_sample_proof_cache_entry",
            "sample_id": self.sample_id,
            "job_id": self.job_id,
            "shard_id": self.shard_id,
            "erasure_commitment": self.erasure_commitment,
            "sample_proof_root": self.sample_proof_root,
            "availability_window_start": self.availability_window_start,
            "availability_window_end": self.availability_window_end,
            "sample_count": self.sample_count,
            "withheld_sample_count": self.withheld_sample_count,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-BATCH-VERIFIER-CACHE-DA-SAMPLE", &self.public_record())
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("da_sample.sample_id", &self.sample_id)?;
        ensure_non_empty("da_sample.job_id", &self.job_id)?;
        ensure_non_empty("da_sample.shard_id", &self.shard_id)?;
        ensure_hex_root("da_sample.erasure_commitment", &self.erasure_commitment)?;
        ensure_hex_root("da_sample.sample_proof_root", &self.sample_proof_root)?;
        ensure_height_order(
            "da_sample",
            self.availability_window_start,
            self.availability_window_end,
        )?;
        if self.sample_count == 0 {
            return Err(format!(
                "da_sample {} sample_count must be positive",
                self.sample_id
            ));
        }
        if self.withheld_sample_count > self.sample_count {
            return Err(format!(
                "da_sample {} withheld count exceeds sample count",
                self.sample_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountRecoveryProofCacheEntry {
    pub recovery_id: String,
    pub job_id: String,
    pub account_commitment: String,
    pub guardian_set_root: String,
    pub recovery_proof_root: String,
    pub nullifier_root: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub guardian_threshold: u64,
    pub privacy_set_size: u64,
    pub status: CacheEntryStatus,
}

impl AccountRecoveryProofCacheEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "account_recovery_proof_cache_entry",
            "recovery_id": self.recovery_id,
            "job_id": self.job_id,
            "account_commitment": self.account_commitment,
            "guardian_set_root": self.guardian_set_root,
            "recovery_proof_root": self.recovery_proof_root,
            "nullifier_root": self.nullifier_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "guardian_threshold": self.guardian_threshold,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-ACCOUNT-RECOVERY",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &PqBatchVerifierCacheConfig) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("account_recovery.recovery_id", &self.recovery_id)?;
        ensure_non_empty("account_recovery.job_id", &self.job_id)?;
        ensure_hex_root(
            "account_recovery.account_commitment",
            &self.account_commitment,
        )?;
        ensure_hex_root(
            "account_recovery.guardian_set_root",
            &self.guardian_set_root,
        )?;
        ensure_hex_root(
            "account_recovery.recovery_proof_root",
            &self.recovery_proof_root,
        )?;
        ensure_hex_root("account_recovery.nullifier_root", &self.nullifier_root)?;
        ensure_height_order("account_recovery", self.created_height, self.expires_height)?;
        if self.guardian_threshold == 0 {
            return Err(format!(
                "account_recovery {} guardian_threshold must be positive",
                self.recovery_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "account_recovery {} privacy set is below minimum",
                self.recovery_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeFinalityAttestationCacheEntry {
    pub attestation_id: String,
    pub job_id: String,
    pub bridge_domain: String,
    pub source_finality_root: String,
    pub destination_checkpoint_root: String,
    pub committee_signature_root: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub finality_depth: u64,
    pub signer_weight_bps: u64,
    pub status: CacheEntryStatus,
}

impl BridgeFinalityAttestationCacheEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_finality_attestation_cache_entry",
            "attestation_id": self.attestation_id,
            "job_id": self.job_id,
            "bridge_domain": self.bridge_domain,
            "source_finality_root": self.source_finality_root,
            "destination_checkpoint_root": self.destination_checkpoint_root,
            "committee_signature_root": self.committee_signature_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "finality_depth": self.finality_depth,
            "signer_weight_bps": self.signer_weight_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-BRIDGE-FINALITY",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("bridge_finality.attestation_id", &self.attestation_id)?;
        ensure_non_empty("bridge_finality.job_id", &self.job_id)?;
        ensure_non_empty("bridge_finality.bridge_domain", &self.bridge_domain)?;
        ensure_hex_root(
            "bridge_finality.source_finality_root",
            &self.source_finality_root,
        )?;
        ensure_hex_root(
            "bridge_finality.destination_checkpoint_root",
            &self.destination_checkpoint_root,
        )?;
        ensure_hex_root(
            "bridge_finality.committee_signature_root",
            &self.committee_signature_root,
        )?;
        ensure_height_order("bridge_finality", self.created_height, self.expires_height)?;
        if self.finality_depth == 0 {
            return Err(format!(
                "bridge_finality {} finality_depth must be positive",
                self.attestation_id
            ));
        }
        if self.signer_weight_bps > PQ_BATCH_VERIFIER_CACHE_MAX_BPS {
            return Err(format!(
                "bridge_finality {} signer_weight_bps exceeds bps max",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvalidationEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub starts_height: u64,
    pub ends_height: u64,
    pub invalidated_root: String,
    pub reason_code: String,
    pub authority_commitment: String,
    pub affected_entry_count: u64,
}

impl InvalidationEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "invalidation_epoch",
            "epoch_id": self.epoch_id,
            "epoch_index": self.epoch_index,
            "starts_height": self.starts_height,
            "ends_height": self.ends_height,
            "invalidated_root": self.invalidated_root,
            "reason_code": self.reason_code,
            "authority_commitment": self.authority_commitment,
            "affected_entry_count": self.affected_entry_count,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-INVALIDATION-EPOCH",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("invalidation.epoch_id", &self.epoch_id)?;
        ensure_non_empty("invalidation.reason_code", &self.reason_code)?;
        ensure_hex_root("invalidation.invalidated_root", &self.invalidated_root)?;
        ensure_hex_root(
            "invalidation.authority_commitment",
            &self.authority_commitment,
        )?;
        ensure_height_order("invalidation", self.starts_height, self.ends_height)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeVerificationLane {
    pub lane_id: String,
    pub lane_kind: PqVerifierLaneKind,
    pub queue_root: String,
    pub sponsor_pool_commitment: String,
    pub max_fee_micro_units: u64,
    pub max_batch_weight: u64,
    pub priority_weight_bps: u64,
    pub reserved_capacity_bps: u64,
    pub privacy_floor: u64,
    pub open_height: u64,
    pub close_height: Option<u64>,
}

impl LowFeeVerificationLane {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_verification_lane",
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "queue_root": self.queue_root,
            "sponsor_pool_commitment": self.sponsor_pool_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_batch_weight": self.max_batch_weight,
            "priority_weight_bps": self.priority_weight_bps,
            "reserved_capacity_bps": self.reserved_capacity_bps,
            "privacy_floor": self.privacy_floor,
            "open_height": self.open_height,
            "close_height": self.close_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-LOW-FEE-LANE",
            &self.public_record(),
        )
    }

    pub fn validate(&self, config: &PqBatchVerifierCacheConfig) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("lane.lane_id", &self.lane_id)?;
        ensure_hex_root("lane.queue_root", &self.queue_root)?;
        ensure_hex_root(
            "lane.sponsor_pool_commitment",
            &self.sponsor_pool_commitment,
        )?;
        if self.max_fee_micro_units > config.low_fee_cap_micro_units {
            return Err(format!("lane {} exceeds low-fee cap", self.lane_id));
        }
        if self.max_batch_weight > config.max_batch_weight {
            return Err(format!("lane {} exceeds max batch weight", self.lane_id));
        }
        if self.priority_weight_bps > PQ_BATCH_VERIFIER_CACHE_MAX_BPS
            || self.reserved_capacity_bps > PQ_BATCH_VERIFIER_CACHE_MAX_BPS
        {
            return Err(format!("lane {} bps values exceed max", self.lane_id));
        }
        if self.privacy_floor < config.min_privacy_set_size {
            return Err(format!("lane {} privacy floor below minimum", self.lane_id));
        }
        if let Some(close_height) = self.close_height {
            if close_height <= self.open_height {
                return Err(format!(
                    "lane {} close height must be after open",
                    self.lane_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyPreservingCacheTag {
    pub tag_id: String,
    pub tag_bucket: String,
    pub blinded_subject_root: String,
    pub unlinkability_set_root: String,
    pub nullifier_domain_root: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub reuse_count: u64,
    pub max_reuse: u64,
}

impl PrivacyPreservingCacheTag {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_preserving_cache_tag",
            "tag_id": self.tag_id,
            "tag_bucket": self.tag_bucket,
            "blinded_subject_root": self.blinded_subject_root,
            "unlinkability_set_root": self.unlinkability_set_root,
            "nullifier_domain_root": self.nullifier_domain_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "privacy_set_size": self.privacy_set_size,
            "reuse_count": self.reuse_count,
            "max_reuse": self.max_reuse,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-BATCH-VERIFIER-CACHE-PRIVACY-TAG", &self.public_record())
    }

    pub fn validate(&self, config: &PqBatchVerifierCacheConfig) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("privacy_tag.tag_id", &self.tag_id)?;
        ensure_non_empty("privacy_tag.tag_bucket", &self.tag_bucket)?;
        ensure_hex_root(
            "privacy_tag.blinded_subject_root",
            &self.blinded_subject_root,
        )?;
        ensure_hex_root(
            "privacy_tag.unlinkability_set_root",
            &self.unlinkability_set_root,
        )?;
        ensure_hex_root(
            "privacy_tag.nullifier_domain_root",
            &self.nullifier_domain_root,
        )?;
        ensure_height_order("privacy_tag", self.created_height, self.expires_height)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "privacy_tag {} privacy set below minimum",
                self.tag_id
            ));
        }
        if self.max_reuse > config.max_reuse_per_tag {
            return Err(format!(
                "privacy_tag {} max reuse exceeds config",
                self.tag_id
            ));
        }
        if self.reuse_count > self.max_reuse {
            return Err(format!("privacy_tag {} reuse exceeds max", self.tag_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeterministicCachePublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_height: u64,
    pub sequence: u64,
    pub publisher_commitment: String,
}

impl DeterministicCachePublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
        emitted_height: u64,
        sequence: u64,
    ) -> PqBatchVerifierCacheResult<Self> {
        ensure_non_empty("public_record.record_kind", record_kind)?;
        ensure_non_empty("public_record.subject_id", subject_id)?;
        ensure_hex_root("public_record.subject_root", subject_root)?;
        let payload = json!({
            "record_kind": record_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "emitted_height": emitted_height,
            "sequence": sequence,
        });
        let payload_root = payload_root("PQ-BATCH-VERIFIER-CACHE-PUBLIC-PAYLOAD", &payload);
        let record_id = domain_hash(
            "PQ-BATCH-VERIFIER-CACHE-PUBLIC-RECORD-ID",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(subject_root),
                HashPart::Int(sequence as i128),
            ],
            16,
        );
        let publisher_commitment = domain_hash(
            "PQ-BATCH-VERIFIER-CACHE-PUBLISHER-COMMITMENT",
            &[
                HashPart::Str(PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL),
                HashPart::Int(emitted_height as i128),
                HashPart::Str(&payload_root),
            ],
            32,
        );

        Ok(Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_height,
            sequence,
            publisher_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_batch_verifier_cache_public_record",
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_height": self.emitted_height,
            "sequence": self.sequence,
            "publisher_commitment": self.publisher_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PQ-BATCH-VERIFIER-CACHE-PUBLIC-RECORD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<()> {
        ensure_non_empty("public_record.record_id", &self.record_id)?;
        ensure_non_empty("public_record.record_kind", &self.record_kind)?;
        ensure_non_empty("public_record.subject_id", &self.subject_id)?;
        ensure_hex_root("public_record.subject_root", &self.subject_root)?;
        ensure_hex_root("public_record.payload_root", &self.payload_root)?;
        ensure_hex_root(
            "public_record.publisher_commitment",
            &self.publisher_commitment,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqBatchVerifierCacheRoots {
    pub config_root: String,
    pub batch_job_root: String,
    pub verifier_key_catalog_root: String,
    pub recursive_proof_cache_root: String,
    pub da_sample_cache_root: String,
    pub account_recovery_cache_root: String,
    pub bridge_finality_cache_root: String,
    pub invalidation_epoch_root: String,
    pub low_fee_lane_root: String,
    pub privacy_tag_root: String,
    pub public_record_root: String,
}

impl PqBatchVerifierCacheRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "batch_job_root": self.batch_job_root,
            "verifier_key_catalog_root": self.verifier_key_catalog_root,
            "recursive_proof_cache_root": self.recursive_proof_cache_root,
            "da_sample_cache_root": self.da_sample_cache_root,
            "account_recovery_cache_root": self.account_recovery_cache_root,
            "bridge_finality_cache_root": self.bridge_finality_cache_root,
            "invalidation_epoch_root": self.invalidation_epoch_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "privacy_tag_root": self.privacy_tag_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-BATCH-VERIFIER-CACHE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqBatchVerifierCacheCounters {
    pub batch_job_count: u64,
    pub live_batch_job_count: u64,
    pub finalized_batch_job_count: u64,
    pub verifier_key_count: u64,
    pub active_verifier_key_count: u64,
    pub recursive_cache_count: u64,
    pub recursive_cache_reuse_count: u64,
    pub da_sample_cache_count: u64,
    pub account_recovery_cache_count: u64,
    pub bridge_finality_cache_count: u64,
    pub invalidation_epoch_count: u64,
    pub invalidated_entry_count: u64,
    pub low_fee_lane_count: u64,
    pub privacy_tag_count: u64,
    pub privacy_tag_reuse_count: u64,
    pub public_record_count: u64,
    pub total_proof_count: u64,
    pub total_batch_weight: u64,
    pub total_batch_bytes: u64,
}

impl PqBatchVerifierCacheCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_job_count": self.batch_job_count,
            "live_batch_job_count": self.live_batch_job_count,
            "finalized_batch_job_count": self.finalized_batch_job_count,
            "verifier_key_count": self.verifier_key_count,
            "active_verifier_key_count": self.active_verifier_key_count,
            "recursive_cache_count": self.recursive_cache_count,
            "recursive_cache_reuse_count": self.recursive_cache_reuse_count,
            "da_sample_cache_count": self.da_sample_cache_count,
            "account_recovery_cache_count": self.account_recovery_cache_count,
            "bridge_finality_cache_count": self.bridge_finality_cache_count,
            "invalidation_epoch_count": self.invalidation_epoch_count,
            "invalidated_entry_count": self.invalidated_entry_count,
            "low_fee_lane_count": self.low_fee_lane_count,
            "privacy_tag_count": self.privacy_tag_count,
            "privacy_tag_reuse_count": self.privacy_tag_reuse_count,
            "public_record_count": self.public_record_count,
            "total_proof_count": self.total_proof_count,
            "total_batch_weight": self.total_batch_weight,
            "total_batch_bytes": self.total_batch_bytes,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-BATCH-VERIFIER-CACHE-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqBatchVerifierCacheState {
    pub height: u64,
    pub status: String,
    pub config: PqBatchVerifierCacheConfig,
    pub batch_jobs: BTreeMap<String, PqSignatureProofBatchJob>,
    pub verifier_keys: BTreeMap<String, VerifierKeyCatalogEntry>,
    pub recursive_proof_cache: BTreeMap<String, RecursiveProofCacheEntry>,
    pub da_sample_cache: BTreeMap<String, DaSampleProofCacheEntry>,
    pub account_recovery_cache: BTreeMap<String, AccountRecoveryProofCacheEntry>,
    pub bridge_finality_cache: BTreeMap<String, BridgeFinalityAttestationCacheEntry>,
    pub invalidation_epochs: BTreeMap<String, InvalidationEpoch>,
    pub low_fee_lanes: BTreeMap<String, LowFeeVerificationLane>,
    pub privacy_tags: BTreeMap<String, PrivacyPreservingCacheTag>,
    pub public_records: BTreeMap<String, DeterministicCachePublicRecord>,
}

impl PqBatchVerifierCacheState {
    pub fn devnet() -> PqBatchVerifierCacheResult<Self> {
        let config = PqBatchVerifierCacheConfig::devnet();
        config.validate()?;
        let mut state = Self {
            height: PQ_BATCH_VERIFIER_CACHE_DEVNET_HEIGHT,
            status: STATE_STATUS_ACTIVE.to_string(),
            config,
            batch_jobs: BTreeMap::new(),
            verifier_keys: BTreeMap::new(),
            recursive_proof_cache: BTreeMap::new(),
            da_sample_cache: BTreeMap::new(),
            account_recovery_cache: BTreeMap::new(),
            bridge_finality_cache: BTreeMap::new(),
            invalidation_epochs: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            privacy_tags: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };

        state.install_devnet_catalog()?;
        state.install_devnet_lanes_and_tags()?;
        state.install_devnet_cache_entries()?;
        state.validate().map(|_| state)
    }

    pub fn set_height(&mut self, height: u64) -> PqBatchVerifierCacheResult<()> {
        self.height = height;
        self.validate().map(|_| ())
    }

    pub fn roots(&self) -> PqBatchVerifierCacheRoots {
        PqBatchVerifierCacheRoots {
            config_root: self.config.state_root(),
            batch_job_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-JOBS",
                sorted_values(&self.batch_jobs, PqSignatureProofBatchJob::public_record),
            ),
            verifier_key_catalog_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-VERIFIER-KEYS",
                sorted_values(&self.verifier_keys, VerifierKeyCatalogEntry::public_record),
            ),
            recursive_proof_cache_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-RECURSIVE-ENTRIES",
                sorted_values(
                    &self.recursive_proof_cache,
                    RecursiveProofCacheEntry::public_record,
                ),
            ),
            da_sample_cache_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-DA-SAMPLES",
                sorted_values(
                    &self.da_sample_cache,
                    DaSampleProofCacheEntry::public_record,
                ),
            ),
            account_recovery_cache_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-ACCOUNT-RECOVERIES",
                sorted_values(
                    &self.account_recovery_cache,
                    AccountRecoveryProofCacheEntry::public_record,
                ),
            ),
            bridge_finality_cache_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-BRIDGE-FINALITY",
                sorted_values(
                    &self.bridge_finality_cache,
                    BridgeFinalityAttestationCacheEntry::public_record,
                ),
            ),
            invalidation_epoch_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-INVALIDATION-EPOCHS",
                sorted_values(&self.invalidation_epochs, InvalidationEpoch::public_record),
            ),
            low_fee_lane_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-LOW-FEE-LANES",
                sorted_values(&self.low_fee_lanes, LowFeeVerificationLane::public_record),
            ),
            privacy_tag_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-PRIVACY-TAGS",
                sorted_values(&self.privacy_tags, PrivacyPreservingCacheTag::public_record),
            ),
            public_record_root: collection_root(
                "PQ-BATCH-VERIFIER-CACHE-PUBLIC-RECORDS",
                sorted_values(
                    &self.public_records,
                    DeterministicCachePublicRecord::public_record,
                ),
            ),
        }
    }

    pub fn counters(&self) -> PqBatchVerifierCacheCounters {
        PqBatchVerifierCacheCounters {
            batch_job_count: self.batch_jobs.len() as u64,
            live_batch_job_count: self
                .batch_jobs
                .values()
                .filter(|job| job.status.live())
                .count() as u64,
            finalized_batch_job_count: self
                .batch_jobs
                .values()
                .filter(|job| job.status.terminal())
                .count() as u64,
            verifier_key_count: self.verifier_keys.len() as u64,
            active_verifier_key_count: self
                .verifier_keys
                .values()
                .filter(|key| key.status.usable())
                .count() as u64,
            recursive_cache_count: self.recursive_proof_cache.len() as u64,
            recursive_cache_reuse_count: self
                .recursive_proof_cache
                .values()
                .map(|entry| entry.reuse_count)
                .sum(),
            da_sample_cache_count: self.da_sample_cache.len() as u64,
            account_recovery_cache_count: self.account_recovery_cache.len() as u64,
            bridge_finality_cache_count: self.bridge_finality_cache.len() as u64,
            invalidation_epoch_count: self.invalidation_epochs.len() as u64,
            invalidated_entry_count: self
                .invalidation_epochs
                .values()
                .map(|epoch| epoch.affected_entry_count)
                .sum(),
            low_fee_lane_count: self.low_fee_lanes.len() as u64,
            privacy_tag_count: self.privacy_tags.len() as u64,
            privacy_tag_reuse_count: self.privacy_tags.values().map(|tag| tag.reuse_count).sum(),
            public_record_count: self.public_records.len() as u64,
            total_proof_count: self.batch_jobs.values().map(|job| job.proof_count).sum(),
            total_batch_weight: self.batch_jobs.values().map(|job| job.batch_weight).sum(),
            total_batch_bytes: self.batch_jobs.values().map(|job| job.byte_size).sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        let mut record = json!({
            "kind": "pq_batch_verifier_cache_state",
            "protocol": PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL,
            "protocol_version": PQ_BATCH_VERIFIER_CACHE_PROTOCOL_VERSION,
            "schema_version": PQ_BATCH_VERIFIER_CACHE_SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "root_commitment": roots.state_root(),
            "counter_commitment": counters.state_root(),
            "batch_jobs": self.batch_jobs.values().map(PqSignatureProofBatchJob::public_record).collect::<Vec<_>>(),
            "verifier_keys": self.verifier_keys.values().map(VerifierKeyCatalogEntry::public_record).collect::<Vec<_>>(),
            "recursive_proof_cache": self.recursive_proof_cache.values().map(RecursiveProofCacheEntry::public_record).collect::<Vec<_>>(),
            "da_sample_cache": self.da_sample_cache.values().map(DaSampleProofCacheEntry::public_record).collect::<Vec<_>>(),
            "account_recovery_cache": self.account_recovery_cache.values().map(AccountRecoveryProofCacheEntry::public_record).collect::<Vec<_>>(),
            "bridge_finality_cache": self.bridge_finality_cache.values().map(BridgeFinalityAttestationCacheEntry::public_record).collect::<Vec<_>>(),
            "invalidation_epochs": self.invalidation_epochs.values().map(InvalidationEpoch::public_record).collect::<Vec<_>>(),
            "low_fee_lanes": self.low_fee_lanes.values().map(LowFeeVerificationLane::public_record).collect::<Vec<_>>(),
            "privacy_tags": self.privacy_tags.values().map(PrivacyPreservingCacheTag::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(DeterministicCachePublicRecord::public_record).collect::<Vec<_>>(),
        });

        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        pq_batch_verifier_cache_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> PqBatchVerifierCacheResult<String> {
        self.config.validate()?;
        ensure_non_empty("state.status", &self.status)?;
        ensure_at_most("batch_jobs", self.batch_jobs.len(), self.config.max_jobs)?;
        ensure_at_most(
            "verifier_keys",
            self.verifier_keys.len(),
            self.config.max_verifier_keys,
        )?;
        ensure_at_most(
            "recursive_proof_cache",
            self.recursive_proof_cache.len(),
            self.config.max_recursive_entries,
        )?;
        ensure_at_most(
            "da_sample_cache",
            self.da_sample_cache.len(),
            self.config.max_da_sample_entries,
        )?;
        ensure_at_most(
            "account_recovery_cache",
            self.account_recovery_cache.len(),
            self.config.max_account_recovery_entries,
        )?;
        ensure_at_most(
            "bridge_finality_cache",
            self.bridge_finality_cache.len(),
            self.config.max_bridge_finality_entries,
        )?;
        ensure_at_most(
            "invalidation_epochs",
            self.invalidation_epochs.len(),
            self.config.max_invalidation_epochs,
        )?;
        ensure_at_most(
            "low_fee_lanes",
            self.low_fee_lanes.len(),
            self.config.max_low_fee_lanes,
        )?;
        ensure_at_most(
            "privacy_tags",
            self.privacy_tags.len(),
            self.config.max_privacy_tags,
        )?;
        ensure_at_most(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;

        let mut lane_ids = BTreeSet::new();
        for (lane_id, lane) in &self.low_fee_lanes {
            if lane_id != &lane.lane_id {
                return Err(format!("lane map key {lane_id} does not match lane_id"));
            }
            lane.validate(&self.config)?;
            lane_ids.insert(lane_id.clone());
        }

        let mut key_ids = BTreeSet::new();
        for (key_id, key) in &self.verifier_keys {
            if key_id != &key.key_id {
                return Err(format!(
                    "verifier key map key {key_id} does not match key_id"
                ));
            }
            key.validate(&self.config)?;
            key_ids.insert(key_id.clone());
        }

        let mut tag_ids = BTreeSet::new();
        for (tag_id, tag) in &self.privacy_tags {
            if tag_id != &tag.tag_id {
                return Err(format!(
                    "privacy tag map key {tag_id} does not match tag_id"
                ));
            }
            tag.validate(&self.config)?;
            tag_ids.insert(tag_id.clone());
        }

        let mut job_ids = BTreeSet::new();
        for (job_id, job) in &self.batch_jobs {
            if job_id != &job.job_id {
                return Err(format!("job map key {job_id} does not match job_id"));
            }
            job.validate(&self.config)?;
            if !key_ids.contains(&job.verifier_key_id) {
                return Err(format!(
                    "job {} references missing verifier key",
                    job.job_id
                ));
            }
            if !lane_ids.contains(&job.lane_id) {
                return Err(format!("job {} references missing lane", job.job_id));
            }
            if !tag_ids.contains(&job.privacy_tag_id) {
                return Err(format!("job {} references missing privacy tag", job.job_id));
            }
            job_ids.insert(job_id.clone());
        }

        for (entry_id, entry) in &self.recursive_proof_cache {
            if entry_id != &entry.entry_id {
                return Err(format!(
                    "recursive cache map key {entry_id} does not match entry_id"
                ));
            }
            entry.validate()?;
            if !job_ids.contains(&entry.job_id) {
                return Err(format!(
                    "recursive cache {} references missing job",
                    entry.entry_id
                ));
            }
            if !key_ids.contains(&entry.verifier_key_id) {
                return Err(format!(
                    "recursive cache {} references missing verifier key",
                    entry.entry_id
                ));
            }
        }

        for (sample_id, entry) in &self.da_sample_cache {
            if sample_id != &entry.sample_id {
                return Err(format!(
                    "da sample map key {sample_id} does not match sample_id"
                ));
            }
            entry.validate()?;
            if !job_ids.contains(&entry.job_id) {
                return Err(format!(
                    "da sample {} references missing job",
                    entry.sample_id
                ));
            }
        }

        for (recovery_id, entry) in &self.account_recovery_cache {
            if recovery_id != &entry.recovery_id {
                return Err(format!(
                    "account recovery map key {recovery_id} does not match recovery_id"
                ));
            }
            entry.validate(&self.config)?;
            if !job_ids.contains(&entry.job_id) {
                return Err(format!(
                    "account recovery {} references missing job",
                    entry.recovery_id
                ));
            }
        }

        for (attestation_id, entry) in &self.bridge_finality_cache {
            if attestation_id != &entry.attestation_id {
                return Err(format!(
                    "bridge finality map key {attestation_id} does not match attestation_id"
                ));
            }
            entry.validate()?;
            if !job_ids.contains(&entry.job_id) {
                return Err(format!(
                    "bridge finality {} references missing job",
                    entry.attestation_id
                ));
            }
        }

        for (epoch_id, epoch) in &self.invalidation_epochs {
            if epoch_id != &epoch.epoch_id {
                return Err(format!(
                    "invalidation epoch map key {epoch_id} does not match epoch_id"
                ));
            }
            epoch.validate()?;
        }

        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err(format!(
                    "public record map key {record_id} does not match record_id"
                ));
            }
            record.validate()?;
        }

        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_batch_verifier_cache_state",
            "protocol": PQ_BATCH_VERIFIER_CACHE_PROTOCOL_LABEL,
            "protocol_version": PQ_BATCH_VERIFIER_CACHE_PROTOCOL_VERSION,
            "schema_version": PQ_BATCH_VERIFIER_CACHE_SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "status": self.status,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "root_commitment": roots.state_root(),
            "counter_commitment": counters.state_root(),
            "batch_jobs": self.batch_jobs.values().map(PqSignatureProofBatchJob::public_record).collect::<Vec<_>>(),
            "verifier_keys": self.verifier_keys.values().map(VerifierKeyCatalogEntry::public_record).collect::<Vec<_>>(),
            "recursive_proof_cache": self.recursive_proof_cache.values().map(RecursiveProofCacheEntry::public_record).collect::<Vec<_>>(),
            "da_sample_cache": self.da_sample_cache.values().map(DaSampleProofCacheEntry::public_record).collect::<Vec<_>>(),
            "account_recovery_cache": self.account_recovery_cache.values().map(AccountRecoveryProofCacheEntry::public_record).collect::<Vec<_>>(),
            "bridge_finality_cache": self.bridge_finality_cache.values().map(BridgeFinalityAttestationCacheEntry::public_record).collect::<Vec<_>>(),
            "invalidation_epochs": self.invalidation_epochs.values().map(InvalidationEpoch::public_record).collect::<Vec<_>>(),
            "low_fee_lanes": self.low_fee_lanes.values().map(LowFeeVerificationLane::public_record).collect::<Vec<_>>(),
            "privacy_tags": self.privacy_tags.values().map(PrivacyPreservingCacheTag::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(DeterministicCachePublicRecord::public_record).collect::<Vec<_>>(),
        })
    }

    fn insert_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        subject_root: &str,
    ) -> PqBatchVerifierCacheResult<()> {
        let sequence = self.public_records.len() as u64;
        let record = DeterministicCachePublicRecord::new(
            record_kind,
            subject_id,
            subject_root,
            self.height,
            sequence,
        )?;
        self.public_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    fn install_devnet_catalog(&mut self) -> PqBatchVerifierCacheResult<()> {
        let keys = vec![
            VerifierKeyCatalogEntry {
                key_id: "vk-ml-dsa-65-devnet-signatures".to_string(),
                work_kind: PqVerifierWorkKind::PqSignature,
                scheme: "ML-DSA-65".to_string(),
                verification_domain: "devnet-wallet-and-sequencer-signatures".to_string(),
                key_commitment: domain_hash(
                    "PQ-BATCH-VERIFIER-CACHE-DEVNET-VK",
                    &[HashPart::Str("ml-dsa-65")],
                    32,
                ),
                parameter_root: domain_hash(
                    "PQ-BATCH-VERIFIER-CACHE-DEVNET-PARAMS",
                    &[HashPart::Str("ml-dsa-65")],
                    32,
                ),
                activated_height: self.height,
                retired_height: None,
                pq_security_bits: 256,
                status: VerifierKeyStatus::Active,
            },
            VerifierKeyCatalogEntry {
                key_id: "vk-recursive-rollup-devnet".to_string(),
                work_kind: PqVerifierWorkKind::RecursiveRollupProof,
                scheme: "stark-recursive-rollup-shake256-devnet".to_string(),
                verification_domain: "devnet-recursive-rollup-validity".to_string(),
                key_commitment: domain_hash(
                    "PQ-BATCH-VERIFIER-CACHE-DEVNET-VK",
                    &[HashPart::Str("recursive-rollup")],
                    32,
                ),
                parameter_root: domain_hash(
                    "PQ-BATCH-VERIFIER-CACHE-DEVNET-PARAMS",
                    &[HashPart::Str("recursive-rollup")],
                    32,
                ),
                activated_height: self.height,
                retired_height: None,
                pq_security_bits: 256,
                status: VerifierKeyStatus::Active,
            },
            VerifierKeyCatalogEntry {
                key_id: "vk-bridge-finality-devnet".to_string(),
                work_kind: PqVerifierWorkKind::BridgeFinalityAttestation,
                scheme: "ml-dsa-87-bridge-finality-threshold".to_string(),
                verification_domain: "devnet-monero-bridge-finality".to_string(),
                key_commitment: domain_hash(
                    "PQ-BATCH-VERIFIER-CACHE-DEVNET-VK",
                    &[HashPart::Str("bridge-finality")],
                    32,
                ),
                parameter_root: domain_hash(
                    "PQ-BATCH-VERIFIER-CACHE-DEVNET-PARAMS",
                    &[HashPart::Str("bridge-finality")],
                    32,
                ),
                activated_height: self.height,
                retired_height: None,
                pq_security_bits: 256,
                status: VerifierKeyStatus::Active,
            },
        ];

        for key in keys {
            key.validate(&self.config)?;
            let root = key.state_root();
            let key_id = key.key_id.clone();
            self.verifier_keys.insert(key_id.clone(), key);
            self.insert_public_record("verifier_key_catalog_entry", &key_id, &root)?;
        }
        Ok(())
    }

    fn install_devnet_lanes_and_tags(&mut self) -> PqBatchVerifierCacheResult<()> {
        let lane = LowFeeVerificationLane {
            lane_id: "lane-low-fee-public-good-devnet".to_string(),
            lane_kind: PqVerifierLaneKind::LowFeePublicGood,
            queue_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-LANE-QUEUE",
                &[HashPart::Str("low-fee-public-good")],
                32,
            ),
            sponsor_pool_commitment: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-LANE-SPONSOR",
                &[HashPart::Str("low-fee-public-good")],
                32,
            ),
            max_fee_micro_units: self.config.low_fee_cap_micro_units,
            max_batch_weight: self.config.max_batch_weight / 2,
            priority_weight_bps: 2_500,
            reserved_capacity_bps: 1_500,
            privacy_floor: self.config.min_privacy_set_size,
            open_height: self.height,
            close_height: None,
        };
        lane.validate(&self.config)?;
        let lane_root = lane.state_root();
        let lane_id = lane.lane_id.clone();
        self.low_fee_lanes.insert(lane_id.clone(), lane);
        self.insert_public_record("low_fee_verification_lane", &lane_id, &lane_root)?;

        let tag = PrivacyPreservingCacheTag {
            tag_id: "tag-devnet-low-fee-bucket-0001".to_string(),
            tag_bucket: "low_fee_public_good_128".to_string(),
            blinded_subject_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-TAG-BLINDED",
                &[HashPart::Str("tag-0001")],
                32,
            ),
            unlinkability_set_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-TAG-UNLINKABILITY",
                &[HashPart::Str("tag-0001")],
                32,
            ),
            nullifier_domain_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-TAG-NULLIFIER",
                &[HashPart::Str("tag-0001")],
                32,
            ),
            created_height: self.height,
            expires_height: self.height + self.config.privacy_tag_ttl_blocks,
            privacy_set_size: self.config.min_privacy_set_size,
            reuse_count: 3,
            max_reuse: self.config.max_reuse_per_tag,
        };
        tag.validate(&self.config)?;
        let tag_root = tag.state_root();
        let tag_id = tag.tag_id.clone();
        self.privacy_tags.insert(tag_id.clone(), tag);
        self.insert_public_record("privacy_preserving_cache_tag", &tag_id, &tag_root)?;
        Ok(())
    }

    fn install_devnet_cache_entries(&mut self) -> PqBatchVerifierCacheResult<()> {
        let job = PqSignatureProofBatchJob {
            job_id: "job-devnet-recursive-fast-path-0001".to_string(),
            lane_id: "lane-low-fee-public-good-devnet".to_string(),
            work_kind: PqVerifierWorkKind::RecursiveRollupProof,
            verifier_key_id: "vk-recursive-rollup-devnet".to_string(),
            input_commitment: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-JOB-INPUT",
                &[HashPart::Str("recursive-fast-path-0001")],
                32,
            ),
            batch_transcript_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-JOB-TRANSCRIPT",
                &[HashPart::Str("recursive-fast-path-0001")],
                32,
            ),
            privacy_tag_id: "tag-devnet-low-fee-bucket-0001".to_string(),
            submitted_height: self.height,
            expires_height: self.height + self.config.job_ttl_blocks,
            proof_count: 64,
            byte_size: 180_000,
            batch_weight: 240_000,
            sponsor_fee_micro_units: self.config.low_fee_cap_micro_units,
            cache_hit_count: 11,
            status: PqBatchJobStatus::Cached,
        };
        job.validate(&self.config)?;
        let job_root = job.state_root();
        let job_id = job.job_id.clone();
        self.batch_jobs.insert(job_id.clone(), job);
        self.insert_public_record("pq_signature_proof_batch_job", &job_id, &job_root)?;

        let recursive = RecursiveProofCacheEntry {
            entry_id: "recursive-cache-devnet-0001".to_string(),
            job_id: job_id.clone(),
            verifier_key_id: "vk-recursive-rollup-devnet".to_string(),
            recursion_layer: 2,
            input_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECURSIVE-INPUT",
                &[HashPart::Str("recursive-cache-0001")],
                32,
            ),
            output_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECURSIVE-OUTPUT",
                &[HashPart::Str("recursive-cache-0001")],
                32,
            ),
            accumulator_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECURSIVE-ACCUMULATOR",
                &[HashPart::Str("recursive-cache-0001")],
                32,
            ),
            created_height: self.height,
            expires_height: self.height + self.config.recursive_entry_ttl_blocks,
            reuse_count: 11,
            status: CacheEntryStatus::Hot,
        };
        recursive.validate()?;
        let recursive_root = recursive.state_root();
        let recursive_id = recursive.entry_id.clone();
        self.recursive_proof_cache
            .insert(recursive_id.clone(), recursive);
        self.insert_public_record(
            "recursive_proof_cache_entry",
            &recursive_id,
            &recursive_root,
        )?;

        let da_sample = DaSampleProofCacheEntry {
            sample_id: "da-sample-devnet-0001".to_string(),
            job_id: job_id.clone(),
            shard_id: "da-shard-private-orders-0001".to_string(),
            erasure_commitment: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-DA-ERASURE",
                &[HashPart::Str("da-sample-0001")],
                32,
            ),
            sample_proof_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-DA-PROOF",
                &[HashPart::Str("da-sample-0001")],
                32,
            ),
            availability_window_start: self.height,
            availability_window_end: self.height + self.config.da_sample_ttl_blocks,
            sample_count: 96,
            withheld_sample_count: 0,
            status: CacheEntryStatus::Warm,
        };
        da_sample.validate()?;
        let da_root = da_sample.state_root();
        let da_id = da_sample.sample_id.clone();
        self.da_sample_cache.insert(da_id.clone(), da_sample);
        self.insert_public_record("da_sample_proof_cache_entry", &da_id, &da_root)?;

        let recovery = AccountRecoveryProofCacheEntry {
            recovery_id: "account-recovery-devnet-0001".to_string(),
            job_id: job_id.clone(),
            account_commitment: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECOVERY-ACCOUNT",
                &[HashPart::Str("recovery-0001")],
                32,
            ),
            guardian_set_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECOVERY-GUARDIANS",
                &[HashPart::Str("recovery-0001")],
                32,
            ),
            recovery_proof_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECOVERY-PROOF",
                &[HashPart::Str("recovery-0001")],
                32,
            ),
            nullifier_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-RECOVERY-NULLIFIER",
                &[HashPart::Str("recovery-0001")],
                32,
            ),
            created_height: self.height,
            expires_height: self.height + self.config.account_recovery_ttl_blocks,
            guardian_threshold: 3,
            privacy_set_size: self.config.min_privacy_set_size,
            status: CacheEntryStatus::Pinned,
        };
        recovery.validate(&self.config)?;
        let recovery_root = recovery.state_root();
        let recovery_id = recovery.recovery_id.clone();
        self.account_recovery_cache
            .insert(recovery_id.clone(), recovery);
        self.insert_public_record(
            "account_recovery_proof_cache_entry",
            &recovery_id,
            &recovery_root,
        )?;

        let bridge = BridgeFinalityAttestationCacheEntry {
            attestation_id: "bridge-finality-devnet-0001".to_string(),
            job_id,
            bridge_domain: "monero-devnet-to-nebula-l2-devnet".to_string(),
            source_finality_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-BRIDGE-SOURCE",
                &[HashPart::Str("bridge-0001")],
                32,
            ),
            destination_checkpoint_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-BRIDGE-DESTINATION",
                &[HashPart::Str("bridge-0001")],
                32,
            ),
            committee_signature_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-BRIDGE-COMMITTEE",
                &[HashPart::Str("bridge-0001")],
                32,
            ),
            created_height: self.height,
            expires_height: self.height + self.config.bridge_finality_ttl_blocks,
            finality_depth: 20,
            signer_weight_bps: 8_000,
            status: CacheEntryStatus::Hot,
        };
        bridge.validate()?;
        let bridge_root = bridge.state_root();
        let bridge_id = bridge.attestation_id.clone();
        self.bridge_finality_cache.insert(bridge_id.clone(), bridge);
        self.insert_public_record(
            "bridge_finality_attestation_cache_entry",
            &bridge_id,
            &bridge_root,
        )?;

        let invalidation = InvalidationEpoch {
            epoch_id: "invalidation-devnet-epoch-0001".to_string(),
            epoch_index: self.height / self.config.epoch_blocks,
            starts_height: self.height,
            ends_height: self.height + self.config.epoch_blocks,
            invalidated_root: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-INVALIDATED",
                &[HashPart::Str("empty")],
                32,
            ),
            reason_code: "devnet-empty-baseline".to_string(),
            authority_commitment: domain_hash(
                "PQ-BATCH-VERIFIER-CACHE-DEVNET-INVALIDATION-AUTHORITY",
                &[HashPart::Str("sequencer-cache-committee")],
                32,
            ),
            affected_entry_count: 0,
        };
        invalidation.validate()?;
        let invalidation_root = invalidation.state_root();
        let invalidation_id = invalidation.epoch_id.clone();
        self.invalidation_epochs
            .insert(invalidation_id.clone(), invalidation);
        self.insert_public_record("invalidation_epoch", &invalidation_id, &invalidation_root)?;
        Ok(())
    }
}

pub fn pq_batch_verifier_cache_state_root_from_record(record: &Value) -> String {
    payload_root("PQ-BATCH-VERIFIER-CACHE-STATE", record)
}
