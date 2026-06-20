use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash, HashPart},
    CHAIN_ID,
};

pub type PrivateSmartContractStateRentCompressorResult<T> = Result<T, String>;

pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_PROTOCOL_VERSION: &str =
    "nebula-private-smart-contract-state-rent-compressor-v1";
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEVNET_HEIGHT: u64 = 2_048;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_HASH_SUITE: &str =
    "SHAKE256-domain-separated";
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_SNAPSHOT_PROOF_SUITE: &str =
    "recursive-private-state-rent-snapshot-proof-v1";
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_WITNESS_CODEC: &str =
    "private-contract-witness-dictionary-delta-v1";
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_ERASURE_SUITE: &str =
    "private-state-erasure-receipt-pq-attested-v1";
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_EPOCH_BLOCKS: u64 = 192;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_RETENTION_BLOCKS: u64 = 21_600;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_COLD_AFTER_BLOCKS: u64 = 720;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_BUCKET_TARGET_KIB: u64 = 64;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_RENT_PER_KIB_UNITS: u64 = 3;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_WITNESS_SAVINGS_BPS: u64 = 6_000;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_LOW_FEE_LANE_CAPACITY_UNITS: u64 =
    500_000;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 25_000;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_MIN_PROOF_SECURITY_BITS: u16 = 192;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS: u64 = 10_000;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BUCKETS: usize = 2_048;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_SNAPSHOTS: usize = 1_024;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_WITNESSES: usize = 2_048;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_RECEIPTS: usize = 1_024;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_PRIVACY_ACCOUNTS: usize = 1_024;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_LANES: usize = 512;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_HINTS: usize = 4_096;
pub const PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_REBATES: usize = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBucketClass {
    ExecutionHot,
    SettlementWarm,
    AuditCold,
    ArchiveProof,
    ViewKeyIndex,
    BridgeMirror,
    EmergencyRecovery,
}

impl StorageBucketClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionHot => "execution_hot",
            Self::SettlementWarm => "settlement_warm",
            Self::AuditCold => "audit_cold",
            Self::ArchiveProof => "archive_proof",
            Self::ViewKeyIndex => "view_key_index",
            Self::BridgeMirror => "bridge_mirror",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn rent_multiplier_bps(self) -> u64 {
        match self {
            Self::ExecutionHot => 16_000,
            Self::SettlementWarm => 10_000,
            Self::AuditCold => 3_500,
            Self::ArchiveProof => 5_500,
            Self::ViewKeyIndex => 8_000,
            Self::BridgeMirror => 12_000,
            Self::EmergencyRecovery => 1_500,
        }
    }

    pub fn default_privacy_weight(self) -> u64 {
        match self {
            Self::ExecutionHot => 90,
            Self::SettlementWarm => 76,
            Self::AuditCold => 35,
            Self::ArchiveProof => 50,
            Self::ViewKeyIndex => 82,
            Self::BridgeMirror => 88,
            Self::EmergencyRecovery => 25,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Draft,
    Active,
    Compressing,
    RebatePending,
    Cold,
    Erasing,
    Erased,
    Frozen,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Compressing => "compressing",
            Self::RebatePending => "rebate_pending",
            Self::Cold => "cold",
            Self::Erasing => "erasing",
            Self::Erased => "erased",
            Self::Frozen => "frozen",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Compressing | Self::RebatePending | Self::Cold | Self::Erasing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Proposed,
    ProofAttached,
    Verified,
    RebateReserved,
    Published,
    Challenged,
    Superseded,
    Rejected,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::ProofAttached => "proof_attached",
            Self::Verified => "verified",
            Self::RebateReserved => "rebate_reserved",
            Self::Published => "published",
            Self::Challenged => "challenged",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub fn payable(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::RebateReserved | Self::Published
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmColdHintKind {
    HotRead,
    HotWrite,
    WarmRead,
    WarmWrite,
    ColdCandidate,
    ArchiveCandidate,
    EvictionGuard,
    EmergencyPin,
}

impl WarmColdHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotRead => "hot_read",
            Self::HotWrite => "hot_write",
            Self::WarmRead => "warm_read",
            Self::WarmWrite => "warm_write",
            Self::ColdCandidate => "cold_candidate",
            Self::ArchiveCandidate => "archive_candidate",
            Self::EvictionGuard => "eviction_guard",
            Self::EmergencyPin => "emergency_pin",
        }
    }

    pub fn heat_delta(self) -> i64 {
        match self {
            Self::HotRead => 18,
            Self::HotWrite => 35,
            Self::WarmRead => 9,
            Self::WarmWrite => 16,
            Self::ColdCandidate => -20,
            Self::ArchiveCandidate => -35,
            Self::EvictionGuard => 8,
            Self::EmergencyPin => 50,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessCompressionMode {
    DictionaryDelta,
    NullifierRunLength,
    SparseMerkleFrontier,
    RecursiveProofCarry,
    ViewTagBloom,
    ErasureTombstone,
}

impl WitnessCompressionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DictionaryDelta => "dictionary_delta",
            Self::NullifierRunLength => "nullifier_run_length",
            Self::SparseMerkleFrontier => "sparse_merkle_frontier",
            Self::RecursiveProofCarry => "recursive_proof_carry",
            Self::ViewTagBloom => "view_tag_bloom",
            Self::ErasureTombstone => "erasure_tombstone",
        }
    }

    pub fn projected_savings_bps(self) -> u64 {
        match self {
            Self::DictionaryDelta => 5_500,
            Self::NullifierRunLength => 4_250,
            Self::SparseMerkleFrontier => 6_750,
            Self::RecursiveProofCarry => 7_200,
            Self::ViewTagBloom => 3_800,
            Self::ErasureTombstone => 8_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureStatus {
    Requested,
    Witnessed,
    Proved,
    RebateReleased,
    Disputed,
    Finalized,
    Cancelled,
}

impl ErasureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Witnessed => "witnessed",
            Self::Proved => "proved",
            Self::RebateReleased => "rebate_released",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Finalized | Self::Cancelled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeLaneStatus {
    Active,
    Saturated,
    Paused,
    Draining,
    Retired,
}

impl LowFeeLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn accepting(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub epoch_blocks: u64,
    pub retention_blocks: u64,
    pub cold_after_blocks: u64,
    pub bucket_target_kib: u64,
    pub rent_per_kib_units: u64,
    pub rebate_bps: u64,
    pub witness_savings_bps: u64,
    pub low_fee_lane_capacity_units: u64,
    pub privacy_budget_units: u64,
    pub min_proof_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_EPOCH_BLOCKS,
            retention_blocks: PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_RETENTION_BLOCKS,
            cold_after_blocks:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_COLD_AFTER_BLOCKS,
            bucket_target_kib:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_BUCKET_TARGET_KIB,
            rent_per_kib_units:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_RENT_PER_KIB_UNITS,
            rebate_bps: PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_REBATE_BPS,
            witness_savings_bps:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_WITNESS_SAVINGS_BPS,
            low_fee_lane_capacity_units:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_LOW_FEE_LANE_CAPACITY_UNITS,
            privacy_budget_units:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_PRIVACY_BUDGET_UNITS,
            min_proof_security_bits:
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEFAULT_MIN_PROOF_SECURITY_BITS,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.epoch_blocks == 0 || self.retention_blocks == 0 || self.cold_after_blocks == 0 {
            return Err("state rent compressor timing windows must be positive".to_string());
        }
        if self.bucket_target_kib == 0 || self.rent_per_kib_units == 0 {
            return Err("state rent compressor bucket economics must be positive".to_string());
        }
        if self.rebate_bps > PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS {
            return Err("state rent compressor rebate exceeds maximum bps".to_string());
        }
        if self.witness_savings_bps > PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS {
            return Err("state rent compressor witness savings exceeds maximum bps".to_string());
        }
        if self.low_fee_lane_capacity_units == 0 || self.privacy_budget_units == 0 {
            return Err("state rent compressor budgets must be positive".to_string());
        }
        if self.min_proof_security_bits < 128 {
            return Err("state rent compressor proof security is below policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "retention_blocks": self.retention_blocks,
            "cold_after_blocks": self.cold_after_blocks,
            "bucket_target_kib": self.bucket_target_kib,
            "rent_per_kib_units": self.rent_per_kib_units,
            "rebate_bps": self.rebate_bps,
            "witness_savings_bps": self.witness_savings_bps,
            "low_fee_lane_capacity_units": self.low_fee_lane_capacity_units,
            "privacy_budget_units": self.privacy_budget_units,
            "min_proof_security_bits": self.min_proof_security_bits,
            "hash_suite": PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_HASH_SUITE,
            "snapshot_proof_suite": PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_SNAPSHOT_PROOF_SUITE,
            "witness_codec": PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_WITNESS_CODEC,
            "erasure_suite": PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_ERASURE_SUITE,
        })
    }

    pub fn root(&self) -> String {
        compressor_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialStorageBucket {
    pub bucket_id: String,
    pub contract_commitment: String,
    pub owner_commitment: String,
    pub class: StorageBucketClass,
    pub status: BucketStatus,
    pub encrypted_state_root: String,
    pub compressed_state_root: String,
    pub witness_root: String,
    pub access_pattern_root: String,
    pub privacy_budget_id: String,
    pub low_fee_lane_id: String,
    pub size_kib: u64,
    pub compressed_kib: u64,
    pub rent_due_units: u64,
    pub rebate_reserved_units: u64,
    pub last_touched_height: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub heat_score: i64,
}

impl ConfidentialStorageBucket {
    pub fn new(
        contract_commitment: &str,
        owner_commitment: &str,
        class: StorageBucketClass,
        size_kib: u64,
        compressed_kib: u64,
        opened_height: u64,
        config: &Config,
    ) -> Self {
        let normalized_compressed = compressed_kib.max(1).min(size_kib.max(1));
        let opened_height_text = opened_height.to_string();
        let size_kib_text = size_kib.to_string();
        let normalized_compressed_text = normalized_compressed.to_string();
        let bucket_id = compressor_hash(
            "BUCKET-ID",
            &[
                HashPart::Str(contract_commitment),
                HashPart::Str(owner_commitment),
                HashPart::Str(class.as_str()),
                HashPart::Str(&opened_height_text),
            ],
        );
        let encrypted_state_root = compressor_hash(
            "BUCKET-ENCRYPTED-STATE",
            &[
                HashPart::Str(&bucket_id),
                HashPart::Str(contract_commitment),
                HashPart::Str(&size_kib_text),
            ],
        );
        let compressed_state_root = compressor_hash(
            "BUCKET-COMPRESSED-STATE",
            &[
                HashPart::Str(&bucket_id),
                HashPart::Str(&normalized_compressed_text),
                HashPart::Str(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_WITNESS_CODEC),
            ],
        );
        let witness_root = compressor_hash(
            "BUCKET-WITNESS",
            &[HashPart::Str(&bucket_id), HashPart::Str(owner_commitment)],
        );
        let access_pattern_root = compressor_hash(
            "BUCKET-ACCESS-PATTERN",
            &[HashPart::Str(&bucket_id), HashPart::Str(class.as_str())],
        );
        let privacy_budget_id = compressor_hash(
            "BUCKET-PRIVACY-BUDGET",
            &[HashPart::Str(owner_commitment), HashPart::Str(&bucket_id)],
        );
        let low_fee_lane_id =
            compressor_hash("BUCKET-LOW-FEE-LANE", &[HashPart::Str(class.as_str())]);
        let rent_due_units = rent_due_units(size_kib, class, config);
        let rebate_reserved_units = rent_due_units.saturating_mul(config.rebate_bps)
            / PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS;
        Self {
            bucket_id,
            contract_commitment: contract_commitment.to_string(),
            owner_commitment: owner_commitment.to_string(),
            class,
            status: BucketStatus::Active,
            encrypted_state_root,
            compressed_state_root,
            witness_root,
            access_pattern_root,
            privacy_budget_id,
            low_fee_lane_id,
            size_kib,
            compressed_kib: normalized_compressed,
            rent_due_units,
            rebate_reserved_units,
            last_touched_height: opened_height,
            opened_height,
            expires_height: opened_height.saturating_add(config.retention_blocks),
            heat_score: class.default_privacy_weight() as i64,
        }
    }

    pub fn with_status(mut self, status: BucketStatus) -> Self {
        self.status = status;
        self
    }

    pub fn compression_savings_bps(&self) -> u64 {
        if self.size_kib == 0 {
            return 0;
        }
        self.size_kib
            .saturating_sub(self.compressed_kib)
            .saturating_mul(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS)
            / self.size_kib
    }

    pub fn touch(&mut self, height: u64, hint: WarmColdHintKind) {
        self.last_touched_height = height;
        self.heat_score = self.heat_score.saturating_add(hint.heat_delta());
        if hint.heat_delta() > 0 && self.status == BucketStatus::Cold {
            self.status = BucketStatus::Active;
        }
    }

    pub fn maybe_cool(&mut self, height: u64, config: &Config) {
        if height.saturating_sub(self.last_touched_height) >= config.cold_after_blocks
            && self.status.live()
        {
            self.status = BucketStatus::Cold;
            self.heat_score = self.heat_score.min(0);
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.bucket_id.is_empty()
            || self.contract_commitment.is_empty()
            || self.owner_commitment.is_empty()
            || self.encrypted_state_root.is_empty()
            || self.compressed_state_root.is_empty()
            || self.witness_root.is_empty()
            || self.access_pattern_root.is_empty()
            || self.privacy_budget_id.is_empty()
            || self.low_fee_lane_id.is_empty()
        {
            return Err("state rent compressor bucket contains empty commitments".to_string());
        }
        if self.size_kib == 0 || self.compressed_kib == 0 || self.rent_due_units == 0 {
            return Err("state rent compressor bucket economics must be positive".to_string());
        }
        if self.compressed_kib > self.size_kib {
            return Err("state rent compressor bucket cannot expand after compression".to_string());
        }
        if self.expires_height <= self.opened_height {
            return Err("state rent compressor bucket expiry must exceed open height".to_string());
        }
        if self.rebate_reserved_units > self.rent_due_units {
            return Err("state rent compressor bucket rebate exceeds rent".to_string());
        }
        if self.compression_savings_bps() < config.witness_savings_bps / 4
            && self.status == BucketStatus::RebatePending
        {
            return Err("state rent compressor rebate bucket lacks minimum savings".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "contract_commitment": self.contract_commitment,
            "owner_commitment": self.owner_commitment,
            "class": self.class.as_str(),
            "status": self.status.as_str(),
            "encrypted_state_root": self.encrypted_state_root,
            "compressed_state_root": self.compressed_state_root,
            "witness_root": self.witness_root,
            "access_pattern_root": self.access_pattern_root,
            "privacy_budget_id": self.privacy_budget_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "size_kib": self.size_kib,
            "compressed_kib": self.compressed_kib,
            "compression_savings_bps": self.compression_savings_bps(),
            "rent_due_units": self.rent_due_units,
            "rebate_reserved_units": self.rebate_reserved_units,
            "last_touched_height": self.last_touched_height,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "heat_score": self.heat_score,
        })
    }

    pub fn record_root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCarryingSnapshot {
    pub snapshot_id: String,
    pub bucket_id: String,
    pub status: SnapshotStatus,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub proof_root: String,
    pub public_input_root: String,
    pub carried_witness_root: String,
    pub verifier_key_root: String,
    pub prover_commitment: String,
    pub security_bits: u16,
    pub original_kib: u64,
    pub compressed_kib: u64,
    pub created_height: u64,
    pub verified_height: u64,
    pub rebate_units: u64,
}

impl ProofCarryingSnapshot {
    pub fn from_bucket(
        bucket: &ConfidentialStorageBucket,
        prover_commitment: &str,
        created_height: u64,
        config: &Config,
    ) -> Self {
        let created_height_text = created_height.to_string();
        let snapshot_id = compressor_hash(
            "SNAPSHOT-ID",
            &[
                HashPart::Str(&bucket.bucket_id),
                HashPart::Str(prover_commitment),
                HashPart::Str(&created_height_text),
            ],
        );
        let pre_state_root = bucket.encrypted_state_root.clone();
        let post_state_root = bucket.compressed_state_root.clone();
        let public_input_root = compressor_hash(
            "SNAPSHOT-PUBLIC-INPUT",
            &[
                HashPart::Str(&bucket.bucket_id),
                HashPart::Str(&pre_state_root),
                HashPart::Str(&post_state_root),
            ],
        );
        let carried_witness_root = compressor_hash(
            "SNAPSHOT-CARRIED-WITNESS",
            &[
                HashPart::Str(&bucket.witness_root),
                HashPart::Str(&snapshot_id),
            ],
        );
        let verifier_key_root = compressor_hash(
            "SNAPSHOT-VERIFIER-KEY",
            &[HashPart::Str(
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_SNAPSHOT_PROOF_SUITE,
            )],
        );
        let proof_root = compressor_hash(
            "SNAPSHOT-PROOF",
            &[
                HashPart::Str(&snapshot_id),
                HashPart::Str(&public_input_root),
                HashPart::Str(&verifier_key_root),
            ],
        );
        let rebate_units = bucket
            .rent_due_units
            .saturating_mul(config.rebate_bps)
            .saturating_mul(bucket.compression_savings_bps())
            / PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS
            / PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS;
        Self {
            snapshot_id,
            bucket_id: bucket.bucket_id.clone(),
            status: SnapshotStatus::ProofAttached,
            pre_state_root,
            post_state_root,
            proof_root,
            public_input_root,
            carried_witness_root,
            verifier_key_root,
            prover_commitment: prover_commitment.to_string(),
            security_bits: config.min_proof_security_bits,
            original_kib: bucket.size_kib,
            compressed_kib: bucket.compressed_kib,
            created_height,
            verified_height: created_height,
            rebate_units,
        }
    }

    pub fn with_status(mut self, status: SnapshotStatus, height: u64) -> Self {
        self.status = status;
        if status.payable() {
            self.verified_height = height;
        }
        self
    }

    pub fn savings_bps(&self) -> u64 {
        if self.original_kib == 0 {
            return 0;
        }
        self.original_kib
            .saturating_sub(self.compressed_kib)
            .saturating_mul(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS)
            / self.original_kib
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.snapshot_id.is_empty()
            || self.bucket_id.is_empty()
            || self.pre_state_root.is_empty()
            || self.post_state_root.is_empty()
            || self.proof_root.is_empty()
            || self.public_input_root.is_empty()
            || self.carried_witness_root.is_empty()
            || self.verifier_key_root.is_empty()
            || self.prover_commitment.is_empty()
        {
            return Err("state rent compressor snapshot contains empty commitments".to_string());
        }
        if self.security_bits < config.min_proof_security_bits {
            return Err("state rent compressor snapshot proof security below policy".to_string());
        }
        if self.original_kib == 0 || self.compressed_kib == 0 {
            return Err("state rent compressor snapshot sizes must be positive".to_string());
        }
        if self.compressed_kib > self.original_kib {
            return Err("state rent compressor snapshot cannot expand state".to_string());
        }
        if self.status.payable() && self.rebate_units == 0 {
            return Err("state rent compressor payable snapshot needs rebate units".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "bucket_id": self.bucket_id,
            "status": self.status.as_str(),
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "proof_root": self.proof_root,
            "public_input_root": self.public_input_root,
            "carried_witness_root": self.carried_witness_root,
            "verifier_key_root": self.verifier_key_root,
            "prover_commitment": self.prover_commitment,
            "security_bits": self.security_bits,
            "original_kib": self.original_kib,
            "compressed_kib": self.compressed_kib,
            "savings_bps": self.savings_bps(),
            "created_height": self.created_height,
            "verified_height": self.verified_height,
            "rebate_units": self.rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmColdStateHint {
    pub hint_id: String,
    pub bucket_id: String,
    pub account_commitment: String,
    pub kind: WarmColdHintKind,
    pub state_key_root: String,
    pub confidence_bps: u64,
    pub expires_height: u64,
    pub emitted_height: u64,
    pub access_nullifier_root: String,
}

impl WarmColdStateHint {
    pub fn new(
        bucket_id: &str,
        account_commitment: &str,
        kind: WarmColdHintKind,
        state_key_label: &str,
        confidence_bps: u64,
        emitted_height: u64,
        config: &Config,
    ) -> Self {
        let emitted_height_text = emitted_height.to_string();
        let state_key_root = compressor_hash(
            "HINT-STATE-KEY",
            &[HashPart::Str(bucket_id), HashPart::Str(state_key_label)],
        );
        let hint_id = compressor_hash(
            "HINT-ID",
            &[
                HashPart::Str(bucket_id),
                HashPart::Str(account_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&state_key_root),
                HashPart::Str(&emitted_height_text),
            ],
        );
        let access_nullifier_root = compressor_hash(
            "HINT-ACCESS-NULLIFIER",
            &[HashPart::Str(&hint_id), HashPart::Str(account_commitment)],
        );
        Self {
            hint_id,
            bucket_id: bucket_id.to_string(),
            account_commitment: account_commitment.to_string(),
            kind,
            state_key_root,
            confidence_bps: confidence_bps
                .min(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS),
            expires_height: emitted_height.saturating_add(config.epoch_blocks),
            emitted_height,
            access_nullifier_root,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.hint_id.is_empty()
            || self.bucket_id.is_empty()
            || self.account_commitment.is_empty()
            || self.state_key_root.is_empty()
            || self.access_nullifier_root.is_empty()
        {
            return Err("state rent compressor hint contains empty commitments".to_string());
        }
        if self.confidence_bps > PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS {
            return Err("state rent compressor hint confidence exceeds maximum".to_string());
        }
        if self.expires_height <= self.emitted_height {
            return Err("state rent compressor hint expiry must exceed emitted height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "bucket_id": self.bucket_id,
            "account_commitment": self.account_commitment,
            "kind": self.kind.as_str(),
            "state_key_root": self.state_key_root,
            "confidence_bps": self.confidence_bps,
            "expires_height": self.expires_height,
            "emitted_height": self.emitted_height,
            "access_nullifier_root": self.access_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedWitnessEnvelope {
    pub witness_id: String,
    pub bucket_id: String,
    pub snapshot_id: String,
    pub mode: WitnessCompressionMode,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub dictionary_root: String,
    pub chunk_commitment_root: String,
    pub decoder_policy_root: String,
    pub availability_attestation_root: String,
    pub submitted_height: u64,
}

impl CompressedWitnessEnvelope {
    pub fn new(
        bucket_id: &str,
        snapshot_id: &str,
        mode: WitnessCompressionMode,
        uncompressed_bytes: u64,
        submitted_height: u64,
    ) -> Self {
        let compressed_bytes = uncompressed_bytes.saturating_mul(
            PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS
                .saturating_sub(mode.projected_savings_bps()),
        ) / PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS;
        let normalized_compressed = compressed_bytes.max(1);
        let submitted_height_text = submitted_height.to_string();
        let normalized_compressed_text = normalized_compressed.to_string();
        let witness_id = compressor_hash(
            "WITNESS-ID",
            &[
                HashPart::Str(bucket_id),
                HashPart::Str(snapshot_id),
                HashPart::Str(mode.as_str()),
                HashPart::Str(&submitted_height_text),
            ],
        );
        let dictionary_root = compressor_hash(
            "WITNESS-DICTIONARY",
            &[HashPart::Str(&witness_id), HashPart::Str(mode.as_str())],
        );
        let chunk_commitment_root = compressor_hash(
            "WITNESS-CHUNKS",
            &[
                HashPart::Str(&witness_id),
                HashPart::Str(&normalized_compressed_text),
            ],
        );
        let decoder_policy_root = compressor_hash(
            "WITNESS-DECODER-POLICY",
            &[HashPart::Str(
                PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_WITNESS_CODEC,
            )],
        );
        let availability_attestation_root = compressor_hash(
            "WITNESS-AVAILABILITY",
            &[
                HashPart::Str(&witness_id),
                HashPart::Str(&chunk_commitment_root),
            ],
        );
        Self {
            witness_id,
            bucket_id: bucket_id.to_string(),
            snapshot_id: snapshot_id.to_string(),
            mode,
            uncompressed_bytes,
            compressed_bytes: normalized_compressed,
            dictionary_root,
            chunk_commitment_root,
            decoder_policy_root,
            availability_attestation_root,
            submitted_height,
        }
    }

    pub fn savings_bps(&self) -> u64 {
        if self.uncompressed_bytes == 0 {
            return 0;
        }
        self.uncompressed_bytes
            .saturating_sub(self.compressed_bytes)
            .saturating_mul(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS)
            / self.uncompressed_bytes
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.witness_id.is_empty()
            || self.bucket_id.is_empty()
            || self.snapshot_id.is_empty()
            || self.dictionary_root.is_empty()
            || self.chunk_commitment_root.is_empty()
            || self.decoder_policy_root.is_empty()
            || self.availability_attestation_root.is_empty()
        {
            return Err("state rent compressor witness contains empty commitments".to_string());
        }
        if self.uncompressed_bytes == 0 || self.compressed_bytes == 0 {
            return Err("state rent compressor witness sizes must be positive".to_string());
        }
        if self.compressed_bytes > self.uncompressed_bytes {
            return Err("state rent compressor witness cannot expand".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "bucket_id": self.bucket_id,
            "snapshot_id": self.snapshot_id,
            "mode": self.mode.as_str(),
            "uncompressed_bytes": self.uncompressed_bytes,
            "compressed_bytes": self.compressed_bytes,
            "savings_bps": self.savings_bps(),
            "dictionary_root": self.dictionary_root,
            "chunk_commitment_root": self.chunk_commitment_root,
            "decoder_policy_root": self.decoder_policy_root,
            "availability_attestation_root": self.availability_attestation_root,
            "submitted_height": self.submitted_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureReceipt {
    pub receipt_id: String,
    pub bucket_id: String,
    pub snapshot_id: String,
    pub status: ErasureStatus,
    pub request_nullifier_root: String,
    pub erased_state_root: String,
    pub tombstone_root: String,
    pub witness_attestation_root: String,
    pub erasure_proof_root: String,
    pub requested_height: u64,
    pub finalized_height: u64,
    pub rebate_units: u64,
}

impl ErasureReceipt {
    pub fn new(
        bucket_id: &str,
        snapshot_id: &str,
        requester_commitment: &str,
        requested_height: u64,
        rebate_units: u64,
    ) -> Self {
        let requested_height_text = requested_height.to_string();
        let request_nullifier_root = compressor_hash(
            "ERASURE-REQUEST-NULLIFIER",
            &[
                HashPart::Str(bucket_id),
                HashPart::Str(snapshot_id),
                HashPart::Str(requester_commitment),
            ],
        );
        let receipt_id = compressor_hash(
            "ERASURE-RECEIPT-ID",
            &[
                HashPart::Str(bucket_id),
                HashPart::Str(snapshot_id),
                HashPart::Str(&request_nullifier_root),
                HashPart::Str(&requested_height_text),
            ],
        );
        let erased_state_root = compressor_hash(
            "ERASURE-STATE",
            &[HashPart::Str(&receipt_id), HashPart::Str(bucket_id)],
        );
        let tombstone_root = compressor_hash(
            "ERASURE-TOMBSTONE",
            &[
                HashPart::Str(&receipt_id),
                HashPart::Str(&erased_state_root),
            ],
        );
        let witness_attestation_root = compressor_hash(
            "ERASURE-WITNESS-ATTESTATION",
            &[
                HashPart::Str(&receipt_id),
                HashPart::Str(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_ERASURE_SUITE),
            ],
        );
        let erasure_proof_root = compressor_hash(
            "ERASURE-PROOF",
            &[HashPart::Str(&receipt_id), HashPart::Str(&tombstone_root)],
        );
        Self {
            receipt_id,
            bucket_id: bucket_id.to_string(),
            snapshot_id: snapshot_id.to_string(),
            status: ErasureStatus::Requested,
            request_nullifier_root,
            erased_state_root,
            tombstone_root,
            witness_attestation_root,
            erasure_proof_root,
            requested_height,
            finalized_height: requested_height,
            rebate_units,
        }
    }

    pub fn with_status(mut self, status: ErasureStatus, height: u64) -> Self {
        self.status = status;
        if status.terminal() || status == ErasureStatus::RebateReleased {
            self.finalized_height = height;
        }
        self
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.receipt_id.is_empty()
            || self.bucket_id.is_empty()
            || self.snapshot_id.is_empty()
            || self.request_nullifier_root.is_empty()
            || self.erased_state_root.is_empty()
            || self.tombstone_root.is_empty()
            || self.witness_attestation_root.is_empty()
            || self.erasure_proof_root.is_empty()
        {
            return Err(
                "state rent compressor erasure receipt contains empty commitments".to_string(),
            );
        }
        if self.finalized_height < self.requested_height {
            return Err("state rent compressor erasure finality precedes request".to_string());
        }
        if self.status == ErasureStatus::RebateReleased && self.rebate_units == 0 {
            return Err("state rent compressor erasure rebate release needs units".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bucket_id": self.bucket_id,
            "snapshot_id": self.snapshot_id,
            "status": self.status.as_str(),
            "request_nullifier_root": self.request_nullifier_root,
            "erased_state_root": self.erased_state_root,
            "tombstone_root": self.tombstone_root,
            "witness_attestation_root": self.witness_attestation_root,
            "erasure_proof_root": self.erasure_proof_root,
            "requested_height": self.requested_height,
            "finalized_height": self.finalized_height,
            "rebate_units": self.rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPrivacyBudget {
    pub budget_id: String,
    pub account_commitment: String,
    pub epoch: u64,
    pub budget_units: u64,
    pub consumed_units: u64,
    pub disclosure_root: String,
    pub nullifier_set_root: String,
    pub reset_height: u64,
}

impl AccountPrivacyBudget {
    pub fn new(account_commitment: &str, epoch: u64, opened_height: u64, config: &Config) -> Self {
        let epoch_text = epoch.to_string();
        let opened_height_text = opened_height.to_string();
        let budget_id = compressor_hash(
            "PRIVACY-BUDGET-ID",
            &[
                HashPart::Str(account_commitment),
                HashPart::Str(&epoch_text),
                HashPart::Str(&opened_height_text),
            ],
        );
        let disclosure_root = compressor_hash(
            "PRIVACY-BUDGET-DISCLOSURE",
            &[HashPart::Str(&budget_id), HashPart::Str(account_commitment)],
        );
        let nullifier_set_root = compressor_hash(
            "PRIVACY-BUDGET-NULLIFIERS",
            &[HashPart::Str(&budget_id), HashPart::Str(&epoch_text)],
        );
        Self {
            budget_id,
            account_commitment: account_commitment.to_string(),
            epoch,
            budget_units: config.privacy_budget_units,
            consumed_units: 0,
            disclosure_root,
            nullifier_set_root,
            reset_height: opened_height.saturating_add(config.epoch_blocks),
        }
    }

    pub fn consume(&mut self, units: u64) -> PrivateSmartContractStateRentCompressorResult<()> {
        let next = self.consumed_units.saturating_add(units);
        if next > self.budget_units {
            return Err("state rent compressor privacy budget exhausted".to_string());
        }
        self.consumed_units = next;
        Ok(())
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.consumed_units)
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.budget_id.is_empty()
            || self.account_commitment.is_empty()
            || self.disclosure_root.is_empty()
            || self.nullifier_set_root.is_empty()
        {
            return Err(
                "state rent compressor privacy budget contains empty commitments".to_string(),
            );
        }
        if self.budget_units == 0 || self.consumed_units > self.budget_units {
            return Err("state rent compressor privacy budget accounting invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "account_commitment": self.account_commitment,
            "epoch": self.epoch,
            "budget_units": self.budget_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "disclosure_root": self.disclosure_root,
            "nullifier_set_root": self.nullifier_set_root,
            "reset_height": self.reset_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeStorageLane {
    pub lane_id: String,
    pub class: StorageBucketClass,
    pub status: LowFeeLaneStatus,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub capacity_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub rebate_policy_root: String,
    pub admission_root: String,
    pub opened_height: u64,
}

impl LowFeeStorageLane {
    pub fn new(
        class: StorageBucketClass,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        opened_height: u64,
        config: &Config,
    ) -> Self {
        let lane_id = compressor_hash(
            "LOW-FEE-LANE-ID",
            &[
                HashPart::Str(class.as_str()),
                HashPart::Str(sponsor_commitment),
                HashPart::Str(fee_asset_id),
            ],
        );
        let rebate_bps_text = config.rebate_bps.to_string();
        let capacity_text = config.low_fee_lane_capacity_units.to_string();
        let rebate_policy_root = compressor_hash(
            "LOW-FEE-LANE-REBATE-POLICY",
            &[HashPart::Str(&lane_id), HashPart::Str(&rebate_bps_text)],
        );
        let admission_root = compressor_hash(
            "LOW-FEE-LANE-ADMISSION",
            &[HashPart::Str(&lane_id), HashPart::Str(&capacity_text)],
        );
        Self {
            lane_id,
            class,
            status: LowFeeLaneStatus::Active,
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            capacity_units: config.low_fee_lane_capacity_units,
            reserved_units: 0,
            spent_units: 0,
            rebate_policy_root,
            admission_root,
            opened_height,
        }
    }

    pub fn reserve(&mut self, units: u64) -> PrivateSmartContractStateRentCompressorResult<()> {
        if !self.status.accepting() {
            return Err(
                "state rent compressor low fee lane is not accepting reservations".to_string(),
            );
        }
        let next = self.reserved_units.saturating_add(units);
        if next > self.capacity_units.saturating_sub(self.spent_units) {
            return Err("state rent compressor low fee lane capacity exceeded".to_string());
        }
        self.reserved_units = next;
        if self.reserved_units.saturating_add(self.spent_units) >= self.capacity_units {
            self.status = LowFeeLaneStatus::Saturated;
        }
        Ok(())
    }

    pub fn settle(&mut self, units: u64) {
        let settled = units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(settled);
        self.spent_units = self.spent_units.saturating_add(settled);
        if self.status == LowFeeLaneStatus::Saturated && self.remaining_units() > 0 {
            self.status = LowFeeLaneStatus::Active;
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.capacity_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.lane_id.is_empty()
            || self.sponsor_commitment.is_empty()
            || self.fee_asset_id.is_empty()
            || self.rebate_policy_root.is_empty()
            || self.admission_root.is_empty()
        {
            return Err(
                "state rent compressor low fee lane contains empty commitments".to_string(),
            );
        }
        if self.capacity_units == 0 {
            return Err("state rent compressor low fee lane capacity must be positive".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.capacity_units {
            return Err("state rent compressor low fee lane accounting invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "class": self.class.as_str(),
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "capacity_units": self.capacity_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "rebate_policy_root": self.rebate_policy_root,
            "admission_root": self.admission_root,
            "opened_height": self.opened_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RentRebateClaim {
    pub claim_id: String,
    pub bucket_id: String,
    pub snapshot_id: String,
    pub lane_id: String,
    pub claimant_commitment: String,
    pub amount_units: u64,
    pub fee_asset_id: String,
    pub eligibility_root: String,
    pub payout_nullifier_root: String,
    pub created_height: u64,
    pub paid_height: u64,
}

impl RentRebateClaim {
    pub fn new(
        snapshot: &ProofCarryingSnapshot,
        lane: &LowFeeStorageLane,
        claimant_commitment: &str,
        created_height: u64,
    ) -> Self {
        let amount_units = snapshot.rebate_units.min(lane.remaining_units());
        let created_height_text = created_height.to_string();
        let eligibility_root = compressor_hash(
            "REBATE-ELIGIBILITY",
            &[
                HashPart::Str(&snapshot.snapshot_id),
                HashPart::Str(&lane.lane_id),
                HashPart::Str(claimant_commitment),
            ],
        );
        let claim_id = compressor_hash(
            "REBATE-CLAIM-ID",
            &[
                HashPart::Str(&snapshot.bucket_id),
                HashPart::Str(&snapshot.snapshot_id),
                HashPart::Str(&eligibility_root),
                HashPart::Str(&created_height_text),
            ],
        );
        let payout_nullifier_root = compressor_hash(
            "REBATE-PAYOUT-NULLIFIER",
            &[HashPart::Str(&claim_id), HashPart::Str(claimant_commitment)],
        );
        Self {
            claim_id,
            bucket_id: snapshot.bucket_id.clone(),
            snapshot_id: snapshot.snapshot_id.clone(),
            lane_id: lane.lane_id.clone(),
            claimant_commitment: claimant_commitment.to_string(),
            amount_units,
            fee_asset_id: lane.fee_asset_id.clone(),
            eligibility_root,
            payout_nullifier_root,
            created_height,
            paid_height: 0,
        }
    }

    pub fn mark_paid(&mut self, height: u64) {
        self.paid_height = height;
    }

    pub fn payable(&self) -> bool {
        self.amount_units > 0 && self.paid_height == 0
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<()> {
        if self.claim_id.is_empty()
            || self.bucket_id.is_empty()
            || self.snapshot_id.is_empty()
            || self.lane_id.is_empty()
            || self.claimant_commitment.is_empty()
            || self.fee_asset_id.is_empty()
            || self.eligibility_root.is_empty()
            || self.payout_nullifier_root.is_empty()
        {
            return Err(
                "state rent compressor rebate claim contains empty commitments".to_string(),
            );
        }
        if self.amount_units == 0 {
            return Err("state rent compressor rebate claim amount must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "bucket_id": self.bucket_id,
            "snapshot_id": self.snapshot_id,
            "lane_id": self.lane_id,
            "claimant_commitment": self.claimant_commitment,
            "amount_units": self.amount_units,
            "fee_asset_id": self.fee_asset_id,
            "eligibility_root": self.eligibility_root,
            "payout_nullifier_root": self.payout_nullifier_root,
            "created_height": self.created_height,
            "paid_height": self.paid_height,
            "payable": self.payable(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub bucket_root: String,
    pub snapshot_root: String,
    pub hint_root: String,
    pub witness_root: String,
    pub erasure_receipt_root: String,
    pub privacy_budget_root: String,
    pub low_fee_lane_root: String,
    pub rebate_claim_root: String,
    pub contract_index_root: String,
    pub account_index_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bucket_root": self.bucket_root,
            "snapshot_root": self.snapshot_root,
            "hint_root": self.hint_root,
            "witness_root": self.witness_root,
            "erasure_receipt_root": self.erasure_receipt_root,
            "privacy_budget_root": self.privacy_budget_root,
            "low_fee_lane_root": self.low_fee_lane_root,
            "rebate_claim_root": self.rebate_claim_root,
            "contract_index_root": self.contract_index_root,
            "account_index_root": self.account_index_root,
        })
    }

    pub fn state_root(&self) -> String {
        compressor_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub bucket_count: u64,
    pub live_bucket_count: u64,
    pub cold_bucket_count: u64,
    pub snapshot_count: u64,
    pub payable_snapshot_count: u64,
    pub hint_count: u64,
    pub active_hint_count: u64,
    pub witness_count: u64,
    pub erasure_receipt_count: u64,
    pub finalized_erasure_count: u64,
    pub privacy_budget_count: u64,
    pub low_fee_lane_count: u64,
    pub accepting_low_fee_lane_count: u64,
    pub rebate_claim_count: u64,
    pub payable_rebate_claim_count: u64,
    pub total_original_kib: u64,
    pub total_compressed_kib: u64,
    pub total_rent_due_units: u64,
    pub total_rebate_units: u64,
    pub remaining_privacy_budget_units: u64,
    pub remaining_low_fee_lane_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_count": self.bucket_count,
            "live_bucket_count": self.live_bucket_count,
            "cold_bucket_count": self.cold_bucket_count,
            "snapshot_count": self.snapshot_count,
            "payable_snapshot_count": self.payable_snapshot_count,
            "hint_count": self.hint_count,
            "active_hint_count": self.active_hint_count,
            "witness_count": self.witness_count,
            "erasure_receipt_count": self.erasure_receipt_count,
            "finalized_erasure_count": self.finalized_erasure_count,
            "privacy_budget_count": self.privacy_budget_count,
            "low_fee_lane_count": self.low_fee_lane_count,
            "accepting_low_fee_lane_count": self.accepting_low_fee_lane_count,
            "rebate_claim_count": self.rebate_claim_count,
            "payable_rebate_claim_count": self.payable_rebate_claim_count,
            "total_original_kib": self.total_original_kib,
            "total_compressed_kib": self.total_compressed_kib,
            "total_rent_due_units": self.total_rent_due_units,
            "total_rebate_units": self.total_rebate_units,
            "remaining_privacy_budget_units": self.remaining_privacy_budget_units,
            "remaining_low_fee_lane_units": self.remaining_low_fee_lane_units,
        })
    }

    pub fn state_root(&self) -> String {
        compressor_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub buckets: BTreeMap<String, ConfidentialStorageBucket>,
    pub snapshots: BTreeMap<String, ProofCarryingSnapshot>,
    pub hints: BTreeMap<String, WarmColdStateHint>,
    pub witnesses: BTreeMap<String, CompressedWitnessEnvelope>,
    pub erasure_receipts: BTreeMap<String, ErasureReceipt>,
    pub privacy_budgets: BTreeMap<String, AccountPrivacyBudget>,
    pub low_fee_lanes: BTreeMap<String, LowFeeStorageLane>,
    pub rebate_claims: BTreeMap<String, RentRebateClaim>,
    pub contract_buckets: BTreeMap<String, BTreeSet<String>>,
    pub account_budgets: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn devnet() -> PrivateSmartContractStateRentCompressorResult<State> {
        let config = Config::devnet();
        let height = PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_DEVNET_HEIGHT;
        let mut state = State {
            height,
            config,
            buckets: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            hints: BTreeMap::new(),
            witnesses: BTreeMap::new(),
            erasure_receipts: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            low_fee_lanes: BTreeMap::new(),
            rebate_claims: BTreeMap::new(),
            contract_buckets: BTreeMap::new(),
            account_budgets: BTreeMap::new(),
        };

        let lane_hot = LowFeeStorageLane::new(
            StorageBucketClass::ExecutionHot,
            "devnet-low-fee-storage-sponsor-hot",
            "asset:wxmr",
            height.saturating_sub(60),
            &state.config,
        );
        let lane_warm = LowFeeStorageLane::new(
            StorageBucketClass::SettlementWarm,
            "devnet-low-fee-storage-sponsor-warm",
            "asset:wxmr",
            height.saturating_sub(60),
            &state.config,
        );
        let lane_archive = LowFeeStorageLane::new(
            StorageBucketClass::ArchiveProof,
            "devnet-low-fee-storage-sponsor-archive",
            "asset:wxmr",
            height.saturating_sub(60),
            &state.config,
        );
        state.insert_low_fee_lane(lane_hot)?;
        state.insert_low_fee_lane(lane_warm)?;
        state.insert_low_fee_lane(lane_archive)?;

        let mut budget_alpha = AccountPrivacyBudget::new(
            "acct:shielded-alpha",
            7,
            height.saturating_sub(64),
            &state.config,
        );
        budget_alpha.consume(2_400)?;
        let mut budget_beta = AccountPrivacyBudget::new(
            "acct:shielded-beta",
            7,
            height.saturating_sub(64),
            &state.config,
        );
        budget_beta.consume(1_250)?;
        state.insert_privacy_budget(budget_alpha)?;
        state.insert_privacy_budget(budget_beta)?;

        let bucket_hot = ConfidentialStorageBucket::new(
            "contract:private-dex-pool",
            "acct:shielded-alpha",
            StorageBucketClass::ExecutionHot,
            192,
            58,
            height.saturating_sub(512),
            &state.config,
        )
        .with_status(BucketStatus::RebatePending);
        let bucket_warm = ConfidentialStorageBucket::new(
            "contract:private-lending-vault",
            "acct:shielded-beta",
            StorageBucketClass::SettlementWarm,
            320,
            120,
            height.saturating_sub(900),
            &state.config,
        )
        .with_status(BucketStatus::Active);
        let bucket_archive = ConfidentialStorageBucket::new(
            "contract:recursive-proof-ledger",
            "acct:shielded-alpha",
            StorageBucketClass::ArchiveProof,
            768,
            96,
            height.saturating_sub(1_800),
            &state.config,
        )
        .with_status(BucketStatus::Cold);
        state.insert_bucket(bucket_hot.clone())?;
        state.insert_bucket(bucket_warm.clone())?;
        state.insert_bucket(bucket_archive.clone())?;

        let snapshot_hot = ProofCarryingSnapshot::from_bucket(
            &bucket_hot,
            "prover:state-rent-alpha",
            height.saturating_sub(12),
            &state.config,
        )
        .with_status(SnapshotStatus::RebateReserved, height.saturating_sub(8));
        let snapshot_archive = ProofCarryingSnapshot::from_bucket(
            &bucket_archive,
            "prover:state-rent-archive",
            height.saturating_sub(24),
            &state.config,
        )
        .with_status(SnapshotStatus::Published, height.saturating_sub(16));
        state.insert_snapshot(snapshot_hot.clone())?;
        state.insert_snapshot(snapshot_archive.clone())?;

        state.insert_hint(WarmColdStateHint::new(
            &bucket_hot.bucket_id,
            "acct:shielded-alpha",
            WarmColdHintKind::HotWrite,
            "pool:swap-nullifier-set",
            9_200,
            height.saturating_sub(5),
            &state.config,
        ))?;
        state.insert_hint(WarmColdStateHint::new(
            &bucket_archive.bucket_id,
            "acct:shielded-alpha",
            WarmColdHintKind::ArchiveCandidate,
            "proof:recursive-ledger-frontier",
            8_700,
            height.saturating_sub(30),
            &state.config,
        ))?;

        state.insert_witness(CompressedWitnessEnvelope::new(
            &bucket_hot.bucket_id,
            &snapshot_hot.snapshot_id,
            WitnessCompressionMode::SparseMerkleFrontier,
            220_000,
            height.saturating_sub(10),
        ))?;
        state.insert_witness(CompressedWitnessEnvelope::new(
            &bucket_archive.bucket_id,
            &snapshot_archive.snapshot_id,
            WitnessCompressionMode::RecursiveProofCarry,
            640_000,
            height.saturating_sub(20),
        ))?;

        let erasure = ErasureReceipt::new(
            &bucket_archive.bucket_id,
            &snapshot_archive.snapshot_id,
            "acct:shielded-alpha",
            height.saturating_sub(14),
            2_100,
        )
        .with_status(ErasureStatus::Proved, height.saturating_sub(7));
        state.insert_erasure_receipt(erasure)?;

        let claim_lane = state
            .low_fee_lanes
            .get(&bucket_hot.low_fee_lane_id)
            .cloned()
            .ok_or_else(|| "state rent compressor devnet missing low fee lane".to_string())?;
        let claim = RentRebateClaim::new(
            &snapshot_hot,
            &claim_lane,
            "acct:shielded-alpha",
            height.saturating_sub(6),
        );
        state.insert_rebate_claim(claim)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateSmartContractStateRentCompressorResult<()> {
        if height < self.height {
            return Err("state rent compressor height cannot decrease".to_string());
        }
        self.height = height;
        for bucket in self.buckets.values_mut() {
            bucket.maybe_cool(height, &self.config);
            if height > bucket.expires_height && bucket.status.live() {
                bucket.status = BucketStatus::Frozen;
            }
        }
        for lane in self.low_fee_lanes.values_mut() {
            if lane.status == LowFeeLaneStatus::Draining && lane.remaining_units() == 0 {
                lane.status = LowFeeLaneStatus::Retired;
            }
        }
        self.validate()?;
        Ok(())
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PrivateSmartContractStateRentCompressorResult<()> {
        self.set_height(height)
    }

    pub fn insert_bucket(
        &mut self,
        bucket: ConfidentialStorageBucket,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        bucket.validate(&self.config)?;
        if self.buckets.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BUCKETS {
            return Err("state rent compressor bucket limit reached".to_string());
        }
        let bucket_id = bucket.bucket_id.clone();
        self.contract_buckets
            .entry(bucket.contract_commitment.clone())
            .or_default()
            .insert(bucket_id.clone());
        self.buckets.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }

    pub fn insert_snapshot(
        &mut self,
        snapshot: ProofCarryingSnapshot,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        snapshot.validate(&self.config)?;
        if !self.buckets.contains_key(&snapshot.bucket_id) {
            return Err("state rent compressor snapshot references missing bucket".to_string());
        }
        if self.snapshots.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_SNAPSHOTS {
            return Err("state rent compressor snapshot limit reached".to_string());
        }
        let snapshot_id = snapshot.snapshot_id.clone();
        self.snapshots.insert(snapshot_id.clone(), snapshot);
        Ok(snapshot_id)
    }

    pub fn insert_hint(
        &mut self,
        hint: WarmColdStateHint,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        hint.validate()?;
        if !self.buckets.contains_key(&hint.bucket_id) {
            return Err("state rent compressor hint references missing bucket".to_string());
        }
        if self.hints.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_HINTS {
            return Err("state rent compressor hint limit reached".to_string());
        }
        if let Some(bucket) = self.buckets.get_mut(&hint.bucket_id) {
            bucket.touch(hint.emitted_height, hint.kind);
        }
        let hint_id = hint.hint_id.clone();
        self.hints.insert(hint_id.clone(), hint);
        Ok(hint_id)
    }

    pub fn insert_witness(
        &mut self,
        witness: CompressedWitnessEnvelope,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        witness.validate()?;
        if !self.buckets.contains_key(&witness.bucket_id) {
            return Err("state rent compressor witness references missing bucket".to_string());
        }
        if !self.snapshots.contains_key(&witness.snapshot_id) {
            return Err("state rent compressor witness references missing snapshot".to_string());
        }
        if self.witnesses.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_WITNESSES {
            return Err("state rent compressor witness limit reached".to_string());
        }
        let witness_id = witness.witness_id.clone();
        self.witnesses.insert(witness_id.clone(), witness);
        Ok(witness_id)
    }

    pub fn insert_erasure_receipt(
        &mut self,
        receipt: ErasureReceipt,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        receipt.validate()?;
        if !self.buckets.contains_key(&receipt.bucket_id) {
            return Err("state rent compressor erasure references missing bucket".to_string());
        }
        if !self.snapshots.contains_key(&receipt.snapshot_id) {
            return Err("state rent compressor erasure references missing snapshot".to_string());
        }
        if self.erasure_receipts.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_RECEIPTS
        {
            return Err("state rent compressor erasure receipt limit reached".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.erasure_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn insert_privacy_budget(
        &mut self,
        budget: AccountPrivacyBudget,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        budget.validate()?;
        if self.privacy_budgets.len()
            >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_PRIVACY_ACCOUNTS
        {
            return Err("state rent compressor privacy budget limit reached".to_string());
        }
        let budget_id = budget.budget_id.clone();
        self.account_budgets
            .entry(budget.account_commitment.clone())
            .or_default()
            .insert(budget_id.clone());
        self.privacy_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_low_fee_lane(
        &mut self,
        lane: LowFeeStorageLane,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        lane.validate()?;
        if self.low_fee_lanes.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_LANES {
            return Err("state rent compressor low fee lane limit reached".to_string());
        }
        let lane_id = lane.lane_id.clone();
        self.low_fee_lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn insert_rebate_claim(
        &mut self,
        claim: RentRebateClaim,
    ) -> PrivateSmartContractStateRentCompressorResult<String> {
        claim.validate()?;
        if !self.buckets.contains_key(&claim.bucket_id) {
            return Err("state rent compressor rebate references missing bucket".to_string());
        }
        if !self.snapshots.contains_key(&claim.snapshot_id) {
            return Err("state rent compressor rebate references missing snapshot".to_string());
        }
        if !self.low_fee_lanes.contains_key(&claim.lane_id) {
            return Err("state rent compressor rebate references missing low fee lane".to_string());
        }
        if self.rebate_claims.len() >= PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_REBATES {
            return Err("state rent compressor rebate claim limit reached".to_string());
        }
        if let Some(lane) = self.low_fee_lanes.get_mut(&claim.lane_id) {
            lane.reserve(claim.amount_units)?;
        }
        let claim_id = claim.claim_id.clone();
        self.rebate_claims.insert(claim_id.clone(), claim);
        Ok(claim_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            bucket_root: map_root(
                "BUCKETS",
                self.buckets
                    .values()
                    .map(ConfidentialStorageBucket::public_record),
            ),
            snapshot_root: map_root(
                "SNAPSHOTS",
                self.snapshots
                    .values()
                    .map(ProofCarryingSnapshot::public_record),
            ),
            hint_root: map_root(
                "HINTS",
                self.hints.values().map(WarmColdStateHint::public_record),
            ),
            witness_root: map_root(
                "WITNESSES",
                self.witnesses
                    .values()
                    .map(CompressedWitnessEnvelope::public_record),
            ),
            erasure_receipt_root: map_root(
                "ERASURE-RECEIPTS",
                self.erasure_receipts
                    .values()
                    .map(ErasureReceipt::public_record),
            ),
            privacy_budget_root: map_root(
                "PRIVACY-BUDGETS",
                self.privacy_budgets
                    .values()
                    .map(AccountPrivacyBudget::public_record),
            ),
            low_fee_lane_root: map_root(
                "LOW-FEE-LANES",
                self.low_fee_lanes
                    .values()
                    .map(LowFeeStorageLane::public_record),
            ),
            rebate_claim_root: map_root(
                "REBATE-CLAIMS",
                self.rebate_claims
                    .values()
                    .map(RentRebateClaim::public_record),
            ),
            contract_index_root: set_map_root("CONTRACT-BUCKET-INDEX", &self.contract_buckets),
            account_index_root: set_map_root("ACCOUNT-BUDGET-INDEX", &self.account_budgets),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            bucket_count: self.buckets.len() as u64,
            live_bucket_count: self
                .buckets
                .values()
                .filter(|bucket| bucket.status.live())
                .count() as u64,
            cold_bucket_count: self
                .buckets
                .values()
                .filter(|bucket| bucket.status == BucketStatus::Cold)
                .count() as u64,
            snapshot_count: self.snapshots.len() as u64,
            payable_snapshot_count: self
                .snapshots
                .values()
                .filter(|snapshot| snapshot.status.payable())
                .count() as u64,
            hint_count: self.hints.len() as u64,
            active_hint_count: self
                .hints
                .values()
                .filter(|hint| hint.expires_height >= self.height)
                .count() as u64,
            witness_count: self.witnesses.len() as u64,
            erasure_receipt_count: self.erasure_receipts.len() as u64,
            finalized_erasure_count: self
                .erasure_receipts
                .values()
                .filter(|receipt| receipt.status.terminal())
                .count() as u64,
            privacy_budget_count: self.privacy_budgets.len() as u64,
            low_fee_lane_count: self.low_fee_lanes.len() as u64,
            accepting_low_fee_lane_count: self
                .low_fee_lanes
                .values()
                .filter(|lane| lane.status.accepting())
                .count() as u64,
            rebate_claim_count: self.rebate_claims.len() as u64,
            payable_rebate_claim_count: self
                .rebate_claims
                .values()
                .filter(|claim| claim.payable())
                .count() as u64,
            total_original_kib: self.buckets.values().map(|bucket| bucket.size_kib).sum(),
            total_compressed_kib: self
                .buckets
                .values()
                .map(|bucket| bucket.compressed_kib)
                .sum(),
            total_rent_due_units: self
                .buckets
                .values()
                .map(|bucket| bucket.rent_due_units)
                .sum(),
            total_rebate_units: self
                .rebate_claims
                .values()
                .map(|claim| claim.amount_units)
                .sum(),
            remaining_privacy_budget_units: self
                .privacy_budgets
                .values()
                .map(AccountPrivacyBudget::remaining_units)
                .sum(),
            remaining_low_fee_lane_units: self
                .low_fee_lanes
                .values()
                .map(LowFeeStorageLane::remaining_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_smart_contract_state_rent_compressor_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_PROTOCOL_VERSION,
            "schema_version": PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "buckets": self.buckets.values().map(ConfidentialStorageBucket::public_record).collect::<Vec<_>>(),
            "snapshots": self.snapshots.values().map(ProofCarryingSnapshot::public_record).collect::<Vec<_>>(),
            "hints": self.hints.values().map(WarmColdStateHint::public_record).collect::<Vec<_>>(),
            "witnesses": self.witnesses.values().map(CompressedWitnessEnvelope::public_record).collect::<Vec<_>>(),
            "erasure_receipts": self.erasure_receipts.values().map(ErasureReceipt::public_record).collect::<Vec<_>>(),
            "privacy_budgets": self.privacy_budgets.values().map(AccountPrivacyBudget::public_record).collect::<Vec<_>>(),
            "low_fee_lanes": self.low_fee_lanes.values().map(LowFeeStorageLane::public_record).collect::<Vec<_>>(),
            "rebate_claims": self.rebate_claims.values().map(RentRebateClaim::public_record).collect::<Vec<_>>(),
            "contract_buckets": index_record(&self.contract_buckets),
            "account_budgets": index_record(&self.account_budgets),
            "state_root": roots.state_root(),
            "counter_root": counters.state_root(),
        })
    }

    pub fn validate(&self) -> PrivateSmartContractStateRentCompressorResult<String> {
        self.config.validate()?;
        let mut bucket_ids = BTreeSet::new();
        for bucket in self.buckets.values() {
            bucket.validate(&self.config)?;
            if !bucket_ids.insert(bucket.bucket_id.clone()) {
                return Err("state rent compressor duplicate bucket id".to_string());
            }
        }
        for snapshot in self.snapshots.values() {
            snapshot.validate(&self.config)?;
            if !self.buckets.contains_key(&snapshot.bucket_id) {
                return Err("state rent compressor snapshot references missing bucket".to_string());
            }
        }
        for hint in self.hints.values() {
            hint.validate()?;
            if !self.buckets.contains_key(&hint.bucket_id) {
                return Err("state rent compressor hint references missing bucket".to_string());
            }
        }
        for witness in self.witnesses.values() {
            witness.validate()?;
            if !self.buckets.contains_key(&witness.bucket_id)
                || !self.snapshots.contains_key(&witness.snapshot_id)
            {
                return Err("state rent compressor witness references missing state".to_string());
            }
        }
        for receipt in self.erasure_receipts.values() {
            receipt.validate()?;
            if !self.buckets.contains_key(&receipt.bucket_id)
                || !self.snapshots.contains_key(&receipt.snapshot_id)
            {
                return Err("state rent compressor erasure references missing state".to_string());
            }
        }
        for budget in self.privacy_budgets.values() {
            budget.validate()?;
        }
        for lane in self.low_fee_lanes.values() {
            lane.validate()?;
        }
        for claim in self.rebate_claims.values() {
            claim.validate()?;
            if !self.buckets.contains_key(&claim.bucket_id)
                || !self.snapshots.contains_key(&claim.snapshot_id)
                || !self.low_fee_lanes.contains_key(&claim.lane_id)
            {
                return Err("state rent compressor rebate references missing state".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn root_from_record(record: &Value) -> String {
    compressor_hash("STATE-ROOT-FROM-RECORD", &[HashPart::Json(record)])
}

pub fn devnet() -> PrivateSmartContractStateRentCompressorResult<State> {
    State::devnet()
}

fn rent_due_units(size_kib: u64, class: StorageBucketClass, config: &Config) -> u64 {
    size_kib
        .saturating_mul(config.rent_per_kib_units)
        .saturating_mul(class.rent_multiplier_bps())
        .saturating_add(PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS - 1)
        / PRIVATE_SMART_CONTRACT_STATE_RENT_COMPRESSOR_MAX_BPS
}

fn compressor_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    stable_hash(
        &format!("PRIVATE-SMART-CONTRACT-STATE-RENT-COMPRESSOR-{domain}"),
        parts,
        32,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let values = records.into_iter().collect::<Vec<_>>();
    compressor_hash(domain, &[HashPart::Json(&json!(values))])
}

fn index_record(index: &BTreeMap<String, BTreeSet<String>>) -> Value {
    let rows = index
        .iter()
        .map(|(key, values)| {
            json!({
                "key": key,
                "values": values.iter().cloned().collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    json!(rows)
}

fn set_map_root(domain: &str, index: &BTreeMap<String, BTreeSet<String>>) -> String {
    compressor_hash(domain, &[HashPart::Json(&index_record(index))])
}
