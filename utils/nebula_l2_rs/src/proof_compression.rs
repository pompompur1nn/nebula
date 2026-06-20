use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProofCompressionResult<T> = Result<T, String>;

pub const PROOF_COMPRESSION_PROTOCOL_VERSION: &str = "nebula-l2-proof-compression-v1";
pub const PROOF_COMPRESSION_SCHEMA_VERSION: u64 = 1;
pub const PROOF_COMPRESSION_HASH_SUITE: &str = "SHAKE256";
pub const PROOF_COMPRESSION_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PROOF_COMPRESSION_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PROOF_COMPRESSION_COMMITMENT_SCHEME: &str = "SHAKE256-merkle-root-v1";
pub const PROOF_COMPRESSION_RECURSION_SCHEME: &str = "nebula-devnet-recursive-proof-folding-v1";
pub const PROOF_COMPRESSION_ROLLUP_PROOF_SYSTEM: &str = "nebula-devnet-pq-rollup-validity-v1";
pub const PROOF_COMPRESSION_BRIDGE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-monero-bridge-validity-v1";
pub const PROOF_COMPRESSION_PRIVACY_POOL_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-privacy-pool-validity-v1";
pub const PROOF_COMPRESSION_DEFI_PROOF_SYSTEM: &str = "nebula-devnet-pq-defi-validity-v1";
pub const PROOF_COMPRESSION_VM_PROOF_SYSTEM: &str = "nebula-devnet-pq-vm-validity-v1";
pub const PROOF_COMPRESSION_DEFAULT_SECURITY_BITS: u64 = 128;
pub const PROOF_COMPRESSION_DEFAULT_MAX_CHILD_PROOFS: u64 = 128;
pub const PROOF_COMPRESSION_DEFAULT_RECURSION_DEPTH: u64 = 2;
pub const PROOF_COMPRESSION_DEFAULT_TARGET_VERIFY_MICROS: u64 = 25_000;
pub const PROOF_COMPRESSION_DEFAULT_TARGET_FINALITY_BLOCKS: u64 = 2;
pub const PROOF_COMPRESSION_DEFAULT_LEASE_BLOCKS: u64 = 6;
pub const PROOF_COMPRESSION_DEFAULT_CACHE_TTL_BLOCKS: u64 = 720;
pub const PROOF_COMPRESSION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 96;
pub const PROOF_COMPRESSION_DEFAULT_LOW_FEE_EPOCH_BLOCKS: u64 = 720;
pub const PROOF_COMPRESSION_MAX_BPS: u64 = 10_000;
pub const PROOF_COMPRESSION_MIN_COMPRESSION_RATIO_BPS: u64 = 500;
pub const PROOF_COMPRESSION_MAX_COMMITTEE_WEIGHT_BPS: u64 = 10_000;

pub const PROOF_COMPRESSION_STATUS_PENDING: &str = "pending";
pub const PROOF_COMPRESSION_STATUS_ACTIVE: &str = "active";
pub const PROOF_COMPRESSION_STATUS_ASSIGNED: &str = "assigned";
pub const PROOF_COMPRESSION_STATUS_RUNNING: &str = "running";
pub const PROOF_COMPRESSION_STATUS_COMPLETED: &str = "completed";
pub const PROOF_COMPRESSION_STATUS_VERIFIED: &str = "verified";
pub const PROOF_COMPRESSION_STATUS_REJECTED: &str = "rejected";
pub const PROOF_COMPRESSION_STATUS_EXPIRED: &str = "expired";
pub const PROOF_COMPRESSION_STATUS_CHALLENGED: &str = "challenged";
pub const PROOF_COMPRESSION_STATUS_RESOLVED: &str = "resolved";
pub const PROOF_COMPRESSION_STATUS_SETTLED: &str = "settled";
pub const PROOF_COMPRESSION_STATUS_SLASHED: &str = "slashed";
pub const PROOF_COMPRESSION_STATUS_PAUSED: &str = "paused";
pub const PROOF_COMPRESSION_STATUS_SEALED: &str = "sealed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCompressionFamily {
    Rollup,
    Bridge,
    PrivacyPool,
    Defi,
    Vm,
}

impl ProofCompressionFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rollup => "rollup",
            Self::Bridge => "bridge",
            Self::PrivacyPool => "privacy_pool",
            Self::Defi => "defi",
            Self::Vm => "vm",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::Rollup => PROOF_COMPRESSION_ROLLUP_PROOF_SYSTEM,
            Self::Bridge => PROOF_COMPRESSION_BRIDGE_PROOF_SYSTEM,
            Self::PrivacyPool => PROOF_COMPRESSION_PRIVACY_POOL_PROOF_SYSTEM,
            Self::Defi => PROOF_COMPRESSION_DEFI_PROOF_SYSTEM,
            Self::Vm => PROOF_COMPRESSION_VM_PROOF_SYSTEM,
        }
    }

    pub fn default_queue_bucket(self) -> &'static str {
        match self {
            Self::Rollup => "fast_rollup",
            Self::Bridge => "bridge_finality",
            Self::PrivacyPool => "privacy_pool",
            Self::Defi => "sealed_defi",
            Self::Vm => "contract_vm",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(self, Self::PrivacyPool | Self::Defi | Self::Vm)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionJobPriority {
    PublicGood,
    LowFee,
    FastFinality,
    BridgeExit,
    Marketplace,
    Maintenance,
}

impl CompressionJobPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicGood => "public_good",
            Self::LowFee => "low_fee",
            Self::FastFinality => "fast_finality",
            Self::BridgeExit => "bridge_exit",
            Self::Marketplace => "marketplace",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn score_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 1_000,
            Self::FastFinality => 900,
            Self::PublicGood => 760,
            Self::LowFee => 700,
            Self::Marketplace => 520,
            Self::Maintenance => 250,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionWorkerClass {
    Cpu,
    Gpu,
    Fpga,
    VerifierCommittee,
}

impl CompressionWorkerClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Fpga => "fpga",
            Self::VerifierCommittee => "verifier_committee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierRole {
    Scheduler,
    Verifier,
    Challenger,
    Watchtower,
    SponsorAuditor,
}

impl PqVerifierRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Verifier => "verifier",
            Self::Challenger => "challenger",
            Self::Watchtower => "watchtower",
            Self::SponsorAuditor => "sponsor_auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierCommitteePolicy {
    WeightedThreshold,
    RotatingQuorum,
    EmergencyUnanimity,
}

impl PqVerifierCommitteePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeightedThreshold => "weighted_threshold",
            Self::RotatingQuorum => "rotating_quorum",
            Self::EmergencyUnanimity => "emergency_unanimity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Accepted,
    Rejected,
    FallbackRequired,
}

impl VerificationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::FallbackRequired => "fallback_required",
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::Accepted => PROOF_COMPRESSION_STATUS_VERIFIED,
            Self::Rejected => PROOF_COMPRESSION_STATUS_REJECTED,
            Self::FallbackRequired => PROOF_COMPRESSION_STATUS_CHALLENGED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackChallengeKind {
    MissingChildProof,
    InvalidPublicInput,
    CommitteeQuorumFailure,
    CompressionMismatch,
    RecursiveAccumulatorMismatch,
    PrivacyMetadataLeak,
    BridgeFinalityMismatch,
    VmTraceMismatch,
    Timeout,
}

impl FallbackChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingChildProof => "missing_child_proof",
            Self::InvalidPublicInput => "invalid_public_input",
            Self::CommitteeQuorumFailure => "committee_quorum_failure",
            Self::CompressionMismatch => "compression_mismatch",
            Self::RecursiveAccumulatorMismatch => "recursive_accumulator_mismatch",
            Self::PrivacyMetadataLeak => "privacy_metadata_leak",
            Self::BridgeFinalityMismatch => "bridge_finality_mismatch",
            Self::VmTraceMismatch => "vm_trace_mismatch",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackChallengeOutcome {
    Pending,
    ProofAccepted,
    ProofRejected,
    Escalated,
    Slashed,
}

impl FallbackChallengeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ProofAccepted => "proof_accepted",
            Self::ProofRejected => "proof_rejected",
            Self::Escalated => "escalated",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeSponsorshipLane {
    PublicGood,
    WalletProofs,
    BridgeProofs,
    PrivateDefi,
    VmMicroBatches,
    EmergencyFallback,
}

impl LowFeeSponsorshipLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicGood => "public_good",
            Self::WalletProofs => "wallet_proofs",
            Self::BridgeProofs => "bridge_proofs",
            Self::PrivateDefi => "private_defi",
            Self::VmMicroBatches => "vm_micro_batches",
            Self::EmergencyFallback => "emergency_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceSettlementKind {
    Sponsored,
    OpenMarket,
    LatencyRebate,
    Slashing,
}

impl MarketplaceSettlementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sponsored => "sponsored",
            Self::OpenMarket => "open_market",
            Self::LatencyRebate => "latency_rebate",
            Self::Slashing => "slashing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySafeProofMetadata {
    pub metadata_id: String,
    pub family: ProofCompressionFamily,
    pub public_input_root: String,
    pub state_bucket_root: String,
    pub fee_bucket: String,
    pub amount_bucket: String,
    pub latency_bucket: String,
    pub participant_bucket_root: String,
    pub nullifier_bucket_root: String,
    pub asset_bucket_root: String,
    pub extra_bucket_root: String,
}

impl PrivacySafeProofMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ProofCompressionFamily,
        public_input_root: impl Into<String>,
        state_bucket_root: impl Into<String>,
        fee_bucket: impl Into<String>,
        amount_bucket: impl Into<String>,
        latency_bucket: impl Into<String>,
        participant_bucket_root: impl Into<String>,
        nullifier_bucket_root: impl Into<String>,
        asset_bucket_root: impl Into<String>,
        extra_bucket_root: impl Into<String>,
    ) -> ProofCompressionResult<Self> {
        let mut metadata = Self {
            metadata_id: String::new(),
            family,
            public_input_root: public_input_root.into(),
            state_bucket_root: state_bucket_root.into(),
            fee_bucket: normalize_label(fee_bucket.into()),
            amount_bucket: normalize_label(amount_bucket.into()),
            latency_bucket: normalize_label(latency_bucket.into()),
            participant_bucket_root: participant_bucket_root.into(),
            nullifier_bucket_root: nullifier_bucket_root.into(),
            asset_bucket_root: asset_bucket_root.into(),
            extra_bucket_root: extra_bucket_root.into(),
        };
        metadata.metadata_id = privacy_safe_metadata_id(
            metadata.family.as_str(),
            &metadata.public_input_root,
            &metadata.state_bucket_root,
            &metadata.fee_bucket,
            &metadata.amount_bucket,
            &metadata.latency_bucket,
        );
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "privacy_safe_proof_metadata",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "family": self.family.as_str(),
            "public_input_root": self.public_input_root,
            "state_bucket_root": self.state_bucket_root,
            "fee_bucket": self.fee_bucket,
            "amount_bucket": self.amount_bucket,
            "latency_bucket": self.latency_bucket,
            "participant_bucket_root": self.participant_bucket_root,
            "nullifier_bucket_root": self.nullifier_bucket_root,
            "asset_bucket_root": self.asset_bucket_root,
            "extra_bucket_root": self.extra_bucket_root,
        })
    }

    pub fn metadata_root(&self) -> String {
        proof_compression_payload_root(
            "PROOF-COMPRESSION-PRIVACY-METADATA",
            &self.identity_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("privacy metadata record object");
        object.insert(
            "metadata_id".to_string(),
            Value::String(self.metadata_id.clone()),
        );
        object.insert(
            "metadata_root".to_string(),
            Value::String(self.metadata_root()),
        );
        record
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.metadata_id, "privacy metadata id")?;
        ensure_hash_like(
            &self.public_input_root,
            "privacy metadata public input root",
        )?;
        ensure_hash_like(
            &self.state_bucket_root,
            "privacy metadata state bucket root",
        )?;
        ensure_non_empty(&self.fee_bucket, "privacy metadata fee bucket")?;
        ensure_non_empty(&self.amount_bucket, "privacy metadata amount bucket")?;
        ensure_non_empty(&self.latency_bucket, "privacy metadata latency bucket")?;
        ensure_hash_like(
            &self.participant_bucket_root,
            "privacy metadata participant bucket root",
        )?;
        ensure_hash_like(
            &self.nullifier_bucket_root,
            "privacy metadata nullifier bucket root",
        )?;
        ensure_hash_like(
            &self.asset_bucket_root,
            "privacy metadata asset bucket root",
        )?;
        ensure_hash_like(
            &self.extra_bucket_root,
            "privacy metadata extra bucket root",
        )?;
        let expected = privacy_safe_metadata_id(
            self.family.as_str(),
            &self.public_input_root,
            &self.state_bucket_root,
            &self.fee_bucket,
            &self.amount_bucket,
            &self.latency_bucket,
        );
        if self.metadata_id != expected {
            return Err("privacy metadata id mismatch".to_string());
        }
        Ok(self.metadata_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveBatchManifest {
    pub manifest_id: String,
    pub family: ProofCompressionFamily,
    pub manifest_version: u64,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub recursion_scheme: String,
    pub max_child_proofs: u64,
    pub max_public_inputs: u64,
    pub target_compressed_bytes: u64,
    pub target_verify_micros: u64,
    pub max_latency_blocks: u64,
    pub security_bits: u64,
    pub public_input_schema_root: String,
    pub privacy_metadata_policy_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl RecursiveBatchManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ProofCompressionFamily,
        manifest_version: u64,
        verifier_key_root: impl Into<String>,
        max_child_proofs: u64,
        max_public_inputs: u64,
        target_compressed_bytes: u64,
        target_verify_micros: u64,
        max_latency_blocks: u64,
        activated_at_height: u64,
        expires_at_height: u64,
        privacy_metadata_policy: &Value,
    ) -> ProofCompressionResult<Self> {
        let verifier_key_root = verifier_key_root.into();
        let proof_system = family.default_proof_system().to_string();
        let public_input_schema_root = recursive_manifest_public_input_schema_root(
            family.as_str(),
            manifest_version,
            max_public_inputs,
            &verifier_key_root,
        );
        let privacy_metadata_policy_root = proof_compression_payload_root(
            "PROOF-COMPRESSION-PRIVACY-METADATA-POLICY",
            privacy_metadata_policy,
        );
        let manifest_id = recursive_batch_manifest_id(
            family.as_str(),
            manifest_version,
            &proof_system,
            &verifier_key_root,
            &public_input_schema_root,
        );
        let manifest = Self {
            manifest_id,
            family,
            manifest_version,
            proof_system,
            verifier_key_root,
            recursion_scheme: PROOF_COMPRESSION_RECURSION_SCHEME.to_string(),
            max_child_proofs,
            max_public_inputs,
            target_compressed_bytes,
            target_verify_micros,
            max_latency_blocks,
            security_bits: PROOF_COMPRESSION_DEFAULT_SECURITY_BITS,
            public_input_schema_root,
            privacy_metadata_policy_root,
            activated_at_height,
            expires_at_height,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_ACTIVE
            && height >= self.activated_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_batch_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "schema_version": PROOF_COMPRESSION_SCHEMA_VERSION,
            "manifest_id": self.manifest_id,
            "family": self.family.as_str(),
            "manifest_version": self.manifest_version,
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "recursion_scheme": self.recursion_scheme,
            "max_child_proofs": self.max_child_proofs,
            "max_public_inputs": self.max_public_inputs,
            "target_compressed_bytes": self.target_compressed_bytes,
            "target_verify_micros": self.target_verify_micros,
            "max_latency_blocks": self.max_latency_blocks,
            "security_bits": self.security_bits,
            "public_input_schema_root": self.public_input_schema_root,
            "privacy_metadata_policy_root": self.privacy_metadata_policy_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.manifest_id, "recursive manifest id")?;
        ensure_non_empty(&self.proof_system, "recursive manifest proof system")?;
        ensure_hash_like(
            &self.verifier_key_root,
            "recursive manifest verifier key root",
        )?;
        ensure_non_empty(
            &self.recursion_scheme,
            "recursive manifest recursion scheme",
        )?;
        ensure_positive(self.manifest_version, "recursive manifest version")?;
        ensure_positive(self.max_child_proofs, "recursive manifest max child proofs")?;
        ensure_positive(
            self.max_public_inputs,
            "recursive manifest max public inputs",
        )?;
        ensure_positive(
            self.target_compressed_bytes,
            "recursive manifest target compressed bytes",
        )?;
        ensure_positive(
            self.target_verify_micros,
            "recursive manifest target verify micros",
        )?;
        ensure_positive(
            self.max_latency_blocks,
            "recursive manifest max latency blocks",
        )?;
        ensure_hash_like(
            &self.public_input_schema_root,
            "recursive manifest public input schema root",
        )?;
        ensure_hash_like(
            &self.privacy_metadata_policy_root,
            "recursive manifest privacy metadata policy root",
        )?;
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_PENDING,
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_PAUSED,
            ],
            "recursive manifest status",
        )?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("recursive manifest expires before activation".to_string());
        }
        let expected = recursive_batch_manifest_id(
            self.family.as_str(),
            self.manifest_version,
            &self.proof_system,
            &self.verifier_key_root,
            &self.public_input_schema_root,
        );
        if self.manifest_id != expected {
            return Err("recursive manifest id mismatch".to_string());
        }
        Ok(recursive_batch_manifest_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofBatch {
    pub batch_id: String,
    pub batch_number: u64,
    pub family: ProofCompressionFamily,
    pub parent_batch_id: String,
    pub manifest_id: String,
    pub child_proof_ids: Vec<String>,
    pub child_proof_root: String,
    pub public_input_roots: Vec<String>,
    pub public_input_root: String,
    pub privacy_metadata_ids: Vec<String>,
    pub privacy_metadata_root: String,
    pub accumulator_root: String,
    pub recursion_depth: u64,
    pub l2_start_height: u64,
    pub l2_end_height: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub status: String,
}

impl RecursiveProofBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_number: u64,
        family: ProofCompressionFamily,
        parent_batch_id: impl Into<String>,
        manifest_id: impl Into<String>,
        child_proof_ids: Vec<String>,
        public_input_roots: Vec<String>,
        privacy_metadata: &[PrivacySafeProofMetadata],
        recursion_depth: u64,
        l2_start_height: u64,
        l2_end_height: u64,
        opened_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let parent_batch_id = parent_batch_id.into();
        let manifest_id = manifest_id.into();
        let child_proof_root =
            proof_compression_string_set_root("PROOF-COMPRESSION-BATCH-CHILD", &child_proof_ids);
        let public_input_root = proof_compression_string_set_root(
            "PROOF-COMPRESSION-BATCH-PUBLIC-INPUT",
            &public_input_roots,
        );
        let privacy_metadata_ids = privacy_metadata
            .iter()
            .map(|metadata| metadata.metadata_id.clone())
            .collect::<Vec<_>>();
        let privacy_records = privacy_metadata
            .iter()
            .map(PrivacySafeProofMetadata::public_record)
            .collect::<Vec<_>>();
        let privacy_metadata_root =
            merkle_root("PROOF-COMPRESSION-BATCH-PRIVACY-METADATA", &privacy_records);
        let accumulator_root = recursive_accumulator_root(
            &child_proof_root,
            &public_input_root,
            &privacy_metadata_root,
            recursion_depth,
            child_proof_ids.len() as u64,
        );
        let batch_id = recursive_proof_batch_id(
            batch_number,
            family.as_str(),
            &parent_batch_id,
            &manifest_id,
            &public_input_root,
            &accumulator_root,
        );
        let batch = Self {
            batch_id,
            batch_number,
            family,
            parent_batch_id,
            manifest_id,
            child_proof_ids,
            child_proof_root,
            public_input_roots,
            public_input_root,
            privacy_metadata_ids,
            privacy_metadata_root,
            accumulator_root,
            recursion_depth,
            l2_start_height,
            l2_end_height,
            opened_at_height,
            sealed_at_height: 0,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn seal(mut self, sealed_at_height: u64) -> ProofCompressionResult<Self> {
        if sealed_at_height < self.opened_at_height {
            return Err("recursive batch sealed before it opened".to_string());
        }
        self.sealed_at_height = sealed_at_height;
        self.status = PROOF_COMPRESSION_STATUS_SEALED.to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "batch_id": self.batch_id,
            "batch_number": self.batch_number,
            "family": self.family.as_str(),
            "parent_batch_id": self.parent_batch_id,
            "manifest_id": self.manifest_id,
            "child_proof_root": self.child_proof_root,
            "child_proof_count": self.child_proof_ids.len() as u64,
            "public_input_root": self.public_input_root,
            "public_input_count": self.public_input_roots.len() as u64,
            "privacy_metadata_root": self.privacy_metadata_root,
            "privacy_metadata_count": self.privacy_metadata_ids.len() as u64,
            "accumulator_root": self.accumulator_root,
            "recursion_depth": self.recursion_depth,
            "l2_start_height": self.l2_start_height,
            "l2_end_height": self.l2_end_height,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.batch_id, "recursive batch id")?;
        ensure_hash_like(&self.manifest_id, "recursive batch manifest id")?;
        ensure_unique_strings(&self.child_proof_ids, "recursive batch child proof id")?;
        ensure_unique_strings(
            &self.public_input_roots,
            "recursive batch public input root",
        )?;
        ensure_unique_strings(
            &self.privacy_metadata_ids,
            "recursive batch privacy metadata id",
        )?;
        for root in &self.public_input_roots {
            ensure_hash_like(root, "recursive batch public input root")?;
        }
        for id in &self.privacy_metadata_ids {
            ensure_hash_like(id, "recursive batch privacy metadata id")?;
        }
        ensure_hash_like(&self.child_proof_root, "recursive batch child proof root")?;
        ensure_hash_like(&self.public_input_root, "recursive batch public input root")?;
        ensure_hash_like(
            &self.privacy_metadata_root,
            "recursive batch privacy metadata root",
        )?;
        ensure_hash_like(&self.accumulator_root, "recursive batch accumulator root")?;
        ensure_positive(self.recursion_depth, "recursive batch recursion depth")?;
        if self.l2_end_height < self.l2_start_height {
            return Err("recursive batch end height precedes start height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_SEALED,
                PROOF_COMPRESSION_STATUS_CHALLENGED,
                PROOF_COMPRESSION_STATUS_RESOLVED,
            ],
            "recursive batch status",
        )?;
        let child_root = proof_compression_string_set_root(
            "PROOF-COMPRESSION-BATCH-CHILD",
            &self.child_proof_ids,
        );
        if child_root != self.child_proof_root {
            return Err("recursive batch child proof root mismatch".to_string());
        }
        let public_input_root = proof_compression_string_set_root(
            "PROOF-COMPRESSION-BATCH-PUBLIC-INPUT",
            &self.public_input_roots,
        );
        if public_input_root != self.public_input_root {
            return Err("recursive batch public input root mismatch".to_string());
        }
        let expected_accumulator = recursive_accumulator_root(
            &self.child_proof_root,
            &self.public_input_root,
            &self.privacy_metadata_root,
            self.recursion_depth,
            self.child_proof_ids.len() as u64,
        );
        if self.accumulator_root != expected_accumulator {
            return Err("recursive batch accumulator root mismatch".to_string());
        }
        let expected = recursive_proof_batch_id(
            self.batch_number,
            self.family.as_str(),
            &self.parent_batch_id,
            &self.manifest_id,
            &self.public_input_root,
            &self.accumulator_root,
        );
        if self.batch_id != expected {
            return Err("recursive batch id mismatch".to_string());
        }
        Ok(recursive_proof_batch_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionJob {
    pub job_id: String,
    pub family: ProofCompressionFamily,
    pub priority: CompressionJobPriority,
    pub manifest_id: String,
    pub batch_id: String,
    pub source_proof_root: String,
    pub source_public_input_root: String,
    pub source_proof_bytes: u64,
    pub target_proof_bytes: u64,
    pub offered_fee_units: u64,
    pub fee_asset_id: String,
    pub sponsorship_id: String,
    pub marketplace_order_id: String,
    pub queue_bucket: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub assigned_worker_id: String,
    pub assigned_lease_id: String,
    pub completed_cache_id: String,
    pub completed_at_height: u64,
    pub status: String,
}

impl CompressionJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: ProofCompressionFamily,
        priority: CompressionJobPriority,
        manifest_id: impl Into<String>,
        batch_id: impl Into<String>,
        source_proof_root: impl Into<String>,
        source_public_input_root: impl Into<String>,
        source_proof_bytes: u64,
        target_proof_bytes: u64,
        offered_fee_units: u64,
        fee_asset_id: impl Into<String>,
        sponsorship_id: Option<&str>,
        marketplace_order_id: Option<&str>,
        opened_at_height: u64,
        deadline_height: u64,
    ) -> ProofCompressionResult<Self> {
        let manifest_id = manifest_id.into();
        let batch_id = batch_id.into();
        let source_proof_root = source_proof_root.into();
        let source_public_input_root = source_public_input_root.into();
        let fee_asset_id = fee_asset_id.into();
        let queue_bucket = format!("{}_{}", family.default_queue_bucket(), priority.as_str());
        let sponsorship_id = sponsorship_id.unwrap_or_default().to_string();
        let marketplace_order_id = marketplace_order_id.unwrap_or_default().to_string();
        let job_id = compression_job_id(
            family.as_str(),
            &manifest_id,
            &batch_id,
            &source_proof_root,
            &source_public_input_root,
            opened_at_height,
        );
        let job = Self {
            job_id,
            family,
            priority,
            manifest_id,
            batch_id,
            source_proof_root,
            source_public_input_root,
            source_proof_bytes,
            target_proof_bytes,
            offered_fee_units,
            fee_asset_id,
            sponsorship_id,
            marketplace_order_id,
            queue_bucket,
            opened_at_height,
            deadline_height,
            assigned_worker_id: String::new(),
            assigned_lease_id: String::new(),
            completed_cache_id: String::new(),
            completed_at_height: 0,
            status: PROOF_COMPRESSION_STATUS_PENDING.to_string(),
        };
        job.validate()?;
        Ok(job)
    }

    pub fn assign(
        mut self,
        worker_id: impl Into<String>,
        lease_id: impl Into<String>,
    ) -> ProofCompressionResult<Self> {
        self.assigned_worker_id = worker_id.into();
        self.assigned_lease_id = lease_id.into();
        self.status = PROOF_COMPRESSION_STATUS_ASSIGNED.to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn mark_completed(
        mut self,
        cache_id: impl Into<String>,
        completed_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        if completed_at_height < self.opened_at_height {
            return Err("compression job completed before it opened".to_string());
        }
        self.completed_cache_id = cache_id.into();
        self.completed_at_height = completed_at_height;
        self.status = PROOF_COMPRESSION_STATUS_COMPLETED.to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn latency_blocks(&self) -> u64 {
        if self.completed_at_height == 0 {
            return 0;
        }
        self.completed_at_height
            .saturating_sub(self.opened_at_height)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        matches!(
            self.status.as_str(),
            PROOF_COMPRESSION_STATUS_PENDING
                | PROOF_COMPRESSION_STATUS_ASSIGNED
                | PROOF_COMPRESSION_STATUS_RUNNING
        ) && height <= self.deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_job",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "job_id": self.job_id,
            "family": self.family.as_str(),
            "priority": self.priority.as_str(),
            "priority_score": self.priority.score_weight(),
            "manifest_id": self.manifest_id,
            "batch_id": self.batch_id,
            "source_proof_root": self.source_proof_root,
            "source_public_input_root": self.source_public_input_root,
            "source_proof_bytes": self.source_proof_bytes,
            "target_proof_bytes": self.target_proof_bytes,
            "offered_fee_units": self.offered_fee_units,
            "fee_asset_id": self.fee_asset_id,
            "sponsorship_id": self.sponsorship_id,
            "marketplace_order_id": self.marketplace_order_id,
            "queue_bucket": self.queue_bucket,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "assigned_worker_id": self.assigned_worker_id,
            "assigned_lease_id": self.assigned_lease_id,
            "completed_cache_id": self.completed_cache_id,
            "completed_at_height": self.completed_at_height,
            "latency_blocks": self.latency_blocks(),
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.job_id, "compression job id")?;
        ensure_hash_like(&self.manifest_id, "compression job manifest id")?;
        ensure_hash_like(&self.batch_id, "compression job batch id")?;
        ensure_hash_like(&self.source_proof_root, "compression job source proof root")?;
        ensure_hash_like(
            &self.source_public_input_root,
            "compression job source public input root",
        )?;
        ensure_positive(
            self.source_proof_bytes,
            "compression job source proof bytes",
        )?;
        ensure_positive(
            self.target_proof_bytes,
            "compression job target proof bytes",
        )?;
        ensure_non_empty(&self.fee_asset_id, "compression job fee asset")?;
        ensure_non_empty(&self.queue_bucket, "compression job queue bucket")?;
        if self.deadline_height < self.opened_at_height {
            return Err("compression job deadline precedes open height".to_string());
        }
        if !self.sponsorship_id.is_empty() {
            ensure_hash_like(&self.sponsorship_id, "compression job sponsorship id")?;
        }
        if !self.assigned_lease_id.is_empty() {
            ensure_hash_like(&self.assigned_lease_id, "compression job assigned lease id")?;
        }
        if !self.completed_cache_id.is_empty() {
            ensure_hash_like(
                &self.completed_cache_id,
                "compression job completed cache id",
            )?;
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_PENDING,
                PROOF_COMPRESSION_STATUS_ASSIGNED,
                PROOF_COMPRESSION_STATUS_RUNNING,
                PROOF_COMPRESSION_STATUS_COMPLETED,
                PROOF_COMPRESSION_STATUS_VERIFIED,
                PROOF_COMPRESSION_STATUS_REJECTED,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_CHALLENGED,
            ],
            "compression job status",
        )?;
        let expected = compression_job_id(
            self.family.as_str(),
            &self.manifest_id,
            &self.batch_id,
            &self.source_proof_root,
            &self.source_public_input_root,
            self.opened_at_height,
        );
        if self.job_id != expected {
            return Err("compression job id mismatch".to_string());
        }
        Ok(compression_job_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerLease {
    pub lease_id: String,
    pub job_id: String,
    pub worker_id: String,
    pub worker_class: CompressionWorkerClass,
    pub capacity_root: String,
    pub pq_public_key_root: String,
    pub supported_manifest_ids: Vec<String>,
    pub supported_manifest_root: String,
    pub max_parallel_jobs: u64,
    pub compute_units_per_block: u64,
    pub latency_target_blocks: u64,
    pub leased_at_height: u64,
    pub expires_at_height: u64,
    pub heartbeat_height: u64,
    pub status: String,
}

impl WorkerLease {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        worker_id: impl Into<String>,
        worker_class: CompressionWorkerClass,
        capacity_root: impl Into<String>,
        pq_public_key_root: impl Into<String>,
        supported_manifest_ids: Vec<String>,
        max_parallel_jobs: u64,
        compute_units_per_block: u64,
        latency_target_blocks: u64,
        leased_at_height: u64,
        expires_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let job_id = job_id.into();
        let worker_id = worker_id.into();
        let capacity_root = capacity_root.into();
        let pq_public_key_root = pq_public_key_root.into();
        let supported_manifest_root = proof_compression_string_set_root(
            "PROOF-COMPRESSION-WORKER-SUPPORTED-MANIFEST",
            &supported_manifest_ids,
        );
        let lease_id = worker_lease_id(
            &job_id,
            &worker_id,
            worker_class.as_str(),
            &capacity_root,
            leased_at_height,
        );
        let lease = Self {
            lease_id,
            job_id,
            worker_id,
            worker_class,
            capacity_root,
            pq_public_key_root,
            supported_manifest_ids,
            supported_manifest_root,
            max_parallel_jobs,
            compute_units_per_block,
            latency_target_blocks,
            leased_at_height,
            expires_at_height,
            heartbeat_height: leased_at_height,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        lease.validate()?;
        Ok(lease)
    }

    pub fn heartbeat(&mut self, height: u64) -> ProofCompressionResult<()> {
        if height < self.leased_at_height {
            return Err("worker lease heartbeat precedes lease height".to_string());
        }
        self.heartbeat_height = height;
        if self.status == PROOF_COMPRESSION_STATUS_ACTIVE && height >= self.expires_at_height {
            self.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
        }
        self.validate()?;
        Ok(())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_ACTIVE
            && height >= self.leased_at_height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "worker_lease",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "lease_id": self.lease_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "worker_class": self.worker_class.as_str(),
            "capacity_root": self.capacity_root,
            "pq_public_key_root": self.pq_public_key_root,
            "supported_manifest_root": self.supported_manifest_root,
            "supported_manifest_count": self.supported_manifest_ids.len() as u64,
            "max_parallel_jobs": self.max_parallel_jobs,
            "compute_units_per_block": self.compute_units_per_block,
            "latency_target_blocks": self.latency_target_blocks,
            "leased_at_height": self.leased_at_height,
            "expires_at_height": self.expires_at_height,
            "heartbeat_height": self.heartbeat_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.lease_id, "worker lease id")?;
        ensure_hash_like(&self.job_id, "worker lease job id")?;
        ensure_non_empty(&self.worker_id, "worker lease worker id")?;
        ensure_hash_like(&self.capacity_root, "worker lease capacity root")?;
        ensure_hash_like(&self.pq_public_key_root, "worker lease PQ key root")?;
        ensure_unique_strings(
            &self.supported_manifest_ids,
            "worker lease supported manifest id",
        )?;
        for manifest_id in &self.supported_manifest_ids {
            ensure_hash_like(manifest_id, "worker lease supported manifest id")?;
        }
        ensure_hash_like(
            &self.supported_manifest_root,
            "worker lease supported manifest root",
        )?;
        ensure_positive(self.max_parallel_jobs, "worker lease max parallel jobs")?;
        ensure_positive(
            self.compute_units_per_block,
            "worker lease compute units per block",
        )?;
        ensure_positive(
            self.latency_target_blocks,
            "worker lease latency target blocks",
        )?;
        if self.expires_at_height <= self.leased_at_height {
            return Err("worker lease expires before it starts".to_string());
        }
        if self.heartbeat_height < self.leased_at_height {
            return Err("worker lease heartbeat precedes lease".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_SLASHED,
                PROOF_COMPRESSION_STATUS_COMPLETED,
            ],
            "worker lease status",
        )?;
        let supported_root = proof_compression_string_set_root(
            "PROOF-COMPRESSION-WORKER-SUPPORTED-MANIFEST",
            &self.supported_manifest_ids,
        );
        if supported_root != self.supported_manifest_root {
            return Err("worker lease supported manifest root mismatch".to_string());
        }
        let expected = worker_lease_id(
            &self.job_id,
            &self.worker_id,
            self.worker_class.as_str(),
            &self.capacity_root,
            self.leased_at_height,
        );
        if self.lease_id != expected {
            return Err("worker lease id mismatch".to_string());
        }
        Ok(worker_lease_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCacheRecord {
    pub cache_id: String,
    pub job_id: String,
    pub batch_id: String,
    pub compressed_proof_id: String,
    pub compressed_proof_commitment: String,
    pub public_input_root: String,
    pub verifier_key_root: String,
    pub source_proof_bytes: u64,
    pub compressed_proof_bytes: u64,
    pub compression_ratio_bps: u64,
    pub cache_bucket: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ProofCacheRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &CompressionJob,
        compressed_proof_id: impl Into<String>,
        compressed_proof_commitment: impl Into<String>,
        verifier_key_root: impl Into<String>,
        compressed_proof_bytes: u64,
        cache_bucket: impl Into<String>,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> ProofCompressionResult<Self> {
        let compressed_proof_id = compressed_proof_id.into();
        let compressed_proof_commitment = compressed_proof_commitment.into();
        let verifier_key_root = verifier_key_root.into();
        let cache_bucket = normalize_label(cache_bucket.into());
        let compression_ratio_bps = ratio_bps(compressed_proof_bytes, job.source_proof_bytes);
        let cache_id = proof_cache_record_id(
            &job.job_id,
            &job.batch_id,
            &compressed_proof_id,
            &compressed_proof_commitment,
            created_at_height,
        );
        let cache = Self {
            cache_id,
            job_id: job.job_id.clone(),
            batch_id: job.batch_id.clone(),
            compressed_proof_id,
            compressed_proof_commitment,
            public_input_root: job.source_public_input_root.clone(),
            verifier_key_root,
            source_proof_bytes: job.source_proof_bytes,
            compressed_proof_bytes,
            compression_ratio_bps,
            cache_bucket,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        cache.validate()?;
        Ok(cache)
    }

    pub fn bytes_saved(&self) -> u64 {
        self.source_proof_bytes
            .saturating_sub(self.compressed_proof_bytes)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_ACTIVE
            && height >= self.created_at_height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_cache_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "cache_id": self.cache_id,
            "job_id": self.job_id,
            "batch_id": self.batch_id,
            "compressed_proof_id": self.compressed_proof_id,
            "compressed_proof_commitment": self.compressed_proof_commitment,
            "public_input_root": self.public_input_root,
            "verifier_key_root": self.verifier_key_root,
            "source_proof_bytes": self.source_proof_bytes,
            "compressed_proof_bytes": self.compressed_proof_bytes,
            "compression_ratio_bps": self.compression_ratio_bps,
            "bytes_saved": self.bytes_saved(),
            "cache_bucket": self.cache_bucket,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.cache_id, "proof cache id")?;
        ensure_hash_like(&self.job_id, "proof cache job id")?;
        ensure_hash_like(&self.batch_id, "proof cache batch id")?;
        ensure_non_empty(&self.compressed_proof_id, "proof cache compressed proof id")?;
        ensure_hash_like(
            &self.compressed_proof_commitment,
            "proof cache compressed proof commitment",
        )?;
        ensure_hash_like(&self.public_input_root, "proof cache public input root")?;
        ensure_hash_like(&self.verifier_key_root, "proof cache verifier key root")?;
        ensure_positive(self.source_proof_bytes, "proof cache source proof bytes")?;
        ensure_positive(
            self.compressed_proof_bytes,
            "proof cache compressed proof bytes",
        )?;
        if self.compressed_proof_bytes >= self.source_proof_bytes {
            return Err("proof cache did not compress source proof".to_string());
        }
        if self.compression_ratio_bps < PROOF_COMPRESSION_MIN_COMPRESSION_RATIO_BPS
            || self.compression_ratio_bps > PROOF_COMPRESSION_MAX_BPS
        {
            return Err("proof cache compression ratio out of bounds".to_string());
        }
        ensure_non_empty(&self.cache_bucket, "proof cache bucket")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("proof cache expires before it is created".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_REJECTED,
                PROOF_COMPRESSION_STATUS_VERIFIED,
            ],
            "proof cache status",
        )?;
        let expected_ratio = ratio_bps(self.compressed_proof_bytes, self.source_proof_bytes);
        if self.compression_ratio_bps != expected_ratio {
            return Err("proof cache compression ratio mismatch".to_string());
        }
        let expected = proof_cache_record_id(
            &self.job_id,
            &self.batch_id,
            &self.compressed_proof_id,
            &self.compressed_proof_commitment,
            self.created_at_height,
        );
        if self.cache_id != expected {
            return Err("proof cache id mismatch".to_string());
        }
        Ok(proof_cache_record_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub receipt_id: String,
    pub cache_id: String,
    pub job_id: String,
    pub batch_id: String,
    pub committee_id: String,
    pub scheduler_attestation_root: String,
    pub outcome: VerificationOutcome,
    pub verify_micros: u64,
    pub verifier_fee_units: u64,
    pub finality_height: u64,
    pub verified_at_height: u64,
    pub status: String,
}

impl VerificationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cache: &ProofCacheRecord,
        committee_id: impl Into<String>,
        scheduler_attestation_root: impl Into<String>,
        outcome: VerificationOutcome,
        verify_micros: u64,
        verifier_fee_units: u64,
        finality_height: u64,
        verified_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let committee_id = committee_id.into();
        let scheduler_attestation_root = scheduler_attestation_root.into();
        let receipt_id = verification_receipt_id(
            &cache.cache_id,
            &cache.job_id,
            &committee_id,
            outcome.as_str(),
            verified_at_height,
        );
        let receipt = Self {
            receipt_id,
            cache_id: cache.cache_id.clone(),
            job_id: cache.job_id.clone(),
            batch_id: cache.batch_id.clone(),
            committee_id,
            scheduler_attestation_root,
            outcome,
            verify_micros,
            verifier_fee_units,
            finality_height,
            verified_at_height,
            status: outcome.status().to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verification_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "cache_id": self.cache_id,
            "job_id": self.job_id,
            "batch_id": self.batch_id,
            "committee_id": self.committee_id,
            "scheduler_attestation_root": self.scheduler_attestation_root,
            "outcome": self.outcome.as_str(),
            "verify_micros": self.verify_micros,
            "verifier_fee_units": self.verifier_fee_units,
            "finality_height": self.finality_height,
            "verified_at_height": self.verified_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.receipt_id, "verification receipt id")?;
        ensure_hash_like(&self.cache_id, "verification receipt cache id")?;
        ensure_hash_like(&self.job_id, "verification receipt job id")?;
        ensure_hash_like(&self.batch_id, "verification receipt batch id")?;
        ensure_hash_like(&self.committee_id, "verification receipt committee id")?;
        ensure_hash_like(
            &self.scheduler_attestation_root,
            "verification receipt attestation root",
        )?;
        ensure_positive(self.verify_micros, "verification receipt verify micros")?;
        if self.finality_height < self.verified_at_height {
            return Err("verification receipt finality height precedes verification".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_VERIFIED,
                PROOF_COMPRESSION_STATUS_REJECTED,
                PROOF_COMPRESSION_STATUS_CHALLENGED,
            ],
            "verification receipt status",
        )?;
        if self.status != self.outcome.status() {
            return Err("verification receipt status does not match outcome".to_string());
        }
        let expected = verification_receipt_id(
            &self.cache_id,
            &self.job_id,
            &self.committee_id,
            self.outcome.as_str(),
            self.verified_at_height,
        );
        if self.receipt_id != expected {
            return Err("verification receipt id mismatch".to_string());
        }
        Ok(verification_receipt_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierMember {
    pub member_id: String,
    pub operator_id: String,
    pub role: PqVerifierRole,
    pub weight: u64,
    pub pq_public_key_root: String,
    pub recovery_public_key_root: String,
    pub stake_root: String,
    pub endpoint_commitment: String,
    pub joined_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqVerifierMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        role: PqVerifierRole,
        weight: u64,
        pq_public_key_root: impl Into<String>,
        recovery_public_key_root: impl Into<String>,
        stake_root: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        joined_at_height: u64,
        expires_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let operator_id = operator_id.into();
        let pq_public_key_root = pq_public_key_root.into();
        let recovery_public_key_root = recovery_public_key_root.into();
        let stake_root = stake_root.into();
        let endpoint_commitment = endpoint_commitment.into();
        let member_id = pq_verifier_member_id(
            &operator_id,
            role.as_str(),
            &pq_public_key_root,
            &recovery_public_key_root,
            joined_at_height,
        );
        let member = Self {
            member_id,
            operator_id,
            role,
            weight,
            pq_public_key_root,
            recovery_public_key_root,
            stake_root,
            endpoint_commitment,
            joined_at_height,
            expires_at_height,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        member.validate()?;
        Ok(member)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_ACTIVE
            && height >= self.joined_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_member",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "weight": self.weight,
            "pq_public_key_root": self.pq_public_key_root,
            "recovery_public_key_root": self.recovery_public_key_root,
            "stake_root": self.stake_root,
            "endpoint_commitment": self.endpoint_commitment,
            "joined_at_height": self.joined_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.member_id, "PQ verifier member id")?;
        ensure_non_empty(&self.operator_id, "PQ verifier operator id")?;
        ensure_positive(self.weight, "PQ verifier member weight")?;
        ensure_hash_like(&self.pq_public_key_root, "PQ verifier PQ public key root")?;
        ensure_hash_like(
            &self.recovery_public_key_root,
            "PQ verifier recovery public key root",
        )?;
        ensure_hash_like(&self.stake_root, "PQ verifier stake root")?;
        ensure_hash_like(&self.endpoint_commitment, "PQ verifier endpoint commitment")?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.joined_at_height {
            return Err("PQ verifier member expires before join height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_PAUSED,
                PROOF_COMPRESSION_STATUS_SLASHED,
            ],
            "PQ verifier member status",
        )?;
        let expected = pq_verifier_member_id(
            &self.operator_id,
            self.role.as_str(),
            &self.pq_public_key_root,
            &self.recovery_public_key_root,
            self.joined_at_height,
        );
        if self.member_id != expected {
            return Err("PQ verifier member id mismatch".to_string());
        }
        Ok(pq_verifier_member_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierCommittee {
    pub committee_id: String,
    pub committee_version: u64,
    pub epoch: u64,
    pub policy: PqVerifierCommitteePolicy,
    pub member_ids: Vec<String>,
    pub member_root: String,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub challenge_window_blocks: u64,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PqVerifierCommittee {
    pub fn from_members(
        committee_version: u64,
        epoch: u64,
        policy: PqVerifierCommitteePolicy,
        members: &[PqVerifierMember],
        threshold_weight: u64,
        challenge_window_blocks: u64,
        activated_at_height: u64,
        expires_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let member_ids = members
            .iter()
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        let total_weight = members
            .iter()
            .fold(0_u64, |total, member| total.saturating_add(member.weight));
        let member_root = pq_verifier_member_set_root(members);
        let committee_id = pq_verifier_committee_id(
            committee_version,
            epoch,
            policy.as_str(),
            &member_root,
            threshold_weight,
        );
        let committee = Self {
            committee_id,
            committee_version,
            epoch,
            policy,
            member_ids,
            member_root,
            threshold_weight,
            total_weight,
            challenge_window_blocks,
            activated_at_height,
            expires_at_height,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_ACTIVE
            && height >= self.activated_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn threshold_bps(&self) -> u64 {
        ratio_bps(self.threshold_weight, self.total_weight)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_committee",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "committee_version": self.committee_version,
            "epoch": self.epoch,
            "policy": self.policy.as_str(),
            "member_root": self.member_root,
            "member_count": self.member_ids.len() as u64,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "threshold_bps": self.threshold_bps(),
            "challenge_window_blocks": self.challenge_window_blocks,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.committee_id, "PQ verifier committee id")?;
        ensure_positive(self.committee_version, "PQ verifier committee version")?;
        ensure_unique_strings(&self.member_ids, "PQ verifier committee member id")?;
        for member_id in &self.member_ids {
            ensure_hash_like(member_id, "PQ verifier committee member id")?;
        }
        ensure_hash_like(&self.member_root, "PQ verifier committee member root")?;
        ensure_positive(self.threshold_weight, "PQ verifier committee threshold")?;
        ensure_positive(self.total_weight, "PQ verifier committee total weight")?;
        if self.threshold_weight > self.total_weight {
            return Err("PQ verifier committee threshold exceeds total weight".to_string());
        }
        if self.threshold_bps() > PROOF_COMPRESSION_MAX_COMMITTEE_WEIGHT_BPS {
            return Err("PQ verifier committee threshold bps out of bounds".to_string());
        }
        ensure_positive(
            self.challenge_window_blocks,
            "PQ verifier committee challenge window",
        )?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.activated_at_height {
            return Err("PQ verifier committee expires before activation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_PAUSED,
            ],
            "PQ verifier committee status",
        )?;
        let expected = pq_verifier_committee_id(
            self.committee_version,
            self.epoch,
            self.policy.as_str(),
            &self.member_root,
            self.threshold_weight,
        );
        if self.committee_id != expected {
            return Err("PQ verifier committee id mismatch".to_string());
        }
        Ok(pq_verifier_committee_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub scheduler_commitment: String,
    pub job_ids: Vec<String>,
    pub job_root: String,
    pub lease_ids: Vec<String>,
    pub lease_root: String,
    pub capacity_snapshot_root: String,
    pub queue_depth_bucket: String,
    pub expected_latency_blocks: u64,
    pub deadline_height: u64,
    pub signature_root: String,
    pub attested_at_height: u64,
    pub status: String,
}

impl SchedulerAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee_id: impl Into<String>,
        scheduler_commitment: impl Into<String>,
        job_ids: Vec<String>,
        lease_ids: Vec<String>,
        capacity_snapshot_root: impl Into<String>,
        queue_depth_bucket: impl Into<String>,
        expected_latency_blocks: u64,
        deadline_height: u64,
        signature_root: impl Into<String>,
        attested_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let committee_id = committee_id.into();
        let scheduler_commitment = scheduler_commitment.into();
        let capacity_snapshot_root = capacity_snapshot_root.into();
        let queue_depth_bucket = normalize_label(queue_depth_bucket.into());
        let signature_root = signature_root.into();
        let job_root =
            proof_compression_string_set_root("PROOF-COMPRESSION-ATTESTED-JOB", &job_ids);
        let lease_root =
            proof_compression_string_set_root("PROOF-COMPRESSION-ATTESTED-LEASE", &lease_ids);
        let attestation_id = scheduler_attestation_id(
            &committee_id,
            &scheduler_commitment,
            &job_root,
            &lease_root,
            attested_at_height,
        );
        let attestation = Self {
            attestation_id,
            committee_id,
            scheduler_commitment,
            job_ids,
            job_root,
            lease_ids,
            lease_root,
            capacity_snapshot_root,
            queue_depth_bucket,
            expected_latency_blocks,
            deadline_height,
            signature_root,
            attested_at_height,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "scheduler_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "scheduler_commitment": self.scheduler_commitment,
            "job_root": self.job_root,
            "job_count": self.job_ids.len() as u64,
            "lease_root": self.lease_root,
            "lease_count": self.lease_ids.len() as u64,
            "capacity_snapshot_root": self.capacity_snapshot_root,
            "queue_depth_bucket": self.queue_depth_bucket,
            "expected_latency_blocks": self.expected_latency_blocks,
            "deadline_height": self.deadline_height,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.attestation_id, "scheduler attestation id")?;
        ensure_hash_like(&self.committee_id, "scheduler attestation committee id")?;
        ensure_hash_like(
            &self.scheduler_commitment,
            "scheduler attestation scheduler commitment",
        )?;
        ensure_unique_strings(&self.job_ids, "scheduler attestation job id")?;
        ensure_unique_strings(&self.lease_ids, "scheduler attestation lease id")?;
        for job_id in &self.job_ids {
            ensure_hash_like(job_id, "scheduler attestation job id")?;
        }
        for lease_id in &self.lease_ids {
            ensure_hash_like(lease_id, "scheduler attestation lease id")?;
        }
        ensure_hash_like(&self.job_root, "scheduler attestation job root")?;
        ensure_hash_like(&self.lease_root, "scheduler attestation lease root")?;
        ensure_hash_like(
            &self.capacity_snapshot_root,
            "scheduler attestation capacity snapshot root",
        )?;
        ensure_non_empty(
            &self.queue_depth_bucket,
            "scheduler attestation queue depth bucket",
        )?;
        ensure_positive(
            self.expected_latency_blocks,
            "scheduler attestation expected latency",
        )?;
        if self.deadline_height < self.attested_at_height {
            return Err("scheduler attestation deadline precedes attestation".to_string());
        }
        ensure_hash_like(&self.signature_root, "scheduler attestation signature root")?;
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_CHALLENGED,
            ],
            "scheduler attestation status",
        )?;
        let job_root =
            proof_compression_string_set_root("PROOF-COMPRESSION-ATTESTED-JOB", &self.job_ids);
        if job_root != self.job_root {
            return Err("scheduler attestation job root mismatch".to_string());
        }
        let lease_root =
            proof_compression_string_set_root("PROOF-COMPRESSION-ATTESTED-LEASE", &self.lease_ids);
        if lease_root != self.lease_root {
            return Err("scheduler attestation lease root mismatch".to_string());
        }
        let expected = scheduler_attestation_id(
            &self.committee_id,
            &self.scheduler_commitment,
            &self.job_root,
            &self.lease_root,
            self.attested_at_height,
        );
        if self.attestation_id != expected {
            return Err("scheduler attestation id mismatch".to_string());
        }
        Ok(scheduler_attestation_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackChallengeRecord {
    pub challenge_id: String,
    pub challenge_kind: FallbackChallengeKind,
    pub target_kind: String,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub fallback_manifest_id: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub resolved_at_height: u64,
    pub outcome: FallbackChallengeOutcome,
    pub status: String,
}

impl FallbackChallengeRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_kind: FallbackChallengeKind,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        fallback_manifest_id: impl Into<String>,
        bond_units: u64,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> ProofCompressionResult<Self> {
        let target_kind = normalize_label(target_kind.into());
        let target_id = target_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let fallback_manifest_id = fallback_manifest_id.into();
        let challenge_id = fallback_challenge_id(
            challenge_kind.as_str(),
            &target_kind,
            &target_id,
            &challenger_commitment,
            &evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            challenge_kind,
            target_kind,
            target_id,
            challenger_commitment,
            evidence_root,
            fallback_manifest_id,
            bond_units,
            opened_at_height,
            deadline_height: opened_at_height.saturating_add(challenge_window_blocks),
            resolved_at_height: 0,
            outcome: FallbackChallengeOutcome::Pending,
            status: PROOF_COMPRESSION_STATUS_CHALLENGED.to_string(),
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn resolve(
        mut self,
        outcome: FallbackChallengeOutcome,
        resolved_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        if resolved_at_height < self.opened_at_height {
            return Err("fallback challenge resolved before it opened".to_string());
        }
        self.outcome = outcome;
        self.resolved_at_height = resolved_at_height;
        self.status = match outcome {
            FallbackChallengeOutcome::Pending => PROOF_COMPRESSION_STATUS_CHALLENGED,
            FallbackChallengeOutcome::ProofAccepted => PROOF_COMPRESSION_STATUS_RESOLVED,
            FallbackChallengeOutcome::ProofRejected => PROOF_COMPRESSION_STATUS_REJECTED,
            FallbackChallengeOutcome::Escalated => PROOF_COMPRESSION_STATUS_CHALLENGED,
            FallbackChallengeOutcome::Slashed => PROOF_COMPRESSION_STATUS_SLASHED,
        }
        .to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_CHALLENGED && height <= self.deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fallback_challenge_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "fallback_manifest_id": self.fallback_manifest_id,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "outcome": self.outcome.as_str(),
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.challenge_id, "fallback challenge id")?;
        ensure_non_empty(&self.target_kind, "fallback challenge target kind")?;
        ensure_hash_like(&self.target_id, "fallback challenge target id")?;
        ensure_hash_like(
            &self.challenger_commitment,
            "fallback challenge challenger commitment",
        )?;
        ensure_hash_like(&self.evidence_root, "fallback challenge evidence root")?;
        ensure_hash_like(
            &self.fallback_manifest_id,
            "fallback challenge fallback manifest id",
        )?;
        ensure_positive(self.bond_units, "fallback challenge bond units")?;
        if self.deadline_height <= self.opened_at_height {
            return Err("fallback challenge deadline precedes open height".to_string());
        }
        if self.resolved_at_height != 0 && self.resolved_at_height < self.opened_at_height {
            return Err("fallback challenge resolved before open height".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_CHALLENGED,
                PROOF_COMPRESSION_STATUS_RESOLVED,
                PROOF_COMPRESSION_STATUS_REJECTED,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_SLASHED,
            ],
            "fallback challenge status",
        )?;
        let expected = fallback_challenge_id(
            self.challenge_kind.as_str(),
            &self.target_kind,
            &self.target_id,
            &self.challenger_commitment,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected {
            return Err("fallback challenge id mismatch".to_string());
        }
        Ok(fallback_challenge_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudProofEscalation {
    pub escalation_id: String,
    pub challenge_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub pre_state_root: String,
    pub claimed_post_state_root: String,
    pub counterexample_root: String,
    pub fallback_execution_root: String,
    pub escalation_root: String,
    pub priority: u64,
    pub escalated_at_height: u64,
    pub status: String,
}

impl FraudProofEscalation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: impl Into<String>,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        pre_state_root: impl Into<String>,
        claimed_post_state_root: impl Into<String>,
        counterexample_root: impl Into<String>,
        fallback_execution_root: impl Into<String>,
        priority: u64,
        escalated_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let challenge_id = challenge_id.into();
        let target_kind = normalize_label(target_kind.into());
        let target_id = target_id.into();
        let pre_state_root = pre_state_root.into();
        let claimed_post_state_root = claimed_post_state_root.into();
        let counterexample_root = counterexample_root.into();
        let fallback_execution_root = fallback_execution_root.into();
        let escalation_root = fraud_proof_escalation_payload_root(
            &challenge_id,
            &target_id,
            &pre_state_root,
            &claimed_post_state_root,
            &counterexample_root,
            &fallback_execution_root,
        );
        let escalation_id = fraud_proof_escalation_id(
            &challenge_id,
            &target_kind,
            &target_id,
            &escalation_root,
            escalated_at_height,
        );
        let escalation = Self {
            escalation_id,
            challenge_id,
            target_kind,
            target_id,
            pre_state_root,
            claimed_post_state_root,
            counterexample_root,
            fallback_execution_root,
            escalation_root,
            priority,
            escalated_at_height,
            status: PROOF_COMPRESSION_STATUS_CHALLENGED.to_string(),
        };
        escalation.validate()?;
        Ok(escalation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fraud_proof_escalation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "escalation_id": self.escalation_id,
            "challenge_id": self.challenge_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "pre_state_root": self.pre_state_root,
            "claimed_post_state_root": self.claimed_post_state_root,
            "counterexample_root": self.counterexample_root,
            "fallback_execution_root": self.fallback_execution_root,
            "escalation_root": self.escalation_root,
            "priority": self.priority,
            "escalated_at_height": self.escalated_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.escalation_id, "fraud proof escalation id")?;
        ensure_hash_like(&self.challenge_id, "fraud proof challenge id")?;
        ensure_non_empty(&self.target_kind, "fraud proof target kind")?;
        ensure_hash_like(&self.target_id, "fraud proof target id")?;
        ensure_hash_like(&self.pre_state_root, "fraud proof pre-state root")?;
        ensure_hash_like(
            &self.claimed_post_state_root,
            "fraud proof claimed post-state root",
        )?;
        ensure_hash_like(&self.counterexample_root, "fraud proof counterexample root")?;
        ensure_hash_like(
            &self.fallback_execution_root,
            "fraud proof fallback execution root",
        )?;
        ensure_hash_like(&self.escalation_root, "fraud proof escalation root")?;
        ensure_positive(self.priority, "fraud proof escalation priority")?;
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_CHALLENGED,
                PROOF_COMPRESSION_STATUS_RESOLVED,
                PROOF_COMPRESSION_STATUS_SLASHED,
            ],
            "fraud proof escalation status",
        )?;
        let escalation_root = fraud_proof_escalation_payload_root(
            &self.challenge_id,
            &self.target_id,
            &self.pre_state_root,
            &self.claimed_post_state_root,
            &self.counterexample_root,
            &self.fallback_execution_root,
        );
        if self.escalation_root != escalation_root {
            return Err("fraud proof escalation root mismatch".to_string());
        }
        let expected = fraud_proof_escalation_id(
            &self.challenge_id,
            &self.target_kind,
            &self.target_id,
            &self.escalation_root,
            self.escalated_at_height,
        );
        if self.escalation_id != expected {
            return Err("fraud proof escalation id mismatch".to_string());
        }
        Ok(fraud_proof_escalation_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane: LowFeeSponsorshipLane,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_per_job_units: u64,
    pub eligible_family_root: String,
    pub beneficiary_bucket_root: String,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl LowFeeProofSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        lane: LowFeeSponsorshipLane,
        fee_asset_id: impl Into<String>,
        budget_units: u64,
        max_fee_per_job_units: u64,
        eligible_families: Vec<ProofCompressionFamily>,
        beneficiary_bucket_root: impl Into<String>,
        starts_at_height: u64,
        ends_at_height: u64,
        nonce: u64,
    ) -> ProofCompressionResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        let beneficiary_bucket_root = beneficiary_bucket_root.into();
        let family_labels = eligible_families
            .iter()
            .map(|family| family.as_str().to_string())
            .collect::<Vec<_>>();
        let eligible_family_root = proof_compression_string_set_root(
            "PROOF-COMPRESSION-SPONSORSHIP-FAMILY",
            &family_labels,
        );
        let sponsorship_id = low_fee_proof_sponsorship_id(
            &sponsor_commitment,
            lane.as_str(),
            &fee_asset_id,
            &eligible_family_root,
            starts_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            lane,
            fee_asset_id,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_per_job_units,
            eligible_family_root,
            beneficiary_bucket_root,
            starts_at_height,
            ends_at_height,
            nonce,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve_units(&mut self, units: u64) -> ProofCompressionResult<()> {
        if units == 0 {
            return Err("sponsorship reserve units cannot be zero".to_string());
        }
        if units > self.available_units() {
            return Err("sponsorship budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        self.validate()?;
        Ok(())
    }

    pub fn spend_reserved_units(&mut self, reserved_units: u64, spent_units: u64) {
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.spent_units = self.spent_units.saturating_add(spent_units);
        if self.available_units() == 0 {
            self.status = PROOF_COMPRESSION_STATUS_SETTLED.to_string();
        }
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_COMPRESSION_STATUS_ACTIVE
            && height >= self.starts_at_height
            && height <= self.ends_at_height
            && self.available_units() > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_per_job_units": self.max_fee_per_job_units,
            "eligible_family_root": self.eligible_family_root,
            "beneficiary_bucket_root": self.beneficiary_bucket_root,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.sponsorship_id, "low-fee proof sponsorship id")?;
        ensure_hash_like(
            &self.sponsor_commitment,
            "low-fee proof sponsorship sponsor commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "low-fee proof sponsorship fee asset")?;
        ensure_positive(self.budget_units, "low-fee proof sponsorship budget")?;
        ensure_positive(
            self.max_fee_per_job_units,
            "low-fee proof sponsorship max fee per job",
        )?;
        ensure_hash_like(
            &self.eligible_family_root,
            "low-fee proof sponsorship family root",
        )?;
        ensure_hash_like(
            &self.beneficiary_bucket_root,
            "low-fee proof sponsorship beneficiary bucket root",
        )?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("low-fee proof sponsorship accounting exceeds budget".to_string());
        }
        if self.ends_at_height < self.starts_at_height {
            return Err("low-fee proof sponsorship ends before start".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_SETTLED,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_PAUSED,
            ],
            "low-fee proof sponsorship status",
        )?;
        let expected = low_fee_proof_sponsorship_id(
            &self.sponsor_commitment,
            self.lane.as_str(),
            &self.fee_asset_id,
            &self.eligible_family_root,
            self.starts_at_height,
            self.nonce,
        );
        if self.sponsorship_id != expected {
            return Err("low-fee proof sponsorship id mismatch".to_string());
        }
        Ok(low_fee_proof_sponsorship_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMarketplaceSettlement {
    pub settlement_id: String,
    pub settlement_kind: MarketplaceSettlementKind,
    pub job_id: String,
    pub worker_id: String,
    pub sponsorship_id: String,
    pub cache_id: String,
    pub receipt_id: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub sponsor_paid_units: u64,
    pub worker_paid_units: u64,
    pub protocol_fee_units: u64,
    pub slashing_units: u64,
    pub latency_rebate_units: u64,
    pub settlement_root: String,
    pub settled_at_height: u64,
    pub status: String,
}

impl ProofMarketplaceSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        settlement_kind: MarketplaceSettlementKind,
        job_id: impl Into<String>,
        worker_id: impl Into<String>,
        sponsorship_id: impl Into<String>,
        cache_id: impl Into<String>,
        receipt_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        gross_fee_units: u64,
        sponsor_paid_units: u64,
        worker_paid_units: u64,
        protocol_fee_units: u64,
        slashing_units: u64,
        latency_rebate_units: u64,
        settled_at_height: u64,
    ) -> ProofCompressionResult<Self> {
        let job_id = job_id.into();
        let worker_id = worker_id.into();
        let sponsorship_id = sponsorship_id.into();
        let cache_id = cache_id.into();
        let receipt_id = receipt_id.into();
        let fee_asset_id = fee_asset_id.into();
        let settlement_root = proof_marketplace_settlement_payload_root(
            settlement_kind.as_str(),
            &job_id,
            &worker_id,
            &sponsorship_id,
            &cache_id,
            &receipt_id,
            gross_fee_units,
            sponsor_paid_units,
            worker_paid_units,
            protocol_fee_units,
            slashing_units,
            latency_rebate_units,
        );
        let settlement_id = proof_marketplace_settlement_id(
            settlement_kind.as_str(),
            &job_id,
            &worker_id,
            &settlement_root,
            settled_at_height,
        );
        let settlement = Self {
            settlement_id,
            settlement_kind,
            job_id,
            worker_id,
            sponsorship_id,
            cache_id,
            receipt_id,
            fee_asset_id,
            gross_fee_units,
            sponsor_paid_units,
            worker_paid_units,
            protocol_fee_units,
            slashing_units,
            latency_rebate_units,
            settlement_root,
            settled_at_height,
            status: PROOF_COMPRESSION_STATUS_SETTLED.to_string(),
        };
        settlement.validate()?;
        Ok(settlement)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_marketplace_settlement",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "settlement_id": self.settlement_id,
            "settlement_kind": self.settlement_kind.as_str(),
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "sponsorship_id": self.sponsorship_id,
            "cache_id": self.cache_id,
            "receipt_id": self.receipt_id,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsor_paid_units": self.sponsor_paid_units,
            "worker_paid_units": self.worker_paid_units,
            "protocol_fee_units": self.protocol_fee_units,
            "slashing_units": self.slashing_units,
            "latency_rebate_units": self.latency_rebate_units,
            "settlement_root": self.settlement_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.settlement_id, "proof marketplace settlement id")?;
        ensure_hash_like(&self.job_id, "proof marketplace settlement job id")?;
        ensure_non_empty(&self.worker_id, "proof marketplace settlement worker id")?;
        if !self.sponsorship_id.is_empty() {
            ensure_hash_like(
                &self.sponsorship_id,
                "proof marketplace settlement sponsorship id",
            )?;
        }
        ensure_hash_like(&self.cache_id, "proof marketplace settlement cache id")?;
        ensure_hash_like(&self.receipt_id, "proof marketplace settlement receipt id")?;
        ensure_non_empty(&self.fee_asset_id, "proof marketplace settlement fee asset")?;
        ensure_positive(
            self.gross_fee_units,
            "proof marketplace settlement gross fee",
        )?;
        if self
            .worker_paid_units
            .saturating_add(self.protocol_fee_units)
            .saturating_add(self.latency_rebate_units)
            > self
                .gross_fee_units
                .saturating_add(self.sponsor_paid_units)
                .saturating_add(self.slashing_units)
        {
            return Err("proof marketplace settlement accounting is unbalanced".to_string());
        }
        ensure_hash_like(
            &self.settlement_root,
            "proof marketplace settlement settlement root",
        )?;
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_SETTLED,
                PROOF_COMPRESSION_STATUS_CHALLENGED,
                PROOF_COMPRESSION_STATUS_SLASHED,
            ],
            "proof marketplace settlement status",
        )?;
        let settlement_root = proof_marketplace_settlement_payload_root(
            self.settlement_kind.as_str(),
            &self.job_id,
            &self.worker_id,
            &self.sponsorship_id,
            &self.cache_id,
            &self.receipt_id,
            self.gross_fee_units,
            self.sponsor_paid_units,
            self.worker_paid_units,
            self.protocol_fee_units,
            self.slashing_units,
            self.latency_rebate_units,
        );
        if self.settlement_root != settlement_root {
            return Err("proof marketplace settlement root mismatch".to_string());
        }
        let expected = proof_marketplace_settlement_id(
            self.settlement_kind.as_str(),
            &self.job_id,
            &self.worker_id,
            &self.settlement_root,
            self.settled_at_height,
        );
        if self.settlement_id != expected {
            return Err("proof marketplace settlement id mismatch".to_string());
        }
        Ok(proof_marketplace_settlement_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastFinalityCapacitySnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub worker_capacity_root: String,
    pub job_queue_root: String,
    pub lease_root: String,
    pub receipt_root: String,
    pub available_compute_units: u64,
    pub reserved_compute_units: u64,
    pub target_finality_blocks: u64,
    pub p50_latency_blocks: u64,
    pub p95_latency_blocks: u64,
    pub backlog_jobs: u64,
    pub saturation_bps: u64,
    pub finality_bucket: String,
    pub status: String,
}

impl FastFinalityCapacitySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        worker_capacity_root: impl Into<String>,
        job_queue_root: impl Into<String>,
        lease_root: impl Into<String>,
        receipt_root: impl Into<String>,
        available_compute_units: u64,
        reserved_compute_units: u64,
        target_finality_blocks: u64,
        p50_latency_blocks: u64,
        p95_latency_blocks: u64,
        backlog_jobs: u64,
    ) -> ProofCompressionResult<Self> {
        let worker_capacity_root = worker_capacity_root.into();
        let job_queue_root = job_queue_root.into();
        let lease_root = lease_root.into();
        let receipt_root = receipt_root.into();
        let total_compute = available_compute_units.saturating_add(reserved_compute_units);
        let saturation_bps = ratio_bps(reserved_compute_units, total_compute);
        let finality_bucket =
            finality_latency_bucket(target_finality_blocks, p95_latency_blocks, saturation_bps);
        let snapshot_id = fast_finality_capacity_snapshot_id(
            height,
            &worker_capacity_root,
            &job_queue_root,
            &lease_root,
            &receipt_root,
        );
        let snapshot = Self {
            snapshot_id,
            height,
            worker_capacity_root,
            job_queue_root,
            lease_root,
            receipt_root,
            available_compute_units,
            reserved_compute_units,
            target_finality_blocks,
            p50_latency_blocks,
            p95_latency_blocks,
            backlog_jobs,
            saturation_bps,
            finality_bucket,
            status: PROOF_COMPRESSION_STATUS_ACTIVE.to_string(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_finality_capacity_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "worker_capacity_root": self.worker_capacity_root,
            "job_queue_root": self.job_queue_root,
            "lease_root": self.lease_root,
            "receipt_root": self.receipt_root,
            "available_compute_units": self.available_compute_units,
            "reserved_compute_units": self.reserved_compute_units,
            "target_finality_blocks": self.target_finality_blocks,
            "p50_latency_blocks": self.p50_latency_blocks,
            "p95_latency_blocks": self.p95_latency_blocks,
            "backlog_jobs": self.backlog_jobs,
            "saturation_bps": self.saturation_bps,
            "finality_bucket": self.finality_bucket,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        ensure_hash_like(&self.snapshot_id, "fast finality snapshot id")?;
        ensure_hash_like(
            &self.worker_capacity_root,
            "fast finality worker capacity root",
        )?;
        ensure_hash_like(&self.job_queue_root, "fast finality job queue root")?;
        ensure_hash_like(&self.lease_root, "fast finality lease root")?;
        ensure_hash_like(&self.receipt_root, "fast finality receipt root")?;
        ensure_positive(
            self.target_finality_blocks,
            "fast finality target finality blocks",
        )?;
        if self.p95_latency_blocks < self.p50_latency_blocks {
            return Err("fast finality p95 latency cannot be below p50".to_string());
        }
        if self.saturation_bps > PROOF_COMPRESSION_MAX_BPS {
            return Err("fast finality saturation bps out of bounds".to_string());
        }
        ensure_non_empty(&self.finality_bucket, "fast finality bucket")?;
        ensure_status(
            &self.status,
            &[
                PROOF_COMPRESSION_STATUS_ACTIVE,
                PROOF_COMPRESSION_STATUS_EXPIRED,
                PROOF_COMPRESSION_STATUS_CHALLENGED,
            ],
            "fast finality snapshot status",
        )?;
        let total_compute = self
            .available_compute_units
            .saturating_add(self.reserved_compute_units);
        let expected_saturation = ratio_bps(self.reserved_compute_units, total_compute);
        if self.saturation_bps != expected_saturation {
            return Err("fast finality saturation mismatch".to_string());
        }
        let expected_bucket = finality_latency_bucket(
            self.target_finality_blocks,
            self.p95_latency_blocks,
            self.saturation_bps,
        );
        if self.finality_bucket != expected_bucket {
            return Err("fast finality bucket mismatch".to_string());
        }
        let expected = fast_finality_capacity_snapshot_id(
            self.height,
            &self.worker_capacity_root,
            &self.job_queue_root,
            &self.lease_root,
            &self.receipt_root,
        );
        if self.snapshot_id != expected {
            return Err("fast finality snapshot id mismatch".to_string());
        }
        Ok(fast_finality_capacity_snapshot_root(self))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCompressionState {
    pub height: u64,
    pub active_manifest_ids: BTreeMap<String, String>,
    pub active_committee_id: Option<String>,
    pub manifests: BTreeMap<String, RecursiveBatchManifest>,
    pub privacy_metadata: BTreeMap<String, PrivacySafeProofMetadata>,
    pub recursive_batches: BTreeMap<String, RecursiveProofBatch>,
    pub compression_jobs: BTreeMap<String, CompressionJob>,
    pub worker_leases: BTreeMap<String, WorkerLease>,
    pub proof_cache: BTreeMap<String, ProofCacheRecord>,
    pub verification_receipts: BTreeMap<String, VerificationReceipt>,
    pub verifier_members: BTreeMap<String, PqVerifierMember>,
    pub verifier_committees: BTreeMap<String, PqVerifierCommittee>,
    pub scheduler_attestations: BTreeMap<String, SchedulerAttestation>,
    pub fallback_challenges: BTreeMap<String, FallbackChallengeRecord>,
    pub fraud_escalations: BTreeMap<String, FraudProofEscalation>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub marketplace_settlements: BTreeMap<String, ProofMarketplaceSettlement>,
    pub capacity_snapshots: BTreeMap<String, FastFinalityCapacitySnapshot>,
}

impl ProofCompressionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> ProofCompressionResult<Self> {
        let mut state = Self::new();
        state.set_height(64);

        let manifests = vec![
            devnet_manifest(
                ProofCompressionFamily::Rollup,
                96,
                65_536,
                18_000,
                2,
                &json!({"scope": "rollup batch roots", "privacy": "roots_only"}),
            )?,
            devnet_manifest(
                ProofCompressionFamily::Bridge,
                48,
                49_152,
                22_000,
                2,
                &json!({"scope": "monero bridge finality", "privacy": "amount_buckets"}),
            )?,
            devnet_manifest(
                ProofCompressionFamily::PrivacyPool,
                128,
                73_728,
                28_000,
                3,
                &json!({"scope": "privacy pool nullifiers", "privacy": "bucket_roots_only"}),
            )?,
            devnet_manifest(
                ProofCompressionFamily::Defi,
                96,
                81_920,
                30_000,
                3,
                &json!({"scope": "sealed defi accounting", "privacy": "asset_buckets"}),
            )?,
            devnet_manifest(
                ProofCompressionFamily::Vm,
                112,
                98_304,
                32_000,
                3,
                &json!({"scope": "contract VM frames", "privacy": "caller_commitment_buckets"}),
            )?,
        ];
        for manifest in manifests {
            let manifest_id = manifest.manifest_id.clone();
            state.insert_manifest(manifest)?;
            state.publish_manifest(&manifest_id)?;
        }

        let members = vec![
            devnet_member("devnet-scheduler-a", PqVerifierRole::Scheduler, 35)?,
            devnet_member("devnet-verifier-b", PqVerifierRole::Verifier, 30)?,
            devnet_member("devnet-watchtower-c", PqVerifierRole::Watchtower, 25)?,
            devnet_member("devnet-challenger-d", PqVerifierRole::Challenger, 20)?,
            devnet_member(
                "devnet-sponsor-auditor-e",
                PqVerifierRole::SponsorAuditor,
                15,
            )?,
        ];
        for member in &members {
            state.insert_verifier_member(member.clone())?;
        }
        let committee = PqVerifierCommittee::from_members(
            1,
            0,
            PqVerifierCommitteePolicy::WeightedThreshold,
            &members,
            75,
            PROOF_COMPRESSION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            0,
            0,
        )?;
        let committee_id = committee.committee_id.clone();
        state.insert_verifier_committee(committee)?;
        state.activate_committee(&committee_id)?;

        let metadata = [
            devnet_metadata(ProofCompressionFamily::Rollup, "rollup")?,
            devnet_metadata(ProofCompressionFamily::Bridge, "bridge")?,
            devnet_metadata(ProofCompressionFamily::PrivacyPool, "privacy-pool")?,
            devnet_metadata(ProofCompressionFamily::Defi, "defi")?,
            devnet_metadata(ProofCompressionFamily::Vm, "vm")?,
        ];
        for item in &metadata {
            state.insert_privacy_metadata(item.clone())?;
        }

        let sponsorship = LowFeeProofSponsorship::new(
            deterministic_commitment("devnet-proof-sponsor"),
            LowFeeSponsorshipLane::PublicGood,
            "asset:wxmr",
            180_000,
            12_000,
            vec![
                ProofCompressionFamily::Rollup,
                ProofCompressionFamily::Bridge,
                ProofCompressionFamily::PrivacyPool,
                ProofCompressionFamily::Defi,
                ProofCompressionFamily::Vm,
            ],
            deterministic_root("devnet-sponsored-beneficiary-bucket"),
            0,
            PROOF_COMPRESSION_DEFAULT_LOW_FEE_EPOCH_BLOCKS - 1,
            1,
        )?;
        let sponsorship_id = state.insert_low_fee_sponsorship(sponsorship)?;

        let mut jobs = Vec::new();
        for (index, family) in [
            ProofCompressionFamily::Rollup,
            ProofCompressionFamily::Bridge,
            ProofCompressionFamily::PrivacyPool,
            ProofCompressionFamily::Defi,
            ProofCompressionFamily::Vm,
        ]
        .into_iter()
        .enumerate()
        {
            let manifest_id = state
                .active_manifest_ids
                .get(family.as_str())
                .ok_or_else(|| "devnet active manifest missing".to_string())?
                .clone();
            let metadata_item = metadata
                .iter()
                .find(|item| item.family == family)
                .ok_or_else(|| "devnet metadata missing".to_string())?;
            let proof_id = deterministic_root(&format!("devnet-{}-child-proof", family.as_str()));
            let batch = RecursiveProofBatch::new(
                index as u64,
                family,
                if index == 0 {
                    "genesis".to_string()
                } else {
                    jobs.last()
                        .map(|job: &CompressionJob| job.batch_id.clone())
                        .unwrap_or_else(|| "genesis".to_string())
                },
                manifest_id.clone(),
                vec![proof_id.clone()],
                vec![metadata_item.public_input_root.clone()],
                &[metadata_item.clone()],
                PROOF_COMPRESSION_DEFAULT_RECURSION_DEPTH,
                40 + (index as u64 * 4),
                43 + (index as u64 * 4),
                50 + index as u64,
            )?
            .seal(56 + index as u64)?;
            let batch_id = state.insert_recursive_batch(batch.clone())?;
            let job = CompressionJob::new(
                family,
                if family == ProofCompressionFamily::Bridge {
                    CompressionJobPriority::BridgeExit
                } else if family == ProofCompressionFamily::Rollup {
                    CompressionJobPriority::FastFinality
                } else {
                    CompressionJobPriority::LowFee
                },
                &manifest_id,
                &batch_id,
                deterministic_root(&format!("devnet-{}-source-proof", family.as_str())),
                &metadata_item.public_input_root,
                420_000 + (index as u64 * 24_000),
                72_000,
                7_500 + (index as u64 * 500),
                "asset:wxmr",
                Some(&sponsorship_id),
                Some(&format!("devnet-market-order-{index}")),
                52 + index as u64,
                60 + index as u64,
            )?;
            jobs.push(job);
        }

        let worker_manifest_ids = state.manifests.keys().cloned().collect::<Vec<_>>();
        for (index, job) in jobs.into_iter().enumerate() {
            let lease = WorkerLease::new(
                &job.job_id,
                format!("devnet-compressor-{}", index + 1),
                if index % 2 == 0 {
                    CompressionWorkerClass::Gpu
                } else {
                    CompressionWorkerClass::Cpu
                },
                deterministic_root(&format!("devnet-worker-capacity-{index}")),
                deterministic_root(&format!("devnet-worker-pq-key-{index}")),
                worker_manifest_ids.clone(),
                4,
                90_000 + (index as u64 * 7_500),
                2 + (index as u64 % 2),
                53 + index as u64,
                53 + index as u64 + PROOF_COMPRESSION_DEFAULT_LEASE_BLOCKS,
            )?;
            let lease_id = lease.lease_id.clone();
            let mut assigned = job.assign(lease.worker_id.clone(), &lease_id)?;
            let cache = ProofCacheRecord::new(
                &assigned,
                format!("devnet-compressed-proof-{index}"),
                deterministic_root(&format!("devnet-compressed-proof-commitment-{index}")),
                deterministic_root(&format!("devnet-verifier-key-{}", assigned.family.as_str())),
                58_000 + (index as u64 * 2_000),
                assigned.family.default_queue_bucket(),
                57 + index as u64,
                PROOF_COMPRESSION_DEFAULT_CACHE_TTL_BLOCKS,
            )?;
            assigned = assigned.mark_completed(&cache.cache_id, 57 + index as u64)?;
            state.insert_compression_job(assigned)?;
            state.insert_worker_lease(lease)?;
            state.insert_proof_cache_record(cache)?;
        }

        let capacity_snapshot = FastFinalityCapacitySnapshot::new(
            state.height,
            deterministic_root("devnet-total-worker-capacity"),
            state.compression_job_root(),
            state.worker_lease_root(),
            state.verification_receipt_root(),
            480_000,
            215_000,
            PROOF_COMPRESSION_DEFAULT_TARGET_FINALITY_BLOCKS,
            1,
            2,
            state.active_job_count(),
        )?;
        let capacity_root = capacity_snapshot.state_root();
        state.insert_capacity_snapshot(capacity_snapshot)?;

        let attestation = SchedulerAttestation::new(
            &committee_id,
            deterministic_commitment("devnet-scheduler"),
            state.compression_jobs.keys().cloned().collect::<Vec<_>>(),
            state.worker_leases.keys().cloned().collect::<Vec<_>>(),
            capacity_root,
            "depth_0_8",
            2,
            66,
            deterministic_root("devnet-scheduler-attestation-signature"),
            64,
        )?;
        let attestation_root = scheduler_attestation_root(&attestation);
        state.insert_scheduler_attestation(attestation)?;

        for cache in state.proof_cache.values().cloned().collect::<Vec<_>>() {
            let receipt = VerificationReceipt::new(
                &cache,
                &committee_id,
                &attestation_root,
                VerificationOutcome::Accepted,
                18_000,
                650,
                65,
                64,
            )?;
            state.insert_verification_receipt(receipt)?;
        }

        let devnet_challenge_target_id = state
            .compression_jobs
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet job missing".to_string())?;
        let devnet_fallback_manifest_id = state
            .active_manifest_ids
            .get(ProofCompressionFamily::Vm.as_str())
            .cloned()
            .ok_or_else(|| "devnet fallback manifest missing".to_string())?;

        let challenge = FallbackChallengeRecord::new(
            FallbackChallengeKind::Timeout,
            "compression_job",
            devnet_challenge_target_id.clone(),
            deterministic_commitment("devnet-watchtower"),
            deterministic_root("devnet-timeout-evidence"),
            devnet_fallback_manifest_id,
            1_000,
            61,
            PROOF_COMPRESSION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        )?
        .resolve(FallbackChallengeOutcome::ProofAccepted, 63)?;
        let challenge_id = state.insert_fallback_challenge(challenge)?;

        let escalation = FraudProofEscalation::new(
            &challenge_id,
            "compression_job",
            devnet_challenge_target_id,
            deterministic_root("devnet-fraud-pre-state"),
            deterministic_root("devnet-fraud-claimed-post-state"),
            deterministic_root("devnet-fraud-counterexample"),
            deterministic_root("devnet-fraud-fallback-execution"),
            10,
            63,
        )?;
        state.insert_fraud_escalation(escalation)?;

        for (index, receipt) in state
            .verification_receipts
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .enumerate()
        {
            let job = state
                .compression_jobs
                .get(&receipt.job_id)
                .ok_or_else(|| "devnet settlement job missing".to_string())?;
            let settlement = ProofMarketplaceSettlement::new(
                MarketplaceSettlementKind::Sponsored,
                &job.job_id,
                &job.assigned_worker_id,
                &job.sponsorship_id,
                &receipt.cache_id,
                &receipt.receipt_id,
                &job.fee_asset_id,
                job.offered_fee_units,
                2_500,
                job.offered_fee_units.saturating_sub(350),
                250,
                0,
                if index == 0 { 100 } else { 0 },
                66 + index as u64,
            )?;
            state.insert_marketplace_settlement(settlement)?;
        }

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for manifest in self.manifests.values_mut() {
            if manifest.expires_at_height != 0
                && height >= manifest.expires_at_height
                && manifest.status == PROOF_COMPRESSION_STATUS_ACTIVE
            {
                manifest.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
        for lease in self.worker_leases.values_mut() {
            if height >= lease.expires_at_height && lease.status == PROOF_COMPRESSION_STATUS_ACTIVE
            {
                lease.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
        for job in self.compression_jobs.values_mut() {
            if height > job.deadline_height
                && matches!(
                    job.status.as_str(),
                    PROOF_COMPRESSION_STATUS_PENDING
                        | PROOF_COMPRESSION_STATUS_ASSIGNED
                        | PROOF_COMPRESSION_STATUS_RUNNING
                )
            {
                job.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
        for cache in self.proof_cache.values_mut() {
            if height >= cache.expires_at_height && cache.status == PROOF_COMPRESSION_STATUS_ACTIVE
            {
                cache.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
        for sponsorship in self.low_fee_sponsorships.values_mut() {
            if height > sponsorship.ends_at_height
                && sponsorship.status == PROOF_COMPRESSION_STATUS_ACTIVE
            {
                sponsorship.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
        for challenge in self.fallback_challenges.values_mut() {
            if height > challenge.deadline_height
                && challenge.status == PROOF_COMPRESSION_STATUS_CHALLENGED
            {
                challenge.status = PROOF_COMPRESSION_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn insert_manifest(
        &mut self,
        manifest: RecursiveBatchManifest,
    ) -> ProofCompressionResult<String> {
        manifest.validate()?;
        insert_unique_record(
            &mut self.manifests,
            manifest.manifest_id.clone(),
            manifest,
            "recursive batch manifest",
        )
    }

    pub fn publish_manifest(
        &mut self,
        manifest_id: &str,
    ) -> ProofCompressionResult<RecursiveBatchManifest> {
        let manifest = self
            .manifests
            .get(manifest_id)
            .ok_or_else(|| "unknown proof compression manifest".to_string())?
            .clone();
        if !manifest.is_active_at(self.height) {
            return Err("proof compression manifest is not active at height".to_string());
        }
        self.active_manifest_ids.insert(
            manifest.family.as_str().to_string(),
            manifest_id.to_string(),
        );
        Ok(manifest)
    }

    pub fn insert_privacy_metadata(
        &mut self,
        metadata: PrivacySafeProofMetadata,
    ) -> ProofCompressionResult<String> {
        metadata.validate()?;
        insert_unique_record(
            &mut self.privacy_metadata,
            metadata.metadata_id.clone(),
            metadata,
            "privacy-safe proof metadata",
        )
    }

    pub fn insert_recursive_batch(
        &mut self,
        batch: RecursiveProofBatch,
    ) -> ProofCompressionResult<String> {
        batch.validate()?;
        if !self.manifests.contains_key(&batch.manifest_id) {
            return Err("recursive batch references unknown manifest".to_string());
        }
        for metadata_id in &batch.privacy_metadata_ids {
            if !self.privacy_metadata.contains_key(metadata_id) {
                return Err("recursive batch references unknown privacy metadata".to_string());
            }
        }
        insert_unique_record(
            &mut self.recursive_batches,
            batch.batch_id.clone(),
            batch,
            "recursive proof batch",
        )
    }

    pub fn insert_compression_job(
        &mut self,
        job: CompressionJob,
    ) -> ProofCompressionResult<String> {
        job.validate()?;
        if !self.manifests.contains_key(&job.manifest_id) {
            return Err("compression job references unknown manifest".to_string());
        }
        if !self.recursive_batches.contains_key(&job.batch_id) {
            return Err("compression job references unknown batch".to_string());
        }
        if !job.sponsorship_id.is_empty()
            && !self.low_fee_sponsorships.contains_key(&job.sponsorship_id)
        {
            return Err("compression job references unknown sponsorship".to_string());
        }
        insert_unique_record(
            &mut self.compression_jobs,
            job.job_id.clone(),
            job,
            "compression job",
        )
    }

    pub fn insert_worker_lease(&mut self, lease: WorkerLease) -> ProofCompressionResult<String> {
        lease.validate()?;
        if !self.recursive_job_exists_or_pending(&lease.job_id) {
            return Err("worker lease references unknown compression job".to_string());
        }
        for manifest_id in &lease.supported_manifest_ids {
            if !self.manifests.contains_key(manifest_id) {
                return Err("worker lease references unknown supported manifest".to_string());
            }
        }
        insert_unique_record(
            &mut self.worker_leases,
            lease.lease_id.clone(),
            lease,
            "worker lease",
        )
    }

    pub fn insert_proof_cache_record(
        &mut self,
        cache: ProofCacheRecord,
    ) -> ProofCompressionResult<String> {
        cache.validate()?;
        if !self.compression_jobs.contains_key(&cache.job_id) {
            return Err("proof cache references unknown compression job".to_string());
        }
        if !self.recursive_batches.contains_key(&cache.batch_id) {
            return Err("proof cache references unknown recursive batch".to_string());
        }
        insert_unique_record(
            &mut self.proof_cache,
            cache.cache_id.clone(),
            cache,
            "proof cache record",
        )
    }

    pub fn insert_verification_receipt(
        &mut self,
        receipt: VerificationReceipt,
    ) -> ProofCompressionResult<String> {
        receipt.validate()?;
        if !self.proof_cache.contains_key(&receipt.cache_id) {
            return Err("verification receipt references unknown cache".to_string());
        }
        if !self.verifier_committees.contains_key(&receipt.committee_id) {
            return Err("verification receipt references unknown committee".to_string());
        }
        insert_unique_record(
            &mut self.verification_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "verification receipt",
        )
    }

    pub fn insert_verifier_member(
        &mut self,
        member: PqVerifierMember,
    ) -> ProofCompressionResult<String> {
        member.validate()?;
        insert_unique_record(
            &mut self.verifier_members,
            member.member_id.clone(),
            member,
            "PQ verifier member",
        )
    }

    pub fn insert_verifier_committee(
        &mut self,
        committee: PqVerifierCommittee,
    ) -> ProofCompressionResult<String> {
        committee.validate()?;
        for member_id in &committee.member_ids {
            if !self.verifier_members.contains_key(member_id) {
                return Err("PQ verifier committee references unknown member".to_string());
            }
        }
        insert_unique_record(
            &mut self.verifier_committees,
            committee.committee_id.clone(),
            committee,
            "PQ verifier committee",
        )
    }

    pub fn activate_committee(
        &mut self,
        committee_id: &str,
    ) -> ProofCompressionResult<PqVerifierCommittee> {
        let committee = self
            .verifier_committees
            .get(committee_id)
            .ok_or_else(|| "unknown PQ verifier committee".to_string())?
            .clone();
        if !committee.is_active_at(self.height) {
            return Err("PQ verifier committee is not active at height".to_string());
        }
        self.active_committee_id = Some(committee_id.to_string());
        Ok(committee)
    }

    pub fn insert_scheduler_attestation(
        &mut self,
        attestation: SchedulerAttestation,
    ) -> ProofCompressionResult<String> {
        attestation.validate()?;
        if !self
            .verifier_committees
            .contains_key(&attestation.committee_id)
        {
            return Err("scheduler attestation references unknown committee".to_string());
        }
        for job_id in &attestation.job_ids {
            if !self.compression_jobs.contains_key(job_id) {
                return Err("scheduler attestation references unknown job".to_string());
            }
        }
        for lease_id in &attestation.lease_ids {
            if !self.worker_leases.contains_key(lease_id) {
                return Err("scheduler attestation references unknown lease".to_string());
            }
        }
        insert_unique_record(
            &mut self.scheduler_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "scheduler attestation",
        )
    }

    pub fn insert_fallback_challenge(
        &mut self,
        challenge: FallbackChallengeRecord,
    ) -> ProofCompressionResult<String> {
        challenge.validate()?;
        if !self.manifests.contains_key(&challenge.fallback_manifest_id) {
            return Err("fallback challenge references unknown fallback manifest".to_string());
        }
        insert_unique_record(
            &mut self.fallback_challenges,
            challenge.challenge_id.clone(),
            challenge,
            "fallback challenge",
        )
    }

    pub fn insert_fraud_escalation(
        &mut self,
        escalation: FraudProofEscalation,
    ) -> ProofCompressionResult<String> {
        escalation.validate()?;
        if !self
            .fallback_challenges
            .contains_key(&escalation.challenge_id)
        {
            return Err("fraud proof escalation references unknown challenge".to_string());
        }
        insert_unique_record(
            &mut self.fraud_escalations,
            escalation.escalation_id.clone(),
            escalation,
            "fraud proof escalation",
        )
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> ProofCompressionResult<String> {
        sponsorship.validate()?;
        insert_unique_record(
            &mut self.low_fee_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "low-fee proof sponsorship",
        )
    }

    pub fn insert_marketplace_settlement(
        &mut self,
        settlement: ProofMarketplaceSettlement,
    ) -> ProofCompressionResult<String> {
        settlement.validate()?;
        if !self.compression_jobs.contains_key(&settlement.job_id) {
            return Err("proof settlement references unknown job".to_string());
        }
        if !self.proof_cache.contains_key(&settlement.cache_id) {
            return Err("proof settlement references unknown cache".to_string());
        }
        if !self
            .verification_receipts
            .contains_key(&settlement.receipt_id)
        {
            return Err("proof settlement references unknown receipt".to_string());
        }
        if !settlement.sponsorship_id.is_empty()
            && !self
                .low_fee_sponsorships
                .contains_key(&settlement.sponsorship_id)
        {
            return Err("proof settlement references unknown sponsorship".to_string());
        }
        insert_unique_record(
            &mut self.marketplace_settlements,
            settlement.settlement_id.clone(),
            settlement,
            "proof marketplace settlement",
        )
    }

    pub fn insert_capacity_snapshot(
        &mut self,
        snapshot: FastFinalityCapacitySnapshot,
    ) -> ProofCompressionResult<String> {
        snapshot.validate()?;
        insert_unique_record(
            &mut self.capacity_snapshots,
            snapshot.snapshot_id.clone(),
            snapshot,
            "fast finality capacity snapshot",
        )
    }

    pub fn recursive_job_exists_or_pending(&self, job_id: &str) -> bool {
        self.compression_jobs.contains_key(job_id)
            || self
                .compression_jobs
                .values()
                .any(|job| job.job_id == job_id)
    }

    pub fn manifest_root(&self) -> String {
        recursive_batch_manifest_set_root(&self.manifests.values().cloned().collect::<Vec<_>>())
    }

    pub fn privacy_metadata_root(&self) -> String {
        privacy_safe_metadata_set_root(&self.privacy_metadata.values().cloned().collect::<Vec<_>>())
    }

    pub fn recursive_batch_root(&self) -> String {
        recursive_proof_batch_set_root(
            &self.recursive_batches.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn compression_job_root(&self) -> String {
        compression_job_set_root(&self.compression_jobs.values().cloned().collect::<Vec<_>>())
    }

    pub fn worker_lease_root(&self) -> String {
        worker_lease_set_root(&self.worker_leases.values().cloned().collect::<Vec<_>>())
    }

    pub fn proof_cache_root(&self) -> String {
        proof_cache_record_set_root(&self.proof_cache.values().cloned().collect::<Vec<_>>())
    }

    pub fn verification_receipt_root(&self) -> String {
        verification_receipt_set_root(
            &self
                .verification_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn verifier_member_root(&self) -> String {
        pq_verifier_member_set_root(&self.verifier_members.values().cloned().collect::<Vec<_>>())
    }

    pub fn verifier_committee_root(&self) -> String {
        pq_verifier_committee_set_root(
            &self
                .verifier_committees
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn scheduler_attestation_root(&self) -> String {
        scheduler_attestation_set_root(
            &self
                .scheduler_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn fallback_challenge_root(&self) -> String {
        fallback_challenge_set_root(
            &self
                .fallback_challenges
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn fraud_escalation_root(&self) -> String {
        fraud_proof_escalation_set_root(
            &self.fraud_escalations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        low_fee_proof_sponsorship_set_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn marketplace_settlement_root(&self) -> String {
        proof_marketplace_settlement_set_root(
            &self
                .marketplace_settlements
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn capacity_snapshot_root(&self) -> String {
        fast_finality_capacity_snapshot_set_root(
            &self
                .capacity_snapshots
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn active_job_count(&self) -> u64 {
        self.compression_jobs
            .values()
            .filter(|job| job.is_open_at(self.height))
            .count() as u64
    }

    pub fn verified_receipt_count(&self) -> u64 {
        self.verification_receipts
            .values()
            .filter(|receipt| receipt.status == PROOF_COMPRESSION_STATUS_VERIFIED)
            .count() as u64
    }

    pub fn open_challenge_count(&self) -> u64 {
        self.fallback_challenges
            .values()
            .filter(|challenge| challenge.is_open_at(self.height))
            .count() as u64
    }

    pub fn total_cached_bytes_saved(&self) -> u64 {
        self.proof_cache.values().fold(0_u64, |total, cache| {
            total.saturating_add(cache.bytes_saved())
        })
    }

    pub fn total_sponsor_available_units(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .fold(0_u64, |total, sponsorship| {
                total.saturating_add(sponsorship.available_units())
            })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "proof_compression_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_COMPRESSION_PROTOCOL_VERSION,
            "schema_version": PROOF_COMPRESSION_SCHEMA_VERSION,
            "height": self.height,
            "active_manifest_ids": self.active_manifest_ids,
            "active_committee_id": self.active_committee_id,
            "manifest_root": self.manifest_root(),
            "privacy_metadata_root": self.privacy_metadata_root(),
            "recursive_batch_root": self.recursive_batch_root(),
            "compression_job_root": self.compression_job_root(),
            "worker_lease_root": self.worker_lease_root(),
            "proof_cache_root": self.proof_cache_root(),
            "verification_receipt_root": self.verification_receipt_root(),
            "verifier_member_root": self.verifier_member_root(),
            "verifier_committee_root": self.verifier_committee_root(),
            "scheduler_attestation_root": self.scheduler_attestation_root(),
            "fallback_challenge_root": self.fallback_challenge_root(),
            "fraud_escalation_root": self.fraud_escalation_root(),
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root(),
            "marketplace_settlement_root": self.marketplace_settlement_root(),
            "capacity_snapshot_root": self.capacity_snapshot_root(),
            "manifest_count": self.manifests.len() as u64,
            "privacy_metadata_count": self.privacy_metadata.len() as u64,
            "recursive_batch_count": self.recursive_batches.len() as u64,
            "compression_job_count": self.compression_jobs.len() as u64,
            "active_job_count": self.active_job_count(),
            "worker_lease_count": self.worker_leases.len() as u64,
            "proof_cache_count": self.proof_cache.len() as u64,
            "verification_receipt_count": self.verification_receipts.len() as u64,
            "verified_receipt_count": self.verified_receipt_count(),
            "verifier_member_count": self.verifier_members.len() as u64,
            "verifier_committee_count": self.verifier_committees.len() as u64,
            "scheduler_attestation_count": self.scheduler_attestations.len() as u64,
            "fallback_challenge_count": self.fallback_challenges.len() as u64,
            "open_challenge_count": self.open_challenge_count(),
            "fraud_escalation_count": self.fraud_escalations.len() as u64,
            "low_fee_sponsorship_count": self.low_fee_sponsorships.len() as u64,
            "marketplace_settlement_count": self.marketplace_settlements.len() as u64,
            "capacity_snapshot_count": self.capacity_snapshots.len() as u64,
            "total_cached_bytes_saved": self.total_cached_bytes_saved(),
            "total_sponsor_available_units": self.total_sponsor_available_units(),
        })
    }

    pub fn state_root(&self) -> String {
        proof_compression_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("proof compression state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ProofCompressionResult<String> {
        for manifest in self.manifests.values() {
            manifest.validate()?;
        }
        for (family, manifest_id) in &self.active_manifest_ids {
            let manifest = self
                .manifests
                .get(manifest_id)
                .ok_or_else(|| "active proof compression manifest is missing".to_string())?;
            if manifest.family.as_str() != family {
                return Err("active proof compression manifest family mismatch".to_string());
            }
            if !manifest.is_active_at(self.height) {
                return Err("active proof compression manifest is not active".to_string());
            }
        }
        for metadata in self.privacy_metadata.values() {
            metadata.validate()?;
        }
        for batch in self.recursive_batches.values() {
            batch.validate()?;
            if !self.manifests.contains_key(&batch.manifest_id) {
                return Err("recursive batch references unknown manifest".to_string());
            }
            for metadata_id in &batch.privacy_metadata_ids {
                if !self.privacy_metadata.contains_key(metadata_id) {
                    return Err("recursive batch references unknown privacy metadata".to_string());
                }
            }
        }
        for member in self.verifier_members.values() {
            member.validate()?;
        }
        for committee in self.verifier_committees.values() {
            committee.validate()?;
            for member_id in &committee.member_ids {
                if !self.verifier_members.contains_key(member_id) {
                    return Err("PQ verifier committee references unknown member".to_string());
                }
            }
        }
        if let Some(active_committee_id) = &self.active_committee_id {
            let committee = self
                .verifier_committees
                .get(active_committee_id)
                .ok_or_else(|| "active proof compression committee is missing".to_string())?;
            if !committee.is_active_at(self.height) {
                return Err("active proof compression committee is not active".to_string());
            }
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
        }
        for job in self.compression_jobs.values() {
            job.validate()?;
            if !self.manifests.contains_key(&job.manifest_id) {
                return Err("compression job references unknown manifest".to_string());
            }
            if !self.recursive_batches.contains_key(&job.batch_id) {
                return Err("compression job references unknown recursive batch".to_string());
            }
            if !job.sponsorship_id.is_empty()
                && !self.low_fee_sponsorships.contains_key(&job.sponsorship_id)
            {
                return Err("compression job references unknown sponsorship".to_string());
            }
        }
        for lease in self.worker_leases.values() {
            lease.validate()?;
            if !self.compression_jobs.contains_key(&lease.job_id) {
                return Err("worker lease references unknown compression job".to_string());
            }
        }
        for cache in self.proof_cache.values() {
            cache.validate()?;
            if !self.compression_jobs.contains_key(&cache.job_id) {
                return Err("proof cache references unknown compression job".to_string());
            }
        }
        for receipt in self.verification_receipts.values() {
            receipt.validate()?;
            if !self.proof_cache.contains_key(&receipt.cache_id) {
                return Err("verification receipt references unknown cache".to_string());
            }
            if !self.verifier_committees.contains_key(&receipt.committee_id) {
                return Err("verification receipt references unknown committee".to_string());
            }
        }
        for attestation in self.scheduler_attestations.values() {
            attestation.validate()?;
        }
        for challenge in self.fallback_challenges.values() {
            challenge.validate()?;
        }
        for escalation in self.fraud_escalations.values() {
            escalation.validate()?;
            if !self
                .fallback_challenges
                .contains_key(&escalation.challenge_id)
            {
                return Err("fraud proof escalation references unknown challenge".to_string());
            }
        }
        for settlement in self.marketplace_settlements.values() {
            settlement.validate()?;
        }
        for snapshot in self.capacity_snapshots.values() {
            snapshot.validate()?;
        }
        Ok(self.state_root())
    }
}

impl FastFinalityCapacitySnapshot {
    pub fn state_root(&self) -> String {
        fast_finality_capacity_snapshot_root(self)
    }
}

pub fn proof_compression_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROOF_COMPRESSION_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn proof_compression_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROOF_COMPRESSION_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn proof_compression_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    let records = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn deterministic_root(label: &str) -> String {
    domain_hash(
        "PROOF-COMPRESSION-DETERMINISTIC-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_commitment(label: &str) -> String {
    domain_hash(
        "PROOF-COMPRESSION-DETERMINISTIC-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn recursive_manifest_public_input_schema_root(
    family: &str,
    manifest_version: u64,
    max_public_inputs: u64,
    verifier_key_root: &str,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-MANIFEST-PUBLIC-INPUT-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Int(manifest_version as i128),
            HashPart::Int(max_public_inputs as i128),
            HashPart::Str(verifier_key_root),
        ],
        32,
    )
}

pub fn privacy_safe_metadata_id(
    family: &str,
    public_input_root: &str,
    state_bucket_root: &str,
    fee_bucket: &str,
    amount_bucket: &str,
    latency_bucket: &str,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-PRIVACY-METADATA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(public_input_root),
            HashPart::Str(state_bucket_root),
            HashPart::Str(fee_bucket),
            HashPart::Str(amount_bucket),
            HashPart::Str(latency_bucket),
        ],
        32,
    )
}

pub fn privacy_safe_metadata_root(metadata: &PrivacySafeProofMetadata) -> String {
    domain_hash(
        "PROOF-COMPRESSION-PRIVACY-METADATA",
        &[HashPart::Json(&metadata.public_record())],
        32,
    )
}

pub fn privacy_safe_metadata_set_root(metadata: &[PrivacySafeProofMetadata]) -> String {
    let mut records = metadata
        .iter()
        .map(|metadata| (metadata.metadata_id.clone(), metadata.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-PRIVACY-METADATA",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn recursive_batch_manifest_id(
    family: &str,
    manifest_version: u64,
    proof_system: &str,
    verifier_key_root: &str,
    public_input_schema_root: &str,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-RECURSIVE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Int(manifest_version as i128),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_root),
            HashPart::Str(public_input_schema_root),
        ],
        32,
    )
}

pub fn recursive_batch_manifest_root(manifest: &RecursiveBatchManifest) -> String {
    domain_hash(
        "PROOF-COMPRESSION-RECURSIVE-MANIFEST",
        &[HashPart::Json(&manifest.public_record())],
        32,
    )
}

pub fn recursive_batch_manifest_set_root(manifests: &[RecursiveBatchManifest]) -> String {
    let mut records = manifests
        .iter()
        .map(|manifest| (manifest.manifest_id.clone(), manifest.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-RECURSIVE-MANIFEST",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn recursive_accumulator_root(
    child_proof_root: &str,
    public_input_root: &str,
    privacy_metadata_root: &str,
    recursion_depth: u64,
    child_count: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-RECURSIVE-ACCUMULATOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(child_proof_root),
            HashPart::Str(public_input_root),
            HashPart::Str(privacy_metadata_root),
            HashPart::Int(recursion_depth as i128),
            HashPart::Int(child_count as i128),
        ],
        32,
    )
}

pub fn recursive_proof_batch_id(
    batch_number: u64,
    family: &str,
    parent_batch_id: &str,
    manifest_id: &str,
    public_input_root: &str,
    accumulator_root: &str,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-RECURSIVE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(batch_number as i128),
            HashPart::Str(family),
            HashPart::Str(parent_batch_id),
            HashPart::Str(manifest_id),
            HashPart::Str(public_input_root),
            HashPart::Str(accumulator_root),
        ],
        32,
    )
}

pub fn recursive_proof_batch_root(batch: &RecursiveProofBatch) -> String {
    domain_hash(
        "PROOF-COMPRESSION-RECURSIVE-BATCH",
        &[HashPart::Json(&batch.public_record())],
        32,
    )
}

pub fn recursive_proof_batch_set_root(batches: &[RecursiveProofBatch]) -> String {
    let mut records = batches
        .iter()
        .map(|batch| (batch.batch_id.clone(), batch.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-RECURSIVE-BATCH",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn compression_job_id(
    family: &str,
    manifest_id: &str,
    batch_id: &str,
    source_proof_root: &str,
    source_public_input_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(manifest_id),
            HashPart::Str(batch_id),
            HashPart::Str(source_proof_root),
            HashPart::Str(source_public_input_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn compression_job_root(job: &CompressionJob) -> String {
    domain_hash(
        "PROOF-COMPRESSION-JOB",
        &[HashPart::Json(&job.public_record())],
        32,
    )
}

pub fn compression_job_set_root(jobs: &[CompressionJob]) -> String {
    let mut records = jobs
        .iter()
        .map(|job| (job.job_id.clone(), job.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-JOB",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn worker_lease_id(
    job_id: &str,
    worker_id: &str,
    worker_class: &str,
    capacity_root: &str,
    leased_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-WORKER-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(worker_id),
            HashPart::Str(worker_class),
            HashPart::Str(capacity_root),
            HashPart::Int(leased_at_height as i128),
        ],
        32,
    )
}

pub fn worker_lease_root(lease: &WorkerLease) -> String {
    domain_hash(
        "PROOF-COMPRESSION-WORKER-LEASE",
        &[HashPart::Json(&lease.public_record())],
        32,
    )
}

pub fn worker_lease_set_root(leases: &[WorkerLease]) -> String {
    let mut records = leases
        .iter()
        .map(|lease| (lease.lease_id.clone(), lease.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-WORKER-LEASE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_cache_record_id(
    job_id: &str,
    batch_id: &str,
    compressed_proof_id: &str,
    compressed_proof_commitment: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-CACHE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(batch_id),
            HashPart::Str(compressed_proof_id),
            HashPart::Str(compressed_proof_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn proof_cache_record_root(cache: &ProofCacheRecord) -> String {
    domain_hash(
        "PROOF-COMPRESSION-CACHE",
        &[HashPart::Json(&cache.public_record())],
        32,
    )
}

pub fn proof_cache_record_set_root(caches: &[ProofCacheRecord]) -> String {
    let mut records = caches
        .iter()
        .map(|cache| (cache.cache_id.clone(), cache.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-CACHE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn verification_receipt_id(
    cache_id: &str,
    job_id: &str,
    committee_id: &str,
    outcome: &str,
    verified_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-VERIFICATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(cache_id),
            HashPart::Str(job_id),
            HashPart::Str(committee_id),
            HashPart::Str(outcome),
            HashPart::Int(verified_at_height as i128),
        ],
        32,
    )
}

pub fn verification_receipt_root(receipt: &VerificationReceipt) -> String {
    domain_hash(
        "PROOF-COMPRESSION-VERIFICATION-RECEIPT",
        &[HashPart::Json(&receipt.public_record())],
        32,
    )
}

pub fn verification_receipt_set_root(receipts: &[VerificationReceipt]) -> String {
    let mut records = receipts
        .iter()
        .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-VERIFICATION-RECEIPT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_verifier_member_id(
    operator_id: &str,
    role: &str,
    pq_public_key_root: &str,
    recovery_public_key_root: &str,
    joined_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-PQ-VERIFIER-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(role),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(recovery_public_key_root),
            HashPart::Int(joined_at_height as i128),
        ],
        32,
    )
}

pub fn pq_verifier_member_root(member: &PqVerifierMember) -> String {
    domain_hash(
        "PROOF-COMPRESSION-PQ-VERIFIER-MEMBER",
        &[HashPart::Json(&member.public_record())],
        32,
    )
}

pub fn pq_verifier_member_set_root(members: &[PqVerifierMember]) -> String {
    let mut records = members
        .iter()
        .map(|member| (member.member_id.clone(), member.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-PQ-VERIFIER-MEMBER",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_verifier_committee_id(
    committee_version: u64,
    epoch: u64,
    policy: &str,
    member_root: &str,
    threshold_weight: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-PQ-VERIFIER-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(committee_version as i128),
            HashPart::Int(epoch as i128),
            HashPart::Str(policy),
            HashPart::Str(member_root),
            HashPart::Int(threshold_weight as i128),
        ],
        32,
    )
}

pub fn pq_verifier_committee_root(committee: &PqVerifierCommittee) -> String {
    domain_hash(
        "PROOF-COMPRESSION-PQ-VERIFIER-COMMITTEE",
        &[HashPart::Json(&committee.public_record())],
        32,
    )
}

pub fn pq_verifier_committee_set_root(committees: &[PqVerifierCommittee]) -> String {
    let mut records = committees
        .iter()
        .map(|committee| (committee.committee_id.clone(), committee.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-PQ-VERIFIER-COMMITTEE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn scheduler_attestation_id(
    committee_id: &str,
    scheduler_commitment: &str,
    job_root: &str,
    lease_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-SCHEDULER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(scheduler_commitment),
            HashPart::Str(job_root),
            HashPart::Str(lease_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn scheduler_attestation_root(attestation: &SchedulerAttestation) -> String {
    domain_hash(
        "PROOF-COMPRESSION-SCHEDULER-ATTESTATION",
        &[HashPart::Json(&attestation.public_record())],
        32,
    )
}

pub fn scheduler_attestation_set_root(attestations: &[SchedulerAttestation]) -> String {
    let mut records = attestations
        .iter()
        .map(|attestation| {
            (
                attestation.attestation_id.clone(),
                attestation.public_record(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-SCHEDULER-ATTESTATION",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn fallback_challenge_id(
    challenge_kind: &str,
    target_kind: &str,
    target_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FALLBACK-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn fallback_challenge_root(challenge: &FallbackChallengeRecord) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FALLBACK-CHALLENGE",
        &[HashPart::Json(&challenge.public_record())],
        32,
    )
}

pub fn fallback_challenge_set_root(challenges: &[FallbackChallengeRecord]) -> String {
    let mut records = challenges
        .iter()
        .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-FALLBACK-CHALLENGE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn fraud_proof_escalation_payload_root(
    challenge_id: &str,
    target_id: &str,
    pre_state_root: &str,
    claimed_post_state_root: &str,
    counterexample_root: &str,
    fallback_execution_root: &str,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FRAUD-ESCALATION-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(target_id),
            HashPart::Str(pre_state_root),
            HashPart::Str(claimed_post_state_root),
            HashPart::Str(counterexample_root),
            HashPart::Str(fallback_execution_root),
        ],
        32,
    )
}

pub fn fraud_proof_escalation_id(
    challenge_id: &str,
    target_kind: &str,
    target_id: &str,
    escalation_root: &str,
    escalated_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FRAUD-ESCALATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(escalation_root),
            HashPart::Int(escalated_at_height as i128),
        ],
        32,
    )
}

pub fn fraud_proof_escalation_root(escalation: &FraudProofEscalation) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FRAUD-ESCALATION",
        &[HashPart::Json(&escalation.public_record())],
        32,
    )
}

pub fn fraud_proof_escalation_set_root(escalations: &[FraudProofEscalation]) -> String {
    let mut records = escalations
        .iter()
        .map(|escalation| (escalation.escalation_id.clone(), escalation.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-FRAUD-ESCALATION",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_proof_sponsorship_id(
    sponsor_commitment: &str,
    lane: &str,
    fee_asset_id: &str,
    eligible_family_root: &str,
    starts_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane),
            HashPart::Str(fee_asset_id),
            HashPart::Str(eligible_family_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn low_fee_proof_sponsorship_root(sponsorship: &LowFeeProofSponsorship) -> String {
    domain_hash(
        "PROOF-COMPRESSION-LOW-FEE-SPONSORSHIP",
        &[HashPart::Json(&sponsorship.public_record())],
        32,
    )
}

pub fn low_fee_proof_sponsorship_set_root(sponsorships: &[LowFeeProofSponsorship]) -> String {
    let mut records = sponsorships
        .iter()
        .map(|sponsorship| {
            (
                sponsorship.sponsorship_id.clone(),
                sponsorship.public_record(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-LOW-FEE-SPONSORSHIP",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn proof_marketplace_settlement_payload_root(
    settlement_kind: &str,
    job_id: &str,
    worker_id: &str,
    sponsorship_id: &str,
    cache_id: &str,
    receipt_id: &str,
    gross_fee_units: u64,
    sponsor_paid_units: u64,
    worker_paid_units: u64,
    protocol_fee_units: u64,
    slashing_units: u64,
    latency_rebate_units: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-MARKETPLACE-SETTLEMENT-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_kind),
            HashPart::Str(job_id),
            HashPart::Str(worker_id),
            HashPart::Str(sponsorship_id),
            HashPart::Str(cache_id),
            HashPart::Str(receipt_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsor_paid_units as i128),
            HashPart::Int(worker_paid_units as i128),
            HashPart::Int(protocol_fee_units as i128),
            HashPart::Int(slashing_units as i128),
            HashPart::Int(latency_rebate_units as i128),
        ],
        32,
    )
}

pub fn proof_marketplace_settlement_id(
    settlement_kind: &str,
    job_id: &str,
    worker_id: &str,
    settlement_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-MARKETPLACE-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_kind),
            HashPart::Str(job_id),
            HashPart::Str(worker_id),
            HashPart::Str(settlement_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn proof_marketplace_settlement_root(settlement: &ProofMarketplaceSettlement) -> String {
    domain_hash(
        "PROOF-COMPRESSION-MARKETPLACE-SETTLEMENT",
        &[HashPart::Json(&settlement.public_record())],
        32,
    )
}

pub fn proof_marketplace_settlement_set_root(settlements: &[ProofMarketplaceSettlement]) -> String {
    let mut records = settlements
        .iter()
        .map(|settlement| (settlement.settlement_id.clone(), settlement.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-MARKETPLACE-SETTLEMENT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn fast_finality_capacity_snapshot_id(
    height: u64,
    worker_capacity_root: &str,
    job_queue_root: &str,
    lease_root: &str,
    receipt_root: &str,
) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FAST-FINALITY-CAPACITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(worker_capacity_root),
            HashPart::Str(job_queue_root),
            HashPart::Str(lease_root),
            HashPart::Str(receipt_root),
        ],
        32,
    )
}

pub fn fast_finality_capacity_snapshot_root(snapshot: &FastFinalityCapacitySnapshot) -> String {
    domain_hash(
        "PROOF-COMPRESSION-FAST-FINALITY-CAPACITY",
        &[HashPart::Json(&snapshot.public_record())],
        32,
    )
}

pub fn fast_finality_capacity_snapshot_set_root(
    snapshots: &[FastFinalityCapacitySnapshot],
) -> String {
    let mut records = snapshots
        .iter()
        .map(|snapshot| (snapshot.snapshot_id.clone(), snapshot.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-COMPRESSION-FAST-FINALITY-CAPACITY",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_compression_state_root_from_record(record: &Value) -> String {
    domain_hash("PROOF-COMPRESSION-STATE", &[HashPart::Json(record)], 32)
}

pub fn proof_compression_state_root(state: &ProofCompressionState) -> String {
    state.state_root()
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(PROOF_COMPRESSION_MAX_BPS)
        .checked_div(denominator)
        .unwrap_or(0)
}

pub fn mul_bps_round_up(value: u64, bps: u64) -> u64 {
    if value == 0 || bps == 0 {
        return 0;
    }
    value
        .saturating_mul(bps)
        .saturating_add(PROOF_COMPRESSION_MAX_BPS - 1)
        / PROOF_COMPRESSION_MAX_BPS
}

pub fn finality_latency_bucket(
    target_finality_blocks: u64,
    p95_latency_blocks: u64,
    saturation_bps: u64,
) -> String {
    if p95_latency_blocks <= target_finality_blocks && saturation_bps <= 6_000 {
        "fast_green".to_string()
    } else if p95_latency_blocks <= target_finality_blocks.saturating_add(1)
        && saturation_bps <= 8_000
    {
        "fast_yellow".to_string()
    } else if saturation_bps >= 9_000 {
        "capacity_red".to_string()
    } else {
        "latency_red".to_string()
    }
}

fn devnet_manifest(
    family: ProofCompressionFamily,
    max_public_inputs: u64,
    target_compressed_bytes: u64,
    target_verify_micros: u64,
    max_latency_blocks: u64,
    privacy_metadata_policy: &Value,
) -> ProofCompressionResult<RecursiveBatchManifest> {
    RecursiveBatchManifest::new(
        family,
        1,
        deterministic_root(&format!("devnet-{}-verifier-key", family.as_str())),
        PROOF_COMPRESSION_DEFAULT_MAX_CHILD_PROOFS,
        max_public_inputs,
        target_compressed_bytes,
        target_verify_micros,
        max_latency_blocks,
        0,
        0,
        privacy_metadata_policy,
    )
}

fn devnet_metadata(
    family: ProofCompressionFamily,
    label: &str,
) -> ProofCompressionResult<PrivacySafeProofMetadata> {
    PrivacySafeProofMetadata::new(
        family,
        deterministic_root(&format!("devnet-{label}-public-input")),
        deterministic_root(&format!("devnet-{label}-state-bucket")),
        "fee_0_10",
        "amount_pow2_bucket",
        "latency_0_2",
        deterministic_root(&format!("devnet-{label}-participant-bucket")),
        deterministic_root(&format!("devnet-{label}-nullifier-bucket")),
        deterministic_root(&format!("devnet-{label}-asset-bucket")),
        deterministic_root(&format!("devnet-{label}-extra-bucket")),
    )
}

fn devnet_member(
    operator_id: &str,
    role: PqVerifierRole,
    weight: u64,
) -> ProofCompressionResult<PqVerifierMember> {
    PqVerifierMember::new(
        operator_id,
        role,
        weight,
        deterministic_root(&format!("{operator_id}-pq-key")),
        deterministic_root(&format!("{operator_id}-recovery-key")),
        deterministic_root(&format!("{operator_id}-stake")),
        deterministic_commitment(&format!("{operator_id}-endpoint")),
        0,
        0,
    )
}

fn normalize_label(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

fn ensure_non_empty(value: &str, label: &str) -> ProofCompressionResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ProofCompressionResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(value: &str, label: &str) -> ProofCompressionResult<()> {
    ensure_non_empty(value, label)?;
    if value.len() < 32 {
        return Err(format!("{label} is too short"));
    }
    if !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex encoded"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> ProofCompressionResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> ProofCompressionResult<()> {
    if values.is_empty() {
        return Err(format!("{label} list cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} must be unique"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> ProofCompressionResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}
