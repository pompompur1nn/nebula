use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-proof-carrying-upgrade-audit-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PUBLIC_RECORD_SCHEMA: &str =
    "nebula.private-l2.pq-confidential-contract-proof-carrying-upgrade-audit.public-record.v1";
pub const UPGRADE_MANIFEST_SCHEME: &str =
    "private-l2-pq-confidential-contract-upgrade-manifest-root-v1";
pub const BYTECODE_COMMITMENT_SCHEME: &str =
    "private-l2-pq-confidential-contract-upgrade-bytecode-commitment-v1";
pub const STORAGE_COMMITMENT_SCHEME: &str =
    "private-l2-pq-confidential-contract-upgrade-storage-commitment-v1";
pub const FORMAL_PROOF_ROOT_SCHEME: &str =
    "private-l2-pq-confidential-proof-carrying-upgrade-formal-proof-root-v1";
pub const PQ_QUORUM_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-proof-carrying-upgrade-quorum-v1";
pub const ROLLBACK_WINDOW_SCHEME: &str =
    "private-l2-pq-confidential-contract-upgrade-rollback-window-v1";
pub const LEAKAGE_BUDGET_SCHEME: &str =
    "private-l2-pq-confidential-contract-upgrade-leakage-budget-v1";
pub const REVIEW_BATCH_SCHEME: &str = "private-l2-low-fee-proof-carrying-upgrade-review-batch-v1";
pub const ROOTS_ONLY_AUDIT_RECORD_SCHEME: &str =
    "private-l2-roots-only-proof-carrying-upgrade-audit-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_640_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_SIGNER_WEIGHT: u64 = 67;
pub const DEFAULT_STRONG_SIGNER_WEIGHT: u64 = 80;
pub const DEFAULT_MANIFEST_NOTICE_BLOCKS: u64 = 2_880;
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 7_200;
pub const DEFAULT_ROLLBACK_FINALITY_LAG_BLOCKS: u64 = 128;
pub const DEFAULT_REVIEW_BATCH_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_REVIEW_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 10;
pub const DEFAULT_PUBLIC_RECORD_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const DEFAULT_GLOBAL_LEAKAGE_BUDGET_MICROBITS: u64 = 2_500;
pub const DEFAULT_PER_CONTRACT_LEAKAGE_BUDGET_MICROBITS: u64 = 400;
pub const DEFAULT_PER_FIELD_LEAKAGE_BUDGET_MICROBITS: u64 = 80;
pub const DEFAULT_MIN_PROOF_COVERAGE_BPS: u64 = 9_500;
pub const DEFAULT_MIN_STORAGE_COVERAGE_BPS: u64 = 9_800;
pub const DEFAULT_MIN_BYTECODE_REPRODUCIBILITY_BPS: u64 = 9_900;
pub const MAX_UPGRADE_MANIFESTS: usize = 1_048_576;
pub const MAX_BYTECODE_COMMITMENTS: usize = 2_097_152;
pub const MAX_STORAGE_COMMITMENTS: usize = 2_097_152;
pub const MAX_FORMAL_PROOF_ROOTS: usize = 2_097_152;
pub const MAX_PQ_SIGNER_QUORUMS: usize = 1_048_576;
pub const MAX_ROLLBACK_WINDOWS: usize = 1_048_576;
pub const MAX_LEAKAGE_BUDGETS: usize = 2_097_152;
pub const MAX_REVIEW_BATCHES: usize = 1_048_576;
pub const MAX_PUBLIC_AUDIT_RECORDS: usize = 2_097_152;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Account,
    Token,
    Dex,
    Lending,
    Derivatives,
    Governance,
    Oracle,
    Bridge,
    Treasury,
    General,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Token => "token",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Derivatives => "derivatives",
            Self::Governance => "governance",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeIntent {
    SecurityPatch,
    PrivacyPatch,
    FeatureRelease,
    StorageMigration,
    VerifierRotation,
    EmergencyRollback,
    Deprecation,
}

impl UpgradeIntent {
    pub fn requires_strong_quorum(self) -> bool {
        matches!(
            self,
            Self::SecurityPatch
                | Self::PrivacyPatch
                | Self::StorageMigration
                | Self::VerifierRotation
                | Self::EmergencyRollback
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Proposed,
    ReviewQueued,
    ProofBound,
    QuorumAttested,
    RollbackReady,
    Approved,
    Rejected,
    Superseded,
    Revoked,
}

impl ManifestStatus {
    pub fn accepts_evidence(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::Proposed
                | Self::ReviewQueued
                | Self::ProofBound
                | Self::QuorumAttested
                | Self::RollbackReady
        )
    }

    pub fn approved(self) -> bool {
        matches!(self, Self::Approved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeVm {
    ConfidentialWasm,
    NoirAcir,
    Cairo,
    Miden,
    RiscZero,
    Sp1,
    Halo2Dsl,
    CustomPqVm,
}

impl BytecodeVm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialWasm => "confidential_wasm",
            Self::NoirAcir => "noir_acir",
            Self::Cairo => "cairo",
            Self::Miden => "miden",
            Self::RiscZero => "risc_zero",
            Self::Sp1 => "sp1",
            Self::Halo2Dsl => "halo2_dsl",
            Self::CustomPqVm => "custom_pq_vm",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Submitted,
    ManifestMatched,
    Reproducible,
    StorageBound,
    ProofBound,
    Accepted,
    Rejected,
    Revoked,
}

impl CommitmentStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Reproducible | Self::StorageBound | Self::ProofBound | Self::Accepted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageScope {
    Layout,
    NullifierSet,
    NoteTree,
    EncryptedSlots,
    EventIndex,
    CrossContractCache,
    FullState,
}

impl StorageScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Layout => "layout",
            Self::NullifierSet => "nullifier_set",
            Self::NoteTree => "note_tree",
            Self::EncryptedSlots => "encrypted_slots",
            Self::EventIndex => "event_index",
            Self::CrossContractCache => "cross_contract_cache",
            Self::FullState => "full_state",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    Lean,
    Coq,
    Dafny,
    K,
    TlaPlus,
    Alloy,
    Plonkish,
    Stark,
    Nova,
    RiscZero,
    Sp1,
    CustomPq,
}

impl ProofSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lean => "lean",
            Self::Coq => "coq",
            Self::Dafny => "dafny",
            Self::K => "k",
            Self::TlaPlus => "tla_plus",
            Self::Alloy => "alloy",
            Self::Plonkish => "plonkish",
            Self::Stark => "stark",
            Self::Nova => "nova",
            Self::RiscZero => "risc_zero",
            Self::Sp1 => "sp1",
            Self::CustomPq => "custom_pq",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofClaim {
    StateTransitionPreserved,
    StorageMigrationBijective,
    NoSecretDisclosure,
    EventPrivacyPreserved,
    AuthorizationInvariant,
    RollbackRestoresState,
    FeeBatchFairness,
    CrossContractCompatibility,
}

impl ProofClaim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateTransitionPreserved => "state_transition_preserved",
            Self::StorageMigrationBijective => "storage_migration_bijective",
            Self::NoSecretDisclosure => "no_secret_disclosure",
            Self::EventPrivacyPreserved => "event_privacy_preserved",
            Self::AuthorizationInvariant => "authorization_invariant",
            Self::RollbackRestoresState => "rollback_restores_state",
            Self::FeeBatchFairness => "fee_batch_fairness",
            Self::CrossContractCompatibility => "cross_contract_compatibility",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAlgorithm {
    MlDsa65,
    MlDsa87,
    SlhDsaShake128f,
    SlhDsaShake256f,
    HybridMlDsa87SlhDsa,
}

impl PqAlgorithm {
    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
            Self::SlhDsaShake128f => 128,
            Self::SlhDsaShake256f => 256,
            Self::HybridMlDsa87SlhDsa => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    Governance,
    SecurityCouncil,
    FormalVerifier,
    PrivacyAuditor,
    ReleaseEngineer,
    Watchtower,
    EmergencyOperator,
}

impl SignerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::SecurityCouncil => "security_council",
            Self::FormalVerifier => "formal_verifier",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::ReleaseEngineer => "release_engineer",
            Self::Watchtower => "watchtower",
            Self::EmergencyOperator => "emergency_operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Planned,
    SnapshotBound,
    Rehearsed,
    Armed,
    Exercised,
    Expired,
    Cancelled,
}

impl RollbackStatus {
    pub fn ready(self) -> bool {
        matches!(self, Self::Rehearsed | Self::Armed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakageClass {
    ViewKeyHint,
    Timing,
    EventShape,
    StorageAccessPattern,
    BatchMembership,
    FeeMetadata,
    ProofTranscript,
}

impl LeakageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKeyHint => "view_key_hint",
            Self::Timing => "timing",
            Self::EventShape => "event_shape",
            Self::StorageAccessPattern => "storage_access_pattern",
            Self::BatchMembership => "batch_membership",
            Self::FeeMetadata => "fee_metadata",
            Self::ProofTranscript => "proof_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewBatchStatus {
    Open,
    Sealed,
    Submitted,
    Verified,
    Rebated,
    Rejected,
    Expired,
}

impl ReviewBatchStatus {
    pub fn accepts_items(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Pending,
    Approved,
    ApprovedWithRollbackWatch,
    NeedsMoreProof,
    Rejected,
    Revoked,
}

impl AuditDecision {
    pub fn public_label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::ApprovedWithRollbackWatch => "approved_with_rollback_watch",
            Self::NeedsMoreProof => "needs_more_proof",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub deployment_domain: String,
    pub min_pq_security_bits: u16,
    pub min_signer_weight: u64,
    pub strong_signer_weight: u64,
    pub manifest_notice_blocks: u64,
    pub rollback_window_blocks: u64,
    pub rollback_finality_lag_blocks: u64,
    pub review_batch_window_blocks: u64,
    pub max_review_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub public_record_ttl_blocks: u64,
    pub max_batch_items: usize,
    pub global_leakage_budget_microbits: u64,
    pub per_contract_leakage_budget_microbits: u64,
    pub per_field_leakage_budget_microbits: u64,
    pub min_proof_coverage_bps: u64,
    pub min_storage_coverage_bps: u64,
    pub min_bytecode_reproducibility_bps: u64,
    pub require_roots_only_public_records: bool,
    pub require_dual_proof_systems: bool,
    pub require_rollback_rehearsal: bool,
    pub require_low_fee_batching_for_public_review: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            deployment_domain: "nebula.private-l2.proof-carrying-upgrade-audit.devnet".to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_signer_weight: DEFAULT_MIN_SIGNER_WEIGHT,
            strong_signer_weight: DEFAULT_STRONG_SIGNER_WEIGHT,
            manifest_notice_blocks: DEFAULT_MANIFEST_NOTICE_BLOCKS,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            rollback_finality_lag_blocks: DEFAULT_ROLLBACK_FINALITY_LAG_BLOCKS,
            review_batch_window_blocks: DEFAULT_REVIEW_BATCH_WINDOW_BLOCKS,
            max_review_fee_bps: DEFAULT_MAX_REVIEW_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            public_record_ttl_blocks: DEFAULT_PUBLIC_RECORD_TTL_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            global_leakage_budget_microbits: DEFAULT_GLOBAL_LEAKAGE_BUDGET_MICROBITS,
            per_contract_leakage_budget_microbits: DEFAULT_PER_CONTRACT_LEAKAGE_BUDGET_MICROBITS,
            per_field_leakage_budget_microbits: DEFAULT_PER_FIELD_LEAKAGE_BUDGET_MICROBITS,
            min_proof_coverage_bps: DEFAULT_MIN_PROOF_COVERAGE_BPS,
            min_storage_coverage_bps: DEFAULT_MIN_STORAGE_COVERAGE_BPS,
            min_bytecode_reproducibility_bps: DEFAULT_MIN_BYTECODE_REPRODUCIBILITY_BPS,
            require_roots_only_public_records: true,
            require_dual_proof_systems: true,
            require_rollback_rehearsal: true,
            require_low_fee_batching_for_public_review: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("deployment_domain", &self.deployment_domain)?;
        require_bps("max_review_fee_bps", self.max_review_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_bps("min_proof_coverage_bps", self.min_proof_coverage_bps)?;
        require_bps("min_storage_coverage_bps", self.min_storage_coverage_bps)?;
        require_bps(
            "min_bytecode_reproducibility_bps",
            self.min_bytecode_reproducibility_bps,
        )?;
        if self.min_signer_weight == 0 || self.strong_signer_weight < self.min_signer_weight {
            return Err("signer weight thresholds are inconsistent".to_string());
        }
        if self.review_batch_window_blocks == 0 || self.rollback_window_blocks == 0 {
            return Err("review and rollback windows must be non-zero".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "deployment_domain": self.deployment_domain,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_signer_weight": self.min_signer_weight,
            "strong_signer_weight": self.strong_signer_weight,
            "manifest_notice_blocks": self.manifest_notice_blocks,
            "rollback_window_blocks": self.rollback_window_blocks,
            "rollback_finality_lag_blocks": self.rollback_finality_lag_blocks,
            "review_batch_window_blocks": self.review_batch_window_blocks,
            "max_review_fee_bps": self.max_review_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "public_record_ttl_blocks": self.public_record_ttl_blocks,
            "max_batch_items": self.max_batch_items,
            "global_leakage_budget_microbits": self.global_leakage_budget_microbits,
            "per_contract_leakage_budget_microbits": self.per_contract_leakage_budget_microbits,
            "per_field_leakage_budget_microbits": self.per_field_leakage_budget_microbits,
            "min_proof_coverage_bps": self.min_proof_coverage_bps,
            "min_storage_coverage_bps": self.min_storage_coverage_bps,
            "min_bytecode_reproducibility_bps": self.min_bytecode_reproducibility_bps,
            "require_roots_only_public_records": self.require_roots_only_public_records,
            "require_dual_proof_systems": self.require_dual_proof_systems,
            "require_rollback_rehearsal": self.require_rollback_rehearsal,
            "require_low_fee_batching_for_public_review": self.require_low_fee_batching_for_public_review,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub upgrade_manifests: u64,
    pub bytecode_commitments: u64,
    pub storage_commitments: u64,
    pub formal_proof_roots: u64,
    pub pq_signer_quorums: u64,
    pub rollback_windows: u64,
    pub leakage_budgets: u64,
    pub review_batches: u64,
    pub public_audit_records: u64,
    pub approved_public_records: u64,
    pub rejected_public_records: u64,
    pub revoked_public_records: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "upgrade_manifests": self.upgrade_manifests,
            "bytecode_commitments": self.bytecode_commitments,
            "storage_commitments": self.storage_commitments,
            "formal_proof_roots": self.formal_proof_roots,
            "pq_signer_quorums": self.pq_signer_quorums,
            "rollback_windows": self.rollback_windows,
            "leakage_budgets": self.leakage_budgets,
            "review_batches": self.review_batches,
            "public_audit_records": self.public_audit_records,
            "approved_public_records": self.approved_public_records,
            "rejected_public_records": self.rejected_public_records,
            "revoked_public_records": self.revoked_public_records,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub upgrade_manifest_root: String,
    pub bytecode_commitment_root: String,
    pub storage_commitment_root: String,
    pub formal_proof_root: String,
    pub pq_signer_quorum_root: String,
    pub rollback_window_root: String,
    pub leakage_budget_root: String,
    pub review_batch_root: String,
    pub public_audit_record_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            upgrade_manifest_root: merkle_root("UPGRADE-AUDIT-EMPTY-MANIFEST", &[]),
            bytecode_commitment_root: merkle_root("UPGRADE-AUDIT-EMPTY-BYTECODE", &[]),
            storage_commitment_root: merkle_root("UPGRADE-AUDIT-EMPTY-STORAGE", &[]),
            formal_proof_root: merkle_root("UPGRADE-AUDIT-EMPTY-PROOF", &[]),
            pq_signer_quorum_root: merkle_root("UPGRADE-AUDIT-EMPTY-PQ-QUORUM", &[]),
            rollback_window_root: merkle_root("UPGRADE-AUDIT-EMPTY-ROLLBACK", &[]),
            leakage_budget_root: merkle_root("UPGRADE-AUDIT-EMPTY-LEAKAGE", &[]),
            review_batch_root: merkle_root("UPGRADE-AUDIT-EMPTY-REVIEW-BATCH", &[]),
            public_audit_record_root: merkle_root("UPGRADE-AUDIT-EMPTY-PUBLIC-RECORD", &[]),
            event_root: merkle_root("UPGRADE-AUDIT-EMPTY-EVENT", &[]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "upgrade_manifest_root": self.upgrade_manifest_root,
            "bytecode_commitment_root": self.bytecode_commitment_root,
            "storage_commitment_root": self.storage_commitment_root,
            "formal_proof_root": self.formal_proof_root,
            "pq_signer_quorum_root": self.pq_signer_quorum_root,
            "rollback_window_root": self.rollback_window_root,
            "leakage_budget_root": self.leakage_budget_root,
            "review_batch_root": self.review_batch_root,
            "public_audit_record_root": self.public_audit_record_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub domain: ContractDomain,
    pub intent: UpgradeIntent,
    pub previous_manifest_id: Option<String>,
    pub current_bytecode_root: String,
    pub candidate_bytecode_root: String,
    pub current_storage_root: String,
    pub candidate_storage_root: String,
    pub formal_spec_root: String,
    pub invariant_manifest_root: String,
    pub migration_plan_root: String,
    pub disclosure_policy_root: String,
    pub author: String,
    pub proposed_at_height: u64,
    pub earliest_activation_height: u64,
    pub expires_at_height: u64,
    pub status: ManifestStatus,
    pub metadata: Value,
}

impl UpgradeManifest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("current_bytecode_root", &self.current_bytecode_root)?;
        require_non_empty("candidate_bytecode_root", &self.candidate_bytecode_root)?;
        require_non_empty("current_storage_root", &self.current_storage_root)?;
        require_non_empty("candidate_storage_root", &self.candidate_storage_root)?;
        require_non_empty("formal_spec_root", &self.formal_spec_root)?;
        require_non_empty("invariant_manifest_root", &self.invariant_manifest_root)?;
        require_non_empty("migration_plan_root", &self.migration_plan_root)?;
        require_non_empty("disclosure_policy_root", &self.disclosure_policy_root)?;
        require_non_empty("author", &self.author)?;
        if self.candidate_bytecode_root == self.current_bytecode_root {
            return Err(
                "candidate bytecode root must differ from current bytecode root".to_string(),
            );
        }
        if self.earliest_activation_height
            < self
                .proposed_at_height
                .saturating_add(config.manifest_notice_blocks)
        {
            return Err("manifest activation height violates notice window".to_string());
        }
        if self.expires_at_height <= self.earliest_activation_height {
            return Err("manifest expiry must follow earliest activation height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": UPGRADE_MANIFEST_SCHEME,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "intent": self.intent,
            "previous_manifest_id": self.previous_manifest_id,
            "current_bytecode_root": self.current_bytecode_root,
            "candidate_bytecode_root": self.candidate_bytecode_root,
            "current_storage_root": self.current_storage_root,
            "candidate_storage_root": self.candidate_storage_root,
            "formal_spec_root": self.formal_spec_root,
            "invariant_manifest_root": self.invariant_manifest_root,
            "migration_plan_root": self.migration_plan_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "proposed_at_height": self.proposed_at_height,
            "earliest_activation_height": self.earliest_activation_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-MANIFEST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BytecodeCommitment {
    pub commitment_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub vm: BytecodeVm,
    pub source_tree_root: String,
    pub build_recipe_root: String,
    pub compiler_root: String,
    pub bytecode_root: String,
    pub abi_root: String,
    pub verifier_key_root: String,
    pub reproducibility_bps: u64,
    pub pq_build_attestation_root: String,
    pub submitted_at_height: u64,
    pub status: CommitmentStatus,
}

impl BytecodeCommitment {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("commitment_id", &self.commitment_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("source_tree_root", &self.source_tree_root)?;
        require_non_empty("build_recipe_root", &self.build_recipe_root)?;
        require_non_empty("compiler_root", &self.compiler_root)?;
        require_non_empty("bytecode_root", &self.bytecode_root)?;
        require_non_empty("abi_root", &self.abi_root)?;
        require_non_empty("verifier_key_root", &self.verifier_key_root)?;
        require_non_empty("pq_build_attestation_root", &self.pq_build_attestation_root)?;
        require_bps("reproducibility_bps", self.reproducibility_bps)?;
        if self.reproducibility_bps < config.min_bytecode_reproducibility_bps {
            return Err("bytecode reproducibility below configured floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": BYTECODE_COMMITMENT_SCHEME,
            "commitment_id": self.commitment_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "vm": self.vm.as_str(),
            "source_tree_root": self.source_tree_root,
            "build_recipe_root": self.build_recipe_root,
            "compiler_root": self.compiler_root,
            "bytecode_root": self.bytecode_root,
            "abi_root": self.abi_root,
            "verifier_key_root": self.verifier_key_root,
            "reproducibility_bps": self.reproducibility_bps,
            "pq_build_attestation_root": self.pq_build_attestation_root,
            "submitted_at_height": self.submitted_at_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-BYTECODE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StorageCommitment {
    pub commitment_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub scope: StorageScope,
    pub pre_upgrade_root: String,
    pub post_upgrade_root: String,
    pub migration_witness_root: String,
    pub encrypted_delta_root: String,
    pub nullifier_preservation_root: String,
    pub rollback_snapshot_root: String,
    pub covered_slots: u64,
    pub total_slots: u64,
    pub coverage_bps: u64,
    pub submitted_at_height: u64,
    pub status: CommitmentStatus,
}

impl StorageCommitment {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("commitment_id", &self.commitment_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("pre_upgrade_root", &self.pre_upgrade_root)?;
        require_non_empty("post_upgrade_root", &self.post_upgrade_root)?;
        require_non_empty("migration_witness_root", &self.migration_witness_root)?;
        require_non_empty("encrypted_delta_root", &self.encrypted_delta_root)?;
        require_non_empty(
            "nullifier_preservation_root",
            &self.nullifier_preservation_root,
        )?;
        require_non_empty("rollback_snapshot_root", &self.rollback_snapshot_root)?;
        require_bps("coverage_bps", self.coverage_bps)?;
        if self.total_slots == 0 || self.covered_slots > self.total_slots {
            return Err("storage slot coverage counts are inconsistent".to_string());
        }
        if self.coverage_bps < config.min_storage_coverage_bps {
            return Err("storage coverage below configured floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": STORAGE_COMMITMENT_SCHEME,
            "commitment_id": self.commitment_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "scope": self.scope.as_str(),
            "pre_upgrade_root": self.pre_upgrade_root,
            "post_upgrade_root": self.post_upgrade_root,
            "migration_witness_root": self.migration_witness_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "nullifier_preservation_root": self.nullifier_preservation_root,
            "rollback_snapshot_root": self.rollback_snapshot_root,
            "covered_slots": self.covered_slots,
            "total_slots": self.total_slots,
            "coverage_bps": self.coverage_bps,
            "submitted_at_height": self.submitted_at_height,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-STORAGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FormalProofRoot {
    pub proof_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub proof_system: ProofSystem,
    pub claims: BTreeSet<ProofClaim>,
    pub theorem_root: String,
    pub proof_artifact_root: String,
    pub verifier_receipt_root: String,
    pub assumption_root: String,
    pub counterexample_search_root: String,
    pub coverage_bps: u64,
    pub machine_checked: bool,
    pub reproducible: bool,
    pub open_obligations: u64,
    pub submitted_at_height: u64,
}

impl FormalProofRoot {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("proof_id", &self.proof_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("theorem_root", &self.theorem_root)?;
        require_non_empty("proof_artifact_root", &self.proof_artifact_root)?;
        require_non_empty("verifier_receipt_root", &self.verifier_receipt_root)?;
        require_non_empty("assumption_root", &self.assumption_root)?;
        require_non_empty(
            "counterexample_search_root",
            &self.counterexample_search_root,
        )?;
        require_bps("coverage_bps", self.coverage_bps)?;
        if self.claims.is_empty() {
            return Err("formal proof root must bind at least one claim".to_string());
        }
        if self.coverage_bps < config.min_proof_coverage_bps {
            return Err("formal proof coverage below configured floor".to_string());
        }
        if !self.machine_checked || !self.reproducible || self.open_obligations > 0 {
            return Err(
                "formal proof must be machine checked, reproducible, and closed".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": FORMAL_PROOF_ROOT_SCHEME,
            "proof_id": self.proof_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "proof_system": self.proof_system.as_str(),
            "claims": self.claims.iter().map(|claim| claim.as_str()).collect::<Vec<_>>(),
            "theorem_root": self.theorem_root,
            "proof_artifact_root": self.proof_artifact_root,
            "verifier_receipt_root": self.verifier_receipt_root,
            "assumption_root": self.assumption_root,
            "counterexample_search_root": self.counterexample_search_root,
            "coverage_bps": self.coverage_bps,
            "machine_checked": self.machine_checked,
            "reproducible": self.reproducible,
            "open_obligations": self.open_obligations,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-FORMAL-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignerAttestation {
    pub signer_id: String,
    pub role: SignerRole,
    pub algorithm: PqAlgorithm,
    pub public_key_root: String,
    pub message_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub weight: u64,
    pub non_replayable: bool,
}

impl PqSignerAttestation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("signer_id", &self.signer_id)?;
        require_non_empty("public_key_root", &self.public_key_root)?;
        require_non_empty("message_root", &self.message_root)?;
        require_non_empty("signature_root", &self.signature_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        if self.algorithm.security_bits() < config.min_pq_security_bits {
            return Err("signer algorithm below configured PQ security floor".to_string());
        }
        if self.weight == 0 {
            return Err("signer weight must be non-zero".to_string());
        }
        if !self.non_replayable {
            return Err("PQ signer attestation must be non-replayable".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "role": self.role.as_str(),
            "algorithm": self.algorithm,
            "public_key_root": self.public_key_root,
            "message_root": self.message_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "weight": self.weight,
            "non_replayable": self.non_replayable,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignerQuorum {
    pub quorum_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub threshold_weight: u64,
    pub collected_weight: u64,
    pub strong_quorum: bool,
    pub attestation_root: String,
    pub signers: Vec<PqSignerAttestation>,
    pub submitted_at_height: u64,
}

impl PqSignerQuorum {
    pub fn validate(&self, config: &Config, strong_required: bool) -> Result<()> {
        require_non_empty("quorum_id", &self.quorum_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("attestation_root", &self.attestation_root)?;
        if self.signers.is_empty() {
            return Err("PQ quorum must include at least one signer".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut weight = 0_u64;
        let mut roles = BTreeSet::new();
        for signer in &self.signers {
            signer.validate(config)?;
            if !seen.insert(signer.signer_id.clone()) {
                return Err("duplicate signer in PQ quorum".to_string());
            }
            roles.insert(signer.role);
            weight = weight.saturating_add(signer.weight);
        }
        if roles.len() < 3 {
            return Err("PQ quorum must include at least three signer roles".to_string());
        }
        if weight != self.collected_weight {
            return Err("PQ quorum collected_weight does not match signer weights".to_string());
        }
        let floor = if strong_required {
            config.strong_signer_weight
        } else {
            config.min_signer_weight
        };
        if self.threshold_weight < floor || self.collected_weight < self.threshold_weight {
            return Err("PQ quorum below configured threshold".to_string());
        }
        if strong_required && !self.strong_quorum {
            return Err("manifest intent requires strong PQ quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let signer_records = self
            .signers
            .iter()
            .map(PqSignerAttestation::public_record)
            .collect::<Vec<_>>();
        json!({
            "scheme": PQ_QUORUM_SCHEME,
            "quorum_id": self.quorum_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "threshold_weight": self.threshold_weight,
            "collected_weight": self.collected_weight,
            "strong_quorum": self.strong_quorum,
            "attestation_root": self.attestation_root,
            "signer_root": merkle_root("UPGRADE-AUDIT-PQ-SIGNER", &signer_records),
            "signer_count": self.signers.len(),
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-PQ-QUORUM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackWindow {
    pub rollback_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub finality_lag_blocks: u64,
    pub snapshot_root: String,
    pub restore_procedure_root: String,
    pub rehearsal_receipt_root: String,
    pub emergency_signer_root: String,
    pub liquidity_impact_limit: u64,
    pub status: RollbackStatus,
}

impl RollbackWindow {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("rollback_id", &self.rollback_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("snapshot_root", &self.snapshot_root)?;
        require_non_empty("restore_procedure_root", &self.restore_procedure_root)?;
        require_non_empty("rehearsal_receipt_root", &self.rehearsal_receipt_root)?;
        require_non_empty("emergency_signer_root", &self.emergency_signer_root)?;
        if self.end_height <= self.start_height {
            return Err("rollback window end must follow start".to_string());
        }
        if self.end_height.saturating_sub(self.start_height) < config.rollback_window_blocks {
            return Err("rollback window shorter than configured minimum".to_string());
        }
        if self.finality_lag_blocks < config.rollback_finality_lag_blocks {
            return Err("rollback finality lag below configured minimum".to_string());
        }
        if config.require_rollback_rehearsal && !self.status.ready() {
            return Err("rollback rehearsal required before audit approval".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": ROLLBACK_WINDOW_SCHEME,
            "rollback_id": self.rollback_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "finality_lag_blocks": self.finality_lag_blocks,
            "snapshot_root": self.snapshot_root,
            "restore_procedure_root": self.restore_procedure_root,
            "rehearsal_receipt_root": self.rehearsal_receipt_root,
            "emergency_signer_root": self.emergency_signer_root,
            "liquidity_impact_limit": self.liquidity_impact_limit,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-ROLLBACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LeakageBudget {
    pub budget_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub class: LeakageClass,
    pub field_commitment_root: String,
    pub measured_microbits: u64,
    pub per_field_limit_microbits: u64,
    pub per_contract_limit_microbits: u64,
    pub global_epoch_limit_microbits: u64,
    pub mitigation_root: String,
    pub auditor_receipt_root: String,
    pub submitted_at_height: u64,
}

impl LeakageBudget {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("budget_id", &self.budget_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("field_commitment_root", &self.field_commitment_root)?;
        require_non_empty("mitigation_root", &self.mitigation_root)?;
        require_non_empty("auditor_receipt_root", &self.auditor_receipt_root)?;
        if self.per_field_limit_microbits > config.per_field_leakage_budget_microbits
            || self.per_contract_limit_microbits > config.per_contract_leakage_budget_microbits
            || self.global_epoch_limit_microbits > config.global_leakage_budget_microbits
        {
            return Err("leakage limits exceed configured budget".to_string());
        }
        if self.measured_microbits > self.per_field_limit_microbits {
            return Err("measured leakage exceeds per-field budget".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": LEAKAGE_BUDGET_SCHEME,
            "budget_id": self.budget_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "class": self.class.as_str(),
            "field_commitment_root": self.field_commitment_root,
            "measured_microbits": self.measured_microbits,
            "per_field_limit_microbits": self.per_field_limit_microbits,
            "per_contract_limit_microbits": self.per_contract_limit_microbits,
            "global_epoch_limit_microbits": self.global_epoch_limit_microbits,
            "mitigation_root": self.mitigation_root,
            "auditor_receipt_root": self.auditor_receipt_root,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-LEAKAGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReviewBatch {
    pub batch_id: String,
    pub manifest_ids: Vec<String>,
    pub reviewer_set_root: String,
    pub fee_sponsor_root: String,
    pub review_request_root: String,
    pub batch_receipt_root: String,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub max_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub status: ReviewBatchStatus,
}

impl ReviewBatch {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("reviewer_set_root", &self.reviewer_set_root)?;
        require_non_empty("fee_sponsor_root", &self.fee_sponsor_root)?;
        require_non_empty("review_request_root", &self.review_request_root)?;
        require_non_empty("batch_receipt_root", &self.batch_receipt_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.manifest_ids.is_empty() || self.manifest_ids.len() > config.max_batch_items {
            return Err("review batch item count outside configured bounds".to_string());
        }
        if self.sealed_at_height
            < self
                .opened_at_height
                .saturating_add(config.review_batch_window_blocks)
        {
            return Err("review batch sealed before configured review window".to_string());
        }
        if self.max_fee_bps > config.max_review_fee_bps {
            return Err("review batch fee exceeds configured low-fee ceiling".to_string());
        }
        if self.target_rebate_bps < config.target_rebate_bps {
            return Err("review batch rebate below configured target".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": REVIEW_BATCH_SCHEME,
            "batch_id": self.batch_id,
            "manifest_root": merkle_root("UPGRADE-AUDIT-REVIEW-BATCH-MANIFEST", &string_values(&self.manifest_ids)),
            "manifest_count": self.manifest_ids.len(),
            "reviewer_set_root": self.reviewer_set_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "review_request_root": self.review_request_root,
            "batch_receipt_root": self.batch_receipt_root,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "max_fee_bps": self.max_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "status": self.status,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-REVIEW-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicAuditRecord {
    pub record_id: String,
    pub manifest_id: String,
    pub contract_id: String,
    pub decision: AuditDecision,
    pub manifest_root: String,
    pub bytecode_commitment_root: String,
    pub storage_commitment_root: String,
    pub formal_proof_root: String,
    pub pq_quorum_root: String,
    pub rollback_root: String,
    pub leakage_budget_root: String,
    pub review_batch_root: String,
    pub emitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PublicAuditRecord {
    pub fn validate(&self) -> Result<()> {
        require_non_empty("record_id", &self.record_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require_non_empty("contract_id", &self.contract_id)?;
        require_non_empty("manifest_root", &self.manifest_root)?;
        require_non_empty("bytecode_commitment_root", &self.bytecode_commitment_root)?;
        require_non_empty("storage_commitment_root", &self.storage_commitment_root)?;
        require_non_empty("formal_proof_root", &self.formal_proof_root)?;
        require_non_empty("pq_quorum_root", &self.pq_quorum_root)?;
        require_non_empty("rollback_root", &self.rollback_root)?;
        require_non_empty("leakage_budget_root", &self.leakage_budget_root)?;
        require_non_empty("review_batch_root", &self.review_batch_root)?;
        if self.expires_at_height <= self.emitted_at_height {
            return Err("public audit record expiry must follow emission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema": ROOTS_ONLY_AUDIT_RECORD_SCHEME,
            "record_id": self.record_id,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "decision": self.decision.public_label(),
            "manifest_root": self.manifest_root,
            "bytecode_commitment_root": self.bytecode_commitment_root,
            "storage_commitment_root": self.storage_commitment_root,
            "formal_proof_root": self.formal_proof_root,
            "pq_quorum_root": self.pq_quorum_root,
            "rollback_root": self.rollback_root,
            "leakage_budget_root": self.leakage_budget_root,
            "review_batch_root": self.review_batch_root,
            "emitted_at_height": self.emitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        record_root("UPGRADE-AUDIT-PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ManifestRegistered,
    BytecodeCommitted,
    StorageCommitted,
    FormalProofRootBound,
    PqQuorumSubmitted,
    RollbackWindowArmed,
    LeakageBudgetFiled,
    ReviewBatchSubmitted,
    PublicRecordEmitted,
    ManifestApproved,
    ManifestRejected,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub upgrade_manifests: BTreeMap<String, UpgradeManifest>,
    pub bytecode_commitments: BTreeMap<String, BytecodeCommitment>,
    pub storage_commitments: BTreeMap<String, StorageCommitment>,
    pub formal_proof_roots: BTreeMap<String, FormalProofRoot>,
    pub pq_signer_quorums: BTreeMap<String, PqSignerQuorum>,
    pub rollback_windows: BTreeMap<String, RollbackWindow>,
    pub leakage_budgets: BTreeMap<String, LeakageBudget>,
    pub review_batches: BTreeMap<String, ReviewBatch>,
    pub public_audit_records: BTreeMap<String, PublicAuditRecord>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            upgrade_manifests: BTreeMap::new(),
            bytecode_commitments: BTreeMap::new(),
            storage_commitments: BTreeMap::new(),
            formal_proof_roots: BTreeMap::new(),
            pq_signer_quorums: BTreeMap::new(),
            rollback_windows: BTreeMap::new(),
            leakage_budgets: BTreeMap::new(),
            review_batches: BTreeMap::new(),
            public_audit_records: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema": PUBLIC_RECORD_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root_with(&self.roots)
    }

    fn compute_state_root_with(&self, roots: &Roots) -> String {
        domain_hash(
            "private_l2_pq_confidential_contract_proof_carrying_upgrade_audit_state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            upgrade_manifest_root: map_root("manifest", &self.upgrade_manifests, |v| {
                v.public_record()
            }),
            bytecode_commitment_root: map_root("bytecode", &self.bytecode_commitments, |v| {
                v.public_record()
            }),
            storage_commitment_root: map_root("storage", &self.storage_commitments, |v| {
                v.public_record()
            }),
            formal_proof_root: map_root("formal-proof", &self.formal_proof_roots, |v| {
                v.public_record()
            }),
            pq_signer_quorum_root: map_root("pq-quorum", &self.pq_signer_quorums, |v| {
                v.public_record()
            }),
            rollback_window_root: map_root("rollback", &self.rollback_windows, |v| {
                v.public_record()
            }),
            leakage_budget_root: map_root("leakage", &self.leakage_budgets, |v| v.public_record()),
            review_batch_root: map_root("review-batch", &self.review_batches, |v| {
                v.public_record()
            }),
            public_audit_record_root: map_root("public-record", &self.public_audit_records, |v| {
                v.public_record()
            }),
            event_root: map_root("event", &self.events, |v| v.public_record()),
        };
    }

    pub fn register_manifest(&mut self, mut manifest: UpgradeManifest) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "upgrade_manifests",
            self.upgrade_manifests.len(),
            MAX_UPGRADE_MANIFESTS,
        )?;
        if manifest.manifest_id.is_empty() {
            manifest.manifest_id = stable_id(
                "manifest",
                &manifest.contract_id,
                &manifest.candidate_bytecode_root,
                self.counters.upgrade_manifests,
            );
        }
        manifest.validate(&self.config)?;
        let manifest_id = manifest.manifest_id.clone();
        if self.upgrade_manifests.contains_key(&manifest_id) {
            return Err("manifest already registered".to_string());
        }
        let root = manifest.record_root();
        self.upgrade_manifests.insert(manifest_id.clone(), manifest);
        self.counters.upgrade_manifests = self.counters.upgrade_manifests.saturating_add(1);
        self.push_event(
            EventKind::ManifestRegistered,
            &manifest_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(manifest_id)
    }

    pub fn bind_bytecode_commitment(
        &mut self,
        mut commitment: BytecodeCommitment,
    ) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "bytecode_commitments",
            self.bytecode_commitments.len(),
            MAX_BYTECODE_COMMITMENTS,
        )?;
        self.require_manifest_accepts_evidence(&commitment.manifest_id)?;
        if commitment.commitment_id.is_empty() {
            commitment.commitment_id = stable_id(
                "bytecode",
                &commitment.manifest_id,
                &commitment.bytecode_root,
                self.counters.bytecode_commitments,
            );
        }
        commitment.validate(&self.config)?;
        let manifest = self
            .upgrade_manifests
            .get(&commitment.manifest_id)
            .ok_or_else(|| "manifest not found for bytecode commitment".to_string())?;
        if manifest.contract_id != commitment.contract_id
            || manifest.candidate_bytecode_root != commitment.bytecode_root
        {
            return Err("bytecode commitment does not match manifest".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        let root = commitment.record_root();
        self.bytecode_commitments
            .insert(commitment_id.clone(), commitment);
        self.counters.bytecode_commitments = self.counters.bytecode_commitments.saturating_add(1);
        self.push_event(
            EventKind::BytecodeCommitted,
            &commitment_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn bind_storage_commitment(&mut self, mut commitment: StorageCommitment) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "storage_commitments",
            self.storage_commitments.len(),
            MAX_STORAGE_COMMITMENTS,
        )?;
        self.require_manifest_accepts_evidence(&commitment.manifest_id)?;
        if commitment.commitment_id.is_empty() {
            commitment.commitment_id = stable_id(
                "storage",
                &commitment.manifest_id,
                &commitment.post_upgrade_root,
                self.counters.storage_commitments,
            );
        }
        commitment.validate(&self.config)?;
        let manifest = self
            .upgrade_manifests
            .get(&commitment.manifest_id)
            .ok_or_else(|| "manifest not found for storage commitment".to_string())?;
        if manifest.contract_id != commitment.contract_id
            || manifest.current_storage_root != commitment.pre_upgrade_root
            || manifest.candidate_storage_root != commitment.post_upgrade_root
        {
            return Err("storage commitment does not match manifest".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        let root = commitment.record_root();
        self.storage_commitments
            .insert(commitment_id.clone(), commitment);
        self.counters.storage_commitments = self.counters.storage_commitments.saturating_add(1);
        self.push_event(
            EventKind::StorageCommitted,
            &commitment_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(commitment_id)
    }

    pub fn bind_formal_proof_root(&mut self, mut proof: FormalProofRoot) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "formal_proof_roots",
            self.formal_proof_roots.len(),
            MAX_FORMAL_PROOF_ROOTS,
        )?;
        self.require_manifest_accepts_evidence(&proof.manifest_id)?;
        if proof.proof_id.is_empty() {
            proof.proof_id = stable_id(
                "formal-proof",
                &proof.manifest_id,
                &proof.proof_artifact_root,
                self.counters.formal_proof_roots,
            );
        }
        proof.validate(&self.config)?;
        let manifest = self
            .upgrade_manifests
            .get(&proof.manifest_id)
            .ok_or_else(|| "manifest not found for proof root".to_string())?;
        if manifest.contract_id != proof.contract_id {
            return Err("formal proof root contract mismatch".to_string());
        }
        let proof_id = proof.proof_id.clone();
        let root = proof.record_root();
        self.formal_proof_roots.insert(proof_id.clone(), proof);
        self.counters.formal_proof_roots = self.counters.formal_proof_roots.saturating_add(1);
        self.push_event(
            EventKind::FormalProofRootBound,
            &proof_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(proof_id)
    }

    pub fn submit_pq_quorum(&mut self, mut quorum: PqSignerQuorum) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "pq_signer_quorums",
            self.pq_signer_quorums.len(),
            MAX_PQ_SIGNER_QUORUMS,
        )?;
        self.require_manifest_accepts_evidence(&quorum.manifest_id)?;
        if quorum.quorum_id.is_empty() {
            quorum.quorum_id = stable_id(
                "pq-quorum",
                &quorum.manifest_id,
                &quorum.attestation_root,
                self.counters.pq_signer_quorums,
            );
        }
        let manifest = self
            .upgrade_manifests
            .get(&quorum.manifest_id)
            .ok_or_else(|| "manifest not found for PQ quorum".to_string())?;
        quorum.validate(&self.config, manifest.intent.requires_strong_quorum())?;
        if manifest.contract_id != quorum.contract_id {
            return Err("PQ quorum contract mismatch".to_string());
        }
        let quorum_id = quorum.quorum_id.clone();
        let root = quorum.record_root();
        self.pq_signer_quorums.insert(quorum_id.clone(), quorum);
        self.counters.pq_signer_quorums = self.counters.pq_signer_quorums.saturating_add(1);
        self.push_event(
            EventKind::PqQuorumSubmitted,
            &quorum_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(quorum_id)
    }

    pub fn arm_rollback_window(&mut self, mut rollback: RollbackWindow) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "rollback_windows",
            self.rollback_windows.len(),
            MAX_ROLLBACK_WINDOWS,
        )?;
        self.require_manifest_accepts_evidence(&rollback.manifest_id)?;
        if rollback.rollback_id.is_empty() {
            rollback.rollback_id = stable_id(
                "rollback",
                &rollback.manifest_id,
                &rollback.snapshot_root,
                self.counters.rollback_windows,
            );
        }
        rollback.validate(&self.config)?;
        let manifest = self
            .upgrade_manifests
            .get(&rollback.manifest_id)
            .ok_or_else(|| "manifest not found for rollback window".to_string())?;
        if manifest.contract_id != rollback.contract_id {
            return Err("rollback window contract mismatch".to_string());
        }
        let rollback_id = rollback.rollback_id.clone();
        let root = rollback.record_root();
        self.rollback_windows.insert(rollback_id.clone(), rollback);
        self.counters.rollback_windows = self.counters.rollback_windows.saturating_add(1);
        self.push_event(
            EventKind::RollbackWindowArmed,
            &rollback_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(rollback_id)
    }

    pub fn file_leakage_budget(&mut self, mut budget: LeakageBudget) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "leakage_budgets",
            self.leakage_budgets.len(),
            MAX_LEAKAGE_BUDGETS,
        )?;
        self.require_manifest_accepts_evidence(&budget.manifest_id)?;
        if budget.budget_id.is_empty() {
            budget.budget_id = stable_id(
                "leakage",
                &budget.manifest_id,
                &budget.field_commitment_root,
                self.counters.leakage_budgets,
            );
        }
        budget.validate(&self.config)?;
        let manifest = self
            .upgrade_manifests
            .get(&budget.manifest_id)
            .ok_or_else(|| "manifest not found for leakage budget".to_string())?;
        if manifest.contract_id != budget.contract_id {
            return Err("leakage budget contract mismatch".to_string());
        }
        let budget_id = budget.budget_id.clone();
        let root = budget.record_root();
        self.leakage_budgets.insert(budget_id.clone(), budget);
        self.counters.leakage_budgets = self.counters.leakage_budgets.saturating_add(1);
        self.push_event(
            EventKind::LeakageBudgetFiled,
            &budget_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn submit_review_batch(&mut self, mut batch: ReviewBatch) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "review_batches",
            self.review_batches.len(),
            MAX_REVIEW_BATCHES,
        )?;
        if self.config.require_low_fee_batching_for_public_review
            && batch.max_fee_bps > self.config.max_review_fee_bps
        {
            return Err("public review must use low-fee batch ceiling".to_string());
        }
        if batch.batch_id.is_empty() {
            batch.batch_id = stable_id(
                "review-batch",
                &batch.reviewer_set_root,
                &batch.review_request_root,
                self.counters.review_batches,
            );
        }
        batch.validate(&self.config)?;
        for manifest_id in &batch.manifest_ids {
            self.require_manifest_accepts_evidence(manifest_id)?;
        }
        let batch_id = batch.batch_id.clone();
        let root = batch.record_root();
        self.review_batches.insert(batch_id.clone(), batch);
        self.counters.review_batches = self.counters.review_batches.saturating_add(1);
        self.push_event(
            EventKind::ReviewBatchSubmitted,
            &batch_id,
            &root,
            DEVNET_HEIGHT,
        );
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn approve_manifest_roots_only(
        &mut self,
        manifest_id: &str,
        batch_id: &str,
        emitted_at_height: u64,
    ) -> Result<String> {
        self.emit_public_record(
            manifest_id,
            batch_id,
            AuditDecision::ApprovedWithRollbackWatch,
            emitted_at_height,
        )
    }

    pub fn reject_manifest_roots_only(
        &mut self,
        manifest_id: &str,
        batch_id: &str,
        emitted_at_height: u64,
    ) -> Result<String> {
        self.emit_public_record(
            manifest_id,
            batch_id,
            AuditDecision::Rejected,
            emitted_at_height,
        )
    }

    pub fn emit_public_record(
        &mut self,
        manifest_id: &str,
        batch_id: &str,
        decision: AuditDecision,
        emitted_at_height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        require_capacity(
            "public_audit_records",
            self.public_audit_records.len(),
            MAX_PUBLIC_AUDIT_RECORDS,
        )?;
        let manifest = self
            .upgrade_manifests
            .get(manifest_id)
            .ok_or_else(|| "manifest not found for public audit record".to_string())?;
        let batch = self
            .review_batches
            .get(batch_id)
            .ok_or_else(|| "review batch not found for public audit record".to_string())?;
        if !batch.manifest_ids.iter().any(|id| id == manifest_id) {
            return Err("review batch does not include manifest".to_string());
        }
        let bytecode_root = self.required_manifest_root(
            "bytecode_commitment",
            manifest_id,
            &self.bytecode_commitments,
            |value| value.manifest_id.as_str(),
            |value| value.public_record(),
        )?;
        let storage_root = self.required_manifest_root(
            "storage_commitment",
            manifest_id,
            &self.storage_commitments,
            |value| value.manifest_id.as_str(),
            |value| value.public_record(),
        )?;
        let proof_root = self.required_manifest_root(
            "formal_proof",
            manifest_id,
            &self.formal_proof_roots,
            |value| value.manifest_id.as_str(),
            |value| value.public_record(),
        )?;
        if self.config.require_dual_proof_systems {
            let proof_systems = self
                .formal_proof_roots
                .values()
                .filter(|proof| proof.manifest_id == manifest_id)
                .map(|proof| proof.proof_system)
                .collect::<BTreeSet<_>>();
            if proof_systems.len() < 2 {
                return Err("dual proof systems required for public approval".to_string());
            }
        }
        let quorum_root = self.required_manifest_root(
            "pq_quorum",
            manifest_id,
            &self.pq_signer_quorums,
            |value| value.manifest_id.as_str(),
            |value| value.public_record(),
        )?;
        let rollback_root = self.required_manifest_root(
            "rollback",
            manifest_id,
            &self.rollback_windows,
            |value| value.manifest_id.as_str(),
            |value| value.public_record(),
        )?;
        let leakage_root = self.required_manifest_root(
            "leakage",
            manifest_id,
            &self.leakage_budgets,
            |value| value.manifest_id.as_str(),
            |value| value.public_record(),
        )?;
        let record_id = stable_id(
            "public-record",
            manifest_id,
            decision.public_label(),
            self.counters.public_audit_records,
        );
        let record = PublicAuditRecord {
            record_id: record_id.clone(),
            manifest_id: manifest_id.to_string(),
            contract_id: manifest.contract_id.clone(),
            decision,
            manifest_root: manifest.record_root(),
            bytecode_commitment_root: bytecode_root,
            storage_commitment_root: storage_root,
            formal_proof_root: proof_root,
            pq_quorum_root: quorum_root,
            rollback_root,
            leakage_budget_root: leakage_root,
            review_batch_root: batch.record_root(),
            emitted_at_height,
            expires_at_height: emitted_at_height
                .saturating_add(self.config.public_record_ttl_blocks),
        };
        record.validate()?;
        let root = record.record_root();
        self.public_audit_records.insert(record_id.clone(), record);
        self.counters.public_audit_records = self.counters.public_audit_records.saturating_add(1);
        match decision {
            AuditDecision::Approved | AuditDecision::ApprovedWithRollbackWatch => {
                self.counters.approved_public_records =
                    self.counters.approved_public_records.saturating_add(1);
                if let Some(manifest) = self.upgrade_manifests.get_mut(manifest_id) {
                    manifest.status = ManifestStatus::Approved;
                }
                self.push_event(
                    EventKind::ManifestApproved,
                    manifest_id,
                    &root,
                    emitted_at_height,
                );
            }
            AuditDecision::Rejected | AuditDecision::NeedsMoreProof => {
                self.counters.rejected_public_records =
                    self.counters.rejected_public_records.saturating_add(1);
                if let Some(manifest) = self.upgrade_manifests.get_mut(manifest_id) {
                    manifest.status = ManifestStatus::Rejected;
                }
                self.push_event(
                    EventKind::ManifestRejected,
                    manifest_id,
                    &root,
                    emitted_at_height,
                );
            }
            AuditDecision::Revoked => {
                self.counters.revoked_public_records =
                    self.counters.revoked_public_records.saturating_add(1);
            }
            AuditDecision::Pending => {}
        }
        self.push_event(
            EventKind::PublicRecordEmitted,
            &record_id,
            &root,
            emitted_at_height,
        );
        self.refresh_roots();
        Ok(record_id)
    }

    fn require_manifest_accepts_evidence(&self, manifest_id: &str) -> Result<()> {
        let manifest = self
            .upgrade_manifests
            .get(manifest_id)
            .ok_or_else(|| "manifest not found".to_string())?;
        if !manifest.status.accepts_evidence() {
            return Err("manifest does not accept more audit evidence".to_string());
        }
        Ok(())
    }

    fn required_manifest_root<T, F, G>(
        &self,
        label: &str,
        manifest_id: &str,
        values: &BTreeMap<String, T>,
        manifest_key: F,
        public_record: G,
    ) -> Result<String>
    where
        F: Fn(&T) -> &str,
        G: Fn(&T) -> Value,
    {
        let records = values
            .values()
            .filter(|value| manifest_key(value) == manifest_id)
            .map(public_record)
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Err(format!("{label} root missing for manifest"));
        }
        Ok(merkle_root(
            &format!("UPGRADE-AUDIT-{}-FOR-MANIFEST", label.to_uppercase()),
            &records,
        ))
    }

    fn push_event(&mut self, kind: EventKind, subject_id: &str, subject_root: &str, height: u64) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = stable_id("event", subject_id, subject_root, self.counters.events);
        self.events.insert(
            event_id.clone(),
            RuntimeEvent {
                event_id,
                kind,
                subject_id: subject_id.to_string(),
                subject_root: subject_root.to_string(),
                height,
            },
        );
        self.counters.events = self.counters.events.saturating_add(1);
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn demo() -> Value {
    let mut runtime = devnet();
    let manifest = UpgradeManifest {
        manifest_id: String::new(),
        contract_id: "confidential-dex-vault".to_string(),
        domain: ContractDomain::Dex,
        intent: UpgradeIntent::PrivacyPatch,
        previous_manifest_id: None,
        current_bytecode_root: sample_root("current-bytecode"),
        candidate_bytecode_root: sample_root("candidate-bytecode"),
        current_storage_root: sample_root("current-storage"),
        candidate_storage_root: sample_root("candidate-storage"),
        formal_spec_root: sample_root("formal-spec"),
        invariant_manifest_root: sample_root("invariant-manifest"),
        migration_plan_root: sample_root("migration-plan"),
        disclosure_policy_root: sample_root("disclosure-policy"),
        author: "release-engineering".to_string(),
        proposed_at_height: DEVNET_HEIGHT,
        earliest_activation_height: DEVNET_HEIGHT + DEFAULT_MANIFEST_NOTICE_BLOCKS,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_PUBLIC_RECORD_TTL_BLOCKS,
        status: ManifestStatus::Proposed,
        metadata: json!({"track": "devnet", "risk": "medium"}),
    };
    let manifest_id = runtime.register_manifest(manifest).expect("demo manifest");
    let bytecode_root = runtime
        .upgrade_manifests
        .get(&manifest_id)
        .expect("manifest")
        .candidate_bytecode_root
        .clone();
    let storage_pre_root = runtime
        .upgrade_manifests
        .get(&manifest_id)
        .expect("manifest")
        .current_storage_root
        .clone();
    let storage_post_root = runtime
        .upgrade_manifests
        .get(&manifest_id)
        .expect("manifest")
        .candidate_storage_root
        .clone();
    runtime
        .bind_bytecode_commitment(BytecodeCommitment {
            commitment_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            vm: BytecodeVm::ConfidentialWasm,
            source_tree_root: sample_root("source-tree"),
            build_recipe_root: sample_root("build-recipe"),
            compiler_root: sample_root("compiler"),
            bytecode_root,
            abi_root: sample_root("abi"),
            verifier_key_root: sample_root("verifier-key"),
            reproducibility_bps: DEFAULT_MIN_BYTECODE_REPRODUCIBILITY_BPS,
            pq_build_attestation_root: sample_root("pq-build"),
            submitted_at_height: DEVNET_HEIGHT + 4,
            status: CommitmentStatus::Accepted,
        })
        .expect("demo bytecode");
    runtime
        .bind_storage_commitment(StorageCommitment {
            commitment_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            scope: StorageScope::FullState,
            pre_upgrade_root: storage_pre_root,
            post_upgrade_root: storage_post_root,
            migration_witness_root: sample_root("migration-witness"),
            encrypted_delta_root: sample_root("encrypted-delta"),
            nullifier_preservation_root: sample_root("nullifier-preservation"),
            rollback_snapshot_root: sample_root("rollback-snapshot"),
            covered_slots: 10_000,
            total_slots: 10_000,
            coverage_bps: DEFAULT_MIN_STORAGE_COVERAGE_BPS,
            submitted_at_height: DEVNET_HEIGHT + 5,
            status: CommitmentStatus::Accepted,
        })
        .expect("demo storage");
    let claims = [
        ProofClaim::StateTransitionPreserved,
        ProofClaim::NoSecretDisclosure,
        ProofClaim::RollbackRestoresState,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    runtime
        .bind_formal_proof_root(FormalProofRoot {
            proof_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            proof_system: ProofSystem::Lean,
            claims: claims.clone(),
            theorem_root: sample_root("lean-theorem"),
            proof_artifact_root: sample_root("lean-artifact"),
            verifier_receipt_root: sample_root("lean-verifier"),
            assumption_root: sample_root("lean-assumptions"),
            counterexample_search_root: sample_root("lean-counterexample-search"),
            coverage_bps: DEFAULT_MIN_PROOF_COVERAGE_BPS,
            machine_checked: true,
            reproducible: true,
            open_obligations: 0,
            submitted_at_height: DEVNET_HEIGHT + 6,
        })
        .expect("demo proof one");
    runtime
        .bind_formal_proof_root(FormalProofRoot {
            proof_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            proof_system: ProofSystem::K,
            claims,
            theorem_root: sample_root("k-theorem"),
            proof_artifact_root: sample_root("k-artifact"),
            verifier_receipt_root: sample_root("k-verifier"),
            assumption_root: sample_root("k-assumptions"),
            counterexample_search_root: sample_root("k-counterexample-search"),
            coverage_bps: DEFAULT_MIN_PROOF_COVERAGE_BPS,
            machine_checked: true,
            reproducible: true,
            open_obligations: 0,
            submitted_at_height: DEVNET_HEIGHT + 7,
        })
        .expect("demo proof two");
    runtime
        .submit_pq_quorum(PqSignerQuorum {
            quorum_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            threshold_weight: DEFAULT_STRONG_SIGNER_WEIGHT,
            collected_weight: 90,
            strong_quorum: true,
            attestation_root: sample_root("pq-attestation"),
            signers: vec![
                demo_signer("governance", SignerRole::Governance, 30),
                demo_signer("formal", SignerRole::FormalVerifier, 30),
                demo_signer("privacy", SignerRole::PrivacyAuditor, 30),
            ],
            submitted_at_height: DEVNET_HEIGHT + 8,
        })
        .expect("demo quorum");
    runtime
        .arm_rollback_window(RollbackWindow {
            rollback_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            start_height: DEVNET_HEIGHT + DEFAULT_MANIFEST_NOTICE_BLOCKS,
            end_height: DEVNET_HEIGHT
                + DEFAULT_MANIFEST_NOTICE_BLOCKS
                + DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            finality_lag_blocks: DEFAULT_ROLLBACK_FINALITY_LAG_BLOCKS,
            snapshot_root: sample_root("rollback-snapshot"),
            restore_procedure_root: sample_root("restore-procedure"),
            rehearsal_receipt_root: sample_root("rehearsal"),
            emergency_signer_root: sample_root("emergency-signers"),
            liquidity_impact_limit: 1_000_000,
            status: RollbackStatus::Armed,
        })
        .expect("demo rollback");
    runtime
        .file_leakage_budget(LeakageBudget {
            budget_id: String::new(),
            manifest_id: manifest_id.clone(),
            contract_id: "confidential-dex-vault".to_string(),
            class: LeakageClass::StorageAccessPattern,
            field_commitment_root: sample_root("field-commitment"),
            measured_microbits: 30,
            per_field_limit_microbits: DEFAULT_PER_FIELD_LEAKAGE_BUDGET_MICROBITS,
            per_contract_limit_microbits: DEFAULT_PER_CONTRACT_LEAKAGE_BUDGET_MICROBITS,
            global_epoch_limit_microbits: DEFAULT_GLOBAL_LEAKAGE_BUDGET_MICROBITS,
            mitigation_root: sample_root("mitigation"),
            auditor_receipt_root: sample_root("auditor-receipt"),
            submitted_at_height: DEVNET_HEIGHT + 9,
        })
        .expect("demo leakage");
    let batch_id = runtime
        .submit_review_batch(ReviewBatch {
            batch_id: String::new(),
            manifest_ids: vec![manifest_id.clone()],
            reviewer_set_root: sample_root("reviewer-set"),
            fee_sponsor_root: sample_root("fee-sponsor"),
            review_request_root: sample_root("review-request"),
            batch_receipt_root: sample_root("batch-receipt"),
            opened_at_height: DEVNET_HEIGHT + 10,
            sealed_at_height: DEVNET_HEIGHT + 10 + DEFAULT_REVIEW_BATCH_WINDOW_BLOCKS,
            max_fee_bps: DEFAULT_MAX_REVIEW_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            status: ReviewBatchStatus::Verified,
        })
        .expect("demo batch");
    runtime
        .approve_manifest_roots_only(
            &manifest_id,
            &batch_id,
            DEVNET_HEIGHT + DEFAULT_MANIFEST_NOTICE_BLOCKS,
        )
        .expect("demo public record");
    runtime.public_record()
}

fn map_root<T, F>(label: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values.values().map(public_record).collect::<Vec<_>>();
    merkle_root(&format!("UPGRADE-AUDIT-{}", label.to_uppercase()), &records)
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn stable_id(kind: &str, primary: &str, secondary: &str, sequence: u64) -> String {
    domain_hash(
        "private_l2_pq_confidential_contract_proof_carrying_upgrade_audit_id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(primary),
            HashPart::Str(secondary),
            HashPart::U64(sequence),
        ],
        16,
    )
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "private_l2_pq_confidential_contract_proof_carrying_upgrade_audit_sample",
        &[HashPart::Str(label)],
        32,
    )
}

fn demo_signer(signer_id: &str, role: SignerRole, weight: u64) -> PqSignerAttestation {
    PqSignerAttestation {
        signer_id: signer_id.to_string(),
        role,
        algorithm: PqAlgorithm::HybridMlDsa87SlhDsa,
        public_key_root: sample_root(&format!("{signer_id}-pk")),
        message_root: sample_root(&format!("{signer_id}-message")),
        signature_root: sample_root(&format!("{signer_id}-signature")),
        transcript_root: sample_root(&format!("{signer_id}-transcript")),
        weight,
        non_replayable: true,
    }
}

fn string_values(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect()
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} must be <= {MAX_BPS}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_emits_roots_only_record() {
        let record = demo();
        assert_eq!(record["protocol_version"], PROTOCOL_VERSION);
        assert!(
            record["roots"]["public_audit_record_root"]
                .as_str()
                .unwrap()
                .len()
                >= 64
        );
    }

    #[test]
    fn stable_ids_are_deterministic() {
        assert_eq!(
            stable_id("manifest", "contract", "root", 7),
            stable_id("manifest", "contract", "root", 7)
        );
    }
}
