use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqCircuitGovernanceResult<T> = Result<T, String>;

pub const PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION: &str = "nebula-l2-pq-circuit-governance-v1";
pub const PQ_CIRCUIT_GOVERNANCE_SCHEMA_VERSION: u64 = 1;
pub const PQ_CIRCUIT_GOVERNANCE_HASH_SUITE: &str = "SHAKE256";
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_SECURITY_BITS: u64 = 128;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_DEVNET_HEIGHT: u64 = 384;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_CHAIN_LABEL: &str = "nebula-devnet";
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_SPONSOR_ASSET_ID: &str = "piconero";
pub const PQ_CIRCUIT_GOVERNANCE_ML_DSA_SCHEME: &str = "ML-DSA-65";
pub const PQ_CIRCUIT_GOVERNANCE_SLH_DSA_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_CIRCUIT_GOVERNANCE_HYBRID_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_NOTICE_BLOCKS: u64 = 720;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_ACTIVATION_DELAY_BLOCKS: u64 = 1_440;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 12;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_DEPRECATION_NOTICE_BLOCKS: u64 = 2_880;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIGRATION_WINDOW_BLOCKS: u64 = 4_320;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 20_160;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 1_440;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_SETTLEMENT_GRACE_BLOCKS: u64 = 96;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS: u64 = 6_700;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIN_PQ_SCHEME_COUNT: usize = 2;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIN_AUDIT_COUNT: usize = 2;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_RECURSION_DEPTH: u64 = 5;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_CHILD_PROOFS: u64 = 96;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_PROOF_BYTES: u64 = 96 * 1024;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_VERIFY_MICROS: u64 = 750_000;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_BASE_FEE_PER_MILLION_CYCLES: u64 = 20;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const PQ_CIRCUIT_GOVERNANCE_DEFAULT_PROTOCOL_FEE_BPS: u64 = 250;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_BPS: u64 = 10_000;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_FAMILY_POLICIES: usize = 64;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_VERIFIER_KEYS: usize = 512;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_COMMITTEES: usize = 64;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_CIRCUITS: usize = 512;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_PROPOSALS: usize = 512;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_ATTESTATIONS: usize = 2_048;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_AUDITS: usize = 1_024;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_DEPRECATIONS: usize = 256;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_COMPATIBILITY_MATRICES: usize = 64;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_RECURSIVE_POLICIES: usize = 128;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_SPONSOR_EPOCHS: usize = 256;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_SPONSOR_BUDGETS: usize = 512;
pub const PQ_CIRCUIT_GOVERNANCE_MAX_MIGRATION_RECEIPTS: usize = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCircuitFamily {
    RollupState,
    MoneroBridgeDeposit,
    MoneroBridgeWithdrawal,
    MoneroBridgeFinality,
    ConfidentialAssetTransfer,
    PrivateDexSwap,
    PrivateLending,
    PrivateStablecoin,
    TokenFactory,
    PrivateContractCall,
    FeeSponsorship,
    RecursiveAggregation,
    WatchtowerRecovery,
}

impl PqCircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupState => "rollup_state",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeWithdrawal => "monero_bridge_withdrawal",
            Self::MoneroBridgeFinality => "monero_bridge_finality",
            Self::ConfidentialAssetTransfer => "confidential_asset_transfer",
            Self::PrivateDexSwap => "private_dex_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivateStablecoin => "private_stablecoin",
            Self::TokenFactory => "token_factory",
            Self::PrivateContractCall => "private_contract_call",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::WatchtowerRecovery => "watchtower_recovery",
        }
    }

    pub fn default_circuit_name(self) -> &'static str {
        match self {
            Self::RollupState => "pq_rollup_state_transition_batch",
            Self::MoneroBridgeDeposit => "pq_monero_deposit_membership",
            Self::MoneroBridgeWithdrawal => "pq_monero_withdrawal_authorization",
            Self::MoneroBridgeFinality => "pq_monero_finality_and_reserve_batch",
            Self::ConfidentialAssetTransfer => "pq_confidential_asset_transfer",
            Self::PrivateDexSwap => "pq_private_dex_swap_path",
            Self::PrivateLending => "pq_private_lending_accounting",
            Self::PrivateStablecoin => "pq_private_stablecoin_mint_burn",
            Self::TokenFactory => "pq_private_token_factory",
            Self::PrivateContractCall => "pq_private_contract_execution_frame",
            Self::FeeSponsorship => "pq_low_fee_sponsorship_epoch",
            Self::RecursiveAggregation => "pq_recursive_aggregation_batch",
            Self::WatchtowerRecovery => "pq_watchtower_recovery_fallback",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridgeDeposit
                | Self::MoneroBridgeWithdrawal
                | Self::MoneroBridgeFinality
                | Self::ConfidentialAssetTransfer
                | Self::PrivateDexSwap
                | Self::PrivateLending
                | Self::PrivateStablecoin
                | Self::PrivateContractCall
                | Self::FeeSponsorship
        )
    }

    pub fn monero_bridge_related(self) -> bool {
        matches!(
            self,
            Self::MoneroBridgeDeposit | Self::MoneroBridgeWithdrawal | Self::MoneroBridgeFinality
        )
    }

    pub fn defi_related(self) -> bool {
        matches!(
            self,
            Self::ConfidentialAssetTransfer
                | Self::PrivateDexSwap
                | Self::PrivateLending
                | Self::PrivateStablecoin
                | Self::TokenFactory
                | Self::PrivateContractCall
        )
    }

    pub fn recursive_only(self) -> bool {
        matches!(self, Self::RecursiveAggregation)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqProofSystem {
    ShakePlonk,
    ShakeStark,
    FfriStark,
    FoldingNovaShake,
    Halo2Shake,
    RiscZeroShake,
    NoirShake,
    MoneroBridgeCustom,
}

impl PqProofSystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShakePlonk => "shake_plonk",
            Self::ShakeStark => "shake_stark",
            Self::FfriStark => "ffri_stark",
            Self::FoldingNovaShake => "folding_nova_shake",
            Self::Halo2Shake => "halo2_shake",
            Self::RiscZeroShake => "risc_zero_shake",
            Self::NoirShake => "noir_shake",
            Self::MoneroBridgeCustom => "monero_bridge_custom",
        }
    }

    pub fn is_hash_based(self) -> bool {
        matches!(
            self,
            Self::ShakeStark | Self::FfriStark | Self::RiscZeroShake
        )
    }

    pub fn supports_recursion(self) -> bool {
        matches!(
            self,
            Self::ShakePlonk | Self::FoldingNovaShake | Self::Halo2Shake | Self::RiscZeroShake
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaShake128s,
    SlhDsaShake192s,
    SlhDsaShake256s,
    HybridMlDsa65SlhDsa128s,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
            Self::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            Self::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            Self::HybridMlDsa65SlhDsa128s => PQ_CIRCUIT_GOVERNANCE_HYBRID_SCHEME,
        }
    }

    pub fn is_mldsa(self) -> bool {
        matches!(self, Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87)
    }

    pub fn is_slhdsa(self) -> bool {
        matches!(
            self,
            Self::SlhDsaShake128s | Self::SlhDsaShake192s | Self::SlhDsaShake256s
        )
    }

    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::HybridMlDsa65SlhDsa128s)
    }

    pub fn security_bits(self) -> u64 {
        match self {
            Self::MlDsa44 | Self::SlhDsaShake128s | Self::HybridMlDsa65SlhDsa128s => 128,
            Self::MlDsa65 | Self::SlhDsaShake192s => 192,
            Self::MlDsa87 | Self::SlhDsaShake256s => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqVerifierKeyStatus {
    Candidate,
    Audited,
    Attested,
    Active,
    GraceOnly,
    Deprecated,
    Disabled,
    Revoked,
}

impl PqVerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Audited => "audited",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::GraceOnly => "grace_only",
            Self::Deprecated => "deprecated",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_new_proofs(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn accepts_migration_proofs(self) -> bool {
        matches!(self, Self::Active | Self::GraceOnly | Self::Deprecated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCircuitStatus {
    Draft,
    Candidate,
    Audited,
    Attested,
    Scheduled,
    Active,
    GraceOnly,
    Deprecated,
    EmergencyPaused,
    Disabled,
}

impl PqCircuitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Candidate => "candidate",
            Self::Audited => "audited",
            Self::Attested => "attested",
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::GraceOnly => "grace_only",
            Self::Deprecated => "deprecated",
            Self::EmergencyPaused => "emergency_paused",
            Self::Disabled => "disabled",
        }
    }

    pub fn accepts_new_proofs(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn accepts_migration_proofs(self) -> bool {
        matches!(self, Self::Active | Self::GraceOnly | Self::Deprecated)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCommitteeRole {
    CircuitAuditor,
    VerifierAttester,
    BridgeGuardian,
    RecursiveVerifier,
    SponsorAuditor,
    EmergencyDeprecator,
    MigrationWitness,
}

impl PqCommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CircuitAuditor => "circuit_auditor",
            Self::VerifierAttester => "verifier_attester",
            Self::BridgeGuardian => "bridge_guardian",
            Self::RecursiveVerifier => "recursive_verifier",
            Self::SponsorAuditor => "sponsor_auditor",
            Self::EmergencyDeprecator => "emergency_deprecator",
            Self::MigrationWitness => "migration_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCommitteeStatus {
    Proposed,
    Active,
    Grace,
    Retired,
    Slashed,
    Revoked,
}

impl PqCommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Grace => "grace",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Active | Self::Grace)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationSubjectKind {
    VerifierKey,
    CircuitActivation,
    CircuitAudit,
    RecursiveAggregationPolicy,
    CompatibilityMatrix,
    DeprecationIncident,
    ProofSponsorshipEpoch,
    MigrationReceipt,
}

impl PqAttestationSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifierKey => "verifier_key",
            Self::CircuitActivation => "circuit_activation",
            Self::CircuitAudit => "circuit_audit",
            Self::RecursiveAggregationPolicy => "recursive_aggregation_policy",
            Self::CompatibilityMatrix => "compatibility_matrix",
            Self::DeprecationIncident => "deprecation_incident",
            Self::ProofSponsorshipEpoch => "proof_sponsorship_epoch",
            Self::MigrationReceipt => "migration_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Pending,
    ThresholdMet,
    Superseded,
    Rejected,
    Expired,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ThresholdMet => "threshold_met",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::ThresholdMet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqActivationProposalStatus {
    Draft,
    UnderReview,
    AuditComplete,
    Attested,
    Scheduled,
    Active,
    Rejected,
    Superseded,
    EmergencyPaused,
}

impl PqActivationProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::UnderReview => "under_review",
            Self::AuditComplete => "audit_complete",
            Self::Attested => "attested",
            Self::Scheduled => "scheduled",
            Self::Active => "active",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::EmergencyPaused => "emergency_paused",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::UnderReview | Self::AuditComplete | Self::Attested | Self::Scheduled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuditSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl PqAuditSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn blocks_activation(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuditStatus {
    Scheduled,
    InProgress,
    Passed,
    PassedWithFindings,
    Failed,
    Superseded,
    Expired,
}

impl PqAuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::InProgress => "in_progress",
            Self::Passed => "passed",
            Self::PassedWithFindings => "passed_with_findings",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Passed | Self::PassedWithFindings)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqDeprecationReason {
    Cryptanalysis,
    ImplementationBug,
    SoundnessIssue,
    PrivacyLeakage,
    PerformanceRegression,
    CommitteeCompromise,
    CompatibilityBreak,
    PlannedRotation,
}

impl PqDeprecationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cryptanalysis => "cryptanalysis",
            Self::ImplementationBug => "implementation_bug",
            Self::SoundnessIssue => "soundness_issue",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::PerformanceRegression => "performance_regression",
            Self::CommitteeCompromise => "committee_compromise",
            Self::CompatibilityBreak => "compatibility_break",
            Self::PlannedRotation => "planned_rotation",
        }
    }

    pub fn emergency(self) -> bool {
        !matches!(self, Self::PlannedRotation | Self::PerformanceRegression)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqDeprecationStatus {
    Reported,
    Quarantined,
    MigrationOpen,
    Deprecated,
    Disabled,
    Recovered,
    Rejected,
}

impl PqDeprecationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reported => "reported",
            Self::Quarantined => "quarantined",
            Self::MigrationOpen => "migration_open",
            Self::Deprecated => "deprecated",
            Self::Disabled => "disabled",
            Self::Recovered => "recovered",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCompatibilityStatus {
    Compatible,
    RequiresAdapter,
    MigrationOnly,
    ReadOnly,
    Incompatible,
    Deprecated,
}

impl PqCompatibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::RequiresAdapter => "requires_adapter",
            Self::MigrationOnly => "migration_only",
            Self::ReadOnly => "read_only",
            Self::Incompatible => "incompatible",
            Self::Deprecated => "deprecated",
        }
    }

    pub fn permits_new_flow(self) -> bool {
        matches!(self, Self::Compatible | Self::RequiresAdapter)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRecursiveAggregationMode {
    None,
    FoldedBatch,
    TreeAggregate,
    RollingAccumulator,
    BridgeFinalityAccumulator,
    EmergencyFallback,
}

impl PqRecursiveAggregationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FoldedBatch => "folded_batch",
            Self::TreeAggregate => "tree_aggregate",
            Self::RollingAccumulator => "rolling_accumulator",
            Self::BridgeFinalityAccumulator => "bridge_finality_accumulator",
            Self::EmergencyFallback => "emergency_fallback",
        }
    }

    pub fn recursive(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSponsorshipEpochStatus {
    Upcoming,
    Active,
    Settling,
    Closed,
    Drained,
    Suspended,
}

impl PqSponsorshipEpochStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upcoming => "upcoming",
            Self::Active => "active",
            Self::Settling => "settling",
            Self::Closed => "closed",
            Self::Drained => "drained",
            Self::Suspended => "suspended",
        }
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqMigrationReceiptStatus {
    Pending,
    Submitted,
    Finalized,
    Expired,
    Rejected,
    Superseded,
}

impl PqMigrationReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitGovernanceConfig {
    pub chain_label: String,
    pub security_bits: u64,
    pub hash_suite: String,
    pub fee_asset_id: String,
    pub sponsor_asset_id: String,
    pub notice_blocks: u64,
    pub activation_delay_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub deprecation_notice_blocks: u64,
    pub migration_window_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub audit_ttl_blocks: u64,
    pub sponsor_epoch_blocks: u64,
    pub settlement_grace_blocks: u64,
    pub min_committee_weight_bps: u64,
    pub min_pq_scheme_count: usize,
    pub min_activation_audits: usize,
    pub max_recursion_depth: u64,
    pub max_child_proofs: u64,
    pub max_proof_bytes: u64,
    pub max_verify_micros: u64,
    pub base_fee_per_million_cycles: u64,
    pub sponsor_rebate_bps: u64,
    pub protocol_fee_bps: u64,
    pub require_monero_bridge_compatibility: bool,
    pub require_private_defi_compatibility: bool,
    pub allow_emergency_disable: bool,
}

impl Default for PqCircuitGovernanceConfig {
    fn default() -> Self {
        Self {
            chain_label: PQ_CIRCUIT_GOVERNANCE_DEFAULT_CHAIN_LABEL.to_string(),
            security_bits: PQ_CIRCUIT_GOVERNANCE_DEFAULT_SECURITY_BITS,
            hash_suite: PQ_CIRCUIT_GOVERNANCE_HASH_SUITE.to_string(),
            fee_asset_id: PQ_CIRCUIT_GOVERNANCE_DEFAULT_FEE_ASSET_ID.to_string(),
            sponsor_asset_id: PQ_CIRCUIT_GOVERNANCE_DEFAULT_SPONSOR_ASSET_ID.to_string(),
            notice_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_NOTICE_BLOCKS,
            activation_delay_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_ACTIVATION_DELAY_BLOCKS,
            emergency_delay_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            deprecation_notice_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_DEPRECATION_NOTICE_BLOCKS,
            migration_window_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIGRATION_WINDOW_BLOCKS,
            attestation_ttl_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_ATTESTATION_TTL_BLOCKS,
            audit_ttl_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_AUDIT_TTL_BLOCKS,
            sponsor_epoch_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_SPONSOR_EPOCH_BLOCKS,
            settlement_grace_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_SETTLEMENT_GRACE_BLOCKS,
            min_committee_weight_bps: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIN_COMMITTEE_WEIGHT_BPS,
            min_pq_scheme_count: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIN_PQ_SCHEME_COUNT,
            min_activation_audits: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIN_AUDIT_COUNT,
            max_recursion_depth: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_RECURSION_DEPTH,
            max_child_proofs: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_CHILD_PROOFS,
            max_proof_bytes: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_PROOF_BYTES,
            max_verify_micros: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_VERIFY_MICROS,
            base_fee_per_million_cycles: PQ_CIRCUIT_GOVERNANCE_DEFAULT_BASE_FEE_PER_MILLION_CYCLES,
            sponsor_rebate_bps: PQ_CIRCUIT_GOVERNANCE_DEFAULT_SPONSOR_REBATE_BPS,
            protocol_fee_bps: PQ_CIRCUIT_GOVERNANCE_DEFAULT_PROTOCOL_FEE_BPS,
            require_monero_bridge_compatibility: true,
            require_private_defi_compatibility: true,
            allow_emergency_disable: true,
        }
    }
}

impl PqCircuitGovernanceConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_circuit_governance_config",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "schema_version": PQ_CIRCUIT_GOVERNANCE_SCHEMA_VERSION,
            "chain_label": self.chain_label,
            "security_bits": self.security_bits,
            "hash_suite": self.hash_suite,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_asset_id": self.sponsor_asset_id,
            "notice_blocks": self.notice_blocks,
            "activation_delay_blocks": self.activation_delay_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "deprecation_notice_blocks": self.deprecation_notice_blocks,
            "migration_window_blocks": self.migration_window_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "audit_ttl_blocks": self.audit_ttl_blocks,
            "sponsor_epoch_blocks": self.sponsor_epoch_blocks,
            "settlement_grace_blocks": self.settlement_grace_blocks,
            "min_committee_weight_bps": self.min_committee_weight_bps,
            "min_pq_scheme_count": self.min_pq_scheme_count,
            "min_activation_audits": self.min_activation_audits,
            "max_recursion_depth": self.max_recursion_depth,
            "max_child_proofs": self.max_child_proofs,
            "max_proof_bytes": self.max_proof_bytes,
            "max_verify_micros": self.max_verify_micros,
            "base_fee_per_million_cycles": self.base_fee_per_million_cycles,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "require_monero_bridge_compatibility": self.require_monero_bridge_compatibility,
            "require_private_defi_compatibility": self.require_private_defi_compatibility,
            "allow_emergency_disable": self.allow_emergency_disable,
        })
    }

    pub fn state_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-CIRCUIT-GOVERNANCE-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("chain label", &self.chain_label)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_non_empty("sponsor asset id", &self.sponsor_asset_id)?;
        if self.security_bits < 128 {
            return Err("pq circuit governance security bits below 128".to_string());
        }
        validate_bps("min committee weight", self.min_committee_weight_bps)?;
        validate_bps("sponsor rebate", self.sponsor_rebate_bps)?;
        validate_bps("protocol fee", self.protocol_fee_bps)?;
        if self.min_committee_weight_bps == 0 {
            return Err("min committee weight must be non-zero".to_string());
        }
        if self.min_pq_scheme_count == 0 {
            return Err("min pq scheme count must be non-zero".to_string());
        }
        if self.min_activation_audits == 0 {
            return Err("min activation audits must be non-zero".to_string());
        }
        if self.activation_delay_blocks < self.notice_blocks {
            return Err("activation delay must cover notice window".to_string());
        }
        if self.deprecation_notice_blocks == 0 || self.migration_window_blocks == 0 {
            return Err("deprecation and migration windows must be non-zero".to_string());
        }
        if self.max_recursion_depth == 0 || self.max_child_proofs == 0 {
            return Err("recursive proof limits must be non-zero".to_string());
        }
        if self.max_verify_micros == 0 || self.max_proof_bytes == 0 {
            return Err("proof byte and verifier time limits must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitFamilyPolicy {
    pub family: PqCircuitFamily,
    pub min_security_bits: u64,
    pub allowed_proof_systems: Vec<PqProofSystem>,
    pub allowed_signature_schemes: Vec<PqSignatureScheme>,
    pub require_ml_dsa_attestation: bool,
    pub require_slh_dsa_attestation: bool,
    pub require_recursive_wrapper: bool,
    pub require_monero_view_key_safety: bool,
    pub require_private_state_compatibility: bool,
    pub max_activation_delay_blocks: u64,
    pub max_migration_window_blocks: u64,
    pub max_verify_micros: u64,
    pub max_proof_bytes: u64,
    pub fee_weight: u64,
    pub notes_root: String,
}

impl PqCircuitFamilyPolicy {
    pub fn new(
        family: PqCircuitFamily,
        allowed_proof_systems: Vec<PqProofSystem>,
        allowed_signature_schemes: Vec<PqSignatureScheme>,
        notes_root: impl Into<String>,
    ) -> PqCircuitGovernanceResult<Self> {
        let policy = Self {
            family,
            min_security_bits: if family.privacy_sensitive() { 192 } else { 128 },
            allowed_proof_systems,
            allowed_signature_schemes,
            require_ml_dsa_attestation: true,
            require_slh_dsa_attestation: family.privacy_sensitive() || family.recursive_only(),
            require_recursive_wrapper: family.monero_bridge_related() || family.recursive_only(),
            require_monero_view_key_safety: family.monero_bridge_related(),
            require_private_state_compatibility: family.privacy_sensitive()
                || family.defi_related(),
            max_activation_delay_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_ACTIVATION_DELAY_BLOCKS * 4,
            max_migration_window_blocks: PQ_CIRCUIT_GOVERNANCE_DEFAULT_MIGRATION_WINDOW_BLOCKS * 2,
            max_verify_micros: if family.recursive_only() {
                1_500_000
            } else {
                PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_VERIFY_MICROS
            },
            max_proof_bytes: if family.recursive_only() {
                192 * 1024
            } else {
                PQ_CIRCUIT_GOVERNANCE_DEFAULT_MAX_PROOF_BYTES
            },
            fee_weight: if family.monero_bridge_related() {
                80
            } else {
                100
            },
            notes_root: notes_root.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_circuit_family_policy",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "family": self.family.as_str(),
            "min_security_bits": self.min_security_bits,
            "allowed_proof_systems": self.allowed_proof_systems.iter().map(|system| system.as_str()).collect::<Vec<_>>(),
            "allowed_signature_schemes": self.allowed_signature_schemes.iter().map(|scheme| scheme.as_str()).collect::<Vec<_>>(),
            "require_ml_dsa_attestation": self.require_ml_dsa_attestation,
            "require_slh_dsa_attestation": self.require_slh_dsa_attestation,
            "require_recursive_wrapper": self.require_recursive_wrapper,
            "require_monero_view_key_safety": self.require_monero_view_key_safety,
            "require_private_state_compatibility": self.require_private_state_compatibility,
            "max_activation_delay_blocks": self.max_activation_delay_blocks,
            "max_migration_window_blocks": self.max_migration_window_blocks,
            "max_verify_micros": self.max_verify_micros,
            "max_proof_bytes": self.max_proof_bytes,
            "fee_weight": self.fee_weight,
            "notes_root": self.notes_root,
        })
    }

    pub fn policy_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-CIRCUIT-FAMILY-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("family policy notes root", &self.notes_root)?;
        if self.min_security_bits < 128 {
            return Err("family policy security bits below 128".to_string());
        }
        if self.allowed_proof_systems.is_empty() {
            return Err("family policy must allow at least one proof system".to_string());
        }
        if self.allowed_signature_schemes.is_empty() {
            return Err("family policy must allow at least one signature scheme".to_string());
        }
        if self.require_ml_dsa_attestation
            && !self
                .allowed_signature_schemes
                .iter()
                .any(|scheme| scheme.is_mldsa())
        {
            return Err("family policy requires ML-DSA but does not allow it".to_string());
        }
        if self.require_slh_dsa_attestation
            && !self
                .allowed_signature_schemes
                .iter()
                .any(|scheme| scheme.is_slhdsa() || scheme.is_hybrid())
        {
            return Err("family policy requires SLH-DSA but does not allow it".to_string());
        }
        if self.max_activation_delay_blocks == 0 || self.max_migration_window_blocks == 0 {
            return Err("family policy windows must be non-zero".to_string());
        }
        if self.max_verify_micros == 0 || self.max_proof_bytes == 0 {
            return Err("family policy proof limits must be non-zero".to_string());
        }
        if self.fee_weight == 0 {
            return Err("family policy fee weight must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierKeyRecord {
    pub key_id: String,
    pub family: PqCircuitFamily,
    pub proof_system: PqProofSystem,
    pub key_version: u64,
    pub verifying_key_root: String,
    pub constraint_system_root: String,
    pub parameters_root: String,
    pub transcript_domain_root: String,
    pub recursion_vk_root: Option<String>,
    pub metadata_root: String,
    pub security_bits: u64,
    pub max_proof_bytes: u64,
    pub max_verify_micros: u64,
    pub activated_at_height: Option<u64>,
    pub expires_at_height: Option<u64>,
    pub status: PqVerifierKeyStatus,
}

impl PqVerifierKeyRecord {
    pub fn new(
        family: PqCircuitFamily,
        proof_system: PqProofSystem,
        key_version: u64,
        verifying_key_root: impl Into<String>,
        constraint_system_root: impl Into<String>,
        parameters_root: impl Into<String>,
        transcript_domain_root: impl Into<String>,
        recursion_vk_root: Option<String>,
        metadata_root: impl Into<String>,
        security_bits: u64,
        max_proof_bytes: u64,
        max_verify_micros: u64,
        activated_at_height: Option<u64>,
        expires_at_height: Option<u64>,
        status: PqVerifierKeyStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let verifying_key_root = verifying_key_root.into();
        let constraint_system_root = constraint_system_root.into();
        let parameters_root = parameters_root.into();
        let transcript_domain_root = transcript_domain_root.into();
        let metadata_root = metadata_root.into();
        let key_id = pq_circuit_governance_verifier_key_id(
            family,
            proof_system,
            key_version,
            &verifying_key_root,
            &constraint_system_root,
            &parameters_root,
        );
        let record = Self {
            key_id,
            family,
            proof_system,
            key_version,
            verifying_key_root,
            constraint_system_root,
            parameters_root,
            transcript_domain_root,
            recursion_vk_root,
            metadata_root,
            security_bits,
            max_proof_bytes,
            max_verify_micros,
            activated_at_height,
            expires_at_height,
            status,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_key_record",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "family": self.family.as_str(),
            "proof_system": self.proof_system.as_str(),
            "key_version": self.key_version,
            "verifying_key_root": self.verifying_key_root,
            "constraint_system_root": self.constraint_system_root,
            "parameters_root": self.parameters_root,
            "transcript_domain_root": self.transcript_domain_root,
            "recursion_vk_root": self.recursion_vk_root,
            "metadata_root": self.metadata_root,
            "security_bits": self.security_bits,
            "max_proof_bytes": self.max_proof_bytes,
            "max_verify_micros": self.max_verify_micros,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "accepts_new_proofs": self.status.accepts_new_proofs(),
            "accepts_migration_proofs": self.status.accepts_migration_proofs(),
        })
    }

    pub fn key_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-VERIFIER-KEY", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("verifier key id", &self.key_id)?;
        require_non_empty("verifying key root", &self.verifying_key_root)?;
        require_non_empty("constraint system root", &self.constraint_system_root)?;
        require_non_empty("parameters root", &self.parameters_root)?;
        require_non_empty("transcript domain root", &self.transcript_domain_root)?;
        require_non_empty("metadata root", &self.metadata_root)?;
        if self.security_bits < 128 {
            return Err("verifier key security bits below 128".to_string());
        }
        if self.max_proof_bytes == 0 || self.max_verify_micros == 0 {
            return Err("verifier key proof limits must be non-zero".to_string());
        }
        if let (Some(activated), Some(expires)) = (self.activated_at_height, self.expires_at_height)
        {
            if expires <= activated {
                return Err("verifier key expiry must be after activation".to_string());
            }
        }
        if self.proof_system.supports_recursion() && self.recursion_vk_root.is_none() {
            return Err(
                "recursive-capable verifier key must declare recursion vk root".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitDescriptor {
    pub circuit_id: String,
    pub family: PqCircuitFamily,
    pub circuit_name: String,
    pub circuit_version: u64,
    pub proof_system: PqProofSystem,
    pub verifier_key_id: String,
    pub previous_circuit_id: Option<String>,
    pub replacement_circuit_id: Option<String>,
    pub public_input_schema_root: String,
    pub private_witness_schema_root: String,
    pub monero_compatibility_root: Option<String>,
    pub defi_compatibility_root: Option<String>,
    pub recursive_policy_id: Option<String>,
    pub audit_bundle_root: String,
    pub activation_proposal_id: Option<String>,
    pub activation_height: Option<u64>,
    pub grace_until_height: Option<u64>,
    pub status: PqCircuitStatus,
    pub low_fee_eligible: bool,
    pub metadata: BTreeMap<String, String>,
}

impl PqCircuitDescriptor {
    pub fn new(
        family: PqCircuitFamily,
        circuit_name: impl Into<String>,
        circuit_version: u64,
        proof_system: PqProofSystem,
        verifier_key_id: impl Into<String>,
        previous_circuit_id: Option<String>,
        public_input_schema_root: impl Into<String>,
        private_witness_schema_root: impl Into<String>,
        monero_compatibility_root: Option<String>,
        defi_compatibility_root: Option<String>,
        recursive_policy_id: Option<String>,
        audit_bundle_root: impl Into<String>,
        activation_proposal_id: Option<String>,
        activation_height: Option<u64>,
        grace_until_height: Option<u64>,
        status: PqCircuitStatus,
        low_fee_eligible: bool,
        metadata: BTreeMap<String, String>,
    ) -> PqCircuitGovernanceResult<Self> {
        let circuit_name = circuit_name.into();
        let verifier_key_id = verifier_key_id.into();
        let public_input_schema_root = public_input_schema_root.into();
        let private_witness_schema_root = private_witness_schema_root.into();
        let audit_bundle_root = audit_bundle_root.into();
        let circuit_id = pq_circuit_governance_circuit_id(
            family,
            &circuit_name,
            circuit_version,
            proof_system,
            &verifier_key_id,
        );
        let descriptor = Self {
            circuit_id,
            family,
            circuit_name,
            circuit_version,
            proof_system,
            verifier_key_id,
            previous_circuit_id,
            replacement_circuit_id: None,
            public_input_schema_root,
            private_witness_schema_root,
            monero_compatibility_root,
            defi_compatibility_root,
            recursive_policy_id,
            audit_bundle_root,
            activation_proposal_id,
            activation_height,
            grace_until_height,
            status,
            low_fee_eligible,
            metadata,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_circuit_descriptor",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "circuit_id": self.circuit_id,
            "family": self.family.as_str(),
            "circuit_name": self.circuit_name,
            "circuit_version": self.circuit_version,
            "proof_system": self.proof_system.as_str(),
            "verifier_key_id": self.verifier_key_id,
            "previous_circuit_id": self.previous_circuit_id,
            "replacement_circuit_id": self.replacement_circuit_id,
            "public_input_schema_root": self.public_input_schema_root,
            "private_witness_schema_root": self.private_witness_schema_root,
            "monero_compatibility_root": self.monero_compatibility_root,
            "defi_compatibility_root": self.defi_compatibility_root,
            "recursive_policy_id": self.recursive_policy_id,
            "audit_bundle_root": self.audit_bundle_root,
            "activation_proposal_id": self.activation_proposal_id,
            "activation_height": self.activation_height,
            "grace_until_height": self.grace_until_height,
            "status": self.status.as_str(),
            "low_fee_eligible": self.low_fee_eligible,
            "metadata": self.metadata,
            "accepts_new_proofs": self.status.accepts_new_proofs(),
            "accepts_migration_proofs": self.status.accepts_migration_proofs(),
        })
    }

    pub fn circuit_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-CIRCUIT-DESCRIPTOR", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("circuit id", &self.circuit_id)?;
        require_non_empty("circuit name", &self.circuit_name)?;
        require_non_empty("verifier key id", &self.verifier_key_id)?;
        require_non_empty("public input schema root", &self.public_input_schema_root)?;
        require_non_empty(
            "private witness schema root",
            &self.private_witness_schema_root,
        )?;
        require_non_empty("audit bundle root", &self.audit_bundle_root)?;
        if self.circuit_version == 0 {
            return Err("circuit version must be non-zero".to_string());
        }
        if self.family.monero_bridge_related() && self.monero_compatibility_root.is_none() {
            return Err("monero bridge circuit missing monero compatibility root".to_string());
        }
        if self.family.defi_related() && self.defi_compatibility_root.is_none() {
            return Err("private defi circuit missing defi compatibility root".to_string());
        }
        if self.family.recursive_only() && self.recursive_policy_id.is_none() {
            return Err("recursive aggregation circuit missing recursive policy".to_string());
        }
        if let (Some(activation), Some(grace_until)) =
            (self.activation_height, self.grace_until_height)
        {
            if grace_until <= activation {
                return Err("circuit grace window must end after activation".to_string());
            }
        }
        if self.status.accepts_new_proofs() && self.activation_height.is_none() {
            return Err("active circuit must have activation height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierCommitteeMember {
    pub member_id: String,
    pub operator_label: String,
    pub role: PqCommitteeRole,
    pub weight: u64,
    pub ml_dsa_public_key_root: String,
    pub slh_dsa_public_key_root: String,
    pub contact_commitment_root: String,
    pub joined_at_height: u64,
    pub retired_at_height: Option<u64>,
}

impl PqVerifierCommitteeMember {
    pub fn new(
        operator_label: impl Into<String>,
        role: PqCommitteeRole,
        weight: u64,
        ml_dsa_public_key_root: impl Into<String>,
        slh_dsa_public_key_root: impl Into<String>,
        contact_commitment_root: impl Into<String>,
        joined_at_height: u64,
    ) -> PqCircuitGovernanceResult<Self> {
        let operator_label = operator_label.into();
        let ml_dsa_public_key_root = ml_dsa_public_key_root.into();
        let slh_dsa_public_key_root = slh_dsa_public_key_root.into();
        let contact_commitment_root = contact_commitment_root.into();
        let member_id = pq_circuit_governance_member_id(
            &operator_label,
            role,
            &ml_dsa_public_key_root,
            &slh_dsa_public_key_root,
            joined_at_height,
        );
        let member = Self {
            member_id,
            operator_label,
            role,
            weight,
            ml_dsa_public_key_root,
            slh_dsa_public_key_root,
            contact_commitment_root,
            joined_at_height,
            retired_at_height: None,
        };
        member.validate()?;
        Ok(member)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_committee_member",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "role": self.role.as_str(),
            "weight": self.weight,
            "ml_dsa_public_key_root": self.ml_dsa_public_key_root,
            "slh_dsa_public_key_root": self.slh_dsa_public_key_root,
            "contact_commitment_root": self.contact_commitment_root,
            "joined_at_height": self.joined_at_height,
            "retired_at_height": self.retired_at_height,
        })
    }

    pub fn member_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-VERIFIER-COMMITTEE-MEMBER", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("committee member id", &self.member_id)?;
        require_non_empty("committee member operator label", &self.operator_label)?;
        require_non_empty(
            "committee member ML-DSA key root",
            &self.ml_dsa_public_key_root,
        )?;
        require_non_empty(
            "committee member SLH-DSA key root",
            &self.slh_dsa_public_key_root,
        )?;
        require_non_empty(
            "committee member contact commitment root",
            &self.contact_commitment_root,
        )?;
        if self.weight == 0 {
            return Err("committee member weight must be non-zero".to_string());
        }
        if let Some(retired) = self.retired_at_height {
            if retired <= self.joined_at_height {
                return Err("committee member retirement must be after join".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierCommittee {
    pub committee_id: String,
    pub label: String,
    pub roles: Vec<PqCommitteeRole>,
    pub members: Vec<PqVerifierCommitteeMember>,
    pub threshold_weight_bps: u64,
    pub min_scheme_count: usize,
    pub valid_from_height: u64,
    pub valid_until_height: Option<u64>,
    pub status: PqCommitteeStatus,
    pub emergency_guardian: bool,
}

impl PqVerifierCommittee {
    pub fn new(
        label: impl Into<String>,
        roles: Vec<PqCommitteeRole>,
        members: Vec<PqVerifierCommitteeMember>,
        threshold_weight_bps: u64,
        min_scheme_count: usize,
        valid_from_height: u64,
        valid_until_height: Option<u64>,
        status: PqCommitteeStatus,
        emergency_guardian: bool,
    ) -> PqCircuitGovernanceResult<Self> {
        let label = label.into();
        let member_root = merkle_root(
            "PQ-VERIFIER-COMMITTEE-MEMBER-ID",
            &members
                .iter()
                .map(|member| json!(member.member_id))
                .collect::<Vec<_>>(),
        );
        let role_root = merkle_root(
            "PQ-VERIFIER-COMMITTEE-ROLE",
            &roles
                .iter()
                .map(|role| json!(role.as_str()))
                .collect::<Vec<_>>(),
        );
        let committee_id =
            pq_circuit_governance_committee_id(&label, &member_root, &role_root, valid_from_height);
        let committee = Self {
            committee_id,
            label,
            roles,
            members,
            threshold_weight_bps,
            min_scheme_count,
            valid_from_height,
            valid_until_height,
            status,
            emergency_guardian,
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn total_weight(&self) -> u64 {
        self.members.iter().map(|member| member.weight).sum()
    }

    pub fn member_ids(&self) -> BTreeSet<String> {
        self.members
            .iter()
            .map(|member| member.member_id.clone())
            .collect()
    }

    pub fn active_at_height(&self, height: u64) -> bool {
        height >= self.valid_from_height
            && self
                .valid_until_height
                .map(|until| height <= until)
                .unwrap_or(true)
            && self.status.accepts_attestations()
    }

    pub fn member_root(&self) -> String {
        merkle_root(
            "PQ-VERIFIER-COMMITTEE-MEMBER",
            &self
                .members
                .iter()
                .map(PqVerifierCommitteeMember::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_committee",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "label": self.label,
            "roles": self.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "member_root": self.member_root(),
            "member_count": self.members.len(),
            "total_weight": self.total_weight(),
            "threshold_weight_bps": self.threshold_weight_bps,
            "min_scheme_count": self.min_scheme_count,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "status": self.status.as_str(),
            "emergency_guardian": self.emergency_guardian,
        })
    }

    pub fn committee_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-VERIFIER-COMMITTEE", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("committee id", &self.committee_id)?;
        require_non_empty("committee label", &self.label)?;
        validate_bps("committee threshold weight", self.threshold_weight_bps)?;
        if self.roles.is_empty() {
            return Err("committee must carry at least one role".to_string());
        }
        if self.members.is_empty() {
            return Err("committee must have at least one member".to_string());
        }
        if self.min_scheme_count == 0 {
            return Err("committee min scheme count must be non-zero".to_string());
        }
        let mut ids = BTreeSet::new();
        for member in &self.members {
            member.validate()?;
            if !ids.insert(member.member_id.clone()) {
                return Err("committee contains duplicate member id".to_string());
            }
        }
        if self.total_weight() == 0 {
            return Err("committee total weight must be non-zero".to_string());
        }
        if let Some(valid_until) = self.valid_until_height {
            if valid_until <= self.valid_from_height {
                return Err("committee valid-until must be after valid-from".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCommitteeSignatureShare {
    pub share_id: String,
    pub member_id: String,
    pub scheme: PqSignatureScheme,
    pub signed_subject_root: String,
    pub signature_root: String,
    pub observed_at_height: u64,
}

impl PqCommitteeSignatureShare {
    pub fn new(
        member_id: impl Into<String>,
        scheme: PqSignatureScheme,
        signed_subject_root: impl Into<String>,
        signature_root: impl Into<String>,
        observed_at_height: u64,
    ) -> PqCircuitGovernanceResult<Self> {
        let member_id = member_id.into();
        let signed_subject_root = signed_subject_root.into();
        let signature_root = signature_root.into();
        let share_id = pq_circuit_governance_signature_share_id(
            &member_id,
            scheme,
            &signed_subject_root,
            &signature_root,
            observed_at_height,
        );
        let share = Self {
            share_id,
            member_id,
            scheme,
            signed_subject_root,
            signature_root,
            observed_at_height,
        };
        share.validate()?;
        Ok(share)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_committee_signature_share",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "share_id": self.share_id,
            "member_id": self.member_id,
            "scheme": self.scheme.as_str(),
            "signed_subject_root": self.signed_subject_root,
            "signature_root": self.signature_root,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn share_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-COMMITTEE-SIGNATURE-SHARE", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("signature share id", &self.share_id)?;
        require_non_empty("signature share member id", &self.member_id)?;
        require_non_empty("signature share subject root", &self.signed_subject_root)?;
        require_non_empty("signature share signature root", &self.signature_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqVerifierAttestation {
    pub attestation_id: String,
    pub subject_kind: PqAttestationSubjectKind,
    pub subject_id: String,
    pub subject_root: String,
    pub committee_id: String,
    pub committee_root: String,
    pub required_weight_bps: u64,
    pub observed_weight_bps: u64,
    pub required_scheme_count: usize,
    pub shares: Vec<PqCommitteeSignatureShare>,
    pub aggregate_signature_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqAttestationStatus,
}

impl PqVerifierAttestation {
    pub fn new(
        subject_kind: PqAttestationSubjectKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        committee_id: impl Into<String>,
        committee_root: impl Into<String>,
        required_weight_bps: u64,
        observed_weight_bps: u64,
        required_scheme_count: usize,
        shares: Vec<PqCommitteeSignatureShare>,
        aggregate_signature_root: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
        status: PqAttestationStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let committee_id = committee_id.into();
        let committee_root = committee_root.into();
        let aggregate_signature_root = aggregate_signature_root.into();
        let share_root = merkle_root(
            "PQ-VERIFIER-ATTESTATION-SHARE-ID",
            &shares
                .iter()
                .map(|share| json!(share.share_id))
                .collect::<Vec<_>>(),
        );
        let attestation_id = pq_circuit_governance_attestation_id(
            subject_kind,
            &subject_id,
            &subject_root,
            &committee_id,
            &share_root,
            created_at_height,
        );
        let attestation = Self {
            attestation_id,
            subject_kind,
            subject_id,
            subject_root,
            committee_id,
            committee_root,
            required_weight_bps,
            observed_weight_bps,
            required_scheme_count,
            shares,
            aggregate_signature_root,
            created_at_height,
            expires_at_height,
            status,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn share_root(&self) -> String {
        merkle_root(
            "PQ-VERIFIER-ATTESTATION-SHARE",
            &self
                .shares
                .iter()
                .map(PqCommitteeSignatureShare::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn scheme_count(&self) -> usize {
        self.shares
            .iter()
            .map(|share| share.scheme)
            .collect::<BTreeSet<_>>()
            .len()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_verifier_attestation",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "committee_id": self.committee_id,
            "committee_root": self.committee_root,
            "required_weight_bps": self.required_weight_bps,
            "observed_weight_bps": self.observed_weight_bps,
            "required_scheme_count": self.required_scheme_count,
            "share_root": self.share_root(),
            "share_count": self.shares.len(),
            "scheme_count": self.scheme_count(),
            "aggregate_signature_root": self.aggregate_signature_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "usable": self.status.usable(),
        })
    }

    pub fn attestation_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-VERIFIER-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("attestation id", &self.attestation_id)?;
        require_non_empty("attestation subject id", &self.subject_id)?;
        require_non_empty("attestation subject root", &self.subject_root)?;
        require_non_empty("attestation committee id", &self.committee_id)?;
        require_non_empty("attestation committee root", &self.committee_root)?;
        require_non_empty(
            "attestation aggregate signature root",
            &self.aggregate_signature_root,
        )?;
        validate_bps("attestation required weight", self.required_weight_bps)?;
        validate_bps("attestation observed weight", self.observed_weight_bps)?;
        if self.required_weight_bps == 0 || self.required_scheme_count == 0 {
            return Err("attestation threshold must be non-zero".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("attestation expiry must be after creation".to_string());
        }
        if self.status.usable() && self.observed_weight_bps < self.required_weight_bps {
            return Err("usable attestation below required weight".to_string());
        }
        if self.status.usable() && self.scheme_count() < self.required_scheme_count {
            return Err("usable attestation below required scheme count".to_string());
        }
        let mut seen = BTreeSet::new();
        for share in &self.shares {
            share.validate()?;
            if share.signed_subject_root != self.subject_root {
                return Err("attestation share signs wrong subject root".to_string());
            }
            if !seen.insert(share.share_id.clone()) {
                return Err("attestation contains duplicate signature share".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqActivationProposal {
    pub proposal_id: String,
    pub circuit_id: String,
    pub family: PqCircuitFamily,
    pub verifier_key_id: String,
    pub proposer_commitment_root: String,
    pub replacement_for: Option<String>,
    pub activation_height: u64,
    pub grace_until_height: u64,
    pub rollback_circuit_id: Option<String>,
    pub migration_plan_root: String,
    pub low_fee_sponsorship_required: bool,
    pub monero_bridge_impact_root: Option<String>,
    pub private_defi_impact_root: Option<String>,
    pub recursive_policy_id: Option<String>,
    pub audit_roots: Vec<String>,
    pub attestation_roots: Vec<String>,
    pub created_at_height: u64,
    pub status: PqActivationProposalStatus,
}

impl PqActivationProposal {
    pub fn new(
        circuit_id: impl Into<String>,
        family: PqCircuitFamily,
        verifier_key_id: impl Into<String>,
        proposer_commitment_root: impl Into<String>,
        replacement_for: Option<String>,
        activation_height: u64,
        grace_until_height: u64,
        rollback_circuit_id: Option<String>,
        migration_plan_root: impl Into<String>,
        low_fee_sponsorship_required: bool,
        monero_bridge_impact_root: Option<String>,
        private_defi_impact_root: Option<String>,
        recursive_policy_id: Option<String>,
        audit_roots: Vec<String>,
        attestation_roots: Vec<String>,
        created_at_height: u64,
        status: PqActivationProposalStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let circuit_id = circuit_id.into();
        let verifier_key_id = verifier_key_id.into();
        let proposer_commitment_root = proposer_commitment_root.into();
        let migration_plan_root = migration_plan_root.into();
        let audit_root = merkle_root(
            "PQ-ACTIVATION-PROPOSAL-AUDIT-ROOT",
            &audit_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PQ-ACTIVATION-PROPOSAL-ATTESTATION-ROOT",
            &attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        );
        let proposal_id = pq_circuit_governance_activation_proposal_id(
            &circuit_id,
            family,
            &verifier_key_id,
            &audit_root,
            &attestation_root,
            activation_height,
        );
        let proposal = Self {
            proposal_id,
            circuit_id,
            family,
            verifier_key_id,
            proposer_commitment_root,
            replacement_for,
            activation_height,
            grace_until_height,
            rollback_circuit_id,
            migration_plan_root,
            low_fee_sponsorship_required,
            monero_bridge_impact_root,
            private_defi_impact_root,
            recursive_policy_id,
            audit_roots,
            attestation_roots,
            created_at_height,
            status,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn audit_root(&self) -> String {
        merkle_root(
            "PQ-ACTIVATION-PROPOSAL-AUDIT",
            &self
                .audit_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "PQ-ACTIVATION-PROPOSAL-ATTESTATION",
            &self
                .attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_activation_proposal",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "proposal_id": self.proposal_id,
            "circuit_id": self.circuit_id,
            "family": self.family.as_str(),
            "verifier_key_id": self.verifier_key_id,
            "proposer_commitment_root": self.proposer_commitment_root,
            "replacement_for": self.replacement_for,
            "activation_height": self.activation_height,
            "grace_until_height": self.grace_until_height,
            "rollback_circuit_id": self.rollback_circuit_id,
            "migration_plan_root": self.migration_plan_root,
            "low_fee_sponsorship_required": self.low_fee_sponsorship_required,
            "monero_bridge_impact_root": self.monero_bridge_impact_root,
            "private_defi_impact_root": self.private_defi_impact_root,
            "recursive_policy_id": self.recursive_policy_id,
            "audit_root": self.audit_root(),
            "audit_count": self.audit_roots.len(),
            "attestation_root": self.attestation_root(),
            "attestation_count": self.attestation_roots.len(),
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn proposal_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-ACTIVATION-PROPOSAL", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("activation proposal id", &self.proposal_id)?;
        require_non_empty("activation proposal circuit id", &self.circuit_id)?;
        require_non_empty("activation proposal verifier key id", &self.verifier_key_id)?;
        require_non_empty(
            "activation proposal proposer commitment root",
            &self.proposer_commitment_root,
        )?;
        require_non_empty(
            "activation proposal migration plan root",
            &self.migration_plan_root,
        )?;
        if self.activation_height <= self.created_at_height {
            return Err("activation proposal activation must be after creation".to_string());
        }
        if self.grace_until_height <= self.activation_height {
            return Err("activation proposal grace window must end after activation".to_string());
        }
        if self.family.monero_bridge_related() && self.monero_bridge_impact_root.is_none() {
            return Err("monero bridge activation proposal missing impact root".to_string());
        }
        if self.family.defi_related() && self.private_defi_impact_root.is_none() {
            return Err("private defi activation proposal missing impact root".to_string());
        }
        if self.family.recursive_only() && self.recursive_policy_id.is_none() {
            return Err("recursive activation proposal missing recursive policy".to_string());
        }
        for root in &self.audit_roots {
            require_non_empty("activation proposal audit root", root)?;
        }
        for root in &self.attestation_roots {
            require_non_empty("activation proposal attestation root", root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitAudit {
    pub audit_id: String,
    pub circuit_id: String,
    pub verifier_key_id: String,
    pub auditor_commitment_root: String,
    pub audit_report_root: String,
    pub finding_root: String,
    pub maximum_severity: PqAuditSeverity,
    pub status: PqAuditStatus,
    pub completed_at_height: u64,
    pub expires_at_height: u64,
    pub reproducible_build_root: String,
    pub fuzz_corpus_root: String,
    pub side_channel_review_root: String,
    pub monero_privacy_review_root: Option<String>,
    pub defi_compatibility_review_root: Option<String>,
}

impl PqCircuitAudit {
    pub fn new(
        circuit_id: impl Into<String>,
        verifier_key_id: impl Into<String>,
        auditor_commitment_root: impl Into<String>,
        audit_report_root: impl Into<String>,
        finding_root: impl Into<String>,
        maximum_severity: PqAuditSeverity,
        status: PqAuditStatus,
        completed_at_height: u64,
        expires_at_height: u64,
        reproducible_build_root: impl Into<String>,
        fuzz_corpus_root: impl Into<String>,
        side_channel_review_root: impl Into<String>,
        monero_privacy_review_root: Option<String>,
        defi_compatibility_review_root: Option<String>,
    ) -> PqCircuitGovernanceResult<Self> {
        let circuit_id = circuit_id.into();
        let verifier_key_id = verifier_key_id.into();
        let auditor_commitment_root = auditor_commitment_root.into();
        let audit_report_root = audit_report_root.into();
        let finding_root = finding_root.into();
        let reproducible_build_root = reproducible_build_root.into();
        let fuzz_corpus_root = fuzz_corpus_root.into();
        let side_channel_review_root = side_channel_review_root.into();
        let audit_id = pq_circuit_governance_audit_id(
            &circuit_id,
            &verifier_key_id,
            &auditor_commitment_root,
            &audit_report_root,
            completed_at_height,
        );
        let audit = Self {
            audit_id,
            circuit_id,
            verifier_key_id,
            auditor_commitment_root,
            audit_report_root,
            finding_root,
            maximum_severity,
            status,
            completed_at_height,
            expires_at_height,
            reproducible_build_root,
            fuzz_corpus_root,
            side_channel_review_root,
            monero_privacy_review_root,
            defi_compatibility_review_root,
        };
        audit.validate()?;
        Ok(audit)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_circuit_audit",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "audit_id": self.audit_id,
            "circuit_id": self.circuit_id,
            "verifier_key_id": self.verifier_key_id,
            "auditor_commitment_root": self.auditor_commitment_root,
            "audit_report_root": self.audit_report_root,
            "finding_root": self.finding_root,
            "maximum_severity": self.maximum_severity.as_str(),
            "blocks_activation": self.maximum_severity.blocks_activation(),
            "status": self.status.as_str(),
            "usable": self.status.usable(),
            "completed_at_height": self.completed_at_height,
            "expires_at_height": self.expires_at_height,
            "reproducible_build_root": self.reproducible_build_root,
            "fuzz_corpus_root": self.fuzz_corpus_root,
            "side_channel_review_root": self.side_channel_review_root,
            "monero_privacy_review_root": self.monero_privacy_review_root,
            "defi_compatibility_review_root": self.defi_compatibility_review_root,
        })
    }

    pub fn audit_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-CIRCUIT-AUDIT", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("audit id", &self.audit_id)?;
        require_non_empty("audit circuit id", &self.circuit_id)?;
        require_non_empty("audit verifier key id", &self.verifier_key_id)?;
        require_non_empty(
            "audit auditor commitment root",
            &self.auditor_commitment_root,
        )?;
        require_non_empty("audit report root", &self.audit_report_root)?;
        require_non_empty("audit finding root", &self.finding_root)?;
        require_non_empty(
            "audit reproducible build root",
            &self.reproducible_build_root,
        )?;
        require_non_empty("audit fuzz corpus root", &self.fuzz_corpus_root)?;
        require_non_empty(
            "audit side-channel review root",
            &self.side_channel_review_root,
        )?;
        if self.expires_at_height <= self.completed_at_height {
            return Err("audit expiry must be after completion".to_string());
        }
        if self.status.usable() && self.maximum_severity.blocks_activation() {
            return Err("usable audit cannot contain high or critical findings".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDeprecationIncident {
    pub incident_id: String,
    pub circuit_id: String,
    pub verifier_key_id: String,
    pub reason: PqDeprecationReason,
    pub severity: PqAuditSeverity,
    pub evidence_root: String,
    pub reporter_commitment_root: String,
    pub replacement_circuit_id: Option<String>,
    pub report_height: u64,
    pub quarantine_height: u64,
    pub migration_start_height: u64,
    pub migration_end_height: u64,
    pub disable_height: u64,
    pub attestation_roots: Vec<String>,
    pub status: PqDeprecationStatus,
}

impl PqDeprecationIncident {
    pub fn new(
        circuit_id: impl Into<String>,
        verifier_key_id: impl Into<String>,
        reason: PqDeprecationReason,
        severity: PqAuditSeverity,
        evidence_root: impl Into<String>,
        reporter_commitment_root: impl Into<String>,
        replacement_circuit_id: Option<String>,
        report_height: u64,
        quarantine_height: u64,
        migration_start_height: u64,
        migration_end_height: u64,
        disable_height: u64,
        attestation_roots: Vec<String>,
        status: PqDeprecationStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let circuit_id = circuit_id.into();
        let verifier_key_id = verifier_key_id.into();
        let evidence_root = evidence_root.into();
        let reporter_commitment_root = reporter_commitment_root.into();
        let incident_id = pq_circuit_governance_deprecation_id(
            &circuit_id,
            &verifier_key_id,
            reason,
            &evidence_root,
            report_height,
        );
        let incident = Self {
            incident_id,
            circuit_id,
            verifier_key_id,
            reason,
            severity,
            evidence_root,
            reporter_commitment_root,
            replacement_circuit_id,
            report_height,
            quarantine_height,
            migration_start_height,
            migration_end_height,
            disable_height,
            attestation_roots,
            status,
        };
        incident.validate()?;
        Ok(incident)
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "PQ-DEPRECATION-INCIDENT-ATTESTATION",
            &self
                .attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_deprecation_incident",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "incident_id": self.incident_id,
            "circuit_id": self.circuit_id,
            "verifier_key_id": self.verifier_key_id,
            "reason": self.reason.as_str(),
            "emergency": self.reason.emergency(),
            "severity": self.severity.as_str(),
            "evidence_root": self.evidence_root,
            "reporter_commitment_root": self.reporter_commitment_root,
            "replacement_circuit_id": self.replacement_circuit_id,
            "report_height": self.report_height,
            "quarantine_height": self.quarantine_height,
            "migration_start_height": self.migration_start_height,
            "migration_end_height": self.migration_end_height,
            "disable_height": self.disable_height,
            "attestation_root": self.attestation_root(),
            "attestation_count": self.attestation_roots.len(),
            "status": self.status.as_str(),
        })
    }

    pub fn incident_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-DEPRECATION-INCIDENT", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("deprecation incident id", &self.incident_id)?;
        require_non_empty("deprecation circuit id", &self.circuit_id)?;
        require_non_empty("deprecation verifier key id", &self.verifier_key_id)?;
        require_non_empty("deprecation evidence root", &self.evidence_root)?;
        require_non_empty(
            "deprecation reporter commitment root",
            &self.reporter_commitment_root,
        )?;
        if self.quarantine_height < self.report_height {
            return Err("deprecation quarantine height before report".to_string());
        }
        if self.migration_start_height < self.quarantine_height {
            return Err("deprecation migration start before quarantine".to_string());
        }
        if self.migration_end_height <= self.migration_start_height {
            return Err("deprecation migration window must be non-empty".to_string());
        }
        if self.disable_height <= self.migration_end_height {
            return Err("deprecation disable height must follow migration window".to_string());
        }
        for root in &self.attestation_roots {
            require_non_empty("deprecation attestation root", root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCompatibilityRule {
    pub rule_id: String,
    pub source_family: PqCircuitFamily,
    pub target_family: PqCircuitFamily,
    pub source_circuit_id: Option<String>,
    pub target_circuit_id: Option<String>,
    pub status: PqCompatibilityStatus,
    pub adapter_circuit_id: Option<String>,
    pub shared_nullifier_domain_root: Option<String>,
    pub shared_asset_domain_root: Option<String>,
    pub monero_network_root: Option<String>,
    pub private_state_domain_root: Option<String>,
    pub effective_from_height: u64,
    pub expires_at_height: Option<u64>,
    pub rationale_root: String,
}

impl PqCompatibilityRule {
    pub fn new(
        source_family: PqCircuitFamily,
        target_family: PqCircuitFamily,
        source_circuit_id: Option<String>,
        target_circuit_id: Option<String>,
        status: PqCompatibilityStatus,
        adapter_circuit_id: Option<String>,
        shared_nullifier_domain_root: Option<String>,
        shared_asset_domain_root: Option<String>,
        monero_network_root: Option<String>,
        private_state_domain_root: Option<String>,
        effective_from_height: u64,
        expires_at_height: Option<u64>,
        rationale_root: impl Into<String>,
    ) -> PqCircuitGovernanceResult<Self> {
        let rationale_root = rationale_root.into();
        let rule_id = pq_circuit_governance_compatibility_rule_id(
            source_family,
            target_family,
            source_circuit_id.as_deref().unwrap_or("family"),
            target_circuit_id.as_deref().unwrap_or("family"),
            status,
            effective_from_height,
        );
        let rule = Self {
            rule_id,
            source_family,
            target_family,
            source_circuit_id,
            target_circuit_id,
            status,
            adapter_circuit_id,
            shared_nullifier_domain_root,
            shared_asset_domain_root,
            monero_network_root,
            private_state_domain_root,
            effective_from_height,
            expires_at_height,
            rationale_root,
        };
        rule.validate()?;
        Ok(rule)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_compatibility_rule",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "rule_id": self.rule_id,
            "source_family": self.source_family.as_str(),
            "target_family": self.target_family.as_str(),
            "source_circuit_id": self.source_circuit_id,
            "target_circuit_id": self.target_circuit_id,
            "status": self.status.as_str(),
            "adapter_circuit_id": self.adapter_circuit_id,
            "shared_nullifier_domain_root": self.shared_nullifier_domain_root,
            "shared_asset_domain_root": self.shared_asset_domain_root,
            "monero_network_root": self.monero_network_root,
            "private_state_domain_root": self.private_state_domain_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
            "rationale_root": self.rationale_root,
        })
    }

    pub fn rule_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-COMPATIBILITY-RULE", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("compatibility rule id", &self.rule_id)?;
        require_non_empty("compatibility rationale root", &self.rationale_root)?;
        if matches!(self.status, PqCompatibilityStatus::RequiresAdapter)
            && self.adapter_circuit_id.is_none()
        {
            return Err("compatibility adapter rule missing adapter circuit id".to_string());
        }
        if (self.source_family.monero_bridge_related()
            || self.target_family.monero_bridge_related())
            && self.monero_network_root.is_none()
        {
            return Err("monero compatibility rule missing monero network root".to_string());
        }
        if (self.source_family.privacy_sensitive() || self.target_family.privacy_sensitive())
            && self.private_state_domain_root.is_none()
        {
            return Err("privacy compatibility rule missing private state domain root".to_string());
        }
        if let Some(expires) = self.expires_at_height {
            if expires <= self.effective_from_height {
                return Err("compatibility rule expiry must be after effective height".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCompatibilityMatrix {
    pub matrix_id: String,
    pub label: String,
    pub rules: BTreeMap<String, PqCompatibilityRule>,
    pub matrix_version: u64,
    pub effective_from_height: u64,
    pub attestation_roots: Vec<String>,
    pub status: PqCompatibilityStatus,
}

impl PqCompatibilityMatrix {
    pub fn new(
        label: impl Into<String>,
        rules: Vec<PqCompatibilityRule>,
        matrix_version: u64,
        effective_from_height: u64,
        attestation_roots: Vec<String>,
        status: PqCompatibilityStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let label = label.into();
        let mut rules_by_id = BTreeMap::new();
        for rule in rules {
            if rules_by_id.insert(rule.rule_id.clone(), rule).is_some() {
                return Err("compatibility matrix contains duplicate rule".to_string());
            }
        }
        let rule_root = merkle_root(
            "PQ-COMPATIBILITY-MATRIX-RULE-ID",
            &rules_by_id
                .keys()
                .map(|rule_id| json!(rule_id))
                .collect::<Vec<_>>(),
        );
        let matrix_id = pq_circuit_governance_matrix_id(
            &label,
            matrix_version,
            &rule_root,
            effective_from_height,
        );
        let matrix = Self {
            matrix_id,
            label,
            rules: rules_by_id,
            matrix_version,
            effective_from_height,
            attestation_roots,
            status,
        };
        matrix.validate()?;
        Ok(matrix)
    }

    pub fn rule_root(&self) -> String {
        merkle_root(
            "PQ-COMPATIBILITY-MATRIX-RULE",
            &self
                .rules
                .values()
                .map(PqCompatibilityRule::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "PQ-COMPATIBILITY-MATRIX-ATTESTATION",
            &self
                .attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_compatibility_matrix",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "matrix_id": self.matrix_id,
            "label": self.label,
            "rule_root": self.rule_root(),
            "rule_count": self.rules.len(),
            "matrix_version": self.matrix_version,
            "effective_from_height": self.effective_from_height,
            "attestation_root": self.attestation_root(),
            "attestation_count": self.attestation_roots.len(),
            "status": self.status.as_str(),
        })
    }

    pub fn matrix_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-COMPATIBILITY-MATRIX", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("compatibility matrix id", &self.matrix_id)?;
        require_non_empty("compatibility matrix label", &self.label)?;
        if self.matrix_version == 0 {
            return Err("compatibility matrix version must be non-zero".to_string());
        }
        if self.rules.is_empty() {
            return Err("compatibility matrix must contain rules".to_string());
        }
        for rule in self.rules.values() {
            rule.validate()?;
        }
        for root in &self.attestation_roots {
            require_non_empty("compatibility matrix attestation root", root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecursiveAggregationPolicy {
    pub policy_id: String,
    pub family: PqCircuitFamily,
    pub mode: PqRecursiveAggregationMode,
    pub aggregator_circuit_id: String,
    pub child_family_allowlist: Vec<PqCircuitFamily>,
    pub max_recursion_depth: u64,
    pub max_child_proofs: u64,
    pub max_aggregate_proof_bytes: u64,
    pub max_verify_micros: u64,
    pub accumulator_schema_root: String,
    pub proof_compression_root: String,
    pub fee_discount_bps: u64,
    pub compatibility_matrix_id: Option<String>,
    pub effective_from_height: u64,
    pub expires_at_height: Option<u64>,
}

impl PqRecursiveAggregationPolicy {
    pub fn new(
        family: PqCircuitFamily,
        mode: PqRecursiveAggregationMode,
        aggregator_circuit_id: impl Into<String>,
        child_family_allowlist: Vec<PqCircuitFamily>,
        max_recursion_depth: u64,
        max_child_proofs: u64,
        max_aggregate_proof_bytes: u64,
        max_verify_micros: u64,
        accumulator_schema_root: impl Into<String>,
        proof_compression_root: impl Into<String>,
        fee_discount_bps: u64,
        compatibility_matrix_id: Option<String>,
        effective_from_height: u64,
        expires_at_height: Option<u64>,
    ) -> PqCircuitGovernanceResult<Self> {
        let aggregator_circuit_id = aggregator_circuit_id.into();
        let accumulator_schema_root = accumulator_schema_root.into();
        let proof_compression_root = proof_compression_root.into();
        let child_root = merkle_root(
            "PQ-RECURSIVE-POLICY-CHILD-FAMILY",
            &child_family_allowlist
                .iter()
                .map(|family| json!(family.as_str()))
                .collect::<Vec<_>>(),
        );
        let policy_id = pq_circuit_governance_recursive_policy_id(
            family,
            mode,
            &aggregator_circuit_id,
            &child_root,
            effective_from_height,
        );
        let policy = Self {
            policy_id,
            family,
            mode,
            aggregator_circuit_id,
            child_family_allowlist,
            max_recursion_depth,
            max_child_proofs,
            max_aggregate_proof_bytes,
            max_verify_micros,
            accumulator_schema_root,
            proof_compression_root,
            fee_discount_bps,
            compatibility_matrix_id,
            effective_from_height,
            expires_at_height,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn child_family_root(&self) -> String {
        merkle_root(
            "PQ-RECURSIVE-POLICY-CHILD",
            &self
                .child_family_allowlist
                .iter()
                .map(|family| json!(family.as_str()))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_aggregation_policy",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "family": self.family.as_str(),
            "mode": self.mode.as_str(),
            "recursive": self.mode.recursive(),
            "aggregator_circuit_id": self.aggregator_circuit_id,
            "child_family_root": self.child_family_root(),
            "child_family_count": self.child_family_allowlist.len(),
            "max_recursion_depth": self.max_recursion_depth,
            "max_child_proofs": self.max_child_proofs,
            "max_aggregate_proof_bytes": self.max_aggregate_proof_bytes,
            "max_verify_micros": self.max_verify_micros,
            "accumulator_schema_root": self.accumulator_schema_root,
            "proof_compression_root": self.proof_compression_root,
            "fee_discount_bps": self.fee_discount_bps,
            "compatibility_matrix_id": self.compatibility_matrix_id,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-RECURSIVE-AGGREGATION-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("recursive policy id", &self.policy_id)?;
        require_non_empty(
            "recursive policy aggregator circuit id",
            &self.aggregator_circuit_id,
        )?;
        require_non_empty(
            "recursive policy accumulator schema root",
            &self.accumulator_schema_root,
        )?;
        require_non_empty(
            "recursive policy proof compression root",
            &self.proof_compression_root,
        )?;
        if !self.mode.recursive() {
            return Err("recursive aggregation policy cannot use none mode".to_string());
        }
        if self.child_family_allowlist.is_empty() {
            return Err("recursive policy must allow at least one child family".to_string());
        }
        if self.max_recursion_depth == 0 || self.max_child_proofs == 0 {
            return Err("recursive policy limits must be non-zero".to_string());
        }
        if self.max_aggregate_proof_bytes == 0 || self.max_verify_micros == 0 {
            return Err("recursive policy proof limits must be non-zero".to_string());
        }
        validate_bps("recursive policy fee discount", self.fee_discount_bps)?;
        if let Some(expires) = self.expires_at_height {
            if expires <= self.effective_from_height {
                return Err("recursive policy expiry must be after effective height".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSponsoredProofBudget {
    pub budget_id: String,
    pub sponsor_commitment_root: String,
    pub family: PqCircuitFamily,
    pub circuit_id: Option<String>,
    pub max_sponsored_proofs: u64,
    pub max_fee_units: u64,
    pub consumed_proofs: u64,
    pub consumed_fee_units: u64,
    pub beneficiary_group_root: String,
    pub eligibility_root: String,
    pub nullifier_domain_root: String,
}

impl PqSponsoredProofBudget {
    pub fn new(
        sponsor_commitment_root: impl Into<String>,
        family: PqCircuitFamily,
        circuit_id: Option<String>,
        max_sponsored_proofs: u64,
        max_fee_units: u64,
        consumed_proofs: u64,
        consumed_fee_units: u64,
        beneficiary_group_root: impl Into<String>,
        eligibility_root: impl Into<String>,
        nullifier_domain_root: impl Into<String>,
    ) -> PqCircuitGovernanceResult<Self> {
        let sponsor_commitment_root = sponsor_commitment_root.into();
        let beneficiary_group_root = beneficiary_group_root.into();
        let eligibility_root = eligibility_root.into();
        let nullifier_domain_root = nullifier_domain_root.into();
        let budget_id = pq_circuit_governance_sponsor_budget_id(
            &sponsor_commitment_root,
            family,
            circuit_id.as_deref().unwrap_or("family"),
            &beneficiary_group_root,
            &eligibility_root,
        );
        let budget = Self {
            budget_id,
            sponsor_commitment_root,
            family,
            circuit_id,
            max_sponsored_proofs,
            max_fee_units,
            consumed_proofs,
            consumed_fee_units,
            beneficiary_group_root,
            eligibility_root,
            nullifier_domain_root,
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn remaining_proofs(&self) -> u64 {
        self.max_sponsored_proofs
            .saturating_sub(self.consumed_proofs)
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.consumed_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_sponsored_proof_budget",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "family": self.family.as_str(),
            "circuit_id": self.circuit_id,
            "max_sponsored_proofs": self.max_sponsored_proofs,
            "max_fee_units": self.max_fee_units,
            "consumed_proofs": self.consumed_proofs,
            "consumed_fee_units": self.consumed_fee_units,
            "remaining_proofs": self.remaining_proofs(),
            "remaining_fee_units": self.remaining_fee_units(),
            "beneficiary_group_root": self.beneficiary_group_root,
            "eligibility_root": self.eligibility_root,
            "nullifier_domain_root": self.nullifier_domain_root,
        })
    }

    pub fn budget_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-SPONSORED-PROOF-BUDGET", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("sponsor budget id", &self.budget_id)?;
        require_non_empty(
            "sponsor budget sponsor commitment root",
            &self.sponsor_commitment_root,
        )?;
        require_non_empty(
            "sponsor budget beneficiary root",
            &self.beneficiary_group_root,
        )?;
        require_non_empty("sponsor budget eligibility root", &self.eligibility_root)?;
        require_non_empty("sponsor budget nullifier root", &self.nullifier_domain_root)?;
        if self.max_sponsored_proofs == 0 || self.max_fee_units == 0 {
            return Err("sponsor budget limits must be non-zero".to_string());
        }
        if self.consumed_proofs > self.max_sponsored_proofs {
            return Err("sponsor budget consumed proofs exceed limit".to_string());
        }
        if self.consumed_fee_units > self.max_fee_units {
            return Err("sponsor budget consumed fees exceed limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqProofSponsorshipEpoch {
    pub epoch_id: String,
    pub label: String,
    pub fee_asset_id: String,
    pub sponsor_asset_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub settlement_height: u64,
    pub rebate_bps: u64,
    pub protocol_fee_bps: u64,
    pub budget_ids: Vec<String>,
    pub aggregate_budget_root: String,
    pub attestation_roots: Vec<String>,
    pub status: PqSponsorshipEpochStatus,
}

impl PqProofSponsorshipEpoch {
    pub fn new(
        label: impl Into<String>,
        fee_asset_id: impl Into<String>,
        sponsor_asset_id: impl Into<String>,
        start_height: u64,
        end_height: u64,
        settlement_height: u64,
        rebate_bps: u64,
        protocol_fee_bps: u64,
        budget_ids: Vec<String>,
        aggregate_budget_root: impl Into<String>,
        attestation_roots: Vec<String>,
        status: PqSponsorshipEpochStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let label = label.into();
        let fee_asset_id = fee_asset_id.into();
        let sponsor_asset_id = sponsor_asset_id.into();
        let aggregate_budget_root = aggregate_budget_root.into();
        let budget_root = merkle_root(
            "PQ-PROOF-SPONSORSHIP-EPOCH-BUDGET-ID",
            &budget_ids
                .iter()
                .map(|budget_id| json!(budget_id))
                .collect::<Vec<_>>(),
        );
        let epoch_id = pq_circuit_governance_sponsorship_epoch_id(
            &label,
            &fee_asset_id,
            &sponsor_asset_id,
            start_height,
            end_height,
            &budget_root,
        );
        let epoch = Self {
            epoch_id,
            label,
            fee_asset_id,
            sponsor_asset_id,
            start_height,
            end_height,
            settlement_height,
            rebate_bps,
            protocol_fee_bps,
            budget_ids,
            aggregate_budget_root,
            attestation_roots,
            status,
        };
        epoch.validate()?;
        Ok(epoch)
    }

    pub fn budget_id_root(&self) -> String {
        merkle_root(
            "PQ-PROOF-SPONSORSHIP-EPOCH-BUDGET",
            &self
                .budget_ids
                .iter()
                .map(|budget_id| json!(budget_id))
                .collect::<Vec<_>>(),
        )
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "PQ-PROOF-SPONSORSHIP-EPOCH-ATTESTATION",
            &self
                .attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_proof_sponsorship_epoch",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "epoch_id": self.epoch_id,
            "label": self.label,
            "fee_asset_id": self.fee_asset_id,
            "sponsor_asset_id": self.sponsor_asset_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "settlement_height": self.settlement_height,
            "rebate_bps": self.rebate_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "budget_id_root": self.budget_id_root(),
            "budget_count": self.budget_ids.len(),
            "aggregate_budget_root": self.aggregate_budget_root,
            "attestation_root": self.attestation_root(),
            "attestation_count": self.attestation_roots.len(),
            "status": self.status.as_str(),
            "accepts_claims": self.status.accepts_claims(),
        })
    }

    pub fn epoch_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-PROOF-SPONSORSHIP-EPOCH", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("sponsorship epoch id", &self.epoch_id)?;
        require_non_empty("sponsorship epoch label", &self.label)?;
        require_non_empty("sponsorship fee asset id", &self.fee_asset_id)?;
        require_non_empty("sponsorship sponsor asset id", &self.sponsor_asset_id)?;
        require_non_empty(
            "sponsorship aggregate budget root",
            &self.aggregate_budget_root,
        )?;
        validate_bps("sponsorship rebate bps", self.rebate_bps)?;
        validate_bps("sponsorship protocol fee bps", self.protocol_fee_bps)?;
        if self.end_height <= self.start_height {
            return Err("sponsorship epoch end must be after start".to_string());
        }
        if self.settlement_height <= self.end_height {
            return Err("sponsorship settlement must follow epoch end".to_string());
        }
        if self.budget_ids.is_empty() {
            return Err("sponsorship epoch must include at least one budget".to_string());
        }
        for budget_id in &self.budget_ids {
            require_non_empty("sponsorship budget id", budget_id)?;
        }
        for root in &self.attestation_roots {
            require_non_empty("sponsorship attestation root", root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMigrationReceipt {
    pub receipt_id: String,
    pub subject_commitment_root: String,
    pub from_circuit_id: String,
    pub to_circuit_id: String,
    pub migration_window_id: String,
    pub migrated_proof_count: u64,
    pub migrated_value_commitment_root: String,
    pub old_nullifier_root: String,
    pub new_nullifier_root: String,
    pub privacy_budget_root: String,
    pub sponsor_epoch_id: Option<String>,
    pub attestation_roots: Vec<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub status: PqMigrationReceiptStatus,
}

impl PqMigrationReceipt {
    pub fn new(
        subject_commitment_root: impl Into<String>,
        from_circuit_id: impl Into<String>,
        to_circuit_id: impl Into<String>,
        migration_window_id: impl Into<String>,
        migrated_proof_count: u64,
        migrated_value_commitment_root: impl Into<String>,
        old_nullifier_root: impl Into<String>,
        new_nullifier_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        sponsor_epoch_id: Option<String>,
        attestation_roots: Vec<String>,
        submitted_at_height: u64,
        expires_at_height: u64,
        finalized_at_height: Option<u64>,
        status: PqMigrationReceiptStatus,
    ) -> PqCircuitGovernanceResult<Self> {
        let subject_commitment_root = subject_commitment_root.into();
        let from_circuit_id = from_circuit_id.into();
        let to_circuit_id = to_circuit_id.into();
        let migration_window_id = migration_window_id.into();
        let migrated_value_commitment_root = migrated_value_commitment_root.into();
        let old_nullifier_root = old_nullifier_root.into();
        let new_nullifier_root = new_nullifier_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        let attestation_root = merkle_root(
            "PQ-MIGRATION-RECEIPT-ATTESTATION-ID",
            &attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        );
        let receipt_id = pq_circuit_governance_migration_receipt_id(
            &subject_commitment_root,
            &from_circuit_id,
            &to_circuit_id,
            &migration_window_id,
            &attestation_root,
            submitted_at_height,
        );
        let receipt = Self {
            receipt_id,
            subject_commitment_root,
            from_circuit_id,
            to_circuit_id,
            migration_window_id,
            migrated_proof_count,
            migrated_value_commitment_root,
            old_nullifier_root,
            new_nullifier_root,
            privacy_budget_root,
            sponsor_epoch_id,
            attestation_roots,
            submitted_at_height,
            expires_at_height,
            finalized_at_height,
            status,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "PQ-MIGRATION-RECEIPT-ATTESTATION",
            &self
                .attestation_roots
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_migration_receipt",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "subject_commitment_root": self.subject_commitment_root,
            "from_circuit_id": self.from_circuit_id,
            "to_circuit_id": self.to_circuit_id,
            "migration_window_id": self.migration_window_id,
            "migrated_proof_count": self.migrated_proof_count,
            "migrated_value_commitment_root": self.migrated_value_commitment_root,
            "old_nullifier_root": self.old_nullifier_root,
            "new_nullifier_root": self.new_nullifier_root,
            "privacy_budget_root": self.privacy_budget_root,
            "sponsor_epoch_id": self.sponsor_epoch_id,
            "attestation_root": self.attestation_root(),
            "attestation_count": self.attestation_roots.len(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-MIGRATION-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<()> {
        require_non_empty("migration receipt id", &self.receipt_id)?;
        require_non_empty(
            "migration receipt subject commitment root",
            &self.subject_commitment_root,
        )?;
        require_non_empty("migration receipt from circuit id", &self.from_circuit_id)?;
        require_non_empty("migration receipt to circuit id", &self.to_circuit_id)?;
        require_non_empty("migration receipt window id", &self.migration_window_id)?;
        require_non_empty(
            "migration receipt value commitment root",
            &self.migrated_value_commitment_root,
        )?;
        require_non_empty(
            "migration receipt old nullifier root",
            &self.old_nullifier_root,
        )?;
        require_non_empty(
            "migration receipt new nullifier root",
            &self.new_nullifier_root,
        )?;
        require_non_empty(
            "migration receipt privacy budget root",
            &self.privacy_budget_root,
        )?;
        if self.from_circuit_id == self.to_circuit_id {
            return Err("migration receipt cannot migrate to same circuit".to_string());
        }
        if self.migrated_proof_count == 0 {
            return Err("migration receipt must migrate at least one proof".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("migration receipt expiry must be after submit height".to_string());
        }
        if let Some(finalized) = self.finalized_at_height {
            if finalized < self.submitted_at_height || finalized > self.expires_at_height {
                return Err("migration receipt finalization outside receipt window".to_string());
            }
        }
        for root in &self.attestation_roots {
            require_non_empty("migration receipt attestation root", root)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitGovernanceRoots {
    pub config_root: String,
    pub family_policy_root: String,
    pub verifier_key_root: String,
    pub committee_root: String,
    pub circuit_root: String,
    pub activation_proposal_root: String,
    pub attestation_root: String,
    pub audit_root: String,
    pub deprecation_incident_root: String,
    pub compatibility_matrix_root: String,
    pub recursive_policy_root: String,
    pub sponsorship_epoch_root: String,
    pub sponsorship_budget_root: String,
    pub migration_receipt_root: String,
}

impl PqCircuitGovernanceRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_circuit_governance_roots",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "family_policy_root": self.family_policy_root,
            "verifier_key_root": self.verifier_key_root,
            "committee_root": self.committee_root,
            "circuit_root": self.circuit_root,
            "activation_proposal_root": self.activation_proposal_root,
            "attestation_root": self.attestation_root,
            "audit_root": self.audit_root,
            "deprecation_incident_root": self.deprecation_incident_root,
            "compatibility_matrix_root": self.compatibility_matrix_root,
            "recursive_policy_root": self.recursive_policy_root,
            "sponsorship_epoch_root": self.sponsorship_epoch_root,
            "sponsorship_budget_root": self.sponsorship_budget_root,
            "migration_receipt_root": self.migration_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        pq_circuit_governance_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitGovernanceCounters {
    pub family_policy_count: usize,
    pub verifier_key_count: usize,
    pub committee_count: usize,
    pub circuit_count: usize,
    pub active_circuit_count: usize,
    pub deprecated_circuit_count: usize,
    pub proposal_count: usize,
    pub open_proposal_count: usize,
    pub attestation_count: usize,
    pub usable_attestation_count: usize,
    pub audit_count: usize,
    pub usable_audit_count: usize,
    pub deprecation_incident_count: usize,
    pub compatibility_matrix_count: usize,
    pub recursive_policy_count: usize,
    pub sponsorship_epoch_count: usize,
    pub active_sponsorship_epoch_count: usize,
    pub sponsorship_budget_count: usize,
    pub migration_receipt_count: usize,
    pub finalized_migration_receipt_count: usize,
}

impl PqCircuitGovernanceCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_circuit_governance_counters",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "family_policy_count": self.family_policy_count,
            "verifier_key_count": self.verifier_key_count,
            "committee_count": self.committee_count,
            "circuit_count": self.circuit_count,
            "active_circuit_count": self.active_circuit_count,
            "deprecated_circuit_count": self.deprecated_circuit_count,
            "proposal_count": self.proposal_count,
            "open_proposal_count": self.open_proposal_count,
            "attestation_count": self.attestation_count,
            "usable_attestation_count": self.usable_attestation_count,
            "audit_count": self.audit_count,
            "usable_audit_count": self.usable_audit_count,
            "deprecation_incident_count": self.deprecation_incident_count,
            "compatibility_matrix_count": self.compatibility_matrix_count,
            "recursive_policy_count": self.recursive_policy_count,
            "sponsorship_epoch_count": self.sponsorship_epoch_count,
            "active_sponsorship_epoch_count": self.active_sponsorship_epoch_count,
            "sponsorship_budget_count": self.sponsorship_budget_count,
            "migration_receipt_count": self.migration_receipt_count,
            "finalized_migration_receipt_count": self.finalized_migration_receipt_count,
        })
    }

    pub fn counters_root(&self) -> String {
        pq_circuit_governance_hash_record("PQ-CIRCUIT-GOVERNANCE-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCircuitGovernanceState {
    pub height: u64,
    pub config: PqCircuitGovernanceConfig,
    pub family_policies: BTreeMap<String, PqCircuitFamilyPolicy>,
    pub verifier_keys: BTreeMap<String, PqVerifierKeyRecord>,
    pub committees: BTreeMap<String, PqVerifierCommittee>,
    pub circuits: BTreeMap<String, PqCircuitDescriptor>,
    pub activation_proposals: BTreeMap<String, PqActivationProposal>,
    pub attestations: BTreeMap<String, PqVerifierAttestation>,
    pub audits: BTreeMap<String, PqCircuitAudit>,
    pub deprecation_incidents: BTreeMap<String, PqDeprecationIncident>,
    pub compatibility_matrices: BTreeMap<String, PqCompatibilityMatrix>,
    pub recursive_policies: BTreeMap<String, PqRecursiveAggregationPolicy>,
    pub sponsorship_epochs: BTreeMap<String, PqProofSponsorshipEpoch>,
    pub sponsorship_budgets: BTreeMap<String, PqSponsoredProofBudget>,
    pub migration_receipts: BTreeMap<String, PqMigrationReceipt>,
    pub next_activation_nonce: u64,
}

impl Default for PqCircuitGovernanceState {
    fn default() -> Self {
        Self {
            height: 0,
            config: PqCircuitGovernanceConfig::default(),
            family_policies: BTreeMap::new(),
            verifier_keys: BTreeMap::new(),
            committees: BTreeMap::new(),
            circuits: BTreeMap::new(),
            activation_proposals: BTreeMap::new(),
            attestations: BTreeMap::new(),
            audits: BTreeMap::new(),
            deprecation_incidents: BTreeMap::new(),
            compatibility_matrices: BTreeMap::new(),
            recursive_policies: BTreeMap::new(),
            sponsorship_epochs: BTreeMap::new(),
            sponsorship_budgets: BTreeMap::new(),
            migration_receipts: BTreeMap::new(),
            next_activation_nonce: 0,
        }
    }
}

impl PqCircuitGovernanceState {
    pub fn devnet() -> PqCircuitGovernanceResult<Self> {
        let mut state = Self::default();
        state.set_height(PQ_CIRCUIT_GOVERNANCE_DEFAULT_DEVNET_HEIGHT)?;
        state.install_devnet_family_policies()?;

        let committee = state.devnet_committee()?;
        let committee_id = committee.committee_id.clone();
        let committee_root = committee.committee_root();
        state.register_committee(committee)?;

        let rollup_key = state.devnet_verifier_key(
            PqCircuitFamily::RollupState,
            PqProofSystem::ShakePlonk,
            1,
            PqVerifierKeyStatus::Active,
            Some(state.height.saturating_sub(120)),
            None,
        )?;
        let bridge_key = state.devnet_verifier_key(
            PqCircuitFamily::MoneroBridgeFinality,
            PqProofSystem::MoneroBridgeCustom,
            1,
            PqVerifierKeyStatus::Active,
            Some(state.height.saturating_sub(96)),
            None,
        )?;
        let dex_key = state.devnet_verifier_key(
            PqCircuitFamily::PrivateDexSwap,
            PqProofSystem::ShakeStark,
            1,
            PqVerifierKeyStatus::Active,
            Some(state.height.saturating_sub(64)),
            None,
        )?;
        let recursive_key = state.devnet_verifier_key(
            PqCircuitFamily::RecursiveAggregation,
            PqProofSystem::FoldingNovaShake,
            1,
            PqVerifierKeyStatus::Active,
            Some(state.height.saturating_sub(48)),
            None,
        )?;
        let old_bridge_key = state.devnet_verifier_key(
            PqCircuitFamily::MoneroBridgeFinality,
            PqProofSystem::ShakePlonk,
            0,
            PqVerifierKeyStatus::GraceOnly,
            Some(state.height.saturating_sub(3_000)),
            Some(state.height.saturating_add(2_400)),
        )?;
        let rollup_key_id = rollup_key.key_id.clone();
        let bridge_key_id = bridge_key.key_id.clone();
        let dex_key_id = dex_key.key_id.clone();
        let recursive_key_id = recursive_key.key_id.clone();
        let old_bridge_key_id = old_bridge_key.key_id.clone();
        state.register_verifier_key(rollup_key)?;
        state.register_verifier_key(bridge_key)?;
        state.register_verifier_key(dex_key)?;
        state.register_verifier_key(recursive_key)?;
        state.register_verifier_key(old_bridge_key)?;

        let recursive_policy = PqRecursiveAggregationPolicy::new(
            PqCircuitFamily::RecursiveAggregation,
            PqRecursiveAggregationMode::BridgeFinalityAccumulator,
            "pending-recursive-aggregator-circuit",
            vec![
                PqCircuitFamily::RollupState,
                PqCircuitFamily::MoneroBridgeFinality,
                PqCircuitFamily::PrivateDexSwap,
                PqCircuitFamily::FeeSponsorship,
            ],
            4,
            64,
            128 * 1024,
            1_200_000,
            pq_circuit_governance_string_root("DEVNET-ACCUMULATOR-SCHEMA", "recursive-v1"),
            pq_circuit_governance_string_root("DEVNET-PROOF-COMPRESSION", "recursive-v1"),
            1_500,
            None,
            state.height.saturating_sub(48),
            None,
        )?;
        let recursive_policy_id = recursive_policy.policy_id.clone();
        state.register_recursive_policy(recursive_policy)?;

        let rollup = state.devnet_circuit(
            PqCircuitFamily::RollupState,
            PqProofSystem::ShakePlonk,
            1,
            &rollup_key_id,
            None,
            None,
            None,
            None,
            Some(state.height.saturating_sub(120)),
            None,
            PqCircuitStatus::Active,
            true,
        )?;
        let bridge = state.devnet_circuit(
            PqCircuitFamily::MoneroBridgeFinality,
            PqProofSystem::MoneroBridgeCustom,
            1,
            &bridge_key_id,
            None,
            Some(pq_circuit_governance_string_root(
                "DEVNET-MONERO-COMPATIBILITY",
                "bridge-v1",
            )),
            Some(pq_circuit_governance_string_root(
                "DEVNET-DEFI-COMPATIBILITY",
                "bridge-v1",
            )),
            Some(recursive_policy_id.clone()),
            Some(state.height.saturating_sub(96)),
            None,
            PqCircuitStatus::Active,
            true,
        )?;
        let dex = state.devnet_circuit(
            PqCircuitFamily::PrivateDexSwap,
            PqProofSystem::ShakeStark,
            1,
            &dex_key_id,
            None,
            None,
            Some(pq_circuit_governance_string_root(
                "DEVNET-DEFI-COMPATIBILITY",
                "dex-v1",
            )),
            None,
            Some(state.height.saturating_sub(64)),
            None,
            PqCircuitStatus::Active,
            true,
        )?;
        let recursive = state.devnet_circuit(
            PqCircuitFamily::RecursiveAggregation,
            PqProofSystem::FoldingNovaShake,
            1,
            &recursive_key_id,
            None,
            None,
            None,
            Some(recursive_policy_id.clone()),
            Some(state.height.saturating_sub(48)),
            None,
            PqCircuitStatus::Active,
            true,
        )?;
        let old_bridge = state.devnet_circuit(
            PqCircuitFamily::MoneroBridgeFinality,
            PqProofSystem::ShakePlonk,
            1,
            &old_bridge_key_id,
            None,
            Some(pq_circuit_governance_string_root(
                "DEVNET-MONERO-COMPATIBILITY",
                "bridge-legacy",
            )),
            Some(pq_circuit_governance_string_root(
                "DEVNET-DEFI-COMPATIBILITY",
                "bridge-legacy",
            )),
            Some(recursive_policy_id.clone()),
            Some(state.height.saturating_sub(3_000)),
            Some(state.height.saturating_add(2_400)),
            PqCircuitStatus::GraceOnly,
            true,
        )?;
        let rollup_id = rollup.circuit_id.clone();
        let bridge_id = bridge.circuit_id.clone();
        let dex_id = dex.circuit_id.clone();
        let recursive_id = recursive.circuit_id.clone();
        let old_bridge_id = old_bridge.circuit_id.clone();
        state.register_circuit(rollup)?;
        state.register_circuit(bridge)?;
        state.register_circuit(dex)?;
        state.register_circuit(recursive)?;
        state.register_circuit(old_bridge)?;

        if let Some(policy) = state.recursive_policies.get_mut(&recursive_policy_id) {
            policy.aggregator_circuit_id = recursive_id.clone();
        }

        let matrix = state.devnet_compatibility_matrix(&bridge_id, &dex_id, &recursive_id)?;
        let matrix_id = matrix.matrix_id.clone();
        let matrix_root = matrix.matrix_root();
        state.register_compatibility_matrix(matrix)?;

        if let Some(policy) = state.recursive_policies.get_mut(&recursive_policy_id) {
            policy.compatibility_matrix_id = Some(matrix_id.clone());
        }

        for (label, circuit_id, key_id, family) in [
            (
                "rollup",
                rollup_id.as_str(),
                rollup_key_id.as_str(),
                PqCircuitFamily::RollupState,
            ),
            (
                "bridge",
                bridge_id.as_str(),
                bridge_key_id.as_str(),
                PqCircuitFamily::MoneroBridgeFinality,
            ),
            (
                "dex",
                dex_id.as_str(),
                dex_key_id.as_str(),
                PqCircuitFamily::PrivateDexSwap,
            ),
            (
                "recursive",
                recursive_id.as_str(),
                recursive_key_id.as_str(),
                PqCircuitFamily::RecursiveAggregation,
            ),
        ] {
            let audit_a = state.devnet_audit(
                circuit_id,
                key_id,
                &format!("{label}-auditor-a"),
                family,
                PqAuditStatus::Passed,
            )?;
            let audit_b = state.devnet_audit(
                circuit_id,
                key_id,
                &format!("{label}-auditor-b"),
                family,
                PqAuditStatus::PassedWithFindings,
            )?;
            state.insert_audit(audit_a)?;
            state.insert_audit(audit_b)?;
        }

        let bridge_subject_root = state
            .circuits
            .get(&bridge_id)
            .ok_or_else(|| "devnet bridge circuit missing".to_string())?
            .circuit_root();
        let bridge_attestation = state.devnet_attestation(
            PqAttestationSubjectKind::CircuitActivation,
            &bridge_id,
            &bridge_subject_root,
            &committee_id,
            &committee_root,
            "bridge-activation",
            state.height.saturating_sub(90),
        )?;
        let bridge_attestation_root = bridge_attestation.attestation_root();
        state.insert_attestation(bridge_attestation)?;

        let matrix_attestation = state.devnet_attestation(
            PqAttestationSubjectKind::CompatibilityMatrix,
            &matrix_id,
            &matrix_root,
            &committee_id,
            &committee_root,
            "compatibility-matrix",
            state.height.saturating_sub(48),
        )?;
        state.insert_attestation(matrix_attestation)?;

        let proposal = PqActivationProposal::new(
            bridge_id.clone(),
            PqCircuitFamily::MoneroBridgeFinality,
            bridge_key_id.clone(),
            pq_circuit_governance_string_root("DEVNET-PROPOSER", "bridge-council"),
            Some(old_bridge_id.clone()),
            state
                .height
                .saturating_add(state.config.activation_delay_blocks),
            state
                .height
                .saturating_add(state.config.activation_delay_blocks)
                .saturating_add(state.config.migration_window_blocks),
            Some(old_bridge_id.clone()),
            pq_circuit_governance_string_root("DEVNET-MIGRATION-PLAN", "bridge-v1"),
            true,
            Some(pq_circuit_governance_string_root(
                "DEVNET-MONERO-IMPACT",
                "bridge-v1",
            )),
            Some(pq_circuit_governance_string_root(
                "DEVNET-DEFI-IMPACT",
                "bridge-v1",
            )),
            Some(recursive_policy_id.clone()),
            state.audit_roots_for_circuit(&bridge_id),
            vec![bridge_attestation_root],
            state.height.saturating_sub(88),
            PqActivationProposalStatus::Scheduled,
        )?;
        state.submit_activation_proposal(proposal)?;

        let deprecation = PqDeprecationIncident::new(
            old_bridge_id.clone(),
            old_bridge_key_id.clone(),
            PqDeprecationReason::PlannedRotation,
            PqAuditSeverity::Medium,
            pq_circuit_governance_string_root("DEVNET-DEPRECATION-EVIDENCE", "legacy-bridge"),
            pq_circuit_governance_string_root("DEVNET-REPORTER", "bridge-council"),
            Some(bridge_id.clone()),
            state.height.saturating_sub(24),
            state.height.saturating_sub(12),
            state.height,
            state
                .height
                .saturating_add(state.config.migration_window_blocks),
            state
                .height
                .saturating_add(state.config.migration_window_blocks)
                .saturating_add(state.config.deprecation_notice_blocks),
            vec![],
            PqDeprecationStatus::MigrationOpen,
        )?;
        let deprecation_id = deprecation.incident_id.clone();
        state.insert_deprecation_incident(deprecation)?;

        let bridge_budget = PqSponsoredProofBudget::new(
            pq_circuit_governance_string_root("DEVNET-SPONSOR", "bridge-sponsor"),
            PqCircuitFamily::MoneroBridgeFinality,
            Some(bridge_id.clone()),
            20_000,
            80_000_000,
            1_250,
            3_500_000,
            pq_circuit_governance_string_root("DEVNET-BENEFICIARY-GROUP", "bridge-users"),
            pq_circuit_governance_string_root("DEVNET-ELIGIBILITY", "bridge-low-fee"),
            pq_circuit_governance_string_root("DEVNET-NULLIFIER-DOMAIN", "bridge-sponsor"),
        )?;
        let dex_budget = PqSponsoredProofBudget::new(
            pq_circuit_governance_string_root("DEVNET-SPONSOR", "dex-sponsor"),
            PqCircuitFamily::PrivateDexSwap,
            Some(dex_id.clone()),
            35_000,
            120_000_000,
            4_800,
            12_400_000,
            pq_circuit_governance_string_root("DEVNET-BENEFICIARY-GROUP", "dex-users"),
            pq_circuit_governance_string_root("DEVNET-ELIGIBILITY", "dex-low-fee"),
            pq_circuit_governance_string_root("DEVNET-NULLIFIER-DOMAIN", "dex-sponsor"),
        )?;
        let bridge_budget_id = bridge_budget.budget_id.clone();
        let dex_budget_id = dex_budget.budget_id.clone();
        let bridge_budget_root = bridge_budget.budget_root();
        let dex_budget_root = dex_budget.budget_root();
        state.insert_sponsorship_budget(bridge_budget)?;
        state.insert_sponsorship_budget(dex_budget)?;
        let aggregate_budget_root = merkle_root(
            "PQ-DEVNET-SPONSOR-AGGREGATE",
            &[json!(bridge_budget_root), json!(dex_budget_root)],
        );
        let sponsor_epoch = PqProofSponsorshipEpoch::new(
            "devnet-pq-proof-sponsorship-epoch-0",
            &state.config.fee_asset_id,
            &state.config.sponsor_asset_id,
            state.height.saturating_sub(120),
            state
                .height
                .saturating_sub(120)
                .saturating_add(state.config.sponsor_epoch_blocks),
            state
                .height
                .saturating_sub(120)
                .saturating_add(state.config.sponsor_epoch_blocks)
                .saturating_add(state.config.settlement_grace_blocks),
            state.config.sponsor_rebate_bps,
            state.config.protocol_fee_bps,
            vec![bridge_budget_id, dex_budget_id],
            aggregate_budget_root,
            vec![],
            PqSponsorshipEpochStatus::Active,
        )?;
        let sponsor_epoch_id = sponsor_epoch.epoch_id.clone();
        state.insert_sponsorship_epoch(sponsor_epoch)?;

        let receipt = PqMigrationReceipt::new(
            pq_circuit_governance_string_root("DEVNET-MIGRATION-SUBJECT", "bridge-user-a"),
            old_bridge_id.clone(),
            bridge_id.clone(),
            deprecation_id,
            12,
            pq_circuit_governance_string_root("DEVNET-MIGRATION-VALUE", "bridge-user-a"),
            pq_circuit_governance_string_root("DEVNET-OLD-NULLIFIER", "bridge-user-a"),
            pq_circuit_governance_string_root("DEVNET-NEW-NULLIFIER", "bridge-user-a"),
            pq_circuit_governance_string_root("DEVNET-PRIVACY-BUDGET", "bridge-user-a"),
            Some(sponsor_epoch_id),
            vec![],
            state.height.saturating_add(1),
            state
                .height
                .saturating_add(state.config.migration_window_blocks),
            Some(state.height.saturating_add(4)),
            PqMigrationReceiptStatus::Finalized,
        )?;
        state.insert_migration_receipt(receipt)?;

        state.refresh_lifecycle();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PqCircuitGovernanceResult<String> {
        if height < self.height {
            return Err("pq circuit governance height cannot move backward".to_string());
        }
        self.height = height;
        self.refresh_lifecycle();
        Ok(self.state_root())
    }

    pub fn roots(&self) -> PqCircuitGovernanceRoots {
        PqCircuitGovernanceRoots {
            config_root: self.config.state_root(),
            family_policy_root: self.family_policy_root(),
            verifier_key_root: self.verifier_key_root(),
            committee_root: self.committee_root(),
            circuit_root: self.circuit_root(),
            activation_proposal_root: self.activation_proposal_root(),
            attestation_root: self.attestation_root(),
            audit_root: self.audit_root(),
            deprecation_incident_root: self.deprecation_incident_root(),
            compatibility_matrix_root: self.compatibility_matrix_root(),
            recursive_policy_root: self.recursive_policy_root(),
            sponsorship_epoch_root: self.sponsorship_epoch_root(),
            sponsorship_budget_root: self.sponsorship_budget_root(),
            migration_receipt_root: self.migration_receipt_root(),
        }
    }

    pub fn counters(&self) -> PqCircuitGovernanceCounters {
        PqCircuitGovernanceCounters {
            family_policy_count: self.family_policies.len(),
            verifier_key_count: self.verifier_keys.len(),
            committee_count: self.committees.len(),
            circuit_count: self.circuits.len(),
            active_circuit_count: self
                .circuits
                .values()
                .filter(|circuit| circuit.status.accepts_new_proofs())
                .count(),
            deprecated_circuit_count: self
                .circuits
                .values()
                .filter(|circuit| {
                    matches!(
                        circuit.status,
                        PqCircuitStatus::GraceOnly
                            | PqCircuitStatus::Deprecated
                            | PqCircuitStatus::Disabled
                    )
                })
                .count(),
            proposal_count: self.activation_proposals.len(),
            open_proposal_count: self
                .activation_proposals
                .values()
                .filter(|proposal| proposal.status.open())
                .count(),
            attestation_count: self.attestations.len(),
            usable_attestation_count: self
                .attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count(),
            audit_count: self.audits.len(),
            usable_audit_count: self
                .audits
                .values()
                .filter(|audit| audit.status.usable())
                .count(),
            deprecation_incident_count: self.deprecation_incidents.len(),
            compatibility_matrix_count: self.compatibility_matrices.len(),
            recursive_policy_count: self.recursive_policies.len(),
            sponsorship_epoch_count: self.sponsorship_epochs.len(),
            active_sponsorship_epoch_count: self
                .sponsorship_epochs
                .values()
                .filter(|epoch| matches!(epoch.status, PqSponsorshipEpochStatus::Active))
                .count(),
            sponsorship_budget_count: self.sponsorship_budgets.len(),
            migration_receipt_count: self.migration_receipts.len(),
            finalized_migration_receipt_count: self
                .migration_receipts
                .values()
                .filter(|receipt| matches!(receipt.status, PqMigrationReceiptStatus::Finalized))
                .count(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_circuit_governance_state",
            "chain_id": CHAIN_ID,
            "pq_circuit_governance_protocol_version": PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION,
            "schema_version": PQ_CIRCUIT_GOVERNANCE_SCHEMA_VERSION,
            "height": self.height,
            "roots": roots.public_record(),
            "roots_state_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "next_activation_nonce": self.next_activation_nonce,
        })
    }

    pub fn state_root(&self) -> String {
        pq_circuit_governance_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PqCircuitGovernanceResult<String> {
        self.config.validate()?;
        validate_count(
            "family policies",
            self.family_policies.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_FAMILY_POLICIES,
        )?;
        validate_count(
            "verifier keys",
            self.verifier_keys.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_VERIFIER_KEYS,
        )?;
        validate_count(
            "committees",
            self.committees.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_COMMITTEES,
        )?;
        validate_count(
            "circuits",
            self.circuits.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_CIRCUITS,
        )?;
        validate_count(
            "activation proposals",
            self.activation_proposals.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_PROPOSALS,
        )?;
        validate_count(
            "attestations",
            self.attestations.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_ATTESTATIONS,
        )?;
        validate_count(
            "audits",
            self.audits.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_AUDITS,
        )?;
        validate_count(
            "deprecations",
            self.deprecation_incidents.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_DEPRECATIONS,
        )?;
        validate_count(
            "compatibility matrices",
            self.compatibility_matrices.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_COMPATIBILITY_MATRICES,
        )?;
        validate_count(
            "recursive policies",
            self.recursive_policies.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_RECURSIVE_POLICIES,
        )?;
        validate_count(
            "sponsorship epochs",
            self.sponsorship_epochs.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_SPONSOR_EPOCHS,
        )?;
        validate_count(
            "sponsorship budgets",
            self.sponsorship_budgets.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_SPONSOR_BUDGETS,
        )?;
        validate_count(
            "migration receipts",
            self.migration_receipts.len(),
            PQ_CIRCUIT_GOVERNANCE_MAX_MIGRATION_RECEIPTS,
        )?;

        for (family_key, policy) in &self.family_policies {
            policy.validate()?;
            if family_key != policy.family.as_str() {
                return Err("family policy map key mismatch".to_string());
            }
        }
        for key in self.verifier_keys.values() {
            key.validate()?;
            if !self.family_policies.contains_key(key.family.as_str()) {
                return Err("verifier key references missing family policy".to_string());
            }
            let policy = self
                .family_policies
                .get(key.family.as_str())
                .ok_or_else(|| "verifier key policy missing".to_string())?;
            if !policy.allowed_proof_systems.contains(&key.proof_system) {
                return Err("verifier key proof system not allowed by family policy".to_string());
            }
            if key.security_bits < policy.min_security_bits {
                return Err("verifier key below family security requirement".to_string());
            }
            if key.max_proof_bytes > policy.max_proof_bytes
                || key.max_verify_micros > policy.max_verify_micros
            {
                return Err("verifier key exceeds family proof limits".to_string());
            }
        }
        for committee in self.committees.values() {
            committee.validate()?;
            if committee.threshold_weight_bps < self.config.min_committee_weight_bps {
                return Err("committee threshold below governance minimum".to_string());
            }
            if committee.min_scheme_count < self.config.min_pq_scheme_count {
                return Err("committee scheme count below governance minimum".to_string());
            }
        }
        for circuit in self.circuits.values() {
            circuit.validate()?;
            let key = self
                .verifier_keys
                .get(&circuit.verifier_key_id)
                .ok_or_else(|| "circuit references missing verifier key".to_string())?;
            if key.family != circuit.family || key.proof_system != circuit.proof_system {
                return Err("circuit verifier key family or proof system mismatch".to_string());
            }
            if self.config.require_monero_bridge_compatibility
                && circuit.family.monero_bridge_related()
                && circuit.monero_compatibility_root.is_none()
            {
                return Err("monero bridge circuit missing required compatibility".to_string());
            }
            if self.config.require_private_defi_compatibility
                && circuit.family.defi_related()
                && circuit.defi_compatibility_root.is_none()
            {
                return Err("private defi circuit missing required compatibility".to_string());
            }
            if let Some(policy_id) = &circuit.recursive_policy_id {
                if !self.recursive_policies.contains_key(policy_id) {
                    return Err("circuit references missing recursive policy".to_string());
                }
            }
            if let Some(previous) = &circuit.previous_circuit_id {
                if !self.circuits.contains_key(previous) {
                    return Err("circuit references missing previous circuit".to_string());
                }
            }
            if let Some(proposal_id) = &circuit.activation_proposal_id {
                if !self.activation_proposals.contains_key(proposal_id) {
                    return Err("circuit references missing activation proposal".to_string());
                }
            }
        }
        for proposal in self.activation_proposals.values() {
            proposal.validate()?;
            if !self.circuits.contains_key(&proposal.circuit_id) {
                return Err("activation proposal references missing circuit".to_string());
            }
            if !self.verifier_keys.contains_key(&proposal.verifier_key_id) {
                return Err("activation proposal references missing verifier key".to_string());
            }
            if proposal.audit_roots.len() < self.config.min_activation_audits {
                return Err("activation proposal below audit threshold".to_string());
            }
            if proposal
                .activation_height
                .saturating_sub(proposal.created_at_height)
                > self
                    .family_policy(proposal.family)?
                    .max_activation_delay_blocks
            {
                return Err("activation proposal exceeds family activation delay".to_string());
            }
            for audit_root in &proposal.audit_roots {
                if !self
                    .audits
                    .values()
                    .any(|audit| audit.audit_root() == *audit_root && audit.status.usable())
                {
                    return Err("activation proposal references missing usable audit".to_string());
                }
            }
            for attestation_root in &proposal.attestation_roots {
                if !self.attestations.values().any(|attestation| {
                    attestation.attestation_root() == *attestation_root
                        && attestation.status.usable()
                }) {
                    return Err(
                        "activation proposal references missing usable attestation".to_string()
                    );
                }
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            let committee = self
                .committees
                .get(&attestation.committee_id)
                .ok_or_else(|| "attestation references missing committee".to_string())?;
            if committee.committee_root() != attestation.committee_root {
                return Err("attestation committee root mismatch".to_string());
            }
            if !committee.active_at_height(attestation.created_at_height) {
                return Err("attestation committee inactive at creation height".to_string());
            }
            let member_ids = committee.member_ids();
            for share in &attestation.shares {
                if !member_ids.contains(&share.member_id) {
                    return Err("attestation share references non-committee member".to_string());
                }
            }
        }
        for audit in self.audits.values() {
            audit.validate()?;
            if !self.circuits.contains_key(&audit.circuit_id) {
                return Err("audit references missing circuit".to_string());
            }
            if !self.verifier_keys.contains_key(&audit.verifier_key_id) {
                return Err("audit references missing verifier key".to_string());
            }
        }
        for incident in self.deprecation_incidents.values() {
            incident.validate()?;
            if !self.circuits.contains_key(&incident.circuit_id) {
                return Err("deprecation references missing circuit".to_string());
            }
            if !self.verifier_keys.contains_key(&incident.verifier_key_id) {
                return Err("deprecation references missing verifier key".to_string());
            }
            if let Some(replacement) = &incident.replacement_circuit_id {
                if !self.circuits.contains_key(replacement) {
                    return Err("deprecation references missing replacement circuit".to_string());
                }
            }
        }
        for matrix in self.compatibility_matrices.values() {
            matrix.validate()?;
        }
        for policy in self.recursive_policies.values() {
            policy.validate()?;
            if let Some(matrix_id) = &policy.compatibility_matrix_id {
                if !self.compatibility_matrices.contains_key(matrix_id) {
                    return Err(
                        "recursive policy references missing compatibility matrix".to_string()
                    );
                }
            }
        }
        for budget in self.sponsorship_budgets.values() {
            budget.validate()?;
            if let Some(circuit_id) = &budget.circuit_id {
                if !self.circuits.contains_key(circuit_id) {
                    return Err("sponsorship budget references missing circuit".to_string());
                }
            }
        }
        for epoch in self.sponsorship_epochs.values() {
            epoch.validate()?;
            for budget_id in &epoch.budget_ids {
                if !self.sponsorship_budgets.contains_key(budget_id) {
                    return Err("sponsorship epoch references missing budget".to_string());
                }
            }
        }
        for receipt in self.migration_receipts.values() {
            receipt.validate()?;
            if !self.circuits.contains_key(&receipt.from_circuit_id)
                || !self.circuits.contains_key(&receipt.to_circuit_id)
            {
                return Err("migration receipt references missing circuit".to_string());
            }
            if let Some(epoch_id) = &receipt.sponsor_epoch_id {
                if !self.sponsorship_epochs.contains_key(epoch_id) {
                    return Err(
                        "migration receipt references missing sponsorship epoch".to_string()
                    );
                }
            }
        }
        Ok(self.state_root())
    }

    pub fn register_family_policy(
        &mut self,
        policy: PqCircuitFamilyPolicy,
    ) -> PqCircuitGovernanceResult<String> {
        policy.validate()?;
        let key = policy.family.as_str().to_string();
        if self.family_policies.contains_key(&key) {
            return Err("family policy already registered".to_string());
        }
        self.family_policies.insert(key.clone(), policy);
        Ok(key)
    }

    pub fn register_verifier_key(
        &mut self,
        verifier_key: PqVerifierKeyRecord,
    ) -> PqCircuitGovernanceResult<String> {
        verifier_key.validate()?;
        if self.verifier_keys.contains_key(&verifier_key.key_id) {
            return Err("verifier key already registered".to_string());
        }
        if !self
            .family_policies
            .contains_key(verifier_key.family.as_str())
        {
            return Err("verifier key references unknown family".to_string());
        }
        let key_id = verifier_key.key_id.clone();
        self.verifier_keys.insert(key_id.clone(), verifier_key);
        Ok(key_id)
    }

    pub fn register_committee(
        &mut self,
        committee: PqVerifierCommittee,
    ) -> PqCircuitGovernanceResult<String> {
        committee.validate()?;
        if self.committees.contains_key(&committee.committee_id) {
            return Err("committee already registered".to_string());
        }
        let committee_id = committee.committee_id.clone();
        self.committees.insert(committee_id.clone(), committee);
        Ok(committee_id)
    }

    pub fn register_circuit(
        &mut self,
        circuit: PqCircuitDescriptor,
    ) -> PqCircuitGovernanceResult<String> {
        circuit.validate()?;
        if self.circuits.contains_key(&circuit.circuit_id) {
            return Err("circuit already registered".to_string());
        }
        if !self.verifier_keys.contains_key(&circuit.verifier_key_id) {
            return Err("circuit references unknown verifier key".to_string());
        }
        let circuit_id = circuit.circuit_id.clone();
        self.circuits.insert(circuit_id.clone(), circuit);
        Ok(circuit_id)
    }

    pub fn submit_activation_proposal(
        &mut self,
        proposal: PqActivationProposal,
    ) -> PqCircuitGovernanceResult<String> {
        proposal.validate()?;
        if self
            .activation_proposals
            .contains_key(&proposal.proposal_id)
        {
            return Err("activation proposal already registered".to_string());
        }
        if !self.circuits.contains_key(&proposal.circuit_id) {
            return Err("activation proposal references unknown circuit".to_string());
        }
        if !self.verifier_keys.contains_key(&proposal.verifier_key_id) {
            return Err("activation proposal references unknown verifier key".to_string());
        }
        let proposal_id = proposal.proposal_id.clone();
        if let Some(circuit) = self.circuits.get_mut(&proposal.circuit_id) {
            circuit.activation_proposal_id = Some(proposal_id.clone());
        }
        self.next_activation_nonce = self.next_activation_nonce.saturating_add(1);
        self.activation_proposals
            .insert(proposal_id.clone(), proposal);
        Ok(proposal_id)
    }

    pub fn insert_attestation(
        &mut self,
        attestation: PqVerifierAttestation,
    ) -> PqCircuitGovernanceResult<String> {
        attestation.validate()?;
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err("attestation already registered".to_string());
        }
        if !self.committees.contains_key(&attestation.committee_id) {
            return Err("attestation references unknown committee".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn insert_audit(&mut self, audit: PqCircuitAudit) -> PqCircuitGovernanceResult<String> {
        audit.validate()?;
        if self.audits.contains_key(&audit.audit_id) {
            return Err("audit already registered".to_string());
        }
        if !self.circuits.contains_key(&audit.circuit_id) {
            return Err("audit references unknown circuit".to_string());
        }
        let audit_id = audit.audit_id.clone();
        self.audits.insert(audit_id.clone(), audit);
        Ok(audit_id)
    }

    pub fn insert_deprecation_incident(
        &mut self,
        incident: PqDeprecationIncident,
    ) -> PqCircuitGovernanceResult<String> {
        incident.validate()?;
        if self
            .deprecation_incidents
            .contains_key(&incident.incident_id)
        {
            return Err("deprecation incident already registered".to_string());
        }
        if !self.circuits.contains_key(&incident.circuit_id) {
            return Err("deprecation references unknown circuit".to_string());
        }
        let incident_id = incident.incident_id.clone();
        self.deprecation_incidents
            .insert(incident_id.clone(), incident);
        self.refresh_lifecycle();
        Ok(incident_id)
    }

    pub fn register_compatibility_matrix(
        &mut self,
        matrix: PqCompatibilityMatrix,
    ) -> PqCircuitGovernanceResult<String> {
        matrix.validate()?;
        if self.compatibility_matrices.contains_key(&matrix.matrix_id) {
            return Err("compatibility matrix already registered".to_string());
        }
        let matrix_id = matrix.matrix_id.clone();
        self.compatibility_matrices
            .insert(matrix_id.clone(), matrix);
        Ok(matrix_id)
    }

    pub fn register_recursive_policy(
        &mut self,
        policy: PqRecursiveAggregationPolicy,
    ) -> PqCircuitGovernanceResult<String> {
        policy.validate()?;
        if self.recursive_policies.contains_key(&policy.policy_id) {
            return Err("recursive policy already registered".to_string());
        }
        let policy_id = policy.policy_id.clone();
        self.recursive_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn insert_sponsorship_budget(
        &mut self,
        budget: PqSponsoredProofBudget,
    ) -> PqCircuitGovernanceResult<String> {
        budget.validate()?;
        if self.sponsorship_budgets.contains_key(&budget.budget_id) {
            return Err("sponsorship budget already registered".to_string());
        }
        let budget_id = budget.budget_id.clone();
        self.sponsorship_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn insert_sponsorship_epoch(
        &mut self,
        epoch: PqProofSponsorshipEpoch,
    ) -> PqCircuitGovernanceResult<String> {
        epoch.validate()?;
        if self.sponsorship_epochs.contains_key(&epoch.epoch_id) {
            return Err("sponsorship epoch already registered".to_string());
        }
        let epoch_id = epoch.epoch_id.clone();
        self.sponsorship_epochs.insert(epoch_id.clone(), epoch);
        self.refresh_lifecycle();
        Ok(epoch_id)
    }

    pub fn insert_migration_receipt(
        &mut self,
        receipt: PqMigrationReceipt,
    ) -> PqCircuitGovernanceResult<String> {
        receipt.validate()?;
        if self.migration_receipts.contains_key(&receipt.receipt_id) {
            return Err("migration receipt already registered".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.migration_receipts.insert(receipt_id.clone(), receipt);
        self.refresh_lifecycle();
        Ok(receipt_id)
    }

    pub fn family_policy(
        &self,
        family: PqCircuitFamily,
    ) -> PqCircuitGovernanceResult<&PqCircuitFamilyPolicy> {
        self.family_policies
            .get(family.as_str())
            .ok_or_else(|| "family policy not found".to_string())
    }

    pub fn active_circuits_for_family(&self, family: PqCircuitFamily) -> Vec<&PqCircuitDescriptor> {
        self.circuits
            .values()
            .filter(|circuit| circuit.family == family && circuit.status.accepts_new_proofs())
            .collect()
    }

    pub fn migration_receipts_for_circuit(&self, circuit_id: &str) -> Vec<&PqMigrationReceipt> {
        self.migration_receipts
            .values()
            .filter(|receipt| {
                receipt.from_circuit_id == circuit_id || receipt.to_circuit_id == circuit_id
            })
            .collect()
    }

    pub fn family_policy_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-FAMILY-POLICY",
            &self
                .family_policies
                .values()
                .map(PqCircuitFamilyPolicy::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn verifier_key_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-VERIFIER-KEY",
            &self
                .verifier_keys
                .values()
                .map(PqVerifierKeyRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn committee_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-COMMITTEE",
            &self
                .committees
                .values()
                .map(PqVerifierCommittee::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn circuit_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-CIRCUIT",
            &self
                .circuits
                .values()
                .map(PqCircuitDescriptor::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn activation_proposal_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-ACTIVATION-PROPOSAL",
            &self
                .activation_proposals
                .values()
                .map(PqActivationProposal::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn attestation_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-ATTESTATION",
            &self
                .attestations
                .values()
                .map(PqVerifierAttestation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn audit_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-AUDIT",
            &self
                .audits
                .values()
                .map(PqCircuitAudit::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn deprecation_incident_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-DEPRECATION",
            &self
                .deprecation_incidents
                .values()
                .map(PqDeprecationIncident::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn compatibility_matrix_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-COMPATIBILITY-MATRIX",
            &self
                .compatibility_matrices
                .values()
                .map(PqCompatibilityMatrix::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn recursive_policy_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-RECURSIVE-POLICY",
            &self
                .recursive_policies
                .values()
                .map(PqRecursiveAggregationPolicy::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_epoch_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-SPONSORSHIP-EPOCH",
            &self
                .sponsorship_epochs
                .values()
                .map(PqProofSponsorshipEpoch::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_budget_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-SPONSORSHIP-BUDGET",
            &self
                .sponsorship_budgets
                .values()
                .map(PqSponsoredProofBudget::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn migration_receipt_root(&self) -> String {
        merkle_root(
            "PQ-CIRCUIT-GOVERNANCE-MIGRATION-RECEIPT",
            &self
                .migration_receipts
                .values()
                .map(PqMigrationReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn refresh_lifecycle(&mut self) {
        for proposal in self.activation_proposals.values_mut() {
            if matches!(proposal.status, PqActivationProposalStatus::Scheduled)
                && self.height >= proposal.activation_height
            {
                proposal.status = PqActivationProposalStatus::Active;
            }
        }
        for circuit in self.circuits.values_mut() {
            if matches!(
                circuit.status,
                PqCircuitStatus::Scheduled | PqCircuitStatus::Attested
            ) && circuit
                .activation_height
                .map(|height| self.height >= height)
                .unwrap_or(false)
            {
                circuit.status = PqCircuitStatus::Active;
            }
            if matches!(circuit.status, PqCircuitStatus::GraceOnly)
                && circuit
                    .grace_until_height
                    .map(|height| self.height > height)
                    .unwrap_or(false)
            {
                circuit.status = PqCircuitStatus::Deprecated;
            }
        }
        for incident in self.deprecation_incidents.values_mut() {
            if matches!(
                incident.status,
                PqDeprecationStatus::Reported | PqDeprecationStatus::Quarantined
            ) && self.height >= incident.migration_start_height
            {
                incident.status = PqDeprecationStatus::MigrationOpen;
            }
            if matches!(incident.status, PqDeprecationStatus::MigrationOpen)
                && self.height > incident.migration_end_height
            {
                incident.status = PqDeprecationStatus::Deprecated;
            }
            if matches!(incident.status, PqDeprecationStatus::Deprecated)
                && self.height >= incident.disable_height
            {
                incident.status = PqDeprecationStatus::Disabled;
            }
        }
        for incident in self.deprecation_incidents.values() {
            if let Some(circuit) = self.circuits.get_mut(&incident.circuit_id) {
                match incident.status {
                    PqDeprecationStatus::MigrationOpen => {
                        if circuit.status.accepts_new_proofs() {
                            circuit.status = PqCircuitStatus::GraceOnly;
                            circuit.grace_until_height = Some(incident.migration_end_height);
                            circuit.replacement_circuit_id =
                                incident.replacement_circuit_id.clone();
                        }
                    }
                    PqDeprecationStatus::Deprecated => {
                        circuit.status = PqCircuitStatus::Deprecated;
                        circuit.replacement_circuit_id = incident.replacement_circuit_id.clone();
                    }
                    PqDeprecationStatus::Disabled => {
                        if self.config.allow_emergency_disable {
                            circuit.status = PqCircuitStatus::Disabled;
                        }
                    }
                    _ => {}
                }
            }
        }
        for epoch in self.sponsorship_epochs.values_mut() {
            if !matches!(epoch.status, PqSponsorshipEpochStatus::Suspended) {
                epoch.status = if self.height < epoch.start_height {
                    PqSponsorshipEpochStatus::Upcoming
                } else if self.height <= epoch.end_height {
                    PqSponsorshipEpochStatus::Active
                } else if self.height <= epoch.settlement_height {
                    PqSponsorshipEpochStatus::Settling
                } else {
                    PqSponsorshipEpochStatus::Closed
                };
            }
        }
        for receipt in self.migration_receipts.values_mut() {
            if matches!(
                receipt.status,
                PqMigrationReceiptStatus::Pending | PqMigrationReceiptStatus::Submitted
            ) && self.height > receipt.expires_at_height
            {
                receipt.status = PqMigrationReceiptStatus::Expired;
            }
            if receipt.finalized_at_height.is_some()
                && !matches!(
                    receipt.status,
                    PqMigrationReceiptStatus::Rejected | PqMigrationReceiptStatus::Superseded
                )
            {
                receipt.status = PqMigrationReceiptStatus::Finalized;
            }
        }
        for attestation in self.attestations.values_mut() {
            if !attestation.status.usable()
                && matches!(attestation.status, PqAttestationStatus::Pending)
                && self.height > attestation.expires_at_height
            {
                attestation.status = PqAttestationStatus::Expired;
            }
        }
        for audit in self.audits.values_mut() {
            if audit.status.usable() && self.height > audit.expires_at_height {
                audit.status = PqAuditStatus::Expired;
            }
        }
    }

    fn install_devnet_family_policies(&mut self) -> PqCircuitGovernanceResult<()> {
        let families = [
            PqCircuitFamily::RollupState,
            PqCircuitFamily::MoneroBridgeFinality,
            PqCircuitFamily::PrivateDexSwap,
            PqCircuitFamily::RecursiveAggregation,
            PqCircuitFamily::FeeSponsorship,
        ];
        for family in families {
            let proof_systems = match family {
                PqCircuitFamily::RecursiveAggregation => vec![
                    PqProofSystem::FoldingNovaShake,
                    PqProofSystem::Halo2Shake,
                    PqProofSystem::RiscZeroShake,
                ],
                PqCircuitFamily::MoneroBridgeFinality => {
                    vec![PqProofSystem::MoneroBridgeCustom, PqProofSystem::ShakePlonk]
                }
                PqCircuitFamily::PrivateDexSwap => {
                    vec![PqProofSystem::ShakeStark, PqProofSystem::FfriStark]
                }
                _ => vec![PqProofSystem::ShakePlonk, PqProofSystem::ShakeStark],
            };
            let policy = PqCircuitFamilyPolicy::new(
                family,
                proof_systems,
                vec![
                    PqSignatureScheme::MlDsa65,
                    PqSignatureScheme::SlhDsaShake128s,
                    PqSignatureScheme::HybridMlDsa65SlhDsa128s,
                ],
                pq_circuit_governance_string_root("DEVNET-FAMILY-POLICY", family.as_str()),
            )?;
            self.register_family_policy(policy)?;
        }
        Ok(())
    }

    fn devnet_committee(&self) -> PqCircuitGovernanceResult<PqVerifierCommittee> {
        let members = vec![
            PqVerifierCommitteeMember::new(
                "devnet-pq-circuit-alice",
                PqCommitteeRole::VerifierAttester,
                40,
                pq_circuit_governance_string_root("DEVNET-ML-DSA-PK", "alice"),
                pq_circuit_governance_string_root("DEVNET-SLH-DSA-PK", "alice"),
                pq_circuit_governance_string_root("DEVNET-CONTACT", "alice"),
                self.height.saturating_sub(240),
            )?,
            PqVerifierCommitteeMember::new(
                "devnet-pq-circuit-bob",
                PqCommitteeRole::CircuitAuditor,
                35,
                pq_circuit_governance_string_root("DEVNET-ML-DSA-PK", "bob"),
                pq_circuit_governance_string_root("DEVNET-SLH-DSA-PK", "bob"),
                pq_circuit_governance_string_root("DEVNET-CONTACT", "bob"),
                self.height.saturating_sub(240),
            )?,
            PqVerifierCommitteeMember::new(
                "devnet-pq-circuit-carol",
                PqCommitteeRole::BridgeGuardian,
                25,
                pq_circuit_governance_string_root("DEVNET-ML-DSA-PK", "carol"),
                pq_circuit_governance_string_root("DEVNET-SLH-DSA-PK", "carol"),
                pq_circuit_governance_string_root("DEVNET-CONTACT", "carol"),
                self.height.saturating_sub(240),
            )?,
        ];
        PqVerifierCommittee::new(
            "devnet-pq-circuit-verifier-committee",
            vec![
                PqCommitteeRole::CircuitAuditor,
                PqCommitteeRole::VerifierAttester,
                PqCommitteeRole::BridgeGuardian,
                PqCommitteeRole::RecursiveVerifier,
                PqCommitteeRole::SponsorAuditor,
                PqCommitteeRole::EmergencyDeprecator,
                PqCommitteeRole::MigrationWitness,
            ],
            members,
            self.config.min_committee_weight_bps,
            self.config.min_pq_scheme_count,
            self.height.saturating_sub(240),
            None,
            PqCommitteeStatus::Active,
            true,
        )
    }

    fn devnet_verifier_key(
        &self,
        family: PqCircuitFamily,
        proof_system: PqProofSystem,
        key_version: u64,
        status: PqVerifierKeyStatus,
        activated_at_height: Option<u64>,
        expires_at_height: Option<u64>,
    ) -> PqCircuitGovernanceResult<PqVerifierKeyRecord> {
        PqVerifierKeyRecord::new(
            family,
            proof_system,
            key_version,
            pq_circuit_governance_string_root(
                "DEVNET-VERIFYING-KEY",
                &format!("{}-{key_version}", family.as_str()),
            ),
            pq_circuit_governance_string_root(
                "DEVNET-CONSTRAINT-SYSTEM",
                &format!("{}-{key_version}", family.as_str()),
            ),
            pq_circuit_governance_string_root(
                "DEVNET-CIRCUIT-PARAMETERS",
                &format!("{}-{key_version}", family.as_str()),
            ),
            pq_circuit_governance_string_root(
                "DEVNET-TRANSCRIPT-DOMAIN",
                &format!("{}-{key_version}", family.as_str()),
            ),
            if proof_system.supports_recursion() {
                Some(pq_circuit_governance_string_root(
                    "DEVNET-RECURSION-VK",
                    &format!("{}-{key_version}", family.as_str()),
                ))
            } else {
                None
            },
            pq_circuit_governance_string_root(
                "DEVNET-VERIFIER-METADATA",
                &format!("{}-{key_version}", family.as_str()),
            ),
            if family.privacy_sensitive() { 192 } else { 128 },
            if family.recursive_only() {
                192 * 1024
            } else {
                96 * 1024
            },
            if family.recursive_only() {
                1_200_000
            } else {
                600_000
            },
            activated_at_height,
            expires_at_height,
            status,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn devnet_circuit(
        &self,
        family: PqCircuitFamily,
        proof_system: PqProofSystem,
        circuit_version: u64,
        verifier_key_id: &str,
        previous_circuit_id: Option<String>,
        monero_compatibility_root: Option<String>,
        defi_compatibility_root: Option<String>,
        recursive_policy_id: Option<String>,
        activation_height: Option<u64>,
        grace_until_height: Option<u64>,
        status: PqCircuitStatus,
        low_fee_eligible: bool,
    ) -> PqCircuitGovernanceResult<PqCircuitDescriptor> {
        let mut metadata = BTreeMap::new();
        metadata.insert("devnet_fixture".to_string(), "true".to_string());
        metadata.insert("family".to_string(), family.as_str().to_string());
        PqCircuitDescriptor::new(
            family,
            family.default_circuit_name(),
            circuit_version,
            proof_system,
            verifier_key_id,
            previous_circuit_id,
            pq_circuit_governance_string_root(
                "DEVNET-PUBLIC-INPUT-SCHEMA",
                &format!("{}-{circuit_version}", family.as_str()),
            ),
            pq_circuit_governance_string_root(
                "DEVNET-PRIVATE-WITNESS-SCHEMA",
                &format!("{}-{circuit_version}", family.as_str()),
            ),
            monero_compatibility_root,
            defi_compatibility_root,
            recursive_policy_id,
            pq_circuit_governance_string_root(
                "DEVNET-AUDIT-BUNDLE",
                &format!("{}-{circuit_version}", family.as_str()),
            ),
            None,
            activation_height,
            grace_until_height,
            status,
            low_fee_eligible,
            metadata,
        )
    }

    fn devnet_audit(
        &self,
        circuit_id: &str,
        key_id: &str,
        auditor: &str,
        family: PqCircuitFamily,
        status: PqAuditStatus,
    ) -> PqCircuitGovernanceResult<PqCircuitAudit> {
        PqCircuitAudit::new(
            circuit_id,
            key_id,
            pq_circuit_governance_string_root("DEVNET-AUDITOR", auditor),
            pq_circuit_governance_string_root("DEVNET-AUDIT-REPORT", auditor),
            pq_circuit_governance_string_root("DEVNET-AUDIT-FINDINGS", auditor),
            PqAuditSeverity::Medium,
            status,
            self.height.saturating_sub(36),
            self.height.saturating_add(self.config.audit_ttl_blocks),
            pq_circuit_governance_string_root("DEVNET-REPRODUCIBLE-BUILD", auditor),
            pq_circuit_governance_string_root("DEVNET-FUZZ-CORPUS", auditor),
            pq_circuit_governance_string_root("DEVNET-SIDE-CHANNEL-REVIEW", auditor),
            if family.monero_bridge_related() {
                Some(pq_circuit_governance_string_root(
                    "DEVNET-MONERO-PRIVACY-REVIEW",
                    auditor,
                ))
            } else {
                None
            },
            if family.defi_related() || family.monero_bridge_related() {
                Some(pq_circuit_governance_string_root(
                    "DEVNET-DEFI-COMPATIBILITY-REVIEW",
                    auditor,
                ))
            } else {
                None
            },
        )
    }

    fn devnet_attestation(
        &self,
        subject_kind: PqAttestationSubjectKind,
        subject_id: &str,
        subject_root: &str,
        committee_id: &str,
        committee_root: &str,
        label: &str,
        created_at_height: u64,
    ) -> PqCircuitGovernanceResult<PqVerifierAttestation> {
        let committee = self
            .committees
            .get(committee_id)
            .ok_or_else(|| "devnet committee missing".to_string())?;
        let mut shares = Vec::new();
        for (member, scheme) in committee.members.iter().take(2).zip([
            PqSignatureScheme::MlDsa65,
            PqSignatureScheme::SlhDsaShake128s,
        ]) {
            shares.push(PqCommitteeSignatureShare::new(
                &member.member_id,
                scheme,
                subject_root,
                pq_circuit_governance_string_root(
                    "DEVNET-ATTESTATION-SIGNATURE",
                    &format!("{label}-{}-{}", member.operator_label, scheme.as_str()),
                ),
                created_at_height,
            )?);
        }
        PqVerifierAttestation::new(
            subject_kind,
            subject_id,
            subject_root,
            committee_id,
            committee_root,
            self.config.min_committee_weight_bps,
            7_500,
            self.config.min_pq_scheme_count,
            shares,
            pq_circuit_governance_string_root("DEVNET-AGGREGATE-SIGNATURE", label),
            created_at_height,
            created_at_height.saturating_add(self.config.attestation_ttl_blocks),
            PqAttestationStatus::ThresholdMet,
        )
    }

    fn devnet_compatibility_matrix(
        &self,
        bridge_id: &str,
        dex_id: &str,
        recursive_id: &str,
    ) -> PqCircuitGovernanceResult<PqCompatibilityMatrix> {
        let rules = vec![
            PqCompatibilityRule::new(
                PqCircuitFamily::MoneroBridgeFinality,
                PqCircuitFamily::PrivateDexSwap,
                Some(bridge_id.to_string()),
                Some(dex_id.to_string()),
                PqCompatibilityStatus::Compatible,
                None,
                Some(pq_circuit_governance_string_root(
                    "DEVNET-NULLIFIER-DOMAIN",
                    "bridge-dex",
                )),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-ASSET-DOMAIN",
                    "wxmr-private-dex",
                )),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-MONERO-NETWORK",
                    "monero-devnet",
                )),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-PRIVATE-STATE",
                    "bridge-dex",
                )),
                self.height.saturating_sub(48),
                None,
                pq_circuit_governance_string_root("DEVNET-COMPAT-RATIONALE", "bridge-dex"),
            )?,
            PqCompatibilityRule::new(
                PqCircuitFamily::RecursiveAggregation,
                PqCircuitFamily::MoneroBridgeFinality,
                Some(recursive_id.to_string()),
                Some(bridge_id.to_string()),
                PqCompatibilityStatus::RequiresAdapter,
                Some(recursive_id.to_string()),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-NULLIFIER-DOMAIN",
                    "recursive-bridge",
                )),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-ASSET-DOMAIN",
                    "recursive-bridge",
                )),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-MONERO-NETWORK",
                    "monero-devnet",
                )),
                Some(pq_circuit_governance_string_root(
                    "DEVNET-PRIVATE-STATE",
                    "recursive-bridge",
                )),
                self.height.saturating_sub(48),
                None,
                pq_circuit_governance_string_root("DEVNET-COMPAT-RATIONALE", "recursive-bridge"),
            )?,
        ];
        PqCompatibilityMatrix::new(
            "devnet-monero-private-defi-compatibility",
            rules,
            1,
            self.height.saturating_sub(48),
            vec![],
            PqCompatibilityStatus::Compatible,
        )
    }

    fn audit_roots_for_circuit(&self, circuit_id: &str) -> Vec<String> {
        self.audits
            .values()
            .filter(|audit| audit.circuit_id == circuit_id && audit.status.usable())
            .map(PqCircuitAudit::audit_root)
            .collect()
    }
}

pub fn pq_circuit_governance_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-CIRCUIT-GOVERNANCE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn pq_circuit_governance_hash_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn pq_circuit_governance_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

fn pq_circuit_governance_verifier_key_id(
    family: PqCircuitFamily,
    proof_system: PqProofSystem,
    key_version: u64,
    verifying_key_root: &str,
    constraint_system_root: &str,
    parameters_root: &str,
) -> String {
    domain_hash(
        "PQ-VERIFIER-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(family.as_str()),
            HashPart::Str(proof_system.as_str()),
            HashPart::Int(key_version as i128),
            HashPart::Str(verifying_key_root),
            HashPart::Str(constraint_system_root),
            HashPart::Str(parameters_root),
        ],
        32,
    )
}

fn pq_circuit_governance_circuit_id(
    family: PqCircuitFamily,
    circuit_name: &str,
    circuit_version: u64,
    proof_system: PqProofSystem,
    verifier_key_id: &str,
) -> String {
    domain_hash(
        "PQ-CIRCUIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(family.as_str()),
            HashPart::Str(circuit_name),
            HashPart::Int(circuit_version as i128),
            HashPart::Str(proof_system.as_str()),
            HashPart::Str(verifier_key_id),
        ],
        32,
    )
}

fn pq_circuit_governance_member_id(
    operator_label: &str,
    role: PqCommitteeRole,
    ml_dsa_public_key_root: &str,
    slh_dsa_public_key_root: &str,
    joined_at_height: u64,
) -> String {
    domain_hash(
        "PQ-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(operator_label),
            HashPart::Str(role.as_str()),
            HashPart::Str(ml_dsa_public_key_root),
            HashPart::Str(slh_dsa_public_key_root),
            HashPart::Int(joined_at_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_committee_id(
    label: &str,
    member_root: &str,
    role_root: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PQ-VERIFIER-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(member_root),
            HashPart::Str(role_root),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_signature_share_id(
    member_id: &str,
    scheme: PqSignatureScheme,
    signed_subject_root: &str,
    signature_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-SIGNATURE-SHARE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(member_id),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(signed_subject_root),
            HashPart::Str(signature_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_attestation_id(
    subject_kind: PqAttestationSubjectKind,
    subject_id: &str,
    subject_root: &str,
    committee_id: &str,
    share_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PQ-VERIFIER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(subject_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(committee_id),
            HashPart::Str(share_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_activation_proposal_id(
    circuit_id: &str,
    family: PqCircuitFamily,
    verifier_key_id: &str,
    audit_root: &str,
    attestation_root: &str,
    activation_height: u64,
) -> String {
    domain_hash(
        "PQ-ACTIVATION-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(circuit_id),
            HashPart::Str(family.as_str()),
            HashPart::Str(verifier_key_id),
            HashPart::Str(audit_root),
            HashPart::Str(attestation_root),
            HashPart::Int(activation_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_audit_id(
    circuit_id: &str,
    verifier_key_id: &str,
    auditor_commitment_root: &str,
    audit_report_root: &str,
    completed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-CIRCUIT-AUDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(circuit_id),
            HashPart::Str(verifier_key_id),
            HashPart::Str(auditor_commitment_root),
            HashPart::Str(audit_report_root),
            HashPart::Int(completed_at_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_deprecation_id(
    circuit_id: &str,
    verifier_key_id: &str,
    reason: PqDeprecationReason,
    evidence_root: &str,
    report_height: u64,
) -> String {
    domain_hash(
        "PQ-DEPRECATION-INCIDENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(circuit_id),
            HashPart::Str(verifier_key_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(report_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_compatibility_rule_id(
    source_family: PqCircuitFamily,
    target_family: PqCircuitFamily,
    source_circuit_id: &str,
    target_circuit_id: &str,
    status: PqCompatibilityStatus,
    effective_from_height: u64,
) -> String {
    domain_hash(
        "PQ-COMPATIBILITY-RULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(source_family.as_str()),
            HashPart::Str(target_family.as_str()),
            HashPart::Str(source_circuit_id),
            HashPart::Str(target_circuit_id),
            HashPart::Str(status.as_str()),
            HashPart::Int(effective_from_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_matrix_id(
    label: &str,
    matrix_version: u64,
    rule_root: &str,
    effective_from_height: u64,
) -> String {
    domain_hash(
        "PQ-COMPATIBILITY-MATRIX-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Int(matrix_version as i128),
            HashPart::Str(rule_root),
            HashPart::Int(effective_from_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_recursive_policy_id(
    family: PqCircuitFamily,
    mode: PqRecursiveAggregationMode,
    aggregator_circuit_id: &str,
    child_root: &str,
    effective_from_height: u64,
) -> String {
    domain_hash(
        "PQ-RECURSIVE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(family.as_str()),
            HashPart::Str(mode.as_str()),
            HashPart::Str(aggregator_circuit_id),
            HashPart::Str(child_root),
            HashPart::Int(effective_from_height as i128),
        ],
        32,
    )
}

fn pq_circuit_governance_sponsor_budget_id(
    sponsor_commitment_root: &str,
    family: PqCircuitFamily,
    circuit_id: &str,
    beneficiary_group_root: &str,
    eligibility_root: &str,
) -> String {
    domain_hash(
        "PQ-SPONSOR-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment_root),
            HashPart::Str(family.as_str()),
            HashPart::Str(circuit_id),
            HashPart::Str(beneficiary_group_root),
            HashPart::Str(eligibility_root),
        ],
        32,
    )
}

fn pq_circuit_governance_sponsorship_epoch_id(
    label: &str,
    fee_asset_id: &str,
    sponsor_asset_id: &str,
    start_height: u64,
    end_height: u64,
    budget_root: &str,
) -> String {
    domain_hash(
        "PQ-SPONSORSHIP-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(fee_asset_id),
            HashPart::Str(sponsor_asset_id),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(budget_root),
        ],
        32,
    )
}

fn pq_circuit_governance_migration_receipt_id(
    subject_commitment_root: &str,
    from_circuit_id: &str,
    to_circuit_id: &str,
    migration_window_id: &str,
    attestation_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "PQ-MIGRATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_CIRCUIT_GOVERNANCE_PROTOCOL_VERSION),
            HashPart::Str(subject_commitment_root),
            HashPart::Str(from_circuit_id),
            HashPart::Str(to_circuit_id),
            HashPart::Str(migration_window_id),
            HashPart::Str(attestation_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

fn validate_bps(label: &str, value: u64) -> PqCircuitGovernanceResult<()> {
    if value > PQ_CIRCUIT_GOVERNANCE_MAX_BPS {
        return Err(format!("{label} exceeds 10000 bps"));
    }
    Ok(())
}

fn validate_count(label: &str, value: usize, max: usize) -> PqCircuitGovernanceResult<()> {
    if value > max {
        return Err(format!("{label} count exceeds maximum"));
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> PqCircuitGovernanceResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be non-empty"));
    }
    Ok(())
}
