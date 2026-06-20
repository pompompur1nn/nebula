use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CIRCUIT_UPGRADE_GOVERNANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-circuit-upgrade-governance-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_GOVERNANCE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-circuit-upgrades-v1";
pub const ANONYMOUS_STAKE_VOTE_SCHEME: &str = "anonymous-stake-weighted-nullifier-vote-root-v1";
pub const COMPATIBILITY_MANIFEST_SCHEME: &str =
    "confidential-circuit-compatibility-manifest-root-v1";
pub const LOW_FEE_BATCH_EXECUTION_SCHEME: &str =
    "low-fee-confidential-circuit-upgrade-batch-receipt-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "privacy-nullifier-fence-v1";
pub const DEVNET_HEIGHT: u64 = 888_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_PROPOSALS: usize = 1_048_576;
pub const DEFAULT_MAX_VALIDATOR_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_KEY_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_VOTE_COMMITMENTS: usize = 8_388_608;
pub const DEFAULT_MAX_EMERGENCY_VETOES: usize = 262_144;
pub const DEFAULT_MAX_MIGRATION_PLANS: usize = 524_288;
pub const DEFAULT_MAX_COMPATIBILITY_MANIFESTS: usize = 524_288;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_BATCH_RECEIPTS: usize = 524_288;
pub const DEFAULT_MAX_EXECUTION_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_EMERGENCY_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_VALIDATOR_ATTESTATION_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_APPROVAL_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_EMERGENCY_VETO_WEIGHT_BPS: u64 = 8_000;
pub const DEFAULT_MIN_COMPATIBILITY_SCORE_BPS: u64 = 9_000;
pub const DEFAULT_MIN_KEY_ROTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_VOTE_WINDOW_BLOCKS: u64 = 7_200;
pub const DEFAULT_MIN_TIMELOCK_BLOCKS: u64 = 1_440;
pub const DEFAULT_MAX_TIMELOCK_BLOCKS: u64 = 172_800;
pub const DEFAULT_EMERGENCY_VETO_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MIGRATION_GRACE_BLOCKS: u64 = 14_400;
pub const DEFAULT_COMPATIBILITY_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_SLASHING_EVIDENCE_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_BATCH_PROPOSALS: usize = 512;
pub const DEFAULT_MAX_EXECUTION_FEE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_SPONSOR_COVERAGE_BPS: u64 = 9_500;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitFamily {
    RollupStateTransition,
    ConfidentialTransfer,
    ConfidentialTokenMintBurn,
    PrivateContractExecution,
    RecursiveAggregation,
    MoneroDepositMembership,
    MoneroWithdrawalAuthorization,
    BridgeFinality,
    PrivateDefiAccounting,
    PrivateOrderflow,
    FeeSponsorship,
    DataAvailabilitySampling,
    WalletPolicy,
    ViewKeyAudit,
    EmergencyEscape,
}

impl CircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupStateTransition => "rollup_state_transition",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::ConfidentialTokenMintBurn => "confidential_token_mint_burn",
            Self::PrivateContractExecution => "private_contract_execution",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::MoneroDepositMembership => "monero_deposit_membership",
            Self::MoneroWithdrawalAuthorization => "monero_withdrawal_authorization",
            Self::BridgeFinality => "bridge_finality",
            Self::PrivateDefiAccounting => "private_defi_accounting",
            Self::PrivateOrderflow => "private_orderflow",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::DataAvailabilitySampling => "data_availability_sampling",
            Self::WalletPolicy => "wallet_policy",
            Self::ViewKeyAudit => "view_key_audit",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn privacy_critical(self) -> bool {
        matches!(
            self,
            Self::ConfidentialTransfer
                | Self::ConfidentialTokenMintBurn
                | Self::PrivateContractExecution
                | Self::MoneroDepositMembership
                | Self::MoneroWithdrawalAuthorization
                | Self::PrivateDefiAccounting
                | Self::PrivateOrderflow
                | Self::FeeSponsorship
                | Self::WalletPolicy
                | Self::ViewKeyAudit
        )
    }

    pub fn bridge_critical(self) -> bool {
        matches!(
            self,
            Self::MoneroDepositMembership
                | Self::MoneroWithdrawalAuthorization
                | Self::BridgeFinality
                | Self::EmergencyEscape
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    ShakePlonk,
    ShakeStark,
    FfriStark,
    FoldingNovaShake,
    Halo2Shake,
    RiscZeroShake,
    NoirShake,
    MoneroBridgeCustom,
    HybridStarkSnark,
}

impl ProofSystem {
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
            Self::HybridStarkSnark => "hybrid_stark_snark",
        }
    }

    pub fn supports_recursion(self) -> bool {
        matches!(
            self,
            Self::ShakePlonk
                | Self::FoldingNovaShake
                | Self::Halo2Shake
                | Self::RiscZeroShake
                | Self::HybridStarkSnark
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake192f,
    SlhDsaShake256f,
    HybridMlDsa87SlhDsa256f,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
            Self::SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
            Self::HybridMlDsa87SlhDsa256f => "ML-DSA-87+SLH-DSA-SHAKE-256f",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::SlhDsaShake192f => 192,
            Self::MlDsa87 | Self::SlhDsaShake256f | Self::HybridMlDsa87SlhDsa256f => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    VerifierKeyRotation,
    CircuitParameterUpgrade,
    ConstraintSystemReplacement,
    RecursiveVerifierMigration,
    PrivacyFenceExpansion,
    CompatibilityPatch,
    EmergencyHotfix,
    LowFeeExecutionPolicy,
    Deprecation,
}

impl ProposalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::CircuitParameterUpgrade => "circuit_parameter_upgrade",
            Self::ConstraintSystemReplacement => "constraint_system_replacement",
            Self::RecursiveVerifierMigration => "recursive_verifier_migration",
            Self::PrivacyFenceExpansion => "privacy_fence_expansion",
            Self::CompatibilityPatch => "compatibility_patch",
            Self::EmergencyHotfix => "emergency_hotfix",
            Self::LowFeeExecutionPolicy => "low_fee_execution_policy",
            Self::Deprecation => "deprecation",
        }
    }

    pub fn emergency_eligible(self) -> bool {
        matches!(self, Self::EmergencyHotfix | Self::PrivacyFenceExpansion)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Drafted,
    Attesting,
    Voting,
    Approved,
    Timelocked,
    Ready,
    Batched,
    Executed,
    Vetoed,
    Rejected,
    Expired,
    Superseded,
    Slashed,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Attesting => "attesting",
            Self::Voting => "voting",
            Self::Approved => "approved",
            Self::Timelocked => "timelocked",
            Self::Ready => "ready",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Vetoed => "vetoed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_attestation(self) -> bool {
        matches!(self, Self::Drafted | Self::Attesting)
    }

    pub fn accepts_vote(self) -> bool {
        matches!(self, Self::Attesting | Self::Voting)
    }

    pub fn accepts_veto(self) -> bool {
        matches!(
            self,
            Self::Drafted | Self::Attesting | Self::Voting | Self::Approved
        )
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Approved | Self::Timelocked | Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approve,
    Reject,
    Abstain,
    NeedsCompatibilityProof,
    NeedsMigrationPlan,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
            Self::NeedsCompatibilityProof => "needs_compatibility_proof",
            Self::NeedsMigrationPlan => "needs_migration_plan",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

impl VoteChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Planned,
    ShadowVerifying,
    DualAccepted,
    PrimarySwitched,
    LegacyGrace,
    LegacyDisabled,
    Completed,
    RolledBack,
}

impl MigrationPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::ShadowVerifying => "shadow_verifying",
            Self::DualAccepted => "dual_accepted",
            Self::PrimarySwitched => "primary_switched",
            Self::LegacyGrace => "legacy_grace",
            Self::LegacyDisabled => "legacy_disabled",
            Self::Completed => "completed",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityGrade {
    Compatible,
    RequiresAdapter,
    RequiresStateMigration,
    ShadowOnly,
    Incompatible,
}

impl CompatibilityGrade {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::RequiresAdapter => "requires_adapter",
            Self::RequiresStateMigration => "requires_state_migration",
            Self::ShadowOnly => "shadow_only",
            Self::Incompatible => "incompatible",
        }
    }

    pub fn executable(self) -> bool {
        !matches!(self, Self::Incompatible | Self::ShadowOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidVerifierKey,
    IncompatibleConstraintSystem,
    DuplicateNullifier,
    VoteEquivocation,
    AttestationEquivocation,
    UnsafeMigrationPlan,
    PrivacySetUnderflow,
    FeeOvercharge,
    EmergencyVetoAbuse,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidVerifierKey => "invalid_verifier_key",
            Self::IncompatibleConstraintSystem => "incompatible_constraint_system",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::VoteEquivocation => "vote_equivocation",
            Self::AttestationEquivocation => "attestation_equivocation",
            Self::UnsafeMigrationPlan => "unsafe_migration_plan",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
            Self::FeeOvercharge => "fee_overcharge",
            Self::EmergencyVetoAbuse => "emergency_veto_abuse",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Reserved,
    Batched,
    Executed,
    Failed,
    Rebated,
    Expired,
}

impl ExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Failed => "failed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub devnet_height: u64,
    pub max_proposals: usize,
    pub max_validator_attestations: usize,
    pub max_key_attestations: usize,
    pub max_vote_commitments: usize,
    pub max_emergency_vetoes: usize,
    pub max_migration_plans: usize,
    pub max_compatibility_manifests: usize,
    pub max_slashing_evidence: usize,
    pub max_privacy_fences: usize,
    pub max_batch_receipts: usize,
    pub max_execution_receipts: usize,
    pub max_batch_proposals: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub emergency_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_validator_attestation_weight_bps: u64,
    pub min_approval_weight_bps: u64,
    pub min_emergency_veto_weight_bps: u64,
    pub min_compatibility_score_bps: u64,
    pub min_key_rotation_quorum_bps: u64,
    pub proposal_ttl_blocks: u64,
    pub vote_window_blocks: u64,
    pub min_timelock_blocks: u64,
    pub max_timelock_blocks: u64,
    pub emergency_veto_window_blocks: u64,
    pub migration_grace_blocks: u64,
    pub compatibility_ttl_blocks: u64,
    pub slashing_evidence_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub max_execution_fee_bps: u64,
    pub low_fee_sponsor_coverage_bps: u64,
    pub require_migration_plan: bool,
    pub require_compatibility_manifest: bool,
    pub require_privacy_fence: bool,
    pub require_low_fee_batch_receipt: bool,
    pub allow_emergency_veto: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            max_proposals: DEFAULT_MAX_PROPOSALS,
            max_validator_attestations: DEFAULT_MAX_VALIDATOR_ATTESTATIONS,
            max_key_attestations: DEFAULT_MAX_KEY_ATTESTATIONS,
            max_vote_commitments: DEFAULT_MAX_VOTE_COMMITMENTS,
            max_emergency_vetoes: DEFAULT_MAX_EMERGENCY_VETOES,
            max_migration_plans: DEFAULT_MAX_MIGRATION_PLANS,
            max_compatibility_manifests: DEFAULT_MAX_COMPATIBILITY_MANIFESTS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_batch_receipts: DEFAULT_MAX_BATCH_RECEIPTS,
            max_execution_receipts: DEFAULT_MAX_EXECUTION_RECEIPTS,
            max_batch_proposals: DEFAULT_MAX_BATCH_PROPOSALS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            emergency_privacy_set_size: DEFAULT_EMERGENCY_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_validator_attestation_weight_bps: DEFAULT_MIN_VALIDATOR_ATTESTATION_WEIGHT_BPS,
            min_approval_weight_bps: DEFAULT_MIN_APPROVAL_WEIGHT_BPS,
            min_emergency_veto_weight_bps: DEFAULT_MIN_EMERGENCY_VETO_WEIGHT_BPS,
            min_compatibility_score_bps: DEFAULT_MIN_COMPATIBILITY_SCORE_BPS,
            min_key_rotation_quorum_bps: DEFAULT_MIN_KEY_ROTATION_QUORUM_BPS,
            proposal_ttl_blocks: DEFAULT_PROPOSAL_TTL_BLOCKS,
            vote_window_blocks: DEFAULT_VOTE_WINDOW_BLOCKS,
            min_timelock_blocks: DEFAULT_MIN_TIMELOCK_BLOCKS,
            max_timelock_blocks: DEFAULT_MAX_TIMELOCK_BLOCKS,
            emergency_veto_window_blocks: DEFAULT_EMERGENCY_VETO_WINDOW_BLOCKS,
            migration_grace_blocks: DEFAULT_MIGRATION_GRACE_BLOCKS,
            compatibility_ttl_blocks: DEFAULT_COMPATIBILITY_TTL_BLOCKS,
            slashing_evidence_ttl_blocks: DEFAULT_SLASHING_EVIDENCE_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            max_execution_fee_bps: DEFAULT_MAX_EXECUTION_FEE_BPS,
            low_fee_sponsor_coverage_bps: DEFAULT_LOW_FEE_SPONSOR_COVERAGE_BPS,
            require_migration_plan: true,
            require_compatibility_manifest: true,
            require_privacy_fence: true,
            require_low_fee_batch_receipt: true,
            allow_emergency_veto: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("confidential circuit governance chain id mismatch".to_string());
        }
        require_positive_usize("max_proposals", self.max_proposals)?;
        require_positive_usize(
            "max_validator_attestations",
            self.max_validator_attestations,
        )?;
        require_positive_usize("max_key_attestations", self.max_key_attestations)?;
        require_positive_usize("max_vote_commitments", self.max_vote_commitments)?;
        require_positive_usize("max_emergency_vetoes", self.max_emergency_vetoes)?;
        require_positive_usize("max_migration_plans", self.max_migration_plans)?;
        require_positive_usize(
            "max_compatibility_manifests",
            self.max_compatibility_manifests,
        )?;
        require_positive_usize("max_slashing_evidence", self.max_slashing_evidence)?;
        require_positive_usize("max_privacy_fences", self.max_privacy_fences)?;
        require_positive_usize("max_batch_receipts", self.max_batch_receipts)?;
        require_positive_usize("max_execution_receipts", self.max_execution_receipts)?;
        require_positive_usize("max_batch_proposals", self.max_batch_proposals)?;
        require_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must be at least minimum privacy set".to_string());
        }
        if self.emergency_privacy_set_size == 0
            || self.emergency_privacy_set_size > self.min_privacy_set_size
        {
            return Err(
                "emergency privacy set must be positive and no larger than normal minimum"
                    .to_string(),
            );
        }
        if self.min_pq_security_bits < 128 {
            return Err("minimum PQ security bits below accepted floor".to_string());
        }
        require_bps(
            "min_validator_attestation_weight_bps",
            self.min_validator_attestation_weight_bps,
        )?;
        require_bps("min_approval_weight_bps", self.min_approval_weight_bps)?;
        require_bps(
            "min_emergency_veto_weight_bps",
            self.min_emergency_veto_weight_bps,
        )?;
        require_bps(
            "min_compatibility_score_bps",
            self.min_compatibility_score_bps,
        )?;
        require_bps(
            "min_key_rotation_quorum_bps",
            self.min_key_rotation_quorum_bps,
        )?;
        require_bps("max_execution_fee_bps", self.max_execution_fee_bps)?;
        require_bps(
            "low_fee_sponsor_coverage_bps",
            self.low_fee_sponsor_coverage_bps,
        )?;
        if self.min_timelock_blocks > self.max_timelock_blocks {
            return Err("minimum timelock cannot exceed maximum timelock".to_string());
        }
        require_positive_u64("proposal_ttl_blocks", self.proposal_ttl_blocks)?;
        require_positive_u64("vote_window_blocks", self.vote_window_blocks)?;
        require_positive_u64("compatibility_ttl_blocks", self.compatibility_ttl_blocks)?;
        require_positive_u64(
            "slashing_evidence_ttl_blocks",
            self.slashing_evidence_ttl_blocks,
        )?;
        require_positive_u64("batch_ttl_blocks", self.batch_ttl_blocks)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "devnet_height": self.devnet_height,
            "max_proposals": self.max_proposals,
            "max_validator_attestations": self.max_validator_attestations,
            "max_key_attestations": self.max_key_attestations,
            "max_vote_commitments": self.max_vote_commitments,
            "max_emergency_vetoes": self.max_emergency_vetoes,
            "max_migration_plans": self.max_migration_plans,
            "max_compatibility_manifests": self.max_compatibility_manifests,
            "max_slashing_evidence": self.max_slashing_evidence,
            "max_privacy_fences": self.max_privacy_fences,
            "max_batch_receipts": self.max_batch_receipts,
            "max_execution_receipts": self.max_execution_receipts,
            "max_batch_proposals": self.max_batch_proposals,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "emergency_privacy_set_size": self.emergency_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_validator_attestation_weight_bps": self.min_validator_attestation_weight_bps,
            "min_approval_weight_bps": self.min_approval_weight_bps,
            "min_emergency_veto_weight_bps": self.min_emergency_veto_weight_bps,
            "min_compatibility_score_bps": self.min_compatibility_score_bps,
            "min_key_rotation_quorum_bps": self.min_key_rotation_quorum_bps,
            "proposal_ttl_blocks": self.proposal_ttl_blocks,
            "vote_window_blocks": self.vote_window_blocks,
            "min_timelock_blocks": self.min_timelock_blocks,
            "max_timelock_blocks": self.max_timelock_blocks,
            "emergency_veto_window_blocks": self.emergency_veto_window_blocks,
            "migration_grace_blocks": self.migration_grace_blocks,
            "compatibility_ttl_blocks": self.compatibility_ttl_blocks,
            "slashing_evidence_ttl_blocks": self.slashing_evidence_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "max_execution_fee_bps": self.max_execution_fee_bps,
            "low_fee_sponsor_coverage_bps": self.low_fee_sponsor_coverage_bps,
            "require_migration_plan": self.require_migration_plan,
            "require_compatibility_manifest": self.require_compatibility_manifest,
            "require_privacy_fence": self.require_privacy_fence,
            "require_low_fee_batch_receipt": self.require_low_fee_batch_receipt,
            "allow_emergency_veto": self.allow_emergency_veto,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub proposals: u64,
    pub validator_attestations: u64,
    pub key_attestations: u64,
    pub vote_commitments: u64,
    pub emergency_vetoes: u64,
    pub migration_plans: u64,
    pub compatibility_manifests: u64,
    pub slashing_evidence: u64,
    pub privacy_fences: u64,
    pub batch_receipts: u64,
    pub execution_receipts: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "proposals": self.proposals,
            "validator_attestations": self.validator_attestations,
            "key_attestations": self.key_attestations,
            "vote_commitments": self.vote_commitments,
            "emergency_vetoes": self.emergency_vetoes,
            "migration_plans": self.migration_plans,
            "compatibility_manifests": self.compatibility_manifests,
            "slashing_evidence": self.slashing_evidence,
            "privacy_fences": self.privacy_fences,
            "batch_receipts": self.batch_receipts,
            "execution_receipts": self.execution_receipts,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub proposal_root: String,
    pub open_proposal_root: String,
    pub validator_attestation_root: String,
    pub key_attestation_root: String,
    pub vote_commitment_root: String,
    pub vote_nullifier_root: String,
    pub emergency_veto_root: String,
    pub migration_plan_root: String,
    pub compatibility_manifest_root: String,
    pub slashing_evidence_root: String,
    pub privacy_fence_root: String,
    pub execution_batch_root: String,
    pub execution_receipt_root: String,
    pub low_fee_receipt_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            proposal_root: empty_root("PROPOSALS"),
            open_proposal_root: empty_root("OPEN-PROPOSALS"),
            validator_attestation_root: empty_root("VALIDATOR-ATTESTATIONS"),
            key_attestation_root: empty_root("KEY-ATTESTATIONS"),
            vote_commitment_root: empty_root("VOTE-COMMITMENTS"),
            vote_nullifier_root: empty_root("VOTE-NULLIFIERS"),
            emergency_veto_root: empty_root("EMERGENCY-VETOES"),
            migration_plan_root: empty_root("MIGRATION-PLANS"),
            compatibility_manifest_root: empty_root("COMPATIBILITY-MANIFESTS"),
            slashing_evidence_root: empty_root("SLASHING-EVIDENCE"),
            privacy_fence_root: empty_root("PRIVACY-FENCES"),
            execution_batch_root: empty_root("EXECUTION-BATCHES"),
            execution_receipt_root: empty_root("EXECUTION-RECEIPTS"),
            low_fee_receipt_root: empty_root("LOW-FEE-RECEIPTS"),
            event_root: empty_root("EVENTS"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proposal_root": self.proposal_root,
            "open_proposal_root": self.open_proposal_root,
            "validator_attestation_root": self.validator_attestation_root,
            "key_attestation_root": self.key_attestation_root,
            "vote_commitment_root": self.vote_commitment_root,
            "vote_nullifier_root": self.vote_nullifier_root,
            "emergency_veto_root": self.emergency_veto_root,
            "migration_plan_root": self.migration_plan_root,
            "compatibility_manifest_root": self.compatibility_manifest_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "privacy_fence_root": self.privacy_fence_root,
            "execution_batch_root": self.execution_batch_root,
            "execution_receipt_root": self.execution_receipt_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitProposalRequest {
    pub family: CircuitFamily,
    pub kind: ProposalKind,
    pub proof_system: ProofSystem,
    pub proposer_commitment: String,
    pub old_verifier_key_root: String,
    pub new_verifier_key_root: String,
    pub constraint_system_root: String,
    pub parameter_root: String,
    pub artifact_bundle_root: String,
    pub compatibility_claim_root: String,
    pub migration_claim_root: String,
    pub privacy_impact_root: String,
    pub fee_policy_root: String,
    pub stake_commitment_root: String,
    pub pq_signature_root: String,
    pub proposal_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub proposed_at_height: u64,
    pub vote_start_height: u64,
    pub vote_end_height: u64,
    pub timelock_end_height: u64,
    pub expires_at_height: u64,
}

impl CircuitProposalRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "family": self.family.as_str(),
            "kind": self.kind.as_str(),
            "proof_system": self.proof_system.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "old_verifier_key_root": self.old_verifier_key_root,
            "new_verifier_key_root": self.new_verifier_key_root,
            "constraint_system_root": self.constraint_system_root,
            "parameter_root": self.parameter_root,
            "artifact_bundle_root": self.artifact_bundle_root,
            "compatibility_claim_root": self.compatibility_claim_root,
            "migration_claim_root": self.migration_claim_root,
            "privacy_impact_root": self.privacy_impact_root,
            "fee_policy_root": self.fee_policy_root,
            "stake_commitment_root": self.stake_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "proposal_nullifier": self.proposal_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "proposed_at_height": self.proposed_at_height,
            "vote_start_height": self.vote_start_height,
            "vote_end_height": self.vote_end_height,
            "timelock_end_height": self.timelock_end_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitProposal {
    pub proposal_id: String,
    pub sequence: u64,
    pub status: ProposalStatus,
    pub request: CircuitProposalRequest,
    pub validator_approval_weight_bps: u64,
    pub validator_reject_weight_bps: u64,
    pub anonymous_approval_weight_bps: u64,
    pub anonymous_reject_weight_bps: u64,
    pub emergency_veto_weight_bps: u64,
    pub compatibility_score_bps: u64,
    pub migration_plan_id: String,
    pub compatibility_manifest_id: String,
    pub privacy_fence_id: String,
    pub batch_id: String,
    pub executed_receipt_id: String,
}

impl CircuitProposal {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
            "validator_approval_weight_bps": self.validator_approval_weight_bps,
            "validator_reject_weight_bps": self.validator_reject_weight_bps,
            "anonymous_approval_weight_bps": self.anonymous_approval_weight_bps,
            "anonymous_reject_weight_bps": self.anonymous_reject_weight_bps,
            "emergency_veto_weight_bps": self.emergency_veto_weight_bps,
            "compatibility_score_bps": self.compatibility_score_bps,
            "migration_plan_id": self.migration_plan_id,
            "compatibility_manifest_id": self.compatibility_manifest_id,
            "privacy_fence_id": self.privacy_fence_id,
            "batch_id": self.batch_id,
            "executed_receipt_id": self.executed_receipt_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidatorAttestationRequest {
    pub proposal_id: String,
    pub validator_commitment: String,
    pub validator_set_root: String,
    pub validator_key_root: String,
    pub attestation_transcript_root: String,
    pub signature_root: String,
    pub verdict: AttestationVerdict,
    pub stake_weight_bps: u64,
    pub pq_security_bits: u16,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_nullifier: String,
}

impl ValidatorAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "validator_commitment": self.validator_commitment,
            "validator_set_root": self.validator_set_root,
            "validator_key_root": self.validator_key_root,
            "attestation_transcript_root": self.attestation_transcript_root,
            "signature_root": self.signature_root,
            "verdict": self.verdict.as_str(),
            "stake_weight_bps": self.stake_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "attestation_nullifier": self.attestation_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidatorAttestation {
    pub attestation_id: String,
    pub sequence: u64,
    pub request: ValidatorAttestationRequest,
}

impl ValidatorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyAttestationRequest {
    pub proposal_id: String,
    pub key_attestor_commitment: String,
    pub old_key_root: String,
    pub new_key_root: String,
    pub key_ceremony_root: String,
    pub entropy_beacon_root: String,
    pub hardware_fence_root: String,
    pub downgrade_resistance_root: String,
    pub pq_signature_scheme: PqSignatureScheme,
    pub pq_signature_root: String,
    pub attestor_weight_bps: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub key_attestation_nullifier: String,
}

impl KeyAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "key_attestor_commitment": self.key_attestor_commitment,
            "old_key_root": self.old_key_root,
            "new_key_root": self.new_key_root,
            "key_ceremony_root": self.key_ceremony_root,
            "entropy_beacon_root": self.entropy_beacon_root,
            "hardware_fence_root": self.hardware_fence_root,
            "downgrade_resistance_root": self.downgrade_resistance_root,
            "pq_signature_scheme": self.pq_signature_scheme.as_str(),
            "pq_signature_root": self.pq_signature_root,
            "attestor_weight_bps": self.attestor_weight_bps,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "key_attestation_nullifier": self.key_attestation_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyAttestation {
    pub key_attestation_id: String,
    pub sequence: u64,
    pub request: KeyAttestationRequest,
}

impl KeyAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "key_attestation_id": self.key_attestation_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnonymousVoteRequest {
    pub proposal_id: String,
    pub vote_choice: VoteChoice,
    pub voter_commitment: String,
    pub stake_weight_commitment: String,
    pub encrypted_weight_root: String,
    pub membership_proof_root: String,
    pub vote_policy_root: String,
    pub anonymity_set_root: String,
    pub vote_nullifier: String,
    pub pq_signature_root: String,
    pub stake_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub cast_at_height: u64,
}

impl AnonymousVoteRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "vote_choice": self.vote_choice.as_str(),
            "voter_commitment": self.voter_commitment,
            "stake_weight_commitment": self.stake_weight_commitment,
            "encrypted_weight_root": self.encrypted_weight_root,
            "membership_proof_root": self.membership_proof_root,
            "vote_policy_root": self.vote_policy_root,
            "anonymity_set_root": self.anonymity_set_root,
            "vote_nullifier": self.vote_nullifier,
            "pq_signature_root": self.pq_signature_root,
            "stake_weight_bps": self.stake_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "cast_at_height": self.cast_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AnonymousVote {
    pub vote_id: String,
    pub sequence: u64,
    pub request: AnonymousVoteRequest,
}

impl AnonymousVote {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyVetoRequest {
    pub proposal_id: String,
    pub guardian_commitment: String,
    pub guardian_set_root: String,
    pub threat_evidence_root: String,
    pub affected_circuit_root: String,
    pub veto_reason_root: String,
    pub emergency_action_root: String,
    pub pq_signature_root: String,
    pub veto_nullifier: String,
    pub guardian_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub vetoed_at_height: u64,
}

impl EmergencyVetoRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "guardian_commitment": self.guardian_commitment,
            "guardian_set_root": self.guardian_set_root,
            "threat_evidence_root": self.threat_evidence_root,
            "affected_circuit_root": self.affected_circuit_root,
            "veto_reason_root": self.veto_reason_root,
            "emergency_action_root": self.emergency_action_root,
            "pq_signature_root": self.pq_signature_root,
            "veto_nullifier": self.veto_nullifier,
            "guardian_weight_bps": self.guardian_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "vetoed_at_height": self.vetoed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyVeto {
    pub veto_id: String,
    pub sequence: u64,
    pub request: EmergencyVetoRequest,
}

impl EmergencyVeto {
    pub fn public_record(&self) -> Value {
        json!({
            "veto_id": self.veto_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierMigrationPlanRequest {
    pub proposal_id: String,
    pub legacy_verifier_key_root: String,
    pub candidate_verifier_key_root: String,
    pub adapter_circuit_root: String,
    pub state_migration_root: String,
    pub transcript_replay_root: String,
    pub rollback_plan_root: String,
    pub shadow_verification_root: String,
    pub phase: MigrationPhase,
    pub planned_at_height: u64,
    pub shadow_start_height: u64,
    pub dual_accept_start_height: u64,
    pub primary_switch_height: u64,
    pub legacy_disable_height: u64,
    pub completed_by_height: u64,
    pub plan_nullifier: String,
}

impl VerifierMigrationPlanRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "legacy_verifier_key_root": self.legacy_verifier_key_root,
            "candidate_verifier_key_root": self.candidate_verifier_key_root,
            "adapter_circuit_root": self.adapter_circuit_root,
            "state_migration_root": self.state_migration_root,
            "transcript_replay_root": self.transcript_replay_root,
            "rollback_plan_root": self.rollback_plan_root,
            "shadow_verification_root": self.shadow_verification_root,
            "phase": self.phase.as_str(),
            "planned_at_height": self.planned_at_height,
            "shadow_start_height": self.shadow_start_height,
            "dual_accept_start_height": self.dual_accept_start_height,
            "primary_switch_height": self.primary_switch_height,
            "legacy_disable_height": self.legacy_disable_height,
            "completed_by_height": self.completed_by_height,
            "plan_nullifier": self.plan_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierMigrationPlan {
    pub migration_plan_id: String,
    pub sequence: u64,
    pub request: VerifierMigrationPlanRequest,
}

impl VerifierMigrationPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "migration_plan_id": self.migration_plan_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompatibilityManifestRequest {
    pub proposal_id: String,
    pub circuit_family: CircuitFamily,
    pub grade: CompatibilityGrade,
    pub old_interface_root: String,
    pub new_interface_root: String,
    pub witness_layout_root: String,
    pub public_input_schema_root: String,
    pub recursive_wrapper_root: String,
    pub proving_key_manifest_root: String,
    pub verifier_api_manifest_root: String,
    pub downstream_dependency_root: String,
    pub audit_report_root: String,
    pub compatibility_score_bps: u64,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub manifest_nullifier: String,
}

impl CompatibilityManifestRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "circuit_family": self.circuit_family.as_str(),
            "grade": self.grade.as_str(),
            "old_interface_root": self.old_interface_root,
            "new_interface_root": self.new_interface_root,
            "witness_layout_root": self.witness_layout_root,
            "public_input_schema_root": self.public_input_schema_root,
            "recursive_wrapper_root": self.recursive_wrapper_root,
            "proving_key_manifest_root": self.proving_key_manifest_root,
            "verifier_api_manifest_root": self.verifier_api_manifest_root,
            "downstream_dependency_root": self.downstream_dependency_root,
            "audit_report_root": self.audit_report_root,
            "compatibility_score_bps": self.compatibility_score_bps,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
            "manifest_nullifier": self.manifest_nullifier,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompatibilityManifest {
    pub manifest_id: String,
    pub sequence: u64,
    pub request: CompatibilityManifestRequest,
}

impl CompatibilityManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRequest {
    pub proposal_id: String,
    pub accused_commitment: String,
    pub evidence_kind: EvidenceKind,
    pub evidence_root: String,
    pub conflicting_record_root: String,
    pub replay_transcript_root: String,
    pub privacy_damage_root: String,
    pub penalty_policy_root: String,
    pub reporter_commitment: String,
    pub reporter_signature_root: String,
    pub evidence_nullifier: String,
    pub slash_weight_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl SlashingEvidenceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "accused_commitment": self.accused_commitment,
            "evidence_kind": self.evidence_kind.as_str(),
            "evidence_root": self.evidence_root,
            "conflicting_record_root": self.conflicting_record_root,
            "replay_transcript_root": self.replay_transcript_root,
            "privacy_damage_root": self.privacy_damage_root,
            "penalty_policy_root": self.penalty_policy_root,
            "reporter_commitment": self.reporter_commitment,
            "reporter_signature_root": self.reporter_signature_root,
            "evidence_nullifier": self.evidence_nullifier,
            "slash_weight_bps": self.slash_weight_bps,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub sequence: u64,
    pub request: SlashingEvidenceRequest,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFenceRequest {
    pub proposal_id: String,
    pub fence_domain: String,
    pub prior_nullifier_root: String,
    pub new_nullifier_root: String,
    pub spent_note_root: String,
    pub unspent_note_root: String,
    pub view_tag_root: String,
    pub decoy_set_root: String,
    pub replay_guard_root: String,
    pub disclosure_policy_root: String,
    pub privacy_audit_root: String,
    pub fence_nullifier: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
}

impl PrivacyNullifierFenceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "fence_domain": self.fence_domain,
            "prior_nullifier_root": self.prior_nullifier_root,
            "new_nullifier_root": self.new_nullifier_root,
            "spent_note_root": self.spent_note_root,
            "unspent_note_root": self.unspent_note_root,
            "view_tag_root": self.view_tag_root,
            "decoy_set_root": self.decoy_set_root,
            "replay_guard_root": self.replay_guard_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "privacy_audit_root": self.privacy_audit_root,
            "fence_nullifier": self.fence_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub sequence: u64,
    pub request: PrivacyNullifierFenceRequest,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "sequence": self.sequence,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchExecutionRequest {
    pub proposal_ids: Vec<String>,
    pub executor_commitment: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_execution_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub reservation_root: String,
    pub execution_plan_root: String,
    pub pre_state_root: String,
    pub expected_post_state_root: String,
    pub privacy_fence_root: String,
    pub compatibility_root: String,
    pub migration_root: String,
    pub pq_signature_root: String,
    pub batch_nullifier: String,
    pub batch_privacy_set_size: u64,
    pub earliest_execution_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeBatchExecutionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_ids": self.proposal_ids,
            "executor_commitment": self.executor_commitment,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_execution_fee_bps": self.max_execution_fee_bps,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "reservation_root": self.reservation_root,
            "execution_plan_root": self.execution_plan_root,
            "pre_state_root": self.pre_state_root,
            "expected_post_state_root": self.expected_post_state_root,
            "privacy_fence_root": self.privacy_fence_root,
            "compatibility_root": self.compatibility_root,
            "migration_root": self.migration_root,
            "pq_signature_root": self.pq_signature_root,
            "batch_nullifier": self.batch_nullifier,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "earliest_execution_height": self.earliest_execution_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchExecutionReceipt {
    pub batch_id: String,
    pub sequence: u64,
    pub status: ExecutionStatus,
    pub request: LowFeeBatchExecutionRequest,
}

impl LowFeeBatchExecutionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptRequest {
    pub batch_id: String,
    pub proposal_id: String,
    pub executor_commitment: String,
    pub applied_verifier_key_root: String,
    pub applied_constraint_system_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub fee_receipt_root: String,
    pub migration_receipt_root: String,
    pub compatibility_receipt_root: String,
    pub privacy_fence_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub pq_signature_root: String,
    pub execution_nullifier: String,
    pub executed_at_height: u64,
}

impl ExecutionReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "proposal_id": self.proposal_id,
            "executor_commitment": self.executor_commitment,
            "applied_verifier_key_root": self.applied_verifier_key_root,
            "applied_constraint_system_root": self.applied_constraint_system_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "fee_receipt_root": self.fee_receipt_root,
            "migration_receipt_root": self.migration_receipt_root,
            "compatibility_receipt_root": self.compatibility_receipt_root,
            "privacy_fence_receipt_root": self.privacy_fence_receipt_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pq_signature_root": self.pq_signature_root,
            "execution_nullifier": self.execution_nullifier,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub status: ExecutionStatus,
    pub request: ExecutionReceiptRequest,
}

impl ExecutionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub sequence: u64,
    pub kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "sequence": self.sequence,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub proposals: BTreeMap<String, CircuitProposal>,
    pub open_proposals: BTreeSet<String>,
    pub validator_attestations: BTreeMap<String, ValidatorAttestation>,
    pub key_attestations: BTreeMap<String, KeyAttestation>,
    pub vote_commitments: BTreeMap<String, AnonymousVote>,
    pub vote_nullifiers: BTreeSet<String>,
    pub emergency_vetoes: BTreeMap<String, EmergencyVeto>,
    pub migration_plans: BTreeMap<String, VerifierMigrationPlan>,
    pub compatibility_manifests: BTreeMap<String, CompatibilityManifest>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub execution_batches: BTreeMap<String, LowFeeBatchExecutionReceipt>,
    pub execution_receipts: BTreeMap<String, ExecutionReceipt>,
    pub low_fee_receipts: BTreeSet<String>,
    pub events: Vec<RuntimeEvent>,
}

pub type Runtime = State;

impl State {
    pub fn devnet() -> Result<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            proposals: BTreeMap::new(),
            open_proposals: BTreeSet::new(),
            validator_attestations: BTreeMap::new(),
            key_attestations: BTreeMap::new(),
            vote_commitments: BTreeMap::new(),
            vote_nullifiers: BTreeSet::new(),
            emergency_vetoes: BTreeMap::new(),
            migration_plans: BTreeMap::new(),
            compatibility_manifests: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            low_fee_receipts: BTreeSet::new(),
            events: Vec::new(),
        };

        let proposal = CircuitProposalRequest {
            family: CircuitFamily::PrivateContractExecution,
            kind: ProposalKind::VerifierKeyRotation,
            proof_system: ProofSystem::HybridStarkSnark,
            proposer_commitment: deterministic_root("DEVNET-PROPOSER", "committee-a"),
            old_verifier_key_root: deterministic_root("DEVNET-OLD-KEY", "private-contract-v1"),
            new_verifier_key_root: deterministic_root("DEVNET-NEW-KEY", "private-contract-v2"),
            constraint_system_root: deterministic_root("DEVNET-CONSTRAINTS", "contract-v2"),
            parameter_root: deterministic_root("DEVNET-PARAMETERS", "contract-v2"),
            artifact_bundle_root: deterministic_root("DEVNET-ARTIFACTS", "contract-v2"),
            compatibility_claim_root: deterministic_root("DEVNET-COMPATIBILITY", "contract-v2"),
            migration_claim_root: deterministic_root("DEVNET-MIGRATION", "contract-v2"),
            privacy_impact_root: deterministic_root("DEVNET-PRIVACY", "contract-v2"),
            fee_policy_root: deterministic_root("DEVNET-FEE-POLICY", "low-fee"),
            stake_commitment_root: deterministic_root("DEVNET-STAKE", "committee-a"),
            pq_signature_root: deterministic_root("DEVNET-PQ-SIGNATURE", "proposal"),
            proposal_nullifier: deterministic_root("DEVNET-PROPOSAL-NULLIFIER", "proposal"),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            proposed_at_height: DEVNET_HEIGHT,
            vote_start_height: DEVNET_HEIGHT + 8,
            vote_end_height: DEVNET_HEIGHT + 8 + DEFAULT_VOTE_WINDOW_BLOCKS,
            timelock_end_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_PROPOSAL_TTL_BLOCKS,
        };
        let proposal_id = state.submit_proposal(proposal)?;

        state.submit_validator_attestation(ValidatorAttestationRequest {
            proposal_id: proposal_id.clone(),
            validator_commitment: deterministic_root("DEVNET-VALIDATOR", "validator-a"),
            validator_set_root: deterministic_root("DEVNET-VALIDATOR-SET", "epoch-1"),
            validator_key_root: deterministic_root("DEVNET-VALIDATOR-KEY", "validator-a"),
            attestation_transcript_root: deterministic_root("DEVNET-ATTESTATION", "validator-a"),
            signature_root: deterministic_root("DEVNET-VALIDATOR-SIGNATURE", "validator-a"),
            verdict: AttestationVerdict::Approve,
            stake_weight_bps: DEFAULT_MIN_VALIDATOR_ATTESTATION_WEIGHT_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            signed_at_height: DEVNET_HEIGHT + 10,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_PROPOSAL_TTL_BLOCKS,
            attestation_nullifier: deterministic_root(
                "DEVNET-VALIDATOR-ATTESTATION-NULLIFIER",
                "validator-a",
            ),
        })?;

        state.submit_key_attestation(KeyAttestationRequest {
            proposal_id: proposal_id.clone(),
            key_attestor_commitment: deterministic_root("DEVNET-KEY-ATTESTOR", "attestor-a"),
            old_key_root: deterministic_root("DEVNET-OLD-KEY", "private-contract-v1"),
            new_key_root: deterministic_root("DEVNET-NEW-KEY", "private-contract-v2"),
            key_ceremony_root: deterministic_root("DEVNET-KEY-CEREMONY", "ceremony-a"),
            entropy_beacon_root: deterministic_root("DEVNET-ENTROPY", "beacon-a"),
            hardware_fence_root: deterministic_root("DEVNET-HARDWARE-FENCE", "attestor-a"),
            downgrade_resistance_root: deterministic_root("DEVNET-DOWNGRADE-FENCE", "v2"),
            pq_signature_scheme: PqSignatureScheme::HybridMlDsa87SlhDsa256f,
            pq_signature_root: deterministic_root("DEVNET-KEY-SIGNATURE", "attestor-a"),
            attestor_weight_bps: DEFAULT_MIN_KEY_ROTATION_QUORUM_BPS,
            signed_at_height: DEVNET_HEIGHT + 11,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_PROPOSAL_TTL_BLOCKS,
            key_attestation_nullifier: deterministic_root("DEVNET-KEY-NULLIFIER", "attestor-a"),
        })?;

        state.publish_migration_plan(VerifierMigrationPlanRequest {
            proposal_id: proposal_id.clone(),
            legacy_verifier_key_root: deterministic_root("DEVNET-OLD-KEY", "private-contract-v1"),
            candidate_verifier_key_root: deterministic_root(
                "DEVNET-NEW-KEY",
                "private-contract-v2",
            ),
            adapter_circuit_root: deterministic_root("DEVNET-ADAPTER", "v1-to-v2"),
            state_migration_root: deterministic_root("DEVNET-STATE-MIGRATION", "v1-to-v2"),
            transcript_replay_root: deterministic_root("DEVNET-REPLAY", "shadow"),
            rollback_plan_root: deterministic_root("DEVNET-ROLLBACK", "v2-to-v1"),
            shadow_verification_root: deterministic_root("DEVNET-SHADOW", "v2"),
            phase: MigrationPhase::DualAccepted,
            planned_at_height: DEVNET_HEIGHT + 12,
            shadow_start_height: DEVNET_HEIGHT + 20,
            dual_accept_start_height: DEVNET_HEIGHT + 40,
            primary_switch_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS,
            legacy_disable_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS
                + DEFAULT_MIGRATION_GRACE_BLOCKS,
            completed_by_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS
                + DEFAULT_MIGRATION_GRACE_BLOCKS
                + DEFAULT_COMPATIBILITY_TTL_BLOCKS,
            plan_nullifier: deterministic_root("DEVNET-MIGRATION-NULLIFIER", "plan-a"),
        })?;

        state.publish_compatibility_manifest(CompatibilityManifestRequest {
            proposal_id: proposal_id.clone(),
            circuit_family: CircuitFamily::PrivateContractExecution,
            grade: CompatibilityGrade::RequiresAdapter,
            old_interface_root: deterministic_root("DEVNET-OLD-INTERFACE", "contract-v1"),
            new_interface_root: deterministic_root("DEVNET-NEW-INTERFACE", "contract-v2"),
            witness_layout_root: deterministic_root("DEVNET-WITNESS-LAYOUT", "contract-v2"),
            public_input_schema_root: deterministic_root("DEVNET-PUBLIC-INPUTS", "contract-v2"),
            recursive_wrapper_root: deterministic_root("DEVNET-RECURSIVE-WRAPPER", "contract-v2"),
            proving_key_manifest_root: deterministic_root("DEVNET-PROVING-KEYS", "contract-v2"),
            verifier_api_manifest_root: deterministic_root("DEVNET-VERIFIER-API", "contract-v2"),
            downstream_dependency_root: deterministic_root("DEVNET-DEPENDENCIES", "contract-v2"),
            audit_report_root: deterministic_root("DEVNET-AUDIT", "contract-v2"),
            compatibility_score_bps: DEFAULT_MIN_COMPATIBILITY_SCORE_BPS,
            published_at_height: DEVNET_HEIGHT + 13,
            expires_at_height: DEVNET_HEIGHT + DEFAULT_COMPATIBILITY_TTL_BLOCKS,
            manifest_nullifier: deterministic_root("DEVNET-MANIFEST-NULLIFIER", "manifest-a"),
        })?;

        state.install_privacy_fence(PrivacyNullifierFenceRequest {
            proposal_id: proposal_id.clone(),
            fence_domain: "private-contract-execution-v2".to_string(),
            prior_nullifier_root: deterministic_root("DEVNET-PRIOR-NULLIFIERS", "contract-v1"),
            new_nullifier_root: deterministic_root("DEVNET-NEW-NULLIFIERS", "contract-v2"),
            spent_note_root: deterministic_root("DEVNET-SPENT-NOTES", "contract-v2"),
            unspent_note_root: deterministic_root("DEVNET-UNSPENT-NOTES", "contract-v2"),
            view_tag_root: deterministic_root("DEVNET-VIEW-TAGS", "contract-v2"),
            decoy_set_root: deterministic_root("DEVNET-DECOYS", "contract-v2"),
            replay_guard_root: deterministic_root("DEVNET-REPLAY-GUARD", "contract-v2"),
            disclosure_policy_root: deterministic_root("DEVNET-DISCLOSURE", "contract-v2"),
            privacy_audit_root: deterministic_root("DEVNET-PRIVACY-AUDIT", "contract-v2"),
            fence_nullifier: deterministic_root("DEVNET-FENCE-NULLIFIER", "fence-a"),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            created_at_height: DEVNET_HEIGHT + 14,
        })?;

        state.cast_anonymous_vote(AnonymousVoteRequest {
            proposal_id: proposal_id.clone(),
            vote_choice: VoteChoice::Approve,
            voter_commitment: deterministic_root("DEVNET-VOTER", "stake-pool-a"),
            stake_weight_commitment: deterministic_root("DEVNET-VOTE-WEIGHT", "stake-pool-a"),
            encrypted_weight_root: deterministic_root("DEVNET-ENCRYPTED-WEIGHT", "stake-pool-a"),
            membership_proof_root: deterministic_root("DEVNET-MEMBERSHIP", "stake-pool-a"),
            vote_policy_root: deterministic_root("DEVNET-VOTE-POLICY", "standard"),
            anonymity_set_root: deterministic_root("DEVNET-ANONYMITY-SET", "epoch-1"),
            vote_nullifier: deterministic_root("DEVNET-VOTE-NULLIFIER", "stake-pool-a"),
            pq_signature_root: deterministic_root("DEVNET-VOTE-SIGNATURE", "stake-pool-a"),
            stake_weight_bps: DEFAULT_MIN_APPROVAL_WEIGHT_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            cast_at_height: DEVNET_HEIGHT + 16,
        })?;

        let batch_id = state.reserve_low_fee_batch(LowFeeBatchExecutionRequest {
            proposal_ids: vec![proposal_id.clone()],
            executor_commitment: deterministic_root("DEVNET-EXECUTOR", "executor-a"),
            sponsor_commitment: deterministic_root("DEVNET-SPONSOR", "sponsor-a"),
            fee_asset_id: "piconero".to_string(),
            max_execution_fee_bps: DEFAULT_MAX_EXECUTION_FEE_BPS,
            sponsor_coverage_bps: DEFAULT_LOW_FEE_SPONSOR_COVERAGE_BPS,
            reservation_root: deterministic_root("DEVNET-RESERVATION", "batch-a"),
            execution_plan_root: deterministic_root("DEVNET-EXECUTION-PLAN", "batch-a"),
            pre_state_root: deterministic_root("DEVNET-PRE-STATE", "batch-a"),
            expected_post_state_root: deterministic_root("DEVNET-POST-STATE", "batch-a"),
            privacy_fence_root: deterministic_root("DEVNET-BATCH-FENCES", "batch-a"),
            compatibility_root: deterministic_root("DEVNET-BATCH-COMPATIBILITY", "batch-a"),
            migration_root: deterministic_root("DEVNET-BATCH-MIGRATION", "batch-a"),
            pq_signature_root: deterministic_root("DEVNET-BATCH-SIGNATURE", "batch-a"),
            batch_nullifier: deterministic_root("DEVNET-BATCH-NULLIFIER", "batch-a"),
            batch_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            earliest_execution_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS,
            expires_at_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS
                + DEFAULT_BATCH_TTL_BLOCKS,
        })?;

        state.publish_execution_receipt(ExecutionReceiptRequest {
            batch_id,
            proposal_id,
            executor_commitment: deterministic_root("DEVNET-EXECUTOR", "executor-a"),
            applied_verifier_key_root: deterministic_root("DEVNET-NEW-KEY", "private-contract-v2"),
            applied_constraint_system_root: deterministic_root("DEVNET-CONSTRAINTS", "contract-v2"),
            pre_state_root: deterministic_root("DEVNET-PRE-STATE", "batch-a"),
            post_state_root: deterministic_root("DEVNET-POST-STATE", "batch-a"),
            fee_receipt_root: deterministic_root("DEVNET-FEE-RECEIPT", "batch-a"),
            migration_receipt_root: deterministic_root("DEVNET-MIGRATION-RECEIPT", "batch-a"),
            compatibility_receipt_root: deterministic_root(
                "DEVNET-COMPATIBILITY-RECEIPT",
                "batch-a",
            ),
            privacy_fence_receipt_root: deterministic_root("DEVNET-FENCE-RECEIPT", "batch-a"),
            low_fee_rebate_root: deterministic_root("DEVNET-REBATE", "batch-a"),
            pq_signature_root: deterministic_root("DEVNET-EXECUTION-SIGNATURE", "batch-a"),
            execution_nullifier: deterministic_root("DEVNET-EXECUTION-NULLIFIER", "batch-a"),
            executed_at_height: DEVNET_HEIGHT
                + 8
                + DEFAULT_VOTE_WINDOW_BLOCKS
                + DEFAULT_MIN_TIMELOCK_BLOCKS
                + 1,
        })?;

        Ok(state)
    }

    pub fn submit_proposal(&mut self, request: CircuitProposalRequest) -> Result<String> {
        self.config.validate()?;
        ensure_capacity("proposals", self.proposals.len(), self.config.max_proposals)?;
        validate_proposal(&request, &self.config)?;
        let sequence = self.counters.proposals.saturating_add(1);
        let proposal_id = proposal_id(&request, sequence);
        ensure_absent(
            "proposal",
            &proposal_id,
            self.proposals.contains_key(&proposal_id),
        )?;
        ensure_unique_set(
            "proposal nullifier",
            &request.proposal_nullifier,
            &self.vote_nullifiers,
        )?;
        let proposal = CircuitProposal {
            proposal_id: proposal_id.clone(),
            sequence,
            status: ProposalStatus::Attesting,
            request,
            validator_approval_weight_bps: 0,
            validator_reject_weight_bps: 0,
            anonymous_approval_weight_bps: 0,
            anonymous_reject_weight_bps: 0,
            emergency_veto_weight_bps: 0,
            compatibility_score_bps: 0,
            migration_plan_id: String::new(),
            compatibility_manifest_id: String::new(),
            privacy_fence_id: String::new(),
            batch_id: String::new(),
            executed_receipt_id: String::new(),
        };
        self.counters.proposals = sequence;
        self.open_proposals.insert(proposal_id.clone());
        self.proposals.insert(proposal_id.clone(), proposal);
        self.push_event("proposal_submitted", &proposal_id, DEVNET_HEIGHT);
        Ok(proposal_id)
    }

    pub fn submit_validator_attestation(
        &mut self,
        request: ValidatorAttestationRequest,
    ) -> Result<String> {
        ensure_capacity(
            "validator attestations",
            self.validator_attestations.len(),
            self.config.max_validator_attestations,
        )?;
        validate_validator_attestation(&request, &self.config)?;
        {
            let proposal = self.require_proposal(&request.proposal_id)?;
            if !proposal.status.accepts_attestation() {
                return Err("proposal does not accept validator attestations".to_string());
            }
        }
        let sequence = self.counters.validator_attestations.saturating_add(1);
        let attestation_id = validator_attestation_id(&request, sequence);
        ensure_absent(
            "validator attestation",
            &attestation_id,
            self.validator_attestations.contains_key(&attestation_id),
        )?;
        let attestation = ValidatorAttestation {
            attestation_id: attestation_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.validator_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.validator_attestations = sequence;
        self.apply_validator_weight(&request)?;
        self.push_event(
            "validator_attestation_submitted",
            &request.proposal_id,
            request.signed_at_height,
        );
        Ok(attestation_id)
    }

    pub fn submit_key_attestation(&mut self, request: KeyAttestationRequest) -> Result<String> {
        ensure_capacity(
            "key attestations",
            self.key_attestations.len(),
            self.config.max_key_attestations,
        )?;
        validate_key_attestation(&request, &self.config)?;
        self.require_proposal(&request.proposal_id)?;
        let sequence = self.counters.key_attestations.saturating_add(1);
        let key_attestation_id = key_attestation_id(&request, sequence);
        ensure_absent(
            "key attestation",
            &key_attestation_id,
            self.key_attestations.contains_key(&key_attestation_id),
        )?;
        let attestation = KeyAttestation {
            key_attestation_id: key_attestation_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.key_attestations
            .insert(key_attestation_id.clone(), attestation);
        self.counters.key_attestations = sequence;
        if request.attestor_weight_bps >= self.config.min_key_rotation_quorum_bps {
            let proposal = self.require_proposal_mut(&request.proposal_id)?;
            if proposal.status == ProposalStatus::Attesting {
                proposal.status = ProposalStatus::Voting;
            }
        }
        self.push_event(
            "key_attestation_submitted",
            &request.proposal_id,
            request.signed_at_height,
        );
        Ok(key_attestation_id)
    }

    pub fn cast_anonymous_vote(&mut self, request: AnonymousVoteRequest) -> Result<String> {
        ensure_capacity(
            "vote commitments",
            self.vote_commitments.len(),
            self.config.max_vote_commitments,
        )?;
        validate_anonymous_vote(&request, &self.config)?;
        ensure_unique_set(
            "vote nullifier",
            &request.vote_nullifier,
            &self.vote_nullifiers,
        )?;
        {
            let proposal = self.require_proposal(&request.proposal_id)?;
            if !proposal.status.accepts_vote() {
                return Err("proposal does not accept anonymous votes".to_string());
            }
            if request.cast_at_height < proposal.request.vote_start_height
                || request.cast_at_height > proposal.request.vote_end_height
            {
                return Err("anonymous vote outside configured vote window".to_string());
            }
        }
        let sequence = self.counters.vote_commitments.saturating_add(1);
        let vote_id = anonymous_vote_id(&request, sequence);
        let vote = AnonymousVote {
            vote_id: vote_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.vote_commitments.insert(vote_id.clone(), vote);
        self.vote_nullifiers.insert(request.vote_nullifier.clone());
        self.counters.vote_commitments = sequence;
        self.apply_vote_weight(&request)?;
        self.push_event(
            "anonymous_vote_cast",
            &request.proposal_id,
            request.cast_at_height,
        );
        Ok(vote_id)
    }

    pub fn submit_emergency_veto(&mut self, request: EmergencyVetoRequest) -> Result<String> {
        if !self.config.allow_emergency_veto {
            return Err("emergency veto disabled by config".to_string());
        }
        ensure_capacity(
            "emergency vetoes",
            self.emergency_vetoes.len(),
            self.config.max_emergency_vetoes,
        )?;
        validate_emergency_veto(&request, &self.config)?;
        {
            let proposal = self.require_proposal(&request.proposal_id)?;
            if !proposal.status.accepts_veto() {
                return Err("proposal does not accept emergency veto".to_string());
            }
            if request.vetoed_at_height
                > proposal
                    .request
                    .proposed_at_height
                    .saturating_add(self.config.emergency_veto_window_blocks)
            {
                return Err("emergency veto outside configured window".to_string());
            }
        }
        let sequence = self.counters.emergency_vetoes.saturating_add(1);
        let veto_id = emergency_veto_id(&request, sequence);
        let veto = EmergencyVeto {
            veto_id: veto_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.emergency_vetoes.insert(veto_id.clone(), veto);
        self.counters.emergency_vetoes = sequence;
        let threshold = self.config.min_emergency_veto_weight_bps;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        proposal.emergency_veto_weight_bps = proposal
            .emergency_veto_weight_bps
            .saturating_add(request.guardian_weight_bps)
            .min(MAX_BPS);
        if proposal.emergency_veto_weight_bps >= threshold {
            proposal.status = ProposalStatus::Vetoed;
            self.open_proposals.remove(&request.proposal_id);
        }
        self.push_event(
            "emergency_veto_submitted",
            &request.proposal_id,
            request.vetoed_at_height,
        );
        Ok(veto_id)
    }

    pub fn publish_migration_plan(
        &mut self,
        request: VerifierMigrationPlanRequest,
    ) -> Result<String> {
        ensure_capacity(
            "migration plans",
            self.migration_plans.len(),
            self.config.max_migration_plans,
        )?;
        validate_migration_plan(&request, &self.config)?;
        self.require_proposal(&request.proposal_id)?;
        let sequence = self.counters.migration_plans.saturating_add(1);
        let migration_plan_id = migration_plan_id(&request, sequence);
        let plan = VerifierMigrationPlan {
            migration_plan_id: migration_plan_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.migration_plans.insert(migration_plan_id.clone(), plan);
        self.counters.migration_plans = sequence;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        proposal.migration_plan_id = migration_plan_id.clone();
        self.push_event(
            "migration_plan_published",
            &request.proposal_id,
            request.planned_at_height,
        );
        Ok(migration_plan_id)
    }

    pub fn publish_compatibility_manifest(
        &mut self,
        request: CompatibilityManifestRequest,
    ) -> Result<String> {
        ensure_capacity(
            "compatibility manifests",
            self.compatibility_manifests.len(),
            self.config.max_compatibility_manifests,
        )?;
        validate_compatibility_manifest(&request, &self.config)?;
        self.require_proposal(&request.proposal_id)?;
        let sequence = self.counters.compatibility_manifests.saturating_add(1);
        let manifest_id = compatibility_manifest_id(&request, sequence);
        let manifest = CompatibilityManifest {
            manifest_id: manifest_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.compatibility_manifests
            .insert(manifest_id.clone(), manifest);
        self.counters.compatibility_manifests = sequence;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        proposal.compatibility_manifest_id = manifest_id.clone();
        proposal.compatibility_score_bps = request.compatibility_score_bps;
        self.push_event(
            "compatibility_manifest_published",
            &request.proposal_id,
            request.published_at_height,
        );
        Ok(manifest_id)
    }

    pub fn publish_slashing_evidence(
        &mut self,
        request: SlashingEvidenceRequest,
    ) -> Result<String> {
        ensure_capacity(
            "slashing evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        validate_slashing_evidence(&request, &self.config)?;
        self.require_proposal(&request.proposal_id)?;
        let sequence = self.counters.slashing_evidence.saturating_add(1);
        let evidence_id = slashing_evidence_id(&request, sequence);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.counters.slashing_evidence = sequence;
        if request.slash_weight_bps >= self.config.min_validator_attestation_weight_bps {
            let proposal = self.require_proposal_mut(&request.proposal_id)?;
            if matches!(
                request.evidence_kind,
                EvidenceKind::InvalidVerifierKey
                    | EvidenceKind::IncompatibleConstraintSystem
                    | EvidenceKind::UnsafeMigrationPlan
                    | EvidenceKind::PrivacySetUnderflow
            ) {
                proposal.status = ProposalStatus::Slashed;
                self.open_proposals.remove(&request.proposal_id);
            }
        }
        self.push_event(
            "slashing_evidence_published",
            &request.proposal_id,
            request.observed_at_height,
        );
        Ok(evidence_id)
    }

    pub fn install_privacy_fence(
        &mut self,
        request: PrivacyNullifierFenceRequest,
    ) -> Result<String> {
        ensure_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        validate_privacy_fence(&request, &self.config)?;
        self.require_proposal(&request.proposal_id)?;
        let sequence = self.counters.privacy_fences.saturating_add(1);
        let fence_id = privacy_fence_id(&request, sequence);
        let fence = PrivacyNullifierFence {
            fence_id: fence_id.clone(),
            sequence,
            request: request.clone(),
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.privacy_fences = sequence;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        proposal.privacy_fence_id = fence_id.clone();
        self.push_event(
            "privacy_fence_installed",
            &request.proposal_id,
            request.created_at_height,
        );
        Ok(fence_id)
    }

    pub fn reserve_low_fee_batch(
        &mut self,
        request: LowFeeBatchExecutionRequest,
    ) -> Result<String> {
        ensure_capacity(
            "batch receipts",
            self.execution_batches.len(),
            self.config.max_batch_receipts,
        )?;
        validate_low_fee_batch(&request, &self.config)?;
        for proposal_id in &request.proposal_ids {
            let proposal = self.require_proposal(proposal_id)?;
            if !proposal.status.batchable() {
                return Err("batch contains proposal that is not batchable".to_string());
            }
            if self.config.require_migration_plan && proposal.migration_plan_id.is_empty() {
                return Err("batch proposal missing migration plan".to_string());
            }
            if self.config.require_compatibility_manifest
                && proposal.compatibility_manifest_id.is_empty()
            {
                return Err("batch proposal missing compatibility manifest".to_string());
            }
            if self.config.require_privacy_fence && proposal.privacy_fence_id.is_empty() {
                return Err("batch proposal missing privacy fence".to_string());
            }
        }
        let sequence = self.counters.batch_receipts.saturating_add(1);
        let batch_id = low_fee_batch_id(&request, sequence);
        let receipt = LowFeeBatchExecutionReceipt {
            batch_id: batch_id.clone(),
            sequence,
            status: ExecutionStatus::Reserved,
            request: request.clone(),
        };
        self.execution_batches.insert(batch_id.clone(), receipt);
        self.low_fee_receipts.insert(batch_id.clone());
        self.counters.batch_receipts = sequence;
        for proposal_id in &request.proposal_ids {
            let proposal = self.require_proposal_mut(proposal_id)?;
            proposal.status = ProposalStatus::Batched;
            proposal.batch_id = batch_id.clone();
        }
        self.push_event(
            "low_fee_batch_reserved",
            &batch_id,
            request.earliest_execution_height,
        );
        Ok(batch_id)
    }

    pub fn publish_execution_receipt(
        &mut self,
        request: ExecutionReceiptRequest,
    ) -> Result<String> {
        ensure_capacity(
            "execution receipts",
            self.execution_receipts.len(),
            self.config.max_execution_receipts,
        )?;
        validate_execution_receipt(&request)?;
        self.require_batch(&request.batch_id)?;
        {
            let proposal = self.require_proposal(&request.proposal_id)?;
            if proposal.batch_id != request.batch_id {
                return Err("execution receipt batch id does not match proposal".to_string());
            }
        }
        let sequence = self.counters.execution_receipts.saturating_add(1);
        let receipt_id = execution_receipt_id(&request, sequence);
        let receipt = ExecutionReceipt {
            receipt_id: receipt_id.clone(),
            sequence,
            status: ExecutionStatus::Executed,
            request: request.clone(),
        };
        self.execution_receipts.insert(receipt_id.clone(), receipt);
        self.counters.execution_receipts = sequence;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        proposal.status = ProposalStatus::Executed;
        proposal.executed_receipt_id = receipt_id.clone();
        self.open_proposals.remove(&request.proposal_id);
        if let Some(batch) = self.execution_batches.get_mut(&request.batch_id) {
            batch.status = ExecutionStatus::Executed;
        }
        self.push_event(
            "circuit_upgrade_executed",
            &request.proposal_id,
            request.executed_at_height,
        );
        Ok(receipt_id)
    }

    pub fn roots(&self) -> Roots {
        let proposal_records = self
            .proposals
            .values()
            .map(CircuitProposal::public_record)
            .collect::<Vec<_>>();
        let open_records = self
            .open_proposals
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        let validator_records = self
            .validator_attestations
            .values()
            .map(ValidatorAttestation::public_record)
            .collect::<Vec<_>>();
        let key_records = self
            .key_attestations
            .values()
            .map(KeyAttestation::public_record)
            .collect::<Vec<_>>();
        let vote_records = self
            .vote_commitments
            .values()
            .map(AnonymousVote::public_record)
            .collect::<Vec<_>>();
        let vote_nullifier_records = self
            .vote_nullifiers
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        let veto_records = self
            .emergency_vetoes
            .values()
            .map(EmergencyVeto::public_record)
            .collect::<Vec<_>>();
        let migration_records = self
            .migration_plans
            .values()
            .map(VerifierMigrationPlan::public_record)
            .collect::<Vec<_>>();
        let manifest_records = self
            .compatibility_manifests
            .values()
            .map(CompatibilityManifest::public_record)
            .collect::<Vec<_>>();
        let evidence_records = self
            .slashing_evidence
            .values()
            .map(SlashingEvidence::public_record)
            .collect::<Vec<_>>();
        let fence_records = self
            .privacy_fences
            .values()
            .map(PrivacyNullifierFence::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .execution_batches
            .values()
            .map(LowFeeBatchExecutionReceipt::public_record)
            .collect::<Vec<_>>();
        let execution_records = self
            .execution_receipts
            .values()
            .map(ExecutionReceipt::public_record)
            .collect::<Vec<_>>();
        let low_fee_records = self
            .low_fee_receipts
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        let event_records = self
            .events
            .iter()
            .map(RuntimeEvent::public_record)
            .collect::<Vec<_>>();
        Roots {
            proposal_root: merkle_root("PQ-CONF-CIRCUIT-GOV-PROPOSALS", &proposal_records),
            open_proposal_root: merkle_root("PQ-CONF-CIRCUIT-GOV-OPEN-PROPOSALS", &open_records),
            validator_attestation_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-VALIDATOR-ATTESTATIONS",
                &validator_records,
            ),
            key_attestation_root: merkle_root("PQ-CONF-CIRCUIT-GOV-KEY-ATTESTATIONS", &key_records),
            vote_commitment_root: merkle_root("PQ-CONF-CIRCUIT-GOV-VOTES", &vote_records),
            vote_nullifier_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-VOTE-NULLIFIERS",
                &vote_nullifier_records,
            ),
            emergency_veto_root: merkle_root("PQ-CONF-CIRCUIT-GOV-VETOES", &veto_records),
            migration_plan_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-MIGRATION-PLANS",
                &migration_records,
            ),
            compatibility_manifest_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-COMPATIBILITY-MANIFESTS",
                &manifest_records,
            ),
            slashing_evidence_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-SLASHING-EVIDENCE",
                &evidence_records,
            ),
            privacy_fence_root: merkle_root("PQ-CONF-CIRCUIT-GOV-PRIVACY-FENCES", &fence_records),
            execution_batch_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-EXECUTION-BATCHES",
                &batch_records,
            ),
            execution_receipt_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-EXECUTION-RECEIPTS",
                &execution_records,
            ),
            low_fee_receipt_root: merkle_root(
                "PQ-CONF-CIRCUIT-GOV-LOW-FEE-RECEIPTS",
                &low_fee_records,
            ),
            event_root: merkle_root("PQ-CONF-CIRCUIT-GOV-EVENTS", &event_records),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_CIRCUIT_UPGRADE_GOVERNANCE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_governance_suite": PQ_GOVERNANCE_SUITE,
            "anonymous_stake_vote_scheme": ANONYMOUS_STAKE_VOTE_SCHEME,
            "compatibility_manifest_scheme": COMPATIBILITY_MANIFEST_SCHEME,
            "low_fee_batch_execution_scheme": LOW_FEE_BATCH_EXECUTION_SCHEME,
            "privacy_fence_scheme": PRIVACY_FENCE_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
        })
    }

    fn apply_validator_weight(&mut self, request: &ValidatorAttestationRequest) -> Result<()> {
        let quorum = self.config.min_validator_attestation_weight_bps;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        match request.verdict {
            AttestationVerdict::Approve => {
                proposal.validator_approval_weight_bps = proposal
                    .validator_approval_weight_bps
                    .saturating_add(request.stake_weight_bps)
                    .min(MAX_BPS);
            }
            AttestationVerdict::Reject => {
                proposal.validator_reject_weight_bps = proposal
                    .validator_reject_weight_bps
                    .saturating_add(request.stake_weight_bps)
                    .min(MAX_BPS);
            }
            AttestationVerdict::Abstain
            | AttestationVerdict::NeedsCompatibilityProof
            | AttestationVerdict::NeedsMigrationPlan => {}
        }
        if proposal.validator_reject_weight_bps >= quorum {
            proposal.status = ProposalStatus::Rejected;
            self.open_proposals.remove(&request.proposal_id);
        } else if proposal.validator_approval_weight_bps >= quorum
            && proposal.status == ProposalStatus::Attesting
        {
            proposal.status = ProposalStatus::Voting;
        }
        Ok(())
    }

    fn apply_vote_weight(&mut self, request: &AnonymousVoteRequest) -> Result<()> {
        let approval_threshold = self.config.min_approval_weight_bps;
        let proposal = self.require_proposal_mut(&request.proposal_id)?;
        match request.vote_choice {
            VoteChoice::Approve => {
                proposal.anonymous_approval_weight_bps = proposal
                    .anonymous_approval_weight_bps
                    .saturating_add(request.stake_weight_bps)
                    .min(MAX_BPS);
            }
            VoteChoice::Reject => {
                proposal.anonymous_reject_weight_bps = proposal
                    .anonymous_reject_weight_bps
                    .saturating_add(request.stake_weight_bps)
                    .min(MAX_BPS);
            }
            VoteChoice::Abstain => {}
        }
        if proposal.anonymous_reject_weight_bps >= approval_threshold {
            proposal.status = ProposalStatus::Rejected;
            self.open_proposals.remove(&request.proposal_id);
        } else if proposal.anonymous_approval_weight_bps >= approval_threshold {
            proposal.status = ProposalStatus::Approved;
        }
        Ok(())
    }

    fn require_proposal(&self, proposal_id: &str) -> Result<&CircuitProposal> {
        self.proposals
            .get(proposal_id)
            .ok_or_else(|| format!("unknown circuit proposal {proposal_id}"))
    }

    fn require_proposal_mut(&mut self, proposal_id: &str) -> Result<&mut CircuitProposal> {
        self.proposals
            .get_mut(proposal_id)
            .ok_or_else(|| format!("unknown circuit proposal {proposal_id}"))
    }

    fn require_batch(&self, batch_id: &str) -> Result<&LowFeeBatchExecutionReceipt> {
        self.execution_batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown low-fee execution batch {batch_id}"))
    }

    fn push_event(&mut self, kind: &str, subject_id: &str, height: u64) {
        let sequence = self.counters.events.saturating_add(1);
        let payload_root = domain_hash(
            "PQ-CONF-CIRCUIT-GOV-EVENT-PAYLOAD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
            32,
        );
        let event_id = domain_hash(
            "PQ-CONF-CIRCUIT-GOV-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(
                    PRIVATE_L2_PQ_CONFIDENTIAL_CIRCUIT_UPGRADE_GOVERNANCE_RUNTIME_PROTOCOL_VERSION,
                ),
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
                HashPart::U64(height),
                HashPart::U64(sequence),
            ],
            32,
        );
        self.counters.events = sequence;
        self.events.push(RuntimeEvent {
            event_id,
            sequence,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            height,
        });
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn devnet_state_root() -> Result<String> {
    Ok(State::devnet()?.state_root())
}

pub fn devnet_public_record() -> Result<Value> {
    Ok(State::devnet()?.public_record())
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CIRCUIT_UPGRADE_GOVERNANCE_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn proposal_id(request: &CircuitProposalRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.family.as_str()),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(request.proof_system.as_str()),
            HashPart::Str(&request.proposer_commitment),
            HashPart::Str(&request.new_verifier_key_root),
            HashPart::Str(&request.proposal_nullifier),
            HashPart::U64(request.proposed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn validator_attestation_id(request: &ValidatorAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-VALIDATOR-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.validator_commitment),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::U64(request.signed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn key_attestation_id(request: &KeyAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-KEY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.key_attestor_commitment),
            HashPart::Str(request.pq_signature_scheme.as_str()),
            HashPart::Str(&request.new_key_root),
            HashPart::Str(&request.key_attestation_nullifier),
            HashPart::U64(request.signed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn anonymous_vote_id(request: &AnonymousVoteRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-ANONYMOUS-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(request.vote_choice.as_str()),
            HashPart::Str(&request.vote_nullifier),
            HashPart::Str(&request.anonymity_set_root),
            HashPart::U64(request.cast_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn emergency_veto_id(request: &EmergencyVetoRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-EMERGENCY-VETO-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.guardian_commitment),
            HashPart::Str(&request.veto_nullifier),
            HashPart::Str(&request.threat_evidence_root),
            HashPart::U64(request.vetoed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn migration_plan_id(request: &VerifierMigrationPlanRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-MIGRATION-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.legacy_verifier_key_root),
            HashPart::Str(&request.candidate_verifier_key_root),
            HashPart::Str(request.phase.as_str()),
            HashPart::Str(&request.plan_nullifier),
            HashPart::U64(request.planned_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn compatibility_manifest_id(request: &CompatibilityManifestRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-COMPATIBILITY-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(request.circuit_family.as_str()),
            HashPart::Str(request.grade.as_str()),
            HashPart::Str(&request.manifest_nullifier),
            HashPart::U64(request.published_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_evidence_id(request: &SlashingEvidenceRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.accused_commitment),
            HashPart::Str(request.evidence_kind.as_str()),
            HashPart::Str(&request.evidence_nullifier),
            HashPart::U64(request.observed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(request: &PrivacyNullifierFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.fence_domain),
            HashPart::Str(&request.prior_nullifier_root),
            HashPart::Str(&request.new_nullifier_root),
            HashPart::Str(&request.fence_nullifier),
            HashPart::U64(request.created_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn low_fee_batch_id(request: &LowFeeBatchExecutionRequest, sequence: u64) -> String {
    let proposal_root = merkle_root(
        "PQ-CONF-CIRCUIT-GOV-BATCH-PROPOSAL-IDS",
        &request
            .proposal_ids
            .iter()
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>(),
    );
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&proposal_root),
            HashPart::Str(&request.executor_commitment),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.batch_nullifier),
            HashPart::U64(request.earliest_execution_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn execution_receipt_id(request: &ExecutionReceiptRequest, sequence: u64) -> String {
    domain_hash(
        "PQ-CONF-CIRCUIT-GOV-EXECUTION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.proposal_id),
            HashPart::Str(&request.post_state_root),
            HashPart::Str(&request.execution_nullifier),
            HashPart::U64(request.executed_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn validate_proposal(request: &CircuitProposalRequest, config: &Config) -> Result<()> {
    require_root("proposer_commitment", &request.proposer_commitment)?;
    require_root("old_verifier_key_root", &request.old_verifier_key_root)?;
    require_root("new_verifier_key_root", &request.new_verifier_key_root)?;
    require_root("constraint_system_root", &request.constraint_system_root)?;
    require_root("parameter_root", &request.parameter_root)?;
    require_root("artifact_bundle_root", &request.artifact_bundle_root)?;
    require_root(
        "compatibility_claim_root",
        &request.compatibility_claim_root,
    )?;
    require_root("migration_claim_root", &request.migration_claim_root)?;
    require_root("privacy_impact_root", &request.privacy_impact_root)?;
    require_root("fee_policy_root", &request.fee_policy_root)?;
    require_root("stake_commitment_root", &request.stake_commitment_root)?;
    require_root("pq_signature_root", &request.pq_signature_root)?;
    require_root("proposal_nullifier", &request.proposal_nullifier)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.family.privacy_critical()
        && request.privacy_set_size < config.target_privacy_set_size
    {
        return Err("privacy-critical proposal below target privacy set".to_string());
    }
    if request.kind == ProposalKind::RecursiveVerifierMigration
        && !request.proof_system.supports_recursion()
    {
        return Err("recursive migration requires recursive-capable proof system".to_string());
    }
    if request.vote_start_height < request.proposed_at_height {
        return Err("vote start cannot precede proposal height".to_string());
    }
    if request.vote_end_height <= request.vote_start_height {
        return Err("vote end must follow vote start".to_string());
    }
    if request
        .vote_end_height
        .saturating_sub(request.vote_start_height)
        > config.vote_window_blocks
    {
        return Err("vote window exceeds configured limit".to_string());
    }
    let timelock = request
        .timelock_end_height
        .saturating_sub(request.vote_end_height);
    if timelock < config.min_timelock_blocks || timelock > config.max_timelock_blocks {
        return Err("proposal timelock outside configured bounds".to_string());
    }
    if request.expires_at_height <= request.timelock_end_height {
        return Err("proposal expiry must follow timelock end".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.proposed_at_height)
        > config.proposal_ttl_blocks
    {
        return Err("proposal TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_validator_attestation(
    request: &ValidatorAttestationRequest,
    config: &Config,
) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root("validator_commitment", &request.validator_commitment)?;
    require_root("validator_set_root", &request.validator_set_root)?;
    require_root("validator_key_root", &request.validator_key_root)?;
    require_root(
        "attestation_transcript_root",
        &request.attestation_transcript_root,
    )?;
    require_root("signature_root", &request.signature_root)?;
    require_root("attestation_nullifier", &request.attestation_nullifier)?;
    require_bps("stake_weight_bps", request.stake_weight_bps)?;
    validate_privacy_and_pq(
        config.min_privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    if request.expires_at_height <= request.signed_at_height {
        return Err("validator attestation expiry must follow signing height".to_string());
    }
    Ok(())
}

fn validate_key_attestation(request: &KeyAttestationRequest, config: &Config) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root("key_attestor_commitment", &request.key_attestor_commitment)?;
    require_root("old_key_root", &request.old_key_root)?;
    require_root("new_key_root", &request.new_key_root)?;
    require_root("key_ceremony_root", &request.key_ceremony_root)?;
    require_root("entropy_beacon_root", &request.entropy_beacon_root)?;
    require_root("hardware_fence_root", &request.hardware_fence_root)?;
    require_root(
        "downgrade_resistance_root",
        &request.downgrade_resistance_root,
    )?;
    require_root("pq_signature_root", &request.pq_signature_root)?;
    require_root(
        "key_attestation_nullifier",
        &request.key_attestation_nullifier,
    )?;
    require_bps("attestor_weight_bps", request.attestor_weight_bps)?;
    if request.pq_signature_scheme.security_bits() < config.min_pq_security_bits {
        return Err("key attestation PQ signature scheme below security floor".to_string());
    }
    if request.expires_at_height <= request.signed_at_height {
        return Err("key attestation expiry must follow signing height".to_string());
    }
    Ok(())
}

fn validate_anonymous_vote(request: &AnonymousVoteRequest, config: &Config) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root("voter_commitment", &request.voter_commitment)?;
    require_root("stake_weight_commitment", &request.stake_weight_commitment)?;
    require_root("encrypted_weight_root", &request.encrypted_weight_root)?;
    require_root("membership_proof_root", &request.membership_proof_root)?;
    require_root("vote_policy_root", &request.vote_policy_root)?;
    require_root("anonymity_set_root", &request.anonymity_set_root)?;
    require_root("vote_nullifier", &request.vote_nullifier)?;
    require_root("pq_signature_root", &request.pq_signature_root)?;
    require_bps("stake_weight_bps", request.stake_weight_bps)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.min_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    Ok(())
}

fn validate_emergency_veto(request: &EmergencyVetoRequest, config: &Config) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root("guardian_commitment", &request.guardian_commitment)?;
    require_root("guardian_set_root", &request.guardian_set_root)?;
    require_root("threat_evidence_root", &request.threat_evidence_root)?;
    require_root("affected_circuit_root", &request.affected_circuit_root)?;
    require_root("veto_reason_root", &request.veto_reason_root)?;
    require_root("emergency_action_root", &request.emergency_action_root)?;
    require_root("pq_signature_root", &request.pq_signature_root)?;
    require_root("veto_nullifier", &request.veto_nullifier)?;
    require_bps("guardian_weight_bps", request.guardian_weight_bps)?;
    validate_privacy_and_pq(
        request.privacy_set_size,
        request.pq_security_bits,
        config.emergency_privacy_set_size,
        config.min_pq_security_bits,
    )?;
    Ok(())
}

fn validate_migration_plan(request: &VerifierMigrationPlanRequest, config: &Config) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root(
        "legacy_verifier_key_root",
        &request.legacy_verifier_key_root,
    )?;
    require_root(
        "candidate_verifier_key_root",
        &request.candidate_verifier_key_root,
    )?;
    require_root("adapter_circuit_root", &request.adapter_circuit_root)?;
    require_root("state_migration_root", &request.state_migration_root)?;
    require_root("transcript_replay_root", &request.transcript_replay_root)?;
    require_root("rollback_plan_root", &request.rollback_plan_root)?;
    require_root(
        "shadow_verification_root",
        &request.shadow_verification_root,
    )?;
    require_root("plan_nullifier", &request.plan_nullifier)?;
    if request.shadow_start_height < request.planned_at_height {
        return Err("migration shadow start cannot precede planning height".to_string());
    }
    if request.dual_accept_start_height < request.shadow_start_height {
        return Err("migration dual accept cannot precede shadow verification".to_string());
    }
    if request.primary_switch_height < request.dual_accept_start_height {
        return Err("migration primary switch cannot precede dual accept".to_string());
    }
    if request.legacy_disable_height
        < request
            .primary_switch_height
            .saturating_add(config.migration_grace_blocks)
    {
        return Err("migration legacy disable before configured grace period".to_string());
    }
    if request.completed_by_height < request.legacy_disable_height {
        return Err("migration completion cannot precede legacy disable".to_string());
    }
    Ok(())
}

fn validate_compatibility_manifest(
    request: &CompatibilityManifestRequest,
    config: &Config,
) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root("old_interface_root", &request.old_interface_root)?;
    require_root("new_interface_root", &request.new_interface_root)?;
    require_root("witness_layout_root", &request.witness_layout_root)?;
    require_root(
        "public_input_schema_root",
        &request.public_input_schema_root,
    )?;
    require_root("recursive_wrapper_root", &request.recursive_wrapper_root)?;
    require_root(
        "proving_key_manifest_root",
        &request.proving_key_manifest_root,
    )?;
    require_root(
        "verifier_api_manifest_root",
        &request.verifier_api_manifest_root,
    )?;
    require_root(
        "downstream_dependency_root",
        &request.downstream_dependency_root,
    )?;
    require_root("audit_report_root", &request.audit_report_root)?;
    require_root("manifest_nullifier", &request.manifest_nullifier)?;
    require_bps("compatibility_score_bps", request.compatibility_score_bps)?;
    if request.compatibility_score_bps < config.min_compatibility_score_bps {
        return Err("compatibility score below configured threshold".to_string());
    }
    if !request.grade.executable() {
        return Err("compatibility manifest grade is not executable".to_string());
    }
    if request.expires_at_height <= request.published_at_height {
        return Err("compatibility manifest expiry must follow publish height".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.published_at_height)
        > config.compatibility_ttl_blocks
    {
        return Err("compatibility manifest TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_slashing_evidence(request: &SlashingEvidenceRequest, config: &Config) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_root("accused_commitment", &request.accused_commitment)?;
    require_root("evidence_root", &request.evidence_root)?;
    require_root("conflicting_record_root", &request.conflicting_record_root)?;
    require_root("replay_transcript_root", &request.replay_transcript_root)?;
    require_root("privacy_damage_root", &request.privacy_damage_root)?;
    require_root("penalty_policy_root", &request.penalty_policy_root)?;
    require_root("reporter_commitment", &request.reporter_commitment)?;
    require_root("reporter_signature_root", &request.reporter_signature_root)?;
    require_root("evidence_nullifier", &request.evidence_nullifier)?;
    require_bps("slash_weight_bps", request.slash_weight_bps)?;
    if request.expires_at_height <= request.observed_at_height {
        return Err("slashing evidence expiry must follow observation height".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.observed_at_height)
        > config.slashing_evidence_ttl_blocks
    {
        return Err("slashing evidence TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_privacy_fence(request: &PrivacyNullifierFenceRequest, config: &Config) -> Result<()> {
    require_root("proposal_id", &request.proposal_id)?;
    require_non_empty("fence_domain", &request.fence_domain)?;
    require_root("prior_nullifier_root", &request.prior_nullifier_root)?;
    require_root("new_nullifier_root", &request.new_nullifier_root)?;
    require_root("spent_note_root", &request.spent_note_root)?;
    require_root("unspent_note_root", &request.unspent_note_root)?;
    require_root("view_tag_root", &request.view_tag_root)?;
    require_root("decoy_set_root", &request.decoy_set_root)?;
    require_root("replay_guard_root", &request.replay_guard_root)?;
    require_root("disclosure_policy_root", &request.disclosure_policy_root)?;
    require_root("privacy_audit_root", &request.privacy_audit_root)?;
    require_root("fence_nullifier", &request.fence_nullifier)?;
    if request.privacy_set_size < config.min_privacy_set_size {
        return Err("privacy nullifier fence below privacy set minimum".to_string());
    }
    Ok(())
}

fn validate_low_fee_batch(request: &LowFeeBatchExecutionRequest, config: &Config) -> Result<()> {
    if request.proposal_ids.is_empty() {
        return Err("low-fee batch must include at least one proposal".to_string());
    }
    if request.proposal_ids.len() > config.max_batch_proposals {
        return Err("low-fee batch exceeds proposal count maximum".to_string());
    }
    for proposal_id in &request.proposal_ids {
        require_root("proposal_id", proposal_id)?;
    }
    require_root("executor_commitment", &request.executor_commitment)?;
    require_root("sponsor_commitment", &request.sponsor_commitment)?;
    require_non_empty("fee_asset_id", &request.fee_asset_id)?;
    require_bps("max_execution_fee_bps", request.max_execution_fee_bps)?;
    require_bps("sponsor_coverage_bps", request.sponsor_coverage_bps)?;
    if request.max_execution_fee_bps > config.max_execution_fee_bps {
        return Err("low-fee batch execution fee exceeds configured cap".to_string());
    }
    if request.sponsor_coverage_bps < config.low_fee_sponsor_coverage_bps {
        return Err("low-fee batch sponsor coverage below configured minimum".to_string());
    }
    require_root("reservation_root", &request.reservation_root)?;
    require_root("execution_plan_root", &request.execution_plan_root)?;
    require_root("pre_state_root", &request.pre_state_root)?;
    require_root(
        "expected_post_state_root",
        &request.expected_post_state_root,
    )?;
    require_root("privacy_fence_root", &request.privacy_fence_root)?;
    require_root("compatibility_root", &request.compatibility_root)?;
    require_root("migration_root", &request.migration_root)?;
    require_root("pq_signature_root", &request.pq_signature_root)?;
    require_root("batch_nullifier", &request.batch_nullifier)?;
    if request.batch_privacy_set_size < config.target_privacy_set_size {
        return Err("low-fee batch privacy set below target".to_string());
    }
    if request.expires_at_height <= request.earliest_execution_height {
        return Err("low-fee batch expiry must follow execution height".to_string());
    }
    if request
        .expires_at_height
        .saturating_sub(request.earliest_execution_height)
        > config.batch_ttl_blocks
    {
        return Err("low-fee batch TTL exceeds configured maximum".to_string());
    }
    Ok(())
}

fn validate_execution_receipt(request: &ExecutionReceiptRequest) -> Result<()> {
    require_root("batch_id", &request.batch_id)?;
    require_root("proposal_id", &request.proposal_id)?;
    require_root("executor_commitment", &request.executor_commitment)?;
    require_root(
        "applied_verifier_key_root",
        &request.applied_verifier_key_root,
    )?;
    require_root(
        "applied_constraint_system_root",
        &request.applied_constraint_system_root,
    )?;
    require_root("pre_state_root", &request.pre_state_root)?;
    require_root("post_state_root", &request.post_state_root)?;
    require_root("fee_receipt_root", &request.fee_receipt_root)?;
    require_root("migration_receipt_root", &request.migration_receipt_root)?;
    require_root(
        "compatibility_receipt_root",
        &request.compatibility_receipt_root,
    )?;
    require_root(
        "privacy_fence_receipt_root",
        &request.privacy_fence_receipt_root,
    )?;
    require_root("low_fee_rebate_root", &request.low_fee_rebate_root)?;
    require_root("pq_signature_root", &request.pq_signature_root)?;
    require_root("execution_nullifier", &request.execution_nullifier)?;
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("privacy set below configured minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("PQ security bits below configured minimum".to_string());
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(field: &str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.len() < 32 {
        return Err(format!("{field} must be a domain-separated root"));
    }
    Ok(())
}

fn require_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} cannot exceed {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn require_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn require_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{name} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_absent(name: &str, id: &str, present: bool) -> Result<()> {
    if present {
        Err(format!("{name} {id} already exists"))
    } else {
        Ok(())
    }
}

fn ensure_unique_set(name: &str, value: &str, set: &BTreeSet<String>) -> Result<()> {
    if set.contains(value) {
        Err(format!("{name} already used"))
    } else {
        Ok(())
    }
}

fn empty_root(label: &str) -> String {
    merkle_root(&format!("PQ-CONF-CIRCUIT-GOV-EMPTY-{label}"), &[])
}

fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_CIRCUIT_UPGRADE_GOVERNANCE_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(label),
        ],
        32,
    )
}
