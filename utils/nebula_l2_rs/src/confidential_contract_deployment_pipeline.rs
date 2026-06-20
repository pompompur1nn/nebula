use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialContractDeploymentPipelineResult<T> = Result<T, String>;

pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION: &str =
    "nebula-confidential-contract-deployment-pipeline-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_SCHEMA_VERSION: u64 = 1;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_SECURITY_MODEL: &str =
    "deterministic-devnet-private-deployment-not-real-crypto";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_ABI_ENCRYPTION_SCHEME: &str =
    "ML-KEM-768+SHAKE256-abi-manifest-seal-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_BYTECODE_COMMITMENT_SCHEME: &str =
    "SHAKE256-canonical-bytecode-commitment-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROVING_KEY_COMMITMENT_SCHEME: &str =
    "SHAKE256-zk-proving-key-commitment-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_CONSTRUCTOR_WITNESS_SCHEME: &str =
    "encrypted-constructor-witness-envelope-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEPLOYER_APPROVAL_SCHEME: &str =
    "pq-deployer-threshold-approval-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_AUDIT_ATTESTATION_SCHEME: &str =
    "pq-auditor-private-contract-attestation-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_UPGRADE_TIMELOCK_SCHEME: &str =
    "private-contract-upgrade-timelock-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_LOW_FEE_SPONSORSHIP_SCHEME: &str =
    "low-fee-confidential-contract-deployment-sponsor-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_POLICY_CHECK_SCHEME: &str =
    "confidential-deployment-policy-check-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_ROLLOUT_SCHEME: &str =
    "private-contract-rollout-batch-v1";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_HEIGHT: u64 = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_LOW_FEE_LANE: &str =
    "confidential-contract-deployments";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_NAMESPACE: &str =
    "nebula.devnet.private";
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_TIMELOCK_BLOCKS: u64 = 96;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_TIMELOCK_EXPIRY_BLOCKS: u64 = 7_200;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_APPROVAL_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 20_160;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 1_440;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_ROLLOUT_WINDOW_BLOCKS: u64 = 240;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MIN_DEPLOYER_APPROVALS: u64 = 2;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MIN_AUDIT_ATTESTATIONS: u64 = 1;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MIN_AUDIT_SCORE_BPS: u64 = 8_500;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_000;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_CONSTRUCTOR_BYTES: u64 = 64 * 1024;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_BYTECODE_BYTES: u64 =
    8 * 1024 * 1024;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_PROVING_KEY_BYTES: u64 =
    64 * 1024 * 1024;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 250_000;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_SPONSORED_FEE_UNITS: u64 = 2_500;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_BATCH_SIZE: usize = 32;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_PACKAGES: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_ABI_MANIFESTS: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_BYTECODE_COMMITMENTS: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_PROVING_KEY_COMMITMENTS: usize = 512;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_APPROVALS: usize = 512;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_ATTESTATIONS: usize = 512;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_TIMELOCKS: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_SPONSORSHIPS: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_WITNESSES: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_POLICY_CHECKS: usize = 512;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_ROLLOUT_BATCHES: usize = 256;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_PUBLIC_RECORDS: usize = 1024;
pub const CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentContractKind {
    PrivateToken,
    PrivateAmm,
    PrivateLending,
    PrivateStablecoin,
    PrivateOracle,
    PrivatePaymaster,
    BridgeAdapter,
    Governance,
    AccountModule,
    Custom,
}

impl DeploymentContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateToken => "private_token",
            Self::PrivateAmm => "private_amm",
            Self::PrivateLending => "private_lending",
            Self::PrivateStablecoin => "private_stablecoin",
            Self::PrivateOracle => "private_oracle",
            Self::PrivatePaymaster => "private_paymaster",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::AccountModule => "account_module",
            Self::Custom => "custom",
        }
    }

    pub fn is_defi(self) -> bool {
        matches!(
            self,
            Self::PrivateAmm | Self::PrivateLending | Self::PrivateStablecoin | Self::PrivateOracle
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPackageStatus {
    Draft,
    Sealed,
    PendingApproval,
    Approved,
    Scheduled,
    Deployed,
    Rejected,
    Revoked,
}

impl DeploymentPackageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::PendingApproval => "pending_approval",
            Self::Approved => "approved",
            Self::Scheduled => "scheduled",
            Self::Deployed => "deployed",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Approved | Self::Scheduled | Self::Deployed)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Deployed | Self::Rejected | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiManifestVisibility {
    CommitmentOnly,
    DeployerDecryptable,
    AuditorDecryptable,
    SelectiveDisclosure,
    PublicSelectors,
}

impl AbiManifestVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::DeployerDecryptable => "deployer_decryptable",
            Self::AuditorDecryptable => "auditor_decryptable",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::PublicSelectors => "public_selectors",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Draft,
    Pinned,
    Verified,
    Superseded,
    Revoked,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Pinned => "pinned",
            Self::Verified => "verified",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::Pinned | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Proposed,
    Approved,
    Used,
    Rejected,
    Expired,
    Revoked,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Used => "used",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Approved | Self::Used)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    Abi,
    Bytecode,
    ProvingKeys,
    ConstructorWitness,
    PrivacyBudget,
    DefiInvariant,
    UpgradePath,
    LowFeeSponsorship,
}

impl AuditScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abi => "abi",
            Self::Bytecode => "bytecode",
            Self::ProvingKeys => "proving_keys",
            Self::ConstructorWitness => "constructor_witness",
            Self::PrivacyBudget => "privacy_budget",
            Self::DefiInvariant => "defi_invariant",
            Self::UpgradePath => "upgrade_path",
            Self::LowFeeSponsorship => "low_fee_sponsorship",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAttestationStatus {
    Draft,
    Accepted,
    Challenged,
    Expired,
    Revoked,
}

impl AuditAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn counts_for_policy(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeTimelockStatus {
    Proposed,
    Queued,
    Ready,
    Executed,
    Cancelled,
    Expired,
}

impl UpgradeTimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Queued => "queued",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Proposed | Self::Queued | Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Consumed,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_sponsor(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessEnvelopeStatus {
    Sealed,
    Admitted,
    Consumed,
    Rejected,
    Expired,
}

impl WitnessEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Consumed => "consumed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_deploy(self) -> bool {
        matches!(self, Self::Sealed | Self::Admitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCheckKind {
    QuantumResistance,
    PrivacyBudget,
    LowFeeEligibility,
    DeployerQuorum,
    AuditQuorum,
    DefiAllowlist,
    UpgradeDelay,
    ConstructorWitness,
}

impl PolicyCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::PrivacyBudget => "privacy_budget",
            Self::LowFeeEligibility => "low_fee_eligibility",
            Self::DeployerQuorum => "deployer_quorum",
            Self::AuditQuorum => "audit_quorum",
            Self::DefiAllowlist => "defi_allowlist",
            Self::UpgradeDelay => "upgrade_delay",
            Self::ConstructorWitness => "constructor_witness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Pass,
    Warn,
    Fail,
    Waived,
}

impl PolicyVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Waived => "waived",
        }
    }

    pub fn permits_deployment(self) -> bool {
        matches!(self, Self::Pass | Self::Warn | Self::Waived)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutBatchStatus {
    Collecting,
    Scheduled,
    Executing,
    Finalized,
    Reverted,
    Cancelled,
}

impl RolloutBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Scheduled => "scheduled",
            Self::Executing => "executing",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Collecting | Self::Scheduled | Self::Executing)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialContractDeploymentConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub security_model: String,
    pub pq_suite: String,
    pub abi_encryption_scheme: String,
    pub bytecode_commitment_scheme: String,
    pub proving_key_commitment_scheme: String,
    pub constructor_witness_scheme: String,
    pub deployer_approval_scheme: String,
    pub audit_attestation_scheme: String,
    pub upgrade_timelock_scheme: String,
    pub low_fee_sponsorship_scheme: String,
    pub policy_check_scheme: String,
    pub rollout_scheme: String,
    pub default_fee_asset_id: String,
    pub default_low_fee_lane: String,
    pub default_namespace: String,
    pub default_timelock_blocks: u64,
    pub default_timelock_expiry_blocks: u64,
    pub default_approval_ttl_blocks: u64,
    pub default_audit_ttl_blocks: u64,
    pub default_sponsor_ttl_blocks: u64,
    pub default_rollout_window_blocks: u64,
    pub min_deployer_approvals: u64,
    pub min_audit_attestations: u64,
    pub min_audit_score_bps: u64,
    pub max_disclosure_bps: u64,
    pub max_constructor_bytes: u64,
    pub max_bytecode_bytes: u64,
    pub max_proving_key_bytes: u64,
    pub default_sponsor_budget_units: u64,
    pub max_sponsored_fee_units: u64,
    pub max_batch_size: usize,
    pub max_packages: usize,
    pub max_abi_manifests: usize,
    pub max_bytecode_commitments: usize,
    pub max_proving_key_commitments: usize,
    pub max_approvals: usize,
    pub max_attestations: usize,
    pub max_timelocks: usize,
    pub max_sponsorships: usize,
    pub max_witnesses: usize,
    pub max_policy_checks: usize,
    pub max_rollout_batches: usize,
    pub max_public_records: usize,
}

impl ConfidentialContractDeploymentConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION
                .to_string(),
            schema_version: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            security_model: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_SECURITY_MODEL.to_string(),
            pq_suite: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PQ_SUITE.to_string(),
            abi_encryption_scheme: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_ABI_ENCRYPTION_SCHEME
                .to_string(),
            bytecode_commitment_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_BYTECODE_COMMITMENT_SCHEME.to_string(),
            proving_key_commitment_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROVING_KEY_COMMITMENT_SCHEME.to_string(),
            constructor_witness_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_CONSTRUCTOR_WITNESS_SCHEME.to_string(),
            deployer_approval_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEPLOYER_APPROVAL_SCHEME.to_string(),
            audit_attestation_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_AUDIT_ATTESTATION_SCHEME.to_string(),
            upgrade_timelock_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_UPGRADE_TIMELOCK_SCHEME.to_string(),
            low_fee_sponsorship_scheme:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_LOW_FEE_SPONSORSHIP_SCHEME.to_string(),
            policy_check_scheme: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_POLICY_CHECK_SCHEME
                .to_string(),
            rollout_scheme: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_ROLLOUT_SCHEME.to_string(),
            default_fee_asset_id: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_FEE_ASSET_ID
                .to_string(),
            default_low_fee_lane: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_LOW_FEE_LANE
                .to_string(),
            default_namespace: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_NAMESPACE
                .to_string(),
            default_timelock_blocks:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_TIMELOCK_BLOCKS,
            default_timelock_expiry_blocks:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_TIMELOCK_EXPIRY_BLOCKS,
            default_approval_ttl_blocks:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_APPROVAL_TTL_BLOCKS,
            default_audit_ttl_blocks:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_AUDIT_TTL_BLOCKS,
            default_sponsor_ttl_blocks:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_SPONSOR_TTL_BLOCKS,
            default_rollout_window_blocks:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_ROLLOUT_WINDOW_BLOCKS,
            min_deployer_approvals:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MIN_DEPLOYER_APPROVALS,
            min_audit_attestations:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MIN_AUDIT_ATTESTATIONS,
            min_audit_score_bps:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MIN_AUDIT_SCORE_BPS,
            max_disclosure_bps:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_DISCLOSURE_BPS,
            max_constructor_bytes:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_CONSTRUCTOR_BYTES,
            max_bytecode_bytes:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_BYTECODE_BYTES,
            max_proving_key_bytes:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_PROVING_KEY_BYTES,
            default_sponsor_budget_units:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_sponsored_fee_units:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_SPONSORED_FEE_UNITS,
            max_batch_size: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_MAX_BATCH_SIZE,
            max_packages: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_PACKAGES,
            max_abi_manifests: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_ABI_MANIFESTS,
            max_bytecode_commitments:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_BYTECODE_COMMITMENTS,
            max_proving_key_commitments:
                CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_PROVING_KEY_COMMITMENTS,
            max_approvals: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_APPROVALS,
            max_attestations: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_ATTESTATIONS,
            max_timelocks: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_TIMELOCKS,
            max_sponsorships: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_SPONSORSHIPS,
            max_witnesses: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_WITNESSES,
            max_policy_checks: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_POLICY_CHECKS,
            max_rollout_batches: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_ROLLOUT_BATCHES,
            max_public_records: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_contract_deployment_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "security_model": self.security_model,
            "pq_suite": self.pq_suite,
            "abi_encryption_scheme": self.abi_encryption_scheme,
            "bytecode_commitment_scheme": self.bytecode_commitment_scheme,
            "proving_key_commitment_scheme": self.proving_key_commitment_scheme,
            "constructor_witness_scheme": self.constructor_witness_scheme,
            "deployer_approval_scheme": self.deployer_approval_scheme,
            "audit_attestation_scheme": self.audit_attestation_scheme,
            "upgrade_timelock_scheme": self.upgrade_timelock_scheme,
            "low_fee_sponsorship_scheme": self.low_fee_sponsorship_scheme,
            "policy_check_scheme": self.policy_check_scheme,
            "rollout_scheme": self.rollout_scheme,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "default_namespace": self.default_namespace,
            "default_timelock_blocks": self.default_timelock_blocks,
            "default_timelock_expiry_blocks": self.default_timelock_expiry_blocks,
            "default_approval_ttl_blocks": self.default_approval_ttl_blocks,
            "default_audit_ttl_blocks": self.default_audit_ttl_blocks,
            "default_sponsor_ttl_blocks": self.default_sponsor_ttl_blocks,
            "default_rollout_window_blocks": self.default_rollout_window_blocks,
            "min_deployer_approvals": self.min_deployer_approvals,
            "min_audit_attestations": self.min_audit_attestations,
            "min_audit_score_bps": self.min_audit_score_bps,
            "max_disclosure_bps": self.max_disclosure_bps,
            "max_constructor_bytes": self.max_constructor_bytes,
            "max_bytecode_bytes": self.max_bytecode_bytes,
            "max_proving_key_bytes": self.max_proving_key_bytes,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "max_sponsored_fee_units": self.max_sponsored_fee_units,
            "max_batch_size": self.max_batch_size,
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_eq(
            "protocol version",
            &self.protocol_version,
            CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
        )?;
        ensure_eq("chain id", &self.chain_id, CHAIN_ID)?;
        ensure_non_empty("security model", &self.security_model)?;
        ensure_non_empty("pq suite", &self.pq_suite)?;
        ensure_non_empty("abi encryption scheme", &self.abi_encryption_scheme)?;
        ensure_non_empty(
            "bytecode commitment scheme",
            &self.bytecode_commitment_scheme,
        )?;
        ensure_non_empty(
            "proving key commitment scheme",
            &self.proving_key_commitment_scheme,
        )?;
        ensure_non_empty(
            "constructor witness scheme",
            &self.constructor_witness_scheme,
        )?;
        ensure_non_empty("deployer approval scheme", &self.deployer_approval_scheme)?;
        ensure_non_empty("audit attestation scheme", &self.audit_attestation_scheme)?;
        ensure_non_empty("upgrade timelock scheme", &self.upgrade_timelock_scheme)?;
        ensure_non_empty(
            "low fee sponsorship scheme",
            &self.low_fee_sponsorship_scheme,
        )?;
        ensure_non_empty("policy check scheme", &self.policy_check_scheme)?;
        ensure_non_empty("rollout scheme", &self.rollout_scheme)?;
        ensure_non_empty("default fee asset id", &self.default_fee_asset_id)?;
        ensure_non_empty("default low fee lane", &self.default_low_fee_lane)?;
        ensure_non_empty("default namespace", &self.default_namespace)?;
        ensure_positive(self.default_timelock_blocks, "default timelock blocks")?;
        ensure_positive(
            self.default_timelock_expiry_blocks,
            "default timelock expiry blocks",
        )?;
        ensure_positive(
            self.default_approval_ttl_blocks,
            "default approval ttl blocks",
        )?;
        ensure_positive(self.default_audit_ttl_blocks, "default audit ttl blocks")?;
        ensure_positive(
            self.default_sponsor_ttl_blocks,
            "default sponsor ttl blocks",
        )?;
        ensure_positive(
            self.default_rollout_window_blocks,
            "default rollout window blocks",
        )?;
        ensure_positive(self.min_deployer_approvals, "minimum deployer approvals")?;
        ensure_positive(self.min_audit_attestations, "minimum audit attestations")?;
        ensure_bps(self.min_audit_score_bps, "minimum audit score")?;
        ensure_bps(self.max_disclosure_bps, "maximum disclosure")?;
        ensure_positive(self.max_constructor_bytes, "maximum constructor bytes")?;
        ensure_positive(self.max_bytecode_bytes, "maximum bytecode bytes")?;
        ensure_positive(self.max_proving_key_bytes, "maximum proving key bytes")?;
        ensure_positive(self.default_sponsor_budget_units, "default sponsor budget")?;
        ensure_positive(self.max_sponsored_fee_units, "maximum sponsored fee")?;
        if self.default_timelock_expiry_blocks <= self.default_timelock_blocks {
            return Err("default timelock expiry must exceed default delay".to_string());
        }
        if self.max_batch_size == 0 {
            return Err("maximum rollout batch size must be non-zero".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPackage {
    pub package_id: String,
    pub namespace: String,
    pub contract_label: String,
    pub contract_kind: DeploymentContractKind,
    pub status: DeploymentPackageStatus,
    pub deployer_commitment: String,
    pub admin_policy_root: String,
    pub abi_manifest_id: String,
    pub bytecode_commitment_id: String,
    pub constructor_witness_id: String,
    pub proving_key_root: String,
    pub upgrade_policy_root: String,
    pub privacy_policy_root: String,
    pub defi_policy_root: String,
    pub sponsor_id: String,
    pub rollout_batch_id: String,
    pub salt_commitment: String,
    pub address_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl DeploymentPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: &str,
        contract_label: &str,
        contract_kind: DeploymentContractKind,
        deployer_commitment: &str,
        abi_manifest_id: &str,
        bytecode_commitment_id: &str,
        constructor_witness_id: &str,
        proving_key_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
        salt_commitment: &str,
    ) -> Self {
        let package_id = deployment_package_id(
            namespace,
            contract_label,
            contract_kind,
            deployer_commitment,
            salt_commitment,
        );
        let address_commitment = deployment_address_commitment(
            namespace,
            contract_label,
            deployer_commitment,
            salt_commitment,
        );
        let admin_policy_root = deployment_string_root("ADMIN-POLICY", deployer_commitment);
        let upgrade_policy_root = deployment_string_root("UPGRADE-POLICY", &package_id);
        let privacy_policy_root = deployment_string_root("PRIVACY-POLICY", &package_id);
        let defi_policy_root = deployment_string_root("DEFI-POLICY", contract_kind.as_str());
        let sponsor_id = deployment_optional_id("no-sponsor", &package_id);
        let rollout_batch_id = deployment_optional_id("unassigned-rollout", &package_id);
        let metadata_root = deployment_payload_root(
            "PACKAGE-METADATA",
            &json!({
                "namespace": namespace,
                "contract_label": contract_label,
                "contract_kind": contract_kind.as_str(),
            }),
        );
        Self {
            package_id,
            namespace: namespace.to_string(),
            contract_label: contract_label.to_string(),
            contract_kind,
            status: DeploymentPackageStatus::Draft,
            deployer_commitment: deployer_commitment.to_string(),
            admin_policy_root,
            abi_manifest_id: abi_manifest_id.to_string(),
            bytecode_commitment_id: bytecode_commitment_id.to_string(),
            constructor_witness_id: constructor_witness_id.to_string(),
            proving_key_root: proving_key_root.to_string(),
            upgrade_policy_root,
            privacy_policy_root,
            defi_policy_root,
            sponsor_id,
            rollout_batch_id,
            salt_commitment: salt_commitment.to_string(),
            address_commitment,
            created_at_height,
            expires_at_height,
            metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deployment_package",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "package_id": self.package_id,
            "namespace": self.namespace,
            "contract_label": self.contract_label,
            "contract_kind": self.contract_kind.as_str(),
            "status": self.status.as_str(),
            "deployer_commitment": self.deployer_commitment,
            "admin_policy_root": self.admin_policy_root,
            "abi_manifest_id": self.abi_manifest_id,
            "bytecode_commitment_id": self.bytecode_commitment_id,
            "constructor_witness_id": self.constructor_witness_id,
            "proving_key_root": self.proving_key_root,
            "upgrade_policy_root": self.upgrade_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "defi_policy_root": self.defi_policy_root,
            "sponsor_id": self.sponsor_id,
            "rollout_batch_id": self.rollout_batch_id,
            "salt_commitment": self.salt_commitment,
            "address_commitment": self.address_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("PACKAGE", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("package id", &self.package_id)?;
        ensure_non_empty("package namespace", &self.namespace)?;
        ensure_non_empty("package contract label", &self.contract_label)?;
        ensure_non_empty("package deployer commitment", &self.deployer_commitment)?;
        ensure_non_empty("package admin policy root", &self.admin_policy_root)?;
        ensure_non_empty("package abi manifest id", &self.abi_manifest_id)?;
        ensure_non_empty(
            "package bytecode commitment id",
            &self.bytecode_commitment_id,
        )?;
        ensure_non_empty(
            "package constructor witness id",
            &self.constructor_witness_id,
        )?;
        ensure_non_empty("package proving key root", &self.proving_key_root)?;
        ensure_non_empty("package upgrade policy root", &self.upgrade_policy_root)?;
        ensure_non_empty("package privacy policy root", &self.privacy_policy_root)?;
        ensure_non_empty("package defi policy root", &self.defi_policy_root)?;
        ensure_non_empty("package salt commitment", &self.salt_commitment)?;
        ensure_non_empty("package address commitment", &self.address_commitment)?;
        ensure_non_empty("package metadata root", &self.metadata_root)?;
        if self.expires_at_height <= self.created_at_height {
            return Err("package expiry must exceed creation height".to_string());
        }
        let reference_id = deployment_package_id(
            &self.namespace,
            &self.contract_label,
            self.contract_kind,
            &self.deployer_commitment,
            &self.salt_commitment,
        );
        if self.package_id != reference_id {
            return Err("package id does not match deterministic package fields".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedAbiManifest {
    pub manifest_id: String,
    pub package_id: String,
    pub visibility: AbiManifestVisibility,
    pub encryption_scheme: String,
    pub manifest_ciphertext_root: String,
    pub selector_root: String,
    pub event_root: String,
    pub error_root: String,
    pub disclosure_policy_root: String,
    pub recipient_key_root: String,
    pub manifest_size_bytes: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedAbiManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        visibility: AbiManifestVisibility,
        manifest_ciphertext_root: &str,
        selector_root: &str,
        event_root: &str,
        error_root: &str,
        recipient_key_root: &str,
        manifest_size_bytes: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let manifest_id = encrypted_abi_manifest_id(
            package_id,
            manifest_ciphertext_root,
            selector_root,
            recipient_key_root,
        );
        let disclosure_policy_root =
            deployment_string_root("ABI-DISCLOSURE-POLICY", visibility.as_str());
        Self {
            manifest_id,
            package_id: package_id.to_string(),
            visibility,
            encryption_scheme: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_ABI_ENCRYPTION_SCHEME
                .to_string(),
            manifest_ciphertext_root: manifest_ciphertext_root.to_string(),
            selector_root: selector_root.to_string(),
            event_root: event_root.to_string(),
            error_root: error_root.to_string(),
            disclosure_policy_root,
            recipient_key_root: recipient_key_root.to_string(),
            manifest_size_bytes,
            created_at_height,
            expires_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_abi_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "package_id": self.package_id,
            "visibility": self.visibility.as_str(),
            "encryption_scheme": self.encryption_scheme,
            "manifest_ciphertext_root": self.manifest_ciphertext_root,
            "selector_root": self.selector_root,
            "event_root": self.event_root,
            "error_root": self.error_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "recipient_key_root": self.recipient_key_root,
            "manifest_size_bytes": self.manifest_size_bytes,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("ENCRYPTED-ABI", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("abi manifest id", &self.manifest_id)?;
        ensure_non_empty("abi package id", &self.package_id)?;
        ensure_non_empty("abi encryption scheme", &self.encryption_scheme)?;
        ensure_non_empty("abi ciphertext root", &self.manifest_ciphertext_root)?;
        ensure_non_empty("abi selector root", &self.selector_root)?;
        ensure_non_empty("abi event root", &self.event_root)?;
        ensure_non_empty("abi error root", &self.error_root)?;
        ensure_non_empty("abi disclosure policy root", &self.disclosure_policy_root)?;
        ensure_non_empty("abi recipient key root", &self.recipient_key_root)?;
        ensure_positive(self.manifest_size_bytes, "abi manifest size")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("abi manifest expiry must exceed creation height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeCommitment {
    pub commitment_id: String,
    pub package_id: String,
    pub bytecode_root: String,
    pub bytecode_hash: String,
    pub bytecode_size_bytes: u64,
    pub vm_profile: String,
    pub optimization_profile_root: String,
    pub reproducible_build_root: String,
    pub status: CommitmentStatus,
}

impl BytecodeCommitment {
    pub fn new(
        package_id: &str,
        bytecode: &[u8],
        vm_profile: &str,
        optimization_profile_root: &str,
        reproducible_build_root: &str,
    ) -> Self {
        let bytecode_root = deployment_blob_root("BYTECODE-BLOB", bytecode);
        let bytecode_hash = deployment_string_root("BYTECODE-HASH", &bytecode_root);
        let commitment_id = bytecode_commitment_id(
            package_id,
            &bytecode_root,
            vm_profile,
            reproducible_build_root,
        );
        Self {
            commitment_id,
            package_id: package_id.to_string(),
            bytecode_root,
            bytecode_hash,
            bytecode_size_bytes: bytecode.len() as u64,
            vm_profile: vm_profile.to_string(),
            optimization_profile_root: optimization_profile_root.to_string(),
            reproducible_build_root: reproducible_build_root.to_string(),
            status: CommitmentStatus::Pinned,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bytecode_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "commitment_id": self.commitment_id,
            "package_id": self.package_id,
            "bytecode_commitment_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_BYTECODE_COMMITMENT_SCHEME,
            "bytecode_root": self.bytecode_root,
            "bytecode_hash": self.bytecode_hash,
            "bytecode_size_bytes": self.bytecode_size_bytes,
            "vm_profile": self.vm_profile,
            "optimization_profile_root": self.optimization_profile_root,
            "reproducible_build_root": self.reproducible_build_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("BYTECODE-COMMITMENT", &self.public_record())
    }

    pub fn validate(
        &self,
        max_bytecode_bytes: u64,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("bytecode commitment id", &self.commitment_id)?;
        ensure_non_empty("bytecode package id", &self.package_id)?;
        ensure_non_empty("bytecode root", &self.bytecode_root)?;
        ensure_non_empty("bytecode hash", &self.bytecode_hash)?;
        ensure_positive(self.bytecode_size_bytes, "bytecode size")?;
        ensure_non_empty("bytecode vm profile", &self.vm_profile)?;
        ensure_non_empty(
            "bytecode optimization profile root",
            &self.optimization_profile_root,
        )?;
        ensure_non_empty(
            "bytecode reproducible build root",
            &self.reproducible_build_root,
        )?;
        if self.bytecode_size_bytes > max_bytecode_bytes {
            return Err("bytecode commitment exceeds configured maximum size".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvingKeyCommitment {
    pub proving_key_id: String,
    pub package_id: String,
    pub circuit_id: String,
    pub proof_system: String,
    pub proving_key_root: String,
    pub verifier_key_root: String,
    pub proving_key_size_bytes: u64,
    pub recursion_profile_root: String,
    pub status: CommitmentStatus,
}

impl ProvingKeyCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        circuit_id: &str,
        proof_system: &str,
        proving_key_root: &str,
        verifier_key_root: &str,
        proving_key_size_bytes: u64,
        recursion_profile_root: &str,
    ) -> Self {
        let proving_key_id = proving_key_commitment_id(
            package_id,
            circuit_id,
            proof_system,
            proving_key_root,
            verifier_key_root,
        );
        Self {
            proving_key_id,
            package_id: package_id.to_string(),
            circuit_id: circuit_id.to_string(),
            proof_system: proof_system.to_string(),
            proving_key_root: proving_key_root.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            proving_key_size_bytes,
            recursion_profile_root: recursion_profile_root.to_string(),
            status: CommitmentStatus::Pinned,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proving_key_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "proving_key_id": self.proving_key_id,
            "package_id": self.package_id,
            "circuit_id": self.circuit_id,
            "proof_system": self.proof_system,
            "proving_key_commitment_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROVING_KEY_COMMITMENT_SCHEME,
            "proving_key_root": self.proving_key_root,
            "verifier_key_root": self.verifier_key_root,
            "proving_key_size_bytes": self.proving_key_size_bytes,
            "recursion_profile_root": self.recursion_profile_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("PROVING-KEY-COMMITMENT", &self.public_record())
    }

    pub fn validate(
        &self,
        max_proving_key_bytes: u64,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("proving key id", &self.proving_key_id)?;
        ensure_non_empty("proving key package id", &self.package_id)?;
        ensure_non_empty("proving key circuit id", &self.circuit_id)?;
        ensure_non_empty("proving key proof system", &self.proof_system)?;
        ensure_non_empty("proving key root", &self.proving_key_root)?;
        ensure_non_empty("verifier key root", &self.verifier_key_root)?;
        ensure_positive(self.proving_key_size_bytes, "proving key size")?;
        ensure_non_empty("recursion profile root", &self.recursion_profile_root)?;
        if self.proving_key_size_bytes > max_proving_key_bytes {
            return Err("proving key commitment exceeds configured maximum size".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqDeployerApproval {
    pub approval_id: String,
    pub package_id: String,
    pub deployer_commitment: String,
    pub approval_authority_root: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub approved_address_commitment: String,
    pub approved_at_height: u64,
    pub expires_at_height: u64,
    pub status: ApprovalStatus,
}

impl PqDeployerApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        deployer_commitment: &str,
        approval_authority_root: &str,
        pq_public_key_root: &str,
        signature_root: &str,
        approved_address_commitment: &str,
        approved_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let approval_id = pq_deployer_approval_id(
            package_id,
            deployer_commitment,
            approval_authority_root,
            signature_root,
        );
        Self {
            approval_id,
            package_id: package_id.to_string(),
            deployer_commitment: deployer_commitment.to_string(),
            approval_authority_root: approval_authority_root.to_string(),
            pq_public_key_root: pq_public_key_root.to_string(),
            signature_root: signature_root.to_string(),
            approved_address_commitment: approved_address_commitment.to_string(),
            approved_at_height,
            expires_at_height,
            status: ApprovalStatus::Approved,
        }
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_for_quorum() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_deployer_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "approval_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEPLOYER_APPROVAL_SCHEME,
            "approval_id": self.approval_id,
            "package_id": self.package_id,
            "deployer_commitment": self.deployer_commitment,
            "approval_authority_root": self.approval_authority_root,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "approved_address_commitment": self.approved_address_commitment,
            "approved_at_height": self.approved_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("PQ-DEPLOYER-APPROVAL", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("approval id", &self.approval_id)?;
        ensure_non_empty("approval package id", &self.package_id)?;
        ensure_non_empty("approval deployer commitment", &self.deployer_commitment)?;
        ensure_non_empty("approval authority root", &self.approval_authority_root)?;
        ensure_non_empty("approval public key root", &self.pq_public_key_root)?;
        ensure_non_empty("approval signature root", &self.signature_root)?;
        ensure_non_empty(
            "approval address commitment",
            &self.approved_address_commitment,
        )?;
        if self.expires_at_height <= self.approved_at_height {
            return Err("approval expiry must exceed approval height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAttestation {
    pub attestation_id: String,
    pub package_id: String,
    pub auditor_commitment: String,
    pub scope: AuditScope,
    pub status: AuditAttestationStatus,
    pub score_bps: u64,
    pub disclosure_bps: u64,
    pub findings_root: String,
    pub remediations_root: String,
    pub signature_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl AuditAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        auditor_commitment: &str,
        scope: AuditScope,
        score_bps: u64,
        disclosure_bps: u64,
        findings_root: &str,
        remediations_root: &str,
        signature_root: &str,
        attested_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let attestation_id =
            audit_attestation_id(package_id, auditor_commitment, scope, findings_root);
        Self {
            attestation_id,
            package_id: package_id.to_string(),
            auditor_commitment: auditor_commitment.to_string(),
            scope,
            status: AuditAttestationStatus::Accepted,
            score_bps,
            disclosure_bps,
            findings_root: findings_root.to_string(),
            remediations_root: remediations_root.to_string(),
            signature_root: signature_root.to_string(),
            attested_at_height,
            expires_at_height,
        }
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_for_policy() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "attestation_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_AUDIT_ATTESTATION_SCHEME,
            "attestation_id": self.attestation_id,
            "package_id": self.package_id,
            "auditor_commitment": self.auditor_commitment,
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "score_bps": self.score_bps,
            "disclosure_bps": self.disclosure_bps,
            "findings_root": self.findings_root,
            "remediations_root": self.remediations_root,
            "signature_root": self.signature_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("AUDIT-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("attestation id", &self.attestation_id)?;
        ensure_non_empty("attestation package id", &self.package_id)?;
        ensure_non_empty("attestation auditor commitment", &self.auditor_commitment)?;
        ensure_bps(self.score_bps, "attestation score")?;
        ensure_bps(self.disclosure_bps, "attestation disclosure")?;
        ensure_non_empty("attestation findings root", &self.findings_root)?;
        ensure_non_empty("attestation remediations root", &self.remediations_root)?;
        ensure_non_empty("attestation signature root", &self.signature_root)?;
        if self.expires_at_height <= self.attested_at_height {
            return Err("attestation expiry must exceed attestation height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeTimelock {
    pub timelock_id: String,
    pub package_id: String,
    pub current_commitment_root: String,
    pub proposed_commitment_root: String,
    pub governance_commitment: String,
    pub pq_signature_root: String,
    pub queued_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: UpgradeTimelockStatus,
}

impl UpgradeTimelock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        current_commitment_root: &str,
        proposed_commitment_root: &str,
        governance_commitment: &str,
        pq_signature_root: &str,
        queued_at_height: u64,
        executable_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let timelock_id = upgrade_timelock_id(
            package_id,
            current_commitment_root,
            proposed_commitment_root,
            queued_at_height,
        );
        Self {
            timelock_id,
            package_id: package_id.to_string(),
            current_commitment_root: current_commitment_root.to_string(),
            proposed_commitment_root: proposed_commitment_root.to_string(),
            governance_commitment: governance_commitment.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            queued_at_height,
            executable_at_height,
            expires_at_height,
            status: UpgradeTimelockStatus::Queued,
        }
    }

    pub fn is_executable_at(&self, height: u64) -> bool {
        self.status.is_open()
            && height >= self.executable_at_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "upgrade_timelock",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "timelock_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_UPGRADE_TIMELOCK_SCHEME,
            "timelock_id": self.timelock_id,
            "package_id": self.package_id,
            "current_commitment_root": self.current_commitment_root,
            "proposed_commitment_root": self.proposed_commitment_root,
            "governance_commitment": self.governance_commitment,
            "pq_signature_root": self.pq_signature_root,
            "queued_at_height": self.queued_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("UPGRADE-TIMELOCK", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("timelock id", &self.timelock_id)?;
        ensure_non_empty("timelock package id", &self.package_id)?;
        ensure_non_empty(
            "timelock current commitment root",
            &self.current_commitment_root,
        )?;
        ensure_non_empty(
            "timelock proposed commitment root",
            &self.proposed_commitment_root,
        )?;
        ensure_non_empty(
            "timelock governance commitment",
            &self.governance_commitment,
        )?;
        ensure_non_empty("timelock pq signature root", &self.pq_signature_root)?;
        if self.executable_at_height <= self.queued_at_height {
            return Err("timelock executable height must exceed queue height".to_string());
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err("timelock expiry must exceed executable height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeDeploymentSponsorship {
    pub sponsor_id: String,
    pub package_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub lane_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub max_fee_units: u64,
    pub privacy_set_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeDeploymentSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        lane_id: &str,
        budget_units: u64,
        max_fee_units: u64,
        privacy_set_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let sponsor_id = low_fee_sponsorship_id(
            package_id,
            sponsor_commitment,
            fee_asset_id,
            created_at_height,
        );
        Self {
            sponsor_id,
            package_id: package_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            lane_id: lane_id.to_string(),
            budget_units,
            reserved_units: 0,
            consumed_units: 0,
            max_fee_units,
            privacy_set_root: privacy_set_root.to_string(),
            created_at_height,
            expires_at_height,
            status: SponsorshipStatus::Offered,
        }
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn can_cover(&self, fee_units: u64, height: u64) -> bool {
        self.status.can_sponsor()
            && height <= self.expires_at_height
            && fee_units <= self.max_fee_units
            && fee_units <= self.remaining_units()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_deployment_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "sponsorship_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_LOW_FEE_SPONSORSHIP_SCHEME,
            "sponsor_id": self.sponsor_id,
            "package_id": self.package_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "lane_id": self.lane_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "remaining_units": self.remaining_units(),
            "max_fee_units": self.max_fee_units,
            "privacy_set_root": self.privacy_set_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("LOW-FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("sponsor id", &self.sponsor_id)?;
        ensure_non_empty("sponsor package id", &self.package_id)?;
        ensure_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        ensure_non_empty("sponsor fee asset id", &self.fee_asset_id)?;
        ensure_non_empty("sponsor lane id", &self.lane_id)?;
        ensure_positive(self.budget_units, "sponsor budget")?;
        ensure_positive(self.max_fee_units, "sponsor max fee")?;
        ensure_non_empty("sponsor privacy set root", &self.privacy_set_root)?;
        if self.reserved_units.saturating_add(self.consumed_units) > self.budget_units {
            return Err("sponsorship reserved and consumed units exceed budget".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("sponsorship expiry must exceed creation height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstructorWitnessEnvelope {
    pub witness_id: String,
    pub package_id: String,
    pub encryption_scheme: String,
    pub constructor_selector_root: String,
    pub encrypted_args_root: String,
    pub witness_ciphertext_root: String,
    pub nullifier_root: String,
    pub recipient_key_root: String,
    pub proof_root: String,
    pub envelope_size_bytes: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: WitnessEnvelopeStatus,
}

impl ConstructorWitnessEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        constructor_selector_root: &str,
        encrypted_args_root: &str,
        witness_ciphertext_root: &str,
        nullifier_root: &str,
        recipient_key_root: &str,
        proof_root: &str,
        envelope_size_bytes: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let witness_id = constructor_witness_id(
            package_id,
            constructor_selector_root,
            encrypted_args_root,
            nullifier_root,
        );
        Self {
            witness_id,
            package_id: package_id.to_string(),
            encryption_scheme: CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_CONSTRUCTOR_WITNESS_SCHEME
                .to_string(),
            constructor_selector_root: constructor_selector_root.to_string(),
            encrypted_args_root: encrypted_args_root.to_string(),
            witness_ciphertext_root: witness_ciphertext_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            recipient_key_root: recipient_key_root.to_string(),
            proof_root: proof_root.to_string(),
            envelope_size_bytes,
            created_at_height,
            expires_at_height,
            status: WitnessEnvelopeStatus::Sealed,
        }
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.can_deploy() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "constructor_witness_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "witness_id": self.witness_id,
            "package_id": self.package_id,
            "encryption_scheme": self.encryption_scheme,
            "constructor_selector_root": self.constructor_selector_root,
            "encrypted_args_root": self.encrypted_args_root,
            "witness_ciphertext_root": self.witness_ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "recipient_key_root": self.recipient_key_root,
            "proof_root": self.proof_root,
            "envelope_size_bytes": self.envelope_size_bytes,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("CONSTRUCTOR-WITNESS", &self.public_record())
    }

    pub fn validate(
        &self,
        max_constructor_bytes: u64,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("witness id", &self.witness_id)?;
        ensure_non_empty("witness package id", &self.package_id)?;
        ensure_non_empty("witness encryption scheme", &self.encryption_scheme)?;
        ensure_non_empty(
            "witness constructor selector root",
            &self.constructor_selector_root,
        )?;
        ensure_non_empty("witness encrypted args root", &self.encrypted_args_root)?;
        ensure_non_empty("witness ciphertext root", &self.witness_ciphertext_root)?;
        ensure_non_empty("witness nullifier root", &self.nullifier_root)?;
        ensure_non_empty("witness recipient key root", &self.recipient_key_root)?;
        ensure_non_empty("witness proof root", &self.proof_root)?;
        ensure_positive(self.envelope_size_bytes, "witness envelope size")?;
        if self.envelope_size_bytes > max_constructor_bytes {
            return Err("constructor witness exceeds configured maximum size".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("constructor witness expiry must exceed creation height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPolicyCheck {
    pub check_id: String,
    pub package_id: String,
    pub check_kind: PolicyCheckKind,
    pub verdict: PolicyVerdict,
    pub observed_root: String,
    pub requirement_root: String,
    pub evaluator_commitment: String,
    pub evaluated_at_height: u64,
    pub expires_at_height: u64,
    pub notes_root: String,
}

impl DeploymentPolicyCheck {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package_id: &str,
        check_kind: PolicyCheckKind,
        verdict: PolicyVerdict,
        observed_root: &str,
        requirement_root: &str,
        evaluator_commitment: &str,
        evaluated_at_height: u64,
        expires_at_height: u64,
        notes_root: &str,
    ) -> Self {
        let check_id = policy_check_id(package_id, check_kind, observed_root, evaluator_commitment);
        Self {
            check_id,
            package_id: package_id.to_string(),
            check_kind,
            verdict,
            observed_root: observed_root.to_string(),
            requirement_root: requirement_root.to_string(),
            evaluator_commitment: evaluator_commitment.to_string(),
            evaluated_at_height,
            expires_at_height,
            notes_root: notes_root.to_string(),
        }
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.verdict.permits_deployment() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deployment_policy_check",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "policy_check_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_POLICY_CHECK_SCHEME,
            "check_id": self.check_id,
            "package_id": self.package_id,
            "check_kind": self.check_kind.as_str(),
            "verdict": self.verdict.as_str(),
            "observed_root": self.observed_root,
            "requirement_root": self.requirement_root,
            "evaluator_commitment": self.evaluator_commitment,
            "evaluated_at_height": self.evaluated_at_height,
            "expires_at_height": self.expires_at_height,
            "notes_root": self.notes_root,
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("POLICY-CHECK", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("policy check id", &self.check_id)?;
        ensure_non_empty("policy check package id", &self.package_id)?;
        ensure_non_empty("policy check observed root", &self.observed_root)?;
        ensure_non_empty("policy check requirement root", &self.requirement_root)?;
        ensure_non_empty(
            "policy check evaluator commitment",
            &self.evaluator_commitment,
        )?;
        ensure_non_empty("policy check notes root", &self.notes_root)?;
        if self.expires_at_height <= self.evaluated_at_height {
            return Err("policy check expiry must exceed evaluation height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutBatch {
    pub batch_id: String,
    pub namespace: String,
    pub package_ids: Vec<String>,
    pub package_root: String,
    pub sequencer_commitment: String,
    pub low_fee_lane: String,
    pub collect_start_height: u64,
    pub execute_after_height: u64,
    pub finalize_before_height: u64,
    pub status: RolloutBatchStatus,
}

impl RolloutBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: &str,
        package_ids: Vec<String>,
        sequencer_commitment: &str,
        low_fee_lane: &str,
        collect_start_height: u64,
        execute_after_height: u64,
        finalize_before_height: u64,
    ) -> Self {
        let package_root = deployment_string_set_root("ROLLOUT-PACKAGES", &package_ids);
        let batch_id = rollout_batch_id(namespace, &package_root, collect_start_height);
        Self {
            batch_id,
            namespace: namespace.to_string(),
            package_ids,
            package_root,
            sequencer_commitment: sequencer_commitment.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            collect_start_height,
            execute_after_height,
            finalize_before_height,
            status: RolloutBatchStatus::Collecting,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollout_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "rollout_scheme": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_ROLLOUT_SCHEME,
            "batch_id": self.batch_id,
            "namespace": self.namespace,
            "package_ids": self.package_ids,
            "package_root": self.package_root,
            "sequencer_commitment": self.sequencer_commitment,
            "low_fee_lane": self.low_fee_lane,
            "collect_start_height": self.collect_start_height,
            "execute_after_height": self.execute_after_height,
            "finalize_before_height": self.finalize_before_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("ROLLOUT-BATCH", &self.public_record())
    }

    pub fn validate(
        &self,
        max_batch_size: usize,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("rollout batch id", &self.batch_id)?;
        ensure_non_empty("rollout namespace", &self.namespace)?;
        ensure_non_empty("rollout package root", &self.package_root)?;
        ensure_non_empty("rollout sequencer commitment", &self.sequencer_commitment)?;
        ensure_non_empty("rollout low fee lane", &self.low_fee_lane)?;
        if self.package_ids.is_empty() {
            return Err("rollout batch must include at least one package".to_string());
        }
        if self.package_ids.len() > max_batch_size {
            return Err("rollout batch exceeds configured maximum size".to_string());
        }
        if self.execute_after_height <= self.collect_start_height {
            return Err("rollout execution height must exceed collection start".to_string());
        }
        if self.finalize_before_height <= self.execute_after_height {
            return Err("rollout finalization height must exceed execution height".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentPublicRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub height: u64,
    pub payload_root: String,
    pub payload: Value,
}

impl DeploymentPublicRecord {
    pub fn new(object_kind: &str, object_id: &str, height: u64, payload: Value) -> Self {
        let payload_root = deployment_payload_root("PUBLIC-RECORD-PAYLOAD", &payload);
        let record_id = public_record_id(object_kind, object_id, height, &payload_root);
        Self {
            record_id,
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            height,
            payload_root,
            payload,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deployment_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "height": self.height,
            "payload_root": self.payload_root,
            "payload": self.payload,
        })
    }

    pub fn root(&self) -> String {
        deployment_payload_root("PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("public record id", &self.record_id)?;
        ensure_non_empty("public record object kind", &self.object_kind)?;
        ensure_non_empty("public record object id", &self.object_id)?;
        ensure_non_empty("public record payload root", &self.payload_root)?;
        let reference_payload_root =
            deployment_payload_root("PUBLIC-RECORD-PAYLOAD", &self.payload);
        if self.payload_root != reference_payload_root {
            return Err("public record payload root mismatch".to_string());
        }
        let reference_id = public_record_id(
            &self.object_kind,
            &self.object_id,
            self.height,
            &self.payload_root,
        );
        if self.record_id != reference_id {
            return Err("public record id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialContractDeploymentRoots {
    pub config_root: String,
    pub package_root: String,
    pub abi_manifest_root: String,
    pub bytecode_commitment_root: String,
    pub proving_key_commitment_root: String,
    pub deployer_approval_root: String,
    pub audit_attestation_root: String,
    pub upgrade_timelock_root: String,
    pub sponsorship_root: String,
    pub constructor_witness_root: String,
    pub policy_check_root: String,
    pub rollout_batch_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl ConfidentialContractDeploymentRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_contract_deployment_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "package_root": self.package_root,
            "abi_manifest_root": self.abi_manifest_root,
            "bytecode_commitment_root": self.bytecode_commitment_root,
            "proving_key_commitment_root": self.proving_key_commitment_root,
            "deployer_approval_root": self.deployer_approval_root,
            "audit_attestation_root": self.audit_attestation_root,
            "upgrade_timelock_root": self.upgrade_timelock_root,
            "sponsorship_root": self.sponsorship_root,
            "constructor_witness_root": self.constructor_witness_root,
            "policy_check_root": self.policy_check_root,
            "rollout_batch_root": self.rollout_batch_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        ensure_non_empty("roots config root", &self.config_root)?;
        ensure_non_empty("roots package root", &self.package_root)?;
        ensure_non_empty("roots abi manifest root", &self.abi_manifest_root)?;
        ensure_non_empty(
            "roots bytecode commitment root",
            &self.bytecode_commitment_root,
        )?;
        ensure_non_empty(
            "roots proving key commitment root",
            &self.proving_key_commitment_root,
        )?;
        ensure_non_empty("roots deployer approval root", &self.deployer_approval_root)?;
        ensure_non_empty("roots audit attestation root", &self.audit_attestation_root)?;
        ensure_non_empty("roots upgrade timelock root", &self.upgrade_timelock_root)?;
        ensure_non_empty("roots sponsorship root", &self.sponsorship_root)?;
        ensure_non_empty(
            "roots constructor witness root",
            &self.constructor_witness_root,
        )?;
        ensure_non_empty("roots policy check root", &self.policy_check_root)?;
        ensure_non_empty("roots rollout batch root", &self.rollout_batch_root)?;
        ensure_non_empty("roots public record root", &self.public_record_root)?;
        ensure_non_empty("roots state root", &self.state_root)?;
        Ok(deployment_payload_root("ROOTS", &self.public_record()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialContractDeploymentCounters {
    pub packages: usize,
    pub live_packages: usize,
    pub abi_manifests: usize,
    pub bytecode_commitments: usize,
    pub proving_key_commitments: usize,
    pub approvals: usize,
    pub active_approvals: usize,
    pub audit_attestations: usize,
    pub active_audit_attestations: usize,
    pub upgrade_timelocks: usize,
    pub open_upgrade_timelocks: usize,
    pub sponsorships: usize,
    pub active_sponsorships: usize,
    pub constructor_witnesses: usize,
    pub active_constructor_witnesses: usize,
    pub policy_checks: usize,
    pub passing_policy_checks: usize,
    pub rollout_batches: usize,
    pub open_rollout_batches: usize,
    pub public_records: usize,
}

impl ConfidentialContractDeploymentCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_contract_deployment_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "packages": self.packages,
            "live_packages": self.live_packages,
            "abi_manifests": self.abi_manifests,
            "bytecode_commitments": self.bytecode_commitments,
            "proving_key_commitments": self.proving_key_commitments,
            "approvals": self.approvals,
            "active_approvals": self.active_approvals,
            "audit_attestations": self.audit_attestations,
            "active_audit_attestations": self.active_audit_attestations,
            "upgrade_timelocks": self.upgrade_timelocks,
            "open_upgrade_timelocks": self.open_upgrade_timelocks,
            "sponsorships": self.sponsorships,
            "active_sponsorships": self.active_sponsorships,
            "constructor_witnesses": self.constructor_witnesses,
            "active_constructor_witnesses": self.active_constructor_witnesses,
            "policy_checks": self.policy_checks,
            "passing_policy_checks": self.passing_policy_checks,
            "rollout_batches": self.rollout_batches,
            "open_rollout_batches": self.open_rollout_batches,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialContractDeploymentState {
    pub config: ConfidentialContractDeploymentConfig,
    pub height: u64,
    pub packages: BTreeMap<String, DeploymentPackage>,
    pub abi_manifests: BTreeMap<String, EncryptedAbiManifest>,
    pub bytecode_commitments: BTreeMap<String, BytecodeCommitment>,
    pub proving_key_commitments: BTreeMap<String, ProvingKeyCommitment>,
    pub deployer_approvals: BTreeMap<String, PqDeployerApproval>,
    pub audit_attestations: BTreeMap<String, AuditAttestation>,
    pub upgrade_timelocks: BTreeMap<String, UpgradeTimelock>,
    pub sponsorships: BTreeMap<String, LowFeeDeploymentSponsorship>,
    pub constructor_witnesses: BTreeMap<String, ConstructorWitnessEnvelope>,
    pub policy_checks: BTreeMap<String, DeploymentPolicyCheck>,
    pub rollout_batches: BTreeMap<String, RolloutBatch>,
    pub public_records: BTreeMap<String, DeploymentPublicRecord>,
}

impl ConfidentialContractDeploymentState {
    pub fn new(config: ConfidentialContractDeploymentConfig, height: u64) -> Self {
        Self {
            config,
            height,
            packages: BTreeMap::new(),
            abi_manifests: BTreeMap::new(),
            bytecode_commitments: BTreeMap::new(),
            proving_key_commitments: BTreeMap::new(),
            deployer_approvals: BTreeMap::new(),
            audit_attestations: BTreeMap::new(),
            upgrade_timelocks: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            constructor_witnesses: BTreeMap::new(),
            policy_checks: BTreeMap::new(),
            rollout_batches: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ConfidentialContractDeploymentPipelineResult<Self> {
        let config = ConfidentialContractDeploymentConfig::devnet();
        let height = CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_DEFAULT_HEIGHT;
        let mut state = Self::new(config.clone(), height);

        let selector_root = deployment_string_set_root(
            "DEVNET-SELECTORS",
            &[
                "mint_private(bytes32,uint64)".to_string(),
                "transfer_private(bytes32,bytes32,uint64)".to_string(),
                "redeem_private(bytes32,uint64)".to_string(),
            ],
        );
        let event_root = deployment_string_set_root(
            "DEVNET-EVENTS",
            &[
                "PrivateMint(bytes32)".to_string(),
                "PrivateTransfer(bytes32)".to_string(),
            ],
        );
        let error_root = deployment_string_set_root(
            "DEVNET-ERRORS",
            &["InsufficientShieldedBalance()".to_string()],
        );
        let package_seed = deployment_string_root("DEVNET-PACKAGE-SEED", "private-token");
        let package_id = deployment_package_id(
            &config.default_namespace,
            "shielded-wxmr-token",
            DeploymentContractKind::PrivateToken,
            "deployer-commitment-devnet-treasury",
            &package_seed,
        );
        let abi = EncryptedAbiManifest::new(
            &package_id,
            AbiManifestVisibility::SelectiveDisclosure,
            &deployment_string_root("DEVNET-ABI-CIPHERTEXT", "shielded-wxmr-token"),
            &selector_root,
            &event_root,
            &error_root,
            &deployment_string_root("DEVNET-ABI-RECIPIENTS", "auditor+deployer"),
            8_192,
            height,
            height + config.default_audit_ttl_blocks,
        );
        let bytecode = BytecodeCommitment::new(
            &package_id,
            b"nebula-devnet-private-token-bytecode-v1",
            "nebula-confidential-wasm-v1",
            &deployment_string_root("DEVNET-OPTIMIZATION", "speed+low-fee"),
            &deployment_string_root("DEVNET-REPRO-BUILD", "private-token-build"),
        );
        let witness = ConstructorWitnessEnvelope::new(
            &package_id,
            &selector_root,
            &deployment_string_root("DEVNET-ARGS", "wxmr-private-token"),
            &deployment_string_root("DEVNET-WITNESS-CIPHERTEXT", "initial-supply"),
            &deployment_string_root("DEVNET-WITNESS-NULLIFIER", "private-token"),
            &deployment_string_root("DEVNET-WITNESS-RECIPIENTS", "sequencer+auditor"),
            &deployment_string_root("DEVNET-WITNESS-PROOF", "constructor-valid"),
            12_288,
            height,
            height + config.default_approval_ttl_blocks,
        );
        let proving_key = ProvingKeyCommitment::new(
            &package_id,
            "private-token-deploy-circuit",
            "plonkish-shake-devnet",
            &deployment_string_root("DEVNET-PROVING-KEY", "private-token"),
            &deployment_string_root("DEVNET-VERIFIER-KEY", "private-token"),
            1_048_576,
            &deployment_string_root("DEVNET-RECURSION", "batch-friendly"),
        );
        let proving_key_root =
            deployment_payload_root("DEVNET-PROVING-KEY-ROOT", &proving_key.public_record());
        let mut package = DeploymentPackage::new(
            &config.default_namespace,
            "shielded-wxmr-token",
            DeploymentContractKind::PrivateToken,
            "deployer-commitment-devnet-treasury",
            &abi.manifest_id,
            &bytecode.commitment_id,
            &witness.witness_id,
            &proving_key_root,
            height,
            height + config.default_audit_ttl_blocks,
            &package_seed,
        );
        package.status = DeploymentPackageStatus::Approved;

        let approval_a = PqDeployerApproval::new(
            &package.package_id,
            &package.deployer_commitment,
            &deployment_string_root("DEVNET-AUTHORITY", "treasury-council-a"),
            &deployment_string_root("DEVNET-PQ-PK", "treasury-council-a"),
            &deployment_string_root("DEVNET-PQ-SIG", "treasury-council-a"),
            &package.address_commitment,
            height,
            height + config.default_approval_ttl_blocks,
        );
        let approval_b = PqDeployerApproval::new(
            &package.package_id,
            &package.deployer_commitment,
            &deployment_string_root("DEVNET-AUTHORITY", "treasury-council-b"),
            &deployment_string_root("DEVNET-PQ-PK", "treasury-council-b"),
            &deployment_string_root("DEVNET-PQ-SIG", "treasury-council-b"),
            &package.address_commitment,
            height,
            height + config.default_approval_ttl_blocks,
        );
        let attestation = AuditAttestation::new(
            &package.package_id,
            "auditor-commitment-devnet-lab",
            AuditScope::PrivacyBudget,
            9_200,
            250,
            &deployment_string_root("DEVNET-FINDINGS", "private-token-clean"),
            &deployment_string_root("DEVNET-REMEDIATIONS", "none"),
            &deployment_string_root("DEVNET-AUDIT-SIG", "devnet-lab"),
            height,
            height + config.default_audit_ttl_blocks,
        );
        let sponsorship = LowFeeDeploymentSponsorship::new(
            &package.package_id,
            "sponsor-commitment-devnet-foundation",
            &config.default_fee_asset_id,
            &config.default_low_fee_lane,
            config.default_sponsor_budget_units,
            config.max_sponsored_fee_units,
            &deployment_string_root("DEVNET-SPONSOR-PRIVACY-SET", "foundation"),
            height,
            height + config.default_sponsor_ttl_blocks,
        );
        package.sponsor_id = sponsorship.sponsor_id.clone();
        let check = DeploymentPolicyCheck::new(
            &package.package_id,
            PolicyCheckKind::QuantumResistance,
            PolicyVerdict::Pass,
            &deployment_string_root("DEVNET-OBSERVED-PQ", &config.pq_suite),
            &deployment_string_root("DEVNET-REQUIRED-PQ", "min-192-bit"),
            "policy-evaluator-devnet",
            height,
            height + config.default_approval_ttl_blocks,
            &deployment_string_root("DEVNET-POLICY-NOTES", "pq-suite-accepted"),
        );
        let rollout = RolloutBatch::new(
            &config.default_namespace,
            vec![package.package_id.clone()],
            "sequencer-commitment-devnet-a",
            &config.default_low_fee_lane,
            height,
            height + config.default_timelock_blocks,
            height + config.default_timelock_blocks + config.default_rollout_window_blocks,
        );
        package.rollout_batch_id = rollout.batch_id.clone();

        state.register_abi_manifest(abi)?;
        state.register_bytecode_commitment(bytecode)?;
        state.register_constructor_witness(witness)?;
        state.register_proving_key_commitment(proving_key)?;
        state.register_package(package.clone())?;
        state.register_deployer_approval(approval_a)?;
        state.register_deployer_approval(approval_b)?;
        state.register_audit_attestation(attestation)?;
        state.register_sponsorship(sponsorship)?;
        state.register_policy_check(check)?;
        state.register_rollout_batch(rollout)?;
        state.publish_public_record(
            "deployment_package",
            &package.package_id,
            package.public_record(),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn register_package(
        &mut self,
        package: DeploymentPackage,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.packages.len() >= self.config.max_packages
            && !self.packages.contains_key(&package.package_id)
        {
            return Err("maximum deployment packages reached".to_string());
        }
        let root = package.validate()?;
        self.packages.insert(package.package_id.clone(), package);
        Ok(root)
    }

    pub fn register_abi_manifest(
        &mut self,
        manifest: EncryptedAbiManifest,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.abi_manifests.len() >= self.config.max_abi_manifests
            && !self.abi_manifests.contains_key(&manifest.manifest_id)
        {
            return Err("maximum abi manifests reached".to_string());
        }
        let root = manifest.validate()?;
        self.abi_manifests
            .insert(manifest.manifest_id.clone(), manifest);
        Ok(root)
    }

    pub fn register_bytecode_commitment(
        &mut self,
        commitment: BytecodeCommitment,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.bytecode_commitments.len() >= self.config.max_bytecode_commitments
            && !self
                .bytecode_commitments
                .contains_key(&commitment.commitment_id)
        {
            return Err("maximum bytecode commitments reached".to_string());
        }
        let root = commitment.validate(self.config.max_bytecode_bytes)?;
        self.bytecode_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(root)
    }

    pub fn register_proving_key_commitment(
        &mut self,
        commitment: ProvingKeyCommitment,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.proving_key_commitments.len() >= self.config.max_proving_key_commitments
            && !self
                .proving_key_commitments
                .contains_key(&commitment.proving_key_id)
        {
            return Err("maximum proving key commitments reached".to_string());
        }
        let root = commitment.validate(self.config.max_proving_key_bytes)?;
        self.proving_key_commitments
            .insert(commitment.proving_key_id.clone(), commitment);
        Ok(root)
    }

    pub fn register_deployer_approval(
        &mut self,
        approval: PqDeployerApproval,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.deployer_approvals.len() >= self.config.max_approvals
            && !self.deployer_approvals.contains_key(&approval.approval_id)
        {
            return Err("maximum deployer approvals reached".to_string());
        }
        let root = approval.validate()?;
        self.deployer_approvals
            .insert(approval.approval_id.clone(), approval);
        Ok(root)
    }

    pub fn register_audit_attestation(
        &mut self,
        attestation: AuditAttestation,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.audit_attestations.len() >= self.config.max_attestations
            && !self
                .audit_attestations
                .contains_key(&attestation.attestation_id)
        {
            return Err("maximum audit attestations reached".to_string());
        }
        let root = attestation.validate()?;
        self.audit_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(root)
    }

    pub fn register_upgrade_timelock(
        &mut self,
        timelock: UpgradeTimelock,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.upgrade_timelocks.len() >= self.config.max_timelocks
            && !self.upgrade_timelocks.contains_key(&timelock.timelock_id)
        {
            return Err("maximum upgrade timelocks reached".to_string());
        }
        let root = timelock.validate()?;
        self.upgrade_timelocks
            .insert(timelock.timelock_id.clone(), timelock);
        Ok(root)
    }

    pub fn register_sponsorship(
        &mut self,
        sponsorship: LowFeeDeploymentSponsorship,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.sponsorships.len() >= self.config.max_sponsorships
            && !self.sponsorships.contains_key(&sponsorship.sponsor_id)
        {
            return Err("maximum deployment sponsorships reached".to_string());
        }
        let root = sponsorship.validate()?;
        self.sponsorships
            .insert(sponsorship.sponsor_id.clone(), sponsorship);
        Ok(root)
    }

    pub fn register_constructor_witness(
        &mut self,
        witness: ConstructorWitnessEnvelope,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.constructor_witnesses.len() >= self.config.max_witnesses
            && !self.constructor_witnesses.contains_key(&witness.witness_id)
        {
            return Err("maximum constructor witnesses reached".to_string());
        }
        let root = witness.validate(self.config.max_constructor_bytes)?;
        self.constructor_witnesses
            .insert(witness.witness_id.clone(), witness);
        Ok(root)
    }

    pub fn register_policy_check(
        &mut self,
        check: DeploymentPolicyCheck,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.policy_checks.len() >= self.config.max_policy_checks
            && !self.policy_checks.contains_key(&check.check_id)
        {
            return Err("maximum deployment policy checks reached".to_string());
        }
        let root = check.validate()?;
        self.policy_checks.insert(check.check_id.clone(), check);
        Ok(root)
    }

    pub fn register_rollout_batch(
        &mut self,
        batch: RolloutBatch,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.rollout_batches.len() >= self.config.max_rollout_batches
            && !self.rollout_batches.contains_key(&batch.batch_id)
        {
            return Err("maximum rollout batches reached".to_string());
        }
        let root = batch.validate(self.config.max_batch_size)?;
        self.rollout_batches.insert(batch.batch_id.clone(), batch);
        Ok(root)
    }

    pub fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        payload: Value,
    ) -> ConfidentialContractDeploymentPipelineResult<String> {
        if self.public_records.len() >= self.config.max_public_records {
            return Err("maximum public records reached".to_string());
        }
        let record = DeploymentPublicRecord::new(object_kind, object_id, self.height, payload);
        let root = record.validate()?;
        self.public_records.insert(record.record_id.clone(), record);
        Ok(root)
    }

    pub fn approval_quorum_for_package(&self, package_id: &str) -> u64 {
        self.deployer_approvals
            .values()
            .filter(|approval| {
                approval.package_id == package_id && approval.is_active_at(self.height)
            })
            .count() as u64
    }

    pub fn audit_quorum_for_package(&self, package_id: &str) -> u64 {
        self.audit_attestations
            .values()
            .filter(|attestation| {
                attestation.package_id == package_id
                    && attestation.is_active_at(self.height)
                    && attestation.score_bps >= self.config.min_audit_score_bps
                    && attestation.disclosure_bps <= self.config.max_disclosure_bps
            })
            .count() as u64
    }

    pub fn policy_allows_package(&self, package_id: &str) -> bool {
        let package_checks = self
            .policy_checks
            .values()
            .filter(|check| check.package_id == package_id)
            .collect::<Vec<_>>();
        !package_checks.is_empty()
            && package_checks
                .iter()
                .all(|check| check.is_active_at(self.height))
    }

    pub fn package_ready_for_rollout(&self, package_id: &str) -> bool {
        let package = match self.packages.get(package_id) {
            Some(package) => package,
            None => return false,
        };
        package.status.is_live()
            && self.abi_manifests.contains_key(&package.abi_manifest_id)
            && self
                .bytecode_commitments
                .contains_key(&package.bytecode_commitment_id)
            && match self
                .constructor_witnesses
                .get(&package.constructor_witness_id)
            {
                Some(witness) => witness.is_active_at(self.height),
                None => false,
            }
            && self.approval_quorum_for_package(package_id) >= self.config.min_deployer_approvals
            && self.audit_quorum_for_package(package_id) >= self.config.min_audit_attestations
            && self.policy_allows_package(package_id)
    }

    pub fn roots(&self) -> ConfidentialContractDeploymentRoots {
        let config_root = self.config.root();
        let package_root = deployment_map_root(
            "PACKAGE-SET",
            self.packages
                .values()
                .map(DeploymentPackage::public_record)
                .collect::<Vec<_>>(),
        );
        let abi_manifest_root = deployment_map_root(
            "ABI-MANIFEST-SET",
            self.abi_manifests
                .values()
                .map(EncryptedAbiManifest::public_record)
                .collect::<Vec<_>>(),
        );
        let bytecode_commitment_root = deployment_map_root(
            "BYTECODE-COMMITMENT-SET",
            self.bytecode_commitments
                .values()
                .map(BytecodeCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        let proving_key_commitment_root = deployment_map_root(
            "PROVING-KEY-COMMITMENT-SET",
            self.proving_key_commitments
                .values()
                .map(ProvingKeyCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        let deployer_approval_root = deployment_map_root(
            "DEPLOYER-APPROVAL-SET",
            self.deployer_approvals
                .values()
                .map(PqDeployerApproval::public_record)
                .collect::<Vec<_>>(),
        );
        let audit_attestation_root = deployment_map_root(
            "AUDIT-ATTESTATION-SET",
            self.audit_attestations
                .values()
                .map(AuditAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let upgrade_timelock_root = deployment_map_root(
            "UPGRADE-TIMELOCK-SET",
            self.upgrade_timelocks
                .values()
                .map(UpgradeTimelock::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsorship_root = deployment_map_root(
            "SPONSORSHIP-SET",
            self.sponsorships
                .values()
                .map(LowFeeDeploymentSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        let constructor_witness_root = deployment_map_root(
            "CONSTRUCTOR-WITNESS-SET",
            self.constructor_witnesses
                .values()
                .map(ConstructorWitnessEnvelope::public_record)
                .collect::<Vec<_>>(),
        );
        let policy_check_root = deployment_map_root(
            "POLICY-CHECK-SET",
            self.policy_checks
                .values()
                .map(DeploymentPolicyCheck::public_record)
                .collect::<Vec<_>>(),
        );
        let rollout_batch_root = deployment_map_root(
            "ROLLOUT-BATCH-SET",
            self.rollout_batches
                .values()
                .map(RolloutBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let public_record_root = deployment_map_root(
            "PUBLIC-RECORD-SET",
            self.public_records
                .values()
                .map(DeploymentPublicRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let state_payload = json!({
            "kind": "confidential_contract_deployment_state_root_payload",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": config_root,
            "package_root": package_root,
            "abi_manifest_root": abi_manifest_root,
            "bytecode_commitment_root": bytecode_commitment_root,
            "proving_key_commitment_root": proving_key_commitment_root,
            "deployer_approval_root": deployer_approval_root,
            "audit_attestation_root": audit_attestation_root,
            "upgrade_timelock_root": upgrade_timelock_root,
            "sponsorship_root": sponsorship_root,
            "constructor_witness_root": constructor_witness_root,
            "policy_check_root": policy_check_root,
            "rollout_batch_root": rollout_batch_root,
            "public_record_root": public_record_root,
            "counters": self.counters().public_record(),
        });
        let state_root = deployment_payload_root("STATE", &state_payload);
        ConfidentialContractDeploymentRoots {
            config_root,
            package_root,
            abi_manifest_root,
            bytecode_commitment_root,
            proving_key_commitment_root,
            deployer_approval_root,
            audit_attestation_root,
            upgrade_timelock_root,
            sponsorship_root,
            constructor_witness_root,
            policy_check_root,
            rollout_batch_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> ConfidentialContractDeploymentCounters {
        ConfidentialContractDeploymentCounters {
            packages: self.packages.len(),
            live_packages: self
                .packages
                .values()
                .filter(|package| package.status.is_live())
                .count(),
            abi_manifests: self.abi_manifests.len(),
            bytecode_commitments: self.bytecode_commitments.len(),
            proving_key_commitments: self.proving_key_commitments.len(),
            approvals: self.deployer_approvals.len(),
            active_approvals: self
                .deployer_approvals
                .values()
                .filter(|approval| approval.is_active_at(self.height))
                .count(),
            audit_attestations: self.audit_attestations.len(),
            active_audit_attestations: self
                .audit_attestations
                .values()
                .filter(|attestation| attestation.is_active_at(self.height))
                .count(),
            upgrade_timelocks: self.upgrade_timelocks.len(),
            open_upgrade_timelocks: self
                .upgrade_timelocks
                .values()
                .filter(|timelock| timelock.status.is_open())
                .count(),
            sponsorships: self.sponsorships.len(),
            active_sponsorships: self
                .sponsorships
                .values()
                .filter(|sponsorship| sponsorship.can_cover(1, self.height))
                .count(),
            constructor_witnesses: self.constructor_witnesses.len(),
            active_constructor_witnesses: self
                .constructor_witnesses
                .values()
                .filter(|witness| witness.is_active_at(self.height))
                .count(),
            policy_checks: self.policy_checks.len(),
            passing_policy_checks: self
                .policy_checks
                .values()
                .filter(|check| check.is_active_at(self.height))
                .count(),
            rollout_batches: self.rollout_batches.len(),
            open_rollout_batches: self
                .rollout_batches
                .values()
                .filter(|batch| batch.status.is_open())
                .count(),
            public_records: self.public_records.len(),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "confidential_contract_deployment_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "packages": self.packages.values().map(DeploymentPackage::public_record).collect::<Vec<_>>(),
            "abi_manifests": self.abi_manifests.values().map(EncryptedAbiManifest::public_record).collect::<Vec<_>>(),
            "bytecode_commitments": self.bytecode_commitments.values().map(BytecodeCommitment::public_record).collect::<Vec<_>>(),
            "proving_key_commitments": self.proving_key_commitments.values().map(ProvingKeyCommitment::public_record).collect::<Vec<_>>(),
            "deployer_approvals": self.deployer_approvals.values().map(PqDeployerApproval::public_record).collect::<Vec<_>>(),
            "audit_attestations": self.audit_attestations.values().map(AuditAttestation::public_record).collect::<Vec<_>>(),
            "upgrade_timelocks": self.upgrade_timelocks.values().map(UpgradeTimelock::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeDeploymentSponsorship::public_record).collect::<Vec<_>>(),
            "constructor_witnesses": self.constructor_witnesses.values().map(ConstructorWitnessEnvelope::public_record).collect::<Vec<_>>(),
            "policy_checks": self.policy_checks.values().map(DeploymentPolicyCheck::public_record).collect::<Vec<_>>(),
            "rollout_batches": self.rollout_batches.values().map(RolloutBatch::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(DeploymentPublicRecord::public_record).collect::<Vec<_>>(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> ConfidentialContractDeploymentPipelineResult<String> {
        self.config.validate()?;
        self.roots().validate()?;
        self.validate_counts()?;
        self.validate_packages()?;
        self.validate_abi_manifests()?;
        self.validate_bytecode_commitments()?;
        self.validate_proving_key_commitments()?;
        self.validate_deployer_approvals()?;
        self.validate_audit_attestations()?;
        self.validate_upgrade_timelocks()?;
        self.validate_sponsorships()?;
        self.validate_constructor_witnesses()?;
        self.validate_policy_checks()?;
        self.validate_rollout_batches()?;
        self.validate_public_records()?;
        Ok(self.state_root())
    }

    fn validate_counts(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        if self.packages.len() > self.config.max_packages {
            return Err("deployment package count exceeds configured maximum".to_string());
        }
        if self.abi_manifests.len() > self.config.max_abi_manifests {
            return Err("abi manifest count exceeds configured maximum".to_string());
        }
        if self.bytecode_commitments.len() > self.config.max_bytecode_commitments {
            return Err("bytecode commitment count exceeds configured maximum".to_string());
        }
        if self.proving_key_commitments.len() > self.config.max_proving_key_commitments {
            return Err("proving key commitment count exceeds configured maximum".to_string());
        }
        if self.deployer_approvals.len() > self.config.max_approvals {
            return Err("deployer approval count exceeds configured maximum".to_string());
        }
        if self.audit_attestations.len() > self.config.max_attestations {
            return Err("audit attestation count exceeds configured maximum".to_string());
        }
        if self.upgrade_timelocks.len() > self.config.max_timelocks {
            return Err("upgrade timelock count exceeds configured maximum".to_string());
        }
        if self.sponsorships.len() > self.config.max_sponsorships {
            return Err("sponsorship count exceeds configured maximum".to_string());
        }
        if self.constructor_witnesses.len() > self.config.max_witnesses {
            return Err("constructor witness count exceeds configured maximum".to_string());
        }
        if self.policy_checks.len() > self.config.max_policy_checks {
            return Err("policy check count exceeds configured maximum".to_string());
        }
        if self.rollout_batches.len() > self.config.max_rollout_batches {
            return Err("rollout batch count exceeds configured maximum".to_string());
        }
        if self.public_records.len() > self.config.max_public_records {
            return Err("public record count exceeds configured maximum".to_string());
        }
        Ok(())
    }

    fn validate_packages(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        let mut namespaces = BTreeSet::<String>::new();
        for (id, package) in &self.packages {
            if id != &package.package_id {
                return Err("package map key mismatch".to_string());
            }
            package.validate()?;
            let namespace_key = format!("{}:{}", package.namespace, package.contract_label);
            if !namespaces.insert(namespace_key) {
                return Err("duplicate deployment namespace and contract label".to_string());
            }
            if !self.abi_manifests.contains_key(&package.abi_manifest_id) {
                return Err("package references missing abi manifest".to_string());
            }
            if !self
                .bytecode_commitments
                .contains_key(&package.bytecode_commitment_id)
            {
                return Err("package references missing bytecode commitment".to_string());
            }
            if !self
                .constructor_witnesses
                .contains_key(&package.constructor_witness_id)
            {
                return Err("package references missing constructor witness".to_string());
            }
            if package.status.is_live()
                && self.approval_quorum_for_package(&package.package_id)
                    < self.config.min_deployer_approvals
            {
                return Err("live package does not have deployer approval quorum".to_string());
            }
            if package.status.is_live()
                && self.audit_quorum_for_package(&package.package_id)
                    < self.config.min_audit_attestations
            {
                return Err("live package does not have audit attestation quorum".to_string());
            }
        }
        Ok(())
    }

    fn validate_abi_manifests(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, manifest) in &self.abi_manifests {
            if id != &manifest.manifest_id {
                return Err("abi manifest map key mismatch".to_string());
            }
            manifest.validate()?;
        }
        Ok(())
    }

    fn validate_bytecode_commitments(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, commitment) in &self.bytecode_commitments {
            if id != &commitment.commitment_id {
                return Err("bytecode commitment map key mismatch".to_string());
            }
            commitment.validate(self.config.max_bytecode_bytes)?;
        }
        Ok(())
    }

    fn validate_proving_key_commitments(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, commitment) in &self.proving_key_commitments {
            if id != &commitment.proving_key_id {
                return Err("proving key commitment map key mismatch".to_string());
            }
            commitment.validate(self.config.max_proving_key_bytes)?;
        }
        Ok(())
    }

    fn validate_deployer_approvals(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, approval) in &self.deployer_approvals {
            if id != &approval.approval_id {
                return Err("deployer approval map key mismatch".to_string());
            }
            approval.validate()?;
            if !self.packages.contains_key(&approval.package_id) {
                return Err("approval references missing package".to_string());
            }
        }
        Ok(())
    }

    fn validate_audit_attestations(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, attestation) in &self.audit_attestations {
            if id != &attestation.attestation_id {
                return Err("audit attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            if !self.packages.contains_key(&attestation.package_id) {
                return Err("attestation references missing package".to_string());
            }
            if attestation.score_bps < self.config.min_audit_score_bps
                && attestation.status.counts_for_policy()
            {
                return Err("accepted attestation score is below configured minimum".to_string());
            }
            if attestation.disclosure_bps > self.config.max_disclosure_bps
                && attestation.status.counts_for_policy()
            {
                return Err(
                    "accepted attestation disclosure exceeds configured maximum".to_string()
                );
            }
        }
        Ok(())
    }

    fn validate_upgrade_timelocks(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, timelock) in &self.upgrade_timelocks {
            if id != &timelock.timelock_id {
                return Err("upgrade timelock map key mismatch".to_string());
            }
            timelock.validate()?;
            if !self.packages.contains_key(&timelock.package_id) {
                return Err("timelock references missing package".to_string());
            }
        }
        Ok(())
    }

    fn validate_sponsorships(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, sponsorship) in &self.sponsorships {
            if id != &sponsorship.sponsor_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
            if !self.packages.contains_key(&sponsorship.package_id) {
                return Err("sponsorship references missing package".to_string());
            }
            if sponsorship.max_fee_units > self.config.max_sponsored_fee_units {
                return Err("sponsorship max fee exceeds configured maximum".to_string());
            }
        }
        Ok(())
    }

    fn validate_constructor_witnesses(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, witness) in &self.constructor_witnesses {
            if id != &witness.witness_id {
                return Err("constructor witness map key mismatch".to_string());
            }
            witness.validate(self.config.max_constructor_bytes)?;
        }
        Ok(())
    }

    fn validate_policy_checks(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, check) in &self.policy_checks {
            if id != &check.check_id {
                return Err("policy check map key mismatch".to_string());
            }
            check.validate()?;
            if !self.packages.contains_key(&check.package_id) {
                return Err("policy check references missing package".to_string());
            }
        }
        Ok(())
    }

    fn validate_rollout_batches(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, batch) in &self.rollout_batches {
            if id != &batch.batch_id {
                return Err("rollout batch map key mismatch".to_string());
            }
            batch.validate(self.config.max_batch_size)?;
            for package_id in &batch.package_ids {
                if !self.packages.contains_key(package_id) {
                    return Err("rollout batch references missing package".to_string());
                }
            }
        }
        Ok(())
    }

    fn validate_public_records(&self) -> ConfidentialContractDeploymentPipelineResult<()> {
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("public record map key mismatch".to_string());
            }
            record.validate()?;
        }
        Ok(())
    }
}

pub fn deployment_package_id(
    namespace: &str,
    contract_label: &str,
    contract_kind: DeploymentContractKind,
    deployer_commitment: &str,
    salt_commitment: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-PACKAGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace.trim()),
            HashPart::Str(contract_label.trim()),
            HashPart::Str(contract_kind.as_str()),
            HashPart::Str(deployer_commitment.trim()),
            HashPart::Str(salt_commitment.trim()),
        ],
        32,
    )
}

pub fn encrypted_abi_manifest_id(
    package_id: &str,
    manifest_ciphertext_root: &str,
    selector_root: &str,
    recipient_key_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-ABI-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(manifest_ciphertext_root),
            HashPart::Str(selector_root),
            HashPart::Str(recipient_key_root),
        ],
        32,
    )
}

pub fn bytecode_commitment_id(
    package_id: &str,
    bytecode_root: &str,
    vm_profile: &str,
    reproducible_build_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-BYTECODE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(bytecode_root),
            HashPart::Str(vm_profile),
            HashPart::Str(reproducible_build_root),
        ],
        32,
    )
}

pub fn proving_key_commitment_id(
    package_id: &str,
    circuit_id: &str,
    proof_system: &str,
    proving_key_root: &str,
    verifier_key_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-PROVING-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(circuit_id),
            HashPart::Str(proof_system),
            HashPart::Str(proving_key_root),
            HashPart::Str(verifier_key_root),
        ],
        32,
    )
}

pub fn pq_deployer_approval_id(
    package_id: &str,
    deployer_commitment: &str,
    approval_authority_root: &str,
    signature_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-PQ-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(deployer_commitment),
            HashPart::Str(approval_authority_root),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

pub fn audit_attestation_id(
    package_id: &str,
    auditor_commitment: &str,
    scope: AuditScope,
    findings_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-AUDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(auditor_commitment),
            HashPart::Str(scope.as_str()),
            HashPart::Str(findings_root),
        ],
        32,
    )
}

pub fn upgrade_timelock_id(
    package_id: &str,
    current_commitment_root: &str,
    proposed_commitment_root: &str,
    queued_at_height: u64,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-UPGRADE-TIMELOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(current_commitment_root),
            HashPart::Str(proposed_commitment_root),
            HashPart::Int(queued_at_height as i128),
        ],
        32,
    )
}

pub fn low_fee_sponsorship_id(
    package_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    created_at_height: u64,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn constructor_witness_id(
    package_id: &str,
    constructor_selector_root: &str,
    encrypted_args_root: &str,
    nullifier_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-CONSTRUCTOR-WITNESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(constructor_selector_root),
            HashPart::Str(encrypted_args_root),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn policy_check_id(
    package_id: &str,
    check_kind: PolicyCheckKind,
    observed_root: &str,
    evaluator_commitment: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-POLICY-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(package_id),
            HashPart::Str(check_kind.as_str()),
            HashPart::Str(observed_root),
            HashPart::Str(evaluator_commitment),
        ],
        32,
    )
}

pub fn rollout_batch_id(namespace: &str, package_root: &str, collect_start_height: u64) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-ROLLOUT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace),
            HashPart::Str(package_root),
            HashPart::Int(collect_start_height as i128),
        ],
        32,
    )
}

pub fn public_record_id(
    object_kind: &str,
    object_id: &str,
    height: u64,
    payload_root: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Int(height as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn deployment_address_commitment(
    namespace: &str,
    contract_label: &str,
    deployer_commitment: &str,
    salt_commitment: &str,
) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-ADDRESS-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace),
            HashPart::Str(contract_label),
            HashPart::Str(deployer_commitment),
            HashPart::Str(salt_commitment),
        ],
        32,
    )
}

pub fn deployment_blob_root(domain: &str, bytes: &[u8]) -> String {
    stable_hash_hex(
        &format!("CONFIDENTIAL-CONTRACT-DEPLOYMENT-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Bytes(bytes)],
        32,
    )
}

pub fn deployment_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(
        &format!("CONFIDENTIAL-CONTRACT-DEPLOYMENT-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn deployment_string_root(domain: &str, value: &str) -> String {
    stable_hash_hex(
        &format!("CONFIDENTIAL-CONTRACT-DEPLOYMENT-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value.trim())],
        32,
    )
}

pub fn deployment_optional_id(label: &str, value: &str) -> String {
    stable_hash_hex(
        "CONFIDENTIAL-CONTRACT-DEPLOYMENT-OPTIONAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label.trim()),
            HashPart::Str(value.trim()),
        ],
        16,
    )
}

pub fn deployment_string_set_root(domain: &str, values: &[String]) -> String {
    let mut normalized = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    let leaves = normalized
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    deployment_map_root(domain, leaves)
}

pub fn deployment_map_root(domain: &str, records: Vec<Value>) -> String {
    if records.is_empty() {
        return stable_hash_hex(
            &format!("CONFIDENTIAL-CONTRACT-DEPLOYMENT-{domain}-EMPTY"),
            &[HashPart::Str(CHAIN_ID)],
            32,
        );
    }
    merkle_root(
        &format!("CONFIDENTIAL-CONTRACT-DEPLOYMENT-{domain}"),
        &records,
    )
}

fn ensure_non_empty(label: &str, value: &str) -> ConfidentialContractDeploymentPipelineResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be set"));
    }
    Ok(())
}

fn ensure_eq(
    label: &str,
    actual: &str,
    reference: &str,
) -> ConfidentialContractDeploymentPipelineResult<()> {
    if actual != reference {
        return Err(format!("{label} is not supported"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> ConfidentialContractDeploymentPipelineResult<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> ConfidentialContractDeploymentPipelineResult<()> {
    if value > CONFIDENTIAL_CONTRACT_DEPLOYMENT_PIPELINE_MAX_BPS {
        return Err(format!("{label} exceeds basis point maximum"));
    }
    Ok(())
}
