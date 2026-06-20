use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ContractVerificationRegistryResult<T> = Result<T, String>;
pub type ContractVerificationResult<T> = ContractVerificationRegistryResult<T>;

pub const CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION: &str =
    "nebula-contract-verification-registry-v1";
pub const CONTRACT_VERIFICATION_REGISTRY_SCHEMA_VERSION: u64 = 1;
pub const CONTRACT_VERIFICATION_ABI_COMMITMENT_SCHEME: &str = "shake256-canonical-json-abi-v1";
pub const CONTRACT_VERIFICATION_BYTECODE_COMMITMENT_SCHEME: &str = "shake256-bytecode-blob-v1";
pub const CONTRACT_VERIFICATION_PROOF_MANIFEST_SCHEME: &str =
    "nebula-private-contract-proof-manifest-v1";
pub const CONTRACT_VERIFICATION_UPGRADE_AUTHORIZATION_SCHEME: &str =
    "pq-governance-upgrade-authorization-v1";
pub const CONTRACT_VERIFICATION_PQ_AUDITOR_ATTESTATION_SCHEME: &str =
    "ml-dsa-65+slh-dsa-shake-auditor-attestation-v1";
pub const CONTRACT_VERIFICATION_PRIVACY_BUDGET_POLICY_SCHEME: &str =
    "bounded-private-contract-budget-v1";
pub const CONTRACT_VERIFICATION_DEPLOYMENT_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-contract-deployment-sponsor-v1";
pub const CONTRACT_VERIFICATION_VERIFIER_KEY_PINNING_SCHEME: &str = "verifier-key-pin-shake256-v1";
pub const CONTRACT_VERIFICATION_REPRODUCIBLE_BUILD_SCHEME: &str =
    "reproducible-build-attested-output-v1";
pub const CONTRACT_VERIFICATION_EMERGENCY_DEPRECATION_SCHEME: &str =
    "emergency-contract-deprecation-v1";
pub const CONTRACT_VERIFICATION_DEFI_ALLOWLIST_GATE_SCHEME: &str =
    "defi-protocol-allowlist-gate-v1";
pub const CONTRACT_VERIFICATION_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const CONTRACT_VERIFICATION_DEFAULT_LOW_FEE_LANE: &str = "private-contract-deployments";
pub const CONTRACT_VERIFICATION_DEFAULT_UPGRADE_TIMELOCK_BLOCKS: u64 = 96;
pub const CONTRACT_VERIFICATION_DEFAULT_UPGRADE_EXPIRY_BLOCKS: u64 = 7_200;
pub const CONTRACT_VERIFICATION_DEFAULT_AUDITOR_ATTESTATION_TTL_BLOCKS: u64 = 20_160;
pub const CONTRACT_VERIFICATION_DEFAULT_PRIVACY_EPOCH_BLOCKS: u64 = 720;
pub const CONTRACT_VERIFICATION_DEFAULT_PRIVACY_AUDIT_WINDOW_BLOCKS: u64 = 120;
pub const CONTRACT_VERIFICATION_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 1_440;
pub const CONTRACT_VERIFICATION_DEFAULT_MIN_ACTIVE_ATTESTATIONS: u64 = 1;
pub const CONTRACT_VERIFICATION_DEFAULT_MIN_AUDIT_SCORE_BPS: u64 = 8_500;
pub const CONTRACT_VERIFICATION_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_000;
pub const CONTRACT_VERIFICATION_DEFAULT_BUILD_REPRODUCTION_QUORUM: u64 = 2;
pub const CONTRACT_VERIFICATION_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedContractKind {
    PrivateToken,
    PrivateAmm,
    PrivateLending,
    PrivatePerps,
    PrivateOptions,
    PrivateStablecoin,
    PrivateOracle,
    PrivatePaymaster,
    BridgeAdapter,
    Governance,
    Custom,
}

impl VerifiedContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateToken => "private_token",
            Self::PrivateAmm => "private_amm",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::PrivateOptions => "private_options",
            Self::PrivateStablecoin => "private_stablecoin",
            Self::PrivateOracle => "private_oracle",
            Self::PrivatePaymaster => "private_paymaster",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractVerificationStatus {
    Draft,
    PendingReview,
    Verified,
    Suspended,
    Deprecated,
    Revoked,
    EmergencyDisabled,
}

impl ContractVerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PendingReview => "pending_review",
            Self::Verified => "verified",
            Self::Suspended => "suspended",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
            Self::EmergencyDisabled => "emergency_disabled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::PendingReview | Self::Verified)
    }

    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::EmergencyDisabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofManifestKind {
    Deployment,
    Upgrade,
    RuntimeExecution,
    StateTransition,
    AbiCompatibility,
    DefiInvariant,
    EmergencyPatch,
}

impl ProofManifestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Upgrade => "upgrade",
            Self::RuntimeExecution => "runtime_execution",
            Self::StateTransition => "state_transition",
            Self::AbiCompatibility => "abi_compatibility",
            Self::DefiInvariant => "defi_invariant",
            Self::EmergencyPatch => "emergency_patch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Draft,
    Pinned,
    Verified,
    Superseded,
    Revoked,
}

impl ManifestStatus {
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
pub enum UpgradeAuthorizationStatus {
    Proposed,
    Timelocked,
    Authorized,
    Executed,
    Rejected,
    Expired,
}

impl UpgradeAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Timelocked => "timelocked",
            Self::Authorized => "authorized",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_execute(self) -> bool {
        matches!(self, Self::Authorized)
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Proposed | Self::Timelocked | Self::Authorized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditorScope {
    Abi,
    Bytecode,
    ProofCircuit,
    VerifierKey,
    PrivacyBudget,
    DefiRisk,
    Upgrade,
    ReproducibleBuild,
}

impl AuditorScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abi => "abi",
            Self::Bytecode => "bytecode",
            Self::ProofCircuit => "proof_circuit",
            Self::VerifierKey => "verifier_key",
            Self::PrivacyBudget => "privacy_budget",
            Self::DefiRisk => "defi_risk",
            Self::Upgrade => "upgrade",
            Self::ReproducibleBuild => "reproducible_build",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditorAttestationStatus {
    Pending,
    Accepted,
    Disputed,
    Revoked,
    Expired,
}

impl AuditorAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_verification(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetMode {
    Disabled,
    Bounded,
    AggregateOnly,
    AuditorEnforced,
    StrictZeroKnowledge,
    EmergencyDisclosure,
}

impl PrivacyBudgetMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Bounded => "bounded",
            Self::AggregateOnly => "aggregate_only",
            Self::AuditorEnforced => "auditor_enforced",
            Self::StrictZeroKnowledge => "strict_zero_knowledge",
            Self::EmergencyDisclosure => "emergency_disclosure",
        }
    }

    pub fn requires_auditor(self) -> bool {
        matches!(self, Self::AuditorEnforced | Self::EmergencyDisclosure)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyPolicyStatus {
    Active,
    Paused,
    Expired,
    Revoked,
}

impl PrivacyPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentSponsorStatus {
    Reserved,
    Active,
    Exhausted,
    Paused,
    Expired,
    Revoked,
}

impl DeploymentSponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Reserved | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Candidate,
    Pinned,
    Rotating,
    Deprecated,
    Revoked,
    Expired,
}

impl VerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Pinned => "pinned",
            Self::Rotating => "rotating",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn is_pinned(self) -> bool {
        matches!(self, Self::Pinned | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildReproducibilityStatus {
    Unchecked,
    Reproducible,
    QuorumReproduced,
    Divergent,
    Revoked,
}

impl BuildReproducibilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unchecked => "unchecked",
            Self::Reproducible => "reproducible",
            Self::QuorumReproduced => "quorum_reproduced",
            Self::Divergent => "divergent",
            Self::Revoked => "revoked",
        }
    }

    pub fn verifies(self) -> bool {
        matches!(self, Self::Reproducible | Self::QuorumReproduced)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeprecationScope {
    Contract,
    Abi,
    BytecodeManifest,
    VerifierKey,
    PrivacyPolicy,
    DefiGate,
}

impl DeprecationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Abi => "abi",
            Self::BytecodeManifest => "bytecode_manifest",
            Self::VerifierKey => "verifier_key",
            Self::PrivacyPolicy => "privacy_policy",
            Self::DefiGate => "defi_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeprecationSeverity {
    Advisory,
    High,
    Critical,
    Emergency,
}

impl DeprecationSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    pub fn halts_contract(self) -> bool {
        matches!(self, Self::Critical | Self::Emergency)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeprecationStatus {
    Proposed,
    Active,
    Mitigated,
    Retired,
}

impl DeprecationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Mitigated => "mitigated",
            Self::Retired => "retired",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiProtocolKind {
    Amm,
    Lending,
    Perps,
    Options,
    Stablecoin,
    Oracle,
    Bridge,
    Vault,
}

impl DefiProtocolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Options => "options",
            Self::Stablecoin => "stablecoin",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Vault => "vault",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiGateStatus {
    Shadow,
    Allowlisted,
    Paused,
    Blocked,
    Retired,
}

impl DefiGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Allowlisted => "allowlisted",
            Self::Paused => "paused",
            Self::Blocked => "blocked",
            Self::Retired => "retired",
        }
    }

    pub fn allows(self) -> bool {
        matches!(self, Self::Allowlisted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerificationRegistryConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub abi_commitment_scheme: String,
    pub bytecode_commitment_scheme: String,
    pub proof_manifest_scheme: String,
    pub upgrade_authorization_scheme: String,
    pub pq_auditor_attestation_scheme: String,
    pub privacy_budget_policy_scheme: String,
    pub deployment_sponsorship_scheme: String,
    pub verifier_key_pinning_scheme: String,
    pub reproducible_build_scheme: String,
    pub emergency_deprecation_scheme: String,
    pub defi_allowlist_gate_scheme: String,
    pub default_fee_asset_id: String,
    pub default_low_fee_lane: String,
    pub default_upgrade_timelock_blocks: u64,
    pub default_upgrade_expiry_blocks: u64,
    pub default_auditor_attestation_ttl_blocks: u64,
    pub default_privacy_epoch_blocks: u64,
    pub default_privacy_audit_window_blocks: u64,
    pub default_sponsor_ttl_blocks: u64,
    pub min_active_auditor_attestations: u64,
    pub min_audit_score_bps: u64,
    pub max_privacy_disclosure_bps: u64,
    pub build_reproduction_quorum: u64,
}

impl Default for ContractVerificationRegistryConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl ContractVerificationRegistryConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION.to_string(),
            schema_version: CONTRACT_VERIFICATION_REGISTRY_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            abi_commitment_scheme: CONTRACT_VERIFICATION_ABI_COMMITMENT_SCHEME.to_string(),
            bytecode_commitment_scheme: CONTRACT_VERIFICATION_BYTECODE_COMMITMENT_SCHEME
                .to_string(),
            proof_manifest_scheme: CONTRACT_VERIFICATION_PROOF_MANIFEST_SCHEME.to_string(),
            upgrade_authorization_scheme: CONTRACT_VERIFICATION_UPGRADE_AUTHORIZATION_SCHEME
                .to_string(),
            pq_auditor_attestation_scheme: CONTRACT_VERIFICATION_PQ_AUDITOR_ATTESTATION_SCHEME
                .to_string(),
            privacy_budget_policy_scheme: CONTRACT_VERIFICATION_PRIVACY_BUDGET_POLICY_SCHEME
                .to_string(),
            deployment_sponsorship_scheme: CONTRACT_VERIFICATION_DEPLOYMENT_SPONSORSHIP_SCHEME
                .to_string(),
            verifier_key_pinning_scheme: CONTRACT_VERIFICATION_VERIFIER_KEY_PINNING_SCHEME
                .to_string(),
            reproducible_build_scheme: CONTRACT_VERIFICATION_REPRODUCIBLE_BUILD_SCHEME.to_string(),
            emergency_deprecation_scheme: CONTRACT_VERIFICATION_EMERGENCY_DEPRECATION_SCHEME
                .to_string(),
            defi_allowlist_gate_scheme: CONTRACT_VERIFICATION_DEFI_ALLOWLIST_GATE_SCHEME
                .to_string(),
            default_fee_asset_id: CONTRACT_VERIFICATION_DEFAULT_FEE_ASSET_ID.to_string(),
            default_low_fee_lane: CONTRACT_VERIFICATION_DEFAULT_LOW_FEE_LANE.to_string(),
            default_upgrade_timelock_blocks: CONTRACT_VERIFICATION_DEFAULT_UPGRADE_TIMELOCK_BLOCKS,
            default_upgrade_expiry_blocks: CONTRACT_VERIFICATION_DEFAULT_UPGRADE_EXPIRY_BLOCKS,
            default_auditor_attestation_ttl_blocks:
                CONTRACT_VERIFICATION_DEFAULT_AUDITOR_ATTESTATION_TTL_BLOCKS,
            default_privacy_epoch_blocks: CONTRACT_VERIFICATION_DEFAULT_PRIVACY_EPOCH_BLOCKS,
            default_privacy_audit_window_blocks:
                CONTRACT_VERIFICATION_DEFAULT_PRIVACY_AUDIT_WINDOW_BLOCKS,
            default_sponsor_ttl_blocks: CONTRACT_VERIFICATION_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_active_auditor_attestations: CONTRACT_VERIFICATION_DEFAULT_MIN_ACTIVE_ATTESTATIONS,
            min_audit_score_bps: CONTRACT_VERIFICATION_DEFAULT_MIN_AUDIT_SCORE_BPS,
            max_privacy_disclosure_bps: CONTRACT_VERIFICATION_DEFAULT_MAX_DISCLOSURE_BPS,
            build_reproduction_quorum: CONTRACT_VERIFICATION_DEFAULT_BUILD_REPRODUCTION_QUORUM,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_verification_registry_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "abi_commitment_scheme": self.abi_commitment_scheme,
            "bytecode_commitment_scheme": self.bytecode_commitment_scheme,
            "proof_manifest_scheme": self.proof_manifest_scheme,
            "upgrade_authorization_scheme": self.upgrade_authorization_scheme,
            "pq_auditor_attestation_scheme": self.pq_auditor_attestation_scheme,
            "privacy_budget_policy_scheme": self.privacy_budget_policy_scheme,
            "deployment_sponsorship_scheme": self.deployment_sponsorship_scheme,
            "verifier_key_pinning_scheme": self.verifier_key_pinning_scheme,
            "reproducible_build_scheme": self.reproducible_build_scheme,
            "emergency_deprecation_scheme": self.emergency_deprecation_scheme,
            "defi_allowlist_gate_scheme": self.defi_allowlist_gate_scheme,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_low_fee_lane": self.default_low_fee_lane,
            "default_upgrade_timelock_blocks": self.default_upgrade_timelock_blocks,
            "default_upgrade_expiry_blocks": self.default_upgrade_expiry_blocks,
            "default_auditor_attestation_ttl_blocks": self.default_auditor_attestation_ttl_blocks,
            "default_privacy_epoch_blocks": self.default_privacy_epoch_blocks,
            "default_privacy_audit_window_blocks": self.default_privacy_audit_window_blocks,
            "default_sponsor_ttl_blocks": self.default_sponsor_ttl_blocks,
            "min_active_auditor_attestations": self.min_active_auditor_attestations,
            "min_audit_score_bps": self.min_audit_score_bps,
            "max_privacy_disclosure_bps": self.max_privacy_disclosure_bps,
            "build_reproduction_quorum": self.build_reproduction_quorum,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root("CONTRACT-VERIFICATION-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("protocol version", &self.protocol_version)?;
        ensure_non_empty("chain id", &self.chain_id)?;
        ensure_non_empty("abi commitment scheme", &self.abi_commitment_scheme)?;
        ensure_non_empty(
            "bytecode commitment scheme",
            &self.bytecode_commitment_scheme,
        )?;
        ensure_non_empty("proof manifest scheme", &self.proof_manifest_scheme)?;
        ensure_non_empty(
            "upgrade authorization scheme",
            &self.upgrade_authorization_scheme,
        )?;
        ensure_non_empty(
            "pq auditor attestation scheme",
            &self.pq_auditor_attestation_scheme,
        )?;
        ensure_non_empty(
            "privacy budget policy scheme",
            &self.privacy_budget_policy_scheme,
        )?;
        ensure_non_empty(
            "deployment sponsorship scheme",
            &self.deployment_sponsorship_scheme,
        )?;
        ensure_non_empty(
            "verifier key pinning scheme",
            &self.verifier_key_pinning_scheme,
        )?;
        ensure_non_empty("reproducible build scheme", &self.reproducible_build_scheme)?;
        ensure_non_empty(
            "emergency deprecation scheme",
            &self.emergency_deprecation_scheme,
        )?;
        ensure_non_empty(
            "defi allowlist gate scheme",
            &self.defi_allowlist_gate_scheme,
        )?;
        ensure_non_empty("default fee asset id", &self.default_fee_asset_id)?;
        ensure_non_empty("default low fee lane", &self.default_low_fee_lane)?;
        ensure_positive(self.schema_version, "schema version")?;
        ensure_positive(
            self.default_upgrade_timelock_blocks,
            "default upgrade timelock",
        )?;
        ensure_positive(self.default_upgrade_expiry_blocks, "default upgrade expiry")?;
        ensure_positive(
            self.default_auditor_attestation_ttl_blocks,
            "default auditor attestation ttl",
        )?;
        ensure_positive(self.default_privacy_epoch_blocks, "default privacy epoch")?;
        ensure_positive(
            self.default_privacy_audit_window_blocks,
            "default privacy audit window",
        )?;
        ensure_positive(self.default_sponsor_ttl_blocks, "default sponsor ttl")?;
        ensure_positive(
            self.min_active_auditor_attestations,
            "minimum active auditor attestations",
        )?;
        ensure_positive(self.build_reproduction_quorum, "build reproduction quorum")?;
        ensure_bps("minimum audit score bps", self.min_audit_score_bps)?;
        ensure_bps(
            "maximum privacy disclosure bps",
            self.max_privacy_disclosure_bps,
        )?;
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiCommitment {
    pub abi_id: String,
    pub contract_id: String,
    pub abi_schema_root: String,
    pub interface_root: String,
    pub selector_root: String,
    pub event_root: String,
    pub error_root: String,
    pub selectors: Vec<String>,
    pub events: Vec<String>,
    pub errors: Vec<String>,
    pub entrypoint_count: u64,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub version: u64,
}

impl AbiCommitment {
    pub fn new(
        contract_id: impl Into<String>,
        abi_schema: &Value,
        selectors: Vec<String>,
        events: Vec<String>,
        errors: Vec<String>,
        interface_metadata: &Value,
        created_at_height: u64,
        version: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        ensure_non_empty("abi contract id", &contract_id)?;
        ensure_positive(version, "abi version")?;
        let selectors = normalize_unique_strings(selectors);
        let events = normalize_unique_strings(events);
        let errors = normalize_unique_strings(errors);
        let abi_schema_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-ABI-SCHEMA", abi_schema);
        let interface_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-ABI-INTERFACE",
            interface_metadata,
        );
        let selector_root =
            contract_verification_string_set_root("CONTRACT-VERIFICATION-ABI-SELECTOR", &selectors);
        let event_root =
            contract_verification_string_set_root("CONTRACT-VERIFICATION-ABI-EVENT", &events);
        let error_root =
            contract_verification_string_set_root("CONTRACT-VERIFICATION-ABI-ERROR", &errors);
        let metadata_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-ABI-METADATA",
            interface_metadata,
        );
        let identity = abi_commitment_identity_record(
            &contract_id,
            &abi_schema_root,
            &interface_root,
            &selector_root,
            &event_root,
            &error_root,
            selectors.len() as u64,
            &metadata_root,
            created_at_height,
            version,
        );
        let abi_id = abi_commitment_id(&identity);
        let commitment = Self {
            abi_id,
            contract_id,
            abi_schema_root,
            interface_root,
            selector_root,
            event_root,
            error_root,
            entrypoint_count: selectors.len() as u64,
            selectors,
            events,
            errors,
            metadata_root,
            created_at_height,
            version,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn identity_record(&self) -> Value {
        abi_commitment_identity_record(
            &self.contract_id,
            &self.abi_schema_root,
            &self.interface_root,
            &self.selector_root,
            &self.event_root,
            &self.error_root,
            self.entrypoint_count,
            &self.metadata_root,
            self.created_at_height,
            self.version,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "abi_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "abi_id": self.abi_id,
            "contract_id": self.contract_id,
            "abi_schema_root": self.abi_schema_root,
            "interface_root": self.interface_root,
            "selector_root": self.selector_root,
            "event_root": self.event_root,
            "error_root": self.error_root,
            "selectors": self.selectors,
            "events": self.events,
            "errors": self.errors,
            "entrypoint_count": self.entrypoint_count,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "version": self.version,
            "commitment_scheme": CONTRACT_VERIFICATION_ABI_COMMITMENT_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root("CONTRACT-VERIFICATION-ABI", &self.public_record())
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("abi id", &self.abi_id)?;
        ensure_non_empty("abi contract id", &self.contract_id)?;
        ensure_non_empty("abi schema root", &self.abi_schema_root)?;
        ensure_non_empty("abi interface root", &self.interface_root)?;
        ensure_non_empty("abi selector root", &self.selector_root)?;
        ensure_non_empty("abi event root", &self.event_root)?;
        ensure_non_empty("abi error root", &self.error_root)?;
        ensure_non_empty("abi metadata root", &self.metadata_root)?;
        ensure_positive(self.version, "abi version")?;
        if self.entrypoint_count != self.selectors.len() as u64 {
            return Err("abi entrypoint count mismatch".to_string());
        }
        if self.selector_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-ABI-SELECTOR",
                &self.selectors,
            )
        {
            return Err("abi selector root mismatch".to_string());
        }
        if self.event_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-ABI-EVENT",
                &self.events,
            )
        {
            return Err("abi event root mismatch".to_string());
        }
        if self.error_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-ABI-ERROR",
                &self.errors,
            )
        {
            return Err("abi error root mismatch".to_string());
        }
        if self.abi_id != abi_commitment_id(&self.identity_record()) {
            return Err("abi id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytecodeProofManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub manifest_kind: ProofManifestKind,
    pub bytecode_root: String,
    pub bytecode_size_bytes: u64,
    pub proof_manifest_root: String,
    pub proof_system: String,
    pub proof_program_hash: String,
    pub verifier_key_root: String,
    pub init_state_root: String,
    pub dependency_root: String,
    pub artifact_root: String,
    pub source_ref_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub version: u64,
    pub status: ManifestStatus,
}

impl BytecodeProofManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        manifest_kind: ProofManifestKind,
        bytecode: &[u8],
        proof_manifest: &Value,
        proof_system: impl Into<String>,
        proof_program_hash: impl Into<String>,
        verifier_key_root: impl Into<String>,
        init_state: &Value,
        dependencies: Vec<String>,
        artifacts: Vec<String>,
        source_ref: &Value,
        metadata: &Value,
        created_at_height: u64,
        version: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let proof_system = proof_system.into();
        let proof_program_hash = proof_program_hash.into();
        let verifier_key_root = verifier_key_root.into();
        ensure_non_empty("manifest contract id", &contract_id)?;
        ensure_non_empty("manifest proof system", &proof_system)?;
        ensure_non_empty("manifest proof program hash", &proof_program_hash)?;
        ensure_non_empty("manifest verifier key root", &verifier_key_root)?;
        ensure_positive(bytecode.len() as u64, "bytecode size")?;
        ensure_positive(version, "manifest version")?;
        let dependencies = normalize_unique_strings(dependencies);
        let artifacts = normalize_unique_strings(artifacts);
        let bytecode_root = contract_verification_bytecode_root(bytecode);
        let proof_manifest_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-PROOF-MANIFEST-PAYLOAD",
            proof_manifest,
        );
        let init_state_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-INIT-STATE", init_state);
        let dependency_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-MANIFEST-DEPENDENCY",
            &dependencies,
        );
        let artifact_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-MANIFEST-ARTIFACT",
            &artifacts,
        );
        let source_ref_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-SOURCE-REF", source_ref);
        let metadata_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-MANIFEST-METADATA", metadata);
        let identity = bytecode_manifest_identity_record(
            &contract_id,
            manifest_kind.as_str(),
            &bytecode_root,
            bytecode.len() as u64,
            &proof_manifest_root,
            &proof_system,
            &proof_program_hash,
            &verifier_key_root,
            &init_state_root,
            &dependency_root,
            &artifact_root,
            &source_ref_root,
            &metadata_root,
            created_at_height,
            version,
        );
        let manifest_id = bytecode_manifest_id(&identity);
        let manifest = Self {
            manifest_id,
            contract_id,
            manifest_kind,
            bytecode_root,
            bytecode_size_bytes: bytecode.len() as u64,
            proof_manifest_root,
            proof_system,
            proof_program_hash,
            verifier_key_root,
            init_state_root,
            dependency_root,
            artifact_root,
            source_ref_root,
            metadata_root,
            created_at_height,
            version,
            status: ManifestStatus::Pinned,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn identity_record(&self) -> Value {
        bytecode_manifest_identity_record(
            &self.contract_id,
            self.manifest_kind.as_str(),
            &self.bytecode_root,
            self.bytecode_size_bytes,
            &self.proof_manifest_root,
            &self.proof_system,
            &self.proof_program_hash,
            &self.verifier_key_root,
            &self.init_state_root,
            &self.dependency_root,
            &self.artifact_root,
            &self.source_ref_root,
            &self.metadata_root,
            self.created_at_height,
            self.version,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bytecode_proof_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "manifest_kind": self.manifest_kind.as_str(),
            "bytecode_root": self.bytecode_root,
            "bytecode_size_bytes": self.bytecode_size_bytes,
            "proof_manifest_root": self.proof_manifest_root,
            "proof_system": self.proof_system,
            "proof_program_hash": self.proof_program_hash,
            "verifier_key_root": self.verifier_key_root,
            "init_state_root": self.init_state_root,
            "dependency_root": self.dependency_root,
            "artifact_root": self.artifact_root,
            "source_ref_root": self.source_ref_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "version": self.version,
            "status": self.status.as_str(),
            "bytecode_commitment_scheme": CONTRACT_VERIFICATION_BYTECODE_COMMITMENT_SCHEME,
            "proof_manifest_scheme": CONTRACT_VERIFICATION_PROOF_MANIFEST_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-BYTECODE-MANIFEST",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("manifest id", &self.manifest_id)?;
        ensure_non_empty("manifest contract id", &self.contract_id)?;
        ensure_non_empty("manifest bytecode root", &self.bytecode_root)?;
        ensure_positive(self.bytecode_size_bytes, "manifest bytecode size")?;
        ensure_non_empty("manifest proof root", &self.proof_manifest_root)?;
        ensure_non_empty("manifest proof system", &self.proof_system)?;
        ensure_non_empty("manifest proof program hash", &self.proof_program_hash)?;
        ensure_non_empty("manifest verifier key root", &self.verifier_key_root)?;
        ensure_non_empty("manifest init state root", &self.init_state_root)?;
        ensure_non_empty("manifest dependency root", &self.dependency_root)?;
        ensure_non_empty("manifest artifact root", &self.artifact_root)?;
        ensure_non_empty("manifest source ref root", &self.source_ref_root)?;
        ensure_non_empty("manifest metadata root", &self.metadata_root)?;
        ensure_positive(self.version, "manifest version")?;
        if self.manifest_id != bytecode_manifest_id(&self.identity_record()) {
            return Err("manifest id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyPin {
    pub pin_id: String,
    pub contract_id: String,
    pub circuit_id: String,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub verifier_key_hash: String,
    pub allowed_manifest_ids: Vec<String>,
    pub allowed_manifest_root: String,
    pub pinned_by_commitment: String,
    pub pinned_at_height: u64,
    pub expires_at_height: u64,
    pub version: u64,
    pub status: VerifierKeyStatus,
}

impl VerifierKeyPin {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        circuit_id: impl Into<String>,
        proof_system: impl Into<String>,
        verifier_key_root: impl Into<String>,
        allowed_manifest_ids: Vec<String>,
        pinned_by_label: &str,
        pinned_at_height: u64,
        expires_at_height: u64,
        version: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let circuit_id = circuit_id.into();
        let proof_system = proof_system.into();
        let verifier_key_root = verifier_key_root.into();
        ensure_non_empty("verifier key contract id", &contract_id)?;
        ensure_non_empty("verifier key circuit id", &circuit_id)?;
        ensure_non_empty("verifier key proof system", &proof_system)?;
        ensure_non_empty("verifier key root", &verifier_key_root)?;
        ensure_non_empty("verifier key pinner label", pinned_by_label)?;
        ensure_positive(version, "verifier key version")?;
        ensure_optional_expiry(pinned_at_height, expires_at_height, "verifier key pin")?;
        let allowed_manifest_ids = normalize_unique_strings(allowed_manifest_ids);
        let allowed_manifest_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-VERIFIER-KEY-MANIFEST",
            &allowed_manifest_ids,
        );
        let pinned_by_commitment = contract_verification_account_commitment(pinned_by_label);
        let verifier_key_hash = verifier_key_hash(&proof_system, &circuit_id, &verifier_key_root);
        let identity = verifier_key_pin_identity_record(
            &contract_id,
            &circuit_id,
            &proof_system,
            &verifier_key_root,
            &verifier_key_hash,
            &allowed_manifest_root,
            &pinned_by_commitment,
            pinned_at_height,
            expires_at_height,
            version,
        );
        let pin_id = verifier_key_pin_id(&identity);
        let pin = Self {
            pin_id,
            contract_id,
            circuit_id,
            proof_system,
            verifier_key_root,
            verifier_key_hash,
            allowed_manifest_ids,
            allowed_manifest_root,
            pinned_by_commitment,
            pinned_at_height,
            expires_at_height,
            version,
            status: VerifierKeyStatus::Pinned,
        };
        pin.validate()?;
        Ok(pin)
    }

    pub fn identity_record(&self) -> Value {
        verifier_key_pin_identity_record(
            &self.contract_id,
            &self.circuit_id,
            &self.proof_system,
            &self.verifier_key_root,
            &self.verifier_key_hash,
            &self.allowed_manifest_root,
            &self.pinned_by_commitment,
            self.pinned_at_height,
            self.expires_at_height,
            self.version,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_key_pin",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "pin_id": self.pin_id,
            "contract_id": self.contract_id,
            "circuit_id": self.circuit_id,
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "verifier_key_hash": self.verifier_key_hash,
            "allowed_manifest_ids": self.allowed_manifest_ids,
            "allowed_manifest_root": self.allowed_manifest_root,
            "pinned_by_commitment": self.pinned_by_commitment,
            "pinned_at_height": self.pinned_at_height,
            "expires_at_height": self.expires_at_height,
            "version": self.version,
            "status": self.status.as_str(),
            "pinning_scheme": CONTRACT_VERIFICATION_VERIFIER_KEY_PINNING_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-VERIFIER-KEY",
            &self.public_record(),
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_pinned()
            && height >= self.pinned_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn allows_manifest(&self, manifest_id: &str) -> bool {
        self.allowed_manifest_ids.is_empty()
            || self
                .allowed_manifest_ids
                .iter()
                .any(|candidate| candidate == manifest_id)
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("verifier key pin id", &self.pin_id)?;
        ensure_non_empty("verifier key contract id", &self.contract_id)?;
        ensure_non_empty("verifier key circuit id", &self.circuit_id)?;
        ensure_non_empty("verifier key proof system", &self.proof_system)?;
        ensure_non_empty("verifier key root", &self.verifier_key_root)?;
        ensure_non_empty("verifier key hash", &self.verifier_key_hash)?;
        ensure_non_empty(
            "verifier key allowed manifest root",
            &self.allowed_manifest_root,
        )?;
        ensure_non_empty("verifier key pinner", &self.pinned_by_commitment)?;
        ensure_optional_expiry(
            self.pinned_at_height,
            self.expires_at_height,
            "verifier key pin",
        )?;
        ensure_positive(self.version, "verifier key version")?;
        if self.allowed_manifest_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-VERIFIER-KEY-MANIFEST",
                &self.allowed_manifest_ids,
            )
        {
            return Err("verifier key manifest root mismatch".to_string());
        }
        if self.verifier_key_hash
            != verifier_key_hash(
                &self.proof_system,
                &self.circuit_id,
                &self.verifier_key_root,
            )
        {
            return Err("verifier key hash mismatch".to_string());
        }
        if self.pin_id != verifier_key_pin_id(&self.identity_record()) {
            return Err("verifier key pin id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibleBuildRecord {
    pub build_id: String,
    pub contract_id: String,
    pub manifest_id: String,
    pub source_commitment: String,
    pub source_tree_root: String,
    pub toolchain_root: String,
    pub dependency_lock_root: String,
    pub environment_root: String,
    pub output_bytecode_root: String,
    pub output_manifest_root: String,
    pub builder_commitment: String,
    pub build_log_root: String,
    pub built_at_height: u64,
    pub reproduction_count: u64,
    pub quorum_required: u64,
    pub status: BuildReproducibilityStatus,
}

impl ReproducibleBuildRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        manifest_id: impl Into<String>,
        source_tree: &Value,
        toolchain: &Value,
        dependency_lock: &Value,
        environment: &Value,
        output_bytecode_root: impl Into<String>,
        output_manifest_root: impl Into<String>,
        builder_label: &str,
        build_log: &Value,
        built_at_height: u64,
        reproduction_count: u64,
        quorum_required: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let manifest_id = manifest_id.into();
        let output_bytecode_root = output_bytecode_root.into();
        let output_manifest_root = output_manifest_root.into();
        ensure_non_empty("build contract id", &contract_id)?;
        ensure_non_empty("build manifest id", &manifest_id)?;
        ensure_non_empty("build output bytecode root", &output_bytecode_root)?;
        ensure_non_empty("build output manifest root", &output_manifest_root)?;
        ensure_non_empty("build builder label", builder_label)?;
        ensure_positive(quorum_required, "build quorum")?;
        let source_tree_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-BUILD-SOURCE-TREE",
            source_tree,
        );
        let source_commitment = domain_hash(
            "CONTRACT-VERIFICATION-BUILD-SOURCE-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&contract_id),
                HashPart::Str(&source_tree_root),
            ],
            32,
        );
        let toolchain_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-BUILD-TOOLCHAIN", toolchain);
        let dependency_lock_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-BUILD-DEPENDENCY-LOCK",
            dependency_lock,
        );
        let environment_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-BUILD-ENVIRONMENT",
            environment,
        );
        let builder_commitment = contract_verification_account_commitment(builder_label);
        let build_log_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-BUILD-LOG", build_log);
        let status = if reproduction_count >= quorum_required {
            BuildReproducibilityStatus::QuorumReproduced
        } else if reproduction_count > 0 {
            BuildReproducibilityStatus::Reproducible
        } else {
            BuildReproducibilityStatus::Unchecked
        };
        let identity = reproducible_build_identity_record(
            &contract_id,
            &manifest_id,
            &source_commitment,
            &source_tree_root,
            &toolchain_root,
            &dependency_lock_root,
            &environment_root,
            &output_bytecode_root,
            &output_manifest_root,
            &builder_commitment,
            &build_log_root,
            built_at_height,
            reproduction_count,
            quorum_required,
        );
        let build_id = reproducible_build_id(&identity);
        let record = Self {
            build_id,
            contract_id,
            manifest_id,
            source_commitment,
            source_tree_root,
            toolchain_root,
            dependency_lock_root,
            environment_root,
            output_bytecode_root,
            output_manifest_root,
            builder_commitment,
            build_log_root,
            built_at_height,
            reproduction_count,
            quorum_required,
            status,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        reproducible_build_identity_record(
            &self.contract_id,
            &self.manifest_id,
            &self.source_commitment,
            &self.source_tree_root,
            &self.toolchain_root,
            &self.dependency_lock_root,
            &self.environment_root,
            &self.output_bytecode_root,
            &self.output_manifest_root,
            &self.builder_commitment,
            &self.build_log_root,
            self.built_at_height,
            self.reproduction_count,
            self.quorum_required,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reproducible_build_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "build_id": self.build_id,
            "contract_id": self.contract_id,
            "manifest_id": self.manifest_id,
            "source_commitment": self.source_commitment,
            "source_tree_root": self.source_tree_root,
            "toolchain_root": self.toolchain_root,
            "dependency_lock_root": self.dependency_lock_root,
            "environment_root": self.environment_root,
            "output_bytecode_root": self.output_bytecode_root,
            "output_manifest_root": self.output_manifest_root,
            "builder_commitment": self.builder_commitment,
            "build_log_root": self.build_log_root,
            "built_at_height": self.built_at_height,
            "reproduction_count": self.reproduction_count,
            "quorum_required": self.quorum_required,
            "status": self.status.as_str(),
            "reproducible_build_scheme": CONTRACT_VERIFICATION_REPRODUCIBLE_BUILD_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-REPRODUCIBLE-BUILD",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("build id", &self.build_id)?;
        ensure_non_empty("build contract id", &self.contract_id)?;
        ensure_non_empty("build manifest id", &self.manifest_id)?;
        ensure_non_empty("build source commitment", &self.source_commitment)?;
        ensure_non_empty("build source tree root", &self.source_tree_root)?;
        ensure_non_empty("build toolchain root", &self.toolchain_root)?;
        ensure_non_empty("build dependency lock root", &self.dependency_lock_root)?;
        ensure_non_empty("build environment root", &self.environment_root)?;
        ensure_non_empty("build output bytecode root", &self.output_bytecode_root)?;
        ensure_non_empty("build output manifest root", &self.output_manifest_root)?;
        ensure_non_empty("build builder", &self.builder_commitment)?;
        ensure_non_empty("build log root", &self.build_log_root)?;
        ensure_positive(self.quorum_required, "build quorum")?;
        if self.status == BuildReproducibilityStatus::QuorumReproduced
            && self.reproduction_count < self.quorum_required
        {
            return Err("build quorum status mismatch".to_string());
        }
        if self.status.verifies() && self.reproduction_count == 0 {
            return Err("build verification count mismatch".to_string());
        }
        if self.build_id != reproducible_build_id(&self.identity_record()) {
            return Err("build id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuditorAttestation {
    pub attestation_id: String,
    pub auditor_commitment: String,
    pub contract_id: String,
    pub manifest_id: String,
    pub verifier_key_pin_id: String,
    pub build_id: String,
    pub privacy_policy_id: String,
    pub defi_gate_id: String,
    pub scope: AuditorScope,
    pub attestation_scope_root: String,
    pub finding_root: String,
    pub audit_score_bps: u64,
    pub signed_statement_root: String,
    pub pq_signature_scheme: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: AuditorAttestationStatus,
}

impl PqAuditorAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auditor_label: &str,
        contract_id: impl Into<String>,
        manifest_id: impl Into<String>,
        verifier_key_pin_id: impl Into<String>,
        build_id: impl Into<String>,
        privacy_policy_id: impl Into<String>,
        defi_gate_id: impl Into<String>,
        scope: AuditorScope,
        findings: &Value,
        signed_statement: &Value,
        audit_score_bps: u64,
        pq_public_key_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        attested_at_height: u64,
        ttl_blocks: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let manifest_id = manifest_id.into();
        let verifier_key_pin_id = verifier_key_pin_id.into();
        let build_id = build_id.into();
        let privacy_policy_id = privacy_policy_id.into();
        let defi_gate_id = defi_gate_id.into();
        let pq_public_key_root = pq_public_key_root.into();
        let pq_signature_root = pq_signature_root.into();
        ensure_non_empty("auditor label", auditor_label)?;
        ensure_non_empty("attestation contract id", &contract_id)?;
        ensure_non_empty("attestation manifest id", &manifest_id)?;
        ensure_non_empty("attestation verifier key pin id", &verifier_key_pin_id)?;
        ensure_non_empty("attestation build id", &build_id)?;
        ensure_non_empty("attestation privacy policy id", &privacy_policy_id)?;
        ensure_non_empty("attestation pq public key root", &pq_public_key_root)?;
        ensure_non_empty("attestation pq signature root", &pq_signature_root)?;
        ensure_positive(ttl_blocks, "attestation ttl")?;
        ensure_bps("audit score bps", audit_score_bps)?;
        let auditor_commitment = contract_verification_account_commitment(auditor_label);
        let attestation_scope_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-AUDITOR-SCOPE",
            &json!({
                "contract_id": contract_id,
                "manifest_id": manifest_id,
                "verifier_key_pin_id": verifier_key_pin_id,
                "build_id": build_id,
                "privacy_policy_id": privacy_policy_id,
                "defi_gate_id": defi_gate_id,
                "scope": scope.as_str(),
            }),
        );
        let finding_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-AUDITOR-FINDINGS", findings);
        let signed_statement_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-AUDITOR-SIGNED-STATEMENT",
            signed_statement,
        );
        let expires_at_height = attested_at_height.saturating_add(ttl_blocks);
        let status = if audit_score_bps >= CONTRACT_VERIFICATION_DEFAULT_MIN_AUDIT_SCORE_BPS {
            AuditorAttestationStatus::Accepted
        } else {
            AuditorAttestationStatus::Pending
        };
        let identity = pq_auditor_attestation_identity_record(
            &auditor_commitment,
            &contract_id,
            &manifest_id,
            &verifier_key_pin_id,
            &build_id,
            &privacy_policy_id,
            &defi_gate_id,
            scope.as_str(),
            &attestation_scope_root,
            &finding_root,
            audit_score_bps,
            &signed_statement_root,
            &pq_public_key_root,
            &pq_signature_root,
            attested_at_height,
            expires_at_height,
        );
        let attestation_id = pq_auditor_attestation_id(&identity);
        let attestation = Self {
            attestation_id,
            auditor_commitment,
            contract_id,
            manifest_id,
            verifier_key_pin_id,
            build_id,
            privacy_policy_id,
            defi_gate_id,
            scope,
            attestation_scope_root,
            finding_root,
            audit_score_bps,
            signed_statement_root,
            pq_signature_scheme: CONTRACT_VERIFICATION_PQ_AUDITOR_ATTESTATION_SCHEME.to_string(),
            pq_public_key_root,
            pq_signature_root,
            attested_at_height,
            expires_at_height,
            status,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn identity_record(&self) -> Value {
        pq_auditor_attestation_identity_record(
            &self.auditor_commitment,
            &self.contract_id,
            &self.manifest_id,
            &self.verifier_key_pin_id,
            &self.build_id,
            &self.privacy_policy_id,
            &self.defi_gate_id,
            self.scope.as_str(),
            &self.attestation_scope_root,
            &self.finding_root,
            self.audit_score_bps,
            &self.signed_statement_root,
            &self.pq_public_key_root,
            &self.pq_signature_root,
            self.attested_at_height,
            self.expires_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_auditor_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "auditor_commitment": self.auditor_commitment,
            "contract_id": self.contract_id,
            "manifest_id": self.manifest_id,
            "verifier_key_pin_id": self.verifier_key_pin_id,
            "build_id": self.build_id,
            "privacy_policy_id": self.privacy_policy_id,
            "defi_gate_id": self.defi_gate_id,
            "scope": self.scope.as_str(),
            "attestation_scope_root": self.attestation_scope_root,
            "finding_root": self.finding_root,
            "audit_score_bps": self.audit_score_bps,
            "signed_statement_root": self.signed_statement_root,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-AUDITOR-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.counts_for_verification()
            && self.attested_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("attestation id", &self.attestation_id)?;
        ensure_non_empty("attestation auditor", &self.auditor_commitment)?;
        ensure_non_empty("attestation contract id", &self.contract_id)?;
        ensure_non_empty("attestation manifest id", &self.manifest_id)?;
        ensure_non_empty("attestation verifier key pin id", &self.verifier_key_pin_id)?;
        ensure_non_empty("attestation build id", &self.build_id)?;
        ensure_non_empty("attestation privacy policy id", &self.privacy_policy_id)?;
        ensure_non_empty("attestation scope root", &self.attestation_scope_root)?;
        ensure_non_empty("attestation finding root", &self.finding_root)?;
        ensure_non_empty(
            "attestation signed statement root",
            &self.signed_statement_root,
        )?;
        ensure_non_empty("attestation pq scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("attestation pq public key root", &self.pq_public_key_root)?;
        ensure_non_empty("attestation pq signature root", &self.pq_signature_root)?;
        ensure_bps("audit score bps", self.audit_score_bps)?;
        if self.expires_at_height <= self.attested_at_height {
            return Err("attestation expiry height mismatch".to_string());
        }
        if self.pq_signature_scheme != CONTRACT_VERIFICATION_PQ_AUDITOR_ATTESTATION_SCHEME {
            return Err("attestation signature scheme mismatch".to_string());
        }
        if self.attestation_id != pq_auditor_attestation_id(&self.identity_record()) {
            return Err("attestation id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetPolicy {
    pub policy_id: String,
    pub contract_id: String,
    pub mode: PrivacyBudgetMode,
    pub epoch_blocks: u64,
    pub max_private_calls_per_epoch: u64,
    pub max_private_state_bytes: u64,
    pub max_private_event_bytes: u64,
    pub max_view_key_disclosure_bps: u64,
    pub audit_window_blocks: u64,
    pub nullifier_root: String,
    pub view_key_policy_root: String,
    pub auditor_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PrivacyPolicyStatus,
}

impl PrivacyBudgetPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        mode: PrivacyBudgetMode,
        epoch_blocks: u64,
        max_private_calls_per_epoch: u64,
        max_private_state_bytes: u64,
        max_private_event_bytes: u64,
        max_view_key_disclosure_bps: u64,
        audit_window_blocks: u64,
        nullifiers: Vec<String>,
        view_key_policy: &Value,
        auditors: Vec<String>,
        metadata: &Value,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        ensure_non_empty("privacy policy contract id", &contract_id)?;
        ensure_positive(epoch_blocks, "privacy policy epoch blocks")?;
        ensure_positive(audit_window_blocks, "privacy policy audit window")?;
        ensure_bps(
            "privacy policy view key disclosure bps",
            max_view_key_disclosure_bps,
        )?;
        ensure_optional_expiry(
            created_at_height,
            expires_at_height,
            "privacy budget policy",
        )?;
        let nullifiers = normalize_unique_strings(nullifiers);
        let auditor_commitments = auditors
            .into_iter()
            .map(|auditor| contract_verification_account_commitment(&auditor))
            .collect::<Vec<_>>();
        let auditor_commitments = normalize_unique_strings(auditor_commitments);
        let nullifier_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-PRIVACY-NULLIFIER",
            &nullifiers,
        );
        let view_key_policy_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-PRIVACY-VIEW-KEY-POLICY",
            view_key_policy,
        );
        let auditor_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-PRIVACY-AUDITOR",
            &auditor_commitments,
        );
        let metadata_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-PRIVACY-METADATA", metadata);
        let identity = privacy_budget_policy_identity_record(
            &contract_id,
            mode.as_str(),
            epoch_blocks,
            max_private_calls_per_epoch,
            max_private_state_bytes,
            max_private_event_bytes,
            max_view_key_disclosure_bps,
            audit_window_blocks,
            &nullifier_root,
            &view_key_policy_root,
            &auditor_root,
            &metadata_root,
            created_at_height,
            expires_at_height,
        );
        let policy_id = privacy_budget_policy_id(&identity);
        let policy = Self {
            policy_id,
            contract_id,
            mode,
            epoch_blocks,
            max_private_calls_per_epoch,
            max_private_state_bytes,
            max_private_event_bytes,
            max_view_key_disclosure_bps,
            audit_window_blocks,
            nullifier_root,
            view_key_policy_root,
            auditor_root,
            metadata_root,
            created_at_height,
            expires_at_height,
            status: PrivacyPolicyStatus::Active,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn identity_record(&self) -> Value {
        privacy_budget_policy_identity_record(
            &self.contract_id,
            self.mode.as_str(),
            self.epoch_blocks,
            self.max_private_calls_per_epoch,
            self.max_private_state_bytes,
            self.max_private_event_bytes,
            self.max_view_key_disclosure_bps,
            self.audit_window_blocks,
            &self.nullifier_root,
            &self.view_key_policy_root,
            &self.auditor_root,
            &self.metadata_root,
            self.created_at_height,
            self.expires_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "mode": self.mode.as_str(),
            "epoch_blocks": self.epoch_blocks,
            "max_private_calls_per_epoch": self.max_private_calls_per_epoch,
            "max_private_state_bytes": self.max_private_state_bytes,
            "max_private_event_bytes": self.max_private_event_bytes,
            "max_view_key_disclosure_bps": self.max_view_key_disclosure_bps,
            "audit_window_blocks": self.audit_window_blocks,
            "nullifier_root": self.nullifier_root,
            "view_key_policy_root": self.view_key_policy_root,
            "auditor_root": self.auditor_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "privacy_budget_policy_scheme": CONTRACT_VERIFICATION_PRIVACY_BUDGET_POLICY_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-PRIVACY-BUDGET",
            &self.public_record(),
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && self.created_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("privacy policy id", &self.policy_id)?;
        ensure_non_empty("privacy policy contract id", &self.contract_id)?;
        ensure_positive(self.epoch_blocks, "privacy policy epoch blocks")?;
        ensure_positive(self.audit_window_blocks, "privacy policy audit window")?;
        ensure_bps(
            "privacy policy view key disclosure bps",
            self.max_view_key_disclosure_bps,
        )?;
        ensure_non_empty("privacy policy nullifier root", &self.nullifier_root)?;
        ensure_non_empty("privacy policy view key root", &self.view_key_policy_root)?;
        ensure_non_empty("privacy policy auditor root", &self.auditor_root)?;
        ensure_non_empty("privacy policy metadata root", &self.metadata_root)?;
        ensure_optional_expiry(
            self.created_at_height,
            self.expires_at_height,
            "privacy budget policy",
        )?;
        if self.mode.requires_auditor()
            && self.auditor_root
                == contract_verification_string_set_root(
                    "CONTRACT-VERIFICATION-PRIVACY-AUDITOR",
                    &[],
                )
        {
            return Err("privacy policy auditor root missing".to_string());
        }
        if self.policy_id != privacy_budget_policy_id(&self.identity_record()) {
            return Err("privacy policy id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSponsorship {
    pub sponsorship_id: String,
    pub contract_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub lane_root: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub per_deployment_cap_units: u64,
    pub max_contracts: u64,
    pub sponsored_contract_count: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub policy_root: String,
    pub status: DeploymentSponsorStatus,
}

impl DeploymentSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        sponsor_label: &str,
        fee_asset_id: impl Into<String>,
        low_fee_lane: impl Into<String>,
        budget_units: u64,
        per_deployment_cap_units: u64,
        max_contracts: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        policy: &Value,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let fee_asset_id = fee_asset_id.into();
        let low_fee_lane = low_fee_lane.into();
        ensure_non_empty("deployment sponsorship contract id", &contract_id)?;
        ensure_non_empty("deployment sponsorship sponsor label", sponsor_label)?;
        ensure_non_empty("deployment sponsorship fee asset", &fee_asset_id)?;
        ensure_non_empty("deployment sponsorship low fee lane", &low_fee_lane)?;
        ensure_positive(budget_units, "deployment sponsorship budget")?;
        ensure_positive(
            per_deployment_cap_units,
            "deployment sponsorship per deployment cap",
        )?;
        ensure_positive(max_contracts, "deployment sponsorship max contracts")?;
        ensure_height_window(
            valid_from_height,
            valid_until_height,
            "deployment sponsorship",
        )?;
        let sponsor_commitment = contract_verification_account_commitment(sponsor_label);
        let lane_root = contract_verification_string_root(
            "CONTRACT-VERIFICATION-DEPLOYMENT-SPONSOR-LANE",
            &low_fee_lane,
        );
        let policy_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-DEPLOYMENT-SPONSOR-POLICY",
            policy,
        );
        let identity = deployment_sponsorship_identity_record(
            &contract_id,
            &sponsor_commitment,
            &fee_asset_id,
            &low_fee_lane,
            &lane_root,
            budget_units,
            per_deployment_cap_units,
            max_contracts,
            valid_from_height,
            valid_until_height,
            &policy_root,
        );
        let sponsorship_id = deployment_sponsorship_id(&identity);
        let sponsorship = Self {
            sponsorship_id,
            contract_id,
            sponsor_commitment,
            fee_asset_id,
            low_fee_lane,
            lane_root,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            per_deployment_cap_units,
            max_contracts,
            sponsored_contract_count: 0,
            valid_from_height,
            valid_until_height,
            policy_root,
            status: DeploymentSponsorStatus::Active,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn identity_record(&self) -> Value {
        deployment_sponsorship_identity_record(
            &self.contract_id,
            &self.sponsor_commitment,
            &self.fee_asset_id,
            &self.low_fee_lane,
            &self.lane_root,
            self.budget_units,
            self.per_deployment_cap_units,
            self.max_contracts,
            self.valid_from_height,
            self.valid_until_height,
            &self.policy_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deployment_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "contract_id": self.contract_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "lane_root": self.lane_root,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "per_deployment_cap_units": self.per_deployment_cap_units,
            "max_contracts": self.max_contracts,
            "sponsored_contract_count": self.sponsored_contract_count,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "policy_root": self.policy_root,
            "status": self.status.as_str(),
            "deployment_sponsorship_scheme": CONTRACT_VERIFICATION_DEPLOYMENT_SPONSORSHIP_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-DEPLOYMENT-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.can_spend()
            && self.valid_from_height <= height
            && height <= self.valid_until_height
            && self.available_units() > 0
            && self.sponsored_contract_count < self.max_contracts
    }

    pub fn reserve_deployment(&mut self, height: u64) -> ContractVerificationRegistryResult<()> {
        if !self.is_active_at(height) {
            return Err("deployment sponsorship inactive".to_string());
        }
        if self.per_deployment_cap_units > self.available_units() {
            return Err("deployment sponsorship budget exhausted".to_string());
        }
        self.reserved_units = self
            .reserved_units
            .saturating_add(self.per_deployment_cap_units);
        self.sponsored_contract_count = self.sponsored_contract_count.saturating_add(1);
        if self.available_units() == 0 || self.sponsored_contract_count >= self.max_contracts {
            self.status = DeploymentSponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn settle_reserved(&mut self, units: u64) -> ContractVerificationRegistryResult<()> {
        if units > self.reserved_units {
            return Err("deployment sponsorship settlement exceeds reserves".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 && self.reserved_units == 0 {
            self.status = DeploymentSponsorStatus::Exhausted;
        }
        Ok(())
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("deployment sponsorship id", &self.sponsorship_id)?;
        ensure_non_empty("deployment sponsorship contract id", &self.contract_id)?;
        ensure_non_empty("deployment sponsorship sponsor", &self.sponsor_commitment)?;
        ensure_non_empty("deployment sponsorship fee asset", &self.fee_asset_id)?;
        ensure_non_empty("deployment sponsorship low fee lane", &self.low_fee_lane)?;
        ensure_non_empty("deployment sponsorship lane root", &self.lane_root)?;
        ensure_non_empty("deployment sponsorship policy root", &self.policy_root)?;
        ensure_positive(self.budget_units, "deployment sponsorship budget")?;
        ensure_positive(
            self.per_deployment_cap_units,
            "deployment sponsorship per deployment cap",
        )?;
        ensure_positive(self.max_contracts, "deployment sponsorship max contracts")?;
        ensure_height_window(
            self.valid_from_height,
            self.valid_until_height,
            "deployment sponsorship",
        )?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("deployment sponsorship accounting exceeds budget".to_string());
        }
        if self.sponsored_contract_count > self.max_contracts {
            return Err("deployment sponsorship contract count exceeds cap".to_string());
        }
        if self.lane_root
            != contract_verification_string_root(
                "CONTRACT-VERIFICATION-DEPLOYMENT-SPONSOR-LANE",
                &self.low_fee_lane,
            )
        {
            return Err("deployment sponsorship lane root mismatch".to_string());
        }
        if self.sponsorship_id != deployment_sponsorship_id(&self.identity_record()) {
            return Err("deployment sponsorship id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeAuthorization {
    pub authorization_id: String,
    pub contract_id: String,
    pub from_manifest_id: String,
    pub to_manifest_id: String,
    pub from_version: u64,
    pub to_version: u64,
    pub authorizer_commitment: String,
    pub governance_root: String,
    pub migration_root: String,
    pub verifier_key_pin_id: String,
    pub timelock_start_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub emergency_override: bool,
    pub nonce: u64,
    pub status: UpgradeAuthorizationStatus,
}

impl UpgradeAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        from_manifest_id: impl Into<String>,
        to_manifest_id: impl Into<String>,
        from_version: u64,
        to_version: u64,
        authorizer_label: &str,
        governance: &Value,
        migration: &Value,
        verifier_key_pin_id: impl Into<String>,
        timelock_start_height: u64,
        timelock_blocks: u64,
        expiry_blocks: u64,
        emergency_override: bool,
        nonce: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let from_manifest_id = from_manifest_id.into();
        let to_manifest_id = to_manifest_id.into();
        let verifier_key_pin_id = verifier_key_pin_id.into();
        ensure_non_empty("upgrade contract id", &contract_id)?;
        ensure_non_empty("upgrade from manifest id", &from_manifest_id)?;
        ensure_non_empty("upgrade to manifest id", &to_manifest_id)?;
        ensure_non_empty("upgrade authorizer label", authorizer_label)?;
        ensure_non_empty("upgrade verifier key pin id", &verifier_key_pin_id)?;
        ensure_positive(from_version, "upgrade from version")?;
        ensure_positive(to_version, "upgrade to version")?;
        ensure_positive(expiry_blocks, "upgrade expiry blocks")?;
        if to_version <= from_version {
            return Err("upgrade version order mismatch".to_string());
        }
        let timelock_blocks = if emergency_override {
            0
        } else {
            timelock_blocks
        };
        let executable_at_height = timelock_start_height.saturating_add(timelock_blocks);
        let expires_at_height = executable_at_height.saturating_add(expiry_blocks);
        let authorizer_commitment = contract_verification_account_commitment(authorizer_label);
        let governance_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-UPGRADE-GOVERNANCE",
            governance,
        );
        let migration_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-UPGRADE-MIGRATION",
            migration,
        );
        let identity = upgrade_authorization_identity_record(
            &contract_id,
            &from_manifest_id,
            &to_manifest_id,
            from_version,
            to_version,
            &authorizer_commitment,
            &governance_root,
            &migration_root,
            &verifier_key_pin_id,
            timelock_start_height,
            executable_at_height,
            expires_at_height,
            emergency_override,
            nonce,
        );
        let authorization_id = upgrade_authorization_id(&identity);
        let status = if emergency_override {
            UpgradeAuthorizationStatus::Authorized
        } else {
            UpgradeAuthorizationStatus::Timelocked
        };
        let authorization = Self {
            authorization_id,
            contract_id,
            from_manifest_id,
            to_manifest_id,
            from_version,
            to_version,
            authorizer_commitment,
            governance_root,
            migration_root,
            verifier_key_pin_id,
            timelock_start_height,
            executable_at_height,
            expires_at_height,
            emergency_override,
            nonce,
            status,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn identity_record(&self) -> Value {
        upgrade_authorization_identity_record(
            &self.contract_id,
            &self.from_manifest_id,
            &self.to_manifest_id,
            self.from_version,
            self.to_version,
            &self.authorizer_commitment,
            &self.governance_root,
            &self.migration_root,
            &self.verifier_key_pin_id,
            self.timelock_start_height,
            self.executable_at_height,
            self.expires_at_height,
            self.emergency_override,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "upgrade_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "contract_id": self.contract_id,
            "from_manifest_id": self.from_manifest_id,
            "to_manifest_id": self.to_manifest_id,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "authorizer_commitment": self.authorizer_commitment,
            "governance_root": self.governance_root,
            "migration_root": self.migration_root,
            "verifier_key_pin_id": self.verifier_key_pin_id,
            "timelock_start_height": self.timelock_start_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "emergency_override": self.emergency_override,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "upgrade_authorization_scheme": CONTRACT_VERIFICATION_UPGRADE_AUTHORIZATION_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-UPGRADE-AUTHORIZATION",
            &self.public_record(),
        )
    }

    pub fn is_executable_at(&self, height: u64) -> bool {
        self.status.can_execute()
            && height >= self.executable_at_height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("upgrade authorization id", &self.authorization_id)?;
        ensure_non_empty("upgrade contract id", &self.contract_id)?;
        ensure_non_empty("upgrade from manifest id", &self.from_manifest_id)?;
        ensure_non_empty("upgrade to manifest id", &self.to_manifest_id)?;
        ensure_non_empty("upgrade authorizer", &self.authorizer_commitment)?;
        ensure_non_empty("upgrade governance root", &self.governance_root)?;
        ensure_non_empty("upgrade migration root", &self.migration_root)?;
        ensure_non_empty("upgrade verifier key pin id", &self.verifier_key_pin_id)?;
        ensure_positive(self.from_version, "upgrade from version")?;
        ensure_positive(self.to_version, "upgrade to version")?;
        if self.to_version <= self.from_version {
            return Err("upgrade version order mismatch".to_string());
        }
        if self.executable_at_height < self.timelock_start_height {
            return Err("upgrade timelock height mismatch".to_string());
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err("upgrade expiry height mismatch".to_string());
        }
        if self.authorization_id != upgrade_authorization_id(&self.identity_record()) {
            return Err("upgrade authorization id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyDeprecationRecord {
    pub deprecation_id: String,
    pub contract_id: String,
    pub scope: DeprecationScope,
    pub severity: DeprecationSeverity,
    pub reason_root: String,
    pub evidence_root: String,
    pub replacement_contract_id: String,
    pub declared_by_commitment: String,
    pub effective_at_height: u64,
    pub review_until_height: u64,
    pub nonce: u64,
    pub status: DeprecationStatus,
}

impl EmergencyDeprecationRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        scope: DeprecationScope,
        severity: DeprecationSeverity,
        reason: &Value,
        evidence: &Value,
        replacement_contract_id: impl Into<String>,
        declared_by_label: &str,
        effective_at_height: u64,
        review_until_height: u64,
        nonce: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let contract_id = contract_id.into();
        let replacement_contract_id = replacement_contract_id.into();
        ensure_non_empty("deprecation contract id", &contract_id)?;
        ensure_non_empty("deprecation declared by label", declared_by_label)?;
        ensure_optional_expiry(
            effective_at_height,
            review_until_height,
            "emergency deprecation",
        )?;
        let reason_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-DEPRECATION-REASON", reason);
        let evidence_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-DEPRECATION-EVIDENCE",
            evidence,
        );
        let declared_by_commitment = contract_verification_account_commitment(declared_by_label);
        let identity = emergency_deprecation_identity_record(
            &contract_id,
            scope.as_str(),
            severity.as_str(),
            &reason_root,
            &evidence_root,
            &replacement_contract_id,
            &declared_by_commitment,
            effective_at_height,
            review_until_height,
            nonce,
        );
        let deprecation_id = emergency_deprecation_id(&identity);
        let record = Self {
            deprecation_id,
            contract_id,
            scope,
            severity,
            reason_root,
            evidence_root,
            replacement_contract_id,
            declared_by_commitment,
            effective_at_height,
            review_until_height,
            nonce,
            status: DeprecationStatus::Active,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        emergency_deprecation_identity_record(
            &self.contract_id,
            self.scope.as_str(),
            self.severity.as_str(),
            &self.reason_root,
            &self.evidence_root,
            &self.replacement_contract_id,
            &self.declared_by_commitment,
            self.effective_at_height,
            self.review_until_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_deprecation_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "deprecation_id": self.deprecation_id,
            "contract_id": self.contract_id,
            "scope": self.scope.as_str(),
            "severity": self.severity.as_str(),
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "replacement_contract_id": self.replacement_contract_id,
            "declared_by_commitment": self.declared_by_commitment,
            "effective_at_height": self.effective_at_height,
            "review_until_height": self.review_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "emergency_deprecation_scheme": CONTRACT_VERIFICATION_EMERGENCY_DEPRECATION_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-EMERGENCY-DEPRECATION",
            &self.public_record(),
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && height >= self.effective_at_height
            && (self.review_until_height == 0 || height <= self.review_until_height)
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("deprecation id", &self.deprecation_id)?;
        ensure_non_empty("deprecation contract id", &self.contract_id)?;
        ensure_non_empty("deprecation reason root", &self.reason_root)?;
        ensure_non_empty("deprecation evidence root", &self.evidence_root)?;
        ensure_non_empty("deprecation declared by", &self.declared_by_commitment)?;
        ensure_optional_expiry(
            self.effective_at_height,
            self.review_until_height,
            "emergency deprecation",
        )?;
        if self.deprecation_id != emergency_deprecation_id(&self.identity_record()) {
            return Err("deprecation id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiProtocolAllowlistGate {
    pub gate_id: String,
    pub protocol_id: String,
    pub contract_id: String,
    pub protocol_kind: DefiProtocolKind,
    pub allowed_selectors: Vec<String>,
    pub allowed_selector_root: String,
    pub allowed_asset_ids: Vec<String>,
    pub asset_root: String,
    pub allowed_counterparty_commitments: Vec<String>,
    pub counterparty_root: String,
    pub risk_policy_root: String,
    pub min_audit_score_bps: u64,
    pub max_tvl_units: u64,
    pub sponsor_required: bool,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub created_at_height: u64,
    pub metadata_root: String,
    pub status: DefiGateStatus,
}

impl DefiProtocolAllowlistGate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_id: impl Into<String>,
        contract_id: impl Into<String>,
        protocol_kind: DefiProtocolKind,
        allowed_selectors: Vec<String>,
        allowed_asset_ids: Vec<String>,
        allowed_counterparty_labels: Vec<String>,
        risk_policy: &Value,
        min_audit_score_bps: u64,
        max_tvl_units: u64,
        sponsor_required: bool,
        valid_from_height: u64,
        valid_until_height: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> ContractVerificationRegistryResult<Self> {
        let protocol_id = protocol_id.into();
        let contract_id = contract_id.into();
        ensure_non_empty("defi gate protocol id", &protocol_id)?;
        ensure_non_empty("defi gate contract id", &contract_id)?;
        ensure_bps("defi gate min audit score bps", min_audit_score_bps)?;
        ensure_height_window(valid_from_height, valid_until_height, "defi gate")?;
        let allowed_selectors = normalize_unique_strings(allowed_selectors);
        let allowed_asset_ids = normalize_unique_strings(allowed_asset_ids);
        let allowed_counterparty_commitments = allowed_counterparty_labels
            .into_iter()
            .map(|label| contract_verification_account_commitment(&label))
            .collect::<Vec<_>>();
        let allowed_counterparty_commitments =
            normalize_unique_strings(allowed_counterparty_commitments);
        let allowed_selector_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-DEFI-GATE-SELECTOR",
            &allowed_selectors,
        );
        let asset_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-DEFI-GATE-ASSET",
            &allowed_asset_ids,
        );
        let counterparty_root = contract_verification_string_set_root(
            "CONTRACT-VERIFICATION-DEFI-GATE-COUNTERPARTY",
            &allowed_counterparty_commitments,
        );
        let risk_policy_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-DEFI-GATE-RISK", risk_policy);
        let metadata_root = contract_verification_payload_root(
            "CONTRACT-VERIFICATION-DEFI-GATE-METADATA",
            metadata,
        );
        let identity = defi_gate_identity_record(
            &protocol_id,
            &contract_id,
            protocol_kind.as_str(),
            &allowed_selector_root,
            &asset_root,
            &counterparty_root,
            &risk_policy_root,
            min_audit_score_bps,
            max_tvl_units,
            sponsor_required,
            valid_from_height,
            valid_until_height,
            created_at_height,
            &metadata_root,
        );
        let gate_id = defi_gate_id(&identity);
        let gate = Self {
            gate_id,
            protocol_id,
            contract_id,
            protocol_kind,
            allowed_selectors,
            allowed_selector_root,
            allowed_asset_ids,
            asset_root,
            allowed_counterparty_commitments,
            counterparty_root,
            risk_policy_root,
            min_audit_score_bps,
            max_tvl_units,
            sponsor_required,
            valid_from_height,
            valid_until_height,
            created_at_height,
            metadata_root,
            status: DefiGateStatus::Allowlisted,
        };
        gate.validate()?;
        Ok(gate)
    }

    pub fn identity_record(&self) -> Value {
        defi_gate_identity_record(
            &self.protocol_id,
            &self.contract_id,
            self.protocol_kind.as_str(),
            &self.allowed_selector_root,
            &self.asset_root,
            &self.counterparty_root,
            &self.risk_policy_root,
            self.min_audit_score_bps,
            self.max_tvl_units,
            self.sponsor_required,
            self.valid_from_height,
            self.valid_until_height,
            self.created_at_height,
            &self.metadata_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_protocol_allowlist_gate",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "gate_id": self.gate_id,
            "protocol_id": self.protocol_id,
            "contract_id": self.contract_id,
            "protocol_kind": self.protocol_kind.as_str(),
            "allowed_selectors": self.allowed_selectors,
            "allowed_selector_root": self.allowed_selector_root,
            "allowed_asset_ids": self.allowed_asset_ids,
            "asset_root": self.asset_root,
            "allowed_counterparty_commitments": self.allowed_counterparty_commitments,
            "counterparty_root": self.counterparty_root,
            "risk_policy_root": self.risk_policy_root,
            "min_audit_score_bps": self.min_audit_score_bps,
            "max_tvl_units": self.max_tvl_units,
            "sponsor_required": self.sponsor_required,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
            "defi_allowlist_gate_scheme": CONTRACT_VERIFICATION_DEFI_ALLOWLIST_GATE_SCHEME,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root("CONTRACT-VERIFICATION-DEFI-GATE", &self.public_record())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.allows()
            && self.valid_from_height <= height
            && height <= self.valid_until_height
    }

    pub fn allows_selector(&self, selector: &str) -> bool {
        self.allowed_selectors.is_empty()
            || self
                .allowed_selectors
                .iter()
                .any(|candidate| candidate == selector || candidate == "*")
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("defi gate id", &self.gate_id)?;
        ensure_non_empty("defi gate protocol id", &self.protocol_id)?;
        ensure_non_empty("defi gate contract id", &self.contract_id)?;
        ensure_non_empty("defi gate selector root", &self.allowed_selector_root)?;
        ensure_non_empty("defi gate asset root", &self.asset_root)?;
        ensure_non_empty("defi gate counterparty root", &self.counterparty_root)?;
        ensure_non_empty("defi gate risk policy root", &self.risk_policy_root)?;
        ensure_non_empty("defi gate metadata root", &self.metadata_root)?;
        ensure_bps("defi gate min audit score bps", self.min_audit_score_bps)?;
        ensure_height_window(self.valid_from_height, self.valid_until_height, "defi gate")?;
        if self.allowed_selector_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-DEFI-GATE-SELECTOR",
                &self.allowed_selectors,
            )
        {
            return Err("defi gate selector root mismatch".to_string());
        }
        if self.asset_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-DEFI-GATE-ASSET",
                &self.allowed_asset_ids,
            )
        {
            return Err("defi gate asset root mismatch".to_string());
        }
        if self.counterparty_root
            != contract_verification_string_set_root(
                "CONTRACT-VERIFICATION-DEFI-GATE-COUNTERPARTY",
                &self.allowed_counterparty_commitments,
            )
        {
            return Err("defi gate counterparty root mismatch".to_string());
        }
        if self.gate_id != defi_gate_id(&self.identity_record()) {
            return Err("defi gate id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedContractRecord {
    pub contract_id: String,
    pub namespace: String,
    pub kind: VerifiedContractKind,
    pub owner_commitment: String,
    pub deployment_salt_root: String,
    pub abi_id: String,
    pub active_manifest_id: String,
    pub verifier_key_pin_id: String,
    pub privacy_policy_id: String,
    pub sponsorship_id: String,
    pub build_id: String,
    pub defi_gate_id: String,
    pub metadata_root: String,
    pub current_version: u64,
    pub deployed_at_height: u64,
    pub updated_at_height: u64,
    pub status: ContractVerificationStatus,
}

impl VerifiedContractRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        namespace: impl Into<String>,
        kind: VerifiedContractKind,
        owner_label: &str,
        deployment_salt: &str,
        abi_id: impl Into<String>,
        active_manifest_id: impl Into<String>,
        verifier_key_pin_id: impl Into<String>,
        privacy_policy_id: impl Into<String>,
        sponsorship_id: impl Into<String>,
        build_id: impl Into<String>,
        defi_gate_id: impl Into<String>,
        metadata: &Value,
        current_version: u64,
        deployed_at_height: u64,
    ) -> ContractVerificationRegistryResult<Self> {
        let namespace = normalize_label(namespace.into());
        let abi_id = abi_id.into();
        let active_manifest_id = active_manifest_id.into();
        let verifier_key_pin_id = verifier_key_pin_id.into();
        let privacy_policy_id = privacy_policy_id.into();
        let sponsorship_id = sponsorship_id.into();
        let build_id = build_id.into();
        let defi_gate_id = defi_gate_id.into();
        ensure_non_empty("verified contract namespace", &namespace)?;
        ensure_non_empty("verified contract owner label", owner_label)?;
        ensure_non_empty("verified contract deployment salt", deployment_salt)?;
        ensure_non_empty("verified contract abi id", &abi_id)?;
        ensure_non_empty("verified contract manifest id", &active_manifest_id)?;
        ensure_non_empty(
            "verified contract verifier key pin id",
            &verifier_key_pin_id,
        )?;
        ensure_non_empty("verified contract privacy policy id", &privacy_policy_id)?;
        ensure_non_empty("verified contract build id", &build_id)?;
        ensure_positive(current_version, "verified contract version")?;
        let owner_commitment = contract_verification_account_commitment(owner_label);
        let deployment_salt_root = contract_verification_string_root(
            "CONTRACT-VERIFICATION-DEPLOYMENT-SALT",
            deployment_salt,
        );
        let contract_id = verified_contract_id(
            &namespace,
            kind.as_str(),
            &owner_commitment,
            &deployment_salt_root,
        );
        let metadata_root =
            contract_verification_payload_root("CONTRACT-VERIFICATION-CONTRACT-METADATA", metadata);
        let record = Self {
            contract_id,
            namespace,
            kind,
            owner_commitment,
            deployment_salt_root,
            abi_id,
            active_manifest_id,
            verifier_key_pin_id,
            privacy_policy_id,
            sponsorship_id,
            build_id,
            defi_gate_id,
            metadata_root,
            current_version,
            deployed_at_height,
            updated_at_height: deployed_at_height,
            status: ContractVerificationStatus::PendingReview,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn identity_record(&self) -> Value {
        verified_contract_identity_record(
            &self.namespace,
            self.kind.as_str(),
            &self.owner_commitment,
            &self.deployment_salt_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verified_contract_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "contract_id": self.contract_id,
            "namespace": self.namespace,
            "contract_kind": self.kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "deployment_salt_root": self.deployment_salt_root,
            "abi_id": self.abi_id,
            "active_manifest_id": self.active_manifest_id,
            "verifier_key_pin_id": self.verifier_key_pin_id,
            "privacy_policy_id": self.privacy_policy_id,
            "sponsorship_id": self.sponsorship_id,
            "build_id": self.build_id,
            "defi_gate_id": self.defi_gate_id,
            "metadata_root": self.metadata_root,
            "current_version": self.current_version,
            "deployed_at_height": self.deployed_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root("CONTRACT-VERIFICATION-CONTRACT", &self.public_record())
    }

    pub fn is_live(&self) -> bool {
        self.status.is_live()
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("verified contract id", &self.contract_id)?;
        ensure_non_empty("verified contract namespace", &self.namespace)?;
        ensure_non_empty("verified contract owner", &self.owner_commitment)?;
        ensure_non_empty(
            "verified contract deployment salt root",
            &self.deployment_salt_root,
        )?;
        ensure_non_empty("verified contract abi id", &self.abi_id)?;
        ensure_non_empty("verified contract manifest id", &self.active_manifest_id)?;
        ensure_non_empty(
            "verified contract verifier key pin id",
            &self.verifier_key_pin_id,
        )?;
        ensure_non_empty(
            "verified contract privacy policy id",
            &self.privacy_policy_id,
        )?;
        ensure_non_empty("verified contract build id", &self.build_id)?;
        ensure_non_empty("verified contract metadata root", &self.metadata_root)?;
        ensure_positive(self.current_version, "verified contract version")?;
        if self.updated_at_height < self.deployed_at_height {
            return Err("verified contract update height mismatch".to_string());
        }
        if self.contract_id != verified_contract_id_from_record(&self.identity_record()) {
            return Err("verified contract id mismatch".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerificationRegistryRoots {
    pub config_root: String,
    pub contract_root: String,
    pub abi_root: String,
    pub manifest_root: String,
    pub upgrade_authorization_root: String,
    pub auditor_attestation_root: String,
    pub privacy_policy_root: String,
    pub deployment_sponsorship_root: String,
    pub verifier_key_root: String,
    pub reproducible_build_root: String,
    pub emergency_deprecation_root: String,
    pub defi_gate_root: String,
    pub active_contract_root: String,
    pub emergency_disabled_contract_root: String,
}

impl ContractVerificationRegistryRoots {
    pub fn aggregate_root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-ROOTS-AGGREGATE",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_verification_registry_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "contract_root": self.contract_root,
            "abi_root": self.abi_root,
            "manifest_root": self.manifest_root,
            "upgrade_authorization_root": self.upgrade_authorization_root,
            "auditor_attestation_root": self.auditor_attestation_root,
            "privacy_policy_root": self.privacy_policy_root,
            "deployment_sponsorship_root": self.deployment_sponsorship_root,
            "verifier_key_root": self.verifier_key_root,
            "reproducible_build_root": self.reproducible_build_root,
            "emergency_deprecation_root": self.emergency_deprecation_root,
            "defi_gate_root": self.defi_gate_root,
            "active_contract_root": self.active_contract_root,
            "emergency_disabled_contract_root": self.emergency_disabled_contract_root,
        })
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        ensure_non_empty("config root", &self.config_root)?;
        ensure_non_empty("contract root", &self.contract_root)?;
        ensure_non_empty("abi root", &self.abi_root)?;
        ensure_non_empty("manifest root", &self.manifest_root)?;
        ensure_non_empty(
            "upgrade authorization root",
            &self.upgrade_authorization_root,
        )?;
        ensure_non_empty("auditor attestation root", &self.auditor_attestation_root)?;
        ensure_non_empty("privacy policy root", &self.privacy_policy_root)?;
        ensure_non_empty(
            "deployment sponsorship root",
            &self.deployment_sponsorship_root,
        )?;
        ensure_non_empty("verifier key root", &self.verifier_key_root)?;
        ensure_non_empty("reproducible build root", &self.reproducible_build_root)?;
        ensure_non_empty(
            "emergency deprecation root",
            &self.emergency_deprecation_root,
        )?;
        ensure_non_empty("defi gate root", &self.defi_gate_root)?;
        ensure_non_empty("active contract root", &self.active_contract_root)?;
        ensure_non_empty(
            "emergency disabled contract root",
            &self.emergency_disabled_contract_root,
        )?;
        Ok(self.aggregate_root())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerificationRegistryCounters {
    pub contract_count: u64,
    pub verified_contract_count: u64,
    pub live_contract_count: u64,
    pub deprecated_contract_count: u64,
    pub emergency_disabled_contract_count: u64,
    pub abi_count: u64,
    pub manifest_count: u64,
    pub usable_manifest_count: u64,
    pub upgrade_authorization_count: u64,
    pub executable_upgrade_count: u64,
    pub auditor_attestation_count: u64,
    pub active_auditor_attestation_count: u64,
    pub privacy_policy_count: u64,
    pub active_privacy_policy_count: u64,
    pub sponsorship_count: u64,
    pub active_sponsorship_count: u64,
    pub verifier_key_count: u64,
    pub active_verifier_key_count: u64,
    pub reproducible_build_count: u64,
    pub verified_build_count: u64,
    pub deprecation_count: u64,
    pub active_deprecation_count: u64,
    pub defi_gate_count: u64,
    pub active_defi_gate_count: u64,
    pub total_sponsor_budget_units: u64,
    pub total_sponsor_reserved_units: u64,
    pub total_sponsor_spent_units: u64,
    pub total_private_call_budget_per_epoch: u64,
    pub total_private_state_budget_bytes: u64,
}

impl ContractVerificationRegistryCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_verification_registry_counters",
            "contract_count": self.contract_count,
            "verified_contract_count": self.verified_contract_count,
            "live_contract_count": self.live_contract_count,
            "deprecated_contract_count": self.deprecated_contract_count,
            "emergency_disabled_contract_count": self.emergency_disabled_contract_count,
            "abi_count": self.abi_count,
            "manifest_count": self.manifest_count,
            "usable_manifest_count": self.usable_manifest_count,
            "upgrade_authorization_count": self.upgrade_authorization_count,
            "executable_upgrade_count": self.executable_upgrade_count,
            "auditor_attestation_count": self.auditor_attestation_count,
            "active_auditor_attestation_count": self.active_auditor_attestation_count,
            "privacy_policy_count": self.privacy_policy_count,
            "active_privacy_policy_count": self.active_privacy_policy_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "verifier_key_count": self.verifier_key_count,
            "active_verifier_key_count": self.active_verifier_key_count,
            "reproducible_build_count": self.reproducible_build_count,
            "verified_build_count": self.verified_build_count,
            "deprecation_count": self.deprecation_count,
            "active_deprecation_count": self.active_deprecation_count,
            "defi_gate_count": self.defi_gate_count,
            "active_defi_gate_count": self.active_defi_gate_count,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_sponsor_reserved_units": self.total_sponsor_reserved_units,
            "total_sponsor_spent_units": self.total_sponsor_spent_units,
            "total_private_call_budget_per_epoch": self.total_private_call_budget_per_epoch,
            "total_private_state_budget_bytes": self.total_private_state_budget_bytes,
        })
    }

    pub fn root(&self) -> String {
        contract_verification_payload_root("CONTRACT-VERIFICATION-COUNTERS", &self.public_record())
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        if self.verified_contract_count > self.contract_count {
            return Err("verified contract count exceeds total".to_string());
        }
        if self.live_contract_count > self.contract_count {
            return Err("live contract count exceeds total".to_string());
        }
        if self.usable_manifest_count > self.manifest_count {
            return Err("usable manifest count exceeds total".to_string());
        }
        if self.active_auditor_attestation_count > self.auditor_attestation_count {
            return Err("active auditor attestation count exceeds total".to_string());
        }
        if self.active_privacy_policy_count > self.privacy_policy_count {
            return Err("active privacy policy count exceeds total".to_string());
        }
        if self.active_sponsorship_count > self.sponsorship_count {
            return Err("active sponsorship count exceeds total".to_string());
        }
        if self.active_verifier_key_count > self.verifier_key_count {
            return Err("active verifier key count exceeds total".to_string());
        }
        if self.verified_build_count > self.reproducible_build_count {
            return Err("verified build count exceeds total".to_string());
        }
        if self.active_deprecation_count > self.deprecation_count {
            return Err("active deprecation count exceeds total".to_string());
        }
        if self.active_defi_gate_count > self.defi_gate_count {
            return Err("active defi gate count exceeds total".to_string());
        }
        if self
            .total_sponsor_reserved_units
            .saturating_add(self.total_sponsor_spent_units)
            > self.total_sponsor_budget_units
        {
            return Err("sponsorship counters exceed budget".to_string());
        }
        Ok(self.root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerificationRegistryState {
    pub height: u64,
    pub config: ContractVerificationRegistryConfig,
    pub contracts: BTreeMap<String, VerifiedContractRecord>,
    pub abi_commitments: BTreeMap<String, AbiCommitment>,
    pub manifests: BTreeMap<String, BytecodeProofManifest>,
    pub upgrade_authorizations: BTreeMap<String, UpgradeAuthorization>,
    pub auditor_attestations: BTreeMap<String, PqAuditorAttestation>,
    pub privacy_policies: BTreeMap<String, PrivacyBudgetPolicy>,
    pub deployment_sponsorships: BTreeMap<String, DeploymentSponsorship>,
    pub verifier_key_pins: BTreeMap<String, VerifierKeyPin>,
    pub build_records: BTreeMap<String, ReproducibleBuildRecord>,
    pub deprecations: BTreeMap<String, EmergencyDeprecationRecord>,
    pub defi_gates: BTreeMap<String, DefiProtocolAllowlistGate>,
}

impl Default for ContractVerificationRegistryState {
    fn default() -> Self {
        Self::new()
    }
}

impl ContractVerificationRegistryState {
    pub fn new() -> Self {
        Self {
            height: 0,
            config: ContractVerificationRegistryConfig::devnet(),
            contracts: BTreeMap::new(),
            abi_commitments: BTreeMap::new(),
            manifests: BTreeMap::new(),
            upgrade_authorizations: BTreeMap::new(),
            auditor_attestations: BTreeMap::new(),
            privacy_policies: BTreeMap::new(),
            deployment_sponsorships: BTreeMap::new(),
            verifier_key_pins: BTreeMap::new(),
            build_records: BTreeMap::new(),
            deprecations: BTreeMap::new(),
            defi_gates: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: ContractVerificationRegistryConfig,
    ) -> ContractVerificationRegistryResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> ContractVerificationRegistryResult<Self> {
        let mut state = Self::with_config(ContractVerificationRegistryConfig::devnet())?;
        state.set_height(144);

        let owner_label = "devnet-private-amm-owner";
        let deployment_salt = "devnet-private-amm-v1";
        let namespace = "devnet_private_amm";
        let owner_commitment = contract_verification_account_commitment(owner_label);
        let deployment_salt_root = contract_verification_string_root(
            "CONTRACT-VERIFICATION-DEPLOYMENT-SALT",
            deployment_salt,
        );
        let contract_id = verified_contract_id(
            namespace,
            VerifiedContractKind::PrivateAmm.as_str(),
            &owner_commitment,
            &deployment_salt_root,
        );

        let abi = AbiCommitment::new(
            contract_id.clone(),
            &json!({
                "name": "DevnetPrivateAmm",
                "version": 1,
                "methods": ["swap_exact_in", "add_liquidity", "remove_liquidity"],
                "events": ["encrypted_swap", "encrypted_liquidity_change"],
            }),
            vec![
                "swap_exact_in".to_string(),
                "add_liquidity".to_string(),
                "remove_liquidity".to_string(),
            ],
            vec![
                "encrypted_swap".to_string(),
                "encrypted_liquidity_change".to_string(),
            ],
            vec!["slippage_bound".to_string(), "pool_paused".to_string()],
            &json!({
                "selector_hash": "devnet-private-amm-selector-root",
                "private_args": true,
            }),
            state.height,
            1,
        )?;
        let abi_id = state.insert_abi_commitment(abi)?;

        let verifier_key_root =
            contract_verification_string_root("DEVNET-VERIFIER-KEY", "private-amm-v1");
        let proof_program_hash =
            contract_verification_string_root("DEVNET-PROOF-PROGRAM", "private-amm-program-v1");
        let mut manifest = BytecodeProofManifest::new(
            contract_id.clone(),
            ProofManifestKind::Deployment,
            b"nebula-devnet-private-amm-bytecode-v1",
            &json!({
                "proofs": ["state_transition", "swap_invariant", "token_conservation"],
                "recursive": true,
                "privacy": "shielded_call",
            }),
            "nebula-plonkish-shake256-devnet",
            proof_program_hash,
            verifier_key_root.clone(),
            &json!({
                "pool": "wxmr-usd-private",
                "reserve_commitments": ["wxmr-reserve", "usd-reserve"],
            }),
            vec![
                "serde-json-canonicalizer-devnet".to_string(),
                "nebula-private-amm-core".to_string(),
            ],
            vec![
                "private_amm.wasm".to_string(),
                "private_amm.proof_manifest.json".to_string(),
            ],
            &json!({
                "repository": "nebula",
                "path": "utils/nebula_l2_rs/examples/private_amm",
                "commit": "devnet-local",
            }),
            &json!({
                "profile": "devnet",
                "optimization": "deterministic",
            }),
            state.height,
            1,
        )?;
        manifest.status = ManifestStatus::Verified;
        let manifest_id = state.insert_manifest(manifest)?;

        let mut upgrade_manifest = BytecodeProofManifest::new(
            contract_id.clone(),
            ProofManifestKind::Upgrade,
            b"nebula-devnet-private-amm-bytecode-v2",
            &json!({
                "proofs": ["state_transition", "swap_invariant", "fee_sponsor_bound"],
                "recursive": true,
                "privacy": "shielded_call",
            }),
            "nebula-plonkish-shake256-devnet",
            contract_verification_string_root("DEVNET-PROOF-PROGRAM", "private-amm-program-v2"),
            verifier_key_root.clone(),
            &json!({
                "pool": "wxmr-usd-private",
                "reserve_commitments": ["wxmr-reserve", "usd-reserve"],
                "fee_controller": "bounded",
            }),
            vec![
                "serde-json-canonicalizer-devnet".to_string(),
                "nebula-private-amm-core".to_string(),
            ],
            vec![
                "private_amm_v2.wasm".to_string(),
                "private_amm_v2.proof_manifest.json".to_string(),
            ],
            &json!({
                "repository": "nebula",
                "path": "utils/nebula_l2_rs/examples/private_amm_v2",
                "commit": "devnet-local",
            }),
            &json!({
                "profile": "devnet",
                "optimization": "deterministic",
                "upgrade": true,
            }),
            state.height.saturating_add(1),
            2,
        )?;
        upgrade_manifest.status = ManifestStatus::Pinned;
        let upgrade_manifest_id = state.insert_manifest(upgrade_manifest)?;

        let verifier_key_pin = VerifierKeyPin::new(
            contract_id.clone(),
            "private_amm_state_transition_v1",
            "nebula-plonkish-shake256-devnet",
            verifier_key_root,
            vec![manifest_id.clone(), upgrade_manifest_id.clone()],
            "devnet-verifier-key-council",
            state.height,
            state
                .height
                .saturating_add(state.config.default_auditor_attestation_ttl_blocks),
            1,
        )?;
        let verifier_key_pin_id = state.insert_verifier_key_pin(verifier_key_pin)?;

        let manifest_record = state
            .manifests
            .get(&manifest_id)
            .ok_or_else(|| "devnet manifest missing".to_string())?
            .clone();
        let build = ReproducibleBuildRecord::new(
            contract_id.clone(),
            manifest_id.clone(),
            &json!({
                "repository": "nebula",
                "commit": "devnet-local",
                "source_root": "private-amm-source-root",
            }),
            &json!({
                "rust": "1.87-devnet",
                "wasm_toolchain": "deterministic-wasm32",
                "zk_compiler": "nebula-circuitc-devnet",
            }),
            &json!({
                "lockfile": "Cargo.lock",
                "dependency_root": manifest_record.dependency_root,
            }),
            &json!({
                "os": "reproducible-container",
                "locale": "C",
                "timezone": "UTC",
            }),
            manifest_record.bytecode_root,
            manifest_record.proof_manifest_root,
            "devnet-repro-builder",
            &json!({
                "status": "reproduced",
                "artifacts": ["private_amm.wasm", "private_amm.proof_manifest.json"],
            }),
            state.height,
            3,
            state.config.build_reproduction_quorum,
        )?;
        let build_id = state.insert_build_record(build)?;

        let privacy_policy = PrivacyBudgetPolicy::new(
            contract_id.clone(),
            PrivacyBudgetMode::AuditorEnforced,
            state.config.default_privacy_epoch_blocks,
            50_000,
            64 * 1024 * 1024,
            8 * 1024 * 1024,
            250,
            state.config.default_privacy_audit_window_blocks,
            vec!["devnet-nullifier-set-amm".to_string()],
            &json!({
                "view_key_access": "auditor-threshold",
                "threshold": 2,
                "disclosure": "aggregate-only",
            }),
            vec![
                "devnet-auditor-alpha".to_string(),
                "devnet-auditor-beta".to_string(),
            ],
            &json!({
                "budget_class": "small-defi",
                "confidential_state": true,
            }),
            state.height,
            state
                .height
                .saturating_add(state.config.default_auditor_attestation_ttl_blocks),
        )?;
        let privacy_policy_id = state.insert_privacy_policy(privacy_policy)?;

        let sponsorship = DeploymentSponsorship::new(
            contract_id.clone(),
            "devnet-low-fee-sponsor",
            state.config.default_fee_asset_id.clone(),
            state.config.default_low_fee_lane.clone(),
            250_000,
            25_000,
            4,
            state.height.saturating_sub(12),
            state
                .height
                .saturating_add(state.config.default_sponsor_ttl_blocks),
            &json!({
                "lane": state.config.default_low_fee_lane,
                "reason": "devnet private contract bootstrap",
            }),
        )?;
        let sponsorship_id = state.insert_deployment_sponsorship(sponsorship)?;

        let defi_gate = DefiProtocolAllowlistGate::new(
            "devnet-private-amm",
            contract_id.clone(),
            DefiProtocolKind::Amm,
            vec![
                "swap_exact_in".to_string(),
                "add_liquidity".to_string(),
                "remove_liquidity".to_string(),
            ],
            vec!["wxmr-devnet".to_string(), "usd-private-devnet".to_string()],
            vec![
                "devnet-market-maker".to_string(),
                "devnet-routing-committee".to_string(),
            ],
            &json!({
                "oracle_deviation_bps": 500,
                "max_pool_imbalance_bps": 2_000,
                "requires_sponsorship": true,
            }),
            state.config.min_audit_score_bps,
            5_000_000_000,
            true,
            state.height.saturating_sub(12),
            state
                .height
                .saturating_add(state.config.default_auditor_attestation_ttl_blocks),
            state.height,
            &json!({
                "risk_tier": "devnet-small-defi",
                "private_router": true,
            }),
        )?;
        let defi_gate_id = state.insert_defi_gate(defi_gate)?;

        let mut contract = VerifiedContractRecord::new(
            namespace,
            VerifiedContractKind::PrivateAmm,
            owner_label,
            deployment_salt,
            abi_id,
            manifest_id.clone(),
            verifier_key_pin_id.clone(),
            privacy_policy_id.clone(),
            sponsorship_id,
            build_id.clone(),
            defi_gate_id.clone(),
            &json!({
                "display": "Devnet Private AMM",
                "confidential": true,
                "asset_pair": "wxmr/usd-private",
            }),
            1,
            state.height,
        )?;
        contract.status = ContractVerificationStatus::Verified;
        let verified_contract_id = state.insert_contract(contract)?;

        let attestation = PqAuditorAttestation::new(
            "devnet-auditor-alpha",
            verified_contract_id.clone(),
            manifest_id.clone(),
            verifier_key_pin_id.clone(),
            build_id,
            privacy_policy_id,
            defi_gate_id,
            AuditorScope::DefiRisk,
            &json!({
                "open_critical_findings": 0,
                "open_high_findings": 0,
                "notes": "devnet risk profile accepted",
            }),
            &json!({
                "contract_id": verified_contract_id,
                "manifest_id": manifest_id,
                "statement": "private AMM manifest and privacy budgets match devnet policy",
            }),
            9_300,
            contract_verification_string_root("DEVNET-AUDITOR-PQ-PUBLIC-KEY", "auditor-alpha"),
            contract_verification_string_root("DEVNET-AUDITOR-PQ-SIGNATURE", "auditor-alpha-sig"),
            state.height,
            state.config.default_auditor_attestation_ttl_blocks,
        )?;
        state.insert_auditor_attestation(attestation)?;

        let mut upgrade = UpgradeAuthorization::new(
            contract_id.clone(),
            manifest_id,
            upgrade_manifest_id,
            1,
            2,
            "devnet-upgrade-council",
            &json!({
                "vote_root": "devnet-upgrade-vote-root",
                "approval_bps": 9_000,
            }),
            &json!({
                "storage_migration": "identity",
                "rollback_window_blocks": 96,
            }),
            verifier_key_pin_id,
            state
                .height
                .saturating_sub(state.config.default_upgrade_timelock_blocks),
            state.config.default_upgrade_timelock_blocks,
            state.config.default_upgrade_expiry_blocks,
            false,
            7,
        )?;
        upgrade.status = UpgradeAuthorizationStatus::Authorized;
        state.insert_upgrade_authorization(upgrade)?;

        let mut advisory = EmergencyDeprecationRecord::new(
            contract_id,
            DeprecationScope::Abi,
            DeprecationSeverity::Advisory,
            &json!({
                "reason": "legacy event name will be retired after v2",
            }),
            &json!({
                "tracking_issue": "devnet-abi-advisory-1",
            }),
            "",
            "devnet-security-council",
            state.height.saturating_add(720),
            state.height.saturating_add(1_440),
            1,
        )?;
        advisory.status = DeprecationStatus::Proposed;
        state.insert_deprecation(advisory)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for sponsorship in self.deployment_sponsorships.values_mut() {
            if self.height > sponsorship.valid_until_height && sponsorship.status.can_spend() {
                sponsorship.status = DeploymentSponsorStatus::Expired;
            }
            if sponsorship.available_units() == 0 && sponsorship.reserved_units == 0 {
                sponsorship.status = DeploymentSponsorStatus::Exhausted;
            }
        }
        for pin in self.verifier_key_pins.values_mut() {
            if pin.expires_at_height != 0
                && self.height > pin.expires_at_height
                && pin.status.is_pinned()
            {
                pin.status = VerifierKeyStatus::Expired;
            }
        }
        for attestation in self.auditor_attestations.values_mut() {
            if self.height > attestation.expires_at_height
                && matches!(
                    attestation.status,
                    AuditorAttestationStatus::Pending | AuditorAttestationStatus::Accepted
                )
            {
                attestation.status = AuditorAttestationStatus::Expired;
            }
        }
        for policy in self.privacy_policies.values_mut() {
            if policy.expires_at_height != 0
                && self.height > policy.expires_at_height
                && policy.status.is_active()
            {
                policy.status = PrivacyPolicyStatus::Expired;
            }
        }
        for gate in self.defi_gates.values_mut() {
            if self.height > gate.valid_until_height && gate.status.allows() {
                gate.status = DefiGateStatus::Retired;
            }
        }
        for upgrade in self.upgrade_authorizations.values_mut() {
            if upgrade.status == UpgradeAuthorizationStatus::Timelocked
                && self.height >= upgrade.executable_at_height
            {
                upgrade.status = UpgradeAuthorizationStatus::Authorized;
            }
            if upgrade.status.is_open() && self.height > upgrade.expires_at_height {
                upgrade.status = UpgradeAuthorizationStatus::Expired;
            }
        }
        let halted_contracts = self
            .deprecations
            .values()
            .filter(|record| record.is_active_at(self.height) && record.severity.halts_contract())
            .map(|record| record.contract_id.clone())
            .collect::<BTreeSet<_>>();
        for contract in self.contracts.values_mut() {
            if halted_contracts.contains(&contract.contract_id) && contract.status.is_live() {
                contract.status = ContractVerificationStatus::EmergencyDisabled;
                contract.updated_at_height = self.height;
            }
        }
    }

    pub fn insert_contract(
        &mut self,
        record: VerifiedContractRecord,
    ) -> ContractVerificationRegistryResult<String> {
        let contract_id = record.contract_id.clone();
        record.validate()?;
        if self.contracts.contains_key(&contract_id) {
            return Err("contract already exists".to_string());
        }
        self.validate_contract_references(&record)?;
        if !record.sponsorship_id.is_empty() {
            let sponsorship = self
                .deployment_sponsorships
                .get_mut(&record.sponsorship_id)
                .ok_or_else(|| "contract sponsorship missing".to_string())?;
            if sponsorship.contract_id != record.contract_id {
                return Err("contract sponsorship id mismatch".to_string());
            }
            if sponsorship.sponsored_contract_count == 0 {
                sponsorship.reserve_deployment(self.height)?;
            }
        }
        self.contracts.insert(contract_id.clone(), record);
        Ok(contract_id)
    }

    pub fn insert_abi_commitment(
        &mut self,
        record: AbiCommitment,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.abi_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.abi_commitments, id, record, "abi commitment")
    }

    pub fn insert_manifest(
        &mut self,
        record: BytecodeProofManifest,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.manifest_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.manifests, id, record, "manifest")
    }

    pub fn insert_upgrade_authorization(
        &mut self,
        record: UpgradeAuthorization,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.authorization_id.clone();
        record.validate()?;
        self.validate_upgrade_references(&record)?;
        insert_unique_record(
            &mut self.upgrade_authorizations,
            id,
            record,
            "upgrade authorization",
        )
    }

    pub fn insert_auditor_attestation(
        &mut self,
        record: PqAuditorAttestation,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.attestation_id.clone();
        record.validate()?;
        self.validate_attestation_references(&record)?;
        insert_unique_record(
            &mut self.auditor_attestations,
            id,
            record,
            "auditor attestation",
        )
    }

    pub fn insert_privacy_policy(
        &mut self,
        record: PrivacyBudgetPolicy,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.policy_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.privacy_policies, id, record, "privacy policy")
    }

    pub fn insert_deployment_sponsorship(
        &mut self,
        record: DeploymentSponsorship,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.sponsorship_id.clone();
        record.validate()?;
        insert_unique_record(
            &mut self.deployment_sponsorships,
            id,
            record,
            "deployment sponsorship",
        )
    }

    pub fn insert_verifier_key_pin(
        &mut self,
        record: VerifierKeyPin,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.pin_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.verifier_key_pins, id, record, "verifier key pin")
    }

    pub fn insert_build_record(
        &mut self,
        record: ReproducibleBuildRecord,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.build_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.build_records, id, record, "build record")
    }

    pub fn insert_deprecation(
        &mut self,
        record: EmergencyDeprecationRecord,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.deprecation_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.deprecations, id, record, "deprecation")
    }

    pub fn insert_defi_gate(
        &mut self,
        record: DefiProtocolAllowlistGate,
    ) -> ContractVerificationRegistryResult<String> {
        let id = record.gate_id.clone();
        record.validate()?;
        insert_unique_record(&mut self.defi_gates, id, record, "defi gate")
    }

    pub fn active_contract_ids(&self) -> Vec<String> {
        self.contracts
            .values()
            .filter(|contract| contract.is_live())
            .map(|contract| contract.contract_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn emergency_disabled_contract_ids(&self) -> Vec<String> {
        self.contracts
            .values()
            .filter(|contract| {
                contract.status == ContractVerificationStatus::EmergencyDisabled
                    || contract.status == ContractVerificationStatus::Revoked
            })
            .map(|contract| contract.contract_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_contract_root(&self) -> String {
        let leaves = self
            .active_contract_ids()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        merkle_root("CONTRACT-VERIFICATION-ACTIVE-CONTRACT", &leaves)
    }

    pub fn emergency_disabled_contract_root(&self) -> String {
        let leaves = self
            .emergency_disabled_contract_ids()
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        merkle_root("CONTRACT-VERIFICATION-EMERGENCY-DISABLED-CONTRACT", &leaves)
    }

    pub fn contract_root(&self) -> String {
        contract_verification_contract_set_root(&self.contracts)
    }

    pub fn abi_root(&self) -> String {
        contract_verification_abi_set_root(&self.abi_commitments)
    }

    pub fn manifest_root(&self) -> String {
        contract_verification_manifest_set_root(&self.manifests)
    }

    pub fn upgrade_authorization_root(&self) -> String {
        contract_verification_upgrade_set_root(&self.upgrade_authorizations)
    }

    pub fn auditor_attestation_root(&self) -> String {
        contract_verification_attestation_set_root(&self.auditor_attestations)
    }

    pub fn privacy_policy_root(&self) -> String {
        contract_verification_privacy_policy_set_root(&self.privacy_policies)
    }

    pub fn deployment_sponsorship_root(&self) -> String {
        contract_verification_sponsorship_set_root(&self.deployment_sponsorships)
    }

    pub fn verifier_key_root(&self) -> String {
        contract_verification_verifier_key_set_root(&self.verifier_key_pins)
    }

    pub fn reproducible_build_root(&self) -> String {
        contract_verification_build_set_root(&self.build_records)
    }

    pub fn emergency_deprecation_root(&self) -> String {
        contract_verification_deprecation_set_root(&self.deprecations)
    }

    pub fn defi_gate_root(&self) -> String {
        contract_verification_defi_gate_set_root(&self.defi_gates)
    }

    pub fn roots(&self) -> ContractVerificationRegistryRoots {
        ContractVerificationRegistryRoots {
            config_root: self.config.root(),
            contract_root: self.contract_root(),
            abi_root: self.abi_root(),
            manifest_root: self.manifest_root(),
            upgrade_authorization_root: self.upgrade_authorization_root(),
            auditor_attestation_root: self.auditor_attestation_root(),
            privacy_policy_root: self.privacy_policy_root(),
            deployment_sponsorship_root: self.deployment_sponsorship_root(),
            verifier_key_root: self.verifier_key_root(),
            reproducible_build_root: self.reproducible_build_root(),
            emergency_deprecation_root: self.emergency_deprecation_root(),
            defi_gate_root: self.defi_gate_root(),
            active_contract_root: self.active_contract_root(),
            emergency_disabled_contract_root: self.emergency_disabled_contract_root(),
        }
    }

    pub fn counters(&self) -> ContractVerificationRegistryCounters {
        let mut counters = ContractVerificationRegistryCounters {
            contract_count: self.contracts.len() as u64,
            abi_count: self.abi_commitments.len() as u64,
            manifest_count: self.manifests.len() as u64,
            upgrade_authorization_count: self.upgrade_authorizations.len() as u64,
            auditor_attestation_count: self.auditor_attestations.len() as u64,
            privacy_policy_count: self.privacy_policies.len() as u64,
            sponsorship_count: self.deployment_sponsorships.len() as u64,
            verifier_key_count: self.verifier_key_pins.len() as u64,
            reproducible_build_count: self.build_records.len() as u64,
            deprecation_count: self.deprecations.len() as u64,
            defi_gate_count: self.defi_gates.len() as u64,
            ..ContractVerificationRegistryCounters::default()
        };
        for contract in self.contracts.values() {
            if contract.status.is_verified() {
                counters.verified_contract_count =
                    counters.verified_contract_count.saturating_add(1);
            }
            if contract.status.is_live() {
                counters.live_contract_count = counters.live_contract_count.saturating_add(1);
            }
            if contract.status == ContractVerificationStatus::Deprecated {
                counters.deprecated_contract_count =
                    counters.deprecated_contract_count.saturating_add(1);
            }
            if contract.status == ContractVerificationStatus::EmergencyDisabled {
                counters.emergency_disabled_contract_count =
                    counters.emergency_disabled_contract_count.saturating_add(1);
            }
        }
        for manifest in self.manifests.values() {
            if manifest.status.is_usable() {
                counters.usable_manifest_count = counters.usable_manifest_count.saturating_add(1);
            }
        }
        for upgrade in self.upgrade_authorizations.values() {
            if upgrade.is_executable_at(self.height) {
                counters.executable_upgrade_count =
                    counters.executable_upgrade_count.saturating_add(1);
            }
        }
        for attestation in self.auditor_attestations.values() {
            if attestation.is_active_at(self.height) {
                counters.active_auditor_attestation_count =
                    counters.active_auditor_attestation_count.saturating_add(1);
            }
        }
        for policy in self.privacy_policies.values() {
            if policy.is_active_at(self.height) {
                counters.active_privacy_policy_count =
                    counters.active_privacy_policy_count.saturating_add(1);
            }
            counters.total_private_call_budget_per_epoch = counters
                .total_private_call_budget_per_epoch
                .saturating_add(policy.max_private_calls_per_epoch);
            counters.total_private_state_budget_bytes = counters
                .total_private_state_budget_bytes
                .saturating_add(policy.max_private_state_bytes);
        }
        for sponsorship in self.deployment_sponsorships.values() {
            if sponsorship.is_active_at(self.height) {
                counters.active_sponsorship_count =
                    counters.active_sponsorship_count.saturating_add(1);
            }
            counters.total_sponsor_budget_units = counters
                .total_sponsor_budget_units
                .saturating_add(sponsorship.budget_units);
            counters.total_sponsor_reserved_units = counters
                .total_sponsor_reserved_units
                .saturating_add(sponsorship.reserved_units);
            counters.total_sponsor_spent_units = counters
                .total_sponsor_spent_units
                .saturating_add(sponsorship.spent_units);
        }
        for pin in self.verifier_key_pins.values() {
            if pin.is_active_at(self.height) {
                counters.active_verifier_key_count =
                    counters.active_verifier_key_count.saturating_add(1);
            }
        }
        for build in self.build_records.values() {
            if build.status.verifies() {
                counters.verified_build_count = counters.verified_build_count.saturating_add(1);
            }
        }
        for deprecation in self.deprecations.values() {
            if deprecation.is_active_at(self.height) {
                counters.active_deprecation_count =
                    counters.active_deprecation_count.saturating_add(1);
            }
        }
        for gate in self.defi_gates.values() {
            if gate.is_active_at(self.height) {
                counters.active_defi_gate_count = counters.active_defi_gate_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        contract_verification_payload_root(
            "CONTRACT-VERIFICATION-REGISTRY-STATE",
            &self.public_record_without_state_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "contract_verification_registry_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn validate(&self) -> ContractVerificationRegistryResult<String> {
        self.config.validate()?;
        let roots = self.roots();
        roots.validate()?;
        let counters = self.counters();
        counters.validate()?;

        let mut contract_namespaces = BTreeSet::<String>::new();
        for (id, contract) in &self.contracts {
            if id != &contract.contract_id {
                return Err("contract map key mismatch".to_string());
            }
            contract.validate()?;
            if !contract_namespaces.insert(contract.namespace.clone()) {
                return Err("contract namespace duplicated".to_string());
            }
            self.validate_contract_references(contract)?;
            if contract.status.is_verified() {
                self.ensure_contract_has_active_attestations(contract)?;
            }
        }

        for (id, abi) in &self.abi_commitments {
            if id != &abi.abi_id {
                return Err("abi map key mismatch".to_string());
            }
            abi.validate()?;
        }

        let mut bytecode_roots = BTreeSet::<String>::new();
        for (id, manifest) in &self.manifests {
            if id != &manifest.manifest_id {
                return Err("manifest map key mismatch".to_string());
            }
            manifest.validate()?;
            if manifest.status.is_usable() && !bytecode_roots.insert(manifest.bytecode_root.clone())
            {
                return Err("usable manifest bytecode root duplicated".to_string());
            }
        }

        for (id, pin) in &self.verifier_key_pins {
            if id != &pin.pin_id {
                return Err("verifier key map key mismatch".to_string());
            }
            pin.validate()?;
            for manifest_id in &pin.allowed_manifest_ids {
                let manifest = self
                    .manifests
                    .get(manifest_id)
                    .ok_or_else(|| "verifier key references missing manifest".to_string())?;
                if manifest.contract_id != pin.contract_id {
                    return Err("verifier key manifest contract mismatch".to_string());
                }
            }
        }

        for (id, build) in &self.build_records {
            if id != &build.build_id {
                return Err("build map key mismatch".to_string());
            }
            build.validate()?;
            let manifest = self
                .manifests
                .get(&build.manifest_id)
                .ok_or_else(|| "build references missing manifest".to_string())?;
            if manifest.contract_id != build.contract_id {
                return Err("build manifest contract mismatch".to_string());
            }
            if build.output_bytecode_root != manifest.bytecode_root {
                return Err("build bytecode root mismatch".to_string());
            }
            if build.output_manifest_root != manifest.proof_manifest_root {
                return Err("build proof manifest root mismatch".to_string());
            }
        }

        for (id, policy) in &self.privacy_policies {
            if id != &policy.policy_id {
                return Err("privacy policy map key mismatch".to_string());
            }
            policy.validate()?;
            if policy.max_view_key_disclosure_bps > self.config.max_privacy_disclosure_bps {
                return Err("privacy policy disclosure exceeds registry bound".to_string());
            }
        }

        for (id, sponsorship) in &self.deployment_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
        }

        for (id, gate) in &self.defi_gates {
            if id != &gate.gate_id {
                return Err("defi gate map key mismatch".to_string());
            }
            gate.validate()?;
            if gate.min_audit_score_bps < self.config.min_audit_score_bps {
                return Err("defi gate audit score floor below registry floor".to_string());
            }
        }

        for (id, attestation) in &self.auditor_attestations {
            if id != &attestation.attestation_id {
                return Err("attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            self.validate_attestation_references(attestation)?;
        }

        for (id, upgrade) in &self.upgrade_authorizations {
            if id != &upgrade.authorization_id {
                return Err("upgrade map key mismatch".to_string());
            }
            upgrade.validate()?;
            self.validate_upgrade_references(upgrade)?;
        }

        for (id, deprecation) in &self.deprecations {
            if id != &deprecation.deprecation_id {
                return Err("deprecation map key mismatch".to_string());
            }
            deprecation.validate()?;
            if !self.contracts.contains_key(&deprecation.contract_id) {
                return Err("deprecation references missing contract".to_string());
            }
            if deprecation.is_active_at(self.height) && deprecation.severity.halts_contract() {
                let contract = self
                    .contracts
                    .get(&deprecation.contract_id)
                    .ok_or_else(|| "deprecation contract missing".to_string())?;
                if contract.status.is_live() {
                    return Err("halting deprecation leaves contract live".to_string());
                }
            }
        }

        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "contract_verification_registry_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    fn validate_contract_references(
        &self,
        contract: &VerifiedContractRecord,
    ) -> ContractVerificationRegistryResult<()> {
        let abi = self
            .abi_commitments
            .get(&contract.abi_id)
            .ok_or_else(|| "contract abi missing".to_string())?;
        if abi.contract_id != contract.contract_id {
            return Err("contract abi reference mismatch".to_string());
        }
        let manifest = self
            .manifests
            .get(&contract.active_manifest_id)
            .ok_or_else(|| "contract manifest missing".to_string())?;
        if manifest.contract_id != contract.contract_id {
            return Err("contract manifest reference mismatch".to_string());
        }
        if !manifest.status.is_usable() && contract.status.is_live() {
            return Err("contract manifest is not usable".to_string());
        }
        let pin = self
            .verifier_key_pins
            .get(&contract.verifier_key_pin_id)
            .ok_or_else(|| "contract verifier key missing".to_string())?;
        if pin.contract_id != contract.contract_id {
            return Err("contract verifier key reference mismatch".to_string());
        }
        if !pin.allows_manifest(&contract.active_manifest_id) {
            return Err("contract manifest not allowed by verifier key".to_string());
        }
        let policy = self
            .privacy_policies
            .get(&contract.privacy_policy_id)
            .ok_or_else(|| "contract privacy policy missing".to_string())?;
        if policy.contract_id != contract.contract_id {
            return Err("contract privacy policy reference mismatch".to_string());
        }
        if contract.status.is_live() && !policy.is_active_at(self.height) {
            return Err("contract privacy policy inactive".to_string());
        }
        let build = self
            .build_records
            .get(&contract.build_id)
            .ok_or_else(|| "contract build record missing".to_string())?;
        if build.contract_id != contract.contract_id {
            return Err("contract build reference mismatch".to_string());
        }
        if build.manifest_id != contract.active_manifest_id {
            return Err("contract build manifest mismatch".to_string());
        }
        if contract.status.is_live() && !build.status.verifies() {
            return Err("contract build not verified".to_string());
        }
        if !contract.sponsorship_id.is_empty() {
            let sponsorship = self
                .deployment_sponsorships
                .get(&contract.sponsorship_id)
                .ok_or_else(|| "contract sponsorship missing".to_string())?;
            if sponsorship.contract_id != contract.contract_id {
                return Err("contract sponsorship reference mismatch".to_string());
            }
        }
        if !contract.defi_gate_id.is_empty() {
            let gate = self
                .defi_gates
                .get(&contract.defi_gate_id)
                .ok_or_else(|| "contract defi gate missing".to_string())?;
            if gate.contract_id != contract.contract_id {
                return Err("contract defi gate reference mismatch".to_string());
            }
            if contract.status.is_live()
                && gate.sponsor_required
                && contract.sponsorship_id.is_empty()
            {
                return Err("contract defi gate requires sponsorship".to_string());
            }
        }
        Ok(())
    }

    fn validate_attestation_references(
        &self,
        attestation: &PqAuditorAttestation,
    ) -> ContractVerificationRegistryResult<()> {
        if !self.contracts.contains_key(&attestation.contract_id) {
            return Err("attestation contract missing".to_string());
        }
        let manifest = self
            .manifests
            .get(&attestation.manifest_id)
            .ok_or_else(|| "attestation manifest missing".to_string())?;
        if manifest.contract_id != attestation.contract_id {
            return Err("attestation manifest contract mismatch".to_string());
        }
        let pin = self
            .verifier_key_pins
            .get(&attestation.verifier_key_pin_id)
            .ok_or_else(|| "attestation verifier key missing".to_string())?;
        if pin.contract_id != attestation.contract_id {
            return Err("attestation verifier key contract mismatch".to_string());
        }
        let build = self
            .build_records
            .get(&attestation.build_id)
            .ok_or_else(|| "attestation build missing".to_string())?;
        if build.contract_id != attestation.contract_id {
            return Err("attestation build contract mismatch".to_string());
        }
        let policy = self
            .privacy_policies
            .get(&attestation.privacy_policy_id)
            .ok_or_else(|| "attestation privacy policy missing".to_string())?;
        if policy.contract_id != attestation.contract_id {
            return Err("attestation privacy policy contract mismatch".to_string());
        }
        if !attestation.defi_gate_id.is_empty() {
            let gate = self
                .defi_gates
                .get(&attestation.defi_gate_id)
                .ok_or_else(|| "attestation defi gate missing".to_string())?;
            if gate.contract_id != attestation.contract_id {
                return Err("attestation defi gate contract mismatch".to_string());
            }
        }
        Ok(())
    }

    fn validate_upgrade_references(
        &self,
        upgrade: &UpgradeAuthorization,
    ) -> ContractVerificationRegistryResult<()> {
        let from_manifest = self
            .manifests
            .get(&upgrade.from_manifest_id)
            .ok_or_else(|| "upgrade from manifest missing".to_string())?;
        let to_manifest = self
            .manifests
            .get(&upgrade.to_manifest_id)
            .ok_or_else(|| "upgrade to manifest missing".to_string())?;
        if from_manifest.contract_id != upgrade.contract_id
            || to_manifest.contract_id != upgrade.contract_id
        {
            return Err("upgrade manifest contract mismatch".to_string());
        }
        if from_manifest.version != upgrade.from_version
            || to_manifest.version != upgrade.to_version
        {
            return Err("upgrade manifest version mismatch".to_string());
        }
        let pin = self
            .verifier_key_pins
            .get(&upgrade.verifier_key_pin_id)
            .ok_or_else(|| "upgrade verifier key missing".to_string())?;
        if pin.contract_id != upgrade.contract_id {
            return Err("upgrade verifier key contract mismatch".to_string());
        }
        if !pin.allows_manifest(&upgrade.to_manifest_id) {
            return Err("upgrade target manifest not allowed by verifier key".to_string());
        }
        Ok(())
    }

    fn ensure_contract_has_active_attestations(
        &self,
        contract: &VerifiedContractRecord,
    ) -> ContractVerificationRegistryResult<()> {
        let active_count = self
            .auditor_attestations
            .values()
            .filter(|attestation| {
                attestation.contract_id == contract.contract_id
                    && attestation.manifest_id == contract.active_manifest_id
                    && attestation.audit_score_bps >= self.config.min_audit_score_bps
                    && attestation.is_active_at(self.height)
            })
            .count() as u64;
        if active_count < self.config.min_active_auditor_attestations {
            return Err("verified contract lacks active auditor attestations".to_string());
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn abi_commitment_identity_record(
    contract_id: &str,
    abi_schema_root: &str,
    interface_root: &str,
    selector_root: &str,
    event_root: &str,
    error_root: &str,
    entrypoint_count: u64,
    metadata_root: &str,
    created_at_height: u64,
    version: u64,
) -> Value {
    json!({
        "kind": "abi_commitment_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "abi_schema_root": abi_schema_root,
        "interface_root": interface_root,
        "selector_root": selector_root,
        "event_root": event_root,
        "error_root": error_root,
        "entrypoint_count": entrypoint_count,
        "metadata_root": metadata_root,
        "created_at_height": created_at_height,
        "version": version,
    })
}

#[allow(clippy::too_many_arguments)]
fn bytecode_manifest_identity_record(
    contract_id: &str,
    manifest_kind: &str,
    bytecode_root: &str,
    bytecode_size_bytes: u64,
    proof_manifest_root: &str,
    proof_system: &str,
    proof_program_hash: &str,
    verifier_key_root: &str,
    init_state_root: &str,
    dependency_root: &str,
    artifact_root: &str,
    source_ref_root: &str,
    metadata_root: &str,
    created_at_height: u64,
    version: u64,
) -> Value {
    json!({
        "kind": "bytecode_proof_manifest_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "manifest_kind": manifest_kind,
        "bytecode_root": bytecode_root,
        "bytecode_size_bytes": bytecode_size_bytes,
        "proof_manifest_root": proof_manifest_root,
        "proof_system": proof_system,
        "proof_program_hash": proof_program_hash,
        "verifier_key_root": verifier_key_root,
        "init_state_root": init_state_root,
        "dependency_root": dependency_root,
        "artifact_root": artifact_root,
        "source_ref_root": source_ref_root,
        "metadata_root": metadata_root,
        "created_at_height": created_at_height,
        "version": version,
    })
}

#[allow(clippy::too_many_arguments)]
fn verifier_key_pin_identity_record(
    contract_id: &str,
    circuit_id: &str,
    proof_system: &str,
    verifier_key_root: &str,
    verifier_key_hash: &str,
    allowed_manifest_root: &str,
    pinned_by_commitment: &str,
    pinned_at_height: u64,
    expires_at_height: u64,
    version: u64,
) -> Value {
    json!({
        "kind": "verifier_key_pin_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "circuit_id": circuit_id,
        "proof_system": proof_system,
        "verifier_key_root": verifier_key_root,
        "verifier_key_hash": verifier_key_hash,
        "allowed_manifest_root": allowed_manifest_root,
        "pinned_by_commitment": pinned_by_commitment,
        "pinned_at_height": pinned_at_height,
        "expires_at_height": expires_at_height,
        "version": version,
    })
}

#[allow(clippy::too_many_arguments)]
fn reproducible_build_identity_record(
    contract_id: &str,
    manifest_id: &str,
    source_commitment: &str,
    source_tree_root: &str,
    toolchain_root: &str,
    dependency_lock_root: &str,
    environment_root: &str,
    output_bytecode_root: &str,
    output_manifest_root: &str,
    builder_commitment: &str,
    build_log_root: &str,
    built_at_height: u64,
    reproduction_count: u64,
    quorum_required: u64,
) -> Value {
    json!({
        "kind": "reproducible_build_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "manifest_id": manifest_id,
        "source_commitment": source_commitment,
        "source_tree_root": source_tree_root,
        "toolchain_root": toolchain_root,
        "dependency_lock_root": dependency_lock_root,
        "environment_root": environment_root,
        "output_bytecode_root": output_bytecode_root,
        "output_manifest_root": output_manifest_root,
        "builder_commitment": builder_commitment,
        "build_log_root": build_log_root,
        "built_at_height": built_at_height,
        "reproduction_count": reproduction_count,
        "quorum_required": quorum_required,
    })
}

#[allow(clippy::too_many_arguments)]
fn pq_auditor_attestation_identity_record(
    auditor_commitment: &str,
    contract_id: &str,
    manifest_id: &str,
    verifier_key_pin_id: &str,
    build_id: &str,
    privacy_policy_id: &str,
    defi_gate_id: &str,
    scope: &str,
    attestation_scope_root: &str,
    finding_root: &str,
    audit_score_bps: u64,
    signed_statement_root: &str,
    pq_public_key_root: &str,
    pq_signature_root: &str,
    attested_at_height: u64,
    expires_at_height: u64,
) -> Value {
    json!({
        "kind": "pq_auditor_attestation_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "auditor_commitment": auditor_commitment,
        "contract_id": contract_id,
        "manifest_id": manifest_id,
        "verifier_key_pin_id": verifier_key_pin_id,
        "build_id": build_id,
        "privacy_policy_id": privacy_policy_id,
        "defi_gate_id": defi_gate_id,
        "scope": scope,
        "attestation_scope_root": attestation_scope_root,
        "finding_root": finding_root,
        "audit_score_bps": audit_score_bps,
        "signed_statement_root": signed_statement_root,
        "pq_public_key_root": pq_public_key_root,
        "pq_signature_root": pq_signature_root,
        "attested_at_height": attested_at_height,
        "expires_at_height": expires_at_height,
    })
}

#[allow(clippy::too_many_arguments)]
fn privacy_budget_policy_identity_record(
    contract_id: &str,
    mode: &str,
    epoch_blocks: u64,
    max_private_calls_per_epoch: u64,
    max_private_state_bytes: u64,
    max_private_event_bytes: u64,
    max_view_key_disclosure_bps: u64,
    audit_window_blocks: u64,
    nullifier_root: &str,
    view_key_policy_root: &str,
    auditor_root: &str,
    metadata_root: &str,
    created_at_height: u64,
    expires_at_height: u64,
) -> Value {
    json!({
        "kind": "privacy_budget_policy_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "mode": mode,
        "epoch_blocks": epoch_blocks,
        "max_private_calls_per_epoch": max_private_calls_per_epoch,
        "max_private_state_bytes": max_private_state_bytes,
        "max_private_event_bytes": max_private_event_bytes,
        "max_view_key_disclosure_bps": max_view_key_disclosure_bps,
        "audit_window_blocks": audit_window_blocks,
        "nullifier_root": nullifier_root,
        "view_key_policy_root": view_key_policy_root,
        "auditor_root": auditor_root,
        "metadata_root": metadata_root,
        "created_at_height": created_at_height,
        "expires_at_height": expires_at_height,
    })
}

#[allow(clippy::too_many_arguments)]
fn deployment_sponsorship_identity_record(
    contract_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    low_fee_lane: &str,
    lane_root: &str,
    budget_units: u64,
    per_deployment_cap_units: u64,
    max_contracts: u64,
    valid_from_height: u64,
    valid_until_height: u64,
    policy_root: &str,
) -> Value {
    json!({
        "kind": "deployment_sponsorship_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "sponsor_commitment": sponsor_commitment,
        "fee_asset_id": fee_asset_id,
        "low_fee_lane": low_fee_lane,
        "lane_root": lane_root,
        "budget_units": budget_units,
        "per_deployment_cap_units": per_deployment_cap_units,
        "max_contracts": max_contracts,
        "valid_from_height": valid_from_height,
        "valid_until_height": valid_until_height,
        "policy_root": policy_root,
    })
}

#[allow(clippy::too_many_arguments)]
fn upgrade_authorization_identity_record(
    contract_id: &str,
    from_manifest_id: &str,
    to_manifest_id: &str,
    from_version: u64,
    to_version: u64,
    authorizer_commitment: &str,
    governance_root: &str,
    migration_root: &str,
    verifier_key_pin_id: &str,
    timelock_start_height: u64,
    executable_at_height: u64,
    expires_at_height: u64,
    emergency_override: bool,
    nonce: u64,
) -> Value {
    json!({
        "kind": "upgrade_authorization_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "from_manifest_id": from_manifest_id,
        "to_manifest_id": to_manifest_id,
        "from_version": from_version,
        "to_version": to_version,
        "authorizer_commitment": authorizer_commitment,
        "governance_root": governance_root,
        "migration_root": migration_root,
        "verifier_key_pin_id": verifier_key_pin_id,
        "timelock_start_height": timelock_start_height,
        "executable_at_height": executable_at_height,
        "expires_at_height": expires_at_height,
        "emergency_override": emergency_override,
        "nonce": nonce,
    })
}

#[allow(clippy::too_many_arguments)]
fn emergency_deprecation_identity_record(
    contract_id: &str,
    scope: &str,
    severity: &str,
    reason_root: &str,
    evidence_root: &str,
    replacement_contract_id: &str,
    declared_by_commitment: &str,
    effective_at_height: u64,
    review_until_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "emergency_deprecation_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "scope": scope,
        "severity": severity,
        "reason_root": reason_root,
        "evidence_root": evidence_root,
        "replacement_contract_id": replacement_contract_id,
        "declared_by_commitment": declared_by_commitment,
        "effective_at_height": effective_at_height,
        "review_until_height": review_until_height,
        "nonce": nonce,
    })
}

#[allow(clippy::too_many_arguments)]
fn defi_gate_identity_record(
    protocol_id: &str,
    contract_id: &str,
    protocol_kind: &str,
    allowed_selector_root: &str,
    asset_root: &str,
    counterparty_root: &str,
    risk_policy_root: &str,
    min_audit_score_bps: u64,
    max_tvl_units: u64,
    sponsor_required: bool,
    valid_from_height: u64,
    valid_until_height: u64,
    created_at_height: u64,
    metadata_root: &str,
) -> Value {
    json!({
        "kind": "defi_gate_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "protocol_id": protocol_id,
        "contract_id": contract_id,
        "protocol_kind": protocol_kind,
        "allowed_selector_root": allowed_selector_root,
        "asset_root": asset_root,
        "counterparty_root": counterparty_root,
        "risk_policy_root": risk_policy_root,
        "min_audit_score_bps": min_audit_score_bps,
        "max_tvl_units": max_tvl_units,
        "sponsor_required": sponsor_required,
        "valid_from_height": valid_from_height,
        "valid_until_height": valid_until_height,
        "created_at_height": created_at_height,
        "metadata_root": metadata_root,
    })
}

fn verified_contract_identity_record(
    namespace: &str,
    contract_kind: &str,
    owner_commitment: &str,
    deployment_salt_root: &str,
) -> Value {
    json!({
        "kind": "verified_contract_identity",
        "chain_id": CHAIN_ID,
        "protocol_version": CONTRACT_VERIFICATION_REGISTRY_PROTOCOL_VERSION,
        "namespace": namespace,
        "contract_kind": contract_kind,
        "owner_commitment": owner_commitment,
        "deployment_salt_root": deployment_salt_root,
    })
}

pub fn abi_commitment_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-ABI-ID", record)
}

pub fn bytecode_manifest_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-MANIFEST-ID", record)
}

pub fn verifier_key_pin_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-VERIFIER-KEY-ID", record)
}

pub fn reproducible_build_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-BUILD-ID", record)
}

pub fn pq_auditor_attestation_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-AUDITOR-ATTESTATION-ID", record)
}

pub fn privacy_budget_policy_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-PRIVACY-POLICY-ID", record)
}

pub fn deployment_sponsorship_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-SPONSORSHIP-ID", record)
}

pub fn upgrade_authorization_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-UPGRADE-ID", record)
}

pub fn emergency_deprecation_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-DEPRECATION-ID", record)
}

pub fn defi_gate_id(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-DEFI-GATE-ID", record)
}

pub fn verified_contract_id(
    namespace: &str,
    contract_kind: &str,
    owner_commitment: &str,
    deployment_salt_root: &str,
) -> String {
    verified_contract_id_from_record(&verified_contract_identity_record(
        namespace,
        contract_kind,
        owner_commitment,
        deployment_salt_root,
    ))
}

pub fn verified_contract_id_from_record(record: &Value) -> String {
    contract_verification_payload_root("CONTRACT-VERIFICATION-CONTRACT-ID", record)
}

pub fn verifier_key_hash(proof_system: &str, circuit_id: &str, verifier_key_root: &str) -> String {
    domain_hash(
        "CONTRACT-VERIFICATION-VERIFIER-KEY-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(circuit_id),
            HashPart::Str(verifier_key_root),
        ],
        32,
    )
}

pub fn contract_verification_bytecode_root(bytecode: &[u8]) -> String {
    domain_hash(
        "CONTRACT-VERIFICATION-BYTECODE",
        &[HashPart::Str(CHAIN_ID), HashPart::Bytes(bytecode)],
        32,
    )
}

pub fn contract_verification_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn contract_verification_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn contract_verification_account_commitment(label: &str) -> String {
    domain_hash(
        "CONTRACT-VERIFICATION-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label.trim())],
        32,
    )
}

pub fn contract_verification_string_set_root(domain: &str, values: &[String]) -> String {
    let normalized = normalize_unique_strings(values.to_vec());
    let leaves = normalized
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn contract_verification_contract_set_root(
    values: &BTreeMap<String, VerifiedContractRecord>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-CONTRACT-SET",
        &values
            .values()
            .map(VerifiedContractRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_abi_set_root(values: &BTreeMap<String, AbiCommitment>) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-ABI-SET",
        &values
            .values()
            .map(AbiCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_manifest_set_root(
    values: &BTreeMap<String, BytecodeProofManifest>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-MANIFEST-SET",
        &values
            .values()
            .map(BytecodeProofManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_upgrade_set_root(
    values: &BTreeMap<String, UpgradeAuthorization>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-UPGRADE-SET",
        &values
            .values()
            .map(UpgradeAuthorization::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_attestation_set_root(
    values: &BTreeMap<String, PqAuditorAttestation>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-AUDITOR-ATTESTATION-SET",
        &values
            .values()
            .map(PqAuditorAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_privacy_policy_set_root(
    values: &BTreeMap<String, PrivacyBudgetPolicy>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-PRIVACY-POLICY-SET",
        &values
            .values()
            .map(PrivacyBudgetPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_sponsorship_set_root(
    values: &BTreeMap<String, DeploymentSponsorship>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-SPONSORSHIP-SET",
        &values
            .values()
            .map(DeploymentSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_verifier_key_set_root(
    values: &BTreeMap<String, VerifierKeyPin>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-VERIFIER-KEY-SET",
        &values
            .values()
            .map(VerifierKeyPin::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_build_set_root(
    values: &BTreeMap<String, ReproducibleBuildRecord>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-BUILD-SET",
        &values
            .values()
            .map(ReproducibleBuildRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_deprecation_set_root(
    values: &BTreeMap<String, EmergencyDeprecationRecord>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-DEPRECATION-SET",
        &values
            .values()
            .map(EmergencyDeprecationRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn contract_verification_defi_gate_set_root(
    values: &BTreeMap<String, DefiProtocolAllowlistGate>,
) -> String {
    merkle_root(
        "CONTRACT-VERIFICATION-DEFI-GATE-SET",
        &values
            .values()
            .map(DefiProtocolAllowlistGate::public_record)
            .collect::<Vec<_>>(),
    )
}

fn normalize_label(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

fn normalize_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn ensure_non_empty(label: &str, value: &str) -> ContractVerificationRegistryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ContractVerificationRegistryResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(label: &str, value: u64) -> ContractVerificationRegistryResult<()> {
    if value > CONTRACT_VERIFICATION_MAX_BPS {
        Err(format!("{label} exceeds maximum bps"))
    } else {
        Ok(())
    }
}

fn ensure_height_window(
    start_height: u64,
    end_height: u64,
    label: &str,
) -> ContractVerificationRegistryResult<()> {
    if end_height <= start_height {
        Err(format!("{label} height window is invalid"))
    } else {
        Ok(())
    }
}

fn ensure_optional_expiry(
    start_height: u64,
    expiry_height: u64,
    label: &str,
) -> ContractVerificationRegistryResult<()> {
    if expiry_height != 0 && expiry_height <= start_height {
        Err(format!("{label} expiry height is invalid"))
    } else {
        Ok(())
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> ContractVerificationRegistryResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}
