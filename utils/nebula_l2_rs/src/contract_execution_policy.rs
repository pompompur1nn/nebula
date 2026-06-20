use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ContractExecutionPolicyResult<T> = Result<T, String>;

pub const CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION: &str =
    "nebula-l2-contract-execution-policy-v1";
pub const CONTRACT_EXECUTION_POLICY_SCHEMA_VERSION: u64 = 1;
pub const CONTRACT_EXECUTION_POLICY_RUNTIME_PROFILE: &str =
    "monero-l2-private-contract-runtime-pq-v1";
pub const CONTRACT_EXECUTION_POLICY_ABI_FORMAT: &str = "canonical-json-abi+selector-root-v1";
pub const CONTRACT_EXECUTION_POLICY_BUILD_REPRODUCIBILITY: &str =
    "deterministic-wasm+canonical-json-manifest";
pub const CONTRACT_EXECUTION_POLICY_PQ_SIGNATURE_SUITE: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const CONTRACT_EXECUTION_POLICY_VERIFIER_KEY_SUITE: &str = "SHAKE256-pinned-verifier-key-root";
pub const CONTRACT_EXECUTION_POLICY_AUDIT_ATTESTATION_SUITE: &str =
    "pq-auditor-attestation-root-v1";
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_FUEL: u64 = 8_000_000;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_GAS_UNITS: u64 = 3_000_000;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_MEMORY_PAGES: u64 = 64;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_HOST_CALLS: u64 = 512;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_STORAGE_READS: u64 = 2_048;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_STORAGE_WRITES: u64 = 512;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_EVENT_BYTES: u64 = 32 * 1024;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 100_000;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MIN_ANONYMITY_SET: u64 = 96;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_UPGRADE_DELAY_BLOCKS: u64 = 1_440;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 = 12;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_DEPRECATION_GRACE_BLOCKS: u64 = 720;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 720;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 75_000;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_MANIFEST_BYTES: u64 = 512 * 1024;
pub const CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_AUDIT_AGE_BLOCKS: u64 = 20_160;
pub const CONTRACT_EXECUTION_POLICY_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONTRACT_EXECUTION_POLICY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractExecutionKind {
    Deploy,
    Call,
    View,
    Prove,
    Upgrade,
    Admin,
    Emergency,
}

impl ContractExecutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Call => "call",
            Self::View => "view",
            Self::Prove => "prove",
            Self::Upgrade => "upgrade",
            Self::Admin => "admin",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPolicyStatus {
    Draft,
    Active,
    Paused,
    Deprecated,
    Disabled,
    Revoked,
}

impl ExecutionPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deprecated => "deprecated",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }

    pub fn admits_execution(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Admission,
    PreExecute,
    Execute,
    PostExecute,
    Prove,
    Finalize,
}

impl ExecutionPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::PreExecute => "pre_execute",
            Self::Execute => "execute",
            Self::PostExecute => "post_execute",
            Self::Prove => "prove",
            Self::Finalize => "finalize",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCallKind {
    StorageRead,
    StorageWrite,
    EmitEvent,
    VerifyPqSignature,
    VerifyPrivacyProof,
    VerifyRingMembership,
    ReadOracle,
    CallPaymaster,
    BridgeQuote,
    ScheduleProof,
    RandomnessBeacon,
    TimelockRead,
    Custom(String),
}

impl HostCallKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::StorageRead => "storage_read".to_string(),
            Self::StorageWrite => "storage_write".to_string(),
            Self::EmitEvent => "emit_event".to_string(),
            Self::VerifyPqSignature => "verify_pq_signature".to_string(),
            Self::VerifyPrivacyProof => "verify_privacy_proof".to_string(),
            Self::VerifyRingMembership => "verify_ring_membership".to_string(),
            Self::ReadOracle => "read_oracle".to_string(),
            Self::CallPaymaster => "call_paymaster".to_string(),
            Self::BridgeQuote => "bridge_quote".to_string(),
            Self::ScheduleProof => "schedule_proof".to_string(),
            Self::RandomnessBeacon => "randomness_beacon".to_string(),
            Self::TimelockRead => "timelock_read".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn default_fuel_cost(&self) -> u64 {
        match self {
            Self::StorageRead => 200,
            Self::StorageWrite => 1_200,
            Self::EmitEvent => 150,
            Self::VerifyPqSignature => 8_000,
            Self::VerifyPrivacyProof => 25_000,
            Self::VerifyRingMembership => 18_000,
            Self::ReadOracle => 1_000,
            Self::CallPaymaster => 800,
            Self::BridgeQuote => 1_500,
            Self::ScheduleProof => 4_000,
            Self::RandomnessBeacon => 900,
            Self::TimelockRead => 100,
            Self::Custom(_) => 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageAccessMode {
    ReadOnly,
    ReadWrite,
    AppendOnly,
    Delete,
    Transient,
}

impl StorageAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
            Self::AppendOnly => "append_only",
            Self::Delete => "delete",
            Self::Transient => "transient",
        }
    }

    pub fn permits_write(self) -> bool {
        matches!(self, Self::ReadWrite | Self::AppendOnly | Self::Delete)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageIsolationLevel {
    ContractLocal,
    NamespaceLocal,
    SharedRead,
    SharedWrite,
    Ephemeral,
}

impl StorageIsolationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractLocal => "contract_local",
            Self::NamespaceLocal => "namespace_local",
            Self::SharedRead => "shared_read",
            Self::SharedWrite => "shared_write",
            Self::Ephemeral => "ephemeral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMeterKind {
    Nullifier,
    ViewTag,
    EncryptedEvent,
    SelectiveDisclosure,
    ShieldedState,
    AuditorDecrypt,
    TraceRedaction,
}

impl PrivacyMeterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::ViewTag => "view_tag",
            Self::EncryptedEvent => "encrypted_event",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::ShieldedState => "shielded_state",
            Self::AuditorDecrypt => "auditor_decrypt",
            Self::TraceRedaction => "trace_redaction",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignerRole {
    Deployer,
    Admin,
    EmergencyAdmin,
    Sponsor,
    Auditor,
    VerifierKeyMaintainer,
}

impl PqSignerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deployer => "deployer",
            Self::Admin => "admin",
            Self::EmergencyAdmin => "emergency_admin",
            Self::Sponsor => "sponsor",
            Self::Auditor => "auditor",
            Self::VerifierKeyMaintainer => "verifier_key_maintainer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa65,
    MlDsa87,
    SlhDsaShake192s,
    SlhDsaShake256s,
    HybridMlDsa65SlhDsa128s,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
            Self::SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
            Self::SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
            Self::HybridMlDsa65SlhDsa128s => CONTRACT_EXECUTION_POLICY_PQ_SIGNATURE_SUITE,
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::SlhDsaShake192s | Self::HybridMlDsa65SlhDsa128s => 192,
            Self::MlDsa87 | Self::SlhDsaShake256s => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyPurpose {
    DeployPolicy,
    ContractCall,
    PrivacyBudget,
    StorageTransition,
    LowFeeSponsorship,
    UpgradeSafety,
    EmergencyDeprecation,
}

impl VerifierKeyPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeployPolicy => "deploy_policy",
            Self::ContractCall => "contract_call",
            Self::PrivacyBudget => "privacy_budget",
            Self::StorageTransition => "storage_transition",
            Self::LowFeeSponsorship => "low_fee_sponsorship",
            Self::UpgradeSafety => "upgrade_safety",
            Self::EmergencyDeprecation => "emergency_deprecation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierKeyStatus {
    Candidate,
    Audited,
    Pinned,
    Active,
    GraceOnly,
    Deprecated,
    Disabled,
    Revoked,
}

impl VerifierKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Audited => "audited",
            Self::Pinned => "pinned",
            Self::Active => "active",
            Self::GraceOnly => "grace_only",
            Self::Deprecated => "deprecated",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_proofs(self) -> bool {
        matches!(self, Self::Pinned | Self::Active | Self::GraceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockStatus {
    Queued,
    Ready,
    Executed,
    Cancelled,
    Expired,
}

impl TimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Ready => "ready",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyDeprecationStatus {
    Announced,
    Effective,
    Grace,
    Replaced,
    Revoked,
}

impl EmergencyDeprecationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Effective => "effective",
            Self::Grace => "grace",
            Self::Replaced => "replaced",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipScope {
    Deployment,
    ContractCall,
    MethodSelector,
    VerifierKeyRegistration,
    AuditAttestation,
}

impl SponsorshipScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::ContractCall => "contract_call",
            Self::MethodSelector => "method_selector",
            Self::VerifierKeyRegistration => "verifier_key_registration",
            Self::AuditAttestation => "audit_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Open,
    Active,
    Paused,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAttestationKind {
    RuntimeDeterminism,
    PrivacyBudget,
    VerifierKey,
    StoragePolicy,
    UpgradeSafety,
    SponsorshipSolvency,
    EmergencyResponse,
}

impl AuditAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeDeterminism => "runtime_determinism",
            Self::PrivacyBudget => "privacy_budget",
            Self::VerifierKey => "verifier_key",
            Self::StoragePolicy => "storage_policy",
            Self::UpgradeSafety => "upgrade_safety",
            Self::SponsorshipSolvency => "sponsorship_solvency",
            Self::EmergencyResponse => "emergency_response",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Passed,
    Conditional,
    Failed,
    Expired,
    Revoked,
}

impl AuditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Passed => "passed",
            Self::Conditional => "conditional",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_acceptable(self) -> bool {
        matches!(self, Self::Passed | Self::Conditional)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecutionPolicyConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub runtime_profile: String,
    pub abi_format: String,
    pub build_reproducibility: String,
    pub min_pq_security_bits: u16,
    pub max_global_fuel_per_tx: u64,
    pub max_global_gas_per_tx: u64,
    pub max_memory_pages: u64,
    pub max_host_calls: u64,
    pub max_storage_reads: u64,
    pub max_storage_writes: u64,
    pub max_event_bytes: u64,
    pub default_privacy_budget_units: u64,
    pub min_anonymity_set: u64,
    pub upgrade_delay_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub deprecation_grace_blocks: u64,
    pub sponsorship_epoch_blocks: u64,
    pub max_sponsorship_budget_units: u64,
    pub max_manifest_bytes: u64,
    pub max_audit_age_blocks: u64,
    pub require_deployer_signature: bool,
    pub require_admin_signature: bool,
    pub require_verifier_key_pin: bool,
    pub allow_low_fee_sponsorship: bool,
}

impl Default for ContractExecutionPolicyConfig {
    fn default() -> Self {
        Self {
            protocol_version: CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION.to_string(),
            schema_version: CONTRACT_EXECUTION_POLICY_SCHEMA_VERSION,
            runtime_profile: CONTRACT_EXECUTION_POLICY_RUNTIME_PROFILE.to_string(),
            abi_format: CONTRACT_EXECUTION_POLICY_ABI_FORMAT.to_string(),
            build_reproducibility: CONTRACT_EXECUTION_POLICY_BUILD_REPRODUCIBILITY.to_string(),
            min_pq_security_bits: CONTRACT_EXECUTION_POLICY_MIN_PQ_SECURITY_BITS,
            max_global_fuel_per_tx: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_FUEL,
            max_global_gas_per_tx: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_GAS_UNITS,
            max_memory_pages: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_MEMORY_PAGES,
            max_host_calls: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_HOST_CALLS,
            max_storage_reads: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_STORAGE_READS,
            max_storage_writes: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_STORAGE_WRITES,
            max_event_bytes: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_EVENT_BYTES,
            default_privacy_budget_units: CONTRACT_EXECUTION_POLICY_DEFAULT_PRIVACY_BUDGET_UNITS,
            min_anonymity_set: CONTRACT_EXECUTION_POLICY_DEFAULT_MIN_ANONYMITY_SET,
            upgrade_delay_blocks: CONTRACT_EXECUTION_POLICY_DEFAULT_UPGRADE_DELAY_BLOCKS,
            emergency_delay_blocks: CONTRACT_EXECUTION_POLICY_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            deprecation_grace_blocks: CONTRACT_EXECUTION_POLICY_DEFAULT_DEPRECATION_GRACE_BLOCKS,
            sponsorship_epoch_blocks: CONTRACT_EXECUTION_POLICY_DEFAULT_SPONSOR_EPOCH_BLOCKS,
            max_sponsorship_budget_units: CONTRACT_EXECUTION_POLICY_DEFAULT_SPONSOR_BUDGET_UNITS,
            max_manifest_bytes: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_MANIFEST_BYTES,
            max_audit_age_blocks: CONTRACT_EXECUTION_POLICY_DEFAULT_MAX_AUDIT_AGE_BLOCKS,
            require_deployer_signature: true,
            require_admin_signature: true,
            require_verifier_key_pin: true,
            allow_low_fee_sponsorship: true,
        }
    }
}

impl ContractExecutionPolicyConfig {
    pub fn devnet() -> Self {
        Self {
            max_global_fuel_per_tx: 10_000_000,
            max_global_gas_per_tx: 4_000_000,
            max_host_calls: 768,
            max_storage_reads: 4_096,
            max_storage_writes: 768,
            default_privacy_budget_units: 150_000,
            min_anonymity_set: 64,
            upgrade_delay_blocks: 360,
            emergency_delay_blocks: 6,
            deprecation_grace_blocks: 180,
            max_sponsorship_budget_units: 125_000,
            max_manifest_bytes: 768 * 1024,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> ContractExecutionPolicyResult<()> {
        ensure_non_empty(&self.protocol_version, "execution policy protocol version")?;
        ensure_non_empty(&self.runtime_profile, "execution policy runtime profile")?;
        ensure_non_empty(&self.abi_format, "execution policy abi format")?;
        ensure_non_empty(
            &self.build_reproducibility,
            "execution policy build reproducibility",
        )?;
        ensure_positive(
            self.max_global_fuel_per_tx,
            "execution policy max global fuel",
        )?;
        ensure_positive(
            self.max_global_gas_per_tx,
            "execution policy max global gas",
        )?;
        ensure_positive(self.max_memory_pages, "execution policy max memory pages")?;
        ensure_positive(self.max_host_calls, "execution policy max host calls")?;
        ensure_positive(self.max_storage_reads, "execution policy max storage reads")?;
        ensure_positive(
            self.max_storage_writes,
            "execution policy max storage writes",
        )?;
        ensure_positive(self.max_event_bytes, "execution policy max event bytes")?;
        ensure_positive(
            self.default_privacy_budget_units,
            "execution policy default privacy budget",
        )?;
        ensure_positive(self.min_anonymity_set, "execution policy min anonymity set")?;
        ensure_positive(
            self.sponsorship_epoch_blocks,
            "execution policy sponsorship epoch blocks",
        )?;
        ensure_positive(
            self.max_sponsorship_budget_units,
            "execution policy max sponsorship budget",
        )?;
        ensure_positive(
            self.max_manifest_bytes,
            "execution policy max manifest bytes",
        )?;
        ensure_positive(
            self.max_audit_age_blocks,
            "execution policy max audit age blocks",
        )?;
        if self.min_pq_security_bits < CONTRACT_EXECUTION_POLICY_MIN_PQ_SECURITY_BITS {
            return Err("execution policy pq security floor is below protocol minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_execution_policy_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "runtime_profile": self.runtime_profile,
            "abi_format": self.abi_format,
            "build_reproducibility": self.build_reproducibility,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_global_fuel_per_tx": self.max_global_fuel_per_tx,
            "max_global_gas_per_tx": self.max_global_gas_per_tx,
            "max_memory_pages": self.max_memory_pages,
            "max_host_calls": self.max_host_calls,
            "max_storage_reads": self.max_storage_reads,
            "max_storage_writes": self.max_storage_writes,
            "max_event_bytes": self.max_event_bytes,
            "default_privacy_budget_units": self.default_privacy_budget_units,
            "min_anonymity_set": self.min_anonymity_set,
            "upgrade_delay_blocks": self.upgrade_delay_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "deprecation_grace_blocks": self.deprecation_grace_blocks,
            "sponsorship_epoch_blocks": self.sponsorship_epoch_blocks,
            "max_sponsorship_budget_units": self.max_sponsorship_budget_units,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_audit_age_blocks": self.max_audit_age_blocks,
            "require_deployer_signature": self.require_deployer_signature,
            "require_admin_signature": self.require_admin_signature,
            "require_verifier_key_pin": self.require_verifier_key_pin,
            "allow_low_fee_sponsorship": self.allow_low_fee_sponsorship,
        })
    }

    pub fn config_root(&self) -> String {
        contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-POLICY-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCapPolicy {
    pub policy_id: String,
    pub contract_id: String,
    pub method_selector: String,
    pub execution_kind: ContractExecutionKind,
    pub max_fuel: u64,
    pub max_gas_units: u64,
    pub max_memory_pages: u64,
    pub max_host_calls: u64,
    pub max_storage_reads: u64,
    pub max_storage_writes: u64,
    pub max_event_bytes: u64,
    pub max_call_depth: u64,
    pub sponsor_credit_fuel_cap: u64,
    pub verifier_key_root: String,
    pub host_call_allowlist_root: String,
    pub storage_policy_root: String,
    pub privacy_budget_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: Option<u64>,
    pub status: ExecutionPolicyStatus,
}

impl ExecutionCapPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        method_selector: impl Into<String>,
        execution_kind: ContractExecutionKind,
        max_fuel: u64,
        max_gas_units: u64,
        max_memory_pages: u64,
        max_host_calls: u64,
        max_storage_reads: u64,
        max_storage_writes: u64,
        max_event_bytes: u64,
        max_call_depth: u64,
        sponsor_credit_fuel_cap: u64,
        verifier_key_root: impl Into<String>,
        host_call_allowlist_root: impl Into<String>,
        storage_policy_root: impl Into<String>,
        privacy_budget_root: impl Into<String>,
        valid_from_height: u64,
        expires_at_height: Option<u64>,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let method_selector = method_selector.into();
        let verifier_key_root = verifier_key_root.into();
        let host_call_allowlist_root = host_call_allowlist_root.into();
        let storage_policy_root = storage_policy_root.into();
        let privacy_budget_root = privacy_budget_root.into();
        ensure_non_empty(&contract_id, "execution cap contract id")?;
        ensure_non_empty(&method_selector, "execution cap method selector")?;
        ensure_positive(max_fuel, "execution cap max fuel")?;
        ensure_positive(max_gas_units, "execution cap max gas units")?;
        ensure_positive(max_memory_pages, "execution cap max memory pages")?;
        ensure_positive(max_host_calls, "execution cap max host calls")?;
        ensure_positive(max_call_depth, "execution cap max call depth")?;
        ensure_non_empty(&verifier_key_root, "execution cap verifier key root")?;
        ensure_non_empty(
            &host_call_allowlist_root,
            "execution cap host call allowlist root",
        )?;
        ensure_non_empty(&storage_policy_root, "execution cap storage policy root")?;
        ensure_non_empty(&privacy_budget_root, "execution cap privacy budget root")?;
        if let Some(expires_at_height) = expires_at_height {
            if expires_at_height <= valid_from_height {
                return Err("execution cap expiry must be after valid_from_height".to_string());
            }
        }
        let policy_id = execution_cap_policy_id(
            &contract_id,
            &method_selector,
            execution_kind,
            max_fuel,
            max_gas_units,
            &verifier_key_root,
            &host_call_allowlist_root,
            &storage_policy_root,
            &privacy_budget_root,
        );
        Ok(Self {
            policy_id,
            contract_id,
            method_selector,
            execution_kind,
            max_fuel,
            max_gas_units,
            max_memory_pages,
            max_host_calls,
            max_storage_reads,
            max_storage_writes,
            max_event_bytes,
            max_call_depth,
            sponsor_credit_fuel_cap,
            verifier_key_root,
            host_call_allowlist_root,
            storage_policy_root,
            privacy_budget_root,
            valid_from_height,
            expires_at_height,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        if !self.status.admits_execution() || height < self.valid_from_height {
            return false;
        }
        match self.expires_at_height {
            Some(expires_at_height) => height <= expires_at_height,
            None => true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_cap_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "method_selector": self.method_selector,
            "execution_kind": self.execution_kind.as_str(),
            "max_fuel": self.max_fuel,
            "max_gas_units": self.max_gas_units,
            "max_memory_pages": self.max_memory_pages,
            "max_host_calls": self.max_host_calls,
            "max_storage_reads": self.max_storage_reads,
            "max_storage_writes": self.max_storage_writes,
            "max_event_bytes": self.max_event_bytes,
            "max_call_depth": self.max_call_depth,
            "sponsor_credit_fuel_cap": self.sponsor_credit_fuel_cap,
            "verifier_key_root": self.verifier_key_root,
            "host_call_allowlist_root": self.host_call_allowlist_root,
            "storage_policy_root": self.storage_policy_root,
            "privacy_budget_root": self.privacy_budget_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn policy_root(&self) -> String {
        execution_cap_policy_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetPolicy {
    pub budget_id: String,
    pub contract_id: String,
    pub method_selector: String,
    pub meter_kind: PrivacyMeterKind,
    pub epoch_length_blocks: u64,
    pub epoch_index: u64,
    pub max_budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub disclosure_count: u64,
    pub max_disclosure_count: u64,
    pub min_anonymity_set: u64,
    pub allowed_disclosure_root: String,
    pub auditor_set_root: String,
    pub nullifier_domain_root: String,
    pub carry_over_bps: u64,
    pub valid_from_height: u64,
    pub status: ExecutionPolicyStatus,
}

impl PrivacyBudgetPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        method_selector: impl Into<String>,
        meter_kind: PrivacyMeterKind,
        epoch_length_blocks: u64,
        max_budget_units: u64,
        max_disclosure_count: u64,
        min_anonymity_set: u64,
        allowed_disclosure_root: impl Into<String>,
        auditor_set_root: impl Into<String>,
        nullifier_domain_root: impl Into<String>,
        carry_over_bps: u64,
        valid_from_height: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let method_selector = method_selector.into();
        let allowed_disclosure_root = allowed_disclosure_root.into();
        let auditor_set_root = auditor_set_root.into();
        let nullifier_domain_root = nullifier_domain_root.into();
        ensure_non_empty(&contract_id, "privacy budget contract id")?;
        ensure_non_empty(&method_selector, "privacy budget method selector")?;
        ensure_positive(epoch_length_blocks, "privacy budget epoch length")?;
        ensure_positive(max_budget_units, "privacy budget max units")?;
        ensure_positive(max_disclosure_count, "privacy budget max disclosure count")?;
        ensure_positive(min_anonymity_set, "privacy budget min anonymity set")?;
        ensure_non_empty(
            &allowed_disclosure_root,
            "privacy budget allowed disclosure root",
        )?;
        ensure_non_empty(&auditor_set_root, "privacy budget auditor set root")?;
        ensure_non_empty(
            &nullifier_domain_root,
            "privacy budget nullifier domain root",
        )?;
        ensure_bps(carry_over_bps, "privacy budget carry over bps")?;
        let budget_id = privacy_budget_policy_id(
            &contract_id,
            &method_selector,
            meter_kind,
            epoch_length_blocks,
            max_budget_units,
            min_anonymity_set,
            &allowed_disclosure_root,
            &auditor_set_root,
            &nullifier_domain_root,
        );
        Ok(Self {
            budget_id,
            contract_id,
            method_selector,
            meter_kind,
            epoch_length_blocks,
            epoch_index: 0,
            max_budget_units,
            reserved_units: 0,
            spent_units: 0,
            disclosure_count: 0,
            max_disclosure_count,
            min_anonymity_set,
            allowed_disclosure_root,
            auditor_set_root,
            nullifier_domain_root,
            carry_over_bps,
            valid_from_height,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn set_height(&mut self, height: u64) {
        self.epoch_index = if self.epoch_length_blocks == 0 {
            0
        } else {
            height / self.epoch_length_blocks
        };
    }

    pub fn available_units(&self) -> u64 {
        self.max_budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn reserve(&mut self, units: u64) -> ContractExecutionPolicyResult<()> {
        if units > self.available_units() {
            return Err("privacy budget reserve exceeds available units".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn spend(&mut self, units: u64, disclosures: u64) -> ContractExecutionPolicyResult<()> {
        if units > self.available_units().saturating_add(self.reserved_units) {
            return Err("privacy budget spend exceeds available units".to_string());
        }
        if disclosures.saturating_add(self.disclosure_count) > self.max_disclosure_count {
            return Err("privacy budget disclosure cap exceeded".to_string());
        }
        let release = units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(release);
        self.spent_units = self.spent_units.saturating_add(units);
        self.disclosure_count = self.disclosure_count.saturating_add(disclosures);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_budget_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "contract_id": self.contract_id,
            "method_selector": self.method_selector,
            "meter_kind": self.meter_kind.as_str(),
            "epoch_length_blocks": self.epoch_length_blocks,
            "epoch_index": self.epoch_index,
            "max_budget_units": self.max_budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "disclosure_count": self.disclosure_count,
            "max_disclosure_count": self.max_disclosure_count,
            "min_anonymity_set": self.min_anonymity_set,
            "allowed_disclosure_root": self.allowed_disclosure_root,
            "auditor_set_root": self.auditor_set_root,
            "nullifier_domain_root": self.nullifier_domain_root,
            "carry_over_bps": self.carry_over_bps,
            "valid_from_height": self.valid_from_height,
            "status": self.status.as_str(),
        })
    }

    pub fn budget_root(&self) -> String {
        privacy_budget_policy_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorizationSignature {
    pub signature_id: String,
    pub role: PqSignerRole,
    pub signer_label: String,
    pub signer_key_id: String,
    pub signer_public_key_root: String,
    pub scheme: PqSignatureScheme,
    pub transcript_hash: String,
    pub message_root: String,
    pub signature_root: String,
    pub authorizes_subject_kind: String,
    pub authorizes_subject_id: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: ExecutionPolicyStatus,
}

impl PqAuthorizationSignature {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: PqSignerRole,
        signer_label: impl Into<String>,
        signer_key_id: impl Into<String>,
        signer_public_key_root: impl Into<String>,
        scheme: PqSignatureScheme,
        message_root: impl Into<String>,
        authorizes_subject_kind: impl Into<String>,
        authorizes_subject_id: impl Into<String>,
        signed_at_height: u64,
        ttl_blocks: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let signer_label = signer_label.into();
        let signer_key_id = signer_key_id.into();
        let signer_public_key_root = signer_public_key_root.into();
        let message_root = message_root.into();
        let authorizes_subject_kind = authorizes_subject_kind.into();
        let authorizes_subject_id = authorizes_subject_id.into();
        ensure_non_empty(&signer_label, "pq signature signer label")?;
        ensure_non_empty(&signer_key_id, "pq signature signer key id")?;
        ensure_non_empty(
            &signer_public_key_root,
            "pq signature signer public key root",
        )?;
        ensure_non_empty(&message_root, "pq signature message root")?;
        ensure_non_empty(
            &authorizes_subject_kind,
            "pq signature authorizes subject kind",
        )?;
        ensure_non_empty(&authorizes_subject_id, "pq signature authorizes subject id")?;
        ensure_positive(ttl_blocks, "pq signature ttl blocks")?;
        let transcript_hash = pq_authorization_transcript_hash(
            role,
            &signer_key_id,
            &signer_public_key_root,
            scheme,
            &message_root,
            &authorizes_subject_kind,
            &authorizes_subject_id,
            signed_at_height,
        );
        let signature_root = pq_authorization_signature_root(
            &signer_label,
            &signer_key_id,
            scheme,
            &transcript_hash,
        );
        let signature_id = pq_authorization_signature_id(
            role,
            &signer_key_id,
            scheme,
            &transcript_hash,
            &signature_root,
        );
        Ok(Self {
            signature_id,
            role,
            signer_label,
            signer_key_id,
            signer_public_key_root,
            scheme,
            transcript_hash,
            message_root,
            signature_root,
            authorizes_subject_kind,
            authorizes_subject_id,
            signed_at_height,
            expires_at_height: signed_at_height.saturating_add(ttl_blocks),
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.admits_execution()
            && height >= self.signed_at_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_authorization_signature",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "signature_id": self.signature_id,
            "role": self.role.as_str(),
            "signer_label": self.signer_label,
            "signer_key_id": self.signer_key_id,
            "signer_public_key_root": self.signer_public_key_root,
            "scheme": self.scheme.as_str(),
            "security_bits": self.scheme.security_bits(),
            "transcript_hash": self.transcript_hash,
            "message_root": self.message_root,
            "signature_root": self.signature_root,
            "authorizes_subject_kind": self.authorizes_subject_kind,
            "authorizes_subject_id": self.authorizes_subject_id,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierKeyPin {
    pub pin_id: String,
    pub verifier_key_id: String,
    pub purpose: VerifierKeyPurpose,
    pub circuit_family: String,
    pub proof_system: String,
    pub verifier_key_hash: String,
    pub verifier_key_root: String,
    pub pinned_by_signature_id: String,
    pub audit_attestation_root: String,
    pub minimum_security_bits: u16,
    pub active_from_height: u64,
    pub expires_at_height: Option<u64>,
    pub status: VerifierKeyStatus,
}

impl VerifierKeyPin {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verifier_key_id: impl Into<String>,
        purpose: VerifierKeyPurpose,
        circuit_family: impl Into<String>,
        proof_system: impl Into<String>,
        verifier_key_hash: impl Into<String>,
        pinned_by_signature_id: impl Into<String>,
        audit_attestation_root: impl Into<String>,
        minimum_security_bits: u16,
        active_from_height: u64,
        expires_at_height: Option<u64>,
    ) -> ContractExecutionPolicyResult<Self> {
        let verifier_key_id = verifier_key_id.into();
        let circuit_family = circuit_family.into();
        let proof_system = proof_system.into();
        let verifier_key_hash = verifier_key_hash.into();
        let pinned_by_signature_id = pinned_by_signature_id.into();
        let audit_attestation_root = audit_attestation_root.into();
        ensure_non_empty(&verifier_key_id, "verifier key id")?;
        ensure_non_empty(&circuit_family, "verifier key circuit family")?;
        ensure_non_empty(&proof_system, "verifier key proof system")?;
        ensure_non_empty(&verifier_key_hash, "verifier key hash")?;
        ensure_non_empty(&pinned_by_signature_id, "verifier key pin signature id")?;
        ensure_non_empty(
            &audit_attestation_root,
            "verifier key audit attestation root",
        )?;
        if minimum_security_bits < CONTRACT_EXECUTION_POLICY_MIN_PQ_SECURITY_BITS {
            return Err("verifier key pin below pq security floor".to_string());
        }
        if let Some(expires_at_height) = expires_at_height {
            if expires_at_height <= active_from_height {
                return Err("verifier key pin expiry must be after activation".to_string());
            }
        }
        let verifier_key_root = verifier_key_public_root(
            &verifier_key_id,
            purpose,
            &circuit_family,
            &proof_system,
            &verifier_key_hash,
            minimum_security_bits,
        );
        let pin_id = verifier_key_pin_id(
            &verifier_key_id,
            purpose,
            &verifier_key_root,
            &pinned_by_signature_id,
            &audit_attestation_root,
            active_from_height,
        );
        Ok(Self {
            pin_id,
            verifier_key_id,
            purpose,
            circuit_family,
            proof_system,
            verifier_key_hash,
            verifier_key_root,
            pinned_by_signature_id,
            audit_attestation_root,
            minimum_security_bits,
            active_from_height,
            expires_at_height,
            status: VerifierKeyStatus::Pinned,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        if !self.status.accepts_proofs() || height < self.active_from_height {
            return false;
        }
        match self.expires_at_height {
            Some(expires_at_height) => height <= expires_at_height,
            None => true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "verifier_key_pin",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "pin_id": self.pin_id,
            "verifier_key_id": self.verifier_key_id,
            "purpose": self.purpose.as_str(),
            "circuit_family": self.circuit_family,
            "proof_system": self.proof_system,
            "verifier_key_hash": self.verifier_key_hash,
            "verifier_key_root": self.verifier_key_root,
            "pinned_by_signature_id": self.pinned_by_signature_id,
            "audit_attestation_root": self.audit_attestation_root,
            "minimum_security_bits": self.minimum_security_bits,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCallPolicy {
    pub host_call_id: String,
    pub contract_id: String,
    pub host_call_kind: HostCallKind,
    pub host_call_label: String,
    pub permission_root: String,
    pub allowed_phase_root: String,
    pub max_invocations_per_tx: u64,
    pub fuel_cost: u64,
    pub gas_cost_units: u64,
    pub privacy_meter_delta_units: u64,
    pub requires_pq_signature: bool,
    pub requires_verifier_key: bool,
    pub valid_from_height: u64,
    pub status: ExecutionPolicyStatus,
}

impl HostCallPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        host_call_kind: HostCallKind,
        permission_labels: &[String],
        allowed_phases: &[ExecutionPhase],
        max_invocations_per_tx: u64,
        fuel_cost: u64,
        gas_cost_units: u64,
        privacy_meter_delta_units: u64,
        requires_pq_signature: bool,
        requires_verifier_key: bool,
        valid_from_height: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        ensure_non_empty(&contract_id, "host call policy contract id")?;
        ensure_unique_strings(permission_labels, "host call policy permissions")?;
        ensure_non_empty_slice(allowed_phases, "host call policy allowed phases")?;
        ensure_positive(max_invocations_per_tx, "host call max invocations per tx")?;
        ensure_positive(fuel_cost, "host call fuel cost")?;
        let host_call_label = host_call_kind.as_str();
        let permission_root = contract_execution_policy_string_set_root(
            "CONTRACT-EXECUTION-HOST-CALL-PERMISSIONS",
            permission_labels,
        );
        let allowed_phase_root = execution_phase_root(allowed_phases);
        let host_call_id = host_call_policy_id(
            &contract_id,
            &host_call_label,
            &permission_root,
            &allowed_phase_root,
            max_invocations_per_tx,
            fuel_cost,
            valid_from_height,
        );
        Ok(Self {
            host_call_id,
            contract_id,
            host_call_kind,
            host_call_label,
            permission_root,
            allowed_phase_root,
            max_invocations_per_tx,
            fuel_cost,
            gas_cost_units,
            privacy_meter_delta_units,
            requires_pq_signature,
            requires_verifier_key,
            valid_from_height,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "host_call_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "host_call_id": self.host_call_id,
            "contract_id": self.contract_id,
            "host_call_kind": self.host_call_kind.as_str(),
            "host_call_label": self.host_call_label,
            "permission_root": self.permission_root,
            "allowed_phase_root": self.allowed_phase_root,
            "max_invocations_per_tx": self.max_invocations_per_tx,
            "fuel_cost": self.fuel_cost,
            "gas_cost_units": self.gas_cost_units,
            "privacy_meter_delta_units": self.privacy_meter_delta_units,
            "requires_pq_signature": self.requires_pq_signature,
            "requires_verifier_key": self.requires_verifier_key,
            "valid_from_height": self.valid_from_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageAccessPolicy {
    pub storage_policy_id: String,
    pub contract_id: String,
    pub namespace: String,
    pub mode: StorageAccessMode,
    pub isolation: StorageIsolationLevel,
    pub key_scope_root: String,
    pub read_budget: u64,
    pub write_budget: u64,
    pub max_value_bytes: u64,
    pub requires_view_capability: bool,
    pub disclosure_policy_root: String,
    pub audit_policy_root: String,
    pub valid_from_height: u64,
    pub status: ExecutionPolicyStatus,
}

impl StorageAccessPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        namespace: impl Into<String>,
        mode: StorageAccessMode,
        isolation: StorageIsolationLevel,
        key_scopes: &[String],
        read_budget: u64,
        write_budget: u64,
        max_value_bytes: u64,
        requires_view_capability: bool,
        disclosure_policy_root: impl Into<String>,
        audit_policy_root: impl Into<String>,
        valid_from_height: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let namespace = normalize_label(namespace.into());
        let disclosure_policy_root = disclosure_policy_root.into();
        let audit_policy_root = audit_policy_root.into();
        ensure_non_empty(&contract_id, "storage access contract id")?;
        ensure_non_empty(&namespace, "storage access namespace")?;
        ensure_unique_strings(key_scopes, "storage access key scopes")?;
        ensure_positive(read_budget, "storage access read budget")?;
        if mode.permits_write() {
            ensure_positive(write_budget, "storage access write budget")?;
        }
        ensure_positive(max_value_bytes, "storage access max value bytes")?;
        ensure_non_empty(
            &disclosure_policy_root,
            "storage access disclosure policy root",
        )?;
        ensure_non_empty(&audit_policy_root, "storage access audit policy root")?;
        let key_scope_root = contract_execution_policy_string_set_root(
            "CONTRACT-EXECUTION-STORAGE-KEY-SCOPE",
            key_scopes,
        );
        let storage_policy_id = storage_access_policy_id(
            &contract_id,
            &namespace,
            mode,
            isolation,
            &key_scope_root,
            read_budget,
            write_budget,
            &disclosure_policy_root,
            &audit_policy_root,
        );
        Ok(Self {
            storage_policy_id,
            contract_id,
            namespace,
            mode,
            isolation,
            key_scope_root,
            read_budget,
            write_budget,
            max_value_bytes,
            requires_view_capability,
            disclosure_policy_root,
            audit_policy_root,
            valid_from_height,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "storage_access_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "storage_policy_id": self.storage_policy_id,
            "contract_id": self.contract_id,
            "namespace": self.namespace,
            "mode": self.mode.as_str(),
            "isolation": self.isolation.as_str(),
            "key_scope_root": self.key_scope_root,
            "read_budget": self.read_budget,
            "write_budget": self.write_budget,
            "max_value_bytes": self.max_value_bytes,
            "requires_view_capability": self.requires_view_capability,
            "disclosure_policy_root": self.disclosure_policy_root,
            "audit_policy_root": self.audit_policy_root,
            "valid_from_height": self.valid_from_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiMethodPin {
    pub method_id: String,
    pub contract_id: String,
    pub selector: String,
    pub method_name: String,
    pub arg_schema_root: String,
    pub return_schema_root: String,
    pub privacy_budget_id: String,
    pub execution_cap_id: String,
    pub required_host_call_root: String,
    pub status: ExecutionPolicyStatus,
}

impl AbiMethodPin {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        selector: impl Into<String>,
        method_name: impl Into<String>,
        arg_schema_root: impl Into<String>,
        return_schema_root: impl Into<String>,
        privacy_budget_id: impl Into<String>,
        execution_cap_id: impl Into<String>,
        required_host_calls: &[HostCallPolicy],
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let selector = selector.into();
        let method_name = method_name.into();
        let arg_schema_root = arg_schema_root.into();
        let return_schema_root = return_schema_root.into();
        let privacy_budget_id = privacy_budget_id.into();
        let execution_cap_id = execution_cap_id.into();
        ensure_non_empty(&contract_id, "abi method contract id")?;
        ensure_non_empty(&selector, "abi method selector")?;
        ensure_non_empty(&method_name, "abi method name")?;
        ensure_non_empty(&arg_schema_root, "abi method arg schema root")?;
        ensure_non_empty(&return_schema_root, "abi method return schema root")?;
        ensure_non_empty(&privacy_budget_id, "abi method privacy budget id")?;
        ensure_non_empty(&execution_cap_id, "abi method execution cap id")?;
        let required_host_call_root = host_call_policy_root(required_host_calls);
        let method_id = abi_method_pin_id(
            &contract_id,
            &selector,
            &method_name,
            &arg_schema_root,
            &return_schema_root,
            &privacy_budget_id,
            &execution_cap_id,
            &required_host_call_root,
        );
        Ok(Self {
            method_id,
            contract_id,
            selector,
            method_name,
            arg_schema_root,
            return_schema_root,
            privacy_budget_id,
            execution_cap_id,
            required_host_call_root,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "abi_method_pin",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "method_id": self.method_id,
            "contract_id": self.contract_id,
            "selector": self.selector,
            "method_name": self.method_name,
            "arg_schema_root": self.arg_schema_root,
            "return_schema_root": self.return_schema_root,
            "privacy_budget_id": self.privacy_budget_id,
            "execution_cap_id": self.execution_cap_id,
            "required_host_call_root": self.required_host_call_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicAbiManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub abi_version: String,
    pub method_root: String,
    pub type_schema_root: String,
    pub event_schema_root: String,
    pub error_schema_root: String,
    pub selector_collision_root: String,
    pub canonical_json_root: String,
    pub generated_at_height: u64,
    pub status: ExecutionPolicyStatus,
}

impl DeterministicAbiManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        abi_version: impl Into<String>,
        methods: &[AbiMethodPin],
        type_schema_root: impl Into<String>,
        event_schema_root: impl Into<String>,
        error_schema_root: impl Into<String>,
        selector_collision_root: impl Into<String>,
        generated_at_height: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let abi_version = abi_version.into();
        let type_schema_root = type_schema_root.into();
        let event_schema_root = event_schema_root.into();
        let error_schema_root = error_schema_root.into();
        let selector_collision_root = selector_collision_root.into();
        ensure_non_empty(&contract_id, "abi manifest contract id")?;
        ensure_non_empty(&abi_version, "abi manifest version")?;
        ensure_non_empty_slice(methods, "abi manifest methods")?;
        ensure_non_empty(&type_schema_root, "abi manifest type schema root")?;
        ensure_non_empty(&event_schema_root, "abi manifest event schema root")?;
        ensure_non_empty(&error_schema_root, "abi manifest error schema root")?;
        ensure_non_empty(
            &selector_collision_root,
            "abi manifest selector collision root",
        )?;
        let method_root = abi_method_pin_root(methods);
        let canonical_json_root = contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-ABI-CANONICAL",
            &json!({
                "contract_id": contract_id,
                "abi_version": abi_version,
                "method_root": method_root,
                "type_schema_root": type_schema_root,
                "event_schema_root": event_schema_root,
                "error_schema_root": error_schema_root,
                "selector_collision_root": selector_collision_root,
            }),
        );
        let manifest_id = abi_manifest_id(
            &contract_id,
            &abi_version,
            &method_root,
            &type_schema_root,
            &event_schema_root,
            &error_schema_root,
            &canonical_json_root,
        );
        Ok(Self {
            manifest_id,
            contract_id,
            abi_version,
            method_root,
            type_schema_root,
            event_schema_root,
            error_schema_root,
            selector_collision_root,
            canonical_json_root,
            generated_at_height,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_abi_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "abi_format": CONTRACT_EXECUTION_POLICY_ABI_FORMAT,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "abi_version": self.abi_version,
            "method_root": self.method_root,
            "type_schema_root": self.type_schema_root,
            "event_schema_root": self.event_schema_root,
            "error_schema_root": self.error_schema_root,
            "selector_collision_root": self.selector_collision_root,
            "canonical_json_root": self.canonical_json_root,
            "generated_at_height": self.generated_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        abi_manifest_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicRuntimeManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub runtime_name: String,
    pub runtime_version: String,
    pub wasm_code_hash: String,
    pub deterministic_build_root: String,
    pub compiler_root: String,
    pub host_profile_root: String,
    pub allowed_host_call_root: String,
    pub storage_policy_root: String,
    pub verifier_key_root: String,
    pub abi_manifest_root: String,
    pub deployer_signature_id: String,
    pub admin_signature_id: String,
    pub bytecode_size_bytes: u64,
    pub status: ExecutionPolicyStatus,
}

impl DeterministicRuntimeManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        runtime_name: impl Into<String>,
        runtime_version: impl Into<String>,
        wasm_code_hash: impl Into<String>,
        deterministic_build_root: impl Into<String>,
        compiler_root: impl Into<String>,
        host_profile_root: impl Into<String>,
        allowed_host_call_root: impl Into<String>,
        storage_policy_root: impl Into<String>,
        verifier_key_root: impl Into<String>,
        abi_manifest_root: impl Into<String>,
        deployer_signature_id: impl Into<String>,
        admin_signature_id: impl Into<String>,
        bytecode_size_bytes: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let runtime_name = runtime_name.into();
        let runtime_version = runtime_version.into();
        let wasm_code_hash = wasm_code_hash.into();
        let deterministic_build_root = deterministic_build_root.into();
        let compiler_root = compiler_root.into();
        let host_profile_root = host_profile_root.into();
        let allowed_host_call_root = allowed_host_call_root.into();
        let storage_policy_root = storage_policy_root.into();
        let verifier_key_root = verifier_key_root.into();
        let abi_manifest_root = abi_manifest_root.into();
        let deployer_signature_id = deployer_signature_id.into();
        let admin_signature_id = admin_signature_id.into();
        ensure_non_empty(&contract_id, "runtime manifest contract id")?;
        ensure_non_empty(&runtime_name, "runtime manifest runtime name")?;
        ensure_non_empty(&runtime_version, "runtime manifest runtime version")?;
        ensure_non_empty(&wasm_code_hash, "runtime manifest wasm code hash")?;
        ensure_non_empty(
            &deterministic_build_root,
            "runtime manifest deterministic build root",
        )?;
        ensure_non_empty(&compiler_root, "runtime manifest compiler root")?;
        ensure_non_empty(&host_profile_root, "runtime manifest host profile root")?;
        ensure_non_empty(
            &allowed_host_call_root,
            "runtime manifest allowed host call root",
        )?;
        ensure_non_empty(&storage_policy_root, "runtime manifest storage policy root")?;
        ensure_non_empty(&verifier_key_root, "runtime manifest verifier key root")?;
        ensure_non_empty(&abi_manifest_root, "runtime manifest abi manifest root")?;
        ensure_non_empty(
            &deployer_signature_id,
            "runtime manifest deployer signature id",
        )?;
        ensure_non_empty(&admin_signature_id, "runtime manifest admin signature id")?;
        ensure_positive(bytecode_size_bytes, "runtime manifest bytecode size")?;
        let manifest_id = runtime_manifest_id(
            &contract_id,
            &runtime_name,
            &runtime_version,
            &wasm_code_hash,
            &deterministic_build_root,
            &allowed_host_call_root,
            &storage_policy_root,
            &verifier_key_root,
            &abi_manifest_root,
        );
        Ok(Self {
            manifest_id,
            contract_id,
            runtime_name,
            runtime_version,
            wasm_code_hash,
            deterministic_build_root,
            compiler_root,
            host_profile_root,
            allowed_host_call_root,
            storage_policy_root,
            verifier_key_root,
            abi_manifest_root,
            deployer_signature_id,
            admin_signature_id,
            bytecode_size_bytes,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "deterministic_runtime_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "runtime_profile": CONTRACT_EXECUTION_POLICY_RUNTIME_PROFILE,
            "build_reproducibility": CONTRACT_EXECUTION_POLICY_BUILD_REPRODUCIBILITY,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "runtime_name": self.runtime_name,
            "runtime_version": self.runtime_version,
            "wasm_code_hash": self.wasm_code_hash,
            "deterministic_build_root": self.deterministic_build_root,
            "compiler_root": self.compiler_root,
            "host_profile_root": self.host_profile_root,
            "allowed_host_call_root": self.allowed_host_call_root,
            "storage_policy_root": self.storage_policy_root,
            "verifier_key_root": self.verifier_key_root,
            "abi_manifest_root": self.abi_manifest_root,
            "deployer_signature_id": self.deployer_signature_id,
            "admin_signature_id": self.admin_signature_id,
            "bytecode_size_bytes": self.bytecode_size_bytes,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        runtime_manifest_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeTimelock {
    pub timelock_id: String,
    pub contract_id: String,
    pub from_manifest_root: String,
    pub to_manifest_root: String,
    pub proposer_signature_id: String,
    pub admin_signature_root: String,
    pub queued_at_height: u64,
    pub earliest_execution_height: u64,
    pub expires_at_height: u64,
    pub emergency_override: bool,
    pub status: TimelockStatus,
}

impl UpgradeTimelock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        from_manifest_root: impl Into<String>,
        to_manifest_root: impl Into<String>,
        proposer_signature_id: impl Into<String>,
        admin_signature_root: impl Into<String>,
        queued_at_height: u64,
        delay_blocks: u64,
        ttl_blocks: u64,
        emergency_override: bool,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let from_manifest_root = from_manifest_root.into();
        let to_manifest_root = to_manifest_root.into();
        let proposer_signature_id = proposer_signature_id.into();
        let admin_signature_root = admin_signature_root.into();
        ensure_non_empty(&contract_id, "upgrade timelock contract id")?;
        ensure_non_empty(&from_manifest_root, "upgrade timelock from manifest root")?;
        ensure_non_empty(&to_manifest_root, "upgrade timelock to manifest root")?;
        ensure_non_empty(
            &proposer_signature_id,
            "upgrade timelock proposer signature",
        )?;
        ensure_non_empty(
            &admin_signature_root,
            "upgrade timelock admin signature root",
        )?;
        ensure_positive(ttl_blocks, "upgrade timelock ttl blocks")?;
        let earliest_execution_height = queued_at_height.saturating_add(delay_blocks);
        let expires_at_height = earliest_execution_height.saturating_add(ttl_blocks);
        let timelock_id = upgrade_timelock_id(
            &contract_id,
            &from_manifest_root,
            &to_manifest_root,
            &proposer_signature_id,
            &admin_signature_root,
            queued_at_height,
            earliest_execution_height,
            emergency_override,
        );
        Ok(Self {
            timelock_id,
            contract_id,
            from_manifest_root,
            to_manifest_root,
            proposer_signature_id,
            admin_signature_root,
            queued_at_height,
            earliest_execution_height,
            expires_at_height,
            emergency_override,
            status: TimelockStatus::Queued,
        })
    }

    pub fn executable_at(&self, height: u64) -> bool {
        matches!(self.status, TimelockStatus::Queued | TimelockStatus::Ready)
            && height >= self.earliest_execution_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "upgrade_timelock",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "timelock_id": self.timelock_id,
            "contract_id": self.contract_id,
            "from_manifest_root": self.from_manifest_root,
            "to_manifest_root": self.to_manifest_root,
            "proposer_signature_id": self.proposer_signature_id,
            "admin_signature_root": self.admin_signature_root,
            "queued_at_height": self.queued_at_height,
            "earliest_execution_height": self.earliest_execution_height,
            "expires_at_height": self.expires_at_height,
            "emergency_override": self.emergency_override,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyDeprecation {
    pub deprecation_id: String,
    pub contract_id: String,
    pub reason_code: String,
    pub replaced_by_contract_id: Option<String>,
    pub announced_at_height: u64,
    pub effective_at_height: u64,
    pub emergency_signature_id: String,
    pub disclosure_record_root: String,
    pub status: EmergencyDeprecationStatus,
}

impl EmergencyDeprecation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        reason_code: impl Into<String>,
        replaced_by_contract_id: Option<String>,
        announced_at_height: u64,
        grace_blocks: u64,
        emergency_signature_id: impl Into<String>,
        disclosure_record_root: impl Into<String>,
    ) -> ContractExecutionPolicyResult<Self> {
        let contract_id = contract_id.into();
        let reason_code = normalize_label(reason_code.into());
        let emergency_signature_id = emergency_signature_id.into();
        let disclosure_record_root = disclosure_record_root.into();
        ensure_non_empty(&contract_id, "emergency deprecation contract id")?;
        ensure_non_empty(&reason_code, "emergency deprecation reason code")?;
        ensure_non_empty(
            &emergency_signature_id,
            "emergency deprecation signature id",
        )?;
        ensure_non_empty(
            &disclosure_record_root,
            "emergency deprecation disclosure root",
        )?;
        let effective_at_height = announced_at_height.saturating_add(grace_blocks);
        let deprecation_id = emergency_deprecation_id(
            &contract_id,
            &reason_code,
            &replaced_by_contract_id,
            announced_at_height,
            effective_at_height,
            &emergency_signature_id,
            &disclosure_record_root,
        );
        Ok(Self {
            deprecation_id,
            contract_id,
            reason_code,
            replaced_by_contract_id,
            announced_at_height,
            effective_at_height,
            emergency_signature_id,
            disclosure_record_root,
            status: EmergencyDeprecationStatus::Announced,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        !matches!(self.status, EmergencyDeprecationStatus::Revoked)
            && height >= self.effective_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_deprecation",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "deprecation_id": self.deprecation_id,
            "contract_id": self.contract_id,
            "reason_code": self.reason_code,
            "replaced_by_contract_id": self.replaced_by_contract_id,
            "announced_at_height": self.announced_at_height,
            "effective_at_height": self.effective_at_height,
            "emergency_signature_id": self.emergency_signature_id,
            "disclosure_record_root": self.disclosure_record_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub contract_id: String,
    pub scope: SponsorshipScope,
    pub scope_value: String,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_units_per_call: u64,
    pub privacy_floor: u64,
    pub epoch_index: u64,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub signature_id: String,
    pub status: SponsorshipStatus,
}

impl LowFeeSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        contract_id: impl Into<String>,
        scope: SponsorshipScope,
        scope_value: impl Into<String>,
        fee_asset_id: impl Into<String>,
        budget_units: u64,
        max_units_per_call: u64,
        privacy_floor: u64,
        epoch_start_height: u64,
        epoch_length_blocks: u64,
        signature_id: impl Into<String>,
    ) -> ContractExecutionPolicyResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let contract_id = contract_id.into();
        let scope_value = scope_value.into();
        let fee_asset_id = fee_asset_id.into();
        let signature_id = signature_id.into();
        ensure_non_empty(&sponsor_commitment, "low fee sponsorship sponsor")?;
        ensure_non_empty(&contract_id, "low fee sponsorship contract id")?;
        ensure_non_empty(&scope_value, "low fee sponsorship scope value")?;
        ensure_non_empty(&fee_asset_id, "low fee sponsorship fee asset id")?;
        ensure_positive(budget_units, "low fee sponsorship budget")?;
        ensure_positive(max_units_per_call, "low fee sponsorship max units per call")?;
        ensure_positive(privacy_floor, "low fee sponsorship privacy floor")?;
        ensure_positive(epoch_length_blocks, "low fee sponsorship epoch length")?;
        ensure_non_empty(&signature_id, "low fee sponsorship signature id")?;
        if max_units_per_call > budget_units {
            return Err("low fee sponsorship max per call exceeds budget".to_string());
        }
        let epoch_index = if epoch_length_blocks == 0 {
            0
        } else {
            epoch_start_height / epoch_length_blocks
        };
        let epoch_end_height = epoch_start_height
            .saturating_add(epoch_length_blocks)
            .saturating_sub(1);
        let sponsorship_id = low_fee_sponsorship_id(
            &sponsor_commitment,
            &contract_id,
            scope,
            &scope_value,
            &fee_asset_id,
            budget_units,
            epoch_start_height,
            epoch_end_height,
            &signature_id,
        );
        Ok(Self {
            sponsorship_id,
            sponsor_commitment,
            contract_id,
            scope,
            scope_value,
            fee_asset_id,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_units_per_call,
            privacy_floor,
            epoch_index,
            epoch_start_height,
            epoch_end_height,
            signature_id,
            status: SponsorshipStatus::Active,
        })
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        matches!(self.status, SponsorshipStatus::Active)
            && height >= self.epoch_start_height
            && height <= self.epoch_end_height
    }

    pub fn can_sponsor(&self, height: u64, units: u64, privacy_set_size: u64) -> bool {
        self.active_at(height)
            && units > 0
            && units <= self.max_units_per_call
            && units <= self.available_units()
            && privacy_set_size >= self.privacy_floor
    }

    pub fn reserve(
        &mut self,
        height: u64,
        units: u64,
        privacy_set_size: u64,
    ) -> ContractExecutionPolicyResult<()> {
        if !self.can_sponsor(height, units, privacy_set_size) {
            return Err("low fee sponsorship cannot cover request".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn settle(&mut self, units: u64) -> ContractExecutionPolicyResult<()> {
        if units > self.reserved_units.saturating_add(self.available_units()) {
            return Err("low fee sponsorship settlement exceeds budget".to_string());
        }
        let release = units.min(self.reserved_units);
        self.reserved_units = self.reserved_units.saturating_sub(release);
        self.spent_units = self.spent_units.saturating_add(units);
        if self.available_units() == 0 {
            self.status = SponsorshipStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "contract_id": self.contract_id,
            "scope": self.scope.as_str(),
            "scope_value": self.scope_value,
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_units_per_call": self.max_units_per_call,
            "privacy_floor": self.privacy_floor,
            "epoch_index": self.epoch_index,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "signature_id": self.signature_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAttestation {
    pub attestation_id: String,
    pub auditor_id: String,
    pub auditor_public_key_root: String,
    pub kind: AuditAttestationKind,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub evidence_root: String,
    pub report_hash: String,
    pub verdict: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub signature_id: String,
    pub status: AuditStatus,
}

impl AuditAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auditor_id: impl Into<String>,
        auditor_public_key_root: impl Into<String>,
        kind: AuditAttestationKind,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        evidence_root: impl Into<String>,
        report_hash: impl Into<String>,
        verdict: impl Into<String>,
        issued_at_height: u64,
        ttl_blocks: u64,
        signature_id: impl Into<String>,
    ) -> ContractExecutionPolicyResult<Self> {
        let auditor_id = auditor_id.into();
        let auditor_public_key_root = auditor_public_key_root.into();
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let evidence_root = evidence_root.into();
        let report_hash = report_hash.into();
        let verdict = verdict.into();
        let signature_id = signature_id.into();
        ensure_non_empty(&auditor_id, "audit attestation auditor id")?;
        ensure_non_empty(
            &auditor_public_key_root,
            "audit attestation auditor public key root",
        )?;
        ensure_non_empty(&subject_kind, "audit attestation subject kind")?;
        ensure_non_empty(&subject_id, "audit attestation subject id")?;
        ensure_non_empty(&subject_root, "audit attestation subject root")?;
        ensure_non_empty(&evidence_root, "audit attestation evidence root")?;
        ensure_non_empty(&report_hash, "audit attestation report hash")?;
        ensure_non_empty(&verdict, "audit attestation verdict")?;
        ensure_positive(ttl_blocks, "audit attestation ttl blocks")?;
        ensure_non_empty(&signature_id, "audit attestation signature id")?;
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks);
        let attestation_id = audit_attestation_id(
            &auditor_id,
            kind,
            &subject_kind,
            &subject_id,
            &subject_root,
            &evidence_root,
            &report_hash,
            issued_at_height,
            &signature_id,
        );
        Ok(Self {
            attestation_id,
            auditor_id,
            auditor_public_key_root,
            kind,
            subject_kind,
            subject_id,
            subject_root,
            evidence_root,
            report_hash,
            verdict,
            issued_at_height,
            expires_at_height,
            signature_id,
            status: AuditStatus::Passed,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.is_acceptable()
            && height >= self.issued_at_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "audit_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "attestation_suite": CONTRACT_EXECUTION_POLICY_AUDIT_ATTESTATION_SUITE,
            "attestation_id": self.attestation_id,
            "auditor_id": self.auditor_id,
            "auditor_public_key_root": self.auditor_public_key_root,
            "attestation_kind": self.kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "report_hash": self.report_hash,
            "verdict": self.verdict,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "signature_id": self.signature_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPolicyPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root: String,
    pub redaction_root: String,
    pub emitted_at_height: u64,
    pub record_sequence: u64,
    pub status: ExecutionPolicyStatus,
}

impl ContractPolicyPublicRecord {
    pub fn new(
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        payload_root: impl Into<String>,
        state_root: impl Into<String>,
        redaction_root: impl Into<String>,
        emitted_at_height: u64,
        record_sequence: u64,
    ) -> ContractExecutionPolicyResult<Self> {
        let subject_kind = subject_kind.into();
        let subject_id = subject_id.into();
        let payload_root = payload_root.into();
        let state_root = state_root.into();
        let redaction_root = redaction_root.into();
        ensure_non_empty(&subject_kind, "contract policy public record subject kind")?;
        ensure_non_empty(&subject_id, "contract policy public record subject id")?;
        ensure_non_empty(&payload_root, "contract policy public record payload root")?;
        ensure_non_empty(&state_root, "contract policy public record state root")?;
        ensure_non_empty(
            &redaction_root,
            "contract policy public record redaction root",
        )?;
        let record_id = contract_policy_public_record_id(
            &subject_kind,
            &subject_id,
            &payload_root,
            &state_root,
            emitted_at_height,
            record_sequence,
        );
        Ok(Self {
            record_id,
            subject_kind,
            subject_id,
            payload_root,
            state_root,
            redaction_root,
            emitted_at_height,
            record_sequence,
            status: ExecutionPolicyStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_policy_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root": self.state_root,
            "redaction_root": self.redaction_root,
            "emitted_at_height": self.emitted_at_height,
            "record_sequence": self.record_sequence,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecutionPolicyCounters {
    pub execution_cap_count: u64,
    pub active_execution_cap_count: u64,
    pub privacy_budget_count: u64,
    pub exhausted_privacy_budget_count: u64,
    pub pq_signature_count: u64,
    pub verifier_key_pin_count: u64,
    pub host_call_policy_count: u64,
    pub storage_policy_count: u64,
    pub pending_upgrade_count: u64,
    pub active_deprecation_count: u64,
    pub sponsorship_count: u64,
    pub available_sponsor_units: u64,
    pub runtime_manifest_count: u64,
    pub abi_manifest_count: u64,
    pub audit_attestation_count: u64,
    pub public_record_count: u64,
}

impl ContractExecutionPolicyCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_execution_policy_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "execution_cap_count": self.execution_cap_count,
            "active_execution_cap_count": self.active_execution_cap_count,
            "privacy_budget_count": self.privacy_budget_count,
            "exhausted_privacy_budget_count": self.exhausted_privacy_budget_count,
            "pq_signature_count": self.pq_signature_count,
            "verifier_key_pin_count": self.verifier_key_pin_count,
            "host_call_policy_count": self.host_call_policy_count,
            "storage_policy_count": self.storage_policy_count,
            "pending_upgrade_count": self.pending_upgrade_count,
            "active_deprecation_count": self.active_deprecation_count,
            "sponsorship_count": self.sponsorship_count,
            "available_sponsor_units": self.available_sponsor_units,
            "runtime_manifest_count": self.runtime_manifest_count,
            "abi_manifest_count": self.abi_manifest_count,
            "audit_attestation_count": self.audit_attestation_count,
            "public_record_count": self.public_record_count,
        })
    }

    pub fn counters_root(&self) -> String {
        contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-POLICY-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecutionPolicyRoots {
    pub config_root: String,
    pub execution_cap_root: String,
    pub privacy_budget_root: String,
    pub pq_signature_root: String,
    pub verifier_key_pin_root: String,
    pub host_call_policy_root: String,
    pub storage_policy_root: String,
    pub upgrade_timelock_root: String,
    pub emergency_deprecation_root: String,
    pub sponsorship_root: String,
    pub runtime_manifest_root: String,
    pub abi_manifest_root: String,
    pub audit_attestation_root: String,
    pub public_record_root: String,
    pub aggregate_root: String,
    pub state_root: String,
}

impl ContractExecutionPolicyRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_execution_policy_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "execution_cap_root": self.execution_cap_root,
            "privacy_budget_root": self.privacy_budget_root,
            "pq_signature_root": self.pq_signature_root,
            "verifier_key_pin_root": self.verifier_key_pin_root,
            "host_call_policy_root": self.host_call_policy_root,
            "storage_policy_root": self.storage_policy_root,
            "upgrade_timelock_root": self.upgrade_timelock_root,
            "emergency_deprecation_root": self.emergency_deprecation_root,
            "sponsorship_root": self.sponsorship_root,
            "runtime_manifest_root": self.runtime_manifest_root,
            "abi_manifest_root": self.abi_manifest_root,
            "audit_attestation_root": self.audit_attestation_root,
            "public_record_root": self.public_record_root,
            "aggregate_root": self.aggregate_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExecutionPolicyState {
    pub config: ContractExecutionPolicyConfig,
    pub height: u64,
    pub execution_caps: BTreeMap<String, ExecutionCapPolicy>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetPolicy>,
    pub pq_signatures: BTreeMap<String, PqAuthorizationSignature>,
    pub verifier_key_pins: BTreeMap<String, VerifierKeyPin>,
    pub host_call_policies: BTreeMap<String, HostCallPolicy>,
    pub storage_policies: BTreeMap<String, StorageAccessPolicy>,
    pub upgrade_timelocks: BTreeMap<String, UpgradeTimelock>,
    pub emergency_deprecations: BTreeMap<String, EmergencyDeprecation>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub runtime_manifests: BTreeMap<String, DeterministicRuntimeManifest>,
    pub abi_manifests: BTreeMap<String, DeterministicAbiManifest>,
    pub audit_attestations: BTreeMap<String, AuditAttestation>,
    pub public_records: BTreeMap<String, ContractPolicyPublicRecord>,
}

impl ContractExecutionPolicyState {
    pub fn new(config: ContractExecutionPolicyConfig) -> Self {
        Self {
            config,
            height: 0,
            execution_caps: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            pq_signatures: BTreeMap::new(),
            verifier_key_pins: BTreeMap::new(),
            host_call_policies: BTreeMap::new(),
            storage_policies: BTreeMap::new(),
            upgrade_timelocks: BTreeMap::new(),
            emergency_deprecations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            runtime_manifests: BTreeMap::new(),
            abi_manifests: BTreeMap::new(),
            audit_attestations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ContractExecutionPolicyResult<Self> {
        let mut state = Self::new(ContractExecutionPolicyConfig::devnet());
        state.set_height(42);

        let contract_id = contract_execution_policy_label_root("devnet-private-contract");
        let deploy_message_root = contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-DEVNET-DEPLOY-MESSAGE",
            &json!({
                "contract_id": contract_id,
                "runtime": "devnet-private-contract",
                "chain_id": CHAIN_ID,
            }),
        );
        let deployer_signature = PqAuthorizationSignature::new(
            PqSignerRole::Deployer,
            "devnet-deployer",
            "devnet-deployer-pq-key",
            contract_execution_policy_label_root("devnet-deployer-pq-public-key"),
            PqSignatureScheme::HybridMlDsa65SlhDsa128s,
            deploy_message_root,
            "contract_deployment",
            contract_id.clone(),
            state.height,
            10_080,
        )?;
        let deployer_signature_id = state.add_pq_signature(deployer_signature)?;

        let admin_message_root = contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-DEVNET-ADMIN-MESSAGE",
            &json!({
                "contract_id": contract_id,
                "admin_policy": "devnet-admin-policy",
                "chain_id": CHAIN_ID,
            }),
        );
        let admin_signature = PqAuthorizationSignature::new(
            PqSignerRole::Admin,
            "devnet-admin",
            "devnet-admin-pq-key",
            contract_execution_policy_label_root("devnet-admin-pq-public-key"),
            PqSignatureScheme::HybridMlDsa65SlhDsa128s,
            admin_message_root.clone(),
            "contract_admin_policy",
            contract_id.clone(),
            state.height,
            10_080,
        )?;
        let admin_signature_id = state.add_pq_signature(admin_signature)?;

        let emergency_signature = PqAuthorizationSignature::new(
            PqSignerRole::EmergencyAdmin,
            "devnet-emergency-admin",
            "devnet-emergency-pq-key",
            contract_execution_policy_label_root("devnet-emergency-pq-public-key"),
            PqSignatureScheme::HybridMlDsa65SlhDsa128s,
            admin_message_root,
            "contract_emergency_deprecation",
            contract_id.clone(),
            state.height,
            10_080,
        )?;
        let emergency_signature_id = state.add_pq_signature(emergency_signature)?;

        let sponsor_signature = PqAuthorizationSignature::new(
            PqSignerRole::Sponsor,
            "devnet-sponsor",
            "devnet-sponsor-pq-key",
            contract_execution_policy_label_root("devnet-sponsor-pq-public-key"),
            PqSignatureScheme::MlDsa65,
            contract_execution_policy_payload_root(
                "CONTRACT-EXECUTION-DEVNET-SPONSOR-MESSAGE",
                &json!({"contract_id": contract_id, "scope": "contract_call"}),
            ),
            "low_fee_sponsorship",
            contract_id.clone(),
            state.height,
            state.config.sponsorship_epoch_blocks,
        )?;
        let sponsor_signature_id = state.add_pq_signature(sponsor_signature)?;

        let host_permissions = vec![
            "private_contract_execute".to_string(),
            "private_contract_host_call".to_string(),
        ];
        let execution_phases = vec![
            ExecutionPhase::Admission,
            ExecutionPhase::Execute,
            ExecutionPhase::PostExecute,
            ExecutionPhase::Prove,
        ];
        let mut host_policies = Vec::new();
        for host_call_kind in [
            HostCallKind::StorageRead,
            HostCallKind::StorageWrite,
            HostCallKind::EmitEvent,
            HostCallKind::VerifyPqSignature,
            HostCallKind::VerifyPrivacyProof,
            HostCallKind::CallPaymaster,
            HostCallKind::ScheduleProof,
        ] {
            let policy = HostCallPolicy::new(
                contract_id.clone(),
                host_call_kind.clone(),
                &host_permissions,
                &execution_phases,
                96,
                host_call_kind.default_fuel_cost(),
                host_call_kind.default_fuel_cost() / 2,
                if matches!(
                    host_call_kind,
                    HostCallKind::EmitEvent | HostCallKind::VerifyPrivacyProof
                ) {
                    25
                } else {
                    0
                },
                matches!(host_call_kind, HostCallKind::StorageWrite),
                matches!(host_call_kind, HostCallKind::VerifyPrivacyProof),
                state.height,
            )?;
            host_policies.push(policy.clone());
            state.add_host_call_policy(policy)?;
        }

        let disclosure_root = contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-DEVNET-DISCLOSURE",
            &json!({"policy": "auditor-decryptable-on-warrant", "chain_id": CHAIN_ID}),
        );
        let audit_policy_root = contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-DEVNET-AUDIT-POLICY",
            &json!({"auditors": ["devnet-auditor"], "threshold": 1}),
        );
        let storage_policies = vec![
            StorageAccessPolicy::new(
                contract_id.clone(),
                "shielded-ledger",
                StorageAccessMode::ReadWrite,
                StorageIsolationLevel::ContractLocal,
                &[
                    "notes".to_string(),
                    "nullifiers".to_string(),
                    "balances".to_string(),
                ],
                1_024,
                256,
                16 * 1024,
                true,
                disclosure_root.clone(),
                audit_policy_root.clone(),
                state.height,
            )?,
            StorageAccessPolicy::new(
                contract_id.clone(),
                "runtime-config",
                StorageAccessMode::ReadOnly,
                StorageIsolationLevel::SharedRead,
                &["config".to_string(), "limits".to_string()],
                256,
                0,
                8 * 1024,
                false,
                disclosure_root.clone(),
                audit_policy_root.clone(),
                state.height,
            )?,
        ];
        for policy in &storage_policies {
            state.add_storage_policy(policy.clone())?;
        }

        let privacy_budget = PrivacyBudgetPolicy::new(
            contract_id.clone(),
            "0x00000001",
            PrivacyMeterKind::ShieldedState,
            120,
            state.config.default_privacy_budget_units,
            512,
            state.config.min_anonymity_set,
            disclosure_root.clone(),
            audit_policy_root.clone(),
            contract_execution_policy_label_root("devnet-nullifier-domain"),
            500,
            state.height,
        )?;
        let privacy_budget_id = state.add_privacy_budget(privacy_budget.clone())?;

        let verifier_pin_signature = PqAuthorizationSignature::new(
            PqSignerRole::VerifierKeyMaintainer,
            "devnet-verifier-maintainer",
            "devnet-verifier-maintainer-pq-key",
            contract_execution_policy_label_root("devnet-verifier-maintainer-pq-public-key"),
            PqSignatureScheme::HybridMlDsa65SlhDsa128s,
            contract_execution_policy_payload_root(
                "CONTRACT-EXECUTION-DEVNET-VK-MESSAGE",
                &json!({"contract_id": contract_id, "purpose": "contract_call"}),
            ),
            "verifier_key_pin",
            contract_id.clone(),
            state.height,
            10_080,
        )?;
        let verifier_pin_signature_id = state.add_pq_signature(verifier_pin_signature)?;
        let verifier_audit_root = contract_execution_policy_payload_root(
            "CONTRACT-EXECUTION-DEVNET-VERIFIER-AUDIT",
            &json!({"audit": "devnet-verifier-key-review", "auditor": "devnet-auditor"}),
        );
        let verifier_key_pin = VerifierKeyPin::new(
            "devnet-private-contract-call-vk",
            VerifierKeyPurpose::ContractCall,
            "private_contract_call",
            "shake-plonk-devnet",
            contract_execution_policy_label_root("devnet-private-contract-call-vk-hash"),
            verifier_pin_signature_id,
            verifier_audit_root,
            state.config.min_pq_security_bits,
            state.height,
            None,
        )?;
        let verifier_key_root = verifier_key_pin.verifier_key_root.clone();
        state.add_verifier_key_pin(verifier_key_pin)?;

        let host_call_allowlist_root = host_call_policy_root(&host_policies);
        let storage_policy_root = storage_access_policy_root(&storage_policies);
        let privacy_budget_root = privacy_budget_policy_root_from_slice(&[privacy_budget]);
        let execution_cap = ExecutionCapPolicy::new(
            contract_id.clone(),
            "0x00000001",
            ContractExecutionKind::Call,
            6_000_000,
            2_250_000,
            48,
            256,
            1_024,
            256,
            24 * 1024,
            8,
            50_000,
            verifier_key_root.clone(),
            host_call_allowlist_root.clone(),
            storage_policy_root.clone(),
            privacy_budget_root,
            state.height,
            None,
        )?;
        let execution_cap_id = state.add_execution_cap(execution_cap.clone())?;

        let abi_method = AbiMethodPin::new(
            contract_id.clone(),
            "0x00000001",
            "execute_private",
            contract_execution_policy_payload_root(
                "CONTRACT-EXECUTION-DEVNET-ABI-ARGS",
                &json!({"type": "shielded_call_args"}),
            ),
            contract_execution_policy_payload_root(
                "CONTRACT-EXECUTION-DEVNET-ABI-RETURNS",
                &json!({"type": "private_execution_receipt"}),
            ),
            privacy_budget_id,
            execution_cap_id,
            &host_policies,
        )?;
        let abi_manifest = DeterministicAbiManifest::new(
            contract_id.clone(),
            "1.0.0",
            std::slice::from_ref(&abi_method),
            contract_execution_policy_label_root("devnet-type-schema-root"),
            contract_execution_policy_label_root("devnet-event-schema-root"),
            contract_execution_policy_label_root("devnet-error-schema-root"),
            contract_execution_policy_payload_root(
                "CONTRACT-EXECUTION-DEVNET-SELECTOR-COLLISIONS",
                &json!({"selectors": ["0x00000001"], "collisions": []}),
            ),
            state.height,
        )?;
        let abi_manifest_root_value = abi_manifest.manifest_root();
        state.add_abi_manifest(abi_manifest)?;

        let runtime_manifest = DeterministicRuntimeManifest::new(
            contract_id.clone(),
            "devnet-private-contract-runtime",
            "1.0.0",
            contract_execution_policy_label_root("devnet-private-contract-wasm"),
            contract_execution_policy_label_root("devnet-private-contract-build"),
            contract_execution_policy_label_root("rustc-devnet-reproducible-toolchain"),
            contract_execution_policy_payload_root(
                "CONTRACT-EXECUTION-DEVNET-HOST-PROFILE",
                &json!({"runtime_profile": CONTRACT_EXECUTION_POLICY_RUNTIME_PROFILE}),
            ),
            host_call_allowlist_root,
            storage_policy_root,
            verifier_key_root,
            abi_manifest_root_value,
            deployer_signature_id.clone(),
            admin_signature_id.clone(),
            196_608,
        )?;
        let runtime_manifest_root_value = runtime_manifest.manifest_root();
        let runtime_manifest_id = state.add_runtime_manifest(runtime_manifest)?;

        let auditor_signature = PqAuthorizationSignature::new(
            PqSignerRole::Auditor,
            "devnet-auditor",
            "devnet-auditor-pq-key",
            contract_execution_policy_label_root("devnet-auditor-pq-public-key"),
            PqSignatureScheme::HybridMlDsa65SlhDsa128s,
            runtime_manifest_root_value.clone(),
            "audit_attestation",
            runtime_manifest_id.clone(),
            state.height,
            state.config.max_audit_age_blocks,
        )?;
        let auditor_signature_id = state.add_pq_signature(auditor_signature)?;
        let attestation = AuditAttestation::new(
            "devnet-auditor",
            contract_execution_policy_label_root("devnet-auditor-pq-public-key"),
            AuditAttestationKind::RuntimeDeterminism,
            "runtime_manifest",
            runtime_manifest_id.clone(),
            runtime_manifest_root_value.clone(),
            contract_execution_policy_label_root("devnet-runtime-audit-evidence"),
            contract_execution_policy_label_root("devnet-runtime-audit-report"),
            "passed",
            state.height,
            state.config.max_audit_age_blocks,
            auditor_signature_id,
        )?;
        state.add_audit_attestation(attestation)?;

        let sponsorship = LowFeeSponsorship::new(
            contract_execution_policy_label_root("devnet-sponsor-commitment"),
            contract_id.clone(),
            SponsorshipScope::ContractCall,
            "0x00000001",
            "wxmr-devnet",
            50_000,
            5_000,
            state.config.min_anonymity_set,
            state.height,
            state.config.sponsorship_epoch_blocks,
            sponsor_signature_id,
        )?;
        state.add_sponsorship(sponsorship)?;

        let upgrade = UpgradeTimelock::new(
            contract_id.clone(),
            runtime_manifest_root_value.clone(),
            contract_execution_policy_label_root("devnet-private-contract-next-runtime"),
            admin_signature_id,
            pq_signature_root_from_map(&state.pq_signatures),
            state.height,
            state.config.upgrade_delay_blocks,
            state.config.upgrade_delay_blocks,
            false,
        )?;
        state.queue_upgrade(upgrade)?;

        let emergency_deprecation = EmergencyDeprecation::new(
            contract_id,
            "devnet-watch-only",
            None,
            state.height,
            state.config.deprecation_grace_blocks,
            emergency_signature_id,
            contract_execution_policy_label_root("devnet-emergency-disclosure-record"),
        )?;
        state.record_emergency_deprecation(emergency_deprecation)?;

        let public_record = ContractPolicyPublicRecord::new(
            "runtime_manifest",
            runtime_manifest_id,
            runtime_manifest_root_value.clone(),
            runtime_manifest_root_value,
            contract_execution_policy_label_root("devnet-public-record-redactions"),
            state.height,
            0,
        )?;
        state.emit_public_record(public_record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for budget in self.privacy_budgets.values_mut() {
            budget.set_height(height);
        }
        for timelock in self.upgrade_timelocks.values_mut() {
            if timelock.status == TimelockStatus::Queued && timelock.executable_at(height) {
                timelock.status = TimelockStatus::Ready;
            } else if height > timelock.expires_at_height
                && timelock.status == TimelockStatus::Queued
            {
                timelock.status = TimelockStatus::Expired;
            }
        }
        for deprecation in self.emergency_deprecations.values_mut() {
            if deprecation.status == EmergencyDeprecationStatus::Announced
                && deprecation.active_at(height)
            {
                deprecation.status = EmergencyDeprecationStatus::Effective;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if height > sponsorship.epoch_end_height
                && sponsorship.status == SponsorshipStatus::Active
            {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
    }

    pub fn add_execution_cap(
        &mut self,
        policy: ExecutionCapPolicy,
    ) -> ContractExecutionPolicyResult<String> {
        let policy_id = policy.policy_id.clone();
        if self.execution_caps.contains_key(&policy_id) {
            return Err(format!("execution cap already exists: {policy_id}"));
        }
        self.execution_caps.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn add_privacy_budget(
        &mut self,
        budget: PrivacyBudgetPolicy,
    ) -> ContractExecutionPolicyResult<String> {
        let budget_id = budget.budget_id.clone();
        if self.privacy_budgets.contains_key(&budget_id) {
            return Err(format!("privacy budget already exists: {budget_id}"));
        }
        self.privacy_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn add_pq_signature(
        &mut self,
        signature: PqAuthorizationSignature,
    ) -> ContractExecutionPolicyResult<String> {
        let signature_id = signature.signature_id.clone();
        if self.pq_signatures.contains_key(&signature_id) {
            return Err(format!("pq signature already exists: {signature_id}"));
        }
        self.pq_signatures.insert(signature_id.clone(), signature);
        Ok(signature_id)
    }

    pub fn add_verifier_key_pin(
        &mut self,
        pin: VerifierKeyPin,
    ) -> ContractExecutionPolicyResult<String> {
        if !self.pq_signatures.contains_key(&pin.pinned_by_signature_id) {
            return Err("verifier key pin references missing pq signature".to_string());
        }
        let pin_id = pin.pin_id.clone();
        if self.verifier_key_pins.contains_key(&pin_id) {
            return Err(format!("verifier key pin already exists: {pin_id}"));
        }
        self.verifier_key_pins.insert(pin_id.clone(), pin);
        Ok(pin_id)
    }

    pub fn add_host_call_policy(
        &mut self,
        policy: HostCallPolicy,
    ) -> ContractExecutionPolicyResult<String> {
        let host_call_id = policy.host_call_id.clone();
        if self.host_call_policies.contains_key(&host_call_id) {
            return Err(format!("host call policy already exists: {host_call_id}"));
        }
        self.host_call_policies.insert(host_call_id.clone(), policy);
        Ok(host_call_id)
    }

    pub fn add_storage_policy(
        &mut self,
        policy: StorageAccessPolicy,
    ) -> ContractExecutionPolicyResult<String> {
        let storage_policy_id = policy.storage_policy_id.clone();
        if self.storage_policies.contains_key(&storage_policy_id) {
            return Err(format!(
                "storage policy already exists: {storage_policy_id}"
            ));
        }
        self.storage_policies
            .insert(storage_policy_id.clone(), policy);
        Ok(storage_policy_id)
    }

    pub fn queue_upgrade(
        &mut self,
        timelock: UpgradeTimelock,
    ) -> ContractExecutionPolicyResult<String> {
        if !self
            .pq_signatures
            .contains_key(&timelock.proposer_signature_id)
        {
            return Err("upgrade timelock references missing proposer signature".to_string());
        }
        let timelock_id = timelock.timelock_id.clone();
        if self.upgrade_timelocks.contains_key(&timelock_id) {
            return Err(format!("upgrade timelock already exists: {timelock_id}"));
        }
        self.upgrade_timelocks.insert(timelock_id.clone(), timelock);
        Ok(timelock_id)
    }

    pub fn record_emergency_deprecation(
        &mut self,
        deprecation: EmergencyDeprecation,
    ) -> ContractExecutionPolicyResult<String> {
        if !self
            .pq_signatures
            .contains_key(&deprecation.emergency_signature_id)
        {
            return Err("emergency deprecation references missing signature".to_string());
        }
        let deprecation_id = deprecation.deprecation_id.clone();
        if self.emergency_deprecations.contains_key(&deprecation_id) {
            return Err(format!(
                "emergency deprecation already exists: {deprecation_id}"
            ));
        }
        self.emergency_deprecations
            .insert(deprecation_id.clone(), deprecation);
        Ok(deprecation_id)
    }

    pub fn add_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsorship,
    ) -> ContractExecutionPolicyResult<String> {
        if !self.pq_signatures.contains_key(&sponsorship.signature_id) {
            return Err("low fee sponsorship references missing signature".to_string());
        }
        if sponsorship.budget_units > self.config.max_sponsorship_budget_units {
            return Err("low fee sponsorship exceeds configured max budget".to_string());
        }
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        if self.sponsorships.contains_key(&sponsorship_id) {
            return Err(format!(
                "low fee sponsorship already exists: {sponsorship_id}"
            ));
        }
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn add_runtime_manifest(
        &mut self,
        manifest: DeterministicRuntimeManifest,
    ) -> ContractExecutionPolicyResult<String> {
        if self.config.require_deployer_signature
            && !self
                .pq_signatures
                .contains_key(&manifest.deployer_signature_id)
        {
            return Err("runtime manifest missing deployer signature".to_string());
        }
        if self.config.require_admin_signature
            && !self
                .pq_signatures
                .contains_key(&manifest.admin_signature_id)
        {
            return Err("runtime manifest missing admin signature".to_string());
        }
        if manifest.bytecode_size_bytes > self.config.max_manifest_bytes {
            return Err("runtime manifest bytecode exceeds configured max".to_string());
        }
        let manifest_id = manifest.manifest_id.clone();
        if self.runtime_manifests.contains_key(&manifest_id) {
            return Err(format!("runtime manifest already exists: {manifest_id}"));
        }
        self.runtime_manifests.insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn add_abi_manifest(
        &mut self,
        manifest: DeterministicAbiManifest,
    ) -> ContractExecutionPolicyResult<String> {
        let manifest_id = manifest.manifest_id.clone();
        if self.abi_manifests.contains_key(&manifest_id) {
            return Err(format!("abi manifest already exists: {manifest_id}"));
        }
        self.abi_manifests.insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn add_audit_attestation(
        &mut self,
        attestation: AuditAttestation,
    ) -> ContractExecutionPolicyResult<String> {
        if !self.pq_signatures.contains_key(&attestation.signature_id) {
            return Err("audit attestation references missing signature".to_string());
        }
        let attestation_id = attestation.attestation_id.clone();
        if self.audit_attestations.contains_key(&attestation_id) {
            return Err(format!(
                "audit attestation already exists: {attestation_id}"
            ));
        }
        self.audit_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn emit_public_record(
        &mut self,
        record: ContractPolicyPublicRecord,
    ) -> ContractExecutionPolicyResult<String> {
        let record_id = record.record_id.clone();
        if self.public_records.contains_key(&record_id) {
            return Err(format!(
                "contract policy public record already exists: {record_id}"
            ));
        }
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn counters(&self) -> ContractExecutionPolicyCounters {
        ContractExecutionPolicyCounters {
            execution_cap_count: self.execution_caps.len() as u64,
            active_execution_cap_count: self
                .execution_caps
                .values()
                .filter(|policy| policy.active_at(self.height))
                .count() as u64,
            privacy_budget_count: self.privacy_budgets.len() as u64,
            exhausted_privacy_budget_count: self
                .privacy_budgets
                .values()
                .filter(|budget| budget.available_units() == 0)
                .count() as u64,
            pq_signature_count: self.pq_signatures.len() as u64,
            verifier_key_pin_count: self.verifier_key_pins.len() as u64,
            host_call_policy_count: self.host_call_policies.len() as u64,
            storage_policy_count: self.storage_policies.len() as u64,
            pending_upgrade_count: self
                .upgrade_timelocks
                .values()
                .filter(|timelock| {
                    matches!(
                        timelock.status,
                        TimelockStatus::Queued | TimelockStatus::Ready
                    )
                })
                .count() as u64,
            active_deprecation_count: self
                .emergency_deprecations
                .values()
                .filter(|deprecation| deprecation.active_at(self.height))
                .count() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            available_sponsor_units: self
                .sponsorships
                .values()
                .map(LowFeeSponsorship::available_units)
                .sum(),
            runtime_manifest_count: self.runtime_manifests.len() as u64,
            abi_manifest_count: self.abi_manifests.len() as u64,
            audit_attestation_count: self.audit_attestations.len() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn roots(&self) -> ContractExecutionPolicyRoots {
        let config_root = self.config.config_root();
        let execution_cap_root = execution_cap_policy_root_from_map(&self.execution_caps);
        let privacy_budget_root = privacy_budget_policy_root_from_map(&self.privacy_budgets);
        let pq_signature_root = pq_signature_root_from_map(&self.pq_signatures);
        let verifier_key_pin_root = verifier_key_pin_root_from_map(&self.verifier_key_pins);
        let host_call_policy_root = host_call_policy_root_from_map(&self.host_call_policies);
        let storage_policy_root = storage_access_policy_root_from_map(&self.storage_policies);
        let upgrade_timelock_root = upgrade_timelock_root_from_map(&self.upgrade_timelocks);
        let emergency_deprecation_root =
            emergency_deprecation_root_from_map(&self.emergency_deprecations);
        let sponsorship_root = low_fee_sponsorship_root_from_map(&self.sponsorships);
        let runtime_manifest_root = runtime_manifest_root_from_map(&self.runtime_manifests);
        let abi_manifest_root = abi_manifest_root_from_map(&self.abi_manifests);
        let audit_attestation_root = audit_attestation_root_from_map(&self.audit_attestations);
        let public_record_root = contract_policy_public_record_root_from_map(&self.public_records);
        let root_record = json!({
            "config_root": config_root,
            "execution_cap_root": execution_cap_root,
            "privacy_budget_root": privacy_budget_root,
            "pq_signature_root": pq_signature_root,
            "verifier_key_pin_root": verifier_key_pin_root,
            "host_call_policy_root": host_call_policy_root,
            "storage_policy_root": storage_policy_root,
            "upgrade_timelock_root": upgrade_timelock_root,
            "emergency_deprecation_root": emergency_deprecation_root,
            "sponsorship_root": sponsorship_root,
            "runtime_manifest_root": runtime_manifest_root,
            "abi_manifest_root": abi_manifest_root,
            "audit_attestation_root": audit_attestation_root,
            "public_record_root": public_record_root,
        });
        let aggregate_root =
            contract_execution_policy_payload_root("CONTRACT-EXECUTION-POLICY-ROOTS", &root_record);
        let state_commitment = json!({
            "kind": "contract_execution_policy_state_commitment",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": config_root,
            "aggregate_root": aggregate_root,
            "counters_root": self.counters().counters_root(),
        });
        let state_root = contract_execution_policy_state_root_from_record(&state_commitment);
        ContractExecutionPolicyRoots {
            config_root,
            execution_cap_root,
            privacy_budget_root,
            pq_signature_root,
            verifier_key_pin_root,
            host_call_policy_root,
            storage_policy_root,
            upgrade_timelock_root,
            emergency_deprecation_root,
            sponsorship_root,
            runtime_manifest_root,
            abi_manifest_root,
            audit_attestation_root,
            public_record_root,
            aggregate_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_execution_policy_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION,
            "schema_version": CONTRACT_EXECUTION_POLICY_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn validate(&self) -> ContractExecutionPolicyResult<String> {
        self.config.validate()?;
        for signature in self.pq_signatures.values() {
            validate_pq_signature(signature, self.config.min_pq_security_bits)?;
        }
        for pin in self.verifier_key_pins.values() {
            validate_verifier_key_pin(pin, self.config.min_pq_security_bits)?;
            if !self.pq_signatures.contains_key(&pin.pinned_by_signature_id) {
                return Err(format!(
                    "verifier key pin references missing signature: {}",
                    pin.pin_id
                ));
            }
        }
        for budget in self.privacy_budgets.values() {
            if budget.reserved_units.saturating_add(budget.spent_units) > budget.max_budget_units {
                return Err(format!("privacy budget overdrawn: {}", budget.budget_id));
            }
            if budget.disclosure_count > budget.max_disclosure_count {
                return Err(format!(
                    "privacy budget disclosure count exceeded: {}",
                    budget.budget_id
                ));
            }
            if budget.min_anonymity_set < self.config.min_anonymity_set {
                return Err(format!(
                    "privacy budget below anonymity floor: {}",
                    budget.budget_id
                ));
            }
        }
        for policy in self.host_call_policies.values() {
            if policy.max_invocations_per_tx > self.config.max_host_calls {
                return Err(format!(
                    "host call invocations exceed global cap: {}",
                    policy.host_call_id
                ));
            }
            if policy.fuel_cost > self.config.max_global_fuel_per_tx {
                return Err(format!(
                    "host call fuel exceeds tx cap: {}",
                    policy.host_call_id
                ));
            }
        }
        for policy in self.storage_policies.values() {
            if policy.read_budget > self.config.max_storage_reads {
                return Err(format!(
                    "storage policy read budget exceeds global cap: {}",
                    policy.storage_policy_id
                ));
            }
            if policy.write_budget > self.config.max_storage_writes {
                return Err(format!(
                    "storage policy write budget exceeds global cap: {}",
                    policy.storage_policy_id
                ));
            }
            if policy.max_value_bytes > self.config.max_event_bytes {
                return Err(format!(
                    "storage policy value bytes exceed event byte cap: {}",
                    policy.storage_policy_id
                ));
            }
        }
        for cap in self.execution_caps.values() {
            if cap.max_fuel > self.config.max_global_fuel_per_tx {
                return Err(format!(
                    "execution cap fuel exceeds global cap: {}",
                    cap.policy_id
                ));
            }
            if cap.max_gas_units > self.config.max_global_gas_per_tx {
                return Err(format!(
                    "execution cap gas exceeds global cap: {}",
                    cap.policy_id
                ));
            }
            if cap.max_memory_pages > self.config.max_memory_pages {
                return Err(format!(
                    "execution cap memory exceeds global cap: {}",
                    cap.policy_id
                ));
            }
            if cap.max_host_calls > self.config.max_host_calls {
                return Err(format!(
                    "execution cap host calls exceed global cap: {}",
                    cap.policy_id
                ));
            }
            if cap.max_storage_reads > self.config.max_storage_reads {
                return Err(format!(
                    "execution cap storage reads exceed global cap: {}",
                    cap.policy_id
                ));
            }
            if cap.max_storage_writes > self.config.max_storage_writes {
                return Err(format!(
                    "execution cap storage writes exceed global cap: {}",
                    cap.policy_id
                ));
            }
            if cap.max_event_bytes > self.config.max_event_bytes {
                return Err(format!(
                    "execution cap event bytes exceed global cap: {}",
                    cap.policy_id
                ));
            }
            if self.config.require_verifier_key_pin && self.verifier_key_pins.is_empty() {
                return Err("execution policy requires verifier key pins".to_string());
            }
        }
        for manifest in self.runtime_manifests.values() {
            if self.config.require_deployer_signature
                && !self
                    .pq_signatures
                    .contains_key(&manifest.deployer_signature_id)
            {
                return Err(format!(
                    "runtime manifest missing deployer signature: {}",
                    manifest.manifest_id
                ));
            }
            if self.config.require_admin_signature
                && !self
                    .pq_signatures
                    .contains_key(&manifest.admin_signature_id)
            {
                return Err(format!(
                    "runtime manifest missing admin signature: {}",
                    manifest.manifest_id
                ));
            }
            if manifest.bytecode_size_bytes > self.config.max_manifest_bytes {
                return Err(format!(
                    "runtime manifest exceeds byte limit: {}",
                    manifest.manifest_id
                ));
            }
        }
        for timelock in self.upgrade_timelocks.values() {
            if !self
                .pq_signatures
                .contains_key(&timelock.proposer_signature_id)
            {
                return Err(format!(
                    "upgrade timelock references missing signature: {}",
                    timelock.timelock_id
                ));
            }
            let required_delay = if timelock.emergency_override {
                self.config.emergency_delay_blocks
            } else {
                self.config.upgrade_delay_blocks
            };
            if timelock.earliest_execution_height
                < timelock.queued_at_height.saturating_add(required_delay)
            {
                return Err(format!(
                    "upgrade timelock delay is below policy: {}",
                    timelock.timelock_id
                ));
            }
            if timelock.expires_at_height <= timelock.earliest_execution_height {
                return Err(format!(
                    "upgrade timelock expiry invalid: {}",
                    timelock.timelock_id
                ));
            }
        }
        for deprecation in self.emergency_deprecations.values() {
            if !self
                .pq_signatures
                .contains_key(&deprecation.emergency_signature_id)
            {
                return Err(format!(
                    "emergency deprecation references missing signature: {}",
                    deprecation.deprecation_id
                ));
            }
            if deprecation.effective_at_height < deprecation.announced_at_height {
                return Err(format!(
                    "emergency deprecation effective height invalid: {}",
                    deprecation.deprecation_id
                ));
            }
        }
        for sponsorship in self.sponsorships.values() {
            if !self.config.allow_low_fee_sponsorship {
                return Err("low fee sponsorship disabled by config".to_string());
            }
            if !self.pq_signatures.contains_key(&sponsorship.signature_id) {
                return Err(format!(
                    "low fee sponsorship references missing signature: {}",
                    sponsorship.sponsorship_id
                ));
            }
            if sponsorship.budget_units > self.config.max_sponsorship_budget_units {
                return Err(format!(
                    "low fee sponsorship exceeds budget cap: {}",
                    sponsorship.sponsorship_id
                ));
            }
            if sponsorship
                .reserved_units
                .saturating_add(sponsorship.spent_units)
                > sponsorship.budget_units
            {
                return Err(format!(
                    "low fee sponsorship overdrawn: {}",
                    sponsorship.sponsorship_id
                ));
            }
            if sponsorship.privacy_floor < self.config.min_anonymity_set {
                return Err(format!(
                    "low fee sponsorship below privacy floor: {}",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for attestation in self.audit_attestations.values() {
            if !self.pq_signatures.contains_key(&attestation.signature_id) {
                return Err(format!(
                    "audit attestation references missing signature: {}",
                    attestation.attestation_id
                ));
            }
            if attestation.expires_at_height <= attestation.issued_at_height {
                return Err(format!(
                    "audit attestation expiry invalid: {}",
                    attestation.attestation_id
                ));
            }
        }
        Ok(self.state_root())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execution_cap_policy_id(
    contract_id: &str,
    method_selector: &str,
    execution_kind: ContractExecutionKind,
    max_fuel: u64,
    max_gas_units: u64,
    verifier_key_root: &str,
    host_call_allowlist_root: &str,
    storage_policy_root: &str,
    privacy_budget_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-CAP-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(method_selector),
            HashPart::Str(execution_kind.as_str()),
            HashPart::Int(max_fuel as i128),
            HashPart::Int(max_gas_units as i128),
            HashPart::Str(verifier_key_root),
            HashPart::Str(host_call_allowlist_root),
            HashPart::Str(storage_policy_root),
            HashPart::Str(privacy_budget_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn privacy_budget_policy_id(
    contract_id: &str,
    method_selector: &str,
    meter_kind: PrivacyMeterKind,
    epoch_length_blocks: u64,
    max_budget_units: u64,
    min_anonymity_set: u64,
    allowed_disclosure_root: &str,
    auditor_set_root: &str,
    nullifier_domain_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(method_selector),
            HashPart::Str(meter_kind.as_str()),
            HashPart::Int(epoch_length_blocks as i128),
            HashPart::Int(max_budget_units as i128),
            HashPart::Int(min_anonymity_set as i128),
            HashPart::Str(allowed_disclosure_root),
            HashPart::Str(auditor_set_root),
            HashPart::Str(nullifier_domain_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_authorization_transcript_hash(
    role: PqSignerRole,
    signer_key_id: &str,
    signer_public_key_root: &str,
    scheme: PqSignatureScheme,
    message_root: &str,
    authorizes_subject_kind: &str,
    authorizes_subject_id: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-PQ-AUTH-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_key_id),
            HashPart::Str(signer_public_key_root),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(message_root),
            HashPart::Str(authorizes_subject_kind),
            HashPart::Str(authorizes_subject_id),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn pq_authorization_signature_root(
    signer_label: &str,
    signer_key_id: &str,
    scheme: PqSignatureScheme,
    transcript_hash: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-PQ-AUTH-SIGNATURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(signer_label),
            HashPart::Str(signer_key_id),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(transcript_hash),
        ],
        32,
    )
}

pub fn pq_authorization_signature_id(
    role: PqSignerRole,
    signer_key_id: &str,
    scheme: PqSignatureScheme,
    transcript_hash: &str,
    signature_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-PQ-AUTH-SIGNATURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_key_id),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(transcript_hash),
            HashPart::Str(signature_root),
        ],
        32,
    )
}

pub fn verifier_key_public_root(
    verifier_key_id: &str,
    purpose: VerifierKeyPurpose,
    circuit_family: &str,
    proof_system: &str,
    verifier_key_hash: &str,
    minimum_security_bits: u16,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-VERIFIER-KEY-PUBLIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(verifier_key_id),
            HashPart::Str(purpose.as_str()),
            HashPart::Str(circuit_family),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_hash),
            HashPart::Int(minimum_security_bits as i128),
        ],
        32,
    )
}

pub fn verifier_key_pin_id(
    verifier_key_id: &str,
    purpose: VerifierKeyPurpose,
    verifier_key_root: &str,
    pinned_by_signature_id: &str,
    audit_attestation_root: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-VERIFIER-KEY-PIN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(verifier_key_id),
            HashPart::Str(purpose.as_str()),
            HashPart::Str(verifier_key_root),
            HashPart::Str(pinned_by_signature_id),
            HashPart::Str(audit_attestation_root),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

pub fn host_call_policy_id(
    contract_id: &str,
    host_call_label: &str,
    permission_root: &str,
    allowed_phase_root: &str,
    max_invocations_per_tx: u64,
    fuel_cost: u64,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-HOST-CALL-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(host_call_label),
            HashPart::Str(permission_root),
            HashPart::Str(allowed_phase_root),
            HashPart::Int(max_invocations_per_tx as i128),
            HashPart::Int(fuel_cost as i128),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn storage_access_policy_id(
    contract_id: &str,
    namespace: &str,
    mode: StorageAccessMode,
    isolation: StorageIsolationLevel,
    key_scope_root: &str,
    read_budget: u64,
    write_budget: u64,
    disclosure_policy_root: &str,
    audit_policy_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-STORAGE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(namespace),
            HashPart::Str(mode.as_str()),
            HashPart::Str(isolation.as_str()),
            HashPart::Str(key_scope_root),
            HashPart::Int(read_budget as i128),
            HashPart::Int(write_budget as i128),
            HashPart::Str(disclosure_policy_root),
            HashPart::Str(audit_policy_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn abi_method_pin_id(
    contract_id: &str,
    selector: &str,
    method_name: &str,
    arg_schema_root: &str,
    return_schema_root: &str,
    privacy_budget_id: &str,
    execution_cap_id: &str,
    required_host_call_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-ABI-METHOD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Str(method_name),
            HashPart::Str(arg_schema_root),
            HashPart::Str(return_schema_root),
            HashPart::Str(privacy_budget_id),
            HashPart::Str(execution_cap_id),
            HashPart::Str(required_host_call_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn abi_manifest_id(
    contract_id: &str,
    abi_version: &str,
    method_root: &str,
    type_schema_root: &str,
    event_schema_root: &str,
    error_schema_root: &str,
    canonical_json_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-ABI-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(abi_version),
            HashPart::Str(method_root),
            HashPart::Str(type_schema_root),
            HashPart::Str(event_schema_root),
            HashPart::Str(error_schema_root),
            HashPart::Str(canonical_json_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_manifest_id(
    contract_id: &str,
    runtime_name: &str,
    runtime_version: &str,
    wasm_code_hash: &str,
    deterministic_build_root: &str,
    allowed_host_call_root: &str,
    storage_policy_root: &str,
    verifier_key_root: &str,
    abi_manifest_root: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-RUNTIME-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(runtime_name),
            HashPart::Str(runtime_version),
            HashPart::Str(wasm_code_hash),
            HashPart::Str(deterministic_build_root),
            HashPart::Str(allowed_host_call_root),
            HashPart::Str(storage_policy_root),
            HashPart::Str(verifier_key_root),
            HashPart::Str(abi_manifest_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn upgrade_timelock_id(
    contract_id: &str,
    from_manifest_root: &str,
    to_manifest_root: &str,
    proposer_signature_id: &str,
    admin_signature_root: &str,
    queued_at_height: u64,
    earliest_execution_height: u64,
    emergency_override: bool,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-UPGRADE-TIMELOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(from_manifest_root),
            HashPart::Str(to_manifest_root),
            HashPart::Str(proposer_signature_id),
            HashPart::Str(admin_signature_root),
            HashPart::Int(queued_at_height as i128),
            HashPart::Int(earliest_execution_height as i128),
            HashPart::Int(bool_int(emergency_override)),
        ],
        32,
    )
}

pub fn emergency_deprecation_id(
    contract_id: &str,
    reason_code: &str,
    replaced_by_contract_id: &Option<String>,
    announced_at_height: u64,
    effective_at_height: u64,
    emergency_signature_id: &str,
    disclosure_record_root: &str,
) -> String {
    let replacement = match replaced_by_contract_id {
        Some(value) => value.as_str(),
        None => "",
    };
    domain_hash(
        "CONTRACT-EXECUTION-EMERGENCY-DEPRECATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(reason_code),
            HashPart::Str(replacement),
            HashPart::Int(announced_at_height as i128),
            HashPart::Int(effective_at_height as i128),
            HashPart::Str(emergency_signature_id),
            HashPart::Str(disclosure_record_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn low_fee_sponsorship_id(
    sponsor_commitment: &str,
    contract_id: &str,
    scope: SponsorshipScope,
    scope_value: &str,
    fee_asset_id: &str,
    budget_units: u64,
    epoch_start_height: u64,
    epoch_end_height: u64,
    signature_id: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-LOW-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(contract_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(scope_value),
            HashPart::Str(fee_asset_id),
            HashPart::Int(budget_units as i128),
            HashPart::Int(epoch_start_height as i128),
            HashPart::Int(epoch_end_height as i128),
            HashPart::Str(signature_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn audit_attestation_id(
    auditor_id: &str,
    kind: AuditAttestationKind,
    subject_kind: &str,
    subject_id: &str,
    subject_root: &str,
    evidence_root: &str,
    report_hash: &str,
    issued_at_height: u64,
    signature_id: &str,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-AUDIT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auditor_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Str(evidence_root),
            HashPart::Str(report_hash),
            HashPart::Int(issued_at_height as i128),
            HashPart::Str(signature_id),
        ],
        32,
    )
}

pub fn contract_policy_public_record_id(
    subject_kind: &str,
    subject_id: &str,
    payload_root: &str,
    state_root: &str,
    emitted_at_height: u64,
    record_sequence: u64,
) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Str(state_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(record_sequence as i128),
        ],
        32,
    )
}

pub fn contract_execution_policy_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn contract_execution_policy_label_root(label: &str) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-POLICY-LABEL",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn contract_execution_policy_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn contract_execution_policy_string_set_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    let leaves = sorted
        .iter()
        .map(|value| json!({"chain_id": CHAIN_ID, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn execution_phase_root(values: &[ExecutionPhase]) -> String {
    let mut records = values
        .iter()
        .map(|phase| phase.as_str().to_string())
        .collect::<Vec<_>>();
    records.sort();
    records.dedup();
    let leaves = records
        .iter()
        .map(|phase| json!({"phase": phase}))
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-PHASE-ROOT", &leaves)
}

pub fn execution_cap_policy_root(value: &ExecutionCapPolicy) -> String {
    contract_execution_policy_payload_root("CONTRACT-EXECUTION-CAP-POLICY", &value.public_record())
}

pub fn execution_cap_policy_root_from_slice(values: &[ExecutionCapPolicy]) -> String {
    let leaves = values
        .iter()
        .map(ExecutionCapPolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-CAP-POLICY-ROOT", &leaves)
}

pub fn execution_cap_policy_root_from_map(values: &BTreeMap<String, ExecutionCapPolicy>) -> String {
    execution_cap_policy_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

pub fn privacy_budget_policy_root(value: &PrivacyBudgetPolicy) -> String {
    contract_execution_policy_payload_root(
        "CONTRACT-EXECUTION-PRIVACY-BUDGET",
        &value.public_record(),
    )
}

pub fn privacy_budget_policy_root_from_slice(values: &[PrivacyBudgetPolicy]) -> String {
    let leaves = values
        .iter()
        .map(PrivacyBudgetPolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-PRIVACY-BUDGET-ROOT", &leaves)
}

pub fn privacy_budget_policy_root_from_map(
    values: &BTreeMap<String, PrivacyBudgetPolicy>,
) -> String {
    privacy_budget_policy_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

pub fn pq_signature_root_from_slice(values: &[PqAuthorizationSignature]) -> String {
    let leaves = values
        .iter()
        .map(PqAuthorizationSignature::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-PQ-SIGNATURE-ROOT", &leaves)
}

pub fn pq_signature_root_from_map(values: &BTreeMap<String, PqAuthorizationSignature>) -> String {
    pq_signature_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

pub fn verifier_key_pin_root_from_slice(values: &[VerifierKeyPin]) -> String {
    let leaves = values
        .iter()
        .map(VerifierKeyPin::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-VERIFIER-KEY-PIN-ROOT", &leaves)
}

pub fn verifier_key_pin_root_from_map(values: &BTreeMap<String, VerifierKeyPin>) -> String {
    verifier_key_pin_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

pub fn host_call_policy_root(values: &[HostCallPolicy]) -> String {
    let leaves = values
        .iter()
        .map(HostCallPolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-HOST-CALL-POLICY-ROOT", &leaves)
}

pub fn host_call_policy_root_from_map(values: &BTreeMap<String, HostCallPolicy>) -> String {
    host_call_policy_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn storage_access_policy_root(values: &[StorageAccessPolicy]) -> String {
    let leaves = values
        .iter()
        .map(StorageAccessPolicy::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-STORAGE-POLICY-ROOT", &leaves)
}

pub fn storage_access_policy_root_from_map(
    values: &BTreeMap<String, StorageAccessPolicy>,
) -> String {
    storage_access_policy_root(&values.values().cloned().collect::<Vec<_>>())
}

pub fn abi_method_pin_root(values: &[AbiMethodPin]) -> String {
    let leaves = values
        .iter()
        .map(AbiMethodPin::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-ABI-METHOD-PIN-ROOT", &leaves)
}

pub fn abi_manifest_root(value: &DeterministicAbiManifest) -> String {
    contract_execution_policy_payload_root(
        "CONTRACT-EXECUTION-ABI-MANIFEST",
        &value.public_record(),
    )
}

pub fn abi_manifest_root_from_map(values: &BTreeMap<String, DeterministicAbiManifest>) -> String {
    let leaves = values
        .values()
        .map(DeterministicAbiManifest::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-ABI-MANIFEST-ROOT", &leaves)
}

pub fn runtime_manifest_root(value: &DeterministicRuntimeManifest) -> String {
    contract_execution_policy_payload_root(
        "CONTRACT-EXECUTION-RUNTIME-MANIFEST",
        &value.public_record(),
    )
}

pub fn runtime_manifest_root_from_map(
    values: &BTreeMap<String, DeterministicRuntimeManifest>,
) -> String {
    let leaves = values
        .values()
        .map(DeterministicRuntimeManifest::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-RUNTIME-MANIFEST-ROOT", &leaves)
}

pub fn upgrade_timelock_root_from_map(values: &BTreeMap<String, UpgradeTimelock>) -> String {
    let leaves = values
        .values()
        .map(UpgradeTimelock::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-UPGRADE-TIMELOCK-ROOT", &leaves)
}

pub fn emergency_deprecation_root_from_map(
    values: &BTreeMap<String, EmergencyDeprecation>,
) -> String {
    let leaves = values
        .values()
        .map(EmergencyDeprecation::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-EMERGENCY-DEPRECATION-ROOT", &leaves)
}

pub fn low_fee_sponsorship_root_from_map(values: &BTreeMap<String, LowFeeSponsorship>) -> String {
    let leaves = values
        .values()
        .map(LowFeeSponsorship::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-LOW-FEE-SPONSORSHIP-ROOT", &leaves)
}

pub fn audit_attestation_root_from_map(values: &BTreeMap<String, AuditAttestation>) -> String {
    let leaves = values
        .values()
        .map(AuditAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-AUDIT-ATTESTATION-ROOT", &leaves)
}

pub fn contract_policy_public_record_root_from_map(
    values: &BTreeMap<String, ContractPolicyPublicRecord>,
) -> String {
    let leaves = values
        .values()
        .map(ContractPolicyPublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root("CONTRACT-EXECUTION-PUBLIC-RECORD-ROOT", &leaves)
}

pub fn contract_execution_policy_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONTRACT-EXECUTION-POLICY-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONTRACT_EXECUTION_POLICY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn validate_pq_signature(
    signature: &PqAuthorizationSignature,
    min_security_bits: u16,
) -> ContractExecutionPolicyResult<()> {
    if signature.scheme.security_bits() < min_security_bits {
        return Err(format!(
            "pq signature below security floor: {}",
            signature.signature_id
        ));
    }
    let recomputed_transcript = pq_authorization_transcript_hash(
        signature.role,
        &signature.signer_key_id,
        &signature.signer_public_key_root,
        signature.scheme,
        &signature.message_root,
        &signature.authorizes_subject_kind,
        &signature.authorizes_subject_id,
        signature.signed_at_height,
    );
    if recomputed_transcript != signature.transcript_hash {
        return Err(format!(
            "pq signature transcript mismatch: {}",
            signature.signature_id
        ));
    }
    let recomputed_signature_root = pq_authorization_signature_root(
        &signature.signer_label,
        &signature.signer_key_id,
        signature.scheme,
        &signature.transcript_hash,
    );
    if recomputed_signature_root != signature.signature_root {
        return Err(format!(
            "pq signature root mismatch: {}",
            signature.signature_id
        ));
    }
    if signature.expires_at_height <= signature.signed_at_height {
        return Err(format!(
            "pq signature expiry invalid: {}",
            signature.signature_id
        ));
    }
    Ok(())
}

fn validate_verifier_key_pin(
    pin: &VerifierKeyPin,
    min_security_bits: u16,
) -> ContractExecutionPolicyResult<()> {
    if pin.minimum_security_bits < min_security_bits {
        return Err(format!("verifier key below security floor: {}", pin.pin_id));
    }
    let recomputed_root = verifier_key_public_root(
        &pin.verifier_key_id,
        pin.purpose,
        &pin.circuit_family,
        &pin.proof_system,
        &pin.verifier_key_hash,
        pin.minimum_security_bits,
    );
    if recomputed_root != pin.verifier_key_root {
        return Err(format!("verifier key root mismatch: {}", pin.pin_id));
    }
    if let Some(expires_at_height) = pin.expires_at_height {
        if expires_at_height <= pin.active_from_height {
            return Err(format!("verifier key expiry invalid: {}", pin.pin_id));
        }
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> ContractExecutionPolicyResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ContractExecutionPolicyResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ContractExecutionPolicyResult<()> {
    if value > CONTRACT_EXECUTION_POLICY_MAX_BPS {
        Err(format!("{label} exceeds bps max"))
    } else {
        Ok(())
    }
}

fn ensure_non_empty_slice<T>(values: &[T], label: &str) -> ContractExecutionPolicyResult<()> {
    if values.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> ContractExecutionPolicyResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value: {value}"));
        }
    }
    Ok(())
}

fn normalize_label(value: String) -> String {
    value.trim().to_ascii_lowercase().replace(' ', "-")
}

fn bool_int(value: bool) -> i128 {
    if value {
        1
    } else {
        0
    }
}
