use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type QuantumMigrationResult<T> = Result<T, String>;

pub const QUANTUM_MIGRATION_PROTOCOL_VERSION: &str = "nebula-l2-quantum-migration-v1";
pub const QUANTUM_MIGRATION_REGISTRY_VERSION: u64 = 1;
pub const QUANTUM_MIGRATION_DISCLOSURE_SYSTEM: &str = "devnet-private-migration-disclosure-v1";
pub const QUANTUM_MIGRATION_ATTESTATION_SCHEME: &str = "ML-DSA-65-devnet-migration-committee";
pub const QUANTUM_MIGRATION_REKEY_PAYLOAD_SCHEME: &str = "ML-KEM-768-sealed-wallet-rekey-root";
pub const QUANTUM_MIGRATION_LOW_FEE_POLICY: &str = "sponsored-rekey-batch-low-fee-v1";
pub const QUANTUM_MIGRATION_DEFAULT_ROTATION_BLOCKS: u64 = 20_160;
pub const QUANTUM_MIGRATION_DEFAULT_ROTATION_NOTICE_BLOCKS: u64 = 1_440;
pub const QUANTUM_MIGRATION_DEFAULT_ROTATION_OVERLAP_BLOCKS: u64 = 720;
pub const QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS: u64 = 10_080;
pub const QUANTUM_MIGRATION_DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 2_880;
pub const QUANTUM_MIGRATION_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const QUANTUM_MIGRATION_DEFAULT_FREEZE_BLOCKS: u64 = 720;
pub const QUANTUM_MIGRATION_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const QUANTUM_MIGRATION_DEFAULT_SPONSORED_BATCH_TTL_BLOCKS: u64 = 1_440;
pub const QUANTUM_MIGRATION_MAX_ALGORITHMS: usize = 32;
pub const QUANTUM_MIGRATION_MAX_DEPRECATION_WINDOWS: usize = 32;
pub const QUANTUM_MIGRATION_MAX_ROTATION_SCHEDULES: usize = 128;
pub const QUANTUM_MIGRATION_MAX_ENROLLMENTS: usize = 256;
pub const QUANTUM_MIGRATION_MAX_MANIFESTS: usize = 256;
pub const QUANTUM_MIGRATION_MAX_REKEY_BUNDLES: usize = 512;
pub const QUANTUM_MIGRATION_MAX_COMMITTEES: usize = 32;
pub const QUANTUM_MIGRATION_MAX_ATTESTATIONS: usize = 512;
pub const QUANTUM_MIGRATION_MAX_FALLBACK_POLICIES: usize = 128;
pub const QUANTUM_MIGRATION_MAX_INCIDENTS: usize = 64;
pub const QUANTUM_MIGRATION_MAX_FREEZES: usize = 64;
pub const QUANTUM_MIGRATION_MAX_SPONSORED_BATCHES: usize = 128;
pub const QUANTUM_MIGRATION_MAX_DISCLOSURES: usize = 512;
pub const QUANTUM_MIGRATION_MAX_CHALLENGES: usize = 256;
pub const QUANTUM_MIGRATION_MAX_SLASHING_RECOMMENDATIONS: usize = 256;
pub const QUANTUM_MIGRATION_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationAlgorithmFamily {
    Signature,
    Kem,
    Hash,
    HybridSignature,
    HybridKem,
    ClassicSignature,
    ClassicKem,
}

impl QuantumMigrationAlgorithmFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Kem => "kem",
            Self::Hash => "hash",
            Self::HybridSignature => "hybrid_signature",
            Self::HybridKem => "hybrid_kem",
            Self::ClassicSignature => "classic_signature",
            Self::ClassicKem => "classic_kem",
        }
    }

    pub fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Self::Signature | Self::Kem | Self::Hash | Self::HybridSignature | Self::HybridKem
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationAlgorithmStatus {
    Candidate,
    Recommended,
    Mandatory,
    Deprecated,
    EmergencyOnly,
    Disabled,
}

impl QuantumMigrationAlgorithmStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Recommended => "recommended",
            Self::Mandatory => "mandatory",
            Self::Deprecated => "deprecated",
            Self::EmergencyOnly => "emergency_only",
            Self::Disabled => "disabled",
        }
    }

    pub fn allows_new_enrollment(self) -> bool {
        matches!(self, Self::Recommended | Self::Mandatory)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationSubjectKind {
    Account,
    Validator,
    Bridge,
    Operator,
    Wallet,
    Contract,
    Token,
    Committee,
}

impl QuantumMigrationSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Validator => "validator",
            Self::Bridge => "bridge",
            Self::Operator => "operator",
            Self::Wallet => "wallet",
            Self::Contract => "contract",
            Self::Token => "token",
            Self::Committee => "committee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationManifestStatus {
    Draft,
    Announced,
    Attested,
    Activating,
    Complete,
    Challenged,
    Frozen,
    Rejected,
    Superseded,
}

impl QuantumMigrationManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Announced => "announced",
            Self::Attested => "attested",
            Self::Activating => "activating",
            Self::Complete => "complete",
            Self::Challenged => "challenged",
            Self::Frozen => "frozen",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationEnrollmentStatus {
    Pending,
    Active,
    Rotating,
    Expired,
    Revoked,
}

impl QuantumMigrationEnrollmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationRekeyStatus {
    Sealed,
    Submitted,
    Sponsored,
    Accepted,
    Applied,
    Rejected,
    Expired,
}

impl QuantumMigrationRekeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Sponsored => "sponsored",
            Self::Accepted => "accepted",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationAttestationDecision {
    Approved,
    NeedsMoreWitnesses,
    Rejected,
    EmergencyApproved,
}

impl QuantumMigrationAttestationDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::NeedsMoreWitnesses => "needs_more_witnesses",
            Self::Rejected => "rejected",
            Self::EmergencyApproved => "emergency_approved",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationFallbackMode {
    HardwareSignerGrace,
    OfflineSignerWindow,
    GuardianRecovery,
    WatchOnlyQuarantine,
    EmergencyFreeze,
    Disabled,
}

impl QuantumMigrationFallbackMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HardwareSignerGrace => "hardware_signer_grace",
            Self::OfflineSignerWindow => "offline_signer_window",
            Self::GuardianRecovery => "guardian_recovery",
            Self::WatchOnlyQuarantine => "watch_only_quarantine",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumRiskSeverity {
    Watch,
    Elevated,
    Critical,
    Catastrophic,
}

impl QuantumRiskSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
            Self::Catastrophic => "catastrophic",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumFreezeScope {
    Enrollment,
    RekeyBundles,
    BridgeSigning,
    ValidatorSet,
    AccountClass,
    NetworkWide,
}

impl QuantumFreezeScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::RekeyBundles => "rekey_bundles",
            Self::BridgeSigning => "bridge_signing",
            Self::ValidatorSet => "validator_set",
            Self::AccountClass => "account_class",
            Self::NetworkWide => "network_wide",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumMigrationDisclosureKind {
    InclusionProof,
    KeyCommitmentOnly,
    RotationWindow,
    SponsoredFeeEligibility,
    HardwareException,
    EmergencyContactCommitment,
}

impl QuantumMigrationDisclosureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InclusionProof => "inclusion_proof",
            Self::KeyCommitmentOnly => "key_commitment_only",
            Self::RotationWindow => "rotation_window",
            Self::SponsoredFeeEligibility => "sponsored_fee_eligibility",
            Self::HardwareException => "hardware_exception",
            Self::EmergencyContactCommitment => "emergency_contact_commitment",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumChallengeKind {
    InvalidProofOfPossession,
    DeprecatedAlgorithmUsed,
    MissingRotation,
    PlaintextLeak,
    CommitteeEquivocation,
    SponsorAbuse,
    FalseIncident,
}

impl QuantumChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProofOfPossession => "invalid_proof_of_possession",
            Self::DeprecatedAlgorithmUsed => "deprecated_algorithm_used",
            Self::MissingRotation => "missing_rotation",
            Self::PlaintextLeak => "plaintext_leak",
            Self::CommitteeEquivocation => "committee_equivocation",
            Self::SponsorAbuse => "sponsor_abuse",
            Self::FalseIncident => "false_incident",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantumSlashingAction {
    None,
    Warning,
    BondSlash,
    RewardForfeit,
    ValidatorJail,
    BridgeSignerRemoval,
    CommitteeRemoval,
}

impl QuantumSlashingAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Warning => "warning",
            Self::BondSlash => "bond_slash",
            Self::RewardForfeit => "reward_forfeit",
            Self::ValidatorJail => "validator_jail",
            Self::BridgeSignerRemoval => "bridge_signer_removal",
            Self::CommitteeRemoval => "committee_removal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostQuantumAlgorithmSpec {
    pub algorithm_id: String,
    pub family: QuantumMigrationAlgorithmFamily,
    pub status: QuantumMigrationAlgorithmStatus,
    pub scheme: String,
    pub standard: String,
    pub security_level: u64,
    pub public_key_bytes: u64,
    pub signature_or_ciphertext_bytes: u64,
    pub registered_at_height: u64,
    pub recommended_from_height: u64,
    pub mandatory_from_height: Option<u64>,
    pub deprecates_at_height: Option<u64>,
    pub disabled_at_height: Option<u64>,
    pub hybrid_required_until_height: Option<u64>,
    pub notes_root: String,
}

impl PostQuantumAlgorithmSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: QuantumMigrationAlgorithmFamily,
        status: QuantumMigrationAlgorithmStatus,
        scheme: &str,
        standard: &str,
        security_level: u64,
        public_key_bytes: u64,
        signature_or_ciphertext_bytes: u64,
        registered_at_height: u64,
        recommended_from_height: u64,
        mandatory_from_height: Option<u64>,
        deprecates_at_height: Option<u64>,
        disabled_at_height: Option<u64>,
        hybrid_required_until_height: Option<u64>,
        notes: &Value,
    ) -> Self {
        let notes_root = quantum_migration_payload_root("QM-ALGORITHM-NOTES", notes);
        let algorithm_id = quantum_migration_algorithm_id(
            family.as_str(),
            scheme,
            security_level,
            registered_at_height,
        );
        Self {
            algorithm_id,
            family,
            status,
            scheme: scheme.to_string(),
            standard: standard.to_string(),
            security_level,
            public_key_bytes,
            signature_or_ciphertext_bytes,
            registered_at_height,
            recommended_from_height,
            mandatory_from_height,
            deprecates_at_height,
            disabled_at_height,
            hybrid_required_until_height,
            notes_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "post_quantum_algorithm_spec",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "algorithm_id": self.algorithm_id,
            "family": self.family.as_str(),
            "status": self.status.as_str(),
            "scheme": self.scheme,
            "standard": self.standard,
            "security_level": self.security_level,
            "public_key_bytes": self.public_key_bytes,
            "signature_or_ciphertext_bytes": self.signature_or_ciphertext_bytes,
            "registered_at_height": self.registered_at_height,
            "recommended_from_height": self.recommended_from_height,
            "mandatory_from_height": self.mandatory_from_height,
            "deprecates_at_height": self.deprecates_at_height,
            "disabled_at_height": self.disabled_at_height,
            "hybrid_required_until_height": self.hybrid_required_until_height,
            "notes_root": self.notes_root,
        })
    }

    pub fn spec_root(&self) -> String {
        quantum_migration_payload_root("QM-ALGORITHM-SPEC", &self.public_record())
    }

    pub fn is_usable_at_height(&self, height: u64) -> bool {
        if self.status == QuantumMigrationAlgorithmStatus::Disabled {
            return false;
        }
        self.disabled_at_height
            .map(|disabled_at| height < disabled_at)
            .unwrap_or(true)
    }

    pub fn accepts_new_enrollment_at_height(&self, height: u64) -> bool {
        self.is_usable_at_height(height)
            && self.status.allows_new_enrollment()
            && height >= self.recommended_from_height
            && self
                .deprecates_at_height
                .map(|deprecates_at| height < deprecates_at)
                .unwrap_or(true)
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.scheme, "algorithm scheme")?;
        ensure_non_empty(&self.standard, "algorithm standard")?;
        ensure_non_empty(&self.notes_root, "algorithm notes root")?;
        if self.security_level == 0 && self.family.is_post_quantum() {
            return Err("post-quantum algorithm security level must be non-zero".to_string());
        }
        if self.public_key_bytes == 0 && self.family != QuantumMigrationAlgorithmFamily::Hash {
            return Err("algorithm public key bytes must be non-zero".to_string());
        }
        if self.signature_or_ciphertext_bytes == 0 {
            return Err("algorithm output bytes must be non-zero".to_string());
        }
        if self.recommended_from_height < self.registered_at_height {
            return Err("algorithm recommended height cannot precede registration".to_string());
        }
        if let Some(mandatory_from_height) = self.mandatory_from_height {
            if mandatory_from_height < self.recommended_from_height {
                return Err("algorithm mandatory height cannot precede recommendation".to_string());
            }
        }
        if let (Some(deprecates_at_height), Some(mandatory_from_height)) =
            (self.deprecates_at_height, self.mandatory_from_height)
        {
            if deprecates_at_height <= mandatory_from_height {
                return Err("algorithm deprecation must follow mandatory window".to_string());
            }
        }
        if let (Some(disabled_at_height), Some(deprecates_at_height)) =
            (self.disabled_at_height, self.deprecates_at_height)
        {
            if disabled_at_height <= deprecates_at_height {
                return Err("algorithm disable height must follow deprecation".to_string());
            }
        }
        let expected_id = quantum_migration_algorithm_id(
            self.family.as_str(),
            &self.scheme,
            self.security_level,
            self.registered_at_height,
        );
        if self.algorithm_id != expected_id {
            return Err("algorithm id does not match algorithm fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmDeprecationWindow {
    pub window_id: String,
    pub algorithm_id: String,
    pub replacement_algorithm_ids: Vec<String>,
    pub replacement_root: String,
    pub warning_height: u64,
    pub deprecation_height: u64,
    pub emergency_only_height: u64,
    pub disabled_height: u64,
    pub grace_blocks: u64,
    pub policy_root: String,
}

impl AlgorithmDeprecationWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algorithm_id: &str,
        replacement_algorithm_ids: Vec<String>,
        warning_height: u64,
        deprecation_height: u64,
        emergency_only_height: u64,
        disabled_height: u64,
        grace_blocks: u64,
        policy: &Value,
    ) -> Self {
        let replacement_root = quantum_migration_string_list_root(
            "QM-ALGORITHM-REPLACEMENT",
            &replacement_algorithm_ids,
        );
        let policy_root = quantum_migration_payload_root("QM-DEPRECATION-POLICY", policy);
        let window_id = quantum_migration_deprecation_window_id(
            algorithm_id,
            &replacement_root,
            warning_height,
            disabled_height,
        );
        Self {
            window_id,
            algorithm_id: algorithm_id.to_string(),
            replacement_algorithm_ids,
            replacement_root,
            warning_height,
            deprecation_height,
            emergency_only_height,
            disabled_height,
            grace_blocks,
            policy_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "algorithm_deprecation_window",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "algorithm_id": self.algorithm_id,
            "replacement_algorithm_ids": self.replacement_algorithm_ids,
            "replacement_root": self.replacement_root,
            "warning_height": self.warning_height,
            "deprecation_height": self.deprecation_height,
            "emergency_only_height": self.emergency_only_height,
            "disabled_height": self.disabled_height,
            "grace_blocks": self.grace_blocks,
            "policy_root": self.policy_root,
        })
    }

    pub fn window_root(&self) -> String {
        quantum_migration_payload_root("QM-DEPRECATION-WINDOW", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.algorithm_id, "deprecation algorithm id")?;
        ensure_non_empty(&self.replacement_root, "deprecation replacement root")?;
        ensure_non_empty(&self.policy_root, "deprecation policy root")?;
        if self.replacement_algorithm_ids.is_empty() {
            return Err("deprecation replacement list cannot be empty".to_string());
        }
        ensure_strictly_increasing(
            &[
                self.warning_height,
                self.deprecation_height,
                self.emergency_only_height,
                self.disabled_height,
            ],
            "deprecation window heights",
        )?;
        if self.grace_blocks == 0 {
            return Err("deprecation grace blocks must be non-zero".to_string());
        }
        let expected_root = quantum_migration_string_list_root(
            "QM-ALGORITHM-REPLACEMENT",
            &self.replacement_algorithm_ids,
        );
        if self.replacement_root != expected_root {
            return Err("deprecation replacement root mismatch".to_string());
        }
        let expected_id = quantum_migration_deprecation_window_id(
            &self.algorithm_id,
            &self.replacement_root,
            self.warning_height,
            self.disabled_height,
        );
        if self.window_id != expected_id {
            return Err("deprecation window id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostQuantumAlgorithmRegistry {
    pub registry_id: String,
    pub version: u64,
    pub current_height: u64,
    pub algorithms: Vec<PostQuantumAlgorithmSpec>,
    pub deprecation_windows: Vec<AlgorithmDeprecationWindow>,
    pub required_family_root: String,
    pub policy_status: String,
}

impl PostQuantumAlgorithmRegistry {
    pub fn new(
        version: u64,
        current_height: u64,
        algorithms: Vec<PostQuantumAlgorithmSpec>,
        deprecation_windows: Vec<AlgorithmDeprecationWindow>,
        required_families: &[QuantumMigrationAlgorithmFamily],
        policy_status: &str,
    ) -> Self {
        let required_family_values = required_families
            .iter()
            .map(|family| family.as_str().to_string())
            .collect::<Vec<_>>();
        let required_family_root =
            quantum_migration_string_list_root("QM-REQUIRED-FAMILY", &required_family_values);
        let algorithm_root = quantum_migration_algorithm_spec_root(&algorithms);
        let window_root = quantum_migration_deprecation_root(&deprecation_windows);
        let registry_id =
            quantum_migration_registry_id(version, current_height, &algorithm_root, &window_root);
        Self {
            registry_id,
            version,
            current_height,
            algorithms,
            deprecation_windows,
            required_family_root,
            policy_status: policy_status.to_string(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
        self.registry_id = quantum_migration_registry_id(
            self.version,
            self.current_height,
            &self.algorithm_root(),
            &self.deprecation_window_root(),
        );
    }

    pub fn algorithm_root(&self) -> String {
        quantum_migration_algorithm_spec_root(&self.algorithms)
    }

    pub fn deprecation_window_root(&self) -> String {
        quantum_migration_deprecation_root(&self.deprecation_windows)
    }

    pub fn algorithm_map(&self) -> BTreeMap<String, &PostQuantumAlgorithmSpec> {
        self.algorithms
            .iter()
            .map(|algorithm| (algorithm.algorithm_id.clone(), algorithm))
            .collect()
    }

    pub fn algorithm_by_id(&self, algorithm_id: &str) -> Option<&PostQuantumAlgorithmSpec> {
        self.algorithms
            .iter()
            .find(|algorithm| algorithm.algorithm_id == algorithm_id)
    }

    pub fn is_algorithm_allowed(&self, algorithm_id: &str) -> bool {
        self.algorithm_by_id(algorithm_id)
            .map(|algorithm| algorithm.is_usable_at_height(self.current_height))
            .unwrap_or(false)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "post_quantum_algorithm_registry",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "registry_id": self.registry_id,
            "version": self.version,
            "current_height": self.current_height,
            "algorithm_root": self.algorithm_root(),
            "deprecation_window_root": self.deprecation_window_root(),
            "required_family_root": self.required_family_root,
            "policy_status": self.policy_status,
            "algorithms": self.algorithms.iter().map(PostQuantumAlgorithmSpec::public_record).collect::<Vec<_>>(),
            "deprecation_windows": self.deprecation_windows.iter().map(AlgorithmDeprecationWindow::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn registry_root(&self) -> String {
        quantum_migration_payload_root("QM-ALGORITHM-REGISTRY", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.policy_status, "algorithm registry policy status")?;
        ensure_max_len(
            self.algorithms.len(),
            QUANTUM_MIGRATION_MAX_ALGORITHMS,
            "algorithm registry",
        )?;
        ensure_max_len(
            self.deprecation_windows.len(),
            QUANTUM_MIGRATION_MAX_DEPRECATION_WINDOWS,
            "deprecation windows",
        )?;
        if self.algorithms.is_empty() {
            return Err("algorithm registry cannot be empty".to_string());
        }
        let mut algorithm_ids = BTreeSet::new();
        for algorithm in &self.algorithms {
            algorithm.validate()?;
            ensure_insert_unique(
                &mut algorithm_ids,
                &algorithm.algorithm_id,
                "algorithm registry",
            )?;
        }
        for window in &self.deprecation_windows {
            window.validate()?;
            if !algorithm_ids.contains(&window.algorithm_id) {
                return Err(format!(
                    "deprecation window references unknown algorithm {}",
                    window.algorithm_id
                ));
            }
            for replacement_id in &window.replacement_algorithm_ids {
                if !algorithm_ids.contains(replacement_id) {
                    return Err(format!(
                        "deprecation replacement references unknown algorithm {replacement_id}"
                    ));
                }
            }
        }
        let expected_id = quantum_migration_registry_id(
            self.version,
            self.current_height,
            &self.algorithm_root(),
            &self.deprecation_window_root(),
        );
        if self.registry_id != expected_id {
            return Err("algorithm registry id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandatoryKeyRotationSchedule {
    pub schedule_id: String,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_id: String,
    pub role: String,
    pub required_algorithm_id: String,
    pub rotate_every_blocks: u64,
    pub notice_blocks: u64,
    pub overlap_blocks: u64,
    pub next_rotation_height: u64,
    pub grace_end_height: u64,
    pub mandatory: bool,
    pub sponsor_eligible: bool,
    pub status: QuantumMigrationEnrollmentStatus,
}

impl MandatoryKeyRotationSchedule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: QuantumMigrationSubjectKind,
        subject_id: &str,
        role: &str,
        required_algorithm_id: &str,
        rotate_every_blocks: u64,
        notice_blocks: u64,
        overlap_blocks: u64,
        next_rotation_height: u64,
        grace_end_height: u64,
        mandatory: bool,
        sponsor_eligible: bool,
        status: QuantumMigrationEnrollmentStatus,
    ) -> Self {
        let schedule_id = quantum_rotation_schedule_id(
            subject_kind.as_str(),
            subject_id,
            role,
            required_algorithm_id,
            next_rotation_height,
        );
        Self {
            schedule_id,
            subject_kind,
            subject_id: subject_id.to_string(),
            role: role.to_string(),
            required_algorithm_id: required_algorithm_id.to_string(),
            rotate_every_blocks,
            notice_blocks,
            overlap_blocks,
            next_rotation_height,
            grace_end_height,
            mandatory,
            sponsor_eligible,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "mandatory_key_rotation_schedule",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "schedule_id": self.schedule_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "role": self.role,
            "required_algorithm_id": self.required_algorithm_id,
            "rotate_every_blocks": self.rotate_every_blocks,
            "notice_blocks": self.notice_blocks,
            "overlap_blocks": self.overlap_blocks,
            "next_rotation_height": self.next_rotation_height,
            "grace_end_height": self.grace_end_height,
            "mandatory": self.mandatory,
            "sponsor_eligible": self.sponsor_eligible,
            "status": self.status.as_str(),
        })
    }

    pub fn schedule_root(&self) -> String {
        quantum_migration_payload_root("QM-ROTATION-SCHEDULE", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.subject_id, "rotation schedule subject id")?;
        ensure_non_empty(&self.role, "rotation schedule role")?;
        ensure_non_empty(
            &self.required_algorithm_id,
            "rotation schedule required algorithm id",
        )?;
        if self.rotate_every_blocks == 0 {
            return Err("rotation schedule interval must be non-zero".to_string());
        }
        if self.notice_blocks > self.rotate_every_blocks {
            return Err("rotation notice cannot exceed rotation interval".to_string());
        }
        if self.overlap_blocks > self.rotate_every_blocks {
            return Err("rotation overlap cannot exceed rotation interval".to_string());
        }
        if self.grace_end_height < self.next_rotation_height {
            return Err("rotation grace end cannot precede next rotation".to_string());
        }
        let expected_id = quantum_rotation_schedule_id(
            self.subject_kind.as_str(),
            &self.subject_id,
            &self.role,
            &self.required_algorithm_id,
            self.next_rotation_height,
        );
        if self.schedule_id != expected_id {
            return Err("rotation schedule id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKeyEnrollment {
    pub enrollment_id: String,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_id: String,
    pub owner_commitment: String,
    pub classic_algorithm_id: String,
    pub pq_algorithm_id: String,
    pub classic_key_root: String,
    pub pq_key_root: String,
    pub hybrid_binding_root: String,
    pub proof_of_possession_root: String,
    pub schedule_id: String,
    pub enrolled_at_height: u64,
    pub activate_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuantumMigrationEnrollmentStatus,
}

impl HybridKeyEnrollment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: QuantumMigrationSubjectKind,
        subject_id: &str,
        owner_commitment: &str,
        classic_algorithm_id: &str,
        pq_algorithm_id: &str,
        classic_key_root: &str,
        pq_key_root: &str,
        proof_of_possession_root: &str,
        schedule_id: &str,
        enrolled_at_height: u64,
        activate_at_height: u64,
        expires_at_height: u64,
        status: QuantumMigrationEnrollmentStatus,
    ) -> Self {
        let hybrid_binding_root = quantum_migration_hybrid_binding_root(
            subject_kind.as_str(),
            subject_id,
            owner_commitment,
            classic_key_root,
            pq_key_root,
        );
        let enrollment_id = hybrid_key_enrollment_id(
            subject_kind.as_str(),
            subject_id,
            owner_commitment,
            &hybrid_binding_root,
            enrolled_at_height,
        );
        Self {
            enrollment_id,
            subject_kind,
            subject_id: subject_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            classic_algorithm_id: classic_algorithm_id.to_string(),
            pq_algorithm_id: pq_algorithm_id.to_string(),
            classic_key_root: classic_key_root.to_string(),
            pq_key_root: pq_key_root.to_string(),
            hybrid_binding_root,
            proof_of_possession_root: proof_of_possession_root.to_string(),
            schedule_id: schedule_id.to_string(),
            enrolled_at_height,
            activate_at_height,
            expires_at_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "hybrid_key_enrollment",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "enrollment_id": self.enrollment_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "owner_commitment": self.owner_commitment,
            "classic_algorithm_id": self.classic_algorithm_id,
            "pq_algorithm_id": self.pq_algorithm_id,
            "classic_key_root": self.classic_key_root,
            "pq_key_root": self.pq_key_root,
            "hybrid_binding_root": self.hybrid_binding_root,
            "proof_of_possession_root": self.proof_of_possession_root,
            "schedule_id": self.schedule_id,
            "enrolled_at_height": self.enrolled_at_height,
            "activate_at_height": self.activate_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn enrollment_root(&self) -> String {
        quantum_migration_payload_root("QM-HYBRID-KEY-ENROLLMENT", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.subject_id, "hybrid enrollment subject id")?;
        ensure_non_empty(&self.owner_commitment, "hybrid enrollment owner commitment")?;
        ensure_non_empty(
            &self.classic_algorithm_id,
            "hybrid enrollment classic algorithm",
        )?;
        ensure_non_empty(&self.pq_algorithm_id, "hybrid enrollment pq algorithm")?;
        ensure_non_empty(&self.classic_key_root, "hybrid enrollment classic key root")?;
        ensure_non_empty(&self.pq_key_root, "hybrid enrollment pq key root")?;
        ensure_non_empty(
            &self.proof_of_possession_root,
            "hybrid enrollment proof root",
        )?;
        ensure_non_empty(&self.schedule_id, "hybrid enrollment schedule id")?;
        ensure_height_order(
            self.enrolled_at_height,
            self.activate_at_height,
            "hybrid enrollment activation",
        )?;
        ensure_height_order(
            self.activate_at_height,
            self.expires_at_height,
            "hybrid enrollment expiry",
        )?;
        let expected_binding_root = quantum_migration_hybrid_binding_root(
            self.subject_kind.as_str(),
            &self.subject_id,
            &self.owner_commitment,
            &self.classic_key_root,
            &self.pq_key_root,
        );
        if self.hybrid_binding_root != expected_binding_root {
            return Err("hybrid enrollment binding root mismatch".to_string());
        }
        let expected_id = hybrid_key_enrollment_id(
            self.subject_kind.as_str(),
            &self.subject_id,
            &self.owner_commitment,
            &self.hybrid_binding_root,
            self.enrolled_at_height,
        );
        if self.enrollment_id != expected_id {
            return Err("hybrid enrollment id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub manifest_id: String,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_id: String,
    pub owner_commitment: String,
    pub enrollment_id: String,
    pub rotation_schedule_id: String,
    pub current_key_root: String,
    pub target_key_root: String,
    pub algorithm_registry_root: String,
    pub schedule_root: String,
    pub wallet_rekey_bundle_id: Option<String>,
    pub wallet_rekey_bundle_root: String,
    pub privacy_disclosure_root: String,
    pub attestation_root: String,
    pub declared_at_height: u64,
    pub target_activation_height: u64,
    pub complete_by_height: u64,
    pub status: QuantumMigrationManifestStatus,
}

impl MigrationManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: QuantumMigrationSubjectKind,
        subject_id: &str,
        owner_commitment: &str,
        enrollment_id: &str,
        rotation_schedule_id: &str,
        current_key_root: &str,
        target_key_root: &str,
        algorithm_registry_root: &str,
        schedule_root: &str,
        wallet_rekey_bundle_id: Option<String>,
        wallet_rekey_bundle_root: &str,
        privacy_disclosure_root: &str,
        attestation_root: &str,
        declared_at_height: u64,
        target_activation_height: u64,
        complete_by_height: u64,
        status: QuantumMigrationManifestStatus,
    ) -> Self {
        let manifest_id = migration_manifest_id(
            subject_kind.as_str(),
            subject_id,
            owner_commitment,
            target_key_root,
            declared_at_height,
        );
        Self {
            manifest_id,
            subject_kind,
            subject_id: subject_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            enrollment_id: enrollment_id.to_string(),
            rotation_schedule_id: rotation_schedule_id.to_string(),
            current_key_root: current_key_root.to_string(),
            target_key_root: target_key_root.to_string(),
            algorithm_registry_root: algorithm_registry_root.to_string(),
            schedule_root: schedule_root.to_string(),
            wallet_rekey_bundle_id,
            wallet_rekey_bundle_root: wallet_rekey_bundle_root.to_string(),
            privacy_disclosure_root: privacy_disclosure_root.to_string(),
            attestation_root: attestation_root.to_string(),
            declared_at_height,
            target_activation_height,
            complete_by_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "migration_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "owner_commitment": self.owner_commitment,
            "enrollment_id": self.enrollment_id,
            "rotation_schedule_id": self.rotation_schedule_id,
            "current_key_root": self.current_key_root,
            "target_key_root": self.target_key_root,
            "algorithm_registry_root": self.algorithm_registry_root,
            "schedule_root": self.schedule_root,
            "wallet_rekey_bundle_id": self.wallet_rekey_bundle_id,
            "wallet_rekey_bundle_root": self.wallet_rekey_bundle_root,
            "privacy_disclosure_root": self.privacy_disclosure_root,
            "attestation_root": self.attestation_root,
            "declared_at_height": self.declared_at_height,
            "target_activation_height": self.target_activation_height,
            "complete_by_height": self.complete_by_height,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        quantum_migration_payload_root("QM-MIGRATION-MANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.subject_id, "migration manifest subject id")?;
        ensure_non_empty(
            &self.owner_commitment,
            "migration manifest owner commitment",
        )?;
        ensure_non_empty(&self.enrollment_id, "migration manifest enrollment id")?;
        ensure_non_empty(
            &self.rotation_schedule_id,
            "migration manifest rotation schedule id",
        )?;
        ensure_non_empty(
            &self.current_key_root,
            "migration manifest current key root",
        )?;
        ensure_non_empty(&self.target_key_root, "migration manifest target key root")?;
        ensure_non_empty(
            &self.algorithm_registry_root,
            "migration manifest algorithm registry root",
        )?;
        ensure_non_empty(&self.schedule_root, "migration manifest schedule root")?;
        ensure_non_empty(
            &self.wallet_rekey_bundle_root,
            "migration manifest rekey bundle root",
        )?;
        ensure_non_empty(
            &self.privacy_disclosure_root,
            "migration manifest disclosure root",
        )?;
        ensure_non_empty(
            &self.attestation_root,
            "migration manifest attestation root",
        )?;
        ensure_height_order(
            self.declared_at_height,
            self.target_activation_height,
            "migration manifest activation",
        )?;
        ensure_height_order(
            self.target_activation_height,
            self.complete_by_height,
            "migration manifest completion",
        )?;
        let expected_id = migration_manifest_id(
            self.subject_kind.as_str(),
            &self.subject_id,
            &self.owner_commitment,
            &self.target_key_root,
            self.declared_at_height,
        );
        if self.manifest_id != expected_id {
            return Err("migration manifest id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRekeyBundle {
    pub bundle_id: String,
    pub account_commitment: String,
    pub wallet_version_root: String,
    pub encrypted_payload_root: String,
    pub recipient_kem_key_root: String,
    pub payload_cipher_suite: String,
    pub proof_of_encryption_root: String,
    pub fee_sponsor_commitment: Option<String>,
    pub created_at_height: u64,
    pub valid_until_height: u64,
    pub nonce: u64,
    pub status: QuantumMigrationRekeyStatus,
}

impl WalletRekeyBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment: &str,
        wallet_version_root: &str,
        encrypted_payload_root: &str,
        recipient_kem_key_root: &str,
        proof_of_encryption_root: &str,
        fee_sponsor_commitment: Option<String>,
        created_at_height: u64,
        valid_until_height: u64,
        nonce: u64,
        status: QuantumMigrationRekeyStatus,
    ) -> Self {
        let bundle_id = wallet_rekey_bundle_id(
            account_commitment,
            encrypted_payload_root,
            created_at_height,
            nonce,
        );
        Self {
            bundle_id,
            account_commitment: account_commitment.to_string(),
            wallet_version_root: wallet_version_root.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            recipient_kem_key_root: recipient_kem_key_root.to_string(),
            payload_cipher_suite: QUANTUM_MIGRATION_REKEY_PAYLOAD_SCHEME.to_string(),
            proof_of_encryption_root: proof_of_encryption_root.to_string(),
            fee_sponsor_commitment,
            created_at_height,
            valid_until_height,
            nonce,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_rekey_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "account_commitment": self.account_commitment,
            "wallet_version_root": self.wallet_version_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "recipient_kem_key_root": self.recipient_kem_key_root,
            "payload_cipher_suite": self.payload_cipher_suite,
            "proof_of_encryption_root": self.proof_of_encryption_root,
            "fee_sponsor_commitment": self.fee_sponsor_commitment,
            "created_at_height": self.created_at_height,
            "valid_until_height": self.valid_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn bundle_root(&self) -> String {
        quantum_migration_payload_root("QM-WALLET-REKEY-BUNDLE", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet rekey account commitment")?;
        ensure_non_empty(
            &self.wallet_version_root,
            "wallet rekey wallet version root",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "wallet rekey encrypted payload root",
        )?;
        ensure_non_empty(
            &self.recipient_kem_key_root,
            "wallet rekey recipient kem key root",
        )?;
        ensure_non_empty(
            &self.payload_cipher_suite,
            "wallet rekey payload cipher suite",
        )?;
        ensure_non_empty(
            &self.proof_of_encryption_root,
            "wallet rekey proof of encryption root",
        )?;
        ensure_height_order(
            self.created_at_height,
            self.valid_until_height,
            "wallet rekey validity",
        )?;
        let expected_id = wallet_rekey_bundle_id(
            &self.account_commitment,
            &self.encrypted_payload_root,
            self.created_at_height,
            self.nonce,
        );
        if self.bundle_id != expected_id {
            return Err("wallet rekey bundle id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationCommitteeMember {
    pub member_id: String,
    pub operator_label: String,
    pub signing_key_root: String,
    pub stake_weight: u64,
    pub privacy_contact_root: String,
    pub active: bool,
}

impl MigrationCommitteeMember {
    pub fn new(
        operator_label: &str,
        signing_key_root: &str,
        stake_weight: u64,
        privacy_contact_root: &str,
        active: bool,
    ) -> Self {
        let member_id = migration_committee_member_id(operator_label, signing_key_root);
        Self {
            member_id,
            operator_label: operator_label.to_string(),
            signing_key_root: signing_key_root.to_string(),
            stake_weight,
            privacy_contact_root: privacy_contact_root.to_string(),
            active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "migration_committee_member",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "signing_key_root": self.signing_key_root,
            "stake_weight": self.stake_weight,
            "privacy_contact_root": self.privacy_contact_root,
            "active": self.active,
        })
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.operator_label, "committee member operator label")?;
        ensure_non_empty(&self.signing_key_root, "committee member signing key root")?;
        ensure_non_empty(
            &self.privacy_contact_root,
            "committee member privacy contact root",
        )?;
        if self.stake_weight == 0 {
            return Err("committee member stake weight must be non-zero".to_string());
        }
        let expected_id =
            migration_committee_member_id(&self.operator_label, &self.signing_key_root);
        if self.member_id != expected_id {
            return Err("committee member id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAttestationCommittee {
    pub committee_id: String,
    pub epoch_index: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub members: Vec<MigrationCommitteeMember>,
    pub threshold_weight: u64,
    pub emergency_threshold_weight: u64,
    pub policy_root: String,
}

impl MigrationAttestationCommittee {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_index: u64,
        start_height: u64,
        end_height: u64,
        members: Vec<MigrationCommitteeMember>,
        threshold_weight: u64,
        emergency_threshold_weight: u64,
        policy: &Value,
    ) -> Self {
        let policy_root = quantum_migration_payload_root("QM-COMMITTEE-POLICY", policy);
        let member_root = migration_committee_member_root(&members);
        let committee_id = migration_committee_id(epoch_index, &member_root, threshold_weight);
        Self {
            committee_id,
            epoch_index,
            start_height,
            end_height,
            members,
            threshold_weight,
            emergency_threshold_weight,
            policy_root,
        }
    }

    pub fn total_active_weight(&self) -> u64 {
        self.members
            .iter()
            .filter(|member| member.active)
            .map(|member| member.stake_weight)
            .sum()
    }

    pub fn member_root(&self) -> String {
        migration_committee_member_root(&self.members)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "migration_attestation_committee",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "epoch_index": self.epoch_index,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "member_root": self.member_root(),
            "threshold_weight": self.threshold_weight,
            "emergency_threshold_weight": self.emergency_threshold_weight,
            "total_active_weight": self.total_active_weight(),
            "policy_root": self.policy_root,
            "members": self.members.iter().map(MigrationCommitteeMember::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn committee_root(&self) -> String {
        quantum_migration_payload_root("QM-MIGRATION-COMMITTEE", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_height_order(self.start_height, self.end_height, "committee epoch")?;
        ensure_non_empty(&self.policy_root, "committee policy root")?;
        if self.members.is_empty() {
            return Err("migration committee cannot be empty".to_string());
        }
        let mut member_ids = BTreeSet::new();
        for member in &self.members {
            member.validate()?;
            ensure_insert_unique(&mut member_ids, &member.member_id, "committee member")?;
        }
        let total_active_weight = self.total_active_weight();
        if self.threshold_weight == 0 || self.threshold_weight > total_active_weight {
            return Err("committee threshold must be within active weight".to_string());
        }
        if self.emergency_threshold_weight == 0
            || self.emergency_threshold_weight > total_active_weight
        {
            return Err("committee emergency threshold must be within active weight".to_string());
        }
        let expected_id =
            migration_committee_id(self.epoch_index, &self.member_root(), self.threshold_weight);
        if self.committee_id != expected_id {
            return Err("committee id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMigrationAttestation {
    pub attestation_id: String,
    pub committee_id: String,
    pub committee_root: String,
    pub manifest_id: String,
    pub manifest_root: String,
    pub decision: QuantumMigrationAttestationDecision,
    pub signer_weight: u64,
    pub threshold_weight: u64,
    pub quorum_met: bool,
    pub signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuantumMigrationManifestStatus,
}

impl PqMigrationAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee: &MigrationAttestationCommittee,
        manifest: &MigrationManifest,
        decision: QuantumMigrationAttestationDecision,
        signer_weight: u64,
        signer_commitments: &[String],
        signed_at_height: u64,
        expires_at_height: u64,
        status: QuantumMigrationManifestStatus,
    ) -> Self {
        let signature_root =
            quantum_migration_string_list_root("QM-ATTESTATION-SIGNATURE", signer_commitments);
        let quorum_threshold = if decision == QuantumMigrationAttestationDecision::EmergencyApproved
        {
            committee.emergency_threshold_weight
        } else {
            committee.threshold_weight
        };
        let quorum_met = signer_weight >= quorum_threshold;
        let attestation_id = pq_migration_attestation_id(
            &committee.committee_id,
            &manifest.manifest_id,
            decision.as_str(),
            signed_at_height,
        );
        Self {
            attestation_id,
            committee_id: committee.committee_id.clone(),
            committee_root: committee.committee_root(),
            manifest_id: manifest.manifest_id.clone(),
            manifest_root: manifest.manifest_root(),
            decision,
            signer_weight,
            threshold_weight: quorum_threshold,
            quorum_met,
            signature_root,
            signed_at_height,
            expires_at_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_migration_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "attestation_scheme": QUANTUM_MIGRATION_ATTESTATION_SCHEME,
            "attestation_id": self.attestation_id,
            "committee_id": self.committee_id,
            "committee_root": self.committee_root,
            "manifest_id": self.manifest_id,
            "manifest_root": self.manifest_root,
            "decision": self.decision.as_str(),
            "signer_weight": self.signer_weight,
            "threshold_weight": self.threshold_weight,
            "quorum_met": self.quorum_met,
            "signature_root": self.signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        quantum_migration_payload_root("QM-PQ-MIGRATION-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.committee_id, "attestation committee id")?;
        ensure_non_empty(&self.committee_root, "attestation committee root")?;
        ensure_non_empty(&self.manifest_id, "attestation manifest id")?;
        ensure_non_empty(&self.manifest_root, "attestation manifest root")?;
        ensure_non_empty(&self.signature_root, "attestation signature root")?;
        ensure_height_order(
            self.signed_at_height,
            self.expires_at_height,
            "attestation validity",
        )?;
        if self.threshold_weight == 0 {
            return Err("attestation threshold must be non-zero".to_string());
        }
        if self.quorum_met != (self.signer_weight >= self.threshold_weight) {
            return Err("attestation quorum flag mismatch".to_string());
        }
        let expected_id = pq_migration_attestation_id(
            &self.committee_id,
            &self.manifest_id,
            self.decision.as_str(),
            self.signed_at_height,
        );
        if self.attestation_id != expected_id {
            return Err("attestation id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackRecoveryPolicy {
    pub policy_id: String,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_id: String,
    pub mode: QuantumMigrationFallbackMode,
    pub hardware_signer_root: String,
    pub offline_signer_root: String,
    pub guardian_set_root: String,
    pub emergency_contact_root: String,
    pub allowed_delay_blocks: u64,
    pub max_retries: u64,
    pub guardian_threshold: u64,
    pub freeze_on_failure: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuantumMigrationEnrollmentStatus,
}

impl FallbackRecoveryPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: QuantumMigrationSubjectKind,
        subject_id: &str,
        mode: QuantumMigrationFallbackMode,
        hardware_signer_root: &str,
        offline_signer_root: &str,
        guardian_set_root: &str,
        emergency_contact_root: &str,
        allowed_delay_blocks: u64,
        max_retries: u64,
        guardian_threshold: u64,
        freeze_on_failure: bool,
        created_at_height: u64,
        expires_at_height: u64,
        status: QuantumMigrationEnrollmentStatus,
    ) -> Self {
        let policy_id = fallback_recovery_policy_id(
            subject_kind.as_str(),
            subject_id,
            mode.as_str(),
            created_at_height,
        );
        Self {
            policy_id,
            subject_kind,
            subject_id: subject_id.to_string(),
            mode,
            hardware_signer_root: hardware_signer_root.to_string(),
            offline_signer_root: offline_signer_root.to_string(),
            guardian_set_root: guardian_set_root.to_string(),
            emergency_contact_root: emergency_contact_root.to_string(),
            allowed_delay_blocks,
            max_retries,
            guardian_threshold,
            freeze_on_failure,
            created_at_height,
            expires_at_height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fallback_recovery_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "mode": self.mode.as_str(),
            "hardware_signer_root": self.hardware_signer_root,
            "offline_signer_root": self.offline_signer_root,
            "guardian_set_root": self.guardian_set_root,
            "emergency_contact_root": self.emergency_contact_root,
            "allowed_delay_blocks": self.allowed_delay_blocks,
            "max_retries": self.max_retries,
            "guardian_threshold": self.guardian_threshold,
            "freeze_on_failure": self.freeze_on_failure,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn policy_root(&self) -> String {
        quantum_migration_payload_root("QM-FALLBACK-RECOVERY-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.subject_id, "fallback policy subject id")?;
        ensure_non_empty(
            &self.hardware_signer_root,
            "fallback policy hardware signer root",
        )?;
        ensure_non_empty(
            &self.offline_signer_root,
            "fallback policy offline signer root",
        )?;
        ensure_non_empty(&self.guardian_set_root, "fallback policy guardian set root")?;
        ensure_non_empty(
            &self.emergency_contact_root,
            "fallback policy emergency contact root",
        )?;
        ensure_height_order(
            self.created_at_height,
            self.expires_at_height,
            "fallback policy expiry",
        )?;
        if self.max_retries == 0 {
            return Err("fallback policy max retries must be non-zero".to_string());
        }
        if self.guardian_threshold == 0
            && self.mode == QuantumMigrationFallbackMode::GuardianRecovery
        {
            return Err("guardian recovery fallback requires guardian threshold".to_string());
        }
        let expected_id = fallback_recovery_policy_id(
            self.subject_kind.as_str(),
            &self.subject_id,
            self.mode.as_str(),
            self.created_at_height,
        );
        if self.policy_id != expected_id {
            return Err("fallback policy id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumRiskIncident {
    pub incident_id: String,
    pub severity: QuantumRiskSeverity,
    pub declared_by_commitment: String,
    pub declaration_root: String,
    pub affected_subject_root: String,
    pub mitigation_root: String,
    pub declared_at_height: u64,
    pub review_by_height: u64,
    pub status: String,
}

impl QuantumRiskIncident {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        severity: QuantumRiskSeverity,
        declared_by_commitment: &str,
        declaration_root: &str,
        affected_subject_root: &str,
        mitigation_root: &str,
        declared_at_height: u64,
        review_by_height: u64,
        status: &str,
    ) -> Self {
        let incident_id = quantum_risk_incident_id(
            severity.as_str(),
            declaration_root,
            declared_by_commitment,
            declared_at_height,
        );
        Self {
            incident_id,
            severity,
            declared_by_commitment: declared_by_commitment.to_string(),
            declaration_root: declaration_root.to_string(),
            affected_subject_root: affected_subject_root.to_string(),
            mitigation_root: mitigation_root.to_string(),
            declared_at_height,
            review_by_height,
            status: status.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "quantum_risk_incident",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "incident_id": self.incident_id,
            "severity": self.severity.as_str(),
            "declared_by_commitment": self.declared_by_commitment,
            "declaration_root": self.declaration_root,
            "affected_subject_root": self.affected_subject_root,
            "mitigation_root": self.mitigation_root,
            "declared_at_height": self.declared_at_height,
            "review_by_height": self.review_by_height,
            "status": self.status,
        })
    }

    pub fn incident_root(&self) -> String {
        quantum_migration_payload_root("QM-QUANTUM-RISK-INCIDENT", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.declared_by_commitment, "incident declarer commitment")?;
        ensure_non_empty(&self.declaration_root, "incident declaration root")?;
        ensure_non_empty(
            &self.affected_subject_root,
            "incident affected subject root",
        )?;
        ensure_non_empty(&self.mitigation_root, "incident mitigation root")?;
        ensure_non_empty(&self.status, "incident status")?;
        ensure_height_order(
            self.declared_at_height,
            self.review_by_height,
            "incident review window",
        )?;
        let expected_id = quantum_risk_incident_id(
            self.severity.as_str(),
            &self.declaration_root,
            &self.declared_by_commitment,
            self.declared_at_height,
        );
        if self.incident_id != expected_id {
            return Err("incident id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyFreeze {
    pub freeze_id: String,
    pub incident_id: String,
    pub scope: QuantumFreezeScope,
    pub subject_root: String,
    pub reason_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub lifted_at_height: Option<u64>,
    pub status: String,
}

impl EmergencyFreeze {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        incident_id: &str,
        scope: QuantumFreezeScope,
        subject_root: &str,
        reason_root: &str,
        start_height: u64,
        end_height: u64,
        lifted_at_height: Option<u64>,
        status: &str,
    ) -> Self {
        let freeze_id =
            emergency_freeze_id(incident_id, scope.as_str(), subject_root, start_height);
        Self {
            freeze_id,
            incident_id: incident_id.to_string(),
            scope,
            subject_root: subject_root.to_string(),
            reason_root: reason_root.to_string(),
            start_height,
            end_height,
            lifted_at_height,
            status: status.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "emergency_freeze",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "freeze_id": self.freeze_id,
            "incident_id": self.incident_id,
            "scope": self.scope.as_str(),
            "subject_root": self.subject_root,
            "reason_root": self.reason_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "lifted_at_height": self.lifted_at_height,
            "status": self.status,
        })
    }

    pub fn freeze_root(&self) -> String {
        quantum_migration_payload_root("QM-EMERGENCY-FREEZE", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.incident_id, "freeze incident id")?;
        ensure_non_empty(&self.subject_root, "freeze subject root")?;
        ensure_non_empty(&self.reason_root, "freeze reason root")?;
        ensure_non_empty(&self.status, "freeze status")?;
        ensure_height_order(self.start_height, self.end_height, "freeze window")?;
        if let Some(lifted_at_height) = self.lifted_at_height {
            if lifted_at_height < self.start_height {
                return Err("freeze lift height cannot precede start".to_string());
            }
        }
        let expected_id = emergency_freeze_id(
            &self.incident_id,
            self.scope.as_str(),
            &self.subject_root,
            self.start_height,
        );
        if self.freeze_id != expected_id {
            return Err("freeze id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredRekeyBatch {
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub used_fee_units: u64,
    pub manifest_ids: Vec<String>,
    pub wallet_bundle_ids: Vec<String>,
    pub manifest_root: String,
    pub wallet_bundle_root: String,
    pub privacy_pool_root: String,
    pub started_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuantumMigrationRekeyStatus,
}

impl SponsoredRekeyBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        reserved_fee_units: u64,
        used_fee_units: u64,
        manifest_ids: Vec<String>,
        wallet_bundle_ids: Vec<String>,
        privacy_pool_root: &str,
        started_at_height: u64,
        expires_at_height: u64,
        status: QuantumMigrationRekeyStatus,
    ) -> Self {
        let manifest_root =
            quantum_migration_string_list_root("QM-SPONSORED-MANIFEST", &manifest_ids);
        let wallet_bundle_root =
            quantum_migration_string_list_root("QM-SPONSORED-WALLET-BUNDLE", &wallet_bundle_ids);
        let batch_id = sponsored_rekey_batch_id(
            sponsor_commitment,
            &manifest_root,
            &wallet_bundle_root,
            started_at_height,
        );
        Self {
            batch_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            reserved_fee_units,
            used_fee_units,
            manifest_ids,
            wallet_bundle_ids,
            manifest_root,
            wallet_bundle_root,
            privacy_pool_root: privacy_pool_root.to_string(),
            started_at_height,
            expires_at_height,
            status,
        }
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.used_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsored_rekey_batch",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "low_fee_policy": QUANTUM_MIGRATION_LOW_FEE_POLICY,
            "batch_id": self.batch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "used_fee_units": self.used_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "manifest_ids": self.manifest_ids,
            "wallet_bundle_ids": self.wallet_bundle_ids,
            "manifest_root": self.manifest_root,
            "wallet_bundle_root": self.wallet_bundle_root,
            "privacy_pool_root": self.privacy_pool_root,
            "started_at_height": self.started_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_root(&self) -> String {
        quantum_migration_payload_root("QM-SPONSORED-REKEY-BATCH", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(
            &self.sponsor_commitment,
            "sponsored batch sponsor commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "sponsored batch fee asset id")?;
        ensure_non_empty(&self.manifest_root, "sponsored batch manifest root")?;
        ensure_non_empty(
            &self.wallet_bundle_root,
            "sponsored batch wallet bundle root",
        )?;
        ensure_non_empty(&self.privacy_pool_root, "sponsored batch privacy pool root")?;
        if self.max_fee_units == 0 {
            return Err("sponsored batch max fee units must be non-zero".to_string());
        }
        if self.reserved_fee_units > self.max_fee_units || self.used_fee_units > self.max_fee_units
        {
            return Err("sponsored batch fee accounting exceeds max fee".to_string());
        }
        ensure_height_order(
            self.started_at_height,
            self.expires_at_height,
            "sponsored batch expiry",
        )?;
        let expected_manifest_root =
            quantum_migration_string_list_root("QM-SPONSORED-MANIFEST", &self.manifest_ids);
        let expected_wallet_bundle_root = quantum_migration_string_list_root(
            "QM-SPONSORED-WALLET-BUNDLE",
            &self.wallet_bundle_ids,
        );
        if self.manifest_root != expected_manifest_root {
            return Err("sponsored batch manifest root mismatch".to_string());
        }
        if self.wallet_bundle_root != expected_wallet_bundle_root {
            return Err("sponsored batch wallet bundle root mismatch".to_string());
        }
        let expected_id = sponsored_rekey_batch_id(
            &self.sponsor_commitment,
            &self.manifest_root,
            &self.wallet_bundle_root,
            self.started_at_height,
        );
        if self.batch_id != expected_id {
            return Err("sponsored batch id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyMigrationDisclosure {
    pub disclosure_id: String,
    pub disclosure_kind: QuantumMigrationDisclosureKind,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_commitment: String,
    pub manifest_id: String,
    pub disclosed_fields_root: String,
    pub zero_knowledge_proof_root: String,
    pub nullifier_root: String,
    pub audience_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl PrivacyMigrationDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        disclosure_kind: QuantumMigrationDisclosureKind,
        subject_kind: QuantumMigrationSubjectKind,
        subject_commitment: &str,
        manifest_id: &str,
        disclosed_fields_root: &str,
        zero_knowledge_proof_root: &str,
        nullifier_root: &str,
        audience_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
        status: &str,
    ) -> Self {
        let disclosure_id = privacy_migration_disclosure_id(
            disclosure_kind.as_str(),
            subject_kind.as_str(),
            subject_commitment,
            manifest_id,
            nullifier_root,
        );
        Self {
            disclosure_id,
            disclosure_kind,
            subject_kind,
            subject_commitment: subject_commitment.to_string(),
            manifest_id: manifest_id.to_string(),
            disclosed_fields_root: disclosed_fields_root.to_string(),
            zero_knowledge_proof_root: zero_knowledge_proof_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            audience_root: audience_root.to_string(),
            created_at_height,
            expires_at_height,
            status: status.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_migration_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "disclosure_system": QUANTUM_MIGRATION_DISCLOSURE_SYSTEM,
            "disclosure_id": self.disclosure_id,
            "disclosure_kind": self.disclosure_kind.as_str(),
            "subject_kind": self.subject_kind.as_str(),
            "subject_commitment": self.subject_commitment,
            "manifest_id": self.manifest_id,
            "disclosed_fields_root": self.disclosed_fields_root,
            "zero_knowledge_proof_root": self.zero_knowledge_proof_root,
            "nullifier_root": self.nullifier_root,
            "audience_root": self.audience_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn disclosure_root(&self) -> String {
        quantum_migration_payload_root("QM-PRIVACY-MIGRATION-DISCLOSURE", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.subject_commitment, "disclosure subject commitment")?;
        ensure_non_empty(&self.manifest_id, "disclosure manifest id")?;
        ensure_non_empty(&self.disclosed_fields_root, "disclosure fields root")?;
        ensure_non_empty(&self.zero_knowledge_proof_root, "disclosure zk proof root")?;
        ensure_non_empty(&self.nullifier_root, "disclosure nullifier root")?;
        ensure_non_empty(&self.audience_root, "disclosure audience root")?;
        ensure_non_empty(&self.status, "disclosure status")?;
        ensure_height_order(
            self.created_at_height,
            self.expires_at_height,
            "disclosure expiry",
        )?;
        let expected_id = privacy_migration_disclosure_id(
            self.disclosure_kind.as_str(),
            self.subject_kind.as_str(),
            &self.subject_commitment,
            &self.manifest_id,
            &self.nullifier_root,
        );
        if self.disclosure_id != expected_id {
            return Err("disclosure id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub kind: QuantumChallengeKind,
    pub challenger_commitment: String,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_id: String,
    pub manifest_id: String,
    pub evidence_root: String,
    pub observed_at_height: u64,
    pub response_due_height: u64,
    pub status: String,
}

impl ChallengeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: QuantumChallengeKind,
        challenger_commitment: &str,
        subject_kind: QuantumMigrationSubjectKind,
        subject_id: &str,
        manifest_id: &str,
        evidence_root: &str,
        observed_at_height: u64,
        response_due_height: u64,
        status: &str,
    ) -> Self {
        let challenge_id = challenge_evidence_id(
            kind.as_str(),
            subject_kind.as_str(),
            subject_id,
            manifest_id,
            evidence_root,
            observed_at_height,
        );
        Self {
            challenge_id,
            kind,
            challenger_commitment: challenger_commitment.to_string(),
            subject_kind,
            subject_id: subject_id.to_string(),
            manifest_id: manifest_id.to_string(),
            evidence_root: evidence_root.to_string(),
            observed_at_height,
            response_due_height,
            status: status.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "manifest_id": self.manifest_id,
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "response_due_height": self.response_due_height,
            "status": self.status,
        })
    }

    pub fn challenge_root(&self) -> String {
        quantum_migration_payload_root("QM-CHALLENGE-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_non_empty(&self.subject_id, "challenge subject id")?;
        ensure_non_empty(&self.manifest_id, "challenge manifest id")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        ensure_non_empty(&self.status, "challenge status")?;
        ensure_height_order(
            self.observed_at_height,
            self.response_due_height,
            "challenge response window",
        )?;
        let expected_id = challenge_evidence_id(
            self.kind.as_str(),
            self.subject_kind.as_str(),
            &self.subject_id,
            &self.manifest_id,
            &self.evidence_root,
            self.observed_at_height,
        );
        if self.challenge_id != expected_id {
            return Err("challenge id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingRecommendation {
    pub recommendation_id: String,
    pub challenge_id: String,
    pub subject_kind: QuantumMigrationSubjectKind,
    pub subject_id: String,
    pub action: QuantumSlashingAction,
    pub penalty_bps: u64,
    pub slash_amount_units: u64,
    pub rationale_root: String,
    pub evidence_root: String,
    pub recommended_by_committee_id: String,
    pub created_at_height: u64,
    pub status: String,
}

impl SlashingRecommendation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_id: &str,
        subject_kind: QuantumMigrationSubjectKind,
        subject_id: &str,
        action: QuantumSlashingAction,
        penalty_bps: u64,
        slash_amount_units: u64,
        rationale_root: &str,
        evidence_root: &str,
        recommended_by_committee_id: &str,
        created_at_height: u64,
        status: &str,
    ) -> Self {
        let recommendation_id = slashing_recommendation_id(
            challenge_id,
            action.as_str(),
            penalty_bps,
            created_at_height,
        );
        Self {
            recommendation_id,
            challenge_id: challenge_id.to_string(),
            subject_kind,
            subject_id: subject_id.to_string(),
            action,
            penalty_bps,
            slash_amount_units,
            rationale_root: rationale_root.to_string(),
            evidence_root: evidence_root.to_string(),
            recommended_by_committee_id: recommended_by_committee_id.to_string(),
            created_at_height,
            status: status.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "slashing_recommendation",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "recommendation_id": self.recommendation_id,
            "challenge_id": self.challenge_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": self.subject_id,
            "action": self.action.as_str(),
            "penalty_bps": self.penalty_bps,
            "slash_amount_units": self.slash_amount_units,
            "rationale_root": self.rationale_root,
            "evidence_root": self.evidence_root,
            "recommended_by_committee_id": self.recommended_by_committee_id,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn recommendation_root(&self) -> String {
        quantum_migration_payload_root("QM-SLASHING-RECOMMENDATION", &self.public_record())
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(&self.challenge_id, "slashing recommendation challenge id")?;
        ensure_non_empty(&self.subject_id, "slashing recommendation subject id")?;
        ensure_non_empty(
            &self.rationale_root,
            "slashing recommendation rationale root",
        )?;
        ensure_non_empty(&self.evidence_root, "slashing recommendation evidence root")?;
        ensure_non_empty(
            &self.recommended_by_committee_id,
            "slashing recommendation committee id",
        )?;
        ensure_non_empty(&self.status, "slashing recommendation status")?;
        if self.penalty_bps > 10_000 {
            return Err("slashing recommendation penalty cannot exceed 10000 bps".to_string());
        }
        if self.action == QuantumSlashingAction::None
            && (self.penalty_bps != 0 || self.slash_amount_units != 0)
        {
            return Err("non-slashing recommendation cannot carry a penalty".to_string());
        }
        let expected_id = slashing_recommendation_id(
            &self.challenge_id,
            self.action.as_str(),
            self.penalty_bps,
            self.created_at_height,
        );
        if self.recommendation_id != expected_id {
            return Err("slashing recommendation id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumMigrationState {
    pub chain_height: u64,
    pub registry: PostQuantumAlgorithmRegistry,
    pub rotation_schedules: Vec<MandatoryKeyRotationSchedule>,
    pub enrollments: Vec<HybridKeyEnrollment>,
    pub manifests: Vec<MigrationManifest>,
    pub wallet_rekey_bundles: Vec<WalletRekeyBundle>,
    pub committees: Vec<MigrationAttestationCommittee>,
    pub attestations: Vec<PqMigrationAttestation>,
    pub fallback_policies: Vec<FallbackRecoveryPolicy>,
    pub incidents: Vec<QuantumRiskIncident>,
    pub emergency_freezes: Vec<EmergencyFreeze>,
    pub sponsored_batches: Vec<SponsoredRekeyBatch>,
    pub disclosures: Vec<PrivacyMigrationDisclosure>,
    pub challenges: Vec<ChallengeEvidence>,
    pub slashing_recommendations: Vec<SlashingRecommendation>,
    pub devnet_notes_root: String,
}

impl QuantumMigrationState {
    pub fn devnet() -> QuantumMigrationResult<Self> {
        let height = 128;
        let ml_dsa = PostQuantumAlgorithmSpec::new(
            QuantumMigrationAlgorithmFamily::Signature,
            QuantumMigrationAlgorithmStatus::Mandatory,
            "ML-DSA-65",
            "NIST FIPS 204",
            3,
            1_952,
            3_309,
            1,
            1,
            Some(64),
            None,
            None,
            Some(1_440),
            &json!({"devnet_use": "online account, validator, operator, and committee signatures"}),
        );
        let slh_dsa = PostQuantumAlgorithmSpec::new(
            QuantumMigrationAlgorithmFamily::Signature,
            QuantumMigrationAlgorithmStatus::Recommended,
            "SLH-DSA-SHAKE-128s",
            "NIST FIPS 205",
            1,
            32,
            7_856,
            1,
            1,
            Some(256),
            None,
            None,
            None,
            &json!({"devnet_use": "offline and recovery signatures"}),
        );
        let ml_kem = PostQuantumAlgorithmSpec::new(
            QuantumMigrationAlgorithmFamily::Kem,
            QuantumMigrationAlgorithmStatus::Mandatory,
            "ML-KEM-768",
            "NIST FIPS 203",
            3,
            1_184,
            1_088,
            1,
            1,
            Some(64),
            None,
            None,
            Some(1_440),
            &json!({"devnet_use": "sealed wallet rekey bundles and transport encryption"}),
        );
        let ed25519 = PostQuantumAlgorithmSpec::new(
            QuantumMigrationAlgorithmFamily::ClassicSignature,
            QuantumMigrationAlgorithmStatus::Deprecated,
            "Ed25519-devnet-legacy",
            "devnet-classic-fallback",
            0,
            32,
            64,
            1,
            1,
            None,
            Some(256),
            Some(1_024),
            Some(1_440),
            &json!({"devnet_use": "legacy signature fallback during hybrid enrollment only"}),
        );
        let x25519 = PostQuantumAlgorithmSpec::new(
            QuantumMigrationAlgorithmFamily::ClassicKem,
            QuantumMigrationAlgorithmStatus::Deprecated,
            "X25519-devnet-legacy",
            "devnet-classic-fallback",
            0,
            32,
            32,
            1,
            1,
            None,
            Some(256),
            Some(1_024),
            Some(1_440),
            &json!({"devnet_use": "legacy transport fallback during hybrid enrollment only"}),
        );
        let deprecation_windows = vec![
            AlgorithmDeprecationWindow::new(
                &ed25519.algorithm_id,
                vec![ml_dsa.algorithm_id.clone(), slh_dsa.algorithm_id.clone()],
                128,
                256,
                1_024,
                1_440,
                384,
                &json!({"policy": "classic signatures must dual-sign until PQ signature activation"}),
            ),
            AlgorithmDeprecationWindow::new(
                &x25519.algorithm_id,
                vec![ml_kem.algorithm_id.clone()],
                128,
                256,
                1_024,
                1_440,
                384,
                &json!({"policy": "classic KEM may only wrap ML-KEM sealed roots during transition"}),
            ),
        ];
        let registry = PostQuantumAlgorithmRegistry::new(
            QUANTUM_MIGRATION_REGISTRY_VERSION,
            height,
            vec![
                ml_dsa.clone(),
                slh_dsa.clone(),
                ml_kem.clone(),
                ed25519.clone(),
                x25519.clone(),
            ],
            deprecation_windows,
            &[
                QuantumMigrationAlgorithmFamily::Signature,
                QuantumMigrationAlgorithmFamily::Kem,
            ],
            "mandatory_pq_enrollment",
        );
        let registry_root = registry.registry_root();

        let account_schedule = MandatoryKeyRotationSchedule::new(
            QuantumMigrationSubjectKind::Account,
            "acct-alice-devnet",
            "spend_authority",
            &ml_dsa.algorithm_id,
            QUANTUM_MIGRATION_DEFAULT_ROTATION_BLOCKS,
            QUANTUM_MIGRATION_DEFAULT_ROTATION_NOTICE_BLOCKS,
            QUANTUM_MIGRATION_DEFAULT_ROTATION_OVERLAP_BLOCKS,
            20_288,
            21_008,
            true,
            true,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let validator_schedule = MandatoryKeyRotationSchedule::new(
            QuantumMigrationSubjectKind::Validator,
            "validator-01",
            "consensus_vote",
            &ml_dsa.algorithm_id,
            10_080,
            720,
            360,
            10_208,
            10_568,
            true,
            false,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let bridge_schedule = MandatoryKeyRotationSchedule::new(
            QuantumMigrationSubjectKind::Bridge,
            "monero-bridge-signer-set",
            "withdrawal_release",
            &ml_dsa.algorithm_id,
            7_200,
            720,
            360,
            7_328,
            7_688,
            true,
            false,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let operator_schedule = MandatoryKeyRotationSchedule::new(
            QuantumMigrationSubjectKind::Operator,
            "operator-alpha",
            "network_operator",
            &ml_dsa.algorithm_id,
            10_080,
            720,
            360,
            10_208,
            10_568,
            true,
            false,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let rotation_schedules = vec![
            account_schedule.clone(),
            validator_schedule.clone(),
            bridge_schedule.clone(),
            operator_schedule.clone(),
        ];

        let account_enrollment = HybridKeyEnrollment::new(
            QuantumMigrationSubjectKind::Account,
            "acct-alice-devnet",
            &quantum_migration_label_commitment("account", "alice"),
            &ed25519.algorithm_id,
            &ml_dsa.algorithm_id,
            &quantum_migration_string_root("classic-account-key", "alice-ed25519-v0"),
            &quantum_migration_string_root("pq-account-key", "alice-ml-dsa-v1"),
            &quantum_migration_string_root("pop", "alice-dual-signature-pop"),
            &account_schedule.schedule_id,
            96,
            128,
            20_288,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let validator_enrollment = HybridKeyEnrollment::new(
            QuantumMigrationSubjectKind::Validator,
            "validator-01",
            &quantum_migration_label_commitment("validator", "validator-01"),
            &ed25519.algorithm_id,
            &ml_dsa.algorithm_id,
            &quantum_migration_string_root("classic-validator-key", "validator-01-ed25519-v0"),
            &quantum_migration_string_root("pq-validator-key", "validator-01-ml-dsa-v1"),
            &quantum_migration_string_root("pop", "validator-01-dual-vote-pop"),
            &validator_schedule.schedule_id,
            96,
            128,
            10_208,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let bridge_enrollment = HybridKeyEnrollment::new(
            QuantumMigrationSubjectKind::Bridge,
            "monero-bridge-signer-set",
            &quantum_migration_label_commitment("bridge", "monero-bridge-signer-set"),
            &ed25519.algorithm_id,
            &ml_dsa.algorithm_id,
            &quantum_migration_string_root("classic-bridge-key", "bridge-ed25519-threshold-v0"),
            &quantum_migration_string_root("pq-bridge-key", "bridge-ml-dsa-threshold-v1"),
            &quantum_migration_string_root("pop", "bridge-threshold-dual-pop"),
            &bridge_schedule.schedule_id,
            96,
            128,
            7_328,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let operator_enrollment = HybridKeyEnrollment::new(
            QuantumMigrationSubjectKind::Operator,
            "operator-alpha",
            &quantum_migration_label_commitment("operator", "operator-alpha"),
            &ed25519.algorithm_id,
            &ml_dsa.algorithm_id,
            &quantum_migration_string_root("classic-operator-key", "operator-alpha-ed25519-v0"),
            &quantum_migration_string_root("pq-operator-key", "operator-alpha-ml-dsa-v1"),
            &quantum_migration_string_root("pop", "operator-alpha-dual-pop"),
            &operator_schedule.schedule_id,
            96,
            128,
            10_208,
            QuantumMigrationEnrollmentStatus::Active,
        );
        let enrollments = vec![
            account_enrollment.clone(),
            validator_enrollment.clone(),
            bridge_enrollment.clone(),
            operator_enrollment.clone(),
        ];

        let wallet_rekey_bundle = WalletRekeyBundle::new(
            &account_enrollment.owner_commitment,
            &quantum_migration_string_root("wallet-version", "nebula-wallet-devnet-2"),
            &wallet_rekey_encrypted_payload_root(
                &account_enrollment.owner_commitment,
                "alice-sealed-rekey-payload-v1",
            ),
            &quantum_migration_string_root("recipient-kem", "alice-ml-kem-768-v1"),
            &quantum_migration_string_root("proof-of-encryption", "alice-rekey-sealed-root-proof"),
            Some(quantum_migration_label_commitment(
                "sponsor",
                "migration-foundation",
            )),
            128,
            128 + QUANTUM_MIGRATION_DEFAULT_BUNDLE_TTL_BLOCKS,
            1,
            QuantumMigrationRekeyStatus::Sponsored,
        );
        let wallet_rekey_bundles = vec![wallet_rekey_bundle.clone()];
        let empty_attestation_root = quantum_migration_attestation_root(&[]);
        let empty_disclosure_root = quantum_migration_privacy_disclosure_root(&[]);

        let account_manifest = MigrationManifest::new(
            QuantumMigrationSubjectKind::Account,
            "acct-alice-devnet",
            &account_enrollment.owner_commitment,
            &account_enrollment.enrollment_id,
            &account_schedule.schedule_id,
            &account_enrollment.classic_key_root,
            &account_enrollment.pq_key_root,
            &registry_root,
            &account_schedule.schedule_root(),
            Some(wallet_rekey_bundle.bundle_id.clone()),
            &wallet_rekey_bundle.bundle_root(),
            &empty_disclosure_root,
            &empty_attestation_root,
            128,
            160,
            128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
            QuantumMigrationManifestStatus::Announced,
        );
        let validator_manifest = MigrationManifest::new(
            QuantumMigrationSubjectKind::Validator,
            "validator-01",
            &validator_enrollment.owner_commitment,
            &validator_enrollment.enrollment_id,
            &validator_schedule.schedule_id,
            &validator_enrollment.classic_key_root,
            &validator_enrollment.pq_key_root,
            &registry_root,
            &validator_schedule.schedule_root(),
            None,
            &quantum_migration_empty_root("QM-NO-WALLET-REKEY"),
            &empty_disclosure_root,
            &empty_attestation_root,
            128,
            160,
            128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
            QuantumMigrationManifestStatus::Announced,
        );
        let bridge_manifest = MigrationManifest::new(
            QuantumMigrationSubjectKind::Bridge,
            "monero-bridge-signer-set",
            &bridge_enrollment.owner_commitment,
            &bridge_enrollment.enrollment_id,
            &bridge_schedule.schedule_id,
            &bridge_enrollment.classic_key_root,
            &bridge_enrollment.pq_key_root,
            &registry_root,
            &bridge_schedule.schedule_root(),
            None,
            &quantum_migration_empty_root("QM-NO-WALLET-REKEY"),
            &empty_disclosure_root,
            &empty_attestation_root,
            128,
            160,
            128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
            QuantumMigrationManifestStatus::Announced,
        );
        let operator_manifest = MigrationManifest::new(
            QuantumMigrationSubjectKind::Operator,
            "operator-alpha",
            &operator_enrollment.owner_commitment,
            &operator_enrollment.enrollment_id,
            &operator_schedule.schedule_id,
            &operator_enrollment.classic_key_root,
            &operator_enrollment.pq_key_root,
            &registry_root,
            &operator_schedule.schedule_root(),
            None,
            &quantum_migration_empty_root("QM-NO-WALLET-REKEY"),
            &empty_disclosure_root,
            &empty_attestation_root,
            128,
            160,
            128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
            QuantumMigrationManifestStatus::Announced,
        );
        let manifests = vec![
            account_manifest.clone(),
            validator_manifest.clone(),
            bridge_manifest.clone(),
            operator_manifest.clone(),
        ];

        let committee_members = vec![
            MigrationCommitteeMember::new(
                "operator-alpha",
                &quantum_migration_string_root("committee-key", "operator-alpha-ml-dsa"),
                1,
                &quantum_migration_string_root("privacy-contact", "operator-alpha-contact"),
                true,
            ),
            MigrationCommitteeMember::new(
                "operator-beta",
                &quantum_migration_string_root("committee-key", "operator-beta-ml-dsa"),
                1,
                &quantum_migration_string_root("privacy-contact", "operator-beta-contact"),
                true,
            ),
            MigrationCommitteeMember::new(
                "watchtower-gamma",
                &quantum_migration_string_root("committee-key", "watchtower-gamma-ml-dsa"),
                1,
                &quantum_migration_string_root("privacy-contact", "watchtower-gamma-contact"),
                true,
            ),
        ];
        let committee = MigrationAttestationCommittee::new(
            0,
            1,
            10_080,
            committee_members,
            2,
            2,
            &json!({"quorum": "two of three migration committee members"}),
        );
        let signer_commitments = vec![
            quantum_migration_label_commitment("committee", "operator-alpha"),
            quantum_migration_label_commitment("committee", "operator-beta"),
        ];
        let attestations = manifests
            .iter()
            .map(|manifest| {
                PqMigrationAttestation::new(
                    &committee,
                    manifest,
                    QuantumMigrationAttestationDecision::Approved,
                    2,
                    &signer_commitments,
                    132,
                    132 + QUANTUM_MIGRATION_DEFAULT_ATTESTATION_TTL_BLOCKS,
                    QuantumMigrationManifestStatus::Attested,
                )
            })
            .collect::<Vec<_>>();

        let fallback_policies = vec![
            FallbackRecoveryPolicy::new(
                QuantumMigrationSubjectKind::Account,
                "acct-alice-devnet",
                QuantumMigrationFallbackMode::HardwareSignerGrace,
                &quantum_migration_string_root("hardware-signer", "alice-ledger-devnet"),
                &quantum_migration_string_root("offline-signer", "alice-paper-slh-dsa-root"),
                &quantum_migration_string_root("guardian-set", "alice-2-of-3-guardians"),
                &quantum_migration_string_root("emergency-contact", "alice-contact-commitment"),
                720,
                3,
                2,
                true,
                128,
                128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
                QuantumMigrationEnrollmentStatus::Active,
            ),
            FallbackRecoveryPolicy::new(
                QuantumMigrationSubjectKind::Operator,
                "operator-alpha",
                QuantumMigrationFallbackMode::OfflineSignerWindow,
                &quantum_migration_string_root("hardware-signer", "operator-alpha-hsm"),
                &quantum_migration_string_root("offline-signer", "operator-alpha-offline-root"),
                &quantum_migration_string_root("guardian-set", "operator-alpha-board"),
                &quantum_migration_string_root("emergency-contact", "operator-alpha-contact"),
                360,
                2,
                2,
                true,
                128,
                128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
                QuantumMigrationEnrollmentStatus::Active,
            ),
        ];

        let incident = QuantumRiskIncident::new(
            QuantumRiskSeverity::Elevated,
            &quantum_migration_label_commitment("incident-declarer", "watchtower-gamma"),
            &quantum_migration_payload_root(
                "QM-INCIDENT-DECLARATION",
                &json!({"scenario": "legacy signature harvest risk tabletop"}),
            ),
            &quantum_migration_manifest_root(&manifests),
            &quantum_migration_payload_root(
                "QM-INCIDENT-MITIGATION",
                &json!({"action": "freeze new classic-only enrollment"}),
            ),
            136,
            136 + QUANTUM_MIGRATION_DEFAULT_FREEZE_BLOCKS,
            "active",
        );
        let freeze = EmergencyFreeze::new(
            &incident.incident_id,
            QuantumFreezeScope::Enrollment,
            &quantum_migration_string_root("freeze-subject", "classic-only-enrollments"),
            &quantum_migration_string_root("freeze-reason", "legacy signature harvest tabletop"),
            136,
            136 + QUANTUM_MIGRATION_DEFAULT_FREEZE_BLOCKS,
            None,
            "active",
        );

        let disclosure = PrivacyMigrationDisclosure::new(
            QuantumMigrationDisclosureKind::KeyCommitmentOnly,
            QuantumMigrationSubjectKind::Account,
            &account_enrollment.owner_commitment,
            &account_manifest.manifest_id,
            &quantum_migration_string_root("disclosed-fields", "account-kind-target-key-root"),
            &quantum_migration_string_root("zk-proof", "alice-migration-inclusion-proof"),
            &quantum_migration_string_root("nullifier", "alice-migration-nullifier"),
            &quantum_migration_string_root("audience", "migration-committee"),
            128,
            128 + QUANTUM_MIGRATION_DEFAULT_MANIFEST_TTL_BLOCKS,
            "active",
        );

        let sponsored_batch = SponsoredRekeyBatch::new(
            &quantum_migration_label_commitment("sponsor", "migration-foundation"),
            QUANTUM_MIGRATION_DEVNET_FEE_ASSET_ID,
            25_000,
            5_000,
            1_250,
            vec![account_manifest.manifest_id.clone()],
            vec![wallet_rekey_bundle.bundle_id.clone()],
            &quantum_migration_string_root("privacy-pool", "sponsored-rekey-pool-epoch-0"),
            128,
            128 + QUANTUM_MIGRATION_DEFAULT_SPONSORED_BATCH_TTL_BLOCKS,
            QuantumMigrationRekeyStatus::Sponsored,
        );

        let challenge = ChallengeEvidence::new(
            QuantumChallengeKind::DeprecatedAlgorithmUsed,
            &quantum_migration_label_commitment("challenger", "watchtower-gamma"),
            QuantumMigrationSubjectKind::Bridge,
            "monero-bridge-signer-set",
            &bridge_manifest.manifest_id,
            &quantum_migration_string_root(
                "challenge-evidence",
                "bridge-classic-signature-observed",
            ),
            140,
            140 + QUANTUM_MIGRATION_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            "pending",
        );
        let slashing = SlashingRecommendation::new(
            &challenge.challenge_id,
            QuantumMigrationSubjectKind::Bridge,
            "monero-bridge-signer-set",
            QuantumSlashingAction::Warning,
            0,
            0,
            &quantum_migration_string_root("slashing-rationale", "warning-for-devnet-tabletop"),
            &challenge.evidence_root,
            &committee.committee_id,
            142,
            "recommended",
        );

        let state = Self {
            chain_height: height,
            registry,
            rotation_schedules,
            enrollments,
            manifests,
            wallet_rekey_bundles,
            committees: vec![committee],
            attestations,
            fallback_policies,
            incidents: vec![incident],
            emergency_freezes: vec![freeze],
            sponsored_batches: vec![sponsored_batch],
            disclosures: vec![disclosure],
            challenges: vec![challenge],
            slashing_recommendations: vec![slashing],
            devnet_notes_root: quantum_migration_payload_root(
                "QM-DEVNET-NOTES",
                &json!({
                    "scope": "deterministic compile-oriented quantum migration prototype",
                    "privacy": "wallet rekey bundles expose encrypted roots only",
                }),
            ),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> QuantumMigrationResult<()> {
        self.chain_height = height;
        self.registry.set_height(height);
        self.validate()
    }

    pub fn state_root(&self) -> String {
        quantum_migration_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut fields) = record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "quantum_migration_state",
            "chain_id": CHAIN_ID,
            "protocol_version": QUANTUM_MIGRATION_PROTOCOL_VERSION,
            "chain_height": self.chain_height,
            "registry": self.registry.public_record(),
            "rotation_schedule_root": quantum_migration_rotation_schedule_root(&self.rotation_schedules),
            "enrollment_root": quantum_migration_enrollment_root(&self.enrollments),
            "manifest_root": quantum_migration_manifest_root(&self.manifests),
            "wallet_rekey_bundle_root": quantum_migration_wallet_rekey_bundle_root(&self.wallet_rekey_bundles),
            "committee_root": quantum_migration_committee_root(&self.committees),
            "attestation_root": quantum_migration_attestation_root(&self.attestations),
            "fallback_policy_root": quantum_migration_fallback_policy_root(&self.fallback_policies),
            "incident_root": quantum_migration_incident_root(&self.incidents),
            "emergency_freeze_root": quantum_migration_emergency_freeze_root(&self.emergency_freezes),
            "sponsored_batch_root": quantum_migration_sponsored_batch_root(&self.sponsored_batches),
            "privacy_disclosure_root": quantum_migration_privacy_disclosure_root(&self.disclosures),
            "challenge_root": quantum_migration_challenge_root(&self.challenges),
            "slashing_recommendation_root": quantum_migration_slashing_recommendation_root(&self.slashing_recommendations),
            "devnet_notes_root": self.devnet_notes_root,
            "rotation_schedules": self.rotation_schedules.iter().map(MandatoryKeyRotationSchedule::public_record).collect::<Vec<_>>(),
            "enrollments": self.enrollments.iter().map(HybridKeyEnrollment::public_record).collect::<Vec<_>>(),
            "manifests": self.manifests.iter().map(MigrationManifest::public_record).collect::<Vec<_>>(),
            "wallet_rekey_bundles": self.wallet_rekey_bundles.iter().map(WalletRekeyBundle::public_record).collect::<Vec<_>>(),
            "committees": self.committees.iter().map(MigrationAttestationCommittee::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.iter().map(PqMigrationAttestation::public_record).collect::<Vec<_>>(),
            "fallback_policies": self.fallback_policies.iter().map(FallbackRecoveryPolicy::public_record).collect::<Vec<_>>(),
            "incidents": self.incidents.iter().map(QuantumRiskIncident::public_record).collect::<Vec<_>>(),
            "emergency_freezes": self.emergency_freezes.iter().map(EmergencyFreeze::public_record).collect::<Vec<_>>(),
            "sponsored_batches": self.sponsored_batches.iter().map(SponsoredRekeyBatch::public_record).collect::<Vec<_>>(),
            "disclosures": self.disclosures.iter().map(PrivacyMigrationDisclosure::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.iter().map(ChallengeEvidence::public_record).collect::<Vec<_>>(),
            "slashing_recommendations": self.slashing_recommendations.iter().map(SlashingRecommendation::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> QuantumMigrationResult<()> {
        ensure_non_empty(
            &self.devnet_notes_root,
            "quantum migration devnet notes root",
        )?;
        self.registry.validate()?;
        ensure_max_len(
            self.rotation_schedules.len(),
            QUANTUM_MIGRATION_MAX_ROTATION_SCHEDULES,
            "rotation schedules",
        )?;
        ensure_max_len(
            self.enrollments.len(),
            QUANTUM_MIGRATION_MAX_ENROLLMENTS,
            "hybrid enrollments",
        )?;
        ensure_max_len(
            self.manifests.len(),
            QUANTUM_MIGRATION_MAX_MANIFESTS,
            "migration manifests",
        )?;
        ensure_max_len(
            self.wallet_rekey_bundles.len(),
            QUANTUM_MIGRATION_MAX_REKEY_BUNDLES,
            "wallet rekey bundles",
        )?;
        ensure_max_len(
            self.committees.len(),
            QUANTUM_MIGRATION_MAX_COMMITTEES,
            "migration committees",
        )?;
        ensure_max_len(
            self.attestations.len(),
            QUANTUM_MIGRATION_MAX_ATTESTATIONS,
            "migration attestations",
        )?;
        ensure_max_len(
            self.fallback_policies.len(),
            QUANTUM_MIGRATION_MAX_FALLBACK_POLICIES,
            "fallback policies",
        )?;
        ensure_max_len(
            self.incidents.len(),
            QUANTUM_MIGRATION_MAX_INCIDENTS,
            "risk incidents",
        )?;
        ensure_max_len(
            self.emergency_freezes.len(),
            QUANTUM_MIGRATION_MAX_FREEZES,
            "emergency freezes",
        )?;
        ensure_max_len(
            self.sponsored_batches.len(),
            QUANTUM_MIGRATION_MAX_SPONSORED_BATCHES,
            "sponsored batches",
        )?;
        ensure_max_len(
            self.disclosures.len(),
            QUANTUM_MIGRATION_MAX_DISCLOSURES,
            "privacy disclosures",
        )?;
        ensure_max_len(
            self.challenges.len(),
            QUANTUM_MIGRATION_MAX_CHALLENGES,
            "challenge evidence",
        )?;
        ensure_max_len(
            self.slashing_recommendations.len(),
            QUANTUM_MIGRATION_MAX_SLASHING_RECOMMENDATIONS,
            "slashing recommendations",
        )?;

        let algorithm_map = self.registry.algorithm_map();
        let mut schedule_ids = BTreeSet::new();
        for schedule in &self.rotation_schedules {
            schedule.validate()?;
            ensure_insert_unique(
                &mut schedule_ids,
                &schedule.schedule_id,
                "rotation schedule",
            )?;
            if !algorithm_map.contains_key(&schedule.required_algorithm_id) {
                return Err(format!(
                    "rotation schedule references unknown algorithm {}",
                    schedule.required_algorithm_id
                ));
            }
        }

        let mut enrollment_ids = BTreeSet::new();
        for enrollment in &self.enrollments {
            enrollment.validate()?;
            ensure_insert_unique(&mut enrollment_ids, &enrollment.enrollment_id, "enrollment")?;
            if !schedule_ids.contains(&enrollment.schedule_id) {
                return Err(format!(
                    "hybrid enrollment references unknown schedule {}",
                    enrollment.schedule_id
                ));
            }
            if !algorithm_map.contains_key(&enrollment.classic_algorithm_id) {
                return Err(format!(
                    "hybrid enrollment references unknown classic algorithm {}",
                    enrollment.classic_algorithm_id
                ));
            }
            if !algorithm_map.contains_key(&enrollment.pq_algorithm_id) {
                return Err(format!(
                    "hybrid enrollment references unknown pq algorithm {}",
                    enrollment.pq_algorithm_id
                ));
            }
        }

        let mut bundle_ids = BTreeSet::new();
        for bundle in &self.wallet_rekey_bundles {
            bundle.validate()?;
            ensure_insert_unique(&mut bundle_ids, &bundle.bundle_id, "wallet rekey bundle")?;
        }

        let mut manifest_ids = BTreeSet::new();
        for manifest in &self.manifests {
            manifest.validate()?;
            ensure_insert_unique(&mut manifest_ids, &manifest.manifest_id, "manifest")?;
            if !enrollment_ids.contains(&manifest.enrollment_id) {
                return Err(format!(
                    "migration manifest references unknown enrollment {}",
                    manifest.enrollment_id
                ));
            }
            if !schedule_ids.contains(&manifest.rotation_schedule_id) {
                return Err(format!(
                    "migration manifest references unknown schedule {}",
                    manifest.rotation_schedule_id
                ));
            }
            if let Some(bundle_id) = &manifest.wallet_rekey_bundle_id {
                if !bundle_ids.contains(bundle_id) {
                    return Err(format!(
                        "migration manifest references unknown rekey bundle {bundle_id}"
                    ));
                }
            }
        }

        let mut committee_ids = BTreeSet::new();
        for committee in &self.committees {
            committee.validate()?;
            ensure_insert_unique(&mut committee_ids, &committee.committee_id, "committee")?;
        }

        let mut attestation_ids = BTreeSet::new();
        for attestation in &self.attestations {
            attestation.validate()?;
            ensure_insert_unique(
                &mut attestation_ids,
                &attestation.attestation_id,
                "attestation",
            )?;
            if !committee_ids.contains(&attestation.committee_id) {
                return Err(format!(
                    "attestation references unknown committee {}",
                    attestation.committee_id
                ));
            }
            if !manifest_ids.contains(&attestation.manifest_id) {
                return Err(format!(
                    "attestation references unknown manifest {}",
                    attestation.manifest_id
                ));
            }
        }

        for policy in &self.fallback_policies {
            policy.validate()?;
        }

        let mut incident_ids = BTreeSet::new();
        for incident in &self.incidents {
            incident.validate()?;
            ensure_insert_unique(&mut incident_ids, &incident.incident_id, "incident")?;
        }
        for freeze in &self.emergency_freezes {
            freeze.validate()?;
            if !incident_ids.contains(&freeze.incident_id) {
                return Err(format!(
                    "emergency freeze references unknown incident {}",
                    freeze.incident_id
                ));
            }
        }

        for batch in &self.sponsored_batches {
            batch.validate()?;
            for manifest_id in &batch.manifest_ids {
                if !manifest_ids.contains(manifest_id) {
                    return Err(format!(
                        "sponsored batch references unknown manifest {manifest_id}"
                    ));
                }
            }
            for bundle_id in &batch.wallet_bundle_ids {
                if !bundle_ids.contains(bundle_id) {
                    return Err(format!(
                        "sponsored batch references unknown wallet bundle {bundle_id}"
                    ));
                }
            }
        }

        for disclosure in &self.disclosures {
            disclosure.validate()?;
            if !manifest_ids.contains(&disclosure.manifest_id) {
                return Err(format!(
                    "privacy disclosure references unknown manifest {}",
                    disclosure.manifest_id
                ));
            }
        }

        let mut challenge_ids = BTreeSet::new();
        for challenge in &self.challenges {
            challenge.validate()?;
            ensure_insert_unique(&mut challenge_ids, &challenge.challenge_id, "challenge")?;
            if !manifest_ids.contains(&challenge.manifest_id) {
                return Err(format!(
                    "challenge references unknown manifest {}",
                    challenge.manifest_id
                ));
            }
        }
        for recommendation in &self.slashing_recommendations {
            recommendation.validate()?;
            if !challenge_ids.contains(&recommendation.challenge_id) {
                return Err(format!(
                    "slashing recommendation references unknown challenge {}",
                    recommendation.challenge_id
                ));
            }
            if !committee_ids.contains(&recommendation.recommended_by_committee_id) {
                return Err(format!(
                    "slashing recommendation references unknown committee {}",
                    recommendation.recommended_by_committee_id
                ));
            }
        }

        Ok(())
    }
}

pub fn devnet() -> QuantumMigrationResult<QuantumMigrationState> {
    QuantumMigrationState::devnet()
}

pub fn quantum_migration_algorithm_id(
    family: &str,
    scheme: &str,
    security_level: u64,
    registered_at_height: u64,
) -> String {
    domain_hash(
        "QM-ALGORITHM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(scheme),
            HashPart::Int(security_level as i128),
            HashPart::Int(registered_at_height as i128),
        ],
        32,
    )
}

pub fn quantum_migration_deprecation_window_id(
    algorithm_id: &str,
    replacement_root: &str,
    warning_height: u64,
    disabled_height: u64,
) -> String {
    domain_hash(
        "QM-DEPRECATION-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(algorithm_id),
            HashPart::Str(replacement_root),
            HashPart::Int(warning_height as i128),
            HashPart::Int(disabled_height as i128),
        ],
        32,
    )
}

pub fn quantum_migration_registry_id(
    version: u64,
    current_height: u64,
    algorithm_root: &str,
    deprecation_window_root: &str,
) -> String {
    domain_hash(
        "QM-REGISTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(version as i128),
            HashPart::Int(current_height as i128),
            HashPart::Str(algorithm_root),
            HashPart::Str(deprecation_window_root),
        ],
        32,
    )
}

pub fn quantum_rotation_schedule_id(
    subject_kind: &str,
    subject_id: &str,
    role: &str,
    required_algorithm_id: &str,
    next_rotation_height: u64,
) -> String {
    domain_hash(
        "QM-ROTATION-SCHEDULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(role),
            HashPart::Str(required_algorithm_id),
            HashPart::Int(next_rotation_height as i128),
        ],
        32,
    )
}

pub fn quantum_migration_hybrid_binding_root(
    subject_kind: &str,
    subject_id: &str,
    owner_commitment: &str,
    classic_key_root: &str,
    pq_key_root: &str,
) -> String {
    domain_hash(
        "QM-HYBRID-BINDING-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(classic_key_root),
            HashPart::Str(pq_key_root),
        ],
        32,
    )
}

pub fn hybrid_key_enrollment_id(
    subject_kind: &str,
    subject_id: &str,
    owner_commitment: &str,
    hybrid_binding_root: &str,
    enrolled_at_height: u64,
) -> String {
    domain_hash(
        "QM-HYBRID-KEY-ENROLLMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(hybrid_binding_root),
            HashPart::Int(enrolled_at_height as i128),
        ],
        32,
    )
}

pub fn migration_manifest_id(
    subject_kind: &str,
    subject_id: &str,
    owner_commitment: &str,
    target_key_root: &str,
    declared_at_height: u64,
) -> String {
    domain_hash(
        "QM-MIGRATION-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(target_key_root),
            HashPart::Int(declared_at_height as i128),
        ],
        32,
    )
}

pub fn wallet_rekey_bundle_id(
    account_commitment: &str,
    encrypted_payload_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "QM-WALLET-REKEY-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_rekey_encrypted_payload_root(
    account_commitment: &str,
    encrypted_payload_commitment: &str,
) -> String {
    domain_hash(
        "QM-WALLET-REKEY-ENCRYPTED-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(encrypted_payload_commitment),
            HashPart::Str(QUANTUM_MIGRATION_REKEY_PAYLOAD_SCHEME),
        ],
        32,
    )
}

pub fn migration_committee_member_id(operator_label: &str, signing_key_root: &str) -> String {
    domain_hash(
        "QM-COMMITTEE-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(signing_key_root),
        ],
        32,
    )
}

pub fn migration_committee_id(
    epoch_index: u64,
    member_root: &str,
    threshold_weight: u64,
) -> String {
    domain_hash(
        "QM-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch_index as i128),
            HashPart::Str(member_root),
            HashPart::Int(threshold_weight as i128),
        ],
        32,
    )
}

pub fn pq_migration_attestation_id(
    committee_id: &str,
    manifest_id: &str,
    decision: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "QM-PQ-MIGRATION-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(manifest_id),
            HashPart::Str(decision),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn fallback_recovery_policy_id(
    subject_kind: &str,
    subject_id: &str,
    mode: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "QM-FALLBACK-RECOVERY-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(mode),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn quantum_risk_incident_id(
    severity: &str,
    declaration_root: &str,
    declared_by_commitment: &str,
    declared_at_height: u64,
) -> String {
    domain_hash(
        "QM-RISK-INCIDENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(severity),
            HashPart::Str(declaration_root),
            HashPart::Str(declared_by_commitment),
            HashPart::Int(declared_at_height as i128),
        ],
        32,
    )
}

pub fn emergency_freeze_id(
    incident_id: &str,
    scope: &str,
    subject_root: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "QM-EMERGENCY-FREEZE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(incident_id),
            HashPart::Str(scope),
            HashPart::Str(subject_root),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn sponsored_rekey_batch_id(
    sponsor_commitment: &str,
    manifest_root: &str,
    wallet_bundle_root: &str,
    started_at_height: u64,
) -> String {
    domain_hash(
        "QM-SPONSORED-REKEY-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(manifest_root),
            HashPart::Str(wallet_bundle_root),
            HashPart::Int(started_at_height as i128),
        ],
        32,
    )
}

pub fn privacy_migration_disclosure_id(
    disclosure_kind: &str,
    subject_kind: &str,
    subject_commitment: &str,
    manifest_id: &str,
    nullifier_root: &str,
) -> String {
    domain_hash(
        "QM-PRIVACY-MIGRATION-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(disclosure_kind),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_commitment),
            HashPart::Str(manifest_id),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn challenge_evidence_id(
    challenge_kind: &str,
    subject_kind: &str,
    subject_id: &str,
    manifest_id: &str,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "QM-CHALLENGE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(manifest_id),
            HashPart::Str(evidence_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn slashing_recommendation_id(
    challenge_id: &str,
    action: &str,
    penalty_bps: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "QM-SLASHING-RECOMMENDATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(action),
            HashPart::Int(penalty_bps as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn quantum_migration_state_root_from_record(record: &Value) -> String {
    quantum_migration_payload_root("QM-STATE", record)
}

pub fn quantum_migration_public_record_root(record: &Value) -> String {
    quantum_migration_payload_root("QM-PUBLIC-RECORD", record)
}

pub fn quantum_migration_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn quantum_migration_string_root(label: &str, value: &str) -> String {
    domain_hash(
        "QM-STRING-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn quantum_migration_label_commitment(label: &str, value: &str) -> String {
    domain_hash(
        "QM-LABEL-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn quantum_migration_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn quantum_migration_string_list_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn quantum_migration_algorithm_spec_root(records: &[PostQuantumAlgorithmSpec]) -> String {
    merkle_root(
        "QM-ALGORITHM-SPEC",
        &records
            .iter()
            .map(PostQuantumAlgorithmSpec::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_deprecation_root(records: &[AlgorithmDeprecationWindow]) -> String {
    merkle_root(
        "QM-DEPRECATION-WINDOW",
        &records
            .iter()
            .map(AlgorithmDeprecationWindow::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_rotation_schedule_root(
    records: &[MandatoryKeyRotationSchedule],
) -> String {
    merkle_root(
        "QM-ROTATION-SCHEDULE",
        &records
            .iter()
            .map(MandatoryKeyRotationSchedule::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_enrollment_root(records: &[HybridKeyEnrollment]) -> String {
    merkle_root(
        "QM-HYBRID-KEY-ENROLLMENT",
        &records
            .iter()
            .map(HybridKeyEnrollment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_manifest_root(records: &[MigrationManifest]) -> String {
    merkle_root(
        "QM-MIGRATION-MANIFEST",
        &records
            .iter()
            .map(MigrationManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_wallet_rekey_bundle_root(records: &[WalletRekeyBundle]) -> String {
    merkle_root(
        "QM-WALLET-REKEY-BUNDLE",
        &records
            .iter()
            .map(WalletRekeyBundle::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn migration_committee_member_root(records: &[MigrationCommitteeMember]) -> String {
    merkle_root(
        "QM-COMMITTEE-MEMBER",
        &records
            .iter()
            .map(MigrationCommitteeMember::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_committee_root(records: &[MigrationAttestationCommittee]) -> String {
    merkle_root(
        "QM-MIGRATION-COMMITTEE",
        &records
            .iter()
            .map(MigrationAttestationCommittee::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_attestation_root(records: &[PqMigrationAttestation]) -> String {
    merkle_root(
        "QM-PQ-MIGRATION-ATTESTATION",
        &records
            .iter()
            .map(PqMigrationAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_fallback_policy_root(records: &[FallbackRecoveryPolicy]) -> String {
    merkle_root(
        "QM-FALLBACK-RECOVERY-POLICY",
        &records
            .iter()
            .map(FallbackRecoveryPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_incident_root(records: &[QuantumRiskIncident]) -> String {
    merkle_root(
        "QM-QUANTUM-RISK-INCIDENT",
        &records
            .iter()
            .map(QuantumRiskIncident::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_emergency_freeze_root(records: &[EmergencyFreeze]) -> String {
    merkle_root(
        "QM-EMERGENCY-FREEZE",
        &records
            .iter()
            .map(EmergencyFreeze::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_sponsored_batch_root(records: &[SponsoredRekeyBatch]) -> String {
    merkle_root(
        "QM-SPONSORED-REKEY-BATCH",
        &records
            .iter()
            .map(SponsoredRekeyBatch::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_privacy_disclosure_root(records: &[PrivacyMigrationDisclosure]) -> String {
    merkle_root(
        "QM-PRIVACY-MIGRATION-DISCLOSURE",
        &records
            .iter()
            .map(PrivacyMigrationDisclosure::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_challenge_root(records: &[ChallengeEvidence]) -> String {
    merkle_root(
        "QM-CHALLENGE-EVIDENCE",
        &records
            .iter()
            .map(ChallengeEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn quantum_migration_slashing_recommendation_root(
    records: &[SlashingRecommendation],
) -> String {
    merkle_root(
        "QM-SLASHING-RECOMMENDATION",
        &records
            .iter()
            .map(SlashingRecommendation::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, label: &str) -> QuantumMigrationResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_height_order(
    start_height: u64,
    end_height: u64,
    label: &str,
) -> QuantumMigrationResult<()> {
    if start_height > end_height {
        Err(format!("{label} start height cannot exceed end height"))
    } else {
        Ok(())
    }
}

fn ensure_strictly_increasing(values: &[u64], label: &str) -> QuantumMigrationResult<()> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        Err(format!("{label} must be strictly increasing"))
    } else {
        Ok(())
    }
}

fn ensure_max_len(count: usize, max: usize, label: &str) -> QuantumMigrationResult<()> {
    if count > max {
        Err(format!("{label} exceeds maximum length {max}"))
    } else {
        Ok(())
    }
}

fn ensure_insert_unique(
    values: &mut BTreeSet<String>,
    value: &str,
    label: &str,
) -> QuantumMigrationResult<()> {
    if !values.insert(value.to_string()) {
        Err(format!("{label} contains duplicate id {value}"))
    } else {
        Ok(())
    }
}
