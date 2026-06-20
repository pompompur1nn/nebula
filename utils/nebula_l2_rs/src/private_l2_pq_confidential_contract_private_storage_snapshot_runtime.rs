use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STORAGE_SNAPSHOT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-private-storage-snapshot-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STORAGE_SNAPSHOT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_SNAPSHOT_MANIFEST_SUITE: &str =
    "ml-kem-1024+xwing-encrypted-private-storage-snapshot-manifest-v1";
pub const CONTRACT_NAMESPACE_ROOT_SUITE: &str =
    "private-l2-confidential-contract-namespace-root-snapshot-v1";
pub const FHE_SLOT_COMMITMENT_SUITE: &str =
    "tfhe-slot-commitment+redacted-view-tag-private-storage-snapshot-v1";
pub const PQ_SNAPSHOT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-storage-snapshot-attestation-v1";
pub const ROLLBACK_FENCE_SUITE: &str = "private-l2-confidential-storage-rollback-fence-v1";
pub const LOW_FEE_SNAPSHOT_REBATE_SUITE: &str =
    "private-l2-low-fee-confidential-storage-snapshot-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "private-storage-snapshot-redaction-budget-v1";
pub const DETERMINISTIC_ROOT_SUITE: &str =
    "deterministic-private-storage-snapshot-roots-and-public-records-v1";
pub const DEVNET_HEIGHT: u64 = 2_112_000;
pub const DEVNET_EPOCH: u64 = 2_934;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 24;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 7;
pub const DEFAULT_REBATE_CAP_BPS: u64 = 15;
pub const DEFAULT_MAX_MANIFEST_BYTES: u64 = 8_388_608;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    FullNamespace,
    IncrementalDelta,
    PreUpgradeFence,
    PostUpgradeCheckpoint,
    EmergencyRecovery,
    RedactedAudit,
}

impl SnapshotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullNamespace => "full_namespace",
            Self::IncrementalDelta => "incremental_delta",
            Self::PreUpgradeFence => "pre_upgrade_fence",
            Self::PostUpgradeCheckpoint => "post_upgrade_checkpoint",
            Self::EmergencyRecovery => "emergency_recovery",
            Self::RedactedAudit => "redacted_audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Draft,
    Sealed,
    Attested,
    Fenced,
    Rebated,
    Superseded,
    Quarantined,
    Expired,
}

impl SnapshotStatus {
    pub fn public_live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Attested | Self::Fenced | Self::Rebated
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceRootStatus {
    Active,
    Rotating,
    Frozen,
    RollbackFenced,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FheSlotKind {
    Balance,
    Allowance,
    OrderState,
    RiskVector,
    OracleMemo,
    GovernanceSecret,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ManifestSeal,
    NamespaceRoot,
    FheSlotCommitment,
    RollbackFence,
    LowFeeEligibility,
    RedactionBudget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackFenceStatus {
    Open,
    Armed,
    Triggered,
    Released,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Paid,
    ClawedBack,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_snapshot_manifest_suite: String,
    pub contract_namespace_root_suite: String,
    pub fhe_slot_commitment_suite: String,
    pub pq_snapshot_attestation_suite: String,
    pub rollback_fence_suite: String,
    pub low_fee_snapshot_rebate_suite: String,
    pub redaction_budget_suite: String,
    pub deterministic_root_suite: String,
    pub fee_asset_id: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub snapshot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_redactions_per_epoch: u64,
    pub low_fee_target_bps: u64,
    pub rebate_cap_bps: u64,
    pub max_manifest_bytes: u64,
    pub deterministic_roots_required: bool,
    pub redact_operator_metadata_by_default: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_snapshot_manifest_suite: ENCRYPTED_SNAPSHOT_MANIFEST_SUITE.to_string(),
            contract_namespace_root_suite: CONTRACT_NAMESPACE_ROOT_SUITE.to_string(),
            fhe_slot_commitment_suite: FHE_SLOT_COMMITMENT_SUITE.to_string(),
            pq_snapshot_attestation_suite: PQ_SNAPSHOT_ATTESTATION_SUITE.to_string(),
            rollback_fence_suite: ROLLBACK_FENCE_SUITE.to_string(),
            low_fee_snapshot_rebate_suite: LOW_FEE_SNAPSHOT_REBATE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            deterministic_root_suite: DETERMINISTIC_ROOT_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            snapshot_ttl_blocks: DEFAULT_SNAPSHOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            rebate_cap_bps: DEFAULT_REBATE_CAP_BPS,
            max_manifest_bytes: DEFAULT_MAX_MANIFEST_BYTES,
            deterministic_roots_required: true,
            redact_operator_metadata_by_default: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_private_storage_snapshot_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "encrypted_snapshot_manifest_suite": self.encrypted_snapshot_manifest_suite,
            "contract_namespace_root_suite": self.contract_namespace_root_suite,
            "fhe_slot_commitment_suite": self.fhe_slot_commitment_suite,
            "pq_snapshot_attestation_suite": self.pq_snapshot_attestation_suite,
            "rollback_fence_suite": self.rollback_fence_suite,
            "low_fee_snapshot_rebate_suite": self.low_fee_snapshot_rebate_suite,
            "redaction_budget_suite": self.redaction_budget_suite,
            "deterministic_root_suite": self.deterministic_root_suite,
            "fee_asset_id": self.fee_asset_id,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "snapshot_ttl_blocks": self.snapshot_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "redaction_epoch_blocks": self.redaction_epoch_blocks,
            "max_redactions_per_epoch": self.max_redactions_per_epoch,
            "low_fee_target_bps": self.low_fee_target_bps,
            "rebate_cap_bps": self.rebate_cap_bps,
            "max_manifest_bytes": self.max_manifest_bytes,
            "deterministic_roots_required": self.deterministic_roots_required,
            "redact_operator_metadata_by_default": self.redact_operator_metadata_by_default,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub manifests_sealed: u64,
    pub namespace_roots_registered: u64,
    pub fhe_slots_committed: u64,
    pub pq_attestations_submitted: u64,
    pub rollback_fences_armed: u64,
    pub low_fee_rebates_reserved: u64,
    pub redaction_budgets_allocated: u64,
    pub public_records_emitted: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub manifest_root: String,
    pub namespace_root: String,
    pub fhe_slot_root: String,
    pub pq_attestation_root: String,
    pub rollback_fence_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            manifest_root: empty_root("MANIFEST"),
            namespace_root: empty_root("NAMESPACE"),
            fhe_slot_root: empty_root("FHE-SLOT"),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            rollback_fence_root: empty_root("ROLLBACK-FENCE"),
            low_fee_rebate_root: empty_root("LOW-FEE-REBATE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            counters_root: empty_root("COUNTERS"),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedSnapshotManifest {
    pub manifest_id: String,
    pub snapshot_kind: SnapshotKind,
    pub status: SnapshotStatus,
    pub contract_id: String,
    pub namespace_id: String,
    pub encrypted_manifest_root: String,
    pub ciphertext_index_root: String,
    pub previous_snapshot_root: Option<String>,
    pub deterministic_snapshot_root: String,
    pub manifest_bytes: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub rollback_fence_id: Option<String>,
    pub attestation_ids: BTreeSet<String>,
}

impl EncryptedSnapshotManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_private_storage_snapshot_manifest",
            "manifest_id": self.manifest_id,
            "snapshot_kind": self.snapshot_kind,
            "status": self.status,
            "contract_id": self.contract_id,
            "namespace_id": self.namespace_id,
            "encrypted_manifest_root": self.encrypted_manifest_root,
            "ciphertext_index_root": self.ciphertext_index_root,
            "previous_snapshot_root": self.previous_snapshot_root,
            "deterministic_snapshot_root": self.deterministic_snapshot_root,
            "manifest_bytes": self.manifest_bytes,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "rollback_fence_id": self.rollback_fence_id,
            "attestation_ids": self.attestation_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractNamespaceRoot {
    pub namespace_id: String,
    pub contract_id: String,
    pub status: NamespaceRootStatus,
    pub namespace_label_commitment: String,
    pub storage_root: String,
    pub slot_index_root: String,
    pub policy_root: String,
    pub latest_manifest_id: Option<String>,
    pub root_epoch: u64,
    pub registered_at_height: u64,
}

impl ContractNamespaceRoot {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FheSlotCommitment {
    pub slot_id: String,
    pub namespace_id: String,
    pub slot_kind: FheSlotKind,
    pub ciphertext_commitment: String,
    pub value_commitment_root: String,
    pub access_policy_root: String,
    pub rotation_counter: u64,
    pub committed_at_height: u64,
}

impl FheSlotCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSnapshotAttestation {
    pub attestation_id: String,
    pub manifest_id: String,
    pub attestation_kind: AttestationKind,
    pub status: AttestationStatus,
    pub attestor_commitment: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub evidence_root: String,
    pub attested_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSnapshotAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackFence {
    pub fence_id: String,
    pub manifest_id: String,
    pub namespace_id: String,
    pub status: RollbackFenceStatus,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub rollback_nonce_commitment: String,
    pub armed_at_height: u64,
    pub release_after_height: u64,
}

impl RollbackFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeSnapshotRebate {
    pub rebate_id: String,
    pub manifest_id: String,
    pub operator_commitment: String,
    pub status: RebateStatus,
    pub fee_asset_id: String,
    pub measured_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
    pub reserved_at_height: u64,
}

impl LowFeeSnapshotRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub namespace_id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub redaction_policy_root: String,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub family: String,
    pub commitment: String,
    pub root: String,
    pub height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub manifests: BTreeMap<String, EncryptedSnapshotManifest>,
    pub namespace_roots: BTreeMap<String, ContractNamespaceRoot>,
    pub fhe_slot_commitments: BTreeMap<String, FheSlotCommitment>,
    pub pq_attestations: BTreeMap<String, PqSnapshotAttestation>,
    pub rollback_fences: BTreeMap<String, RollbackFence>,
    pub low_fee_rebates: BTreeMap<String, LowFeeSnapshotRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub fenced_manifests: BTreeSet<String>,
    pub spent_snapshot_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            manifests: BTreeMap::new(),
            namespace_roots: BTreeMap::new(),
            fhe_slot_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rollback_fences: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            fenced_manifests: BTreeSet::new(),
            spent_snapshot_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn register_namespace_root(
        &mut self,
        mut root: ContractNamespaceRoot,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("namespace_id", &root.namespace_id)?;
        required("contract_id", &root.contract_id)?;
        required("storage_root", &root.storage_root)?;
        ensure!(
            !self.namespace_roots.contains_key(&root.namespace_id),
            "namespace root already exists"
        );
        root.registered_at_height = self.height;
        let namespace_id = root.namespace_id.clone();
        self.namespace_roots.insert(namespace_id.clone(), root);
        self.counters.namespace_roots_registered += 1;
        self.emit_public_record("namespace_root", &namespace_id);
        self.refresh_roots();
        Ok(namespace_id)
    }

    pub fn seal_manifest(
        &mut self,
        request: SealSnapshotManifestRequest,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("contract_id", &request.contract_id)?;
        required("namespace_id", &request.namespace_id)?;
        required("encrypted_manifest_root", &request.encrypted_manifest_root)?;
        required("ciphertext_index_root", &request.ciphertext_index_root)?;
        ensure!(
            self.namespace_roots.contains_key(&request.namespace_id),
            "unknown namespace root"
        );
        ensure!(
            request.manifest_bytes <= self.config.max_manifest_bytes,
            "manifest exceeds max bytes"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits too low"
        );
        let sequence = self.counters.manifests_sealed + 1;
        let manifest_id = deterministic_id("SNAPSHOT-MANIFEST-ID", sequence, &json!(request));
        let deterministic_snapshot_root = deterministic_record_root(
            "PRIVATE-STORAGE-SNAPSHOT-MANIFEST-ROOT",
            &json!({
                "manifest_id": manifest_id,
                "request": request,
                "height": self.height,
                "epoch": self.epoch,
            }),
        );
        let manifest = EncryptedSnapshotManifest {
            manifest_id: manifest_id.clone(),
            snapshot_kind: request.snapshot_kind,
            status: SnapshotStatus::Sealed,
            contract_id: request.contract_id,
            namespace_id: request.namespace_id.clone(),
            encrypted_manifest_root: request.encrypted_manifest_root,
            ciphertext_index_root: request.ciphertext_index_root,
            previous_snapshot_root: request.previous_snapshot_root,
            deterministic_snapshot_root,
            manifest_bytes: request.manifest_bytes,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            sealed_at_height: self.height,
            expires_at_height: self.height + self.config.snapshot_ttl_blocks,
            rollback_fence_id: None,
            attestation_ids: BTreeSet::new(),
        };
        if let Some(namespace) = self.namespace_roots.get_mut(&request.namespace_id) {
            namespace.latest_manifest_id = Some(manifest_id.clone());
        }
        self.manifests.insert(manifest_id.clone(), manifest);
        self.counters.manifests_sealed += 1;
        self.emit_public_record("manifest", &manifest_id);
        self.refresh_roots();
        Ok(manifest_id)
    }

    pub fn commit_fhe_slot(
        &mut self,
        request: CommitFheSlotRequest,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("namespace_id", &request.namespace_id)?;
        required("ciphertext_commitment", &request.ciphertext_commitment)?;
        ensure!(
            self.namespace_roots.contains_key(&request.namespace_id),
            "unknown namespace root"
        );
        let sequence = self.counters.fhe_slots_committed + 1;
        let slot_id = deterministic_id("FHE-SLOT-COMMITMENT-ID", sequence, &json!(request));
        let record = FheSlotCommitment {
            slot_id: slot_id.clone(),
            namespace_id: request.namespace_id,
            slot_kind: request.slot_kind,
            ciphertext_commitment: request.ciphertext_commitment,
            value_commitment_root: request.value_commitment_root,
            access_policy_root: request.access_policy_root,
            rotation_counter: request.rotation_counter,
            committed_at_height: self.height,
        };
        self.fhe_slot_commitments.insert(slot_id.clone(), record);
        self.counters.fhe_slots_committed += 1;
        self.emit_public_record("fhe_slot_commitment", &slot_id);
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn submit_pq_attestation(
        &mut self,
        request: SubmitPqSnapshotAttestationRequest,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("manifest_id", &request.manifest_id)?;
        required("attestor_commitment", &request.attestor_commitment)?;
        required("signature_root", &request.signature_root)?;
        ensure!(
            self.manifests.contains_key(&request.manifest_id),
            "unknown manifest"
        );
        let sequence = self.counters.pq_attestations_submitted + 1;
        let attestation_id =
            deterministic_id("PQ-SNAPSHOT-ATTESTATION-ID", sequence, &json!(request));
        let record = PqSnapshotAttestation {
            attestation_id: attestation_id.clone(),
            manifest_id: request.manifest_id.clone(),
            attestation_kind: request.attestation_kind,
            status: AttestationStatus::Accepted,
            attestor_commitment: request.attestor_commitment,
            public_key_commitment: request.public_key_commitment,
            signature_root: request.signature_root,
            evidence_root: request.evidence_root,
            attested_root: request.attested_root,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.attestation_ttl_blocks,
        };
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest.status = SnapshotStatus::Attested;
            manifest.attestation_ids.insert(attestation_id.clone());
        }
        self.pq_attestations.insert(attestation_id.clone(), record);
        self.counters.pq_attestations_submitted += 1;
        self.emit_public_record("pq_snapshot_attestation", &attestation_id);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn arm_rollback_fence(
        &mut self,
        request: ArmRollbackFenceRequest,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("manifest_id", &request.manifest_id)?;
        required("namespace_id", &request.namespace_id)?;
        ensure!(
            self.manifests.contains_key(&request.manifest_id),
            "unknown manifest"
        );
        let sequence = self.counters.rollback_fences_armed + 1;
        let fence_id = deterministic_id("ROLLBACK-FENCE-ID", sequence, &json!(request));
        let record = RollbackFence {
            fence_id: fence_id.clone(),
            manifest_id: request.manifest_id.clone(),
            namespace_id: request.namespace_id,
            status: RollbackFenceStatus::Armed,
            pre_state_root: request.pre_state_root,
            post_state_root: request.post_state_root,
            rollback_nonce_commitment: request.rollback_nonce_commitment,
            armed_at_height: self.height,
            release_after_height: self.height + request.release_delay_blocks,
        };
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest.status = SnapshotStatus::Fenced;
            manifest.rollback_fence_id = Some(fence_id.clone());
        }
        self.fenced_manifests.insert(request.manifest_id);
        self.rollback_fences.insert(fence_id.clone(), record);
        self.counters.rollback_fences_armed += 1;
        self.emit_public_record("rollback_fence", &fence_id);
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn reserve_low_fee_rebate(
        &mut self,
        request: ReserveLowFeeSnapshotRebateRequest,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("manifest_id", &request.manifest_id)?;
        ensure!(
            self.manifests.contains_key(&request.manifest_id),
            "unknown manifest"
        );
        ensure!(request.measured_fee_bps <= MAX_BPS, "fee bps out of range");
        ensure!(
            request.rebate_bps <= self.config.rebate_cap_bps,
            "rebate exceeds cap"
        );
        let sequence = self.counters.low_fee_rebates_reserved + 1;
        let rebate_id = deterministic_id("LOW-FEE-SNAPSHOT-REBATE-ID", sequence, &json!(request));
        let record = LowFeeSnapshotRebate {
            rebate_id: rebate_id.clone(),
            manifest_id: request.manifest_id.clone(),
            operator_commitment: request.operator_commitment,
            status: RebateStatus::Reserved,
            fee_asset_id: self.config.fee_asset_id.clone(),
            measured_fee_bps: request.measured_fee_bps,
            rebate_bps: request.rebate_bps,
            rebate_micro_units: request.rebate_micro_units,
            reserved_at_height: self.height,
        };
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest.status = SnapshotStatus::Rebated;
        }
        self.low_fee_rebates.insert(rebate_id.clone(), record);
        self.counters.low_fee_rebates_reserved += 1;
        self.emit_public_record("low_fee_snapshot_rebate", &rebate_id);
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: AllocateRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<String> {
        required("namespace_id", &request.namespace_id)?;
        ensure!(
            request.max_redactions <= self.config.max_redactions_per_epoch,
            "redaction budget exceeds epoch cap"
        );
        let sequence = self.counters.redaction_budgets_allocated + 1;
        let budget_id = deterministic_id("REDACTION-BUDGET-ID", sequence, &json!(request));
        let record = RedactionBudget {
            budget_id: budget_id.clone(),
            namespace_id: request.namespace_id,
            operator_commitment: request.operator_commitment,
            epoch: request.epoch,
            max_redactions: request.max_redactions,
            used_redactions: 0,
            redaction_policy_root: request.redaction_policy_root,
        };
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.counters.redaction_budgets_allocated += 1;
        self.emit_public_record("redaction_budget", &budget_id);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_private_storage_snapshot_runtime_state",
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "live_manifest_count": self.manifests.values().filter(|record| record.status.public_live()).count(),
            "namespace_root_count": self.namespace_roots.len(),
            "fhe_slot_commitment_count": self.fhe_slot_commitments.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "rollback_fence_count": self.rollback_fences.len(),
            "low_fee_rebate_count": self.low_fee_rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "public_records": self.public_records.values().map(DeterministicPublicRecord::public_record).collect::<Vec<_>>(),
            "fenced_manifests": self.fenced_manifests,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "config_root": self.roots.config_root,
            "manifest_root": self.roots.manifest_root,
            "namespace_root": self.roots.namespace_root,
            "fhe_slot_root": self.roots.fhe_slot_root,
            "pq_attestation_root": self.roots.pq_attestation_root,
            "rollback_fence_root": self.roots.rollback_fence_root,
            "low_fee_rebate_root": self.roots.low_fee_rebate_root,
            "redaction_budget_root": self.roots.redaction_budget_root,
            "public_record_root": self.roots.public_record_root,
            "counters_root": self.roots.counters_root,
            "height": self.height,
            "epoch": self.epoch,
        }))
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = deterministic_record_root(
            "PRIVATE-STORAGE-SNAPSHOT-CONFIG",
            &self.config.public_record(),
        );
        self.roots.manifest_root = public_record_root(
            "MANIFEST",
            &values_record(&self.manifests, EncryptedSnapshotManifest::public_record),
        );
        self.roots.namespace_root = public_record_root(
            "NAMESPACE-ROOT",
            &values_record(&self.namespace_roots, ContractNamespaceRoot::public_record),
        );
        self.roots.fhe_slot_root = public_record_root(
            "FHE-SLOT",
            &values_record(&self.fhe_slot_commitments, FheSlotCommitment::public_record),
        );
        self.roots.pq_attestation_root = public_record_root(
            "PQ-ATTESTATION",
            &values_record(&self.pq_attestations, PqSnapshotAttestation::public_record),
        );
        self.roots.rollback_fence_root = public_record_root(
            "ROLLBACK-FENCE",
            &values_record(&self.rollback_fences, RollbackFence::public_record),
        );
        self.roots.low_fee_rebate_root = public_record_root(
            "LOW-FEE-REBATE",
            &values_record(&self.low_fee_rebates, LowFeeSnapshotRebate::public_record),
        );
        self.roots.redaction_budget_root = public_record_root(
            "REDACTION-BUDGET",
            &values_record(&self.redaction_budgets, RedactionBudget::public_record),
        );
        self.roots.public_record_root = public_record_root(
            "PUBLIC-RECORD",
            &values_record(
                &self.public_records,
                DeterministicPublicRecord::public_record,
            ),
        );
        self.roots.counters_root = deterministic_record_root(
            "PRIVATE-STORAGE-SNAPSHOT-COUNTERS",
            &self.counters.public_record(),
        );
        self.roots.state_root = self.state_root();
    }

    fn emit_public_record(&mut self, family: &str, commitment: &str) {
        let record_root = deterministic_record_root(
            "PRIVATE-STORAGE-SNAPSHOT-PUBLIC-RECORD-COMMITMENT",
            &json!({
                "family": family,
                "commitment": commitment,
                "height": self.height,
                "epoch": self.epoch,
            }),
        );
        let sequence = self.counters.public_records_emitted + 1;
        let record_id = deterministic_id(
            "DETERMINISTIC-PUBLIC-RECORD-ID",
            sequence,
            &json!({
                "family": family,
                "commitment": commitment,
                "root": record_root,
            }),
        );
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                family: family.to_string(),
                commitment: commitment.to_string(),
                root: record_root,
                height: self.height,
            },
        );
        self.counters.public_records_emitted += 1;
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealSnapshotManifestRequest {
    pub snapshot_kind: SnapshotKind,
    pub contract_id: String,
    pub namespace_id: String,
    pub encrypted_manifest_root: String,
    pub ciphertext_index_root: String,
    pub previous_snapshot_root: Option<String>,
    pub manifest_bytes: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitFheSlotRequest {
    pub namespace_id: String,
    pub slot_kind: FheSlotKind,
    pub ciphertext_commitment: String,
    pub value_commitment_root: String,
    pub access_policy_root: String,
    pub rotation_counter: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPqSnapshotAttestationRequest {
    pub manifest_id: String,
    pub attestation_kind: AttestationKind,
    pub attestor_commitment: String,
    pub public_key_commitment: String,
    pub signature_root: String,
    pub evidence_root: String,
    pub attested_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArmRollbackFenceRequest {
    pub manifest_id: String,
    pub namespace_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub rollback_nonce_commitment: String,
    pub release_delay_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLowFeeSnapshotRebateRequest {
    pub manifest_id: String,
    pub operator_commitment: String,
    pub measured_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllocateRedactionBudgetRequest {
    pub namespace_id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub max_redactions: u64,
    pub redaction_policy_root: String,
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH);
    let namespace_id = deterministic_id(
        "DEVNET-NAMESPACE-ID",
        1,
        &json!({
            "label": "private-vault-storage",
            "contract": "contract:commitment:devnet-private-vault",
        }),
    );
    state
        .register_namespace_root(ContractNamespaceRoot {
            namespace_id: namespace_id.clone(),
            contract_id: "contract:commitment:devnet-private-vault".to_string(),
            status: NamespaceRootStatus::Active,
            namespace_label_commitment: "commitment:namespace:private-vault-storage".to_string(),
            storage_root: "root:storage:private-vault:sealed".to_string(),
            slot_index_root: "root:slot-index:private-vault:fhe".to_string(),
            policy_root: "root:policy:private-vault:redacted-read".to_string(),
            latest_manifest_id: None,
            root_epoch: DEVNET_EPOCH,
            registered_at_height: DEVNET_HEIGHT,
        })
        .expect("generated devnet namespace root");
    let manifest_id = state
        .seal_manifest(SealSnapshotManifestRequest {
            snapshot_kind: SnapshotKind::FullNamespace,
            contract_id: "contract:commitment:devnet-private-vault".to_string(),
            namespace_id: namespace_id.clone(),
            encrypted_manifest_root: "root:encrypted-manifest:devnet-private-vault".to_string(),
            ciphertext_index_root: "root:ciphertext-index:devnet-private-vault".to_string(),
            previous_snapshot_root: None,
            manifest_bytes: 524_288,
            privacy_set_size: 131_072,
            pq_security_bits: 256,
        })
        .expect("generated devnet manifest");
    state
        .commit_fhe_slot(CommitFheSlotRequest {
            namespace_id: namespace_id.clone(),
            slot_kind: FheSlotKind::Balance,
            ciphertext_commitment: "commitment:fhe-slot:balance:vault".to_string(),
            value_commitment_root: "root:value-commitment:balance:vault".to_string(),
            access_policy_root: "root:access-policy:balance:vault".to_string(),
            rotation_counter: 1,
        })
        .expect("generated devnet fhe slot");
    state
        .submit_pq_attestation(SubmitPqSnapshotAttestationRequest {
            manifest_id: manifest_id.clone(),
            attestation_kind: AttestationKind::ManifestSeal,
            attestor_commitment: "commitment:attestor:ml-dsa-87:devnet".to_string(),
            public_key_commitment: "commitment:pq-public-key:attestor:devnet".to_string(),
            signature_root: "root:pq-signature:manifest-seal:devnet".to_string(),
            evidence_root: "root:evidence:snapshot-manifest:devnet".to_string(),
            attested_root: "root:encrypted-manifest:devnet-private-vault".to_string(),
        })
        .expect("generated devnet attestation");
    state
        .allocate_redaction_budget(AllocateRedactionBudgetRequest {
            namespace_id: namespace_id.clone(),
            operator_commitment: "commitment:operator:snapshot-redactor:devnet".to_string(),
            epoch: DEVNET_EPOCH,
            max_redactions: 8,
            redaction_policy_root: "root:redaction-policy:snapshot-public-records".to_string(),
        })
        .expect("generated devnet redaction budget");
    state
        .arm_rollback_fence(ArmRollbackFenceRequest {
            manifest_id: manifest_id.clone(),
            namespace_id,
            pre_state_root: "root:state:pre-snapshot:devnet".to_string(),
            post_state_root: "root:state:post-snapshot:devnet".to_string(),
            rollback_nonce_commitment: "commitment:rollback-nonce:devnet".to_string(),
            release_delay_blocks: 720,
        })
        .expect("generated devnet rollback fence");
    state
        .reserve_low_fee_rebate(ReserveLowFeeSnapshotRebateRequest {
            manifest_id,
            operator_commitment: "commitment:operator:snapshotter:devnet".to_string(),
            measured_fee_bps: 5,
            rebate_bps: 7,
            rebate_micro_units: 18_000,
        })
        .expect("generated devnet snapshot rebate");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let namespace_id = deterministic_id(
        "DEMO-NAMESPACE-ID",
        1,
        &json!({
            "label": "sealed-orderbook-storage",
            "contract": "contract:commitment:demo-orderbook",
        }),
    );
    state
        .register_namespace_root(ContractNamespaceRoot {
            namespace_id: namespace_id.clone(),
            contract_id: "contract:commitment:demo-orderbook".to_string(),
            status: NamespaceRootStatus::Rotating,
            namespace_label_commitment: "commitment:namespace:sealed-orderbook-storage".to_string(),
            storage_root: "root:storage:demo-orderbook:before-upgrade".to_string(),
            slot_index_root: "root:slot-index:demo-orderbook:fhe".to_string(),
            policy_root: "root:policy:demo-orderbook:maker-taker-redaction".to_string(),
            latest_manifest_id: None,
            root_epoch: DEVNET_EPOCH + 1,
            registered_at_height: DEVNET_HEIGHT + 16,
        })
        .expect("generated demo namespace root");
    let manifest_id = state
        .seal_manifest(SealSnapshotManifestRequest {
            snapshot_kind: SnapshotKind::PreUpgradeFence,
            contract_id: "contract:commitment:demo-orderbook".to_string(),
            namespace_id: namespace_id.clone(),
            encrypted_manifest_root: "root:encrypted-manifest:demo-orderbook:pre-upgrade"
                .to_string(),
            ciphertext_index_root: "root:ciphertext-index:demo-orderbook:pre-upgrade".to_string(),
            previous_snapshot_root: Some("root:snapshot:demo-orderbook:last".to_string()),
            manifest_bytes: 262_144,
            privacy_set_size: 262_144,
            pq_security_bits: 256,
        })
        .expect("generated demo manifest");
    state
        .commit_fhe_slot(CommitFheSlotRequest {
            namespace_id,
            slot_kind: FheSlotKind::OrderState,
            ciphertext_commitment: "commitment:fhe-slot:sealed-order-state".to_string(),
            value_commitment_root: "root:value-commitment:sealed-order-state".to_string(),
            access_policy_root: "root:access-policy:sealed-order-state".to_string(),
            rotation_counter: 3,
        })
        .expect("generated demo fhe slot");
    state
        .submit_pq_attestation(SubmitPqSnapshotAttestationRequest {
            manifest_id,
            attestation_kind: AttestationKind::RollbackFence,
            attestor_commitment: "commitment:attestor:upgrade-watchtower:demo".to_string(),
            public_key_commitment: "commitment:pq-public-key:upgrade-watchtower:demo".to_string(),
            signature_root: "root:pq-signature:rollback-fence:demo".to_string(),
            evidence_root: "root:evidence:rollback-fence:demo".to_string(),
            attested_root: "root:encrypted-manifest:demo-orderbook:pre-upgrade".to_string(),
        })
        .expect("generated demo attestation");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(kind: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-SNAPSHOT:{kind}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-SNAPSHOT:{domain}-ROOT"),
        records,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-SNAPSHOT:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(public_record).collect()
}

fn required(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractPrivateStorageSnapshotRuntimeResult<()> {
    ensure!(!value.trim().is_empty(), "{field} is required");
    Ok(())
}
