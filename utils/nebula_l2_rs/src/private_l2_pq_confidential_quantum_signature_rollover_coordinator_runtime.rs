use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialQuantumSignatureRolloverCoordinatorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_SIGNATURE_ROLLOVER_COORDINATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-quantum-signature-rollover-coordinator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_QUANTUM_SIGNATURE_ROLLOVER_COORDINATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "deterministic-fnv1a128-canonical-json-v1";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f+XMSS-MT-rollover-v1";
pub const HYBRID_SIGNATURE_SUITE: &str =
    "Ed25519+secp256k1+BLS12-381-to-ML-DSA-87-hybrid-cutover-v1";
pub const LEGACY_QUARANTINE_SCHEME: &str = "legacy-signature-quarantine-nullifier-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "pq-rollover-watchtower-attestation-root-v1";
pub const BRIDGE_CUTOVER_SCHEME: &str = "confidential-bridge-signing-key-cutover-v1";
pub const PRIVACY_AUDIT_SCHEME: &str = "privacy-preserving-rollover-audit-summary-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-pq-rollover-rotation-proof-batch-v1";
pub const EMERGENCY_PAUSE_SCHEME: &str = "quantum-rollover-emergency-pause-v1";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_ROLLOVER_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SESSION_GRACE_BLOCKS: u64 = 192;
pub const DEFAULT_CONTRACT_GRACE_BLOCKS: u64 = 720;
pub const DEFAULT_BRIDGE_CUTOVER_DELAY_BLOCKS: u64 = 360;
pub const DEFAULT_LEGACY_QUARANTINE_BLOCKS: u64 = 4_320;
pub const DEFAULT_EMERGENCY_REVIEW_BLOCKS: u64 = 96;
pub const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 256;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MULTISIG_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_BRIDGE_QUORUM_BPS: u64 = 7_500;
pub const MAX_ROLLOVER_EPOCHS: usize = 262_144;
pub const MAX_ACCOUNTS: usize = 1_048_576;
pub const MAX_SESSIONS: usize = 2_097_152;
pub const MAX_CONTRACTS: usize = 1_048_576;
pub const MAX_MULTISIG_GROUPS: usize = 524_288;
pub const MAX_BRIDGE_KEYS: usize = 262_144;
pub const MAX_WATCHERS: usize = 524_288;
pub const MAX_ROLLOVER_REQUESTS: usize = 4_194_304;
pub const MAX_ROTATION_PROOFS: usize = 4_194_304;
pub const MAX_QUARANTINE_RECORDS: usize = 2_097_152;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_AUDIT_SUMMARIES: usize = 524_288;
pub const MAX_PAUSE_RECORDS: usize = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDomain {
    AccountSpend,
    AccountView,
    SessionAuth,
    ContractAdmin,
    ContractExecution,
    MultisigSigner,
    BridgeSigning,
    WatcherAttestation,
}

impl KeyDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountSpend => "account_spend",
            Self::AccountView => "account_view",
            Self::SessionAuth => "session_auth",
            Self::ContractAdmin => "contract_admin",
            Self::ContractExecution => "contract_execution",
            Self::MultisigSigner => "multisig_signer",
            Self::BridgeSigning => "bridge_signing",
            Self::WatcherAttestation => "watcher_attestation",
        }
    }

    pub fn grace_blocks(self, config: &Config) -> u64 {
        match self {
            Self::SessionAuth => config.session_grace_blocks,
            Self::ContractAdmin | Self::ContractExecution => config.contract_grace_blocks,
            Self::BridgeSigning => config.bridge_cutover_delay_blocks,
            _ => config.rollover_ttl_blocks,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    Ed25519,
    Secp256k1,
    Bls12381,
    MoneroSpendKey,
    MlDsa65,
    MlDsa87,
    SlhDsaShake192f,
    SlhDsaShake256f,
    XmssMtShake256,
    HybridEd25519MlDsa87,
    HybridSecp256k1MlDsa87,
    HybridBlsMlDsa87,
    HybridMoneroSpendMlDsa87,
}

impl SignatureAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Secp256k1 => "secp256k1",
            Self::Bls12381 => "bls12_381",
            Self::MoneroSpendKey => "monero_spend_key",
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake192f => "slh_dsa_shake_192f",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::XmssMtShake256 => "xmss_mt_shake_256",
            Self::HybridEd25519MlDsa87 => "hybrid_ed25519_ml_dsa_87",
            Self::HybridSecp256k1MlDsa87 => "hybrid_secp256k1_ml_dsa_87",
            Self::HybridBlsMlDsa87 => "hybrid_bls_ml_dsa_87",
            Self::HybridMoneroSpendMlDsa87 => "hybrid_monero_spend_ml_dsa_87",
        }
    }

    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 | Self::SlhDsaShake192f => 192,
            Self::MlDsa87
            | Self::SlhDsaShake256f
            | Self::XmssMtShake256
            | Self::HybridEd25519MlDsa87
            | Self::HybridSecp256k1MlDsa87
            | Self::HybridBlsMlDsa87
            | Self::HybridMoneroSpendMlDsa87 => 256,
            Self::Ed25519 | Self::Secp256k1 | Self::Bls12381 | Self::MoneroSpendKey => 0,
        }
    }

    pub fn is_legacy(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::Secp256k1 | Self::Bls12381 | Self::MoneroSpendKey
        )
    }

    pub fn is_pq_or_hybrid(self) -> bool {
        self.pq_security_bits() > 0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloverStage {
    Announced,
    Inventory,
    DualSignature,
    PqPreferred,
    LegacyQuarantine,
    PqEnforced,
    Finalized,
    Revoked,
}

impl RolloverStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Inventory => "inventory",
            Self::DualSignature => "dual_signature",
            Self::PqPreferred => "pq_preferred",
            Self::LegacyQuarantine => "legacy_quarantine",
            Self::PqEnforced => "pq_enforced",
            Self::Finalized => "finalized",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_new_requests(self) -> bool {
        matches!(
            self,
            Self::Inventory | Self::DualSignature | Self::PqPreferred
        )
    }

    pub fn enforces_quarantine(self) -> bool {
        matches!(
            self,
            Self::LegacyQuarantine | Self::PqEnforced | Self::Finalized
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStatus {
    Pending,
    ProofRecorded,
    WatcherAttested,
    Batched,
    CutoverReady,
    Activated,
    Quarantined,
    Rejected,
    Expired,
}

impl MigrationStatus {
    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::ProofRecorded | Self::WatcherAttested | Self::CutoverReady
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Activated | Self::Quarantined | Self::Rejected | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MultisigStatus {
    Registered,
    RolloverOpen,
    ThresholdMet,
    Activated,
    Frozen,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeCutoverStatus {
    Proposed,
    WatcherAttested,
    DelayWindow,
    Ready,
    Active,
    Cancelled,
    EmergencyFrozen,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    LegacyAfterDeadline,
    WeakPqSecurity,
    MissingDualSignature,
    ReplayFenceHit,
    WatcherVeto,
    BridgeCutoverMismatch,
    EmergencyPause,
    PolicyViolation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PauseScope {
    Global,
    Accounts,
    Sessions,
    Contracts,
    Multisig,
    Bridge,
    Watchers,
    Batching,
}

impl PauseScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Accounts => "accounts",
            Self::Sessions => "sessions",
            Self::Contracts => "contracts",
            Self::Multisig => "multisig",
            Self::Bridge => "bridge",
            Self::Watchers => "watchers",
            Self::Batching => "batching",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditBucket {
    Accounts,
    Sessions,
    Contracts,
    Multisig,
    Bridge,
    LegacyQuarantine,
    WatcherCoverage,
    LowFeeBatches,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub coordinator_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub rollover_ttl_blocks: u64,
    pub session_grace_blocks: u64,
    pub contract_grace_blocks: u64,
    pub bridge_cutover_delay_blocks: u64,
    pub legacy_quarantine_blocks: u64,
    pub emergency_review_blocks: u64,
    pub low_fee_batch_target: usize,
    pub low_fee_batch_limit: usize,
    pub watcher_quorum_bps: u64,
    pub multisig_quorum_bps: u64,
    pub bridge_quorum_bps: u64,
    pub allow_hybrid_intermediate: bool,
    pub require_watcher_attestation: bool,
    pub require_privacy_summary: bool,
    pub quarantine_legacy_signatures: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: "nebula-devnet".to_string(),
            coordinator_id: "pq-rollover-coordinator-devnet".to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            rollover_ttl_blocks: DEFAULT_ROLLOVER_TTL_BLOCKS,
            session_grace_blocks: DEFAULT_SESSION_GRACE_BLOCKS,
            contract_grace_blocks: DEFAULT_CONTRACT_GRACE_BLOCKS,
            bridge_cutover_delay_blocks: DEFAULT_BRIDGE_CUTOVER_DELAY_BLOCKS,
            legacy_quarantine_blocks: DEFAULT_LEGACY_QUARANTINE_BLOCKS,
            emergency_review_blocks: DEFAULT_EMERGENCY_REVIEW_BLOCKS,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            multisig_quorum_bps: DEFAULT_MULTISIG_QUORUM_BPS,
            bridge_quorum_bps: DEFAULT_BRIDGE_QUORUM_BPS,
            allow_hybrid_intermediate: true,
            require_watcher_attestation: true,
            require_privacy_summary: true,
            quarantine_legacy_signatures: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub epochs_opened: u64,
    pub epochs_finalized: u64,
    pub accounts_registered: u64,
    pub sessions_registered: u64,
    pub contracts_registered: u64,
    pub multisig_groups_registered: u64,
    pub bridge_keys_registered: u64,
    pub watchers_registered: u64,
    pub rollover_requests: u64,
    pub proofs_recorded: u64,
    pub watcher_attestations: u64,
    pub multisig_approvals: u64,
    pub bridge_cutovers: u64,
    pub legacy_quarantines: u64,
    pub emergency_pauses: u64,
    pub emergency_resumes: u64,
    pub batches_opened: u64,
    pub batches_sealed: u64,
    pub audit_summaries: u64,
    pub rejected_operations: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub epoch_root: String,
    pub inventory_root: String,
    pub request_root: String,
    pub proof_root: String,
    pub watcher_root: String,
    pub multisig_root: String,
    pub bridge_root: String,
    pub quarantine_root: String,
    pub batch_root: String,
    pub audit_root: String,
    pub pause_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RolloverEpoch {
    pub epoch_id: String,
    pub stage: RolloverStage,
    pub start_height: u64,
    pub dual_signature_height: u64,
    pub pq_preferred_height: u64,
    pub quarantine_height: u64,
    pub enforce_height: u64,
    pub expires_height: u64,
    pub target_algorithms: BTreeSet<SignatureAlgorithm>,
    pub target_domains: BTreeSet<KeyDomain>,
    pub privacy_floor: u64,
    pub watcher_quorum_bps: u64,
    pub memo_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyInventoryRecord {
    pub record_id: String,
    pub owner_commitment: String,
    pub domain: KeyDomain,
    pub legacy_algorithm: SignatureAlgorithm,
    pub current_algorithm: SignatureAlgorithm,
    pub pq_key_commitment: String,
    pub migration_epoch: String,
    pub registered_height: u64,
    pub grace_expires_height: u64,
    pub status: MigrationStatus,
    pub privacy_set_size: u64,
    pub nullifier_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RolloverRequest {
    pub request_id: String,
    pub epoch_id: String,
    pub inventory_id: String,
    pub domain: KeyDomain,
    pub from_algorithm: SignatureAlgorithm,
    pub to_algorithm: SignatureAlgorithm,
    pub requester_commitment: String,
    pub old_key_commitment: String,
    pub new_key_commitment: String,
    pub dual_signature_commitment: String,
    pub privacy_proof_commitment: String,
    pub requested_height: u64,
    pub deadline_height: u64,
    pub fee_limit_microunits: u64,
    pub status: MigrationStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RotationProofRecord {
    pub proof_id: String,
    pub request_id: String,
    pub epoch_id: String,
    pub proof_commitment: String,
    pub nullifier: String,
    pub old_signature_digest: String,
    pub pq_signature_digest: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub recorded_height: u64,
    pub accepted: bool,
    pub batch_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherRecord {
    pub watcher_id: String,
    pub operator_commitment: String,
    pub attestation_key_commitment: String,
    pub stake_commitment: String,
    pub weight_bps: u64,
    pub active: bool,
    pub last_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherAttestationRecord {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_id: String,
    pub epoch_id: String,
    pub statement_root: String,
    pub signature_digest: String,
    pub weight_bps: u64,
    pub height: u64,
    pub veto: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultisigGroupRecord {
    pub group_id: String,
    pub policy_commitment: String,
    pub epoch_id: String,
    pub threshold_bps: u64,
    pub signer_count: u32,
    pub migrated_signers: BTreeSet<String>,
    pub pending_signers: BTreeSet<String>,
    pub status: MultisigStatus,
    pub activated_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MultisigApprovalRecord {
    pub approval_id: String,
    pub group_id: String,
    pub signer_commitment: String,
    pub old_key_commitment: String,
    pub new_pq_key_commitment: String,
    pub proof_id: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeSigningKeyRecord {
    pub bridge_id: String,
    pub lane_id: String,
    pub old_key_commitment: String,
    pub new_pq_key_commitment: String,
    pub cutover_epoch: String,
    pub proposed_height: u64,
    pub ready_height: u64,
    pub active_height: u64,
    pub watcher_weight_bps: u64,
    pub status: BridgeCutoverStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LegacyQuarantineRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub domain: KeyDomain,
    pub algorithm: SignatureAlgorithm,
    pub reason: QuarantineReason,
    pub signature_digest: String,
    pub quarantined_height: u64,
    pub release_height: u64,
    pub watcher_attestation_root: String,
    pub sealed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBatchRecord {
    pub batch_id: String,
    pub epoch_id: String,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub proof_ids: BTreeSet<String>,
    pub aggregated_proof_commitment: String,
    pub fee_microunits: u64,
    pub privacy_set_size: u64,
    pub sealed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmergencyPauseRecord {
    pub pause_id: String,
    pub scope: PauseScope,
    pub reason_commitment: String,
    pub asserted_by: String,
    pub start_height: u64,
    pub review_height: u64,
    pub resume_height: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditSummaryRecord {
    pub summary_id: String,
    pub epoch_id: String,
    pub bucket: AuditBucket,
    pub range_start_height: u64,
    pub range_end_height: u64,
    pub subject_count_commitment: String,
    pub success_count_commitment: String,
    pub quarantine_count_commitment: String,
    pub watcher_coverage_bps: u64,
    pub privacy_set_floor: u64,
    pub summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub active_epoch: Option<String>,
    pub paused_scopes: BTreeSet<PauseScope>,
    pub rollover_epochs: BTreeMap<String, RolloverEpoch>,
    pub inventories: BTreeMap<String, KeyInventoryRecord>,
    pub requests: BTreeMap<String, RolloverRequest>,
    pub proofs: BTreeMap<String, RotationProofRecord>,
    pub replay_fences: BTreeSet<String>,
    pub watchers: BTreeMap<String, WatcherRecord>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestationRecord>,
    pub watcher_subject_index: BTreeMap<String, BTreeSet<String>>,
    pub multisig_groups: BTreeMap<String, MultisigGroupRecord>,
    pub multisig_approvals: BTreeMap<String, MultisigApprovalRecord>,
    pub bridge_keys: BTreeMap<String, BridgeSigningKeyRecord>,
    pub quarantines: BTreeMap<String, LegacyQuarantineRecord>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatchRecord>,
    pub pending_batch_queue: VecDeque<String>,
    pub emergency_pauses: BTreeMap<String, EmergencyPauseRecord>,
    pub audit_summaries: BTreeMap<String, AuditSummaryRecord>,
    pub event_log: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT)
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            current_height,
            active_epoch: None,
            paused_scopes: BTreeSet::new(),
            rollover_epochs: BTreeMap::new(),
            inventories: BTreeMap::new(),
            requests: BTreeMap::new(),
            proofs: BTreeMap::new(),
            replay_fences: BTreeSet::new(),
            watchers: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            watcher_subject_index: BTreeMap::new(),
            multisig_groups: BTreeMap::new(),
            multisig_approvals: BTreeMap::new(),
            bridge_keys: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            pending_batch_queue: VecDeque::new(),
            emergency_pauses: BTreeMap::new(),
            audit_summaries: BTreeMap::new(),
            event_log: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn open_epoch(&mut self, mut epoch: RolloverEpoch) -> Result<String> {
        self.ensure_not_paused(PauseScope::Global)?;
        self.ensure_capacity(
            self.rollover_epochs.len(),
            MAX_ROLLOVER_EPOCHS,
            "rollover epochs",
        )?;
        if self.rollover_epochs.contains_key(&epoch.epoch_id) {
            self.reject("duplicate epoch id")?;
        }
        if epoch.expires_height <= epoch.start_height {
            self.reject("epoch expiry must be after start height")?;
        }
        if epoch.privacy_floor < self.config.min_privacy_set_size {
            epoch.privacy_floor = self.config.min_privacy_set_size;
        }
        epoch.stage = RolloverStage::Announced;
        let epoch_id = epoch.epoch_id.clone();
        self.rollover_epochs.insert(epoch_id.clone(), epoch);
        self.active_epoch = Some(epoch_id.clone());
        self.counters.epochs_opened = self.counters.epochs_opened.saturating_add(1);
        self.event("epoch_opened", &epoch_id);
        self.refresh_roots();
        Ok(epoch_id)
    }

    pub fn advance_epoch_stage(&mut self, epoch_id: &str, stage: RolloverStage) -> Result<()> {
        self.ensure_not_paused(PauseScope::Global)?;
        let epoch = self
            .rollover_epochs
            .get_mut(epoch_id)
            .ok_or_else(|| "unknown rollover epoch".to_string())?;
        if epoch.stage == RolloverStage::Revoked || epoch.stage == RolloverStage::Finalized {
            self.reject("terminal epoch cannot advance")?;
        }
        epoch.stage = stage;
        if stage == RolloverStage::Finalized {
            self.counters.epochs_finalized = self.counters.epochs_finalized.saturating_add(1);
        }
        self.event("epoch_stage_advanced", epoch_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn register_inventory(&mut self, mut record: KeyInventoryRecord) -> Result<String> {
        self.ensure_domain_not_paused(record.domain)?;
        self.ensure_inventory_capacity(record.domain)?;
        if self.inventories.contains_key(&record.record_id) {
            self.reject("duplicate inventory record")?;
        }
        if record.privacy_set_size < self.config.min_privacy_set_size {
            self.reject("privacy set too small")?;
        }
        if record.current_algorithm.is_legacy() && self.config.quarantine_legacy_signatures {
            record.status = MigrationStatus::Pending;
        }
        record.grace_expires_height = record
            .registered_height
            .saturating_add(record.domain.grace_blocks(&self.config));
        let id = record.record_id.clone();
        match record.domain {
            KeyDomain::AccountSpend | KeyDomain::AccountView => {
                self.counters.accounts_registered =
                    self.counters.accounts_registered.saturating_add(1);
            }
            KeyDomain::SessionAuth => {
                self.counters.sessions_registered =
                    self.counters.sessions_registered.saturating_add(1);
            }
            KeyDomain::ContractAdmin | KeyDomain::ContractExecution => {
                self.counters.contracts_registered =
                    self.counters.contracts_registered.saturating_add(1);
            }
            KeyDomain::MultisigSigner => {}
            KeyDomain::BridgeSigning => {
                self.counters.bridge_keys_registered =
                    self.counters.bridge_keys_registered.saturating_add(1);
            }
            KeyDomain::WatcherAttestation => {
                self.counters.watchers_registered =
                    self.counters.watchers_registered.saturating_add(1);
            }
        }
        self.inventories.insert(id.clone(), record);
        self.event("inventory_registered", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn request_rollover(&mut self, mut request: RolloverRequest) -> Result<String> {
        self.ensure_domain_not_paused(request.domain)?;
        self.ensure_capacity(
            self.requests.len(),
            MAX_ROLLOVER_REQUESTS,
            "rollover requests",
        )?;
        if self.requests.contains_key(&request.request_id) {
            self.reject("duplicate request")?;
        }
        let epoch = self
            .rollover_epochs
            .get(&request.epoch_id)
            .ok_or_else(|| "unknown rollover epoch".to_string())?;
        if !epoch.stage.accepts_new_requests() {
            self.reject("epoch does not accept rollover requests")?;
        }
        if !epoch.target_domains.contains(&request.domain) {
            self.reject("domain not enabled for epoch")?;
        }
        if !epoch.target_algorithms.contains(&request.to_algorithm) {
            self.reject("target algorithm not enabled for epoch")?;
        }
        if request.to_algorithm.pq_security_bits() < self.config.min_pq_security_bits {
            self.reject("target algorithm below pq security floor")?;
        }
        if request.from_algorithm.is_legacy() && request.dual_signature_commitment.is_empty() {
            self.reject("legacy rollover requires dual signature commitment")?;
        }
        let inventory = self
            .inventories
            .get_mut(&request.inventory_id)
            .ok_or_else(|| "unknown inventory record".to_string())?;
        if inventory.domain != request.domain {
            self.reject("inventory domain mismatch")?;
        }
        inventory.status = MigrationStatus::Pending;
        request.deadline_height = request
            .requested_height
            .saturating_add(request.domain.grace_blocks(&self.config));
        request.status = MigrationStatus::Pending;
        let id = request.request_id.clone();
        self.requests.insert(id.clone(), request);
        self.counters.rollover_requests = self.counters.rollover_requests.saturating_add(1);
        self.event("rollover_requested", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_rotation_proof(&mut self, mut proof: RotationProofRecord) -> Result<String> {
        self.ensure_not_paused(PauseScope::Global)?;
        self.ensure_not_paused(PauseScope::Batching)?;
        self.ensure_capacity(self.proofs.len(), MAX_ROTATION_PROOFS, "rotation proofs")?;
        if self.proofs.contains_key(&proof.proof_id) {
            self.reject("duplicate proof")?;
        }
        if self.replay_fences.contains(&proof.nullifier) {
            self.quarantine_from_proof(&proof, QuarantineReason::ReplayFenceHit)?;
            self.reject("replay fence hit")?;
        }
        if proof.privacy_set_size < self.config.min_privacy_set_size {
            self.reject("proof privacy set too small")?;
        }
        if proof.pq_security_bits < self.config.min_pq_security_bits {
            self.quarantine_from_proof(&proof, QuarantineReason::WeakPqSecurity)?;
            self.reject("proof pq security below floor")?;
        }
        let request = self
            .requests
            .get_mut(&proof.request_id)
            .ok_or_else(|| "unknown rollover request".to_string())?;
        if request.epoch_id != proof.epoch_id {
            self.reject("proof epoch mismatch")?;
        }
        request.status = MigrationStatus::ProofRecorded;
        proof.accepted = true;
        let id = proof.proof_id.clone();
        self.replay_fences.insert(proof.nullifier.clone());
        self.proofs.insert(id.clone(), proof);
        self.pending_batch_queue.push_back(id.clone());
        self.counters.proofs_recorded = self.counters.proofs_recorded.saturating_add(1);
        self.event("rotation_proof_recorded", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn register_watcher(&mut self, watcher: WatcherRecord) -> Result<String> {
        self.ensure_not_paused(PauseScope::Watchers)?;
        self.ensure_capacity(self.watchers.len(), MAX_WATCHERS, "watchers")?;
        if watcher.weight_bps == 0 || watcher.weight_bps > MAX_BPS {
            self.reject("watcher weight out of range")?;
        }
        if self.watchers.contains_key(&watcher.watcher_id) {
            self.reject("duplicate watcher")?;
        }
        let id = watcher.watcher_id.clone();
        self.watchers.insert(id.clone(), watcher);
        self.counters.watchers_registered = self.counters.watchers_registered.saturating_add(1);
        self.event("watcher_registered", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_watcher_attestation(
        &mut self,
        attestation: WatcherAttestationRecord,
    ) -> Result<String> {
        self.ensure_not_paused(PauseScope::Watchers)?;
        let watcher = self
            .watchers
            .get(&attestation.watcher_id)
            .ok_or_else(|| "unknown watcher".to_string())?;
        if !watcher.active {
            self.reject("inactive watcher")?;
        }
        if attestation.weight_bps > watcher.weight_bps {
            self.reject("attestation exceeds watcher weight")?;
        }
        if self
            .watcher_attestations
            .contains_key(&attestation.attestation_id)
        {
            self.reject("duplicate watcher attestation")?;
        }
        let id = attestation.attestation_id.clone();
        let subject = attestation.subject_id.clone();
        let veto = attestation.veto;
        self.watcher_attestations.insert(id.clone(), attestation);
        self.watcher_subject_index
            .entry(subject.clone())
            .or_default()
            .insert(id.clone());
        if veto {
            self.quarantine_subject(
                &subject,
                KeyDomain::WatcherAttestation,
                SignatureAlgorithm::MlDsa87,
                QuarantineReason::WatcherVeto,
                id.clone(),
            )?;
        } else {
            self.mark_subject_watcher_attested(&subject);
        }
        self.counters.watcher_attestations = self.counters.watcher_attestations.saturating_add(1);
        self.event("watcher_attestation_recorded", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn register_multisig_group(&mut self, group: MultisigGroupRecord) -> Result<String> {
        self.ensure_not_paused(PauseScope::Multisig)?;
        self.ensure_capacity(
            self.multisig_groups.len(),
            MAX_MULTISIG_GROUPS,
            "multisig groups",
        )?;
        if group.threshold_bps == 0 || group.threshold_bps > MAX_BPS {
            self.reject("multisig threshold out of range")?;
        }
        if self.multisig_groups.contains_key(&group.group_id) {
            self.reject("duplicate multisig group")?;
        }
        let id = group.group_id.clone();
        self.multisig_groups.insert(id.clone(), group);
        self.counters.multisig_groups_registered =
            self.counters.multisig_groups_registered.saturating_add(1);
        self.event("multisig_group_registered", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_multisig_approval(&mut self, approval: MultisigApprovalRecord) -> Result<String> {
        self.ensure_not_paused(PauseScope::Multisig)?;
        if self.multisig_approvals.contains_key(&approval.approval_id) {
            self.reject("duplicate multisig approval")?;
        }
        if !self.proofs.contains_key(&approval.proof_id) {
            self.reject("unknown proof for multisig approval")?;
        }
        let group = self
            .multisig_groups
            .get_mut(&approval.group_id)
            .ok_or_else(|| "unknown multisig group".to_string())?;
        group.pending_signers.remove(&approval.signer_commitment);
        group
            .migrated_signers
            .insert(approval.signer_commitment.clone());
        group.status = MultisigStatus::RolloverOpen;
        let migrated = group.migrated_signers.len() as u64;
        let total = if group.signer_count == 0 {
            1
        } else {
            group.signer_count as u64
        };
        let migrated_bps = migrated.saturating_mul(MAX_BPS) / total;
        if migrated_bps >= group.threshold_bps.max(self.config.multisig_quorum_bps) {
            group.status = MultisigStatus::ThresholdMet;
            group.activated_height = approval.height;
        }
        let id = approval.approval_id.clone();
        self.multisig_approvals.insert(id.clone(), approval);
        self.counters.multisig_approvals = self.counters.multisig_approvals.saturating_add(1);
        self.event("multisig_approval_recorded", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn propose_bridge_cutover(&mut self, bridge: BridgeSigningKeyRecord) -> Result<String> {
        self.ensure_not_paused(PauseScope::Bridge)?;
        self.ensure_capacity(self.bridge_keys.len(), MAX_BRIDGE_KEYS, "bridge keys")?;
        if self.bridge_keys.contains_key(&bridge.bridge_id) {
            self.reject("duplicate bridge key")?;
        }
        let id = bridge.bridge_id.clone();
        self.bridge_keys.insert(id.clone(), bridge);
        self.counters.bridge_keys_registered =
            self.counters.bridge_keys_registered.saturating_add(1);
        self.event("bridge_cutover_proposed", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn update_bridge_cutover(&mut self, bridge_id: &str, height: u64) -> Result<()> {
        self.ensure_not_paused(PauseScope::Bridge)?;
        let current_weight = self.subject_watcher_weight(bridge_id);
        let bridge = self
            .bridge_keys
            .get_mut(bridge_id)
            .ok_or_else(|| "unknown bridge key".to_string())?;
        bridge.watcher_weight_bps = current_weight;
        if current_weight >= self.config.bridge_quorum_bps {
            bridge.status = BridgeCutoverStatus::WatcherAttested;
        }
        if matches!(bridge.status, BridgeCutoverStatus::WatcherAttested) {
            bridge.ready_height = bridge
                .proposed_height
                .saturating_add(self.config.bridge_cutover_delay_blocks);
            bridge.status = BridgeCutoverStatus::DelayWindow;
        }
        if matches!(bridge.status, BridgeCutoverStatus::DelayWindow)
            && height >= bridge.ready_height
        {
            bridge.status = BridgeCutoverStatus::Ready;
        }
        if matches!(bridge.status, BridgeCutoverStatus::Ready) {
            bridge.status = BridgeCutoverStatus::Active;
            bridge.active_height = height;
            self.counters.bridge_cutovers = self.counters.bridge_cutovers.saturating_add(1);
        }
        self.event("bridge_cutover_updated", bridge_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn open_low_fee_batch(
        &mut self,
        batch_id: String,
        epoch_id: String,
        height: u64,
    ) -> Result<String> {
        self.ensure_not_paused(PauseScope::Batching)?;
        self.ensure_capacity(self.low_fee_batches.len(), MAX_BATCHES, "low fee batches")?;
        if self.low_fee_batches.contains_key(&batch_id) {
            self.reject("duplicate batch")?;
        }
        if !self.rollover_epochs.contains_key(&epoch_id) {
            self.reject("unknown batch epoch")?;
        }
        let batch = LowFeeBatchRecord {
            batch_id: batch_id.clone(),
            epoch_id,
            opened_height: height,
            sealed_height: 0,
            proof_ids: BTreeSet::new(),
            aggregated_proof_commitment: String::new(),
            fee_microunits: 0,
            privacy_set_size: self.config.batch_privacy_set_size,
            sealed: false,
        };
        self.low_fee_batches.insert(batch_id.clone(), batch);
        self.counters.batches_opened = self.counters.batches_opened.saturating_add(1);
        self.event("low_fee_batch_opened", &batch_id);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn fill_low_fee_batch(&mut self, batch_id: &str, max_items: usize) -> Result<usize> {
        self.ensure_not_paused(PauseScope::Batching)?;
        let limit = max_items.min(self.config.low_fee_batch_limit);
        let mut selected = Vec::new();
        while selected.len() < limit {
            match self.pending_batch_queue.pop_front() {
                Some(proof_id) => {
                    let available = match self.proofs.get(&proof_id) {
                        Some(proof) => proof.accepted && proof.batch_id.is_none(),
                        None => false,
                    };
                    if available {
                        selected.push(proof_id);
                    }
                }
                None => break,
            }
        }
        let batch = self
            .low_fee_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        if batch.sealed {
            self.reject("sealed batch cannot be filled")?;
        }
        for proof_id in &selected {
            batch.proof_ids.insert(proof_id.clone());
            if let Some(proof) = self.proofs.get_mut(proof_id) {
                proof.batch_id = Some(batch_id.to_string());
            }
        }
        self.event("low_fee_batch_filled", batch_id);
        self.refresh_roots();
        Ok(selected.len())
    }

    pub fn seal_low_fee_batch(
        &mut self,
        batch_id: &str,
        height: u64,
        fee_microunits: u64,
    ) -> Result<()> {
        self.ensure_not_paused(PauseScope::Batching)?;
        let proof_ids = {
            let batch = self
                .low_fee_batches
                .get(batch_id)
                .ok_or_else(|| "unknown batch".to_string())?;
            if batch.sealed {
                self.reject("batch already sealed")?;
            }
            batch.proof_ids.clone()
        };
        let aggregate = digest_set("batch_proofs", &proof_ids);
        let batch = self
            .low_fee_batches
            .get_mut(batch_id)
            .ok_or_else(|| "unknown batch".to_string())?;
        batch.aggregated_proof_commitment = aggregate;
        batch.sealed_height = height;
        batch.fee_microunits = fee_microunits;
        batch.sealed = true;
        for proof_id in proof_ids {
            if let Some(proof) = self.proofs.get(&proof_id) {
                if let Some(request) = self.requests.get_mut(&proof.request_id) {
                    request.status = MigrationStatus::Batched;
                }
            }
        }
        self.counters.batches_sealed = self.counters.batches_sealed.saturating_add(1);
        self.event("low_fee_batch_sealed", batch_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_legacy_signature(
        &mut self,
        subject_id: String,
        domain: KeyDomain,
        algorithm: SignatureAlgorithm,
        reason: QuarantineReason,
        signature_digest: String,
        height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.quarantines.len(),
            MAX_QUARANTINE_RECORDS,
            "quarantine records",
        )?;
        let id = digest_parts(
            "legacy_quarantine",
            &[
                &subject_id,
                domain.as_str(),
                algorithm.as_str(),
                &signature_digest,
                &height.to_string(),
            ],
        );
        if self.quarantines.contains_key(&id) {
            return Ok(id);
        }
        let record = LegacyQuarantineRecord {
            quarantine_id: id.clone(),
            subject_id,
            domain,
            algorithm,
            reason,
            signature_digest,
            quarantined_height: height,
            release_height: height.saturating_add(self.config.legacy_quarantine_blocks),
            watcher_attestation_root: self.roots.watcher_root.clone(),
            sealed: true,
        };
        self.quarantines.insert(id.clone(), record);
        self.counters.legacy_quarantines = self.counters.legacy_quarantines.saturating_add(1);
        self.event("legacy_signature_quarantined", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn emergency_pause(
        &mut self,
        pause_id: String,
        scope: PauseScope,
        reason_commitment: String,
        asserted_by: String,
        height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.emergency_pauses.len(),
            MAX_PAUSE_RECORDS,
            "pause records",
        )?;
        if self.emergency_pauses.contains_key(&pause_id) {
            self.reject("duplicate pause")?;
        }
        let record = EmergencyPauseRecord {
            pause_id: pause_id.clone(),
            scope,
            reason_commitment,
            asserted_by,
            start_height: height,
            review_height: height.saturating_add(self.config.emergency_review_blocks),
            resume_height: 0,
            active: true,
        };
        self.paused_scopes.insert(scope);
        self.emergency_pauses.insert(pause_id.clone(), record);
        self.counters.emergency_pauses = self.counters.emergency_pauses.saturating_add(1);
        self.event("emergency_pause", &pause_id);
        self.refresh_roots();
        Ok(pause_id)
    }

    pub fn resume_from_pause(&mut self, pause_id: &str, height: u64) -> Result<()> {
        let pause = self
            .emergency_pauses
            .get_mut(pause_id)
            .ok_or_else(|| "unknown pause".to_string())?;
        pause.active = false;
        pause.resume_height = height;
        let scope = pause.scope;
        let still_active = self
            .emergency_pauses
            .values()
            .any(|p| p.active && p.scope == scope && p.pause_id != pause_id);
        if !still_active {
            self.paused_scopes.remove(&scope);
        }
        self.counters.emergency_resumes = self.counters.emergency_resumes.saturating_add(1);
        self.event("emergency_resume", pause_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn record_audit_summary(&mut self, mut summary: AuditSummaryRecord) -> Result<String> {
        self.ensure_capacity(
            self.audit_summaries.len(),
            MAX_AUDIT_SUMMARIES,
            "audit summaries",
        )?;
        if self.audit_summaries.contains_key(&summary.summary_id) {
            self.reject("duplicate audit summary")?;
        }
        if summary.privacy_set_floor < self.config.min_privacy_set_size {
            self.reject("audit privacy floor too small")?;
        }
        summary.summary_root = digest_value("audit_summary", &to_value(&summary));
        let id = summary.summary_id.clone();
        self.audit_summaries.insert(id.clone(), summary);
        self.counters.audit_summaries = self.counters.audit_summaries.saturating_add(1);
        self.event("audit_summary_recorded", &id);
        self.refresh_roots();
        Ok(id)
    }

    pub fn activate_ready_requests(&mut self, height: u64) -> usize {
        let mut activated = 0usize;
        let request_ids: Vec<String> = self.requests.keys().cloned().collect();
        for request_id in request_ids {
            let watcher_ready =
                self.subject_watcher_weight(&request_id) >= self.config.watcher_quorum_bps;
            if let Some(request) = self.requests.get_mut(&request_id) {
                if request.status == MigrationStatus::Batched
                    || (!self.config.require_watcher_attestation
                        && request.status == MigrationStatus::ProofRecorded)
                    || (watcher_ready && request.status == MigrationStatus::WatcherAttested)
                {
                    request.status = MigrationStatus::Activated;
                    activated = activated.saturating_add(1);
                    if let Some(inventory) = self.inventories.get_mut(&request.inventory_id) {
                        inventory.current_algorithm = request.to_algorithm;
                        inventory.status = MigrationStatus::Activated;
                        inventory.grace_expires_height = height;
                    }
                }
            }
        }
        if activated > 0 {
            self.event("requests_activated", &activated.to_string());
            self.refresh_roots();
        }
        activated
    }

    pub fn expire_deadlines(&mut self, height: u64) -> usize {
        let epoch_stages: BTreeMap<String, RolloverStage> = self
            .rollover_epochs
            .iter()
            .map(|(id, epoch)| (id.clone(), epoch.stage))
            .collect();
        let mut expired = 0usize;
        let mut quarantines = Vec::new();
        for request in self.requests.values_mut() {
            if !request.status.terminal() && height > request.deadline_height {
                request.status = MigrationStatus::Expired;
                expired = expired.saturating_add(1);
                let stage = match epoch_stages.get(&request.epoch_id).copied() {
                    Some(value) => value,
                    None => RolloverStage::LegacyQuarantine,
                };
                if stage.enforces_quarantine() && request.from_algorithm.is_legacy() {
                    quarantines.push((
                        request.request_id.clone(),
                        request.domain,
                        request.from_algorithm,
                        QuarantineReason::LegacyAfterDeadline,
                        request.old_key_commitment.clone(),
                    ));
                }
            }
        }
        for (subject, domain, algorithm, reason, sig) in quarantines {
            let _ =
                self.quarantine_legacy_signature(subject, domain, algorithm, reason, sig, height);
        }
        if expired > 0 {
            self.event("deadlines_expired", &expired.to_string());
            self.refresh_roots();
        }
        expired
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_signature_suite": PQ_SIGNATURE_SUITE,
            "hybrid_signature_suite": HYBRID_SIGNATURE_SUITE,
            "legacy_quarantine_scheme": LEGACY_QUARANTINE_SCHEME,
            "watcher_attestation_scheme": WATCHER_ATTESTATION_SCHEME,
            "bridge_cutover_scheme": BRIDGE_CUTOVER_SCHEME,
            "privacy_audit_scheme": PRIVACY_AUDIT_SCHEME,
            "low_fee_batch_scheme": LOW_FEE_BATCH_SCHEME,
            "emergency_pause_scheme": EMERGENCY_PAUSE_SCHEME,
            "config": {
                "chain_id": self.config.chain_id,
                "coordinator_id": self.config.coordinator_id,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "batch_privacy_set_size": self.config.batch_privacy_set_size,
                "watcher_quorum_bps": self.config.watcher_quorum_bps,
                "multisig_quorum_bps": self.config.multisig_quorum_bps,
                "bridge_quorum_bps": self.config.bridge_quorum_bps,
                "quarantine_legacy_signatures": self.config.quarantine_legacy_signatures,
            },
            "current_height": self.current_height,
            "active_epoch": self.active_epoch,
            "paused_scopes": self.paused_scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "counters": self.counters,
            "roots": self.roots,
            "sizes": {
                "epochs": self.rollover_epochs.len(),
                "inventories": self.inventories.len(),
                "requests": self.requests.len(),
                "proofs": self.proofs.len(),
                "watchers": self.watchers.len(),
                "watcher_attestations": self.watcher_attestations.len(),
                "multisig_groups": self.multisig_groups.len(),
                "bridge_keys": self.bridge_keys.len(),
                "quarantines": self.quarantines.len(),
                "low_fee_batches": self.low_fee_batches.len(),
                "audit_summaries": self.audit_summaries.len(),
            }
        })
    }

    pub fn state_root(&self) -> String {
        digest_value("state", &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.epoch_root = digest_map("epochs", &self.rollover_epochs);
        self.roots.inventory_root = digest_map("inventories", &self.inventories);
        self.roots.request_root = digest_map("requests", &self.requests);
        self.roots.proof_root = digest_map("proofs", &self.proofs);
        self.roots.watcher_root = digest_map("watchers", &self.watcher_attestations);
        self.roots.multisig_root = digest_map("multisig", &self.multisig_groups);
        self.roots.bridge_root = digest_map("bridge", &self.bridge_keys);
        self.roots.quarantine_root = digest_map("quarantine", &self.quarantines);
        self.roots.batch_root = digest_map("batches", &self.low_fee_batches);
        self.roots.audit_root = digest_map("audits", &self.audit_summaries);
        self.roots.pause_root = digest_map("pauses", &self.emergency_pauses);
        let composite = json!({
            "epoch_root": self.roots.epoch_root,
            "inventory_root": self.roots.inventory_root,
            "request_root": self.roots.request_root,
            "proof_root": self.roots.proof_root,
            "watcher_root": self.roots.watcher_root,
            "multisig_root": self.roots.multisig_root,
            "bridge_root": self.roots.bridge_root,
            "quarantine_root": self.roots.quarantine_root,
            "batch_root": self.roots.batch_root,
            "audit_root": self.roots.audit_root,
            "pause_root": self.roots.pause_root,
            "counters": self.counters,
            "height": self.current_height,
        });
        self.roots.state_root = digest_value("state_roots", &composite);
    }

    fn ensure_domain_not_paused(&self, domain: KeyDomain) -> Result<()> {
        self.ensure_not_paused(PauseScope::Global)?;
        match domain {
            KeyDomain::AccountSpend | KeyDomain::AccountView => {
                self.ensure_not_paused(PauseScope::Accounts)
            }
            KeyDomain::SessionAuth => self.ensure_not_paused(PauseScope::Sessions),
            KeyDomain::ContractAdmin | KeyDomain::ContractExecution => {
                self.ensure_not_paused(PauseScope::Contracts)
            }
            KeyDomain::MultisigSigner => self.ensure_not_paused(PauseScope::Multisig),
            KeyDomain::BridgeSigning => self.ensure_not_paused(PauseScope::Bridge),
            KeyDomain::WatcherAttestation => self.ensure_not_paused(PauseScope::Watchers),
        }
    }

    fn ensure_not_paused(&self, scope: PauseScope) -> Result<()> {
        if self.paused_scopes.contains(&PauseScope::Global) || self.paused_scopes.contains(&scope) {
            Err(format!("scope paused: {}", scope.as_str()))
        } else {
            Ok(())
        }
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            Err(format!("capacity exceeded for {}", label))
        } else {
            Ok(())
        }
    }

    fn ensure_inventory_capacity(&self, domain: KeyDomain) -> Result<()> {
        let count = self
            .inventories
            .values()
            .filter(|r| r.domain == domain)
            .count();
        match domain {
            KeyDomain::AccountSpend | KeyDomain::AccountView => {
                self.ensure_capacity(count, MAX_ACCOUNTS, "account inventory")
            }
            KeyDomain::SessionAuth => {
                self.ensure_capacity(count, MAX_SESSIONS, "session inventory")
            }
            KeyDomain::ContractAdmin | KeyDomain::ContractExecution => {
                self.ensure_capacity(count, MAX_CONTRACTS, "contract inventory")
            }
            KeyDomain::MultisigSigner => {
                self.ensure_capacity(count, MAX_MULTISIG_GROUPS, "multisig signer inventory")
            }
            KeyDomain::BridgeSigning => {
                self.ensure_capacity(count, MAX_BRIDGE_KEYS, "bridge inventory")
            }
            KeyDomain::WatcherAttestation => {
                self.ensure_capacity(count, MAX_WATCHERS, "watcher inventory")
            }
        }
    }

    fn subject_watcher_weight(&self, subject_id: &str) -> u64 {
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        if let Some(attestation_ids) = self.watcher_subject_index.get(subject_id) {
            for attestation_id in attestation_ids {
                if let Some(attestation) = self.watcher_attestations.get(attestation_id) {
                    if !attestation.veto && seen.insert(attestation.watcher_id.clone()) {
                        total = total.saturating_add(attestation.weight_bps);
                    }
                }
            }
        }
        total.min(MAX_BPS)
    }

    fn mark_subject_watcher_attested(&mut self, subject_id: &str) {
        if let Some(request) = self.requests.get_mut(subject_id) {
            if request.status == MigrationStatus::ProofRecorded {
                request.status = MigrationStatus::WatcherAttested;
            }
        }
        let weight = self.subject_watcher_weight(subject_id);
        if let Some(bridge) = self.bridge_keys.get_mut(subject_id) {
            bridge.watcher_weight_bps = weight;
            if weight >= self.config.bridge_quorum_bps {
                bridge.status = BridgeCutoverStatus::WatcherAttested;
            }
        }
    }

    fn quarantine_from_proof(
        &mut self,
        proof: &RotationProofRecord,
        reason: QuarantineReason,
    ) -> Result<String> {
        self.quarantine_legacy_signature(
            proof.request_id.clone(),
            KeyDomain::AccountSpend,
            SignatureAlgorithm::Ed25519,
            reason,
            proof.old_signature_digest.clone(),
            proof.recorded_height,
        )
    }

    fn quarantine_subject(
        &mut self,
        subject_id: &str,
        domain: KeyDomain,
        algorithm: SignatureAlgorithm,
        reason: QuarantineReason,
        signature_digest: String,
    ) -> Result<String> {
        self.quarantine_legacy_signature(
            subject_id.to_string(),
            domain,
            algorithm,
            reason,
            signature_digest,
            self.current_height,
        )
    }

    fn reject<T>(&mut self, message: &str) -> Result<T> {
        self.counters.rejected_operations = self.counters.rejected_operations.saturating_add(1);
        Err(message.to_string())
    }

    fn event(&mut self, kind: &str, id: &str) {
        let entry = format!("{}:{}:{}", self.current_height, kind, id);
        self.event_log.push(entry);
        if self.event_log.len() > 512 {
            let excess = self.event_log.len().saturating_sub(512);
            self.event_log.drain(0..excess);
        }
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT);
    let mut targets = BTreeSet::new();
    targets.insert(SignatureAlgorithm::MlDsa87);
    targets.insert(SignatureAlgorithm::SlhDsaShake256f);
    targets.insert(SignatureAlgorithm::HybridEd25519MlDsa87);
    let mut domains = BTreeSet::new();
    domains.insert(KeyDomain::AccountSpend);
    domains.insert(KeyDomain::AccountView);
    domains.insert(KeyDomain::SessionAuth);
    domains.insert(KeyDomain::ContractAdmin);
    domains.insert(KeyDomain::ContractExecution);
    domains.insert(KeyDomain::MultisigSigner);
    domains.insert(KeyDomain::BridgeSigning);
    let epoch = RolloverEpoch {
        epoch_id: "devnet-pq-rollover-epoch-001".to_string(),
        stage: RolloverStage::Announced,
        start_height: DEVNET_HEIGHT,
        dual_signature_height: DEVNET_HEIGHT.saturating_add(32),
        pq_preferred_height: DEVNET_HEIGHT.saturating_add(96),
        quarantine_height: DEVNET_HEIGHT.saturating_add(384),
        enforce_height: DEVNET_HEIGHT.saturating_add(720),
        expires_height: DEVNET_HEIGHT.saturating_add(DEFAULT_ROLLOVER_TTL_BLOCKS),
        target_algorithms: targets,
        target_domains: domains,
        privacy_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
        watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
        memo_commitment: "devnet-rollover-policy-root".to_string(),
    };
    let _ = state.open_epoch(epoch);
    let _ = state.advance_epoch_stage("devnet-pq-rollover-epoch-001", RolloverStage::DualSignature);
    let _ = state.register_watcher(WatcherRecord {
        watcher_id: "watcher-alpha".to_string(),
        operator_commitment: "operator-alpha-commitment".to_string(),
        attestation_key_commitment: "watcher-alpha-pq-attestation-key".to_string(),
        stake_commitment: "watcher-alpha-stake".to_string(),
        weight_bps: 3_400,
        active: true,
        last_height: DEVNET_HEIGHT,
    });
    let _ = state.register_watcher(WatcherRecord {
        watcher_id: "watcher-beta".to_string(),
        operator_commitment: "operator-beta-commitment".to_string(),
        attestation_key_commitment: "watcher-beta-pq-attestation-key".to_string(),
        stake_commitment: "watcher-beta-stake".to_string(),
        weight_bps: 3_400,
        active: true,
        last_height: DEVNET_HEIGHT,
    });
    let _ = state.register_inventory(KeyInventoryRecord {
        record_id: "acct-inventory-001".to_string(),
        owner_commitment: "account-owner-commitment-001".to_string(),
        domain: KeyDomain::AccountSpend,
        legacy_algorithm: SignatureAlgorithm::Ed25519,
        current_algorithm: SignatureAlgorithm::Ed25519,
        pq_key_commitment: "account-new-ml-dsa-key-001".to_string(),
        migration_epoch: "devnet-pq-rollover-epoch-001".to_string(),
        registered_height: DEVNET_HEIGHT,
        grace_expires_height: 0,
        status: MigrationStatus::Pending,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        nullifier_commitment: "acct-nullifier-001".to_string(),
    });
    let _ = state.request_rollover(RolloverRequest {
        request_id: "rollover-request-001".to_string(),
        epoch_id: "devnet-pq-rollover-epoch-001".to_string(),
        inventory_id: "acct-inventory-001".to_string(),
        domain: KeyDomain::AccountSpend,
        from_algorithm: SignatureAlgorithm::Ed25519,
        to_algorithm: SignatureAlgorithm::MlDsa87,
        requester_commitment: "account-owner-commitment-001".to_string(),
        old_key_commitment: "account-old-ed25519-key-001".to_string(),
        new_key_commitment: "account-new-ml-dsa-key-001".to_string(),
        dual_signature_commitment: "dual-signature-commitment-001".to_string(),
        privacy_proof_commitment: "privacy-proof-commitment-001".to_string(),
        requested_height: DEVNET_HEIGHT.saturating_add(2),
        deadline_height: 0,
        fee_limit_microunits: 25,
        status: MigrationStatus::Pending,
    });
    let _ = state.record_rotation_proof(RotationProofRecord {
        proof_id: "rotation-proof-001".to_string(),
        request_id: "rollover-request-001".to_string(),
        epoch_id: "devnet-pq-rollover-epoch-001".to_string(),
        proof_commitment: "rotation-proof-root-001".to_string(),
        nullifier: "rotation-nullifier-001".to_string(),
        old_signature_digest: "old-ed25519-signature-digest-001".to_string(),
        pq_signature_digest: "pq-ml-dsa-signature-digest-001".to_string(),
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        recorded_height: DEVNET_HEIGHT.saturating_add(3),
        accepted: false,
        batch_id: None,
    });
    let _ = state.record_watcher_attestation(WatcherAttestationRecord {
        attestation_id: "watcher-alpha-attests-request-001".to_string(),
        watcher_id: "watcher-alpha".to_string(),
        subject_id: "rollover-request-001".to_string(),
        epoch_id: "devnet-pq-rollover-epoch-001".to_string(),
        statement_root: "watcher-statement-root-alpha-001".to_string(),
        signature_digest: "watcher-alpha-signature-digest-001".to_string(),
        weight_bps: 3_400,
        height: DEVNET_HEIGHT.saturating_add(4),
        veto: false,
    });
    let _ = state.record_watcher_attestation(WatcherAttestationRecord {
        attestation_id: "watcher-beta-attests-request-001".to_string(),
        watcher_id: "watcher-beta".to_string(),
        subject_id: "rollover-request-001".to_string(),
        epoch_id: "devnet-pq-rollover-epoch-001".to_string(),
        statement_root: "watcher-statement-root-beta-001".to_string(),
        signature_digest: "watcher-beta-signature-digest-001".to_string(),
        weight_bps: 3_400,
        height: DEVNET_HEIGHT.saturating_add(4),
        veto: false,
    });
    let _ = state.open_low_fee_batch(
        "low-fee-rollover-batch-001".to_string(),
        "devnet-pq-rollover-epoch-001".to_string(),
        DEVNET_HEIGHT.saturating_add(5),
    );
    let _ = state.fill_low_fee_batch("low-fee-rollover-batch-001", DEFAULT_LOW_FEE_BATCH_TARGET);
    let _ = state.seal_low_fee_batch(
        "low-fee-rollover-batch-001",
        DEVNET_HEIGHT.saturating_add(6),
        9,
    );
    let _ = state.record_audit_summary(AuditSummaryRecord {
        summary_id: "privacy-audit-summary-001".to_string(),
        epoch_id: "devnet-pq-rollover-epoch-001".to_string(),
        bucket: AuditBucket::Accounts,
        range_start_height: DEVNET_HEIGHT,
        range_end_height: DEVNET_HEIGHT.saturating_add(6),
        subject_count_commitment: "audit-subject-count-commitment".to_string(),
        success_count_commitment: "audit-success-count-commitment".to_string(),
        quarantine_count_commitment: "audit-quarantine-count-commitment".to_string(),
        watcher_coverage_bps: 6_800,
        privacy_set_floor: DEFAULT_MIN_PRIVACY_SET_SIZE,
        summary_root: String::new(),
    });
    state.refresh_roots();
    state
}

pub fn demo() -> Value {
    devnet().public_record()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn to_value<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(v) => v,
        Err(_) => Value::Null,
    }
}

fn digest_map<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let mut parts = Vec::new();
    for (key, value) in map {
        parts.push(format!("{}={}", key, canonical_json(&to_value(value))));
    }
    digest_parts(
        domain,
        &parts.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

fn digest_set(domain: &str, set: &BTreeSet<String>) -> String {
    let parts: Vec<&str> = set.iter().map(String::as_str).collect();
    digest_parts(domain, &parts)
}

fn digest_value(domain: &str, value: &Value) -> String {
    let encoded = canonical_json(value);
    digest_parts(domain, &[&encoded])
}

fn digest_parts(domain: &str, parts: &[&str]) -> String {
    let mut hi: u64 = 0xcbf29ce484222325;
    let mut lo: u64 = 0x100000001b3;
    absorb(&mut hi, &mut lo, PROTOCOL_VERSION);
    absorb(&mut hi, &mut lo, domain);
    for part in parts {
        absorb(&mut hi, &mut lo, "|");
        absorb(&mut hi, &mut lo, part);
    }
    format!("{:016x}{:016x}", hi, lo)
}

fn absorb(hi: &mut u64, lo: &mut u64, input: &str) {
    for byte in input.as_bytes() {
        *hi ^= u64::from(*byte);
        *hi = hi.wrapping_mul(0x100000001b3);
        *lo ^= hi.rotate_left(13) ^ u64::from(*byte);
        *lo = lo.wrapping_mul(0x9e3779b185ebca87);
    }
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => quote_json_string(s),
        Value::Array(values) => {
            let body = values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{}]", body)
        }
        Value::Object(map) => {
            let mut entries = Vec::new();
            for (key, item) in map {
                entries.push(format!(
                    "{}:{}",
                    quote_json_string(key),
                    canonical_json(item)
                ));
            }
            format!("{{{}}}", entries.join(","))
        }
    }
}

fn quote_json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len().saturating_add(2));
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
