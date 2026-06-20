use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type DurableStateStoreResult<T> = Result<T, String>;

pub const DURABLE_STATE_STORE_PROTOCOL_VERSION: u64 = 1;
pub const DURABLE_STATE_STORE_SCHEMA_VERSION: u64 = 1;
pub const DURABLE_STATE_STORE_DEFAULT_RECENT_HEIGHTS: u64 = 14_400;
pub const DURABLE_STATE_STORE_DEFAULT_SNAPSHOT_INTERVAL: u64 = 120;
pub const DURABLE_STATE_STORE_DEFAULT_ARCHIVE_INTERVAL: u64 = 7_200;
pub const DURABLE_STATE_STORE_DEFAULT_RESTORE_WINDOW_BLOCKS: u64 = 720;
pub const DURABLE_STATE_STORE_DEFAULT_CRASH_INTENT_TTL_BLOCKS: u64 = 120;
pub const DURABLE_STATE_STORE_DEFAULT_REDACTION_TTL_BLOCKS: u64 = 43_200;
pub const DURABLE_STATE_STORE_DEFAULT_CUSTODIAN_TTL_BLOCKS: u64 = 86_400;
pub const DURABLE_STATE_STORE_DEFAULT_LOW_FEE_ASSET_ID: &str = "dxmr";
pub const DURABLE_STATE_STORE_DEVNET_OPERATOR: &str = "durable-state-devnet-operator";
pub const DURABLE_STATE_STORE_DEVNET_CUSTODIAN: &str = "durable-state-devnet-custodian";
pub const DURABLE_STATE_STORE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableJournalEntryKind {
    StateDelta,
    SnapshotManifest,
    RestorePlan,
    ErasureChunkManifest,
    RetentionPolicy,
    PruningDecision,
    CheckpointNotarization,
    CrashRecoveryIntent,
    LowFeeArchiveSponsorship,
    RedactionManifest,
    PqCustodianAttestation,
    ValidationReport,
}

impl DurableJournalEntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StateDelta => "state_delta",
            Self::SnapshotManifest => "snapshot_manifest",
            Self::RestorePlan => "restore_plan",
            Self::ErasureChunkManifest => "erasure_chunk_manifest",
            Self::RetentionPolicy => "retention_policy",
            Self::PruningDecision => "pruning_decision",
            Self::CheckpointNotarization => "checkpoint_notarization",
            Self::CrashRecoveryIntent => "crash_recovery_intent",
            Self::LowFeeArchiveSponsorship => "low_fee_archive_sponsorship",
            Self::RedactionManifest => "redaction_manifest",
            Self::PqCustodianAttestation => "pq_custodian_attestation",
            Self::ValidationReport => "validation_report",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableJournalEntryStatus {
    Prepared,
    Committed,
    Superseded,
    Reverted,
    Quarantined,
}

impl DurableJournalEntryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::Superseded => "superseded",
            Self::Reverted => "reverted",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn is_committed(&self) -> bool {
        matches!(self, Self::Committed | Self::Superseded)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Committed | Self::Superseded | Self::Reverted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableSnapshotKind {
    Full,
    Incremental,
    StateRootOnly,
    RedactedPublic,
}

impl DurableSnapshotKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Incremental => "incremental",
            Self::StateRootOnly => "state_root_only",
            Self::RedactedPublic => "redacted_public",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableErasureCodec {
    ReedSolomon,
    RaptorQ,
    XorParity,
    Identity,
}

impl DurableErasureCodec {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReedSolomon => "reed_solomon",
            Self::RaptorQ => "raptor_q",
            Self::XorParity => "xor_parity",
            Self::Identity => "identity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableRestorePlanStatus {
    Draft,
    Ready,
    Restoring,
    Completed,
    Failed,
    Quarantined,
}

impl DurableRestorePlanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Ready => "ready",
            Self::Restoring => "restoring",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Draft | Self::Ready | Self::Restoring)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableRetentionAction {
    RetainHot,
    RetainArchive,
    SponsorArchive,
    Redact,
    Prune,
    Quarantine,
}

impl DurableRetentionAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RetainHot => "retain_hot",
            Self::RetainArchive => "retain_archive",
            Self::SponsorArchive => "sponsor_archive",
            Self::Redact => "redact",
            Self::Prune => "prune",
            Self::Quarantine => "quarantine",
        }
    }

    pub fn is_destructive(&self) -> bool {
        matches!(self, Self::Redact | Self::Prune | Self::Quarantine)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableRetentionReason {
    RecentHeight,
    Checkpointed,
    LegalHold,
    LowFeeSponsored,
    ArchiveCadence,
    Expired,
    Corrupt,
    PrivacyRedaction,
}

impl DurableRetentionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RecentHeight => "recent_height",
            Self::Checkpointed => "checkpointed",
            Self::LegalHold => "legal_hold",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::ArchiveCadence => "archive_cadence",
            Self::Expired => "expired",
            Self::Corrupt => "corrupt",
            Self::PrivacyRedaction => "privacy_redaction",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableNotarizationStatus {
    Pending,
    QuorumCertified,
    Anchored,
    Disputed,
    Revoked,
}

impl DurableNotarizationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::QuorumCertified => "quorum_certified",
            Self::Anchored => "anchored",
            Self::Disputed => "disputed",
            Self::Revoked => "revoked",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn accepted(&self) -> bool {
        matches!(self, Self::QuorumCertified | Self::Anchored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableCrashRecoveryIntentKind {
    ReplayJournal,
    RestoreSnapshot,
    QuarantineTip,
    RebuildErasureSet,
    ReconcileCheckpoint,
}

impl DurableCrashRecoveryIntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReplayJournal => "replay_journal",
            Self::RestoreSnapshot => "restore_snapshot",
            Self::QuarantineTip => "quarantine_tip",
            Self::RebuildErasureSet => "rebuild_erasure_set",
            Self::ReconcileCheckpoint => "reconcile_checkpoint",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableCrashRecoveryStatus {
    Open,
    Replaying,
    Restored,
    Failed,
    Expired,
    Cancelled,
}

impl DurableCrashRecoveryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Replaying => "replaying",
            Self::Restored => "restored",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Open | Self::Replaying)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableArchiveSponsorshipStatus {
    Offered,
    Reserved,
    Active,
    Settled,
    Exhausted,
    Expired,
    Slashed,
}

impl DurableArchiveSponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Settled => "settled",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Reserved | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableRedactionScope {
    Snapshot,
    Chunk,
    JournalEntry,
    RestorePlan,
    PublicManifest,
}

impl DurableRedactionScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Chunk => "chunk",
            Self::JournalEntry => "journal_entry",
            Self::RestorePlan => "restore_plan",
            Self::PublicManifest => "public_manifest",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableRedactionPolicy {
    CommitmentOnly,
    ViewKeyEscrow,
    AggregateDisclosure,
    LegalHold,
    Tombstone,
}

impl DurableRedactionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::ViewKeyEscrow => "view_key_escrow",
            Self::AggregateDisclosure => "aggregate_disclosure",
            Self::LegalHold => "legal_hold",
            Self::Tombstone => "tombstone",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableCustodianAttestationStatus {
    Offered,
    Accepted,
    Challenged,
    Expired,
    Slashed,
}

impl DurableCustodianAttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableValidationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl DurableValidationSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    pub fn blocks_restore(&self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableValidationStatus {
    Passed,
    Warning,
    Failed,
    Quarantined,
}

impl DurableValidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warning => "warning",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn status(&self) -> &'static str {
        self.as_str()
    }

    pub fn accepted(&self) -> bool {
        matches!(self, Self::Passed | Self::Warning)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableStateStoreBounds {
    pub max_journal_entries: u64,
    pub max_snapshot_manifests: u64,
    pub max_restore_plans: u64,
    pub max_erasure_chunk_manifests: u64,
    pub max_retention_policies: u64,
    pub max_pruning_decisions: u64,
    pub max_checkpoint_notarizations: u64,
    pub max_crash_recovery_intents: u64,
    pub max_archive_sponsorships: u64,
    pub max_redaction_manifests: u64,
    pub max_custodian_attestations: u64,
    pub max_validation_reports: u64,
}

impl Default for DurableStateStoreBounds {
    fn default() -> Self {
        Self {
            max_journal_entries: 65_536,
            max_snapshot_manifests: 4_096,
            max_restore_plans: 2_048,
            max_erasure_chunk_manifests: 262_144,
            max_retention_policies: 64,
            max_pruning_decisions: 16_384,
            max_checkpoint_notarizations: 8_192,
            max_crash_recovery_intents: 4_096,
            max_archive_sponsorships: 8_192,
            max_redaction_manifests: 8_192,
            max_custodian_attestations: 16_384,
            max_validation_reports: 8_192,
        }
    }
}

impl DurableStateStoreBounds {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_state_store_bounds",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "max_journal_entries": self.max_journal_entries,
            "max_snapshot_manifests": self.max_snapshot_manifests,
            "max_restore_plans": self.max_restore_plans,
            "max_erasure_chunk_manifests": self.max_erasure_chunk_manifests,
            "max_retention_policies": self.max_retention_policies,
            "max_pruning_decisions": self.max_pruning_decisions,
            "max_checkpoint_notarizations": self.max_checkpoint_notarizations,
            "max_crash_recovery_intents": self.max_crash_recovery_intents,
            "max_archive_sponsorships": self.max_archive_sponsorships,
            "max_redaction_manifests": self.max_redaction_manifests,
            "max_custodian_attestations": self.max_custodian_attestations,
            "max_validation_reports": self.max_validation_reports,
        })
    }

    pub fn bounds_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-STATE-STORE-BOUNDS", &self.public_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_positive(self.max_journal_entries, "durable journal entry bound")?;
        ensure_positive(self.max_snapshot_manifests, "durable snapshot bound")?;
        ensure_positive(self.max_restore_plans, "durable restore plan bound")?;
        ensure_positive(
            self.max_erasure_chunk_manifests,
            "durable erasure chunk bound",
        )?;
        ensure_positive(
            self.max_checkpoint_notarizations,
            "durable checkpoint notarization bound",
        )?;
        Ok(self.bounds_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableStateJournalEntry {
    pub entry_id: String,
    pub sequence: u64,
    pub previous_entry_id: String,
    pub entry_kind: DurableJournalEntryKind,
    pub subject_id: String,
    pub subject_root: String,
    pub previous_store_root: String,
    pub resulting_collection_root: String,
    pub block_height: u64,
    pub recorded_at_ms: u64,
    pub writer_commitment: String,
    pub status: DurableJournalEntryStatus,
}

impl DurableStateJournalEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence: u64,
        previous_entry_id: impl Into<String>,
        entry_kind: DurableJournalEntryKind,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        previous_store_root: impl Into<String>,
        resulting_collection_root: impl Into<String>,
        block_height: u64,
        recorded_at_ms: u64,
        writer_commitment: impl Into<String>,
        status: DurableJournalEntryStatus,
    ) -> DurableStateStoreResult<Self> {
        let mut entry = Self {
            entry_id: String::new(),
            sequence,
            previous_entry_id: previous_entry_id.into(),
            entry_kind,
            subject_id: subject_id.into(),
            subject_root: subject_root.into(),
            previous_store_root: previous_store_root.into(),
            resulting_collection_root: resulting_collection_root.into(),
            block_height,
            recorded_at_ms,
            writer_commitment: writer_commitment.into(),
            status,
        };
        entry.entry_id = durable_journal_entry_id(&entry.identity_record());
        entry.validate()?;
        Ok(entry)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_state_journal_entry_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "sequence": self.sequence,
            "previous_entry_id": &self.previous_entry_id,
            "entry_kind": self.entry_kind.as_str(),
            "subject_id": &self.subject_id,
            "subject_root": &self.subject_root,
            "previous_store_root": &self.previous_store_root,
            "resulting_collection_root": &self.resulting_collection_root,
            "block_height": self.block_height,
            "recorded_at_ms": self.recorded_at_ms,
            "writer_commitment": &self.writer_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_state_journal_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "entry_id": &self.entry_id,
            "sequence": self.sequence,
            "previous_entry_id": &self.previous_entry_id,
            "entry_kind": self.entry_kind.as_str(),
            "subject_id": &self.subject_id,
            "subject_root": &self.subject_root,
            "previous_store_root": &self.previous_store_root,
            "resulting_collection_root": &self.resulting_collection_root,
            "block_height": self.block_height,
            "recorded_at_ms": self.recorded_at_ms,
            "writer_commitment": &self.writer_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn journal_entry_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-JOURNAL-ENTRY", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.entry_id == durable_journal_entry_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        if self.sequence > 0 {
            ensure_non_empty(&self.previous_entry_id, "durable journal previous entry")?;
        }
        ensure_non_empty(&self.subject_id, "durable journal subject id")?;
        ensure_non_empty(&self.subject_root, "durable journal subject root")?;
        ensure_non_empty(
            &self.previous_store_root,
            "durable journal previous store root",
        )?;
        ensure_non_empty(
            &self.resulting_collection_root,
            "durable journal resulting collection root",
        )?;
        ensure_non_empty(&self.writer_commitment, "durable journal writer commitment")?;
        if !self.verify_id() {
            return Err("durable journal entry id mismatch".to_string());
        }
        Ok(self.journal_entry_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableSnapshotManifest {
    pub snapshot_id: String,
    pub snapshot_kind: DurableSnapshotKind,
    pub block_height: u64,
    pub block_hash: String,
    pub previous_block_hash: String,
    pub state_root: String,
    pub execution_root: String,
    pub component_roots: BTreeMap<String, String>,
    pub service_roots: BTreeMap<String, String>,
    pub base_snapshot_id: String,
    pub erasure_chunk_root: String,
    pub erasure_chunk_count: u64,
    pub logical_bytes: u64,
    pub encoded_bytes: u64,
    pub redaction_manifest_root: String,
    pub custodian_attestation_root: String,
    pub created_at_ms: u64,
    pub finalized: bool,
}

impl DurableSnapshotManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_kind: DurableSnapshotKind,
        block_height: u64,
        block_hash: impl Into<String>,
        previous_block_hash: impl Into<String>,
        state_root: impl Into<String>,
        execution_root: impl Into<String>,
        component_roots: BTreeMap<String, String>,
        service_roots: BTreeMap<String, String>,
        base_snapshot_id: impl Into<String>,
        erasure_chunk_root: impl Into<String>,
        erasure_chunk_count: u64,
        logical_bytes: u64,
        encoded_bytes: u64,
        redaction_manifest_root: impl Into<String>,
        custodian_attestation_root: impl Into<String>,
        created_at_ms: u64,
        finalized: bool,
    ) -> DurableStateStoreResult<Self> {
        let mut manifest = Self {
            snapshot_id: String::new(),
            snapshot_kind,
            block_height,
            block_hash: block_hash.into(),
            previous_block_hash: previous_block_hash.into(),
            state_root: state_root.into(),
            execution_root: execution_root.into(),
            component_roots,
            service_roots,
            base_snapshot_id: base_snapshot_id.into(),
            erasure_chunk_root: erasure_chunk_root.into(),
            erasure_chunk_count,
            logical_bytes,
            encoded_bytes,
            redaction_manifest_root: redaction_manifest_root.into(),
            custodian_attestation_root: custodian_attestation_root.into(),
            created_at_ms,
            finalized,
        };
        manifest.snapshot_id = durable_snapshot_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_snapshot_manifest_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "snapshot_kind": self.snapshot_kind.as_str(),
            "block_height": self.block_height,
            "block_hash": &self.block_hash,
            "previous_block_hash": &self.previous_block_hash,
            "state_root": &self.state_root,
            "execution_root": &self.execution_root,
            "component_roots": &self.component_roots,
            "service_roots": &self.service_roots,
            "base_snapshot_id": &self.base_snapshot_id,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_snapshot_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "snapshot_id": &self.snapshot_id,
            "snapshot_kind": self.snapshot_kind.as_str(),
            "block_height": self.block_height,
            "block_hash": &self.block_hash,
            "previous_block_hash": &self.previous_block_hash,
            "state_root": &self.state_root,
            "execution_root": &self.execution_root,
            "component_roots": &self.component_roots,
            "component_root": durable_string_map_root("DURABLE-SNAPSHOT-COMPONENT", &self.component_roots),
            "service_roots": &self.service_roots,
            "service_root": durable_string_map_root("DURABLE-SNAPSHOT-SERVICE", &self.service_roots),
            "base_snapshot_id": &self.base_snapshot_id,
            "erasure_chunk_root": &self.erasure_chunk_root,
            "erasure_chunk_count": self.erasure_chunk_count,
            "logical_bytes": self.logical_bytes,
            "encoded_bytes": self.encoded_bytes,
            "redaction_manifest_root": &self.redaction_manifest_root,
            "custodian_attestation_root": &self.custodian_attestation_root,
            "created_at_ms": self.created_at_ms,
            "finalized": self.finalized,
        })
    }

    pub fn snapshot_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-SNAPSHOT-MANIFEST", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.snapshot_id == durable_snapshot_manifest_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.block_hash, "durable snapshot block hash")?;
        ensure_non_empty(
            &self.previous_block_hash,
            "durable snapshot previous block hash",
        )?;
        ensure_non_empty(&self.state_root, "durable snapshot state root")?;
        ensure_non_empty(&self.execution_root, "durable snapshot execution root")?;
        if self.erasure_chunk_count > 0 {
            ensure_non_empty(
                &self.erasure_chunk_root,
                "durable snapshot erasure chunk root",
            )?;
        }
        if self.encoded_bytes < self.logical_bytes {
            return Err("durable snapshot encoded bytes below logical bytes".to_string());
        }
        if !self.verify_id() {
            return Err("durable snapshot manifest id mismatch".to_string());
        }
        Ok(self.snapshot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableRestorePlan {
    pub restore_plan_id: String,
    pub target_snapshot_id: String,
    pub target_block_height: u64,
    pub target_state_root: String,
    pub source_snapshot_ids: BTreeSet<String>,
    pub required_chunk_ids: BTreeSet<String>,
    pub required_custodian_root: String,
    pub redaction_manifest_root: String,
    pub expected_journal_entry_id: String,
    pub restore_window_start_height: u64,
    pub restore_window_end_height: u64,
    pub created_at_ms: u64,
    pub operator_commitment: String,
    pub status: DurableRestorePlanStatus,
}

impl DurableRestorePlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_snapshot_id: impl Into<String>,
        target_block_height: u64,
        target_state_root: impl Into<String>,
        source_snapshot_ids: BTreeSet<String>,
        required_chunk_ids: BTreeSet<String>,
        required_custodian_root: impl Into<String>,
        redaction_manifest_root: impl Into<String>,
        expected_journal_entry_id: impl Into<String>,
        restore_window_start_height: u64,
        restore_window_end_height: u64,
        created_at_ms: u64,
        operator_commitment: impl Into<String>,
        status: DurableRestorePlanStatus,
    ) -> DurableStateStoreResult<Self> {
        let mut plan = Self {
            restore_plan_id: String::new(),
            target_snapshot_id: target_snapshot_id.into(),
            target_block_height,
            target_state_root: target_state_root.into(),
            source_snapshot_ids,
            required_chunk_ids,
            required_custodian_root: required_custodian_root.into(),
            redaction_manifest_root: redaction_manifest_root.into(),
            expected_journal_entry_id: expected_journal_entry_id.into(),
            restore_window_start_height,
            restore_window_end_height,
            created_at_ms,
            operator_commitment: operator_commitment.into(),
            status,
        };
        plan.restore_plan_id = durable_restore_plan_id(&plan.identity_record());
        plan.validate()?;
        Ok(plan)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_restore_plan_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "target_snapshot_id": &self.target_snapshot_id,
            "target_block_height": self.target_block_height,
            "target_state_root": &self.target_state_root,
            "source_snapshot_ids": self.source_snapshot_ids.iter().cloned().collect::<Vec<_>>(),
            "required_chunk_ids": self.required_chunk_ids.iter().cloned().collect::<Vec<_>>(),
            "required_custodian_root": &self.required_custodian_root,
            "redaction_manifest_root": &self.redaction_manifest_root,
            "expected_journal_entry_id": &self.expected_journal_entry_id,
            "restore_window_start_height": self.restore_window_start_height,
            "restore_window_end_height": self.restore_window_end_height,
            "created_at_ms": self.created_at_ms,
            "operator_commitment": &self.operator_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_restore_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "restore_plan_id": &self.restore_plan_id,
            "target_snapshot_id": &self.target_snapshot_id,
            "target_block_height": self.target_block_height,
            "target_state_root": &self.target_state_root,
            "source_snapshot_ids": self.source_snapshot_ids.iter().cloned().collect::<Vec<_>>(),
            "source_snapshot_root": durable_string_set_root("DURABLE-RESTORE-SOURCE-SNAPSHOT", &self.source_snapshot_ids),
            "required_chunk_ids": self.required_chunk_ids.iter().cloned().collect::<Vec<_>>(),
            "required_chunk_root": durable_string_set_root("DURABLE-RESTORE-REQUIRED-CHUNK", &self.required_chunk_ids),
            "required_custodian_root": &self.required_custodian_root,
            "redaction_manifest_root": &self.redaction_manifest_root,
            "expected_journal_entry_id": &self.expected_journal_entry_id,
            "restore_window_start_height": self.restore_window_start_height,
            "restore_window_end_height": self.restore_window_end_height,
            "created_at_ms": self.created_at_ms,
            "operator_commitment": &self.operator_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn restore_plan_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-RESTORE-PLAN", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.restore_plan_id == durable_restore_plan_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.target_snapshot_id, "durable restore target snapshot")?;
        ensure_non_empty(&self.target_state_root, "durable restore target state root")?;
        ensure_non_empty(&self.operator_commitment, "durable restore operator")?;
        if self.source_snapshot_ids.is_empty() {
            return Err("durable restore plan requires a source snapshot".to_string());
        }
        validate_height_window(
            self.restore_window_start_height,
            self.restore_window_end_height,
            "durable restore window",
        )?;
        if !self.verify_id() {
            return Err("durable restore plan id mismatch".to_string());
        }
        Ok(self.restore_plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableErasureChunkManifest {
    pub chunk_id: String,
    pub snapshot_id: String,
    pub erasure_set_id: String,
    pub chunk_index: u64,
    pub shard_index: u64,
    pub original_shard_count: u64,
    pub parity_shard_count: u64,
    pub codec: DurableErasureCodec,
    pub plaintext_chunk_hash: String,
    pub encoded_chunk_hash: String,
    pub encrypted_chunk_hash: String,
    pub byte_count: u64,
    pub storage_location_commitment: String,
    pub custodian_commitment: String,
    pub retention_until_height: u64,
    pub created_at_ms: u64,
}

impl DurableErasureChunkManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: impl Into<String>,
        erasure_set_id: impl Into<String>,
        chunk_index: u64,
        shard_index: u64,
        original_shard_count: u64,
        parity_shard_count: u64,
        codec: DurableErasureCodec,
        plaintext_chunk_hash: impl Into<String>,
        encoded_chunk_hash: impl Into<String>,
        encrypted_chunk_hash: impl Into<String>,
        byte_count: u64,
        storage_location_commitment: impl Into<String>,
        custodian_commitment: impl Into<String>,
        retention_until_height: u64,
        created_at_ms: u64,
    ) -> DurableStateStoreResult<Self> {
        let mut manifest = Self {
            chunk_id: String::new(),
            snapshot_id: snapshot_id.into(),
            erasure_set_id: erasure_set_id.into(),
            chunk_index,
            shard_index,
            original_shard_count,
            parity_shard_count,
            codec,
            plaintext_chunk_hash: plaintext_chunk_hash.into(),
            encoded_chunk_hash: encoded_chunk_hash.into(),
            encrypted_chunk_hash: encrypted_chunk_hash.into(),
            byte_count,
            storage_location_commitment: storage_location_commitment.into(),
            custodian_commitment: custodian_commitment.into(),
            retention_until_height,
            created_at_ms,
        };
        manifest.chunk_id = durable_erasure_chunk_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn total_shards(&self) -> u64 {
        self.original_shard_count
            .saturating_add(self.parity_shard_count)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_erasure_chunk_manifest_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "snapshot_id": &self.snapshot_id,
            "erasure_set_id": &self.erasure_set_id,
            "chunk_index": self.chunk_index,
            "shard_index": self.shard_index,
            "original_shard_count": self.original_shard_count,
            "parity_shard_count": self.parity_shard_count,
            "codec": self.codec.as_str(),
            "plaintext_chunk_hash": &self.plaintext_chunk_hash,
            "encoded_chunk_hash": &self.encoded_chunk_hash,
            "encrypted_chunk_hash": &self.encrypted_chunk_hash,
            "byte_count": self.byte_count,
            "storage_location_commitment": &self.storage_location_commitment,
            "custodian_commitment": &self.custodian_commitment,
            "retention_until_height": self.retention_until_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_erasure_chunk_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "chunk_id": &self.chunk_id,
            "snapshot_id": &self.snapshot_id,
            "erasure_set_id": &self.erasure_set_id,
            "chunk_index": self.chunk_index,
            "shard_index": self.shard_index,
            "original_shard_count": self.original_shard_count,
            "parity_shard_count": self.parity_shard_count,
            "total_shards": self.total_shards(),
            "codec": self.codec.as_str(),
            "plaintext_chunk_hash": &self.plaintext_chunk_hash,
            "encoded_chunk_hash": &self.encoded_chunk_hash,
            "encrypted_chunk_hash": &self.encrypted_chunk_hash,
            "byte_count": self.byte_count,
            "storage_location_commitment": &self.storage_location_commitment,
            "custodian_commitment": &self.custodian_commitment,
            "retention_until_height": self.retention_until_height,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn chunk_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-ERASURE-CHUNK-MANIFEST", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.chunk_id == durable_erasure_chunk_manifest_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.snapshot_id, "durable chunk snapshot id")?;
        ensure_non_empty(&self.erasure_set_id, "durable chunk erasure set id")?;
        ensure_positive(self.original_shard_count, "durable chunk original shards")?;
        if self.codec != DurableErasureCodec::Identity {
            ensure_positive(self.parity_shard_count, "durable chunk parity shards")?;
        }
        if self.shard_index >= self.total_shards() {
            return Err("durable chunk shard index outside erasure set".to_string());
        }
        ensure_non_empty(&self.plaintext_chunk_hash, "durable chunk plaintext hash")?;
        ensure_non_empty(&self.encoded_chunk_hash, "durable chunk encoded hash")?;
        ensure_non_empty(&self.encrypted_chunk_hash, "durable chunk encrypted hash")?;
        ensure_positive(self.byte_count, "durable chunk byte count")?;
        ensure_non_empty(
            &self.storage_location_commitment,
            "durable chunk storage commitment",
        )?;
        ensure_non_empty(&self.custodian_commitment, "durable chunk custodian")?;
        if !self.verify_id() {
            return Err("durable erasure chunk manifest id mismatch".to_string());
        }
        Ok(self.chunk_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableRetentionPolicy {
    pub policy_id: String,
    pub label: String,
    pub min_recent_heights: u64,
    pub snapshot_interval: u64,
    pub archival_interval: u64,
    pub min_checkpoint_depth: u64,
    pub prune_below_height: u64,
    pub redact_after_height: u64,
    pub low_fee_sponsorship_required: bool,
    pub legal_hold_root: String,
    pub created_at_height: u64,
}

impl DurableRetentionPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        min_recent_heights: u64,
        snapshot_interval: u64,
        archival_interval: u64,
        min_checkpoint_depth: u64,
        prune_below_height: u64,
        redact_after_height: u64,
        low_fee_sponsorship_required: bool,
        legal_hold_root: impl Into<String>,
        created_at_height: u64,
    ) -> DurableStateStoreResult<Self> {
        let mut policy = Self {
            policy_id: String::new(),
            label: label.into(),
            min_recent_heights,
            snapshot_interval,
            archival_interval,
            min_checkpoint_depth,
            prune_below_height,
            redact_after_height,
            low_fee_sponsorship_required,
            legal_hold_root: legal_hold_root.into(),
            created_at_height,
        };
        policy.policy_id = durable_retention_policy_id(&policy.identity_record());
        policy.validate()?;
        Ok(policy)
    }

    pub fn devnet(created_at_height: u64) -> DurableStateStoreResult<Self> {
        Self::new(
            "devnet-default-retention",
            DURABLE_STATE_STORE_DEFAULT_RECENT_HEIGHTS,
            DURABLE_STATE_STORE_DEFAULT_SNAPSHOT_INTERVAL,
            DURABLE_STATE_STORE_DEFAULT_ARCHIVE_INTERVAL,
            12,
            0,
            DURABLE_STATE_STORE_DEFAULT_REDACTION_TTL_BLOCKS,
            true,
            &durable_state_store_string_root("DURABLE-LEGAL-HOLD", "none"),
            created_at_height,
        )
    }

    pub fn action_for_height(
        &self,
        current_height: u64,
        candidate_height: u64,
        checkpointed: bool,
        legal_hold: bool,
        sponsored: bool,
    ) -> DurableRetentionAction {
        if legal_hold {
            return DurableRetentionAction::RetainArchive;
        }
        if candidate_height.saturating_add(self.min_recent_heights) >= current_height {
            return DurableRetentionAction::RetainHot;
        }
        if checkpointed
            && current_height.saturating_sub(candidate_height) <= self.min_checkpoint_depth
        {
            return DurableRetentionAction::RetainHot;
        }
        if self.low_fee_sponsorship_required && !sponsored {
            return DurableRetentionAction::SponsorArchive;
        }
        if self.redact_after_height > 0
            && candidate_height.saturating_add(self.redact_after_height) < current_height
        {
            return DurableRetentionAction::Redact;
        }
        if self.prune_below_height > 0 && candidate_height < self.prune_below_height {
            return DurableRetentionAction::Prune;
        }
        if self.archival_interval > 0 && candidate_height % self.archival_interval == 0 {
            return DurableRetentionAction::RetainArchive;
        }
        DurableRetentionAction::Prune
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_retention_policy_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "label": &self.label,
            "min_recent_heights": self.min_recent_heights,
            "snapshot_interval": self.snapshot_interval,
            "archival_interval": self.archival_interval,
            "min_checkpoint_depth": self.min_checkpoint_depth,
            "prune_below_height": self.prune_below_height,
            "redact_after_height": self.redact_after_height,
            "low_fee_sponsorship_required": self.low_fee_sponsorship_required,
            "legal_hold_root": &self.legal_hold_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_retention_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "policy_id": &self.policy_id,
            "label": &self.label,
            "min_recent_heights": self.min_recent_heights,
            "snapshot_interval": self.snapshot_interval,
            "archival_interval": self.archival_interval,
            "min_checkpoint_depth": self.min_checkpoint_depth,
            "prune_below_height": self.prune_below_height,
            "redact_after_height": self.redact_after_height,
            "low_fee_sponsorship_required": self.low_fee_sponsorship_required,
            "legal_hold_root": &self.legal_hold_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-RETENTION-POLICY", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.policy_id == durable_retention_policy_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.label, "durable retention policy label")?;
        ensure_positive(
            self.min_recent_heights,
            "durable retention recent height window",
        )?;
        ensure_positive(
            self.snapshot_interval,
            "durable retention snapshot interval",
        )?;
        ensure_positive(self.archival_interval, "durable retention archive interval")?;
        ensure_non_empty(&self.legal_hold_root, "durable retention legal hold root")?;
        if !self.verify_id() {
            return Err("durable retention policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurablePruningDecision {
    pub decision_id: String,
    pub policy_id: String,
    pub subject_kind: DurableJournalEntryKind,
    pub subject_id: String,
    pub action: DurableRetentionAction,
    pub reason: DurableRetentionReason,
    pub decided_at_height: u64,
    pub effective_height: u64,
    pub evidence_root: String,
    pub operator_commitment: String,
}

impl DurablePruningDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: impl Into<String>,
        subject_kind: DurableJournalEntryKind,
        subject_id: impl Into<String>,
        action: DurableRetentionAction,
        reason: DurableRetentionReason,
        decided_at_height: u64,
        effective_height: u64,
        evidence_root: impl Into<String>,
        operator_commitment: impl Into<String>,
    ) -> DurableStateStoreResult<Self> {
        let mut decision = Self {
            decision_id: String::new(),
            policy_id: policy_id.into(),
            subject_kind,
            subject_id: subject_id.into(),
            action,
            reason,
            decided_at_height,
            effective_height,
            evidence_root: evidence_root.into(),
            operator_commitment: operator_commitment.into(),
        };
        decision.decision_id = durable_pruning_decision_id(&decision.identity_record());
        decision.validate()?;
        Ok(decision)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_pruning_decision_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "policy_id": &self.policy_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": &self.subject_id,
            "action": self.action.as_str(),
            "reason": self.reason.as_str(),
            "decided_at_height": self.decided_at_height,
            "effective_height": self.effective_height,
            "evidence_root": &self.evidence_root,
            "operator_commitment": &self.operator_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_pruning_decision",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "decision_id": &self.decision_id,
            "policy_id": &self.policy_id,
            "subject_kind": self.subject_kind.as_str(),
            "subject_id": &self.subject_id,
            "action": self.action.as_str(),
            "reason": self.reason.as_str(),
            "decided_at_height": self.decided_at_height,
            "effective_height": self.effective_height,
            "evidence_root": &self.evidence_root,
            "operator_commitment": &self.operator_commitment,
        })
    }

    pub fn decision_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-PRUNING-DECISION", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.decision_id == durable_pruning_decision_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.policy_id, "durable pruning policy id")?;
        ensure_non_empty(&self.subject_id, "durable pruning subject id")?;
        ensure_non_empty(&self.evidence_root, "durable pruning evidence root")?;
        ensure_non_empty(&self.operator_commitment, "durable pruning operator")?;
        if self.effective_height < self.decided_at_height {
            return Err("durable pruning decision effective height precedes decision".to_string());
        }
        if !self.verify_id() {
            return Err("durable pruning decision id mismatch".to_string());
        }
        Ok(self.decision_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableCheckpointNotarization {
    pub checkpoint_id: String,
    pub snapshot_id: String,
    pub block_height: u64,
    pub state_root: String,
    pub journal_root: String,
    pub checkpoint_root: String,
    pub notary_set_root: String,
    pub aggregate_signature_root: String,
    pub quorum_bps: u64,
    pub notarized_at_height: u64,
    pub monero_anchor_txid: String,
    pub status: DurableNotarizationStatus,
}

impl DurableCheckpointNotarization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snapshot_id: impl Into<String>,
        block_height: u64,
        state_root: impl Into<String>,
        journal_root: impl Into<String>,
        checkpoint_root: impl Into<String>,
        notary_set_root: impl Into<String>,
        aggregate_signature_root: impl Into<String>,
        quorum_bps: u64,
        notarized_at_height: u64,
        monero_anchor_txid: impl Into<String>,
        status: DurableNotarizationStatus,
    ) -> DurableStateStoreResult<Self> {
        let mut checkpoint = Self {
            checkpoint_id: String::new(),
            snapshot_id: snapshot_id.into(),
            block_height,
            state_root: state_root.into(),
            journal_root: journal_root.into(),
            checkpoint_root: checkpoint_root.into(),
            notary_set_root: notary_set_root.into(),
            aggregate_signature_root: aggregate_signature_root.into(),
            quorum_bps,
            notarized_at_height,
            monero_anchor_txid: monero_anchor_txid.into(),
            status,
        };
        checkpoint.checkpoint_id =
            durable_checkpoint_notarization_id(&checkpoint.identity_record());
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_checkpoint_notarization_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "snapshot_id": &self.snapshot_id,
            "block_height": self.block_height,
            "state_root": &self.state_root,
            "journal_root": &self.journal_root,
            "checkpoint_root": &self.checkpoint_root,
            "notary_set_root": &self.notary_set_root,
            "aggregate_signature_root": &self.aggregate_signature_root,
            "quorum_bps": self.quorum_bps,
            "notarized_at_height": self.notarized_at_height,
            "monero_anchor_txid": &self.monero_anchor_txid,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_checkpoint_notarization",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "checkpoint_id": &self.checkpoint_id,
            "snapshot_id": &self.snapshot_id,
            "block_height": self.block_height,
            "state_root": &self.state_root,
            "journal_root": &self.journal_root,
            "checkpoint_root": &self.checkpoint_root,
            "notary_set_root": &self.notary_set_root,
            "aggregate_signature_root": &self.aggregate_signature_root,
            "quorum_bps": self.quorum_bps,
            "notarized_at_height": self.notarized_at_height,
            "monero_anchor_txid": &self.monero_anchor_txid,
            "status": self.status.as_str(),
        })
    }

    pub fn notarization_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-CHECKPOINT-NOTARIZATION", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.checkpoint_id == durable_checkpoint_notarization_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.snapshot_id, "durable checkpoint snapshot")?;
        ensure_non_empty(&self.state_root, "durable checkpoint state root")?;
        ensure_non_empty(&self.journal_root, "durable checkpoint journal root")?;
        ensure_non_empty(&self.checkpoint_root, "durable checkpoint root")?;
        ensure_non_empty(&self.notary_set_root, "durable checkpoint notary set")?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "durable checkpoint aggregate signature",
        )?;
        validate_bps(self.quorum_bps, "durable checkpoint quorum")?;
        if self.notarized_at_height < self.block_height {
            return Err("durable checkpoint notarization precedes checkpoint height".to_string());
        }
        if !self.verify_id() {
            return Err("durable checkpoint notarization id mismatch".to_string());
        }
        Ok(self.notarization_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableCrashRecoveryIntent {
    pub intent_id: String,
    pub intent_kind: DurableCrashRecoveryIntentKind,
    pub recovery_epoch: u64,
    pub last_committed_entry_id: String,
    pub replay_from_entry_id: String,
    pub target_snapshot_id: String,
    pub observed_store_root: String,
    pub expected_store_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub opened_at_ms: u64,
    pub operator_commitment: String,
    pub status: DurableCrashRecoveryStatus,
}

impl DurableCrashRecoveryIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_kind: DurableCrashRecoveryIntentKind,
        recovery_epoch: u64,
        last_committed_entry_id: impl Into<String>,
        replay_from_entry_id: impl Into<String>,
        target_snapshot_id: impl Into<String>,
        observed_store_root: impl Into<String>,
        expected_store_root: impl Into<String>,
        opened_at_height: u64,
        expires_at_height: u64,
        opened_at_ms: u64,
        operator_commitment: impl Into<String>,
        status: DurableCrashRecoveryStatus,
    ) -> DurableStateStoreResult<Self> {
        let mut intent = Self {
            intent_id: String::new(),
            intent_kind,
            recovery_epoch,
            last_committed_entry_id: last_committed_entry_id.into(),
            replay_from_entry_id: replay_from_entry_id.into(),
            target_snapshot_id: target_snapshot_id.into(),
            observed_store_root: observed_store_root.into(),
            expected_store_root: expected_store_root.into(),
            opened_at_height,
            expires_at_height,
            opened_at_ms,
            operator_commitment: operator_commitment.into(),
            status,
        };
        intent.intent_id = durable_crash_recovery_intent_id(&intent.identity_record());
        intent.validate()?;
        Ok(intent)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_crash_recovery_intent_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "intent_kind": self.intent_kind.as_str(),
            "recovery_epoch": self.recovery_epoch,
            "last_committed_entry_id": &self.last_committed_entry_id,
            "replay_from_entry_id": &self.replay_from_entry_id,
            "target_snapshot_id": &self.target_snapshot_id,
            "observed_store_root": &self.observed_store_root,
            "expected_store_root": &self.expected_store_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "opened_at_ms": self.opened_at_ms,
            "operator_commitment": &self.operator_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_crash_recovery_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "intent_id": &self.intent_id,
            "intent_kind": self.intent_kind.as_str(),
            "recovery_epoch": self.recovery_epoch,
            "last_committed_entry_id": &self.last_committed_entry_id,
            "replay_from_entry_id": &self.replay_from_entry_id,
            "target_snapshot_id": &self.target_snapshot_id,
            "observed_store_root": &self.observed_store_root,
            "expected_store_root": &self.expected_store_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "opened_at_ms": self.opened_at_ms,
            "operator_commitment": &self.operator_commitment,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-CRASH-RECOVERY-INTENT", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.intent_id == durable_crash_recovery_intent_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(
            &self.observed_store_root,
            "durable crash intent observed store root",
        )?;
        ensure_non_empty(
            &self.expected_store_root,
            "durable crash intent expected store root",
        )?;
        ensure_non_empty(&self.operator_commitment, "durable crash intent operator")?;
        validate_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "durable crash intent ttl",
        )?;
        if !self.verify_id() {
            return Err("durable crash recovery intent id mismatch".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableLowFeeArchiveSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub archive_provider_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub covered_snapshot_root: String,
    pub covered_chunk_root: String,
    pub coverage_start_height: u64,
    pub coverage_end_height: u64,
    pub low_fee_lane_id: String,
    pub authorization_root: String,
    pub status: DurableArchiveSponsorshipStatus,
}

impl DurableLowFeeArchiveSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        archive_provider_commitment: impl Into<String>,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        reserved_fee_units: u64,
        spent_fee_units: u64,
        covered_snapshot_root: impl Into<String>,
        covered_chunk_root: impl Into<String>,
        coverage_start_height: u64,
        coverage_end_height: u64,
        low_fee_lane_id: impl Into<String>,
        authorization_root: impl Into<String>,
        status: DurableArchiveSponsorshipStatus,
    ) -> DurableStateStoreResult<Self> {
        let mut sponsorship = Self {
            sponsorship_id: String::new(),
            sponsor_commitment: sponsor_commitment.into(),
            archive_provider_commitment: archive_provider_commitment.into(),
            fee_asset_id: fee_asset_id.into(),
            max_fee_units,
            reserved_fee_units,
            spent_fee_units,
            covered_snapshot_root: covered_snapshot_root.into(),
            covered_chunk_root: covered_chunk_root.into(),
            coverage_start_height,
            coverage_end_height,
            low_fee_lane_id: low_fee_lane_id.into(),
            authorization_root: authorization_root.into(),
            status,
        };
        sponsorship.sponsorship_id =
            durable_low_fee_archive_sponsorship_id(&sponsorship.identity_record());
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_fee_units(&self) -> u64 {
        self.max_fee_units
            .saturating_sub(self.reserved_fee_units)
            .saturating_sub(self.spent_fee_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.active()
            && height >= self.coverage_start_height
            && height <= self.coverage_end_height
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_low_fee_archive_sponsorship_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "sponsor_commitment": &self.sponsor_commitment,
            "archive_provider_commitment": &self.archive_provider_commitment,
            "fee_asset_id": &self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "covered_snapshot_root": &self.covered_snapshot_root,
            "covered_chunk_root": &self.covered_chunk_root,
            "coverage_start_height": self.coverage_start_height,
            "coverage_end_height": self.coverage_end_height,
            "low_fee_lane_id": &self.low_fee_lane_id,
            "authorization_root": &self.authorization_root,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_low_fee_archive_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "sponsorship_id": &self.sponsorship_id,
            "sponsor_commitment": &self.sponsor_commitment,
            "archive_provider_commitment": &self.archive_provider_commitment,
            "fee_asset_id": &self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "available_fee_units": self.available_fee_units(),
            "covered_snapshot_root": &self.covered_snapshot_root,
            "covered_chunk_root": &self.covered_chunk_root,
            "coverage_start_height": self.coverage_start_height,
            "coverage_end_height": self.coverage_end_height,
            "low_fee_lane_id": &self.low_fee_lane_id,
            "authorization_root": &self.authorization_root,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        durable_state_store_payload_root(
            "DURABLE-LOW-FEE-ARCHIVE-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.sponsorship_id == durable_low_fee_archive_sponsorship_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.sponsor_commitment, "durable archive sponsor")?;
        ensure_non_empty(
            &self.archive_provider_commitment,
            "durable archive provider",
        )?;
        ensure_non_empty(&self.fee_asset_id, "durable archive fee asset")?;
        ensure_positive(self.max_fee_units, "durable archive max fee")?;
        if self.reserved_fee_units.saturating_add(self.spent_fee_units) > self.max_fee_units {
            return Err("durable archive sponsorship over-reserved".to_string());
        }
        ensure_non_empty(
            &self.covered_snapshot_root,
            "durable archive covered snapshot root",
        )?;
        ensure_non_empty(
            &self.covered_chunk_root,
            "durable archive covered chunk root",
        )?;
        validate_height_window(
            self.coverage_start_height,
            self.coverage_end_height,
            "durable archive coverage",
        )?;
        ensure_non_empty(&self.low_fee_lane_id, "durable archive low fee lane")?;
        ensure_non_empty(&self.authorization_root, "durable archive authorization")?;
        if !self.verify_id() {
            return Err("durable low fee archive sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableRedactionManifest {
    pub redaction_id: String,
    pub scope: DurableRedactionScope,
    pub policy: DurableRedactionPolicy,
    pub subject_id: String,
    pub snapshot_id: String,
    pub redacted_field_commitments: BTreeSet<String>,
    pub disclosed_field_root: String,
    pub redacted_record_root: String,
    pub salt_commitment_root: String,
    pub proof_root: String,
    pub authorized_by_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl DurableRedactionManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: DurableRedactionScope,
        policy: DurableRedactionPolicy,
        subject_id: impl Into<String>,
        snapshot_id: impl Into<String>,
        redacted_field_commitments: BTreeSet<String>,
        disclosed_field_root: impl Into<String>,
        redacted_record_root: impl Into<String>,
        salt_commitment_root: impl Into<String>,
        proof_root: impl Into<String>,
        authorized_by_commitment: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> DurableStateStoreResult<Self> {
        let mut manifest = Self {
            redaction_id: String::new(),
            scope,
            policy,
            subject_id: subject_id.into(),
            snapshot_id: snapshot_id.into(),
            redacted_field_commitments,
            disclosed_field_root: disclosed_field_root.into(),
            redacted_record_root: redacted_record_root.into(),
            salt_commitment_root: salt_commitment_root.into(),
            proof_root: proof_root.into(),
            authorized_by_commitment: authorized_by_commitment.into(),
            created_at_height,
            expires_at_height,
        };
        manifest.redaction_id = durable_redaction_manifest_id(&manifest.identity_record());
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_redaction_manifest_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "scope": self.scope.as_str(),
            "policy": self.policy.as_str(),
            "subject_id": &self.subject_id,
            "snapshot_id": &self.snapshot_id,
            "redacted_field_commitments": self.redacted_field_commitments.iter().cloned().collect::<Vec<_>>(),
            "disclosed_field_root": &self.disclosed_field_root,
            "redacted_record_root": &self.redacted_record_root,
            "salt_commitment_root": &self.salt_commitment_root,
            "proof_root": &self.proof_root,
            "authorized_by_commitment": &self.authorized_by_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_redaction_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "redaction_id": &self.redaction_id,
            "scope": self.scope.as_str(),
            "policy": self.policy.as_str(),
            "subject_id": &self.subject_id,
            "snapshot_id": &self.snapshot_id,
            "redacted_field_commitments": self.redacted_field_commitments.iter().cloned().collect::<Vec<_>>(),
            "redacted_field_root": durable_string_set_root("DURABLE-REDACTED-FIELD", &self.redacted_field_commitments),
            "disclosed_field_root": &self.disclosed_field_root,
            "redacted_record_root": &self.redacted_record_root,
            "salt_commitment_root": &self.salt_commitment_root,
            "proof_root": &self.proof_root,
            "authorized_by_commitment": &self.authorized_by_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn redaction_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-REDACTION-MANIFEST", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.redaction_id == durable_redaction_manifest_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.subject_id, "durable redaction subject")?;
        ensure_non_empty(&self.snapshot_id, "durable redaction snapshot")?;
        if self.redacted_field_commitments.is_empty() {
            return Err("durable redaction manifest requires field commitments".to_string());
        }
        ensure_non_empty(
            &self.disclosed_field_root,
            "durable redaction disclosure root",
        )?;
        ensure_non_empty(&self.redacted_record_root, "durable redaction record root")?;
        ensure_non_empty(&self.salt_commitment_root, "durable redaction salt root")?;
        ensure_non_empty(&self.proof_root, "durable redaction proof root")?;
        ensure_non_empty(
            &self.authorized_by_commitment,
            "durable redaction authorization",
        )?;
        validate_height_window(
            self.created_at_height,
            self.expires_at_height,
            "durable redaction ttl",
        )?;
        if !self.verify_id() {
            return Err("durable redaction manifest id mismatch".to_string());
        }
        Ok(self.redaction_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurablePqStorageCustodianAttestation {
    pub attestation_id: String,
    pub custodian_id: String,
    pub custodian_commitment: String,
    pub snapshot_id: String,
    pub chunk_id: String,
    pub storage_root: String,
    pub availability_window_start_height: u64,
    pub availability_window_end_height: u64,
    pub capacity_bytes: u64,
    pub pq_signature_scheme: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: DurableCustodianAttestationStatus,
}

impl DurablePqStorageCustodianAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        custodian_id: impl Into<String>,
        custodian_commitment: impl Into<String>,
        snapshot_id: impl Into<String>,
        chunk_id: impl Into<String>,
        storage_root: impl Into<String>,
        availability_window_start_height: u64,
        availability_window_end_height: u64,
        capacity_bytes: u64,
        pq_signature_scheme: impl Into<String>,
        pq_public_key_commitment: impl Into<String>,
        pq_signature_root: impl Into<String>,
        signed_at_height: u64,
        expires_at_height: u64,
        status: DurableCustodianAttestationStatus,
    ) -> DurableStateStoreResult<Self> {
        let mut attestation = Self {
            attestation_id: String::new(),
            custodian_id: custodian_id.into(),
            custodian_commitment: custodian_commitment.into(),
            snapshot_id: snapshot_id.into(),
            chunk_id: chunk_id.into(),
            storage_root: storage_root.into(),
            availability_window_start_height,
            availability_window_end_height,
            capacity_bytes,
            pq_signature_scheme: pq_signature_scheme.into(),
            pq_public_key_commitment: pq_public_key_commitment.into(),
            pq_signature_root: pq_signature_root.into(),
            signed_at_height,
            expires_at_height,
            status,
        };
        attestation.attestation_id =
            durable_pq_custodian_attestation_id(&attestation.identity_record());
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepted()
            && height >= self.availability_window_start_height
            && height <= self.availability_window_end_height
            && height <= self.expires_at_height
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_pq_storage_custodian_attestation_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "custodian_id": &self.custodian_id,
            "custodian_commitment": &self.custodian_commitment,
            "snapshot_id": &self.snapshot_id,
            "chunk_id": &self.chunk_id,
            "storage_root": &self.storage_root,
            "availability_window_start_height": self.availability_window_start_height,
            "availability_window_end_height": self.availability_window_end_height,
            "capacity_bytes": self.capacity_bytes,
            "pq_signature_scheme": &self.pq_signature_scheme,
            "pq_public_key_commitment": &self.pq_public_key_commitment,
            "pq_signature_root": &self.pq_signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_pq_storage_custodian_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "attestation_id": &self.attestation_id,
            "custodian_id": &self.custodian_id,
            "custodian_commitment": &self.custodian_commitment,
            "snapshot_id": &self.snapshot_id,
            "chunk_id": &self.chunk_id,
            "storage_root": &self.storage_root,
            "availability_window_start_height": self.availability_window_start_height,
            "availability_window_end_height": self.availability_window_end_height,
            "capacity_bytes": self.capacity_bytes,
            "pq_signature_scheme": &self.pq_signature_scheme,
            "pq_public_key_commitment": &self.pq_public_key_commitment,
            "pq_signature_root": &self.pq_signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn attestation_root(&self) -> String {
        durable_state_store_payload_root(
            "DURABLE-PQ-STORAGE-CUSTODIAN-ATTESTATION",
            &self.public_record(),
        )
    }

    pub fn verify_id(&self) -> bool {
        self.attestation_id == durable_pq_custodian_attestation_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(&self.custodian_id, "durable custodian id")?;
        ensure_non_empty(&self.custodian_commitment, "durable custodian commitment")?;
        ensure_non_empty(&self.snapshot_id, "durable custodian snapshot")?;
        ensure_non_empty(&self.storage_root, "durable custodian storage root")?;
        validate_height_window(
            self.availability_window_start_height,
            self.availability_window_end_height,
            "durable custodian availability",
        )?;
        ensure_positive(self.capacity_bytes, "durable custodian capacity")?;
        ensure_non_empty(&self.pq_signature_scheme, "durable custodian pq scheme")?;
        ensure_non_empty(
            &self.pq_public_key_commitment,
            "durable custodian pq public key",
        )?;
        ensure_non_empty(&self.pq_signature_root, "durable custodian pq signature")?;
        validate_height_window(
            self.signed_at_height,
            self.expires_at_height,
            "durable custodian signature ttl",
        )?;
        if !self.verify_id() {
            return Err("durable pq storage custodian attestation id mismatch".to_string());
        }
        Ok(self.attestation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableStateValidationReport {
    pub validation_id: String,
    pub height: u64,
    pub expected_state_root: String,
    pub observed_state_root: String,
    pub roots_root: String,
    pub counters_root: String,
    pub checked_record_root: String,
    pub issue_commitments: BTreeSet<String>,
    pub severity: DurableValidationSeverity,
    pub status: DurableValidationStatus,
    pub validator_commitment: String,
    pub created_at_ms: u64,
}

impl DurableStateValidationReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        expected_state_root: impl Into<String>,
        observed_state_root: impl Into<String>,
        roots_root: impl Into<String>,
        counters_root: impl Into<String>,
        checked_record_root: impl Into<String>,
        issue_commitments: BTreeSet<String>,
        severity: DurableValidationSeverity,
        status: DurableValidationStatus,
        validator_commitment: impl Into<String>,
        created_at_ms: u64,
    ) -> DurableStateStoreResult<Self> {
        let mut report = Self {
            validation_id: String::new(),
            height,
            expected_state_root: expected_state_root.into(),
            observed_state_root: observed_state_root.into(),
            roots_root: roots_root.into(),
            counters_root: counters_root.into(),
            checked_record_root: checked_record_root.into(),
            issue_commitments,
            severity,
            status,
            validator_commitment: validator_commitment.into(),
            created_at_ms,
        };
        report.validation_id = durable_validation_report_id(&report.identity_record());
        report.validate()?;
        Ok(report)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "durable_state_validation_report_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "height": self.height,
            "expected_state_root": &self.expected_state_root,
            "observed_state_root": &self.observed_state_root,
            "roots_root": &self.roots_root,
            "counters_root": &self.counters_root,
            "checked_record_root": &self.checked_record_root,
            "issue_commitments": self.issue_commitments.iter().cloned().collect::<Vec<_>>(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "validator_commitment": &self.validator_commitment,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_state_validation_report",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "validation_id": &self.validation_id,
            "height": self.height,
            "expected_state_root": &self.expected_state_root,
            "observed_state_root": &self.observed_state_root,
            "roots_root": &self.roots_root,
            "counters_root": &self.counters_root,
            "checked_record_root": &self.checked_record_root,
            "issue_commitments": self.issue_commitments.iter().cloned().collect::<Vec<_>>(),
            "issue_root": durable_string_set_root("DURABLE-VALIDATION-ISSUE", &self.issue_commitments),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "validator_commitment": &self.validator_commitment,
            "created_at_ms": self.created_at_ms,
        })
    }

    pub fn validation_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-STATE-VALIDATION-REPORT", &self.public_record())
    }

    pub fn verify_id(&self) -> bool {
        self.validation_id == durable_validation_report_id(&self.identity_record())
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        ensure_non_empty(
            &self.expected_state_root,
            "durable validation expected root",
        )?;
        ensure_non_empty(
            &self.observed_state_root,
            "durable validation observed root",
        )?;
        ensure_non_empty(&self.roots_root, "durable validation roots root")?;
        ensure_non_empty(&self.counters_root, "durable validation counters root")?;
        ensure_non_empty(
            &self.checked_record_root,
            "durable validation checked record root",
        )?;
        ensure_non_empty(&self.validator_commitment, "durable validation validator")?;
        if self.status == DurableValidationStatus::Passed
            && self.expected_state_root != self.observed_state_root
        {
            return Err("durable validation passed with mismatched roots".to_string());
        }
        if self.severity.blocks_restore() && self.issue_commitments.is_empty() {
            return Err(
                "durable validation blocking severity requires issue commitment".to_string(),
            );
        }
        if !self.verify_id() {
            return Err("durable validation report id mismatch".to_string());
        }
        Ok(self.validation_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableStateStoreRoots {
    pub bounds_root: String,
    pub journal_root: String,
    pub snapshot_manifest_root: String,
    pub restore_plan_root: String,
    pub erasure_chunk_manifest_root: String,
    pub retention_policy_root: String,
    pub pruning_decision_root: String,
    pub checkpoint_notarization_root: String,
    pub crash_recovery_intent_root: String,
    pub low_fee_archive_sponsorship_root: String,
    pub redaction_manifest_root: String,
    pub pq_custodian_attestation_root: String,
    pub validation_report_root: String,
    pub state_root: String,
}

impl DurableStateStoreRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_state_store_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "bounds_root": &self.bounds_root,
            "journal_root": &self.journal_root,
            "snapshot_manifest_root": &self.snapshot_manifest_root,
            "restore_plan_root": &self.restore_plan_root,
            "erasure_chunk_manifest_root": &self.erasure_chunk_manifest_root,
            "retention_policy_root": &self.retention_policy_root,
            "pruning_decision_root": &self.pruning_decision_root,
            "checkpoint_notarization_root": &self.checkpoint_notarization_root,
            "crash_recovery_intent_root": &self.crash_recovery_intent_root,
            "low_fee_archive_sponsorship_root": &self.low_fee_archive_sponsorship_root,
            "redaction_manifest_root": &self.redaction_manifest_root,
            "pq_custodian_attestation_root": &self.pq_custodian_attestation_root,
            "validation_report_root": &self.validation_report_root,
            "state_root": &self.state_root,
        })
    }

    pub fn aggregate_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-STATE-STORE-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableStateStoreCounters {
    pub height: u64,
    pub journal_entry_count: u64,
    pub committed_journal_entry_count: u64,
    pub snapshot_manifest_count: u64,
    pub finalized_snapshot_count: u64,
    pub restore_plan_count: u64,
    pub open_restore_plan_count: u64,
    pub erasure_chunk_manifest_count: u64,
    pub retention_policy_count: u64,
    pub pruning_decision_count: u64,
    pub destructive_pruning_decision_count: u64,
    pub checkpoint_notarization_count: u64,
    pub accepted_checkpoint_count: u64,
    pub crash_recovery_intent_count: u64,
    pub active_crash_recovery_intent_count: u64,
    pub low_fee_archive_sponsorship_count: u64,
    pub active_low_fee_archive_sponsorship_count: u64,
    pub redaction_manifest_count: u64,
    pub pq_custodian_attestation_count: u64,
    pub accepted_pq_custodian_attestation_count: u64,
    pub validation_report_count: u64,
    pub accepted_validation_report_count: u64,
    pub total_logical_snapshot_bytes: u64,
    pub total_encoded_snapshot_bytes: u64,
    pub total_erasure_chunk_bytes: u64,
    pub total_sponsored_fee_units: u64,
    pub total_reserved_fee_units: u64,
    pub total_spent_fee_units: u64,
}

impl DurableStateStoreCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "durable_state_store_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "height": self.height,
            "journal_entry_count": self.journal_entry_count,
            "committed_journal_entry_count": self.committed_journal_entry_count,
            "snapshot_manifest_count": self.snapshot_manifest_count,
            "finalized_snapshot_count": self.finalized_snapshot_count,
            "restore_plan_count": self.restore_plan_count,
            "open_restore_plan_count": self.open_restore_plan_count,
            "erasure_chunk_manifest_count": self.erasure_chunk_manifest_count,
            "retention_policy_count": self.retention_policy_count,
            "pruning_decision_count": self.pruning_decision_count,
            "destructive_pruning_decision_count": self.destructive_pruning_decision_count,
            "checkpoint_notarization_count": self.checkpoint_notarization_count,
            "accepted_checkpoint_count": self.accepted_checkpoint_count,
            "crash_recovery_intent_count": self.crash_recovery_intent_count,
            "active_crash_recovery_intent_count": self.active_crash_recovery_intent_count,
            "low_fee_archive_sponsorship_count": self.low_fee_archive_sponsorship_count,
            "active_low_fee_archive_sponsorship_count": self.active_low_fee_archive_sponsorship_count,
            "redaction_manifest_count": self.redaction_manifest_count,
            "pq_custodian_attestation_count": self.pq_custodian_attestation_count,
            "accepted_pq_custodian_attestation_count": self.accepted_pq_custodian_attestation_count,
            "validation_report_count": self.validation_report_count,
            "accepted_validation_report_count": self.accepted_validation_report_count,
            "total_logical_snapshot_bytes": self.total_logical_snapshot_bytes,
            "total_encoded_snapshot_bytes": self.total_encoded_snapshot_bytes,
            "total_erasure_chunk_bytes": self.total_erasure_chunk_bytes,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_reserved_fee_units": self.total_reserved_fee_units,
            "total_spent_fee_units": self.total_spent_fee_units,
        })
    }

    pub fn counters_root(&self) -> String {
        durable_state_store_payload_root("DURABLE-STATE-STORE-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableStateStoreState {
    pub height: u64,
    pub bounds: DurableStateStoreBounds,
    pub latest_journal_entry_id: String,
    pub latest_finalized_snapshot_id: String,
    pub journal_entries: Vec<DurableStateJournalEntry>,
    pub snapshot_manifests: BTreeMap<String, DurableSnapshotManifest>,
    pub restore_plans: BTreeMap<String, DurableRestorePlan>,
    pub erasure_chunk_manifests: BTreeMap<String, DurableErasureChunkManifest>,
    pub retention_policies: BTreeMap<String, DurableRetentionPolicy>,
    pub pruning_decisions: BTreeMap<String, DurablePruningDecision>,
    pub checkpoint_notarizations: BTreeMap<String, DurableCheckpointNotarization>,
    pub crash_recovery_intents: BTreeMap<String, DurableCrashRecoveryIntent>,
    pub low_fee_archive_sponsorships: BTreeMap<String, DurableLowFeeArchiveSponsorship>,
    pub redaction_manifests: BTreeMap<String, DurableRedactionManifest>,
    pub pq_custodian_attestations: BTreeMap<String, DurablePqStorageCustodianAttestation>,
    pub validation_reports: BTreeMap<String, DurableStateValidationReport>,
}

impl Default for DurableStateStoreState {
    fn default() -> Self {
        Self::new()
    }
}

impl DurableStateStoreState {
    pub fn new() -> Self {
        Self {
            height: 0,
            bounds: DurableStateStoreBounds::default(),
            latest_journal_entry_id: String::new(),
            latest_finalized_snapshot_id: String::new(),
            journal_entries: Vec::new(),
            snapshot_manifests: BTreeMap::new(),
            restore_plans: BTreeMap::new(),
            erasure_chunk_manifests: BTreeMap::new(),
            retention_policies: BTreeMap::new(),
            pruning_decisions: BTreeMap::new(),
            checkpoint_notarizations: BTreeMap::new(),
            crash_recovery_intents: BTreeMap::new(),
            low_fee_archive_sponsorships: BTreeMap::new(),
            redaction_manifests: BTreeMap::new(),
            pq_custodian_attestations: BTreeMap::new(),
            validation_reports: BTreeMap::new(),
        }
    }

    pub fn with_bounds(bounds: DurableStateStoreBounds) -> DurableStateStoreResult<Self> {
        bounds.validate()?;
        let mut state = Self::new();
        state.bounds = bounds;
        Ok(state)
    }

    pub fn devnet() -> DurableStateStoreResult<Self> {
        let mut state = Self::new();
        state.set_height(32)?;

        let policy = DurableRetentionPolicy::devnet(1)?;
        let policy_id = state.insert_retention_policy(policy)?;

        let component_roots = btree_map([
            ("account", devnet_root("account", "state")),
            ("asset", devnet_root("asset", "state")),
            ("bridge", devnet_root("bridge", "state")),
            ("fee", devnet_root("fee", "state")),
            ("note", devnet_root("note", "state")),
        ]);
        let service_roots = btree_map([
            ("availability", devnet_root("availability", "service")),
            ("network", devnet_root("network", "service")),
            ("proof", devnet_root("proof", "service")),
        ]);
        let preliminary_snapshot = DurableSnapshotManifest::new(
            DurableSnapshotKind::Full,
            32,
            devnet_root("block", "32"),
            devnet_root("block", "31"),
            devnet_root("state", "32"),
            devnet_root("execution", "32"),
            component_roots.clone(),
            service_roots.clone(),
            "",
            merkle_root("DURABLE-ERASURE-CHUNK-MANIFEST", &[]),
            0,
            8_192,
            0,
            merkle_root("DURABLE-REDACTION-MANIFEST", &[]),
            merkle_root("DURABLE-PQ-STORAGE-CUSTODIAN-ATTESTATION", &[]),
            1_000,
            true,
        )?;
        let chunk = DurableErasureChunkManifest::new(
            preliminary_snapshot.snapshot_id.clone(),
            devnet_root("erasure-set", "32"),
            0,
            0,
            4,
            2,
            DurableErasureCodec::ReedSolomon,
            devnet_root("plaintext", "chunk-0"),
            devnet_root("encoded", "chunk-0"),
            devnet_root("encrypted", "chunk-0"),
            2_048,
            "commitment:devnet-storage-location",
            "commitment:devnet-custodian",
            32 + DURABLE_STATE_STORE_DEFAULT_RECENT_HEIGHTS,
            1_001,
        )?;
        let snapshot = DurableSnapshotManifest::new(
            DurableSnapshotKind::Full,
            32,
            devnet_root("block", "32"),
            devnet_root("block", "31"),
            devnet_root("state", "32"),
            devnet_root("execution", "32"),
            component_roots,
            service_roots,
            "",
            durable_erasure_chunk_manifest_root(&[chunk.clone()]),
            1,
            8_192,
            2_048,
            merkle_root("DURABLE-REDACTION-MANIFEST", &[]),
            merkle_root("DURABLE-PQ-STORAGE-CUSTODIAN-ATTESTATION", &[]),
            1_000,
            true,
        )?;
        let snapshot_id = state.insert_snapshot_manifest(snapshot.clone())?;
        let chunk_id = state.insert_erasure_chunk_manifest(chunk.clone())?;

        let checkpoint = DurableCheckpointNotarization::new(
            snapshot_id.clone(),
            32,
            snapshot.state_root.clone(),
            state.journal_root(),
            snapshot.snapshot_root(),
            devnet_root("notary-set", "storage"),
            devnet_root("aggregate-signature", "checkpoint"),
            6_667,
            34,
            "monero-devnet-anchor-txid",
            DurableNotarizationStatus::QuorumCertified,
        )?;
        state.insert_checkpoint_notarization(checkpoint)?;

        let crash_intent = DurableCrashRecoveryIntent::new(
            DurableCrashRecoveryIntentKind::ReplayJournal,
            1,
            state.latest_journal_entry_id.clone(),
            state.latest_journal_entry_id.clone(),
            snapshot_id.clone(),
            state.state_root(),
            state.state_root(),
            35,
            35 + DURABLE_STATE_STORE_DEFAULT_CRASH_INTENT_TTL_BLOCKS,
            1_002,
            DURABLE_STATE_STORE_DEVNET_OPERATOR,
            DurableCrashRecoveryStatus::Open,
        )?;
        state.insert_crash_recovery_intent(crash_intent)?;

        let sponsorship = DurableLowFeeArchiveSponsorship::new(
            "commitment:devnet-archive-sponsor",
            "commitment:devnet-archive-provider",
            DURABLE_STATE_STORE_DEFAULT_LOW_FEE_ASSET_ID,
            500_000,
            50_000,
            0,
            durable_string_set_root(
                "DURABLE-SPONSORED-SNAPSHOT",
                &btree_set([snapshot_id.as_str()]),
            ),
            durable_string_set_root("DURABLE-SPONSORED-CHUNK", &btree_set([chunk_id.as_str()])),
            32,
            32 + DURABLE_STATE_STORE_DEFAULT_RECENT_HEIGHTS,
            "low-fee-archive-devnet",
            devnet_root("archive-auth", "sponsor"),
            DurableArchiveSponsorshipStatus::Active,
        )?;
        state.insert_low_fee_archive_sponsorship(sponsorship)?;

        let redaction = DurableRedactionManifest::new(
            DurableRedactionScope::Snapshot,
            DurableRedactionPolicy::CommitmentOnly,
            snapshot_id.clone(),
            snapshot_id.clone(),
            btree_set(["commitment:private-note-path", "commitment:view-tag-path"]),
            devnet_root("disclosed-fields", "snapshot"),
            devnet_root("redacted-record", "snapshot"),
            devnet_root("salt", "snapshot"),
            devnet_root("redaction-proof", "snapshot"),
            "commitment:devnet-redaction-authority",
            32,
            32 + DURABLE_STATE_STORE_DEFAULT_REDACTION_TTL_BLOCKS,
        )?;
        state.insert_redaction_manifest(redaction)?;

        let attestation = DurablePqStorageCustodianAttestation::new(
            DURABLE_STATE_STORE_DEVNET_CUSTODIAN,
            "commitment:devnet-custodian",
            snapshot_id.clone(),
            chunk_id.clone(),
            chunk.chunk_root(),
            32,
            32 + DURABLE_STATE_STORE_DEFAULT_CUSTODIAN_TTL_BLOCKS,
            1_048_576,
            "ML-DSA-65",
            "commitment:devnet-custodian-pq-key",
            devnet_root("custodian-signature", "chunk-0"),
            33,
            33 + DURABLE_STATE_STORE_DEFAULT_CUSTODIAN_TTL_BLOCKS,
            DurableCustodianAttestationStatus::Accepted,
        )?;
        state.insert_pq_custodian_attestation(attestation)?;

        let restore_plan = DurableRestorePlan::new(
            snapshot_id.clone(),
            32,
            snapshot.state_root.clone(),
            btree_set([snapshot_id.as_str()]),
            btree_set([chunk_id.as_str()]),
            state.pq_custodian_attestation_root(),
            state.redaction_manifest_root(),
            state.latest_journal_entry_id.clone(),
            32,
            32 + DURABLE_STATE_STORE_DEFAULT_RESTORE_WINDOW_BLOCKS,
            1_003,
            DURABLE_STATE_STORE_DEVNET_OPERATOR,
            DurableRestorePlanStatus::Ready,
        )?;
        state.insert_restore_plan(restore_plan)?;

        let pruning = DurablePruningDecision::new(
            policy_id,
            DurableJournalEntryKind::ErasureChunkManifest,
            chunk_id,
            DurableRetentionAction::RetainArchive,
            DurableRetentionReason::LowFeeSponsored,
            36,
            36,
            devnet_root("retention-evidence", "chunk-0"),
            DURABLE_STATE_STORE_DEVNET_OPERATOR,
        )?;
        state.insert_pruning_decision(pruning)?;

        let roots = state.roots();
        let counters = state.counters();
        let validation = DurableStateValidationReport::new(
            state.height,
            roots.state_root.clone(),
            roots.state_root.clone(),
            roots.aggregate_root(),
            counters.counters_root(),
            state.public_record_root(),
            BTreeSet::new(),
            DurableValidationSeverity::Info,
            DurableValidationStatus::Passed,
            "commitment:devnet-validator",
            1_004,
        )?;
        state.insert_validation_report(validation)?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> DurableStateStoreResult<()> {
        if height < self.height {
            return Err("durable state store height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn insert_snapshot_manifest(
        &mut self,
        manifest: DurableSnapshotManifest,
    ) -> DurableStateStoreResult<String> {
        manifest.validate()?;
        ensure_room(
            self.snapshot_manifests.len(),
            self.bounds.max_snapshot_manifests,
            "durable snapshot manifest",
        )?;
        self.ensure_journal_room()?;
        let id = manifest.snapshot_id.clone();
        let root = manifest.snapshot_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.snapshot_manifests,
            id.clone(),
            manifest.clone(),
            "durable snapshot manifest",
        )?;
        if manifest.finalized {
            self.latest_finalized_snapshot_id = id.clone();
        }
        let collection_root = self.snapshot_manifest_root();
        self.append_journal_entry(
            DurableJournalEntryKind::SnapshotManifest,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            manifest.block_height,
            manifest.created_at_ms,
        )?;
        Ok(id)
    }

    pub fn insert_restore_plan(
        &mut self,
        plan: DurableRestorePlan,
    ) -> DurableStateStoreResult<String> {
        plan.validate()?;
        ensure_room(
            self.restore_plans.len(),
            self.bounds.max_restore_plans,
            "durable restore plan",
        )?;
        self.ensure_journal_room()?;
        if !self
            .snapshot_manifests
            .contains_key(&plan.target_snapshot_id)
        {
            return Err("durable restore plan references unknown target snapshot".to_string());
        }
        for snapshot_id in &plan.source_snapshot_ids {
            if !self.snapshot_manifests.contains_key(snapshot_id) {
                return Err("durable restore plan references unknown source snapshot".to_string());
            }
        }
        for chunk_id in &plan.required_chunk_ids {
            if !self.erasure_chunk_manifests.contains_key(chunk_id) {
                return Err("durable restore plan references unknown chunk".to_string());
            }
        }
        let id = plan.restore_plan_id.clone();
        let root = plan.restore_plan_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.restore_plans,
            id.clone(),
            plan.clone(),
            "durable restore plan",
        )?;
        let collection_root = self.restore_plan_root();
        self.append_journal_entry(
            DurableJournalEntryKind::RestorePlan,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            plan.target_block_height,
            plan.created_at_ms,
        )?;
        Ok(id)
    }

    pub fn insert_erasure_chunk_manifest(
        &mut self,
        manifest: DurableErasureChunkManifest,
    ) -> DurableStateStoreResult<String> {
        manifest.validate()?;
        ensure_room(
            self.erasure_chunk_manifests.len(),
            self.bounds.max_erasure_chunk_manifests,
            "durable erasure chunk manifest",
        )?;
        self.ensure_journal_room()?;
        if !self.snapshot_manifests.contains_key(&manifest.snapshot_id) {
            return Err("durable erasure chunk references unknown snapshot".to_string());
        }
        let id = manifest.chunk_id.clone();
        let root = manifest.chunk_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.erasure_chunk_manifests,
            id.clone(),
            manifest.clone(),
            "durable erasure chunk manifest",
        )?;
        let collection_root = self.erasure_chunk_manifest_root();
        self.append_journal_entry(
            DurableJournalEntryKind::ErasureChunkManifest,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            self.height,
            manifest.created_at_ms,
        )?;
        Ok(id)
    }

    pub fn insert_retention_policy(
        &mut self,
        policy: DurableRetentionPolicy,
    ) -> DurableStateStoreResult<String> {
        policy.validate()?;
        ensure_room(
            self.retention_policies.len(),
            self.bounds.max_retention_policies,
            "durable retention policy",
        )?;
        self.ensure_journal_room()?;
        let id = policy.policy_id.clone();
        let root = policy.policy_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.retention_policies,
            id.clone(),
            policy.clone(),
            "durable retention policy",
        )?;
        let collection_root = self.retention_policy_root();
        self.append_journal_entry(
            DurableJournalEntryKind::RetentionPolicy,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            policy.created_at_height,
            0,
        )?;
        Ok(id)
    }

    pub fn insert_pruning_decision(
        &mut self,
        decision: DurablePruningDecision,
    ) -> DurableStateStoreResult<String> {
        decision.validate()?;
        ensure_room(
            self.pruning_decisions.len(),
            self.bounds.max_pruning_decisions,
            "durable pruning decision",
        )?;
        self.ensure_journal_room()?;
        if !self.retention_policies.contains_key(&decision.policy_id) {
            return Err("durable pruning decision references unknown policy".to_string());
        }
        let id = decision.decision_id.clone();
        let root = decision.decision_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.pruning_decisions,
            id.clone(),
            decision.clone(),
            "durable pruning decision",
        )?;
        let collection_root = self.pruning_decision_root();
        self.append_journal_entry(
            DurableJournalEntryKind::PruningDecision,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            decision.decided_at_height,
            0,
        )?;
        Ok(id)
    }

    pub fn insert_checkpoint_notarization(
        &mut self,
        checkpoint: DurableCheckpointNotarization,
    ) -> DurableStateStoreResult<String> {
        checkpoint.validate()?;
        ensure_room(
            self.checkpoint_notarizations.len(),
            self.bounds.max_checkpoint_notarizations,
            "durable checkpoint notarization",
        )?;
        self.ensure_journal_room()?;
        let snapshot = self
            .snapshot_manifests
            .get(&checkpoint.snapshot_id)
            .ok_or_else(|| "durable checkpoint references unknown snapshot".to_string())?;
        if snapshot.state_root != checkpoint.state_root {
            return Err("durable checkpoint state root mismatches snapshot".to_string());
        }
        let id = checkpoint.checkpoint_id.clone();
        let root = checkpoint.notarization_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.checkpoint_notarizations,
            id.clone(),
            checkpoint.clone(),
            "durable checkpoint notarization",
        )?;
        let collection_root = self.checkpoint_notarization_root();
        self.append_journal_entry(
            DurableJournalEntryKind::CheckpointNotarization,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            checkpoint.notarized_at_height,
            0,
        )?;
        Ok(id)
    }

    pub fn insert_crash_recovery_intent(
        &mut self,
        intent: DurableCrashRecoveryIntent,
    ) -> DurableStateStoreResult<String> {
        intent.validate()?;
        ensure_room(
            self.crash_recovery_intents.len(),
            self.bounds.max_crash_recovery_intents,
            "durable crash recovery intent",
        )?;
        self.ensure_journal_room()?;
        if !intent.target_snapshot_id.is_empty()
            && !self
                .snapshot_manifests
                .contains_key(&intent.target_snapshot_id)
        {
            return Err("durable crash recovery intent references unknown snapshot".to_string());
        }
        let id = intent.intent_id.clone();
        let root = intent.intent_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.crash_recovery_intents,
            id.clone(),
            intent.clone(),
            "durable crash recovery intent",
        )?;
        let collection_root = self.crash_recovery_intent_root();
        self.append_journal_entry(
            DurableJournalEntryKind::CrashRecoveryIntent,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            intent.opened_at_height,
            intent.opened_at_ms,
        )?;
        Ok(id)
    }

    pub fn insert_low_fee_archive_sponsorship(
        &mut self,
        sponsorship: DurableLowFeeArchiveSponsorship,
    ) -> DurableStateStoreResult<String> {
        sponsorship.validate()?;
        ensure_room(
            self.low_fee_archive_sponsorships.len(),
            self.bounds.max_archive_sponsorships,
            "durable low fee archive sponsorship",
        )?;
        self.ensure_journal_room()?;
        let id = sponsorship.sponsorship_id.clone();
        let root = sponsorship.sponsorship_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.low_fee_archive_sponsorships,
            id.clone(),
            sponsorship.clone(),
            "durable low fee archive sponsorship",
        )?;
        let collection_root = self.low_fee_archive_sponsorship_root();
        self.append_journal_entry(
            DurableJournalEntryKind::LowFeeArchiveSponsorship,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            sponsorship.coverage_start_height,
            0,
        )?;
        Ok(id)
    }

    pub fn insert_redaction_manifest(
        &mut self,
        manifest: DurableRedactionManifest,
    ) -> DurableStateStoreResult<String> {
        manifest.validate()?;
        ensure_room(
            self.redaction_manifests.len(),
            self.bounds.max_redaction_manifests,
            "durable redaction manifest",
        )?;
        self.ensure_journal_room()?;
        if !self.snapshot_manifests.contains_key(&manifest.snapshot_id) {
            return Err("durable redaction references unknown snapshot".to_string());
        }
        let id = manifest.redaction_id.clone();
        let root = manifest.redaction_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.redaction_manifests,
            id.clone(),
            manifest.clone(),
            "durable redaction manifest",
        )?;
        let collection_root = self.redaction_manifest_root();
        self.append_journal_entry(
            DurableJournalEntryKind::RedactionManifest,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            manifest.created_at_height,
            0,
        )?;
        Ok(id)
    }

    pub fn insert_pq_custodian_attestation(
        &mut self,
        attestation: DurablePqStorageCustodianAttestation,
    ) -> DurableStateStoreResult<String> {
        attestation.validate()?;
        ensure_room(
            self.pq_custodian_attestations.len(),
            self.bounds.max_custodian_attestations,
            "durable pq custodian attestation",
        )?;
        self.ensure_journal_room()?;
        if !self
            .snapshot_manifests
            .contains_key(&attestation.snapshot_id)
        {
            return Err("durable custodian attestation references unknown snapshot".to_string());
        }
        if !attestation.chunk_id.is_empty()
            && !self
                .erasure_chunk_manifests
                .contains_key(&attestation.chunk_id)
        {
            return Err("durable custodian attestation references unknown chunk".to_string());
        }
        let id = attestation.attestation_id.clone();
        let root = attestation.attestation_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.pq_custodian_attestations,
            id.clone(),
            attestation.clone(),
            "durable pq custodian attestation",
        )?;
        let collection_root = self.pq_custodian_attestation_root();
        self.append_journal_entry(
            DurableJournalEntryKind::PqCustodianAttestation,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            attestation.signed_at_height,
            0,
        )?;
        Ok(id)
    }

    pub fn insert_validation_report(
        &mut self,
        report: DurableStateValidationReport,
    ) -> DurableStateStoreResult<String> {
        report.validate()?;
        ensure_room(
            self.validation_reports.len(),
            self.bounds.max_validation_reports,
            "durable validation report",
        )?;
        self.ensure_journal_room()?;
        let id = report.validation_id.clone();
        let root = report.validation_root();
        let previous_store_root = self.state_root();
        insert_unique_record(
            &mut self.validation_reports,
            id.clone(),
            report.clone(),
            "durable validation report",
        )?;
        let collection_root = self.validation_report_root();
        self.append_journal_entry(
            DurableJournalEntryKind::ValidationReport,
            id.clone(),
            root,
            previous_store_root,
            collection_root,
            report.height,
            report.created_at_ms,
        )?;
        Ok(id)
    }

    pub fn append_state_delta(
        &mut self,
        subject_id: impl Into<String>,
        subject_root: impl Into<String>,
        resulting_collection_root: impl Into<String>,
        block_height: u64,
        recorded_at_ms: u64,
        writer_commitment: impl Into<String>,
    ) -> DurableStateStoreResult<String> {
        self.ensure_journal_room()?;
        let subject_id = subject_id.into();
        let subject_root = subject_root.into();
        let previous_store_root = self.state_root();
        let resulting_collection_root = resulting_collection_root.into();
        let entry = DurableStateJournalEntry::new(
            self.journal_entries.len() as u64,
            self.latest_journal_entry_id.clone(),
            DurableJournalEntryKind::StateDelta,
            subject_id,
            subject_root,
            previous_store_root,
            resulting_collection_root,
            block_height,
            recorded_at_ms,
            writer_commitment,
            DurableJournalEntryStatus::Committed,
        )?;
        let entry_id = entry.entry_id.clone();
        self.latest_journal_entry_id = entry_id.clone();
        self.journal_entries.push(entry);
        Ok(entry_id)
    }

    pub fn journal_root(&self) -> String {
        durable_journal_root(&self.journal_entries)
    }

    pub fn snapshot_manifest_root(&self) -> String {
        durable_snapshot_manifest_root(
            &self
                .snapshot_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn restore_plan_root(&self) -> String {
        durable_restore_plan_root(&self.restore_plans.values().cloned().collect::<Vec<_>>())
    }

    pub fn erasure_chunk_manifest_root(&self) -> String {
        durable_erasure_chunk_manifest_root(
            &self
                .erasure_chunk_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn retention_policy_root(&self) -> String {
        durable_retention_policy_root(
            &self
                .retention_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pruning_decision_root(&self) -> String {
        durable_pruning_decision_root(&self.pruning_decisions.values().cloned().collect::<Vec<_>>())
    }

    pub fn checkpoint_notarization_root(&self) -> String {
        durable_checkpoint_notarization_root(
            &self
                .checkpoint_notarizations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn crash_recovery_intent_root(&self) -> String {
        durable_crash_recovery_intent_root(
            &self
                .crash_recovery_intents
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_archive_sponsorship_root(&self) -> String {
        durable_low_fee_archive_sponsorship_root(
            &self
                .low_fee_archive_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn redaction_manifest_root(&self) -> String {
        durable_redaction_manifest_root(
            &self
                .redaction_manifests
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_custodian_attestation_root(&self) -> String {
        durable_pq_custodian_attestation_root(
            &self
                .pq_custodian_attestations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn validation_report_root(&self) -> String {
        durable_validation_report_root(
            &self
                .validation_reports
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record_root(&self) -> String {
        durable_state_store_payload_root(
            "DURABLE-STATE-STORE-PUBLIC-RECORD",
            &self.public_record_without_state_root(),
        )
    }

    pub fn roots(&self) -> DurableStateStoreRoots {
        let bounds_root = self.bounds.bounds_root();
        let journal_root = self.journal_root();
        let snapshot_manifest_root = self.snapshot_manifest_root();
        let restore_plan_root = self.restore_plan_root();
        let erasure_chunk_manifest_root = self.erasure_chunk_manifest_root();
        let retention_policy_root = self.retention_policy_root();
        let pruning_decision_root = self.pruning_decision_root();
        let checkpoint_notarization_root = self.checkpoint_notarization_root();
        let crash_recovery_intent_root = self.crash_recovery_intent_root();
        let low_fee_archive_sponsorship_root = self.low_fee_archive_sponsorship_root();
        let redaction_manifest_root = self.redaction_manifest_root();
        let pq_custodian_attestation_root = self.pq_custodian_attestation_root();
        let validation_report_root = self.validation_report_root();
        let counters = self.counters();
        let state_record = json!({
            "kind": "durable_state_store_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "schema_version": DURABLE_STATE_STORE_SCHEMA_VERSION,
            "height": self.height,
            "latest_journal_entry_id": &self.latest_journal_entry_id,
            "latest_finalized_snapshot_id": &self.latest_finalized_snapshot_id,
            "bounds_root": &bounds_root,
            "journal_root": &journal_root,
            "snapshot_manifest_root": &snapshot_manifest_root,
            "restore_plan_root": &restore_plan_root,
            "erasure_chunk_manifest_root": &erasure_chunk_manifest_root,
            "retention_policy_root": &retention_policy_root,
            "pruning_decision_root": &pruning_decision_root,
            "checkpoint_notarization_root": &checkpoint_notarization_root,
            "crash_recovery_intent_root": &crash_recovery_intent_root,
            "low_fee_archive_sponsorship_root": &low_fee_archive_sponsorship_root,
            "redaction_manifest_root": &redaction_manifest_root,
            "pq_custodian_attestation_root": &pq_custodian_attestation_root,
            "validation_report_root": &validation_report_root,
            "counters": counters.public_record(),
        });
        let state_root = durable_state_store_state_root_from_record(&state_record);
        DurableStateStoreRoots {
            bounds_root,
            journal_root,
            snapshot_manifest_root,
            restore_plan_root,
            erasure_chunk_manifest_root,
            retention_policy_root,
            pruning_decision_root,
            checkpoint_notarization_root,
            crash_recovery_intent_root,
            low_fee_archive_sponsorship_root,
            redaction_manifest_root,
            pq_custodian_attestation_root,
            validation_report_root,
            state_root,
        }
    }

    pub fn counters(&self) -> DurableStateStoreCounters {
        let mut counters = DurableStateStoreCounters {
            height: self.height,
            journal_entry_count: self.journal_entries.len() as u64,
            snapshot_manifest_count: self.snapshot_manifests.len() as u64,
            restore_plan_count: self.restore_plans.len() as u64,
            erasure_chunk_manifest_count: self.erasure_chunk_manifests.len() as u64,
            retention_policy_count: self.retention_policies.len() as u64,
            pruning_decision_count: self.pruning_decisions.len() as u64,
            checkpoint_notarization_count: self.checkpoint_notarizations.len() as u64,
            crash_recovery_intent_count: self.crash_recovery_intents.len() as u64,
            low_fee_archive_sponsorship_count: self.low_fee_archive_sponsorships.len() as u64,
            redaction_manifest_count: self.redaction_manifests.len() as u64,
            pq_custodian_attestation_count: self.pq_custodian_attestations.len() as u64,
            validation_report_count: self.validation_reports.len() as u64,
            ..DurableStateStoreCounters::default()
        };
        for entry in &self.journal_entries {
            if entry.status.is_committed() {
                counters.committed_journal_entry_count =
                    counters.committed_journal_entry_count.saturating_add(1);
            }
        }
        for snapshot in self.snapshot_manifests.values() {
            counters.total_logical_snapshot_bytes = counters
                .total_logical_snapshot_bytes
                .saturating_add(snapshot.logical_bytes);
            counters.total_encoded_snapshot_bytes = counters
                .total_encoded_snapshot_bytes
                .saturating_add(snapshot.encoded_bytes);
            if snapshot.finalized {
                counters.finalized_snapshot_count =
                    counters.finalized_snapshot_count.saturating_add(1);
            }
        }
        for plan in self.restore_plans.values() {
            if plan.status.is_open() {
                counters.open_restore_plan_count =
                    counters.open_restore_plan_count.saturating_add(1);
            }
        }
        for chunk in self.erasure_chunk_manifests.values() {
            counters.total_erasure_chunk_bytes = counters
                .total_erasure_chunk_bytes
                .saturating_add(chunk.byte_count);
        }
        for decision in self.pruning_decisions.values() {
            if decision.action.is_destructive() {
                counters.destructive_pruning_decision_count = counters
                    .destructive_pruning_decision_count
                    .saturating_add(1);
            }
        }
        for checkpoint in self.checkpoint_notarizations.values() {
            if checkpoint.status.accepted() {
                counters.accepted_checkpoint_count =
                    counters.accepted_checkpoint_count.saturating_add(1);
            }
        }
        for intent in self.crash_recovery_intents.values() {
            if intent.status.active() {
                counters.active_crash_recovery_intent_count = counters
                    .active_crash_recovery_intent_count
                    .saturating_add(1);
            }
        }
        for sponsorship in self.low_fee_archive_sponsorships.values() {
            counters.total_sponsored_fee_units = counters
                .total_sponsored_fee_units
                .saturating_add(sponsorship.max_fee_units);
            counters.total_reserved_fee_units = counters
                .total_reserved_fee_units
                .saturating_add(sponsorship.reserved_fee_units);
            counters.total_spent_fee_units = counters
                .total_spent_fee_units
                .saturating_add(sponsorship.spent_fee_units);
            if sponsorship.active_at(self.height) {
                counters.active_low_fee_archive_sponsorship_count = counters
                    .active_low_fee_archive_sponsorship_count
                    .saturating_add(1);
            }
        }
        for attestation in self.pq_custodian_attestations.values() {
            if attestation.status.accepted() {
                counters.accepted_pq_custodian_attestation_count = counters
                    .accepted_pq_custodian_attestation_count
                    .saturating_add(1);
            }
        }
        for report in self.validation_reports.values() {
            if report.status.accepted() {
                counters.accepted_validation_report_count =
                    counters.accepted_validation_report_count.saturating_add(1);
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "durable_state_store_state",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "schema_version": DURABLE_STATE_STORE_SCHEMA_VERSION,
            "height": self.height,
            "bounds": self.bounds.public_record(),
            "latest_journal_entry_id": &self.latest_journal_entry_id,
            "latest_finalized_snapshot_id": &self.latest_finalized_snapshot_id,
            "journal_entries": self.journal_entries.iter().map(DurableStateJournalEntry::public_record).collect::<Vec<_>>(),
            "snapshot_manifests": self.snapshot_manifests.values().map(DurableSnapshotManifest::public_record).collect::<Vec<_>>(),
            "restore_plans": self.restore_plans.values().map(DurableRestorePlan::public_record).collect::<Vec<_>>(),
            "erasure_chunk_manifests": self.erasure_chunk_manifests.values().map(DurableErasureChunkManifest::public_record).collect::<Vec<_>>(),
            "retention_policies": self.retention_policies.values().map(DurableRetentionPolicy::public_record).collect::<Vec<_>>(),
            "pruning_decisions": self.pruning_decisions.values().map(DurablePruningDecision::public_record).collect::<Vec<_>>(),
            "checkpoint_notarizations": self.checkpoint_notarizations.values().map(DurableCheckpointNotarization::public_record).collect::<Vec<_>>(),
            "crash_recovery_intents": self.crash_recovery_intents.values().map(DurableCrashRecoveryIntent::public_record).collect::<Vec<_>>(),
            "low_fee_archive_sponsorships": self.low_fee_archive_sponsorships.values().map(DurableLowFeeArchiveSponsorship::public_record).collect::<Vec<_>>(),
            "redaction_manifests": self.redaction_manifests.values().map(DurableRedactionManifest::public_record).collect::<Vec<_>>(),
            "pq_custodian_attestations": self.pq_custodian_attestations.values().map(DurablePqStorageCustodianAttestation::public_record).collect::<Vec<_>>(),
            "validation_reports": self.validation_reports.values().map(DurableStateValidationReport::public_record).collect::<Vec<_>>(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> DurableStateStoreResult<String> {
        self.bounds.validate()?;
        ensure_len_bound(
            self.journal_entries.len(),
            self.bounds.max_journal_entries,
            "durable journal entries",
        )?;
        ensure_len_bound(
            self.snapshot_manifests.len(),
            self.bounds.max_snapshot_manifests,
            "durable snapshot manifests",
        )?;
        ensure_len_bound(
            self.restore_plans.len(),
            self.bounds.max_restore_plans,
            "durable restore plans",
        )?;
        ensure_len_bound(
            self.erasure_chunk_manifests.len(),
            self.bounds.max_erasure_chunk_manifests,
            "durable erasure chunk manifests",
        )?;
        ensure_len_bound(
            self.retention_policies.len(),
            self.bounds.max_retention_policies,
            "durable retention policies",
        )?;
        ensure_len_bound(
            self.pruning_decisions.len(),
            self.bounds.max_pruning_decisions,
            "durable pruning decisions",
        )?;
        ensure_len_bound(
            self.checkpoint_notarizations.len(),
            self.bounds.max_checkpoint_notarizations,
            "durable checkpoint notarizations",
        )?;
        ensure_len_bound(
            self.crash_recovery_intents.len(),
            self.bounds.max_crash_recovery_intents,
            "durable crash recovery intents",
        )?;
        ensure_len_bound(
            self.low_fee_archive_sponsorships.len(),
            self.bounds.max_archive_sponsorships,
            "durable archive sponsorships",
        )?;
        ensure_len_bound(
            self.redaction_manifests.len(),
            self.bounds.max_redaction_manifests,
            "durable redaction manifests",
        )?;
        ensure_len_bound(
            self.pq_custodian_attestations.len(),
            self.bounds.max_custodian_attestations,
            "durable custodian attestations",
        )?;
        ensure_len_bound(
            self.validation_reports.len(),
            self.bounds.max_validation_reports,
            "durable validation reports",
        )?;

        let mut previous_entry_id = String::new();
        for (index, entry) in self.journal_entries.iter().enumerate() {
            if entry.sequence != index as u64 {
                return Err("durable journal sequence gap".to_string());
            }
            if entry.previous_entry_id != previous_entry_id {
                return Err("durable journal previous entry mismatch".to_string());
            }
            entry.validate()?;
            previous_entry_id = entry.entry_id.clone();
        }
        if self.latest_journal_entry_id != previous_entry_id {
            return Err("durable latest journal entry mismatch".to_string());
        }

        for (snapshot_id, snapshot) in &self.snapshot_manifests {
            if snapshot_id != &snapshot.snapshot_id {
                return Err("durable snapshot map key mismatch".to_string());
            }
            snapshot.validate()?;
            if !snapshot.base_snapshot_id.is_empty()
                && !self
                    .snapshot_manifests
                    .contains_key(&snapshot.base_snapshot_id)
            {
                return Err("durable snapshot references unknown base snapshot".to_string());
            }
        }
        for (plan_id, plan) in &self.restore_plans {
            if plan_id != &plan.restore_plan_id {
                return Err("durable restore plan map key mismatch".to_string());
            }
            plan.validate()?;
            if !self
                .snapshot_manifests
                .contains_key(&plan.target_snapshot_id)
            {
                return Err("durable restore plan missing target snapshot".to_string());
            }
            for snapshot_id in &plan.source_snapshot_ids {
                if !self.snapshot_manifests.contains_key(snapshot_id) {
                    return Err("durable restore plan missing source snapshot".to_string());
                }
            }
            for chunk_id in &plan.required_chunk_ids {
                if !self.erasure_chunk_manifests.contains_key(chunk_id) {
                    return Err("durable restore plan missing required chunk".to_string());
                }
            }
        }
        for (chunk_id, chunk) in &self.erasure_chunk_manifests {
            if chunk_id != &chunk.chunk_id {
                return Err("durable chunk map key mismatch".to_string());
            }
            chunk.validate()?;
            if !self.snapshot_manifests.contains_key(&chunk.snapshot_id) {
                return Err("durable chunk missing snapshot".to_string());
            }
        }
        for (policy_id, policy) in &self.retention_policies {
            if policy_id != &policy.policy_id {
                return Err("durable retention policy map key mismatch".to_string());
            }
            policy.validate()?;
        }
        for (decision_id, decision) in &self.pruning_decisions {
            if decision_id != &decision.decision_id {
                return Err("durable pruning decision map key mismatch".to_string());
            }
            decision.validate()?;
            if !self.retention_policies.contains_key(&decision.policy_id) {
                return Err("durable pruning decision missing policy".to_string());
            }
        }
        for (checkpoint_id, checkpoint) in &self.checkpoint_notarizations {
            if checkpoint_id != &checkpoint.checkpoint_id {
                return Err("durable checkpoint map key mismatch".to_string());
            }
            checkpoint.validate()?;
            let snapshot = self
                .snapshot_manifests
                .get(&checkpoint.snapshot_id)
                .ok_or_else(|| "durable checkpoint references unknown snapshot".to_string())?;
            if checkpoint.state_root != snapshot.state_root {
                return Err("durable checkpoint state root mismatch".to_string());
            }
        }
        for (intent_id, intent) in &self.crash_recovery_intents {
            if intent_id != &intent.intent_id {
                return Err("durable crash intent map key mismatch".to_string());
            }
            intent.validate()?;
            if !intent.target_snapshot_id.is_empty()
                && !self
                    .snapshot_manifests
                    .contains_key(&intent.target_snapshot_id)
            {
                return Err("durable crash intent missing target snapshot".to_string());
            }
        }
        for (sponsorship_id, sponsorship) in &self.low_fee_archive_sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("durable sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
        }
        for (redaction_id, redaction) in &self.redaction_manifests {
            if redaction_id != &redaction.redaction_id {
                return Err("durable redaction map key mismatch".to_string());
            }
            redaction.validate()?;
            if !self.snapshot_manifests.contains_key(&redaction.snapshot_id) {
                return Err("durable redaction missing snapshot".to_string());
            }
        }
        for (attestation_id, attestation) in &self.pq_custodian_attestations {
            if attestation_id != &attestation.attestation_id {
                return Err("durable custodian attestation map key mismatch".to_string());
            }
            attestation.validate()?;
            if !self
                .snapshot_manifests
                .contains_key(&attestation.snapshot_id)
            {
                return Err("durable custodian attestation missing snapshot".to_string());
            }
            if !attestation.chunk_id.is_empty()
                && !self
                    .erasure_chunk_manifests
                    .contains_key(&attestation.chunk_id)
            {
                return Err("durable custodian attestation missing chunk".to_string());
            }
        }
        for (validation_id, report) in &self.validation_reports {
            if validation_id != &report.validation_id {
                return Err("durable validation report map key mismatch".to_string());
            }
            report.validate()?;
        }
        if !self.latest_finalized_snapshot_id.is_empty()
            && !self
                .snapshot_manifests
                .contains_key(&self.latest_finalized_snapshot_id)
        {
            return Err("durable latest finalized snapshot missing".to_string());
        }
        Ok(self.state_root())
    }

    fn ensure_journal_room(&self) -> DurableStateStoreResult<()> {
        ensure_room(
            self.journal_entries.len(),
            self.bounds.max_journal_entries,
            "durable journal entry",
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_journal_entry(
        &mut self,
        entry_kind: DurableJournalEntryKind,
        subject_id: String,
        subject_root: String,
        previous_store_root: String,
        resulting_collection_root: String,
        block_height: u64,
        recorded_at_ms: u64,
    ) -> DurableStateStoreResult<String> {
        let entry = DurableStateJournalEntry::new(
            self.journal_entries.len() as u64,
            self.latest_journal_entry_id.clone(),
            entry_kind,
            subject_id,
            subject_root,
            previous_store_root,
            resulting_collection_root,
            block_height,
            recorded_at_ms,
            DURABLE_STATE_STORE_DEVNET_OPERATOR,
            DurableJournalEntryStatus::Committed,
        )?;
        let entry_id = entry.entry_id.clone();
        self.latest_journal_entry_id = entry_id.clone();
        self.journal_entries.push(entry);
        Ok(entry_id)
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "durable_state_store_state_unsigned",
            "chain_id": CHAIN_ID,
            "protocol_version": DURABLE_STATE_STORE_PROTOCOL_VERSION,
            "schema_version": DURABLE_STATE_STORE_SCHEMA_VERSION,
            "height": self.height,
            "bounds_root": self.bounds.bounds_root(),
            "latest_journal_entry_id": &self.latest_journal_entry_id,
            "latest_finalized_snapshot_id": &self.latest_finalized_snapshot_id,
            "journal_root": self.journal_root(),
            "snapshot_manifest_root": self.snapshot_manifest_root(),
            "restore_plan_root": self.restore_plan_root(),
            "erasure_chunk_manifest_root": self.erasure_chunk_manifest_root(),
            "retention_policy_root": self.retention_policy_root(),
            "pruning_decision_root": self.pruning_decision_root(),
            "checkpoint_notarization_root": self.checkpoint_notarization_root(),
            "crash_recovery_intent_root": self.crash_recovery_intent_root(),
            "low_fee_archive_sponsorship_root": self.low_fee_archive_sponsorship_root(),
            "redaction_manifest_root": self.redaction_manifest_root(),
            "pq_custodian_attestation_root": self.pq_custodian_attestation_root(),
            "validation_report_root": self.validation_report_root(),
            "counters": self.counters().public_record(),
        })
    }
}

pub fn durable_state_store_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "DURABLE-STATE-STORE-STATE-ROOT",
        &[
            HashPart::Int(DURABLE_STATE_STORE_PROTOCOL_VERSION as i128),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn durable_state_store_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Int(DURABLE_STATE_STORE_PROTOCOL_VERSION as i128),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn durable_state_store_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Int(DURABLE_STATE_STORE_PROTOCOL_VERSION as i128),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn durable_string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(durable_state_store_string_root(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn durable_string_map_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
                "entry_root": durable_state_store_payload_root(
                    domain,
                    &json!({"key": key, "value": value})
                ),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn durable_journal_entry_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-JOURNAL-ENTRY-ID", record)
}

pub fn durable_snapshot_manifest_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-SNAPSHOT-MANIFEST-ID", record)
}

pub fn durable_restore_plan_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-RESTORE-PLAN-ID", record)
}

pub fn durable_erasure_chunk_manifest_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-ERASURE-CHUNK-MANIFEST-ID", record)
}

pub fn durable_retention_policy_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-RETENTION-POLICY-ID", record)
}

pub fn durable_pruning_decision_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-PRUNING-DECISION-ID", record)
}

pub fn durable_checkpoint_notarization_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-CHECKPOINT-NOTARIZATION-ID", record)
}

pub fn durable_crash_recovery_intent_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-CRASH-RECOVERY-INTENT-ID", record)
}

pub fn durable_low_fee_archive_sponsorship_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-LOW-FEE-ARCHIVE-SPONSORSHIP-ID", record)
}

pub fn durable_redaction_manifest_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-REDACTION-MANIFEST-ID", record)
}

pub fn durable_pq_custodian_attestation_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-PQ-CUSTODIAN-ATTESTATION-ID", record)
}

pub fn durable_validation_report_id(record: &Value) -> String {
    durable_state_store_payload_root("DURABLE-VALIDATION-REPORT-ID", record)
}

pub fn durable_journal_root(entries: &[DurableStateJournalEntry]) -> String {
    merkle_root(
        "DURABLE-JOURNAL",
        &entries
            .iter()
            .map(DurableStateJournalEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_snapshot_manifest_root(manifests: &[DurableSnapshotManifest]) -> String {
    merkle_root(
        "DURABLE-SNAPSHOT-MANIFEST",
        &manifests
            .iter()
            .map(DurableSnapshotManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_restore_plan_root(plans: &[DurableRestorePlan]) -> String {
    merkle_root(
        "DURABLE-RESTORE-PLAN",
        &plans
            .iter()
            .map(DurableRestorePlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_erasure_chunk_manifest_root(manifests: &[DurableErasureChunkManifest]) -> String {
    merkle_root(
        "DURABLE-ERASURE-CHUNK-MANIFEST",
        &manifests
            .iter()
            .map(DurableErasureChunkManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_retention_policy_root(policies: &[DurableRetentionPolicy]) -> String {
    merkle_root(
        "DURABLE-RETENTION-POLICY",
        &policies
            .iter()
            .map(DurableRetentionPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_pruning_decision_root(decisions: &[DurablePruningDecision]) -> String {
    merkle_root(
        "DURABLE-PRUNING-DECISION",
        &decisions
            .iter()
            .map(DurablePruningDecision::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_checkpoint_notarization_root(
    checkpoints: &[DurableCheckpointNotarization],
) -> String {
    merkle_root(
        "DURABLE-CHECKPOINT-NOTARIZATION",
        &checkpoints
            .iter()
            .map(DurableCheckpointNotarization::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_crash_recovery_intent_root(intents: &[DurableCrashRecoveryIntent]) -> String {
    merkle_root(
        "DURABLE-CRASH-RECOVERY-INTENT",
        &intents
            .iter()
            .map(DurableCrashRecoveryIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_low_fee_archive_sponsorship_root(
    sponsorships: &[DurableLowFeeArchiveSponsorship],
) -> String {
    merkle_root(
        "DURABLE-LOW-FEE-ARCHIVE-SPONSORSHIP",
        &sponsorships
            .iter()
            .map(DurableLowFeeArchiveSponsorship::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_redaction_manifest_root(manifests: &[DurableRedactionManifest]) -> String {
    merkle_root(
        "DURABLE-REDACTION-MANIFEST",
        &manifests
            .iter()
            .map(DurableRedactionManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_pq_custodian_attestation_root(
    attestations: &[DurablePqStorageCustodianAttestation],
) -> String {
    merkle_root(
        "DURABLE-PQ-CUSTODIAN-ATTESTATION",
        &attestations
            .iter()
            .map(DurablePqStorageCustodianAttestation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn durable_validation_report_root(reports: &[DurableStateValidationReport]) -> String {
    merkle_root(
        "DURABLE-VALIDATION-REPORT",
        &reports
            .iter()
            .map(DurableStateValidationReport::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, label: &str) -> DurableStateStoreResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> DurableStateStoreResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_room(current_len: usize, max_len: u64, label: &str) -> DurableStateStoreResult<()> {
    if max_len > 0 && (current_len as u64) >= max_len {
        return Err(format!("{label} bound exceeded"));
    }
    Ok(())
}

fn ensure_len_bound(current_len: usize, max_len: u64, label: &str) -> DurableStateStoreResult<()> {
    if max_len > 0 && (current_len as u64) > max_len {
        return Err(format!("{label} exceed configured bound"));
    }
    Ok(())
}

fn validate_bps(value: u64, label: &str) -> DurableStateStoreResult<()> {
    if value > DURABLE_STATE_STORE_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn validate_height_window(start: u64, end: u64, label: &str) -> DurableStateStoreResult<()> {
    if end > 0 && end < start {
        Err(format!("{label} ends before it starts"))
    } else {
        Ok(())
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> DurableStateStoreResult<()> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id, record);
    Ok(())
}

fn btree_set<const N: usize>(values: [&str; N]) -> BTreeSet<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn btree_map<const N: usize>(values: [(&str, String); N]) -> BTreeMap<String, String> {
    values
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

fn devnet_root(label: &str, value: &str) -> String {
    durable_state_store_string_root(
        "DURABLE-STATE-STORE-DEVNET-ROOT",
        &format!("{label}:{value}"),
    )
}
