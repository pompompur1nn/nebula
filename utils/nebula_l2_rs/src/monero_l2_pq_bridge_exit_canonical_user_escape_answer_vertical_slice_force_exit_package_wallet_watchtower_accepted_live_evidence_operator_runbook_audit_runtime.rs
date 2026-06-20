use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageWalletWatchtowerAcceptedLiveEvidenceOperatorRunbookAuditRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-wallet-watchtower-accepted-live-evidence-operator-runbook-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_SUITE: &str =
    "monero-l2-pq-force-exit-wallet-watchtower-live-evidence-runbook-audit-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_280_512;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_WATCHTOWER_REPLAY_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_RECOVERY_NOTICE_SLA_BLOCKS: u64 = 36;
pub const DEFAULT_USER_ESCAPE_NOTICE_SLA_BLOCKS: u64 = 24;
pub const DEFAULT_DASHBOARD_REFRESH_BLOCKS: u64 = 6;
pub const DEFAULT_MAX_WALLET_GAP_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_OPERATOR_SIGNOFFS: u64 = 2;
pub const DEFAULT_MAX_IMPORTS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveEvidenceKind {
    WalletTranscript,
    WatchtowerReplay,
    UserEscapeNotice,
    RecoveryNotice,
    OperatorAttestation,
    ReleaseDashboardReadiness,
    FailClosedBlocker,
}

impl LiveEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTranscript => "wallet_transcript",
            Self::WatchtowerReplay => "watchtower_replay",
            Self::UserEscapeNotice => "user_escape_notice",
            Self::RecoveryNotice => "recovery_notice",
            Self::OperatorAttestation => "operator_attestation",
            Self::ReleaseDashboardReadiness => "release_dashboard_readiness",
            Self::FailClosedBlocker => "fail_closed_blocker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Accepted,
    Quarantined,
    Superseded,
    Rejected,
}

impl ImportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Quarantined | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptFinding {
    Clean,
    Gap,
    DivergentWalletRoot,
    MissingViewTagScan,
    KeyImageMismatch,
    UnreviewedRecoveryPath,
    MetadataLeak,
}

impl TranscriptFinding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Gap => "gap",
            Self::DivergentWalletRoot => "divergent_wallet_root",
            Self::MissingViewTagScan => "missing_viewtag_scan",
            Self::KeyImageMismatch => "key_image_mismatch",
            Self::UnreviewedRecoveryPath => "unreviewed_recovery_path",
            Self::MetadataLeak => "metadata_leak",
        }
    }

    pub fn is_blocking(self) -> bool {
        matches!(
            self,
            Self::DivergentWalletRoot
                | Self::KeyImageMismatch
                | Self::UnreviewedRecoveryPath
                | Self::MetadataLeak
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayItemStatus {
    Passed,
    Warning,
    Missing,
    Failed,
}

impl ReplayItemStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warning => "warning",
            Self::Missing => "missing",
            Self::Failed => "failed",
        }
    }

    pub fn counts_as_complete(self) -> bool {
        matches!(self, Self::Passed | Self::Warning)
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Missing | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeDeliveryStatus {
    Drafted,
    Published,
    Acknowledged,
    Expired,
    Blocked,
}

impl NoticeDeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Published => "published",
            Self::Acknowledged => "acknowledged",
            Self::Expired => "expired",
            Self::Blocked => "blocked",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Published | Self::Acknowledged)
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Drafted | Self::Expired | Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHandlingStatus {
    NotRequired,
    Queued,
    Contacted,
    WalletProofReviewed,
    Escalated,
    Completed,
    Blocked,
}

impl RecoveryHandlingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Queued => "queued",
            Self::Contacted => "contacted",
            Self::WalletProofReviewed => "wallet_proof_reviewed",
            Self::Escalated => "escalated",
            Self::Completed => "completed",
            Self::Blocked => "blocked",
        }
    }

    pub fn satisfies_release(self) -> bool {
        matches!(
            self,
            Self::NotRequired | Self::WalletProofReviewed | Self::Completed
        )
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Queued | Self::Escalated | Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardReadinessStatus {
    Ready,
    Watch,
    Blocked,
}

impl DashboardReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedBlockerKind {
    NoAcceptedWalletTranscript,
    WalletTranscriptFinding,
    WatchtowerReplayIncomplete,
    UserEscapeNoticeMissing,
    RecoveryNoticeUnresolved,
    ImportQuarantined,
    OperatorSignoffInsufficient,
    DashboardStale,
    ReleaseDashboardBlocked,
    MoneroConfirmationsTooShallow,
    EvidenceRootMismatch,
}

impl FailClosedBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoAcceptedWalletTranscript => "no_accepted_wallet_transcript",
            Self::WalletTranscriptFinding => "wallet_transcript_finding",
            Self::WatchtowerReplayIncomplete => "watchtower_replay_incomplete",
            Self::UserEscapeNoticeMissing => "user_escape_notice_missing",
            Self::RecoveryNoticeUnresolved => "recovery_notice_unresolved",
            Self::ImportQuarantined => "import_quarantined",
            Self::OperatorSignoffInsufficient => "operator_signoff_insufficient",
            Self::DashboardStale => "dashboard_stale",
            Self::ReleaseDashboardBlocked => "release_dashboard_blocked",
            Self::MoneroConfirmationsTooShallow => "monero_confirmations_too_shallow",
            Self::EvidenceRootMismatch => "evidence_root_mismatch",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::NoAcceptedWalletTranscript => "wallet_review",
            Self::WalletTranscriptFinding => "wallet_review",
            Self::WatchtowerReplayIncomplete => "watchtower_replay",
            Self::UserEscapeNoticeMissing => "user_escape_notice",
            Self::RecoveryNoticeUnresolved => "recovery_handling",
            Self::ImportQuarantined => "live_evidence_import",
            Self::OperatorSignoffInsufficient => "operator_runbook",
            Self::DashboardStale => "release_dashboard",
            Self::ReleaseDashboardBlocked => "release_dashboard",
            Self::MoneroConfirmationsTooShallow => "monero_finality",
            Self::EvidenceRootMismatch => "evidence_binding",
        }
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(
            self,
            Self::NoAcceptedWalletTranscript
                | Self::WalletTranscriptFinding
                | Self::WatchtowerReplayIncomplete
                | Self::UserEscapeNoticeMissing
                | Self::RecoveryNoticeUnresolved
                | Self::ImportQuarantined
                | Self::ReleaseDashboardBlocked
                | Self::EvidenceRootMismatch
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_suite: String,
    pub current_height: u64,
    pub min_monero_confirmations: u64,
    pub watchtower_replay_confirmations: u64,
    pub recovery_notice_sla_blocks: u64,
    pub user_escape_notice_sla_blocks: u64,
    pub dashboard_refresh_blocks: u64,
    pub max_wallet_gap_blocks: u64,
    pub min_operator_signoffs: u64,
    pub max_imports: usize,
    pub fail_closed_on_notice_gap: bool,
    pub fail_closed_on_recovery_gap: bool,
    pub fail_closed_on_replay_gap: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_suite: RUNBOOK_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            watchtower_replay_confirmations: DEFAULT_WATCHTOWER_REPLAY_CONFIRMATIONS,
            recovery_notice_sla_blocks: DEFAULT_RECOVERY_NOTICE_SLA_BLOCKS,
            user_escape_notice_sla_blocks: DEFAULT_USER_ESCAPE_NOTICE_SLA_BLOCKS,
            dashboard_refresh_blocks: DEFAULT_DASHBOARD_REFRESH_BLOCKS,
            max_wallet_gap_blocks: DEFAULT_MAX_WALLET_GAP_BLOCKS,
            min_operator_signoffs: DEFAULT_MIN_OPERATOR_SIGNOFFS,
            max_imports: DEFAULT_MAX_IMPORTS,
            fail_closed_on_notice_gap: true,
            fail_closed_on_recovery_gap: true,
            fail_closed_on_replay_gap: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"chain_id": self.chain_id, "protocol_version": self.protocol_version, "schema_version": self.schema_version, "hash_suite": self.hash_suite, "runbook_suite": self.runbook_suite, "current_height": self.current_height, "min_monero_confirmations": self.min_monero_confirmations, "watchtower_replay_confirmations": self.watchtower_replay_confirmations, "recovery_notice_sla_blocks": self.recovery_notice_sla_blocks, "user_escape_notice_sla_blocks": self.user_escape_notice_sla_blocks, "dashboard_refresh_blocks": self.dashboard_refresh_blocks, "max_wallet_gap_blocks": self.max_wallet_gap_blocks, "min_operator_signoffs": self.min_operator_signoffs, "max_imports": self.max_imports, "fail_closed_on_notice_gap": self.fail_closed_on_notice_gap, "fail_closed_on_recovery_gap": self.fail_closed_on_recovery_gap, "fail_closed_on_replay_gap": self.fail_closed_on_replay_gap})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveEvidenceImport {
    pub import_id: String,
    pub evidence_kind: LiveEvidenceKind,
    pub imported_at_height: u64,
    pub accepted_height: u64,
    pub source_lane: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub source_record_root: String,
    pub operator_id: String,
    pub status: ImportStatus,
    pub note: String,
}

impl LiveEvidenceImport {
    pub fn accepted(
        import_id: &str,
        evidence_kind: LiveEvidenceKind,
        height: u64,
        source_lane: &str,
        subject_id: &str,
        operator_id: &str,
        note: &str,
    ) -> Self {
        let seed = json!({
            "import_id": import_id,
            "evidence_kind": evidence_kind.as_str(),
            "height": height,
            "source_lane": source_lane,
            "subject_id": subject_id,
            "operator_id": operator_id,
            "note": note,
        });
        let evidence_root = domain_hash(
            "MONERO-FORCE-EXIT-LIVE-EVIDENCE-SEED",
            &[HashPart::Json(&seed)],
            32,
        );
        Self {
            import_id: import_id.to_string(),
            evidence_kind,
            imported_at_height: height,
            accepted_height: height,
            source_lane: source_lane.to_string(),
            subject_id: subject_id.to_string(),
            evidence_root: evidence_root.clone(),
            source_record_root: domain_hash(
                "MONERO-FORCE-EXIT-LIVE-EVIDENCE-SOURCE",
                &[HashPart::Str(source_lane), HashPart::Str(&evidence_root)],
                32,
            ),
            operator_id: operator_id.to_string(),
            status: ImportStatus::Accepted,
            note: note.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"import_id": self.import_id, "evidence_kind": self.evidence_kind.as_str(), "imported_at_height": self.imported_at_height, "accepted_height": self.accepted_height, "source_lane": self.source_lane, "subject_id": self.subject_id, "evidence_root": self.evidence_root, "source_record_root": self.source_record_root, "operator_id": self.operator_id, "status": self.status.as_str(), "note": self.note})
    }

    pub fn is_live_for_release(&self) -> bool {
        self.status.is_accepted() && self.accepted_height >= self.imported_at_height
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletTranscriptReview {
    pub review_id: String,
    pub wallet_id: String,
    pub transcript_root: String,
    pub import_id: String,
    pub first_height: u64,
    pub last_height: u64,
    pub observed_gap_blocks: u64,
    pub monero_confirmations: u64,
    pub findings: Vec<TranscriptFinding>,
    pub reviewer_id: String,
    pub reviewed_at_height: u64,
}

impl WalletTranscriptReview {
    pub fn new(
        review_id: &str,
        wallet_id: &str,
        import: &LiveEvidenceImport,
        first_height: u64,
        last_height: u64,
        monero_confirmations: u64,
        reviewer_id: &str,
    ) -> Self {
        Self {
            review_id: review_id.to_string(),
            wallet_id: wallet_id.to_string(),
            transcript_root: import.evidence_root.clone(),
            import_id: import.import_id.clone(),
            first_height,
            last_height,
            observed_gap_blocks: last_height.saturating_sub(first_height),
            monero_confirmations,
            findings: vec![TranscriptFinding::Clean],
            reviewer_id: reviewer_id.to_string(),
            reviewed_at_height: import.accepted_height,
        }
    }

    pub fn with_findings(mut self, findings: Vec<TranscriptFinding>) -> Self {
        self.findings = findings;
        self
    }

    pub fn public_record(&self) -> Value {
        let findings = self
            .findings
            .iter()
            .map(|finding| Value::String(finding.as_str().to_string()))
            .collect::<Vec<_>>();
        json!({"review_id": self.review_id, "wallet_id": self.wallet_id, "transcript_root": self.transcript_root, "import_id": self.import_id, "first_height": self.first_height, "last_height": self.last_height, "observed_gap_blocks": self.observed_gap_blocks, "monero_confirmations": self.monero_confirmations, "findings": findings, "reviewer_id": self.reviewer_id, "reviewed_at_height": self.reviewed_at_height, "blocks_release": self.blocks_release()})
    }

    pub fn blocks_release(&self) -> bool {
        self.findings.iter().any(|finding| finding.is_blocking())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatchtowerReplayItem {
    pub item_id: String,
    pub label: String,
    pub expected_root: String,
    pub observed_root: String,
    pub status: ReplayItemStatus,
    pub replayed_at_height: u64,
}

impl WatchtowerReplayItem {
    pub fn passed(item_id: &str, label: &str, expected_root: &str, height: u64) -> Self {
        Self {
            item_id: item_id.to_string(),
            label: label.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: expected_root.to_string(),
            status: ReplayItemStatus::Passed,
            replayed_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"item_id": self.item_id, "label": self.label, "expected_root": self.expected_root, "observed_root": self.observed_root, "status": self.status.as_str(), "replayed_at_height": self.replayed_at_height})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatchtowerReplayChecklist {
    pub checklist_id: String,
    pub watchtower_id: String,
    pub import_id: String,
    pub replay_root: String,
    pub replay_confirmations: u64,
    pub items: Vec<WatchtowerReplayItem>,
    pub operator_id: String,
}

impl WatchtowerReplayChecklist {
    pub fn new(
        checklist_id: &str,
        watchtower_id: &str,
        import: &LiveEvidenceImport,
        replay_confirmations: u64,
        operator_id: &str,
    ) -> Self {
        let items = vec![
            WatchtowerReplayItem::passed(
                "chain-tip",
                "monero chain tip anchored",
                &import.evidence_root,
                import.accepted_height,
            ),
            WatchtowerReplayItem::passed(
                "exit-claim",
                "forced exit claim replayed",
                &import.source_record_root,
                import.accepted_height,
            ),
            WatchtowerReplayItem::passed(
                "wallet-binding",
                "wallet transcript binding replayed",
                &import.evidence_root,
                import.accepted_height,
            ),
        ];
        let leaves = items
            .iter()
            .map(|item| item.public_record())
            .collect::<Vec<_>>();
        Self {
            checklist_id: checklist_id.to_string(),
            watchtower_id: watchtower_id.to_string(),
            import_id: import.import_id.clone(),
            replay_root: merkle_root("MONERO-FORCE-EXIT-WATCHTOWER-REPLAY", &leaves),
            replay_confirmations,
            items,
            operator_id: operator_id.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        let items = self
            .items
            .iter()
            .map(|item| item.public_record())
            .collect::<Vec<_>>();
        json!({"checklist_id": self.checklist_id, "watchtower_id": self.watchtower_id, "import_id": self.import_id, "replay_root": self.replay_root, "replay_confirmations": self.replay_confirmations, "items": items, "complete_items": self.complete_items(), "blocking_items": self.blocking_items(), "operator_id": self.operator_id})
    }

    pub fn complete_items(&self) -> u64 {
        self.items
            .iter()
            .filter(|item| item.status.counts_as_complete())
            .count() as u64
    }

    pub fn blocking_items(&self) -> u64 {
        self.items
            .iter()
            .filter(|item| item.status.blocks_release())
            .count() as u64
    }

    pub fn blocks_release(&self) -> bool {
        self.blocking_items() > 0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserEscapeNotice {
    pub notice_id: String,
    pub wallet_id: String,
    pub force_exit_id: String,
    pub import_id: String,
    pub notice_root: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub delivery_status: NoticeDeliveryStatus,
    pub channel: String,
    pub operator_id: String,
}

impl UserEscapeNotice {
    pub fn published(
        notice_id: &str,
        wallet_id: &str,
        force_exit_id: &str,
        import: &LiveEvidenceImport,
        expires_height: u64,
        channel: &str,
        operator_id: &str,
    ) -> Self {
        let notice_seed = json!({
            "notice_id": notice_id,
            "wallet_id": wallet_id,
            "force_exit_id": force_exit_id,
            "import_id": import.import_id,
            "channel": channel,
        });
        Self {
            notice_id: notice_id.to_string(),
            wallet_id: wallet_id.to_string(),
            force_exit_id: force_exit_id.to_string(),
            import_id: import.import_id.clone(),
            notice_root: domain_hash(
                "MONERO-FORCE-EXIT-USER-ESCAPE-NOTICE",
                &[HashPart::Json(&notice_seed)],
                32,
            ),
            issued_height: import.accepted_height,
            expires_height,
            delivery_status: NoticeDeliveryStatus::Published,
            channel: channel.to_string(),
            operator_id: operator_id.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"notice_id": self.notice_id, "wallet_id": self.wallet_id, "force_exit_id": self.force_exit_id, "import_id": self.import_id, "notice_root": self.notice_root, "issued_height": self.issued_height, "expires_height": self.expires_height, "delivery_status": self.delivery_status.as_str(), "channel": self.channel, "operator_id": self.operator_id, "live_for_release": self.delivery_status.is_live()})
    }

    pub fn blocks_release(&self, current_height: u64) -> bool {
        self.delivery_status.blocks_release() || current_height > self.expires_height
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryNoticeHandling {
    pub recovery_id: String,
    pub wallet_id: String,
    pub notice_id: String,
    pub recovery_root: String,
    pub status: RecoveryHandlingStatus,
    pub queued_height: u64,
    pub last_contact_height: u64,
    pub operator_id: String,
    pub escalation_note: String,
}

impl RecoveryNoticeHandling {
    pub fn not_required(recovery_id: &str, wallet_id: &str, notice: &UserEscapeNotice) -> Self {
        let seed = json!({
            "recovery_id": recovery_id,
            "wallet_id": wallet_id,
            "notice_id": notice.notice_id,
            "status": RecoveryHandlingStatus::NotRequired.as_str(),
        });
        Self {
            recovery_id: recovery_id.to_string(),
            wallet_id: wallet_id.to_string(),
            notice_id: notice.notice_id.clone(),
            recovery_root: domain_hash(
                "MONERO-FORCE-EXIT-RECOVERY-NOTICE-HANDLING",
                &[HashPart::Json(&seed)],
                32,
            ),
            status: RecoveryHandlingStatus::NotRequired,
            queued_height: notice.issued_height,
            last_contact_height: notice.issued_height,
            operator_id: notice.operator_id.clone(),
            escalation_note: "not required for clean wallet transcript".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"recovery_id": self.recovery_id, "wallet_id": self.wallet_id, "notice_id": self.notice_id, "recovery_root": self.recovery_root, "status": self.status.as_str(), "queued_height": self.queued_height, "last_contact_height": self.last_contact_height, "operator_id": self.operator_id, "escalation_note": self.escalation_note, "satisfies_release": self.status.satisfies_release()})
    }

    pub fn blocks_release(&self, current_height: u64, sla_blocks: u64) -> bool {
        if self.status.blocks_release() {
            return true;
        }
        current_height.saturating_sub(self.last_contact_height) > sla_blocks
            && !self.status.satisfies_release()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorRunbookSignoff {
    pub signoff_id: String,
    pub operator_id: String,
    pub role: String,
    pub signed_root: String,
    pub signed_at_height: u64,
}

impl OperatorRunbookSignoff {
    pub fn new(
        signoff_id: &str,
        operator_id: &str,
        role: &str,
        signed_root: &str,
        signed_at_height: u64,
    ) -> Self {
        Self {
            signoff_id: signoff_id.to_string(),
            operator_id: operator_id.to_string(),
            role: role.to_string(),
            signed_root: signed_root.to_string(),
            signed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"signoff_id": self.signoff_id, "operator_id": self.operator_id, "role": self.role, "signed_root": self.signed_root, "signed_at_height": self.signed_at_height})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseDashboardReadiness {
    pub dashboard_id: String,
    pub release_id: String,
    pub dashboard_root: String,
    pub status: DashboardReadinessStatus,
    pub refreshed_at_height: u64,
    pub wallet_review_root: String,
    pub watchtower_replay_root: String,
    pub notice_root: String,
    pub recovery_root: String,
    pub blocker_root: String,
}

impl ReleaseDashboardReadiness {
    pub fn from_roots(
        dashboard_id: &str,
        release_id: &str,
        refreshed_at_height: u64,
        wallet_review_root: &str,
        watchtower_replay_root: &str,
        notice_root: &str,
        recovery_root: &str,
        blockers: &[FailClosedBlocker],
    ) -> Self {
        let blocker_records = blockers
            .iter()
            .map(|blocker| blocker.public_record())
            .collect::<Vec<_>>();
        let blocker_root = merkle_root("MONERO-FORCE-EXIT-DASHBOARD-BLOCKERS", &blocker_records);
        let status = if blockers.iter().any(|blocker| blocker.fail_closed) {
            DashboardReadinessStatus::Blocked
        } else if blockers.is_empty() {
            DashboardReadinessStatus::Ready
        } else {
            DashboardReadinessStatus::Watch
        };
        let seed = json!({
            "dashboard_id": dashboard_id,
            "release_id": release_id,
            "refreshed_at_height": refreshed_at_height,
            "wallet_review_root": wallet_review_root,
            "watchtower_replay_root": watchtower_replay_root,
            "notice_root": notice_root,
            "recovery_root": recovery_root,
            "blocker_root": blocker_root,
            "status": status.as_str(),
        });
        Self {
            dashboard_id: dashboard_id.to_string(),
            release_id: release_id.to_string(),
            dashboard_root: domain_hash(
                "MONERO-FORCE-EXIT-RELEASE-DASHBOARD-READINESS",
                &[HashPart::Json(&seed)],
                32,
            ),
            status,
            refreshed_at_height,
            wallet_review_root: wallet_review_root.to_string(),
            watchtower_replay_root: watchtower_replay_root.to_string(),
            notice_root: notice_root.to_string(),
            recovery_root: recovery_root.to_string(),
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"dashboard_id": self.dashboard_id, "release_id": self.release_id, "dashboard_root": self.dashboard_root, "status": self.status.as_str(), "refreshed_at_height": self.refreshed_at_height, "wallet_review_root": self.wallet_review_root, "watchtower_replay_root": self.watchtower_replay_root, "notice_root": self.notice_root, "recovery_root": self.recovery_root, "blocker_root": self.blocker_root})
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-FORCE-EXIT-RELEASE-DASHBOARD-READINESS-RECORD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn blocks_release(&self, current_height: u64, refresh_blocks: u64) -> bool {
        matches!(self.status, DashboardReadinessStatus::Blocked)
            || current_height.saturating_sub(self.refreshed_at_height) > refresh_blocks
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedBlocker {
    pub blocker_id: String,
    pub kind: FailClosedBlockerKind,
    pub subject_id: String,
    pub evidence_root: String,
    pub owner_lane: String,
    pub opened_height: u64,
    pub fail_closed: bool,
    pub detail: String,
}

impl FailClosedBlocker {
    pub fn new(
        kind: FailClosedBlockerKind,
        subject_id: &str,
        evidence_root: &str,
        opened_height: u64,
        detail: &str,
    ) -> Self {
        let blocker_id = domain_hash(
            "MONERO-FORCE-EXIT-FAIL-CLOSED-BLOCKER-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(evidence_root),
                HashPart::U64(opened_height),
            ],
            16,
        );
        Self {
            blocker_id,
            kind,
            subject_id: subject_id.to_string(),
            evidence_root: evidence_root.to_string(),
            owner_lane: kind.owner_lane().to_string(),
            opened_height,
            fail_closed: kind.is_fail_closed(),
            detail: detail.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({"blocker_id": self.blocker_id, "kind": self.kind.as_str(), "subject_id": self.subject_id, "evidence_root": self.evidence_root, "owner_lane": self.owner_lane, "opened_height": self.opened_height, "fail_closed": self.fail_closed, "detail": self.detail})
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditRoots {
    pub import_root: String,
    pub wallet_review_root: String,
    pub watchtower_replay_root: String,
    pub user_escape_notice_root: String,
    pub recovery_handling_root: String,
    pub signoff_root: String,
    pub blocker_root: String,
    pub dashboard_root: String,
}

impl AuditRoots {
    pub fn public_record(&self) -> Value {
        json!({"import_root": self.import_root, "wallet_review_root": self.wallet_review_root, "watchtower_replay_root": self.watchtower_replay_root, "user_escape_notice_root": self.user_escape_notice_root, "recovery_handling_root": self.recovery_handling_root, "signoff_root": self.signoff_root, "blocker_root": self.blocker_root, "dashboard_root": self.dashboard_root})
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-FORCE-EXIT-RUNBOOK-AUDIT-ROOTS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub release_id: String,
    pub imports: BTreeMap<String, LiveEvidenceImport>,
    pub wallet_reviews: BTreeMap<String, WalletTranscriptReview>,
    pub watchtower_checklists: BTreeMap<String, WatchtowerReplayChecklist>,
    pub user_escape_notices: BTreeMap<String, UserEscapeNotice>,
    pub recovery_handlers: BTreeMap<String, RecoveryNoticeHandling>,
    pub signoffs: BTreeMap<String, OperatorRunbookSignoff>,
    pub blockers: BTreeMap<String, FailClosedBlocker>,
    pub dashboard: Option<ReleaseDashboardReadiness>,
}

impl State {
    pub fn new(config: Config, release_id: &str) -> Self {
        Self {
            config,
            release_id: release_id.to_string(),
            imports: BTreeMap::new(),
            wallet_reviews: BTreeMap::new(),
            watchtower_checklists: BTreeMap::new(),
            user_escape_notices: BTreeMap::new(),
            recovery_handlers: BTreeMap::new(),
            signoffs: BTreeMap::new(),
            blockers: BTreeMap::new(),
            dashboard: None,
        }
    }

    pub fn devnet(operator_label: &str) -> Result<Self> {
        let config = Config::devnet();
        let mut state = Self::new(config.clone(), "force-exit-release-dashboard-devnet");
        let wallet_import = LiveEvidenceImport::accepted(
            "import-wallet-transcript-devnet",
            LiveEvidenceKind::WalletTranscript,
            config.current_height.saturating_sub(18),
            "wallet-transcript-review",
            "wallet-devnet-escape-001",
            operator_label,
            "accepted live wallet transcript for force exit package",
        );
        let replay_import = LiveEvidenceImport::accepted(
            "import-watchtower-replay-devnet",
            LiveEvidenceKind::WatchtowerReplay,
            config.current_height.saturating_sub(16),
            "watchtower-replay",
            "watchtower-devnet-a",
            operator_label,
            "accepted watchtower replay evidence for force exit package",
        );
        let notice_import = LiveEvidenceImport::accepted(
            "import-user-escape-notice-devnet",
            LiveEvidenceKind::UserEscapeNotice,
            config.current_height.saturating_sub(12),
            "user-escape-notice",
            "wallet-devnet-escape-001",
            operator_label,
            "published user escape notice evidence",
        );
        state.accept_import(wallet_import.clone())?;
        state.accept_import(replay_import.clone())?;
        state.accept_import(notice_import.clone())?;
        let wallet_review = WalletTranscriptReview::new(
            "wallet-review-devnet",
            "wallet-devnet-escape-001",
            &wallet_import,
            config.current_height.saturating_sub(80),
            config.current_height.saturating_sub(18),
            18,
            operator_label,
        );
        state.record_wallet_review(wallet_review)?;
        let checklist = WatchtowerReplayChecklist::new(
            "watchtower-checklist-devnet",
            "watchtower-devnet-a",
            &replay_import,
            config.watchtower_replay_confirmations,
            operator_label,
        );
        state.record_watchtower_replay(checklist)?;
        let notice = UserEscapeNotice::published(
            "escape-notice-devnet",
            "wallet-devnet-escape-001",
            "force-exit-devnet-001",
            &notice_import,
            config
                .current_height
                .saturating_add(config.user_escape_notice_sla_blocks),
            "release-dashboard",
            operator_label,
        );
        state.record_user_escape_notice(notice.clone())?;
        state.record_recovery_handling(RecoveryNoticeHandling::not_required(
            "recovery-handling-devnet",
            "wallet-devnet-escape-001",
            &notice,
        ))?;
        let pre_root = state.roots().state_root();
        state.record_signoff(OperatorRunbookSignoff::new(
            "signoff-release-ops-devnet",
            operator_label,
            "release_ops",
            &pre_root,
            config.current_height,
        ))?;
        state.record_signoff(OperatorRunbookSignoff::new(
            "signoff-wallet-ops-devnet",
            "wallet-ops-devnet",
            "wallet_ops",
            &pre_root,
            config.current_height,
        ))?;
        state.evaluate_fail_closed_blockers();
        state.refresh_dashboard("dashboard-devnet")?;
        Ok(state)
    }

    pub fn accept_import(&mut self, import: LiveEvidenceImport) -> Result<()> {
        if self.imports.len() >= self.config.max_imports {
            return Err("live evidence import capacity exceeded".to_string());
        }
        if import.import_id.trim().is_empty() {
            return Err("live evidence import id is empty".to_string());
        }
        if import.evidence_root.trim().is_empty() {
            return Err("live evidence root is empty".to_string());
        }
        self.imports.insert(import.import_id.clone(), import);
        Ok(())
    }

    pub fn record_wallet_review(&mut self, review: WalletTranscriptReview) -> Result<()> {
        if !self.imports.contains_key(&review.import_id) {
            return Err("wallet transcript review references unknown import".to_string());
        }
        self.wallet_reviews.insert(review.review_id.clone(), review);
        Ok(())
    }

    pub fn record_watchtower_replay(&mut self, checklist: WatchtowerReplayChecklist) -> Result<()> {
        if !self.imports.contains_key(&checklist.import_id) {
            return Err("watchtower replay checklist references unknown import".to_string());
        }
        self.watchtower_checklists
            .insert(checklist.checklist_id.clone(), checklist);
        Ok(())
    }

    pub fn record_user_escape_notice(&mut self, notice: UserEscapeNotice) -> Result<()> {
        if !self.imports.contains_key(&notice.import_id) {
            return Err("user escape notice references unknown import".to_string());
        }
        self.user_escape_notices
            .insert(notice.notice_id.clone(), notice);
        Ok(())
    }

    pub fn record_recovery_handling(&mut self, handling: RecoveryNoticeHandling) -> Result<()> {
        if !self.user_escape_notices.contains_key(&handling.notice_id) {
            return Err("recovery handling references unknown notice".to_string());
        }
        self.recovery_handlers
            .insert(handling.recovery_id.clone(), handling);
        Ok(())
    }

    pub fn record_signoff(&mut self, signoff: OperatorRunbookSignoff) -> Result<()> {
        if signoff.signed_root.trim().is_empty() {
            return Err("operator signoff root is empty".to_string());
        }
        self.signoffs.insert(signoff.signoff_id.clone(), signoff);
        Ok(())
    }

    pub fn evaluate_fail_closed_blockers(&mut self) {
        self.blockers.clear();
        for blocker in self.derive_blockers() {
            self.blockers.insert(blocker.blocker_id.clone(), blocker);
        }
    }

    pub fn refresh_dashboard(&mut self, dashboard_id: &str) -> Result<String> {
        self.evaluate_fail_closed_blockers();
        let roots = self.roots();
        let blockers = self.blockers.values().cloned().collect::<Vec<_>>();
        let dashboard = ReleaseDashboardReadiness::from_roots(
            dashboard_id,
            &self.release_id,
            self.config.current_height,
            &roots.wallet_review_root,
            &roots.watchtower_replay_root,
            &roots.user_escape_notice_root,
            &roots.recovery_handling_root,
            &blockers,
        );
        let root = dashboard.state_root();
        self.dashboard = Some(dashboard);
        Ok(root)
    }

    pub fn derive_blockers(&self) -> Vec<FailClosedBlocker> {
        let mut blockers = Vec::new();
        for import in self.imports.values() {
            if import.status.blocks_release() {
                blockers.push(FailClosedBlocker::new(
                    FailClosedBlockerKind::ImportQuarantined,
                    &import.import_id,
                    &import.evidence_root,
                    self.config.current_height,
                    "live evidence import is not accepted for release dashboard binding",
                ));
            }
        }
        if self.wallet_reviews.is_empty() {
            blockers.push(FailClosedBlocker::new(
                FailClosedBlockerKind::NoAcceptedWalletTranscript,
                &self.release_id,
                &self.roots().import_root,
                self.config.current_height,
                "release dashboard has no accepted wallet transcript review",
            ));
        } else {
            for review in self.wallet_reviews.values() {
                let shallow = review.monero_confirmations < self.config.min_monero_confirmations;
                let gapped = review.observed_gap_blocks > self.config.max_wallet_gap_blocks;
                if shallow || gapped || review.blocks_release() {
                    let kind = if shallow {
                        FailClosedBlockerKind::MoneroConfirmationsTooShallow
                    } else {
                        FailClosedBlockerKind::WalletTranscriptFinding
                    };
                    blockers.push(FailClosedBlocker::new(
                        kind,
                        &review.review_id,
                        &review.transcript_root,
                        self.config.current_height,
                        "wallet transcript review is not release-ready",
                    ));
                }
            }
        }
        if self.config.fail_closed_on_replay_gap && self.watchtower_checklists.is_empty() {
            blockers.push(FailClosedBlocker::new(
                FailClosedBlockerKind::WatchtowerReplayIncomplete,
                &self.release_id,
                &self.roots().import_root,
                self.config.current_height,
                "release dashboard has no watchtower replay checklist",
            ));
        }
        for checklist in self.watchtower_checklists.values() {
            let under_confirmed =
                checklist.replay_confirmations < self.config.watchtower_replay_confirmations;
            if under_confirmed || checklist.blocks_release() {
                blockers.push(FailClosedBlocker::new(
                    FailClosedBlockerKind::WatchtowerReplayIncomplete,
                    &checklist.checklist_id,
                    &checklist.replay_root,
                    self.config.current_height,
                    "watchtower replay checklist is incomplete or under-confirmed",
                ));
            }
        }
        if self.config.fail_closed_on_notice_gap && self.user_escape_notices.is_empty() {
            blockers.push(FailClosedBlocker::new(
                FailClosedBlockerKind::UserEscapeNoticeMissing,
                &self.release_id,
                &self.roots().import_root,
                self.config.current_height,
                "release dashboard has no published user escape notice",
            ));
        }
        for notice in self.user_escape_notices.values() {
            if notice.blocks_release(self.config.current_height) {
                blockers.push(FailClosedBlocker::new(
                    FailClosedBlockerKind::UserEscapeNoticeMissing,
                    &notice.notice_id,
                    &notice.notice_root,
                    self.config.current_height,
                    "user escape notice is missing, expired, blocked, or not live",
                ));
            }
        }
        if self.config.fail_closed_on_recovery_gap
            && !self.user_escape_notices.is_empty()
            && self.recovery_handlers.is_empty()
        {
            blockers.push(FailClosedBlocker::new(
                FailClosedBlockerKind::RecoveryNoticeUnresolved,
                &self.release_id,
                &self.roots().user_escape_notice_root,
                self.config.current_height,
                "release dashboard has escape notices without recovery handling records",
            ));
        }
        for handling in self.recovery_handlers.values() {
            if handling.blocks_release(
                self.config.current_height,
                self.config.recovery_notice_sla_blocks,
            ) {
                blockers.push(FailClosedBlocker::new(
                    FailClosedBlockerKind::RecoveryNoticeUnresolved,
                    &handling.recovery_id,
                    &handling.recovery_root,
                    self.config.current_height,
                    "recovery notice handling is unresolved or stale",
                ));
            }
        }
        let unique_operators = self
            .signoffs
            .values()
            .map(|signoff| signoff.operator_id.clone())
            .collect::<BTreeSet<_>>();
        if (unique_operators.len() as u64) < self.config.min_operator_signoffs {
            blockers.push(FailClosedBlocker::new(
                FailClosedBlockerKind::OperatorSignoffInsufficient,
                &self.release_id,
                &self.roots().signoff_root,
                self.config.current_height,
                "operator runbook has insufficient distinct operator signoffs",
            ));
        }
        if let Some(dashboard) = &self.dashboard {
            if dashboard.blocks_release(
                self.config.current_height,
                self.config.dashboard_refresh_blocks,
            ) {
                blockers.push(FailClosedBlocker::new(
                    FailClosedBlockerKind::ReleaseDashboardBlocked,
                    &dashboard.dashboard_id,
                    &dashboard.dashboard_root,
                    self.config.current_height,
                    "release dashboard is blocked or stale",
                ));
            }
        }
        blockers
    }

    pub fn roots(&self) -> AuditRoots {
        AuditRoots {
            import_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-IMPORTS",
                &self
                    .imports
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            wallet_review_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-WALLET-REVIEWS",
                &self
                    .wallet_reviews
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            watchtower_replay_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-WATCHTOWER-REPLAYS",
                &self
                    .watchtower_checklists
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            user_escape_notice_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-USER-ESCAPE-NOTICES",
                &self
                    .user_escape_notices
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            recovery_handling_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-RECOVERY-HANDLING",
                &self
                    .recovery_handlers
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            signoff_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-SIGNOFFS",
                &self
                    .signoffs
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            blocker_root: merkle_root(
                "MONERO-FORCE-EXIT-RUNBOOK-BLOCKERS",
                &self
                    .blockers
                    .values()
                    .map(|record| record.public_record())
                    .collect::<Vec<_>>(),
            ),
            dashboard_root: self
                .dashboard
                .as_ref()
                .map(|dashboard| dashboard.state_root())
                .unwrap_or_else(|| {
                    domain_hash(
                        "MONERO-FORCE-EXIT-RUNBOOK-DASHBOARD-EMPTY",
                        &[HashPart::Str(&self.release_id)],
                        32,
                    )
                }),
        }
    }

    pub fn readiness_summary(&self) -> Value {
        let fail_closed_blockers = self
            .blockers
            .values()
            .filter(|blocker| blocker.fail_closed)
            .count() as u64;
        let watch_blockers = self
            .blockers
            .values()
            .filter(|blocker| !blocker.fail_closed)
            .count() as u64;
        let status = if fail_closed_blockers > 0 {
            DashboardReadinessStatus::Blocked
        } else if watch_blockers > 0 {
            DashboardReadinessStatus::Watch
        } else {
            DashboardReadinessStatus::Ready
        };
        let summary_seed = json!({
            "release_id": self.release_id,
            "status": status.as_str(),
            "accepted_imports": self.accepted_imports(),
            "wallet_reviews": self.wallet_reviews.len(),
            "watchtower_checklists": self.watchtower_checklists.len(),
            "user_notices": self.user_escape_notices.len(),
            "recovery_handlers": self.recovery_handlers.len(),
            "operator_signoffs": self.signoffs.len(),
            "fail_closed_blockers": fail_closed_blockers,
            "watch_blockers": watch_blockers,
            "roots": self.roots().public_record(),
        });
        json!({
            "release_id": self.release_id,
            "ready": matches!(status, DashboardReadinessStatus::Ready),
            "status": status.as_str(),
            "accepted_imports": self.accepted_imports(),
            "wallet_reviews": self.wallet_reviews.len(),
            "watchtower_checklists": self.watchtower_checklists.len(),
            "user_notices": self.user_escape_notices.len(),
            "recovery_handlers": self.recovery_handlers.len(),
            "operator_signoffs": self.signoffs.len(),
            "fail_closed_blockers": fail_closed_blockers,
            "watch_blockers": watch_blockers,
            "root": domain_hash(
                "MONERO-FORCE-EXIT-RUNBOOK-READINESS-SUMMARY",
                &[HashPart::Json(&summary_seed)],
                32,
            ),
        })
    }

    pub fn accepted_imports(&self) -> u64 {
        self.imports
            .values()
            .filter(|import| import.is_live_for_release())
            .count() as u64
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "release_id": self.release_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "readiness_summary": self.readiness_summary(),
            "imports": self.imports.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "wallet_reviews": self.wallet_reviews.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "watchtower_checklists": self.watchtower_checklists.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "user_escape_notices": self.user_escape_notices.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "recovery_handlers": self.recovery_handlers.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "signoffs": self.signoffs.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "blockers": self.blockers.values().map(|record| record.public_record()).collect::<Vec<_>>(),
            "dashboard": self.dashboard.as_ref().map(|dashboard| dashboard.public_record()),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-FORCE-EXIT-RUNBOOK-AUDIT-RUNTIME-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

pub fn devnet_for_operator(operator_label: &str) -> Result<State> {
    State::devnet(operator_label)
}

pub fn devnet() -> State {
    match State::devnet("wallet-watchtower-release-operator") {
        Ok(state) => state,
        Err(_) => State::new(Config::devnet(), "force-exit-release-dashboard-fallback"),
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}
