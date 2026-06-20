use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageAuditSecurityAcceptedLiveEvidenceOperatorRunbookAuditRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-audit-security-accepted-live-evidence-operator-runbook-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_AUDIT_SUITE: &str =
    "monero-l2-pq-bridge-exit-force-exit-live-evidence-operator-runbook-audit-v1";
pub const DEFAULT_MIN_REVIEWER_SIGNOFFS: u64 = 4;
pub const DEFAULT_MIN_FINDINGS_CLOSED: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_ATTESTATIONS: u64 = 5;
pub const DEFAULT_MIN_LIVE_EVIDENCE_IMPORTS: u64 = 9;
pub const DEFAULT_MAX_OPEN_FINDINGS: u64 = 0;
pub const DEFAULT_MAX_ESCALATION_HOLDS: u64 = 0;
pub const DEFAULT_MAX_RUNBOOK_RECORDS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceImportDomain {
    CanonicalUserEscapeAnswer,
    ForceExitPackage,
    LiveOperatorRunbook,
    SecurityAcceptedAudit,
    ReleaseDashboardReadiness,
    PrivacyNonLinkage,
    ReviewerSignoff,
    FindingClosure,
    EscalationHold,
    FailClosedBlocker,
}

impl EvidenceImportDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalUserEscapeAnswer => "canonical_user_escape_answer",
            Self::ForceExitPackage => "force_exit_package",
            Self::LiveOperatorRunbook => "live_operator_runbook",
            Self::SecurityAcceptedAudit => "security_accepted_audit",
            Self::ReleaseDashboardReadiness => "release_dashboard_readiness",
            Self::PrivacyNonLinkage => "privacy_non_linkage",
            Self::ReviewerSignoff => "reviewer_signoff",
            Self::FindingClosure => "finding_closure",
            Self::EscalationHold => "escalation_hold",
            Self::FailClosedBlocker => "fail_closed_blocker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookStepKind {
    IntakeLiveEvidence,
    BindCanonicalAnswer,
    VerifyForceExitPackage,
    ReviewSecurityAcceptance,
    CloseFindings,
    AttestPrivacyNonLinkage,
    CheckEscalationHolds,
    PublishDashboardReadiness,
    PreserveFailClosedBlockers,
    ArchiveAuditPacket,
}

impl RunbookStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntakeLiveEvidence => "intake_live_evidence",
            Self::BindCanonicalAnswer => "bind_canonical_answer",
            Self::VerifyForceExitPackage => "verify_force_exit_package",
            Self::ReviewSecurityAcceptance => "review_security_acceptance",
            Self::CloseFindings => "close_findings",
            Self::AttestPrivacyNonLinkage => "attest_privacy_non_linkage",
            Self::CheckEscalationHolds => "check_escalation_holds",
            Self::PublishDashboardReadiness => "publish_dashboard_readiness",
            Self::PreserveFailClosedBlockers => "preserve_fail_closed_blockers",
            Self::ArchiveAuditPacket => "archive_audit_packet",
        }
    }

    pub fn expected_domain(self) -> EvidenceImportDomain {
        match self {
            Self::IntakeLiveEvidence => EvidenceImportDomain::LiveOperatorRunbook,
            Self::BindCanonicalAnswer => EvidenceImportDomain::CanonicalUserEscapeAnswer,
            Self::VerifyForceExitPackage => EvidenceImportDomain::ForceExitPackage,
            Self::ReviewSecurityAcceptance => EvidenceImportDomain::SecurityAcceptedAudit,
            Self::CloseFindings => EvidenceImportDomain::FindingClosure,
            Self::AttestPrivacyNonLinkage => EvidenceImportDomain::PrivacyNonLinkage,
            Self::CheckEscalationHolds => EvidenceImportDomain::EscalationHold,
            Self::PublishDashboardReadiness => EvidenceImportDomain::ReleaseDashboardReadiness,
            Self::PreserveFailClosedBlockers => EvidenceImportDomain::FailClosedBlocker,
            Self::ArchiveAuditPacket => EvidenceImportDomain::LiveOperatorRunbook,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepDisposition {
    Accepted,
    Watch,
    Blocked,
    Rejected,
    Deferred,
}

impl StepDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
        }
    }

    pub fn is_fail_closed(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected | Self::Deferred)
    }

    pub fn blocks_dashboard(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerRole {
    ReleaseCaptain,
    SecurityReviewer,
    PrivacyReviewer,
    RuntimeMaintainer,
    IncidentCommander,
    AuditArchivist,
}

impl ReviewerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCaptain => "release_captain",
            Self::SecurityReviewer => "security_reviewer",
            Self::PrivacyReviewer => "privacy_reviewer",
            Self::RuntimeMaintainer => "runtime_maintainer",
            Self::IncidentCommander => "incident_commander",
            Self::AuditArchivist => "audit_archivist",
        }
    }

    pub fn is_required_for_release(self) -> bool {
        matches!(
            self,
            Self::ReleaseCaptain
                | Self::SecurityReviewer
                | Self::PrivacyReviewer
                | Self::RuntimeMaintainer
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Mitigated,
    Closed,
    AcceptedRisk,
    Reopened,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Mitigated => "mitigated",
            Self::Closed => "closed",
            Self::AcceptedRisk => "accepted_risk",
            Self::Reopened => "reopened",
        }
    }

    pub fn is_closed(self) -> bool {
        matches!(self, Self::Mitigated | Self::Closed | Self::AcceptedRisk)
    }

    pub fn is_open(self) -> bool {
        matches!(self, Self::Open | Self::Reopened)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAttestationKind {
    NoLinkageAcrossEscapeAnswers,
    NoOperatorAddressCorrelation,
    NoReceiptGraphDisclosure,
    NoReviewerIdentityLeak,
    RedactionBudgetPreserved,
    DashboardOnlyShowsPublicRoots,
}

impl PrivacyAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoLinkageAcrossEscapeAnswers => "no_linkage_across_escape_answers",
            Self::NoOperatorAddressCorrelation => "no_operator_address_correlation",
            Self::NoReceiptGraphDisclosure => "no_receipt_graph_disclosure",
            Self::NoReviewerIdentityLeak => "no_reviewer_identity_leak",
            Self::RedactionBudgetPreserved => "redaction_budget_preserved",
            Self::DashboardOnlyShowsPublicRoots => "dashboard_only_shows_public_roots",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationHoldKind {
    IncidentReview,
    ReviewerConflict,
    PrivacyRegression,
    EvidenceMismatch,
    ForceExitPackageGap,
    ReleaseDashboardFreeze,
}

impl EscalationHoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncidentReview => "incident_review",
            Self::ReviewerConflict => "reviewer_conflict",
            Self::PrivacyRegression => "privacy_regression",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::ForceExitPackageGap => "force_exit_package_gap",
            Self::ReleaseDashboardFreeze => "release_dashboard_freeze",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardReadinessStatus {
    Ready,
    ReadyForUserReleaseOnly,
    Watch,
    Blocked,
    Rejected,
}

impl DashboardReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ReadyForUserReleaseOnly => "ready_for_user_release_only",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_audit_suite: String,
    pub min_reviewer_signoffs: u64,
    pub min_findings_closed: u64,
    pub min_privacy_attestations: u64,
    pub min_live_evidence_imports: u64,
    pub max_open_findings: u64,
    pub max_escalation_holds: u64,
    pub max_runbook_records: usize,
    pub production_dashboard_enabled: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_audit_suite: RUNBOOK_AUDIT_SUITE.to_string(),
            min_reviewer_signoffs: DEFAULT_MIN_REVIEWER_SIGNOFFS,
            min_findings_closed: DEFAULT_MIN_FINDINGS_CLOSED,
            min_privacy_attestations: DEFAULT_MIN_PRIVACY_ATTESTATIONS,
            min_live_evidence_imports: DEFAULT_MIN_LIVE_EVIDENCE_IMPORTS,
            max_open_findings: DEFAULT_MAX_OPEN_FINDINGS,
            max_escalation_holds: DEFAULT_MAX_ESCALATION_HOLDS,
            max_runbook_records: DEFAULT_MAX_RUNBOOK_RECORDS,
            production_dashboard_enabled: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "runbook_audit_suite": self.runbook_audit_suite,
            "min_reviewer_signoffs": self.min_reviewer_signoffs,
            "min_findings_closed": self.min_findings_closed,
            "min_privacy_attestations": self.min_privacy_attestations,
            "min_live_evidence_imports": self.min_live_evidence_imports,
            "max_open_findings": self.max_open_findings,
            "max_escalation_holds": self.max_escalation_holds,
            "max_runbook_records": self.max_runbook_records,
            "production_dashboard_enabled": self.production_dashboard_enabled,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveEvidenceImport {
    pub import_id: String,
    pub domain: EvidenceImportDomain,
    pub label: String,
    pub source_system: String,
    pub source_record_id: String,
    pub evidence_root: String,
    pub accepted_root: String,
    pub canonical_answer_root: String,
    pub force_exit_package_root: String,
    pub redacted_public_record: Value,
    pub imported_by: String,
    pub imported_at_slot: u64,
    pub accepted_by_security: bool,
    pub dashboard_visible: bool,
}

impl LiveEvidenceImport {
    pub fn public_record(&self) -> Value {
        json!({
            "import_id": self.import_id,
            "domain": self.domain.as_str(),
            "label": self.label,
            "source_system": self.source_system,
            "source_record_id": self.source_record_id,
            "evidence_root": self.evidence_root,
            "accepted_root": self.accepted_root,
            "canonical_answer_root": self.canonical_answer_root,
            "force_exit_package_root": self.force_exit_package_root,
            "redacted_public_record": self.redacted_public_record,
            "imported_by": self.imported_by,
            "imported_at_slot": self.imported_at_slot,
            "accepted_by_security": self.accepted_by_security,
            "dashboard_visible": self.dashboard_visible,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_evidence_import", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReviewerSignoff {
    pub signoff_id: String,
    pub role: ReviewerRole,
    pub reviewer_id: String,
    pub runbook_step: RunbookStepKind,
    pub evidence_root: String,
    pub signoff_root: String,
    pub signed_at_slot: u64,
    pub accepted: bool,
    pub notes_root: String,
}

impl ReviewerSignoff {
    pub fn public_record(&self) -> Value {
        json!({
            "signoff_id": self.signoff_id,
            "role": self.role.as_str(),
            "reviewer_id": self.reviewer_id,
            "runbook_step": self.runbook_step.as_str(),
            "evidence_root": self.evidence_root,
            "signoff_root": self.signoff_root,
            "signed_at_slot": self.signed_at_slot,
            "accepted": self.accepted,
            "notes_root": self.notes_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reviewer_signoff", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FindingClosure {
    pub finding_id: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub title: String,
    pub source_evidence_root: String,
    pub closure_evidence_root: String,
    pub reviewer_signoff_root: String,
    pub remediation_summary: String,
    pub closed_at_slot: u64,
    pub dashboard_blocker: bool,
}

impl FindingClosure {
    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "title": self.title,
            "source_evidence_root": self.source_evidence_root,
            "closure_evidence_root": self.closure_evidence_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
            "remediation_summary": self.remediation_summary,
            "closed_at_slot": self.closed_at_slot,
            "dashboard_blocker": self.dashboard_blocker,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("finding_closure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNonLinkageAttestation {
    pub attestation_id: String,
    pub kind: PrivacyAttestationKind,
    pub attestor_id: String,
    pub source_evidence_root: String,
    pub non_linkage_root: String,
    pub redaction_policy_root: String,
    pub public_dashboard_root: String,
    pub attested_at_slot: u64,
    pub passes: bool,
}

impl PrivacyNonLinkageAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "attestor_id": self.attestor_id,
            "source_evidence_root": self.source_evidence_root,
            "non_linkage_root": self.non_linkage_root,
            "redaction_policy_root": self.redaction_policy_root,
            "public_dashboard_root": self.public_dashboard_root,
            "attested_at_slot": self.attested_at_slot,
            "passes": self.passes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("privacy_non_linkage_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscalationHold {
    pub hold_id: String,
    pub kind: EscalationHoldKind,
    pub owner_role: ReviewerRole,
    pub reason: String,
    pub source_evidence_root: String,
    pub hold_root: String,
    pub opened_at_slot: u64,
    pub released_at_slot: u64,
    pub active: bool,
}

impl EscalationHold {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "kind": self.kind.as_str(),
            "owner_role": self.owner_role.as_str(),
            "reason": self.reason,
            "source_evidence_root": self.source_evidence_root,
            "hold_root": self.hold_root,
            "opened_at_slot": self.opened_at_slot,
            "released_at_slot": self.released_at_slot,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("escalation_hold", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunbookStepAudit {
    pub step_id: String,
    pub kind: RunbookStepKind,
    pub domain: EvidenceImportDomain,
    pub disposition: StepDisposition,
    pub sequence_index: u64,
    pub evidence_import_root: String,
    pub reviewer_signoff_root: String,
    pub finding_closure_root: String,
    pub privacy_attestation_root: String,
    pub escalation_hold_root: String,
    pub operator_instruction: String,
    pub fail_closed_reason: String,
    pub step_root: String,
}

impl RunbookStepAudit {
    pub fn blocks_dashboard(&self) -> bool {
        self.disposition.blocks_dashboard()
            || self.escalation_hold_root != EMPTY_ROOT
            || !self.fail_closed_reason.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "kind": self.kind.as_str(),
            "domain": self.domain.as_str(),
            "disposition": self.disposition.as_str(),
            "sequence_index": self.sequence_index,
            "evidence_import_root": self.evidence_import_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
            "finding_closure_root": self.finding_closure_root,
            "privacy_attestation_root": self.privacy_attestation_root,
            "escalation_hold_root": self.escalation_hold_root,
            "operator_instruction": self.operator_instruction,
            "fail_closed_reason": self.fail_closed_reason,
            "step_root": self.step_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.step_root.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditCounters {
    pub live_evidence_imports: u64,
    pub security_accepted_imports: u64,
    pub dashboard_visible_imports: u64,
    pub reviewer_signoffs: u64,
    pub required_reviewer_signoffs: u64,
    pub findings_total: u64,
    pub findings_closed: u64,
    pub findings_open: u64,
    pub high_or_critical_findings_open: u64,
    pub privacy_attestations: u64,
    pub privacy_attestations_passed: u64,
    pub escalation_holds_total: u64,
    pub escalation_holds_active: u64,
    pub runbook_steps: u64,
    pub runbook_steps_accepted: u64,
    pub runbook_steps_fail_closed: u64,
    pub dashboard_blockers: u64,
}

impl AuditCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "live_evidence_imports": self.live_evidence_imports,
            "security_accepted_imports": self.security_accepted_imports,
            "dashboard_visible_imports": self.dashboard_visible_imports,
            "reviewer_signoffs": self.reviewer_signoffs,
            "required_reviewer_signoffs": self.required_reviewer_signoffs,
            "findings_total": self.findings_total,
            "findings_closed": self.findings_closed,
            "findings_open": self.findings_open,
            "high_or_critical_findings_open": self.high_or_critical_findings_open,
            "privacy_attestations": self.privacy_attestations,
            "privacy_attestations_passed": self.privacy_attestations_passed,
            "escalation_holds_total": self.escalation_holds_total,
            "escalation_holds_active": self.escalation_holds_active,
            "runbook_steps": self.runbook_steps,
            "runbook_steps_accepted": self.runbook_steps_accepted,
            "runbook_steps_fail_closed": self.runbook_steps_fail_closed,
            "dashboard_blockers": self.dashboard_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("audit_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailClosedBlocker {
    pub blocker_id: String,
    pub label: String,
    pub owner_role: ReviewerRole,
    pub source_root: String,
    pub blocker_root: String,
    pub release_dashboard_reason: String,
    pub user_release_reason: String,
    pub active: bool,
}

impl FailClosedBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "label": self.label,
            "owner_role": self.owner_role.as_str(),
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "release_dashboard_reason": self.release_dashboard_reason,
            "user_release_reason": self.user_release_reason,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        self.blocker_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DashboardReadiness {
    pub dashboard_id: String,
    pub status: DashboardReadinessStatus,
    pub readiness_label: String,
    pub user_release_answer: String,
    pub production_release_answer: String,
    pub evidence_import_root: String,
    pub runbook_step_root: String,
    pub reviewer_signoff_root: String,
    pub finding_closure_root: String,
    pub privacy_attestation_root: String,
    pub escalation_hold_root: String,
    pub fail_closed_blocker_root: String,
    pub counter_root: String,
    pub dashboard_root: String,
}

impl DashboardReadiness {
    pub fn public_record(&self) -> Value {
        json!({
            "dashboard_id": self.dashboard_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "user_release_answer": self.user_release_answer,
            "production_release_answer": self.production_release_answer,
            "evidence_import_root": self.evidence_import_root,
            "runbook_step_root": self.runbook_step_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
            "finding_closure_root": self.finding_closure_root,
            "privacy_attestation_root": self.privacy_attestation_root,
            "escalation_hold_root": self.escalation_hold_root,
            "fail_closed_blocker_root": self.fail_closed_blocker_root,
            "counter_root": self.counter_root,
            "dashboard_root": self.dashboard_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.dashboard_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence_imports: BTreeMap<String, LiveEvidenceImport>,
    pub reviewer_signoffs: BTreeMap<String, ReviewerSignoff>,
    pub finding_closures: BTreeMap<String, FindingClosure>,
    pub privacy_attestations: BTreeMap<String, PrivacyNonLinkageAttestation>,
    pub escalation_holds: BTreeMap<String, EscalationHold>,
    pub runbook_steps: BTreeMap<String, RunbookStepAudit>,
    pub fail_closed_blockers: BTreeMap<String, FailClosedBlocker>,
    pub counters: AuditCounters,
    pub dashboard: DashboardReadiness,
}

impl State {
    pub fn new(config: Config) -> Self {
        let seed_root = seed_root(&config.chain_id);
        let evidence_imports = default_evidence_imports(&seed_root);
        let reviewer_signoffs = default_reviewer_signoffs(&seed_root, &evidence_imports);
        let finding_closures = default_finding_closures(&seed_root, &reviewer_signoffs);
        let privacy_attestations = default_privacy_attestations(&seed_root, &evidence_imports);
        let escalation_holds = default_escalation_holds(&seed_root, &evidence_imports);
        Self::from_records(
            config,
            evidence_imports,
            reviewer_signoffs,
            finding_closures,
            privacy_attestations,
            escalation_holds,
        )
    }

    pub fn from_records(
        config: Config,
        evidence_imports: BTreeMap<String, LiveEvidenceImport>,
        reviewer_signoffs: BTreeMap<String, ReviewerSignoff>,
        finding_closures: BTreeMap<String, FindingClosure>,
        privacy_attestations: BTreeMap<String, PrivacyNonLinkageAttestation>,
        escalation_holds: BTreeMap<String, EscalationHold>,
    ) -> Self {
        let mut limited_imports = BTreeMap::new();
        for (key, value) in evidence_imports
            .into_iter()
            .take(config.max_runbook_records)
        {
            limited_imports.insert(key, value);
        }
        let mut limited_signoffs = BTreeMap::new();
        for (key, value) in reviewer_signoffs
            .into_iter()
            .take(config.max_runbook_records)
        {
            limited_signoffs.insert(key, value);
        }
        let mut limited_findings = BTreeMap::new();
        for (key, value) in finding_closures
            .into_iter()
            .take(config.max_runbook_records)
        {
            limited_findings.insert(key, value);
        }
        let mut limited_privacy = BTreeMap::new();
        for (key, value) in privacy_attestations
            .into_iter()
            .take(config.max_runbook_records)
        {
            limited_privacy.insert(key, value);
        }
        let mut limited_holds = BTreeMap::new();
        for (key, value) in escalation_holds
            .into_iter()
            .take(config.max_runbook_records)
        {
            limited_holds.insert(key, value);
        }
        let counters = derive_counters(
            &limited_imports,
            &limited_signoffs,
            &limited_findings,
            &limited_privacy,
            &limited_holds,
        );
        let runbook_steps = derive_runbook_steps(
            &config,
            &limited_imports,
            &limited_signoffs,
            &limited_findings,
            &limited_privacy,
            &limited_holds,
            &counters,
        );
        let fail_closed_blockers = derive_fail_closed_blockers(
            &config,
            &limited_imports,
            &limited_signoffs,
            &limited_findings,
            &limited_privacy,
            &limited_holds,
            &runbook_steps,
            &counters,
        );
        let counters = with_step_counters(counters, &runbook_steps, &fail_closed_blockers);
        let dashboard = build_dashboard_readiness(
            &config,
            &limited_imports,
            &limited_signoffs,
            &limited_findings,
            &limited_privacy,
            &limited_holds,
            &runbook_steps,
            &fail_closed_blockers,
            &counters,
        );
        Self {
            config,
            evidence_imports: limited_imports,
            reviewer_signoffs: limited_signoffs,
            finding_closures: limited_findings,
            privacy_attestations: limited_privacy,
            escalation_holds: limited_holds,
            runbook_steps,
            fail_closed_blockers,
            counters,
            dashboard,
        }
    }

    pub fn ingest_evidence_import(&mut self, import: LiveEvidenceImport) -> Result<()> {
        ensure_capacity(self.evidence_imports.len(), self.config.max_runbook_records)?;
        self.evidence_imports
            .insert(import.import_id.clone(), import);
        self.rebuild();
        Ok(())
    }

    pub fn add_reviewer_signoff(&mut self, signoff: ReviewerSignoff) -> Result<()> {
        ensure_capacity(
            self.reviewer_signoffs.len(),
            self.config.max_runbook_records,
        )?;
        self.reviewer_signoffs
            .insert(signoff.signoff_id.clone(), signoff);
        self.rebuild();
        Ok(())
    }

    pub fn close_finding(&mut self, closure: FindingClosure) -> Result<()> {
        ensure_capacity(self.finding_closures.len(), self.config.max_runbook_records)?;
        self.finding_closures
            .insert(closure.finding_id.clone(), closure);
        self.rebuild();
        Ok(())
    }

    pub fn attest_privacy(&mut self, attestation: PrivacyNonLinkageAttestation) -> Result<()> {
        ensure_capacity(
            self.privacy_attestations.len(),
            self.config.max_runbook_records,
        )?;
        self.privacy_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.rebuild();
        Ok(())
    }

    pub fn place_escalation_hold(&mut self, hold: EscalationHold) -> Result<()> {
        ensure_capacity(self.escalation_holds.len(), self.config.max_runbook_records)?;
        self.escalation_holds.insert(hold.hold_id.clone(), hold);
        self.rebuild();
        Ok(())
    }

    pub fn release_dashboard_ready(&self) -> bool {
        matches!(self.dashboard.status, DashboardReadinessStatus::Ready)
    }

    pub fn user_release_ready(&self) -> bool {
        matches!(
            self.dashboard.status,
            DashboardReadinessStatus::Ready | DashboardReadinessStatus::ReadyForUserReleaseOnly
        )
    }

    pub fn fail_closed(&self) -> bool {
        !self.fail_closed_blockers.is_empty()
            || self.counters.dashboard_blockers > 0
            || self.counters.escalation_holds_active > self.config.max_escalation_holds
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-force-exit-live-evidence-runbook-audit-state",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.dashboard.dashboard_root),
                HashPart::Str(&self.dashboard.evidence_import_root),
                HashPart::Str(&self.dashboard.runbook_step_root),
                HashPart::Str(&self.dashboard.fail_closed_blocker_root),
                HashPart::Str(&self.counters.state_root()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "runbook_audit_suite": RUNBOOK_AUDIT_SUITE,
            "chain_id": self.config.chain_id,
            "state_root": self.state_root(),
            "config": self.config.public_record(),
            "dashboard": self.dashboard.public_record(),
            "counters": self.counters.public_record(),
            "evidence_imports": self.evidence_imports.values().map(LiveEvidenceImport::public_record).collect::<Vec<_>>(),
            "reviewer_signoffs": self.reviewer_signoffs.values().map(ReviewerSignoff::public_record).collect::<Vec<_>>(),
            "finding_closures": self.finding_closures.values().map(FindingClosure::public_record).collect::<Vec<_>>(),
            "privacy_attestations": self.privacy_attestations.values().map(PrivacyNonLinkageAttestation::public_record).collect::<Vec<_>>(),
            "escalation_holds": self.escalation_holds.values().map(EscalationHold::public_record).collect::<Vec<_>>(),
            "runbook_steps": self.runbook_steps.values().map(RunbookStepAudit::public_record).collect::<Vec<_>>(),
            "fail_closed_blockers": self.fail_closed_blockers.values().map(FailClosedBlocker::public_record).collect::<Vec<_>>(),
            "release_dashboard_binding": {
                "dashboard_status": self.dashboard.status.as_str(),
                "user_release_ready": self.user_release_ready(),
                "production_release_ready": self.release_dashboard_ready(),
                "fail_closed": self.fail_closed(),
                "accepted_live_evidence_imports": self.counters.security_accepted_imports,
                "privacy_non_linkage_attestations_passed": self.counters.privacy_attestations_passed,
                "open_findings": self.counters.findings_open,
                "active_escalation_holds": self.counters.escalation_holds_active,
            },
        })
    }

    fn rebuild(&mut self) {
        *self = Self::from_records(
            self.config.clone(),
            self.evidence_imports.clone(),
            self.reviewer_signoffs.clone(),
            self.finding_closures.clone(),
            self.privacy_attestations.clone(),
            self.escalation_holds.clone(),
        );
    }
}

pub fn devnet() -> State {
    State::new(Config::devnet())
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn ensure_capacity(current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        return Err("operator runbook audit runtime capacity reached".to_string());
    }
    Ok(())
}

fn derive_counters(
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
    finding_closures: &BTreeMap<String, FindingClosure>,
    privacy_attestations: &BTreeMap<String, PrivacyNonLinkageAttestation>,
    escalation_holds: &BTreeMap<String, EscalationHold>,
) -> AuditCounters {
    let mut counters = AuditCounters::default();
    counters.live_evidence_imports = evidence_imports.len() as u64;
    counters.security_accepted_imports = evidence_imports
        .values()
        .filter(|import| import.accepted_by_security)
        .count() as u64;
    counters.dashboard_visible_imports = evidence_imports
        .values()
        .filter(|import| import.dashboard_visible)
        .count() as u64;
    counters.reviewer_signoffs = reviewer_signoffs
        .values()
        .filter(|signoff| signoff.accepted)
        .count() as u64;
    counters.required_reviewer_signoffs = reviewer_signoffs
        .values()
        .filter(|signoff| signoff.accepted && signoff.role.is_required_for_release())
        .count() as u64;
    counters.findings_total = finding_closures.len() as u64;
    counters.findings_closed = finding_closures
        .values()
        .filter(|finding| finding.status.is_closed())
        .count() as u64;
    counters.findings_open = finding_closures
        .values()
        .filter(|finding| finding.status.is_open())
        .count() as u64;
    counters.high_or_critical_findings_open = finding_closures
        .values()
        .filter(|finding| finding.status.is_open() && finding.severity.blocks_release())
        .count() as u64;
    counters.privacy_attestations = privacy_attestations.len() as u64;
    counters.privacy_attestations_passed = privacy_attestations
        .values()
        .filter(|attestation| attestation.passes)
        .count() as u64;
    counters.escalation_holds_total = escalation_holds.len() as u64;
    counters.escalation_holds_active =
        escalation_holds.values().filter(|hold| hold.active).count() as u64;
    counters
}

fn with_step_counters(
    mut counters: AuditCounters,
    runbook_steps: &BTreeMap<String, RunbookStepAudit>,
    fail_closed_blockers: &BTreeMap<String, FailClosedBlocker>,
) -> AuditCounters {
    counters.runbook_steps = runbook_steps.len() as u64;
    counters.runbook_steps_accepted = runbook_steps
        .values()
        .filter(|step| matches!(step.disposition, StepDisposition::Accepted))
        .count() as u64;
    counters.runbook_steps_fail_closed = runbook_steps
        .values()
        .filter(|step| step.disposition.is_fail_closed())
        .count() as u64;
    counters.dashboard_blockers = fail_closed_blockers
        .values()
        .filter(|blocker| blocker.active)
        .count() as u64;
    counters
}

fn derive_runbook_steps(
    config: &Config,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
    finding_closures: &BTreeMap<String, FindingClosure>,
    privacy_attestations: &BTreeMap<String, PrivacyNonLinkageAttestation>,
    escalation_holds: &BTreeMap<String, EscalationHold>,
    counters: &AuditCounters,
) -> BTreeMap<String, RunbookStepAudit> {
    let kinds = [
        RunbookStepKind::IntakeLiveEvidence,
        RunbookStepKind::BindCanonicalAnswer,
        RunbookStepKind::VerifyForceExitPackage,
        RunbookStepKind::ReviewSecurityAcceptance,
        RunbookStepKind::CloseFindings,
        RunbookStepKind::AttestPrivacyNonLinkage,
        RunbookStepKind::CheckEscalationHolds,
        RunbookStepKind::PublishDashboardReadiness,
        RunbookStepKind::PreserveFailClosedBlockers,
        RunbookStepKind::ArchiveAuditPacket,
    ];
    let mut steps = BTreeMap::new();
    for (index, kind) in kinds.iter().enumerate() {
        let step = derive_runbook_step(
            config,
            *kind,
            index as u64,
            evidence_imports,
            reviewer_signoffs,
            finding_closures,
            privacy_attestations,
            escalation_holds,
            counters,
        );
        steps.insert(step.step_id.clone(), step);
    }
    steps
}

fn derive_runbook_step(
    config: &Config,
    kind: RunbookStepKind,
    sequence_index: u64,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
    finding_closures: &BTreeMap<String, FindingClosure>,
    privacy_attestations: &BTreeMap<String, PrivacyNonLinkageAttestation>,
    escalation_holds: &BTreeMap<String, EscalationHold>,
    counters: &AuditCounters,
) -> RunbookStepAudit {
    let domain = kind.expected_domain();
    let evidence_import_root = root_for_domain(evidence_imports, domain);
    let reviewer_signoff_root = root_for_step_signoff(reviewer_signoffs, kind);
    let finding_closure_root = root_for_findings(finding_closures);
    let privacy_attestation_root = root_for_privacy(privacy_attestations);
    let escalation_hold_root = root_for_holds(escalation_holds, true);
    let disposition = disposition_for_step(config, kind, counters);
    let fail_closed_reason = fail_closed_reason_for_step(config, kind, counters);
    let operator_instruction = operator_instruction_for_step(kind, disposition);
    let step_id = runbook_step_id(kind, sequence_index, &evidence_import_root);
    let step_root = domain_hash(
        "monero-l2-pq-bridge-exit-runbook-step-audit",
        &[
            HashPart::Str(&step_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(domain.as_str()),
            HashPart::Str(disposition.as_str()),
            HashPart::U64(sequence_index),
            HashPart::Str(&evidence_import_root),
            HashPart::Str(&reviewer_signoff_root),
            HashPart::Str(&finding_closure_root),
            HashPart::Str(&privacy_attestation_root),
            HashPart::Str(&escalation_hold_root),
            HashPart::Str(&operator_instruction),
            HashPart::Str(&fail_closed_reason),
        ],
        32,
    );
    RunbookStepAudit {
        step_id,
        kind,
        domain,
        disposition,
        sequence_index,
        evidence_import_root,
        reviewer_signoff_root,
        finding_closure_root,
        privacy_attestation_root,
        escalation_hold_root,
        operator_instruction,
        fail_closed_reason,
        step_root,
    }
}

fn disposition_for_step(
    config: &Config,
    kind: RunbookStepKind,
    counters: &AuditCounters,
) -> StepDisposition {
    match kind {
        RunbookStepKind::IntakeLiveEvidence => {
            if counters.live_evidence_imports >= config.min_live_evidence_imports {
                StepDisposition::Accepted
            } else {
                StepDisposition::Blocked
            }
        }
        RunbookStepKind::BindCanonicalAnswer => {
            if counters.security_accepted_imports >= 2 {
                StepDisposition::Accepted
            } else {
                StepDisposition::Blocked
            }
        }
        RunbookStepKind::VerifyForceExitPackage => {
            if counters.dashboard_visible_imports >= 3 {
                StepDisposition::Accepted
            } else {
                StepDisposition::Watch
            }
        }
        RunbookStepKind::ReviewSecurityAcceptance => {
            if counters.required_reviewer_signoffs >= config.min_reviewer_signoffs {
                StepDisposition::Accepted
            } else {
                StepDisposition::Blocked
            }
        }
        RunbookStepKind::CloseFindings => {
            if counters.findings_closed >= config.min_findings_closed
                && counters.findings_open <= config.max_open_findings
                && counters.high_or_critical_findings_open == 0
            {
                StepDisposition::Accepted
            } else {
                StepDisposition::Blocked
            }
        }
        RunbookStepKind::AttestPrivacyNonLinkage => {
            if counters.privacy_attestations_passed >= config.min_privacy_attestations {
                StepDisposition::Accepted
            } else {
                StepDisposition::Rejected
            }
        }
        RunbookStepKind::CheckEscalationHolds => {
            if counters.escalation_holds_active <= config.max_escalation_holds {
                StepDisposition::Accepted
            } else {
                StepDisposition::Blocked
            }
        }
        RunbookStepKind::PublishDashboardReadiness => {
            if config.production_dashboard_enabled {
                StepDisposition::Accepted
            } else {
                StepDisposition::Deferred
            }
        }
        RunbookStepKind::PreserveFailClosedBlockers => {
            if counters.high_or_critical_findings_open == 0
                && counters.escalation_holds_active <= config.max_escalation_holds
            {
                StepDisposition::Accepted
            } else {
                StepDisposition::Blocked
            }
        }
        RunbookStepKind::ArchiveAuditPacket => {
            if counters.reviewer_signoffs >= config.min_reviewer_signoffs {
                StepDisposition::Accepted
            } else {
                StepDisposition::Watch
            }
        }
    }
}

fn fail_closed_reason_for_step(
    config: &Config,
    kind: RunbookStepKind,
    counters: &AuditCounters,
) -> String {
    match kind {
        RunbookStepKind::IntakeLiveEvidence
            if counters.live_evidence_imports < config.min_live_evidence_imports =>
        {
            "insufficient_accepted_live_evidence_imports".to_string()
        }
        RunbookStepKind::BindCanonicalAnswer if counters.security_accepted_imports < 2 => {
            "canonical_user_escape_answer_not_bound_to_security_accepted_imports".to_string()
        }
        RunbookStepKind::ReviewSecurityAcceptance
            if counters.required_reviewer_signoffs < config.min_reviewer_signoffs =>
        {
            "required_reviewer_signoff_quorum_missing".to_string()
        }
        RunbookStepKind::CloseFindings if counters.high_or_critical_findings_open > 0 => {
            "high_or_critical_findings_remain_open".to_string()
        }
        RunbookStepKind::CloseFindings if counters.findings_open > config.max_open_findings => {
            "finding_closure_checklist_has_open_items".to_string()
        }
        RunbookStepKind::AttestPrivacyNonLinkage
            if counters.privacy_attestations_passed < config.min_privacy_attestations =>
        {
            "privacy_non_linkage_attestation_quorum_missing".to_string()
        }
        RunbookStepKind::CheckEscalationHolds
            if counters.escalation_holds_active > config.max_escalation_holds =>
        {
            "active_escalation_hold_requires_fail_closed_release_dashboard".to_string()
        }
        RunbookStepKind::PublishDashboardReadiness if !config.production_dashboard_enabled => {
            "production_dashboard_flag_disabled_for_devnet_audit_runtime".to_string()
        }
        RunbookStepKind::PreserveFailClosedBlockers
            if counters.high_or_critical_findings_open > 0 =>
        {
            "fail_closed_blocker_preserved_for_open_severe_findings".to_string()
        }
        _ => String::new(),
    }
}

fn operator_instruction_for_step(kind: RunbookStepKind, disposition: StepDisposition) -> String {
    let action = match kind {
        RunbookStepKind::IntakeLiveEvidence => {
            "import only redacted live evidence roots accepted by security reviewers"
        }
        RunbookStepKind::BindCanonicalAnswer => {
            "bind canonical user escape answer to force-exit package and accepted evidence roots"
        }
        RunbookStepKind::VerifyForceExitPackage => {
            "verify forced exit package roots match dashboard-visible evidence roots"
        }
        RunbookStepKind::ReviewSecurityAcceptance => {
            "collect release captain security privacy and runtime maintainer signoffs"
        }
        RunbookStepKind::CloseFindings => {
            "close or explicitly accept every finding before dashboard readiness promotion"
        }
        RunbookStepKind::AttestPrivacyNonLinkage => {
            "attest public dashboard roots do not link users operators receipts or reviewers"
        }
        RunbookStepKind::CheckEscalationHolds => {
            "hold release while any incident reviewer conflict or evidence mismatch remains active"
        }
        RunbookStepKind::PublishDashboardReadiness => {
            "publish readiness only after fail-closed blockers are absent and dashboard flag is enabled"
        }
        RunbookStepKind::PreserveFailClosedBlockers => {
            "preserve blockers as public roots so automation cannot silently bypass release holds"
        }
        RunbookStepKind::ArchiveAuditPacket => {
            "archive immutable public audit packet for release-dashboard replay"
        }
    };
    format!("{action}; disposition={}", disposition.as_str())
}

fn derive_fail_closed_blockers(
    config: &Config,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
    finding_closures: &BTreeMap<String, FindingClosure>,
    privacy_attestations: &BTreeMap<String, PrivacyNonLinkageAttestation>,
    escalation_holds: &BTreeMap<String, EscalationHold>,
    runbook_steps: &BTreeMap<String, RunbookStepAudit>,
    counters: &AuditCounters,
) -> BTreeMap<String, FailClosedBlocker> {
    let mut blockers = BTreeMap::new();
    maybe_insert_blocker(
        &mut blockers,
        counters.live_evidence_imports < config.min_live_evidence_imports,
        "live-evidence-import-quorum",
        ReviewerRole::RuntimeMaintainer,
        root_for_all_imports(evidence_imports),
        "release dashboard cannot claim readiness without accepted live evidence import quorum",
        "user release remains blocked until canonical evidence imports are complete",
    );
    maybe_insert_blocker(
        &mut blockers,
        counters.required_reviewer_signoffs < config.min_reviewer_signoffs,
        "required-reviewer-signoff-quorum",
        ReviewerRole::ReleaseCaptain,
        root_for_all_signoffs(reviewer_signoffs),
        "release dashboard cannot advance without required reviewer signoff quorum",
        "user release answer remains watch because reviewer quorum is incomplete",
    );
    maybe_insert_blocker(
        &mut blockers,
        counters.findings_open > config.max_open_findings
            || counters.high_or_critical_findings_open > 0,
        "finding-closure-checklist-open",
        ReviewerRole::SecurityReviewer,
        root_for_findings(finding_closures),
        "release dashboard cannot mark ready while findings remain open",
        "force-exit package remains fail-closed until findings are closed or accepted",
    );
    maybe_insert_blocker(
        &mut blockers,
        counters.privacy_attestations_passed < config.min_privacy_attestations,
        "privacy-non-linkage-quorum",
        ReviewerRole::PrivacyReviewer,
        root_for_privacy(privacy_attestations),
        "release dashboard cannot expose roots without privacy non-linkage attestation quorum",
        "user escape answer remains private until non-linkage evidence passes",
    );
    maybe_insert_blocker(
        &mut blockers,
        counters.escalation_holds_active > config.max_escalation_holds,
        "active-escalation-hold",
        ReviewerRole::IncidentCommander,
        root_for_holds(escalation_holds, true),
        "release dashboard is frozen by active escalation hold",
        "user release answer remains held until incident or mismatch is released",
    );
    maybe_insert_blocker(
        &mut blockers,
        !config.production_dashboard_enabled,
        "production-dashboard-disabled",
        ReviewerRole::ReleaseCaptain,
        root_for_steps(runbook_steps),
        "production dashboard flag is disabled so runtime must fail closed",
        "user release may be inspected locally but production readiness is blocked",
    );
    blockers
}

fn maybe_insert_blocker(
    blockers: &mut BTreeMap<String, FailClosedBlocker>,
    condition: bool,
    label: &str,
    owner_role: ReviewerRole,
    source_root: String,
    release_dashboard_reason: &str,
    user_release_reason: &str,
) {
    if condition {
        let blocker_root = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-fail-closed-blocker",
            &[
                HashPart::Str(label),
                HashPart::Str(owner_role.as_str()),
                HashPart::Str(&source_root),
                HashPart::Str(release_dashboard_reason),
                HashPart::Str(user_release_reason),
            ],
            32,
        );
        let blocker_id = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-fail-closed-blocker-id",
            &[HashPart::Str(label), HashPart::Str(&blocker_root)],
            16,
        );
        blockers.insert(
            blocker_id.clone(),
            FailClosedBlocker {
                blocker_id,
                label: label.to_string(),
                owner_role,
                source_root,
                blocker_root,
                release_dashboard_reason: release_dashboard_reason.to_string(),
                user_release_reason: user_release_reason.to_string(),
                active: true,
            },
        );
    }
}

fn build_dashboard_readiness(
    config: &Config,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
    finding_closures: &BTreeMap<String, FindingClosure>,
    privacy_attestations: &BTreeMap<String, PrivacyNonLinkageAttestation>,
    escalation_holds: &BTreeMap<String, EscalationHold>,
    runbook_steps: &BTreeMap<String, RunbookStepAudit>,
    fail_closed_blockers: &BTreeMap<String, FailClosedBlocker>,
    counters: &AuditCounters,
) -> DashboardReadiness {
    let evidence_import_root = root_for_all_imports(evidence_imports);
    let runbook_step_root = root_for_steps(runbook_steps);
    let reviewer_signoff_root = root_for_all_signoffs(reviewer_signoffs);
    let finding_closure_root = root_for_findings(finding_closures);
    let privacy_attestation_root = root_for_privacy(privacy_attestations);
    let escalation_hold_root = root_for_holds(escalation_holds, true);
    let fail_closed_blocker_root = root_for_blockers(fail_closed_blockers);
    let counter_root = counters.state_root();
    let has_blockers = fail_closed_blockers.values().any(|blocker| blocker.active);
    let status = if has_blockers && counters.high_or_critical_findings_open > 0 {
        DashboardReadinessStatus::Rejected
    } else if has_blockers {
        DashboardReadinessStatus::Blocked
    } else if config.production_dashboard_enabled {
        DashboardReadinessStatus::Ready
    } else if counters.privacy_attestations_passed >= config.min_privacy_attestations
        && counters.required_reviewer_signoffs >= config.min_reviewer_signoffs
    {
        DashboardReadinessStatus::ReadyForUserReleaseOnly
    } else {
        DashboardReadinessStatus::Watch
    };
    let readiness_label = readiness_label(status, counters);
    let user_release_answer = user_release_answer(status, counters);
    let production_release_answer = production_release_answer(status, counters);
    let dashboard_id = domain_hash(
        "monero-l2-pq-bridge-exit-runbook-dashboard-id",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(&counter_root),
        ],
        16,
    );
    let dashboard_root = domain_hash(
        "monero-l2-pq-bridge-exit-runbook-dashboard-readiness",
        &[
            HashPart::Str(&dashboard_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(&readiness_label),
            HashPart::Str(&user_release_answer),
            HashPart::Str(&production_release_answer),
            HashPart::Str(&evidence_import_root),
            HashPart::Str(&runbook_step_root),
            HashPart::Str(&reviewer_signoff_root),
            HashPart::Str(&finding_closure_root),
            HashPart::Str(&privacy_attestation_root),
            HashPart::Str(&escalation_hold_root),
            HashPart::Str(&fail_closed_blocker_root),
            HashPart::Str(&counter_root),
        ],
        32,
    );
    DashboardReadiness {
        dashboard_id,
        status,
        readiness_label,
        user_release_answer,
        production_release_answer,
        evidence_import_root,
        runbook_step_root,
        reviewer_signoff_root,
        finding_closure_root,
        privacy_attestation_root,
        escalation_hold_root,
        fail_closed_blocker_root,
        counter_root,
        dashboard_root,
    }
}

fn readiness_label(status: DashboardReadinessStatus, counters: &AuditCounters) -> String {
    match status {
        DashboardReadinessStatus::Ready => {
            "release_dashboard_ready_with_audit_security_accepted_live_evidence".to_string()
        }
        DashboardReadinessStatus::ReadyForUserReleaseOnly => {
            "user_release_ready_but_production_dashboard_not_enabled".to_string()
        }
        DashboardReadinessStatus::Watch => format!(
            "watch_signoffs_{}_privacy_{}_findings_open_{}",
            counters.required_reviewer_signoffs,
            counters.privacy_attestations_passed,
            counters.findings_open
        ),
        DashboardReadinessStatus::Blocked => {
            "blocked_fail_closed_operator_runbook_audit_requirements".to_string()
        }
        DashboardReadinessStatus::Rejected => {
            "rejected_open_high_or_critical_security_findings".to_string()
        }
    }
}

fn user_release_answer(status: DashboardReadinessStatus, counters: &AuditCounters) -> String {
    match status {
        DashboardReadinessStatus::Ready | DashboardReadinessStatus::ReadyForUserReleaseOnly => {
            "yes_user_escape_answer_can_be_replayed_from_public_roots".to_string()
        }
        DashboardReadinessStatus::Watch => {
            "watch_user_escape_answer_until_reviewer_and_privacy_quorums_complete".to_string()
        }
        DashboardReadinessStatus::Blocked => format!(
            "no_user_release_blocked_by_{}_active_dashboard_blockers",
            counters.dashboard_blockers
        ),
        DashboardReadinessStatus::Rejected => {
            "no_user_release_rejected_until_severe_findings_are_closed".to_string()
        }
    }
}

fn production_release_answer(status: DashboardReadinessStatus, counters: &AuditCounters) -> String {
    match status {
        DashboardReadinessStatus::Ready => {
            "yes_production_dashboard_readiness_can_be_published".to_string()
        }
        DashboardReadinessStatus::ReadyForUserReleaseOnly => {
            "no_production_dashboard_flag_not_enabled".to_string()
        }
        DashboardReadinessStatus::Watch => format!(
            "watch_production_release_pending_{}_accepted_imports",
            counters.security_accepted_imports
        ),
        DashboardReadinessStatus::Blocked => {
            "no_production_release_fail_closed_blockers_active".to_string()
        }
        DashboardReadinessStatus::Rejected => {
            "no_production_release_rejected_by_open_severe_security_findings".to_string()
        }
    }
}

const EMPTY_ROOT: &str = "empty";

fn root_for_domain(
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
    domain: EvidenceImportDomain,
) -> String {
    let leaves = evidence_imports
        .values()
        .filter(|import| import.domain == domain)
        .map(LiveEvidenceImport::public_record)
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-runbook-domain-imports", &leaves)
}

fn root_for_all_imports(evidence_imports: &BTreeMap<String, LiveEvidenceImport>) -> String {
    let leaves = evidence_imports
        .values()
        .map(LiveEvidenceImport::public_record)
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-runbook-all-imports", &leaves)
}

fn root_for_all_signoffs(reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>) -> String {
    let leaves = reviewer_signoffs
        .values()
        .map(ReviewerSignoff::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runbook-reviewer-signoffs",
        &leaves,
    )
}

fn root_for_step_signoff(
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
    step: RunbookStepKind,
) -> String {
    let leaves = reviewer_signoffs
        .values()
        .filter(|signoff| signoff.runbook_step == step)
        .map(ReviewerSignoff::public_record)
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-runbook-step-signoffs", &leaves)
}

fn root_for_findings(finding_closures: &BTreeMap<String, FindingClosure>) -> String {
    let leaves = finding_closures
        .values()
        .map(FindingClosure::public_record)
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-runbook-finding-closures", &leaves)
}

fn root_for_privacy(
    privacy_attestations: &BTreeMap<String, PrivacyNonLinkageAttestation>,
) -> String {
    let leaves = privacy_attestations
        .values()
        .map(PrivacyNonLinkageAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runbook-privacy-attestations",
        &leaves,
    )
}

fn root_for_holds(
    escalation_holds: &BTreeMap<String, EscalationHold>,
    active_only: bool,
) -> String {
    let leaves = escalation_holds
        .values()
        .filter(|hold| !active_only || hold.active)
        .map(EscalationHold::public_record)
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-runbook-escalation-holds", &leaves)
}

fn root_for_steps(runbook_steps: &BTreeMap<String, RunbookStepAudit>) -> String {
    let leaves = runbook_steps
        .values()
        .map(RunbookStepAudit::public_record)
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-runbook-steps", &leaves)
}

fn root_for_blockers(fail_closed_blockers: &BTreeMap<String, FailClosedBlocker>) -> String {
    let leaves = fail_closed_blockers
        .values()
        .map(FailClosedBlocker::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runbook-fail-closed-blockers",
        &leaves,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runbook-audit-record",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

fn seed_root(chain_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runbook-audit-seed",
        &[HashPart::Str(chain_id), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn evidence_root(label: &str, parent_root: &str, index: u64) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runbook-audit-evidence-root",
        &[
            HashPart::Str(label),
            HashPart::Str(parent_root),
            HashPart::U64(index),
        ],
        32,
    )
}

fn runbook_step_id(kind: RunbookStepKind, sequence_index: u64, source_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runbook-step-id",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence_index),
            HashPart::Str(source_root),
        ],
        16,
    )
}

fn default_evidence_imports(seed_root: &str) -> BTreeMap<String, LiveEvidenceImport> {
    let specs = [
        (
            EvidenceImportDomain::CanonicalUserEscapeAnswer,
            "canonical user escape answer package",
            "escape-answer-ledger",
            true,
            true,
        ),
        (
            EvidenceImportDomain::ForceExitPackage,
            "force exit package transcript",
            "force-exit-builder",
            true,
            true,
        ),
        (
            EvidenceImportDomain::LiveOperatorRunbook,
            "operator handoff runbook recording",
            "operator-runbook",
            true,
            true,
        ),
        (
            EvidenceImportDomain::SecurityAcceptedAudit,
            "security accepted audit packet",
            "audit-console",
            true,
            true,
        ),
        (
            EvidenceImportDomain::ReleaseDashboardReadiness,
            "release dashboard readiness feed",
            "release-dashboard",
            true,
            true,
        ),
        (
            EvidenceImportDomain::PrivacyNonLinkage,
            "privacy non-linkage public root",
            "privacy-review",
            true,
            true,
        ),
        (
            EvidenceImportDomain::ReviewerSignoff,
            "reviewer signoff evidence bundle",
            "review-console",
            true,
            true,
        ),
        (
            EvidenceImportDomain::FindingClosure,
            "finding closure checklist import",
            "finding-tracker",
            true,
            true,
        ),
        (
            EvidenceImportDomain::FailClosedBlocker,
            "fail-closed blocker preservation import",
            "release-gate",
            true,
            true,
        ),
        (
            EvidenceImportDomain::EscalationHold,
            "active escalation hold import",
            "incident-console",
            true,
            true,
        ),
    ];
    let mut imports = BTreeMap::new();
    for (index, (domain, label, source_system, accepted, visible)) in specs.iter().enumerate() {
        let source_root = evidence_root(label, seed_root, index as u64);
        let accepted_root = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-audit-accepted-root",
            &[
                HashPart::Str(domain.as_str()),
                HashPart::Str(&source_root),
                HashPart::Str(source_system),
            ],
            32,
        );
        let canonical_answer_root = evidence_root("canonical-answer", &accepted_root, index as u64);
        let force_exit_package_root =
            evidence_root("force-exit-package", &accepted_root, index as u64);
        let redacted_public_record = json!({
            "domain": domain.as_str(),
            "label": label,
            "source_system": source_system,
            "redaction": "public_roots_only",
            "contains_user_address": false,
            "contains_operator_identity": false,
            "contains_private_receipt_graph": false,
        });
        let import_id = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-audit-import-id",
            &[
                HashPart::Str(domain.as_str()),
                HashPart::Str(&accepted_root),
            ],
            16,
        );
        imports.insert(
            import_id.clone(),
            LiveEvidenceImport {
                import_id,
                domain: *domain,
                label: (*label).to_string(),
                source_system: (*source_system).to_string(),
                source_record_id: format!("devnet-{}-{index}", domain.as_str()),
                evidence_root: source_root,
                accepted_root,
                canonical_answer_root,
                force_exit_package_root,
                redacted_public_record,
                imported_by: "devnet-operator-audit-bot".to_string(),
                imported_at_slot: 82_000 + index as u64,
                accepted_by_security: *accepted,
                dashboard_visible: *visible,
            },
        );
    }
    imports
}

fn default_reviewer_signoffs(
    seed_root: &str,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
) -> BTreeMap<String, ReviewerSignoff> {
    let import_root = root_for_all_imports(evidence_imports);
    let specs = [
        (
            ReviewerRole::ReleaseCaptain,
            RunbookStepKind::PublishDashboardReadiness,
            "release-captain-devnet",
            true,
        ),
        (
            ReviewerRole::SecurityReviewer,
            RunbookStepKind::ReviewSecurityAcceptance,
            "security-reviewer-devnet",
            true,
        ),
        (
            ReviewerRole::PrivacyReviewer,
            RunbookStepKind::AttestPrivacyNonLinkage,
            "privacy-reviewer-devnet",
            true,
        ),
        (
            ReviewerRole::RuntimeMaintainer,
            RunbookStepKind::VerifyForceExitPackage,
            "runtime-maintainer-devnet",
            true,
        ),
        (
            ReviewerRole::IncidentCommander,
            RunbookStepKind::CheckEscalationHolds,
            "incident-commander-devnet",
            true,
        ),
        (
            ReviewerRole::AuditArchivist,
            RunbookStepKind::ArchiveAuditPacket,
            "audit-archivist-devnet",
            true,
        ),
    ];
    let mut signoffs = BTreeMap::new();
    for (index, (role, step, reviewer_id, accepted)) in specs.iter().enumerate() {
        let notes_root = evidence_root("reviewer-notes", seed_root, index as u64);
        let signoff_root = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-reviewer-signoff-root",
            &[
                HashPart::Str(role.as_str()),
                HashPart::Str(step.as_str()),
                HashPart::Str(reviewer_id),
                HashPart::Str(&import_root),
                HashPart::Str(&notes_root),
            ],
            32,
        );
        let signoff_id = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-reviewer-signoff-id",
            &[HashPart::Str(role.as_str()), HashPart::Str(&signoff_root)],
            16,
        );
        signoffs.insert(
            signoff_id.clone(),
            ReviewerSignoff {
                signoff_id,
                role: *role,
                reviewer_id: (*reviewer_id).to_string(),
                runbook_step: *step,
                evidence_root: import_root.clone(),
                signoff_root,
                signed_at_slot: 82_100 + index as u64,
                accepted: *accepted,
                notes_root,
            },
        );
    }
    signoffs
}

fn default_finding_closures(
    seed_root: &str,
    reviewer_signoffs: &BTreeMap<String, ReviewerSignoff>,
) -> BTreeMap<String, FindingClosure> {
    let signoff_root = root_for_all_signoffs(reviewer_signoffs);
    let specs = [
        (
            FindingSeverity::Critical,
            FindingStatus::Closed,
            "escape answer replay mismatch",
        ),
        (
            FindingSeverity::High,
            FindingStatus::Closed,
            "force exit package omitted timeout proof",
        ),
        (
            FindingSeverity::High,
            FindingStatus::Closed,
            "operator runbook skipped privacy redaction",
        ),
        (
            FindingSeverity::Medium,
            FindingStatus::Mitigated,
            "dashboard readiness stale root",
        ),
        (
            FindingSeverity::Medium,
            FindingStatus::Closed,
            "reviewer signoff ordering ambiguity",
        ),
        (
            FindingSeverity::Low,
            FindingStatus::Closed,
            "audit archive filename collision",
        ),
        (
            FindingSeverity::Low,
            FindingStatus::Closed,
            "incident hold label drift",
        ),
        (
            FindingSeverity::Informational,
            FindingStatus::Closed,
            "public packet schema note",
        ),
    ];
    let mut findings = BTreeMap::new();
    for (index, (severity, status, title)) in specs.iter().enumerate() {
        let source_evidence_root = evidence_root("finding-source", seed_root, index as u64);
        let closure_evidence_root =
            evidence_root("finding-closure", &source_evidence_root, index as u64);
        let finding_id = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-finding-id",
            &[HashPart::Str(severity.as_str()), HashPart::Str(title)],
            16,
        );
        findings.insert(
            finding_id.clone(),
            FindingClosure {
                finding_id,
                severity: *severity,
                status: *status,
                title: (*title).to_string(),
                source_evidence_root,
                closure_evidence_root,
                reviewer_signoff_root: signoff_root.clone(),
                remediation_summary:
                    "closure evidence accepted into release-dashboard audit packet".to_string(),
                closed_at_slot: 82_200 + index as u64,
                dashboard_blocker: status.is_open()
                    || severity.blocks_release() && !status.is_closed(),
            },
        );
    }
    findings
}

fn default_privacy_attestations(
    seed_root: &str,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
) -> BTreeMap<String, PrivacyNonLinkageAttestation> {
    let import_root = root_for_all_imports(evidence_imports);
    let specs = [
        PrivacyAttestationKind::NoLinkageAcrossEscapeAnswers,
        PrivacyAttestationKind::NoOperatorAddressCorrelation,
        PrivacyAttestationKind::NoReceiptGraphDisclosure,
        PrivacyAttestationKind::NoReviewerIdentityLeak,
        PrivacyAttestationKind::RedactionBudgetPreserved,
        PrivacyAttestationKind::DashboardOnlyShowsPublicRoots,
    ];
    let mut attestations = BTreeMap::new();
    for (index, kind) in specs.iter().enumerate() {
        let non_linkage_root = evidence_root(kind.as_str(), seed_root, index as u64);
        let redaction_policy_root =
            evidence_root("redaction-policy", &non_linkage_root, index as u64);
        let public_dashboard_root =
            evidence_root("public-dashboard", &redaction_policy_root, index as u64);
        let attestation_id = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-privacy-attestation-id",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&non_linkage_root),
            ],
            16,
        );
        attestations.insert(
            attestation_id.clone(),
            PrivacyNonLinkageAttestation {
                attestation_id,
                kind: *kind,
                attestor_id: format!("privacy-attestor-devnet-{index}"),
                source_evidence_root: import_root.clone(),
                non_linkage_root,
                redaction_policy_root,
                public_dashboard_root,
                attested_at_slot: 82_300 + index as u64,
                passes: true,
            },
        );
    }
    attestations
}

fn default_escalation_holds(
    seed_root: &str,
    evidence_imports: &BTreeMap<String, LiveEvidenceImport>,
) -> BTreeMap<String, EscalationHold> {
    let import_root = root_for_all_imports(evidence_imports);
    let specs = [
        (
            EscalationHoldKind::IncidentReview,
            ReviewerRole::IncidentCommander,
            "devnet incident review released after evidence replay",
            false,
        ),
        (
            EscalationHoldKind::EvidenceMismatch,
            ReviewerRole::SecurityReviewer,
            "live evidence mismatch hold retained active for fail-closed demonstration",
            true,
        ),
    ];
    let mut holds = BTreeMap::new();
    for (index, (kind, owner_role, reason, active)) in specs.iter().enumerate() {
        let hold_root = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-escalation-hold-root",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(owner_role.as_str()),
                HashPart::Str(reason),
                HashPart::Str(&import_root),
                HashPart::U64(index as u64),
            ],
            32,
        );
        let hold_id = domain_hash(
            "monero-l2-pq-bridge-exit-runbook-escalation-hold-id",
            &[HashPart::Str(kind.as_str()), HashPart::Str(&hold_root)],
            16,
        );
        holds.insert(
            hold_id.clone(),
            EscalationHold {
                hold_id,
                kind: *kind,
                owner_role: *owner_role,
                reason: (*reason).to_string(),
                source_evidence_root: import_root.clone(),
                hold_root,
                opened_at_slot: 82_400 + index as u64,
                released_at_slot: if *active { 0 } else { 82_500 + index as u64 },
                active: *active,
            },
        );
    }
    holds
}
