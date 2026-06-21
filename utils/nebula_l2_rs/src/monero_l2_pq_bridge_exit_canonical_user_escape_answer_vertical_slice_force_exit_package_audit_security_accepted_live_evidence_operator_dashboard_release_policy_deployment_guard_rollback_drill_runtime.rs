use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageAuditSecurityAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-audit-security-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROLLBACK_DRILL_SUITE: &str =
    "monero-l2-pq-bridge-force-exit-audit-security-deployment-guard-rollback-drill-v1";
pub const DEFAULT_HEIGHT: u64 = 95_184;
pub const DEFAULT_DRILL_WINDOW_START_HEIGHT: u64 = 95_160;
pub const DEFAULT_DRILL_WINDOW_END_HEIGHT: u64 = 95_248;
pub const DEFAULT_MAX_SOURCE_GUARD_AGE_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_TRANSCRIPT_ROOTS: u64 = 4;
pub const DEFAULT_MIN_ABORT_COMMANDS: u64 = 4;
pub const DEFAULT_MIN_RECEIPTS: u64 = 6;
pub const DEFAULT_MIN_OPERATOR_ACKS: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_REPLAY_ROOTS: u64 = 4;
pub const DEFAULT_MIN_FINDING_REOPEN_ROOTS: u64 = 3;
pub const DEFAULT_MAX_RELEASE_BLOCKERS: u64 = 0;
pub const DEFAULT_MAX_ACTIVE_HOLDS: u64 = 0;
pub const DEFAULT_MAX_RECORDS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackDrillLane {
    SourceDeploymentGuard,
    SecurityRollbackTranscript,
    FindingReopenAbort,
    PrivacyAuditBlockerReplay,
    OperatorAcknowledgement,
    HoldUnholdState,
    ReceiptArchive,
    ReleaseVerdict,
}

impl RollbackDrillLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::SourceDeploymentGuard,
            Self::SecurityRollbackTranscript,
            Self::FindingReopenAbort,
            Self::PrivacyAuditBlockerReplay,
            Self::OperatorAcknowledgement,
            Self::HoldUnholdState,
            Self::ReceiptArchive,
            Self::ReleaseVerdict,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceDeploymentGuard => "source_deployment_guard",
            Self::SecurityRollbackTranscript => "security_rollback_transcript",
            Self::FindingReopenAbort => "finding_reopen_abort",
            Self::PrivacyAuditBlockerReplay => "privacy_audit_blocker_replay",
            Self::OperatorAcknowledgement => "operator_acknowledgement",
            Self::HoldUnholdState => "hold_unhold_state",
            Self::ReceiptArchive => "receipt_archive",
            Self::ReleaseVerdict => "release_verdict",
        }
    }

    pub fn required_for_unhold(self) -> bool {
        matches!(
            self,
            Self::SourceDeploymentGuard
                | Self::SecurityRollbackTranscript
                | Self::FindingReopenAbort
                | Self::PrivacyAuditBlockerReplay
                | Self::OperatorAcknowledgement
                | Self::HoldUnholdState
                | Self::ReceiptArchive
                | Self::ReleaseVerdict
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillStepKind {
    SnapshotPreDeployGuard,
    OpenSyntheticSecurityFinding,
    ReplayPrivacyAuditBlocker,
    InvokeAbortCommand,
    VerifyFailClosedHold,
    RestoreReleaseGuard,
    RecloseFinding,
    RecordOperatorAck,
    VerifyUnholdCandidate,
}

impl DrillStepKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::SnapshotPreDeployGuard,
            Self::OpenSyntheticSecurityFinding,
            Self::ReplayPrivacyAuditBlocker,
            Self::InvokeAbortCommand,
            Self::VerifyFailClosedHold,
            Self::RestoreReleaseGuard,
            Self::RecloseFinding,
            Self::RecordOperatorAck,
            Self::VerifyUnholdCandidate,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotPreDeployGuard => "snapshot_pre_deploy_guard",
            Self::OpenSyntheticSecurityFinding => "open_synthetic_security_finding",
            Self::ReplayPrivacyAuditBlocker => "replay_privacy_audit_blocker",
            Self::InvokeAbortCommand => "invoke_abort_command",
            Self::VerifyFailClosedHold => "verify_fail_closed_hold",
            Self::RestoreReleaseGuard => "restore_release_guard",
            Self::RecloseFinding => "reclose_finding",
            Self::RecordOperatorAck => "record_operator_ack",
            Self::VerifyUnholdCandidate => "verify_unhold_candidate",
        }
    }

    pub fn expected_fail_closed(self) -> bool {
        matches!(
            self,
            Self::OpenSyntheticSecurityFinding
                | Self::ReplayPrivacyAuditBlocker
                | Self::InvokeAbortCommand
                | Self::VerifyFailClosedHold
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCommandKind {
    FreezeReleaseWindow,
    RevokeUnholdCandidate,
    DisableBridgeExitPublish,
    RequireSecurityReacceptance,
    RequirePrivacyReplay,
    SealRollbackArchive,
}

impl AbortCommandKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::FreezeReleaseWindow,
            Self::RevokeUnholdCandidate,
            Self::DisableBridgeExitPublish,
            Self::RequireSecurityReacceptance,
            Self::RequirePrivacyReplay,
            Self::SealRollbackArchive,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreezeReleaseWindow => "freeze_release_window",
            Self::RevokeUnholdCandidate => "revoke_unhold_candidate",
            Self::DisableBridgeExitPublish => "disable_bridge_exit_publish",
            Self::RequireSecurityReacceptance => "require_security_reacceptance",
            Self::RequirePrivacyReplay => "require_privacy_replay",
            Self::SealRollbackArchive => "seal_rollback_archive",
        }
    }

    pub fn required_receipt(self) -> &'static str {
        match self {
            Self::FreezeReleaseWindow => "release_window_frozen_receipt",
            Self::RevokeUnholdCandidate => "unhold_candidate_revoked_receipt",
            Self::DisableBridgeExitPublish => "bridge_exit_publish_disabled_receipt",
            Self::RequireSecurityReacceptance => "security_reacceptance_required_receipt",
            Self::RequirePrivacyReplay => "privacy_replay_required_receipt",
            Self::SealRollbackArchive => "rollback_archive_sealed_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReopenCriterionKind {
    FindingRootMismatch,
    ClosureEvidenceStale,
    AcceptedRiskExpired,
    PrivacyBoundaryRegression,
    AbortReceiptMissing,
    OperatorAckMissing,
    TranscriptRootMismatch,
}

impl ReopenCriterionKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::FindingRootMismatch,
            Self::ClosureEvidenceStale,
            Self::AcceptedRiskExpired,
            Self::PrivacyBoundaryRegression,
            Self::AbortReceiptMissing,
            Self::OperatorAckMissing,
            Self::TranscriptRootMismatch,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FindingRootMismatch => "finding_root_mismatch",
            Self::ClosureEvidenceStale => "closure_evidence_stale",
            Self::AcceptedRiskExpired => "accepted_risk_expired",
            Self::PrivacyBoundaryRegression => "privacy_boundary_regression",
            Self::AbortReceiptMissing => "abort_receipt_missing",
            Self::OperatorAckMissing => "operator_ack_missing",
            Self::TranscriptRootMismatch => "transcript_root_mismatch",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            Self::FindingRootMismatch
                | Self::ClosureEvidenceStale
                | Self::AcceptedRiskExpired
                | Self::PrivacyBoundaryRegression
                | Self::AbortReceiptMissing
                | Self::OperatorAckMissing
                | Self::TranscriptRootMismatch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyReplayBoundary {
    WalletScanMetadata,
    WatchtowerObservation,
    PqReserveRotation,
    BridgeExitPublication,
    AuditArchiveRedaction,
}

impl PrivacyReplayBoundary {
    pub fn all() -> Vec<Self> {
        vec![
            Self::WalletScanMetadata,
            Self::WatchtowerObservation,
            Self::PqReserveRotation,
            Self::BridgeExitPublication,
            Self::AuditArchiveRedaction,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanMetadata => "wallet_scan_metadata",
            Self::WatchtowerObservation => "watchtower_observation",
            Self::PqReserveRotation => "pq_reserve_rotation",
            Self::BridgeExitPublication => "bridge_exit_publication",
            Self::AuditArchiveRedaction => "audit_archive_redaction",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    ReleaseCaptain,
    SecurityLead,
    PrivacyLead,
    RuntimeMaintainer,
    DashboardOwner,
    IncidentCommander,
    RollbackOwner,
    AuditCustodian,
}

impl OperatorRole {
    pub fn all_required() -> Vec<Self> {
        vec![
            Self::ReleaseCaptain,
            Self::SecurityLead,
            Self::PrivacyLead,
            Self::RuntimeMaintainer,
            Self::DashboardOwner,
            Self::RollbackOwner,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCaptain => "release_captain",
            Self::SecurityLead => "security_lead",
            Self::PrivacyLead => "privacy_lead",
            Self::RuntimeMaintainer => "runtime_maintainer",
            Self::DashboardOwner => "dashboard_owner",
            Self::IncidentCommander => "incident_commander",
            Self::RollbackOwner => "rollback_owner",
            Self::AuditCustodian => "audit_custodian",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldUnholdVerdict {
    Hold,
    UnholdCandidate,
    Unheld,
    Abort,
}

impl HoldUnholdVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::UnholdCandidate => "unhold_candidate",
            Self::Unheld => "unheld",
            Self::Abort => "abort",
        }
    }

    pub fn allows_release(self) -> bool {
        matches!(self, Self::Unheld)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackDrillBlockerKind {
    MissingSourceGuardRoot,
    SourceGuardStale,
    SourceGuardNotUnheld,
    MissingSecurityRollbackTranscriptRoot,
    SecurityTranscriptRejected,
    MissingFindingReopenRoot,
    FindingReopenAbortNotObserved,
    MissingPrivacyReplayRoot,
    PrivacyBlockerReplayRejected,
    MissingAbortCommandRoot,
    AbortReceiptMissing,
    AbortReceiptRejected,
    MissingOperatorAcknowledgement,
    OperatorAcknowledgementRejected,
    ReleaseHoldNotFailClosed,
    ReleaseUnholdWithoutReacceptance,
    ActiveManualHold,
    ReleasePolicyRootMismatch,
    DashboardRootMismatch,
    DrillWindowClosed,
    DrillWindowNotOpen,
}

impl RollbackDrillBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingSourceGuardRoot => "missing_source_guard_root",
            Self::SourceGuardStale => "source_guard_stale",
            Self::SourceGuardNotUnheld => "source_guard_not_unheld",
            Self::MissingSecurityRollbackTranscriptRoot => {
                "missing_security_rollback_transcript_root"
            }
            Self::SecurityTranscriptRejected => "security_transcript_rejected",
            Self::MissingFindingReopenRoot => "missing_finding_reopen_root",
            Self::FindingReopenAbortNotObserved => "finding_reopen_abort_not_observed",
            Self::MissingPrivacyReplayRoot => "missing_privacy_replay_root",
            Self::PrivacyBlockerReplayRejected => "privacy_blocker_replay_rejected",
            Self::MissingAbortCommandRoot => "missing_abort_command_root",
            Self::AbortReceiptMissing => "abort_receipt_missing",
            Self::AbortReceiptRejected => "abort_receipt_rejected",
            Self::MissingOperatorAcknowledgement => "missing_operator_acknowledgement",
            Self::OperatorAcknowledgementRejected => "operator_acknowledgement_rejected",
            Self::ReleaseHoldNotFailClosed => "release_hold_not_fail_closed",
            Self::ReleaseUnholdWithoutReacceptance => "release_unhold_without_reacceptance",
            Self::ActiveManualHold => "active_manual_hold",
            Self::ReleasePolicyRootMismatch => "release_policy_root_mismatch",
            Self::DashboardRootMismatch => "dashboard_root_mismatch",
            Self::DrillWindowClosed => "drill_window_closed",
            Self::DrillWindowNotOpen => "drill_window_not_open",
        }
    }

    pub fn fail_closed(self) -> bool {
        matches!(
            self,
            Self::MissingSourceGuardRoot
                | Self::SourceGuardStale
                | Self::SourceGuardNotUnheld
                | Self::MissingSecurityRollbackTranscriptRoot
                | Self::SecurityTranscriptRejected
                | Self::MissingFindingReopenRoot
                | Self::FindingReopenAbortNotObserved
                | Self::MissingPrivacyReplayRoot
                | Self::PrivacyBlockerReplayRejected
                | Self::MissingAbortCommandRoot
                | Self::AbortReceiptMissing
                | Self::AbortReceiptRejected
                | Self::MissingOperatorAcknowledgement
                | Self::OperatorAcknowledgementRejected
                | Self::ReleaseHoldNotFailClosed
                | Self::ReleaseUnholdWithoutReacceptance
                | Self::ActiveManualHold
                | Self::ReleasePolicyRootMismatch
                | Self::DashboardRootMismatch
                | Self::DrillWindowClosed
                | Self::DrillWindowNotOpen
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub rollback_drill_suite: String,
    pub rollback_drill_id: String,
    pub release_policy_root: String,
    pub operator_dashboard_root: String,
    pub source_deployment_guard_root: String,
    pub source_deployment_guard_height: u64,
    pub drill_window_start_height: u64,
    pub drill_window_end_height: u64,
    pub max_source_guard_age_blocks: u64,
    pub min_transcript_roots: u64,
    pub min_abort_commands: u64,
    pub min_receipts: u64,
    pub min_operator_acks: u64,
    pub min_privacy_replay_roots: u64,
    pub min_finding_reopen_roots: u64,
    pub max_release_blockers: u64,
    pub max_active_holds: u64,
    pub max_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            rollback_drill_suite: ROLLBACK_DRILL_SUITE.to_string(),
            rollback_drill_id: stable_id("rollback-drill", "wave85-devnet"),
            release_policy_root: fixture_root("wave84-release-policy-root"),
            operator_dashboard_root: fixture_root("wave84-operator-dashboard-root"),
            source_deployment_guard_root: fixture_root("wave84-audit-security-deployment-guard"),
            source_deployment_guard_height: DEFAULT_HEIGHT - 24,
            drill_window_start_height: DEFAULT_DRILL_WINDOW_START_HEIGHT,
            drill_window_end_height: DEFAULT_DRILL_WINDOW_END_HEIGHT,
            max_source_guard_age_blocks: DEFAULT_MAX_SOURCE_GUARD_AGE_BLOCKS,
            min_transcript_roots: DEFAULT_MIN_TRANSCRIPT_ROOTS,
            min_abort_commands: DEFAULT_MIN_ABORT_COMMANDS,
            min_receipts: DEFAULT_MIN_RECEIPTS,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            min_privacy_replay_roots: DEFAULT_MIN_PRIVACY_REPLAY_ROOTS,
            min_finding_reopen_roots: DEFAULT_MIN_FINDING_REOPEN_ROOTS,
            max_release_blockers: DEFAULT_MAX_RELEASE_BLOCKERS,
            max_active_holds: DEFAULT_MAX_ACTIVE_HOLDS,
            max_records: DEFAULT_MAX_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "rollback_drill_suite": self.rollback_drill_suite,
            "rollback_drill_id": self.rollback_drill_id,
            "release_policy_root": self.release_policy_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "source_deployment_guard_root": self.source_deployment_guard_root,
            "source_deployment_guard_height": self.source_deployment_guard_height,
            "drill_window_start_height": self.drill_window_start_height,
            "drill_window_end_height": self.drill_window_end_height,
            "max_source_guard_age_blocks": self.max_source_guard_age_blocks,
            "min_transcript_roots": self.min_transcript_roots,
            "min_abort_commands": self.min_abort_commands,
            "min_receipts": self.min_receipts,
            "min_operator_acks": self.min_operator_acks,
            "min_privacy_replay_roots": self.min_privacy_replay_roots,
            "min_finding_reopen_roots": self.min_finding_reopen_roots,
            "max_release_blockers": self.max_release_blockers,
            "max_active_holds": self.max_active_holds,
            "max_records": self.max_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceDeploymentGuardBinding {
    pub binding_id: String,
    pub guard_root: String,
    pub guard_height: u64,
    pub release_policy_root: String,
    pub operator_dashboard_root: String,
    pub guard_decision: HoldUnholdVerdict,
    pub accepted_security_root: String,
    pub privacy_review_root: String,
    pub rollback_proof_root: String,
    pub abort_root: String,
}

impl SourceDeploymentGuardBinding {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "guard_root": self.guard_root,
            "guard_height": self.guard_height,
            "release_policy_root": self.release_policy_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "guard_decision": self.guard_decision.as_str(),
            "accepted_security_root": self.accepted_security_root,
            "privacy_review_root": self.privacy_review_root,
            "rollback_proof_root": self.rollback_proof_root,
            "abort_root": self.abort_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-SOURCE-GUARD-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityRollbackTranscript {
    pub transcript_id: String,
    pub step: DrillStepKind,
    pub source_guard_root: String,
    pub pre_state_root: String,
    pub command_root: String,
    pub observed_state_root: String,
    pub expected_receipt_root: String,
    pub fail_closed_observed: bool,
    pub accepted: bool,
    pub observed_at_height: u64,
}

impl SecurityRollbackTranscript {
    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "step": self.step.as_str(),
            "source_guard_root": self.source_guard_root,
            "pre_state_root": self.pre_state_root,
            "command_root": self.command_root,
            "observed_state_root": self.observed_state_root,
            "expected_receipt_root": self.expected_receipt_root,
            "fail_closed_observed": self.fail_closed_observed,
            "accepted": self.accepted,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-SECURITY-TRANSCRIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FindingReopenCriterion {
    pub criterion_id: String,
    pub finding_id: String,
    pub kind: ReopenCriterionKind,
    pub source_finding_root: String,
    pub reopen_trigger_root: String,
    pub abort_command_root: String,
    pub expected_reopened_root: String,
    pub release_blocking: bool,
    pub accepted: bool,
}

impl FindingReopenCriterion {
    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "finding_id": self.finding_id,
            "kind": self.kind.as_str(),
            "source_finding_root": self.source_finding_root,
            "reopen_trigger_root": self.reopen_trigger_root,
            "abort_command_root": self.abort_command_root,
            "expected_reopened_root": self.expected_reopened_root,
            "release_blocking": self.release_blocking,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "ROLLBACK-DRILL-FINDING-REOPEN-CRITERION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyAuditBlockerReplay {
    pub replay_id: String,
    pub boundary: PrivacyReplayBoundary,
    pub audit_blocker_root: String,
    pub replay_input_root: String,
    pub replay_result_root: String,
    pub redaction_receipt_root: String,
    pub no_linkage_receipt_root: String,
    pub release_blocking: bool,
    pub accepted: bool,
}

impl PrivacyAuditBlockerReplay {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_id": self.replay_id,
            "boundary": self.boundary.as_str(),
            "audit_blocker_root": self.audit_blocker_root,
            "replay_input_root": self.replay_input_root,
            "replay_result_root": self.replay_result_root,
            "redaction_receipt_root": self.redaction_receipt_root,
            "no_linkage_receipt_root": self.no_linkage_receipt_root,
            "release_blocking": self.release_blocking,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "ROLLBACK-DRILL-PRIVACY-BLOCKER-REPLAY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbortCommandEvidence {
    pub command_id: String,
    pub command_kind: AbortCommandKind,
    pub issued_by_role: OperatorRole,
    pub command_root: String,
    pub target_guard_root: String,
    pub expected_receipt_label: String,
    pub expected_receipt_root: String,
    pub fail_closed_required: bool,
    pub observed_at_height: u64,
}

impl AbortCommandEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "command_id": self.command_id,
            "command_kind": self.command_kind.as_str(),
            "issued_by_role": self.issued_by_role.as_str(),
            "command_root": self.command_root,
            "target_guard_root": self.target_guard_root,
            "expected_receipt_label": self.expected_receipt_label,
            "expected_receipt_root": self.expected_receipt_root,
            "fail_closed_required": self.fail_closed_required,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-ABORT-COMMAND", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExpectedReceiptEvidence {
    pub receipt_id: String,
    pub command_id: String,
    pub receipt_label: String,
    pub receipt_root: String,
    pub observed_state_root: String,
    pub matches_expected: bool,
    pub fail_closed_observed: bool,
    pub archived: bool,
    pub observed_at_height: u64,
}

impl ExpectedReceiptEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "command_id": self.command_id,
            "receipt_label": self.receipt_label,
            "receipt_root": self.receipt_root,
            "observed_state_root": self.observed_state_root,
            "matches_expected": self.matches_expected,
            "fail_closed_observed": self.fail_closed_observed,
            "archived": self.archived,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-EXPECTED-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_role: OperatorRole,
    pub operator_id: String,
    pub signed_drill_root: String,
    pub signed_abort_root: String,
    pub signed_hold_state_root: String,
    pub acknowledges_fail_closed: bool,
    pub acknowledges_reacceptance_required: bool,
    pub accepted: bool,
    pub observed_at_height: u64,
}

impl OperatorAcknowledgement {
    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_role": self.operator_role.as_str(),
            "operator_id": self.operator_id,
            "signed_drill_root": self.signed_drill_root,
            "signed_abort_root": self.signed_abort_root,
            "signed_hold_state_root": self.signed_hold_state_root,
            "acknowledges_fail_closed": self.acknowledges_fail_closed,
            "acknowledges_reacceptance_required": self.acknowledges_reacceptance_required,
            "accepted": self.accepted,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-OPERATOR-ACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldUnholdDrillState {
    pub state_id: String,
    pub hold_id: String,
    pub hold_active: bool,
    pub unhold_allowed: bool,
    pub release_blockers: Vec<RollbackDrillBlockerKind>,
    pub hold_root: String,
    pub unhold_criteria_root: String,
    pub reacceptance_root: String,
    pub rollback_archive_root: String,
    pub verdict: HoldUnholdVerdict,
}

impl HoldUnholdDrillState {
    pub fn public_record(&self) -> Value {
        json!({
            "state_id": self.state_id,
            "hold_id": self.hold_id,
            "hold_active": self.hold_active,
            "unhold_allowed": self.unhold_allowed,
            "release_blockers": self.release_blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "hold_root": self.hold_root,
            "unhold_criteria_root": self.unhold_criteria_root,
            "reacceptance_root": self.reacceptance_root,
            "rollback_archive_root": self.rollback_archive_root,
            "verdict": self.verdict.as_str(),
            "release_allowed": self.verdict.allows_release(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-HOLD-UNHOLD-STATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DrillCounters {
    pub source_guard_bindings: u64,
    pub accepted_transcripts: u64,
    pub accepted_finding_reopen_roots: u64,
    pub accepted_privacy_replay_roots: u64,
    pub abort_commands: u64,
    pub matched_receipts: u64,
    pub operator_acknowledgements: u64,
    pub active_holds: u64,
    pub release_blockers: u64,
    pub fail_closed_blockers: u64,
}

impl DrillCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "source_guard_bindings": self.source_guard_bindings,
            "accepted_transcripts": self.accepted_transcripts,
            "accepted_finding_reopen_roots": self.accepted_finding_reopen_roots,
            "accepted_privacy_replay_roots": self.accepted_privacy_replay_roots,
            "abort_commands": self.abort_commands,
            "matched_receipts": self.matched_receipts,
            "operator_acknowledgements": self.operator_acknowledgements,
            "active_holds": self.active_holds,
            "release_blockers": self.release_blockers,
            "fail_closed_blockers": self.fail_closed_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DrillVerdict {
    pub verdict: HoldUnholdVerdict,
    pub fail_closed: bool,
    pub release_allowed: bool,
    pub release_hold_root: String,
    pub release_unhold_root: String,
    pub blocker_root: String,
    pub required_reacceptance_root: String,
    pub operator_ack_root: String,
    pub receipt_archive_root: String,
}

impl DrillVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "fail_closed": self.fail_closed,
            "release_allowed": self.release_allowed,
            "release_hold_root": self.release_hold_root,
            "release_unhold_root": self.release_unhold_root,
            "blocker_root": self.blocker_root,
            "required_reacceptance_root": self.required_reacceptance_root,
            "operator_ack_root": self.operator_ack_root,
            "receipt_archive_root": self.receipt_archive_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-VERDICT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub source_guard: SourceDeploymentGuardBinding,
    pub transcripts: BTreeMap<String, SecurityRollbackTranscript>,
    pub finding_reopen_criteria: BTreeMap<String, FindingReopenCriterion>,
    pub privacy_replays: BTreeMap<String, PrivacyAuditBlockerReplay>,
    pub abort_commands: BTreeMap<String, AbortCommandEvidence>,
    pub expected_receipts: BTreeMap<String, ExpectedReceiptEvidence>,
    pub operator_acknowledgements: BTreeMap<String, OperatorAcknowledgement>,
    pub hold_unhold_state: HoldUnholdDrillState,
    pub blockers: BTreeMap<String, Vec<RollbackDrillBlockerKind>>,
    pub lane_roots: BTreeMap<String, String>,
    pub counters: DrillCounters,
    pub verdict: DrillVerdict,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        source_guard: SourceDeploymentGuardBinding,
        transcripts: BTreeMap<String, SecurityRollbackTranscript>,
        finding_reopen_criteria: BTreeMap<String, FindingReopenCriterion>,
        privacy_replays: BTreeMap<String, PrivacyAuditBlockerReplay>,
        abort_commands: BTreeMap<String, AbortCommandEvidence>,
        expected_receipts: BTreeMap<String, ExpectedReceiptEvidence>,
        operator_acknowledgements: BTreeMap<String, OperatorAcknowledgement>,
        hold_unhold_state: HoldUnholdDrillState,
    ) -> Result<Self> {
        ensure_non_empty("rollback_drill_id", &config.rollback_drill_id)?;
        ensure_window(
            config.drill_window_start_height,
            config.drill_window_end_height,
        )?;
        ensure_root(
            "source_deployment_guard_root",
            &config.source_deployment_guard_root,
        )?;
        ensure_root("release_policy_root", &config.release_policy_root)?;
        ensure_root("operator_dashboard_root", &config.operator_dashboard_root)?;
        ensure_capacity(transcripts.len(), config.max_records)?;
        ensure_capacity(finding_reopen_criteria.len(), config.max_records)?;
        ensure_capacity(privacy_replays.len(), config.max_records)?;
        ensure_capacity(abort_commands.len(), config.max_records)?;
        ensure_capacity(expected_receipts.len(), config.max_records)?;
        ensure_capacity(operator_acknowledgements.len(), config.max_records)?;

        let blockers = evaluate_blockers(
            &config,
            height,
            &source_guard,
            &transcripts,
            &finding_reopen_criteria,
            &privacy_replays,
            &abort_commands,
            &expected_receipts,
            &operator_acknowledgements,
            &hold_unhold_state,
        );
        let counters = count_records(
            &source_guard,
            &transcripts,
            &finding_reopen_criteria,
            &privacy_replays,
            &abort_commands,
            &expected_receipts,
            &operator_acknowledgements,
            &hold_unhold_state,
            &blockers,
        );
        let lane_roots = build_lane_roots(
            &source_guard,
            &transcripts,
            &finding_reopen_criteria,
            &privacy_replays,
            &abort_commands,
            &expected_receipts,
            &operator_acknowledgements,
            &hold_unhold_state,
            &counters,
        );
        let verdict = build_verdict(&hold_unhold_state, &blockers, &lane_roots, &counters);

        Ok(Self {
            config,
            height,
            source_guard,
            transcripts,
            finding_reopen_criteria,
            privacy_replays,
            abort_commands,
            expected_receipts,
            operator_acknowledgements,
            hold_unhold_state,
            blockers,
            lane_roots,
            counters,
            verdict,
        })
    }

    pub fn devnet() -> Self {
        build_devnet().unwrap_or_else_state()
    }

    pub fn add_transcript(&mut self, record: SecurityRollbackTranscript) -> Result<()> {
        ensure_capacity(self.transcripts.len(), self.config.max_records)?;
        ensure_non_empty("transcript_id", &record.transcript_id)?;
        ensure_root("command_root", &record.command_root)?;
        self.transcripts
            .insert(record.transcript_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn add_finding_reopen_criterion(&mut self, record: FindingReopenCriterion) -> Result<()> {
        ensure_capacity(self.finding_reopen_criteria.len(), self.config.max_records)?;
        ensure_non_empty("criterion_id", &record.criterion_id)?;
        ensure_non_empty("finding_id", &record.finding_id)?;
        ensure_root("abort_command_root", &record.abort_command_root)?;
        self.finding_reopen_criteria
            .insert(record.criterion_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn add_privacy_replay(&mut self, record: PrivacyAuditBlockerReplay) -> Result<()> {
        ensure_capacity(self.privacy_replays.len(), self.config.max_records)?;
        ensure_non_empty("replay_id", &record.replay_id)?;
        ensure_root("audit_blocker_root", &record.audit_blocker_root)?;
        self.privacy_replays
            .insert(record.replay_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn add_abort_command(&mut self, record: AbortCommandEvidence) -> Result<()> {
        ensure_capacity(self.abort_commands.len(), self.config.max_records)?;
        ensure_non_empty("command_id", &record.command_id)?;
        ensure_root("command_root", &record.command_root)?;
        self.abort_commands
            .insert(record.command_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn add_expected_receipt(&mut self, record: ExpectedReceiptEvidence) -> Result<()> {
        ensure_capacity(self.expected_receipts.len(), self.config.max_records)?;
        ensure_non_empty("receipt_id", &record.receipt_id)?;
        ensure_root("receipt_root", &record.receipt_root)?;
        self.expected_receipts
            .insert(record.receipt_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn add_operator_acknowledgement(&mut self, record: OperatorAcknowledgement) -> Result<()> {
        ensure_capacity(
            self.operator_acknowledgements.len(),
            self.config.max_records,
        )?;
        ensure_non_empty("acknowledgement_id", &record.acknowledgement_id)?;
        ensure_root("signed_drill_root", &record.signed_drill_root)?;
        self.operator_acknowledgements
            .insert(record.acknowledgement_id.clone(), record);
        self.recompute();
        Ok(())
    }

    pub fn blockers_for_lane(&self, lane: RollbackDrillLane) -> Vec<RollbackDrillBlockerKind> {
        self.blockers
            .get(lane.as_str())
            .cloned()
            .unwrap_or_default()
    }

    pub fn release_allowed(&self) -> bool {
        self.verdict.release_allowed
    }

    pub fn fail_closed(&self) -> bool {
        self.verdict.fail_closed
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "source_guard": self.source_guard.public_record(),
            "transcripts": records_map(&self.transcripts, SecurityRollbackTranscript::public_record),
            "finding_reopen_criteria": records_map(&self.finding_reopen_criteria, FindingReopenCriterion::public_record),
            "privacy_replays": records_map(&self.privacy_replays, PrivacyAuditBlockerReplay::public_record),
            "abort_commands": records_map(&self.abort_commands, AbortCommandEvidence::public_record),
            "expected_receipts": records_map(&self.expected_receipts, ExpectedReceiptEvidence::public_record),
            "operator_acknowledgements": records_map(&self.operator_acknowledgements, OperatorAcknowledgement::public_record),
            "hold_unhold_state": self.hold_unhold_state.public_record(),
            "blockers": blockers_record(&self.blockers),
            "lane_roots": self.lane_roots,
            "counters": self.counters.public_record(),
            "verdict": self.verdict.public_record(),
            "config_root": self.config.state_root(),
            "source_guard_root": self.source_guard.state_root(),
            "hold_unhold_state_root": self.hold_unhold_state.state_root(),
            "counters_root": self.counters.state_root(),
            "verdict_root": self.verdict.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ROLLBACK-DRILL-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.rollback_drill_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.source_guard.state_root()),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-TRANSCRIPTS",
                    &self.transcripts,
                    SecurityRollbackTranscript::state_root,
                )),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-FINDING-REOPEN",
                    &self.finding_reopen_criteria,
                    FindingReopenCriterion::state_root,
                )),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-PRIVACY-REPLAY",
                    &self.privacy_replays,
                    PrivacyAuditBlockerReplay::state_root,
                )),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-ABORT-COMMANDS",
                    &self.abort_commands,
                    AbortCommandEvidence::state_root,
                )),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-RECEIPTS",
                    &self.expected_receipts,
                    ExpectedReceiptEvidence::state_root,
                )),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-OPERATOR-ACKS",
                    &self.operator_acknowledgements,
                    OperatorAcknowledgement::state_root,
                )),
                HashPart::Str(&self.hold_unhold_state.state_root()),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.verdict.state_root()),
            ],
        )
    }

    fn recompute(&mut self) {
        self.blockers = evaluate_blockers(
            &self.config,
            self.height,
            &self.source_guard,
            &self.transcripts,
            &self.finding_reopen_criteria,
            &self.privacy_replays,
            &self.abort_commands,
            &self.expected_receipts,
            &self.operator_acknowledgements,
            &self.hold_unhold_state,
        );
        self.counters = count_records(
            &self.source_guard,
            &self.transcripts,
            &self.finding_reopen_criteria,
            &self.privacy_replays,
            &self.abort_commands,
            &self.expected_receipts,
            &self.operator_acknowledgements,
            &self.hold_unhold_state,
            &self.blockers,
        );
        self.lane_roots = build_lane_roots(
            &self.source_guard,
            &self.transcripts,
            &self.finding_reopen_criteria,
            &self.privacy_replays,
            &self.abort_commands,
            &self.expected_receipts,
            &self.operator_acknowledgements,
            &self.hold_unhold_state,
            &self.counters,
        );
        self.verdict = build_verdict(
            &self.hold_unhold_state,
            &self.blockers,
            &self.lane_roots,
            &self.counters,
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

trait DevnetFallback {
    fn unwrap_or_else_state(self) -> State;
}

impl DevnetFallback for Result<State> {
    fn unwrap_or_else_state(self) -> State {
        match self {
            Ok(state) => state,
            Err(_) => build_devnet_held_fallback(),
        }
    }
}

fn build_devnet_held_fallback() -> State {
    let config = Config::devnet();
    let height = DEFAULT_HEIGHT;
    let source_guard = SourceDeploymentGuardBinding {
        binding_id: stable_id("fallback-source-guard", "audit-security"),
        guard_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-GUARD",
            &json!({"lane": "audit_security"}),
        ),
        guard_height: height,
        release_policy_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-RELEASE-POLICY",
            &json!({"status": "held"}),
        ),
        operator_dashboard_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-DASHBOARD",
            &json!({"operator_dashboard": "held"}),
        ),
        guard_decision: HoldUnholdVerdict::Hold,
        accepted_security_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-SECURITY",
            &json!({"accepted": false}),
        ),
        privacy_review_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-PRIVACY",
            &json!({"accepted": false}),
        ),
        rollback_proof_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-ROLLBACK",
            &json!({"accepted": false}),
        ),
        abort_root: record_root("ROLLBACK-DRILL-FALLBACK-ABORT", &json!({"held": true})),
    };
    let hold_unhold_state = HoldUnholdDrillState {
        state_id: stable_id("fallback-hold-state", "audit-security"),
        hold_id: "fallback-audit-security-hold".to_string(),
        hold_active: true,
        unhold_allowed: false,
        release_blockers: vec![
            RollbackDrillBlockerKind::ActiveManualHold,
            RollbackDrillBlockerKind::ReleaseHoldNotFailClosed,
        ],
        hold_root: record_root("ROLLBACK-DRILL-FALLBACK-HOLD", &json!({"active": true})),
        unhold_criteria_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-UNHOLD",
            &json!({"allowed": false}),
        ),
        reacceptance_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-REACCEPTANCE",
            &json!({"required": true}),
        ),
        rollback_archive_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-ARCHIVE",
            &json!({"archived": false}),
        ),
        verdict: HoldUnholdVerdict::Hold,
    };
    let mut blockers = BTreeMap::new();
    blockers.insert(
        "audit_security".to_string(),
        vec![
            RollbackDrillBlockerKind::ActiveManualHold,
            RollbackDrillBlockerKind::MissingSecurityRollbackTranscriptRoot,
        ],
    );
    let mut lane_roots = BTreeMap::new();
    lane_roots.insert("source_guard".to_string(), source_guard.state_root());
    lane_roots.insert(
        "hold_unhold_state".to_string(),
        hold_unhold_state.state_root(),
    );
    let counters = DrillCounters {
        source_guard_bindings: 1,
        accepted_transcripts: 0,
        accepted_finding_reopen_roots: 0,
        accepted_privacy_replay_roots: 0,
        abort_commands: 0,
        matched_receipts: 0,
        operator_acknowledgements: 0,
        active_holds: 1,
        release_blockers: 2,
        fail_closed_blockers: 2,
    };
    let verdict = DrillVerdict {
        verdict: HoldUnholdVerdict::Hold,
        fail_closed: true,
        release_allowed: false,
        release_hold_root: hold_unhold_state.hold_root.clone(),
        release_unhold_root: hold_unhold_state.unhold_criteria_root.clone(),
        blocker_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-BLOCKERS",
            &json!({"blockers": ["active_manual_hold", "missing_security_rollback_transcript_root"]}),
        ),
        required_reacceptance_root: hold_unhold_state.reacceptance_root.clone(),
        operator_ack_root: record_root(
            "ROLLBACK-DRILL-FALLBACK-OPERATOR-ACK",
            &json!({"accepted": false}),
        ),
        receipt_archive_root: hold_unhold_state.rollback_archive_root.clone(),
    };
    State {
        config,
        height,
        source_guard,
        transcripts: BTreeMap::new(),
        finding_reopen_criteria: BTreeMap::new(),
        privacy_replays: BTreeMap::new(),
        abort_commands: BTreeMap::new(),
        expected_receipts: BTreeMap::new(),
        operator_acknowledgements: BTreeMap::new(),
        hold_unhold_state,
        blockers,
        lane_roots,
        counters,
        verdict,
    }
}

fn build_devnet() -> Result<State> {
    let config = Config::devnet();
    let height = DEFAULT_HEIGHT;
    let source_guard = SourceDeploymentGuardBinding {
        binding_id: stable_id("source-guard-binding", "wave84-audit-security"),
        guard_root: config.source_deployment_guard_root.clone(),
        guard_height: config.source_deployment_guard_height,
        release_policy_root: config.release_policy_root.clone(),
        operator_dashboard_root: config.operator_dashboard_root.clone(),
        guard_decision: HoldUnholdVerdict::Unheld,
        accepted_security_root: fixture_root("wave84-accepted-security-root"),
        privacy_review_root: fixture_root("wave84-privacy-review-root"),
        rollback_proof_root: fixture_root("wave84-rollback-proof-root"),
        abort_root: fixture_root("wave84-abort-root"),
    };
    let transcripts = build_devnet_transcripts(&source_guard);
    let finding_reopen_criteria = build_devnet_finding_reopen_criteria(&source_guard);
    let privacy_replays = build_devnet_privacy_replays();
    let abort_commands = build_devnet_abort_commands(&source_guard);
    let expected_receipts = build_devnet_receipts(&abort_commands);
    let operator_acknowledgements = build_devnet_operator_acks(&source_guard);
    let hold_unhold_state = HoldUnholdDrillState {
        state_id: stable_id("hold-unhold-state", "wave85-devnet"),
        hold_id: stable_id("release-hold", "rollback-drill-cleared"),
        hold_active: false,
        unhold_allowed: true,
        release_blockers: Vec::new(),
        hold_root: fixture_root("rollback-drill-hold-cleared-root"),
        unhold_criteria_root: fixture_root("rollback-drill-unhold-criteria-root"),
        reacceptance_root: fixture_root("rollback-drill-security-reacceptance-root"),
        rollback_archive_root: fixture_root("rollback-drill-archive-root"),
        verdict: HoldUnholdVerdict::Unheld,
    };

    State::new(
        config,
        height,
        source_guard,
        transcripts,
        finding_reopen_criteria,
        privacy_replays,
        abort_commands,
        expected_receipts,
        operator_acknowledgements,
        hold_unhold_state,
    )
}

fn build_devnet_transcripts(
    source_guard: &SourceDeploymentGuardBinding,
) -> BTreeMap<String, SecurityRollbackTranscript> {
    DrillStepKind::all()
        .into_iter()
        .enumerate()
        .map(|(index, step)| {
            let id = stable_id("security-rollback-transcript", step.as_str());
            let command_root =
                fixture_root(&format!("rollback-transcript-command-{}", step.as_str()));
            let record = SecurityRollbackTranscript {
                transcript_id: id.clone(),
                step,
                source_guard_root: source_guard.guard_root.clone(),
                pre_state_root: fixture_root(&format!("rollback-pre-state-{}", step.as_str())),
                command_root,
                observed_state_root: fixture_root(&format!(
                    "rollback-observed-state-{}",
                    step.as_str()
                )),
                expected_receipt_root: fixture_root(&format!(
                    "rollback-expected-receipt-{}",
                    step.as_str()
                )),
                fail_closed_observed: step.expected_fail_closed() || index >= 5,
                accepted: true,
                observed_at_height: DEFAULT_HEIGHT + index as u64,
            };
            (id, record)
        })
        .collect()
}

fn build_devnet_finding_reopen_criteria(
    source_guard: &SourceDeploymentGuardBinding,
) -> BTreeMap<String, FindingReopenCriterion> {
    ReopenCriterionKind::all()
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let finding_id = format!("SEC-W85-REOPEN-{index:03}");
            let id = stable_id("finding-reopen", kind.as_str());
            let record = FindingReopenCriterion {
                criterion_id: id.clone(),
                finding_id,
                kind,
                source_finding_root: fixture_root(&format!(
                    "source-finding-root-{}",
                    kind.as_str()
                )),
                reopen_trigger_root: fixture_root(&format!(
                    "reopen-trigger-root-{}",
                    kind.as_str()
                )),
                abort_command_root: source_guard.abort_root.clone(),
                expected_reopened_root: fixture_root(&format!(
                    "expected-reopened-root-{}",
                    kind.as_str()
                )),
                release_blocking: kind.blocks_release(),
                accepted: true,
            };
            (id, record)
        })
        .collect()
}

fn build_devnet_privacy_replays() -> BTreeMap<String, PrivacyAuditBlockerReplay> {
    PrivacyReplayBoundary::all()
        .into_iter()
        .map(|boundary| {
            let id = stable_id("privacy-blocker-replay", boundary.as_str());
            let record = PrivacyAuditBlockerReplay {
                replay_id: id.clone(),
                boundary,
                audit_blocker_root: fixture_root(&format!(
                    "privacy-audit-blocker-{}",
                    boundary.as_str()
                )),
                replay_input_root: fixture_root(&format!(
                    "privacy-replay-input-{}",
                    boundary.as_str()
                )),
                replay_result_root: fixture_root(&format!(
                    "privacy-replay-result-{}",
                    boundary.as_str()
                )),
                redaction_receipt_root: fixture_root(&format!(
                    "redaction-receipt-{}",
                    boundary.as_str()
                )),
                no_linkage_receipt_root: fixture_root(&format!(
                    "no-linkage-receipt-{}",
                    boundary.as_str()
                )),
                release_blocking: false,
                accepted: true,
            };
            (id, record)
        })
        .collect()
}

fn build_devnet_abort_commands(
    source_guard: &SourceDeploymentGuardBinding,
) -> BTreeMap<String, AbortCommandEvidence> {
    AbortCommandKind::all()
        .into_iter()
        .enumerate()
        .map(|(index, command_kind)| {
            let id = stable_id("abort-command", command_kind.as_str());
            let record = AbortCommandEvidence {
                command_id: id.clone(),
                command_kind,
                issued_by_role: match index % 4 {
                    0 => OperatorRole::IncidentCommander,
                    1 => OperatorRole::SecurityLead,
                    2 => OperatorRole::PrivacyLead,
                    _ => OperatorRole::RollbackOwner,
                },
                command_root: fixture_root(&format!(
                    "abort-command-root-{}",
                    command_kind.as_str()
                )),
                target_guard_root: source_guard.guard_root.clone(),
                expected_receipt_label: command_kind.required_receipt().to_string(),
                expected_receipt_root: fixture_root(command_kind.required_receipt()),
                fail_closed_required: true,
                observed_at_height: DEFAULT_HEIGHT + 16 + index as u64,
            };
            (id, record)
        })
        .collect()
}

fn build_devnet_receipts(
    abort_commands: &BTreeMap<String, AbortCommandEvidence>,
) -> BTreeMap<String, ExpectedReceiptEvidence> {
    abort_commands
        .values()
        .enumerate()
        .map(|(index, command)| {
            let id = stable_id("expected-receipt", &command.command_id);
            let record = ExpectedReceiptEvidence {
                receipt_id: id.clone(),
                command_id: command.command_id.clone(),
                receipt_label: command.expected_receipt_label.clone(),
                receipt_root: command.expected_receipt_root.clone(),
                observed_state_root: fixture_root(&format!(
                    "receipt-observed-state-{}",
                    command.command_kind.as_str()
                )),
                matches_expected: true,
                fail_closed_observed: true,
                archived: true,
                observed_at_height: command.observed_at_height + 1 + index as u64,
            };
            (id, record)
        })
        .collect()
}

fn build_devnet_operator_acks(
    source_guard: &SourceDeploymentGuardBinding,
) -> BTreeMap<String, OperatorAcknowledgement> {
    OperatorRole::all_required()
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            let id = stable_id("operator-ack", role.as_str());
            let record = OperatorAcknowledgement {
                acknowledgement_id: id.clone(),
                operator_role: role,
                operator_id: stable_id("operator", role.as_str()),
                signed_drill_root: fixture_root(&format!(
                    "operator-signed-drill-{}",
                    role.as_str()
                )),
                signed_abort_root: source_guard.abort_root.clone(),
                signed_hold_state_root: fixture_root(&format!(
                    "operator-signed-hold-state-{}",
                    role.as_str()
                )),
                acknowledges_fail_closed: true,
                acknowledges_reacceptance_required: true,
                accepted: true,
                observed_at_height: DEFAULT_HEIGHT + 32 + index as u64,
            };
            (id, record)
        })
        .collect()
}

fn evaluate_blockers(
    config: &Config,
    height: u64,
    source_guard: &SourceDeploymentGuardBinding,
    transcripts: &BTreeMap<String, SecurityRollbackTranscript>,
    finding_reopen_criteria: &BTreeMap<String, FindingReopenCriterion>,
    privacy_replays: &BTreeMap<String, PrivacyAuditBlockerReplay>,
    abort_commands: &BTreeMap<String, AbortCommandEvidence>,
    expected_receipts: &BTreeMap<String, ExpectedReceiptEvidence>,
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
    hold_unhold_state: &HoldUnholdDrillState,
) -> BTreeMap<String, Vec<RollbackDrillBlockerKind>> {
    let mut blockers = BTreeMap::new();

    let mut source_blockers = Vec::new();
    if source_guard.guard_root.is_empty() {
        source_blockers.push(RollbackDrillBlockerKind::MissingSourceGuardRoot);
    }
    if source_guard.guard_height + config.max_source_guard_age_blocks < height {
        source_blockers.push(RollbackDrillBlockerKind::SourceGuardStale);
    }
    if !source_guard.guard_decision.allows_release() {
        source_blockers.push(RollbackDrillBlockerKind::SourceGuardNotUnheld);
    }
    if source_guard.release_policy_root != config.release_policy_root {
        source_blockers.push(RollbackDrillBlockerKind::ReleasePolicyRootMismatch);
    }
    if source_guard.operator_dashboard_root != config.operator_dashboard_root {
        source_blockers.push(RollbackDrillBlockerKind::DashboardRootMismatch);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::SourceDeploymentGuard,
        source_blockers,
    );

    let mut transcript_blockers = Vec::new();
    if accepted_count(transcripts.values().map(|record| record.accepted))
        < config.min_transcript_roots
    {
        transcript_blockers.push(RollbackDrillBlockerKind::MissingSecurityRollbackTranscriptRoot);
    }
    if transcripts
        .values()
        .any(|record| !record.accepted || !record.fail_closed_observed)
    {
        transcript_blockers.push(RollbackDrillBlockerKind::SecurityTranscriptRejected);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::SecurityRollbackTranscript,
        transcript_blockers,
    );

    let mut finding_blockers = Vec::new();
    if accepted_count(
        finding_reopen_criteria
            .values()
            .map(|record| record.accepted),
    ) < config.min_finding_reopen_roots
    {
        finding_blockers.push(RollbackDrillBlockerKind::MissingFindingReopenRoot);
    }
    if finding_reopen_criteria
        .values()
        .any(|record| record.release_blocking && !record.accepted)
    {
        finding_blockers.push(RollbackDrillBlockerKind::FindingReopenAbortNotObserved);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::FindingReopenAbort,
        finding_blockers,
    );

    let mut privacy_blockers = Vec::new();
    if accepted_count(privacy_replays.values().map(|record| record.accepted))
        < config.min_privacy_replay_roots
    {
        privacy_blockers.push(RollbackDrillBlockerKind::MissingPrivacyReplayRoot);
    }
    if privacy_replays
        .values()
        .any(|record| record.release_blocking || !record.accepted)
    {
        privacy_blockers.push(RollbackDrillBlockerKind::PrivacyBlockerReplayRejected);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::PrivacyAuditBlockerReplay,
        privacy_blockers,
    );

    let mut abort_blockers = Vec::new();
    if (abort_commands.len() as u64) < config.min_abort_commands {
        abort_blockers.push(RollbackDrillBlockerKind::MissingAbortCommandRoot);
    }
    let command_ids = abort_commands.keys().cloned().collect::<BTreeSet<_>>();
    let receipt_command_ids = expected_receipts
        .values()
        .filter(|receipt| {
            receipt.matches_expected && receipt.fail_closed_observed && receipt.archived
        })
        .map(|receipt| receipt.command_id.clone())
        .collect::<BTreeSet<_>>();
    if !command_ids.is_subset(&receipt_command_ids) {
        abort_blockers.push(RollbackDrillBlockerKind::AbortReceiptMissing);
    }
    if accepted_count(expected_receipts.values().map(|receipt| {
        receipt.matches_expected && receipt.fail_closed_observed && receipt.archived
    })) < config.min_receipts
    {
        abort_blockers.push(RollbackDrillBlockerKind::AbortReceiptRejected);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::ReceiptArchive,
        abort_blockers,
    );

    let mut ack_blockers = Vec::new();
    if accepted_count(
        operator_acknowledgements
            .values()
            .map(|record| record.accepted),
    ) < config.min_operator_acks
    {
        ack_blockers.push(RollbackDrillBlockerKind::MissingOperatorAcknowledgement);
    }
    if operator_acknowledgements.values().any(|record| {
        !record.accepted
            || !record.acknowledges_fail_closed
            || !record.acknowledges_reacceptance_required
    }) {
        ack_blockers.push(RollbackDrillBlockerKind::OperatorAcknowledgementRejected);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::OperatorAcknowledgement,
        ack_blockers,
    );

    let mut hold_blockers = hold_unhold_state.release_blockers.clone();
    if height < config.drill_window_start_height {
        hold_blockers.push(RollbackDrillBlockerKind::DrillWindowNotOpen);
    }
    if height > config.drill_window_end_height {
        hold_blockers.push(RollbackDrillBlockerKind::DrillWindowClosed);
    }
    if hold_unhold_state.hold_active && config.max_active_holds == 0 {
        hold_blockers.push(RollbackDrillBlockerKind::ActiveManualHold);
    }
    if hold_unhold_state.verdict == HoldUnholdVerdict::Unheld
        && hold_unhold_state.reacceptance_root.is_empty()
    {
        hold_blockers.push(RollbackDrillBlockerKind::ReleaseUnholdWithoutReacceptance);
    }
    if hold_unhold_state.verdict == HoldUnholdVerdict::Abort && !hold_unhold_state.hold_active {
        hold_blockers.push(RollbackDrillBlockerKind::ReleaseHoldNotFailClosed);
    }
    insert_if_any(
        &mut blockers,
        RollbackDrillLane::HoldUnholdState,
        hold_blockers,
    );

    blockers
}

fn count_records(
    _source_guard: &SourceDeploymentGuardBinding,
    transcripts: &BTreeMap<String, SecurityRollbackTranscript>,
    finding_reopen_criteria: &BTreeMap<String, FindingReopenCriterion>,
    privacy_replays: &BTreeMap<String, PrivacyAuditBlockerReplay>,
    abort_commands: &BTreeMap<String, AbortCommandEvidence>,
    expected_receipts: &BTreeMap<String, ExpectedReceiptEvidence>,
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
    hold_unhold_state: &HoldUnholdDrillState,
    blockers: &BTreeMap<String, Vec<RollbackDrillBlockerKind>>,
) -> DrillCounters {
    let release_blockers = blockers
        .values()
        .map(|items| items.len() as u64)
        .sum::<u64>();
    let fail_closed_blockers = blockers
        .values()
        .flatten()
        .filter(|blocker| blocker.fail_closed())
        .count() as u64;
    DrillCounters {
        source_guard_bindings: 1,
        accepted_transcripts: accepted_count(transcripts.values().map(|record| record.accepted)),
        accepted_finding_reopen_roots: accepted_count(
            finding_reopen_criteria
                .values()
                .map(|record| record.accepted),
        ),
        accepted_privacy_replay_roots: accepted_count(
            privacy_replays.values().map(|record| record.accepted),
        ),
        abort_commands: abort_commands.len() as u64,
        matched_receipts: accepted_count(expected_receipts.values().map(|record| {
            record.matches_expected && record.fail_closed_observed && record.archived
        })),
        operator_acknowledgements: accepted_count(
            operator_acknowledgements
                .values()
                .map(|record| record.accepted),
        ),
        active_holds: if hold_unhold_state.hold_active { 1 } else { 0 },
        release_blockers,
        fail_closed_blockers,
    }
}

fn build_lane_roots(
    source_guard: &SourceDeploymentGuardBinding,
    transcripts: &BTreeMap<String, SecurityRollbackTranscript>,
    finding_reopen_criteria: &BTreeMap<String, FindingReopenCriterion>,
    privacy_replays: &BTreeMap<String, PrivacyAuditBlockerReplay>,
    abort_commands: &BTreeMap<String, AbortCommandEvidence>,
    expected_receipts: &BTreeMap<String, ExpectedReceiptEvidence>,
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
    hold_unhold_state: &HoldUnholdDrillState,
    counters: &DrillCounters,
) -> BTreeMap<String, String> {
    let mut lane_roots = BTreeMap::new();
    lane_roots.insert(
        RollbackDrillLane::SourceDeploymentGuard
            .as_str()
            .to_string(),
        source_guard.state_root(),
    );
    lane_roots.insert(
        RollbackDrillLane::SecurityRollbackTranscript
            .as_str()
            .to_string(),
        map_root(
            "ROLLBACK-DRILL-LANE-SECURITY-TRANSCRIPTS",
            transcripts,
            SecurityRollbackTranscript::state_root,
        ),
    );
    lane_roots.insert(
        RollbackDrillLane::FindingReopenAbort.as_str().to_string(),
        map_root(
            "ROLLBACK-DRILL-LANE-FINDING-REOPEN",
            finding_reopen_criteria,
            FindingReopenCriterion::state_root,
        ),
    );
    lane_roots.insert(
        RollbackDrillLane::PrivacyAuditBlockerReplay
            .as_str()
            .to_string(),
        map_root(
            "ROLLBACK-DRILL-LANE-PRIVACY-REPLAY",
            privacy_replays,
            PrivacyAuditBlockerReplay::state_root,
        ),
    );
    lane_roots.insert(
        RollbackDrillLane::OperatorAcknowledgement
            .as_str()
            .to_string(),
        map_root(
            "ROLLBACK-DRILL-LANE-OPERATOR-ACKS",
            operator_acknowledgements,
            OperatorAcknowledgement::state_root,
        ),
    );
    lane_roots.insert(
        RollbackDrillLane::HoldUnholdState.as_str().to_string(),
        hold_unhold_state.state_root(),
    );
    lane_roots.insert(
        RollbackDrillLane::ReceiptArchive.as_str().to_string(),
        domain_hash(
            "ROLLBACK-DRILL-LANE-RECEIPT-ARCHIVE",
            &[
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-LANE-ABORT-COMMANDS",
                    abort_commands,
                    AbortCommandEvidence::state_root,
                )),
                HashPart::Str(&map_root(
                    "ROLLBACK-DRILL-LANE-EXPECTED-RECEIPTS",
                    expected_receipts,
                    ExpectedReceiptEvidence::state_root,
                )),
            ],
        ),
    );
    lane_roots.insert(
        RollbackDrillLane::ReleaseVerdict.as_str().to_string(),
        counters.state_root(),
    );
    lane_roots
}

fn build_verdict(
    hold_unhold_state: &HoldUnholdDrillState,
    blockers: &BTreeMap<String, Vec<RollbackDrillBlockerKind>>,
    lane_roots: &BTreeMap<String, String>,
    counters: &DrillCounters,
) -> DrillVerdict {
    let has_blockers = blockers.values().any(|items| !items.is_empty());
    let verdict = if has_blockers {
        HoldUnholdVerdict::Hold
    } else {
        hold_unhold_state.verdict
    };
    DrillVerdict {
        verdict,
        fail_closed: !verdict.allows_release() || counters.fail_closed_blockers == 0,
        release_allowed: verdict.allows_release() && !has_blockers,
        release_hold_root: hold_unhold_state.hold_root.clone(),
        release_unhold_root: hold_unhold_state.unhold_criteria_root.clone(),
        blocker_root: blockers_root(blockers),
        required_reacceptance_root: hold_unhold_state.reacceptance_root.clone(),
        operator_ack_root: lane_roots
            .get(RollbackDrillLane::OperatorAcknowledgement.as_str())
            .cloned()
            .unwrap_or_else(|| fixture_root("missing-operator-ack-root")),
        receipt_archive_root: lane_roots
            .get(RollbackDrillLane::ReceiptArchive.as_str())
            .cloned()
            .unwrap_or_else(|| fixture_root("missing-receipt-archive-root")),
    }
}

fn insert_if_any(
    blockers: &mut BTreeMap<String, Vec<RollbackDrillBlockerKind>>,
    lane: RollbackDrillLane,
    lane_blockers: Vec<RollbackDrillBlockerKind>,
) {
    if !lane_blockers.is_empty() {
        blockers.insert(lane.as_str().to_string(), lane_blockers);
    }
}

fn accepted_count<I>(items: I) -> u64
where
    I: IntoIterator<Item = bool>,
{
    items.into_iter().filter(|accepted| *accepted).count() as u64
}

fn records_map<T, F>(records: &BTreeMap<String, T>, public_record: F) -> BTreeMap<String, Value>
where
    F: Fn(&T) -> Value,
{
    records
        .iter()
        .map(|(key, record)| (key.clone(), public_record(record)))
        .collect()
}

fn blockers_record(
    blockers: &BTreeMap<String, Vec<RollbackDrillBlockerKind>>,
) -> BTreeMap<String, Vec<&'static str>> {
    blockers
        .iter()
        .map(|(lane, lane_blockers)| {
            (
                lane.clone(),
                lane_blockers
                    .iter()
                    .map(|blocker| blocker.as_str())
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn blockers_root(blockers: &BTreeMap<String, Vec<RollbackDrillBlockerKind>>) -> String {
    let leaves = blockers
        .iter()
        .flat_map(|(lane, lane_blockers)| {
            lane_blockers.iter().map(move |blocker| {
                domain_hash(
                    "ROLLBACK-DRILL-BLOCKER",
                    &[HashPart::Str(lane), HashPart::Str(blocker.as_str())],
                )
            })
        })
        .collect::<Vec<_>>();
    merkle_or_empty("ROLLBACK-DRILL-BLOCKERS", leaves)
}

fn map_root<T, F>(label: &str, records: &BTreeMap<String, T>, state_root: F) -> String
where
    F: Fn(&T) -> String,
{
    let leaves = records
        .iter()
        .map(|(key, record)| {
            domain_hash(
                "ROLLBACK-DRILL-MAP-LEAF",
                &[HashPart::Str(key), HashPart::Str(&state_root(record))],
            )
        })
        .collect::<Vec<_>>();
    merkle_or_empty(label, leaves)
}

fn merkle_or_empty(label: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        domain_hash(label, &[HashPart::Str("empty")])
    } else {
        merkle_root(label, &leaves)
    }
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        label,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
    )
}

fn fixture_root(label: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-FIXTURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
    )
}

fn stable_id(prefix: &str, label: &str) -> String {
    format!(
        "{}-{}",
        prefix,
        domain_hash(
            "ROLLBACK-DRILL-STABLE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(prefix),
                HashPart::Str(label)
            ]
        )
    )
}

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(label: &str, value: &str) -> Result<()> {
    ensure_non_empty(label, value)?;
    if value.len() < 16 {
        Err(format!("{label} must look like a deterministic root"))
    } else {
        Ok(())
    }
}

fn ensure_window(start: u64, end: u64) -> Result<()> {
    if start > end {
        Err("drill window start must be before end".to_string())
    } else {
        Ok(())
    }
}

fn ensure_capacity(current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!(
            "rollback drill record capacity exceeded: {current} >= {max}"
        ))
    } else {
        Ok(())
    }
}
