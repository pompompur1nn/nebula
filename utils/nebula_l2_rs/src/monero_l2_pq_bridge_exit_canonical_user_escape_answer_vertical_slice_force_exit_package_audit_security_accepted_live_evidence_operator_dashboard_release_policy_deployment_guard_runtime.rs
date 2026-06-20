use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageAuditSecurityAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-audit-security-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GUARD_SUITE: &str =
    "monero-l2-pq-bridge-exit-force-exit-audit-security-dashboard-deployment-guard-v1";
pub const DEFAULT_HEIGHT: u64 = 94_084;
pub const DEFAULT_DEPLOY_WINDOW_START_HEIGHT: u64 = 94_096;
pub const DEFAULT_DEPLOY_WINDOW_END_HEIGHT: u64 = 94_168;
pub const DEFAULT_MAX_GO_NO_GO_AGE_BLOCKS: u64 = 48;
pub const DEFAULT_MIN_SIGNOFF_GATES: u64 = 6;
pub const DEFAULT_MIN_OPERATOR_APPROVALS: u64 = 4;
pub const DEFAULT_MIN_ROLLBACK_PROOFS: u64 = 5;
pub const DEFAULT_MIN_ABORT_ROOTS: u64 = 4;
pub const DEFAULT_MAX_ACTIVE_HOLDS: u64 = 0;
pub const DEFAULT_MAX_OPEN_BLOCKERS: u64 = 0;
pub const DEFAULT_MAX_DEPLOY_RECORDS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardEvidenceLane {
    Wave83GoNoGoBinding,
    AuditSecurityClosure,
    PrivacyReview,
    AdversarialEvidence,
    DeploymentWindow,
    RollbackProof,
    AbortRoot,
    OperatorDashboardApproval,
    ProductionState,
}

impl GuardEvidenceLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Wave83GoNoGoBinding,
            Self::AuditSecurityClosure,
            Self::PrivacyReview,
            Self::AdversarialEvidence,
            Self::DeploymentWindow,
            Self::RollbackProof,
            Self::AbortRoot,
            Self::OperatorDashboardApproval,
            Self::ProductionState,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave83GoNoGoBinding => "wave83_go_no_go_binding",
            Self::AuditSecurityClosure => "audit_security_closure",
            Self::PrivacyReview => "privacy_review",
            Self::AdversarialEvidence => "adversarial_evidence",
            Self::DeploymentWindow => "deployment_window",
            Self::RollbackProof => "rollback_proof",
            Self::AbortRoot => "abort_root",
            Self::OperatorDashboardApproval => "operator_dashboard_approval",
            Self::ProductionState => "production_state",
        }
    }

    pub fn required_for_unhold(self) -> bool {
        matches!(
            self,
            Self::Wave83GoNoGoBinding
                | Self::AuditSecurityClosure
                | Self::PrivacyReview
                | Self::DeploymentWindow
                | Self::RollbackProof
                | Self::AbortRoot
                | Self::OperatorDashboardApproval
                | Self::ProductionState
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecision {
    Hold,
    Unhold,
    Abort,
}

impl GuardDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Unhold => "unhold",
            Self::Abort => "abort",
        }
    }

    pub fn permits_deploy(self) -> bool {
        matches!(self, Self::Unhold)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardBlockerKind {
    MissingWave83GoNoGoRoot,
    Wave83NoGo,
    StaleGoNoGoRoot,
    MissingAuditClosureRoot,
    MissingFindingClosureRoot,
    OpenSecurityFinding,
    MissingPrivacyReviewRoot,
    PrivacySignoffRejected,
    MissingAdversarialEvidenceRoot,
    ActiveAdversarialRegression,
    DeployWindowClosed,
    DeployWindowNotOpen,
    MissingRollbackProof,
    RollbackProofRejected,
    MissingAbortRoot,
    MissingOperatorApproval,
    OperatorApprovalRejected,
    ManualSecurityHold,
    ManualPrivacyHold,
    ProductionStateNotFailClosed,
    ReleasePolicyRootMismatch,
    DashboardRootMismatch,
}

impl GuardBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave83GoNoGoRoot => "missing_wave83_go_no_go_root",
            Self::Wave83NoGo => "wave83_no_go",
            Self::StaleGoNoGoRoot => "stale_go_no_go_root",
            Self::MissingAuditClosureRoot => "missing_audit_closure_root",
            Self::MissingFindingClosureRoot => "missing_finding_closure_root",
            Self::OpenSecurityFinding => "open_security_finding",
            Self::MissingPrivacyReviewRoot => "missing_privacy_review_root",
            Self::PrivacySignoffRejected => "privacy_signoff_rejected",
            Self::MissingAdversarialEvidenceRoot => "missing_adversarial_evidence_root",
            Self::ActiveAdversarialRegression => "active_adversarial_regression",
            Self::DeployWindowClosed => "deploy_window_closed",
            Self::DeployWindowNotOpen => "deploy_window_not_open",
            Self::MissingRollbackProof => "missing_rollback_proof",
            Self::RollbackProofRejected => "rollback_proof_rejected",
            Self::MissingAbortRoot => "missing_abort_root",
            Self::MissingOperatorApproval => "missing_operator_approval",
            Self::OperatorApprovalRejected => "operator_approval_rejected",
            Self::ManualSecurityHold => "manual_security_hold",
            Self::ManualPrivacyHold => "manual_privacy_hold",
            Self::ProductionStateNotFailClosed => "production_state_not_fail_closed",
            Self::ReleasePolicyRootMismatch => "release_policy_root_mismatch",
            Self::DashboardRootMismatch => "dashboard_root_mismatch",
        }
    }

    pub fn fail_closed(self) -> bool {
        matches!(
            self,
            Self::MissingWave83GoNoGoRoot
                | Self::Wave83NoGo
                | Self::StaleGoNoGoRoot
                | Self::MissingAuditClosureRoot
                | Self::MissingFindingClosureRoot
                | Self::OpenSecurityFinding
                | Self::MissingPrivacyReviewRoot
                | Self::PrivacySignoffRejected
                | Self::MissingAdversarialEvidenceRoot
                | Self::ActiveAdversarialRegression
                | Self::DeployWindowClosed
                | Self::DeployWindowNotOpen
                | Self::MissingRollbackProof
                | Self::RollbackProofRejected
                | Self::MissingAbortRoot
                | Self::MissingOperatorApproval
                | Self::OperatorApprovalRejected
                | Self::ManualSecurityHold
                | Self::ManualPrivacyHold
                | Self::ProductionStateNotFailClosed
                | Self::ReleasePolicyRootMismatch
                | Self::DashboardRootMismatch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateRole {
    ReleaseCaptain,
    SecurityLead,
    PrivacyLead,
    RuntimeMaintainer,
    OperatorDashboardOwner,
    IncidentCommander,
    RollbackOwner,
    AuditArchiveCustodian,
}

impl GateRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCaptain => "release_captain",
            Self::SecurityLead => "security_lead",
            Self::PrivacyLead => "privacy_lead",
            Self::RuntimeMaintainer => "runtime_maintainer",
            Self::OperatorDashboardOwner => "operator_dashboard_owner",
            Self::IncidentCommander => "incident_commander",
            Self::RollbackOwner => "rollback_owner",
            Self::AuditArchiveCustodian => "audit_archive_custodian",
        }
    }

    pub fn required_for_deploy(self) -> bool {
        matches!(
            self,
            Self::ReleaseCaptain
                | Self::SecurityLead
                | Self::PrivacyLead
                | Self::RuntimeMaintainer
                | Self::OperatorDashboardOwner
                | Self::IncidentCommander
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDisposition {
    Accepted,
    AcceptedWithWatch,
    Held,
    Rejected,
}

impl GateDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithWatch => "accepted_with_watch",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedWithWatch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldKind {
    Security,
    Privacy,
    ReleasePolicy,
    OperatorDashboard,
    IncidentResponse,
}

impl HoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Privacy => "privacy",
            Self::ReleasePolicy => "release_policy",
            Self::OperatorDashboard => "operator_dashboard",
            Self::IncidentResponse => "incident_response",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldStatus {
    Active,
    Cleared,
    Superseded,
}

impl HoldStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Cleared => "cleared",
            Self::Superseded => "superseded",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackProofKind {
    StateSnapshot,
    ReleaseManifest,
    BinaryAttestation,
    DatabaseMigrationReversal,
    WatchtowerReplay,
    IncidentDrill,
}

impl RollbackProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateSnapshot => "state_snapshot",
            Self::ReleaseManifest => "release_manifest",
            Self::BinaryAttestation => "binary_attestation",
            Self::DatabaseMigrationReversal => "database_migration_reversal",
            Self::WatchtowerReplay => "watchtower_replay",
            Self::IncidentDrill => "incident_drill",
        }
    }

    pub fn required_for_guard(self) -> bool {
        matches!(
            self,
            Self::StateSnapshot
                | Self::ReleaseManifest
                | Self::BinaryAttestation
                | Self::DatabaseMigrationReversal
                | Self::WatchtowerReplay
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Accepted,
    AcceptedWithWatch,
    Rejected,
    Missing,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithWatch => "accepted_with_watch",
            Self::Rejected => "rejected",
            Self::Missing => "missing",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::AcceptedWithWatch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortRootKind {
    StopSequencer,
    FreezeReleaseManifest,
    RestorePreviousRuntime,
    NotifyOperators,
    PreserveEvidence,
}

impl AbortRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StopSequencer => "stop_sequencer",
            Self::FreezeReleaseManifest => "freeze_release_manifest",
            Self::RestorePreviousRuntime => "restore_previous_runtime",
            Self::NotifyOperators => "notify_operators",
            Self::PreserveEvidence => "preserve_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionMode {
    FailClosedHeld,
    DeployWindowArmed,
    Deploying,
    Released,
    Aborted,
}

impl ProductionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedHeld => "fail_closed_held",
            Self::DeployWindowArmed => "deploy_window_armed",
            Self::Deploying => "deploying",
            Self::Released => "released",
            Self::Aborted => "aborted",
        }
    }

    pub fn fail_closed(self) -> bool {
        matches!(self, Self::FailClosedHeld | Self::Aborted)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub guard_suite: String,
    pub deployment_guard_id: String,
    pub wave83_go_no_go_binding_root: String,
    pub release_policy_root: String,
    pub operator_dashboard_root: String,
    pub required_lanes: Vec<GuardEvidenceLane>,
    pub deploy_window_start_height: u64,
    pub deploy_window_end_height: u64,
    pub max_go_no_go_age_blocks: u64,
    pub min_signoff_gates: u64,
    pub min_operator_approvals: u64,
    pub min_rollback_proofs: u64,
    pub min_abort_roots: u64,
    pub max_active_holds: u64,
    pub max_open_blockers: u64,
    pub fail_closed: bool,
    pub require_privacy_signoff: bool,
    pub require_security_signoff: bool,
    pub require_dashboard_root_match: bool,
    pub require_release_policy_root_match: bool,
    pub max_deploy_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        let wave83_go_no_go_binding_root = fixture_root("wave83-go-no-go-binding-root");
        let release_policy_root = fixture_root("wave83-release-policy-root");
        let operator_dashboard_root = fixture_root("wave83-operator-dashboard-root");
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            guard_suite: GUARD_SUITE.to_string(),
            deployment_guard_id: stable_id("deployment-guard", "wave84-audit-security-guard"),
            wave83_go_no_go_binding_root,
            release_policy_root,
            operator_dashboard_root,
            required_lanes: GuardEvidenceLane::all(),
            deploy_window_start_height: DEFAULT_DEPLOY_WINDOW_START_HEIGHT,
            deploy_window_end_height: DEFAULT_DEPLOY_WINDOW_END_HEIGHT,
            max_go_no_go_age_blocks: DEFAULT_MAX_GO_NO_GO_AGE_BLOCKS,
            min_signoff_gates: DEFAULT_MIN_SIGNOFF_GATES,
            min_operator_approvals: DEFAULT_MIN_OPERATOR_APPROVALS,
            min_rollback_proofs: DEFAULT_MIN_ROLLBACK_PROOFS,
            min_abort_roots: DEFAULT_MIN_ABORT_ROOTS,
            max_active_holds: DEFAULT_MAX_ACTIVE_HOLDS,
            max_open_blockers: DEFAULT_MAX_OPEN_BLOCKERS,
            fail_closed: true,
            require_privacy_signoff: true,
            require_security_signoff: true,
            require_dashboard_root_match: true,
            require_release_policy_root_match: true,
            max_deploy_records: DEFAULT_MAX_DEPLOY_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("guard_suite", &self.guard_suite)?;
        ensure_non_empty("deployment_guard_id", &self.deployment_guard_id)?;
        ensure_non_empty(
            "wave83_go_no_go_binding_root",
            &self.wave83_go_no_go_binding_root,
        )?;
        ensure_non_empty("release_policy_root", &self.release_policy_root)?;
        ensure_non_empty("operator_dashboard_root", &self.operator_dashboard_root)?;
        ensure(self.schema_version > 0, "schema version must be non-zero")?;
        ensure(
            !self.required_lanes.is_empty(),
            "required deployment guard lanes must be non-empty",
        )?;
        ensure(
            self.deploy_window_start_height < self.deploy_window_end_height,
            "deploy window start must precede end",
        )?;
        ensure(
            self.max_go_no_go_age_blocks > 0,
            "go-no-go age window must be non-zero",
        )?;
        ensure(
            self.min_signoff_gates > 0,
            "signoff gate quorum must be non-zero",
        )?;
        ensure(
            self.min_operator_approvals > 0,
            "operator approval quorum must be non-zero",
        )?;
        ensure(
            self.min_rollback_proofs > 0,
            "rollback proof quorum must be non-zero",
        )?;
        ensure(
            self.min_abort_roots > 0,
            "abort root quorum must be non-zero",
        )?;
        ensure(
            self.max_deploy_records > 0,
            "deployment guard record capacity must be non-zero",
        )?;
        let mut seen = BTreeSet::new();
        for lane in &self.required_lanes {
            ensure(
                seen.insert(*lane),
                "duplicate required deployment guard lane",
            )?;
            ensure(
                lane.required_for_unhold(),
                "required lane must participate in unhold evidence",
            )?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "guard_suite": self.guard_suite,
            "deployment_guard_id": self.deployment_guard_id,
            "wave83_go_no_go_binding_root": self.wave83_go_no_go_binding_root,
            "release_policy_root": self.release_policy_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "required_lanes": self.required_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "deploy_window_start_height": self.deploy_window_start_height,
            "deploy_window_end_height": self.deploy_window_end_height,
            "max_go_no_go_age_blocks": self.max_go_no_go_age_blocks,
            "min_signoff_gates": self.min_signoff_gates,
            "min_operator_approvals": self.min_operator_approvals,
            "min_rollback_proofs": self.min_rollback_proofs,
            "min_abort_roots": self.min_abort_roots,
            "max_active_holds": self.max_active_holds,
            "max_open_blockers": self.max_open_blockers,
            "fail_closed": self.fail_closed,
            "require_privacy_signoff": self.require_privacy_signoff,
            "require_security_signoff": self.require_security_signoff,
            "require_dashboard_root_match": self.require_dashboard_root_match,
            "require_release_policy_root_match": self.require_release_policy_root_match,
            "max_deploy_records": self.max_deploy_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoNoGoBindingEvidence {
    pub binding_id: String,
    pub go_no_go_root: String,
    pub release_policy_root: String,
    pub operator_dashboard_root: String,
    pub lane_binding_root: String,
    pub coordinator_root: String,
    pub blocker_root: String,
    pub decision_root: String,
    pub observed_at_height: u64,
    pub release_allowed: bool,
    pub fail_closed_when_blocked: bool,
}

impl GoNoGoBindingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "go_no_go_root": self.go_no_go_root,
            "release_policy_root": self.release_policy_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "lane_binding_root": self.lane_binding_root,
            "coordinator_root": self.coordinator_root,
            "blocker_root": self.blocker_root,
            "decision_root": self.decision_root,
            "observed_at_height": self.observed_at_height,
            "release_allowed": self.release_allowed,
            "fail_closed_when_blocked": self.fail_closed_when_blocked,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-GO-NO-GO-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FindingClosureEvidence {
    pub finding_id: String,
    pub closure_root: String,
    pub mitigation_root: String,
    pub accepted_risk_root: String,
    pub owner_role: GateRole,
    pub severity: String,
    pub closed_at_height: u64,
    pub release_blocking: bool,
    pub open_after_guard: bool,
}

impl FindingClosureEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "closure_root": self.closure_root,
            "mitigation_root": self.mitigation_root,
            "accepted_risk_root": self.accepted_risk_root,
            "owner_role": self.owner_role.as_str(),
            "severity": self.severity,
            "closed_at_height": self.closed_at_height,
            "release_blocking": self.release_blocking,
            "open_after_guard": self.open_after_guard,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-FINDING-CLOSURE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyReviewEvidence {
    pub review_id: String,
    pub privacy_review_root: String,
    pub non_linkage_root: String,
    pub redaction_policy_root: String,
    pub reviewer_role: GateRole,
    pub disposition: GateDisposition,
    pub reviewed_at_height: u64,
    pub monero_address_material_exposed: bool,
    pub pq_key_material_exposed: bool,
}

impl PrivacyReviewEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "review_id": self.review_id,
            "privacy_review_root": self.privacy_review_root,
            "non_linkage_root": self.non_linkage_root,
            "redaction_policy_root": self.redaction_policy_root,
            "reviewer_role": self.reviewer_role.as_str(),
            "disposition": self.disposition.as_str(),
            "reviewed_at_height": self.reviewed_at_height,
            "monero_address_material_exposed": self.monero_address_material_exposed,
            "pq_key_material_exposed": self.pq_key_material_exposed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-PRIVACY-REVIEW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdversarialEvidencePlaceholder {
    pub placeholder_id: String,
    pub scenario: String,
    pub evidence_root: String,
    pub replay_root: String,
    pub regression_root: String,
    pub owner_role: GateRole,
    pub disposition: ProofStatus,
    pub observed_at_height: u64,
    pub active_regression: bool,
}

impl AdversarialEvidencePlaceholder {
    pub fn public_record(&self) -> Value {
        json!({
            "placeholder_id": self.placeholder_id,
            "scenario": self.scenario,
            "evidence_root": self.evidence_root,
            "replay_root": self.replay_root,
            "regression_root": self.regression_root,
            "owner_role": self.owner_role.as_str(),
            "disposition": self.disposition.as_str(),
            "observed_at_height": self.observed_at_height,
            "active_regression": self.active_regression,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "DEPLOYMENT-GUARD-ADVERSARIAL-EVIDENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeployWindowEvidence {
    pub window_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub freeze_root: String,
    pub calendar_root: String,
    pub operator_notice_root: String,
    pub incident_channel_root: String,
    pub release_policy_root: String,
    pub dashboard_root: String,
}

impl DeployWindowEvidence {
    pub fn contains_height(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "freeze_root": self.freeze_root,
            "calendar_root": self.calendar_root,
            "operator_notice_root": self.operator_notice_root,
            "incident_channel_root": self.incident_channel_root,
            "release_policy_root": self.release_policy_root,
            "dashboard_root": self.dashboard_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-DEPLOY-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackProof {
    pub proof_id: String,
    pub kind: RollbackProofKind,
    pub proof_root: String,
    pub previous_state_root: String,
    pub restore_command_root: String,
    pub operator_ack_root: String,
    pub owner_role: GateRole,
    pub status: ProofStatus,
    pub observed_at_height: u64,
    pub required_for_guard: bool,
}

impl RollbackProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "kind": self.kind.as_str(),
            "proof_root": self.proof_root,
            "previous_state_root": self.previous_state_root,
            "restore_command_root": self.restore_command_root,
            "operator_ack_root": self.operator_ack_root,
            "owner_role": self.owner_role.as_str(),
            "status": self.status.as_str(),
            "observed_at_height": self.observed_at_height,
            "required_for_guard": self.required_for_guard,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-ROLLBACK-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbortRoot {
    pub abort_id: String,
    pub kind: AbortRootKind,
    pub abort_root: String,
    pub command_root: String,
    pub evidence_preservation_root: String,
    pub owner_role: GateRole,
    pub armed: bool,
    pub observed_at_height: u64,
}

impl AbortRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "abort_id": self.abort_id,
            "kind": self.kind.as_str(),
            "abort_root": self.abort_root,
            "command_root": self.command_root,
            "evidence_preservation_root": self.evidence_preservation_root,
            "owner_role": self.owner_role.as_str(),
            "armed": self.armed,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-ABORT-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorApproval {
    pub approval_id: String,
    pub role: GateRole,
    pub dashboard_root: String,
    pub release_policy_root: String,
    pub deployment_guard_root: String,
    pub disposition: GateDisposition,
    pub signed_at_height: u64,
    pub required_for_unhold: bool,
}

impl OperatorApproval {
    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "role": self.role.as_str(),
            "dashboard_root": self.dashboard_root,
            "release_policy_root": self.release_policy_root,
            "deployment_guard_root": self.deployment_guard_root,
            "disposition": self.disposition.as_str(),
            "signed_at_height": self.signed_at_height,
            "required_for_unhold": self.required_for_unhold,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-OPERATOR-APPROVAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldDecisionRecord {
    pub hold_id: String,
    pub kind: HoldKind,
    pub status: HoldStatus,
    pub opened_at_height: u64,
    pub cleared_at_height: u64,
    pub evidence_root: String,
    pub unhold_criteria_root: String,
    pub owner_role: GateRole,
    pub fail_closed: bool,
}

impl HoldDecisionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "cleared_at_height": self.cleared_at_height,
            "evidence_root": self.evidence_root,
            "unhold_criteria_root": self.unhold_criteria_root,
            "owner_role": self.owner_role.as_str(),
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-HOLD-DECISION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionDeploymentState {
    pub mode: ProductionMode,
    pub fail_closed: bool,
    pub deployment_guard_root: String,
    pub current_release_manifest_root: String,
    pub candidate_release_manifest_root: String,
    pub abort_root: String,
    pub rollback_root: String,
    pub last_safe_state_root: String,
    pub observed_at_height: u64,
}

impl ProductionDeploymentState {
    pub fn public_record(&self) -> Value {
        json!({
            "mode": self.mode.as_str(),
            "fail_closed": self.fail_closed,
            "deployment_guard_root": self.deployment_guard_root,
            "current_release_manifest_root": self.current_release_manifest_root,
            "candidate_release_manifest_root": self.candidate_release_manifest_root,
            "abort_root": self.abort_root,
            "rollback_root": self.rollback_root,
            "last_safe_state_root": self.last_safe_state_root,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-PRODUCTION-STATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardCounters {
    pub go_no_go_bindings: u64,
    pub finding_closures: u64,
    pub open_release_blocking_findings: u64,
    pub privacy_reviews: u64,
    pub accepted_privacy_reviews: u64,
    pub adversarial_evidence_records: u64,
    pub active_adversarial_regressions: u64,
    pub deploy_windows: u64,
    pub active_deploy_windows: u64,
    pub rollback_proofs: u64,
    pub accepted_rollback_proofs: u64,
    pub abort_roots: u64,
    pub armed_abort_roots: u64,
    pub operator_approvals: u64,
    pub accepted_operator_approvals: u64,
    pub required_signoff_gates: u64,
    pub accepted_required_signoff_gates: u64,
    pub active_holds: u64,
    pub open_blockers: u64,
    pub fail_closed_blockers: u64,
}

impl GuardCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "go_no_go_bindings": self.go_no_go_bindings,
            "finding_closures": self.finding_closures,
            "open_release_blocking_findings": self.open_release_blocking_findings,
            "privacy_reviews": self.privacy_reviews,
            "accepted_privacy_reviews": self.accepted_privacy_reviews,
            "adversarial_evidence_records": self.adversarial_evidence_records,
            "active_adversarial_regressions": self.active_adversarial_regressions,
            "deploy_windows": self.deploy_windows,
            "active_deploy_windows": self.active_deploy_windows,
            "rollback_proofs": self.rollback_proofs,
            "accepted_rollback_proofs": self.accepted_rollback_proofs,
            "abort_roots": self.abort_roots,
            "armed_abort_roots": self.armed_abort_roots,
            "operator_approvals": self.operator_approvals,
            "accepted_operator_approvals": self.accepted_operator_approvals,
            "required_signoff_gates": self.required_signoff_gates,
            "accepted_required_signoff_gates": self.accepted_required_signoff_gates,
            "active_holds": self.active_holds,
            "open_blockers": self.open_blockers,
            "fail_closed_blockers": self.fail_closed_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentGuardVerdict {
    pub decision: GuardDecision,
    pub fail_closed: bool,
    pub can_deploy: bool,
    pub hold_root: String,
    pub unhold_criteria_root: String,
    pub blocker_root: String,
    pub rollback_root: String,
    pub abort_root: String,
    pub signoff_root: String,
    pub production_state_root: String,
    pub counter_root: String,
    pub verdict_root: String,
    pub reasons: Vec<String>,
}

impl DeploymentGuardVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "fail_closed": self.fail_closed,
            "can_deploy": self.can_deploy,
            "hold_root": self.hold_root,
            "unhold_criteria_root": self.unhold_criteria_root,
            "blocker_root": self.blocker_root,
            "rollback_root": self.rollback_root,
            "abort_root": self.abort_root,
            "signoff_root": self.signoff_root,
            "production_state_root": self.production_state_root,
            "counter_root": self.counter_root,
            "verdict_root": self.verdict_root,
            "reasons": self.reasons,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub go_no_go_binding: GoNoGoBindingEvidence,
    pub finding_closures: BTreeMap<String, FindingClosureEvidence>,
    pub privacy_reviews: BTreeMap<String, PrivacyReviewEvidence>,
    pub adversarial_evidence: BTreeMap<String, AdversarialEvidencePlaceholder>,
    pub deploy_windows: BTreeMap<String, DeployWindowEvidence>,
    pub rollback_proofs: BTreeMap<String, RollbackProof>,
    pub abort_roots: BTreeMap<String, AbortRoot>,
    pub operator_approvals: BTreeMap<String, OperatorApproval>,
    pub hold_decisions: BTreeMap<String, HoldDecisionRecord>,
    pub production_state: ProductionDeploymentState,
    pub counters: GuardCounters,
    pub blockers: BTreeMap<String, Vec<GuardBlockerKind>>,
    pub verdict: DeploymentGuardVerdict,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        go_no_go_binding: GoNoGoBindingEvidence,
        production_state: ProductionDeploymentState,
    ) -> Result<Self> {
        config.validate()?;
        ensure(
            go_no_go_binding.go_no_go_root == config.wave83_go_no_go_binding_root,
            "go-no-go binding root must match config",
        )?;
        ensure(
            go_no_go_binding.release_policy_root == config.release_policy_root,
            "release policy root must match config",
        )?;
        ensure(
            go_no_go_binding.operator_dashboard_root == config.operator_dashboard_root,
            "operator dashboard root must match config",
        )?;
        Ok(Self {
            config,
            height,
            go_no_go_binding,
            finding_closures: BTreeMap::new(),
            privacy_reviews: BTreeMap::new(),
            adversarial_evidence: BTreeMap::new(),
            deploy_windows: BTreeMap::new(),
            rollback_proofs: BTreeMap::new(),
            abort_roots: BTreeMap::new(),
            operator_approvals: BTreeMap::new(),
            hold_decisions: BTreeMap::new(),
            production_state,
            counters: empty_counters(),
            blockers: BTreeMap::new(),
            verdict: empty_verdict(),
        })
    }

    pub fn devnet() -> Self {
        build_devnet().unwrap_or_else_state()
    }

    pub fn add_finding_closure(&mut self, record: FindingClosureEvidence) -> Result<()> {
        ensure_capacity(self.finding_closures.len(), self.config.max_deploy_records)?;
        ensure_non_empty("finding_id", &record.finding_id)?;
        ensure_non_empty("closure_root", &record.closure_root)?;
        ensure_non_empty("mitigation_root", &record.mitigation_root)?;
        self.finding_closures
            .insert(record.finding_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_privacy_review(&mut self, record: PrivacyReviewEvidence) -> Result<()> {
        ensure_capacity(self.privacy_reviews.len(), self.config.max_deploy_records)?;
        ensure_non_empty("review_id", &record.review_id)?;
        ensure_non_empty("privacy_review_root", &record.privacy_review_root)?;
        ensure_non_empty("non_linkage_root", &record.non_linkage_root)?;
        self.privacy_reviews
            .insert(record.review_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_adversarial_evidence(
        &mut self,
        record: AdversarialEvidencePlaceholder,
    ) -> Result<()> {
        ensure_capacity(
            self.adversarial_evidence.len(),
            self.config.max_deploy_records,
        )?;
        ensure_non_empty("placeholder_id", &record.placeholder_id)?;
        ensure_non_empty("evidence_root", &record.evidence_root)?;
        self.adversarial_evidence
            .insert(record.placeholder_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_deploy_window(&mut self, record: DeployWindowEvidence) -> Result<()> {
        ensure_capacity(self.deploy_windows.len(), self.config.max_deploy_records)?;
        ensure_non_empty("window_id", &record.window_id)?;
        ensure(
            record.start_height < record.end_height,
            "deploy window start must precede end",
        )?;
        self.deploy_windows.insert(record.window_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_rollback_proof(&mut self, record: RollbackProof) -> Result<()> {
        ensure_capacity(self.rollback_proofs.len(), self.config.max_deploy_records)?;
        ensure_non_empty("proof_id", &record.proof_id)?;
        ensure_non_empty("proof_root", &record.proof_root)?;
        self.rollback_proofs.insert(record.proof_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_abort_root(&mut self, record: AbortRoot) -> Result<()> {
        ensure_capacity(self.abort_roots.len(), self.config.max_deploy_records)?;
        ensure_non_empty("abort_id", &record.abort_id)?;
        ensure_non_empty("abort_root", &record.abort_root)?;
        self.abort_roots.insert(record.abort_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_operator_approval(&mut self, record: OperatorApproval) -> Result<()> {
        ensure_capacity(
            self.operator_approvals.len(),
            self.config.max_deploy_records,
        )?;
        ensure_non_empty("approval_id", &record.approval_id)?;
        ensure_non_empty("dashboard_root", &record.dashboard_root)?;
        ensure_non_empty("release_policy_root", &record.release_policy_root)?;
        self.operator_approvals
            .insert(record.approval_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn add_hold_decision(&mut self, record: HoldDecisionRecord) -> Result<()> {
        ensure_capacity(self.hold_decisions.len(), self.config.max_deploy_records)?;
        ensure_non_empty("hold_id", &record.hold_id)?;
        ensure_non_empty("evidence_root", &record.evidence_root)?;
        self.hold_decisions.insert(record.hold_id.clone(), record);
        self.refresh();
        Ok(())
    }

    pub fn finding_closure_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-FINDING-CLOSURES",
            self.finding_closures
                .values()
                .map(FindingClosureEvidence::state_root),
        )
    }

    pub fn privacy_review_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-PRIVACY-REVIEWS",
            self.privacy_reviews
                .values()
                .map(PrivacyReviewEvidence::state_root),
        )
    }

    pub fn adversarial_evidence_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-ADVERSARIAL-EVIDENCE",
            self.adversarial_evidence
                .values()
                .map(AdversarialEvidencePlaceholder::state_root),
        )
    }

    pub fn deploy_window_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-DEPLOY-WINDOWS",
            self.deploy_windows
                .values()
                .map(DeployWindowEvidence::state_root),
        )
    }

    pub fn rollback_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-ROLLBACK-PROOFS",
            self.rollback_proofs.values().map(RollbackProof::state_root),
        )
    }

    pub fn abort_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-ABORT-ROOTS",
            self.abort_roots.values().map(AbortRoot::state_root),
        )
    }

    pub fn operator_approval_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-OPERATOR-APPROVALS",
            self.operator_approvals
                .values()
                .map(OperatorApproval::state_root),
        )
    }

    pub fn hold_root(&self) -> String {
        map_root(
            "DEPLOYMENT-GUARD-HOLD-DECISIONS",
            self.hold_decisions
                .values()
                .map(HoldDecisionRecord::state_root),
        )
    }

    pub fn unhold_criteria_root(&self) -> String {
        let criteria = json!({
            "wave83_go_no_go_root": self.go_no_go_binding.go_no_go_root,
            "finding_closure_root": self.finding_closure_root(),
            "privacy_review_root": self.privacy_review_root(),
            "adversarial_evidence_root": self.adversarial_evidence_root(),
            "deploy_window_root": self.deploy_window_root(),
            "rollback_root": self.rollback_root(),
            "abort_root": self.abort_root(),
            "operator_approval_root": self.operator_approval_root(),
            "production_state_root": self.production_state.state_root(),
            "min_signoff_gates": self.config.min_signoff_gates,
            "min_operator_approvals": self.config.min_operator_approvals,
            "min_rollback_proofs": self.config.min_rollback_proofs,
            "min_abort_roots": self.config.min_abort_roots,
            "fail_closed": self.config.fail_closed,
        });
        record_root("DEPLOYMENT-GUARD-UNHOLD-CRITERIA", &criteria)
    }

    pub fn blocker_root(&self) -> String {
        let leaves = self
            .blockers
            .iter()
            .map(|(subject, blockers)| {
                json!({
                    "subject": subject,
                    "blockers": blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        merkle_root("DEPLOYMENT-GUARD-BLOCKERS", &leaves)
    }

    pub fn refresh(&mut self) {
        self.counters = self.compute_counters();
        self.blockers = self.evaluate_blockers();
        self.verdict = self.compute_verdict();
    }

    pub fn compute_counters(&self) -> GuardCounters {
        let go_no_go_bindings = 1;
        let finding_closures = self.finding_closures.len() as u64;
        let open_release_blocking_findings = self
            .finding_closures
            .values()
            .filter(|finding| finding.release_blocking && finding.open_after_guard)
            .count() as u64;
        let privacy_reviews = self.privacy_reviews.len() as u64;
        let accepted_privacy_reviews = self
            .privacy_reviews
            .values()
            .filter(|review| review.disposition.passes())
            .count() as u64;
        let adversarial_evidence_records = self.adversarial_evidence.len() as u64;
        let active_adversarial_regressions = self
            .adversarial_evidence
            .values()
            .filter(|evidence| evidence.active_regression)
            .count() as u64;
        let deploy_windows = self.deploy_windows.len() as u64;
        let active_deploy_windows = self
            .deploy_windows
            .values()
            .filter(|window| window.contains_height(self.height))
            .count() as u64;
        let rollback_proofs = self.rollback_proofs.len() as u64;
        let accepted_rollback_proofs = self
            .rollback_proofs
            .values()
            .filter(|proof| proof.required_for_guard && proof.status.accepted())
            .count() as u64;
        let abort_roots = self.abort_roots.len() as u64;
        let armed_abort_roots = self.abort_roots.values().filter(|root| root.armed).count() as u64;
        let operator_approvals = self.operator_approvals.len() as u64;
        let accepted_operator_approvals = self
            .operator_approvals
            .values()
            .filter(|approval| approval.disposition.passes())
            .count() as u64;
        let required_signoff_gates = self
            .operator_approvals
            .values()
            .filter(|approval| approval.required_for_unhold)
            .count() as u64;
        let accepted_required_signoff_gates = self
            .operator_approvals
            .values()
            .filter(|approval| approval.required_for_unhold && approval.disposition.passes())
            .count() as u64;
        let active_holds = self
            .hold_decisions
            .values()
            .filter(|hold| hold.status.active())
            .count() as u64;
        let open_blockers = self.blockers.values().map(Vec::len).sum::<usize>() as u64;
        let fail_closed_blockers = self
            .blockers
            .values()
            .flat_map(|blockers| blockers.iter())
            .filter(|blocker| blocker.fail_closed())
            .count() as u64;
        GuardCounters {
            go_no_go_bindings,
            finding_closures,
            open_release_blocking_findings,
            privacy_reviews,
            accepted_privacy_reviews,
            adversarial_evidence_records,
            active_adversarial_regressions,
            deploy_windows,
            active_deploy_windows,
            rollback_proofs,
            accepted_rollback_proofs,
            abort_roots,
            armed_abort_roots,
            operator_approvals,
            accepted_operator_approvals,
            required_signoff_gates,
            accepted_required_signoff_gates,
            active_holds,
            open_blockers,
            fail_closed_blockers,
        }
    }

    pub fn evaluate_blockers(&self) -> BTreeMap<String, Vec<GuardBlockerKind>> {
        let mut blockers = BTreeMap::<String, Vec<GuardBlockerKind>>::new();
        if self.go_no_go_binding.go_no_go_root.is_empty() {
            push_blocker(
                &mut blockers,
                "wave83_go_no_go",
                GuardBlockerKind::MissingWave83GoNoGoRoot,
            );
        }
        if !self.go_no_go_binding.release_allowed {
            push_blocker(
                &mut blockers,
                "wave83_go_no_go",
                GuardBlockerKind::Wave83NoGo,
            );
        }
        if self
            .height
            .saturating_sub(self.go_no_go_binding.observed_at_height)
            > self.config.max_go_no_go_age_blocks
        {
            push_blocker(
                &mut blockers,
                "wave83_go_no_go",
                GuardBlockerKind::StaleGoNoGoRoot,
            );
        }
        if self.config.require_release_policy_root_match
            && self.go_no_go_binding.release_policy_root != self.config.release_policy_root
        {
            push_blocker(
                &mut blockers,
                "release_policy",
                GuardBlockerKind::ReleasePolicyRootMismatch,
            );
        }
        if self.config.require_dashboard_root_match
            && self.go_no_go_binding.operator_dashboard_root != self.config.operator_dashboard_root
        {
            push_blocker(
                &mut blockers,
                "operator_dashboard",
                GuardBlockerKind::DashboardRootMismatch,
            );
        }
        if self.finding_closures.is_empty() {
            push_blocker(
                &mut blockers,
                "finding_closure",
                GuardBlockerKind::MissingFindingClosureRoot,
            );
        }
        for finding in self.finding_closures.values() {
            if finding.closure_root.is_empty() {
                push_blocker(
                    &mut blockers,
                    &finding.finding_id,
                    GuardBlockerKind::MissingAuditClosureRoot,
                );
            }
            if finding.release_blocking && finding.open_after_guard {
                push_blocker(
                    &mut blockers,
                    &finding.finding_id,
                    GuardBlockerKind::OpenSecurityFinding,
                );
            }
        }
        if self.privacy_reviews.is_empty() {
            push_blocker(
                &mut blockers,
                "privacy_review",
                GuardBlockerKind::MissingPrivacyReviewRoot,
            );
        }
        for review in self.privacy_reviews.values() {
            if review.privacy_review_root.is_empty() {
                push_blocker(
                    &mut blockers,
                    &review.review_id,
                    GuardBlockerKind::MissingPrivacyReviewRoot,
                );
            }
            if self.config.require_privacy_signoff && !review.disposition.passes() {
                push_blocker(
                    &mut blockers,
                    &review.review_id,
                    GuardBlockerKind::PrivacySignoffRejected,
                );
            }
        }
        if self.adversarial_evidence.is_empty() {
            push_blocker(
                &mut blockers,
                "adversarial_evidence",
                GuardBlockerKind::MissingAdversarialEvidenceRoot,
            );
        }
        for evidence in self.adversarial_evidence.values() {
            if evidence.evidence_root.is_empty() {
                push_blocker(
                    &mut blockers,
                    &evidence.placeholder_id,
                    GuardBlockerKind::MissingAdversarialEvidenceRoot,
                );
            }
            if evidence.active_regression {
                push_blocker(
                    &mut blockers,
                    &evidence.placeholder_id,
                    GuardBlockerKind::ActiveAdversarialRegression,
                );
            }
        }
        let active_window_count = self
            .deploy_windows
            .values()
            .filter(|window| window.contains_height(self.height))
            .count();
        if active_window_count == 0 {
            if self.height < self.config.deploy_window_start_height {
                push_blocker(
                    &mut blockers,
                    "deploy_window",
                    GuardBlockerKind::DeployWindowNotOpen,
                );
            } else {
                push_blocker(
                    &mut blockers,
                    "deploy_window",
                    GuardBlockerKind::DeployWindowClosed,
                );
            }
        }
        if (self
            .rollback_proofs
            .values()
            .filter(|proof| proof.required_for_guard && proof.status.accepted())
            .count() as u64)
            < self.config.min_rollback_proofs
        {
            push_blocker(
                &mut blockers,
                "rollback_proof",
                GuardBlockerKind::MissingRollbackProof,
            );
        }
        for proof in self.rollback_proofs.values() {
            if proof.required_for_guard && !proof.status.accepted() {
                push_blocker(
                    &mut blockers,
                    &proof.proof_id,
                    GuardBlockerKind::RollbackProofRejected,
                );
            }
        }
        if (self.abort_roots.values().filter(|root| root.armed).count() as u64)
            < self.config.min_abort_roots
        {
            push_blocker(
                &mut blockers,
                "abort_root",
                GuardBlockerKind::MissingAbortRoot,
            );
        }
        if (self
            .operator_approvals
            .values()
            .filter(|approval| approval.disposition.passes())
            .count() as u64)
            < self.config.min_operator_approvals
        {
            push_blocker(
                &mut blockers,
                "operator_approval",
                GuardBlockerKind::MissingOperatorApproval,
            );
        }
        for approval in self.operator_approvals.values() {
            if approval.required_for_unhold && !approval.disposition.passes() {
                push_blocker(
                    &mut blockers,
                    &approval.approval_id,
                    GuardBlockerKind::OperatorApprovalRejected,
                );
            }
        }
        for hold in self.hold_decisions.values() {
            if hold.status.active() {
                let blocker = match hold.kind {
                    HoldKind::Security => GuardBlockerKind::ManualSecurityHold,
                    HoldKind::Privacy => GuardBlockerKind::ManualPrivacyHold,
                    HoldKind::ReleasePolicy
                    | HoldKind::OperatorDashboard
                    | HoldKind::IncidentResponse => GuardBlockerKind::Wave83NoGo,
                };
                push_blocker(&mut blockers, &hold.hold_id, blocker);
            }
        }
        if self.config.fail_closed && !self.production_state.fail_closed {
            push_blocker(
                &mut blockers,
                "production_state",
                GuardBlockerKind::ProductionStateNotFailClosed,
            );
        }
        blockers
    }

    pub fn compute_verdict(&self) -> DeploymentGuardVerdict {
        let blockers = self.evaluate_blockers();
        let blocker_count = blockers.values().map(Vec::len).sum::<usize>() as u64;
        let fail_closed_blocker_count = blockers
            .values()
            .flat_map(|items| items.iter())
            .filter(|blocker| blocker.fail_closed())
            .count() as u64;
        let counter_root = self.compute_counters().state_root();
        let blocker_root = {
            let leaves = blockers
                .iter()
                .map(|(subject, items)| {
                    json!({
                        "subject": subject,
                        "blockers": items.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();
            merkle_root("DEPLOYMENT-GUARD-VERDICT-BLOCKERS", &leaves)
        };
        let hold_root = self.hold_root();
        let unhold_criteria_root = self.unhold_criteria_root();
        let rollback_root = self.rollback_root();
        let abort_root = self.abort_root();
        let signoff_root = self.operator_approval_root();
        let production_state_root = self.production_state.state_root();
        let can_deploy = blocker_count <= self.config.max_open_blockers
            && self.counters.active_holds <= self.config.max_active_holds
            && self.counters.accepted_required_signoff_gates >= self.config.min_signoff_gates
            && self.counters.accepted_operator_approvals >= self.config.min_operator_approvals
            && self.counters.accepted_rollback_proofs >= self.config.min_rollback_proofs
            && self.counters.armed_abort_roots >= self.config.min_abort_roots
            && self.go_no_go_binding.release_allowed
            && self.production_state.fail_closed;
        let decision = if can_deploy {
            GuardDecision::Unhold
        } else if fail_closed_blocker_count > 0 {
            GuardDecision::Hold
        } else {
            GuardDecision::Abort
        };
        let fail_closed = self.config.fail_closed && !decision.permits_deploy();
        let reasons = verdict_reasons(
            can_deploy,
            blocker_count,
            fail_closed_blocker_count,
            self.counters.active_holds,
        );
        let verdict_record = json!({
            "decision": decision.as_str(),
            "can_deploy": can_deploy,
            "fail_closed": fail_closed,
            "blocker_count": blocker_count,
            "fail_closed_blocker_count": fail_closed_blocker_count,
            "hold_root": hold_root,
            "unhold_criteria_root": unhold_criteria_root,
            "rollback_root": rollback_root,
            "abort_root": abort_root,
            "signoff_root": signoff_root,
            "production_state_root": production_state_root,
            "counter_root": counter_root,
            "reasons": reasons,
        });
        let verdict_root = record_root("DEPLOYMENT-GUARD-VERDICT", &verdict_record);
        DeploymentGuardVerdict {
            decision,
            fail_closed,
            can_deploy,
            hold_root,
            unhold_criteria_root,
            blocker_root,
            rollback_root,
            abort_root,
            signoff_root,
            production_state_root,
            counter_root,
            verdict_root,
            reasons,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "go_no_go_binding": self.go_no_go_binding.public_record(),
            "finding_closure_root": self.finding_closure_root(),
            "privacy_review_root": self.privacy_review_root(),
            "adversarial_evidence_root": self.adversarial_evidence_root(),
            "deploy_window_root": self.deploy_window_root(),
            "rollback_root": self.rollback_root(),
            "abort_root": self.abort_root(),
            "operator_approval_root": self.operator_approval_root(),
            "hold_root": self.hold_root(),
            "unhold_criteria_root": self.unhold_criteria_root(),
            "production_state": self.production_state.public_record(),
            "counters": self.counters.public_record(),
            "blocker_root": self.blocker_root(),
            "verdict": self.verdict.public_record(),
            "finding_closures": self.finding_closures.values().map(FindingClosureEvidence::public_record).collect::<Vec<_>>(),
            "privacy_reviews": self.privacy_reviews.values().map(PrivacyReviewEvidence::public_record).collect::<Vec<_>>(),
            "adversarial_evidence": self.adversarial_evidence.values().map(AdversarialEvidencePlaceholder::public_record).collect::<Vec<_>>(),
            "deploy_windows": self.deploy_windows.values().map(DeployWindowEvidence::public_record).collect::<Vec<_>>(),
            "rollback_proofs": self.rollback_proofs.values().map(RollbackProof::public_record).collect::<Vec<_>>(),
            "abort_roots": self.abort_roots.values().map(AbortRoot::public_record).collect::<Vec<_>>(),
            "operator_approvals": self.operator_approvals.values().map(OperatorApproval::public_record).collect::<Vec<_>>(),
            "hold_decisions": self.hold_decisions.values().map(HoldDecisionRecord::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(|(subject, blockers)| {
                json!({
                    "subject": subject,
                    "blockers": blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "DEPLOYMENT-GUARD-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.deployment_guard_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.go_no_go_binding.state_root()),
                HashPart::Str(&self.finding_closure_root()),
                HashPart::Str(&self.privacy_review_root()),
                HashPart::Str(&self.adversarial_evidence_root()),
                HashPart::Str(&self.deploy_window_root()),
                HashPart::Str(&self.rollback_root()),
                HashPart::Str(&self.abort_root()),
                HashPart::Str(&self.operator_approval_root()),
                HashPart::Str(&self.hold_root()),
                HashPart::Str(&self.production_state.state_root()),
                HashPart::Str(&self.verdict.verdict_root),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
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
            Err(error) => fallback_state(&error),
        }
    }
}

fn build_devnet() -> Result<State> {
    let config = Config::devnet();
    let go_no_go_binding = build_go_no_go_binding(&config);
    let production_state = build_production_state(&config, "initial");
    let mut state = State::new(
        config,
        DEFAULT_DEPLOY_WINDOW_START_HEIGHT,
        go_no_go_binding,
        production_state,
    )?;
    for (index, severity, role, release_blocking) in finding_closure_plan() {
        state.add_finding_closure(build_finding_closure(
            index,
            severity,
            role,
            release_blocking,
        ))?;
    }
    for (index, role) in privacy_review_plan() {
        state.add_privacy_review(build_privacy_review(index, role))?;
    }
    for (index, scenario, role) in adversarial_evidence_plan() {
        state.add_adversarial_evidence(build_adversarial_evidence(index, scenario, role))?;
    }
    state.add_deploy_window(build_deploy_window(&state.config))?;
    for (index, kind, role) in rollback_proof_plan() {
        state.add_rollback_proof(build_rollback_proof(index, kind, role))?;
    }
    for (index, kind, role) in abort_root_plan() {
        state.add_abort_root(build_abort_root(index, kind, role))?;
    }
    let guard_root = state.unhold_criteria_root();
    for (index, role) in operator_approval_plan() {
        state.add_operator_approval(build_operator_approval(
            index,
            role,
            &state.config,
            &guard_root,
        ))?;
    }
    for (index, kind, status, role) in hold_decision_plan() {
        state.add_hold_decision(build_hold_decision(index, kind, status, role))?;
    }
    state.production_state = build_production_state(&state.config, &state.unhold_criteria_root());
    state.refresh();
    Ok(state)
}

fn fallback_state(error: &str) -> State {
    let config = Config::devnet();
    let go_no_go_binding = GoNoGoBindingEvidence {
        binding_id: stable_id("fallback-go-no-go", error),
        go_no_go_root: config.wave83_go_no_go_binding_root.clone(),
        release_policy_root: config.release_policy_root.clone(),
        operator_dashboard_root: config.operator_dashboard_root.clone(),
        lane_binding_root: empty_root("fallback-lane-binding"),
        coordinator_root: empty_root("fallback-coordinator"),
        blocker_root: empty_root("fallback-blocker"),
        decision_root: fixture_root("fallback-decision-root"),
        observed_at_height: DEFAULT_HEIGHT,
        release_allowed: false,
        fail_closed_when_blocked: true,
    };
    let production_state = ProductionDeploymentState {
        mode: ProductionMode::FailClosedHeld,
        fail_closed: true,
        deployment_guard_root: fixture_root("fallback-deployment-guard"),
        current_release_manifest_root: fixture_root("fallback-current-release"),
        candidate_release_manifest_root: fixture_root("fallback-candidate-release"),
        abort_root: empty_root("fallback-abort-root"),
        rollback_root: empty_root("fallback-rollback-root"),
        last_safe_state_root: fixture_root("fallback-last-safe-state"),
        observed_at_height: DEFAULT_HEIGHT,
    };
    let mut blockers = BTreeMap::new();
    blockers.insert(
        "fallback".to_string(),
        vec![
            GuardBlockerKind::Wave83NoGo,
            GuardBlockerKind::ManualSecurityHold,
        ],
    );
    let counters = GuardCounters {
        go_no_go_bindings: 1,
        finding_closures: 0,
        open_release_blocking_findings: 1,
        privacy_reviews: 0,
        accepted_privacy_reviews: 0,
        adversarial_evidence_records: 0,
        active_adversarial_regressions: 1,
        deploy_windows: 0,
        active_deploy_windows: 0,
        rollback_proofs: 0,
        accepted_rollback_proofs: 0,
        abort_roots: 0,
        armed_abort_roots: 0,
        operator_approvals: 0,
        accepted_operator_approvals: 0,
        required_signoff_gates: 0,
        accepted_required_signoff_gates: 0,
        active_holds: 1,
        open_blockers: 2,
        fail_closed_blockers: 2,
    };
    let counter_root = counters.state_root();
    let blocker_root = merkle_root(
        "DEPLOYMENT-GUARD-FALLBACK-BLOCKERS",
        &[json!({
            "subject": "fallback",
            "blockers": ["wave83_no_go", "manual_security_hold"],
        })],
    );
    let verdict_root = domain_hash(
        "DEPLOYMENT-GUARD-FALLBACK-VERDICT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(error),
            HashPart::Str(&counter_root),
            HashPart::Str(&blocker_root),
        ],
        32,
    );
    let verdict = DeploymentGuardVerdict {
        decision: GuardDecision::Hold,
        fail_closed: true,
        can_deploy: false,
        hold_root: empty_root("fallback-hold"),
        unhold_criteria_root: empty_root("fallback-unhold-criteria"),
        blocker_root,
        rollback_root: empty_root("fallback-rollback"),
        abort_root: empty_root("fallback-abort"),
        signoff_root: empty_root("fallback-signoff"),
        production_state_root: production_state.state_root(),
        counter_root,
        verdict_root,
        reasons: vec![
            "devnet_construction_failed_fail_closed".to_string(),
            error.to_string(),
        ],
    };
    State {
        config,
        height: DEFAULT_HEIGHT,
        go_no_go_binding,
        finding_closures: BTreeMap::new(),
        privacy_reviews: BTreeMap::new(),
        adversarial_evidence: BTreeMap::new(),
        deploy_windows: BTreeMap::new(),
        rollback_proofs: BTreeMap::new(),
        abort_roots: BTreeMap::new(),
        operator_approvals: BTreeMap::new(),
        hold_decisions: BTreeMap::new(),
        production_state,
        counters,
        blockers,
        verdict,
    }
}

fn build_go_no_go_binding(config: &Config) -> GoNoGoBindingEvidence {
    GoNoGoBindingEvidence {
        binding_id: stable_id(
            "wave83-go-no-go-binding",
            "accepted-dashboard-release-policy",
        ),
        go_no_go_root: config.wave83_go_no_go_binding_root.clone(),
        release_policy_root: config.release_policy_root.clone(),
        operator_dashboard_root: config.operator_dashboard_root.clone(),
        lane_binding_root: fixture_root("wave83-lane-binding-root"),
        coordinator_root: fixture_root("wave83-coordinator-approval-root"),
        blocker_root: empty_root("wave83-cleared-blocker-root"),
        decision_root: fixture_root("wave83-go-decision-root"),
        observed_at_height: DEFAULT_HEIGHT,
        release_allowed: true,
        fail_closed_when_blocked: true,
    }
}

fn build_production_state(
    config: &Config,
    deployment_guard_seed: &str,
) -> ProductionDeploymentState {
    ProductionDeploymentState {
        mode: ProductionMode::FailClosedHeld,
        fail_closed: true,
        deployment_guard_root: domain_hash(
            "DEPLOYMENT-GUARD-PRODUCTION-GUARD-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.deployment_guard_id),
                HashPart::Str(deployment_guard_seed),
            ],
            32,
        ),
        current_release_manifest_root: fixture_root("production-current-release-manifest"),
        candidate_release_manifest_root: fixture_root("production-candidate-release-manifest"),
        abort_root: fixture_root("production-armed-abort-root"),
        rollback_root: fixture_root("production-accepted-rollback-root"),
        last_safe_state_root: fixture_root("production-last-safe-state-root"),
        observed_at_height: DEFAULT_DEPLOY_WINDOW_START_HEIGHT,
    }
}

fn finding_closure_plan() -> Vec<(u64, &'static str, GateRole, bool)> {
    vec![
        (0, "medium", GateRole::SecurityLead, true),
        (1, "high", GateRole::SecurityLead, true),
        (2, "medium", GateRole::RuntimeMaintainer, true),
        (3, "high", GateRole::PrivacyLead, true),
        (4, "low", GateRole::OperatorDashboardOwner, false),
        (5, "medium", GateRole::AuditArchiveCustodian, true),
        (6, "low", GateRole::ReleaseCaptain, false),
        (7, "medium", GateRole::IncidentCommander, true),
    ]
}

fn privacy_review_plan() -> Vec<(u64, GateRole)> {
    vec![
        (0, GateRole::PrivacyLead),
        (1, GateRole::SecurityLead),
        (2, GateRole::AuditArchiveCustodian),
    ]
}

fn adversarial_evidence_plan() -> Vec<(u64, &'static str, GateRole)> {
    vec![
        (0, "dashboard_root_substitution", GateRole::SecurityLead),
        (1, "rollback_manifest_replay", GateRole::RollbackOwner),
        (2, "privacy_non_linkage_probe", GateRole::PrivacyLead),
        (
            3,
            "operator_approval_replay",
            GateRole::OperatorDashboardOwner,
        ),
        (4, "abort_command_integrity", GateRole::IncidentCommander),
    ]
}

fn rollback_proof_plan() -> Vec<(u64, RollbackProofKind, GateRole)> {
    vec![
        (0, RollbackProofKind::StateSnapshot, GateRole::RollbackOwner),
        (
            1,
            RollbackProofKind::ReleaseManifest,
            GateRole::ReleaseCaptain,
        ),
        (
            2,
            RollbackProofKind::BinaryAttestation,
            GateRole::RuntimeMaintainer,
        ),
        (
            3,
            RollbackProofKind::DatabaseMigrationReversal,
            GateRole::RollbackOwner,
        ),
        (
            4,
            RollbackProofKind::WatchtowerReplay,
            GateRole::SecurityLead,
        ),
        (
            5,
            RollbackProofKind::IncidentDrill,
            GateRole::IncidentCommander,
        ),
    ]
}

fn abort_root_plan() -> Vec<(u64, AbortRootKind, GateRole)> {
    vec![
        (0, AbortRootKind::StopSequencer, GateRole::IncidentCommander),
        (
            1,
            AbortRootKind::FreezeReleaseManifest,
            GateRole::ReleaseCaptain,
        ),
        (
            2,
            AbortRootKind::RestorePreviousRuntime,
            GateRole::RollbackOwner,
        ),
        (
            3,
            AbortRootKind::NotifyOperators,
            GateRole::OperatorDashboardOwner,
        ),
        (
            4,
            AbortRootKind::PreserveEvidence,
            GateRole::AuditArchiveCustodian,
        ),
    ]
}

fn operator_approval_plan() -> Vec<(u64, GateRole)> {
    vec![
        (0, GateRole::ReleaseCaptain),
        (1, GateRole::SecurityLead),
        (2, GateRole::PrivacyLead),
        (3, GateRole::RuntimeMaintainer),
        (4, GateRole::OperatorDashboardOwner),
        (5, GateRole::IncidentCommander),
        (6, GateRole::RollbackOwner),
    ]
}

fn hold_decision_plan() -> Vec<(u64, HoldKind, HoldStatus, GateRole)> {
    vec![
        (
            0,
            HoldKind::Security,
            HoldStatus::Cleared,
            GateRole::SecurityLead,
        ),
        (
            1,
            HoldKind::Privacy,
            HoldStatus::Cleared,
            GateRole::PrivacyLead,
        ),
        (
            2,
            HoldKind::ReleasePolicy,
            HoldStatus::Superseded,
            GateRole::ReleaseCaptain,
        ),
        (
            3,
            HoldKind::OperatorDashboard,
            HoldStatus::Cleared,
            GateRole::OperatorDashboardOwner,
        ),
    ]
}

fn build_finding_closure(
    index: u64,
    severity: &str,
    role: GateRole,
    release_blocking: bool,
) -> FindingClosureEvidence {
    let closure_root = domain_hash(
        "DEPLOYMENT-GUARD-FINDING-CLOSURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(severity),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    let mitigation_root = domain_hash(
        "DEPLOYMENT-GUARD-FINDING-MITIGATION-ROOT",
        &[
            HashPart::Str(&closure_root),
            HashPart::Str(severity),
            HashPart::Str("release-blocker-closed-before-deploy-guard"),
        ],
        32,
    );
    let accepted_risk_root = domain_hash(
        "DEPLOYMENT-GUARD-FINDING-ACCEPTED-RISK-ROOT",
        &[
            HashPart::Str(&mitigation_root),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    FindingClosureEvidence {
        finding_id: domain_hash(
            "DEPLOYMENT-GUARD-FINDING-ID",
            &[
                HashPart::Str(severity),
                HashPart::Str(role.as_str()),
                HashPart::Str(&closure_root),
            ],
            16,
        ),
        closure_root,
        mitigation_root,
        accepted_risk_root,
        owner_role: role,
        severity: severity.to_string(),
        closed_at_height: DEFAULT_HEIGHT.saturating_sub(14).saturating_add(index),
        release_blocking,
        open_after_guard: false,
    }
}

fn build_privacy_review(index: u64, role: GateRole) -> PrivacyReviewEvidence {
    let privacy_review_root = domain_hash(
        "DEPLOYMENT-GUARD-PRIVACY-REVIEW-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    let non_linkage_root = domain_hash(
        "DEPLOYMENT-GUARD-PRIVACY-NON-LINKAGE-ROOT",
        &[HashPart::Str(&privacy_review_root), HashPart::U64(index)],
        32,
    );
    let redaction_policy_root = domain_hash(
        "DEPLOYMENT-GUARD-PRIVACY-REDACTION-POLICY-ROOT",
        &[
            HashPart::Str(&non_linkage_root),
            HashPart::Str("no-monero-address-or-pq-key-material-in-public-record"),
        ],
        32,
    );
    PrivacyReviewEvidence {
        review_id: domain_hash(
            "DEPLOYMENT-GUARD-PRIVACY-REVIEW-ID",
            &[
                HashPart::Str(role.as_str()),
                HashPart::Str(&privacy_review_root),
                HashPart::U64(index),
            ],
            16,
        ),
        privacy_review_root,
        non_linkage_root,
        redaction_policy_root,
        reviewer_role: role,
        disposition: GateDisposition::Accepted,
        reviewed_at_height: DEFAULT_HEIGHT.saturating_sub(8).saturating_add(index),
        monero_address_material_exposed: false,
        pq_key_material_exposed: false,
    }
}

fn build_adversarial_evidence(
    index: u64,
    scenario: &str,
    role: GateRole,
) -> AdversarialEvidencePlaceholder {
    let evidence_root = domain_hash(
        "DEPLOYMENT-GUARD-ADVERSARIAL-EVIDENCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(scenario),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    let replay_root = domain_hash(
        "DEPLOYMENT-GUARD-ADVERSARIAL-REPLAY-ROOT",
        &[HashPart::Str(&evidence_root), HashPart::Str(scenario)],
        32,
    );
    let regression_root = domain_hash(
        "DEPLOYMENT-GUARD-ADVERSARIAL-REGRESSION-ROOT",
        &[
            HashPart::Str(&replay_root),
            HashPart::Str("no-active-regression"),
            HashPart::U64(index),
        ],
        32,
    );
    AdversarialEvidencePlaceholder {
        placeholder_id: domain_hash(
            "DEPLOYMENT-GUARD-ADVERSARIAL-EVIDENCE-ID",
            &[HashPart::Str(scenario), HashPart::Str(&evidence_root)],
            16,
        ),
        scenario: scenario.to_string(),
        evidence_root,
        replay_root,
        regression_root,
        owner_role: role,
        disposition: ProofStatus::Accepted,
        observed_at_height: DEFAULT_HEIGHT.saturating_sub(6).saturating_add(index),
        active_regression: false,
    }
}

fn build_deploy_window(config: &Config) -> DeployWindowEvidence {
    DeployWindowEvidence {
        window_id: stable_id("deploy-window", "wave84-production-guard-window"),
        start_height: config.deploy_window_start_height,
        end_height: config.deploy_window_end_height,
        freeze_root: fixture_root("deploy-window-freeze-root"),
        calendar_root: fixture_root("deploy-window-calendar-root"),
        operator_notice_root: fixture_root("deploy-window-operator-notice-root"),
        incident_channel_root: fixture_root("deploy-window-incident-channel-root"),
        release_policy_root: config.release_policy_root.clone(),
        dashboard_root: config.operator_dashboard_root.clone(),
    }
}

fn build_rollback_proof(index: u64, kind: RollbackProofKind, role: GateRole) -> RollbackProof {
    let proof_root = domain_hash(
        "DEPLOYMENT-GUARD-ROLLBACK-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    RollbackProof {
        proof_id: domain_hash(
            "DEPLOYMENT-GUARD-ROLLBACK-PROOF-ID",
            &[HashPart::Str(kind.as_str()), HashPart::Str(&proof_root)],
            16,
        ),
        kind,
        proof_root: proof_root.clone(),
        previous_state_root: fixture_root(&format!("rollback-previous-state-{}", kind.as_str())),
        restore_command_root: fixture_root(&format!("rollback-restore-command-{}", kind.as_str())),
        operator_ack_root: fixture_root(&format!("rollback-operator-ack-{}", kind.as_str())),
        owner_role: role,
        status: ProofStatus::Accepted,
        observed_at_height: DEFAULT_HEIGHT.saturating_sub(4).saturating_add(index),
        required_for_guard: kind.required_for_guard(),
    }
}

fn build_abort_root(index: u64, kind: AbortRootKind, role: GateRole) -> AbortRoot {
    let abort_root = domain_hash(
        "DEPLOYMENT-GUARD-ABORT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    AbortRoot {
        abort_id: domain_hash(
            "DEPLOYMENT-GUARD-ABORT-ID",
            &[HashPart::Str(kind.as_str()), HashPart::Str(&abort_root)],
            16,
        ),
        kind,
        abort_root: abort_root.clone(),
        command_root: fixture_root(&format!("abort-command-{}", kind.as_str())),
        evidence_preservation_root: fixture_root(&format!("abort-evidence-{}", kind.as_str())),
        owner_role: role,
        armed: true,
        observed_at_height: DEFAULT_HEIGHT.saturating_sub(3).saturating_add(index),
    }
}

fn build_operator_approval(
    index: u64,
    role: GateRole,
    config: &Config,
    guard_root: &str,
) -> OperatorApproval {
    let approval_root = domain_hash(
        "DEPLOYMENT-GUARD-OPERATOR-APPROVAL-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(role.as_str()),
            HashPart::Str(&config.operator_dashboard_root),
            HashPart::Str(&config.release_policy_root),
            HashPart::Str(guard_root),
            HashPart::U64(index),
        ],
        32,
    );
    OperatorApproval {
        approval_id: domain_hash(
            "DEPLOYMENT-GUARD-OPERATOR-APPROVAL-ID",
            &[HashPart::Str(role.as_str()), HashPart::Str(&approval_root)],
            16,
        ),
        role,
        dashboard_root: config.operator_dashboard_root.clone(),
        release_policy_root: config.release_policy_root.clone(),
        deployment_guard_root: guard_root.to_string(),
        disposition: GateDisposition::Accepted,
        signed_at_height: DEFAULT_HEIGHT.saturating_sub(2).saturating_add(index),
        required_for_unhold: role.required_for_deploy(),
    }
}

fn build_hold_decision(
    index: u64,
    kind: HoldKind,
    status: HoldStatus,
    role: GateRole,
) -> HoldDecisionRecord {
    let evidence_root = domain_hash(
        "DEPLOYMENT-GUARD-HOLD-EVIDENCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(role.as_str()),
            HashPart::U64(index),
        ],
        32,
    );
    let unhold_criteria_root = domain_hash(
        "DEPLOYMENT-GUARD-HOLD-UNHOLD-CRITERIA-ROOT",
        &[
            HashPart::Str(&evidence_root),
            HashPart::Str("all-wave84-deployment-guard-criteria-satisfied"),
        ],
        32,
    );
    HoldDecisionRecord {
        hold_id: domain_hash(
            "DEPLOYMENT-GUARD-HOLD-ID",
            &[HashPart::Str(kind.as_str()), HashPart::Str(&evidence_root)],
            16,
        ),
        kind,
        status,
        opened_at_height: DEFAULT_HEIGHT.saturating_sub(24).saturating_add(index),
        cleared_at_height: DEFAULT_HEIGHT.saturating_sub(1).saturating_add(index),
        evidence_root,
        unhold_criteria_root,
        owner_role: role,
        fail_closed: true,
    }
}

fn verdict_reasons(
    can_deploy: bool,
    blocker_count: u64,
    fail_closed_blocker_count: u64,
    active_holds: u64,
) -> Vec<String> {
    if can_deploy {
        vec![
            "wave83_go_no_go_binding_accepted".to_string(),
            "security_and_privacy_signoff_gates_passed".to_string(),
            "rollback_and_abort_roots_armed".to_string(),
            "production_state_remains_fail_closed_until_execution".to_string(),
        ]
    } else {
        vec![
            "deployment_guard_fail_closed".to_string(),
            format!("open_blockers:{blocker_count}"),
            format!("fail_closed_blockers:{fail_closed_blocker_count}"),
            format!("active_holds:{active_holds}"),
        ]
    }
}

fn empty_counters() -> GuardCounters {
    GuardCounters {
        go_no_go_bindings: 0,
        finding_closures: 0,
        open_release_blocking_findings: 0,
        privacy_reviews: 0,
        accepted_privacy_reviews: 0,
        adversarial_evidence_records: 0,
        active_adversarial_regressions: 0,
        deploy_windows: 0,
        active_deploy_windows: 0,
        rollback_proofs: 0,
        accepted_rollback_proofs: 0,
        abort_roots: 0,
        armed_abort_roots: 0,
        operator_approvals: 0,
        accepted_operator_approvals: 0,
        required_signoff_gates: 0,
        accepted_required_signoff_gates: 0,
        active_holds: 0,
        open_blockers: 0,
        fail_closed_blockers: 0,
    }
}

fn empty_verdict() -> DeploymentGuardVerdict {
    DeploymentGuardVerdict {
        decision: GuardDecision::Hold,
        fail_closed: true,
        can_deploy: false,
        hold_root: empty_root("initial-hold"),
        unhold_criteria_root: empty_root("initial-unhold"),
        blocker_root: empty_root("initial-blocker"),
        rollback_root: empty_root("initial-rollback"),
        abort_root: empty_root("initial-abort"),
        signoff_root: empty_root("initial-signoff"),
        production_state_root: empty_root("initial-production-state"),
        counter_root: empty_root("initial-counter"),
        verdict_root: empty_root("initial-verdict"),
        reasons: vec!["initial_fail_closed_until_refreshed".to_string()],
    }
}

fn push_blocker(
    blockers: &mut BTreeMap<String, Vec<GuardBlockerKind>>,
    subject: &str,
    blocker: GuardBlockerKind,
) {
    blockers
        .entry(subject.to_string())
        .or_default()
        .push(blocker);
}

fn stable_id(label: &str, value: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-STABLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        16,
    )
}

fn fixture_root(label: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-FIXTURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn empty_root(label: &str) -> String {
    let leaves: Vec<Value> = Vec::new();
    merkle_root(&format!("DEPLOYMENT-GUARD-EMPTY-{label}"), &leaves)
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        label,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn map_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{field} must be non-empty"),
    )
}

fn ensure_capacity(current_len: usize, max_len: usize) -> Result<()> {
    ensure(
        current_len < max_len,
        "deployment guard record capacity exceeded",
    )
}
