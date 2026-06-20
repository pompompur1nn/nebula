use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageRuntimeReplayAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-runtime-replay-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEPLOYMENT_GUARD_SUITE: &str =
    "runtime-replay-dashboard-release-policy-deployment-guard-v1";
pub const DEFAULT_HEIGHT: u64 = 84_084;
pub const DEFAULT_MIN_REPLAY_COMMANDS: u16 = 7;
pub const DEFAULT_MIN_OPERATOR_APPROVALS: u16 = 4;
pub const DEFAULT_MIN_ROLLBACK_PROOFS: u16 = 3;
pub const DEFAULT_MIN_ABORT_ROOTS: u16 = 3;
pub const DEFAULT_MAX_REPLAY_AGE_BLOCKS: u64 = 64;
pub const DEFAULT_DEPLOY_WINDOW_BLOCKS: u64 = 24;
pub const DEFAULT_MAX_WATCH_ITEMS: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePolicyGoNoGoVerdict {
    Go,
    Watch,
    NoGo,
}

impl ReleasePolicyGoNoGoVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Watch => "watch",
            Self::NoGo => "no_go",
        }
    }

    pub fn allows_guard_evaluation(self) -> bool {
        matches!(self, Self::Go | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAgreementStatus {
    Agreed,
    Watch,
    MissingExpected,
    MissingObserved,
    Mismatched,
}

impl ReceiptAgreementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agreed => "agreed",
            Self::Watch => "watch",
            Self::MissingExpected => "missing_expected",
            Self::MissingObserved => "missing_observed",
            Self::Mismatched => "mismatched",
        }
    }

    pub fn blocks_deploy(self) -> bool {
        matches!(
            self,
            Self::MissingExpected | Self::MissingObserved | Self::Mismatched
        )
    }

    pub fn is_watch(self) -> bool {
        matches!(self, Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayFreshnessStatus {
    Fresh,
    Aging,
    Expired,
}

impl ReplayFreshnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Aging => "aging",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_deploy(self) -> bool {
        matches!(self, Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployWindowStatus {
    Open,
    Pending,
    Expired,
    Frozen,
}

impl DeployWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Pending => "pending",
            Self::Expired => "expired",
            Self::Frozen => "frozen",
        }
    }

    pub fn blocks_deploy(self) -> bool {
        !matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldDecisionKind {
    Hold,
    Unhold,
}

impl HoldDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Unhold => "unhold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRole {
    RuntimeReplayOperator,
    ReleaseCoordinator,
    DashboardOwner,
    SecurityReviewer,
    RollbackCommander,
    ProductionSre,
}

impl ApprovalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeReplayOperator => "runtime_replay_operator",
            Self::ReleaseCoordinator => "release_coordinator",
            Self::DashboardOwner => "dashboard_owner",
            Self::SecurityReviewer => "security_reviewer",
            Self::RollbackCommander => "rollback_commander",
            Self::ProductionSre => "production_sre",
        }
    }

    pub fn required() -> [Self; 6] {
        [
            Self::RuntimeReplayOperator,
            Self::ReleaseCoordinator,
            Self::DashboardOwner,
            Self::SecurityReviewer,
            Self::RollbackCommander,
            Self::ProductionSre,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Watch,
    Hold,
    Rejected,
}

impl ApprovalDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Rejected => "rejected",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Approved)
    }

    pub fn blocks_deploy(self) -> bool {
        matches!(self, Self::Hold | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackProofStatus {
    Armed,
    Watch,
    Missing,
    Invalid,
}

impl RollbackProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Watch => "watch",
            Self::Missing => "missing",
            Self::Invalid => "invalid",
        }
    }

    pub fn deploy_ready(self) -> bool {
        matches!(self, Self::Armed)
    }

    pub fn blocks_deploy(self) -> bool {
        matches!(self, Self::Missing | Self::Invalid)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionDeploymentState {
    FailClosed,
    Held,
    GuardedReady,
    Deploying,
    Aborted,
    RolledBack,
}

impl ProductionDeploymentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::Held => "held",
            Self::GuardedReady => "guarded_ready",
            Self::Deploying => "deploying",
            Self::Aborted => "aborted",
            Self::RolledBack => "rolled_back",
        }
    }

    pub fn permits_production(self) -> bool {
        matches!(self, Self::GuardedReady | Self::Deploying)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentBlockerKind {
    GoNoGoNotGo,
    GoNoGoEvidenceMissing,
    ReplayReceiptMismatch,
    ReplayReceiptMissing,
    ReplayExpired,
    DeployWindowClosed,
    HoldActive,
    UnholdCriteriaMissing,
    RollbackProofMissing,
    AbortRootMissing,
    OperatorApprovalMissing,
    OperatorApprovalRejected,
    ReplayCommandEvidenceMissing,
    ReleasePolicyRootMismatch,
    DashboardRootMismatch,
    ProductionFailClosed,
    ManualFreeze,
}

impl DeploymentBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GoNoGoNotGo => "go_no_go_not_go",
            Self::GoNoGoEvidenceMissing => "go_no_go_evidence_missing",
            Self::ReplayReceiptMismatch => "replay_receipt_mismatch",
            Self::ReplayReceiptMissing => "replay_receipt_missing",
            Self::ReplayExpired => "replay_expired",
            Self::DeployWindowClosed => "deploy_window_closed",
            Self::HoldActive => "hold_active",
            Self::UnholdCriteriaMissing => "unhold_criteria_missing",
            Self::RollbackProofMissing => "rollback_proof_missing",
            Self::AbortRootMissing => "abort_root_missing",
            Self::OperatorApprovalMissing => "operator_approval_missing",
            Self::OperatorApprovalRejected => "operator_approval_rejected",
            Self::ReplayCommandEvidenceMissing => "replay_command_evidence_missing",
            Self::ReleasePolicyRootMismatch => "release_policy_root_mismatch",
            Self::DashboardRootMismatch => "dashboard_root_mismatch",
            Self::ProductionFailClosed => "production_fail_closed",
            Self::ManualFreeze => "manual_freeze",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Watch,
    Blocking,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Blocking => "blocking",
        }
    }

    pub fn blocks_deploy(self) -> bool {
        matches!(self, Self::Blocking)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub deployment_guard_suite: String,
    pub max_replay_age_blocks: u64,
    pub deploy_window_blocks: u64,
    pub min_replay_commands: u16,
    pub min_operator_approvals: u16,
    pub min_rollback_proofs: u16,
    pub min_abort_roots: u16,
    pub max_watch_items: u16,
    pub require_go_no_go_go: bool,
    pub require_receipt_agreement: bool,
    pub require_replay_freshness: bool,
    pub require_open_deploy_window: bool,
    pub require_unhold_decision: bool,
    pub require_rollback_proofs: bool,
    pub require_abort_roots: bool,
    pub require_release_policy_root_match: bool,
    pub require_dashboard_root_match: bool,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            deployment_guard_suite: DEPLOYMENT_GUARD_SUITE.to_string(),
            max_replay_age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS,
            deploy_window_blocks: DEFAULT_DEPLOY_WINDOW_BLOCKS,
            min_replay_commands: DEFAULT_MIN_REPLAY_COMMANDS,
            min_operator_approvals: DEFAULT_MIN_OPERATOR_APPROVALS,
            min_rollback_proofs: DEFAULT_MIN_ROLLBACK_PROOFS,
            min_abort_roots: DEFAULT_MIN_ABORT_ROOTS,
            max_watch_items: DEFAULT_MAX_WATCH_ITEMS,
            require_go_no_go_go: true,
            require_receipt_agreement: true,
            require_replay_freshness: true,
            require_open_deploy_window: true,
            require_unhold_decision: true,
            require_rollback_proofs: true,
            require_abort_roots: true,
            require_release_policy_root_match: true,
            require_dashboard_root_match: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("deployment_guard_suite", &self.deployment_guard_suite)?;
        ensure(
            self.max_replay_age_blocks > 0,
            "replay age window must be non-zero",
        )?;
        ensure(
            self.deploy_window_blocks > 0,
            "deploy window must be non-zero",
        )?;
        ensure(
            self.min_replay_commands > 0,
            "minimum replay commands must be non-zero",
        )?;
        ensure(
            self.min_operator_approvals > 0,
            "minimum operator approvals must be non-zero",
        )?;
        ensure(
            self.min_rollback_proofs > 0,
            "minimum rollback proofs must be non-zero",
        )?;
        ensure(
            self.min_abort_roots > 0,
            "minimum abort roots must be non-zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "deployment_guard_suite": self.deployment_guard_suite,
            "max_replay_age_blocks": self.max_replay_age_blocks,
            "deploy_window_blocks": self.deploy_window_blocks,
            "min_replay_commands": self.min_replay_commands,
            "min_operator_approvals": self.min_operator_approvals,
            "min_rollback_proofs": self.min_rollback_proofs,
            "min_abort_roots": self.min_abort_roots,
            "max_watch_items": self.max_watch_items,
            "require_go_no_go_go": self.require_go_no_go_go,
            "require_receipt_agreement": self.require_receipt_agreement,
            "require_replay_freshness": self.require_replay_freshness,
            "require_open_deploy_window": self.require_open_deploy_window,
            "require_unhold_decision": self.require_unhold_decision,
            "require_rollback_proofs": self.require_rollback_proofs,
            "require_abort_roots": self.require_abort_roots,
            "require_release_policy_root_match": self.require_release_policy_root_match,
            "require_dashboard_root_match": self.require_dashboard_root_match,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment_guard_config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GoNoGoBindingEvidence {
    pub binding_id: String,
    pub verdict: ReleasePolicyGoNoGoVerdict,
    pub go_no_go_evidence_root: String,
    pub dashboard_root: String,
    pub release_policy_root: String,
    pub blocker_root: String,
    pub lane_binding_root: String,
    pub coordinator_root: String,
    pub imported_live_evidence_root: String,
    pub observed_at_height: u64,
}

impl GoNoGoBindingEvidence {
    pub fn new(
        binding_id: impl Into<String>,
        verdict: ReleasePolicyGoNoGoVerdict,
        observed_at_height: u64,
    ) -> Self {
        let binding_id = binding_id.into();
        Self {
            go_no_go_evidence_root: sample_root(&binding_id, "go-no-go-evidence"),
            dashboard_root: sample_root(&binding_id, "operator-dashboard"),
            release_policy_root: sample_root(&binding_id, "release-policy"),
            blocker_root: sample_root(&binding_id, "go-no-go-blockers"),
            lane_binding_root: sample_root(&binding_id, "lane-bindings"),
            coordinator_root: sample_root(&binding_id, "coordinator-quorum"),
            imported_live_evidence_root: sample_root(&binding_id, "accepted-live-evidence"),
            binding_id,
            verdict,
            observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "verdict": self.verdict.as_str(),
            "go_no_go_evidence_root": self.go_no_go_evidence_root,
            "dashboard_root": self.dashboard_root,
            "release_policy_root": self.release_policy_root,
            "blocker_root": self.blocker_root,
            "lane_binding_root": self.lane_binding_root,
            "coordinator_root": self.coordinator_root,
            "imported_live_evidence_root": self.imported_live_evidence_root,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("go_no_go_binding_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayReceiptAgreement {
    pub agreement_id: String,
    pub command: String,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub accepted_live_evidence_root: String,
    pub replay_command_root: String,
    pub status: ReceiptAgreementStatus,
    pub compared_at_height: u64,
}

impl ReplayReceiptAgreement {
    pub fn new(
        command: impl Into<String>,
        expected_receipt_root: impl Into<String>,
        observed_receipt_root: impl Into<String>,
        compared_at_height: u64,
    ) -> Result<Self> {
        let command = command.into();
        let expected_receipt_root = expected_receipt_root.into();
        let observed_receipt_root = observed_receipt_root.into();
        ensure_non_empty("command", &command)?;
        ensure_root("expected_receipt_root", &expected_receipt_root)?;
        ensure_root("observed_receipt_root", &observed_receipt_root)?;
        let status = if expected_receipt_root == observed_receipt_root {
            ReceiptAgreementStatus::Agreed
        } else {
            ReceiptAgreementStatus::Mismatched
        };
        let accepted_live_evidence_root = command_sample_root(&command, "accepted-live-evidence");
        let replay_command_root = replay_command_root(
            &command,
            &expected_receipt_root,
            &observed_receipt_root,
            compared_at_height,
        );
        let agreement_id = replay_receipt_agreement_id(
            &command,
            status,
            &expected_receipt_root,
            &observed_receipt_root,
            compared_at_height,
        );
        Ok(Self {
            agreement_id,
            command,
            expected_receipt_root,
            observed_receipt_root,
            accepted_live_evidence_root,
            replay_command_root,
            status,
            compared_at_height,
        })
    }

    pub fn watch(
        command: impl Into<String>,
        expected_receipt_root: impl Into<String>,
        observed_receipt_root: impl Into<String>,
        compared_at_height: u64,
    ) -> Result<Self> {
        let mut agreement = Self::new(
            command,
            expected_receipt_root,
            observed_receipt_root,
            compared_at_height,
        )?;
        agreement.status = ReceiptAgreementStatus::Watch;
        agreement.agreement_id = replay_receipt_agreement_id(
            &agreement.command,
            agreement.status,
            &agreement.expected_receipt_root,
            &agreement.observed_receipt_root,
            agreement.compared_at_height,
        );
        Ok(agreement)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "agreement_id": self.agreement_id,
            "command": self.command,
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "replay_command_root": self.replay_command_root,
            "status": self.status.as_str(),
            "compared_at_height": self.compared_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay_receipt_agreement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayFreshness {
    pub freshness_id: String,
    pub replay_root: String,
    pub replayed_at_height: u64,
    pub observed_at_height: u64,
    pub max_age_blocks: u64,
    pub status: ReplayFreshnessStatus,
}

impl ReplayFreshness {
    pub fn new(
        replay_root: impl Into<String>,
        replayed_at_height: u64,
        observed_at_height: u64,
        max_age_blocks: u64,
    ) -> Result<Self> {
        let replay_root = replay_root.into();
        ensure_root("replay_root", &replay_root)?;
        ensure(max_age_blocks > 0, "max age blocks must be non-zero")?;
        let age = observed_at_height.saturating_sub(replayed_at_height);
        let status = if age > max_age_blocks {
            ReplayFreshnessStatus::Expired
        } else if age.saturating_mul(2) >= max_age_blocks {
            ReplayFreshnessStatus::Aging
        } else {
            ReplayFreshnessStatus::Fresh
        };
        let freshness_id = replay_freshness_id(
            &replay_root,
            replayed_at_height,
            observed_at_height,
            max_age_blocks,
        );
        Ok(Self {
            freshness_id,
            replay_root,
            replayed_at_height,
            observed_at_height,
            max_age_blocks,
            status,
        })
    }

    pub fn age_blocks(&self) -> u64 {
        self.observed_at_height
            .saturating_sub(self.replayed_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "freshness_id": self.freshness_id,
            "replay_root": self.replay_root,
            "replayed_at_height": self.replayed_at_height,
            "observed_at_height": self.observed_at_height,
            "max_age_blocks": self.max_age_blocks,
            "age_blocks": self.age_blocks(),
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay_freshness", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeployWindow {
    pub window_id: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub observed_at_height: u64,
    pub freeze_root: String,
    pub status: DeployWindowStatus,
}

impl DeployWindow {
    pub fn new(
        opens_at_height: u64,
        closes_at_height: u64,
        observed_at_height: u64,
        freeze_root: impl Into<String>,
    ) -> Result<Self> {
        let freeze_root = freeze_root.into();
        ensure(
            closes_at_height >= opens_at_height,
            "deploy window close height must not precede open height",
        )?;
        ensure_root("freeze_root", &freeze_root)?;
        let status = if freeze_root != no_freeze_root() {
            DeployWindowStatus::Frozen
        } else if observed_at_height < opens_at_height {
            DeployWindowStatus::Pending
        } else if observed_at_height > closes_at_height {
            DeployWindowStatus::Expired
        } else {
            DeployWindowStatus::Open
        };
        let window_id = deploy_window_id(
            opens_at_height,
            closes_at_height,
            observed_at_height,
            &freeze_root,
        );
        Ok(Self {
            window_id,
            opens_at_height,
            closes_at_height,
            observed_at_height,
            freeze_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "observed_at_height": self.observed_at_height,
            "freeze_root": self.freeze_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deploy_window", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldCriterion {
    pub criterion_id: String,
    pub label: String,
    pub evidence_root: String,
    pub satisfied: bool,
    pub detail: String,
}

impl HoldCriterion {
    pub fn new(
        label: impl Into<String>,
        evidence_root: impl Into<String>,
        satisfied: bool,
        detail: impl Into<String>,
    ) -> Result<Self> {
        let label = label.into();
        let evidence_root = evidence_root.into();
        let detail = detail.into();
        ensure_non_empty("label", &label)?;
        ensure_root("evidence_root", &evidence_root)?;
        ensure_non_empty("detail", &detail)?;
        let criterion_id = hold_criterion_id(&label, &evidence_root, satisfied);
        Ok(Self {
            criterion_id,
            label,
            evidence_root,
            satisfied,
            detail,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "label": self.label,
            "evidence_root": self.evidence_root,
            "satisfied": self.satisfied,
            "detail": self.detail,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("hold_criterion", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldDecision {
    pub decision_id: String,
    pub kind: HoldDecisionKind,
    pub decision_root: String,
    pub criteria_root: String,
    pub actor_id: String,
    pub decided_at_height: u64,
    pub note: String,
}

impl HoldDecision {
    pub fn new(
        kind: HoldDecisionKind,
        actor_id: impl Into<String>,
        criteria: &[HoldCriterion],
        decided_at_height: u64,
        note: impl Into<String>,
    ) -> Result<Self> {
        let actor_id = actor_id.into();
        let note = note.into();
        ensure_non_empty("actor_id", &actor_id)?;
        ensure_non_empty("note", &note)?;
        let criteria_root = merkle_root(
            "deployment-guard-hold-decision-criteria",
            &criteria
                .iter()
                .map(HoldCriterion::public_record)
                .collect::<Vec<_>>(),
        );
        let decision_root = hold_decision_root(kind, &actor_id, &criteria_root, decided_at_height);
        let decision_id = hold_decision_id(kind, &decision_root, decided_at_height);
        Ok(Self {
            decision_id,
            kind,
            decision_root,
            criteria_root,
            actor_id,
            decided_at_height,
            note,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "kind": self.kind.as_str(),
            "decision_root": self.decision_root,
            "criteria_root": self.criteria_root,
            "actor_id": self.actor_id,
            "decided_at_height": self.decided_at_height,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("hold_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackProof {
    pub proof_id: String,
    pub lane: String,
    pub rollback_root: String,
    pub abort_root: String,
    pub runbook_root: String,
    pub signer_root: String,
    pub status: RollbackProofStatus,
    pub observed_at_height: u64,
}

impl RollbackProof {
    pub fn new(
        lane: impl Into<String>,
        status: RollbackProofStatus,
        observed_at_height: u64,
    ) -> Result<Self> {
        let lane = lane.into();
        ensure_non_empty("lane", &lane)?;
        let rollback_root = lane_guard_root(&lane, "rollback");
        let abort_root = lane_guard_root(&lane, "abort");
        let runbook_root = lane_guard_root(&lane, "rollback-runbook");
        let signer_root = lane_guard_root(&lane, "signer-quorum");
        let proof_id = rollback_proof_id(
            &lane,
            status,
            &rollback_root,
            &abort_root,
            observed_at_height,
        );
        Ok(Self {
            proof_id,
            lane,
            rollback_root,
            abort_root,
            runbook_root,
            signer_root,
            status,
            observed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "lane": self.lane,
            "rollback_root": self.rollback_root,
            "abort_root": self.abort_root,
            "runbook_root": self.runbook_root,
            "signer_root": self.signer_root,
            "status": self.status.as_str(),
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback_proof", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorApproval {
    pub approval_id: String,
    pub operator_id: String,
    pub role: ApprovalRole,
    pub decision: ApprovalDecision,
    pub dashboard_root: String,
    pub release_policy_root: String,
    pub deployment_guard_root: String,
    pub signed_statement_root: String,
    pub approved_at_height: u64,
}

impl OperatorApproval {
    pub fn new(
        operator_id: impl Into<String>,
        role: ApprovalRole,
        decision: ApprovalDecision,
        dashboard_root: impl Into<String>,
        release_policy_root: impl Into<String>,
        deployment_guard_root: impl Into<String>,
        approved_at_height: u64,
    ) -> Result<Self> {
        let operator_id = operator_id.into();
        let dashboard_root = dashboard_root.into();
        let release_policy_root = release_policy_root.into();
        let deployment_guard_root = deployment_guard_root.into();
        ensure_non_empty("operator_id", &operator_id)?;
        ensure_root("dashboard_root", &dashboard_root)?;
        ensure_root("release_policy_root", &release_policy_root)?;
        ensure_root("deployment_guard_root", &deployment_guard_root)?;
        let signed_statement_root = operator_signed_statement_root(
            &operator_id,
            role,
            decision,
            &dashboard_root,
            &release_policy_root,
            &deployment_guard_root,
            approved_at_height,
        );
        let approval_id = operator_approval_id(
            &operator_id,
            role,
            decision,
            &signed_statement_root,
            approved_at_height,
        );
        Ok(Self {
            approval_id,
            operator_id,
            role,
            decision,
            dashboard_root,
            release_policy_root,
            deployment_guard_root,
            signed_statement_root,
            approved_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "decision": self.decision.as_str(),
            "dashboard_root": self.dashboard_root,
            "release_policy_root": self.release_policy_root,
            "deployment_guard_root": self.deployment_guard_root,
            "signed_statement_root": self.signed_statement_root,
            "approved_at_height": self.approved_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator_approval", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentBlocker {
    pub blocker_id: String,
    pub kind: DeploymentBlockerKind,
    pub severity: BlockerSeverity,
    pub subject: String,
    pub evidence_root: String,
    pub detail: String,
    pub observed_at_height: u64,
}

impl DeploymentBlocker {
    pub fn new(
        kind: DeploymentBlockerKind,
        severity: BlockerSeverity,
        subject: impl Into<String>,
        evidence_root: impl Into<String>,
        detail: impl Into<String>,
        observed_at_height: u64,
    ) -> Result<Self> {
        let subject = subject.into();
        let evidence_root = evidence_root.into();
        let detail = detail.into();
        ensure_non_empty("subject", &subject)?;
        ensure_root("evidence_root", &evidence_root)?;
        ensure_non_empty("detail", &detail)?;
        let blocker_id =
            deployment_blocker_id(kind, severity, &subject, &evidence_root, observed_at_height);
        Ok(Self {
            blocker_id,
            kind,
            severity,
            subject,
            evidence_root,
            detail,
            observed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "subject": self.subject,
            "evidence_root": self.evidence_root,
            "detail": self.detail,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentCounters {
    pub replay_command_count: u16,
    pub agreed_receipts: u16,
    pub watch_receipts: u16,
    pub armed_rollback_proofs: u16,
    pub abort_roots: u16,
    pub operator_approvals: u16,
    pub approval_roles: u16,
    pub blocking_blockers: u16,
    pub watch_blockers: u16,
    pub hold_criteria_satisfied: u16,
    pub hold_criteria_total: u16,
}

impl DeploymentCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_command_count": self.replay_command_count,
            "agreed_receipts": self.agreed_receipts,
            "watch_receipts": self.watch_receipts,
            "armed_rollback_proofs": self.armed_rollback_proofs,
            "abort_roots": self.abort_roots,
            "operator_approvals": self.operator_approvals,
            "approval_roles": self.approval_roles,
            "blocking_blockers": self.blocking_blockers,
            "watch_blockers": self.watch_blockers,
            "hold_criteria_satisfied": self.hold_criteria_satisfied,
            "hold_criteria_total": self.hold_criteria_total,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentGuardDecision {
    pub decision_id: String,
    pub production_state: ProductionDeploymentState,
    pub deployment_allowed: bool,
    pub fail_closed: bool,
    pub go_no_go_verdict: ReleasePolicyGoNoGoVerdict,
    pub replay_agreement_root: String,
    pub replay_freshness_root: String,
    pub deploy_window_root: String,
    pub hold_decision_root: String,
    pub rollback_proof_root: String,
    pub operator_approval_root: String,
    pub blocker_root: String,
    pub counters_root: String,
    pub decided_at_height: u64,
}

impl DeploymentGuardDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "production_state": self.production_state.as_str(),
            "deployment_allowed": self.deployment_allowed,
            "fail_closed": self.fail_closed,
            "go_no_go_verdict": self.go_no_go_verdict.as_str(),
            "replay_agreement_root": self.replay_agreement_root,
            "replay_freshness_root": self.replay_freshness_root,
            "deploy_window_root": self.deploy_window_root,
            "hold_decision_root": self.hold_decision_root,
            "rollback_proof_root": self.rollback_proof_root,
            "operator_approval_root": self.operator_approval_root,
            "blocker_root": self.blocker_root,
            "counters_root": self.counters_root,
            "decided_at_height": self.decided_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment_guard_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub go_no_go_binding: GoNoGoBindingEvidence,
    pub replay_receipt_agreements: BTreeMap<String, ReplayReceiptAgreement>,
    pub replay_freshness: ReplayFreshness,
    pub deploy_window: DeployWindow,
    pub hold_criteria: Vec<HoldCriterion>,
    pub hold_decision: HoldDecision,
    pub rollback_proofs: BTreeMap<String, RollbackProof>,
    pub operator_approvals: BTreeMap<String, OperatorApproval>,
    pub expected_release_policy_root: String,
    pub expected_dashboard_root: String,
    pub manual_freeze_root: String,
    pub replay_agreement_root: String,
    pub rollback_proof_root: String,
    pub operator_approval_root: String,
    pub hold_criteria_root: String,
    pub blocker_root: String,
    pub deployment_guard_evidence_root: String,
    pub decision: DeploymentGuardDecision,
}

impl State {
    pub fn new(input: StateInput) -> Result<Self> {
        input.config.validate()?;
        ensure_root(
            "expected_release_policy_root",
            &input.expected_release_policy_root,
        )?;
        ensure_root("expected_dashboard_root", &input.expected_dashboard_root)?;
        ensure_root("manual_freeze_root", &input.manual_freeze_root)?;
        let replay_agreement_root = map_root(
            "deployment-guard-replay-agreements",
            input
                .replay_receipt_agreements
                .values()
                .map(ReplayReceiptAgreement::state_root),
        );
        let rollback_proof_root = map_root(
            "deployment-guard-rollback-proofs",
            input
                .rollback_proofs
                .values()
                .map(RollbackProof::state_root),
        );
        let operator_approval_root = map_root(
            "deployment-guard-operator-approvals",
            input
                .operator_approvals
                .values()
                .map(OperatorApproval::state_root),
        );
        let hold_criteria_root = merkle_root(
            "deployment-guard-hold-criteria",
            &input
                .hold_criteria
                .iter()
                .map(HoldCriterion::public_record)
                .collect::<Vec<_>>(),
        );
        let counters = counters(
            &input.replay_receipt_agreements,
            &input.rollback_proofs,
            &input.operator_approvals,
            &input.hold_criteria,
        );
        let mut blockers = Vec::new();
        push_policy_blockers(&input, &counters, &mut blockers);
        push_replay_blockers(&input, &counters, &mut blockers);
        push_window_blockers(&input, &mut blockers);
        push_hold_blockers(&input, &counters, &mut blockers);
        push_rollback_blockers(&input, &counters, &mut blockers);
        push_operator_blockers(&input, &counters, &mut blockers);
        let blocker_root = merkle_root(
            "deployment-guard-blockers",
            &blockers
                .iter()
                .map(DeploymentBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let counters_root = counters.state_root();
        let production_state =
            production_state(&input, &counters, &blockers, input.config.fail_closed);
        let deployment_allowed = production_state.permits_production()
            && blockers
                .iter()
                .filter(|blocker| blocker.severity.blocks_deploy())
                .count()
                == 0;
        let fail_closed = input.config.fail_closed && !deployment_allowed;
        let deployment_guard_evidence_root = domain_hash(
            "DEPLOYMENT-GUARD-EVIDENCE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&input.go_no_go_binding.state_root()),
                HashPart::Str(&replay_agreement_root),
                HashPart::Str(&input.replay_freshness.state_root()),
                HashPart::Str(&input.deploy_window.state_root()),
                HashPart::Str(&hold_criteria_root),
                HashPart::Str(&input.hold_decision.state_root()),
                HashPart::Str(&rollback_proof_root),
                HashPart::Str(&operator_approval_root),
                HashPart::Str(&blocker_root),
                HashPart::Str(&counters_root),
                HashPart::Int(input.height as i128),
            ],
            32,
        );
        let decision_id = deployment_guard_decision_id(
            production_state,
            &deployment_guard_evidence_root,
            &blocker_root,
            &counters_root,
            input.height,
        );
        let decision = DeploymentGuardDecision {
            decision_id,
            production_state,
            deployment_allowed,
            fail_closed,
            go_no_go_verdict: input.go_no_go_binding.verdict,
            replay_agreement_root: replay_agreement_root.clone(),
            replay_freshness_root: input.replay_freshness.state_root(),
            deploy_window_root: input.deploy_window.state_root(),
            hold_decision_root: input.hold_decision.state_root(),
            rollback_proof_root: rollback_proof_root.clone(),
            operator_approval_root: operator_approval_root.clone(),
            blocker_root: blocker_root.clone(),
            counters_root,
            decided_at_height: input.height,
        };
        Ok(Self {
            config: input.config,
            height: input.height,
            go_no_go_binding: input.go_no_go_binding,
            replay_receipt_agreements: input.replay_receipt_agreements,
            replay_freshness: input.replay_freshness,
            deploy_window: input.deploy_window,
            hold_criteria: input.hold_criteria,
            hold_decision: input.hold_decision,
            rollback_proofs: input.rollback_proofs,
            operator_approvals: input.operator_approvals,
            expected_release_policy_root: input.expected_release_policy_root,
            expected_dashboard_root: input.expected_dashboard_root,
            manual_freeze_root: input.manual_freeze_root,
            replay_agreement_root,
            rollback_proof_root,
            operator_approval_root,
            hold_criteria_root,
            blocker_root,
            deployment_guard_evidence_root,
            decision,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let go_no_go_binding = GoNoGoBindingEvidence::new(
            "wave83-runtime-replay-dashboard-release-policy-go-no-go",
            ReleasePolicyGoNoGoVerdict::Go,
            height.saturating_sub(4),
        );
        let expected_release_policy_root = go_no_go_binding.release_policy_root.clone();
        let expected_dashboard_root = go_no_go_binding.dashboard_root.clone();
        let replay_receipt_agreements = replay_commands(height)
            .into_iter()
            .filter_map(|command| {
                let root = command_sample_root(command, "receipt");
                match ReplayReceiptAgreement::new(command, root.clone(), root, height - 3) {
                    Ok(agreement) => Some((agreement.command.clone(), agreement)),
                    Err(_) => None,
                }
            })
            .collect::<BTreeMap<_, _>>();
        let replay_agreement_root = map_root(
            "deployment-guard-devnet-replay-root",
            replay_receipt_agreements
                .values()
                .map(ReplayReceiptAgreement::state_root),
        );
        let replay_freshness = match ReplayFreshness::new(
            replay_agreement_root,
            height.saturating_sub(3),
            height,
            config.max_replay_age_blocks,
        ) {
            Ok(freshness) => freshness,
            Err(_) => return Self::fallback(),
        };
        let deploy_window = match DeployWindow::new(
            height.saturating_sub(2),
            height.saturating_add(config.deploy_window_blocks),
            height,
            no_freeze_root(),
        ) {
            Ok(window) => window,
            Err(_) => return Self::fallback(),
        };
        let hold_criteria = devnet_hold_criteria(&go_no_go_binding, &replay_freshness);
        let hold_decision = match HoldDecision::new(
            HoldDecisionKind::Unhold,
            "release-coordinator-alpha",
            &hold_criteria,
            height,
            "deployment guard unholds after replay receipts, freshness, rollback, and dashboard approvals agree",
        ) {
            Ok(decision) => decision,
            Err(_) => return Self::fallback(),
        };
        let rollback_proofs = ["runtime_replay", "force_exit_package", "operator_dashboard"]
            .into_iter()
            .filter_map(
                |lane| match RollbackProof::new(lane, RollbackProofStatus::Armed, height) {
                    Ok(proof) => Some((proof.lane.clone(), proof)),
                    Err(_) => None,
                },
            )
            .collect::<BTreeMap<_, _>>();
        let provisional_guard_root = sample_root("wave84", "deployment-guard-provisional");
        let operator_approvals = devnet_operator_approvals(
            &go_no_go_binding.dashboard_root,
            &go_no_go_binding.release_policy_root,
            &provisional_guard_root,
            height,
        );
        let input = StateInput {
            config,
            height,
            go_no_go_binding,
            replay_receipt_agreements,
            replay_freshness,
            deploy_window,
            hold_criteria,
            hold_decision,
            rollback_proofs,
            operator_approvals,
            expected_release_policy_root,
            expected_dashboard_root,
            manual_freeze_root: no_freeze_root(),
        };
        match Self::new(input) {
            Ok(state) => state,
            Err(_) => Self::fallback(),
        }
    }

    pub fn fallback() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let go_no_go_binding = GoNoGoBindingEvidence::new(
            "fallback-runtime-replay-dashboard-release-policy-go-no-go",
            ReleasePolicyGoNoGoVerdict::NoGo,
            height,
        );
        let receipt_root = command_sample_root("fallback-runtime-replay", "receipt");
        let mut replay_receipt_agreements = BTreeMap::new();
        if let Ok(agreement) = ReplayReceiptAgreement::watch(
            "fallback-runtime-replay",
            receipt_root.clone(),
            receipt_root,
            height,
        ) {
            replay_receipt_agreements.insert(agreement.command.clone(), agreement);
        }
        let replay_freshness = ReplayFreshness::new(
            sample_root("fallback", "replay-root"),
            height.saturating_sub(config.max_replay_age_blocks + 1),
            height,
            config.max_replay_age_blocks,
        )
        .unwrap_or_else_fallback(height, config.max_replay_age_blocks);
        let deploy_window = DeployWindow::new(
            height.saturating_add(1),
            height.saturating_add(config.deploy_window_blocks),
            height,
            no_freeze_root(),
        )
        .unwrap_or_else_fallback(height);
        let hold_criteria = vec![HoldCriterion {
            criterion_id: sample_root("fallback", "hold-criterion-id"),
            label: "fallback_fail_closed".to_string(),
            evidence_root: go_no_go_binding.state_root(),
            satisfied: false,
            detail: "fallback deployment guard remains fail-closed".to_string(),
        }];
        let hold_decision = HoldDecision {
            decision_id: sample_root("fallback", "hold-decision-id"),
            kind: HoldDecisionKind::Hold,
            decision_root: sample_root("fallback", "hold-decision-root"),
            criteria_root: merkle_root(
                "deployment-guard-fallback-hold-criteria",
                &hold_criteria
                    .iter()
                    .map(HoldCriterion::public_record)
                    .collect::<Vec<_>>(),
            ),
            actor_id: "fallback-release-coordinator".to_string(),
            decided_at_height: height,
            note: "fallback state keeps production deployment closed".to_string(),
        };
        let rollback_proofs = BTreeMap::new();
        let operator_approvals = BTreeMap::new();
        let replay_agreement_root = map_root(
            "deployment-guard-fallback-replay-agreements",
            replay_receipt_agreements
                .values()
                .map(ReplayReceiptAgreement::state_root),
        );
        let rollback_proof_root = map_root(
            "deployment-guard-fallback-rollback-proofs",
            rollback_proofs.values().map(RollbackProof::state_root),
        );
        let operator_approval_root = map_root(
            "deployment-guard-fallback-operator-approvals",
            operator_approvals
                .values()
                .map(OperatorApproval::state_root),
        );
        let hold_criteria_root = merkle_root(
            "deployment-guard-fallback-hold-criteria-root",
            &hold_criteria
                .iter()
                .map(HoldCriterion::public_record)
                .collect::<Vec<_>>(),
        );
        let blocker = DeploymentBlocker {
            blocker_id: sample_root("fallback", "blocker-id"),
            kind: DeploymentBlockerKind::ProductionFailClosed,
            severity: BlockerSeverity::Blocking,
            subject: "production_deployment".to_string(),
            evidence_root: go_no_go_binding.state_root(),
            detail: "fallback deployment guard has no complete go-no-go evidence".to_string(),
            observed_at_height: height,
        };
        let blocker_root = merkle_root(
            "deployment-guard-fallback-blockers",
            &[blocker.public_record()],
        );
        let counters = DeploymentCounters {
            replay_command_count: 1,
            agreed_receipts: 0,
            watch_receipts: 1,
            armed_rollback_proofs: 0,
            abort_roots: 0,
            operator_approvals: 0,
            approval_roles: 0,
            blocking_blockers: 1,
            watch_blockers: 0,
            hold_criteria_satisfied: 0,
            hold_criteria_total: 1,
        };
        let counters_root = counters.state_root();
        let deployment_guard_evidence_root = domain_hash(
            "DEPLOYMENT-GUARD-FALLBACK-EVIDENCE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&go_no_go_binding.state_root()),
                HashPart::Str(&blocker_root),
                HashPart::Str(&counters_root),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let decision = DeploymentGuardDecision {
            decision_id: deployment_guard_decision_id(
                ProductionDeploymentState::FailClosed,
                &deployment_guard_evidence_root,
                &blocker_root,
                &counters_root,
                height,
            ),
            production_state: ProductionDeploymentState::FailClosed,
            deployment_allowed: false,
            fail_closed: true,
            go_no_go_verdict: go_no_go_binding.verdict,
            replay_agreement_root: replay_agreement_root.clone(),
            replay_freshness_root: replay_freshness.state_root(),
            deploy_window_root: deploy_window.state_root(),
            hold_decision_root: hold_decision.state_root(),
            rollback_proof_root: rollback_proof_root.clone(),
            operator_approval_root: operator_approval_root.clone(),
            blocker_root: blocker_root.clone(),
            counters_root,
            decided_at_height: height,
        };
        Self {
            config,
            height,
            expected_release_policy_root: go_no_go_binding.release_policy_root.clone(),
            expected_dashboard_root: go_no_go_binding.dashboard_root.clone(),
            manual_freeze_root: no_freeze_root(),
            go_no_go_binding,
            replay_receipt_agreements,
            replay_freshness,
            deploy_window,
            hold_criteria,
            hold_decision,
            rollback_proofs,
            operator_approvals,
            replay_agreement_root,
            rollback_proof_root,
            operator_approval_root,
            hold_criteria_root,
            blocker_root,
            deployment_guard_evidence_root,
            decision,
        }
    }

    pub fn counters(&self) -> DeploymentCounters {
        counters(
            &self.replay_receipt_agreements,
            &self.rollback_proofs,
            &self.operator_approvals,
            &self.hold_criteria,
        )
    }

    pub fn blockers(&self) -> Vec<DeploymentBlocker> {
        let input = StateInput {
            config: self.config.clone(),
            height: self.height,
            go_no_go_binding: self.go_no_go_binding.clone(),
            replay_receipt_agreements: self.replay_receipt_agreements.clone(),
            replay_freshness: self.replay_freshness.clone(),
            deploy_window: self.deploy_window.clone(),
            hold_criteria: self.hold_criteria.clone(),
            hold_decision: self.hold_decision.clone(),
            rollback_proofs: self.rollback_proofs.clone(),
            operator_approvals: self.operator_approvals.clone(),
            expected_release_policy_root: self.expected_release_policy_root.clone(),
            expected_dashboard_root: self.expected_dashboard_root.clone(),
            manual_freeze_root: self.manual_freeze_root.clone(),
        };
        let counters = self.counters();
        let mut blockers = Vec::new();
        push_policy_blockers(&input, &counters, &mut blockers);
        push_replay_blockers(&input, &counters, &mut blockers);
        push_window_blockers(&input, &mut blockers);
        push_hold_blockers(&input, &counters, &mut blockers);
        push_rollback_blockers(&input, &counters, &mut blockers);
        push_operator_blockers(&input, &counters, &mut blockers);
        blockers
    }

    pub fn public_record(&self) -> Value {
        let blockers = self.blockers();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "go_no_go_binding": self.go_no_go_binding.public_record(),
            "expected_release_policy_root": self.expected_release_policy_root,
            "expected_dashboard_root": self.expected_dashboard_root,
            "manual_freeze_root": self.manual_freeze_root,
            "replay_agreement_root": self.replay_agreement_root,
            "replay_freshness": self.replay_freshness.public_record(),
            "deploy_window": self.deploy_window.public_record(),
            "hold_criteria_root": self.hold_criteria_root,
            "hold_decision": self.hold_decision.public_record(),
            "rollback_proof_root": self.rollback_proof_root,
            "operator_approval_root": self.operator_approval_root,
            "blocker_root": self.blocker_root,
            "deployment_guard_evidence_root": self.deployment_guard_evidence_root,
            "decision": self.decision.public_record(),
            "counters": counters.public_record(),
            "replay_receipt_agreements": self.replay_receipt_agreements.values().map(ReplayReceiptAgreement::public_record).collect::<Vec<_>>(),
            "hold_criteria": self.hold_criteria.iter().map(HoldCriterion::public_record).collect::<Vec<_>>(),
            "rollback_proofs": self.rollback_proofs.values().map(RollbackProof::public_record).collect::<Vec<_>>(),
            "operator_approvals": self.operator_approvals.values().map(OperatorApproval::public_record).collect::<Vec<_>>(),
            "blockers": blockers.iter().map(DeploymentBlocker::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment_guard_state", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateInput {
    pub config: Config,
    pub height: u64,
    pub go_no_go_binding: GoNoGoBindingEvidence,
    pub replay_receipt_agreements: BTreeMap<String, ReplayReceiptAgreement>,
    pub replay_freshness: ReplayFreshness,
    pub deploy_window: DeployWindow,
    pub hold_criteria: Vec<HoldCriterion>,
    pub hold_decision: HoldDecision,
    pub rollback_proofs: BTreeMap<String, RollbackProof>,
    pub operator_approvals: BTreeMap<String, OperatorApproval>,
    pub expected_release_policy_root: String,
    pub expected_dashboard_root: String,
    pub manual_freeze_root: String,
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

fn counters(
    replay_receipt_agreements: &BTreeMap<String, ReplayReceiptAgreement>,
    rollback_proofs: &BTreeMap<String, RollbackProof>,
    operator_approvals: &BTreeMap<String, OperatorApproval>,
    hold_criteria: &[HoldCriterion],
) -> DeploymentCounters {
    let approval_roles = operator_approvals
        .values()
        .filter(|approval| approval.decision.counts_for_quorum())
        .map(|approval| approval.role)
        .collect::<BTreeSet<_>>()
        .len() as u16;
    DeploymentCounters {
        replay_command_count: replay_receipt_agreements.len() as u16,
        agreed_receipts: replay_receipt_agreements
            .values()
            .filter(|agreement| agreement.status == ReceiptAgreementStatus::Agreed)
            .count() as u16,
        watch_receipts: replay_receipt_agreements
            .values()
            .filter(|agreement| agreement.status.is_watch())
            .count() as u16,
        armed_rollback_proofs: rollback_proofs
            .values()
            .filter(|proof| proof.status.deploy_ready())
            .count() as u16,
        abort_roots: rollback_proofs
            .values()
            .filter(|proof| !proof.abort_root.is_empty())
            .count() as u16,
        operator_approvals: operator_approvals
            .values()
            .filter(|approval| approval.decision.counts_for_quorum())
            .count() as u16,
        approval_roles,
        blocking_blockers: 0,
        watch_blockers: 0,
        hold_criteria_satisfied: hold_criteria
            .iter()
            .filter(|criterion| criterion.satisfied)
            .count() as u16,
        hold_criteria_total: hold_criteria.len() as u16,
    }
}

fn production_state(
    input: &StateInput,
    counters: &DeploymentCounters,
    blockers: &[DeploymentBlocker],
    fail_closed: bool,
) -> ProductionDeploymentState {
    if fail_closed
        && blockers
            .iter()
            .any(|blocker| blocker.severity.blocks_deploy())
    {
        return ProductionDeploymentState::FailClosed;
    }
    if input.hold_decision.kind == HoldDecisionKind::Hold {
        return ProductionDeploymentState::Held;
    }
    if input.deploy_window.status.blocks_deploy() {
        return ProductionDeploymentState::Held;
    }
    if input.go_no_go_binding.verdict != ReleasePolicyGoNoGoVerdict::Go {
        return ProductionDeploymentState::Held;
    }
    if counters.watch_blockers > input.config.max_watch_items {
        return ProductionDeploymentState::Held;
    }
    ProductionDeploymentState::GuardedReady
}

fn push_policy_blockers(
    input: &StateInput,
    _counters: &DeploymentCounters,
    blockers: &mut Vec<DeploymentBlocker>,
) {
    if input.config.require_go_no_go_go
        && input.go_no_go_binding.verdict != ReleasePolicyGoNoGoVerdict::Go
    {
        push_blocker(
            blockers,
            DeploymentBlockerKind::GoNoGoNotGo,
            BlockerSeverity::Blocking,
            "go_no_go_binding",
            &input.go_no_go_binding.state_root(),
            format!(
                "release-policy go-no-go verdict is {}",
                input.go_no_go_binding.verdict.as_str()
            ),
            input.height,
        );
    }
    if !input.go_no_go_binding.verdict.allows_guard_evaluation() {
        push_blocker(
            blockers,
            DeploymentBlockerKind::GoNoGoEvidenceMissing,
            BlockerSeverity::Blocking,
            "go_no_go_binding",
            &input.go_no_go_binding.state_root(),
            "go-no-go evidence does not allow deployment guard evaluation",
            input.height,
        );
    }
    if input.config.require_release_policy_root_match
        && input.go_no_go_binding.release_policy_root != input.expected_release_policy_root
    {
        push_blocker(
            blockers,
            DeploymentBlockerKind::ReleasePolicyRootMismatch,
            BlockerSeverity::Blocking,
            "release_policy_root",
            &input.go_no_go_binding.state_root(),
            "go-no-go release policy root differs from expected deployment guard root",
            input.height,
        );
    }
    if input.config.require_dashboard_root_match
        && input.go_no_go_binding.dashboard_root != input.expected_dashboard_root
    {
        push_blocker(
            blockers,
            DeploymentBlockerKind::DashboardRootMismatch,
            BlockerSeverity::Blocking,
            "operator_dashboard_root",
            &input.go_no_go_binding.state_root(),
            "go-no-go dashboard root differs from expected deployment guard root",
            input.height,
        );
    }
}

fn push_replay_blockers(
    input: &StateInput,
    counters: &DeploymentCounters,
    blockers: &mut Vec<DeploymentBlocker>,
) {
    if counters.replay_command_count < input.config.min_replay_commands {
        push_blocker(
            blockers,
            DeploymentBlockerKind::ReplayCommandEvidenceMissing,
            BlockerSeverity::Blocking,
            "replay_commands",
            &input.go_no_go_binding.state_root(),
            format!(
                "replay command evidence count {} below required {}",
                counters.replay_command_count, input.config.min_replay_commands
            ),
            input.height,
        );
    }
    for agreement in input.replay_receipt_agreements.values() {
        if agreement.status.blocks_deploy() {
            let kind = match agreement.status {
                ReceiptAgreementStatus::MissingExpected
                | ReceiptAgreementStatus::MissingObserved => {
                    DeploymentBlockerKind::ReplayReceiptMissing
                }
                ReceiptAgreementStatus::Mismatched => DeploymentBlockerKind::ReplayReceiptMismatch,
                ReceiptAgreementStatus::Agreed | ReceiptAgreementStatus::Watch => {
                    DeploymentBlockerKind::ReplayReceiptMismatch
                }
            };
            push_blocker(
                blockers,
                kind,
                BlockerSeverity::Blocking,
                &agreement.command,
                &agreement.state_root(),
                "expected and observed replay receipts do not agree",
                input.height,
            );
        }
        if agreement.status.is_watch() {
            push_blocker(
                blockers,
                DeploymentBlockerKind::ReplayReceiptMismatch,
                BlockerSeverity::Watch,
                &agreement.command,
                &agreement.state_root(),
                "replay receipt agreement is watch-listed",
                input.height,
            );
        }
    }
    if input.config.require_replay_freshness && input.replay_freshness.status.blocks_deploy() {
        push_blocker(
            blockers,
            DeploymentBlockerKind::ReplayExpired,
            BlockerSeverity::Blocking,
            "replay_freshness",
            &input.replay_freshness.state_root(),
            "runtime replay freshness is outside deployment guard window",
            input.height,
        );
    }
}

fn push_window_blockers(input: &StateInput, blockers: &mut Vec<DeploymentBlocker>) {
    if input.config.require_open_deploy_window && input.deploy_window.status.blocks_deploy() {
        let kind = if input.deploy_window.status == DeployWindowStatus::Frozen {
            DeploymentBlockerKind::ManualFreeze
        } else {
            DeploymentBlockerKind::DeployWindowClosed
        };
        push_blocker(
            blockers,
            kind,
            BlockerSeverity::Blocking,
            "deploy_window",
            &input.deploy_window.state_root(),
            format!("deploy window is {}", input.deploy_window.status.as_str()),
            input.height,
        );
    }
    if input.manual_freeze_root != no_freeze_root() {
        push_blocker(
            blockers,
            DeploymentBlockerKind::ManualFreeze,
            BlockerSeverity::Blocking,
            "manual_freeze",
            &input.manual_freeze_root,
            "manual deployment freeze root is active",
            input.height,
        );
    }
}

fn push_hold_blockers(
    input: &StateInput,
    counters: &DeploymentCounters,
    blockers: &mut Vec<DeploymentBlocker>,
) {
    if input.hold_decision.kind == HoldDecisionKind::Hold {
        push_blocker(
            blockers,
            DeploymentBlockerKind::HoldActive,
            BlockerSeverity::Blocking,
            "hold_decision",
            &input.hold_decision.state_root(),
            "deployment guard remains held by explicit hold decision",
            input.height,
        );
    }
    if input.config.require_unhold_decision && input.hold_decision.kind != HoldDecisionKind::Unhold
    {
        push_blocker(
            blockers,
            DeploymentBlockerKind::UnholdCriteriaMissing,
            BlockerSeverity::Blocking,
            "hold_decision",
            &input.hold_decision.state_root(),
            "deployment guard requires explicit unhold decision",
            input.height,
        );
    }
    if counters.hold_criteria_satisfied < counters.hold_criteria_total {
        push_blocker(
            blockers,
            DeploymentBlockerKind::UnholdCriteriaMissing,
            BlockerSeverity::Blocking,
            "hold_criteria",
            &input.hold_decision.criteria_root,
            "one or more replay hold or unhold criteria are unsatisfied",
            input.height,
        );
    }
}

fn push_rollback_blockers(
    input: &StateInput,
    counters: &DeploymentCounters,
    blockers: &mut Vec<DeploymentBlocker>,
) {
    if input.config.require_rollback_proofs
        && counters.armed_rollback_proofs < input.config.min_rollback_proofs
    {
        push_blocker(
            blockers,
            DeploymentBlockerKind::RollbackProofMissing,
            BlockerSeverity::Blocking,
            "rollback_proofs",
            &input.go_no_go_binding.state_root(),
            format!(
                "armed rollback proofs {} below required {}",
                counters.armed_rollback_proofs, input.config.min_rollback_proofs
            ),
            input.height,
        );
    }
    if input.config.require_abort_roots && counters.abort_roots < input.config.min_abort_roots {
        push_blocker(
            blockers,
            DeploymentBlockerKind::AbortRootMissing,
            BlockerSeverity::Blocking,
            "abort_roots",
            &input.go_no_go_binding.state_root(),
            format!(
                "abort roots {} below required {}",
                counters.abort_roots, input.config.min_abort_roots
            ),
            input.height,
        );
    }
    for proof in input.rollback_proofs.values() {
        if proof.status.blocks_deploy() {
            push_blocker(
                blockers,
                DeploymentBlockerKind::RollbackProofMissing,
                BlockerSeverity::Blocking,
                &proof.lane,
                &proof.state_root(),
                format!("rollback proof status is {}", proof.status.as_str()),
                input.height,
            );
        }
        if proof.status == RollbackProofStatus::Watch {
            push_blocker(
                blockers,
                DeploymentBlockerKind::RollbackProofMissing,
                BlockerSeverity::Watch,
                &proof.lane,
                &proof.state_root(),
                "rollback proof is watch-listed",
                input.height,
            );
        }
    }
}

fn push_operator_blockers(
    input: &StateInput,
    counters: &DeploymentCounters,
    blockers: &mut Vec<DeploymentBlocker>,
) {
    if counters.operator_approvals < input.config.min_operator_approvals {
        push_blocker(
            blockers,
            DeploymentBlockerKind::OperatorApprovalMissing,
            BlockerSeverity::Blocking,
            "operator_approvals",
            &input.go_no_go_binding.state_root(),
            format!(
                "operator approvals {} below required {}",
                counters.operator_approvals, input.config.min_operator_approvals
            ),
            input.height,
        );
    }
    let roles = input
        .operator_approvals
        .values()
        .filter(|approval| approval.decision.counts_for_quorum())
        .map(|approval| approval.role)
        .collect::<BTreeSet<_>>();
    for role in ApprovalRole::required() {
        if !roles.contains(&role) && role != ApprovalRole::RollbackCommander {
            push_blocker(
                blockers,
                DeploymentBlockerKind::OperatorApprovalMissing,
                BlockerSeverity::Blocking,
                role.as_str(),
                &input.go_no_go_binding.state_root(),
                format!(
                    "required operator approval role is absent: {}",
                    role.as_str()
                ),
                input.height,
            );
        }
    }
    for approval in input.operator_approvals.values() {
        if approval.decision.blocks_deploy() {
            push_blocker(
                blockers,
                DeploymentBlockerKind::OperatorApprovalRejected,
                BlockerSeverity::Blocking,
                &approval.operator_id,
                &approval.state_root(),
                format!("operator approval is {}", approval.decision.as_str()),
                input.height,
            );
        }
    }
}

fn devnet_hold_criteria(
    go_no_go_binding: &GoNoGoBindingEvidence,
    replay_freshness: &ReplayFreshness,
) -> Vec<HoldCriterion> {
    [
        (
            "go_no_go_verdict_go",
            go_no_go_binding.state_root(),
            go_no_go_binding.verdict == ReleasePolicyGoNoGoVerdict::Go,
            "release-policy go-no-go binding is go",
        ),
        (
            "replay_freshness_within_window",
            replay_freshness.state_root(),
            !replay_freshness.status.blocks_deploy(),
            "runtime replay freshness is inside deployment window",
        ),
        (
            "rollback_abort_roots_armed",
            sample_root("wave84", "rollback-abort-roots"),
            true,
            "rollback and abort roots are armed before production deploy",
        ),
        (
            "operator_dashboard_approvals_bound",
            go_no_go_binding.dashboard_root.clone(),
            true,
            "operator dashboard approvals are bound to the deployment guard",
        ),
    ]
    .into_iter()
    .filter_map(|(label, root, satisfied, detail)| {
        HoldCriterion::new(label, root, satisfied, detail).ok()
    })
    .collect()
}

fn devnet_operator_approvals(
    dashboard_root: &str,
    release_policy_root: &str,
    deployment_guard_root: &str,
    height: u64,
) -> BTreeMap<String, OperatorApproval> {
    [
        (
            "runtime-replay-operator-alpha",
            ApprovalRole::RuntimeReplayOperator,
        ),
        (
            "release-coordinator-alpha",
            ApprovalRole::ReleaseCoordinator,
        ),
        ("operator-dashboard-owner", ApprovalRole::DashboardOwner),
        ("security-reviewer-alpha", ApprovalRole::SecurityReviewer),
        ("production-sre-alpha", ApprovalRole::ProductionSre),
    ]
    .into_iter()
    .filter_map(|(operator_id, role)| {
        match OperatorApproval::new(
            operator_id,
            role,
            ApprovalDecision::Approved,
            dashboard_root,
            release_policy_root,
            deployment_guard_root,
            height,
        ) {
            Ok(approval) => Some((approval.operator_id.clone(), approval)),
            Err(_) => None,
        }
    })
    .collect()
}

fn replay_commands(_height: u64) -> Vec<&'static str> {
    vec![
        "import_accepted_live_evidence",
        "load_canonical_user_escape_answer",
        "load_force_exit_package",
        "execute_runtime_replay",
        "compare_replay_root",
        "publish_operator_dashboard",
        "bind_release_policy",
    ]
}

fn replay_command_root(
    command: &str,
    expected_receipt_root: &str,
    observed_receipt_root: &str,
    compared_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-REPLAY-COMMAND-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Int(compared_at_height as i128),
        ],
        32,
    )
}

fn replay_receipt_agreement_id(
    command: &str,
    status: ReceiptAgreementStatus,
    expected_receipt_root: &str,
    observed_receipt_root: &str,
    compared_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-REPLAY-RECEIPT-AGREEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command),
            HashPart::Str(status.as_str()),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Int(compared_at_height as i128),
        ],
        32,
    )
}

fn replay_freshness_id(
    replay_root: &str,
    replayed_at_height: u64,
    observed_at_height: u64,
    max_age_blocks: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-REPLAY-FRESHNESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(replay_root),
            HashPart::Int(replayed_at_height as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(max_age_blocks as i128),
        ],
        32,
    )
}

fn deploy_window_id(
    opens_at_height: u64,
    closes_at_height: u64,
    observed_at_height: u64,
    freeze_root: &str,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-DEPLOY-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(opens_at_height as i128),
            HashPart::Int(closes_at_height as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Str(freeze_root),
        ],
        32,
    )
}

fn hold_criterion_id(label: &str, evidence_root: &str, satisfied: bool) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-HOLD-CRITERION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(evidence_root),
            HashPart::Str(if satisfied {
                "satisfied"
            } else {
                "unsatisfied"
            }),
        ],
        32,
    )
}

fn hold_decision_root(
    kind: HoldDecisionKind,
    actor_id: &str,
    criteria_root: &str,
    decided_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-HOLD-DECISION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(actor_id),
            HashPart::Str(criteria_root),
            HashPart::Int(decided_at_height as i128),
        ],
        32,
    )
}

fn hold_decision_id(kind: HoldDecisionKind, decision_root: &str, decided_at_height: u64) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-HOLD-DECISION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(decision_root),
            HashPart::Int(decided_at_height as i128),
        ],
        32,
    )
}

fn rollback_proof_id(
    lane: &str,
    status: RollbackProofStatus,
    rollback_root: &str,
    abort_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-ROLLBACK-PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(status.as_str()),
            HashPart::Str(rollback_root),
            HashPart::Str(abort_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn operator_signed_statement_root(
    operator_id: &str,
    role: ApprovalRole,
    decision: ApprovalDecision,
    dashboard_root: &str,
    release_policy_root: &str,
    deployment_guard_root: &str,
    approved_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-OPERATOR-SIGNED-STATEMENT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(dashboard_root),
            HashPart::Str(release_policy_root),
            HashPart::Str(deployment_guard_root),
            HashPart::Int(approved_at_height as i128),
        ],
        32,
    )
}

fn operator_approval_id(
    operator_id: &str,
    role: ApprovalRole,
    decision: ApprovalDecision,
    signed_statement_root: &str,
    approved_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-OPERATOR-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(signed_statement_root),
            HashPart::Int(approved_at_height as i128),
        ],
        32,
    )
}

fn deployment_blocker_id(
    kind: DeploymentBlockerKind,
    severity: BlockerSeverity,
    subject: &str,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-BLOCKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(subject),
            HashPart::Str(evidence_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn deployment_guard_decision_id(
    production_state: ProductionDeploymentState,
    evidence_root: &str,
    blocker_root: &str,
    counters_root: &str,
    decided_at_height: u64,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-DECISION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(production_state.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(blocker_root),
            HashPart::Str(counters_root),
            HashPart::Int(decided_at_height as i128),
        ],
        32,
    )
}

fn no_freeze_root() -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-NO-FREEZE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn lane_guard_root(lane: &str, label: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-LANE-GUARD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(label),
        ],
        32,
    )
}

fn command_sample_root(command: &str, label: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-COMMAND-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command),
            HashPart::Str(label),
        ],
        32,
    )
}

fn sample_root(label: &str, kind: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-DEVNET-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(kind),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn map_root<I>(domain: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn push_blocker(
    blockers: &mut Vec<DeploymentBlocker>,
    kind: DeploymentBlockerKind,
    severity: BlockerSeverity,
    subject: impl Into<String>,
    evidence_root: &str,
    detail: impl Into<String>,
    observed_at_height: u64,
) {
    if let Ok(blocker) = DeploymentBlocker::new(
        kind,
        severity,
        subject,
        evidence_root.to_string(),
        detail,
        observed_at_height,
    ) {
        blockers.push(blocker);
    }
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{label} must be non-empty"),
    )
}

fn ensure_root(label: &str, value: &str) -> Result<()> {
    ensure_non_empty(label, value)?;
    ensure(value.len() >= 32, &format!("{label} must be root-like"))
}

trait FallbackFreshness {
    fn unwrap_or_else_fallback(self, height: u64, max_age_blocks: u64) -> ReplayFreshness;
}

impl FallbackFreshness for Result<ReplayFreshness> {
    fn unwrap_or_else_fallback(self, height: u64, max_age_blocks: u64) -> ReplayFreshness {
        match self {
            Ok(value) => value,
            Err(_) => ReplayFreshness {
                freshness_id: sample_root("fallback", "freshness-id"),
                replay_root: sample_root("fallback", "freshness-root"),
                replayed_at_height: height.saturating_sub(max_age_blocks + 1),
                observed_at_height: height,
                max_age_blocks,
                status: ReplayFreshnessStatus::Expired,
            },
        }
    }
}

trait FallbackWindow {
    fn unwrap_or_else_fallback(self, height: u64) -> DeployWindow;
}

impl FallbackWindow for Result<DeployWindow> {
    fn unwrap_or_else_fallback(self, height: u64) -> DeployWindow {
        match self {
            Ok(value) => value,
            Err(_) => DeployWindow {
                window_id: sample_root("fallback", "deploy-window-id"),
                opens_at_height: height.saturating_add(1),
                closes_at_height: height.saturating_add(DEFAULT_DEPLOY_WINDOW_BLOCKS),
                observed_at_height: height,
                freeze_root: no_freeze_root(),
                status: DeployWindowStatus::Pending,
            },
        }
    }
}
