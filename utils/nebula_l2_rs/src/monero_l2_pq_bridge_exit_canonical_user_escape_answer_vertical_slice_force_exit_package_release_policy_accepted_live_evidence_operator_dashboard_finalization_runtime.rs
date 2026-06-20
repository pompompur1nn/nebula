use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReleasePolicyAcceptedLiveEvidenceOperatorDashboardFinalizationRuntimeResult<
    T,
> = Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_FINALIZATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-force-exit-release-policy-accepted-live-evidence-operator-dashboard-finalization-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_FINALIZATION_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_HEIGHT: u64 = 93_000;
pub const DEFAULT_MAX_DASHBOARD_AGE_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_OPERATOR_REVIEWERS: u16 = 2;
pub const DEFAULT_MIN_RELEASE_COORDINATORS: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardLane {
    CompileRuntime,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
}

impl DashboardLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::CompileRuntime,
            Self::RuntimeReplay,
            Self::AuditSecurity,
            Self::BridgeCustody,
            Self::WalletWatchtower,
            Self::PqReservePrivacy,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime",
            Self::RuntimeReplay => "runtime_replay",
            Self::AuditSecurity => "audit_security",
            Self::BridgeCustody => "bridge_custody",
            Self::WalletWatchtower => "wallet_watchtower",
            Self::PqReservePrivacy => "pq_reserve_privacy",
        }
    }

    pub fn runbook_module(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime_operator_runbook_audit",
            Self::RuntimeReplay => "runtime_replay_operator_runbook_audit",
            Self::AuditSecurity => "audit_security_operator_runbook_audit",
            Self::BridgeCustody => "bridge_custody_operator_runbook_audit",
            Self::WalletWatchtower => "wallet_watchtower_operator_runbook_audit",
            Self::PqReservePrivacy => "pq_reserve_privacy_operator_runbook_audit",
        }
    }

    pub fn requires_privacy_notice(self) -> bool {
        matches!(
            self,
            Self::AuditSecurity | Self::WalletWatchtower | Self::PqReservePrivacy
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardStatus {
    Missing,
    Draft,
    ReviewPending,
    Accepted,
    Rejected,
    Expired,
}

impl DashboardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Draft => "draft",
            Self::ReviewPending => "review_pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardActionStatus {
    Open,
    Acknowledged,
    Completed,
    Blocked,
}

impl DashboardActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Completed => "completed",
            Self::Blocked => "blocked",
        }
    }

    pub fn closed(self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardBlockerKind {
    MissingRunbook,
    ReviewPending,
    RejectedRunbook,
    ExpiredRunbook,
    MissingPrivacyNotice,
    MissingOperatorReview,
    MissingReleaseCoordinator,
    OpenAction,
    MissingImportedEvidence,
    MissingDashboardRoot,
}

impl DashboardBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRunbook => "missing_runbook",
            Self::ReviewPending => "review_pending",
            Self::RejectedRunbook => "rejected_runbook",
            Self::ExpiredRunbook => "expired_runbook",
            Self::MissingPrivacyNotice => "missing_privacy_notice",
            Self::MissingOperatorReview => "missing_operator_review",
            Self::MissingReleaseCoordinator => "missing_release_coordinator",
            Self::OpenAction => "open_action",
            Self::MissingImportedEvidence => "missing_imported_evidence",
            Self::MissingDashboardRoot => "missing_dashboard_root",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub dashboard_policy_id: String,
    pub required_lanes: Vec<DashboardLane>,
    pub max_dashboard_age_blocks: u64,
    pub min_operator_reviewers: u16,
    pub min_release_coordinators: u16,
    pub require_imported_evidence_root: bool,
    pub require_privacy_notices: bool,
    pub require_all_actions_closed: bool,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            dashboard_policy_id: dashboard_policy_id("devnet-release-dashboard-finalizer"),
            required_lanes: DashboardLane::all(),
            max_dashboard_age_blocks: DEFAULT_MAX_DASHBOARD_AGE_BLOCKS,
            min_operator_reviewers: DEFAULT_MIN_OPERATOR_REVIEWERS,
            min_release_coordinators: DEFAULT_MIN_RELEASE_COORDINATORS,
            require_imported_evidence_root: true,
            require_privacy_notices: true,
            require_all_actions_closed: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("dashboard_policy_id", &self.dashboard_policy_id)?;
        ensure(
            !self.required_lanes.is_empty(),
            "at least one dashboard lane is required",
        )?;
        ensure(
            self.max_dashboard_age_blocks > 0,
            "dashboard age window must be non-zero",
        )?;
        ensure(
            self.min_operator_reviewers > 0,
            "operator reviewer quorum must be non-zero",
        )?;
        ensure(
            self.min_release_coordinators > 0,
            "release coordinator quorum must be non-zero",
        )?;
        let mut seen = BTreeSet::new();
        for lane in &self.required_lanes {
            ensure(seen.insert(*lane), "duplicate dashboard lane")?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "dashboard_policy_id": self.dashboard_policy_id,
            "required_lanes": self.required_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "max_dashboard_age_blocks": self.max_dashboard_age_blocks,
            "min_operator_reviewers": self.min_operator_reviewers,
            "min_release_coordinators": self.min_release_coordinators,
            "require_imported_evidence_root": self.require_imported_evidence_root,
            "require_privacy_notices": self.require_privacy_notices,
            "require_all_actions_closed": self.require_all_actions_closed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn policy_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunbookAuditRecord {
    pub lane: DashboardLane,
    pub runbook_id: String,
    pub source_import_root: String,
    pub runbook_root: String,
    pub reviewer_root: String,
    pub action_root: String,
    pub privacy_notice_root: String,
    pub produced_at_height: u64,
    pub reviewed_at_height: u64,
    pub expires_at_height: u64,
    pub status: DashboardStatus,
}

impl RunbookAuditRecord {
    pub fn new(
        config: &Config,
        lane: DashboardLane,
        runbook_id: &str,
        produced_at_height: u64,
        reviewed_at_height: u64,
        status: DashboardStatus,
    ) -> Result<Self> {
        ensure_non_empty("runbook_id", runbook_id)?;
        ensure(
            reviewed_at_height >= produced_at_height,
            "review height must not precede production height",
        )?;
        let expires_at_height = produced_at_height.saturating_add(config.max_dashboard_age_blocks);
        let record = Self {
            lane,
            runbook_id: runbook_id.to_string(),
            source_import_root: sample_root(lane, runbook_id, "accepted-live-evidence-import"),
            runbook_root: sample_root(lane, runbook_id, "operator-runbook"),
            reviewer_root: sample_root(lane, runbook_id, "operator-review"),
            action_root: sample_root(lane, runbook_id, "dashboard-actions"),
            privacy_notice_root: if lane.requires_privacy_notice() {
                sample_root(lane, runbook_id, "privacy-notice")
            } else {
                sample_root(lane, runbook_id, "privacy-notice-not-required")
            },
            produced_at_height,
            reviewed_at_height,
            expires_at_height,
            status,
        };
        record.validate(config)?;
        Ok(record)
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("runbook_id", &self.runbook_id)?;
        ensure_root("source_import_root", &self.source_import_root)?;
        ensure_root("runbook_root", &self.runbook_root)?;
        ensure_root("reviewer_root", &self.reviewer_root)?;
        ensure_root("action_root", &self.action_root)?;
        if config.require_privacy_notices && self.lane.requires_privacy_notice() {
            ensure_root("privacy_notice_root", &self.privacy_notice_root)?;
        }
        ensure(
            self.reviewed_at_height >= self.produced_at_height,
            "review height must not precede production height",
        )?;
        ensure(
            self.expires_at_height >= self.reviewed_at_height,
            "expiry height must not precede review height",
        )?;
        Ok(())
    }

    pub fn fresh_at(&self, height: u64) -> bool {
        self.produced_at_height <= height && height <= self.expires_at_height
    }

    pub fn accepted_and_fresh_at(&self, height: u64) -> bool {
        self.status.accepted() && self.fresh_at(height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "runbook_id": self.runbook_id,
            "source_import_root": self.source_import_root,
            "runbook_root": self.runbook_root,
            "reviewer_root": self.reviewer_root,
            "action_root": self.action_root,
            "privacy_notice_root": self.privacy_notice_root,
            "produced_at_height": self.produced_at_height,
            "reviewed_at_height": self.reviewed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "module": self.lane.runbook_module(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-RUNBOOK-AUDIT-RECORD",
            &self.public_record(),
        )
    }

    pub fn dashboard_cell_root(&self) -> String {
        domain_hash(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-CELL",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.runbook_id),
                HashPart::Str(&self.source_import_root),
                HashPart::Str(&self.runbook_root),
                HashPart::Str(self.status.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardAction {
    pub action_id: String,
    pub lane: DashboardLane,
    pub owner: String,
    pub action_root: String,
    pub evidence_root: String,
    pub status: DashboardActionStatus,
    pub due_at_height: u64,
}

impl DashboardAction {
    pub fn new(
        lane: DashboardLane,
        owner: &str,
        label: &str,
        status: DashboardActionStatus,
        due_at_height: u64,
    ) -> Result<Self> {
        ensure_non_empty("owner", owner)?;
        ensure_non_empty("label", label)?;
        let action_root = sample_root(lane, label, "operator-dashboard-action");
        let evidence_root = sample_root(lane, label, "operator-dashboard-action-evidence");
        Ok(Self {
            action_id: action_id(lane, owner, label, due_at_height),
            lane,
            owner: owner.to_string(),
            action_root,
            evidence_root,
            status,
            due_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "lane": self.lane.as_str(),
            "owner": self.owner,
            "action_root": self.action_root,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "due_at_height": self.due_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-ACTION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardReviewer {
    pub reviewer_id: String,
    pub review_root: String,
    pub signed_dashboard_root: String,
    pub reviewed_at_height: u64,
}

impl DashboardReviewer {
    pub fn new(
        reviewer_id: &str,
        review_root: &str,
        signed_dashboard_root: &str,
        reviewed_at_height: u64,
    ) -> Result<Self> {
        ensure_non_empty("reviewer_id", reviewer_id)?;
        ensure_root("review_root", review_root)?;
        ensure_root("signed_dashboard_root", signed_dashboard_root)?;
        Ok(Self {
            reviewer_id: reviewer_id.to_string(),
            review_root: review_root.to_string(),
            signed_dashboard_root: signed_dashboard_root.to_string(),
            reviewed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reviewer_id": self.reviewer_id,
            "review_root": self.review_root,
            "signed_dashboard_root": self.signed_dashboard_root,
            "reviewed_at_height": self.reviewed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-REVIEWER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseCoordinator {
    pub coordinator_id: String,
    pub coordination_root: String,
    pub signed_dashboard_root: String,
    pub coordinated_at_height: u64,
}

impl ReleaseCoordinator {
    pub fn new(
        coordinator_id: &str,
        coordination_root: &str,
        signed_dashboard_root: &str,
        coordinated_at_height: u64,
    ) -> Result<Self> {
        ensure_non_empty("coordinator_id", coordinator_id)?;
        ensure_root("coordination_root", coordination_root)?;
        ensure_root("signed_dashboard_root", signed_dashboard_root)?;
        Ok(Self {
            coordinator_id: coordinator_id.to_string(),
            coordination_root: coordination_root.to_string(),
            signed_dashboard_root: signed_dashboard_root.to_string(),
            coordinated_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coordinator_id": self.coordinator_id,
            "coordination_root": self.coordination_root,
            "signed_dashboard_root": self.signed_dashboard_root,
            "coordinated_at_height": self.coordinated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-COORDINATOR",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardBlocker {
    pub blocker_id: String,
    pub lane: String,
    pub kind: DashboardBlockerKind,
    pub evidence_root: String,
    pub detail: String,
    pub observed_at_height: u64,
}

impl DashboardBlocker {
    pub fn new(
        lane: &str,
        kind: DashboardBlockerKind,
        evidence_root: &str,
        detail: &str,
        observed_at_height: u64,
    ) -> Self {
        Self {
            blocker_id: blocker_id(lane, kind, evidence_root, observed_at_height),
            lane: lane.to_string(),
            kind,
            evidence_root: evidence_root.to_string(),
            detail: detail.to_string(),
            observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "lane": self.lane,
            "kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "detail": self.detail,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-BLOCKER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub required_lanes: usize,
    pub accepted_lanes: usize,
    pub fresh_lanes: usize,
    pub closed_actions: usize,
    pub total_actions: usize,
    pub reviewer_count: usize,
    pub coordinator_count: usize,
    pub dashboard_ready: bool,
}

impl DashboardSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "required_lanes": self.required_lanes,
            "accepted_lanes": self.accepted_lanes,
            "fresh_lanes": self.fresh_lanes,
            "closed_actions": self.closed_actions,
            "total_actions": self.total_actions,
            "reviewer_count": self.reviewer_count,
            "coordinator_count": self.coordinator_count,
            "dashboard_ready": self.dashboard_ready,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-SUMMARY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub imported_evidence_root: String,
    pub final_go_no_go_root: String,
    pub release_dashboard_root: String,
    pub runbooks: BTreeMap<DashboardLane, RunbookAuditRecord>,
    pub actions: BTreeMap<String, DashboardAction>,
    pub reviewers: BTreeMap<String, DashboardReviewer>,
    pub coordinators: BTreeMap<String, ReleaseCoordinator>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            imported_evidence_root: String::new(),
            final_go_no_go_root: String::new(),
            release_dashboard_root: String::new(),
            runbooks: BTreeMap::new(),
            actions: BTreeMap::new(),
            reviewers: BTreeMap::new(),
            coordinators: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = match Self::new(config, DEFAULT_HEIGHT) {
            Ok(state) => state,
            Err(_) => Self {
                config: Config::devnet(),
                height: DEFAULT_HEIGHT,
                imported_evidence_root: String::new(),
                final_go_no_go_root: String::new(),
                release_dashboard_root: String::new(),
                runbooks: BTreeMap::new(),
                actions: BTreeMap::new(),
                reviewers: BTreeMap::new(),
                coordinators: BTreeMap::new(),
            },
        };
        state.imported_evidence_root = generic_sample_root("wave-81-imported-evidence-root");
        state.final_go_no_go_root = generic_sample_root("wave-80-final-go-no-go-root");
        for (index, lane) in DashboardLane::all().into_iter().enumerate() {
            let runbook_id = format!("devnet-{}-operator-runbook", lane.as_str());
            if let Ok(runbook) = RunbookAuditRecord::new(
                &state.config,
                lane,
                &runbook_id,
                DEFAULT_HEIGHT
                    .saturating_sub(18)
                    .saturating_add(index as u64),
                DEFAULT_HEIGHT
                    .saturating_sub(9)
                    .saturating_add(index as u64),
                DashboardStatus::Accepted,
            ) {
                let _ = state.add_runbook(runbook);
            }
            if let Ok(action) = DashboardAction::new(
                lane,
                "release-operator",
                &format!("{}-dashboard-closeout", lane.as_str()),
                DashboardActionStatus::Completed,
                DEFAULT_HEIGHT.saturating_add(16),
            ) {
                let _ = state.add_action(action);
            }
        }
        let dashboard_root = state.dashboard_root();
        state.release_dashboard_root = dashboard_root.clone();
        for index in 0..state.config.min_operator_reviewers {
            if let Ok(reviewer) = DashboardReviewer::new(
                &format!("operator-reviewer-{index}"),
                &generic_sample_root(&format!("operator-reviewer-{index}-root")),
                &dashboard_root,
                DEFAULT_HEIGHT.saturating_add(u64::from(index)),
            ) {
                let _ = state.add_reviewer(reviewer);
            }
        }
        for index in 0..state.config.min_release_coordinators {
            if let Ok(coordinator) = ReleaseCoordinator::new(
                &format!("release-coordinator-{index}"),
                &generic_sample_root(&format!("release-coordinator-{index}-root")),
                &dashboard_root,
                DEFAULT_HEIGHT
                    .saturating_add(4)
                    .saturating_add(u64::from(index)),
            ) {
                let _ = state.add_coordinator(coordinator);
            }
        }
        state
    }

    pub fn bind_imported_evidence_root(&mut self, root: &str) -> Result<()> {
        ensure_root("imported_evidence_root", root)?;
        self.imported_evidence_root = root.to_string();
        Ok(())
    }

    pub fn bind_final_go_no_go_root(&mut self, root: &str) -> Result<()> {
        ensure_root("final_go_no_go_root", root)?;
        self.final_go_no_go_root = root.to_string();
        Ok(())
    }

    pub fn bind_release_dashboard_root(&mut self, root: &str) -> Result<()> {
        ensure_root("release_dashboard_root", root)?;
        self.release_dashboard_root = root.to_string();
        Ok(())
    }

    pub fn add_runbook(&mut self, runbook: RunbookAuditRecord) -> Result<()> {
        runbook.validate(&self.config)?;
        ensure(
            self.config.required_lanes.contains(&runbook.lane),
            "runbook lane is not required by dashboard policy",
        )?;
        self.runbooks.insert(runbook.lane, runbook);
        Ok(())
    }

    pub fn add_action(&mut self, action: DashboardAction) -> Result<()> {
        ensure_non_empty("action_id", &action.action_id)?;
        ensure_root("action_root", &action.action_root)?;
        self.actions.insert(action.action_id.clone(), action);
        Ok(())
    }

    pub fn add_reviewer(&mut self, reviewer: DashboardReviewer) -> Result<()> {
        ensure_root("signed_dashboard_root", &reviewer.signed_dashboard_root)?;
        self.reviewers
            .insert(reviewer.reviewer_id.clone(), reviewer);
        Ok(())
    }

    pub fn add_coordinator(&mut self, coordinator: ReleaseCoordinator) -> Result<()> {
        ensure_root("signed_dashboard_root", &coordinator.signed_dashboard_root)?;
        self.coordinators
            .insert(coordinator.coordinator_id.clone(), coordinator);
        Ok(())
    }

    pub fn runbook_root(&self) -> String {
        map_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-RUNBOOKS",
            self.config.required_lanes.iter().map(|lane| {
                self.runbooks
                    .get(lane)
                    .map(RunbookAuditRecord::dashboard_cell_root)
                    .unwrap_or_else(|| missing_lane_root(*lane))
            }),
        )
    }

    pub fn action_root(&self) -> String {
        map_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-ACTIONS",
            self.actions.values().map(DashboardAction::state_root),
        )
    }

    pub fn reviewer_root(&self) -> String {
        map_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-REVIEWERS",
            self.reviewers.values().map(DashboardReviewer::state_root),
        )
    }

    pub fn coordinator_root(&self) -> String {
        map_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-COORDINATORS",
            self.coordinators
                .values()
                .map(ReleaseCoordinator::state_root),
        )
    }

    pub fn summary(&self) -> DashboardSummary {
        let mut accepted_lanes = 0usize;
        let mut fresh_lanes = 0usize;
        for lane in &self.config.required_lanes {
            if let Some(runbook) = self.runbooks.get(lane) {
                if runbook.status.accepted() {
                    accepted_lanes = accepted_lanes.saturating_add(1);
                }
                if runbook.accepted_and_fresh_at(self.height) {
                    fresh_lanes = fresh_lanes.saturating_add(1);
                }
            }
        }
        let closed_actions = self
            .actions
            .values()
            .filter(|action| action.status.closed())
            .count();
        let mut dashboard_ready = accepted_lanes == self.config.required_lanes.len()
            && fresh_lanes == self.config.required_lanes.len()
            && self.reviewers.len() >= usize::from(self.config.min_operator_reviewers)
            && self.coordinators.len() >= usize::from(self.config.min_release_coordinators)
            && !self.release_dashboard_root.is_empty();
        if self.config.require_all_actions_closed {
            dashboard_ready = dashboard_ready && closed_actions == self.actions.len();
        }
        if self.config.require_imported_evidence_root {
            dashboard_ready = dashboard_ready && !self.imported_evidence_root.is_empty();
        }
        DashboardSummary {
            required_lanes: self.config.required_lanes.len(),
            accepted_lanes,
            fresh_lanes,
            closed_actions,
            total_actions: self.actions.len(),
            reviewer_count: self.reviewers.len(),
            coordinator_count: self.coordinators.len(),
            dashboard_ready,
        }
    }

    pub fn blockers(&self) -> Vec<DashboardBlocker> {
        let mut blockers = Vec::new();
        for lane in &self.config.required_lanes {
            match self.runbooks.get(lane) {
                Some(runbook) => {
                    if !runbook.fresh_at(self.height) {
                        blockers.push(DashboardBlocker::new(
                            lane.as_str(),
                            DashboardBlockerKind::ExpiredRunbook,
                            &runbook.state_root(),
                            "runbook audit record has exceeded the dashboard freshness window",
                            self.height,
                        ));
                    }
                    match runbook.status {
                        DashboardStatus::Missing => blockers.push(DashboardBlocker::new(
                            lane.as_str(),
                            DashboardBlockerKind::MissingRunbook,
                            &runbook.state_root(),
                            "runbook audit record reports missing runbook evidence",
                            self.height,
                        )),
                        DashboardStatus::Draft | DashboardStatus::ReviewPending => {
                            blockers.push(DashboardBlocker::new(
                                lane.as_str(),
                                DashboardBlockerKind::ReviewPending,
                                &runbook.state_root(),
                                "runbook audit record is not accepted by operator review",
                                self.height,
                            ))
                        }
                        DashboardStatus::Rejected => blockers.push(DashboardBlocker::new(
                            lane.as_str(),
                            DashboardBlockerKind::RejectedRunbook,
                            &runbook.state_root(),
                            "operator runbook was rejected",
                            self.height,
                        )),
                        DashboardStatus::Expired => blockers.push(DashboardBlocker::new(
                            lane.as_str(),
                            DashboardBlockerKind::ExpiredRunbook,
                            &runbook.state_root(),
                            "operator runbook status is expired",
                            self.height,
                        )),
                        DashboardStatus::Accepted => {}
                    }
                    if self.config.require_privacy_notices
                        && lane.requires_privacy_notice()
                        && runbook.privacy_notice_root.is_empty()
                    {
                        blockers.push(DashboardBlocker::new(
                            lane.as_str(),
                            DashboardBlockerKind::MissingPrivacyNotice,
                            &runbook.state_root(),
                            "privacy-sensitive lane requires a dashboard privacy notice root",
                            self.height,
                        ));
                    }
                }
                None => blockers.push(DashboardBlocker::new(
                    lane.as_str(),
                    DashboardBlockerKind::MissingRunbook,
                    &missing_lane_root(*lane),
                    "required lane has no operator runbook audit record",
                    self.height,
                )),
            }
        }
        for action in self.actions.values() {
            if self.config.require_all_actions_closed && !action.status.closed() {
                blockers.push(DashboardBlocker::new(
                    action.lane.as_str(),
                    DashboardBlockerKind::OpenAction,
                    &action.state_root(),
                    "operator dashboard action is not closed",
                    self.height,
                ));
            }
        }
        if self.config.require_imported_evidence_root && self.imported_evidence_root.is_empty() {
            blockers.push(DashboardBlocker::new(
                "release_dashboard",
                DashboardBlockerKind::MissingImportedEvidence,
                &self.config.policy_root(),
                "accepted live-evidence import root must be bound before dashboard finalization",
                self.height,
            ));
        }
        if self.release_dashboard_root.is_empty() {
            blockers.push(DashboardBlocker::new(
                "release_dashboard",
                DashboardBlockerKind::MissingDashboardRoot,
                &self.config.policy_root(),
                "release dashboard root must be published before finalization",
                self.height,
            ));
        }
        if self.reviewers.len() < usize::from(self.config.min_operator_reviewers) {
            blockers.push(DashboardBlocker::new(
                "operator_review",
                DashboardBlockerKind::MissingOperatorReview,
                &self.runbook_root(),
                "operator reviewer quorum is below dashboard policy",
                self.height,
            ));
        }
        if self.coordinators.len() < usize::from(self.config.min_release_coordinators) {
            blockers.push(DashboardBlocker::new(
                "release_coordination",
                DashboardBlockerKind::MissingReleaseCoordinator,
                &self.runbook_root(),
                "release coordinator quorum is below dashboard policy",
                self.height,
            ));
        }
        blockers
    }

    pub fn blocker_root(&self) -> String {
        map_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-BLOCKERS",
            self.blockers().iter().map(DashboardBlocker::state_root),
        )
    }

    pub fn dashboard_root(&self) -> String {
        domain_hash(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.imported_evidence_root),
                HashPart::Str(&self.final_go_no_go_root),
                HashPart::Str(&self.runbook_root()),
                HashPart::Str(&self.action_root()),
                HashPart::Int(self.height as i128),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let summary = self.summary();
        let blockers = self.blockers();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "imported_evidence_root": self.imported_evidence_root,
            "final_go_no_go_root": self.final_go_no_go_root,
            "release_dashboard_root": self.release_dashboard_root,
            "runbook_root": self.runbook_root(),
            "action_root": self.action_root(),
            "reviewer_root": self.reviewer_root(),
            "coordinator_root": self.coordinator_root(),
            "blocker_root": self.blocker_root(),
            "summary": summary.public_record(),
            "runbooks": self.runbooks.values().map(RunbookAuditRecord::public_record).collect::<Vec<_>>(),
            "actions": self.actions.values().map(DashboardAction::public_record).collect::<Vec<_>>(),
            "reviewers": self.reviewers.values().map(DashboardReviewer::public_record).collect::<Vec<_>>(),
            "coordinators": self.coordinators.values().map(ReleaseCoordinator::public_record).collect::<Vec<_>>(),
            "blockers": blockers.iter().map(DashboardBlocker::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "RELEASE-POLICY-OPERATOR-DASHBOARD-FINALIZATION-STATE",
            &self.public_record(),
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

pub fn dashboard_root() -> String {
    devnet().dashboard_root()
}

fn dashboard_policy_id(label: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-OPERATOR-DASHBOARD-POLICY-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn action_id(lane: DashboardLane, owner: &str, label: &str, due_at_height: u64) -> String {
    domain_hash(
        "RELEASE-POLICY-OPERATOR-DASHBOARD-ACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(owner),
            HashPart::Str(label),
            HashPart::Int(due_at_height as i128),
        ],
        32,
    )
}

fn blocker_id(
    lane: &str,
    kind: DashboardBlockerKind,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "RELEASE-POLICY-OPERATOR-DASHBOARD-BLOCKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn missing_lane_root(lane: DashboardLane) -> String {
    domain_hash(
        "RELEASE-POLICY-OPERATOR-DASHBOARD-MISSING-LANE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
        ],
        32,
    )
}

fn sample_root(lane: DashboardLane, item: &str, label: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-OPERATOR-DASHBOARD-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(item),
            HashPart::Str(label),
        ],
        32,
    )
}

fn generic_sample_root(label: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-OPERATOR-DASHBOARD-DEVNET-GENERIC",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
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
