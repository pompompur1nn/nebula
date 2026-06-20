use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReleasePolicyAcceptedLiveEvidenceOperatorDashboardReleaseHoldUnholdDeploymentGuardRuntimeResult<
    T,
> = Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_HOLD_UNHOLD_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-force-exit-release-policy-accepted-live-evidence-operator-dashboard-release-hold-unhold-deployment-guard-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_HOLD_UNHOLD_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_HEIGHT: u64 = 95_000;
pub const DEFAULT_MAX_GUARD_AGE_BLOCKS: u64 = 64;
pub const DEFAULT_MIN_DEPLOYMENT_COORDINATOR_WEIGHT: u64 = 75;
pub const DEFAULT_MIN_LANE_GUARD_SCORE: u64 = 93;
pub const DEFAULT_MIN_ROLLBACK_SCORE: u64 = 95;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentGuardLane {
    CompileRuntime,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
}

impl DeploymentGuardLane {
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

    pub fn deployment_guard_module(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime_dashboard_release_policy_deployment_guard",
            Self::RuntimeReplay => "runtime_replay_dashboard_release_policy_deployment_guard",
            Self::AuditSecurity => "audit_security_dashboard_release_policy_deployment_guard",
            Self::BridgeCustody => "bridge_custody_dashboard_release_policy_deployment_guard",
            Self::WalletWatchtower => "wallet_watchtower_dashboard_release_policy_deployment_guard",
            Self::PqReservePrivacy => {
                "pq_reserve_privacy_dashboard_release_policy_deployment_guard"
            }
        }
    }

    pub fn production_risks(self) -> Vec<&'static str> {
        match self {
            Self::CompileRuntime => vec![
                "cargo_check_deferred",
                "cargo_test_deferred",
                "clippy_deferred",
                "rustfmt_receipt_only",
            ],
            Self::RuntimeReplay => vec![
                "replay_runtime_not_executed",
                "observed_receipts_deferred",
                "mismatch_run_deferred",
                "live_replay_window_unproven",
            ],
            Self::AuditSecurity => vec![
                "external_audit_deferred",
                "adversarial_review_deferred",
                "privacy_audit_deferred",
                "finding_replay_deferred",
            ],
            Self::BridgeCustody => vec![
                "custody_ceremony_deferred",
                "monero_release_observation_deferred",
                "reserve_handoff_deferred",
                "challenge_window_live_run_deferred",
            ],
            Self::WalletWatchtower => vec![
                "wallet_scan_live_run_deferred",
                "watchtower_replay_deferred",
                "user_escape_drill_deferred",
                "freshness_window_unproven",
            ],
            Self::PqReservePrivacy => vec![
                "pq_rotation_live_run_deferred",
                "reserve_coverage_live_run_deferred",
                "privacy_boundary_audit_deferred",
                "metadata_regression_deferred",
            ],
        }
    }

    pub fn requires_privacy_boundary(self) -> bool {
        matches!(
            self,
            Self::AuditSecurity | Self::WalletWatchtower | Self::PqReservePrivacy
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentGuardStatus {
    Missing,
    Draft,
    Hold,
    UnholdCandidate,
    Unheld,
    Rejected,
    Expired,
}

impl DeploymentGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Draft => "draft",
            Self::Hold => "hold",
            Self::UnholdCandidate => "unhold_candidate",
            Self::Unheld => "unheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn allows_deployment(self) -> bool {
        matches!(self, Self::Unheld)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatorVote {
    Pending,
    ApproveDeployment,
    HoldDeployment,
    RejectDeployment,
}

impl CoordinatorVote {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ApproveDeployment => "approve_deployment",
            Self::HoldDeployment => "hold_deployment",
            Self::RejectDeployment => "reject_deployment",
        }
    }

    pub fn approving(self) -> bool {
        matches!(self, Self::ApproveDeployment)
    }

    pub fn blocking(self) -> bool {
        matches!(self, Self::HoldDeployment | Self::RejectDeployment)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentBlockerKind {
    MissingLaneGuard,
    DuplicateLaneGuard,
    StaleLaneGuard,
    LaneStillHeld,
    LaneRejected,
    LaneScoreTooLow,
    RollbackScoreTooLow,
    MissingGoNoGoRoot,
    MissingDeploymentWindowRoot,
    MissingRollbackRoot,
    MissingAbortRoot,
    MissingOperatorAcknowledgementRoot,
    MissingPrivacyBoundaryRoot,
    CoordinatorWeightTooLow,
    CoordinatorHold,
    CoordinatorReject,
    EmergencyHoldActive,
    HeavyGateDeferred,
    ProductionReadinessDeferred,
}

impl DeploymentBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLaneGuard => "missing_lane_guard",
            Self::DuplicateLaneGuard => "duplicate_lane_guard",
            Self::StaleLaneGuard => "stale_lane_guard",
            Self::LaneStillHeld => "lane_still_held",
            Self::LaneRejected => "lane_rejected",
            Self::LaneScoreTooLow => "lane_score_too_low",
            Self::RollbackScoreTooLow => "rollback_score_too_low",
            Self::MissingGoNoGoRoot => "missing_go_no_go_root",
            Self::MissingDeploymentWindowRoot => "missing_deployment_window_root",
            Self::MissingRollbackRoot => "missing_rollback_root",
            Self::MissingAbortRoot => "missing_abort_root",
            Self::MissingOperatorAcknowledgementRoot => "missing_operator_acknowledgement_root",
            Self::MissingPrivacyBoundaryRoot => "missing_privacy_boundary_root",
            Self::CoordinatorWeightTooLow => "coordinator_weight_too_low",
            Self::CoordinatorHold => "coordinator_hold",
            Self::CoordinatorReject => "coordinator_reject",
            Self::EmergencyHoldActive => "emergency_hold_active",
            Self::HeavyGateDeferred => "heavy_gate_deferred",
            Self::ProductionReadinessDeferred => "production_readiness_deferred",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub deployment_policy_id: String,
    pub required_lanes: Vec<DeploymentGuardLane>,
    pub max_guard_age_blocks: u64,
    pub min_deployment_coordinator_weight: u64,
    pub min_lane_guard_score: u64,
    pub min_rollback_score: u64,
    pub require_go_no_go_root: bool,
    pub require_deployment_window_root: bool,
    pub require_rollback_root: bool,
    pub require_abort_root: bool,
    pub require_operator_acknowledgement_root: bool,
    pub require_privacy_boundary_roots: bool,
    pub keep_release_held_while_heavy_gates_deferred: bool,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            deployment_policy_id: deployment_policy_id("devnet-release-hold-unhold-guard"),
            required_lanes: DeploymentGuardLane::all(),
            max_guard_age_blocks: DEFAULT_MAX_GUARD_AGE_BLOCKS,
            min_deployment_coordinator_weight: DEFAULT_MIN_DEPLOYMENT_COORDINATOR_WEIGHT,
            min_lane_guard_score: DEFAULT_MIN_LANE_GUARD_SCORE,
            min_rollback_score: DEFAULT_MIN_ROLLBACK_SCORE,
            require_go_no_go_root: true,
            require_deployment_window_root: true,
            require_rollback_root: true,
            require_abort_root: true,
            require_operator_acknowledgement_root: true,
            require_privacy_boundary_roots: true,
            keep_release_held_while_heavy_gates_deferred: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("deployment_policy_id", &self.deployment_policy_id)?;
        ensure(
            !self.required_lanes.is_empty(),
            "at least one deployment guard lane is required",
        )?;
        ensure(
            self.max_guard_age_blocks > 0,
            "deployment guard age window must be non-zero",
        )?;
        ensure(
            self.min_deployment_coordinator_weight > 0,
            "deployment coordinator weight must be non-zero",
        )?;
        ensure(
            self.min_lane_guard_score > 0,
            "lane guard score threshold must be non-zero",
        )?;
        ensure(
            self.min_rollback_score > 0,
            "rollback score threshold must be non-zero",
        )?;
        let mut seen = BTreeSet::new();
        for lane in &self.required_lanes {
            ensure(
                seen.insert(*lane),
                "duplicate required deployment guard lane",
            )?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "deployment_policy_id": self.deployment_policy_id,
            "required_lanes": self.required_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "max_guard_age_blocks": self.max_guard_age_blocks,
            "min_deployment_coordinator_weight": self.min_deployment_coordinator_weight,
            "min_lane_guard_score": self.min_lane_guard_score,
            "min_rollback_score": self.min_rollback_score,
            "require_go_no_go_root": self.require_go_no_go_root,
            "require_deployment_window_root": self.require_deployment_window_root,
            "require_rollback_root": self.require_rollback_root,
            "require_abort_root": self.require_abort_root,
            "require_operator_acknowledgement_root": self.require_operator_acknowledgement_root,
            "require_privacy_boundary_roots": self.require_privacy_boundary_roots,
            "keep_release_held_while_heavy_gates_deferred": self.keep_release_held_while_heavy_gates_deferred,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "release-hold-unhold-deployment-guard-config",
            &[
                HashPart::Str(&self.deployment_policy_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneDeploymentGuard {
    pub lane: DeploymentGuardLane,
    pub guard_id: String,
    pub go_no_go_binding_root: String,
    pub deployment_window_root: String,
    pub rollback_root: String,
    pub abort_root: String,
    pub operator_acknowledgement_root: String,
    pub privacy_boundary_root: String,
    pub heavy_gate_receipt_root: String,
    pub deferred_risk_roots: BTreeMap<String, String>,
    pub status: DeploymentGuardStatus,
    pub lane_guard_score: u64,
    pub rollback_score: u64,
    pub observed_at_height: u64,
    pub release_hold_reason: String,
}

impl LaneDeploymentGuard {
    pub fn new(
        lane: DeploymentGuardLane,
        guard_id: impl Into<String>,
        observed_at_height: u64,
    ) -> Self {
        let guard_id = guard_id.into();
        let deferred_risk_roots = lane
            .production_risks()
            .into_iter()
            .map(|risk| (risk.to_string(), guard_root(lane, &guard_id, risk)))
            .collect::<BTreeMap<_, _>>();
        Self {
            lane,
            guard_id: guard_id.clone(),
            go_no_go_binding_root: guard_root(lane, &guard_id, "go-no-go-binding"),
            deployment_window_root: guard_root(lane, &guard_id, "deployment-window"),
            rollback_root: guard_root(lane, &guard_id, "rollback-plan"),
            abort_root: guard_root(lane, &guard_id, "abort-plan"),
            operator_acknowledgement_root: guard_root(lane, &guard_id, "operator-ack"),
            privacy_boundary_root: guard_root(lane, &guard_id, "privacy-boundary"),
            heavy_gate_receipt_root: String::new(),
            deferred_risk_roots,
            status: DeploymentGuardStatus::Hold,
            lane_guard_score: DEFAULT_MIN_LANE_GUARD_SCORE + 1,
            rollback_score: DEFAULT_MIN_ROLLBACK_SCORE,
            observed_at_height,
            release_hold_reason: format!(
                "{} deployment remains held until heavy gates and live receipts clear",
                lane.as_str()
            ),
        }
    }

    pub fn unheld_candidate(mut self) -> Self {
        self.status = DeploymentGuardStatus::UnholdCandidate;
        self
    }

    pub fn with_heavy_gate_receipt(mut self, receipt_root: impl Into<String>) -> Self {
        self.heavy_gate_receipt_root = receipt_root.into();
        if !self.heavy_gate_receipt_root.is_empty() {
            self.status = DeploymentGuardStatus::Unheld;
            self.release_hold_reason =
                "heavy-gate receipt root is present and lane guard can unhold".to_string();
        }
        self
    }

    pub fn stale(&self, height: u64, max_age: u64) -> bool {
        height.saturating_sub(self.observed_at_height) > max_age
    }

    pub fn missing_required_roots(&self, config: &Config) -> Vec<DeploymentBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_go_no_go_root && self.go_no_go_binding_root.is_empty() {
            blockers.push(DeploymentBlockerKind::MissingGoNoGoRoot);
        }
        if config.require_deployment_window_root && self.deployment_window_root.is_empty() {
            blockers.push(DeploymentBlockerKind::MissingDeploymentWindowRoot);
        }
        if config.require_rollback_root && self.rollback_root.is_empty() {
            blockers.push(DeploymentBlockerKind::MissingRollbackRoot);
        }
        if config.require_abort_root && self.abort_root.is_empty() {
            blockers.push(DeploymentBlockerKind::MissingAbortRoot);
        }
        if config.require_operator_acknowledgement_root
            && self.operator_acknowledgement_root.is_empty()
        {
            blockers.push(DeploymentBlockerKind::MissingOperatorAcknowledgementRoot);
        }
        if config.require_privacy_boundary_roots
            && self.lane.requires_privacy_boundary()
            && self.privacy_boundary_root.is_empty()
        {
            blockers.push(DeploymentBlockerKind::MissingPrivacyBoundaryRoot);
        }
        blockers
    }

    pub fn blockers(&self, config: &Config, height: u64) -> Vec<DeploymentBlockerKind> {
        let mut blockers = self.missing_required_roots(config);
        if self.stale(height, config.max_guard_age_blocks) {
            blockers.push(DeploymentBlockerKind::StaleLaneGuard);
        }
        match self.status {
            DeploymentGuardStatus::Unheld => {}
            DeploymentGuardStatus::Rejected => blockers.push(DeploymentBlockerKind::LaneRejected),
            _ => blockers.push(DeploymentBlockerKind::LaneStillHeld),
        }
        if self.lane_guard_score < config.min_lane_guard_score {
            blockers.push(DeploymentBlockerKind::LaneScoreTooLow);
        }
        if self.rollback_score < config.min_rollback_score {
            blockers.push(DeploymentBlockerKind::RollbackScoreTooLow);
        }
        if config.keep_release_held_while_heavy_gates_deferred
            && self.heavy_gate_receipt_root.is_empty()
        {
            blockers.push(DeploymentBlockerKind::HeavyGateDeferred);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "deployment_guard_module": self.lane.deployment_guard_module(),
            "guard_id": self.guard_id,
            "go_no_go_binding_root": self.go_no_go_binding_root,
            "deployment_window_root": self.deployment_window_root,
            "rollback_root": self.rollback_root,
            "abort_root": self.abort_root,
            "operator_acknowledgement_root": self.operator_acknowledgement_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "heavy_gate_receipt_root": self.heavy_gate_receipt_root,
            "deferred_risk_roots": self.deferred_risk_roots,
            "status": self.status.as_str(),
            "lane_guard_score": self.lane_guard_score,
            "rollback_score": self.rollback_score,
            "observed_at_height": self.observed_at_height,
            "release_hold_reason": self.release_hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "release-hold-unhold-deployment-guard-lane",
            &[
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.guard_id),
                HashPart::U64(self.observed_at_height),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentCoordinator {
    pub coordinator_id: String,
    pub vote: CoordinatorVote,
    pub approval_weight: u64,
    pub signed_guard_root: String,
    pub signed_rollback_root: String,
    pub signed_at_height: u64,
    pub note: String,
}

impl DeploymentCoordinator {
    pub fn approval(
        coordinator_id: impl Into<String>,
        approval_weight: u64,
        signed_at_height: u64,
    ) -> Self {
        let coordinator_id = coordinator_id.into();
        Self {
            coordinator_id: coordinator_id.clone(),
            vote: CoordinatorVote::ApproveDeployment,
            approval_weight,
            signed_guard_root: coordinator_root(&coordinator_id, signed_at_height, "guard"),
            signed_rollback_root: coordinator_root(&coordinator_id, signed_at_height, "rollback"),
            signed_at_height,
            note: format!(
                "{coordinator_id} approves deployment guard once every lane has live heavy-gate roots"
            ),
        }
    }

    pub fn hold(coordinator_id: impl Into<String>, signed_at_height: u64) -> Self {
        let coordinator_id = coordinator_id.into();
        Self {
            coordinator_id: coordinator_id.clone(),
            vote: CoordinatorVote::HoldDeployment,
            approval_weight: 0,
            signed_guard_root: coordinator_root(&coordinator_id, signed_at_height, "hold-guard"),
            signed_rollback_root: coordinator_root(
                &coordinator_id,
                signed_at_height,
                "hold-rollback",
            ),
            signed_at_height,
            note: format!("{coordinator_id} holds deployment pending live heavy-gate receipts"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coordinator_id": self.coordinator_id,
            "vote": self.vote.as_str(),
            "approval_weight": self.approval_weight,
            "signed_guard_root": self.signed_guard_root,
            "signed_rollback_root": self.signed_rollback_root,
            "signed_at_height": self.signed_at_height,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "release-hold-unhold-deployment-guard-coordinator",
            &[
                HashPart::Str(&self.coordinator_id),
                HashPart::Str(self.vote.as_str()),
                HashPart::U64(self.approval_weight),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregateHold {
    pub hold_id: String,
    pub active: bool,
    pub reason: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
}

impl AggregateHold {
    pub fn active(hold_id: impl Into<String>, reason: impl Into<String>, height: u64) -> Self {
        let hold_id = hold_id.into();
        let reason = reason.into();
        Self {
            evidence_root: domain_hash(
                "release-hold-unhold-deployment-guard-active-hold",
                &[
                    HashPart::Str(&hold_id),
                    HashPart::Str(&reason),
                    HashPart::U64(height),
                ],
                32,
            ),
            hold_id,
            active: true,
            reason,
            opened_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "active": self.active,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "release-hold-unhold-deployment-guard-hold",
            &[
                HashPart::Str(&self.hold_id),
                HashPart::U64(self.opened_at_height),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentDecision {
    pub deployment_allowed: bool,
    pub release_held: bool,
    pub lane_count: usize,
    pub unheld_lane_count: usize,
    pub coordinator_weight: u64,
    pub blocker_count: usize,
    pub decision_root: String,
    pub lane_guard_root: String,
    pub coordinator_root: String,
    pub hold_root: String,
    pub blocker_root: String,
}

impl DeploymentDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "deployment_allowed": self.deployment_allowed,
            "release_held": self.release_held,
            "lane_count": self.lane_count,
            "unheld_lane_count": self.unheld_lane_count,
            "coordinator_weight": self.coordinator_weight,
            "blocker_count": self.blocker_count,
            "decision_root": self.decision_root,
            "lane_guard_root": self.lane_guard_root,
            "coordinator_root": self.coordinator_root,
            "hold_root": self.hold_root,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lane_guards: Vec<LaneDeploymentGuard>,
    pub deployment_coordinators: Vec<DeploymentCoordinator>,
    pub aggregate_holds: Vec<AggregateHold>,
    pub blockers: BTreeMap<String, Vec<DeploymentBlockerKind>>,
    pub lane_guard_root: String,
    pub coordinator_root: String,
    pub hold_root: String,
    pub blocker_root: String,
    pub decision: DeploymentDecision,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        lane_guards: Vec<LaneDeploymentGuard>,
        deployment_coordinators: Vec<DeploymentCoordinator>,
        aggregate_holds: Vec<AggregateHold>,
    ) -> Result<Self> {
        config.validate()?;
        let blockers = evaluate_blockers(
            &config,
            height,
            &lane_guards,
            &deployment_coordinators,
            &aggregate_holds,
        );
        let lane_guard_root = merkle_root(
            "release-hold-unhold-deployment-guard-lanes",
            &lane_guards
                .iter()
                .map(LaneDeploymentGuard::public_record)
                .collect::<Vec<_>>(),
        );
        let coordinator_root = merkle_root(
            "release-hold-unhold-deployment-guard-coordinators",
            &deployment_coordinators
                .iter()
                .map(DeploymentCoordinator::public_record)
                .collect::<Vec<_>>(),
        );
        let hold_root = merkle_root(
            "release-hold-unhold-deployment-guard-holds",
            &aggregate_holds
                .iter()
                .map(AggregateHold::public_record)
                .collect::<Vec<_>>(),
        );
        let blocker_root = merkle_root(
            "release-hold-unhold-deployment-guard-blockers",
            &blockers
                .iter()
                .map(|(subject, blockers)| {
                    json!({
                        "subject": subject,
                        "blockers": blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let unheld_lane_count = lane_guards
            .iter()
            .filter(|guard| guard.status.allows_deployment())
            .count();
        let coordinator_weight = deployment_coordinators
            .iter()
            .filter(|coordinator| coordinator.vote.approving())
            .map(|coordinator| coordinator.approval_weight)
            .sum::<u64>();
        let blocker_count = blockers.values().map(Vec::len).sum::<usize>();
        let release_held = blocker_count > 0
            || aggregate_holds.iter().any(|hold| hold.active)
            || config.fail_closed;
        let deployment_allowed = blocker_count == 0
            && unheld_lane_count == config.required_lanes.len()
            && coordinator_weight >= config.min_deployment_coordinator_weight
            && !aggregate_holds.iter().any(|hold| hold.active);
        let decision_root = domain_hash(
            "release-hold-unhold-deployment-guard-decision",
            &[
                HashPart::Str(&config.deployment_policy_id),
                HashPart::U64(height),
                HashPart::U64(unheld_lane_count as u64),
                HashPart::U64(coordinator_weight),
                HashPart::U64(blocker_count as u64),
                HashPart::Str(&lane_guard_root),
                HashPart::Str(&coordinator_root),
                HashPart::Str(&hold_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        let decision = DeploymentDecision {
            deployment_allowed,
            release_held: release_held || !deployment_allowed,
            lane_count: lane_guards.len(),
            unheld_lane_count,
            coordinator_weight,
            blocker_count,
            decision_root,
            lane_guard_root: lane_guard_root.clone(),
            coordinator_root: coordinator_root.clone(),
            hold_root: hold_root.clone(),
            blocker_root: blocker_root.clone(),
        };
        Ok(Self {
            config,
            height,
            lane_guards,
            deployment_coordinators,
            aggregate_holds,
            blockers,
            lane_guard_root,
            coordinator_root,
            hold_root,
            blocker_root,
            decision,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let lane_guards = DeploymentGuardLane::all()
            .into_iter()
            .enumerate()
            .map(|(index, lane)| {
                LaneDeploymentGuard::new(
                    lane,
                    format!("wave84-{}-deployment-guard", lane.as_str()),
                    height.saturating_sub(5 + index as u64),
                )
                .unheld_candidate()
            })
            .collect::<Vec<_>>();
        let deployment_coordinators = vec![
            DeploymentCoordinator::approval("deployment-coordinator-alpha", 30, height),
            DeploymentCoordinator::approval("deployment-coordinator-beta", 30, height),
            DeploymentCoordinator::approval("deployment-coordinator-gamma", 20, height),
        ];
        let aggregate_holds = vec![AggregateHold::active(
            "wave84-heavy-gates-deferred",
            "release remains held because cargo, runtime replay, clippy, tests, adversarial review, and audit receipts are intentionally deferred",
            height,
        )];
        match Self::new(
            config,
            height,
            lane_guards,
            deployment_coordinators,
            aggregate_holds,
        ) {
            Ok(state) => state,
            Err(_) => Self::fallback(),
        }
    }

    pub fn fallback() -> Self {
        let config = Config {
            deployment_policy_id: "fallback-release-hold-unhold-deployment-guard".to_string(),
            required_lanes: vec![DeploymentGuardLane::CompileRuntime],
            max_guard_age_blocks: DEFAULT_MAX_GUARD_AGE_BLOCKS,
            min_deployment_coordinator_weight: DEFAULT_MIN_DEPLOYMENT_COORDINATOR_WEIGHT,
            min_lane_guard_score: DEFAULT_MIN_LANE_GUARD_SCORE,
            min_rollback_score: DEFAULT_MIN_ROLLBACK_SCORE,
            require_go_no_go_root: true,
            require_deployment_window_root: true,
            require_rollback_root: true,
            require_abort_root: true,
            require_operator_acknowledgement_root: true,
            require_privacy_boundary_roots: true,
            keep_release_held_while_heavy_gates_deferred: true,
            fail_closed: true,
        };
        let lane = LaneDeploymentGuard::new(
            DeploymentGuardLane::CompileRuntime,
            "fallback-compile-runtime-deployment-guard",
            DEFAULT_HEIGHT,
        );
        let coordinator =
            DeploymentCoordinator::hold("fallback-deployment-coordinator", DEFAULT_HEIGHT);
        let hold = AggregateHold::active(
            "fallback-release-held",
            "fallback state keeps deployment held",
            DEFAULT_HEIGHT,
        );
        let lane_guard_root = merkle_root(
            "release-hold-unhold-deployment-guard-fallback-lanes",
            &[lane.public_record()],
        );
        let coordinator_root = merkle_root(
            "release-hold-unhold-deployment-guard-fallback-coordinators",
            &[coordinator.public_record()],
        );
        let hold_root = merkle_root(
            "release-hold-unhold-deployment-guard-fallback-holds",
            &[hold.public_record()],
        );
        let mut blockers = BTreeMap::new();
        blockers.insert(
            DeploymentGuardLane::CompileRuntime.as_str().to_string(),
            vec![
                DeploymentBlockerKind::LaneStillHeld,
                DeploymentBlockerKind::HeavyGateDeferred,
            ],
        );
        let blocker_root = merkle_root(
            "release-hold-unhold-deployment-guard-fallback-blockers",
            &[json!({
                "subject": DeploymentGuardLane::CompileRuntime.as_str(),
                "blockers": ["lane_still_held", "heavy_gate_deferred"],
            })],
        );
        let decision_root = domain_hash(
            "release-hold-unhold-deployment-guard-fallback-decision",
            &[
                HashPart::Str(&config.deployment_policy_id),
                HashPart::Str(&lane_guard_root),
                HashPart::Str(&coordinator_root),
                HashPart::Str(&hold_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        Self {
            config,
            height: DEFAULT_HEIGHT,
            lane_guards: vec![lane],
            deployment_coordinators: vec![coordinator],
            aggregate_holds: vec![hold],
            blockers,
            lane_guard_root: lane_guard_root.clone(),
            coordinator_root: coordinator_root.clone(),
            hold_root: hold_root.clone(),
            blocker_root: blocker_root.clone(),
            decision: DeploymentDecision {
                deployment_allowed: false,
                release_held: true,
                lane_count: 1,
                unheld_lane_count: 0,
                coordinator_weight: 0,
                blocker_count: 2,
                decision_root,
                lane_guard_root,
                coordinator_root,
                hold_root,
                blocker_root,
            },
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "lane_guard_root": self.lane_guard_root,
            "coordinator_root": self.coordinator_root,
            "hold_root": self.hold_root,
            "blocker_root": self.blocker_root,
            "decision": self.decision.public_record(),
            "lane_guards": self.lane_guards.iter().map(LaneDeploymentGuard::public_record).collect::<Vec<_>>(),
            "deployment_coordinators": self.deployment_coordinators.iter().map(DeploymentCoordinator::public_record).collect::<Vec<_>>(),
            "aggregate_holds": self.aggregate_holds.iter().map(AggregateHold::public_record).collect::<Vec<_>>(),
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
            "release-hold-unhold-deployment-guard-state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.deployment_policy_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.lane_guard_root),
                HashPart::Str(&self.coordinator_root),
                HashPart::Str(&self.hold_root),
                HashPart::Str(&self.blocker_root),
                HashPart::Str(&self.decision.decision_root),
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

fn evaluate_blockers(
    config: &Config,
    height: u64,
    lane_guards: &[LaneDeploymentGuard],
    deployment_coordinators: &[DeploymentCoordinator],
    aggregate_holds: &[AggregateHold],
) -> BTreeMap<String, Vec<DeploymentBlockerKind>> {
    let mut blockers = BTreeMap::<String, Vec<DeploymentBlockerKind>>::new();
    let mut lanes_seen = BTreeSet::new();
    for guard in lane_guards {
        let lane_key = guard.lane.as_str().to_string();
        if !lanes_seen.insert(guard.lane) {
            blockers
                .entry(lane_key.clone())
                .or_default()
                .push(DeploymentBlockerKind::DuplicateLaneGuard);
        }
        let lane_blockers = guard.blockers(config, height);
        if !lane_blockers.is_empty() {
            blockers.entry(lane_key).or_default().extend(lane_blockers);
        }
    }
    for lane in &config.required_lanes {
        if !lanes_seen.contains(lane) {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(DeploymentBlockerKind::MissingLaneGuard);
        }
    }
    let coordinator_weight = deployment_coordinators
        .iter()
        .filter(|coordinator| coordinator.vote.approving())
        .map(|coordinator| coordinator.approval_weight)
        .sum::<u64>();
    if coordinator_weight < config.min_deployment_coordinator_weight {
        blockers
            .entry("deployment_coordinator_quorum".to_string())
            .or_default()
            .push(DeploymentBlockerKind::CoordinatorWeightTooLow);
    }
    for coordinator in deployment_coordinators {
        if coordinator.vote.blocking() {
            let blocker = match coordinator.vote {
                CoordinatorVote::HoldDeployment => DeploymentBlockerKind::CoordinatorHold,
                CoordinatorVote::RejectDeployment => DeploymentBlockerKind::CoordinatorReject,
                CoordinatorVote::Pending | CoordinatorVote::ApproveDeployment => {
                    DeploymentBlockerKind::CoordinatorWeightTooLow
                }
            };
            blockers
                .entry(coordinator.coordinator_id.clone())
                .or_default()
                .push(blocker);
        }
    }
    for hold in aggregate_holds {
        if hold.active {
            blockers
                .entry(hold.hold_id.clone())
                .or_default()
                .push(DeploymentBlockerKind::EmergencyHoldActive);
            blockers
                .entry(hold.hold_id.clone())
                .or_default()
                .push(DeploymentBlockerKind::ProductionReadinessDeferred);
        }
    }
    blockers
}

fn deployment_policy_id(label: &str) -> String {
    domain_hash(
        "release-hold-unhold-deployment-guard-id",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        16,
    )
}

fn guard_root(lane: DeploymentGuardLane, guard_id: &str, domain: &str) -> String {
    domain_hash(
        "release-hold-unhold-deployment-guard-root",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(guard_id),
            HashPart::Str(domain),
        ],
        32,
    )
}

fn coordinator_root(coordinator_id: &str, height: u64, domain: &str) -> String {
    domain_hash(
        "release-hold-unhold-deployment-guard-coordinator-root",
        &[
            HashPart::Str(coordinator_id),
            HashPart::U64(height),
            HashPart::Str(domain),
        ],
        32,
    )
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{name} must not be empty"),
    )
}
