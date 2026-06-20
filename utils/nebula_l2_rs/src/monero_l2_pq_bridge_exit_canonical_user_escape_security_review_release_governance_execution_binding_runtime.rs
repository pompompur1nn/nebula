use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_canonical_user_escape_security_review_release_governance_gate_runtime as governance_gate,
    monero_l2_pq_bridge_exit_canonical_user_escape_security_review_release_hold_unhold_drill_runtime as hold_unhold_drill,
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSecurityReviewReleaseGovernanceExecutionBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_RELEASE_GOVERNANCE_EXECUTION_BINDING_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-security-review-release-governance-execution-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_RELEASE_GOVERNANCE_EXECUTION_BINDING_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-release-governance-execution-binding";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub binding_suite: String,
    pub execution_policy: String,
    pub min_execution_lanes: u64,
    pub min_guard_cases: u64,
    pub require_governance_gate: u64,
    pub require_hold_unhold_drill: u64,
    pub require_reviewer_receipt_replay: u64,
    pub require_pq_custody_authority: u64,
    pub require_wallet_escape_priority: u64,
    pub require_roots_only_outputs: u64,
    pub require_zero_linkage_exports: u64,
    pub require_pause_timelock: u64,
    pub execution_permit_count: u64,
    pub release_can_execute: u64,
    pub production_release_allowed: u64,
    pub max_linkage_exports: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            binding_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-release-governance-execution-binding-v1"
                    .to_string(),
            execution_policy: "governance-and-drill-rooted-release-held-execution-v1".to_string(),
            min_execution_lanes: 10,
            min_guard_cases: 7,
            require_governance_gate: 1,
            require_hold_unhold_drill: 1,
            require_reviewer_receipt_replay: 1,
            require_pq_custody_authority: 1,
            require_wallet_escape_priority: 1,
            require_roots_only_outputs: 1,
            require_zero_linkage_exports: 1,
            require_pause_timelock: 1,
            execution_permit_count: 0,
            release_can_execute: 0,
            production_release_allowed: 0,
            max_linkage_exports: 0,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "binding_suite": self.binding_suite,
            "execution_policy": self.execution_policy,
            "min_execution_lanes": self.min_execution_lanes,
            "min_guard_cases": self.min_guard_cases,
            "require_governance_gate": self.require_governance_gate,
            "require_hold_unhold_drill": self.require_hold_unhold_drill,
            "require_reviewer_receipt_replay": self.require_reviewer_receipt_replay,
            "require_pq_custody_authority": self.require_pq_custody_authority,
            "require_wallet_escape_priority": self.require_wallet_escape_priority,
            "require_roots_only_outputs": self.require_roots_only_outputs,
            "require_zero_linkage_exports": self.require_zero_linkage_exports,
            "require_pause_timelock": self.require_pause_timelock,
            "execution_permit_count": self.execution_permit_count,
            "release_can_execute": self.release_can_execute,
            "production_release_allowed": self.production_release_allowed,
            "max_linkage_exports": self.max_linkage_exports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLane {
    GovernanceGateSnapshot,
    HoldUnholdDrillVerdict,
    ReviewerReceiptReplay,
    PqCustodyAuthority,
    WalletEscapePriority,
    PrivacyBoundaryRoots,
    FinalGateShadow,
    EmergencyPauseTimelock,
    FailureCaseReplay,
    ReleaseDecisionSeal,
}

impl ExecutionLane {
    pub fn ordered() -> [Self; 10] {
        [
            Self::GovernanceGateSnapshot,
            Self::HoldUnholdDrillVerdict,
            Self::ReviewerReceiptReplay,
            Self::PqCustodyAuthority,
            Self::WalletEscapePriority,
            Self::PrivacyBoundaryRoots,
            Self::FinalGateShadow,
            Self::EmergencyPauseTimelock,
            Self::FailureCaseReplay,
            Self::ReleaseDecisionSeal,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GovernanceGateSnapshot => "governance_gate_snapshot",
            Self::HoldUnholdDrillVerdict => "hold_unhold_drill_verdict",
            Self::ReviewerReceiptReplay => "reviewer_receipt_replay",
            Self::PqCustodyAuthority => "pq_custody_authority",
            Self::WalletEscapePriority => "wallet_escape_priority",
            Self::PrivacyBoundaryRoots => "privacy_boundary_roots",
            Self::FinalGateShadow => "final_gate_shadow",
            Self::EmergencyPauseTimelock => "emergency_pause_timelock",
            Self::FailureCaseReplay => "failure_case_replay",
            Self::ReleaseDecisionSeal => "release_decision_seal",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::GovernanceGateSnapshot => "governance_execution_owner",
            Self::HoldUnholdDrillVerdict => "hold_unhold_drill_owner",
            Self::ReviewerReceiptReplay => "reviewer_receipt_execution_owner",
            Self::PqCustodyAuthority => "pq_custody_execution_owner",
            Self::WalletEscapePriority => "wallet_escape_execution_owner",
            Self::PrivacyBoundaryRoots => "privacy_boundary_execution_owner",
            Self::FinalGateShadow => "final_gate_execution_owner",
            Self::EmergencyPauseTimelock => "pause_timelock_execution_owner",
            Self::FailureCaseReplay => "failure_case_execution_owner",
            Self::ReleaseDecisionSeal => "release_decision_execution_owner",
        }
    }

    pub fn question(self) -> &'static str {
        match self {
            Self::GovernanceGateSnapshot => {
                "Does execution consume the governance state, governance root, and release hold root?"
            }
            Self::HoldUnholdDrillVerdict => {
                "Does execution consume the hold/unhold drill verdict and its blockers?"
            }
            Self::ReviewerReceiptReplay => {
                "Does execution replay reviewer receipt roots before release movement?"
            }
            Self::PqCustodyAuthority => {
                "Does execution bind PQ authority, custody policy, and authority crosscheck roots?"
            }
            Self::WalletEscapePriority => {
                "Does execution keep wallet escape and forced-exit replay ahead of release?"
            }
            Self::PrivacyBoundaryRoots => {
                "Does execution publish roots only and export zero linkage material?"
            }
            Self::FinalGateShadow => {
                "Does execution shadow the final gate while production release remains held?"
            }
            Self::EmergencyPauseTimelock => {
                "Does execution require emergency pause and timelock evidence?"
            }
            Self::FailureCaseReplay => {
                "Does execution replay every hostile drill case as a release hold?"
            }
            Self::ReleaseDecisionSeal => {
                "Does execution seal the release decision as held until every lane is proven?"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardCaseKind {
    PrematureExecutionRequest,
    MissingGovernanceRoot,
    MissingDrillVerdict,
    PqCustodyMismatch,
    WalletEscapeBlocked,
    MetadataDisclosureProbe,
    EmergencyPauseGap,
}

impl GuardCaseKind {
    pub fn ordered() -> [Self; 7] {
        [
            Self::PrematureExecutionRequest,
            Self::MissingGovernanceRoot,
            Self::MissingDrillVerdict,
            Self::PqCustodyMismatch,
            Self::WalletEscapeBlocked,
            Self::MetadataDisclosureProbe,
            Self::EmergencyPauseGap,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrematureExecutionRequest => "premature_execution_request",
            Self::MissingGovernanceRoot => "missing_governance_root",
            Self::MissingDrillVerdict => "missing_drill_verdict",
            Self::PqCustodyMismatch => "pq_custody_mismatch",
            Self::WalletEscapeBlocked => "wallet_escape_blocked",
            Self::MetadataDisclosureProbe => "metadata_disclosure_probe",
            Self::EmergencyPauseGap => "emergency_pause_gap",
        }
    }

    pub fn expected_response(self) -> &'static str {
        match self {
            Self::PrematureExecutionRequest => "hold_release_and_deny_execution",
            Self::MissingGovernanceRoot => "hold_release_and_rebuild_governance_root",
            Self::MissingDrillVerdict => "hold_release_and_replay_hold_unhold_drill",
            Self::PqCustodyMismatch => "hold_release_and_recheck_pq_custody_authority",
            Self::WalletEscapeBlocked => "hold_release_and_prioritize_wallet_escape",
            Self::MetadataDisclosureProbe => "hold_release_and_publish_roots_only",
            Self::EmergencyPauseGap => "hold_release_and_require_pause_timelock",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBundle {
    pub governance_gate_state_root: String,
    pub governance_root: String,
    pub governance_condition_root: String,
    pub governance_release_hold_root: String,
    pub governance_verdict_root: String,
    pub governance_release_allowed_count: u64,
    pub governance_release_hold_count: u64,
    pub governance_production_release_allowed: u64,
    pub hold_unhold_drill_state_root: String,
    pub hold_unhold_drill_root: String,
    pub hold_unhold_phase_root: String,
    pub hold_unhold_failure_case_root: String,
    pub hold_unhold_release_hold_root: String,
    pub hold_unhold_unhold_blocker_root: String,
    pub hold_unhold_verdict_root: String,
    pub hold_unhold_release_can_unhold_count: u64,
    pub hold_unhold_failure_case_count: u64,
    pub hold_unhold_roots_only_count: u64,
    pub hold_unhold_zero_linkage_count: u64,
    pub reviewer_receipt_gate_state_root: String,
    pub pq_authority_verification_state_root: String,
    pub custody_release_authority_spec_state_root: String,
    pub authority_crosscheck_state_root: String,
    pub forced_exit_dry_run_state_root: String,
    pub wallet_handoff_state_root: String,
    pub final_release_gate_state_root: String,
    pub go_no_go_matrix_root: String,
    pub source_root: String,
}

impl SourceBundle {
    pub fn devnet() -> Self {
        let governance = governance_gate::devnet();
        let drill = hold_unhold_drill::devnet();
        Self::from_states(&governance, &drill)
    }

    pub fn from_states(
        governance: &governance_gate::State,
        drill: &hold_unhold_drill::State,
    ) -> Self {
        let source_root = source_bundle_root(governance, drill);
        Self {
            governance_gate_state_root: governance.state_root(),
            governance_root: governance.governance_root.clone(),
            governance_condition_root: governance.condition_root.clone(),
            governance_release_hold_root: governance.release_hold_root.clone(),
            governance_verdict_root: governance.verdict.verdict_root.clone(),
            governance_release_allowed_count: governance.verdict.release_allowed_count,
            governance_release_hold_count: governance.verdict.release_hold_count,
            governance_production_release_allowed: governance.verdict.production_release_allowed,
            hold_unhold_drill_state_root: drill.state_root(),
            hold_unhold_drill_root: drill.drill_root.clone(),
            hold_unhold_phase_root: drill.phase_root.clone(),
            hold_unhold_failure_case_root: drill.failure_case_root.clone(),
            hold_unhold_release_hold_root: drill.release_hold_drill_root.clone(),
            hold_unhold_unhold_blocker_root: drill.unhold_blocker_root.clone(),
            hold_unhold_verdict_root: drill.verdict.verdict_root.clone(),
            hold_unhold_release_can_unhold_count: drill.verdict.release_can_unhold_count,
            hold_unhold_failure_case_count: drill.verdict.failure_case_count,
            hold_unhold_roots_only_count: drill.verdict.roots_only_count,
            hold_unhold_zero_linkage_count: drill.verdict.zero_linkage_count,
            reviewer_receipt_gate_state_root: governance
                .source_roots
                .reviewer_receipt_gate_state_root
                .clone(),
            pq_authority_verification_state_root: governance
                .source_roots
                .pq_authority_verification_state_root
                .clone(),
            custody_release_authority_spec_state_root: governance
                .source_roots
                .custody_release_authority_spec_state_root
                .clone(),
            authority_crosscheck_state_root: governance
                .source_roots
                .authority_crosscheck_state_root
                .clone(),
            forced_exit_dry_run_state_root: governance
                .source_roots
                .forced_exit_dry_run_state_root
                .clone(),
            wallet_handoff_state_root: governance.source_roots.wallet_handoff_state_root.clone(),
            final_release_gate_state_root: governance
                .source_roots
                .final_release_gate_state_root
                .clone(),
            go_no_go_matrix_root: governance.source_roots.go_no_go_matrix_root.clone(),
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "governance_gate_state_root": self.governance_gate_state_root,
            "governance_root": self.governance_root,
            "governance_condition_root": self.governance_condition_root,
            "governance_release_hold_root": self.governance_release_hold_root,
            "governance_verdict_root": self.governance_verdict_root,
            "governance_release_allowed_count": self.governance_release_allowed_count,
            "governance_release_hold_count": self.governance_release_hold_count,
            "governance_production_release_allowed": self.governance_production_release_allowed,
            "hold_unhold_drill_state_root": self.hold_unhold_drill_state_root,
            "hold_unhold_drill_root": self.hold_unhold_drill_root,
            "hold_unhold_phase_root": self.hold_unhold_phase_root,
            "hold_unhold_failure_case_root": self.hold_unhold_failure_case_root,
            "hold_unhold_release_hold_root": self.hold_unhold_release_hold_root,
            "hold_unhold_unhold_blocker_root": self.hold_unhold_unhold_blocker_root,
            "hold_unhold_verdict_root": self.hold_unhold_verdict_root,
            "hold_unhold_release_can_unhold_count": self.hold_unhold_release_can_unhold_count,
            "hold_unhold_failure_case_count": self.hold_unhold_failure_case_count,
            "hold_unhold_roots_only_count": self.hold_unhold_roots_only_count,
            "hold_unhold_zero_linkage_count": self.hold_unhold_zero_linkage_count,
            "reviewer_receipt_gate_state_root": self.reviewer_receipt_gate_state_root,
            "pq_authority_verification_state_root": self.pq_authority_verification_state_root,
            "custody_release_authority_spec_state_root": self.custody_release_authority_spec_state_root,
            "authority_crosscheck_state_root": self.authority_crosscheck_state_root,
            "forced_exit_dry_run_state_root": self.forced_exit_dry_run_state_root,
            "wallet_handoff_state_root": self.wallet_handoff_state_root,
            "final_release_gate_state_root": self.final_release_gate_state_root,
            "go_no_go_matrix_root": self.go_no_go_matrix_root,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-bundle", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBindingLane {
    pub ordinal: u64,
    pub lane: ExecutionLane,
    pub owner_lane: String,
    pub question: String,
    pub source_root: String,
    pub evidence_root: String,
    pub execution_blocker_root: String,
    pub pq_control_root: String,
    pub wallet_escape_root: String,
    pub privacy_output_root: String,
    pub release_hold_root: String,
    pub decision_root: String,
    pub execution_permitted: u64,
    pub release_must_remain_held: u64,
    pub linkage_exports_allowed: u64,
    pub lane_root: String,
}

impl ExecutionBindingLane {
    pub fn devnet(
        config: &Config,
        source: &SourceBundle,
        lane: ExecutionLane,
        ordinal: u64,
    ) -> Self {
        let source_root = lane_source_root(source, lane);
        let evidence_root = lane_evidence_root(config, source, lane, &source_root);
        let execution_blocker_root =
            lane_execution_blocker_root(config, source, lane, &evidence_root);
        let pq_control_root = lane_pq_control_root(config, source, lane, &evidence_root);
        let wallet_escape_root = lane_wallet_escape_root(config, source, lane, &evidence_root);
        let privacy_output_root = lane_privacy_output_root(config, source, lane, &evidence_root);
        let release_hold_root = lane_release_hold_root(
            config,
            source,
            lane,
            &execution_blocker_root,
            &privacy_output_root,
        );
        let decision_root = lane_decision_root(
            config,
            source,
            lane,
            &execution_blocker_root,
            &pq_control_root,
            &wallet_escape_root,
            &privacy_output_root,
            &release_hold_root,
        );
        let lane_root = lane_root(
            config,
            source,
            lane,
            ordinal,
            &source_root,
            &evidence_root,
            &execution_blocker_root,
            &release_hold_root,
            &decision_root,
        );

        Self {
            ordinal,
            lane,
            owner_lane: lane.owner_lane().to_string(),
            question: lane.question().to_string(),
            source_root,
            evidence_root,
            execution_blocker_root,
            pq_control_root,
            wallet_escape_root,
            privacy_output_root,
            release_hold_root,
            decision_root,
            execution_permitted: config.release_can_execute,
            release_must_remain_held: 1,
            linkage_exports_allowed: config.max_linkage_exports,
            lane_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "lane": self.lane.as_str(),
            "owner_lane": self.owner_lane,
            "question": self.question,
            "source_root": self.source_root,
            "evidence_root": self.evidence_root,
            "execution_blocker_root": self.execution_blocker_root,
            "pq_control_root": self.pq_control_root,
            "wallet_escape_root": self.wallet_escape_root,
            "privacy_output_root": self.privacy_output_root,
            "release_hold_root": self.release_hold_root,
            "decision_root": self.decision_root,
            "execution_permitted": self.execution_permitted,
            "release_must_remain_held": self.release_must_remain_held,
            "linkage_exports_allowed": self.linkage_exports_allowed,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardCase {
    pub ordinal: u64,
    pub kind: GuardCaseKind,
    pub expected_response: String,
    pub trigger_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub recovery_root: String,
    pub execution_permitted: u64,
    pub guard_case_root: String,
}

impl GuardCase {
    pub fn devnet(
        config: &Config,
        source: &SourceBundle,
        kind: GuardCaseKind,
        ordinal: u64,
    ) -> Self {
        let trigger_root = guard_trigger_root(config, source, kind);
        let source_root = guard_source_root(config, source, kind, &trigger_root);
        let blocker_root = guard_blocker_root(config, source, kind, &source_root);
        let recovery_root = guard_recovery_root(config, source, kind, &blocker_root);
        let guard_case_root = guard_case_root(
            config,
            source,
            kind,
            ordinal,
            &trigger_root,
            &source_root,
            &blocker_root,
            &recovery_root,
        );

        Self {
            ordinal,
            kind,
            expected_response: kind.expected_response().to_string(),
            trigger_root,
            source_root,
            blocker_root,
            recovery_root,
            execution_permitted: config.release_can_execute,
            guard_case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "kind": self.kind.as_str(),
            "expected_response": self.expected_response,
            "trigger_root": self.trigger_root,
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "recovery_root": self.recovery_root,
            "execution_permitted": self.execution_permitted,
            "guard_case_root": self.guard_case_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBindingVerdict {
    pub lane_count: u64,
    pub guard_case_count: u64,
    pub execution_permitted_count: u64,
    pub release_hold_count: u64,
    pub guard_block_count: u64,
    pub zero_linkage_count: u64,
    pub production_release_allowed: u64,
    pub drill_unhold_count: u64,
    pub governance_unhold_count: u64,
    pub binding_status: String,
    pub verdict_root: String,
}

impl ExecutionBindingVerdict {
    pub fn new(
        config: &Config,
        source: &SourceBundle,
        lanes: &[ExecutionBindingLane],
        guards: &[GuardCase],
    ) -> Self {
        let lane_count = lanes.len() as u64;
        let guard_case_count = guards.len() as u64;
        let execution_permitted_count = lanes
            .iter()
            .filter(|lane| lane.execution_permitted == 1)
            .count() as u64;
        let release_hold_count = lanes
            .iter()
            .filter(|lane| lane.release_must_remain_held == 1)
            .count() as u64;
        let guard_block_count = guards
            .iter()
            .filter(|guard| guard.execution_permitted == 0)
            .count() as u64;
        let zero_linkage_count = lanes
            .iter()
            .filter(|lane| lane.linkage_exports_allowed <= config.max_linkage_exports)
            .count() as u64;
        let production_release_allowed = config.production_release_allowed;
        let drill_unhold_count = source.hold_unhold_release_can_unhold_count;
        let governance_unhold_count = source.governance_release_allowed_count;
        let binding_status = if lane_count >= config.min_execution_lanes
            && guard_case_count >= config.min_guard_cases
            && execution_permitted_count == config.execution_permit_count
            && release_hold_count == lane_count
            && guard_block_count == guard_case_count
            && zero_linkage_count == lane_count
            && production_release_allowed == 0
            && drill_unhold_count == 0
            && governance_unhold_count == 0
        {
            "release_governance_execution_binding_ready_release_held"
        } else {
            "release_governance_execution_binding_gap_release_held"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.execution_policy),
                HashPart::Str(&source.governance_root),
                HashPart::Str(&source.hold_unhold_drill_root),
                HashPart::U64(lane_count),
                HashPart::U64(guard_case_count),
                HashPart::U64(execution_permitted_count),
                HashPart::U64(release_hold_count),
                HashPart::U64(guard_block_count),
                HashPart::U64(zero_linkage_count),
                HashPart::U64(production_release_allowed),
                HashPart::U64(drill_unhold_count),
                HashPart::U64(governance_unhold_count),
                HashPart::Str(&binding_status),
            ],
            32,
        );

        Self {
            lane_count,
            guard_case_count,
            execution_permitted_count,
            release_hold_count,
            guard_block_count,
            zero_linkage_count,
            production_release_allowed,
            drill_unhold_count,
            governance_unhold_count,
            binding_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let binding_status =
            "release_governance_execution_binding_construction_gap_release_held".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.execution_policy),
                HashPart::Str(reason),
                HashPart::Str(&binding_status),
            ],
            32,
        );

        Self {
            lane_count: 0,
            guard_case_count: 0,
            execution_permitted_count: 0,
            release_hold_count: 1,
            guard_block_count: 1,
            zero_linkage_count: 0,
            production_release_allowed: 0,
            drill_unhold_count: 0,
            governance_unhold_count: 0,
            binding_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "guard_case_count": self.guard_case_count,
            "execution_permitted_count": self.execution_permitted_count,
            "release_hold_count": self.release_hold_count,
            "guard_block_count": self.guard_block_count,
            "zero_linkage_count": self.zero_linkage_count,
            "production_release_allowed": self.production_release_allowed,
            "drill_unhold_count": self.drill_unhold_count,
            "governance_unhold_count": self.governance_unhold_count,
            "binding_status": self.binding_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source: SourceBundle,
    pub lanes: Vec<ExecutionBindingLane>,
    pub guard_cases: Vec<GuardCase>,
    pub verdict: ExecutionBindingVerdict,
    pub lane_root: String,
    pub guard_case_root: String,
    pub execution_hold_root: String,
    pub execution_blocker_root: String,
    pub execution_binding_root: String,
}

impl State {
    pub fn new(config: Config, source: SourceBundle) -> Result<Self> {
        validate_config(&config)?;
        validate_source(&config, &source)?;
        let lanes = ExecutionLane::ordered()
            .iter()
            .enumerate()
            .map(|(index, lane)| {
                ExecutionBindingLane::devnet(&config, &source, *lane, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let guard_cases = GuardCaseKind::ordered()
            .iter()
            .enumerate()
            .map(|(index, kind)| GuardCase::devnet(&config, &source, *kind, index as u64 + 1))
            .collect::<Vec<_>>();
        let verdict = ExecutionBindingVerdict::new(&config, &source, &lanes, &guard_cases);
        let lane_root = lane_vector_root(&lanes);
        let guard_case_root = guard_case_vector_root(&guard_cases);
        let execution_hold_root =
            aggregate_execution_hold_root(&config, &source, &lane_root, &guard_case_root, &verdict);
        let execution_blocker_root =
            aggregate_execution_blocker_root(&config, &source, &lanes, &guard_cases, &verdict);
        let execution_binding_root = execution_binding_root(
            &config,
            &source,
            &lane_root,
            &guard_case_root,
            &execution_hold_root,
            &execution_blocker_root,
            &verdict,
        );

        Ok(Self {
            config,
            source,
            lanes,
            guard_cases,
            verdict,
            lane_root,
            guard_case_root,
            execution_hold_root,
            execution_blocker_root,
            execution_binding_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), SourceBundle::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_security_review_release_governance_execution_binding_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source": self.source.public_record(),
            "lane_root": self.lane_root,
            "guard_case_root": self.guard_case_root,
            "execution_hold_root": self.execution_hold_root,
            "execution_blocker_root": self.execution_blocker_root,
            "execution_binding_root": self.execution_binding_root,
            "verdict": self.verdict.public_record(),
            "lanes": self
                .lanes
                .iter()
                .map(ExecutionBindingLane::public_record)
                .collect::<Vec<_>>(),
            "guard_cases": self
                .guard_cases
                .iter()
                .map(GuardCase::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "source_root": self.source.state_root(),
                "lane_root": self.lane_root,
                "guard_case_root": self.guard_case_root,
                "execution_hold_root": self.execution_hold_root,
                "execution_blocker_root": self.execution_blocker_root,
                "execution_binding_root": self.execution_binding_root,
                "verdict_root": self.verdict.verdict_root,
            }),
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

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("release execution binding config chain id mismatch".to_string());
    }
    if config.min_execution_lanes < ExecutionLane::ordered().len() as u64 {
        return Err("release execution binding requires every lane".to_string());
    }
    if config.min_guard_cases < GuardCaseKind::ordered().len() as u64 {
        return Err("release execution binding requires every guard case".to_string());
    }
    if config.require_governance_gate != 1 {
        return Err("release execution binding requires governance gate".to_string());
    }
    if config.require_hold_unhold_drill != 1 {
        return Err("release execution binding requires hold/unhold drill".to_string());
    }
    if config.require_reviewer_receipt_replay != 1 {
        return Err("release execution binding requires reviewer receipt replay".to_string());
    }
    if config.require_pq_custody_authority != 1 {
        return Err("release execution binding requires pq custody authority".to_string());
    }
    if config.require_wallet_escape_priority != 1 {
        return Err("release execution binding requires wallet escape priority".to_string());
    }
    if config.require_roots_only_outputs != 1 {
        return Err("release execution binding requires roots only outputs".to_string());
    }
    if config.require_zero_linkage_exports != 1 {
        return Err("release execution binding requires zero linkage exports".to_string());
    }
    if config.require_pause_timelock != 1 {
        return Err("release execution binding requires pause timelock".to_string());
    }
    if config.execution_permit_count != 0 {
        return Err("release execution binding cannot permit execution by default".to_string());
    }
    if config.release_can_execute != 0 {
        return Err("release execution binding must hold execution".to_string());
    }
    if config.production_release_allowed != 0 {
        return Err("release execution binding production release must be held".to_string());
    }
    if config.max_linkage_exports != 0 {
        return Err("release execution binding must export zero linkage material".to_string());
    }
    Ok(())
}

fn validate_source(config: &Config, source: &SourceBundle) -> Result<()> {
    if source.governance_release_hold_root.is_empty() {
        return Err("release execution binding missing governance hold root".to_string());
    }
    if source.hold_unhold_drill_root.is_empty() {
        return Err("release execution binding missing hold drill root".to_string());
    }
    if source.governance_release_allowed_count != config.release_can_execute {
        return Err("release execution binding saw governance execution permit".to_string());
    }
    if source.hold_unhold_release_can_unhold_count != config.release_can_execute {
        return Err("release execution binding saw drill unhold permit".to_string());
    }
    if source.governance_production_release_allowed != config.production_release_allowed {
        return Err("release execution binding saw production release flag".to_string());
    }
    if source.hold_unhold_zero_linkage_count < source.hold_unhold_roots_only_count {
        return Err("release execution binding saw linkage export gap".to_string());
    }
    Ok(())
}

fn lane_source_root(source: &SourceBundle, lane: ExecutionLane) -> String {
    match lane {
        ExecutionLane::GovernanceGateSnapshot => source.governance_gate_state_root.clone(),
        ExecutionLane::HoldUnholdDrillVerdict => source.hold_unhold_drill_state_root.clone(),
        ExecutionLane::ReviewerReceiptReplay => source.reviewer_receipt_gate_state_root.clone(),
        ExecutionLane::PqCustodyAuthority => source.pq_authority_verification_state_root.clone(),
        ExecutionLane::WalletEscapePriority => source.wallet_handoff_state_root.clone(),
        ExecutionLane::PrivacyBoundaryRoots => source.hold_unhold_phase_root.clone(),
        ExecutionLane::FinalGateShadow => source.final_release_gate_state_root.clone(),
        ExecutionLane::EmergencyPauseTimelock => source.go_no_go_matrix_root.clone(),
        ExecutionLane::FailureCaseReplay => source.hold_unhold_failure_case_root.clone(),
        ExecutionLane::ReleaseDecisionSeal => source.governance_release_hold_root.clone(),
    }
}

fn lane_evidence_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    lane_source_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-evidence"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.binding_suite),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane_source_root),
            HashPart::Str(&source.governance_root),
            HashPart::Str(&source.hold_unhold_drill_root),
        ],
        32,
    )
}

fn lane_execution_blocker_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-execution-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(lane.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(&source.hold_unhold_unhold_blocker_root),
            HashPart::U64(config.release_can_execute),
            HashPart::U64(source.governance_release_allowed_count),
            HashPart::U64(source.hold_unhold_release_can_unhold_count),
        ],
        32,
    )
}

fn lane_pq_control_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-pq-control"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.pq_authority_verification_state_root),
            HashPart::Str(&source.custody_release_authority_spec_state_root),
            HashPart::Str(&source.authority_crosscheck_state_root),
            HashPart::U64(config.require_pq_custody_authority),
        ],
        32,
    )
}

fn lane_wallet_escape_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-wallet-escape"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.forced_exit_dry_run_state_root),
            HashPart::Str(&source.wallet_handoff_state_root),
            HashPart::U64(config.require_wallet_escape_priority),
        ],
        32,
    )
}

fn lane_privacy_output_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-privacy-output"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.hold_unhold_phase_root),
            HashPart::Str(&source.hold_unhold_failure_case_root),
            HashPart::U64(config.require_roots_only_outputs),
            HashPart::U64(config.require_zero_linkage_exports),
            HashPart::U64(config.max_linkage_exports),
        ],
        32,
    )
}

fn lane_release_hold_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    execution_blocker_root: &str,
    privacy_output_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(execution_blocker_root),
            HashPart::Str(privacy_output_root),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(&source.hold_unhold_release_hold_root),
            HashPart::U64(config.release_can_execute),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn lane_decision_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    execution_blocker_root: &str,
    pq_control_root: &str,
    wallet_escape_root: &str,
    privacy_output_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-decision"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(lane.as_str()),
            HashPart::Str(&source.source_root),
            HashPart::Str(execution_blocker_root),
            HashPart::Str(pq_control_root),
            HashPart::Str(wallet_escape_root),
            HashPart::Str(privacy_output_root),
            HashPart::Str(release_hold_root),
            HashPart::U64(config.execution_permit_count),
            HashPart::U64(config.release_can_execute),
        ],
        32,
    )
}

fn lane_root(
    config: &Config,
    source: &SourceBundle,
    lane: ExecutionLane,
    ordinal: u64,
    source_root: &str,
    evidence_root: &str,
    execution_blocker_root: &str,
    release_hold_root: &str,
    decision_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.binding_suite),
            HashPart::U64(ordinal),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane.owner_lane()),
            HashPart::Str(source_root),
            HashPart::Str(evidence_root),
            HashPart::Str(execution_blocker_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(decision_root),
            HashPart::Str(&source.source_root),
        ],
        32,
    )
}

fn guard_trigger_root(config: &Config, source: &SourceBundle, kind: GuardCaseKind) -> String {
    domain_hash(
        &format!("{DOMAIN}:guard-trigger"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.binding_suite),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&source.governance_root),
            HashPart::Str(&source.hold_unhold_drill_root),
        ],
        32,
    )
}

fn guard_source_root(
    config: &Config,
    source: &SourceBundle,
    kind: GuardCaseKind,
    trigger_root: &str,
) -> String {
    let affected_root = match kind {
        GuardCaseKind::PrematureExecutionRequest => &source.governance_release_hold_root,
        GuardCaseKind::MissingGovernanceRoot => &source.governance_root,
        GuardCaseKind::MissingDrillVerdict => &source.hold_unhold_verdict_root,
        GuardCaseKind::PqCustodyMismatch => &source.pq_authority_verification_state_root,
        GuardCaseKind::WalletEscapeBlocked => &source.wallet_handoff_state_root,
        GuardCaseKind::MetadataDisclosureProbe => &source.hold_unhold_phase_root,
        GuardCaseKind::EmergencyPauseGap => &source.go_no_go_matrix_root,
    };
    domain_hash(
        &format!("{DOMAIN}:guard-source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(kind.as_str()),
            HashPart::Str(trigger_root),
            HashPart::Str(affected_root),
            HashPart::Str(&source.source_root),
        ],
        32,
    )
}

fn guard_blocker_root(
    config: &Config,
    source: &SourceBundle,
    kind: GuardCaseKind,
    source_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:guard-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(kind.expected_response()),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(&source.hold_unhold_unhold_blocker_root),
            HashPart::U64(config.release_can_execute),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn guard_recovery_root(
    config: &Config,
    source: &SourceBundle,
    kind: GuardCaseKind,
    blocker_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:guard-recovery"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(blocker_root),
            HashPart::Str(&source.forced_exit_dry_run_state_root),
            HashPart::Str(&source.wallet_handoff_state_root),
            HashPart::Str(&source.authority_crosscheck_state_root),
            HashPart::U64(config.require_wallet_escape_priority),
            HashPart::U64(config.require_pq_custody_authority),
        ],
        32,
    )
}

fn guard_case_root(
    config: &Config,
    source: &SourceBundle,
    kind: GuardCaseKind,
    ordinal: u64,
    trigger_root: &str,
    source_root: &str,
    blocker_root: &str,
    recovery_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:guard-case"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.binding_suite),
            HashPart::U64(ordinal),
            HashPart::Str(kind.as_str()),
            HashPart::Str(trigger_root),
            HashPart::Str(source_root),
            HashPart::Str(blocker_root),
            HashPart::Str(recovery_root),
            HashPart::Str(&source.source_root),
            HashPart::U64(config.release_can_execute),
        ],
        32,
    )
}

fn lane_vector_root(lanes: &[ExecutionBindingLane]) -> String {
    let leaves = lanes
        .iter()
        .map(ExecutionBindingLane::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:lanes"), &leaves)
}

fn guard_case_vector_root(cases: &[GuardCase]) -> String {
    let leaves = cases
        .iter()
        .map(GuardCase::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:guard-cases"), &leaves)
}

fn aggregate_execution_hold_root(
    config: &Config,
    source: &SourceBundle,
    lane_root: &str,
    guard_case_root: &str,
    verdict: &ExecutionBindingVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:aggregate-execution-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(&source.hold_unhold_release_hold_root),
            HashPart::Str(lane_root),
            HashPart::Str(guard_case_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_hold_count),
            HashPart::U64(verdict.guard_block_count),
            HashPart::U64(config.release_can_execute),
        ],
        32,
    )
}

fn aggregate_execution_blocker_root(
    config: &Config,
    source: &SourceBundle,
    lanes: &[ExecutionBindingLane],
    guards: &[GuardCase],
    verdict: &ExecutionBindingVerdict,
) -> String {
    let lane_blocker_root = merkle_root(
        &format!("{DOMAIN}:lane-blockers"),
        &lanes
            .iter()
            .map(|lane| {
                json!({
                    "lane": lane.lane.as_str(),
                    "execution_blocker_root": lane.execution_blocker_root,
                    "execution_permitted": lane.execution_permitted,
                })
            })
            .collect::<Vec<_>>(),
    );
    let guard_blocker_root = merkle_root(
        &format!("{DOMAIN}:guard-blockers"),
        &guards
            .iter()
            .map(|guard| {
                json!({
                    "kind": guard.kind.as_str(),
                    "blocker_root": guard.blocker_root,
                    "execution_permitted": guard.execution_permitted,
                })
            })
            .collect::<Vec<_>>(),
    );
    domain_hash(
        &format!("{DOMAIN}:aggregate-execution-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.execution_policy),
            HashPart::Str(&source.governance_verdict_root),
            HashPart::Str(&source.hold_unhold_verdict_root),
            HashPart::Str(&lane_blocker_root),
            HashPart::Str(&guard_blocker_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.execution_permitted_count),
            HashPart::U64(verdict.drill_unhold_count),
            HashPart::U64(verdict.governance_unhold_count),
        ],
        32,
    )
}

fn execution_binding_root(
    config: &Config,
    source: &SourceBundle,
    lane_root: &str,
    guard_case_root: &str,
    execution_hold_root: &str,
    execution_blocker_root: &str,
    verdict: &ExecutionBindingVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:execution-binding-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.binding_suite),
            HashPart::Str(&source.governance_gate_state_root),
            HashPart::Str(&source.hold_unhold_drill_state_root),
            HashPart::Str(&source.source_root),
            HashPart::Str(lane_root),
            HashPart::Str(guard_case_root),
            HashPart::Str(execution_hold_root),
            HashPart::Str(execution_blocker_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(config.execution_permit_count),
            HashPart::U64(config.release_can_execute),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn source_bundle_root(
    governance: &governance_gate::State,
    drill: &hold_unhold_drill::State,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:source-bundle"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&governance.governance_root),
            HashPart::Str(&governance.condition_root),
            HashPart::Str(&governance.release_hold_root),
            HashPart::Str(&governance.verdict.verdict_root),
            HashPart::Str(&drill.drill_root),
            HashPart::Str(&drill.release_hold_drill_root),
            HashPart::Str(&drill.unhold_blocker_root),
            HashPart::Str(&drill.verdict.verdict_root),
            HashPart::U64(governance.verdict.release_allowed_count),
            HashPart::U64(drill.verdict.release_can_unhold_count),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let reason_ref = reason.as_str();
    let source = SourceBundle {
        governance_gate_state_root: record_root(
            "fallback-governance-gate",
            &json!({ "reason": reason_ref }),
        ),
        governance_root: record_root("fallback-governance", &json!({ "reason": reason_ref })),
        governance_condition_root: record_root(
            "fallback-governance-condition",
            &json!({ "reason": reason_ref }),
        ),
        governance_release_hold_root: record_root(
            "fallback-governance-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        governance_verdict_root: record_root(
            "fallback-governance-verdict",
            &json!({ "reason": reason_ref }),
        ),
        governance_release_allowed_count: 0,
        governance_release_hold_count: 1,
        governance_production_release_allowed: 0,
        hold_unhold_drill_state_root: record_root(
            "fallback-hold-unhold-drill-state",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_drill_root: record_root(
            "fallback-hold-unhold-drill",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_phase_root: record_root(
            "fallback-hold-unhold-phase",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_failure_case_root: record_root(
            "fallback-hold-unhold-failure-case",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_release_hold_root: record_root(
            "fallback-hold-unhold-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_unhold_blocker_root: record_root(
            "fallback-hold-unhold-blocker",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_verdict_root: record_root(
            "fallback-hold-unhold-verdict",
            &json!({ "reason": reason_ref }),
        ),
        hold_unhold_release_can_unhold_count: 0,
        hold_unhold_failure_case_count: 0,
        hold_unhold_roots_only_count: 0,
        hold_unhold_zero_linkage_count: 0,
        reviewer_receipt_gate_state_root: record_root(
            "fallback-reviewer-receipt-gate",
            &json!({ "reason": reason_ref }),
        ),
        pq_authority_verification_state_root: record_root(
            "fallback-pq-authority",
            &json!({ "reason": reason_ref }),
        ),
        custody_release_authority_spec_state_root: record_root(
            "fallback-custody-authority",
            &json!({ "reason": reason_ref }),
        ),
        authority_crosscheck_state_root: record_root(
            "fallback-authority-crosscheck",
            &json!({ "reason": reason_ref }),
        ),
        forced_exit_dry_run_state_root: record_root(
            "fallback-forced-exit-dry-run",
            &json!({ "reason": reason_ref }),
        ),
        wallet_handoff_state_root: record_root(
            "fallback-wallet-handoff",
            &json!({ "reason": reason_ref }),
        ),
        final_release_gate_state_root: record_root(
            "fallback-final-gate",
            &json!({ "reason": reason_ref }),
        ),
        go_no_go_matrix_root: record_root("fallback-go-no-go", &json!({ "reason": reason_ref })),
        source_root: record_root("fallback-source", &json!({ "reason": reason_ref })),
    };
    let lanes = Vec::new();
    let guard_cases = Vec::new();
    let verdict = ExecutionBindingVerdict::fallback(&config, reason_ref);
    let lane_root = lane_vector_root(&lanes);
    let guard_case_root = guard_case_vector_root(&guard_cases);
    let execution_hold_root =
        aggregate_execution_hold_root(&config, &source, &lane_root, &guard_case_root, &verdict);
    let execution_blocker_root =
        aggregate_execution_blocker_root(&config, &source, &lanes, &guard_cases, &verdict);
    let execution_binding_root = execution_binding_root(
        &config,
        &source,
        &lane_root,
        &guard_case_root,
        &execution_hold_root,
        &execution_blocker_root,
        &verdict,
    );

    State {
        config,
        source,
        lanes,
        guard_cases,
        verdict,
        lane_root,
        guard_case_root,
        execution_hold_root,
        execution_blocker_root,
        execution_binding_root,
    }
}
