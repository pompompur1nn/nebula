use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_canonical_user_escape_security_review_release_governance_gate_runtime as governance_gate,
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSecurityReviewReleaseHoldUnholdDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_RELEASE_HOLD_UNHOLD_DRILL_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-security-review-release-hold-unhold-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SECURITY_REVIEW_RELEASE_HOLD_UNHOLD_DRILL_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-security-review-release-hold-unhold-drill";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub drill_suite: String,
    pub release_policy: String,
    pub min_drill_phases: u64,
    pub min_failure_cases: u64,
    pub require_governance_release_hold_root: u64,
    pub require_reviewer_receipts: u64,
    pub require_pq_authority_quorum: u64,
    pub require_custody_authority: u64,
    pub require_wallet_escape_replay: u64,
    pub require_roots_only_publication: u64,
    pub require_zero_linkage_exports: u64,
    pub require_emergency_pause_timelock: u64,
    pub release_can_unhold: u64,
    pub production_release_allowed: u64,
    pub max_linkage_exports: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            drill_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-release-hold-unhold-drill-v1"
                    .to_string(),
            release_policy: "governance-rooted-release-held-unhold-denied-v1".to_string(),
            min_drill_phases: 9,
            min_failure_cases: 7,
            require_governance_release_hold_root: 1,
            require_reviewer_receipts: 1,
            require_pq_authority_quorum: 1,
            require_custody_authority: 1,
            require_wallet_escape_replay: 1,
            require_roots_only_publication: 1,
            require_zero_linkage_exports: 1,
            require_emergency_pause_timelock: 1,
            release_can_unhold: 0,
            production_release_allowed: 0,
            max_linkage_exports: 0,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "drill_suite": self.drill_suite,
            "release_policy": self.release_policy,
            "min_drill_phases": self.min_drill_phases,
            "min_failure_cases": self.min_failure_cases,
            "require_governance_release_hold_root": self.require_governance_release_hold_root,
            "require_reviewer_receipts": self.require_reviewer_receipts,
            "require_pq_authority_quorum": self.require_pq_authority_quorum,
            "require_custody_authority": self.require_custody_authority,
            "require_wallet_escape_replay": self.require_wallet_escape_replay,
            "require_roots_only_publication": self.require_roots_only_publication,
            "require_zero_linkage_exports": self.require_zero_linkage_exports,
            "require_emergency_pause_timelock": self.require_emergency_pause_timelock,
            "release_can_unhold": self.release_can_unhold,
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
pub enum DrillPhase {
    GovernanceSnapshot,
    EvidenceCollection,
    ReviewerReceiptReplay,
    PqCustodyAuthorityCheck,
    WalletEscapeReplay,
    PrivacyBoundaryAudit,
    FinalGateShadowDecision,
    EmergencyPauseTimelock,
    ReleaseDecision,
}

impl DrillPhase {
    pub fn ordered() -> [Self; 9] {
        [
            Self::GovernanceSnapshot,
            Self::EvidenceCollection,
            Self::ReviewerReceiptReplay,
            Self::PqCustodyAuthorityCheck,
            Self::WalletEscapeReplay,
            Self::PrivacyBoundaryAudit,
            Self::FinalGateShadowDecision,
            Self::EmergencyPauseTimelock,
            Self::ReleaseDecision,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GovernanceSnapshot => "governance_snapshot",
            Self::EvidenceCollection => "evidence_collection",
            Self::ReviewerReceiptReplay => "reviewer_receipt_replay",
            Self::PqCustodyAuthorityCheck => "pq_custody_authority_check",
            Self::WalletEscapeReplay => "wallet_escape_replay",
            Self::PrivacyBoundaryAudit => "privacy_boundary_audit",
            Self::FinalGateShadowDecision => "final_gate_shadow_decision",
            Self::EmergencyPauseTimelock => "emergency_pause_timelock",
            Self::ReleaseDecision => "release_decision",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::GovernanceSnapshot => "release_governance_owner",
            Self::EvidenceCollection => "live_evidence_owner",
            Self::ReviewerReceiptReplay => "reviewer_receipt_owner",
            Self::PqCustodyAuthorityCheck => "pq_custody_authority_owner",
            Self::WalletEscapeReplay => "wallet_escape_owner",
            Self::PrivacyBoundaryAudit => "privacy_boundary_owner",
            Self::FinalGateShadowDecision => "final_release_gate_owner",
            Self::EmergencyPauseTimelock => "emergency_pause_owner",
            Self::ReleaseDecision => "release_decision_owner",
        }
    }

    pub fn question(self) -> &'static str {
        match self {
            Self::GovernanceSnapshot => {
                "Did the drill bind the governance root, condition root, and release hold root?"
            }
            Self::EvidenceCollection => {
                "Did the drill require live evidence roots before any unhold path can advance?"
            }
            Self::ReviewerReceiptReplay => {
                "Did the drill require reviewer receipts to replay against held release roots?"
            }
            Self::PqCustodyAuthorityCheck => {
                "Did the drill bind PQ authority, custody policy, and authority crosscheck roots?"
            }
            Self::WalletEscapeReplay => {
                "Did the drill keep user forced-exit and wallet handoff evidence first class?"
            }
            Self::PrivacyBoundaryAudit => {
                "Did the drill publish only roots and keep linkage exports at zero?"
            }
            Self::FinalGateShadowDecision => {
                "Did the drill shadow the final gate without allowing production release?"
            }
            Self::EmergencyPauseTimelock => {
                "Did the drill require pause and timelock evidence before release can move?"
            }
            Self::ReleaseDecision => {
                "Did the drill keep release held until every required domain is proven?"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCaseKind {
    MoneroReorgReceiptMismatch,
    MissingReviewerReceipt,
    WatcherQuorumGap,
    CustodyPolicyGap,
    WalletEscapeReplayGap,
    MetadataLeakAttempt,
    EmergencyPauseMissing,
}

impl FailureCaseKind {
    pub fn ordered() -> [Self; 7] {
        [
            Self::MoneroReorgReceiptMismatch,
            Self::MissingReviewerReceipt,
            Self::WatcherQuorumGap,
            Self::CustodyPolicyGap,
            Self::WalletEscapeReplayGap,
            Self::MetadataLeakAttempt,
            Self::EmergencyPauseMissing,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroReorgReceiptMismatch => "monero_reorg_receipt_mismatch",
            Self::MissingReviewerReceipt => "missing_reviewer_receipt",
            Self::WatcherQuorumGap => "watcher_quorum_gap",
            Self::CustodyPolicyGap => "custody_policy_gap",
            Self::WalletEscapeReplayGap => "wallet_escape_replay_gap",
            Self::MetadataLeakAttempt => "metadata_leak_attempt",
            Self::EmergencyPauseMissing => "emergency_pause_missing",
        }
    }

    pub fn expected_response(self) -> &'static str {
        match self {
            Self::MoneroReorgReceiptMismatch => "hold_release_and_replay_monero_finality",
            Self::MissingReviewerReceipt => "hold_release_and_request_reviewer_receipt",
            Self::WatcherQuorumGap => "hold_release_and_rebuild_pq_watcher_quorum",
            Self::CustodyPolicyGap => "hold_release_and_recheck_custody_policy",
            Self::WalletEscapeReplayGap => "hold_release_and_prioritize_user_escape",
            Self::MetadataLeakAttempt => "hold_release_and_publish_roots_only",
            Self::EmergencyPauseMissing => "hold_release_and_require_pause_timelock",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub governance_gate_state_root: String,
    pub governance_root: String,
    pub condition_root: String,
    pub governance_release_hold_root: String,
    pub governance_verdict_root: String,
    pub reviewer_receipt_gate_state_root: String,
    pub reviewer_release_hold_root: String,
    pub signoff_execution_release_hold_root: String,
    pub signoff_bundle_release_hold_root: String,
    pub final_release_gate_state_root: String,
    pub execution_release_gate_plan_state_root: String,
    pub pq_authority_verification_state_root: String,
    pub pq_release_authority_quorum_replay_state_root: String,
    pub custody_release_authority_spec_state_root: String,
    pub authority_crosscheck_state_root: String,
    pub forced_exit_dry_run_state_root: String,
    pub wallet_handoff_state_root: String,
    pub go_no_go_matrix_root: String,
    pub governance_condition_count: u64,
    pub governance_release_hold_count: u64,
    pub governance_release_allowed_count: u64,
    pub governance_zero_linkage_condition_count: u64,
    pub governance_roots_only_condition_count: u64,
    pub governance_production_release_allowed: u64,
    pub source_root: String,
}

impl SourceSnapshot {
    pub fn devnet() -> Self {
        let gate = governance_gate::devnet();
        Self::from_gate(&gate)
    }

    pub fn from_gate(gate: &governance_gate::State) -> Self {
        let source_root = source_snapshot_root(gate);
        Self {
            governance_gate_state_root: gate.state_root(),
            governance_root: gate.governance_root.clone(),
            condition_root: gate.condition_root.clone(),
            governance_release_hold_root: gate.release_hold_root.clone(),
            governance_verdict_root: gate.verdict.verdict_root.clone(),
            reviewer_receipt_gate_state_root: gate
                .source_roots
                .reviewer_receipt_gate_state_root
                .clone(),
            reviewer_release_hold_root: gate.source_roots.reviewer_release_hold_root.clone(),
            signoff_execution_release_hold_root: gate
                .source_roots
                .signoff_execution_release_hold_root
                .clone(),
            signoff_bundle_release_hold_root: gate
                .source_roots
                .signoff_bundle_release_hold_root
                .clone(),
            final_release_gate_state_root: gate.source_roots.final_release_gate_state_root.clone(),
            execution_release_gate_plan_state_root: gate
                .source_roots
                .execution_release_gate_plan_state_root
                .clone(),
            pq_authority_verification_state_root: gate
                .source_roots
                .pq_authority_verification_state_root
                .clone(),
            pq_release_authority_quorum_replay_state_root: gate
                .source_roots
                .pq_release_authority_quorum_replay_state_root
                .clone(),
            custody_release_authority_spec_state_root: gate
                .source_roots
                .custody_release_authority_spec_state_root
                .clone(),
            authority_crosscheck_state_root: gate
                .source_roots
                .authority_crosscheck_state_root
                .clone(),
            forced_exit_dry_run_state_root: gate
                .source_roots
                .forced_exit_dry_run_state_root
                .clone(),
            wallet_handoff_state_root: gate.source_roots.wallet_handoff_state_root.clone(),
            go_no_go_matrix_root: gate.source_roots.go_no_go_matrix_root.clone(),
            governance_condition_count: gate.verdict.governance_condition_count,
            governance_release_hold_count: gate.verdict.release_hold_count,
            governance_release_allowed_count: gate.verdict.release_allowed_count,
            governance_zero_linkage_condition_count: gate.verdict.zero_linkage_condition_count,
            governance_roots_only_condition_count: gate.verdict.roots_only_condition_count,
            governance_production_release_allowed: gate.verdict.production_release_allowed,
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "governance_gate_state_root": self.governance_gate_state_root,
            "governance_root": self.governance_root,
            "condition_root": self.condition_root,
            "governance_release_hold_root": self.governance_release_hold_root,
            "governance_verdict_root": self.governance_verdict_root,
            "reviewer_receipt_gate_state_root": self.reviewer_receipt_gate_state_root,
            "reviewer_release_hold_root": self.reviewer_release_hold_root,
            "signoff_execution_release_hold_root": self.signoff_execution_release_hold_root,
            "signoff_bundle_release_hold_root": self.signoff_bundle_release_hold_root,
            "final_release_gate_state_root": self.final_release_gate_state_root,
            "execution_release_gate_plan_state_root": self.execution_release_gate_plan_state_root,
            "pq_authority_verification_state_root": self.pq_authority_verification_state_root,
            "pq_release_authority_quorum_replay_state_root": self.pq_release_authority_quorum_replay_state_root,
            "custody_release_authority_spec_state_root": self.custody_release_authority_spec_state_root,
            "authority_crosscheck_state_root": self.authority_crosscheck_state_root,
            "forced_exit_dry_run_state_root": self.forced_exit_dry_run_state_root,
            "wallet_handoff_state_root": self.wallet_handoff_state_root,
            "go_no_go_matrix_root": self.go_no_go_matrix_root,
            "governance_condition_count": self.governance_condition_count,
            "governance_release_hold_count": self.governance_release_hold_count,
            "governance_release_allowed_count": self.governance_release_allowed_count,
            "governance_zero_linkage_condition_count": self.governance_zero_linkage_condition_count,
            "governance_roots_only_condition_count": self.governance_roots_only_condition_count,
            "governance_production_release_allowed": self.governance_production_release_allowed,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-snapshot", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillStep {
    pub ordinal: u64,
    pub phase: DrillPhase,
    pub owner_lane: String,
    pub question: String,
    pub required_source_root: String,
    pub evidence_root: String,
    pub hold_assertion_root: String,
    pub unhold_blocker_root: String,
    pub pq_control_root: String,
    pub wallet_escape_root: String,
    pub privacy_boundary_root: String,
    pub decision_root: String,
    pub release_can_unhold: u64,
    pub release_must_remain_held: u64,
    pub roots_only_required: u64,
    pub linkage_exports_allowed: u64,
    pub step_root: String,
}

impl DrillStep {
    pub fn devnet(
        config: &Config,
        source: &SourceSnapshot,
        phase: DrillPhase,
        ordinal: u64,
    ) -> Self {
        let required_source_root = required_source_root(source, phase);
        let evidence_root = phase_evidence_root(config, source, phase, &required_source_root);
        let hold_assertion_root = phase_hold_assertion_root(config, source, phase, &evidence_root);
        let unhold_blocker_root =
            phase_unhold_blocker_root(config, source, phase, &evidence_root, &hold_assertion_root);
        let pq_control_root = phase_pq_control_root(config, source, phase, &evidence_root);
        let wallet_escape_root = phase_wallet_escape_root(config, source, phase, &evidence_root);
        let privacy_boundary_root =
            phase_privacy_boundary_root(config, source, phase, &evidence_root);
        let decision_root = phase_decision_root(
            config,
            source,
            phase,
            &hold_assertion_root,
            &unhold_blocker_root,
            &pq_control_root,
            &wallet_escape_root,
            &privacy_boundary_root,
        );
        let step_root = phase_step_root(
            config,
            source,
            phase,
            ordinal,
            &required_source_root,
            &evidence_root,
            &hold_assertion_root,
            &unhold_blocker_root,
            &decision_root,
        );

        Self {
            ordinal,
            phase,
            owner_lane: phase.owner_lane().to_string(),
            question: phase.question().to_string(),
            required_source_root,
            evidence_root,
            hold_assertion_root,
            unhold_blocker_root,
            pq_control_root,
            wallet_escape_root,
            privacy_boundary_root,
            decision_root,
            release_can_unhold: config.release_can_unhold,
            release_must_remain_held: 1,
            roots_only_required: config.require_roots_only_publication,
            linkage_exports_allowed: config.max_linkage_exports,
            step_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "phase": self.phase.as_str(),
            "owner_lane": self.owner_lane,
            "question": self.question,
            "required_source_root": self.required_source_root,
            "evidence_root": self.evidence_root,
            "hold_assertion_root": self.hold_assertion_root,
            "unhold_blocker_root": self.unhold_blocker_root,
            "pq_control_root": self.pq_control_root,
            "wallet_escape_root": self.wallet_escape_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "decision_root": self.decision_root,
            "release_can_unhold": self.release_can_unhold,
            "release_must_remain_held": self.release_must_remain_held,
            "roots_only_required": self.roots_only_required,
            "linkage_exports_allowed": self.linkage_exports_allowed,
            "step_root": self.step_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCase {
    pub ordinal: u64,
    pub kind: FailureCaseKind,
    pub expected_response: String,
    pub trigger_root: String,
    pub source_root: String,
    pub expected_hold_root: String,
    pub recovery_root: String,
    pub release_can_unhold: u64,
    pub failure_case_root: String,
}

impl FailureCase {
    pub fn devnet(
        config: &Config,
        source: &SourceSnapshot,
        kind: FailureCaseKind,
        ordinal: u64,
    ) -> Self {
        let trigger_root = failure_trigger_root(config, source, kind);
        let source_root = failure_source_root(config, source, kind, &trigger_root);
        let expected_hold_root = failure_hold_root(config, source, kind, &source_root);
        let recovery_root = failure_recovery_root(config, source, kind, &expected_hold_root);
        let failure_case_root = failure_case_root(
            config,
            source,
            kind,
            ordinal,
            &trigger_root,
            &source_root,
            &expected_hold_root,
            &recovery_root,
        );

        Self {
            ordinal,
            kind,
            expected_response: kind.expected_response().to_string(),
            trigger_root,
            source_root,
            expected_hold_root,
            recovery_root,
            release_can_unhold: config.release_can_unhold,
            failure_case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "kind": self.kind.as_str(),
            "expected_response": self.expected_response,
            "trigger_root": self.trigger_root,
            "source_root": self.source_root,
            "expected_hold_root": self.expected_hold_root,
            "recovery_root": self.recovery_root,
            "release_can_unhold": self.release_can_unhold,
            "failure_case_root": self.failure_case_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillVerdict {
    pub phase_count: u64,
    pub failure_case_count: u64,
    pub release_can_unhold_count: u64,
    pub release_hold_count: u64,
    pub failure_hold_count: u64,
    pub roots_only_count: u64,
    pub zero_linkage_count: u64,
    pub production_release_allowed: u64,
    pub governance_release_allowed_count: u64,
    pub governance_release_hold_count: u64,
    pub drill_status: String,
    pub verdict_root: String,
}

impl DrillVerdict {
    pub fn new(
        config: &Config,
        source: &SourceSnapshot,
        phases: &[DrillStep],
        failures: &[FailureCase],
    ) -> Self {
        let phase_count = phases.len() as u64;
        let failure_case_count = failures.len() as u64;
        let release_can_unhold_count = phases
            .iter()
            .filter(|step| step.release_can_unhold == 1)
            .count() as u64;
        let release_hold_count = phases
            .iter()
            .filter(|step| step.release_must_remain_held == 1)
            .count() as u64;
        let failure_hold_count = failures
            .iter()
            .filter(|case| case.release_can_unhold == 0)
            .count() as u64;
        let roots_only_count = phases
            .iter()
            .filter(|step| step.roots_only_required == 1)
            .count() as u64;
        let zero_linkage_count = phases
            .iter()
            .filter(|step| step.linkage_exports_allowed <= config.max_linkage_exports)
            .count() as u64;
        let production_release_allowed = config.production_release_allowed;
        let drill_status = if phase_count >= config.min_drill_phases
            && failure_case_count >= config.min_failure_cases
            && release_can_unhold_count == 0
            && release_hold_count == phase_count
            && failure_hold_count == failure_case_count
            && roots_only_count == phase_count
            && zero_linkage_count == phase_count
            && production_release_allowed == 0
            && source.governance_release_allowed_count == 0
            && source.governance_release_hold_count >= source.governance_condition_count
        {
            "release_hold_unhold_drill_ready_release_held"
        } else {
            "release_hold_unhold_drill_gap_release_held"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.release_policy),
                HashPart::Str(&source.governance_root),
                HashPart::Str(&source.governance_release_hold_root),
                HashPart::U64(phase_count),
                HashPart::U64(failure_case_count),
                HashPart::U64(release_can_unhold_count),
                HashPart::U64(release_hold_count),
                HashPart::U64(failure_hold_count),
                HashPart::U64(roots_only_count),
                HashPart::U64(zero_linkage_count),
                HashPart::U64(production_release_allowed),
                HashPart::U64(source.governance_release_allowed_count),
                HashPart::U64(source.governance_release_hold_count),
                HashPart::Str(&drill_status),
            ],
            32,
        );

        Self {
            phase_count,
            failure_case_count,
            release_can_unhold_count,
            release_hold_count,
            failure_hold_count,
            roots_only_count,
            zero_linkage_count,
            production_release_allowed,
            governance_release_allowed_count: source.governance_release_allowed_count,
            governance_release_hold_count: source.governance_release_hold_count,
            drill_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let drill_status = "release_hold_unhold_drill_construction_gap_release_held".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.release_policy),
                HashPart::Str(reason),
                HashPart::Str(&drill_status),
            ],
            32,
        );

        Self {
            phase_count: 0,
            failure_case_count: 0,
            release_can_unhold_count: 0,
            release_hold_count: 1,
            failure_hold_count: 1,
            roots_only_count: 0,
            zero_linkage_count: 0,
            production_release_allowed: 0,
            governance_release_allowed_count: 0,
            governance_release_hold_count: 1,
            drill_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "phase_count": self.phase_count,
            "failure_case_count": self.failure_case_count,
            "release_can_unhold_count": self.release_can_unhold_count,
            "release_hold_count": self.release_hold_count,
            "failure_hold_count": self.failure_hold_count,
            "roots_only_count": self.roots_only_count,
            "zero_linkage_count": self.zero_linkage_count,
            "production_release_allowed": self.production_release_allowed,
            "governance_release_allowed_count": self.governance_release_allowed_count,
            "governance_release_hold_count": self.governance_release_hold_count,
            "drill_status": self.drill_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source: SourceSnapshot,
    pub phases: Vec<DrillStep>,
    pub failure_cases: Vec<FailureCase>,
    pub verdict: DrillVerdict,
    pub phase_root: String,
    pub failure_case_root: String,
    pub release_hold_drill_root: String,
    pub unhold_blocker_root: String,
    pub drill_root: String,
}

impl State {
    pub fn new(config: Config, source: SourceSnapshot) -> Result<Self> {
        validate_config(&config)?;
        validate_source(&config, &source)?;
        let phases = DrillPhase::ordered()
            .iter()
            .enumerate()
            .map(|(index, phase)| DrillStep::devnet(&config, &source, *phase, index as u64 + 1))
            .collect::<Vec<_>>();
        let failure_cases = FailureCaseKind::ordered()
            .iter()
            .enumerate()
            .map(|(index, kind)| FailureCase::devnet(&config, &source, *kind, index as u64 + 1))
            .collect::<Vec<_>>();
        let verdict = DrillVerdict::new(&config, &source, &phases, &failure_cases);
        let phase_root = phase_vector_root(&phases);
        let failure_case_root = failure_case_vector_root(&failure_cases);
        let release_hold_drill_root =
            aggregate_hold_drill_root(&config, &source, &phase_root, &failure_case_root, &verdict);
        let unhold_blocker_root =
            aggregate_unhold_blocker_root(&config, &source, &phases, &failure_cases, &verdict);
        let drill_root = drill_root(
            &config,
            &source,
            &phase_root,
            &failure_case_root,
            &release_hold_drill_root,
            &unhold_blocker_root,
            &verdict,
        );

        Ok(Self {
            config,
            source,
            phases,
            failure_cases,
            verdict,
            phase_root,
            failure_case_root,
            release_hold_drill_root,
            unhold_blocker_root,
            drill_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), SourceSnapshot::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_security_review_release_hold_unhold_drill_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source": self.source.public_record(),
            "phase_root": self.phase_root,
            "failure_case_root": self.failure_case_root,
            "release_hold_drill_root": self.release_hold_drill_root,
            "unhold_blocker_root": self.unhold_blocker_root,
            "drill_root": self.drill_root,
            "verdict": self.verdict.public_record(),
            "phases": self
                .phases
                .iter()
                .map(DrillStep::public_record)
                .collect::<Vec<_>>(),
            "failure_cases": self
                .failure_cases
                .iter()
                .map(FailureCase::public_record)
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
                "phase_root": self.phase_root,
                "failure_case_root": self.failure_case_root,
                "release_hold_drill_root": self.release_hold_drill_root,
                "unhold_blocker_root": self.unhold_blocker_root,
                "drill_root": self.drill_root,
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
        return Err("release hold drill config chain id mismatch".to_string());
    }
    if config.min_drill_phases < DrillPhase::ordered().len() as u64 {
        return Err("release hold drill requires every phase".to_string());
    }
    if config.min_failure_cases < FailureCaseKind::ordered().len() as u64 {
        return Err("release hold drill requires every failure case".to_string());
    }
    if config.require_governance_release_hold_root != 1 {
        return Err("release hold drill requires governance hold root".to_string());
    }
    if config.require_reviewer_receipts != 1 {
        return Err("release hold drill requires reviewer receipts".to_string());
    }
    if config.require_pq_authority_quorum != 1 {
        return Err("release hold drill requires pq authority quorum".to_string());
    }
    if config.require_custody_authority != 1 {
        return Err("release hold drill requires custody authority".to_string());
    }
    if config.require_wallet_escape_replay != 1 {
        return Err("release hold drill requires wallet escape replay".to_string());
    }
    if config.require_roots_only_publication != 1 {
        return Err("release hold drill requires roots only publication".to_string());
    }
    if config.require_zero_linkage_exports != 1 {
        return Err("release hold drill requires zero linkage exports".to_string());
    }
    if config.require_emergency_pause_timelock != 1 {
        return Err("release hold drill requires pause timelock".to_string());
    }
    if config.release_can_unhold != 0 {
        return Err("release hold drill cannot unhold by default".to_string());
    }
    if config.production_release_allowed != 0 {
        return Err("release hold drill production release must be held".to_string());
    }
    if config.max_linkage_exports != 0 {
        return Err("release hold drill must export zero linkage material".to_string());
    }
    Ok(())
}

fn validate_source(config: &Config, source: &SourceSnapshot) -> Result<()> {
    if source.governance_release_hold_root.is_empty() {
        return Err("release hold drill missing governance hold root".to_string());
    }
    if source.governance_release_allowed_count != config.release_can_unhold {
        return Err("release hold drill saw governance unhold count".to_string());
    }
    if source.governance_production_release_allowed != config.production_release_allowed {
        return Err("release hold drill saw production release flag".to_string());
    }
    if source.governance_zero_linkage_condition_count < source.governance_condition_count {
        return Err("release hold drill saw linkage export gap".to_string());
    }
    if source.governance_roots_only_condition_count < source.governance_condition_count {
        return Err("release hold drill saw roots only gap".to_string());
    }
    Ok(())
}

fn required_source_root(source: &SourceSnapshot, phase: DrillPhase) -> String {
    match phase {
        DrillPhase::GovernanceSnapshot => source.governance_root.clone(),
        DrillPhase::EvidenceCollection => source.condition_root.clone(),
        DrillPhase::ReviewerReceiptReplay => source.reviewer_receipt_gate_state_root.clone(),
        DrillPhase::PqCustodyAuthorityCheck => source.pq_authority_verification_state_root.clone(),
        DrillPhase::WalletEscapeReplay => source.wallet_handoff_state_root.clone(),
        DrillPhase::PrivacyBoundaryAudit => source.signoff_bundle_release_hold_root.clone(),
        DrillPhase::FinalGateShadowDecision => source.final_release_gate_state_root.clone(),
        DrillPhase::EmergencyPauseTimelock => source.go_no_go_matrix_root.clone(),
        DrillPhase::ReleaseDecision => source.governance_release_hold_root.clone(),
    }
}

fn phase_evidence_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    required_source_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-evidence"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_suite),
            HashPart::Str(phase.as_str()),
            HashPart::Str(required_source_root),
            HashPart::Str(&source.governance_gate_state_root),
            HashPart::Str(&source.governance_verdict_root),
        ],
        32,
    )
}

fn phase_hold_assertion_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-hold-assertion"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_policy),
            HashPart::Str(phase.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(&source.reviewer_release_hold_root),
            HashPart::U64(config.require_governance_release_hold_root),
            HashPart::U64(config.release_can_unhold),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn phase_unhold_blocker_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    evidence_root: &str,
    hold_assertion_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-unhold-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(phase.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(hold_assertion_root),
            HashPart::Str(&source.governance_verdict_root),
            HashPart::U64(source.governance_release_allowed_count),
            HashPart::U64(config.release_can_unhold),
        ],
        32,
    )
}

fn phase_pq_control_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-pq-control"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(phase.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.pq_authority_verification_state_root),
            HashPart::Str(&source.pq_release_authority_quorum_replay_state_root),
            HashPart::Str(&source.custody_release_authority_spec_state_root),
            HashPart::Str(&source.authority_crosscheck_state_root),
            HashPart::U64(config.require_pq_authority_quorum),
            HashPart::U64(config.require_custody_authority),
        ],
        32,
    )
}

fn phase_wallet_escape_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-wallet-escape"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(phase.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.forced_exit_dry_run_state_root),
            HashPart::Str(&source.wallet_handoff_state_root),
            HashPart::U64(config.require_wallet_escape_replay),
        ],
        32,
    )
}

fn phase_privacy_boundary_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-privacy-boundary"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(phase.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.signoff_execution_release_hold_root),
            HashPart::Str(&source.signoff_bundle_release_hold_root),
            HashPart::U64(config.require_roots_only_publication),
            HashPart::U64(config.require_zero_linkage_exports),
            HashPart::U64(config.max_linkage_exports),
        ],
        32,
    )
}

fn phase_decision_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    hold_assertion_root: &str,
    unhold_blocker_root: &str,
    pq_control_root: &str,
    wallet_escape_root: &str,
    privacy_boundary_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-decision"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_policy),
            HashPart::Str(phase.as_str()),
            HashPart::Str(&source.governance_root),
            HashPart::Str(hold_assertion_root),
            HashPart::Str(unhold_blocker_root),
            HashPart::Str(pq_control_root),
            HashPart::Str(wallet_escape_root),
            HashPart::Str(privacy_boundary_root),
            HashPart::U64(config.release_can_unhold),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn phase_step_root(
    config: &Config,
    source: &SourceSnapshot,
    phase: DrillPhase,
    ordinal: u64,
    required_source_root: &str,
    evidence_root: &str,
    hold_assertion_root: &str,
    unhold_blocker_root: &str,
    decision_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:phase-step"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_suite),
            HashPart::U64(ordinal),
            HashPart::Str(phase.as_str()),
            HashPart::Str(phase.owner_lane()),
            HashPart::Str(required_source_root),
            HashPart::Str(evidence_root),
            HashPart::Str(hold_assertion_root),
            HashPart::Str(unhold_blocker_root),
            HashPart::Str(decision_root),
            HashPart::Str(&source.source_root),
        ],
        32,
    )
}

fn failure_trigger_root(config: &Config, source: &SourceSnapshot, kind: FailureCaseKind) -> String {
    domain_hash(
        &format!("{DOMAIN}:failure-trigger"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_suite),
            HashPart::Str(kind.as_str()),
            HashPart::Str(&source.governance_root),
            HashPart::Str(&source.condition_root),
        ],
        32,
    )
}

fn failure_source_root(
    config: &Config,
    source: &SourceSnapshot,
    kind: FailureCaseKind,
    trigger_root: &str,
) -> String {
    let affected_root = match kind {
        FailureCaseKind::MoneroReorgReceiptMismatch => &source.final_release_gate_state_root,
        FailureCaseKind::MissingReviewerReceipt => &source.reviewer_receipt_gate_state_root,
        FailureCaseKind::WatcherQuorumGap => &source.pq_release_authority_quorum_replay_state_root,
        FailureCaseKind::CustodyPolicyGap => &source.custody_release_authority_spec_state_root,
        FailureCaseKind::WalletEscapeReplayGap => &source.wallet_handoff_state_root,
        FailureCaseKind::MetadataLeakAttempt => &source.signoff_bundle_release_hold_root,
        FailureCaseKind::EmergencyPauseMissing => &source.go_no_go_matrix_root,
    };
    domain_hash(
        &format!("{DOMAIN}:failure-source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_policy),
            HashPart::Str(kind.as_str()),
            HashPart::Str(trigger_root),
            HashPart::Str(affected_root),
            HashPart::Str(&source.governance_release_hold_root),
        ],
        32,
    )
}

fn failure_hold_root(
    config: &Config,
    source: &SourceSnapshot,
    kind: FailureCaseKind,
    source_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:failure-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(kind.expected_response()),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(&source.reviewer_release_hold_root),
            HashPart::U64(config.release_can_unhold),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn failure_recovery_root(
    config: &Config,
    source: &SourceSnapshot,
    kind: FailureCaseKind,
    expected_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:failure-recovery"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(expected_hold_root),
            HashPart::Str(&source.forced_exit_dry_run_state_root),
            HashPart::Str(&source.wallet_handoff_state_root),
            HashPart::Str(&source.authority_crosscheck_state_root),
            HashPart::U64(config.require_wallet_escape_replay),
            HashPart::U64(config.require_pq_authority_quorum),
        ],
        32,
    )
}

fn failure_case_root(
    config: &Config,
    source: &SourceSnapshot,
    kind: FailureCaseKind,
    ordinal: u64,
    trigger_root: &str,
    source_root: &str,
    expected_hold_root: &str,
    recovery_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:failure-case"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_suite),
            HashPart::U64(ordinal),
            HashPart::Str(kind.as_str()),
            HashPart::Str(trigger_root),
            HashPart::Str(source_root),
            HashPart::Str(expected_hold_root),
            HashPart::Str(recovery_root),
            HashPart::Str(&source.source_root),
            HashPart::U64(config.release_can_unhold),
        ],
        32,
    )
}

fn phase_vector_root(phases: &[DrillStep]) -> String {
    let leaves = phases
        .iter()
        .map(DrillStep::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:phases"), &leaves)
}

fn failure_case_vector_root(cases: &[FailureCase]) -> String {
    let leaves = cases
        .iter()
        .map(FailureCase::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:failure-cases"), &leaves)
}

fn aggregate_hold_drill_root(
    config: &Config,
    source: &SourceSnapshot,
    phase_root: &str,
    failure_case_root: &str,
    verdict: &DrillVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:aggregate-hold-drill"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_policy),
            HashPart::Str(&source.governance_release_hold_root),
            HashPart::Str(phase_root),
            HashPart::Str(failure_case_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_hold_count),
            HashPart::U64(verdict.failure_hold_count),
            HashPart::U64(config.release_can_unhold),
        ],
        32,
    )
}

fn aggregate_unhold_blocker_root(
    config: &Config,
    source: &SourceSnapshot,
    phases: &[DrillStep],
    failures: &[FailureCase],
    verdict: &DrillVerdict,
) -> String {
    let phase_blocker_root = merkle_root(
        &format!("{DOMAIN}:phase-unhold-blockers"),
        &phases
            .iter()
            .map(|step| {
                json!({
                    "phase": step.phase.as_str(),
                    "unhold_blocker_root": step.unhold_blocker_root,
                    "release_can_unhold": step.release_can_unhold,
                })
            })
            .collect::<Vec<_>>(),
    );
    let failure_blocker_root = merkle_root(
        &format!("{DOMAIN}:failure-unhold-blockers"),
        &failures
            .iter()
            .map(|case| {
                json!({
                    "kind": case.kind.as_str(),
                    "expected_hold_root": case.expected_hold_root,
                    "release_can_unhold": case.release_can_unhold,
                })
            })
            .collect::<Vec<_>>(),
    );
    domain_hash(
        &format!("{DOMAIN}:aggregate-unhold-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_policy),
            HashPart::Str(&source.governance_verdict_root),
            HashPart::Str(&phase_blocker_root),
            HashPart::Str(&failure_blocker_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_can_unhold_count),
            HashPart::U64(source.governance_release_allowed_count),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn drill_root(
    config: &Config,
    source: &SourceSnapshot,
    phase_root: &str,
    failure_case_root: &str,
    release_hold_drill_root: &str,
    unhold_blocker_root: &str,
    verdict: &DrillVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:drill-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_suite),
            HashPart::Str(&source.governance_gate_state_root),
            HashPart::Str(&source.source_root),
            HashPart::Str(phase_root),
            HashPart::Str(failure_case_root),
            HashPart::Str(release_hold_drill_root),
            HashPart::Str(unhold_blocker_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(config.release_can_unhold),
            HashPart::U64(config.production_release_allowed),
            HashPart::U64(config.max_linkage_exports),
        ],
        32,
    )
}

fn source_snapshot_root(gate: &governance_gate::State) -> String {
    domain_hash(
        &format!("{DOMAIN}:source-snapshot"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&gate.governance_root),
            HashPart::Str(&gate.condition_root),
            HashPart::Str(&gate.release_hold_root),
            HashPart::Str(&gate.verdict.verdict_root),
            HashPart::U64(gate.verdict.governance_condition_count),
            HashPart::U64(gate.verdict.release_hold_count),
            HashPart::U64(gate.verdict.release_allowed_count),
            HashPart::U64(gate.verdict.production_release_allowed),
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
    let source = SourceSnapshot {
        governance_gate_state_root: record_root(
            "fallback-governance-gate-state",
            &json!({ "reason": reason_ref }),
        ),
        governance_root: record_root("fallback-governance", &json!({ "reason": reason_ref })),
        condition_root: record_root(
            "fallback-governance-conditions",
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
        reviewer_receipt_gate_state_root: record_root(
            "fallback-reviewer-receipt-gate",
            &json!({ "reason": reason_ref }),
        ),
        reviewer_release_hold_root: record_root(
            "fallback-reviewer-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        signoff_execution_release_hold_root: record_root(
            "fallback-execution-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        signoff_bundle_release_hold_root: record_root(
            "fallback-bundle-release-hold",
            &json!({ "reason": reason_ref }),
        ),
        final_release_gate_state_root: record_root(
            "fallback-final-release-gate",
            &json!({ "reason": reason_ref }),
        ),
        execution_release_gate_plan_state_root: record_root(
            "fallback-execution-release-plan",
            &json!({ "reason": reason_ref }),
        ),
        pq_authority_verification_state_root: record_root(
            "fallback-pq-authority",
            &json!({ "reason": reason_ref }),
        ),
        pq_release_authority_quorum_replay_state_root: record_root(
            "fallback-pq-quorum-replay",
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
        go_no_go_matrix_root: record_root("fallback-go-no-go", &json!({ "reason": reason_ref })),
        governance_condition_count: 0,
        governance_release_hold_count: 1,
        governance_release_allowed_count: 0,
        governance_zero_linkage_condition_count: 0,
        governance_roots_only_condition_count: 0,
        governance_production_release_allowed: 0,
        source_root: record_root("fallback-source", &json!({ "reason": reason_ref })),
    };
    let phases = Vec::new();
    let failure_cases = Vec::new();
    let verdict = DrillVerdict::fallback(&config, reason_ref);
    let phase_root = phase_vector_root(&phases);
    let failure_case_root = failure_case_vector_root(&failure_cases);
    let release_hold_drill_root =
        aggregate_hold_drill_root(&config, &source, &phase_root, &failure_case_root, &verdict);
    let unhold_blocker_root =
        aggregate_unhold_blocker_root(&config, &source, &phases, &failure_cases, &verdict);
    let drill_root = drill_root(
        &config,
        &source,
        &phase_root,
        &failure_case_root,
        &release_hold_drill_root,
        &unhold_blocker_root,
        &verdict,
    );

    State {
        config,
        source,
        phases,
        failure_cases,
        verdict,
        phase_root,
        failure_case_root,
        release_hold_drill_root,
        unhold_blocker_root,
        drill_root,
    }
}
