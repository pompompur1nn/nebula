use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageRuntimeReplayAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-runtime-replay-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROLLBACK_DRILL_SUITE: &str = "runtime-replay-deployment-guard-rollback-drill-v1";
pub const DEFAULT_HEIGHT: u64 = 85_085;
pub const DEFAULT_REPLAY_ACCEPTED_HEIGHT: u64 = 85_060;
pub const DEFAULT_MAX_REPLAY_AGE_BLOCKS: u64 = 64;
pub const DEFAULT_MIN_ROLLBACK_COMMANDS: u16 = 8;
pub const DEFAULT_MIN_EXPECTED_RECEIPTS: u16 = 8;
pub const DEFAULT_MIN_ABORT_CRITERIA: u16 = 5;
pub const DEFAULT_MIN_OPERATOR_ACKS: u16 = 5;
pub const DEFAULT_MIN_HOLD_UNHOLD_EVENTS: u16 = 3;
pub const DEFAULT_MAX_WATCH_ITEMS: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackDrillPhase {
    Prepare,
    HoldAsserted,
    ReplayRollback,
    ReceiptCompare,
    AbortCriteriaReview,
    OperatorSignoff,
    UnholdRehearsal,
    FailClosedComplete,
}

impl RollbackDrillPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::HoldAsserted => "hold_asserted",
            Self::ReplayRollback => "replay_rollback",
            Self::ReceiptCompare => "receipt_compare",
            Self::AbortCriteriaReview => "abort_criteria_review",
            Self::OperatorSignoff => "operator_signoff",
            Self::UnholdRehearsal => "unhold_rehearsal",
            Self::FailClosedComplete => "fail_closed_complete",
        }
    }

    pub fn ordinal(self) -> u8 {
        match self {
            Self::Prepare => 0,
            Self::HoldAsserted => 1,
            Self::ReplayRollback => 2,
            Self::ReceiptCompare => 3,
            Self::AbortCriteriaReview => 4,
            Self::OperatorSignoff => 5,
            Self::UnholdRehearsal => 6,
            Self::FailClosedComplete => 7,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::Prepare,
            Self::HoldAsserted,
            Self::ReplayRollback,
            Self::ReceiptCompare,
            Self::AbortCriteriaReview,
            Self::OperatorSignoff,
            Self::UnholdRehearsal,
            Self::FailClosedComplete,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillVerdict {
    Pass,
    Watch,
    Hold,
    Abort,
}

impl DrillVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Abort => "abort",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Hold | Self::Abort)
    }

    pub fn is_watch(self) -> bool {
        matches!(self, Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Matched,
    Watch,
    MissingExpected,
    MissingObserved,
    Mismatched,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Watch => "watch",
            Self::MissingExpected => "missing_expected",
            Self::MissingObserved => "missing_observed",
            Self::Mismatched => "mismatched",
        }
    }

    pub fn blocks_release(self) -> bool {
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
pub enum FreshnessStatus {
    Fresh,
    Aging,
    Blocked,
}

impl FreshnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Aging => "aging",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCriterionKind {
    ReceiptMismatch,
    StaleReplay,
    MissingRollbackCommand,
    OperatorReject,
    HoldRootMismatch,
    UnexpectedUnhold,
    ManualFreeze,
    WatchLimitExceeded,
}

impl AbortCriterionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::StaleReplay => "stale_replay",
            Self::MissingRollbackCommand => "missing_rollback_command",
            Self::OperatorReject => "operator_reject",
            Self::HoldRootMismatch => "hold_root_mismatch",
            Self::UnexpectedUnhold => "unexpected_unhold",
            Self::ManualFreeze => "manual_freeze",
            Self::WatchLimitExceeded => "watch_limit_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCriterionStatus {
    Armed,
    Watch,
    Triggered,
    Missing,
}

impl AbortCriterionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Watch => "watch",
            Self::Triggered => "triggered",
            Self::Missing => "missing",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Triggered | Self::Missing)
    }

    pub fn is_watch(self) -> bool {
        matches!(self, Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    RuntimeReplayOperator,
    RollbackCommander,
    ReleaseCoordinator,
    DashboardOwner,
    SecurityReviewer,
    ProductionSre,
}

impl OperatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeReplayOperator => "runtime_replay_operator",
            Self::RollbackCommander => "rollback_commander",
            Self::ReleaseCoordinator => "release_coordinator",
            Self::DashboardOwner => "dashboard_owner",
            Self::SecurityReviewer => "security_reviewer",
            Self::ProductionSre => "production_sre",
        }
    }

    pub fn required() -> [Self; 6] {
        [
            Self::RuntimeReplayOperator,
            Self::RollbackCommander,
            Self::ReleaseCoordinator,
            Self::DashboardOwner,
            Self::SecurityReviewer,
            Self::ProductionSre,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorAckDecision {
    Acknowledge,
    Watch,
    Hold,
    Reject,
}

impl OperatorAckDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledge => "acknowledge",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Acknowledge)
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Hold | Self::Reject)
    }

    pub fn is_watch(self) -> bool {
        matches!(self, Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldUnholdAction {
    AssertHold,
    ProveHold,
    RequestUnhold,
    RejectUnhold,
    RestoreHold,
}

impl HoldUnholdAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssertHold => "assert_hold",
            Self::ProveHold => "prove_hold",
            Self::RequestUnhold => "request_unhold",
            Self::RejectUnhold => "reject_unhold",
            Self::RestoreHold => "restore_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldState {
    FailClosedHeld,
    HeldByGuard,
    UnholdRequested,
    UnholdRejected,
    UnheldForDeploy,
    RollbackRestoredHold,
}

impl ReleaseHoldState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedHeld => "fail_closed_held",
            Self::HeldByGuard => "held_by_guard",
            Self::UnholdRequested => "unhold_requested",
            Self::UnholdRejected => "unhold_rejected",
            Self::UnheldForDeploy => "unheld_for_deploy",
            Self::RollbackRestoredHold => "rollback_restored_hold",
        }
    }

    pub fn release_is_held(self) -> bool {
        !matches!(self, Self::UnheldForDeploy)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    DeploymentGuardRootMissing,
    RuntimeReplayRootMissing,
    RollbackTranscriptMissing,
    RollbackCommandMissing,
    ExpectedReceiptMissing,
    ObservedReceiptMissing,
    ReceiptMismatch,
    ReplayFreshnessBlocked,
    AbortCriterionMissing,
    AbortCriterionTriggered,
    OperatorAckMissing,
    OperatorAckRejected,
    HoldUnholdMismatch,
    FailClosedReleaseHold,
    WatchLimitExceeded,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentGuardRootMissing => "deployment_guard_root_missing",
            Self::RuntimeReplayRootMissing => "runtime_replay_root_missing",
            Self::RollbackTranscriptMissing => "rollback_transcript_missing",
            Self::RollbackCommandMissing => "rollback_command_missing",
            Self::ExpectedReceiptMissing => "expected_receipt_missing",
            Self::ObservedReceiptMissing => "observed_receipt_missing",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::ReplayFreshnessBlocked => "replay_freshness_blocked",
            Self::AbortCriterionMissing => "abort_criterion_missing",
            Self::AbortCriterionTriggered => "abort_criterion_triggered",
            Self::OperatorAckMissing => "operator_ack_missing",
            Self::OperatorAckRejected => "operator_ack_rejected",
            Self::HoldUnholdMismatch => "hold_unhold_mismatch",
            Self::FailClosedReleaseHold => "fail_closed_release_hold",
            Self::WatchLimitExceeded => "watch_limit_exceeded",
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

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Blocking)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub rollback_drill_suite: String,
    pub max_replay_age_blocks: u64,
    pub min_rollback_commands: u16,
    pub min_expected_receipts: u16,
    pub min_abort_criteria: u16,
    pub min_operator_acks: u16,
    pub min_hold_unhold_events: u16,
    pub max_watch_items: u16,
    pub require_deployment_guard_root: bool,
    pub require_runtime_replay_root: bool,
    pub require_rollback_transcripts: bool,
    pub require_command_roots: bool,
    pub require_expected_receipts: bool,
    pub require_observed_receipts: bool,
    pub require_replay_freshness: bool,
    pub require_abort_criteria: bool,
    pub require_operator_acknowledgements: bool,
    pub require_fail_closed_hold: bool,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            rollback_drill_suite: ROLLBACK_DRILL_SUITE.to_string(),
            max_replay_age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS,
            min_rollback_commands: DEFAULT_MIN_ROLLBACK_COMMANDS,
            min_expected_receipts: DEFAULT_MIN_EXPECTED_RECEIPTS,
            min_abort_criteria: DEFAULT_MIN_ABORT_CRITERIA,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            min_hold_unhold_events: DEFAULT_MIN_HOLD_UNHOLD_EVENTS,
            max_watch_items: DEFAULT_MAX_WATCH_ITEMS,
            require_deployment_guard_root: true,
            require_runtime_replay_root: true,
            require_rollback_transcripts: true,
            require_command_roots: true,
            require_expected_receipts: true,
            require_observed_receipts: true,
            require_replay_freshness: true,
            require_abort_criteria: true,
            require_operator_acknowledgements: true,
            require_fail_closed_hold: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("rollback_drill_suite", &self.rollback_drill_suite)?;
        ensure(
            self.max_replay_age_blocks > 0,
            "replay freshness window must be non-zero",
        )?;
        ensure(
            self.min_rollback_commands > 0,
            "minimum rollback commands must be non-zero",
        )?;
        ensure(
            self.min_expected_receipts > 0,
            "minimum expected receipts must be non-zero",
        )?;
        ensure(
            self.min_abort_criteria > 0,
            "minimum abort criteria must be non-zero",
        )?;
        ensure(
            self.min_operator_acks > 0,
            "minimum operator acknowledgements must be non-zero",
        )?;
        ensure(
            self.min_hold_unhold_events > 0,
            "minimum hold/unhold events must be non-zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "rollback_drill_suite": self.rollback_drill_suite,
            "max_replay_age_blocks": self.max_replay_age_blocks,
            "min_rollback_commands": self.min_rollback_commands,
            "min_expected_receipts": self.min_expected_receipts,
            "min_abort_criteria": self.min_abort_criteria,
            "min_operator_acks": self.min_operator_acks,
            "min_hold_unhold_events": self.min_hold_unhold_events,
            "max_watch_items": self.max_watch_items,
            "require_deployment_guard_root": self.require_deployment_guard_root,
            "require_runtime_replay_root": self.require_runtime_replay_root,
            "require_rollback_transcripts": self.require_rollback_transcripts,
            "require_command_roots": self.require_command_roots,
            "require_expected_receipts": self.require_expected_receipts,
            "require_observed_receipts": self.require_observed_receipts,
            "require_replay_freshness": self.require_replay_freshness,
            "require_abort_criteria": self.require_abort_criteria,
            "require_operator_acknowledgements": self.require_operator_acknowledgements,
            "require_fail_closed_hold": self.require_fail_closed_hold,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback_drill_config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentGuardBinding {
    pub binding_id: String,
    pub wave84_deployment_guard_root: String,
    pub wave84_deployment_guard_decision_root: String,
    pub release_policy_root: String,
    pub operator_dashboard_root: String,
    pub accepted_live_evidence_root: String,
    pub runtime_replay_root: String,
    pub deployment_window_root: String,
    pub release_hold_root: String,
    pub rollback_readiness_root: String,
    pub imported_at_height: u64,
}

impl DeploymentGuardBinding {
    pub fn devnet(height: u64) -> Self {
        let binding_id = scoped_id("wave85", "deployment-guard-binding", height);
        Self {
            wave84_deployment_guard_root: sample_root("wave84", "deployment-guard-root"),
            wave84_deployment_guard_decision_root: sample_root(
                "wave84",
                "deployment-guard-decision-root",
            ),
            release_policy_root: sample_root("wave84", "release-policy-root"),
            operator_dashboard_root: sample_root("wave84", "operator-dashboard-root"),
            accepted_live_evidence_root: sample_root("wave84", "accepted-live-evidence-root"),
            runtime_replay_root: sample_root("wave84", "runtime-replay-root"),
            deployment_window_root: sample_root("wave84", "deployment-window-root"),
            release_hold_root: sample_root("wave84", "release-hold-unhold-root"),
            rollback_readiness_root: sample_root("wave84", "rollback-readiness-root"),
            binding_id,
            imported_at_height: height,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("binding_id", &self.binding_id)?;
        if config.require_deployment_guard_root {
            ensure_root(
                "wave84_deployment_guard_root",
                &self.wave84_deployment_guard_root,
            )?;
            ensure_root(
                "wave84_deployment_guard_decision_root",
                &self.wave84_deployment_guard_decision_root,
            )?;
        }
        if config.require_runtime_replay_root {
            ensure_root("runtime_replay_root", &self.runtime_replay_root)?;
        }
        ensure_root("release_policy_root", &self.release_policy_root)?;
        ensure_root("operator_dashboard_root", &self.operator_dashboard_root)?;
        ensure_root(
            "accepted_live_evidence_root",
            &self.accepted_live_evidence_root,
        )?;
        ensure_root("release_hold_root", &self.release_hold_root)?;
        ensure_root("rollback_readiness_root", &self.rollback_readiness_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "wave84_deployment_guard_root": self.wave84_deployment_guard_root,
            "wave84_deployment_guard_decision_root": self.wave84_deployment_guard_decision_root,
            "release_policy_root": self.release_policy_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "runtime_replay_root": self.runtime_replay_root,
            "deployment_window_root": self.deployment_window_root,
            "release_hold_root": self.release_hold_root,
            "rollback_readiness_root": self.rollback_readiness_root,
            "imported_at_height": self.imported_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment_guard_binding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackTranscript {
    pub transcript_id: String,
    pub phase: RollbackDrillPhase,
    pub source_runtime_replay_root: String,
    pub rollback_transcript_root: String,
    pub transcript_command_root: String,
    pub operator_dashboard_root: String,
    pub release_policy_root: String,
    pub previous_hold_state_root: String,
    pub resulting_hold_state_root: String,
    pub observed_at_height: u64,
    pub verdict: DrillVerdict,
    pub note: String,
}

impl RollbackTranscript {
    pub fn new(
        phase: RollbackDrillPhase,
        source_runtime_replay_root: impl Into<String>,
        operator_dashboard_root: impl Into<String>,
        release_policy_root: impl Into<String>,
        previous_hold_state_root: impl Into<String>,
        resulting_hold_state_root: impl Into<String>,
        observed_at_height: u64,
        verdict: DrillVerdict,
        note: impl Into<String>,
    ) -> Result<Self> {
        let source_runtime_replay_root = source_runtime_replay_root.into();
        let operator_dashboard_root = operator_dashboard_root.into();
        let release_policy_root = release_policy_root.into();
        let previous_hold_state_root = previous_hold_state_root.into();
        let resulting_hold_state_root = resulting_hold_state_root.into();
        let note = note.into();
        ensure_root("source_runtime_replay_root", &source_runtime_replay_root)?;
        ensure_root("operator_dashboard_root", &operator_dashboard_root)?;
        ensure_root("release_policy_root", &release_policy_root)?;
        ensure_root("previous_hold_state_root", &previous_hold_state_root)?;
        ensure_root("resulting_hold_state_root", &resulting_hold_state_root)?;
        ensure_non_empty("note", &note)?;
        let transcript_id = transcript_id(
            phase,
            &source_runtime_replay_root,
            &previous_hold_state_root,
            &resulting_hold_state_root,
            observed_at_height,
        );
        let transcript_command_root = command_root(
            "rollback_transcript",
            phase.as_str(),
            &source_runtime_replay_root,
            observed_at_height,
        );
        let rollback_transcript_root = domain_hash(
            "ROLLBACK-DRILL-TRANSCRIPT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(phase.as_str()),
                HashPart::Str(&source_runtime_replay_root),
                HashPart::Str(&operator_dashboard_root),
                HashPart::Str(&release_policy_root),
                HashPart::Str(&previous_hold_state_root),
                HashPart::Str(&resulting_hold_state_root),
                HashPart::Str(verdict.as_str()),
                HashPart::Int(observed_at_height as i128),
            ],
            32,
        );
        Ok(Self {
            transcript_id,
            phase,
            source_runtime_replay_root,
            rollback_transcript_root,
            transcript_command_root,
            operator_dashboard_root,
            release_policy_root,
            previous_hold_state_root,
            resulting_hold_state_root,
            observed_at_height,
            verdict,
            note,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "phase": self.phase.as_str(),
            "phase_ordinal": self.phase.ordinal(),
            "source_runtime_replay_root": self.source_runtime_replay_root,
            "rollback_transcript_root": self.rollback_transcript_root,
            "transcript_command_root": self.transcript_command_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "release_policy_root": self.release_policy_root,
            "previous_hold_state_root": self.previous_hold_state_root,
            "resulting_hold_state_root": self.resulting_hold_state_root,
            "observed_at_height": self.observed_at_height,
            "verdict": self.verdict.as_str(),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback_transcript", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayRollbackCommand {
    pub command_id: String,
    pub command_label: String,
    pub command_index: u16,
    pub command_root: String,
    pub replay_input_root: String,
    pub rollback_effect_root: String,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub abort_criterion_root: String,
    pub executed_at_height: u64,
    pub verdict: DrillVerdict,
}

impl ReplayRollbackCommand {
    pub fn new(
        command_label: impl Into<String>,
        command_index: u16,
        replay_input_root: impl Into<String>,
        rollback_effect_root: impl Into<String>,
        expected_receipt_root: impl Into<String>,
        observed_receipt_root: impl Into<String>,
        abort_criterion_root: impl Into<String>,
        executed_at_height: u64,
        verdict: DrillVerdict,
    ) -> Result<Self> {
        let command_label = command_label.into();
        let replay_input_root = replay_input_root.into();
        let rollback_effect_root = rollback_effect_root.into();
        let expected_receipt_root = expected_receipt_root.into();
        let observed_receipt_root = observed_receipt_root.into();
        let abort_criterion_root = abort_criterion_root.into();
        ensure_non_empty("command_label", &command_label)?;
        ensure_root("replay_input_root", &replay_input_root)?;
        ensure_root("rollback_effect_root", &rollback_effect_root)?;
        ensure_root("expected_receipt_root", &expected_receipt_root)?;
        ensure_root("observed_receipt_root", &observed_receipt_root)?;
        ensure_root("abort_criterion_root", &abort_criterion_root)?;
        let command_root = rollback_command_root(
            &command_label,
            command_index,
            &replay_input_root,
            &rollback_effect_root,
            &expected_receipt_root,
            executed_at_height,
        );
        let command_id = command_id(&command_label, command_index, &command_root);
        Ok(Self {
            command_id,
            command_label,
            command_index,
            command_root,
            replay_input_root,
            rollback_effect_root,
            expected_receipt_root,
            observed_receipt_root,
            abort_criterion_root,
            executed_at_height,
            verdict,
        })
    }

    pub fn receipt_status(&self) -> ReceiptStatus {
        if self.expected_receipt_root.is_empty() {
            ReceiptStatus::MissingExpected
        } else if self.observed_receipt_root.is_empty() {
            ReceiptStatus::MissingObserved
        } else if self.verdict == DrillVerdict::Watch {
            ReceiptStatus::Watch
        } else if self.expected_receipt_root == self.observed_receipt_root {
            ReceiptStatus::Matched
        } else {
            ReceiptStatus::Mismatched
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "command_id": self.command_id,
            "command_label": self.command_label,
            "command_index": self.command_index,
            "command_root": self.command_root,
            "replay_input_root": self.replay_input_root,
            "rollback_effect_root": self.rollback_effect_root,
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "abort_criterion_root": self.abort_criterion_root,
            "executed_at_height": self.executed_at_height,
            "verdict": self.verdict.as_str(),
            "receipt_status": self.receipt_status().as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay_rollback_command", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExpectedReceipt {
    pub receipt_id: String,
    pub command_label: String,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub comparison_root: String,
    pub status: ReceiptStatus,
    pub compared_at_height: u64,
}

impl ExpectedReceipt {
    pub fn from_command(command: &ReplayRollbackCommand, compared_at_height: u64) -> Self {
        let status = command.receipt_status();
        let comparison_root = receipt_comparison_root(
            &command.command_label,
            &command.expected_receipt_root,
            &command.observed_receipt_root,
            status,
            compared_at_height,
        );
        let receipt_id = scoped_id(&command.command_label, status.as_str(), compared_at_height);
        Self {
            receipt_id,
            command_label: command.command_label.clone(),
            expected_receipt_root: command.expected_receipt_root.clone(),
            observed_receipt_root: command.observed_receipt_root.clone(),
            comparison_root,
            status,
            compared_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "command_label": self.command_label,
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "comparison_root": self.comparison_root,
            "status": self.status.as_str(),
            "compared_at_height": self.compared_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("expected_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReplayFreshnessBlocker {
    pub freshness_id: String,
    pub source_runtime_replay_root: String,
    pub replay_accepted_height: u64,
    pub observed_at_height: u64,
    pub max_age_blocks: u64,
    pub age_blocks: u64,
    pub status: FreshnessStatus,
    pub blocker_replay_root: String,
}

impl ReplayFreshnessBlocker {
    pub fn new(
        source_runtime_replay_root: impl Into<String>,
        replay_accepted_height: u64,
        observed_at_height: u64,
        max_age_blocks: u64,
    ) -> Result<Self> {
        let source_runtime_replay_root = source_runtime_replay_root.into();
        ensure_root("source_runtime_replay_root", &source_runtime_replay_root)?;
        ensure(max_age_blocks > 0, "max replay age must be non-zero")?;
        let age_blocks = observed_at_height.saturating_sub(replay_accepted_height);
        let status = if age_blocks > max_age_blocks {
            FreshnessStatus::Blocked
        } else if age_blocks.saturating_mul(2) >= max_age_blocks {
            FreshnessStatus::Aging
        } else {
            FreshnessStatus::Fresh
        };
        let freshness_id = replay_freshness_id(
            &source_runtime_replay_root,
            replay_accepted_height,
            observed_at_height,
            max_age_blocks,
        );
        let blocker_replay_root = domain_hash(
            "ROLLBACK-DRILL-FRESHNESS-BLOCKER-REPLAY-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&source_runtime_replay_root),
                HashPart::Int(replay_accepted_height as i128),
                HashPart::Int(observed_at_height as i128),
                HashPart::Int(max_age_blocks as i128),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        Ok(Self {
            freshness_id,
            source_runtime_replay_root,
            replay_accepted_height,
            observed_at_height,
            max_age_blocks,
            age_blocks,
            status,
            blocker_replay_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "freshness_id": self.freshness_id,
            "source_runtime_replay_root": self.source_runtime_replay_root,
            "replay_accepted_height": self.replay_accepted_height,
            "observed_at_height": self.observed_at_height,
            "max_age_blocks": self.max_age_blocks,
            "age_blocks": self.age_blocks,
            "status": self.status.as_str(),
            "blocker_replay_root": self.blocker_replay_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("replay_freshness_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AbortCriterion {
    pub criterion_id: String,
    pub kind: AbortCriterionKind,
    pub subject: String,
    pub evidence_root: String,
    pub command_root: String,
    pub abort_root: String,
    pub status: AbortCriterionStatus,
    pub observed_at_height: u64,
    pub detail: String,
}

impl AbortCriterion {
    pub fn new(
        kind: AbortCriterionKind,
        subject: impl Into<String>,
        evidence_root: impl Into<String>,
        command_root: impl Into<String>,
        status: AbortCriterionStatus,
        observed_at_height: u64,
        detail: impl Into<String>,
    ) -> Result<Self> {
        let subject = subject.into();
        let evidence_root = evidence_root.into();
        let command_root = command_root.into();
        let detail = detail.into();
        ensure_non_empty("subject", &subject)?;
        ensure_root("evidence_root", &evidence_root)?;
        ensure_root("command_root", &command_root)?;
        ensure_non_empty("detail", &detail)?;
        let abort_root = abort_root(kind, &subject, &evidence_root, &command_root, status);
        let criterion_id = abort_criterion_id(kind, &subject, &abort_root, observed_at_height);
        Ok(Self {
            criterion_id,
            kind,
            subject,
            evidence_root,
            command_root,
            abort_root,
            status,
            observed_at_height,
            detail,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "kind": self.kind.as_str(),
            "subject": self.subject,
            "evidence_root": self.evidence_root,
            "command_root": self.command_root,
            "abort_root": self.abort_root,
            "status": self.status.as_str(),
            "observed_at_height": self.observed_at_height,
            "detail": self.detail,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("abort_criterion", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub role: OperatorRole,
    pub decision: OperatorAckDecision,
    pub signed_dashboard_root: String,
    pub signed_release_policy_root: String,
    pub signed_rollback_drill_root: String,
    pub signed_statement_root: String,
    pub acknowledged_at_height: u64,
    pub note: String,
}

impl OperatorAcknowledgement {
    pub fn new(
        operator_id: impl Into<String>,
        role: OperatorRole,
        decision: OperatorAckDecision,
        signed_dashboard_root: impl Into<String>,
        signed_release_policy_root: impl Into<String>,
        signed_rollback_drill_root: impl Into<String>,
        acknowledged_at_height: u64,
        note: impl Into<String>,
    ) -> Result<Self> {
        let operator_id = operator_id.into();
        let signed_dashboard_root = signed_dashboard_root.into();
        let signed_release_policy_root = signed_release_policy_root.into();
        let signed_rollback_drill_root = signed_rollback_drill_root.into();
        let note = note.into();
        ensure_non_empty("operator_id", &operator_id)?;
        ensure_root("signed_dashboard_root", &signed_dashboard_root)?;
        ensure_root("signed_release_policy_root", &signed_release_policy_root)?;
        ensure_root("signed_rollback_drill_root", &signed_rollback_drill_root)?;
        ensure_non_empty("note", &note)?;
        let signed_statement_root = operator_signed_statement_root(
            &operator_id,
            role,
            decision,
            &signed_dashboard_root,
            &signed_release_policy_root,
            &signed_rollback_drill_root,
            acknowledged_at_height,
        );
        let acknowledgement_id = operator_acknowledgement_id(
            &operator_id,
            role,
            decision,
            &signed_statement_root,
            acknowledged_at_height,
        );
        Ok(Self {
            acknowledgement_id,
            operator_id,
            role,
            decision,
            signed_dashboard_root,
            signed_release_policy_root,
            signed_rollback_drill_root,
            signed_statement_root,
            acknowledged_at_height,
            note,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "decision": self.decision.as_str(),
            "signed_dashboard_root": self.signed_dashboard_root,
            "signed_release_policy_root": self.signed_release_policy_root,
            "signed_rollback_drill_root": self.signed_rollback_drill_root,
            "signed_statement_root": self.signed_statement_root,
            "acknowledged_at_height": self.acknowledged_at_height,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator_acknowledgement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldUnholdDrillEvent {
    pub event_id: String,
    pub action: HoldUnholdAction,
    pub hold_state: ReleaseHoldState,
    pub previous_hold_root: String,
    pub resulting_hold_root: String,
    pub actor_id: String,
    pub evidence_root: String,
    pub event_height: u64,
    pub fail_closed: bool,
    pub note: String,
}

impl HoldUnholdDrillEvent {
    pub fn new(
        action: HoldUnholdAction,
        hold_state: ReleaseHoldState,
        previous_hold_root: impl Into<String>,
        actor_id: impl Into<String>,
        evidence_root: impl Into<String>,
        event_height: u64,
        fail_closed: bool,
        note: impl Into<String>,
    ) -> Result<Self> {
        let previous_hold_root = previous_hold_root.into();
        let actor_id = actor_id.into();
        let evidence_root = evidence_root.into();
        let note = note.into();
        ensure_root("previous_hold_root", &previous_hold_root)?;
        ensure_non_empty("actor_id", &actor_id)?;
        ensure_root("evidence_root", &evidence_root)?;
        ensure_non_empty("note", &note)?;
        let resulting_hold_root = hold_state_root(
            action,
            hold_state,
            &previous_hold_root,
            &actor_id,
            &evidence_root,
            event_height,
            fail_closed,
        );
        let event_id = hold_unhold_event_id(action, hold_state, &resulting_hold_root, event_height);
        Ok(Self {
            event_id,
            action,
            hold_state,
            previous_hold_root,
            resulting_hold_root,
            actor_id,
            evidence_root,
            event_height,
            fail_closed,
            note,
        })
    }

    pub fn release_held(&self) -> bool {
        self.fail_closed || self.hold_state.release_is_held()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "action": self.action.as_str(),
            "hold_state": self.hold_state.as_str(),
            "previous_hold_root": self.previous_hold_root,
            "resulting_hold_root": self.resulting_hold_root,
            "actor_id": self.actor_id,
            "evidence_root": self.evidence_root,
            "event_height": self.event_height,
            "fail_closed": self.fail_closed,
            "release_held": self.release_held(),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("hold_unhold_drill_event", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackDrillBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub severity: BlockerSeverity,
    pub subject: String,
    pub evidence_root: String,
    pub detail: String,
    pub observed_at_height: u64,
}

impl RollbackDrillBlocker {
    pub fn new(
        kind: BlockerKind,
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
        let blocker_id = blocker_id(kind, severity, &subject, &evidence_root, observed_at_height);
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
        record_root("rollback_drill_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DrillCounters {
    pub transcript_count: u16,
    pub pass_transcript_count: u16,
    pub rollback_command_count: u16,
    pub expected_receipt_count: u16,
    pub matched_receipt_count: u16,
    pub abort_criterion_count: u16,
    pub armed_abort_criterion_count: u16,
    pub operator_ack_count: u16,
    pub hold_unhold_event_count: u16,
    pub release_held_event_count: u16,
    pub watch_count: u16,
    pub blocking_count: u16,
}

impl DrillCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "transcript_count": self.transcript_count,
            "pass_transcript_count": self.pass_transcript_count,
            "rollback_command_count": self.rollback_command_count,
            "expected_receipt_count": self.expected_receipt_count,
            "matched_receipt_count": self.matched_receipt_count,
            "abort_criterion_count": self.abort_criterion_count,
            "armed_abort_criterion_count": self.armed_abort_criterion_count,
            "operator_ack_count": self.operator_ack_count,
            "hold_unhold_event_count": self.hold_unhold_event_count,
            "release_held_event_count": self.release_held_event_count,
            "watch_count": self.watch_count,
            "blocking_count": self.blocking_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback_drill_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackDrillDecision {
    pub release_held: bool,
    pub rollback_drill_passed: bool,
    pub fail_closed: bool,
    pub verdict: DrillVerdict,
    pub evidence_root: String,
    pub blocker_root: String,
    pub command_root: String,
    pub receipt_root: String,
    pub abort_root: String,
    pub acknowledgement_root: String,
    pub hold_unhold_root: String,
    pub counters_root: String,
    pub decision_root: String,
    pub decided_at_height: u64,
}

impl RollbackDrillDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "release_held": self.release_held,
            "rollback_drill_passed": self.rollback_drill_passed,
            "fail_closed": self.fail_closed,
            "verdict": self.verdict.as_str(),
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "command_root": self.command_root,
            "receipt_root": self.receipt_root,
            "abort_root": self.abort_root,
            "acknowledgement_root": self.acknowledgement_root,
            "hold_unhold_root": self.hold_unhold_root,
            "counters_root": self.counters_root,
            "decision_root": self.decision_root,
            "decided_at_height": self.decided_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateInput {
    pub config: Config,
    pub height: u64,
    pub guard_binding: DeploymentGuardBinding,
    pub transcripts: Vec<RollbackTranscript>,
    pub rollback_commands: Vec<ReplayRollbackCommand>,
    pub expected_receipts: Vec<ExpectedReceipt>,
    pub freshness_blocker: ReplayFreshnessBlocker,
    pub abort_criteria: Vec<AbortCriterion>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub hold_unhold_events: Vec<HoldUnholdDrillEvent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub guard_binding: DeploymentGuardBinding,
    pub transcripts: Vec<RollbackTranscript>,
    pub rollback_commands: Vec<ReplayRollbackCommand>,
    pub expected_receipts: Vec<ExpectedReceipt>,
    pub freshness_blocker: ReplayFreshnessBlocker,
    pub abort_criteria: Vec<AbortCriterion>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub hold_unhold_events: Vec<HoldUnholdDrillEvent>,
    pub blockers: Vec<RollbackDrillBlocker>,
    pub counters: DrillCounters,
    pub transcript_root: String,
    pub command_root: String,
    pub receipt_root: String,
    pub freshness_root: String,
    pub abort_root: String,
    pub acknowledgement_root: String,
    pub hold_unhold_root: String,
    pub evidence_root: String,
    pub blocker_root: String,
    pub decision: RollbackDrillDecision,
}

impl State {
    pub fn new(input: StateInput) -> Result<Self> {
        input.config.validate()?;
        input.guard_binding.validate(&input.config)?;
        ensure(
            !input.transcripts.is_empty(),
            "rollback drill requires at least one transcript",
        )?;
        ensure(
            !input.rollback_commands.is_empty(),
            "rollback drill requires at least one command",
        )?;
        ensure(
            !input.expected_receipts.is_empty(),
            "rollback drill requires at least one receipt",
        )?;
        let transcript_root = merkle_root(
            "rollback-drill-transcripts",
            &input
                .transcripts
                .iter()
                .map(RollbackTranscript::public_record)
                .collect::<Vec<_>>(),
        );
        let command_root = merkle_root(
            "rollback-drill-commands",
            &input
                .rollback_commands
                .iter()
                .map(ReplayRollbackCommand::public_record)
                .collect::<Vec<_>>(),
        );
        let receipt_root = merkle_root(
            "rollback-drill-expected-receipts",
            &input
                .expected_receipts
                .iter()
                .map(ExpectedReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let freshness_root = input.freshness_blocker.state_root();
        let abort_root = merkle_root(
            "rollback-drill-abort-criteria",
            &input
                .abort_criteria
                .iter()
                .map(AbortCriterion::public_record)
                .collect::<Vec<_>>(),
        );
        let acknowledgement_root = merkle_root(
            "rollback-drill-operator-acknowledgements",
            &input
                .operator_acknowledgements
                .iter()
                .map(OperatorAcknowledgement::public_record)
                .collect::<Vec<_>>(),
        );
        let hold_unhold_root = merkle_root(
            "rollback-drill-hold-unhold-events",
            &input
                .hold_unhold_events
                .iter()
                .map(HoldUnholdDrillEvent::public_record)
                .collect::<Vec<_>>(),
        );
        let mut counters = compute_counters(&input);
        let mut blockers = evaluate_blockers(&input, &counters);
        if counters.watch_count > input.config.max_watch_items {
            push_blocker(
                &mut blockers,
                BlockerKind::WatchLimitExceeded,
                BlockerSeverity::Blocking,
                "watch_count",
                &counters.state_root(),
                format!(
                    "watch count {} exceeds configured maximum {}",
                    counters.watch_count, input.config.max_watch_items
                ),
                input.height,
            );
        }
        let blocker_root = merkle_root(
            "rollback-drill-blockers",
            &blockers
                .iter()
                .map(RollbackDrillBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        counters.blocking_count = blockers
            .iter()
            .filter(|blocker| blocker.severity.blocks_release())
            .count() as u16;
        let counters_root = counters.state_root();
        let evidence_root = domain_hash(
            "ROLLBACK-DRILL-EVIDENCE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&input.guard_binding.state_root()),
                HashPart::Str(&transcript_root),
                HashPart::Str(&command_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&freshness_root),
                HashPart::Str(&abort_root),
                HashPart::Str(&acknowledgement_root),
                HashPart::Str(&hold_unhold_root),
                HashPart::Str(&counters_root),
            ],
            32,
        );
        let blocking_count = blockers
            .iter()
            .filter(|blocker| blocker.severity.blocks_release())
            .count() as u16;
        let release_held_by_events = input
            .hold_unhold_events
            .last()
            .map(HoldUnholdDrillEvent::release_held)
            .unwrap_or(true);
        let fail_closed = input.config.fail_closed || input.config.require_fail_closed_hold;
        let rollback_drill_passed = blocking_count == 0
            && counters.rollback_command_count >= input.config.min_rollback_commands
            && counters.expected_receipt_count >= input.config.min_expected_receipts
            && counters.matched_receipt_count >= input.config.min_expected_receipts
            && counters.armed_abort_criterion_count >= input.config.min_abort_criteria
            && counters.operator_ack_count >= input.config.min_operator_acks
            && counters.hold_unhold_event_count >= input.config.min_hold_unhold_events
            && !input.freshness_blocker.status.blocks_release();
        let verdict = if blocking_count > 0 {
            DrillVerdict::Hold
        } else if counters.watch_count > 0
            || input.freshness_blocker.status == FreshnessStatus::Aging
        {
            DrillVerdict::Watch
        } else {
            DrillVerdict::Pass
        };
        let release_held = fail_closed || release_held_by_events || !rollback_drill_passed;
        let decision_root = decision_root(
            release_held,
            rollback_drill_passed,
            fail_closed,
            verdict,
            &evidence_root,
            &blocker_root,
            &counters_root,
            input.height,
        );
        let decision = RollbackDrillDecision {
            release_held,
            rollback_drill_passed,
            fail_closed,
            verdict,
            evidence_root: evidence_root.clone(),
            blocker_root: blocker_root.clone(),
            command_root: command_root.clone(),
            receipt_root: receipt_root.clone(),
            abort_root: abort_root.clone(),
            acknowledgement_root: acknowledgement_root.clone(),
            hold_unhold_root: hold_unhold_root.clone(),
            counters_root,
            decision_root,
            decided_at_height: input.height,
        };
        Ok(Self {
            config: input.config,
            height: input.height,
            guard_binding: input.guard_binding,
            transcripts: input.transcripts,
            rollback_commands: input.rollback_commands,
            expected_receipts: input.expected_receipts,
            freshness_blocker: input.freshness_blocker,
            abort_criteria: input.abort_criteria,
            operator_acknowledgements: input.operator_acknowledgements,
            hold_unhold_events: input.hold_unhold_events,
            blockers,
            counters,
            transcript_root,
            command_root,
            receipt_root,
            freshness_root,
            abort_root,
            acknowledgement_root,
            hold_unhold_root,
            evidence_root,
            blocker_root,
            decision,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let guard_binding = DeploymentGuardBinding::devnet(height);
        let hold_events = devnet_hold_unhold_events(&guard_binding, height);
        let transcripts = devnet_transcripts(&guard_binding, &hold_events, height);
        let rollback_commands = devnet_rollback_commands(&guard_binding, height);
        let expected_receipts = rollback_commands
            .iter()
            .map(|command| ExpectedReceipt::from_command(command, height))
            .collect::<Vec<_>>();
        let freshness_blocker = ReplayFreshnessBlocker::new(
            guard_binding.runtime_replay_root.clone(),
            DEFAULT_REPLAY_ACCEPTED_HEIGHT,
            height,
            config.max_replay_age_blocks,
        )
        .unwrap_or_else_fallback(height, config.max_replay_age_blocks);
        let abort_criteria = devnet_abort_criteria(&rollback_commands, height);
        let provisional_drill_root = merkle_root(
            "rollback-drill-devnet-provisional-root",
            &[
                guard_binding.public_record(),
                json!({ "command_root": merkle_root(
                    "rollback-drill-devnet-provisional-commands",
                    &rollback_commands
                        .iter()
                        .map(ReplayRollbackCommand::public_record)
                        .collect::<Vec<_>>(),
                ) }),
            ],
        );
        let operator_acknowledgements =
            devnet_operator_acknowledgements(&guard_binding, &provisional_drill_root, height);
        match Self::new(StateInput {
            config,
            height,
            guard_binding,
            transcripts,
            rollback_commands,
            expected_receipts,
            freshness_blocker,
            abort_criteria,
            operator_acknowledgements,
            hold_unhold_events: hold_events,
        }) {
            Ok(state) => state,
            Err(_) => Self::fallback(),
        }
    }

    pub fn fallback() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let guard_binding = DeploymentGuardBinding::devnet(height);
        let fallback_hold_root = sample_root("fallback", "hold-root");
        let hold_event = HoldUnholdDrillEvent::new(
            HoldUnholdAction::AssertHold,
            ReleaseHoldState::FailClosedHeld,
            fallback_hold_root,
            "fallback-release-coordinator",
            guard_binding.release_hold_root.clone(),
            height,
            true,
            "fallback rollback drill keeps release held",
        )
        .unwrap_or_else_fallback(height);
        let transcript = RollbackTranscript::new(
            RollbackDrillPhase::Prepare,
            guard_binding.runtime_replay_root.clone(),
            guard_binding.operator_dashboard_root.clone(),
            guard_binding.release_policy_root.clone(),
            hold_event.previous_hold_root.clone(),
            hold_event.resulting_hold_root.clone(),
            height,
            DrillVerdict::Hold,
            "fallback transcript records fail-closed rollback drill hold",
        )
        .unwrap_or_else_fallback(height);
        let command = ReplayRollbackCommand::new(
            "fallback_assert_fail_closed_hold",
            0,
            guard_binding.runtime_replay_root.clone(),
            hold_event.resulting_hold_root.clone(),
            sample_root("fallback", "expected-receipt"),
            sample_root("fallback", "observed-receipt"),
            sample_root("fallback", "abort-criterion"),
            height,
            DrillVerdict::Hold,
        )
        .unwrap_or_else_fallback(height);
        let receipt = ExpectedReceipt::from_command(&command, height);
        let freshness_blocker = ReplayFreshnessBlocker::new(
            guard_binding.runtime_replay_root.clone(),
            height.saturating_sub(DEFAULT_MAX_REPLAY_AGE_BLOCKS + 1),
            height,
            DEFAULT_MAX_REPLAY_AGE_BLOCKS,
        )
        .unwrap_or_else_fallback(height, DEFAULT_MAX_REPLAY_AGE_BLOCKS);
        let abort = AbortCriterion::new(
            AbortCriterionKind::StaleReplay,
            "fallback_freshness",
            freshness_blocker.state_root(),
            command.command_root.clone(),
            AbortCriterionStatus::Triggered,
            height,
            "fallback freshness blocker is triggered",
        )
        .unwrap_or_else_fallback(height);
        let ack = OperatorAcknowledgement::new(
            "fallback-operator",
            OperatorRole::RuntimeReplayOperator,
            OperatorAckDecision::Hold,
            guard_binding.operator_dashboard_root.clone(),
            guard_binding.release_policy_root.clone(),
            transcript.state_root(),
            height,
            "fallback operator holds release",
        )
        .unwrap_or_else_fallback(height);
        match Self::new(StateInput {
            config,
            height,
            guard_binding,
            transcripts: vec![transcript],
            rollback_commands: vec![command],
            expected_receipts: vec![receipt],
            freshness_blocker,
            abort_criteria: vec![abort],
            operator_acknowledgements: vec![ack],
            hold_unhold_events: vec![hold_event],
        }) {
            Ok(state) => state,
            Err(_) => minimal_fallback_state(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "guard_binding": self.guard_binding.public_record(),
            "transcript_root": self.transcript_root,
            "command_root": self.command_root,
            "receipt_root": self.receipt_root,
            "freshness_root": self.freshness_root,
            "abort_root": self.abort_root,
            "acknowledgement_root": self.acknowledgement_root,
            "hold_unhold_root": self.hold_unhold_root,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "counters": self.counters.public_record(),
            "decision": self.decision.public_record(),
            "transcripts": self.transcripts.iter().map(RollbackTranscript::public_record).collect::<Vec<_>>(),
            "rollback_commands": self.rollback_commands.iter().map(ReplayRollbackCommand::public_record).collect::<Vec<_>>(),
            "expected_receipts": self.expected_receipts.iter().map(ExpectedReceipt::public_record).collect::<Vec<_>>(),
            "freshness_blocker": self.freshness_blocker.public_record(),
            "abort_criteria": self.abort_criteria.iter().map(AbortCriterion::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "hold_unhold_events": self.hold_unhold_events.iter().map(HoldUnholdDrillEvent::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(RollbackDrillBlocker::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ROLLBACK-DRILL-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Int(self.height as i128),
                HashPart::Str(&self.guard_binding.state_root()),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.command_root),
                HashPart::Str(&self.receipt_root),
                HashPart::Str(&self.freshness_root),
                HashPart::Str(&self.abort_root),
                HashPart::Str(&self.acknowledgement_root),
                HashPart::Str(&self.hold_unhold_root),
                HashPart::Str(&self.evidence_root),
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

fn compute_counters(input: &StateInput) -> DrillCounters {
    let transcript_count = input.transcripts.len() as u16;
    let pass_transcript_count = input
        .transcripts
        .iter()
        .filter(|transcript| transcript.verdict == DrillVerdict::Pass)
        .count() as u16;
    let rollback_command_count = input.rollback_commands.len() as u16;
    let expected_receipt_count = input
        .expected_receipts
        .iter()
        .filter(|receipt| !receipt.expected_receipt_root.is_empty())
        .count() as u16;
    let matched_receipt_count = input
        .expected_receipts
        .iter()
        .filter(|receipt| receipt.status == ReceiptStatus::Matched)
        .count() as u16;
    let abort_criterion_count = input.abort_criteria.len() as u16;
    let armed_abort_criterion_count = input
        .abort_criteria
        .iter()
        .filter(|criterion| criterion.status == AbortCriterionStatus::Armed)
        .count() as u16;
    let operator_ack_count = input
        .operator_acknowledgements
        .iter()
        .filter(|ack| ack.decision.counts_for_quorum())
        .count() as u16;
    let hold_unhold_event_count = input.hold_unhold_events.len() as u16;
    let release_held_event_count = input
        .hold_unhold_events
        .iter()
        .filter(|event| event.release_held())
        .count() as u16;
    let transcript_watch = input
        .transcripts
        .iter()
        .filter(|transcript| transcript.verdict.is_watch())
        .count() as u16;
    let command_watch = input
        .rollback_commands
        .iter()
        .filter(|command| command.verdict.is_watch())
        .count() as u16;
    let receipt_watch = input
        .expected_receipts
        .iter()
        .filter(|receipt| receipt.status.is_watch())
        .count() as u16;
    let abort_watch = input
        .abort_criteria
        .iter()
        .filter(|criterion| criterion.status.is_watch())
        .count() as u16;
    let ack_watch = input
        .operator_acknowledgements
        .iter()
        .filter(|ack| ack.decision.is_watch())
        .count() as u16;
    let freshness_watch = if input.freshness_blocker.status == FreshnessStatus::Aging {
        1
    } else {
        0
    };
    DrillCounters {
        transcript_count,
        pass_transcript_count,
        rollback_command_count,
        expected_receipt_count,
        matched_receipt_count,
        abort_criterion_count,
        armed_abort_criterion_count,
        operator_ack_count,
        hold_unhold_event_count,
        release_held_event_count,
        watch_count: transcript_watch
            + command_watch
            + receipt_watch
            + abort_watch
            + ack_watch
            + freshness_watch,
        blocking_count: 0,
    }
}

fn evaluate_blockers(input: &StateInput, counters: &DrillCounters) -> Vec<RollbackDrillBlocker> {
    let mut blockers = Vec::new();
    push_binding_blockers(input, &mut blockers);
    push_transcript_blockers(input, counters, &mut blockers);
    push_command_blockers(input, counters, &mut blockers);
    push_receipt_blockers(input, counters, &mut blockers);
    push_freshness_blockers(input, &mut blockers);
    push_abort_blockers(input, counters, &mut blockers);
    push_operator_blockers(input, counters, &mut blockers);
    push_hold_unhold_blockers(input, counters, &mut blockers);
    blockers
}

fn push_binding_blockers(input: &StateInput, blockers: &mut Vec<RollbackDrillBlocker>) {
    if input.config.require_deployment_guard_root
        && input.guard_binding.wave84_deployment_guard_root.is_empty()
    {
        push_blocker(
            blockers,
            BlockerKind::DeploymentGuardRootMissing,
            BlockerSeverity::Blocking,
            "wave84_deployment_guard_root",
            &input.guard_binding.state_root(),
            "Wave 84 deployment guard root is missing from rollback drill binding",
            input.height,
        );
    }
    if input.config.require_runtime_replay_root
        && input.guard_binding.runtime_replay_root.is_empty()
    {
        push_blocker(
            blockers,
            BlockerKind::RuntimeReplayRootMissing,
            BlockerSeverity::Blocking,
            "runtime_replay_root",
            &input.guard_binding.state_root(),
            "Wave 84 runtime replay root is missing from rollback drill binding",
            input.height,
        );
    }
}

fn push_transcript_blockers(
    input: &StateInput,
    counters: &DrillCounters,
    blockers: &mut Vec<RollbackDrillBlocker>,
) {
    if input.config.require_rollback_transcripts && counters.transcript_count == 0 {
        push_blocker(
            blockers,
            BlockerKind::RollbackTranscriptMissing,
            BlockerSeverity::Blocking,
            "rollback_transcripts",
            &input.guard_binding.state_root(),
            "rollback drill has no transcript roots",
            input.height,
        );
    }
    let phases = input
        .transcripts
        .iter()
        .map(|transcript| transcript.phase)
        .collect::<BTreeSet<_>>();
    for phase in RollbackDrillPhase::all() {
        if !phases.contains(&phase) {
            push_blocker(
                blockers,
                BlockerKind::RollbackTranscriptMissing,
                BlockerSeverity::Watch,
                phase.as_str(),
                &input.guard_binding.state_root(),
                format!(
                    "rollback drill phase transcript is absent: {}",
                    phase.as_str()
                ),
                input.height,
            );
        }
    }
    for transcript in &input.transcripts {
        if transcript.verdict.blocks_release() {
            push_blocker(
                blockers,
                BlockerKind::RollbackTranscriptMissing,
                BlockerSeverity::Blocking,
                &transcript.transcript_id,
                &transcript.state_root(),
                format!(
                    "rollback transcript verdict is {}",
                    transcript.verdict.as_str()
                ),
                input.height,
            );
        } else if transcript.verdict.is_watch() {
            push_blocker(
                blockers,
                BlockerKind::RollbackTranscriptMissing,
                BlockerSeverity::Watch,
                &transcript.transcript_id,
                &transcript.state_root(),
                "rollback transcript is watch-listed",
                input.height,
            );
        }
    }
}

fn push_command_blockers(
    input: &StateInput,
    counters: &DrillCounters,
    blockers: &mut Vec<RollbackDrillBlocker>,
) {
    if input.config.require_command_roots
        && counters.rollback_command_count < input.config.min_rollback_commands
    {
        push_blocker(
            blockers,
            BlockerKind::RollbackCommandMissing,
            BlockerSeverity::Blocking,
            "rollback_commands",
            &input.guard_binding.state_root(),
            format!(
                "rollback command roots {} below required {}",
                counters.rollback_command_count, input.config.min_rollback_commands
            ),
            input.height,
        );
    }
    let mut command_labels = BTreeSet::new();
    for command in &input.rollback_commands {
        command_labels.insert(command.command_label.clone());
        if command.command_root.is_empty() {
            push_blocker(
                blockers,
                BlockerKind::RollbackCommandMissing,
                BlockerSeverity::Blocking,
                &command.command_label,
                &command.state_root(),
                "rollback command root is missing",
                input.height,
            );
        }
        if command.verdict.blocks_release() {
            push_blocker(
                blockers,
                BlockerKind::RollbackCommandMissing,
                BlockerSeverity::Blocking,
                &command.command_label,
                &command.state_root(),
                format!("rollback command verdict is {}", command.verdict.as_str()),
                input.height,
            );
        }
    }
    for label in rollback_command_labels() {
        if !command_labels.contains(label) {
            push_blocker(
                blockers,
                BlockerKind::RollbackCommandMissing,
                BlockerSeverity::Blocking,
                label,
                &input.guard_binding.state_root(),
                format!("required rollback command is absent: {label}"),
                input.height,
            );
        }
    }
}

fn push_receipt_blockers(
    input: &StateInput,
    counters: &DrillCounters,
    blockers: &mut Vec<RollbackDrillBlocker>,
) {
    if input.config.require_expected_receipts
        && counters.expected_receipt_count < input.config.min_expected_receipts
    {
        push_blocker(
            blockers,
            BlockerKind::ExpectedReceiptMissing,
            BlockerSeverity::Blocking,
            "expected_receipts",
            &input.guard_binding.state_root(),
            format!(
                "expected receipt roots {} below required {}",
                counters.expected_receipt_count, input.config.min_expected_receipts
            ),
            input.height,
        );
    }
    for receipt in &input.expected_receipts {
        match receipt.status {
            ReceiptStatus::Matched => {}
            ReceiptStatus::Watch => push_blocker(
                blockers,
                BlockerKind::ReceiptMismatch,
                BlockerSeverity::Watch,
                &receipt.command_label,
                &receipt.state_root(),
                "receipt comparison is watch-listed",
                input.height,
            ),
            ReceiptStatus::MissingExpected => push_blocker(
                blockers,
                BlockerKind::ExpectedReceiptMissing,
                BlockerSeverity::Blocking,
                &receipt.command_label,
                &receipt.state_root(),
                "expected receipt root is missing",
                input.height,
            ),
            ReceiptStatus::MissingObserved => push_blocker(
                blockers,
                BlockerKind::ObservedReceiptMissing,
                BlockerSeverity::Blocking,
                &receipt.command_label,
                &receipt.state_root(),
                "observed receipt root is missing",
                input.height,
            ),
            ReceiptStatus::Mismatched => push_blocker(
                blockers,
                BlockerKind::ReceiptMismatch,
                BlockerSeverity::Blocking,
                &receipt.command_label,
                &receipt.state_root(),
                "expected and observed rollback receipts do not match",
                input.height,
            ),
        }
    }
}

fn push_freshness_blockers(input: &StateInput, blockers: &mut Vec<RollbackDrillBlocker>) {
    if input.config.require_replay_freshness && input.freshness_blocker.status.blocks_release() {
        push_blocker(
            blockers,
            BlockerKind::ReplayFreshnessBlocked,
            BlockerSeverity::Blocking,
            "freshness_blocker",
            &input.freshness_blocker.state_root(),
            "runtime replay freshness blocker replay is outside the allowed window",
            input.height,
        );
    } else if input.freshness_blocker.status == FreshnessStatus::Aging {
        push_blocker(
            blockers,
            BlockerKind::ReplayFreshnessBlocked,
            BlockerSeverity::Watch,
            "freshness_blocker",
            &input.freshness_blocker.state_root(),
            "runtime replay freshness blocker replay is aging",
            input.height,
        );
    }
}

fn push_abort_blockers(
    input: &StateInput,
    counters: &DrillCounters,
    blockers: &mut Vec<RollbackDrillBlocker>,
) {
    if input.config.require_abort_criteria
        && counters.armed_abort_criterion_count < input.config.min_abort_criteria
    {
        push_blocker(
            blockers,
            BlockerKind::AbortCriterionMissing,
            BlockerSeverity::Blocking,
            "abort_criteria",
            &input.guard_binding.state_root(),
            format!(
                "armed abort criteria {} below required {}",
                counters.armed_abort_criterion_count, input.config.min_abort_criteria
            ),
            input.height,
        );
    }
    for criterion in &input.abort_criteria {
        if criterion.status.blocks_release() {
            let kind = if criterion.status == AbortCriterionStatus::Triggered {
                BlockerKind::AbortCriterionTriggered
            } else {
                BlockerKind::AbortCriterionMissing
            };
            push_blocker(
                blockers,
                kind,
                BlockerSeverity::Blocking,
                &criterion.subject,
                &criterion.state_root(),
                format!("abort criterion is {}", criterion.status.as_str()),
                input.height,
            );
        } else if criterion.status.is_watch() {
            push_blocker(
                blockers,
                BlockerKind::AbortCriterionTriggered,
                BlockerSeverity::Watch,
                &criterion.subject,
                &criterion.state_root(),
                "abort criterion is watch-listed",
                input.height,
            );
        }
    }
}

fn push_operator_blockers(
    input: &StateInput,
    counters: &DrillCounters,
    blockers: &mut Vec<RollbackDrillBlocker>,
) {
    if input.config.require_operator_acknowledgements
        && counters.operator_ack_count < input.config.min_operator_acks
    {
        push_blocker(
            blockers,
            BlockerKind::OperatorAckMissing,
            BlockerSeverity::Blocking,
            "operator_acknowledgements",
            &input.guard_binding.state_root(),
            format!(
                "operator acknowledgement quorum {} below required {}",
                counters.operator_ack_count, input.config.min_operator_acks
            ),
            input.height,
        );
    }
    let roles = input
        .operator_acknowledgements
        .iter()
        .filter(|ack| ack.decision.counts_for_quorum())
        .map(|ack| ack.role)
        .collect::<BTreeSet<_>>();
    for role in OperatorRole::required() {
        if !roles.contains(&role) {
            push_blocker(
                blockers,
                BlockerKind::OperatorAckMissing,
                BlockerSeverity::Blocking,
                role.as_str(),
                &input.guard_binding.state_root(),
                format!(
                    "required operator acknowledgement role is absent: {}",
                    role.as_str()
                ),
                input.height,
            );
        }
    }
    for acknowledgement in &input.operator_acknowledgements {
        if acknowledgement.decision.blocks_release() {
            push_blocker(
                blockers,
                BlockerKind::OperatorAckRejected,
                BlockerSeverity::Blocking,
                &acknowledgement.operator_id,
                &acknowledgement.state_root(),
                format!(
                    "operator acknowledgement is {}",
                    acknowledgement.decision.as_str()
                ),
                input.height,
            );
        } else if acknowledgement.decision.is_watch() {
            push_blocker(
                blockers,
                BlockerKind::OperatorAckRejected,
                BlockerSeverity::Watch,
                &acknowledgement.operator_id,
                &acknowledgement.state_root(),
                "operator acknowledgement is watch-listed",
                input.height,
            );
        }
    }
}

fn push_hold_unhold_blockers(
    input: &StateInput,
    counters: &DrillCounters,
    blockers: &mut Vec<RollbackDrillBlocker>,
) {
    if counters.hold_unhold_event_count < input.config.min_hold_unhold_events {
        push_blocker(
            blockers,
            BlockerKind::HoldUnholdMismatch,
            BlockerSeverity::Blocking,
            "hold_unhold_events",
            &input.guard_binding.release_hold_root,
            format!(
                "hold/unhold drill events {} below required {}",
                counters.hold_unhold_event_count, input.config.min_hold_unhold_events
            ),
            input.height,
        );
    }
    if input.config.require_fail_closed_hold {
        let has_fail_closed_hold = input
            .hold_unhold_events
            .iter()
            .any(|event| event.fail_closed && event.release_held());
        if !has_fail_closed_hold {
            push_blocker(
                blockers,
                BlockerKind::FailClosedReleaseHold,
                BlockerSeverity::Blocking,
                "fail_closed_hold",
                &input.guard_binding.release_hold_root,
                "rollback drill did not demonstrate fail-closed release hold",
                input.height,
            );
        }
    }
    for event in &input.hold_unhold_events {
        if event.action == HoldUnholdAction::RequestUnhold && event.release_held() {
            push_blocker(
                blockers,
                BlockerKind::FailClosedReleaseHold,
                BlockerSeverity::Watch,
                &event.event_id,
                &event.state_root(),
                "unhold request remained held because fail-closed policy stayed active",
                input.height,
            );
        }
        if event.action == HoldUnholdAction::RejectUnhold && !event.release_held() {
            push_blocker(
                blockers,
                BlockerKind::HoldUnholdMismatch,
                BlockerSeverity::Blocking,
                &event.event_id,
                &event.state_root(),
                "unhold rejection did not leave release held",
                input.height,
            );
        }
    }
}

fn devnet_hold_unhold_events(
    guard_binding: &DeploymentGuardBinding,
    height: u64,
) -> Vec<HoldUnholdDrillEvent> {
    let seed_hold_root = guard_binding.release_hold_root.clone();
    let first = HoldUnholdDrillEvent::new(
        HoldUnholdAction::AssertHold,
        ReleaseHoldState::FailClosedHeld,
        seed_hold_root,
        "release-coordinator-alpha",
        guard_binding.wave84_deployment_guard_root.clone(),
        height.saturating_sub(6),
        true,
        "assert fail-closed hold before rollback transcript replay",
    )
    .ok();
    let second = first.as_ref().and_then(|event| {
        HoldUnholdDrillEvent::new(
            HoldUnholdAction::ProveHold,
            ReleaseHoldState::HeldByGuard,
            event.resulting_hold_root.clone(),
            "operator-dashboard-owner",
            guard_binding.operator_dashboard_root.clone(),
            height.saturating_sub(5),
            true,
            "prove operator dashboard still binds the release hold root",
        )
        .ok()
    });
    let third = second.as_ref().and_then(|event| {
        HoldUnholdDrillEvent::new(
            HoldUnholdAction::RequestUnhold,
            ReleaseHoldState::UnholdRequested,
            event.resulting_hold_root.clone(),
            "rollback-commander-alpha",
            guard_binding.rollback_readiness_root.clone(),
            height.saturating_sub(4),
            true,
            "exercise unhold request while fail-closed policy remains active",
        )
        .ok()
    });
    let fourth = third.as_ref().and_then(|event| {
        HoldUnholdDrillEvent::new(
            HoldUnholdAction::RejectUnhold,
            ReleaseHoldState::UnholdRejected,
            event.resulting_hold_root.clone(),
            "security-reviewer-alpha",
            guard_binding.accepted_live_evidence_root.clone(),
            height.saturating_sub(3),
            true,
            "reject unhold because heavy production gates remain intentionally deferred",
        )
        .ok()
    });
    let fifth = fourth.as_ref().and_then(|event| {
        HoldUnholdDrillEvent::new(
            HoldUnholdAction::RestoreHold,
            ReleaseHoldState::RollbackRestoredHold,
            event.resulting_hold_root.clone(),
            "production-sre-alpha",
            guard_binding.release_hold_root.clone(),
            height.saturating_sub(2),
            true,
            "restore rollback drill hold after unhold rejection",
        )
        .ok()
    });
    [first, second, third, fourth, fifth]
        .into_iter()
        .flatten()
        .collect()
}

fn devnet_transcripts(
    guard_binding: &DeploymentGuardBinding,
    hold_events: &[HoldUnholdDrillEvent],
    height: u64,
) -> Vec<RollbackTranscript> {
    let first_hold = hold_events
        .first()
        .map(|event| event.previous_hold_root.clone())
        .unwrap_or_else(|| guard_binding.release_hold_root.clone());
    let last_hold = hold_events
        .last()
        .map(|event| event.resulting_hold_root.clone())
        .unwrap_or_else(|| guard_binding.release_hold_root.clone());
    RollbackDrillPhase::all()
        .into_iter()
        .enumerate()
        .filter_map(|(index, phase)| {
            let previous = if index == 0 {
                first_hold.clone()
            } else {
                hold_events
                    .get(index.saturating_sub(1))
                    .map(|event| event.resulting_hold_root.clone())
                    .unwrap_or_else(|| last_hold.clone())
            };
            let resulting = hold_events
                .get(index)
                .map(|event| event.resulting_hold_root.clone())
                .unwrap_or_else(|| last_hold.clone());
            RollbackTranscript::new(
                phase,
                guard_binding.runtime_replay_root.clone(),
                guard_binding.operator_dashboard_root.clone(),
                guard_binding.release_policy_root.clone(),
                previous,
                resulting,
                height.saturating_sub(8).saturating_add(index as u64),
                DrillVerdict::Pass,
                format!(
                    "rollback drill phase {} binds Wave 84 runtime replay deployment guard outputs",
                    phase.as_str()
                ),
            )
            .ok()
        })
        .collect()
}

fn devnet_rollback_commands(
    guard_binding: &DeploymentGuardBinding,
    height: u64,
) -> Vec<ReplayRollbackCommand> {
    rollback_command_labels()
        .into_iter()
        .enumerate()
        .filter_map(|(index, label)| {
            let expected = command_receipt_root(label, index as u16, "expected");
            let observed = expected.clone();
            ReplayRollbackCommand::new(
                label,
                index as u16,
                command_input_root(label, &guard_binding.runtime_replay_root),
                command_effect_root(label, &guard_binding.release_hold_root),
                expected,
                observed,
                command_abort_root(label, index as u16),
                height.saturating_sub(8).saturating_add(index as u64),
                DrillVerdict::Pass,
            )
            .ok()
        })
        .collect()
}

fn devnet_abort_criteria(commands: &[ReplayRollbackCommand], height: u64) -> Vec<AbortCriterion> {
    let kinds = [
        AbortCriterionKind::ReceiptMismatch,
        AbortCriterionKind::StaleReplay,
        AbortCriterionKind::MissingRollbackCommand,
        AbortCriterionKind::OperatorReject,
        AbortCriterionKind::HoldRootMismatch,
        AbortCriterionKind::UnexpectedUnhold,
        AbortCriterionKind::ManualFreeze,
        AbortCriterionKind::WatchLimitExceeded,
    ];
    commands
        .iter()
        .zip(kinds.into_iter().cycle())
        .enumerate()
        .filter_map(|(index, (command, kind))| {
            AbortCriterion::new(
                kind,
                command.command_label.clone(),
                command.state_root(),
                command.command_root.clone(),
                AbortCriterionStatus::Armed,
                height.saturating_sub(7).saturating_add(index as u64),
                format!(
                    "abort criterion {} remains armed for rollback command {}",
                    kind.as_str(),
                    command.command_label
                ),
            )
            .ok()
        })
        .collect()
}

fn devnet_operator_acknowledgements(
    guard_binding: &DeploymentGuardBinding,
    rollback_drill_root: &str,
    height: u64,
) -> Vec<OperatorAcknowledgement> {
    [
        (
            "runtime-replay-operator-alpha",
            OperatorRole::RuntimeReplayOperator,
        ),
        ("rollback-commander-alpha", OperatorRole::RollbackCommander),
        (
            "release-coordinator-alpha",
            OperatorRole::ReleaseCoordinator,
        ),
        ("operator-dashboard-owner", OperatorRole::DashboardOwner),
        ("security-reviewer-alpha", OperatorRole::SecurityReviewer),
        ("production-sre-alpha", OperatorRole::ProductionSre),
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(index, (operator_id, role))| {
        OperatorAcknowledgement::new(
            operator_id,
            role,
            OperatorAckDecision::Acknowledge,
            guard_binding.operator_dashboard_root.clone(),
            guard_binding.release_policy_root.clone(),
            rollback_drill_root.to_string(),
            height.saturating_sub(2).saturating_add(index as u64),
            format!(
                "{} acknowledges rollback drill evidence and fail-closed release hold",
                role.as_str()
            ),
        )
        .ok()
    })
    .collect()
}

fn rollback_command_labels() -> Vec<&'static str> {
    vec![
        "assert_fail_closed_release_hold",
        "import_wave84_deployment_guard",
        "load_runtime_replay_accepted_evidence",
        "replay_rollback_transcript",
        "compare_expected_receipts",
        "arm_abort_criteria",
        "request_unhold_rehearsal",
        "reject_unhold_and_restore_hold",
    ]
}

fn minimal_fallback_state() -> State {
    let config = Config::devnet();
    let height = DEFAULT_HEIGHT;
    let guard_binding = DeploymentGuardBinding::devnet(height);
    let counters = DrillCounters {
        transcript_count: 0,
        pass_transcript_count: 0,
        rollback_command_count: 0,
        expected_receipt_count: 0,
        matched_receipt_count: 0,
        abort_criterion_count: 0,
        armed_abort_criterion_count: 0,
        operator_ack_count: 0,
        hold_unhold_event_count: 0,
        release_held_event_count: 0,
        watch_count: 0,
        blocking_count: 1,
    };
    let transcript_root = merkle_root("rollback-drill-minimal-transcripts", &Vec::<Value>::new());
    let command_root = merkle_root("rollback-drill-minimal-commands", &Vec::<Value>::new());
    let receipt_root = merkle_root("rollback-drill-minimal-receipts", &Vec::<Value>::new());
    let freshness_root = sample_root("minimal-fallback", "freshness-root");
    let abort_root = merkle_root("rollback-drill-minimal-aborts", &Vec::<Value>::new());
    let acknowledgement_root = merkle_root(
        "rollback-drill-minimal-acknowledgements",
        &Vec::<Value>::new(),
    );
    let hold_unhold_root = merkle_root("rollback-drill-minimal-hold-events", &Vec::<Value>::new());
    let counters_root = counters.state_root();
    let evidence_root = sample_root("minimal-fallback", "evidence-root");
    let blocker = RollbackDrillBlocker::new(
        BlockerKind::FailClosedReleaseHold,
        BlockerSeverity::Blocking,
        "minimal_fallback",
        evidence_root.clone(),
        "minimal fallback state keeps release held",
        height,
    )
    .unwrap_or_else_fallback(height);
    let blocker_root = merkle_root(
        "rollback-drill-minimal-blockers",
        &[blocker.public_record()],
    );
    let decision_root = decision_root(
        true,
        false,
        true,
        DrillVerdict::Hold,
        &evidence_root,
        &blocker_root,
        &counters_root,
        height,
    );
    let freshness_blocker = ReplayFreshnessBlocker {
        freshness_id: sample_root("minimal-fallback", "freshness-id"),
        source_runtime_replay_root: guard_binding.runtime_replay_root.clone(),
        replay_accepted_height: height.saturating_sub(DEFAULT_MAX_REPLAY_AGE_BLOCKS + 1),
        observed_at_height: height,
        max_age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS,
        age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS + 1,
        status: FreshnessStatus::Blocked,
        blocker_replay_root: freshness_root.clone(),
    };
    State {
        config,
        height,
        guard_binding,
        transcripts: Vec::new(),
        rollback_commands: Vec::new(),
        expected_receipts: Vec::new(),
        freshness_blocker,
        abort_criteria: Vec::new(),
        operator_acknowledgements: Vec::new(),
        hold_unhold_events: Vec::new(),
        blockers: vec![blocker],
        counters,
        transcript_root,
        command_root: command_root.clone(),
        receipt_root: receipt_root.clone(),
        freshness_root,
        abort_root: abort_root.clone(),
        acknowledgement_root: acknowledgement_root.clone(),
        hold_unhold_root: hold_unhold_root.clone(),
        evidence_root: evidence_root.clone(),
        blocker_root: blocker_root.clone(),
        decision: RollbackDrillDecision {
            release_held: true,
            rollback_drill_passed: false,
            fail_closed: true,
            verdict: DrillVerdict::Hold,
            evidence_root,
            blocker_root,
            command_root,
            receipt_root,
            abort_root,
            acknowledgement_root,
            hold_unhold_root,
            counters_root,
            decision_root,
            decided_at_height: height,
        },
    }
}

fn scoped_id(scope: &str, label: &str, height: u64) -> String {
    domain_hash(
        "ROLLBACK-DRILL-SCOPED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(scope),
            HashPart::Str(label),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn transcript_id(
    phase: RollbackDrillPhase,
    source_runtime_replay_root: &str,
    previous_hold_state_root: &str,
    resulting_hold_state_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(phase.as_str()),
            HashPart::Str(source_runtime_replay_root),
            HashPart::Str(previous_hold_state_root),
            HashPart::Str(resulting_hold_state_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn command_root(
    command_family: &str,
    command_label: &str,
    input_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-COMMAND-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_family),
            HashPart::Str(command_label),
            HashPart::Str(input_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn rollback_command_root(
    command_label: &str,
    command_index: u16,
    replay_input_root: &str,
    rollback_effect_root: &str,
    expected_receipt_root: &str,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-REPLAY-ROLLBACK-COMMAND-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Int(command_index as i128),
            HashPart::Str(replay_input_root),
            HashPart::Str(rollback_effect_root),
            HashPart::Str(expected_receipt_root),
            HashPart::Int(executed_at_height as i128),
        ],
        32,
    )
}

fn command_id(command_label: &str, command_index: u16, command_root: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-COMMAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Int(command_index as i128),
            HashPart::Str(command_root),
        ],
        32,
    )
}

fn receipt_comparison_root(
    command_label: &str,
    expected_receipt_root: &str,
    observed_receipt_root: &str,
    status: ReceiptStatus,
    compared_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-RECEIPT-COMPARISON-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Str(status.as_str()),
            HashPart::Int(compared_at_height as i128),
        ],
        32,
    )
}

fn replay_freshness_id(
    source_runtime_replay_root: &str,
    replay_accepted_height: u64,
    observed_at_height: u64,
    max_age_blocks: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-REPLAY-FRESHNESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(source_runtime_replay_root),
            HashPart::Int(replay_accepted_height as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(max_age_blocks as i128),
        ],
        32,
    )
}

fn abort_root(
    kind: AbortCriterionKind,
    subject: &str,
    evidence_root: &str,
    command_root: &str,
    status: AbortCriterionStatus,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-ABORT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject),
            HashPart::Str(evidence_root),
            HashPart::Str(command_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn abort_criterion_id(
    kind: AbortCriterionKind,
    subject: &str,
    abort_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-ABORT-CRITERION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject),
            HashPart::Str(abort_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

fn operator_signed_statement_root(
    operator_id: &str,
    role: OperatorRole,
    decision: OperatorAckDecision,
    dashboard_root: &str,
    release_policy_root: &str,
    rollback_drill_root: &str,
    acknowledged_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-OPERATOR-SIGNED-STATEMENT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(dashboard_root),
            HashPart::Str(release_policy_root),
            HashPart::Str(rollback_drill_root),
            HashPart::Int(acknowledged_at_height as i128),
        ],
        32,
    )
}

fn operator_acknowledgement_id(
    operator_id: &str,
    role: OperatorRole,
    decision: OperatorAckDecision,
    signed_statement_root: &str,
    acknowledged_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-OPERATOR-ACKNOWLEDGEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(signed_statement_root),
            HashPart::Int(acknowledged_at_height as i128),
        ],
        32,
    )
}

fn hold_state_root(
    action: HoldUnholdAction,
    hold_state: ReleaseHoldState,
    previous_hold_root: &str,
    actor_id: &str,
    evidence_root: &str,
    event_height: u64,
    fail_closed: bool,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-HOLD-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(action.as_str()),
            HashPart::Str(hold_state.as_str()),
            HashPart::Str(previous_hold_root),
            HashPart::Str(actor_id),
            HashPart::Str(evidence_root),
            HashPart::Int(event_height as i128),
            HashPart::Str(if fail_closed { "fail_closed" } else { "open" }),
        ],
        32,
    )
}

fn hold_unhold_event_id(
    action: HoldUnholdAction,
    hold_state: ReleaseHoldState,
    resulting_hold_root: &str,
    event_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-HOLD-UNHOLD-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(action.as_str()),
            HashPart::Str(hold_state.as_str()),
            HashPart::Str(resulting_hold_root),
            HashPart::Int(event_height as i128),
        ],
        32,
    )
}

fn blocker_id(
    kind: BlockerKind,
    severity: BlockerSeverity,
    subject: &str,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-BLOCKER-ID",
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

fn decision_root(
    release_held: bool,
    rollback_drill_passed: bool,
    fail_closed: bool,
    verdict: DrillVerdict,
    evidence_root: &str,
    blocker_root: &str,
    counters_root: &str,
    decided_at_height: u64,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-DECISION-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(if release_held {
                "release_held"
            } else {
                "release_unheld"
            }),
            HashPart::Str(if rollback_drill_passed {
                "rollback_drill_passed"
            } else {
                "rollback_drill_not_passed"
            }),
            HashPart::Str(if fail_closed {
                "fail_closed"
            } else {
                "not_fail_closed"
            }),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(blocker_root),
            HashPart::Str(counters_root),
            HashPart::Int(decided_at_height as i128),
        ],
        32,
    )
}

fn command_input_root(command_label: &str, runtime_replay_root: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-COMMAND-INPUT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Str(runtime_replay_root),
        ],
        32,
    )
}

fn command_effect_root(command_label: &str, release_hold_root: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-COMMAND-EFFECT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Str(release_hold_root),
        ],
        32,
    )
}

fn command_receipt_root(command_label: &str, command_index: u16, side: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-COMMAND-RECEIPT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Int(command_index as i128),
            HashPart::Str(side),
        ],
        32,
    )
}

fn command_abort_root(command_label: &str, command_index: u16) -> String {
    domain_hash(
        "ROLLBACK-DRILL-COMMAND-ABORT-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(command_label),
            HashPart::Int(command_index as i128),
        ],
        32,
    )
}

fn sample_root(label: &str, kind: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-DEVNET-SAMPLE-ROOT",
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
        "ROLLBACK-DRILL-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn push_blocker(
    blockers: &mut Vec<RollbackDrillBlocker>,
    kind: BlockerKind,
    severity: BlockerSeverity,
    subject: impl Into<String>,
    evidence_root: &str,
    detail: impl Into<String>,
    observed_at_height: u64,
) {
    if let Ok(blocker) = RollbackDrillBlocker::new(
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
    fn unwrap_or_else_fallback(self, height: u64, max_age_blocks: u64) -> ReplayFreshnessBlocker;
}

impl FallbackFreshness for Result<ReplayFreshnessBlocker> {
    fn unwrap_or_else_fallback(self, height: u64, max_age_blocks: u64) -> ReplayFreshnessBlocker {
        match self {
            Ok(value) => value,
            Err(_) => ReplayFreshnessBlocker {
                freshness_id: sample_root("fallback", "freshness-id"),
                source_runtime_replay_root: sample_root("fallback", "runtime-replay-root"),
                replay_accepted_height: height.saturating_sub(max_age_blocks + 1),
                observed_at_height: height,
                max_age_blocks,
                age_blocks: max_age_blocks + 1,
                status: FreshnessStatus::Blocked,
                blocker_replay_root: sample_root("fallback", "freshness-blocker-replay-root"),
            },
        }
    }
}

trait FallbackHoldEvent {
    fn unwrap_or_else_fallback(self, height: u64) -> HoldUnholdDrillEvent;
}

impl FallbackHoldEvent for Result<HoldUnholdDrillEvent> {
    fn unwrap_or_else_fallback(self, height: u64) -> HoldUnholdDrillEvent {
        match self {
            Ok(value) => value,
            Err(_) => HoldUnholdDrillEvent {
                event_id: sample_root("fallback", "hold-event-id"),
                action: HoldUnholdAction::AssertHold,
                hold_state: ReleaseHoldState::FailClosedHeld,
                previous_hold_root: sample_root("fallback", "previous-hold-root"),
                resulting_hold_root: sample_root("fallback", "resulting-hold-root"),
                actor_id: "fallback-actor".to_string(),
                evidence_root: sample_root("fallback", "hold-evidence-root"),
                event_height: height,
                fail_closed: true,
                note: "fallback hold/unhold event keeps release held".to_string(),
            },
        }
    }
}

trait FallbackTranscript {
    fn unwrap_or_else_fallback(self, height: u64) -> RollbackTranscript;
}

impl FallbackTranscript for Result<RollbackTranscript> {
    fn unwrap_or_else_fallback(self, height: u64) -> RollbackTranscript {
        match self {
            Ok(value) => value,
            Err(_) => RollbackTranscript {
                transcript_id: sample_root("fallback", "transcript-id"),
                phase: RollbackDrillPhase::Prepare,
                source_runtime_replay_root: sample_root("fallback", "runtime-replay-root"),
                rollback_transcript_root: sample_root("fallback", "rollback-transcript-root"),
                transcript_command_root: sample_root("fallback", "transcript-command-root"),
                operator_dashboard_root: sample_root("fallback", "dashboard-root"),
                release_policy_root: sample_root("fallback", "release-policy-root"),
                previous_hold_state_root: sample_root("fallback", "previous-hold-root"),
                resulting_hold_state_root: sample_root("fallback", "resulting-hold-root"),
                observed_at_height: height,
                verdict: DrillVerdict::Hold,
                note: "fallback transcript keeps rollback drill held".to_string(),
            },
        }
    }
}

trait FallbackCommand {
    fn unwrap_or_else_fallback(self, height: u64) -> ReplayRollbackCommand;
}

impl FallbackCommand for Result<ReplayRollbackCommand> {
    fn unwrap_or_else_fallback(self, height: u64) -> ReplayRollbackCommand {
        match self {
            Ok(value) => value,
            Err(_) => ReplayRollbackCommand {
                command_id: sample_root("fallback", "command-id"),
                command_label: "fallback_assert_fail_closed_hold".to_string(),
                command_index: 0,
                command_root: sample_root("fallback", "command-root"),
                replay_input_root: sample_root("fallback", "replay-input-root"),
                rollback_effect_root: sample_root("fallback", "rollback-effect-root"),
                expected_receipt_root: sample_root("fallback", "expected-receipt-root"),
                observed_receipt_root: sample_root("fallback", "observed-receipt-root"),
                abort_criterion_root: sample_root("fallback", "abort-criterion-root"),
                executed_at_height: height,
                verdict: DrillVerdict::Hold,
            },
        }
    }
}

trait FallbackAbort {
    fn unwrap_or_else_fallback(self, height: u64) -> AbortCriterion;
}

impl FallbackAbort for Result<AbortCriterion> {
    fn unwrap_or_else_fallback(self, height: u64) -> AbortCriterion {
        match self {
            Ok(value) => value,
            Err(_) => AbortCriterion {
                criterion_id: sample_root("fallback", "abort-id"),
                kind: AbortCriterionKind::StaleReplay,
                subject: "fallback_freshness".to_string(),
                evidence_root: sample_root("fallback", "abort-evidence-root"),
                command_root: sample_root("fallback", "abort-command-root"),
                abort_root: sample_root("fallback", "abort-root"),
                status: AbortCriterionStatus::Triggered,
                observed_at_height: height,
                detail: "fallback abort criterion is triggered".to_string(),
            },
        }
    }
}

trait FallbackAck {
    fn unwrap_or_else_fallback(self, height: u64) -> OperatorAcknowledgement;
}

impl FallbackAck for Result<OperatorAcknowledgement> {
    fn unwrap_or_else_fallback(self, height: u64) -> OperatorAcknowledgement {
        match self {
            Ok(value) => value,
            Err(_) => OperatorAcknowledgement {
                acknowledgement_id: sample_root("fallback", "ack-id"),
                operator_id: "fallback-operator".to_string(),
                role: OperatorRole::RuntimeReplayOperator,
                decision: OperatorAckDecision::Hold,
                signed_dashboard_root: sample_root("fallback", "dashboard-root"),
                signed_release_policy_root: sample_root("fallback", "release-policy-root"),
                signed_rollback_drill_root: sample_root("fallback", "rollback-drill-root"),
                signed_statement_root: sample_root("fallback", "signed-statement-root"),
                acknowledged_at_height: height,
                note: "fallback acknowledgement holds release".to_string(),
            },
        }
    }
}

trait FallbackBlocker {
    fn unwrap_or_else_fallback(self, height: u64) -> RollbackDrillBlocker;
}

impl FallbackBlocker for Result<RollbackDrillBlocker> {
    fn unwrap_or_else_fallback(self, height: u64) -> RollbackDrillBlocker {
        match self {
            Ok(value) => value,
            Err(_) => RollbackDrillBlocker {
                blocker_id: sample_root("fallback", "blocker-id"),
                kind: BlockerKind::FailClosedReleaseHold,
                severity: BlockerSeverity::Blocking,
                subject: "fallback".to_string(),
                evidence_root: sample_root("fallback", "blocker-evidence-root"),
                detail: "fallback blocker keeps release held".to_string(),
                observed_at_height: height,
            },
        }
    }
}
