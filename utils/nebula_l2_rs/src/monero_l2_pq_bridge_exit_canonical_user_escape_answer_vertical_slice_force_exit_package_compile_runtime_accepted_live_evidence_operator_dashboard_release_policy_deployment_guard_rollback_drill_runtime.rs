use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DRILL_SUITE: &str =
    "monero-l2-pq-force-exit-compile-runtime-deployment-guard-rollback-drill-v1";
pub const DEFAULT_RELEASE_EPOCH: u64 = 85;
pub const DEFAULT_WAVE_84_RELEASE_EPOCH: u64 = 84;
pub const DEFAULT_DRILL_HEIGHT: u64 = 850_000;
pub const DEFAULT_BINDING_HEIGHT: u64 = 849_960;
pub const DEFAULT_MAX_BINDING_AGE_BLOCKS: u64 = 80;
pub const DEFAULT_MIN_OPERATOR_ACKS: u16 = 4;
pub const DEFAULT_MIN_ROLLBACK_RECEIPTS: u16 = 4;
pub const DEFAULT_MIN_ABORT_RECEIPTS: u16 = 3;
pub const DEFAULT_MIN_RUNBOOK_TRANSCRIPTS: u16 = 3;
pub const DEFAULT_MIN_HEAVY_GATE_REPLAYS: u16 = 3;
pub const DEFAULT_MIN_HOLD_UNHOLD_RECEIPTS: u16 = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub drill_suite: String,
    pub release_epoch: u64,
    pub wave_84_release_epoch: u64,
    pub drill_height: u64,
    pub binding_height: u64,
    pub release_channel: String,
    pub deployment_environment: String,
    pub max_binding_age_blocks: u64,
    pub min_operator_acks: u16,
    pub min_rollback_receipts: u16,
    pub min_abort_receipts: u16,
    pub min_runbook_transcripts: u16,
    pub min_heavy_gate_replays: u16,
    pub min_hold_unhold_receipts: u16,
    pub require_wave_84_guard_root: bool,
    pub require_runbook_transcript_root: bool,
    pub require_rollback_command_root: bool,
    pub require_abort_criteria_root: bool,
    pub require_operator_acknowledgement_root: bool,
    pub require_deferred_gate_replay_root: bool,
    pub require_hold_unhold_drill_root: bool,
    pub require_release_hold_on_blocker: bool,
    pub require_fail_closed_default: bool,
    pub allow_unhold_without_heavy_gates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            drill_suite: DRILL_SUITE.to_string(),
            release_epoch: DEFAULT_RELEASE_EPOCH,
            wave_84_release_epoch: DEFAULT_WAVE_84_RELEASE_EPOCH,
            drill_height: DEFAULT_DRILL_HEIGHT,
            binding_height: DEFAULT_BINDING_HEIGHT,
            release_channel: "devnet-compile-runtime-deployment-guard-rollback-drill".to_string(),
            deployment_environment: "devnet-production-shadow".to_string(),
            max_binding_age_blocks: DEFAULT_MAX_BINDING_AGE_BLOCKS,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            min_rollback_receipts: DEFAULT_MIN_ROLLBACK_RECEIPTS,
            min_abort_receipts: DEFAULT_MIN_ABORT_RECEIPTS,
            min_runbook_transcripts: DEFAULT_MIN_RUNBOOK_TRANSCRIPTS,
            min_heavy_gate_replays: DEFAULT_MIN_HEAVY_GATE_REPLAYS,
            min_hold_unhold_receipts: DEFAULT_MIN_HOLD_UNHOLD_RECEIPTS,
            require_wave_84_guard_root: true,
            require_runbook_transcript_root: true,
            require_rollback_command_root: true,
            require_abort_criteria_root: true,
            require_operator_acknowledgement_root: true,
            require_deferred_gate_replay_root: true,
            require_hold_unhold_drill_root: true,
            require_release_hold_on_blocker: true,
            require_fail_closed_default: true,
            allow_unhold_without_heavy_gates: false,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("drill_suite", &self.drill_suite)?;
        ensure_non_empty("release_channel", &self.release_channel)?;
        ensure_non_empty("deployment_environment", &self.deployment_environment)?;
        ensure(self.schema_version > 0, "schema version must be non-zero")?;
        ensure(self.release_epoch > 0, "release epoch must be non-zero")?;
        ensure(
            self.wave_84_release_epoch > 0,
            "wave 84 release epoch must be non-zero",
        )?;
        ensure(
            self.release_epoch > self.wave_84_release_epoch,
            "rollback drill release epoch must follow wave 84",
        )?;
        ensure(self.drill_height > 0, "drill height must be non-zero")?;
        ensure(self.binding_height > 0, "binding height must be non-zero")?;
        ensure(
            self.drill_height >= self.binding_height,
            "drill height must not precede binding height",
        )?;
        ensure(
            self.drill_height - self.binding_height <= self.max_binding_age_blocks,
            "binding age exceeds configured drill window",
        )?;
        ensure(
            self.min_operator_acks > 0,
            "operator acknowledgement minimum must be non-zero",
        )?;
        ensure(
            self.min_rollback_receipts > 0,
            "rollback receipt minimum must be non-zero",
        )?;
        ensure(
            self.min_abort_receipts > 0,
            "abort receipt minimum must be non-zero",
        )?;
        ensure(
            self.min_runbook_transcripts > 0,
            "runbook transcript minimum must be non-zero",
        )?;
        ensure(
            self.min_heavy_gate_replays > 0,
            "heavy gate replay minimum must be non-zero",
        )?;
        ensure(
            self.min_hold_unhold_receipts > 0,
            "hold unhold receipt minimum must be non-zero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "drill_suite": self.drill_suite,
            "release_epoch": self.release_epoch,
            "wave_84_release_epoch": self.wave_84_release_epoch,
            "drill_height": self.drill_height,
            "binding_height": self.binding_height,
            "release_channel": self.release_channel,
            "deployment_environment": self.deployment_environment,
            "max_binding_age_blocks": self.max_binding_age_blocks,
            "min_operator_acks": self.min_operator_acks,
            "min_rollback_receipts": self.min_rollback_receipts,
            "min_abort_receipts": self.min_abort_receipts,
            "min_runbook_transcripts": self.min_runbook_transcripts,
            "min_heavy_gate_replays": self.min_heavy_gate_replays,
            "min_hold_unhold_receipts": self.min_hold_unhold_receipts,
            "require_wave_84_guard_root": self.require_wave_84_guard_root,
            "require_runbook_transcript_root": self.require_runbook_transcript_root,
            "require_rollback_command_root": self.require_rollback_command_root,
            "require_abort_criteria_root": self.require_abort_criteria_root,
            "require_operator_acknowledgement_root": self.require_operator_acknowledgement_root,
            "require_deferred_gate_replay_root": self.require_deferred_gate_replay_root,
            "require_hold_unhold_drill_root": self.require_hold_unhold_drill_root,
            "require_release_hold_on_blocker": self.require_release_hold_on_blocker,
            "require_fail_closed_default": self.require_fail_closed_default,
            "allow_unhold_without_heavy_gates": self.allow_unhold_without_heavy_gates,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Wave84GuardRootKind {
    CompileRuntimeDeploymentGuard,
    ReleaseHoldUnholdDeploymentGuard,
    GoNoGoBinding,
    RustfmtReceipt,
    DeferredHeavyGateBlocker,
}

impl Wave84GuardRootKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::CompileRuntimeDeploymentGuard,
            Self::ReleaseHoldUnholdDeploymentGuard,
            Self::GoNoGoBinding,
            Self::RustfmtReceipt,
            Self::DeferredHeavyGateBlocker,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntimeDeploymentGuard => "compile_runtime_deployment_guard",
            Self::ReleaseHoldUnholdDeploymentGuard => "release_hold_unhold_deployment_guard",
            Self::GoNoGoBinding => "go_no_go_binding",
            Self::RustfmtReceipt => "rustfmt_receipt",
            Self::DeferredHeavyGateBlocker => "deferred_heavy_gate_blocker",
        }
    }

    pub fn module_hint(self) -> &'static str {
        match self {
            Self::CompileRuntimeDeploymentGuard => {
                "compile_runtime_accepted_live_evidence_operator_dashboard_release_policy_deployment_guard_runtime"
            }
            Self::ReleaseHoldUnholdDeploymentGuard => {
                "release_policy_accepted_live_evidence_operator_dashboard_release_hold_unhold_deployment_guard_runtime"
            }
            Self::GoNoGoBinding => "release_policy_operator_dashboard_go_no_go_binding_runtime",
            Self::RustfmtReceipt => "compile_runtime_rustfmt_receipt_runtime",
            Self::DeferredHeavyGateBlocker => "compile_runtime_deferred_heavy_gate_blockers",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillStepKind {
    BindWave84Outputs,
    AnnounceFailClosedHold,
    ReadRunbook,
    StageRollbackCommand,
    VerifyAbortCriteria,
    ReplayDeferredGateBlocker,
    OperatorAcknowledgement,
    HoldUnholdDecision,
    PublishEvidenceBundle,
}

impl DrillStepKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::BindWave84Outputs,
            Self::AnnounceFailClosedHold,
            Self::ReadRunbook,
            Self::StageRollbackCommand,
            Self::VerifyAbortCriteria,
            Self::ReplayDeferredGateBlocker,
            Self::OperatorAcknowledgement,
            Self::HoldUnholdDecision,
            Self::PublishEvidenceBundle,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BindWave84Outputs => "bind_wave_84_outputs",
            Self::AnnounceFailClosedHold => "announce_fail_closed_hold",
            Self::ReadRunbook => "read_runbook",
            Self::StageRollbackCommand => "stage_rollback_command",
            Self::VerifyAbortCriteria => "verify_abort_criteria",
            Self::ReplayDeferredGateBlocker => "replay_deferred_gate_blocker",
            Self::OperatorAcknowledgement => "operator_acknowledgement",
            Self::HoldUnholdDecision => "hold_unhold_decision",
            Self::PublishEvidenceBundle => "publish_evidence_bundle",
        }
    }

    pub fn must_precede_unhold(self) -> bool {
        matches!(
            self,
            Self::BindWave84Outputs
                | Self::AnnounceFailClosedHold
                | Self::ReadRunbook
                | Self::StageRollbackCommand
                | Self::VerifyAbortCriteria
                | Self::ReplayDeferredGateBlocker
                | Self::OperatorAcknowledgement
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackCommandKind {
    FreezeDeploymentWindow,
    PinPreviousArtifact,
    RepointOperatorDashboard,
    RestoreBridgeExitPolicy,
    RevokeUnholdCandidate,
    PublishRollbackNotice,
}

impl RollbackCommandKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::FreezeDeploymentWindow,
            Self::PinPreviousArtifact,
            Self::RepointOperatorDashboard,
            Self::RestoreBridgeExitPolicy,
            Self::RevokeUnholdCandidate,
            Self::PublishRollbackNotice,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreezeDeploymentWindow => "freeze_deployment_window",
            Self::PinPreviousArtifact => "pin_previous_artifact",
            Self::RepointOperatorDashboard => "repoint_operator_dashboard",
            Self::RestoreBridgeExitPolicy => "restore_bridge_exit_policy",
            Self::RevokeUnholdCandidate => "revoke_unhold_candidate",
            Self::PublishRollbackNotice => "publish_rollback_notice",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCriterionKind {
    MissingWave84Binding,
    StaleReceiptRoot,
    DeferredHeavyGateUnresolved,
    OperatorQuorumMissing,
    RunbookMismatch,
    RollbackReceiptMissing,
    HoldUnholdContradiction,
    DashboardRootDrift,
}

impl AbortCriterionKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::MissingWave84Binding,
            Self::StaleReceiptRoot,
            Self::DeferredHeavyGateUnresolved,
            Self::OperatorQuorumMissing,
            Self::RunbookMismatch,
            Self::RollbackReceiptMissing,
            Self::HoldUnholdContradiction,
            Self::DashboardRootDrift,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave84Binding => "missing_wave_84_binding",
            Self::StaleReceiptRoot => "stale_receipt_root",
            Self::DeferredHeavyGateUnresolved => "deferred_heavy_gate_unresolved",
            Self::OperatorQuorumMissing => "operator_quorum_missing",
            Self::RunbookMismatch => "runbook_mismatch",
            Self::RollbackReceiptMissing => "rollback_receipt_missing",
            Self::HoldUnholdContradiction => "hold_unhold_contradiction",
            Self::DashboardRootDrift => "dashboard_root_drift",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeavyGateKind {
    CargoCheck,
    CargoTest,
    CargoClippy,
}

impl HeavyGateKind {
    pub fn all() -> Vec<Self> {
        vec![Self::CargoCheck, Self::CargoTest, Self::CargoClippy]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoCheck => "cargo_check",
            Self::CargoTest => "cargo_test",
            Self::CargoClippy => "cargo_clippy",
        }
    }

    pub fn command_label(self) -> &'static str {
        match self {
            Self::CargoCheck => "cargo check --workspace --all-targets",
            Self::CargoTest => "cargo test --workspace",
            Self::CargoClippy => "cargo clippy --workspace --all-targets",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDisposition {
    Deferred,
    Blocked,
    PassedInShadow,
    FailedInShadow,
}

impl ReplayDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::PassedInShadow => "passed_in_shadow",
            Self::FailedInShadow => "failed_in_shadow",
        }
    }

    pub fn blocks_unhold(self) -> bool {
        matches!(self, Self::Deferred | Self::Blocked | Self::FailedInShadow)
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Wave84GuardBinding {
    pub kind: Wave84GuardRootKind,
    pub label: String,
    pub module_hint: String,
    pub release_epoch: u64,
    pub observed_height: u64,
    pub root: String,
    pub binding_root: String,
}

impl Wave84GuardBinding {
    pub fn devnet(kind: Wave84GuardRootKind, config: &Config, ordinal: u64) -> Self {
        let label = kind.as_str().to_string();
        let root = sample_root("wave-84-guard-output", &label, ordinal);
        let binding_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ROLLBACK-DRILL-WAVE-84-BINDING",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind.as_str()),
                HashPart::Str(kind.module_hint()),
                HashPart::U64(config.wave_84_release_epoch),
                HashPart::U64(config.binding_height),
                HashPart::Str(&root),
            ],
            32,
        );
        Self {
            kind,
            label,
            module_hint: kind.module_hint().to_string(),
            release_epoch: config.wave_84_release_epoch,
            observed_height: config.binding_height,
            root,
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "label": self.label,
            "module_hint": self.module_hint,
            "release_epoch": self.release_epoch,
            "observed_height": self.observed_height,
            "root": self.root,
            "binding_root": self.binding_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wave-84-guard-binding", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("wave 84 binding label", &self.label)?;
        ensure_non_empty("wave 84 binding module hint", &self.module_hint)?;
        ensure_non_empty("wave 84 binding root", &self.root)?;
        ensure_non_empty("wave 84 binding commitment", &self.binding_root)?;
        ensure(
            self.release_epoch == DEFAULT_WAVE_84_RELEASE_EPOCH,
            "wave 84 binding must reference the prior release epoch",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunbookTranscript {
    pub transcript_id: String,
    pub operator_id: String,
    pub role: String,
    pub section: String,
    pub line_count: u64,
    pub transcript_root: String,
    pub acknowledged_abort_criteria: bool,
    pub acknowledged_fail_closed_hold: bool,
}

impl RunbookTranscript {
    pub fn new(
        operator_id: &str,
        role: &str,
        section: &str,
        line_count: u64,
        ordinal: u64,
    ) -> Self {
        let transcript_id = stable_id("runbook-transcript", operator_id, ordinal);
        let transcript_root = sample_root("runbook-transcript-root", section, ordinal);
        Self {
            transcript_id,
            operator_id: operator_id.to_string(),
            role: role.to_string(),
            section: section.to_string(),
            line_count,
            transcript_root,
            acknowledged_abort_criteria: true,
            acknowledged_fail_closed_hold: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "operator_id": self.operator_id,
            "role": self.role,
            "section": self.section,
            "line_count": self.line_count,
            "transcript_root": self.transcript_root,
            "acknowledged_abort_criteria": self.acknowledged_abort_criteria,
            "acknowledged_fail_closed_hold": self.acknowledged_fail_closed_hold,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("runbook-transcript", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("transcript id", &self.transcript_id)?;
        ensure_non_empty("operator id", &self.operator_id)?;
        ensure_non_empty("operator role", &self.role)?;
        ensure_non_empty("runbook section", &self.section)?;
        ensure_non_empty("transcript root", &self.transcript_root)?;
        ensure(self.line_count > 0, "runbook transcript must contain lines")?;
        ensure(
            self.acknowledged_abort_criteria,
            "runbook transcript must acknowledge abort criteria",
        )?;
        ensure(
            self.acknowledged_fail_closed_hold,
            "runbook transcript must acknowledge fail-closed hold",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackCommandReceipt {
    pub command_id: String,
    pub kind: RollbackCommandKind,
    pub command_label: String,
    pub target_root: String,
    pub expected_receipt_root: String,
    pub dry_run_receipt_root: String,
    pub prepared: bool,
    pub executed_in_production: bool,
}

impl RollbackCommandReceipt {
    pub fn devnet(kind: RollbackCommandKind, ordinal: u64) -> Self {
        let command_label = kind.as_str().to_string();
        Self {
            command_id: stable_id("rollback-command", &command_label, ordinal),
            kind,
            command_label: command_label.clone(),
            target_root: sample_root("rollback-command-target", &command_label, ordinal),
            expected_receipt_root: sample_root(
                "rollback-command-expected-receipt",
                &command_label,
                ordinal,
            ),
            dry_run_receipt_root: sample_root("rollback-command-dry-run", &command_label, ordinal),
            prepared: true,
            executed_in_production: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "command_id": self.command_id,
            "kind": self.kind.as_str(),
            "command_label": self.command_label,
            "target_root": self.target_root,
            "expected_receipt_root": self.expected_receipt_root,
            "dry_run_receipt_root": self.dry_run_receipt_root,
            "prepared": self.prepared,
            "executed_in_production": self.executed_in_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback-command-receipt", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("rollback command id", &self.command_id)?;
        ensure_non_empty("rollback command label", &self.command_label)?;
        ensure_non_empty("rollback command target root", &self.target_root)?;
        ensure_non_empty(
            "rollback command expected receipt root",
            &self.expected_receipt_root,
        )?;
        ensure_non_empty(
            "rollback command dry run receipt root",
            &self.dry_run_receipt_root,
        )?;
        ensure(self.prepared, "rollback command must be prepared")?;
        ensure(
            !self.executed_in_production,
            "rollback drill must not execute production rollback command",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbortCriterion {
    pub criterion_id: String,
    pub kind: AbortCriterionKind,
    pub description: String,
    pub evidence_root: String,
    pub active: bool,
    pub blocks_unhold: bool,
}

impl AbortCriterion {
    pub fn devnet(kind: AbortCriterionKind, active: bool, ordinal: u64) -> Self {
        let description = format!(
            "{} abort criterion bound into rollback drill",
            kind.as_str()
        );
        Self {
            criterion_id: stable_id("abort-criterion", kind.as_str(), ordinal),
            kind,
            description,
            evidence_root: sample_root("abort-criterion-evidence", kind.as_str(), ordinal),
            active,
            blocks_unhold: active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "kind": self.kind.as_str(),
            "description": self.description,
            "evidence_root": self.evidence_root,
            "active": self.active,
            "blocks_unhold": self.blocks_unhold,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("abort-criterion", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("abort criterion id", &self.criterion_id)?;
        ensure_non_empty("abort criterion description", &self.description)?;
        ensure_non_empty("abort criterion evidence root", &self.evidence_root)?;
        ensure(
            !self.active || self.blocks_unhold,
            "active abort criterion must block unhold",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeferredGateReplay {
    pub replay_id: String,
    pub gate: HeavyGateKind,
    pub command_label: String,
    pub blocker_root: String,
    pub replay_receipt_root: String,
    pub disposition: ReplayDisposition,
    pub replayed_in_shadow: bool,
    pub production_gate_executed: bool,
}

impl DeferredGateReplay {
    pub fn devnet(gate: HeavyGateKind, disposition: ReplayDisposition, ordinal: u64) -> Self {
        Self {
            replay_id: stable_id("deferred-gate-replay", gate.as_str(), ordinal),
            gate,
            command_label: gate.command_label().to_string(),
            blocker_root: sample_root("deferred-gate-blocker", gate.as_str(), ordinal),
            replay_receipt_root: sample_root(
                "deferred-gate-replay-receipt",
                gate.as_str(),
                ordinal,
            ),
            disposition,
            replayed_in_shadow: matches!(disposition, ReplayDisposition::PassedInShadow),
            production_gate_executed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "replay_id": self.replay_id,
            "gate": self.gate.as_str(),
            "command_label": self.command_label,
            "blocker_root": self.blocker_root,
            "replay_receipt_root": self.replay_receipt_root,
            "disposition": self.disposition.as_str(),
            "replayed_in_shadow": self.replayed_in_shadow,
            "production_gate_executed": self.production_gate_executed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deferred-gate-replay", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("deferred gate replay id", &self.replay_id)?;
        ensure_non_empty("deferred gate command label", &self.command_label)?;
        ensure_non_empty("deferred gate blocker root", &self.blocker_root)?;
        ensure_non_empty(
            "deferred gate replay receipt root",
            &self.replay_receipt_root,
        )?;
        ensure(
            !self.production_gate_executed,
            "drill must not claim production heavy gate execution",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrillStepReceipt {
    pub step_id: String,
    pub kind: DrillStepKind,
    pub operator_id: String,
    pub input_root: String,
    pub output_root: String,
    pub sequence: u64,
    pub completed: bool,
    pub blocks_unhold_when_missing: bool,
}

impl DrillStepReceipt {
    pub fn devnet(kind: DrillStepKind, operator_id: &str, sequence: u64, completed: bool) -> Self {
        Self {
            step_id: stable_id("rollback-drill-step", kind.as_str(), sequence),
            kind,
            operator_id: operator_id.to_string(),
            input_root: sample_root("rollback-drill-step-input", kind.as_str(), sequence),
            output_root: sample_root("rollback-drill-step-output", kind.as_str(), sequence),
            sequence,
            completed,
            blocks_unhold_when_missing: kind.must_precede_unhold(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "kind": self.kind.as_str(),
            "operator_id": self.operator_id,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "sequence": self.sequence,
            "completed": self.completed,
            "blocks_unhold_when_missing": self.blocks_unhold_when_missing,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("drill-step-receipt", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("drill step id", &self.step_id)?;
        ensure_non_empty("drill step operator id", &self.operator_id)?;
        ensure_non_empty("drill step input root", &self.input_root)?;
        ensure_non_empty("drill step output root", &self.output_root)?;
        ensure(self.sequence > 0, "drill step sequence must be non-zero")?;
        ensure(
            self.completed || self.blocks_unhold_when_missing,
            "incomplete non-blocking drill step is not meaningful evidence",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub dashboard_role: String,
    pub runbook_transcript_root: String,
    pub rollback_command_root: String,
    pub abort_criteria_root: String,
    pub acknowledged_hold_state: bool,
    pub acknowledged_unhold_blockers: bool,
    pub signed_at_height: u64,
}

impl OperatorAcknowledgement {
    pub fn devnet(operator_id: &str, role: &str, config: &Config, ordinal: u64) -> Self {
        Self {
            acknowledgement_id: stable_id("operator-acknowledgement", operator_id, ordinal),
            operator_id: operator_id.to_string(),
            dashboard_role: role.to_string(),
            runbook_transcript_root: sample_root("operator-runbook-ack-root", operator_id, ordinal),
            rollback_command_root: sample_root("operator-rollback-ack-root", operator_id, ordinal),
            abort_criteria_root: sample_root("operator-abort-ack-root", operator_id, ordinal),
            acknowledged_hold_state: true,
            acknowledged_unhold_blockers: true,
            signed_at_height: config.drill_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "dashboard_role": self.dashboard_role,
            "runbook_transcript_root": self.runbook_transcript_root,
            "rollback_command_root": self.rollback_command_root,
            "abort_criteria_root": self.abort_criteria_root,
            "acknowledged_hold_state": self.acknowledged_hold_state,
            "acknowledged_unhold_blockers": self.acknowledged_unhold_blockers,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator-acknowledgement", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("operator acknowledgement id", &self.acknowledgement_id)?;
        ensure_non_empty("operator acknowledgement operator id", &self.operator_id)?;
        ensure_non_empty("operator acknowledgement role", &self.dashboard_role)?;
        ensure_non_empty(
            "operator acknowledgement runbook transcript root",
            &self.runbook_transcript_root,
        )?;
        ensure_non_empty(
            "operator acknowledgement rollback command root",
            &self.rollback_command_root,
        )?;
        ensure_non_empty(
            "operator acknowledgement abort criteria root",
            &self.abort_criteria_root,
        )?;
        ensure(
            self.acknowledged_hold_state,
            "operator must acknowledge hold state",
        )?;
        ensure(
            self.acknowledged_unhold_blockers,
            "operator must acknowledge unhold blockers",
        )?;
        ensure(
            self.signed_at_height > 0,
            "operator acknowledgement height must be non-zero",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldUnholdDrillState {
    pub state_id: String,
    pub previous_hold_root: String,
    pub current_hold_root: String,
    pub candidate_unhold_root: String,
    pub final_verdict: HoldUnholdVerdict,
    pub fail_closed_hold_active: bool,
    pub release_unheld: bool,
    pub blocker_count: u64,
}

impl HoldUnholdDrillState {
    pub fn devnet(blocker_count: u64) -> Self {
        let final_verdict = if blocker_count == 0 {
            HoldUnholdVerdict::UnholdCandidate
        } else {
            HoldUnholdVerdict::Hold
        };
        Self {
            state_id: stable_id("hold-unhold-drill-state", "devnet", blocker_count),
            previous_hold_root: sample_root("hold-unhold-previous-hold", "devnet", 1),
            current_hold_root: sample_root("hold-unhold-current-hold", "devnet", blocker_count),
            candidate_unhold_root: sample_root("hold-unhold-candidate-unhold", "devnet", 2),
            final_verdict,
            fail_closed_hold_active: true,
            release_unheld: final_verdict.allows_release(),
            blocker_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_id": self.state_id,
            "previous_hold_root": self.previous_hold_root,
            "current_hold_root": self.current_hold_root,
            "candidate_unhold_root": self.candidate_unhold_root,
            "final_verdict": self.final_verdict.as_str(),
            "fail_closed_hold_active": self.fail_closed_hold_active,
            "release_unheld": self.release_unheld,
            "blocker_count": self.blocker_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("hold-unhold-drill-state", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("hold unhold drill state id", &self.state_id)?;
        ensure_non_empty("previous hold root", &self.previous_hold_root)?;
        ensure_non_empty("current hold root", &self.current_hold_root)?;
        ensure_non_empty("candidate unhold root", &self.candidate_unhold_root)?;
        ensure(
            self.fail_closed_hold_active || self.release_unheld,
            "hold-unhold drill must either hold fail-closed or record a release unhold",
        )?;
        ensure(
            !self.release_unheld || self.final_verdict.allows_release(),
            "release unheld flag must match final verdict",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackDrillVerdict {
    pub fail_closed: bool,
    pub release_held: bool,
    pub release_unheld: bool,
    pub production_deploy_allowed: bool,
    pub wave_84_binding_count: usize,
    pub runbook_transcript_count: usize,
    pub rollback_receipt_count: usize,
    pub abort_receipt_count: usize,
    pub operator_ack_count: usize,
    pub heavy_gate_blocker_count: usize,
    pub active_abort_count: usize,
    pub completed_drill_step_count: usize,
    pub blocker_count: usize,
    pub binding_root: String,
    pub runbook_transcript_root: String,
    pub rollback_command_root: String,
    pub abort_criteria_root: String,
    pub deferred_gate_replay_root: String,
    pub drill_step_root: String,
    pub operator_acknowledgement_root: String,
    pub hold_unhold_drill_root: String,
    pub blocker_root: String,
    pub verdict_root: String,
}

impl RollbackDrillVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "fail_closed": self.fail_closed,
            "release_held": self.release_held,
            "release_unheld": self.release_unheld,
            "production_deploy_allowed": self.production_deploy_allowed,
            "wave_84_binding_count": self.wave_84_binding_count,
            "runbook_transcript_count": self.runbook_transcript_count,
            "rollback_receipt_count": self.rollback_receipt_count,
            "abort_receipt_count": self.abort_receipt_count,
            "operator_ack_count": self.operator_ack_count,
            "heavy_gate_blocker_count": self.heavy_gate_blocker_count,
            "active_abort_count": self.active_abort_count,
            "completed_drill_step_count": self.completed_drill_step_count,
            "blocker_count": self.blocker_count,
            "binding_root": self.binding_root,
            "runbook_transcript_root": self.runbook_transcript_root,
            "rollback_command_root": self.rollback_command_root,
            "abort_criteria_root": self.abort_criteria_root,
            "deferred_gate_replay_root": self.deferred_gate_replay_root,
            "drill_step_root": self.drill_step_root,
            "operator_acknowledgement_root": self.operator_acknowledgement_root,
            "hold_unhold_drill_root": self.hold_unhold_drill_root,
            "blocker_root": self.blocker_root,
            "verdict_root": self.verdict_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback-drill-verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub wave_84_bindings: Vec<Wave84GuardBinding>,
    pub runbook_transcripts: Vec<RunbookTranscript>,
    pub rollback_commands: Vec<RollbackCommandReceipt>,
    pub abort_criteria: Vec<AbortCriterion>,
    pub deferred_gate_replays: Vec<DeferredGateReplay>,
    pub drill_steps: Vec<DrillStepReceipt>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub hold_unhold_drill_state: HoldUnholdDrillState,
    pub blockers: BTreeMap<String, Vec<String>>,
    pub verdict: RollbackDrillVerdict,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        match Self::try_devnet(config) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn try_devnet(config: Config) -> Result<Self> {
        config.validate()?;
        let wave_84_bindings = Wave84GuardRootKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| Wave84GuardBinding::devnet(kind, &config, one_based(index)))
            .collect::<Vec<_>>();
        let runbook_transcripts = vec![
            RunbookTranscript::new(
                "operator-release-captain",
                "release_captain",
                "rollback-drill-overview",
                42,
                1,
            ),
            RunbookTranscript::new(
                "operator-runtime-owner",
                "runtime_owner",
                "compile-runtime-guard-bindings",
                36,
                2,
            ),
            RunbookTranscript::new(
                "operator-security-watch",
                "security_watch",
                "abort-and-hold-unhold-criteria",
                39,
                3,
            ),
            RunbookTranscript::new(
                "operator-bridge-custody",
                "bridge_custody",
                "rollback-command-receipts",
                33,
                4,
            ),
        ];
        let rollback_commands = RollbackCommandKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| RollbackCommandReceipt::devnet(kind, one_based(index)))
            .collect::<Vec<_>>();
        let abort_criteria = AbortCriterionKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                let active = matches!(
                    kind,
                    AbortCriterionKind::DeferredHeavyGateUnresolved
                        | AbortCriterionKind::RollbackReceiptMissing
                );
                AbortCriterion::devnet(kind, active, one_based(index))
            })
            .collect::<Vec<_>>();
        let deferred_gate_replays = vec![
            DeferredGateReplay::devnet(HeavyGateKind::CargoCheck, ReplayDisposition::Deferred, 1),
            DeferredGateReplay::devnet(HeavyGateKind::CargoTest, ReplayDisposition::Deferred, 2),
            DeferredGateReplay::devnet(HeavyGateKind::CargoClippy, ReplayDisposition::Deferred, 3),
        ];
        let drill_steps = DrillStepKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                DrillStepReceipt::devnet(kind, operator_for_step(kind), one_based(index), true)
            })
            .collect::<Vec<_>>();
        let operator_acknowledgements = vec![
            OperatorAcknowledgement::devnet(
                "operator-release-captain",
                "release_captain",
                &config,
                1,
            ),
            OperatorAcknowledgement::devnet("operator-runtime-owner", "runtime_owner", &config, 2),
            OperatorAcknowledgement::devnet(
                "operator-security-watch",
                "security_watch",
                &config,
                3,
            ),
            OperatorAcknowledgement::devnet(
                "operator-bridge-custody",
                "bridge_custody",
                &config,
                4,
            ),
        ];
        validate_unique_roots(
            "wave 84 binding roots",
            wave_84_bindings.iter().map(|binding| &binding.binding_root),
        )?;
        for binding in &wave_84_bindings {
            binding.validate()?;
        }
        for transcript in &runbook_transcripts {
            transcript.validate()?;
        }
        for command in &rollback_commands {
            command.validate()?;
        }
        for criterion in &abort_criteria {
            criterion.validate()?;
        }
        for replay in &deferred_gate_replays {
            replay.validate()?;
        }
        for step in &drill_steps {
            step.validate()?;
        }
        for acknowledgement in &operator_acknowledgements {
            acknowledgement.validate()?;
        }
        let blockers = evaluate_blockers(
            &config,
            &wave_84_bindings,
            &runbook_transcripts,
            &rollback_commands,
            &abort_criteria,
            &deferred_gate_replays,
            &drill_steps,
            &operator_acknowledgements,
        );
        let blocker_count = blockers.values().map(Vec::len).sum::<usize>() as u64;
        let hold_unhold_drill_state = HoldUnholdDrillState::devnet(blocker_count);
        hold_unhold_drill_state.validate()?;
        let verdict = build_verdict(
            &config,
            &wave_84_bindings,
            &runbook_transcripts,
            &rollback_commands,
            &abort_criteria,
            &deferred_gate_replays,
            &drill_steps,
            &operator_acknowledgements,
            &hold_unhold_drill_state,
            &blockers,
        );
        Ok(Self {
            config,
            wave_84_bindings,
            runbook_transcripts,
            rollback_commands,
            abort_criteria,
            deferred_gate_replays,
            drill_steps,
            operator_acknowledgements,
            hold_unhold_drill_state,
            blockers,
            verdict,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "wave_84_bindings": self.wave_84_bindings.iter().map(Wave84GuardBinding::public_record).collect::<Vec<_>>(),
            "runbook_transcripts": self.runbook_transcripts.iter().map(RunbookTranscript::public_record).collect::<Vec<_>>(),
            "rollback_commands": self.rollback_commands.iter().map(RollbackCommandReceipt::public_record).collect::<Vec<_>>(),
            "abort_criteria": self.abort_criteria.iter().map(AbortCriterion::public_record).collect::<Vec<_>>(),
            "deferred_gate_replays": self.deferred_gate_replays.iter().map(DeferredGateReplay::public_record).collect::<Vec<_>>(),
            "drill_steps": self.drill_steps.iter().map(DrillStepReceipt::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "hold_unhold_drill_state": self.hold_unhold_drill_state.public_record(),
            "blockers": self.blockers,
            "verdict": self.verdict.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-ROLLBACK-DRILL-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.release_channel),
                HashPart::U64(self.config.release_epoch),
                HashPart::U64(self.config.drill_height),
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

fn build_verdict(
    config: &Config,
    wave_84_bindings: &[Wave84GuardBinding],
    runbook_transcripts: &[RunbookTranscript],
    rollback_commands: &[RollbackCommandReceipt],
    abort_criteria: &[AbortCriterion],
    deferred_gate_replays: &[DeferredGateReplay],
    drill_steps: &[DrillStepReceipt],
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_unhold_drill_state: &HoldUnholdDrillState,
    blockers: &BTreeMap<String, Vec<String>>,
) -> RollbackDrillVerdict {
    let binding_root = roots_root(
        "rollback-drill-wave-84-bindings",
        wave_84_bindings.iter().map(Wave84GuardBinding::state_root),
    );
    let runbook_transcript_root = roots_root(
        "rollback-drill-runbook-transcripts",
        runbook_transcripts
            .iter()
            .map(RunbookTranscript::state_root),
    );
    let rollback_command_root = roots_root(
        "rollback-drill-rollback-commands",
        rollback_commands
            .iter()
            .map(RollbackCommandReceipt::state_root),
    );
    let abort_criteria_root = roots_root(
        "rollback-drill-abort-criteria",
        abort_criteria.iter().map(AbortCriterion::state_root),
    );
    let deferred_gate_replay_root = roots_root(
        "rollback-drill-deferred-gate-replays",
        deferred_gate_replays
            .iter()
            .map(DeferredGateReplay::state_root),
    );
    let drill_step_root = roots_root(
        "rollback-drill-steps",
        drill_steps.iter().map(DrillStepReceipt::state_root),
    );
    let operator_acknowledgement_root = roots_root(
        "rollback-drill-operator-acks",
        operator_acknowledgements
            .iter()
            .map(OperatorAcknowledgement::state_root),
    );
    let hold_unhold_drill_root = hold_unhold_drill_state.state_root();
    let blocker_root = blockers_root(blockers);
    let active_abort_count = abort_criteria
        .iter()
        .filter(|criterion| criterion.active)
        .count();
    let heavy_gate_blocker_count = deferred_gate_replays
        .iter()
        .filter(|replay| replay.disposition.blocks_unhold())
        .count();
    let completed_drill_step_count = drill_steps.iter().filter(|step| step.completed).count();
    let blocker_count = blockers.values().map(Vec::len).sum::<usize>();
    let release_unheld = hold_unhold_drill_state.release_unheld
        && blocker_count == 0
        && (config.allow_unhold_without_heavy_gates || heavy_gate_blocker_count == 0);
    let production_deploy_allowed = release_unheld && !config.require_fail_closed_default;
    let release_held = !production_deploy_allowed;
    let verdict_root = roots_root(
        "rollback-drill-verdict",
        [
            config.state_root(),
            binding_root.clone(),
            runbook_transcript_root.clone(),
            rollback_command_root.clone(),
            abort_criteria_root.clone(),
            deferred_gate_replay_root.clone(),
            drill_step_root.clone(),
            operator_acknowledgement_root.clone(),
            hold_unhold_drill_root.clone(),
            blocker_root.clone(),
        ],
    );
    RollbackDrillVerdict {
        fail_closed: config.require_fail_closed_default,
        release_held,
        release_unheld,
        production_deploy_allowed,
        wave_84_binding_count: wave_84_bindings.len(),
        runbook_transcript_count: runbook_transcripts.len(),
        rollback_receipt_count: rollback_commands.len(),
        abort_receipt_count: abort_criteria.len(),
        operator_ack_count: operator_acknowledgements.len(),
        heavy_gate_blocker_count,
        active_abort_count,
        completed_drill_step_count,
        blocker_count,
        binding_root,
        runbook_transcript_root,
        rollback_command_root,
        abort_criteria_root,
        deferred_gate_replay_root,
        drill_step_root,
        operator_acknowledgement_root,
        hold_unhold_drill_root,
        blocker_root,
        verdict_root,
    }
}

fn evaluate_blockers(
    config: &Config,
    wave_84_bindings: &[Wave84GuardBinding],
    runbook_transcripts: &[RunbookTranscript],
    rollback_commands: &[RollbackCommandReceipt],
    abort_criteria: &[AbortCriterion],
    deferred_gate_replays: &[DeferredGateReplay],
    drill_steps: &[DrillStepReceipt],
    operator_acknowledgements: &[OperatorAcknowledgement],
) -> BTreeMap<String, Vec<String>> {
    let mut blockers = BTreeMap::<String, Vec<String>>::new();
    if config.require_wave_84_guard_root
        && wave_84_bindings.len() < Wave84GuardRootKind::all().len()
    {
        blockers
            .entry("wave_84_bindings".to_string())
            .or_default()
            .push("missing_required_wave_84_guard_root".to_string());
    }
    if config.require_runbook_transcript_root
        && runbook_transcripts.len() < usize::from(config.min_runbook_transcripts)
    {
        blockers
            .entry("runbook_transcripts".to_string())
            .or_default()
            .push("runbook_transcript_quorum_missing".to_string());
    }
    if config.require_rollback_command_root
        && rollback_commands.len() < usize::from(config.min_rollback_receipts)
    {
        blockers
            .entry("rollback_commands".to_string())
            .or_default()
            .push("rollback_command_receipts_missing".to_string());
    }
    let abort_receipts = abort_criteria
        .iter()
        .filter(|criterion| !criterion.evidence_root.trim().is_empty())
        .count();
    if config.require_abort_criteria_root && abort_receipts < usize::from(config.min_abort_receipts)
    {
        blockers
            .entry("abort_criteria".to_string())
            .or_default()
            .push("abort_criteria_receipts_missing".to_string());
    }
    let active_abort_count = abort_criteria
        .iter()
        .filter(|criterion| criterion.active && criterion.blocks_unhold)
        .count();
    if active_abort_count > 0 {
        blockers
            .entry("abort_criteria".to_string())
            .or_default()
            .push("active_abort_criteria_block_unhold".to_string());
    }
    let heavy_gate_blocker_count = deferred_gate_replays
        .iter()
        .filter(|replay| replay.disposition.blocks_unhold())
        .count();
    if config.require_deferred_gate_replay_root
        && deferred_gate_replays.len() < usize::from(config.min_heavy_gate_replays)
    {
        blockers
            .entry("deferred_gate_replays".to_string())
            .or_default()
            .push("deferred_gate_replay_receipts_missing".to_string());
    }
    if heavy_gate_blocker_count > 0 {
        blockers
            .entry("deferred_gate_replays".to_string())
            .or_default()
            .push("deferred_heavy_gate_blockers_replayed_as_hold".to_string());
    }
    let completed_required_steps = drill_steps
        .iter()
        .filter(|step| step.completed && step.blocks_unhold_when_missing)
        .count();
    let required_step_count = DrillStepKind::all()
        .into_iter()
        .filter(|step| step.must_precede_unhold())
        .count();
    if completed_required_steps < required_step_count {
        blockers
            .entry("drill_steps".to_string())
            .or_default()
            .push("required_drill_steps_incomplete".to_string());
    }
    if config.require_operator_acknowledgement_root
        && operator_acknowledgements.len() < usize::from(config.min_operator_acks)
    {
        blockers
            .entry("operator_acknowledgements".to_string())
            .or_default()
            .push("operator_acknowledgement_quorum_missing".to_string());
    }
    if config.require_release_hold_on_blocker && active_abort_count + heavy_gate_blocker_count > 0 {
        blockers
            .entry("release_hold".to_string())
            .or_default()
            .push("release_hold_required_while_blockers_active".to_string());
    }
    if config.require_fail_closed_default {
        blockers
            .entry("release_hold".to_string())
            .or_default()
            .push("fail_closed_default_prevents_unhold_in_drill".to_string());
    }
    blockers
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let wave_84_bindings = Vec::new();
    let runbook_transcripts = Vec::new();
    let rollback_commands = Vec::new();
    let abort_criteria = vec![AbortCriterion::devnet(
        AbortCriterionKind::DashboardRootDrift,
        true,
        1,
    )];
    let deferred_gate_replays = Vec::new();
    let drill_steps = Vec::new();
    let operator_acknowledgements = Vec::new();
    let hold_unhold_drill_state = HoldUnholdDrillState {
        state_id: stable_id("hold-unhold-drill-state", "fallback", 0),
        previous_hold_root: sample_root("hold-unhold-previous-hold", "fallback", 0),
        current_hold_root: sample_root("hold-unhold-current-hold", "fallback", 0),
        candidate_unhold_root: sample_root("hold-unhold-candidate-unhold", "fallback", 0),
        final_verdict: HoldUnholdVerdict::Abort,
        fail_closed_hold_active: true,
        release_unheld: false,
        blocker_count: 2,
    };
    let mut blockers = BTreeMap::<String, Vec<String>>::new();
    blockers
        .entry("fallback".to_string())
        .or_default()
        .push("rollback_drill_state_construction_failed".to_string());
    blockers
        .entry("fallback".to_string())
        .or_default()
        .push(reason);
    let verdict = build_verdict(
        &config,
        &wave_84_bindings,
        &runbook_transcripts,
        &rollback_commands,
        &abort_criteria,
        &deferred_gate_replays,
        &drill_steps,
        &operator_acknowledgements,
        &hold_unhold_drill_state,
        &blockers,
    );
    State {
        config,
        wave_84_bindings,
        runbook_transcripts,
        rollback_commands,
        abort_criteria,
        deferred_gate_replays,
        drill_steps,
        operator_acknowledgements,
        hold_unhold_drill_state,
        blockers,
        verdict,
    }
}

fn operator_for_step(kind: DrillStepKind) -> &'static str {
    match kind {
        DrillStepKind::BindWave84Outputs => "operator-runtime-owner",
        DrillStepKind::AnnounceFailClosedHold => "operator-release-captain",
        DrillStepKind::ReadRunbook => "operator-release-captain",
        DrillStepKind::StageRollbackCommand => "operator-bridge-custody",
        DrillStepKind::VerifyAbortCriteria => "operator-security-watch",
        DrillStepKind::ReplayDeferredGateBlocker => "operator-runtime-owner",
        DrillStepKind::OperatorAcknowledgement => "operator-release-captain",
        DrillStepKind::HoldUnholdDecision => "operator-release-captain",
        DrillStepKind::PublishEvidenceBundle => "operator-runtime-owner",
    }
}

fn one_based(index: usize) -> u64 {
    index as u64 + 1
}

fn validate_unique_roots<'a, I>(label: &str, roots: I) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut seen = BTreeSet::new();
    for root in roots {
        ensure_non_empty(label, root)?;
        ensure(seen.insert(root), &format!("{label} must be unique"))?;
    }
    Ok(())
}

fn blockers_root(blockers: &BTreeMap<String, Vec<String>>) -> String {
    let leaves = blockers
        .iter()
        .map(|(subject, blocker_list)| {
            json!({
                "subject": subject,
                "blockers": blocker_list,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("rollback-drill-blockers", &leaves)
}

fn roots_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-ROLLBACK-DRILL-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-ROLLBACK-DRILL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn sample_root(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-ROLLBACK-DRILL-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::U64(ordinal),
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

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{label} must be non-empty"),
    )
}
