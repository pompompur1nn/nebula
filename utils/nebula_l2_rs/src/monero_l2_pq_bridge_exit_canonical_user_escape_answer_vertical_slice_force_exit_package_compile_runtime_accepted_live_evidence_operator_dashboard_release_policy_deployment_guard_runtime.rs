use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GUARD_SUITE: &str =
    "monero-l2-pq-force-exit-compile-runtime-release-policy-deployment-guard-v1";
pub const DEFAULT_RELEASE_EPOCH: u64 = 84;
pub const DEFAULT_RELEASE_HEIGHT: u64 = 840_000;
pub const DEFAULT_BINDING_HEIGHT: u64 = 839_960;
pub const DEFAULT_MAX_BINDING_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_OPERATOR_APPROVALS: u16 = 3;
pub const DEFAULT_MIN_RUNBOOK_ACKS: u16 = 3;
pub const DEFAULT_MIN_ROLLBACK_PROOFS: u16 = 3;
pub const DEFAULT_MIN_UNHOLD_PROOFS: u16 = 4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub guard_suite: String,
    pub release_epoch: u64,
    pub release_height: u64,
    pub binding_height: u64,
    pub release_channel: String,
    pub deployment_environment: String,
    pub max_binding_age_blocks: u64,
    pub min_operator_approvals: u16,
    pub min_runbook_acks: u16,
    pub min_rollback_proofs: u16,
    pub min_unhold_proofs: u16,
    pub require_go_no_go_binding_root: bool,
    pub require_compile_runtime_binding_root: bool,
    pub require_rustfmt_receipt_root: bool,
    pub require_cargo_check_receipt: bool,
    pub require_cargo_test_receipt: bool,
    pub require_cargo_clippy_receipt: bool,
    pub require_operator_dashboard_approval: bool,
    pub require_runbook_acknowledgement: bool,
    pub require_rollback_abort_roots: bool,
    pub require_hold_unhold_criteria: bool,
    pub require_window_closed_on_blocker: bool,
    pub fail_closed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            guard_suite: GUARD_SUITE.to_string(),
            release_epoch: DEFAULT_RELEASE_EPOCH,
            release_height: DEFAULT_RELEASE_HEIGHT,
            binding_height: DEFAULT_BINDING_HEIGHT,
            release_channel: "devnet-compile-runtime-dashboard-release-policy-guard".to_string(),
            deployment_environment: "devnet-production-shadow".to_string(),
            max_binding_age_blocks: DEFAULT_MAX_BINDING_AGE_BLOCKS,
            min_operator_approvals: DEFAULT_MIN_OPERATOR_APPROVALS,
            min_runbook_acks: DEFAULT_MIN_RUNBOOK_ACKS,
            min_rollback_proofs: DEFAULT_MIN_ROLLBACK_PROOFS,
            min_unhold_proofs: DEFAULT_MIN_UNHOLD_PROOFS,
            require_go_no_go_binding_root: true,
            require_compile_runtime_binding_root: true,
            require_rustfmt_receipt_root: true,
            require_cargo_check_receipt: true,
            require_cargo_test_receipt: true,
            require_cargo_clippy_receipt: true,
            require_operator_dashboard_approval: true,
            require_runbook_acknowledgement: true,
            require_rollback_abort_roots: true,
            require_hold_unhold_criteria: true,
            require_window_closed_on_blocker: true,
            fail_closed: true,
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
        ensure_non_empty("guard_suite", &self.guard_suite)?;
        ensure_non_empty("release_channel", &self.release_channel)?;
        ensure_non_empty("deployment_environment", &self.deployment_environment)?;
        ensure(self.schema_version > 0, "schema version must be non-zero")?;
        ensure(self.release_epoch > 0, "release epoch must be non-zero")?;
        ensure(self.release_height > 0, "release height must be non-zero")?;
        ensure(self.binding_height > 0, "binding height must be non-zero")?;
        ensure(
            self.release_height >= self.binding_height,
            "release height must not precede binding height",
        )?;
        ensure(
            self.max_binding_age_blocks > 0,
            "binding age window must be non-zero",
        )?;
        ensure(
            self.min_operator_approvals > 0,
            "operator approval minimum must be non-zero",
        )?;
        ensure(
            self.min_runbook_acks > 0,
            "runbook acknowledgement minimum must be non-zero",
        )?;
        ensure(
            self.min_rollback_proofs > 0,
            "rollback proof minimum must be non-zero",
        )?;
        ensure(
            self.min_unhold_proofs > 0,
            "unhold proof minimum must be non-zero",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "guard_suite": self.guard_suite,
            "release_epoch": self.release_epoch,
            "release_height": self.release_height,
            "binding_height": self.binding_height,
            "release_channel": self.release_channel,
            "deployment_environment": self.deployment_environment,
            "max_binding_age_blocks": self.max_binding_age_blocks,
            "min_operator_approvals": self.min_operator_approvals,
            "min_runbook_acks": self.min_runbook_acks,
            "min_rollback_proofs": self.min_rollback_proofs,
            "min_unhold_proofs": self.min_unhold_proofs,
            "require_go_no_go_binding_root": self.require_go_no_go_binding_root,
            "require_compile_runtime_binding_root": self.require_compile_runtime_binding_root,
            "require_rustfmt_receipt_root": self.require_rustfmt_receipt_root,
            "require_cargo_check_receipt": self.require_cargo_check_receipt,
            "require_cargo_test_receipt": self.require_cargo_test_receipt,
            "require_cargo_clippy_receipt": self.require_cargo_clippy_receipt,
            "require_operator_dashboard_approval": self.require_operator_dashboard_approval,
            "require_runbook_acknowledgement": self.require_runbook_acknowledgement,
            "require_rollback_abort_roots": self.require_rollback_abort_roots,
            "require_hold_unhold_criteria": self.require_hold_unhold_criteria,
            "require_window_closed_on_blocker": self.require_window_closed_on_blocker,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingSourceKind {
    CompileRuntimeDashboardReleasePolicy,
    ReleasePolicyGoNoGo,
}

impl BindingSourceKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::CompileRuntimeDashboardReleasePolicy,
            Self::ReleasePolicyGoNoGo,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntimeDashboardReleasePolicy => {
                "compile_runtime_dashboard_release_policy"
            }
            Self::ReleasePolicyGoNoGo => "release_policy_go_no_go",
        }
    }

    pub fn module_hint(self) -> &'static str {
        match self {
            Self::CompileRuntimeDashboardReleasePolicy => {
                "compile_runtime_accepted_live_evidence_operator_dashboard_release_policy_binding"
            }
            Self::ReleasePolicyGoNoGo => {
                "release_policy_accepted_live_evidence_operator_dashboard_go_no_go_binding"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptGateKind {
    Rustfmt,
    CargoCheck,
    CargoTest,
    CargoClippy,
}

impl ReceiptGateKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Rustfmt,
            Self::CargoCheck,
            Self::CargoTest,
            Self::CargoClippy,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rustfmt => "rustfmt",
            Self::CargoCheck => "cargo_check",
            Self::CargoTest => "cargo_test",
            Self::CargoClippy => "cargo_clippy",
        }
    }

    pub fn command_label(self) -> &'static str {
        match self {
            Self::Rustfmt => "rustfmt-target-runtime-file",
            Self::CargoCheck => "cargo-check-deferred",
            Self::CargoTest => "cargo-test-deferred",
            Self::CargoClippy => "cargo-clippy-deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    DeferredBlocker,
    Missing,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::DeferredBlocker => "deferred_blocker",
            Self::Missing => "missing",
        }
    }

    pub fn allows_deploy(self) -> bool {
        matches!(self, Self::Accepted)
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

    pub fn blocks_deploy(self) -> bool {
        matches!(self, Self::Hold | Self::Abort)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentWindowStatus {
    Open,
    Closed,
    Suspended,
}

impl DeploymentWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Suspended => "suspended",
        }
    }

    pub fn deployable(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    FailClosedHeld,
    GuardedReady,
    Aborted,
}

impl DeploymentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedHeld => "fail_closed_held",
            Self::GuardedReady => "guarded_ready",
            Self::Aborted => "aborted",
        }
    }

    pub fn allows_production(self) -> bool {
        matches!(self, Self::GuardedReady)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    MissingCompileRuntimeBindingRoot,
    MissingGoNoGoBindingRoot,
    BindingTooOld,
    GoNoGoNotAccepted,
    MissingRustfmtReceiptRoot,
    CargoCheckDeferred,
    CargoTestDeferred,
    CargoClippyDeferred,
    OperatorApprovalQuorumMissing,
    RunbookAcknowledgementMissing,
    RollbackAbortRootMissing,
    HoldDecisionActive,
    UnholdCriteriaIncomplete,
    DeploymentWindowClosed,
    FailClosedProductionState,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCompileRuntimeBindingRoot => "missing_compile_runtime_binding_root",
            Self::MissingGoNoGoBindingRoot => "missing_go_no_go_binding_root",
            Self::BindingTooOld => "binding_too_old",
            Self::GoNoGoNotAccepted => "go_no_go_not_accepted",
            Self::MissingRustfmtReceiptRoot => "missing_rustfmt_receipt_root",
            Self::CargoCheckDeferred => "cargo_check_deferred",
            Self::CargoTestDeferred => "cargo_test_deferred",
            Self::CargoClippyDeferred => "cargo_clippy_deferred",
            Self::OperatorApprovalQuorumMissing => "operator_approval_quorum_missing",
            Self::RunbookAcknowledgementMissing => "runbook_acknowledgement_missing",
            Self::RollbackAbortRootMissing => "rollback_abort_root_missing",
            Self::HoldDecisionActive => "hold_decision_active",
            Self::UnholdCriteriaIncomplete => "unhold_criteria_incomplete",
            Self::DeploymentWindowClosed => "deployment_window_closed",
            Self::FailClosedProductionState => "fail_closed_production_state",
        }
    }

    pub fn severity(self) -> &'static str {
        match self {
            Self::CargoCheckDeferred
            | Self::CargoTestDeferred
            | Self::CargoClippyDeferred
            | Self::FailClosedProductionState => "critical",
            Self::HoldDecisionActive
            | Self::GoNoGoNotAccepted
            | Self::DeploymentWindowClosed
            | Self::BindingTooOld => "high",
            _ => "medium",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackRootKind {
    PreviousRuntimeManifest,
    ForceExitCircuitBreaker,
    OperatorAbortRunbook,
    BridgeCustodyFreeze,
    DashboardIncidentSnapshot,
}

impl RollbackRootKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::PreviousRuntimeManifest,
            Self::ForceExitCircuitBreaker,
            Self::OperatorAbortRunbook,
            Self::BridgeCustodyFreeze,
            Self::DashboardIncidentSnapshot,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreviousRuntimeManifest => "previous_runtime_manifest",
            Self::ForceExitCircuitBreaker => "force_exit_circuit_breaker",
            Self::OperatorAbortRunbook => "operator_abort_runbook",
            Self::BridgeCustodyFreeze => "bridge_custody_freeze",
            Self::DashboardIncidentSnapshot => "dashboard_incident_snapshot",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BindingRoot {
    pub binding_id: String,
    pub source: BindingSourceKind,
    pub binding_root: String,
    pub accepted: bool,
    pub binding_height: u64,
    pub imported_evidence_root: String,
    pub dashboard_root: String,
    pub runbook_root: String,
}

impl BindingRoot {
    pub fn devnet(config: &Config, source: BindingSourceKind, ordinal: u64) -> Self {
        Self {
            binding_id: stable_id("binding", source.as_str(), ordinal),
            source,
            binding_root: sample_root("binding-root", source.as_str(), ordinal),
            accepted: true,
            binding_height: config.binding_height.saturating_sub(ordinal),
            imported_evidence_root: sample_root("imported-evidence", source.as_str(), ordinal),
            dashboard_root: sample_root("dashboard", source.as_str(), ordinal),
            runbook_root: sample_root("runbook", source.as_str(), ordinal),
        }
    }

    pub fn age_blocks(&self, release_height: u64) -> u64 {
        release_height.saturating_sub(self.binding_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "source": self.source.as_str(),
            "module_hint": self.source.module_hint(),
            "binding_root": self.binding_root,
            "accepted": self.accepted,
            "binding_height": self.binding_height,
            "imported_evidence_root": self.imported_evidence_root,
            "dashboard_root": self.dashboard_root,
            "runbook_root": self.runbook_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("binding-root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptEvidence {
    pub receipt_id: String,
    pub gate: ReceiptGateKind,
    pub status: ReceiptStatus,
    pub command_label: String,
    pub receipt_root: String,
    pub blocker_root: String,
    pub deferred_reason: String,
    pub operator_note_root: String,
}

impl ReceiptEvidence {
    pub fn devnet(gate: ReceiptGateKind, ordinal: u64) -> Self {
        let status = match gate {
            ReceiptGateKind::Rustfmt => ReceiptStatus::Accepted,
            ReceiptGateKind::CargoCheck
            | ReceiptGateKind::CargoTest
            | ReceiptGateKind::CargoClippy => ReceiptStatus::DeferredBlocker,
        };
        let deferred_reason = match gate {
            ReceiptGateKind::Rustfmt => "rustfmt receipt accepted for target runtime file only",
            ReceiptGateKind::CargoCheck => "cargo check intentionally deferred by worker contract",
            ReceiptGateKind::CargoTest => "cargo test intentionally deferred by worker contract",
            ReceiptGateKind::CargoClippy => {
                "cargo clippy intentionally deferred by worker contract"
            }
        };
        Self {
            receipt_id: stable_id("receipt", gate.as_str(), ordinal),
            gate,
            status,
            command_label: gate.command_label().to_string(),
            receipt_root: sample_root("receipt", gate.as_str(), ordinal),
            blocker_root: sample_root("receipt-blocker", gate.as_str(), ordinal),
            deferred_reason: deferred_reason.to_string(),
            operator_note_root: sample_root("operator-note", gate.as_str(), ordinal),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "gate": self.gate.as_str(),
            "status": self.status.as_str(),
            "command_label": self.command_label,
            "receipt_root": self.receipt_root,
            "blocker_root": self.blocker_root,
            "deferred_reason": self.deferred_reason,
            "operator_note_root": self.operator_note_root,
            "allows_deploy": self.status.allows_deploy(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldCriterion {
    pub criterion_id: String,
    pub decision: GuardDecision,
    pub reason: String,
    pub evidence_root: String,
    pub satisfied: bool,
    pub required_for_unhold: bool,
}

impl HoldCriterion {
    pub fn new(
        decision: GuardDecision,
        reason: &str,
        satisfied: bool,
        required_for_unhold: bool,
        ordinal: u64,
    ) -> Self {
        Self {
            criterion_id: stable_id("hold-criterion", decision.as_str(), ordinal),
            decision,
            reason: reason.to_string(),
            evidence_root: sample_root("hold-criterion", reason, ordinal),
            satisfied,
            required_for_unhold,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "decision": self.decision.as_str(),
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "satisfied": self.satisfied,
            "required_for_unhold": self.required_for_unhold,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("hold-criterion", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentWindow {
    pub window_id: String,
    pub environment: String,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub status: DeploymentWindowStatus,
    pub status_root: String,
    pub blocker_policy_root: String,
}

impl DeploymentWindow {
    pub fn devnet(config: &Config, blockers_present: bool) -> Self {
        let status = if blockers_present {
            DeploymentWindowStatus::Closed
        } else {
            DeploymentWindowStatus::Open
        };
        Self {
            window_id: stable_id("deployment-window", &config.deployment_environment, 0),
            environment: config.deployment_environment.clone(),
            opens_at_height: config.release_height,
            closes_at_height: config.release_height + 24,
            status,
            status_root: sample_root("deployment-window-status", status.as_str(), 0),
            blocker_policy_root: sample_root(
                "deployment-window-blocker-policy",
                &config.release_channel,
                0,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "environment": self.environment,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "status": self.status.as_str(),
            "status_root": self.status_root,
            "blocker_policy_root": self.blocker_policy_root,
            "deployable": self.status.deployable(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment-window", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackProof {
    pub proof_id: String,
    pub kind: RollbackRootKind,
    pub proof_root: String,
    pub abort_root: String,
    pub operator: String,
    pub acknowledged: bool,
}

impl RollbackProof {
    pub fn devnet(kind: RollbackRootKind, ordinal: u64) -> Self {
        Self {
            proof_id: stable_id("rollback-proof", kind.as_str(), ordinal),
            kind,
            proof_root: sample_root("rollback-proof", kind.as_str(), ordinal),
            abort_root: sample_root("abort-root", kind.as_str(), ordinal),
            operator: format!("release-operator-{}", ordinal + 1),
            acknowledged: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "kind": self.kind.as_str(),
            "proof_root": self.proof_root,
            "abort_root": self.abort_root,
            "operator": self.operator,
            "acknowledged": self.acknowledged,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("rollback-proof", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorApproval {
    pub approval_id: String,
    pub operator: String,
    pub dashboard_root: String,
    pub runbook_ack_root: String,
    pub approved: bool,
    pub acknowledged_fail_closed: bool,
    pub acknowledged_blockers: bool,
}

impl OperatorApproval {
    pub fn devnet(ordinal: u64) -> Self {
        Self {
            approval_id: stable_id("operator-approval", "dashboard", ordinal),
            operator: format!("release-operator-{}", ordinal + 1),
            dashboard_root: sample_root("operator-dashboard", "approval", ordinal),
            runbook_ack_root: sample_root("runbook-ack", "approval", ordinal),
            approved: true,
            acknowledged_fail_closed: true,
            acknowledged_blockers: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "operator": self.operator,
            "dashboard_root": self.dashboard_root,
            "runbook_ack_root": self.runbook_ack_root,
            "approved": self.approved,
            "acknowledged_fail_closed": self.acknowledged_fail_closed,
            "acknowledged_blockers": self.acknowledged_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator-approval", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeployBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub active: bool,
    pub severity: String,
    pub evidence_root: String,
    pub resolution_root: String,
    pub description: String,
}

impl DeployBlocker {
    pub fn new(kind: BlockerKind, description: &str, active: bool, ordinal: u64) -> Self {
        Self {
            blocker_id: stable_id("deploy-blocker", kind.as_str(), ordinal),
            kind,
            active,
            severity: kind.severity().to_string(),
            evidence_root: sample_root("deploy-blocker-evidence", kind.as_str(), ordinal),
            resolution_root: sample_root("deploy-blocker-resolution", kind.as_str(), ordinal),
            description: description.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "active": self.active,
            "severity": self.severity,
            "evidence_root": self.evidence_root,
            "resolution_root": self.resolution_root,
            "description": self.description,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deploy-blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardVerdict {
    pub deployment_state: DeploymentState,
    pub production_deploy_allowed: bool,
    pub fail_closed: bool,
    pub active_blocker_count: usize,
    pub hold_count: usize,
    pub unhold_criteria_count: usize,
    pub unhold_criteria_satisfied: usize,
    pub operator_approval_count: usize,
    pub runbook_ack_count: usize,
    pub rollback_proof_count: usize,
    pub binding_root: String,
    pub receipt_root: String,
    pub blocker_root: String,
    pub hold_unhold_root: String,
    pub deployment_window_root: String,
    pub rollback_root: String,
    pub operator_approval_root: String,
    pub verdict_root: String,
}

impl GuardVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "deployment_state": self.deployment_state.as_str(),
            "production_deploy_allowed": self.production_deploy_allowed,
            "fail_closed": self.fail_closed,
            "active_blocker_count": self.active_blocker_count,
            "hold_count": self.hold_count,
            "unhold_criteria_count": self.unhold_criteria_count,
            "unhold_criteria_satisfied": self.unhold_criteria_satisfied,
            "operator_approval_count": self.operator_approval_count,
            "runbook_ack_count": self.runbook_ack_count,
            "rollback_proof_count": self.rollback_proof_count,
            "binding_root": self.binding_root,
            "receipt_root": self.receipt_root,
            "blocker_root": self.blocker_root,
            "hold_unhold_root": self.hold_unhold_root,
            "deployment_window_root": self.deployment_window_root,
            "rollback_root": self.rollback_root,
            "operator_approval_root": self.operator_approval_root,
            "verdict_root": self.verdict_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("guard-verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub binding_roots: Vec<BindingRoot>,
    pub receipt_evidence: Vec<ReceiptEvidence>,
    pub hold_criteria: Vec<HoldCriterion>,
    pub deploy_blockers: Vec<DeployBlocker>,
    pub deployment_windows: Vec<DeploymentWindow>,
    pub rollback_proofs: Vec<RollbackProof>,
    pub operator_approvals: Vec<OperatorApproval>,
    pub verdict: GuardVerdict,
}

impl State {
    pub fn devnet() -> Self {
        Self::build(Config::devnet()).unwrap_or_else(fallback_state)
    }

    pub fn build(config: Config) -> Result<Self> {
        config.validate()?;
        let binding_roots = BindingSourceKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, source)| BindingRoot::devnet(&config, source, index as u64))
            .collect::<Vec<_>>();
        let receipt_evidence = ReceiptGateKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, gate)| ReceiptEvidence::devnet(gate, index as u64))
            .collect::<Vec<_>>();
        let hold_criteria = devnet_hold_criteria();
        let mut deploy_blockers =
            evaluate_blockers(&config, &binding_roots, &receipt_evidence, &hold_criteria);
        let operator_approvals = (0..config.min_operator_approvals)
            .map(|index| OperatorApproval::devnet(index as u64))
            .collect::<Vec<_>>();
        let rollback_proofs = RollbackRootKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| RollbackProof::devnet(kind, index as u64))
            .collect::<Vec<_>>();
        add_quorum_blockers(
            &config,
            &operator_approvals,
            &rollback_proofs,
            &mut deploy_blockers,
        );
        let blockers_present = deploy_blockers.iter().any(|blocker| blocker.active);
        let deployment_windows = vec![DeploymentWindow::devnet(&config, blockers_present)];
        add_window_blockers(&config, &deployment_windows, &mut deploy_blockers);
        let verdict = build_verdict(
            &config,
            &binding_roots,
            &receipt_evidence,
            &hold_criteria,
            &deploy_blockers,
            &deployment_windows,
            &rollback_proofs,
            &operator_approvals,
        );
        Ok(Self {
            config,
            binding_roots,
            receipt_evidence,
            hold_criteria,
            deploy_blockers,
            deployment_windows,
            rollback_proofs,
            operator_approvals,
            verdict,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "binding_roots": self.binding_roots.iter().map(BindingRoot::public_record).collect::<Vec<_>>(),
            "receipt_evidence": self.receipt_evidence.iter().map(ReceiptEvidence::public_record).collect::<Vec<_>>(),
            "hold_criteria": self.hold_criteria.iter().map(HoldCriterion::public_record).collect::<Vec<_>>(),
            "deploy_blockers": self.deploy_blockers.iter().map(DeployBlocker::public_record).collect::<Vec<_>>(),
            "deployment_windows": self.deployment_windows.iter().map(DeploymentWindow::public_record).collect::<Vec<_>>(),
            "rollback_proofs": self.rollback_proofs.iter().map(RollbackProof::public_record).collect::<Vec<_>>(),
            "operator_approvals": self.operator_approvals.iter().map(OperatorApproval::public_record).collect::<Vec<_>>(),
            "verdict": self.verdict.public_record(),
            "state_root": self.state_root_material(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    fn state_root_material(&self) -> String {
        roots_root(
            "deployment-guard-state-material",
            [
                self.config.state_root(),
                roots_root(
                    "binding-roots",
                    self.binding_roots.iter().map(BindingRoot::state_root),
                ),
                roots_root(
                    "receipt-evidence",
                    self.receipt_evidence
                        .iter()
                        .map(ReceiptEvidence::state_root),
                ),
                roots_root(
                    "hold-criteria",
                    self.hold_criteria.iter().map(HoldCriterion::state_root),
                ),
                roots_root(
                    "deploy-blockers",
                    self.deploy_blockers.iter().map(DeployBlocker::state_root),
                ),
                roots_root(
                    "deployment-windows",
                    self.deployment_windows
                        .iter()
                        .map(DeploymentWindow::state_root),
                ),
                roots_root(
                    "rollback-proofs",
                    self.rollback_proofs.iter().map(RollbackProof::state_root),
                ),
                roots_root(
                    "operator-approvals",
                    self.operator_approvals
                        .iter()
                        .map(OperatorApproval::state_root),
                ),
                self.verdict.state_root(),
            ],
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

fn devnet_hold_criteria() -> Vec<HoldCriterion> {
    vec![
        HoldCriterion::new(
            GuardDecision::Hold,
            "cargo check receipt remains deferred and therefore blocks production deployment",
            true,
            true,
            0,
        ),
        HoldCriterion::new(
            GuardDecision::Hold,
            "cargo test receipt remains deferred and therefore blocks production deployment",
            true,
            true,
            1,
        ),
        HoldCriterion::new(
            GuardDecision::Hold,
            "cargo clippy receipt remains deferred and therefore blocks production deployment",
            true,
            true,
            2,
        ),
        HoldCriterion::new(
            GuardDecision::Unhold,
            "rustfmt receipt root is present for the target runtime file",
            true,
            false,
            3,
        ),
        HoldCriterion::new(
            GuardDecision::Unhold,
            "operator dashboard acknowledges fail-closed deployment state",
            true,
            false,
            4,
        ),
    ]
}

fn evaluate_blockers(
    config: &Config,
    binding_roots: &[BindingRoot],
    receipt_evidence: &[ReceiptEvidence],
    hold_criteria: &[HoldCriterion],
) -> Vec<DeployBlocker> {
    let mut blockers = Vec::new();
    let source_set = binding_roots
        .iter()
        .map(|binding| binding.source)
        .collect::<BTreeSet<_>>();
    let binding_by_source = binding_roots
        .iter()
        .map(|binding| (binding.source, binding))
        .collect::<BTreeMap<_, _>>();
    if config.require_compile_runtime_binding_root
        && !source_set.contains(&BindingSourceKind::CompileRuntimeDashboardReleasePolicy)
    {
        blockers.push(DeployBlocker::new(
            BlockerKind::MissingCompileRuntimeBindingRoot,
            "compile/runtime dashboard release-policy binding root is absent",
            true,
            blockers.len() as u64,
        ));
    }
    if config.require_go_no_go_binding_root
        && !source_set.contains(&BindingSourceKind::ReleasePolicyGoNoGo)
    {
        blockers.push(DeployBlocker::new(
            BlockerKind::MissingGoNoGoBindingRoot,
            "release-policy go/no-go binding root is absent",
            true,
            blockers.len() as u64,
        ));
    }
    for binding in binding_roots {
        if binding.age_blocks(config.release_height) > config.max_binding_age_blocks {
            blockers.push(DeployBlocker::new(
                BlockerKind::BindingTooOld,
                "imported go/no-go binding is outside the accepted block-age window",
                true,
                blockers.len() as u64,
            ));
        }
        if !binding.accepted {
            blockers.push(DeployBlocker::new(
                BlockerKind::GoNoGoNotAccepted,
                "imported binding does not carry an accepted go/no-go decision",
                true,
                blockers.len() as u64,
            ));
        }
    }
    if config.require_go_no_go_binding_root {
        if let Some(binding) = binding_by_source.get(&BindingSourceKind::ReleasePolicyGoNoGo) {
            if !binding.accepted {
                blockers.push(DeployBlocker::new(
                    BlockerKind::GoNoGoNotAccepted,
                    "release-policy dashboard go/no-go binding is not accepted",
                    true,
                    blockers.len() as u64,
                ));
            }
        }
    }
    for receipt in receipt_evidence {
        match receipt.gate {
            ReceiptGateKind::Rustfmt => {
                if config.require_rustfmt_receipt_root && !receipt.status.allows_deploy() {
                    blockers.push(DeployBlocker::new(
                        BlockerKind::MissingRustfmtReceiptRoot,
                        "rustfmt receipt root is required before production deployment",
                        true,
                        blockers.len() as u64,
                    ));
                }
            }
            ReceiptGateKind::CargoCheck => {
                if config.require_cargo_check_receipt && !receipt.status.allows_deploy() {
                    blockers.push(DeployBlocker::new(
                        BlockerKind::CargoCheckDeferred,
                        "cargo check receipt is intentionally deferred and blocks deployment",
                        true,
                        blockers.len() as u64,
                    ));
                }
            }
            ReceiptGateKind::CargoTest => {
                if config.require_cargo_test_receipt && !receipt.status.allows_deploy() {
                    blockers.push(DeployBlocker::new(
                        BlockerKind::CargoTestDeferred,
                        "cargo test receipt is intentionally deferred and blocks deployment",
                        true,
                        blockers.len() as u64,
                    ));
                }
            }
            ReceiptGateKind::CargoClippy => {
                if config.require_cargo_clippy_receipt && !receipt.status.allows_deploy() {
                    blockers.push(DeployBlocker::new(
                        BlockerKind::CargoClippyDeferred,
                        "cargo clippy receipt is intentionally deferred and blocks deployment",
                        true,
                        blockers.len() as u64,
                    ));
                }
            }
        }
    }
    if config.require_hold_unhold_criteria
        && hold_criteria
            .iter()
            .any(|criterion| criterion.decision.blocks_deploy() && criterion.satisfied)
    {
        blockers.push(DeployBlocker::new(
            BlockerKind::HoldDecisionActive,
            "one or more deployment hold criteria are satisfied",
            true,
            blockers.len() as u64,
        ));
    }
    if config.require_hold_unhold_criteria
        && hold_criteria
            .iter()
            .filter(|criterion| criterion.required_for_unhold)
            .any(|criterion| !criterion.satisfied)
    {
        blockers.push(DeployBlocker::new(
            BlockerKind::UnholdCriteriaIncomplete,
            "at least one required unhold criterion remains unsatisfied",
            true,
            blockers.len() as u64,
        ));
    }
    blockers
}

fn add_quorum_blockers(
    config: &Config,
    operator_approvals: &[OperatorApproval],
    rollback_proofs: &[RollbackProof],
    blockers: &mut Vec<DeployBlocker>,
) {
    let approved = operator_approvals
        .iter()
        .filter(|approval| {
            approval.approved
                && approval.acknowledged_fail_closed
                && approval.acknowledged_blockers
                && !approval.runbook_ack_root.trim().is_empty()
        })
        .count();
    if config.require_operator_dashboard_approval
        && approved < config.min_operator_approvals as usize
    {
        blockers.push(DeployBlocker::new(
            BlockerKind::OperatorApprovalQuorumMissing,
            "operator dashboard approval quorum is below deployment guard minimum",
            true,
            blockers.len() as u64,
        ));
    }
    let runbook_acks = operator_approvals
        .iter()
        .filter(|approval| approval.approved && !approval.runbook_ack_root.trim().is_empty())
        .count();
    if config.require_runbook_acknowledgement && runbook_acks < config.min_runbook_acks as usize {
        blockers.push(DeployBlocker::new(
            BlockerKind::RunbookAcknowledgementMissing,
            "operator runbook acknowledgement quorum is below deployment guard minimum",
            true,
            blockers.len() as u64,
        ));
    }
    let rollback_ready = rollback_proofs
        .iter()
        .filter(|proof| proof.acknowledged && !proof.abort_root.trim().is_empty())
        .count();
    if config.require_rollback_abort_roots && rollback_ready < config.min_rollback_proofs as usize {
        blockers.push(DeployBlocker::new(
            BlockerKind::RollbackAbortRootMissing,
            "rollback or abort proof root quorum is below deployment guard minimum",
            true,
            blockers.len() as u64,
        ));
    }
}

fn add_window_blockers(
    config: &Config,
    deployment_windows: &[DeploymentWindow],
    blockers: &mut Vec<DeployBlocker>,
) {
    if config.require_window_closed_on_blocker
        && deployment_windows
            .iter()
            .any(|window| !window.status.deployable())
    {
        blockers.push(DeployBlocker::new(
            BlockerKind::DeploymentWindowClosed,
            "deployment window is closed because active blockers force fail-closed state",
            true,
            blockers.len() as u64,
        ));
    }
    if config.fail_closed {
        blockers.push(DeployBlocker::new(
            BlockerKind::FailClosedProductionState,
            "production deployment remains fail-closed until every blocker is cleared",
            true,
            blockers.len() as u64,
        ));
    }
}

fn build_verdict(
    config: &Config,
    binding_roots: &[BindingRoot],
    receipt_evidence: &[ReceiptEvidence],
    hold_criteria: &[HoldCriterion],
    deploy_blockers: &[DeployBlocker],
    deployment_windows: &[DeploymentWindow],
    rollback_proofs: &[RollbackProof],
    operator_approvals: &[OperatorApproval],
) -> GuardVerdict {
    let active_blocker_count = deploy_blockers
        .iter()
        .filter(|blocker| blocker.active)
        .count();
    let hold_count = hold_criteria
        .iter()
        .filter(|criterion| criterion.decision.blocks_deploy() && criterion.satisfied)
        .count();
    let unhold_criteria = hold_criteria
        .iter()
        .filter(|criterion| criterion.required_for_unhold)
        .collect::<Vec<_>>();
    let unhold_criteria_satisfied = unhold_criteria
        .iter()
        .filter(|criterion| criterion.satisfied)
        .count();
    let operator_approval_count = operator_approvals
        .iter()
        .filter(|approval| approval.approved)
        .count();
    let runbook_ack_count = operator_approvals
        .iter()
        .filter(|approval| !approval.runbook_ack_root.trim().is_empty())
        .count();
    let rollback_proof_count = rollback_proofs
        .iter()
        .filter(|proof| proof.acknowledged)
        .count();
    let deployment_window_open = deployment_windows
        .iter()
        .any(|window| window.status.deployable());
    let production_deploy_allowed =
        active_blocker_count == 0 && deployment_window_open && !config.fail_closed;
    let deployment_state = if production_deploy_allowed {
        DeploymentState::GuardedReady
    } else {
        DeploymentState::FailClosedHeld
    };
    let binding_root = roots_root(
        "binding-roots",
        binding_roots.iter().map(BindingRoot::state_root),
    );
    let receipt_root = roots_root(
        "receipt-evidence",
        receipt_evidence.iter().map(ReceiptEvidence::state_root),
    );
    let blocker_root = roots_root(
        "deploy-blockers",
        deploy_blockers.iter().map(DeployBlocker::state_root),
    );
    let hold_unhold_root = roots_root(
        "hold-criteria",
        hold_criteria.iter().map(HoldCriterion::state_root),
    );
    let deployment_window_root = roots_root(
        "deployment-windows",
        deployment_windows.iter().map(DeploymentWindow::state_root),
    );
    let rollback_root = roots_root(
        "rollback-proofs",
        rollback_proofs.iter().map(RollbackProof::state_root),
    );
    let operator_approval_root = roots_root(
        "operator-approvals",
        operator_approvals.iter().map(OperatorApproval::state_root),
    );
    let verdict_root = roots_root(
        "deployment-guard-verdict",
        [
            binding_root.clone(),
            receipt_root.clone(),
            blocker_root.clone(),
            hold_unhold_root.clone(),
            deployment_window_root.clone(),
            rollback_root.clone(),
            operator_approval_root.clone(),
            config.state_root(),
        ],
    );
    GuardVerdict {
        deployment_state,
        production_deploy_allowed,
        fail_closed: config.fail_closed,
        active_blocker_count,
        hold_count,
        unhold_criteria_count: unhold_criteria.len(),
        unhold_criteria_satisfied,
        operator_approval_count,
        runbook_ack_count,
        rollback_proof_count,
        binding_root,
        receipt_root,
        blocker_root,
        hold_unhold_root,
        deployment_window_root,
        rollback_root,
        operator_approval_root,
        verdict_root,
    }
}

fn fallback_state() -> State {
    let config = Config::default();
    let binding_roots = Vec::new();
    let receipt_evidence = Vec::new();
    let hold_criteria = vec![HoldCriterion::new(
        GuardDecision::Abort,
        "fallback state is fail-closed because guard construction failed validation",
        true,
        true,
        0,
    )];
    let deploy_blockers = vec![DeployBlocker::new(
        BlockerKind::FailClosedProductionState,
        "fallback deployment guard state denies production deployment",
        true,
        0,
    )];
    let deployment_windows = vec![DeploymentWindow::devnet(&config, true)];
    let rollback_proofs = Vec::new();
    let operator_approvals = Vec::new();
    let verdict = build_verdict(
        &config,
        &binding_roots,
        &receipt_evidence,
        &hold_criteria,
        &deploy_blockers,
        &deployment_windows,
        &rollback_proofs,
        &operator_approvals,
    );
    State {
        config,
        binding_roots,
        receipt_evidence,
        hold_criteria,
        deploy_blockers,
        deployment_windows,
        rollback_proofs,
        operator_approvals,
        verdict,
    }
}

fn stable_id(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-DEPLOYMENT-GUARD-ID",
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
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-DEPLOYMENT-GUARD-SAMPLE-ROOT",
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

fn roots_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let collected = roots.into_iter().collect::<Vec<_>>();
    let leaves = collected.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-DEPLOYMENT-GUARD-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
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
