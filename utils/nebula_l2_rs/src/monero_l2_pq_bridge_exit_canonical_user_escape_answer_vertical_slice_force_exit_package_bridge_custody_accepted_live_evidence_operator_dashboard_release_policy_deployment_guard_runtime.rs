use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageBridgeCustodyAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-bridge-custody-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GUARD_SUITE: &str =
    "monero-l2-pq-bridge-custody-dashboard-release-policy-deployment-guard-v1";
pub const DEFAULT_WAVE: u64 = 84;
pub const DEFAULT_SOURCE_WAVE: u64 = 83;
pub const DEFAULT_DEPLOYMENT_HEIGHT: u64 = 1_445_120;
pub const DEFAULT_RELEASE_HEIGHT: u64 = 2_913_104;
pub const DEFAULT_MIN_SIGNER_COUNT: u64 = 4;
pub const DEFAULT_MIN_SIGNER_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_APPROVAL_COUNT: u64 = 4;
pub const DEFAULT_MIN_APPROVAL_WEIGHT: u64 = 76;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 32;
pub const DEFAULT_MIN_RESERVE_CONFIRMATIONS: u64 = 16;
pub const DEFAULT_MIN_CHALLENGE_CLEARANCE_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_BINDING_AGE_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_DEPLOY_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_ROLLBACK_REHEARSAL_COUNT: u64 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Pending,
    Rejected,
    Blocked,
    Expired,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::Rejected | Self::Blocked | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecision {
    Hold,
    Unhold,
}

impl GuardDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::Unhold => "unhold",
        }
    }

    pub fn allows_deploy(self) -> bool {
        matches!(self, Self::Unhold)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionDeploymentState {
    FailClosedHold,
    EvidenceReady,
    Deployable,
    Deploying,
    RolledBack,
    Aborted,
}

impl ProductionDeploymentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedHold => "fail_closed_hold",
            Self::EvidenceReady => "evidence_ready",
            Self::Deployable => "deployable",
            Self::Deploying => "deploying",
            Self::RolledBack => "rolled_back",
            Self::Aborted => "aborted",
        }
    }

    pub fn production_open(self) -> bool {
        matches!(self, Self::Deployable | Self::Deploying)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentGuardBlockerKind {
    MissingGoNoGoBindingRoot,
    MissingBridgeCustodyBindingRoot,
    SourceBindingStale,
    SourceBindingRejected,
    MissingCustodySignerQuorum,
    InsufficientCustodySignerWeight,
    MissingSignerHandoffEvidence,
    MissingMoneroReleaseObservationRoot,
    InsufficientMoneroConfirmations,
    MissingReserveHandoffRoot,
    InsufficientReserveConfirmations,
    ChallengeWindowOpen,
    ChallengeClearanceRejected,
    DeployWindowClosed,
    RollbackProofMissing,
    RollbackRehearsalInsufficient,
    AbortRootMissing,
    DashboardApprovalMissing,
    DashboardApprovalWeightLow,
    EmergencyHoldActive,
    ProductionStateFailClosed,
    ReleasePolicyRootMismatch,
    CustodyCriteriaMismatch,
    OperatorAcknowledgementMissing,
}

impl DeploymentGuardBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingGoNoGoBindingRoot => "missing_go_no_go_binding_root",
            Self::MissingBridgeCustodyBindingRoot => "missing_bridge_custody_binding_root",
            Self::SourceBindingStale => "source_binding_stale",
            Self::SourceBindingRejected => "source_binding_rejected",
            Self::MissingCustodySignerQuorum => "missing_custody_signer_quorum",
            Self::InsufficientCustodySignerWeight => "insufficient_custody_signer_weight",
            Self::MissingSignerHandoffEvidence => "missing_signer_handoff_evidence",
            Self::MissingMoneroReleaseObservationRoot => "missing_monero_release_observation_root",
            Self::InsufficientMoneroConfirmations => "insufficient_monero_confirmations",
            Self::MissingReserveHandoffRoot => "missing_reserve_handoff_root",
            Self::InsufficientReserveConfirmations => "insufficient_reserve_confirmations",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::ChallengeClearanceRejected => "challenge_clearance_rejected",
            Self::DeployWindowClosed => "deploy_window_closed",
            Self::RollbackProofMissing => "rollback_proof_missing",
            Self::RollbackRehearsalInsufficient => "rollback_rehearsal_insufficient",
            Self::AbortRootMissing => "abort_root_missing",
            Self::DashboardApprovalMissing => "dashboard_approval_missing",
            Self::DashboardApprovalWeightLow => "dashboard_approval_weight_low",
            Self::EmergencyHoldActive => "emergency_hold_active",
            Self::ProductionStateFailClosed => "production_state_fail_closed",
            Self::ReleasePolicyRootMismatch => "release_policy_root_mismatch",
            Self::CustodyCriteriaMismatch => "custody_criteria_mismatch",
            Self::OperatorAcknowledgementMissing => "operator_acknowledgement_missing",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardApprovalRole {
    CustodyLead,
    ReleaseCoordinator,
    IncidentCommander,
    MoneroObserver,
    ReserveOperator,
    DeploymentOperator,
}

impl DashboardApprovalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyLead => "custody_lead",
            Self::ReleaseCoordinator => "release_coordinator",
            Self::IncidentCommander => "incident_commander",
            Self::MoneroObserver => "monero_observer",
            Self::ReserveOperator => "reserve_operator",
            Self::DeploymentOperator => "deployment_operator",
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::CustodyLead,
            Self::ReleaseCoordinator,
            Self::IncidentCommander,
            Self::MoneroObserver,
            Self::ReserveOperator,
            Self::DeploymentOperator,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardCriterionKind {
    CustodyHold,
    CustodyUnhold,
    SignerHandoff,
    MoneroReleaseObservation,
    ReserveHandoff,
    ChallengeClearance,
    DeployWindow,
    RollbackAbort,
    DashboardApproval,
    FailClosedState,
}

impl GuardCriterionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyHold => "custody_hold",
            Self::CustodyUnhold => "custody_unhold",
            Self::SignerHandoff => "signer_handoff",
            Self::MoneroReleaseObservation => "monero_release_observation",
            Self::ReserveHandoff => "reserve_handoff",
            Self::ChallengeClearance => "challenge_clearance",
            Self::DeployWindow => "deploy_window",
            Self::RollbackAbort => "rollback_abort",
            Self::DashboardApproval => "dashboard_approval",
            Self::FailClosedState => "fail_closed_state",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub guard_suite: String,
    pub deployment_guard_id: String,
    pub source_go_no_go_binding_id: String,
    pub source_bridge_custody_binding_id: String,
    pub release_policy_id: String,
    pub bridge_custody_lane_id: String,
    pub wave: u64,
    pub source_wave: u64,
    pub deployment_height: u64,
    pub max_binding_age_blocks: u64,
    pub min_signer_count: u64,
    pub min_signer_weight: u64,
    pub min_dashboard_approval_count: u64,
    pub min_dashboard_approval_weight: u64,
    pub min_monero_confirmations: u64,
    pub min_reserve_confirmations: u64,
    pub min_challenge_clearance_blocks: u64,
    pub min_deploy_window_blocks: u64,
    pub rollback_rehearsal_count: u64,
    pub require_source_binding_roots: bool,
    pub require_signer_handoff: bool,
    pub require_monero_release_observation: bool,
    pub require_reserve_handoff: bool,
    pub require_challenge_clearance: bool,
    pub require_deploy_window: bool,
    pub require_rollback_abort_roots: bool,
    pub require_dashboard_approval_quorum: bool,
    pub require_fail_closed_until_unhold: bool,
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
            deployment_guard_id: guard_id("bridge-custody-release-policy-deployment-guard-devnet"),
            source_go_no_go_binding_id: guard_id("wave-83-release-policy-go-no-go-binding"),
            source_bridge_custody_binding_id: guard_id(
                "wave-83-bridge-custody-release-policy-binding",
            ),
            release_policy_id: guard_id("force-exit-package-bridge-custody-release-policy"),
            bridge_custody_lane_id: "bridge_custody".to_string(),
            wave: DEFAULT_WAVE,
            source_wave: DEFAULT_SOURCE_WAVE,
            deployment_height: DEFAULT_DEPLOYMENT_HEIGHT,
            max_binding_age_blocks: DEFAULT_MAX_BINDING_AGE_BLOCKS,
            min_signer_count: DEFAULT_MIN_SIGNER_COUNT,
            min_signer_weight: DEFAULT_MIN_SIGNER_WEIGHT,
            min_dashboard_approval_count: DEFAULT_MIN_APPROVAL_COUNT,
            min_dashboard_approval_weight: DEFAULT_MIN_APPROVAL_WEIGHT,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_reserve_confirmations: DEFAULT_MIN_RESERVE_CONFIRMATIONS,
            min_challenge_clearance_blocks: DEFAULT_MIN_CHALLENGE_CLEARANCE_BLOCKS,
            min_deploy_window_blocks: DEFAULT_MIN_DEPLOY_WINDOW_BLOCKS,
            rollback_rehearsal_count: DEFAULT_ROLLBACK_REHEARSAL_COUNT,
            require_source_binding_roots: true,
            require_signer_handoff: true,
            require_monero_release_observation: true,
            require_reserve_handoff: true,
            require_challenge_clearance: true,
            require_deploy_window: true,
            require_rollback_abort_roots: true,
            require_dashboard_approval_quorum: true,
            require_fail_closed_until_unhold: true,
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
        ensure_non_empty("deployment_guard_id", &self.deployment_guard_id)?;
        ensure_non_empty(
            "source_go_no_go_binding_id",
            &self.source_go_no_go_binding_id,
        )?;
        ensure_non_empty(
            "source_bridge_custody_binding_id",
            &self.source_bridge_custody_binding_id,
        )?;
        ensure_non_empty("release_policy_id", &self.release_policy_id)?;
        ensure_non_empty("bridge_custody_lane_id", &self.bridge_custody_lane_id)?;
        ensure(
            self.wave > self.source_wave,
            "guard wave must follow source wave",
        )?;
        ensure(
            self.deployment_height > 0,
            "deployment height must be non-zero",
        )?;
        ensure(
            self.max_binding_age_blocks > 0,
            "max binding age must be non-zero",
        )?;
        ensure(self.min_signer_count > 0, "signer count must be non-zero")?;
        ensure(self.min_signer_weight > 0, "signer weight must be non-zero")?;
        ensure(
            self.min_dashboard_approval_count > 0,
            "approval count must be non-zero",
        )?;
        ensure(
            self.min_dashboard_approval_weight > 0,
            "approval weight must be non-zero",
        )?;
        ensure(
            self.min_monero_confirmations > 0,
            "monero confirmation floor must be non-zero",
        )?;
        ensure(
            self.min_reserve_confirmations > 0,
            "reserve confirmation floor must be non-zero",
        )?;
        ensure(
            self.min_challenge_clearance_blocks > 0,
            "challenge clearance window must be non-zero",
        )?;
        ensure(
            self.min_deploy_window_blocks > 0,
            "deploy window must be non-zero",
        )?;
        ensure(
            self.rollback_rehearsal_count > 0,
            "rollback rehearsal count must be non-zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "guard_suite": self.guard_suite,
            "deployment_guard_id": self.deployment_guard_id,
            "source_go_no_go_binding_id": self.source_go_no_go_binding_id,
            "source_bridge_custody_binding_id": self.source_bridge_custody_binding_id,
            "release_policy_id": self.release_policy_id,
            "bridge_custody_lane_id": self.bridge_custody_lane_id,
            "wave": self.wave,
            "source_wave": self.source_wave,
            "deployment_height": self.deployment_height,
            "max_binding_age_blocks": self.max_binding_age_blocks,
            "min_signer_count": self.min_signer_count,
            "min_signer_weight": self.min_signer_weight,
            "min_dashboard_approval_count": self.min_dashboard_approval_count,
            "min_dashboard_approval_weight": self.min_dashboard_approval_weight,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_reserve_confirmations": self.min_reserve_confirmations,
            "min_challenge_clearance_blocks": self.min_challenge_clearance_blocks,
            "min_deploy_window_blocks": self.min_deploy_window_blocks,
            "rollback_rehearsal_count": self.rollback_rehearsal_count,
            "require_source_binding_roots": self.require_source_binding_roots,
            "require_signer_handoff": self.require_signer_handoff,
            "require_monero_release_observation": self.require_monero_release_observation,
            "require_reserve_handoff": self.require_reserve_handoff,
            "require_challenge_clearance": self.require_challenge_clearance,
            "require_deploy_window": self.require_deploy_window,
            "require_rollback_abort_roots": self.require_rollback_abort_roots,
            "require_dashboard_approval_quorum": self.require_dashboard_approval_quorum,
            "require_fail_closed_until_unhold": self.require_fail_closed_until_unhold,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceBindingRoot {
    pub binding_id: String,
    pub binding_kind: String,
    pub observed_height: u64,
    pub operator_dashboard_root: String,
    pub runbook_audit_root: String,
    pub accepted_live_evidence_root: String,
    pub release_policy_root: String,
    pub custody_policy_root: String,
    pub binding_state_root: String,
    pub status: EvidenceStatus,
}

impl SourceBindingRoot {
    pub fn devnet_go_no_go(config: &Config) -> Self {
        Self::devnet(
            config,
            &config.source_go_no_go_binding_id,
            "go_no_go_binding",
            24,
        )
    }

    pub fn devnet_bridge_custody(config: &Config) -> Self {
        Self::devnet(
            config,
            &config.source_bridge_custody_binding_id,
            "bridge_custody_release_policy_binding",
            20,
        )
    }

    pub fn devnet(config: &Config, binding_id: &str, binding_kind: &str, age: u64) -> Self {
        let observed_height = config.deployment_height.saturating_sub(age);
        let operator_dashboard_root =
            binding_component_root(config, binding_id, binding_kind, "operator-dashboard");
        let runbook_audit_root =
            binding_component_root(config, binding_id, binding_kind, "runbook-audit");
        let accepted_live_evidence_root =
            binding_component_root(config, binding_id, binding_kind, "accepted-live-evidence");
        let release_policy_root =
            binding_component_root(config, binding_id, binding_kind, "release-policy");
        let custody_policy_root =
            binding_component_root(config, binding_id, binding_kind, "custody-policy");
        let binding_state_root = merkle_root(
            "DEPLOYMENT-GUARD-SOURCE-BINDING-STATE",
            &[
                json!({"kind": "operator_dashboard", "root": operator_dashboard_root}),
                json!({"kind": "runbook_audit", "root": runbook_audit_root}),
                json!({"kind": "accepted_live_evidence", "root": accepted_live_evidence_root}),
                json!({"kind": "release_policy", "root": release_policy_root}),
                json!({"kind": "custody_policy", "root": custody_policy_root}),
            ],
        );
        Self {
            binding_id: binding_id.to_string(),
            binding_kind: binding_kind.to_string(),
            observed_height,
            operator_dashboard_root,
            runbook_audit_root,
            accepted_live_evidence_root,
            release_policy_root,
            custody_policy_root,
            binding_state_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn stale(&self, config: &Config) -> bool {
        config
            .deployment_height
            .saturating_sub(self.observed_height)
            > config.max_binding_age_blocks
    }

    pub fn complete(&self, config: &Config) -> bool {
        let roots_present = !self.operator_dashboard_root.is_empty()
            && !self.runbook_audit_root.is_empty()
            && !self.accepted_live_evidence_root.is_empty()
            && !self.release_policy_root.is_empty()
            && !self.custody_policy_root.is_empty()
            && !self.binding_state_root.is_empty();
        (!config.require_source_binding_roots || roots_present)
            && self.status.accepted()
            && !self.stale(config)
    }

    pub fn blockers(&self, config: &Config) -> Vec<DeploymentGuardBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_source_binding_roots
            && (self.binding_state_root.is_empty()
                || self.operator_dashboard_root.is_empty()
                || self.runbook_audit_root.is_empty()
                || self.accepted_live_evidence_root.is_empty())
        {
            if self.binding_kind == "go_no_go_binding" {
                blockers.push(DeploymentGuardBlockerKind::MissingGoNoGoBindingRoot);
            } else {
                blockers.push(DeploymentGuardBlockerKind::MissingBridgeCustodyBindingRoot);
            }
        }
        if self.stale(config) {
            blockers.push(DeploymentGuardBlockerKind::SourceBindingStale);
        }
        if !self.status.accepted() {
            blockers.push(DeploymentGuardBlockerKind::SourceBindingRejected);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "binding_kind": self.binding_kind,
            "observed_height": self.observed_height,
            "operator_dashboard_root": self.operator_dashboard_root,
            "runbook_audit_root": self.runbook_audit_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "release_policy_root": self.release_policy_root,
            "custody_policy_root": self.custody_policy_root,
            "binding_state_root": self.binding_state_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-SOURCE-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyCriterion {
    pub criterion_id: String,
    pub kind: GuardCriterionKind,
    pub description: String,
    pub required_root: String,
    pub observed_root: String,
    pub threshold: u64,
    pub observed_value: u64,
    pub decision: GuardDecision,
    pub status: EvidenceStatus,
}

impl CustodyCriterion {
    pub fn hold(config: &Config, label: &str, ordinal: u64) -> Self {
        let criterion_id = evidence_id(config, "custody-hold-criterion", label, ordinal);
        let required_root = criterion_root(config, GuardCriterionKind::CustodyHold, label, ordinal);
        let observed_root = criterion_root(
            config,
            GuardCriterionKind::CustodyHold,
            &format!("{}-observed", label),
            ordinal,
        );
        Self {
            criterion_id,
            kind: GuardCriterionKind::CustodyHold,
            description: format!("hold production custody when {} is unresolved", label),
            required_root,
            observed_root,
            threshold: 1,
            observed_value: 1,
            decision: GuardDecision::Hold,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn unhold(
        config: &Config,
        label: &str,
        ordinal: u64,
        threshold: u64,
        observed: u64,
    ) -> Self {
        let criterion_id = evidence_id(config, "custody-unhold-criterion", label, ordinal);
        let required_root =
            criterion_root(config, GuardCriterionKind::CustodyUnhold, label, ordinal);
        let observed_root = criterion_root(
            config,
            GuardCriterionKind::CustodyUnhold,
            &format!("{}-observed", label),
            ordinal,
        );
        Self {
            criterion_id,
            kind: GuardCriterionKind::CustodyUnhold,
            description: format!("allow unhold only when {} reaches policy floor", label),
            required_root,
            observed_root,
            threshold,
            observed_value: observed,
            decision: GuardDecision::Unhold,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn satisfied(&self) -> bool {
        self.status.accepted()
            && !self.required_root.is_empty()
            && !self.observed_root.is_empty()
            && self.observed_value >= self.threshold
    }

    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "kind": self.kind.as_str(),
            "description": self.description,
            "required_root": self.required_root,
            "observed_root": self.observed_root,
            "threshold": self.threshold,
            "observed_value": self.observed_value,
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-CUSTODY-CRITERION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerHandoffEvidence {
    pub handoff_id: String,
    pub signer_id: String,
    pub signer_weight: u64,
    pub custody_receipt_root: String,
    pub handoff_attestation_root: String,
    pub ml_dsa_signature_root: String,
    pub slh_dsa_signature_root: String,
    pub dashboard_cell_root: String,
    pub status: EvidenceStatus,
}

impl SignerHandoffEvidence {
    pub fn devnet(config: &Config, ordinal: u64, signer_id: &str, signer_weight: u64) -> Self {
        let handoff_id = evidence_id(config, "signer-handoff", signer_id, ordinal);
        let custody_receipt_root =
            signer_component_root(config, signer_id, ordinal, "custody-receipt");
        let handoff_attestation_root =
            signer_component_root(config, signer_id, ordinal, "handoff-attestation");
        let ml_dsa_signature_root = signer_component_root(config, signer_id, ordinal, "ml-dsa-87");
        let slh_dsa_signature_root =
            signer_component_root(config, signer_id, ordinal, "slh-dsa-shake-256f");
        let dashboard_cell_root = dashboard_cell_root(config, "signer_handoff", &handoff_id);
        Self {
            handoff_id,
            signer_id: signer_id.to_string(),
            signer_weight,
            custody_receipt_root,
            handoff_attestation_root,
            ml_dsa_signature_root,
            slh_dsa_signature_root,
            dashboard_cell_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.custody_receipt_root.is_empty()
            && !self.handoff_attestation_root.is_empty()
            && !self.ml_dsa_signature_root.is_empty()
            && !self.slh_dsa_signature_root.is_empty()
            && !self.dashboard_cell_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_id": self.handoff_id,
            "signer_id": self.signer_id,
            "signer_weight": self.signer_weight,
            "custody_receipt_root": self.custody_receipt_root,
            "handoff_attestation_root": self.handoff_attestation_root,
            "ml_dsa_signature_root": self.ml_dsa_signature_root,
            "slh_dsa_signature_root": self.slh_dsa_signature_root,
            "dashboard_cell_root": self.dashboard_cell_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-SIGNER-HANDOFF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroReleaseObservationRoot {
    pub observation_id: String,
    pub release_txid: String,
    pub observed_height: u64,
    pub confirmations: u64,
    pub view_key_scan_root: String,
    pub output_membership_root: String,
    pub amount_commitment_root: String,
    pub destination_binding_root: String,
    pub release_observation_root: String,
    pub status: EvidenceStatus,
}

impl MoneroReleaseObservationRoot {
    pub fn devnet(config: &Config) -> Self {
        let observation_id = evidence_id(config, "monero-release-observation", "primary", 1);
        let release_txid = domain_hash(
            "DEPLOYMENT-GUARD-MONERO-RELEASE-TXID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.deployment_guard_id),
                HashPart::U64(DEFAULT_RELEASE_HEIGHT),
            ],
            32,
        );
        let view_key_scan_root = monero_component_root(config, &release_txid, "view-key-scan");
        let output_membership_root =
            monero_component_root(config, &release_txid, "output-membership");
        let amount_commitment_root =
            monero_component_root(config, &release_txid, "amount-commitment");
        let destination_binding_root =
            monero_component_root(config, &release_txid, "destination-binding");
        let release_observation_root = merkle_root(
            "DEPLOYMENT-GUARD-MONERO-RELEASE-OBSERVATION",
            &[
                json!({"kind": "release_txid", "root": release_txid}),
                json!({"kind": "view_key_scan", "root": view_key_scan_root}),
                json!({"kind": "output_membership", "root": output_membership_root}),
                json!({"kind": "amount_commitment", "root": amount_commitment_root}),
                json!({"kind": "destination_binding", "root": destination_binding_root}),
            ],
        );
        Self {
            observation_id,
            release_txid,
            observed_height: DEFAULT_RELEASE_HEIGHT,
            confirmations: config.min_monero_confirmations,
            view_key_scan_root,
            output_membership_root,
            amount_commitment_root,
            destination_binding_root,
            release_observation_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && self.confirmations >= config.min_monero_confirmations
            && !self.release_txid.is_empty()
            && !self.view_key_scan_root.is_empty()
            && !self.output_membership_root.is_empty()
            && !self.amount_commitment_root.is_empty()
            && !self.destination_binding_root.is_empty()
            && !self.release_observation_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<DeploymentGuardBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_monero_release_observation && self.release_observation_root.is_empty() {
            blockers.push(DeploymentGuardBlockerKind::MissingMoneroReleaseObservationRoot);
        }
        if self.confirmations < config.min_monero_confirmations {
            blockers.push(DeploymentGuardBlockerKind::InsufficientMoneroConfirmations);
        }
        if !self.status.accepted() {
            blockers.push(DeploymentGuardBlockerKind::MissingMoneroReleaseObservationRoot);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "release_txid": self.release_txid,
            "observed_height": self.observed_height,
            "confirmations": self.confirmations,
            "view_key_scan_root": self.view_key_scan_root,
            "output_membership_root": self.output_membership_root,
            "amount_commitment_root": self.amount_commitment_root,
            "destination_binding_root": self.destination_binding_root,
            "release_observation_root": self.release_observation_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-MONERO-RELEASE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveHandoffEvidence {
    pub handoff_id: String,
    pub reserve_operator_id: String,
    pub handoff_height: u64,
    pub confirmations: u64,
    pub reserve_balance_root: String,
    pub custody_delta_root: String,
    pub emergency_recovery_root: String,
    pub handoff_observation_root: String,
    pub dashboard_cell_root: String,
    pub status: EvidenceStatus,
}

impl ReserveHandoffEvidence {
    pub fn devnet(config: &Config) -> Self {
        let reserve_operator_id = "reserve-operator-devnet-primary";
        let handoff_id = evidence_id(config, "reserve-handoff", reserve_operator_id, 1);
        let reserve_balance_root =
            reserve_component_root(config, reserve_operator_id, "reserve-balance");
        let custody_delta_root =
            reserve_component_root(config, reserve_operator_id, "custody-delta");
        let emergency_recovery_root =
            reserve_component_root(config, reserve_operator_id, "emergency-recovery");
        let handoff_observation_root = merkle_root(
            "DEPLOYMENT-GUARD-RESERVE-HANDOFF",
            &[
                json!({"kind": "reserve_balance", "root": reserve_balance_root}),
                json!({"kind": "custody_delta", "root": custody_delta_root}),
                json!({"kind": "emergency_recovery", "root": emergency_recovery_root}),
                json!({"kind": "operator", "root": reserve_operator_id}),
            ],
        );
        let dashboard_cell_root = dashboard_cell_root(config, "reserve_handoff", &handoff_id);
        Self {
            handoff_id,
            reserve_operator_id: reserve_operator_id.to_string(),
            handoff_height: config.deployment_height.saturating_sub(28),
            confirmations: config.min_reserve_confirmations,
            reserve_balance_root,
            custody_delta_root,
            emergency_recovery_root,
            handoff_observation_root,
            dashboard_cell_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && self.confirmations >= config.min_reserve_confirmations
            && !self.reserve_balance_root.is_empty()
            && !self.custody_delta_root.is_empty()
            && !self.emergency_recovery_root.is_empty()
            && !self.handoff_observation_root.is_empty()
            && !self.dashboard_cell_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<DeploymentGuardBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_reserve_handoff && self.handoff_observation_root.is_empty() {
            blockers.push(DeploymentGuardBlockerKind::MissingReserveHandoffRoot);
        }
        if self.confirmations < config.min_reserve_confirmations {
            blockers.push(DeploymentGuardBlockerKind::InsufficientReserveConfirmations);
        }
        if !self.status.accepted() {
            blockers.push(DeploymentGuardBlockerKind::MissingReserveHandoffRoot);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_id": self.handoff_id,
            "reserve_operator_id": self.reserve_operator_id,
            "handoff_height": self.handoff_height,
            "confirmations": self.confirmations,
            "reserve_balance_root": self.reserve_balance_root,
            "custody_delta_root": self.custody_delta_root,
            "emergency_recovery_root": self.emergency_recovery_root,
            "handoff_observation_root": self.handoff_observation_root,
            "dashboard_cell_root": self.dashboard_cell_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-RESERVE-HANDOFF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeClearance {
    pub clearance_id: String,
    pub challenge_window_root: String,
    pub fraud_proof_queue_root: String,
    pub dispute_ticket_root: String,
    pub clearance_height: u64,
    pub cleared_blocks: u64,
    pub status: EvidenceStatus,
}

impl ChallengeClearance {
    pub fn devnet(config: &Config) -> Self {
        let clearance_id = evidence_id(config, "challenge-clearance", "primary", 1);
        let challenge_window_root = challenge_component_root(config, "challenge-window");
        let fraud_proof_queue_root = challenge_component_root(config, "fraud-proof-queue-empty");
        let dispute_ticket_root = challenge_component_root(config, "operator-dispute-ticket-empty");
        Self {
            clearance_id,
            challenge_window_root,
            fraud_proof_queue_root,
            dispute_ticket_root,
            clearance_height: config
                .deployment_height
                .saturating_sub(config.min_challenge_clearance_blocks),
            cleared_blocks: config.min_challenge_clearance_blocks,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && self.cleared_blocks >= config.min_challenge_clearance_blocks
            && !self.challenge_window_root.is_empty()
            && !self.fraud_proof_queue_root.is_empty()
            && !self.dispute_ticket_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<DeploymentGuardBlockerKind> {
        let mut blockers = Vec::new();
        if self.cleared_blocks < config.min_challenge_clearance_blocks {
            blockers.push(DeploymentGuardBlockerKind::ChallengeWindowOpen);
        }
        if !self.status.accepted() {
            blockers.push(DeploymentGuardBlockerKind::ChallengeClearanceRejected);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "clearance_id": self.clearance_id,
            "challenge_window_root": self.challenge_window_root,
            "fraud_proof_queue_root": self.fraud_proof_queue_root,
            "dispute_ticket_root": self.dispute_ticket_root,
            "clearance_height": self.clearance_height,
            "cleared_blocks": self.cleared_blocks,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "DEPLOYMENT-GUARD-CHALLENGE-CLEARANCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeployWindow {
    pub window_id: String,
    pub earliest_height: u64,
    pub latest_height: u64,
    pub observed_height: u64,
    pub freeze_root: String,
    pub release_manifest_root: String,
    pub deploy_window_root: String,
    pub status: EvidenceStatus,
}

impl DeployWindow {
    pub fn devnet(config: &Config) -> Self {
        let window_id = evidence_id(config, "deploy-window", "primary", 1);
        let earliest_height = config.deployment_height.saturating_sub(4);
        let latest_height = config
            .deployment_height
            .saturating_add(config.min_deploy_window_blocks);
        let freeze_root = deploy_component_root(config, "operator-freeze");
        let release_manifest_root = deploy_component_root(config, "release-manifest");
        let deploy_window_root = merkle_root(
            "DEPLOYMENT-GUARD-DEPLOY-WINDOW",
            &[
                json!({"kind": "window_id", "root": window_id}),
                json!({"kind": "freeze", "root": freeze_root}),
                json!({"kind": "release_manifest", "root": release_manifest_root}),
                json!({"kind": "earliest_height", "root": earliest_height}),
                json!({"kind": "latest_height", "root": latest_height}),
            ],
        );
        Self {
            window_id,
            earliest_height,
            latest_height,
            observed_height: config.deployment_height,
            freeze_root,
            release_manifest_root,
            deploy_window_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn open(&self) -> bool {
        self.status.accepted()
            && self.observed_height >= self.earliest_height
            && self.observed_height <= self.latest_height
            && !self.freeze_root.is_empty()
            && !self.release_manifest_root.is_empty()
            && !self.deploy_window_root.is_empty()
    }

    pub fn blockers(&self) -> Vec<DeploymentGuardBlockerKind> {
        if self.open() {
            Vec::new()
        } else {
            vec![DeploymentGuardBlockerKind::DeployWindowClosed]
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "earliest_height": self.earliest_height,
            "latest_height": self.latest_height,
            "observed_height": self.observed_height,
            "freeze_root": self.freeze_root,
            "release_manifest_root": self.release_manifest_root,
            "deploy_window_root": self.deploy_window_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-DEPLOY-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackAbortProof {
    pub proof_id: String,
    pub rollback_root: String,
    pub abort_root: String,
    pub traffic_cutover_reversal_root: String,
    pub custody_freeze_restore_root: String,
    pub rehearsed_count: u64,
    pub incident_commander_ack_root: String,
    pub status: EvidenceStatus,
}

impl RollbackAbortProof {
    pub fn devnet(config: &Config) -> Self {
        let proof_id = evidence_id(config, "rollback-abort-proof", "primary", 1);
        let rollback_root = rollback_component_root(config, "rollback");
        let abort_root = rollback_component_root(config, "abort");
        let traffic_cutover_reversal_root =
            rollback_component_root(config, "traffic-cutover-reversal");
        let custody_freeze_restore_root = rollback_component_root(config, "custody-freeze-restore");
        let incident_commander_ack_root = rollback_component_root(config, "incident-commander-ack");
        Self {
            proof_id,
            rollback_root,
            abort_root,
            traffic_cutover_reversal_root,
            custody_freeze_restore_root,
            rehearsed_count: config.rollback_rehearsal_count,
            incident_commander_ack_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && self.rehearsed_count >= config.rollback_rehearsal_count
            && !self.rollback_root.is_empty()
            && !self.abort_root.is_empty()
            && !self.traffic_cutover_reversal_root.is_empty()
            && !self.custody_freeze_restore_root.is_empty()
            && !self.incident_commander_ack_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<DeploymentGuardBlockerKind> {
        let mut blockers = Vec::new();
        if self.rollback_root.is_empty() {
            blockers.push(DeploymentGuardBlockerKind::RollbackProofMissing);
        }
        if self.abort_root.is_empty() {
            blockers.push(DeploymentGuardBlockerKind::AbortRootMissing);
        }
        if self.rehearsed_count < config.rollback_rehearsal_count {
            blockers.push(DeploymentGuardBlockerKind::RollbackRehearsalInsufficient);
        }
        if !self.status.accepted() {
            blockers.push(DeploymentGuardBlockerKind::RollbackProofMissing);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "rollback_root": self.rollback_root,
            "abort_root": self.abort_root,
            "traffic_cutover_reversal_root": self.traffic_cutover_reversal_root,
            "custody_freeze_restore_root": self.custody_freeze_restore_root,
            "rehearsed_count": self.rehearsed_count,
            "incident_commander_ack_root": self.incident_commander_ack_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-ROLLBACK-ABORT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorDashboardApproval {
    pub approval_id: String,
    pub operator_id: String,
    pub role: DashboardApprovalRole,
    pub approval_weight: u64,
    pub approval_root: String,
    pub release_policy_root: String,
    pub deployment_guard_root: String,
    pub status: EvidenceStatus,
}

impl OperatorDashboardApproval {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        role: DashboardApprovalRole,
        approval_weight: u64,
    ) -> Self {
        let operator_id = format!("{}-operator-devnet-{}", role.as_str(), ordinal);
        let approval_id = evidence_id(config, "dashboard-approval", &operator_id, ordinal);
        let approval_root = approval_component_root(config, &operator_id, role, "approval");
        let release_policy_root =
            approval_component_root(config, &operator_id, role, "release-policy");
        let deployment_guard_root =
            approval_component_root(config, &operator_id, role, "deployment-guard");
        Self {
            approval_id,
            operator_id,
            role,
            approval_weight,
            approval_root,
            release_policy_root,
            deployment_guard_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.approval_root.is_empty()
            && !self.release_policy_root.is_empty()
            && !self.deployment_guard_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "approval_weight": self.approval_weight,
            "approval_root": self.approval_root,
            "release_policy_root": self.release_policy_root,
            "deployment_guard_root": self.deployment_guard_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-DASHBOARD-APPROVAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentBlocker {
    pub blocker_id: String,
    pub kind: DeploymentGuardBlockerKind,
    pub source_root: String,
    pub severity: u64,
    pub message: String,
}

impl DeploymentBlocker {
    pub fn new(config: &Config, kind: DeploymentGuardBlockerKind, source_root: String) -> Self {
        let blocker_id = domain_hash(
            "DEPLOYMENT-GUARD-BLOCKER-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.deployment_guard_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&source_root),
            ],
            16,
        );
        let severity = match kind {
            DeploymentGuardBlockerKind::EmergencyHoldActive
            | DeploymentGuardBlockerKind::ProductionStateFailClosed
            | DeploymentGuardBlockerKind::ReleasePolicyRootMismatch
            | DeploymentGuardBlockerKind::CustodyCriteriaMismatch => 100,
            DeploymentGuardBlockerKind::MissingCustodySignerQuorum
            | DeploymentGuardBlockerKind::InsufficientCustodySignerWeight
            | DeploymentGuardBlockerKind::MissingSignerHandoffEvidence => 90,
            DeploymentGuardBlockerKind::RollbackProofMissing
            | DeploymentGuardBlockerKind::AbortRootMissing
            | DeploymentGuardBlockerKind::ChallengeWindowOpen => 80,
            _ => 70,
        };
        Self {
            blocker_id,
            kind,
            source_root,
            severity,
            message: format!("deployment guard blocks production for {}", kind.as_str()),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "source_root": self.source_root,
            "severity": self.severity,
            "message": self.message,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentGuardDecision {
    pub decision_id: String,
    pub decision: GuardDecision,
    pub production_state: ProductionDeploymentState,
    pub hold_reason_root: String,
    pub unhold_evidence_root: String,
    pub blocker_root: String,
    pub fail_closed: bool,
}

impl DeploymentGuardDecision {
    pub fn from_state(config: &Config, state: &State, blockers: &[DeploymentBlocker]) -> Self {
        let blocker_root = merkle_root(
            "DEPLOYMENT-GUARD-BLOCKER-ROOT",
            &blockers
                .iter()
                .map(DeploymentBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let unhold_evidence_root = merkle_root(
            "DEPLOYMENT-GUARD-UNHOLD-EVIDENCE",
            &[
                state.signer_handoff_root_record(),
                state.monero_release_observation.public_record(),
                state.reserve_handoff.public_record(),
                state.challenge_clearance.public_record(),
                state.deploy_window.public_record(),
                state.rollback_abort_proof.public_record(),
                json!({"dashboard_approval_root": state.dashboard_approval_root()}),
            ],
        );
        let hold_reason_root = merkle_root(
            "DEPLOYMENT-GUARD-HOLD-REASONS",
            &[
                json!({"blocker_root": blocker_root}),
                json!({"custody_hold_root": state.custody_hold_root()}),
                json!({"fail_closed": config.fail_closed}),
            ],
        );
        let decision = if blockers.is_empty() {
            GuardDecision::Unhold
        } else {
            GuardDecision::Hold
        };
        let production_state = if decision.allows_deploy() {
            ProductionDeploymentState::Deployable
        } else {
            ProductionDeploymentState::FailClosedHold
        };
        let decision_id = domain_hash(
            "DEPLOYMENT-GUARD-DECISION-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.deployment_guard_id),
                HashPart::Str(decision.as_str()),
                HashPart::Str(&blocker_root),
            ],
            16,
        );
        Self {
            decision_id,
            decision,
            production_state,
            hold_reason_root,
            unhold_evidence_root,
            blocker_root,
            fail_closed: config.fail_closed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "decision": self.decision.as_str(),
            "production_state": self.production_state.as_str(),
            "hold_reason_root": self.hold_reason_root,
            "unhold_evidence_root": self.unhold_evidence_root,
            "blocker_root": self.blocker_root,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-DECISION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub source_go_no_go_binding: SourceBindingRoot,
    pub source_bridge_custody_binding: SourceBindingRoot,
    pub custody_hold_criteria: Vec<CustodyCriterion>,
    pub custody_unhold_criteria: Vec<CustodyCriterion>,
    pub signer_handoffs: Vec<SignerHandoffEvidence>,
    pub monero_release_observation: MoneroReleaseObservationRoot,
    pub reserve_handoff: ReserveHandoffEvidence,
    pub challenge_clearance: ChallengeClearance,
    pub deploy_window: DeployWindow,
    pub rollback_abort_proof: RollbackAbortProof,
    pub dashboard_approvals: Vec<OperatorDashboardApproval>,
    pub emergency_hold_active: bool,
    pub production_state: ProductionDeploymentState,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self::from_config(config)
    }

    pub fn from_config(config: Config) -> Self {
        let source_go_no_go_binding = SourceBindingRoot::devnet_go_no_go(&config);
        let source_bridge_custody_binding = SourceBindingRoot::devnet_bridge_custody(&config);
        let custody_hold_criteria = vec![
            CustodyCriterion::hold(&config, "missing-signer-handoff", 1),
            CustodyCriterion::hold(&config, "open-challenge-window", 2),
            CustodyCriterion::hold(&config, "rollback-abort-proof-missing", 3),
            CustodyCriterion::hold(&config, "operator-dashboard-approval-missing", 4),
        ];
        let custody_unhold_criteria = vec![
            CustodyCriterion::unhold(
                &config,
                "signer-weight",
                1,
                config.min_signer_weight,
                config.min_signer_weight + 8,
            ),
            CustodyCriterion::unhold(
                &config,
                "monero-confirmations",
                2,
                config.min_monero_confirmations,
                config.min_monero_confirmations,
            ),
            CustodyCriterion::unhold(
                &config,
                "reserve-confirmations",
                3,
                config.min_reserve_confirmations,
                config.min_reserve_confirmations,
            ),
            CustodyCriterion::unhold(
                &config,
                "challenge-clearance-blocks",
                4,
                config.min_challenge_clearance_blocks,
                config.min_challenge_clearance_blocks,
            ),
        ];
        let signer_handoffs = vec![
            SignerHandoffEvidence::devnet(&config, 1, "custody-signer-alpha", 18),
            SignerHandoffEvidence::devnet(&config, 2, "custody-signer-bravo", 17),
            SignerHandoffEvidence::devnet(&config, 3, "custody-signer-charlie", 16),
            SignerHandoffEvidence::devnet(&config, 4, "custody-signer-delta", 16),
            SignerHandoffEvidence::devnet(&config, 5, "custody-signer-echo", 8),
        ];
        let monero_release_observation = MoneroReleaseObservationRoot::devnet(&config);
        let reserve_handoff = ReserveHandoffEvidence::devnet(&config);
        let challenge_clearance = ChallengeClearance::devnet(&config);
        let deploy_window = DeployWindow::devnet(&config);
        let rollback_abort_proof = RollbackAbortProof::devnet(&config);
        let dashboard_approvals = vec![
            OperatorDashboardApproval::devnet(&config, 1, DashboardApprovalRole::CustodyLead, 20),
            OperatorDashboardApproval::devnet(
                &config,
                2,
                DashboardApprovalRole::ReleaseCoordinator,
                20,
            ),
            OperatorDashboardApproval::devnet(
                &config,
                3,
                DashboardApprovalRole::IncidentCommander,
                18,
            ),
            OperatorDashboardApproval::devnet(
                &config,
                4,
                DashboardApprovalRole::MoneroObserver,
                12,
            ),
            OperatorDashboardApproval::devnet(
                &config,
                5,
                DashboardApprovalRole::ReserveOperator,
                10,
            ),
        ];
        Self {
            config,
            source_go_no_go_binding,
            source_bridge_custody_binding,
            custody_hold_criteria,
            custody_unhold_criteria,
            signer_handoffs,
            monero_release_observation,
            reserve_handoff,
            challenge_clearance,
            deploy_window,
            rollback_abort_proof,
            dashboard_approvals,
            emergency_hold_active: false,
            production_state: ProductionDeploymentState::FailClosedHold,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure(
            self.source_go_no_go_binding.complete(&self.config),
            "go-no-go source binding root is not accepted",
        )?;
        ensure(
            self.source_bridge_custody_binding.complete(&self.config),
            "bridge custody source binding root is not accepted",
        )?;
        ensure(
            self.signer_count() >= self.config.min_signer_count,
            "custody signer quorum is below threshold",
        )?;
        ensure(
            self.signer_weight() >= self.config.min_signer_weight,
            "custody signer weight is below threshold",
        )?;
        ensure(
            self.monero_release_observation.accepted(&self.config),
            "monero release observation is not accepted",
        )?;
        ensure(
            self.reserve_handoff.accepted(&self.config),
            "reserve handoff is not accepted",
        )?;
        ensure(
            self.challenge_clearance.accepted(&self.config),
            "challenge clearance is not accepted",
        )?;
        ensure(self.deploy_window.open(), "deploy window is not open")?;
        ensure(
            self.rollback_abort_proof.accepted(&self.config),
            "rollback and abort proof is not accepted",
        )?;
        ensure(
            self.dashboard_approval_count() >= self.config.min_dashboard_approval_count,
            "dashboard approval count is below threshold",
        )?;
        ensure(
            self.dashboard_approval_weight() >= self.config.min_dashboard_approval_weight,
            "dashboard approval weight is below threshold",
        )?;
        ensure(!self.emergency_hold_active, "emergency hold is active")?;
        ensure(
            self.custody_unhold_criteria
                .iter()
                .all(CustodyCriterion::satisfied),
            "custody unhold criteria are not satisfied",
        )?;
        Ok(())
    }

    pub fn signer_count(&self) -> u64 {
        self.signer_handoffs
            .iter()
            .filter(|handoff| handoff.accepted())
            .count() as u64
    }

    pub fn signer_weight(&self) -> u64 {
        self.signer_handoffs
            .iter()
            .filter(|handoff| handoff.accepted())
            .map(|handoff| handoff.signer_weight)
            .sum()
    }

    pub fn dashboard_approval_count(&self) -> u64 {
        self.dashboard_approvals
            .iter()
            .filter(|approval| approval.accepted())
            .count() as u64
    }

    pub fn dashboard_approval_weight(&self) -> u64 {
        self.dashboard_approvals
            .iter()
            .filter(|approval| approval.accepted())
            .map(|approval| approval.approval_weight)
            .sum()
    }

    pub fn signer_handoff_root_record(&self) -> Value {
        json!({
            "signer_handoff_roots": self.signer_handoffs.iter().map(SignerHandoffEvidence::state_root).collect::<Vec<_>>(),
            "accepted_signer_count": self.signer_count(),
            "accepted_signer_weight": self.signer_weight(),
        })
    }

    pub fn signer_handoff_root(&self) -> String {
        merkle_root(
            "DEPLOYMENT-GUARD-SIGNER-HANDOFF-ROOT",
            &self
                .signer_handoffs
                .iter()
                .map(SignerHandoffEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn custody_hold_root(&self) -> String {
        merkle_root(
            "DEPLOYMENT-GUARD-CUSTODY-HOLD-ROOT",
            &self
                .custody_hold_criteria
                .iter()
                .map(CustodyCriterion::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn custody_unhold_root(&self) -> String {
        merkle_root(
            "DEPLOYMENT-GUARD-CUSTODY-UNHOLD-ROOT",
            &self
                .custody_unhold_criteria
                .iter()
                .map(CustodyCriterion::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn dashboard_approval_root(&self) -> String {
        merkle_root(
            "DEPLOYMENT-GUARD-DASHBOARD-APPROVAL-ROOT",
            &self
                .dashboard_approvals
                .iter()
                .map(OperatorDashboardApproval::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn source_binding_root(&self) -> String {
        merkle_root(
            "DEPLOYMENT-GUARD-SOURCE-BINDING-ROOT",
            &[
                self.source_go_no_go_binding.public_record(),
                self.source_bridge_custody_binding.public_record(),
            ],
        )
    }

    pub fn blockers(&self) -> Vec<DeploymentBlocker> {
        let mut kinds = Vec::new();
        kinds.extend(self.source_go_no_go_binding.blockers(&self.config));
        kinds.extend(self.source_bridge_custody_binding.blockers(&self.config));
        if self.signer_count() < self.config.min_signer_count {
            kinds.push(DeploymentGuardBlockerKind::MissingCustodySignerQuorum);
        }
        if self.signer_weight() < self.config.min_signer_weight {
            kinds.push(DeploymentGuardBlockerKind::InsufficientCustodySignerWeight);
        }
        if self.config.require_signer_handoff
            && self
                .signer_handoffs
                .iter()
                .any(|handoff| !handoff.accepted())
        {
            kinds.push(DeploymentGuardBlockerKind::MissingSignerHandoffEvidence);
        }
        kinds.extend(self.monero_release_observation.blockers(&self.config));
        kinds.extend(self.reserve_handoff.blockers(&self.config));
        kinds.extend(self.challenge_clearance.blockers(&self.config));
        kinds.extend(self.deploy_window.blockers());
        kinds.extend(self.rollback_abort_proof.blockers(&self.config));
        if self.dashboard_approval_count() < self.config.min_dashboard_approval_count {
            kinds.push(DeploymentGuardBlockerKind::DashboardApprovalMissing);
        }
        if self.dashboard_approval_weight() < self.config.min_dashboard_approval_weight {
            kinds.push(DeploymentGuardBlockerKind::DashboardApprovalWeightLow);
        }
        if self.emergency_hold_active {
            kinds.push(DeploymentGuardBlockerKind::EmergencyHoldActive);
        }
        if self.config.require_fail_closed_until_unhold && self.production_state.production_open() {
            kinds.push(DeploymentGuardBlockerKind::ProductionStateFailClosed);
        }
        if self
            .custody_unhold_criteria
            .iter()
            .any(|criterion| !criterion.satisfied())
        {
            kinds.push(DeploymentGuardBlockerKind::CustodyCriteriaMismatch);
        }
        self.unique_blockers(kinds)
    }

    fn unique_blockers(&self, kinds: Vec<DeploymentGuardBlockerKind>) -> Vec<DeploymentBlocker> {
        let mut seen = BTreeSet::new();
        let source_root = self.guard_evidence_root();
        kinds
            .into_iter()
            .filter(|kind| seen.insert(*kind))
            .map(|kind| DeploymentBlocker::new(&self.config, kind, source_root.clone()))
            .collect()
    }

    pub fn decision(&self) -> DeploymentGuardDecision {
        let blockers = self.blockers();
        DeploymentGuardDecision::from_state(&self.config, self, &blockers)
    }

    pub fn guard_evidence_root(&self) -> String {
        merkle_root(
            "DEPLOYMENT-GUARD-EVIDENCE-ROOT",
            &[
                json!({"config_root": self.config.state_root()}),
                json!({"source_binding_root": self.source_binding_root()}),
                json!({"custody_hold_root": self.custody_hold_root()}),
                json!({"custody_unhold_root": self.custody_unhold_root()}),
                json!({"signer_handoff_root": self.signer_handoff_root()}),
                json!({"monero_release_observation_root": self.monero_release_observation.state_root()}),
                json!({"reserve_handoff_root": self.reserve_handoff.state_root()}),
                json!({"challenge_clearance_root": self.challenge_clearance.state_root()}),
                json!({"deploy_window_root": self.deploy_window.state_root()}),
                json!({"rollback_abort_root": self.rollback_abort_proof.state_root()}),
                json!({"dashboard_approval_root": self.dashboard_approval_root()}),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let blockers = self.blockers();
        let decision = DeploymentGuardDecision::from_state(&self.config, self, &blockers);
        json!({
            "config": self.config.public_record(),
            "source_go_no_go_binding": self.source_go_no_go_binding.public_record(),
            "source_bridge_custody_binding": self.source_bridge_custody_binding.public_record(),
            "custody_hold_criteria": self.custody_hold_criteria.iter().map(CustodyCriterion::public_record).collect::<Vec<_>>(),
            "custody_unhold_criteria": self.custody_unhold_criteria.iter().map(CustodyCriterion::public_record).collect::<Vec<_>>(),
            "signer_handoffs": self.signer_handoffs.iter().map(SignerHandoffEvidence::public_record).collect::<Vec<_>>(),
            "monero_release_observation": self.monero_release_observation.public_record(),
            "reserve_handoff": self.reserve_handoff.public_record(),
            "challenge_clearance": self.challenge_clearance.public_record(),
            "deploy_window": self.deploy_window.public_record(),
            "rollback_abort_proof": self.rollback_abort_proof.public_record(),
            "dashboard_approvals": self.dashboard_approvals.iter().map(OperatorDashboardApproval::public_record).collect::<Vec<_>>(),
            "emergency_hold_active": self.emergency_hold_active,
            "production_state": self.production_state.as_str(),
            "accepted_signer_count": self.signer_count(),
            "accepted_signer_weight": self.signer_weight(),
            "dashboard_approval_count": self.dashboard_approval_count(),
            "dashboard_approval_weight": self.dashboard_approval_weight(),
            "guard_evidence_root": self.guard_evidence_root(),
            "blockers": blockers.iter().map(DeploymentBlocker::public_record).collect::<Vec<_>>(),
            "decision": decision.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("DEPLOYMENT-GUARD-STATE", &self.guard_state_record())
    }

    fn guard_state_record(&self) -> Value {
        json!({
            "config_root": self.config.state_root(),
            "source_binding_root": self.source_binding_root(),
            "custody_hold_root": self.custody_hold_root(),
            "custody_unhold_root": self.custody_unhold_root(),
            "signer_handoff_root": self.signer_handoff_root(),
            "monero_release_observation_root": self.monero_release_observation.state_root(),
            "reserve_handoff_root": self.reserve_handoff.state_root(),
            "challenge_clearance_root": self.challenge_clearance.state_root(),
            "deploy_window_root": self.deploy_window.state_root(),
            "rollback_abort_root": self.rollback_abort_proof.state_root(),
            "dashboard_approval_root": self.dashboard_approval_root(),
            "decision_root": self.decision().state_root(),
        })
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

fn guard_id(label: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-ID",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        16,
    )
}

fn evidence_id(config: &Config, kind: &str, subject: &str, ordinal: u64) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-EVIDENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(kind),
            HashPart::Str(subject),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn binding_component_root(
    config: &Config,
    binding_id: &str,
    binding_kind: &str,
    component: &str,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-BINDING-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(binding_id),
            HashPart::Str(binding_kind),
            HashPart::Str(component),
        ],
        32,
    )
}

fn criterion_root(config: &Config, kind: GuardCriterionKind, label: &str, ordinal: u64) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-CRITERION-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn signer_component_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    component: &str,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-SIGNER-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::Str(component),
        ],
        32,
    )
}

fn monero_component_root(config: &Config, release_txid: &str, component: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-MONERO-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(release_txid),
            HashPart::Str(component),
        ],
        32,
    )
}

fn reserve_component_root(config: &Config, reserve_operator_id: &str, component: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-RESERVE-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(reserve_operator_id),
            HashPart::Str(component),
        ],
        32,
    )
}

fn challenge_component_root(config: &Config, component: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-CHALLENGE-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(component),
            HashPart::U64(config.deployment_height),
        ],
        32,
    )
}

fn deploy_component_root(config: &Config, component: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-DEPLOY-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(component),
            HashPart::U64(config.deployment_height),
        ],
        32,
    )
}

fn rollback_component_root(config: &Config, component: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-ROLLBACK-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(component),
            HashPart::U64(config.rollback_rehearsal_count),
        ],
        32,
    )
}

fn approval_component_root(
    config: &Config,
    operator_id: &str,
    role: DashboardApprovalRole,
    component: &str,
) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-APPROVAL-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(component),
        ],
        32,
    )
}

fn dashboard_cell_root(config: &Config, cell: &str, evidence_id: &str) -> String {
    domain_hash(
        "DEPLOYMENT-GUARD-DASHBOARD-CELL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.deployment_guard_id),
            HashPart::Str(cell),
            HashPart::Str(evidence_id),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
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

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    ensure(!value.is_empty(), &format!("{} must not be empty", field))
}
