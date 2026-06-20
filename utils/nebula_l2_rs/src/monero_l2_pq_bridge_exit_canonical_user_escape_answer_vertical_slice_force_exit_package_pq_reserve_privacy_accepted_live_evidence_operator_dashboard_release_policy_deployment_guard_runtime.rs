use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqReservePrivacyAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-pq-reserve-privacy-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_HEIGHT: u64 = 95_000;
pub const DEFAULT_WAVE_NUMBER: u16 = 84;
pub const DEFAULT_SOURCE_WAVE_NUMBER: u16 = 83;
pub const DEFAULT_KEY_EPOCH: u64 = 83;
pub const DEFAULT_DEPLOY_WINDOW_START: u64 = 95_004;
pub const DEFAULT_DEPLOY_WINDOW_END: u64 = 95_052;
pub const DEFAULT_MAX_EVIDENCE_AGE_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 128;
pub const DEFAULT_MIN_PQ_QUORUM_SIGNERS: u16 = 5;
pub const DEFAULT_MIN_PQ_QUORUM_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_ROTATION_RECEIPTS: u16 = 3;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u16 = 10_500;
pub const DEFAULT_MIN_RESERVE_PROOF_COUNT: u16 = 3;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const DEFAULT_MAX_PRIVACY_BUDGET_BPS: u16 = 2_500;
pub const DEFAULT_MIN_PRIVACY_BOUNDARY_RECEIPTS: u16 = 3;
pub const DEFAULT_MIN_OPERATOR_APPROVALS: u16 = 3;
pub const DEFAULT_MIN_ROLLBACK_ROOTS: u16 = 4;
pub const DEFAULT_PACKAGE_ID: &str = "force-exit-package-pq-reserve-privacy";
pub const DEFAULT_RELEASE_POLICY_ID: &str = "wave-83-pq-reserve-privacy-release-policy-binding";
pub const DEFAULT_GO_NO_GO_ID: &str = "wave-83-pq-reserve-privacy-dashboard-go-no-go";
pub const DEFAULT_DEPLOYMENT_GUARD_ID: &str = "wave-84-pq-reserve-privacy-deployment-guard";
pub const DEFAULT_OPERATOR_DASHBOARD_ID: &str =
    "wave-83-pq-reserve-privacy-release-policy-dashboard";
pub const STATUS_ACCEPTED: &str = "accepted";
pub const STATUS_HELD: &str = "held";
pub const STATUS_BLOCKED: &str = "blocked";
pub const STATUS_REJECTED: &str = "rejected";
pub const STATUS_PENDING: &str = "pending";
pub const DECISION_DEPLOY: &str = "deploy";
pub const DECISION_HOLD: &str = "hold";
pub const DECISION_ABORT: &str = "abort";
pub const DECISION_FAIL_CLOSED: &str = "fail_closed";

const REQUIRED_GUARD_GATES: &[DeploymentGuardGate] = &[
    DeploymentGuardGate::ReleasePolicyBinding,
    DeploymentGuardGate::GoNoGoBinding,
    DeploymentGuardGate::PqQuorum,
    DeploymentGuardGate::PqRotation,
    DeploymentGuardGate::ReserveCoverage,
    DeploymentGuardGate::PrivacyBoundary,
    DeploymentGuardGate::DeployWindow,
    DeploymentGuardGate::RollbackAbort,
    DeploymentGuardGate::OperatorApproval,
    DeploymentGuardGate::ProductionFailClosed,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Held,
    Blocked,
    Rejected,
    Pending,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => STATUS_ACCEPTED,
            Self::Held => STATUS_HELD,
            Self::Blocked => STATUS_BLOCKED,
            Self::Rejected => STATUS_REJECTED,
            Self::Pending => STATUS_PENDING,
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocking(self) -> bool {
        matches!(self, Self::Held | Self::Blocked | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentDecision {
    Deploy,
    Hold,
    Abort,
    FailClosed,
}

impl DeploymentDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deploy => DECISION_DEPLOY,
            Self::Hold => DECISION_HOLD,
            Self::Abort => DECISION_ABORT,
            Self::FailClosed => DECISION_FAIL_CLOSED,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentGuardGate {
    ReleasePolicyBinding,
    GoNoGoBinding,
    PqQuorum,
    PqRotation,
    ReserveCoverage,
    PrivacyBoundary,
    DeployWindow,
    RollbackAbort,
    OperatorApproval,
    ProductionFailClosed,
}

impl DeploymentGuardGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleasePolicyBinding => "release_policy_binding",
            Self::GoNoGoBinding => "go_no_go_binding",
            Self::PqQuorum => "pq_quorum",
            Self::PqRotation => "pq_rotation",
            Self::ReserveCoverage => "reserve_coverage",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::DeployWindow => "deploy_window",
            Self::RollbackAbort => "rollback_abort",
            Self::OperatorApproval => "operator_approval",
            Self::ProductionFailClosed => "production_fail_closed",
        }
    }

    pub fn evidence_label(self) -> &'static str {
        match self {
            Self::ReleasePolicyBinding => "wave_83_release_policy_binding_root",
            Self::GoNoGoBinding => "wave_83_go_no_go_binding_root",
            Self::PqQuorum => "pq_quorum_rotation_weight_receipts",
            Self::PqRotation => "pq_key_epoch_rotation_evidence",
            Self::ReserveCoverage => "reserve_coverage_over_required_liability",
            Self::PrivacyBoundary => "privacy_boundary_non_disclosure_receipts",
            Self::DeployWindow => "release_window_and_change_freeze_receipts",
            Self::RollbackAbort => "rollback_abort_rehearsal_roots",
            Self::OperatorApproval => "operator_dashboard_approvals",
            Self::ProductionFailClosed => "production_state_fail_closed_guard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldReason {
    MissingReleasePolicyRoot,
    MissingGoNoGoRoot,
    GoNoGoNotAccepted,
    PqQuorumShortfall,
    PqRotationShortfall,
    PqSecurityBitsShortfall,
    PqEpochMismatch,
    ReserveCoverageShortfall,
    ReserveProofShortfall,
    PrivacyBoundaryShortfall,
    PrivacySetTooSmall,
    PrivacyBudgetExceeded,
    DeployWindowClosed,
    DeployWindowNotOpen,
    RollbackRootShortfall,
    AbortRootMissing,
    OperatorApprovalShortfall,
    OpenDeployBlocker,
    FailClosedStateMissing,
    ProductionNotFailClosed,
    StaleEvidence,
    RootMismatch,
}

impl HoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingReleasePolicyRoot => "missing_release_policy_root",
            Self::MissingGoNoGoRoot => "missing_go_no_go_root",
            Self::GoNoGoNotAccepted => "go_no_go_not_accepted",
            Self::PqQuorumShortfall => "pq_quorum_shortfall",
            Self::PqRotationShortfall => "pq_rotation_shortfall",
            Self::PqSecurityBitsShortfall => "pq_security_bits_shortfall",
            Self::PqEpochMismatch => "pq_epoch_mismatch",
            Self::ReserveCoverageShortfall => "reserve_coverage_shortfall",
            Self::ReserveProofShortfall => "reserve_proof_shortfall",
            Self::PrivacyBoundaryShortfall => "privacy_boundary_shortfall",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::DeployWindowClosed => "deploy_window_closed",
            Self::DeployWindowNotOpen => "deploy_window_not_open",
            Self::RollbackRootShortfall => "rollback_root_shortfall",
            Self::AbortRootMissing => "abort_root_missing",
            Self::OperatorApprovalShortfall => "operator_approval_shortfall",
            Self::OpenDeployBlocker => "open_deploy_blocker",
            Self::FailClosedStateMissing => "fail_closed_state_missing",
            Self::ProductionNotFailClosed => "production_not_fail_closed",
            Self::StaleEvidence => "stale_evidence",
            Self::RootMismatch => "root_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub deployment_guard_id: String,
    pub release_policy_id: String,
    pub go_no_go_id: String,
    pub operator_dashboard_id: String,
    pub force_exit_package_id: String,
    pub expected_release_policy_root: String,
    pub expected_go_no_go_root: String,
    pub expected_dashboard_root: String,
    pub expected_key_epoch: u64,
    pub deploy_window_start: u64,
    pub deploy_window_end: u64,
    pub max_evidence_age_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_pq_quorum_signers: u16,
    pub min_pq_quorum_weight_bps: u16,
    pub min_rotation_receipts: u16,
    pub min_reserve_coverage_bps: u16,
    pub min_reserve_proof_count: u16,
    pub min_privacy_set_size: u64,
    pub max_privacy_budget_bps: u16,
    pub min_privacy_boundary_receipts: u16,
    pub min_operator_approvals: u16,
    pub min_rollback_roots: u16,
    pub require_fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        let deployment_guard_id = runtime_id(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEFAULT_DEPLOYMENT_GUARD_ID),
                HashPart::U64(u64::from(DEFAULT_WAVE_NUMBER)),
            ],
        );
        let release_policy_id = runtime_id(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-RELEASE-POLICY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEFAULT_RELEASE_POLICY_ID),
                HashPart::U64(u64::from(DEFAULT_SOURCE_WAVE_NUMBER)),
            ],
        );
        let go_no_go_id = runtime_id(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-GO-NO-GO-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEFAULT_GO_NO_GO_ID),
                HashPart::Str(&release_policy_id),
            ],
        );
        let expected_release_policy_root = sample_root("wave-83-release-policy-binding-root");
        let expected_go_no_go_root = runtime_id(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-GO-NO-GO-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&release_policy_id),
                HashPart::Str(&expected_release_policy_root),
                HashPart::Str(DEFAULT_GO_NO_GO_ID),
            ],
        );
        let expected_dashboard_root = runtime_id(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-DASHBOARD-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEFAULT_OPERATOR_DASHBOARD_ID),
                HashPart::Str(&expected_go_no_go_root),
            ],
        );
        Self {
            deployment_guard_id,
            release_policy_id,
            go_no_go_id,
            operator_dashboard_id: DEFAULT_OPERATOR_DASHBOARD_ID.to_string(),
            force_exit_package_id: DEFAULT_PACKAGE_ID.to_string(),
            expected_release_policy_root,
            expected_go_no_go_root,
            expected_dashboard_root,
            expected_key_epoch: DEFAULT_KEY_EPOCH,
            deploy_window_start: DEFAULT_DEPLOY_WINDOW_START,
            deploy_window_end: DEFAULT_DEPLOY_WINDOW_END,
            max_evidence_age_blocks: DEFAULT_MAX_EVIDENCE_AGE_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_pq_quorum_signers: DEFAULT_MIN_PQ_QUORUM_SIGNERS,
            min_pq_quorum_weight_bps: DEFAULT_MIN_PQ_QUORUM_WEIGHT_BPS,
            min_rotation_receipts: DEFAULT_MIN_ROTATION_RECEIPTS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_reserve_proof_count: DEFAULT_MIN_RESERVE_PROOF_COUNT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_privacy_budget_bps: DEFAULT_MAX_PRIVACY_BUDGET_BPS,
            min_privacy_boundary_receipts: DEFAULT_MIN_PRIVACY_BOUNDARY_RECEIPTS,
            min_operator_approvals: DEFAULT_MIN_OPERATOR_APPROVALS,
            min_rollback_roots: DEFAULT_MIN_ROLLBACK_ROOTS,
            require_fail_closed: true,
        }
    }

    pub fn config_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-CONFIG",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deployment_guard_id": self.deployment_guard_id,
            "release_policy_id": self.release_policy_id,
            "go_no_go_id": self.go_no_go_id,
            "operator_dashboard_id": self.operator_dashboard_id,
            "force_exit_package_id": self.force_exit_package_id,
            "expected_release_policy_root": self.expected_release_policy_root,
            "expected_go_no_go_root": self.expected_go_no_go_root,
            "expected_dashboard_root": self.expected_dashboard_root,
            "expected_key_epoch": self.expected_key_epoch,
            "deploy_window_start": self.deploy_window_start,
            "deploy_window_end": self.deploy_window_end,
            "max_evidence_age_blocks": self.max_evidence_age_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_pq_quorum_signers": self.min_pq_quorum_signers,
            "min_pq_quorum_weight_bps": self.min_pq_quorum_weight_bps,
            "min_rotation_receipts": self.min_rotation_receipts,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_reserve_proof_count": self.min_reserve_proof_count,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_privacy_budget_bps": self.max_privacy_budget_bps,
            "min_privacy_boundary_receipts": self.min_privacy_boundary_receipts,
            "min_operator_approvals": self.min_operator_approvals,
            "min_rollback_roots": self.min_rollback_roots,
            "require_fail_closed": self.require_fail_closed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleasePolicyBindingEvidence {
    pub binding_id: String,
    pub release_policy_root: String,
    pub go_no_go_root: String,
    pub dashboard_root: String,
    pub accepted_live_evidence_root: String,
    pub policy_clause_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl ReleasePolicyBindingEvidence {
    pub fn new(
        binding_id: &str,
        release_policy_root: &str,
        go_no_go_root: &str,
        dashboard_root: &str,
        accepted_live_evidence_root: &str,
        policy_clause_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("binding_id", binding_id)?;
        ensure_root("release_policy_root", release_policy_root)?;
        ensure_root("go_no_go_root", go_no_go_root)?;
        ensure_root("dashboard_root", dashboard_root)?;
        ensure_root("accepted_live_evidence_root", accepted_live_evidence_root)?;
        ensure_root("policy_clause_root", policy_clause_root)?;
        Ok(Self {
            binding_id: binding_id.to_string(),
            release_policy_root: release_policy_root.to_string(),
            go_no_go_root: go_no_go_root.to_string(),
            dashboard_root: dashboard_root.to_string(),
            accepted_live_evidence_root: accepted_live_evidence_root.to_string(),
            policy_clause_root: policy_clause_root.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-RELEASE-BINDING",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "release_policy_root": self.release_policy_root,
            "go_no_go_root": self.go_no_go_root,
            "dashboard_root": self.dashboard_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "policy_clause_root": self.policy_clause_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
            "evidence_root": runtime_id("PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-RELEASE-BINDING-ID", &[
                HashPart::Str(&self.binding_id),
                HashPart::Str(&self.release_policy_root),
                HashPart::Str(&self.go_no_go_root),
                HashPart::U64(self.observed_at_height),
            ]),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqQuorumEvidence {
    pub quorum_id: String,
    pub key_epoch: u64,
    pub security_bits: u16,
    pub signer_ids: Vec<String>,
    pub signer_weight_bps: u16,
    pub quorum_transcript_root: String,
    pub rotation_receipt_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl PqQuorumEvidence {
    pub fn new(
        quorum_id: &str,
        key_epoch: u64,
        security_bits: u16,
        signer_ids: Vec<String>,
        signer_weight_bps: u16,
        quorum_transcript_root: &str,
        rotation_receipt_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("quorum_id", quorum_id)?;
        ensure_unique_non_empty("signer_ids", &signer_ids)?;
        ensure_bps_ceiling(signer_weight_bps, "signer_weight_bps")?;
        ensure_root("quorum_transcript_root", quorum_transcript_root)?;
        ensure_root("rotation_receipt_root", rotation_receipt_root)?;
        Ok(Self {
            quorum_id: quorum_id.to_string(),
            key_epoch,
            security_bits,
            signer_ids: sorted_unique(signer_ids),
            signer_weight_bps,
            quorum_transcript_root: quorum_transcript_root.to_string(),
            rotation_receipt_root: rotation_receipt_root.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn signer_count(&self) -> u16 {
        bounded_u16(self.signer_ids.len())
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-PQ-QUORUM",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "key_epoch": self.key_epoch,
            "security_bits": self.security_bits,
            "signer_ids": self.signer_ids,
            "signer_count": self.signer_count(),
            "signer_weight_bps": self.signer_weight_bps,
            "quorum_transcript_root": self.quorum_transcript_root,
            "rotation_receipt_root": self.rotation_receipt_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRotationEvidence {
    pub rotation_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub signer_id: String,
    pub old_key_commitment_root: String,
    pub new_key_commitment_root: String,
    pub handoff_transcript_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl PqRotationEvidence {
    pub fn new(
        rotation_id: &str,
        from_epoch: u64,
        to_epoch: u64,
        signer_id: &str,
        old_key_commitment_root: &str,
        new_key_commitment_root: &str,
        handoff_transcript_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("rotation_id", rotation_id)?;
        ensure_non_empty("signer_id", signer_id)?;
        ensure_root("old_key_commitment_root", old_key_commitment_root)?;
        ensure_root("new_key_commitment_root", new_key_commitment_root)?;
        ensure_root("handoff_transcript_root", handoff_transcript_root)?;
        Ok(Self {
            rotation_id: rotation_id.to_string(),
            from_epoch,
            to_epoch,
            signer_id: signer_id.to_string(),
            old_key_commitment_root: old_key_commitment_root.to_string(),
            new_key_commitment_root: new_key_commitment_root.to_string(),
            handoff_transcript_root: handoff_transcript_root.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-PQ-ROTATION",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "from_epoch": self.from_epoch,
            "to_epoch": self.to_epoch,
            "signer_id": self.signer_id,
            "old_key_commitment_root": self.old_key_commitment_root,
            "new_key_commitment_root": self.new_key_commitment_root,
            "handoff_transcript_root": self.handoff_transcript_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveCoverageEvidence {
    pub reserve_id: String,
    pub asset: String,
    pub required_atomic_units: u128,
    pub covered_atomic_units: u128,
    pub custodian_root: String,
    pub liability_root: String,
    pub reserve_proof_root: String,
    pub observer_ids: Vec<String>,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl ReserveCoverageEvidence {
    pub fn new(
        reserve_id: &str,
        asset: &str,
        required_atomic_units: u128,
        covered_atomic_units: u128,
        custodian_root: &str,
        liability_root: &str,
        reserve_proof_root: &str,
        observer_ids: Vec<String>,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("reserve_id", reserve_id)?;
        ensure_non_empty("asset", asset)?;
        ensure_root("custodian_root", custodian_root)?;
        ensure_root("liability_root", liability_root)?;
        ensure_root("reserve_proof_root", reserve_proof_root)?;
        ensure_unique_non_empty("observer_ids", &observer_ids)?;
        Ok(Self {
            reserve_id: reserve_id.to_string(),
            asset: asset.to_string(),
            required_atomic_units,
            covered_atomic_units,
            custodian_root: custodian_root.to_string(),
            liability_root: liability_root.to_string(),
            reserve_proof_root: reserve_proof_root.to_string(),
            observer_ids: sorted_unique(observer_ids),
            observed_at_height,
            status,
        })
    }

    pub fn coverage_bps(&self) -> u16 {
        coverage_bps(self.covered_atomic_units, self.required_atomic_units)
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-RESERVE-COVERAGE",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "asset": self.asset,
            "required_atomic_units": clamped_i128(self.required_atomic_units),
            "covered_atomic_units": clamped_i128(self.covered_atomic_units),
            "coverage_bps": self.coverage_bps(),
            "custodian_root": self.custodian_root,
            "liability_root": self.liability_root,
            "reserve_proof_root": self.reserve_proof_root,
            "observer_ids": self.observer_ids,
            "observer_count": self.observer_ids.len(),
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBoundaryEvidence {
    pub boundary_id: String,
    pub privacy_policy_root: String,
    pub non_linkage_root: String,
    pub disclosure_control_root: String,
    pub redaction_manifest_root: String,
    pub min_set_size: u64,
    pub privacy_budget_bps: u16,
    pub reviewer_ids: Vec<String>,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl PrivacyBoundaryEvidence {
    pub fn new(
        boundary_id: &str,
        privacy_policy_root: &str,
        non_linkage_root: &str,
        disclosure_control_root: &str,
        redaction_manifest_root: &str,
        min_set_size: u64,
        privacy_budget_bps: u16,
        reviewer_ids: Vec<String>,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("boundary_id", boundary_id)?;
        ensure_root("privacy_policy_root", privacy_policy_root)?;
        ensure_root("non_linkage_root", non_linkage_root)?;
        ensure_root("disclosure_control_root", disclosure_control_root)?;
        ensure_root("redaction_manifest_root", redaction_manifest_root)?;
        ensure_bps_ceiling(privacy_budget_bps, "privacy_budget_bps")?;
        ensure_unique_non_empty("reviewer_ids", &reviewer_ids)?;
        Ok(Self {
            boundary_id: boundary_id.to_string(),
            privacy_policy_root: privacy_policy_root.to_string(),
            non_linkage_root: non_linkage_root.to_string(),
            disclosure_control_root: disclosure_control_root.to_string(),
            redaction_manifest_root: redaction_manifest_root.to_string(),
            min_set_size,
            privacy_budget_bps,
            reviewer_ids: sorted_unique(reviewer_ids),
            observed_at_height,
            status,
        })
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-PRIVACY-BOUNDARY",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "boundary_id": self.boundary_id,
            "privacy_policy_root": self.privacy_policy_root,
            "non_linkage_root": self.non_linkage_root,
            "disclosure_control_root": self.disclosure_control_root,
            "redaction_manifest_root": self.redaction_manifest_root,
            "min_set_size": self.min_set_size,
            "privacy_budget_bps": self.privacy_budget_bps,
            "reviewer_ids": self.reviewer_ids,
            "reviewer_count": self.reviewer_ids.len(),
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeployWindowEvidence {
    pub window_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub freeze_lift_root: String,
    pub canary_plan_root: String,
    pub traffic_ramp_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl DeployWindowEvidence {
    pub fn new(
        window_id: &str,
        window_start_height: u64,
        window_end_height: u64,
        freeze_lift_root: &str,
        canary_plan_root: &str,
        traffic_ramp_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("window_id", window_id)?;
        ensure(
            window_start_height <= window_end_height,
            "window_start_height must be <= window_end_height",
        )?;
        ensure_root("freeze_lift_root", freeze_lift_root)?;
        ensure_root("canary_plan_root", canary_plan_root)?;
        ensure_root("traffic_ramp_root", traffic_ramp_root)?;
        Ok(Self {
            window_id: window_id.to_string(),
            window_start_height,
            window_end_height,
            freeze_lift_root: freeze_lift_root.to_string(),
            canary_plan_root: canary_plan_root.to_string(),
            traffic_ramp_root: traffic_ramp_root.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn contains_height(&self, height: u64) -> bool {
        self.window_start_height <= height && height <= self.window_end_height
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-DEPLOY-WINDOW",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "freeze_lift_root": self.freeze_lift_root,
            "canary_plan_root": self.canary_plan_root,
            "traffic_ramp_root": self.traffic_ramp_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackAbortEvidence {
    pub proof_id: String,
    pub rollback_root: String,
    pub abort_root: String,
    pub rehearsal_root: String,
    pub data_restore_root: String,
    pub operator_runbook_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl RollbackAbortEvidence {
    pub fn new(
        proof_id: &str,
        rollback_root: &str,
        abort_root: &str,
        rehearsal_root: &str,
        data_restore_root: &str,
        operator_runbook_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("proof_id", proof_id)?;
        ensure_root("rollback_root", rollback_root)?;
        ensure_root("abort_root", abort_root)?;
        ensure_root("rehearsal_root", rehearsal_root)?;
        ensure_root("data_restore_root", data_restore_root)?;
        ensure_root("operator_runbook_root", operator_runbook_root)?;
        Ok(Self {
            proof_id: proof_id.to_string(),
            rollback_root: rollback_root.to_string(),
            abort_root: abort_root.to_string(),
            rehearsal_root: rehearsal_root.to_string(),
            data_restore_root: data_restore_root.to_string(),
            operator_runbook_root: operator_runbook_root.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-ROLLBACK-ABORT",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "rollback_root": self.rollback_root,
            "abort_root": self.abort_root,
            "rehearsal_root": self.rehearsal_root,
            "data_restore_root": self.data_restore_root,
            "operator_runbook_root": self.operator_runbook_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorApproval {
    pub approval_id: String,
    pub operator_id: String,
    pub role: String,
    pub dashboard_root: String,
    pub guard_root: String,
    pub approved_gate: DeploymentGuardGate,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl OperatorApproval {
    pub fn new(
        approval_id: &str,
        operator_id: &str,
        role: &str,
        dashboard_root: &str,
        guard_root: &str,
        approved_gate: DeploymentGuardGate,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("approval_id", approval_id)?;
        ensure_non_empty("operator_id", operator_id)?;
        ensure_non_empty("role", role)?;
        ensure_root("dashboard_root", dashboard_root)?;
        ensure_root("guard_root", guard_root)?;
        Ok(Self {
            approval_id: approval_id.to_string(),
            operator_id: operator_id.to_string(),
            role: role.to_string(),
            dashboard_root: dashboard_root.to_string(),
            guard_root: guard_root.to_string(),
            approved_gate,
            observed_at_height,
            status,
        })
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-OPERATOR-APPROVAL",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "operator_id": self.operator_id,
            "role": self.role,
            "dashboard_root": self.dashboard_root,
            "guard_root": self.guard_root,
            "approved_gate": self.approved_gate.as_str(),
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionFailClosedState {
    pub state_id: String,
    pub production_mode: String,
    pub deploy_enabled: bool,
    pub force_exit_enabled: bool,
    pub pq_bridge_enabled: bool,
    pub reserve_mint_enabled: bool,
    pub privacy_export_enabled: bool,
    pub circuit_breaker_root: String,
    pub fail_closed_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl ProductionFailClosedState {
    pub fn new(
        state_id: &str,
        production_mode: &str,
        deploy_enabled: bool,
        force_exit_enabled: bool,
        pq_bridge_enabled: bool,
        reserve_mint_enabled: bool,
        privacy_export_enabled: bool,
        circuit_breaker_root: &str,
        fail_closed_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("state_id", state_id)?;
        ensure_non_empty("production_mode", production_mode)?;
        ensure_root("circuit_breaker_root", circuit_breaker_root)?;
        ensure_root("fail_closed_root", fail_closed_root)?;
        Ok(Self {
            state_id: state_id.to_string(),
            production_mode: production_mode.to_string(),
            deploy_enabled,
            force_exit_enabled,
            pq_bridge_enabled,
            reserve_mint_enabled,
            privacy_export_enabled,
            circuit_breaker_root: circuit_breaker_root.to_string(),
            fail_closed_root: fail_closed_root.to_string(),
            observed_at_height,
            status,
        })
    }

    pub fn is_fail_closed(&self) -> bool {
        !self.deploy_enabled
            && !self.force_exit_enabled
            && !self.pq_bridge_enabled
            && !self.reserve_mint_enabled
            && !self.privacy_export_enabled
            && self.status.accepted()
    }

    pub fn evidence_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-FAIL-CLOSED",
            &self.public_record(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_id": self.state_id,
            "production_mode": self.production_mode,
            "deploy_enabled": self.deploy_enabled,
            "force_exit_enabled": self.force_exit_enabled,
            "pq_bridge_enabled": self.pq_bridge_enabled,
            "reserve_mint_enabled": self.reserve_mint_enabled,
            "privacy_export_enabled": self.privacy_export_enabled,
            "circuit_breaker_root": self.circuit_breaker_root,
            "fail_closed_root": self.fail_closed_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
            "is_fail_closed": self.is_fail_closed(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeployBlocker {
    pub blocker_id: String,
    pub gate: DeploymentGuardGate,
    pub reason: HoldReason,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub closed_at_height: Option<u64>,
    pub status: EvidenceStatus,
}

impl DeployBlocker {
    pub fn new(
        blocker_id: &str,
        gate: DeploymentGuardGate,
        reason: HoldReason,
        evidence_root: &str,
        opened_at_height: u64,
        closed_at_height: Option<u64>,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("blocker_id", blocker_id)?;
        ensure_root("evidence_root", evidence_root)?;
        Ok(Self {
            blocker_id: blocker_id.to_string(),
            gate,
            reason,
            evidence_root: evidence_root.to_string(),
            opened_at_height,
            closed_at_height,
            status,
        })
    }

    pub fn open(&self) -> bool {
        self.closed_at_height.is_none() || self.status.blocking()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "gate": self.gate.as_str(),
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "closed_at_height": self.closed_at_height,
            "status": self.status.as_str(),
            "open": self.open(),
        })
    }

    pub fn blocker_root(&self) -> String {
        record_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-BLOCKER",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardDecisionRecord {
    pub decision: DeploymentDecision,
    pub hold_reasons: Vec<HoldReason>,
    pub guard_root: String,
    pub evaluated_at_height: u64,
}

impl GuardDecisionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "hold_reasons": self.hold_reasons.iter().map(|reason| reason.as_str()).collect::<Vec<_>>(),
            "guard_root": self.guard_root,
            "evaluated_at_height": self.evaluated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub release_policy_binding: ReleasePolicyBindingEvidence,
    pub pq_quorum_evidence: Vec<PqQuorumEvidence>,
    pub pq_rotation_evidence: Vec<PqRotationEvidence>,
    pub reserve_coverage_evidence: Vec<ReserveCoverageEvidence>,
    pub privacy_boundary_evidence: Vec<PrivacyBoundaryEvidence>,
    pub deploy_window_evidence: Vec<DeployWindowEvidence>,
    pub rollback_abort_evidence: Vec<RollbackAbortEvidence>,
    pub operator_approvals: Vec<OperatorApproval>,
    pub production_fail_closed_state: Option<ProductionFailClosedState>,
    pub deploy_blockers: Vec<DeployBlocker>,
    pub gate_roots: BTreeMap<String, String>,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        release_policy_binding: ReleasePolicyBindingEvidence,
    ) -> Self {
        Self {
            config,
            height,
            release_policy_binding,
            pq_quorum_evidence: Vec::new(),
            pq_rotation_evidence: Vec::new(),
            reserve_coverage_evidence: Vec::new(),
            privacy_boundary_evidence: Vec::new(),
            deploy_window_evidence: Vec::new(),
            rollback_abort_evidence: Vec::new(),
            operator_approvals: Vec::new(),
            production_fail_closed_state: None,
            deploy_blockers: Vec::new(),
            gate_roots: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let release_policy_binding = ReleasePolicyBindingEvidence::new(
            "wave-83-release-policy-go-no-go-binding",
            &config.expected_release_policy_root,
            &config.expected_go_no_go_root,
            &config.expected_dashboard_root,
            &sample_root("wave-83-accepted-live-evidence-import-root"),
            &sample_root("wave-83-release-policy-clause-root"),
            DEFAULT_HEIGHT.saturating_sub(18),
            EvidenceStatus::Accepted,
        )
        .unwrap_or_else_result();
        let mut state = Self::new(config, DEFAULT_HEIGHT, release_policy_binding);
        state.seed_devnet();
        state.refresh_gate_roots();
        state
    }

    pub fn add_pq_quorum_evidence(&mut self, evidence: PqQuorumEvidence) -> Result<()> {
        ensure_fresh(
            self.height,
            evidence.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.pq_quorum_evidence.push(evidence);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_pq_rotation_evidence(&mut self, evidence: PqRotationEvidence) -> Result<()> {
        ensure_fresh(
            self.height,
            evidence.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.pq_rotation_evidence.push(evidence);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_reserve_coverage_evidence(
        &mut self,
        evidence: ReserveCoverageEvidence,
    ) -> Result<()> {
        ensure_fresh(
            self.height,
            evidence.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.reserve_coverage_evidence.push(evidence);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_privacy_boundary_evidence(
        &mut self,
        evidence: PrivacyBoundaryEvidence,
    ) -> Result<()> {
        ensure_fresh(
            self.height,
            evidence.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.privacy_boundary_evidence.push(evidence);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_deploy_window_evidence(&mut self, evidence: DeployWindowEvidence) -> Result<()> {
        ensure_fresh(
            self.height,
            evidence.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.deploy_window_evidence.push(evidence);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_rollback_abort_evidence(&mut self, evidence: RollbackAbortEvidence) -> Result<()> {
        ensure_fresh(
            self.height,
            evidence.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.rollback_abort_evidence.push(evidence);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_operator_approval(&mut self, approval: OperatorApproval) -> Result<()> {
        ensure_fresh(
            self.height,
            approval.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.operator_approvals.push(approval);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn set_production_fail_closed_state(
        &mut self,
        state: ProductionFailClosedState,
    ) -> Result<()> {
        ensure_fresh(
            self.height,
            state.observed_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.production_fail_closed_state = Some(state);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn add_deploy_blocker(&mut self, blocker: DeployBlocker) -> Result<()> {
        ensure_fresh(
            self.height,
            blocker.opened_at_height,
            self.config.max_evidence_age_blocks,
        )?;
        self.deploy_blockers.push(blocker);
        self.refresh_gate_roots();
        Ok(())
    }

    pub fn release_binding_root(&self) -> String {
        self.release_policy_binding.evidence_root()
    }

    pub fn pq_quorum_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-PQ-QUORUM-ROOT",
            self.pq_quorum_evidence
                .iter()
                .map(PqQuorumEvidence::evidence_root),
        )
    }

    pub fn pq_rotation_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-PQ-ROTATION-ROOT",
            self.pq_rotation_evidence
                .iter()
                .map(PqRotationEvidence::evidence_root),
        )
    }

    pub fn reserve_coverage_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-RESERVE-ROOT",
            self.reserve_coverage_evidence
                .iter()
                .map(ReserveCoverageEvidence::evidence_root),
        )
    }

    pub fn privacy_boundary_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-PRIVACY-ROOT",
            self.privacy_boundary_evidence
                .iter()
                .map(PrivacyBoundaryEvidence::evidence_root),
        )
    }

    pub fn deploy_window_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-WINDOW-ROOT",
            self.deploy_window_evidence
                .iter()
                .map(DeployWindowEvidence::evidence_root),
        )
    }

    pub fn rollback_abort_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-ROLLBACK-ROOT",
            self.rollback_abort_evidence
                .iter()
                .map(RollbackAbortEvidence::evidence_root),
        )
    }

    pub fn operator_approval_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-OPERATOR-ROOT",
            self.operator_approvals
                .iter()
                .map(OperatorApproval::evidence_root),
        )
    }

    pub fn fail_closed_root(&self) -> String {
        match &self.production_fail_closed_state {
            Some(state) => state.evidence_root(),
            None => map_root(
                "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-FAIL-CLOSED-EMPTY",
                Vec::<String>::new(),
            ),
        }
    }

    pub fn deploy_blocker_root(&self) -> String {
        map_root(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-BLOCKER-ROOT",
            self.deploy_blockers.iter().map(DeployBlocker::blocker_root),
        )
    }

    pub fn refresh_gate_roots(&mut self) {
        let mut roots = BTreeMap::new();
        roots.insert(
            DeploymentGuardGate::ReleasePolicyBinding
                .as_str()
                .to_string(),
            self.release_binding_root(),
        );
        roots.insert(
            DeploymentGuardGate::GoNoGoBinding.as_str().to_string(),
            self.release_policy_binding.go_no_go_root.clone(),
        );
        roots.insert(
            DeploymentGuardGate::PqQuorum.as_str().to_string(),
            self.pq_quorum_root(),
        );
        roots.insert(
            DeploymentGuardGate::PqRotation.as_str().to_string(),
            self.pq_rotation_root(),
        );
        roots.insert(
            DeploymentGuardGate::ReserveCoverage.as_str().to_string(),
            self.reserve_coverage_root(),
        );
        roots.insert(
            DeploymentGuardGate::PrivacyBoundary.as_str().to_string(),
            self.privacy_boundary_root(),
        );
        roots.insert(
            DeploymentGuardGate::DeployWindow.as_str().to_string(),
            self.deploy_window_root(),
        );
        roots.insert(
            DeploymentGuardGate::RollbackAbort.as_str().to_string(),
            self.rollback_abort_root(),
        );
        roots.insert(
            DeploymentGuardGate::OperatorApproval.as_str().to_string(),
            self.operator_approval_root(),
        );
        roots.insert(
            DeploymentGuardGate::ProductionFailClosed
                .as_str()
                .to_string(),
            self.fail_closed_root(),
        );
        self.gate_roots = roots;
    }

    pub fn hold_reasons(&self) -> Vec<HoldReason> {
        let mut reasons = Vec::new();
        if !self.release_policy_binding.status.accepted() {
            reasons.push(HoldReason::GoNoGoNotAccepted);
        }
        if self.release_policy_binding.release_policy_root
            != self.config.expected_release_policy_root
        {
            reasons.push(HoldReason::MissingReleasePolicyRoot);
        }
        if self.release_policy_binding.go_no_go_root != self.config.expected_go_no_go_root {
            reasons.push(HoldReason::MissingGoNoGoRoot);
        }
        if self.release_policy_binding.dashboard_root != self.config.expected_dashboard_root {
            reasons.push(HoldReason::RootMismatch);
        }
        if self.accepted_pq_quorum_signer_count() < self.config.min_pq_quorum_signers {
            reasons.push(HoldReason::PqQuorumShortfall);
        }
        if self.accepted_pq_quorum_weight_bps() < self.config.min_pq_quorum_weight_bps {
            reasons.push(HoldReason::PqQuorumShortfall);
        }
        if self.accepted_pq_security_bits() < self.config.min_pq_security_bits {
            reasons.push(HoldReason::PqSecurityBitsShortfall);
        }
        if !self.pq_quorum_evidence.iter().any(|evidence| {
            evidence.status.accepted() && evidence.key_epoch == self.config.expected_key_epoch
        }) {
            reasons.push(HoldReason::PqEpochMismatch);
        }
        if self.accepted_rotation_count() < self.config.min_rotation_receipts {
            reasons.push(HoldReason::PqRotationShortfall);
        }
        if self.accepted_reserve_proof_count() < self.config.min_reserve_proof_count {
            reasons.push(HoldReason::ReserveProofShortfall);
        }
        if self.min_reserve_coverage_bps() < self.config.min_reserve_coverage_bps {
            reasons.push(HoldReason::ReserveCoverageShortfall);
        }
        if self.accepted_privacy_boundary_count() < self.config.min_privacy_boundary_receipts {
            reasons.push(HoldReason::PrivacyBoundaryShortfall);
        }
        if self.min_privacy_set_size() < self.config.min_privacy_set_size {
            reasons.push(HoldReason::PrivacySetTooSmall);
        }
        if self.max_privacy_budget_bps() > self.config.max_privacy_budget_bps {
            reasons.push(HoldReason::PrivacyBudgetExceeded);
        }
        if !self.deploy_window_evidence.iter().any(|window| {
            window.status.accepted() && window.contains_height(self.config.deploy_window_start)
        }) {
            reasons.push(HoldReason::DeployWindowNotOpen);
        }
        if self.height > self.config.deploy_window_end {
            reasons.push(HoldReason::DeployWindowClosed);
        }
        if self.accepted_rollback_root_count() < self.config.min_rollback_roots {
            reasons.push(HoldReason::RollbackRootShortfall);
        }
        if !self
            .rollback_abort_evidence
            .iter()
            .any(|proof| proof.status.accepted())
        {
            reasons.push(HoldReason::AbortRootMissing);
        }
        if self.accepted_operator_approval_count() < self.config.min_operator_approvals {
            reasons.push(HoldReason::OperatorApprovalShortfall);
        }
        if self.deploy_blockers.iter().any(DeployBlocker::open) {
            reasons.push(HoldReason::OpenDeployBlocker);
        }
        match &self.production_fail_closed_state {
            Some(state) if self.config.require_fail_closed && !state.is_fail_closed() => {
                reasons.push(HoldReason::ProductionNotFailClosed);
            }
            None if self.config.require_fail_closed => {
                reasons.push(HoldReason::FailClosedStateMissing);
            }
            _ => {}
        }
        sorted_reasons(reasons)
    }

    pub fn decision(&self) -> GuardDecisionRecord {
        let hold_reasons = self.hold_reasons();
        let decision = if hold_reasons.is_empty() {
            DeploymentDecision::Deploy
        } else if hold_reasons.iter().any(|reason| {
            matches!(
                reason,
                HoldReason::ProductionNotFailClosed
                    | HoldReason::FailClosedStateMissing
                    | HoldReason::OpenDeployBlocker
            )
        }) {
            DeploymentDecision::FailClosed
        } else if hold_reasons.iter().any(|reason| {
            matches!(
                reason,
                HoldReason::PrivacyBudgetExceeded
                    | HoldReason::PrivacySetTooSmall
                    | HoldReason::ReserveCoverageShortfall
                    | HoldReason::PqSecurityBitsShortfall
            )
        }) {
            DeploymentDecision::Abort
        } else {
            DeploymentDecision::Hold
        };
        GuardDecisionRecord {
            decision,
            hold_reasons,
            guard_root: self.guard_evidence_root(),
            evaluated_at_height: self.height,
        }
    }

    pub fn accepted_pq_quorum_signer_count(&self) -> u16 {
        let mut signers = BTreeSet::new();
        for evidence in &self.pq_quorum_evidence {
            if evidence.status.accepted() {
                for signer in &evidence.signer_ids {
                    signers.insert(signer.clone());
                }
            }
        }
        bounded_u16(signers.len())
    }

    pub fn accepted_pq_quorum_weight_bps(&self) -> u16 {
        self.pq_quorum_evidence
            .iter()
            .filter(|evidence| evidence.status.accepted())
            .map(|evidence| evidence.signer_weight_bps)
            .max()
            .unwrap_or_default()
    }

    pub fn accepted_pq_security_bits(&self) -> u16 {
        self.pq_quorum_evidence
            .iter()
            .filter(|evidence| evidence.status.accepted())
            .map(|evidence| evidence.security_bits)
            .max()
            .unwrap_or_default()
    }

    pub fn accepted_rotation_count(&self) -> u16 {
        bounded_u16(
            self.pq_rotation_evidence
                .iter()
                .filter(|evidence| {
                    evidence.status.accepted()
                        && evidence.to_epoch == self.config.expected_key_epoch
                })
                .count(),
        )
    }

    pub fn accepted_reserve_proof_count(&self) -> u16 {
        bounded_u16(
            self.reserve_coverage_evidence
                .iter()
                .filter(|evidence| evidence.status.accepted())
                .count(),
        )
    }

    pub fn min_reserve_coverage_bps(&self) -> u16 {
        self.reserve_coverage_evidence
            .iter()
            .filter(|evidence| evidence.status.accepted())
            .map(ReserveCoverageEvidence::coverage_bps)
            .min()
            .unwrap_or_default()
    }

    pub fn accepted_privacy_boundary_count(&self) -> u16 {
        bounded_u16(
            self.privacy_boundary_evidence
                .iter()
                .filter(|evidence| evidence.status.accepted())
                .count(),
        )
    }

    pub fn min_privacy_set_size(&self) -> u64 {
        self.privacy_boundary_evidence
            .iter()
            .filter(|evidence| evidence.status.accepted())
            .map(|evidence| evidence.min_set_size)
            .min()
            .unwrap_or_default()
    }

    pub fn max_privacy_budget_bps(&self) -> u16 {
        self.privacy_boundary_evidence
            .iter()
            .filter(|evidence| evidence.status.accepted())
            .map(|evidence| evidence.privacy_budget_bps)
            .max()
            .unwrap_or(u16::MAX)
    }

    pub fn accepted_rollback_root_count(&self) -> u16 {
        let mut roots = BTreeSet::new();
        for proof in &self.rollback_abort_evidence {
            if proof.status.accepted() {
                roots.insert(proof.rollback_root.clone());
                roots.insert(proof.abort_root.clone());
                roots.insert(proof.rehearsal_root.clone());
                roots.insert(proof.data_restore_root.clone());
                roots.insert(proof.operator_runbook_root.clone());
            }
        }
        bounded_u16(roots.len())
    }

    pub fn accepted_operator_approval_count(&self) -> u16 {
        let mut operators = BTreeSet::new();
        for approval in &self.operator_approvals {
            if approval.status.accepted()
                && approval.dashboard_root == self.config.expected_dashboard_root
            {
                operators.insert(approval.operator_id.clone());
            }
        }
        bounded_u16(operators.len())
    }

    pub fn guard_evidence_root(&self) -> String {
        let leaves = REQUIRED_GUARD_GATES
            .iter()
            .map(|gate| {
                json!({
                    "gate": gate.as_str(),
                    "label": gate.evidence_label(),
                    "root": self.gate_roots.get(gate.as_str()).cloned().unwrap_or_default(),
                })
            })
            .collect::<Vec<_>>();
        merkle_root("PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-GATE-EVIDENCE", &leaves)
    }

    pub fn public_record(&self) -> Value {
        let decision = self.decision();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "config_root": self.config.config_root(),
            "release_policy_binding": self.release_policy_binding.public_record(),
            "pq_quorum_evidence": self.pq_quorum_evidence.iter().map(PqQuorumEvidence::public_record).collect::<Vec<_>>(),
            "pq_rotation_evidence": self.pq_rotation_evidence.iter().map(PqRotationEvidence::public_record).collect::<Vec<_>>(),
            "reserve_coverage_evidence": self.reserve_coverage_evidence.iter().map(ReserveCoverageEvidence::public_record).collect::<Vec<_>>(),
            "privacy_boundary_evidence": self.privacy_boundary_evidence.iter().map(PrivacyBoundaryEvidence::public_record).collect::<Vec<_>>(),
            "deploy_window_evidence": self.deploy_window_evidence.iter().map(DeployWindowEvidence::public_record).collect::<Vec<_>>(),
            "rollback_abort_evidence": self.rollback_abort_evidence.iter().map(RollbackAbortEvidence::public_record).collect::<Vec<_>>(),
            "operator_approvals": self.operator_approvals.iter().map(OperatorApproval::public_record).collect::<Vec<_>>(),
            "production_fail_closed_state": self.production_fail_closed_state.as_ref().map(ProductionFailClosedState::public_record),
            "deploy_blockers": self.deploy_blockers.iter().map(DeployBlocker::public_record).collect::<Vec<_>>(),
            "gate_roots": self.gate_roots,
            "guard_evidence_root": self.guard_evidence_root(),
            "deploy_blocker_root": self.deploy_blocker_root(),
            "decision": decision.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.deployment_guard_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.config.config_root()),
                HashPart::Str(&self.release_binding_root()),
                HashPart::Str(&self.guard_evidence_root()),
                HashPart::Str(&self.deploy_blocker_root()),
                HashPart::Json(&self.decision().public_record()),
            ],
            32,
        )
    }

    fn seed_devnet(&mut self) {
        let signer_ids = (0..self.config.min_pq_quorum_signers)
            .map(|index| format!("pq-rotation-signer-{index}"))
            .collect::<Vec<_>>();
        if let Ok(evidence) = PqQuorumEvidence::new(
            "wave-84-pq-quorum-main",
            self.config.expected_key_epoch,
            192,
            signer_ids,
            7_200,
            &sample_root("wave-84-pq-quorum-transcript-root"),
            &sample_root("wave-84-pq-rotation-receipt-aggregate-root"),
            self.height.saturating_sub(14),
            EvidenceStatus::Accepted,
        ) {
            let _ = self.add_pq_quorum_evidence(evidence);
        }
        for index in 0..self.config.min_rotation_receipts {
            if let Ok(evidence) = PqRotationEvidence::new(
                &format!("wave-84-pq-rotation-{index}"),
                self.config.expected_key_epoch.saturating_sub(1),
                self.config.expected_key_epoch,
                &format!("pq-rotation-signer-{index}"),
                &sample_root(&format!("old-pq-key-commitment-{index}")),
                &sample_root(&format!("new-pq-key-commitment-{index}")),
                &sample_root(&format!("pq-handoff-transcript-{index}")),
                self.height
                    .saturating_sub(13)
                    .saturating_add(u64::from(index)),
                EvidenceStatus::Accepted,
            ) {
                let _ = self.add_pq_rotation_evidence(evidence);
            }
        }
        for (index, asset) in ["xmr", "reserve-note", "fee-buffer"].iter().enumerate() {
            if let Ok(evidence) = ReserveCoverageEvidence::new(
                &format!("wave-84-reserve-coverage-{asset}"),
                asset,
                1_000_000_000_000 + (index as u128 * 10_000_000),
                1_080_000_000_000 + (index as u128 * 11_000_000),
                &sample_root(&format!("{asset}-custodian-root")),
                &sample_root(&format!("{asset}-liability-root")),
                &sample_root(&format!("{asset}-reserve-proof-root")),
                vec![
                    format!("{asset}-reserve-observer-0"),
                    format!("{asset}-reserve-observer-1"),
                    format!("{asset}-reserve-observer-2"),
                ],
                self.height.saturating_sub(12).saturating_add(index as u64),
                EvidenceStatus::Accepted,
            ) {
                let _ = self.add_reserve_coverage_evidence(evidence);
            }
        }
        for index in 0..self.config.min_privacy_boundary_receipts {
            if let Ok(evidence) = PrivacyBoundaryEvidence::new(
                &format!("wave-84-privacy-boundary-{index}"),
                &sample_root(&format!("privacy-policy-root-{index}")),
                &sample_root(&format!("non-linkage-root-{index}")),
                &sample_root(&format!("disclosure-control-root-{index}")),
                &sample_root(&format!("redaction-manifest-root-{index}")),
                512 + u64::from(index),
                1_700,
                vec![
                    format!("privacy-reviewer-{index}-0"),
                    format!("privacy-reviewer-{index}-1"),
                    format!("privacy-reviewer-{index}-2"),
                ],
                self.height
                    .saturating_sub(11)
                    .saturating_add(u64::from(index)),
                EvidenceStatus::Accepted,
            ) {
                let _ = self.add_privacy_boundary_evidence(evidence);
            }
        }
        if let Ok(window) = DeployWindowEvidence::new(
            "wave-84-deploy-window-primary",
            self.config.deploy_window_start,
            self.config.deploy_window_end,
            &sample_root("wave-84-freeze-lift-root"),
            &sample_root("wave-84-canary-plan-root"),
            &sample_root("wave-84-traffic-ramp-root"),
            self.height.saturating_sub(8),
            EvidenceStatus::Accepted,
        ) {
            let _ = self.add_deploy_window_evidence(window);
        }
        if let Ok(proof) = RollbackAbortEvidence::new(
            "wave-84-rollback-abort-rehearsal",
            &sample_root("wave-84-rollback-root"),
            &sample_root("wave-84-abort-root"),
            &sample_root("wave-84-rehearsal-root"),
            &sample_root("wave-84-data-restore-root"),
            &sample_root("wave-84-operator-runbook-root"),
            self.height.saturating_sub(7),
            EvidenceStatus::Accepted,
        ) {
            let _ = self.add_rollback_abort_evidence(proof);
        }
        let provisional_guard_root = sample_root("wave-84-provisional-guard-root");
        for index in 0..self.config.min_operator_approvals {
            let gate = REQUIRED_GUARD_GATES
                .get(index as usize % REQUIRED_GUARD_GATES.len())
                .copied()
                .unwrap_or(DeploymentGuardGate::OperatorApproval);
            if let Ok(approval) = OperatorApproval::new(
                &format!("wave-84-operator-approval-{index}"),
                &format!("deployment-operator-{index}"),
                "deployment_guard_approver",
                &self.config.expected_dashboard_root,
                &provisional_guard_root,
                gate,
                self.height
                    .saturating_sub(6)
                    .saturating_add(u64::from(index)),
                EvidenceStatus::Accepted,
            ) {
                let _ = self.add_operator_approval(approval);
            }
        }
        if let Ok(state) = ProductionFailClosedState::new(
            "wave-84-production-fail-closed",
            "pre_deploy_guarded",
            false,
            false,
            false,
            false,
            false,
            &sample_root("wave-84-circuit-breaker-root"),
            &sample_root("wave-84-fail-closed-root"),
            self.height.saturating_sub(5),
            EvidenceStatus::Accepted,
        ) {
            let _ = self.set_production_fail_closed_state(state);
        }
        if let Ok(blocker) = DeployBlocker::new(
            "wave-84-prior-dashboard-action-closed",
            DeploymentGuardGate::OperatorApproval,
            HoldReason::OpenDeployBlocker,
            &sample_root("wave-84-closed-dashboard-action-root"),
            self.height.saturating_sub(20),
            Some(self.height.saturating_sub(4)),
            EvidenceStatus::Accepted,
        ) {
            let _ = self.add_deploy_blocker(blocker);
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> serde_json::Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn deployment_guard_decision() -> GuardDecisionRecord {
    devnet().decision()
}

pub fn deployment_guard_hold_reasons() -> Vec<Value> {
    devnet()
        .hold_reasons()
        .iter()
        .map(|reason| json!({ "reason": reason.as_str() }))
        .collect()
}

fn runtime_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn sample_root(label: &str) -> String {
    runtime_id(
        "PQ-RESERVE-PRIVACY-DEPLOYMENT-GUARD-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
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
    let leaves = roots
        .into_iter()
        .map(|root| json!({ "root": root }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn coverage_bps(covered_atomic_units: u128, required_atomic_units: u128) -> u16 {
    if required_atomic_units == 0 {
        return 0;
    }
    let bps = covered_atomic_units.saturating_mul(10_000) / required_atomic_units;
    if bps > u16::MAX as u128 {
        u16::MAX
    } else {
        bps as u16
    }
}

fn clamped_i128(value: u128) -> i128 {
    if value > i128::MAX as u128 {
        i128::MAX
    } else {
        value as i128
    }
}

fn bounded_u16(value: usize) -> u16 {
    if value > u16::MAX as usize {
        u16::MAX
    } else {
        value as u16
    }
}

fn sorted_unique(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sorted_reasons(reasons: Vec<HoldReason>) -> Vec<HoldReason> {
    reasons
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
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

fn ensure_bps_ceiling(value: u16, label: &str) -> Result<()> {
    ensure(value <= 10_000, &format!("{label} must be <= 10000"))
}

fn ensure_unique_non_empty(label: &str, values: &[String]) -> Result<()> {
    ensure(!values.is_empty(), &format!("{label} must not be empty"))?;
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(label, value)?;
        ensure(
            seen.insert(value),
            &format!("{label} contains duplicate value"),
        )?;
    }
    Ok(())
}

fn ensure_fresh(current_height: u64, observed_at_height: u64, max_age: u64) -> Result<()> {
    ensure(
        observed_at_height <= current_height,
        "observed_at_height must be <= current height",
    )?;
    ensure(
        current_height.saturating_sub(observed_at_height) <= max_age,
        "evidence is stale",
    )
}

trait ResultFallback<T> {
    fn unwrap_or_else_result(self) -> T;
}

impl<T> ResultFallback<T> for Result<T>
where
    T: DefaultFallback,
{
    fn unwrap_or_else_result(self) -> T {
        match self {
            Ok(value) => value,
            Err(_) => T::fallback(),
        }
    }
}

trait DefaultFallback {
    fn fallback() -> Self;
}

impl DefaultFallback for ReleasePolicyBindingEvidence {
    fn fallback() -> Self {
        let config = Config::devnet();
        Self {
            binding_id: "fallback-release-policy-binding".to_string(),
            release_policy_root: config.expected_release_policy_root,
            go_no_go_root: config.expected_go_no_go_root,
            dashboard_root: config.expected_dashboard_root,
            accepted_live_evidence_root: sample_root("fallback-accepted-live-evidence"),
            policy_clause_root: sample_root("fallback-policy-clause"),
            observed_at_height: DEFAULT_HEIGHT,
            status: EvidenceStatus::Accepted,
        }
    }
}
