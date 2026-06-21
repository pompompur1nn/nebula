use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqReservePrivacyAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-pq-reserve-privacy-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION;

pub const DEFAULT_HEIGHT: u64 = 95_084;
pub const DEFAULT_WAVE_NUMBER: u16 = 85;
pub const DEFAULT_SOURCE_WAVE_NUMBER: u16 = 84;
pub const DEFAULT_KEY_EPOCH: u64 = 84;
pub const DEFAULT_MAX_EVIDENCE_AGE_BLOCKS: u64 = 128;
pub const DEFAULT_MIN_PQ_ROLLBACK_ROOTS: u16 = 3;
pub const DEFAULT_MIN_RESERVE_ROLLBACK_PROOFS: u16 = 3;
pub const DEFAULT_MIN_PRIVACY_ROLLBACK_MARKERS: u16 = 3;
pub const DEFAULT_MIN_ABORT_COMMANDS: u16 = 3;
pub const DEFAULT_MIN_EXPECTED_RECEIPTS: u16 = 5;
pub const DEFAULT_MIN_OPERATOR_ACKS: u16 = 4;
pub const DEFAULT_MIN_OPERATOR_WEIGHT_BPS: u16 = 7_000;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u16 = 10_500;
pub const DEFAULT_MAX_PRIVACY_BUDGET_BPS: u16 = 2_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const DEFAULT_DRILL_ID: &str = "wave-85-pq-reserve-privacy-rollback-drill";
pub const DEFAULT_DEPLOYMENT_GUARD_ID: &str = "wave-84-pq-reserve-privacy-deployment-guard";
pub const DEFAULT_RELEASE_HOLD_ID: &str = "wave-84-release-policy-hold-unhold-deployment-guard";
pub const DEFAULT_PACKAGE_ID: &str = "force-exit-package-pq-reserve-privacy";
pub const STATUS_ACCEPTED: &str = "accepted";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_HELD: &str = "held";
pub const STATUS_REJECTED: &str = "rejected";
pub const VERDICT_HOLD: &str = "hold";
pub const VERDICT_UNHOLD_READY: &str = "unhold_ready";
pub const VERDICT_FAIL_CLOSED: &str = "fail_closed";
pub const VERDICT_ABORT: &str = "abort";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Pending,
    Held,
    Rejected,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => STATUS_ACCEPTED,
            Self::Pending => STATUS_PENDING,
            Self::Held => STATUS_HELD,
            Self::Rejected => STATUS_REJECTED,
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocking(self) -> bool {
        matches!(self, Self::Held | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillVerdict {
    Hold,
    UnholdReady,
    FailClosed,
    Abort,
}

impl DrillVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hold => VERDICT_HOLD,
            Self::UnholdReady => VERDICT_UNHOLD_READY,
            Self::FailClosed => VERDICT_FAIL_CLOSED,
            Self::Abort => VERDICT_ABORT,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardOutputKind {
    DeploymentGuardRoot,
    ReleaseHoldRoot,
    PqRotationRoot,
    ReserveCoverageRoot,
    PrivacyBoundaryRoot,
    AbortRoot,
    OperatorDashboardRoot,
    FailClosedRoot,
}

impl GuardOutputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentGuardRoot => "deployment_guard_root",
            Self::ReleaseHoldRoot => "release_hold_root",
            Self::PqRotationRoot => "pq_rotation_root",
            Self::ReserveCoverageRoot => "reserve_coverage_root",
            Self::PrivacyBoundaryRoot => "privacy_boundary_root",
            Self::AbortRoot => "abort_root",
            Self::OperatorDashboardRoot => "operator_dashboard_root",
            Self::FailClosedRoot => "fail_closed_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortCriterion {
    PqEpochMismatch,
    PqRollbackRootMissing,
    ReserveCoverageShortfall,
    ReserveProofMissing,
    PrivacyBoundaryMissing,
    PrivacyBudgetExceeded,
    ReceiptMissing,
    OperatorAckMissing,
    ReleaseHoldActive,
    FailClosedNotAsserted,
    GuardRootMismatch,
    StaleEvidence,
    EmergencyAbortCommand,
}

impl AbortCriterion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqEpochMismatch => "pq_epoch_mismatch",
            Self::PqRollbackRootMissing => "pq_rollback_root_missing",
            Self::ReserveCoverageShortfall => "reserve_coverage_shortfall",
            Self::ReserveProofMissing => "reserve_proof_missing",
            Self::PrivacyBoundaryMissing => "privacy_boundary_missing",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::ReceiptMissing => "receipt_missing",
            Self::OperatorAckMissing => "operator_ack_missing",
            Self::ReleaseHoldActive => "release_hold_active",
            Self::FailClosedNotAsserted => "fail_closed_not_asserted",
            Self::GuardRootMismatch => "guard_root_mismatch",
            Self::StaleEvidence => "stale_evidence",
            Self::EmergencyAbortCommand => "emergency_abort_command",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub drill_id: String,
    pub package_id: String,
    pub deployment_guard_id: String,
    pub release_hold_id: String,
    pub wave_number: u16,
    pub source_wave_number: u16,
    pub key_epoch: u64,
    pub max_evidence_age_blocks: u64,
    pub min_pq_rollback_roots: u16,
    pub min_reserve_rollback_proofs: u16,
    pub min_privacy_rollback_markers: u16,
    pub min_abort_commands: u16,
    pub min_expected_receipts: u16,
    pub min_operator_acks: u16,
    pub min_operator_weight_bps: u16,
    pub min_reserve_coverage_bps: u16,
    pub max_privacy_budget_bps: u16,
    pub min_privacy_set_size: u64,
    pub expected_deployment_guard_root: String,
    pub expected_release_hold_root: String,
    pub expected_fail_closed_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            drill_id: DEFAULT_DRILL_ID.to_string(),
            package_id: DEFAULT_PACKAGE_ID.to_string(),
            deployment_guard_id: DEFAULT_DEPLOYMENT_GUARD_ID.to_string(),
            release_hold_id: DEFAULT_RELEASE_HOLD_ID.to_string(),
            wave_number: DEFAULT_WAVE_NUMBER,
            source_wave_number: DEFAULT_SOURCE_WAVE_NUMBER,
            key_epoch: DEFAULT_KEY_EPOCH,
            max_evidence_age_blocks: DEFAULT_MAX_EVIDENCE_AGE_BLOCKS,
            min_pq_rollback_roots: DEFAULT_MIN_PQ_ROLLBACK_ROOTS,
            min_reserve_rollback_proofs: DEFAULT_MIN_RESERVE_ROLLBACK_PROOFS,
            min_privacy_rollback_markers: DEFAULT_MIN_PRIVACY_ROLLBACK_MARKERS,
            min_abort_commands: DEFAULT_MIN_ABORT_COMMANDS,
            min_expected_receipts: DEFAULT_MIN_EXPECTED_RECEIPTS,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            min_operator_weight_bps: DEFAULT_MIN_OPERATOR_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_privacy_budget_bps: DEFAULT_MAX_PRIVACY_BUDGET_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            expected_deployment_guard_root: sample_root("wave-84-deployment-guard-root"),
            expected_release_hold_root: sample_root("wave-84-release-hold-root"),
            expected_fail_closed_root: sample_root("wave-84-fail-closed-root"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "drill_id": self.drill_id,
            "package_id": self.package_id,
            "deployment_guard_id": self.deployment_guard_id,
            "release_hold_id": self.release_hold_id,
            "wave_number": self.wave_number,
            "source_wave_number": self.source_wave_number,
            "key_epoch": self.key_epoch,
            "max_evidence_age_blocks": self.max_evidence_age_blocks,
            "min_pq_rollback_roots": self.min_pq_rollback_roots,
            "min_reserve_rollback_proofs": self.min_reserve_rollback_proofs,
            "min_privacy_rollback_markers": self.min_privacy_rollback_markers,
            "min_abort_commands": self.min_abort_commands,
            "min_expected_receipts": self.min_expected_receipts,
            "min_operator_acks": self.min_operator_acks,
            "min_operator_weight_bps": self.min_operator_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_privacy_budget_bps": self.max_privacy_budget_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "expected_deployment_guard_root": self.expected_deployment_guard_root,
            "expected_release_hold_root": self.expected_release_hold_root,
            "expected_fail_closed_root": self.expected_fail_closed_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardOutput {
    pub output_id: String,
    pub kind: GuardOutputKind,
    pub root: String,
    pub source_wave: u16,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl GuardOutput {
    pub fn new(
        output_id: &str,
        kind: GuardOutputKind,
        root: &str,
        source_wave: u16,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("output_id", output_id)?;
        ensure_root("root", root)?;
        Ok(Self {
            output_id: output_id.to_string(),
            kind,
            root: root.to_string(),
            source_wave,
            observed_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "output_id": self.output_id,
            "kind": self.kind.as_str(),
            "root": self.root,
            "source_wave": self.source_wave,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root("rollback-drill-guard-output", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRollbackRoot {
    pub root_id: String,
    pub key_epoch: u64,
    pub rotation_root_before: String,
    pub rotation_root_after: String,
    pub rollback_root: String,
    pub signer_set_root: String,
    pub quorum_weight_bps: u16,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl PqRollbackRoot {
    pub fn new(
        root_id: &str,
        key_epoch: u64,
        rotation_root_before: &str,
        rotation_root_after: &str,
        signer_set_root: &str,
        quorum_weight_bps: u16,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("root_id", root_id)?;
        ensure_root("rotation_root_before", rotation_root_before)?;
        ensure_root("rotation_root_after", rotation_root_after)?;
        ensure_root("signer_set_root", signer_set_root)?;
        ensure_bps("quorum_weight_bps", quorum_weight_bps)?;
        let rollback_root = runtime_id(
            "rollback-drill-pq-rollback-root",
            &[
                HashPart::Str(root_id),
                HashPart::U64(key_epoch),
                HashPart::Str(rotation_root_before),
                HashPart::Str(rotation_root_after),
                HashPart::Str(signer_set_root),
                HashPart::U64(quorum_weight_bps as u64),
            ],
        );
        Ok(Self {
            root_id: root_id.to_string(),
            key_epoch,
            rotation_root_before: rotation_root_before.to_string(),
            rotation_root_after: rotation_root_after.to_string(),
            rollback_root,
            signer_set_root: signer_set_root.to_string(),
            quorum_weight_bps,
            observed_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "key_epoch": self.key_epoch,
            "rotation_root_before": self.rotation_root_before,
            "rotation_root_after": self.rotation_root_after,
            "rollback_root": self.rollback_root,
            "signer_set_root": self.signer_set_root,
            "quorum_weight_bps": self.quorum_weight_bps,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root("rollback-drill-pq-rollback-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveRollbackProof {
    pub proof_id: String,
    pub reserve_asset: String,
    pub liability_atomic_units: u128,
    pub covered_atomic_units: u128,
    pub coverage_bps: u16,
    pub proof_root: String,
    pub rollback_liquidity_root: String,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl ReserveRollbackProof {
    pub fn new(
        proof_id: &str,
        reserve_asset: &str,
        liability_atomic_units: u128,
        covered_atomic_units: u128,
        proof_root: &str,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("proof_id", proof_id)?;
        ensure_non_empty("reserve_asset", reserve_asset)?;
        ensure_root("proof_root", proof_root)?;
        ensure(
            liability_atomic_units > 0,
            "liability_atomic_units must be positive",
        )?;
        let coverage_bps = coverage_bps(covered_atomic_units, liability_atomic_units);
        let rollback_liquidity_root = runtime_id(
            "rollback-drill-reserve-liquidity-root",
            &[
                HashPart::Str(proof_id),
                HashPart::Str(reserve_asset),
                HashPart::Int(clamped_i128(liability_atomic_units)),
                HashPart::Int(clamped_i128(covered_atomic_units)),
                HashPart::Str(proof_root),
            ],
        );
        Ok(Self {
            proof_id: proof_id.to_string(),
            reserve_asset: reserve_asset.to_string(),
            liability_atomic_units,
            covered_atomic_units,
            coverage_bps,
            proof_root: proof_root.to_string(),
            rollback_liquidity_root,
            observed_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "reserve_asset": self.reserve_asset,
            "liability_atomic_units": self.liability_atomic_units.to_string(),
            "covered_atomic_units": self.covered_atomic_units.to_string(),
            "coverage_bps": self.coverage_bps,
            "proof_root": self.proof_root,
            "rollback_liquidity_root": self.rollback_liquidity_root,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root("rollback-drill-reserve-proof-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBoundaryRollbackMarker {
    pub marker_id: String,
    pub boundary_name: String,
    pub boundary_root: String,
    pub rollback_marker_root: String,
    pub anonymity_set_size: u64,
    pub privacy_budget_bps: u16,
    pub metadata_fields: Vec<String>,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl PrivacyBoundaryRollbackMarker {
    pub fn new(
        marker_id: &str,
        boundary_name: &str,
        boundary_root: &str,
        anonymity_set_size: u64,
        privacy_budget_bps: u16,
        metadata_fields: Vec<String>,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("marker_id", marker_id)?;
        ensure_non_empty("boundary_name", boundary_name)?;
        ensure_root("boundary_root", boundary_root)?;
        ensure_bps("privacy_budget_bps", privacy_budget_bps)?;
        let metadata_fields = sorted_unique(metadata_fields);
        ensure(
            !metadata_fields.is_empty(),
            "metadata_fields must not be empty",
        )?;
        let rollback_marker_root = runtime_id(
            "rollback-drill-privacy-boundary-marker-root",
            &[
                HashPart::Str(marker_id),
                HashPart::Str(boundary_name),
                HashPart::Str(boundary_root),
                HashPart::U64(anonymity_set_size),
                HashPart::U64(privacy_budget_bps as u64),
                HashPart::Json(&json!(metadata_fields)),
            ],
        );
        Ok(Self {
            marker_id: marker_id.to_string(),
            boundary_name: boundary_name.to_string(),
            boundary_root: boundary_root.to_string(),
            rollback_marker_root,
            anonymity_set_size,
            privacy_budget_bps,
            metadata_fields,
            observed_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "marker_id": self.marker_id,
            "boundary_name": self.boundary_name,
            "boundary_root": self.boundary_root,
            "rollback_marker_root": self.rollback_marker_root,
            "anonymity_set_size": self.anonymity_set_size,
            "privacy_budget_bps": self.privacy_budget_bps,
            "metadata_fields": self.metadata_fields,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root(
            "rollback-drill-privacy-marker-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbortCommand {
    pub command_id: String,
    pub criterion: AbortCriterion,
    pub command_root: String,
    pub issuer: String,
    pub armed: bool,
    pub fail_closed_required: bool,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl AbortCommand {
    pub fn new(
        command_id: &str,
        criterion: AbortCriterion,
        issuer: &str,
        armed: bool,
        fail_closed_required: bool,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("command_id", command_id)?;
        ensure_non_empty("issuer", issuer)?;
        let command_root = runtime_id(
            "rollback-drill-abort-command-root",
            &[
                HashPart::Str(command_id),
                HashPart::Str(criterion.as_str()),
                HashPart::Str(issuer),
                HashPart::Str(if armed { "armed" } else { "monitor" }),
                HashPart::Str(if fail_closed_required {
                    "fail_closed_required"
                } else {
                    "fail_closed_optional"
                }),
            ],
        );
        Ok(Self {
            command_id: command_id.to_string(),
            criterion,
            command_root,
            issuer: issuer.to_string(),
            armed,
            fail_closed_required,
            observed_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "command_id": self.command_id,
            "criterion": self.criterion.as_str(),
            "command_root": self.command_root,
            "issuer": self.issuer,
            "armed": self.armed,
            "fail_closed_required": self.fail_closed_required,
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root("rollback-drill-abort-command-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpectedReceipt {
    pub receipt_id: String,
    pub subject: String,
    pub expected_root: String,
    pub received_root: String,
    pub received: bool,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl ExpectedReceipt {
    pub fn new(
        receipt_id: &str,
        subject: &str,
        expected_root: &str,
        received_root: &str,
        received: bool,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("receipt_id", receipt_id)?;
        ensure_non_empty("subject", subject)?;
        ensure_root("expected_root", expected_root)?;
        ensure_root("received_root", received_root)?;
        Ok(Self {
            receipt_id: receipt_id.to_string(),
            subject: subject.to_string(),
            expected_root: expected_root.to_string(),
            received_root: received_root.to_string(),
            received,
            observed_at_height,
            status,
        })
    }

    pub fn matches_expected(&self) -> bool {
        self.received && self.expected_root == self.received_root && self.status.accepted()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject": self.subject,
            "expected_root": self.expected_root,
            "received_root": self.received_root,
            "received": self.received,
            "matches_expected": self.matches_expected(),
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root(
            "rollback-drill-expected-receipt-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub operator_id: String,
    pub role: String,
    pub acknowledgement_root: String,
    pub weight_bps: u16,
    pub accepts_fail_closed_hold: bool,
    pub accepts_unhold_after_drill: bool,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl OperatorAcknowledgement {
    pub fn new(
        operator_id: &str,
        role: &str,
        weight_bps: u16,
        accepts_fail_closed_hold: bool,
        accepts_unhold_after_drill: bool,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("operator_id", operator_id)?;
        ensure_non_empty("role", role)?;
        ensure_bps("weight_bps", weight_bps)?;
        let acknowledgement_root = runtime_id(
            "rollback-drill-operator-acknowledgement-root",
            &[
                HashPart::Str(operator_id),
                HashPart::Str(role),
                HashPart::U64(weight_bps as u64),
                HashPart::Str(if accepts_fail_closed_hold {
                    "accepts_fail_closed_hold"
                } else {
                    "rejects_fail_closed_hold"
                }),
                HashPart::Str(if accepts_unhold_after_drill {
                    "accepts_unhold_after_drill"
                } else {
                    "rejects_unhold_after_drill"
                }),
            ],
        );
        Ok(Self {
            operator_id: operator_id.to_string(),
            role: role.to_string(),
            acknowledgement_root,
            weight_bps,
            accepts_fail_closed_hold,
            accepts_unhold_after_drill,
            observed_at_height,
            status,
        })
    }

    pub fn approving(&self) -> bool {
        self.status.accepted() && self.accepts_fail_closed_hold && self.accepts_unhold_after_drill
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "role": self.role,
            "acknowledgement_root": self.acknowledgement_root,
            "weight_bps": self.weight_bps,
            "accepts_fail_closed_hold": self.accepts_fail_closed_hold,
            "accepts_unhold_after_drill": self.accepts_unhold_after_drill,
            "approving": self.approving(),
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root(
            "rollback-drill-operator-acknowledgement-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldUnholdState {
    pub state_id: String,
    pub release_hold_root: String,
    pub fail_closed_root: String,
    pub hold_asserted: bool,
    pub unhold_requested: bool,
    pub unhold_allowed: bool,
    pub production_writes_disabled: bool,
    pub observed_at_height: u64,
    pub status: EvidenceStatus,
}

impl HoldUnholdState {
    pub fn new(
        state_id: &str,
        release_hold_root: &str,
        fail_closed_root: &str,
        hold_asserted: bool,
        unhold_requested: bool,
        unhold_allowed: bool,
        production_writes_disabled: bool,
        observed_at_height: u64,
        status: EvidenceStatus,
    ) -> Result<Self> {
        ensure_non_empty("state_id", state_id)?;
        ensure_root("release_hold_root", release_hold_root)?;
        ensure_root("fail_closed_root", fail_closed_root)?;
        Ok(Self {
            state_id: state_id.to_string(),
            release_hold_root: release_hold_root.to_string(),
            fail_closed_root: fail_closed_root.to_string(),
            hold_asserted,
            unhold_requested,
            unhold_allowed,
            production_writes_disabled,
            observed_at_height,
            status,
        })
    }

    pub fn fail_closed(&self) -> bool {
        self.status.accepted() && self.hold_asserted && self.production_writes_disabled
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_id": self.state_id,
            "release_hold_root": self.release_hold_root,
            "fail_closed_root": self.fail_closed_root,
            "hold_asserted": self.hold_asserted,
            "unhold_requested": self.unhold_requested,
            "unhold_allowed": self.unhold_allowed,
            "production_writes_disabled": self.production_writes_disabled,
            "fail_closed": self.fail_closed(),
            "observed_at_height": self.observed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn record_root(&self) -> String {
        record_root(
            "rollback-drill-hold-unhold-state-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrillDecision {
    pub verdict: DrillVerdict,
    pub accepted: bool,
    pub fail_closed_release_hold: bool,
    pub unhold_after_drill: bool,
    pub criteria: Vec<AbortCriterion>,
    pub guard_output_root: String,
    pub pq_rollback_root: String,
    pub reserve_rollback_root: String,
    pub privacy_rollback_root: String,
    pub abort_command_root: String,
    pub expected_receipt_root: String,
    pub operator_ack_root: String,
    pub hold_unhold_root: String,
    pub decision_root: String,
}

impl DrillDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "accepted": self.accepted,
            "fail_closed_release_hold": self.fail_closed_release_hold,
            "unhold_after_drill": self.unhold_after_drill,
            "criteria": self.criteria.iter().map(|criterion| criterion.as_str()).collect::<Vec<_>>(),
            "guard_output_root": self.guard_output_root,
            "pq_rollback_root": self.pq_rollback_root,
            "reserve_rollback_root": self.reserve_rollback_root,
            "privacy_rollback_root": self.privacy_rollback_root,
            "abort_command_root": self.abort_command_root,
            "expected_receipt_root": self.expected_receipt_root,
            "operator_ack_root": self.operator_ack_root,
            "hold_unhold_root": self.hold_unhold_root,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub guard_outputs: Vec<GuardOutput>,
    pub pq_rollback_roots: Vec<PqRollbackRoot>,
    pub reserve_rollback_proofs: Vec<ReserveRollbackProof>,
    pub privacy_rollback_markers: Vec<PrivacyBoundaryRollbackMarker>,
    pub abort_commands: Vec<AbortCommand>,
    pub expected_receipts: Vec<ExpectedReceipt>,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub hold_unhold_state: HoldUnholdState,
    pub guard_output_root: String,
    pub pq_rollback_root: String,
    pub reserve_rollback_root: String,
    pub privacy_rollback_root: String,
    pub abort_command_root: String,
    pub expected_receipt_root: String,
    pub operator_ack_root: String,
    pub hold_unhold_root: String,
    pub decision: DrillDecision,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        guard_outputs: Vec<GuardOutput>,
        pq_rollback_roots: Vec<PqRollbackRoot>,
        reserve_rollback_proofs: Vec<ReserveRollbackProof>,
        privacy_rollback_markers: Vec<PrivacyBoundaryRollbackMarker>,
        abort_commands: Vec<AbortCommand>,
        expected_receipts: Vec<ExpectedReceipt>,
        operator_acknowledgements: Vec<OperatorAcknowledgement>,
        hold_unhold_state: HoldUnholdState,
    ) -> Result<Self> {
        let guard_output_root = vec_root(
            "rollback-drill-guard-output-root",
            guard_outputs.iter().map(GuardOutput::record_root),
        );
        let pq_rollback_root = vec_root(
            "rollback-drill-pq-rollback-root",
            pq_rollback_roots.iter().map(PqRollbackRoot::record_root),
        );
        let reserve_rollback_root = vec_root(
            "rollback-drill-reserve-rollback-root",
            reserve_rollback_proofs
                .iter()
                .map(ReserveRollbackProof::record_root),
        );
        let privacy_rollback_root = vec_root(
            "rollback-drill-privacy-rollback-root",
            privacy_rollback_markers
                .iter()
                .map(PrivacyBoundaryRollbackMarker::record_root),
        );
        let abort_command_root = vec_root(
            "rollback-drill-abort-command-root",
            abort_commands.iter().map(AbortCommand::record_root),
        );
        let expected_receipt_root = vec_root(
            "rollback-drill-expected-receipt-root",
            expected_receipts.iter().map(ExpectedReceipt::record_root),
        );
        let operator_ack_root = vec_root(
            "rollback-drill-operator-ack-root",
            operator_acknowledgements
                .iter()
                .map(OperatorAcknowledgement::record_root),
        );
        let hold_unhold_root = hold_unhold_state.record_root();
        let criteria = evaluate_abort_criteria(
            &config,
            height,
            &guard_outputs,
            &pq_rollback_roots,
            &reserve_rollback_proofs,
            &privacy_rollback_markers,
            &abort_commands,
            &expected_receipts,
            &operator_acknowledgements,
            &hold_unhold_state,
        );
        let operator_weight = operator_acknowledgements
            .iter()
            .filter(|ack| ack.approving())
            .map(|ack| ack.weight_bps as u32)
            .sum::<u32>();
        let fail_closed_release_hold = hold_unhold_state.fail_closed();
        let unhold_after_drill = criteria.is_empty()
            && operator_weight >= config.min_operator_weight_bps as u32
            && hold_unhold_state.unhold_requested
            && hold_unhold_state.unhold_allowed;
        let verdict = if criteria
            .iter()
            .any(|criterion| matches!(criterion, AbortCriterion::EmergencyAbortCommand))
        {
            DrillVerdict::Abort
        } else if unhold_after_drill {
            DrillVerdict::UnholdReady
        } else if fail_closed_release_hold {
            DrillVerdict::FailClosed
        } else {
            DrillVerdict::Hold
        };
        let accepted = matches!(
            verdict,
            DrillVerdict::UnholdReady | DrillVerdict::FailClosed
        );
        let decision_root = runtime_id(
            "rollback-drill-decision-root",
            &[
                HashPart::Str(verdict.as_str()),
                HashPart::Str(if accepted { "accepted" } else { "blocked" }),
                HashPart::Str(&guard_output_root),
                HashPart::Str(&pq_rollback_root),
                HashPart::Str(&reserve_rollback_root),
                HashPart::Str(&privacy_rollback_root),
                HashPart::Str(&abort_command_root),
                HashPart::Str(&expected_receipt_root),
                HashPart::Str(&operator_ack_root),
                HashPart::Str(&hold_unhold_root),
                HashPart::Json(&json!(criteria
                    .iter()
                    .map(|criterion| criterion.as_str())
                    .collect::<Vec<_>>())),
            ],
        );
        let decision = DrillDecision {
            verdict,
            accepted,
            fail_closed_release_hold,
            unhold_after_drill,
            criteria,
            guard_output_root: guard_output_root.clone(),
            pq_rollback_root: pq_rollback_root.clone(),
            reserve_rollback_root: reserve_rollback_root.clone(),
            privacy_rollback_root: privacy_rollback_root.clone(),
            abort_command_root: abort_command_root.clone(),
            expected_receipt_root: expected_receipt_root.clone(),
            operator_ack_root: operator_ack_root.clone(),
            hold_unhold_root: hold_unhold_root.clone(),
            decision_root,
        };
        Ok(Self {
            config,
            height,
            guard_outputs,
            pq_rollback_roots,
            reserve_rollback_proofs,
            privacy_rollback_markers,
            abort_commands,
            expected_receipts,
            operator_acknowledgements,
            hold_unhold_state,
            guard_output_root,
            pq_rollback_root,
            reserve_rollback_root,
            privacy_rollback_root,
            abort_command_root,
            expected_receipt_root,
            operator_ack_root,
            hold_unhold_root,
            decision,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let guard_outputs = devnet_guard_outputs(&config, height);
        let pq_rollback_roots = devnet_pq_rollback_roots(&config, height);
        let reserve_rollback_proofs = devnet_reserve_rollback_proofs(height);
        let privacy_rollback_markers = devnet_privacy_rollback_markers(height);
        let abort_commands = devnet_abort_commands(height);
        let expected_receipts = devnet_expected_receipts(&config, &pq_rollback_roots, height);
        let operator_acknowledgements = devnet_operator_acknowledgements(height);
        let hold_unhold_state = HoldUnholdState::new(
            "wave-85-fail-closed-release-hold-unhold-state",
            &config.expected_release_hold_root,
            &config.expected_fail_closed_root,
            true,
            true,
            true,
            true,
            height.saturating_sub(2),
            EvidenceStatus::Accepted,
        )
        .unwrap_or_else(|_| fallback_hold_unhold_state(&config, height));
        Self::new(
            config,
            height,
            guard_outputs,
            pq_rollback_roots,
            reserve_rollback_proofs,
            privacy_rollback_markers,
            abort_commands,
            expected_receipts,
            operator_acknowledgements,
            hold_unhold_state,
        )
        .unwrap_or_else(|_| Self::fallback())
    }

    pub fn fallback() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let hold_unhold_state = fallback_hold_unhold_state(&config, height);
        let guard_output_root = sample_root("fallback-guard-output-root");
        let pq_rollback_root = sample_root("fallback-pq-rollback-root");
        let reserve_rollback_root = sample_root("fallback-reserve-rollback-root");
        let privacy_rollback_root = sample_root("fallback-privacy-rollback-root");
        let abort_command_root = sample_root("fallback-abort-command-root");
        let expected_receipt_root = sample_root("fallback-expected-receipt-root");
        let operator_ack_root = sample_root("fallback-operator-ack-root");
        let hold_unhold_root = hold_unhold_state.record_root();
        let decision_root = runtime_id(
            "rollback-drill-fallback-decision-root",
            &[
                HashPart::Str(&guard_output_root),
                HashPart::Str(&pq_rollback_root),
                HashPart::Str(&reserve_rollback_root),
                HashPart::Str(&privacy_rollback_root),
                HashPart::Str(&abort_command_root),
                HashPart::Str(&expected_receipt_root),
                HashPart::Str(&operator_ack_root),
                HashPart::Str(&hold_unhold_root),
            ],
        );
        let decision = DrillDecision {
            verdict: DrillVerdict::Hold,
            accepted: false,
            fail_closed_release_hold: true,
            unhold_after_drill: false,
            criteria: vec![AbortCriterion::GuardRootMismatch],
            guard_output_root: guard_output_root.clone(),
            pq_rollback_root: pq_rollback_root.clone(),
            reserve_rollback_root: reserve_rollback_root.clone(),
            privacy_rollback_root: privacy_rollback_root.clone(),
            abort_command_root: abort_command_root.clone(),
            expected_receipt_root: expected_receipt_root.clone(),
            operator_ack_root: operator_ack_root.clone(),
            hold_unhold_root: hold_unhold_root.clone(),
            decision_root,
        };
        Self {
            config,
            height,
            guard_outputs: Vec::new(),
            pq_rollback_roots: Vec::new(),
            reserve_rollback_proofs: Vec::new(),
            privacy_rollback_markers: Vec::new(),
            abort_commands: Vec::new(),
            expected_receipts: Vec::new(),
            operator_acknowledgements: Vec::new(),
            hold_unhold_state,
            guard_output_root,
            pq_rollback_root,
            reserve_rollback_root,
            privacy_rollback_root,
            abort_command_root,
            expected_receipt_root,
            operator_ack_root,
            hold_unhold_root,
            decision,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "guard_output_root": self.guard_output_root,
            "pq_rollback_root": self.pq_rollback_root,
            "reserve_rollback_root": self.reserve_rollback_root,
            "privacy_rollback_root": self.privacy_rollback_root,
            "abort_command_root": self.abort_command_root,
            "expected_receipt_root": self.expected_receipt_root,
            "operator_ack_root": self.operator_ack_root,
            "hold_unhold_root": self.hold_unhold_root,
            "decision": self.decision.public_record(),
            "guard_outputs": self.guard_outputs.iter().map(GuardOutput::public_record).collect::<Vec<_>>(),
            "pq_rollback_roots": self.pq_rollback_roots.iter().map(PqRollbackRoot::public_record).collect::<Vec<_>>(),
            "reserve_rollback_proofs": self.reserve_rollback_proofs.iter().map(ReserveRollbackProof::public_record).collect::<Vec<_>>(),
            "privacy_rollback_markers": self.privacy_rollback_markers.iter().map(PrivacyBoundaryRollbackMarker::public_record).collect::<Vec<_>>(),
            "abort_commands": self.abort_commands.iter().map(AbortCommand::public_record).collect::<Vec<_>>(),
            "expected_receipts": self.expected_receipts.iter().map(ExpectedReceipt::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "hold_unhold_state": self.hold_unhold_state.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "rollback-drill-state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.drill_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.guard_output_root),
                HashPart::Str(&self.pq_rollback_root),
                HashPart::Str(&self.reserve_rollback_root),
                HashPart::Str(&self.privacy_rollback_root),
                HashPart::Str(&self.abort_command_root),
                HashPart::Str(&self.expected_receipt_root),
                HashPart::Str(&self.operator_ack_root),
                HashPart::Str(&self.hold_unhold_root),
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

pub fn public_record() -> serde_json::Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn evaluate_abort_criteria(
    config: &Config,
    height: u64,
    guard_outputs: &[GuardOutput],
    pq_rollback_roots: &[PqRollbackRoot],
    reserve_rollback_proofs: &[ReserveRollbackProof],
    privacy_rollback_markers: &[PrivacyBoundaryRollbackMarker],
    abort_commands: &[AbortCommand],
    expected_receipts: &[ExpectedReceipt],
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_unhold_state: &HoldUnholdState,
) -> Vec<AbortCriterion> {
    let mut criteria = BTreeSet::new();
    let guard_map = guard_outputs
        .iter()
        .map(|output| (output.kind, output.root.as_str()))
        .collect::<BTreeMap<_, _>>();
    if guard_map.get(&GuardOutputKind::DeploymentGuardRoot)
        != Some(&config.expected_deployment_guard_root.as_str())
    {
        criteria.insert(AbortCriterion::GuardRootMismatch);
    }
    if guard_map.get(&GuardOutputKind::ReleaseHoldRoot)
        != Some(&config.expected_release_hold_root.as_str())
    {
        criteria.insert(AbortCriterion::ReleaseHoldActive);
    }
    if guard_map.get(&GuardOutputKind::FailClosedRoot)
        != Some(&config.expected_fail_closed_root.as_str())
    {
        criteria.insert(AbortCriterion::FailClosedNotAsserted);
    }
    if accepted_fresh_count(
        height,
        config.max_evidence_age_blocks,
        pq_rollback_roots
            .iter()
            .map(|item| (item.status, item.observed_at_height)),
    ) < config.min_pq_rollback_roots
    {
        criteria.insert(AbortCriterion::PqRollbackRootMissing);
    }
    if pq_rollback_roots
        .iter()
        .any(|item| item.key_epoch != config.key_epoch)
    {
        criteria.insert(AbortCriterion::PqEpochMismatch);
    }
    if accepted_fresh_count(
        height,
        config.max_evidence_age_blocks,
        reserve_rollback_proofs
            .iter()
            .map(|item| (item.status, item.observed_at_height)),
    ) < config.min_reserve_rollback_proofs
    {
        criteria.insert(AbortCriterion::ReserveProofMissing);
    }
    if reserve_rollback_proofs
        .iter()
        .any(|item| item.coverage_bps < config.min_reserve_coverage_bps)
    {
        criteria.insert(AbortCriterion::ReserveCoverageShortfall);
    }
    if accepted_fresh_count(
        height,
        config.max_evidence_age_blocks,
        privacy_rollback_markers
            .iter()
            .map(|item| (item.status, item.observed_at_height)),
    ) < config.min_privacy_rollback_markers
    {
        criteria.insert(AbortCriterion::PrivacyBoundaryMissing);
    }
    if privacy_rollback_markers.iter().any(|item| {
        item.privacy_budget_bps > config.max_privacy_budget_bps
            || item.anonymity_set_size < config.min_privacy_set_size
    }) {
        criteria.insert(AbortCriterion::PrivacyBudgetExceeded);
    }
    if accepted_fresh_count(
        height,
        config.max_evidence_age_blocks,
        abort_commands
            .iter()
            .map(|item| (item.status, item.observed_at_height)),
    ) < config.min_abort_commands
    {
        criteria.insert(AbortCriterion::EmergencyAbortCommand);
    }
    if abort_commands
        .iter()
        .any(|item| item.armed && item.status.blocking())
    {
        criteria.insert(AbortCriterion::EmergencyAbortCommand);
    }
    if expected_receipts
        .iter()
        .filter(|receipt| receipt.matches_expected())
        .count()
        < config.min_expected_receipts as usize
    {
        criteria.insert(AbortCriterion::ReceiptMissing);
    }
    let operator_weight = operator_acknowledgements
        .iter()
        .filter(|ack| ack.approving())
        .map(|ack| ack.weight_bps as u32)
        .sum::<u32>();
    if operator_acknowledgements
        .iter()
        .filter(|ack| ack.approving())
        .count()
        < config.min_operator_acks as usize
        || operator_weight < config.min_operator_weight_bps as u32
    {
        criteria.insert(AbortCriterion::OperatorAckMissing);
    }
    if !hold_unhold_state.fail_closed() {
        criteria.insert(AbortCriterion::FailClosedNotAsserted);
    }
    if all_observed_heights(
        guard_outputs,
        pq_rollback_roots,
        reserve_rollback_proofs,
        privacy_rollback_markers,
        abort_commands,
        expected_receipts,
        operator_acknowledgements,
        hold_unhold_state,
    )
    .into_iter()
    .any(|observed_at_height| {
        observed_at_height > height
            || height.saturating_sub(observed_at_height) > config.max_evidence_age_blocks
    }) {
        criteria.insert(AbortCriterion::StaleEvidence);
    }
    criteria.into_iter().collect()
}

fn all_observed_heights(
    guard_outputs: &[GuardOutput],
    pq_rollback_roots: &[PqRollbackRoot],
    reserve_rollback_proofs: &[ReserveRollbackProof],
    privacy_rollback_markers: &[PrivacyBoundaryRollbackMarker],
    abort_commands: &[AbortCommand],
    expected_receipts: &[ExpectedReceipt],
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_unhold_state: &HoldUnholdState,
) -> Vec<u64> {
    let mut heights = Vec::new();
    heights.extend(guard_outputs.iter().map(|item| item.observed_at_height));
    heights.extend(pq_rollback_roots.iter().map(|item| item.observed_at_height));
    heights.extend(
        reserve_rollback_proofs
            .iter()
            .map(|item| item.observed_at_height),
    );
    heights.extend(
        privacy_rollback_markers
            .iter()
            .map(|item| item.observed_at_height),
    );
    heights.extend(abort_commands.iter().map(|item| item.observed_at_height));
    heights.extend(expected_receipts.iter().map(|item| item.observed_at_height));
    heights.extend(
        operator_acknowledgements
            .iter()
            .map(|item| item.observed_at_height),
    );
    heights.push(hold_unhold_state.observed_at_height);
    heights
}

fn accepted_fresh_count<I>(height: u64, max_age: u64, items: I) -> u16
where
    I: IntoIterator<Item = (EvidenceStatus, u64)>,
{
    let count = items
        .into_iter()
        .filter(|(status, observed_at_height)| {
            status.accepted()
                && *observed_at_height <= height
                && height.saturating_sub(*observed_at_height) <= max_age
        })
        .count();
    bounded_u16(count)
}

fn devnet_guard_outputs(config: &Config, height: u64) -> Vec<GuardOutput> {
    vec![
        GuardOutput::new(
            "wave-84-deployment-guard-output",
            GuardOutputKind::DeploymentGuardRoot,
            &config.expected_deployment_guard_root,
            config.source_wave_number,
            height.saturating_sub(12),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-release-hold-output",
            GuardOutputKind::ReleaseHoldRoot,
            &config.expected_release_hold_root,
            config.source_wave_number,
            height.saturating_sub(11),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-pq-rotation-output",
            GuardOutputKind::PqRotationRoot,
            &sample_root("wave-84-pq-rotation-output"),
            config.source_wave_number,
            height.saturating_sub(10),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-reserve-coverage-output",
            GuardOutputKind::ReserveCoverageRoot,
            &sample_root("wave-84-reserve-coverage-output"),
            config.source_wave_number,
            height.saturating_sub(9),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-privacy-boundary-output",
            GuardOutputKind::PrivacyBoundaryRoot,
            &sample_root("wave-84-privacy-boundary-output"),
            config.source_wave_number,
            height.saturating_sub(8),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-abort-root-output",
            GuardOutputKind::AbortRoot,
            &sample_root("wave-84-abort-root-output"),
            config.source_wave_number,
            height.saturating_sub(7),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-operator-dashboard-output",
            GuardOutputKind::OperatorDashboardRoot,
            &sample_root("wave-84-operator-dashboard-output"),
            config.source_wave_number,
            height.saturating_sub(6),
            EvidenceStatus::Accepted,
        ),
        GuardOutput::new(
            "wave-84-fail-closed-output",
            GuardOutputKind::FailClosedRoot,
            &config.expected_fail_closed_root,
            config.source_wave_number,
            height.saturating_sub(5),
            EvidenceStatus::Accepted,
        ),
    ]
    .into_iter()
    .filter_map(std::result::Result::ok)
    .collect()
}

fn devnet_pq_rollback_roots(config: &Config, height: u64) -> Vec<PqRollbackRoot> {
    ["alpha", "beta", "gamma"]
        .iter()
        .enumerate()
        .filter_map(|(index, suffix)| {
            PqRollbackRoot::new(
                &format!("pq-rollback-{suffix}"),
                config.key_epoch,
                &sample_root(&format!("pq-rotation-before-{suffix}")),
                &sample_root(&format!("pq-rotation-after-{suffix}")),
                &sample_root(&format!("pq-signer-set-{suffix}")),
                7_500 + index as u16 * 250,
                height.saturating_sub(6 + index as u64),
                EvidenceStatus::Accepted,
            )
            .ok()
        })
        .collect()
}

fn devnet_reserve_rollback_proofs(height: u64) -> Vec<ReserveRollbackProof> {
    vec![
        (
            "reserve-xmr-hot",
            "xmr",
            10_000_000_000_000_u128,
            10_900_000_000_000_u128,
        ),
        (
            "reserve-xmr-cold",
            "xmr",
            25_000_000_000_000_u128,
            27_000_000_000_000_u128,
        ),
        (
            "reserve-usdc-hedge",
            "usdc",
            7_000_000_000_u128,
            7_600_000_000_u128,
        ),
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(index, (proof_id, asset, liability, covered))| {
        ReserveRollbackProof::new(
            proof_id,
            asset,
            liability,
            covered,
            &sample_root(&format!("reserve-proof-{proof_id}")),
            height.saturating_sub(9 + index as u64),
            EvidenceStatus::Accepted,
        )
        .ok()
    })
    .collect()
}

fn devnet_privacy_rollback_markers(height: u64) -> Vec<PrivacyBoundaryRollbackMarker> {
    vec![
        (
            "privacy-marker-wallet",
            "wallet_scan_boundary",
            192_u64,
            1_100_u16,
            vec!["scan_height".to_string(), "view_tag_bucket".to_string()],
        ),
        (
            "privacy-marker-reserve",
            "reserve_proof_boundary",
            256_u64,
            900_u16,
            vec!["liability_bucket".to_string(), "asset_class".to_string()],
        ),
        (
            "privacy-marker-operator",
            "operator_dashboard_boundary",
            160_u64,
            1_250_u16,
            vec!["operator_role".to_string(), "ack_window".to_string()],
        ),
    ]
    .into_iter()
    .enumerate()
    .filter_map(
        |(index, (marker_id, boundary_name, set_size, budget, fields))| {
            PrivacyBoundaryRollbackMarker::new(
                marker_id,
                boundary_name,
                &sample_root(&format!("privacy-boundary-{marker_id}")),
                set_size,
                budget,
                fields,
                height.saturating_sub(10 + index as u64),
                EvidenceStatus::Accepted,
            )
            .ok()
        },
    )
    .collect()
}

fn devnet_abort_commands(height: u64) -> Vec<AbortCommand> {
    vec![
        (
            "abort-pq-root-missing",
            AbortCriterion::PqRollbackRootMissing,
            "release-captain",
        ),
        (
            "abort-reserve-shortfall",
            AbortCriterion::ReserveCoverageShortfall,
            "reserve-operator",
        ),
        (
            "abort-privacy-budget",
            AbortCriterion::PrivacyBudgetExceeded,
            "privacy-operator",
        ),
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(index, (command_id, criterion, issuer))| {
        AbortCommand::new(
            command_id,
            criterion,
            issuer,
            true,
            true,
            height.saturating_sub(4 + index as u64),
            EvidenceStatus::Accepted,
        )
        .ok()
    })
    .collect()
}

fn devnet_expected_receipts(
    config: &Config,
    pq_roots: &[PqRollbackRoot],
    height: u64,
) -> Vec<ExpectedReceipt> {
    let mut roots = vec![
        (
            "deployment_guard",
            config.expected_deployment_guard_root.clone(),
        ),
        ("release_hold", config.expected_release_hold_root.clone()),
        ("fail_closed", config.expected_fail_closed_root.clone()),
    ];
    roots.extend(
        pq_roots
            .iter()
            .map(|root| (root.root_id.as_str(), root.rollback_root.clone())),
    );
    roots
        .into_iter()
        .enumerate()
        .filter_map(|(index, (subject, root))| {
            ExpectedReceipt::new(
                &format!("expected-receipt-{subject}"),
                subject,
                &root,
                &root,
                true,
                height.saturating_sub(3 + index as u64),
                EvidenceStatus::Accepted,
            )
            .ok()
        })
        .collect()
}

fn devnet_operator_acknowledgements(height: u64) -> Vec<OperatorAcknowledgement> {
    vec![
        ("operator-release-captain", "release_captain", 2_000_u16),
        ("operator-pq", "pq_rotation", 2_000_u16),
        ("operator-reserve", "reserve_liquidity", 2_000_u16),
        ("operator-privacy", "privacy_boundary", 2_000_u16),
    ]
    .into_iter()
    .enumerate()
    .filter_map(|(index, (operator_id, role, weight))| {
        OperatorAcknowledgement::new(
            operator_id,
            role,
            weight,
            true,
            true,
            height.saturating_sub(2 + index as u64),
            EvidenceStatus::Accepted,
        )
        .ok()
    })
    .collect()
}

fn fallback_hold_unhold_state(config: &Config, height: u64) -> HoldUnholdState {
    HoldUnholdState {
        state_id: "fallback-hold-unhold-state".to_string(),
        release_hold_root: config.expected_release_hold_root.clone(),
        fail_closed_root: config.expected_fail_closed_root.clone(),
        hold_asserted: true,
        unhold_requested: false,
        unhold_allowed: false,
        production_writes_disabled: true,
        observed_at_height: height,
        status: EvidenceStatus::Accepted,
    }
}

fn runtime_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn sample_root(label: &str) -> String {
    runtime_id(
        "ROLLBACK-DRILL-DEVNET-SAMPLE",
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

fn vec_root<I>(domain: &str, roots: I) -> String
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

fn ensure_bps(label: &str, value: u16) -> Result<()> {
    ensure(value <= 10_000, &format!("{label} must be <= 10000"))
}
