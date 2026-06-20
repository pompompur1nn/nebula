use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqReservePrivacyAcceptedLiveEvidenceOperatorRunbookAuditRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-pq-reserve-privacy-accepted-live-evidence-operator-runbook-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_OPERATOR_ID: &str = "monero-l2-force-exit-runbook-operator-devnet";
pub const DEFAULT_RELEASE_DASHBOARD_ID: &str = "release-dashboard-monero-l2-pq-exit-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 128;
pub const DEFAULT_MIN_PQ_QUORUM_SIGNERS: u16 = 5;
pub const DEFAULT_MIN_PQ_QUORUM_WEIGHT_BPS: u16 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u16 = 10_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const DEFAULT_MAX_PRIVACY_BUDGET_BPS: u16 = 2_500;
pub const DEFAULT_MAX_EVIDENCE_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_RELEASE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_ATTESTER_COUNT: u16 = 3;
pub const STATUS_ACCEPTED: &str = "accepted";
pub const STATUS_REJECTED: &str = "rejected";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_BLOCKED: &str = "blocked";
pub const STATUS_READY: &str = "ready";
pub const STATUS_FAIL_CLOSED: &str = "fail_closed";

const ACCEPTED_SEVERITIES: &[&str] = &["info", "notice", "warning", "critical"];
const ACCEPTED_DOMAINS: &[EvidenceDomain] = &[
    EvidenceDomain::PqQuorum,
    EvidenceDomain::KeyEpoch,
    EvidenceDomain::ReserveCoverage,
    EvidenceDomain::PrivacyBudget,
    EvidenceDomain::NonLinkage,
    EvidenceDomain::RunbookOperator,
    EvidenceDomain::ReleaseDashboard,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDomain {
    PqQuorum,
    KeyEpoch,
    ReserveCoverage,
    PrivacyBudget,
    NonLinkage,
    RunbookOperator,
    ReleaseDashboard,
}

impl EvidenceDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PqQuorum => "pq_quorum",
            Self::KeyEpoch => "key_epoch",
            Self::ReserveCoverage => "reserve_coverage",
            Self::PrivacyBudget => "privacy_budget",
            Self::NonLinkage => "non_linkage",
            Self::RunbookOperator => "runbook_operator",
            Self::ReleaseDashboard => "release_dashboard",
        }
    }

    pub fn release_gate_name(&self) -> &'static str {
        match self {
            Self::PqQuorum => "pq_quorum_review",
            Self::KeyEpoch => "key_epoch_review",
            Self::ReserveCoverage => "reserve_coverage_confirmation",
            Self::PrivacyBudget => "privacy_budget_attestation",
            Self::NonLinkage => "non_linkage_attestation",
            Self::RunbookOperator => "operator_runbook_binding",
            Self::ReleaseDashboard => "release_dashboard_import",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    MissingEvidence,
    StaleEvidence,
    PqQuorumShortfall,
    KeyEpochMismatch,
    ReserveUnderCovered,
    PrivacyBudgetExceeded,
    LinkageRisk,
    DashboardNotBound,
    OperatorRunbookMismatch,
    RejectedEvidence,
}

impl BlockerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MissingEvidence => "missing_evidence",
            Self::StaleEvidence => "stale_evidence",
            Self::PqQuorumShortfall => "pq_quorum_shortfall",
            Self::KeyEpochMismatch => "key_epoch_mismatch",
            Self::ReserveUnderCovered => "reserve_under_covered",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::LinkageRisk => "linkage_risk",
            Self::DashboardNotBound => "dashboard_not_bound",
            Self::OperatorRunbookMismatch => "operator_runbook_mismatch",
            Self::RejectedEvidence => "rejected_evidence",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub operator_id: String,
    pub release_dashboard_id: String,
    pub runbook_package_id: String,
    pub force_exit_package_root: String,
    pub expected_key_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_pq_quorum_signers: u16,
    pub min_pq_quorum_weight_bps: u16,
    pub min_reserve_coverage_bps: u16,
    pub min_privacy_set_size: u64,
    pub max_privacy_budget_bps: u16,
    pub max_evidence_age_blocks: u64,
    pub release_window_blocks: u64,
    pub min_attester_count: u16,
    pub fail_closed_on_warning: bool,
}

impl Config {
    pub fn devnet() -> Self {
        let runbook_package_id = runtime_id(
            "RUNBOOK-PACKAGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEFAULT_OPERATOR_ID),
                HashPart::Str("force-exit-package-pq-reserve-privacy"),
            ],
        );
        let force_exit_package_root = runtime_id(
            "FORCE-EXIT-PACKAGE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(DEFAULT_RELEASE_DASHBOARD_ID),
                HashPart::Str(&runbook_package_id),
            ],
        );
        Self {
            operator_id: DEFAULT_OPERATOR_ID.to_string(),
            release_dashboard_id: DEFAULT_RELEASE_DASHBOARD_ID.to_string(),
            runbook_package_id,
            force_exit_package_root,
            expected_key_epoch: 82,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_pq_quorum_signers: DEFAULT_MIN_PQ_QUORUM_SIGNERS,
            min_pq_quorum_weight_bps: DEFAULT_MIN_PQ_QUORUM_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_privacy_budget_bps: DEFAULT_MAX_PRIVACY_BUDGET_BPS,
            max_evidence_age_blocks: DEFAULT_MAX_EVIDENCE_AGE_BLOCKS,
            release_window_blocks: DEFAULT_RELEASE_WINDOW_BLOCKS,
            min_attester_count: DEFAULT_MIN_ATTESTER_COUNT,
            fail_closed_on_warning: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_audit_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "operator_id": self.operator_id,
            "release_dashboard_id": self.release_dashboard_id,
            "runbook_package_id": self.runbook_package_id,
            "force_exit_package_root": self.force_exit_package_root,
            "expected_key_epoch": self.expected_key_epoch,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_pq_quorum_signers": self.min_pq_quorum_signers,
            "min_pq_quorum_weight_bps": self.min_pq_quorum_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_privacy_budget_bps": self.max_privacy_budget_bps,
            "max_evidence_age_blocks": self.max_evidence_age_blocks,
            "release_window_blocks": self.release_window_blocks,
            "min_attester_count": self.min_attester_count,
            "fail_closed_on_warning": self.fail_closed_on_warning,
        })
    }

    pub fn config_root(&self) -> String {
        payload_root("OPERATOR-RUNBOOK-AUDIT-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.operator_id, "operator id")?;
        ensure_non_empty(&self.release_dashboard_id, "release dashboard id")?;
        ensure_non_empty(&self.runbook_package_id, "runbook package id")?;
        ensure_non_empty(&self.force_exit_package_root, "force exit package root")?;
        ensure_non_zero(self.expected_key_epoch, "expected key epoch")?;
        ensure_non_zero(self.min_pq_security_bits as u64, "minimum pq security bits")?;
        ensure_non_zero(
            self.min_pq_quorum_signers as u64,
            "minimum pq quorum signers",
        )?;
        ensure_bps(
            self.min_pq_quorum_weight_bps,
            "minimum pq quorum weight bps",
        )?;
        ensure_non_zero(
            self.min_reserve_coverage_bps as u64,
            "minimum reserve coverage bps",
        )?;
        ensure_bps(
            self.max_privacy_budget_bps,
            "maximum privacy budget consumed bps",
        )?;
        ensure_non_zero(self.min_privacy_set_size, "minimum privacy set size")?;
        ensure_non_zero(self.max_evidence_age_blocks, "maximum evidence age blocks")?;
        ensure_non_zero(self.release_window_blocks, "release window blocks")?;
        ensure_non_zero(self.min_attester_count as u64, "minimum attester count")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceImport {
    pub evidence_id: String,
    pub domain: EvidenceDomain,
    pub source_system: String,
    pub import_batch_id: String,
    pub artifact_root: String,
    pub acceptance_root: String,
    pub accepted_by: String,
    pub accepted_at_height: u64,
    pub observed_height: u64,
    pub status: String,
    pub severity: String,
    pub attester_ids: Vec<String>,
    pub metadata_root: String,
}

impl EvidenceImport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: EvidenceDomain,
        source_system: impl Into<String>,
        import_batch_id: impl Into<String>,
        artifact_root: impl Into<String>,
        acceptance_root: impl Into<String>,
        accepted_by: impl Into<String>,
        accepted_at_height: u64,
        observed_height: u64,
        status: impl Into<String>,
        severity: impl Into<String>,
        attester_ids: Vec<String>,
        metadata: &Value,
    ) -> Result<Self> {
        let source_system = source_system.into();
        let import_batch_id = import_batch_id.into();
        let artifact_root = artifact_root.into();
        let acceptance_root = acceptance_root.into();
        let accepted_by = accepted_by.into();
        let status = status.into();
        let severity = severity.into();
        let metadata_root = payload_root("OPERATOR-RUNBOOK-EVIDENCE-METADATA", metadata);
        let evidence_id = evidence_id(
            domain,
            &source_system,
            &import_batch_id,
            &artifact_root,
            &acceptance_root,
            accepted_at_height,
        );
        let import = Self {
            evidence_id,
            domain,
            source_system,
            import_batch_id,
            artifact_root,
            acceptance_root,
            accepted_by,
            accepted_at_height,
            observed_height,
            status,
            severity,
            attester_ids: sorted_unique(attester_ids),
            metadata_root,
        };
        import.validate()?;
        Ok(import)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.evidence_id, "evidence id")?;
        ensure_non_empty(&self.source_system, "evidence source system")?;
        ensure_non_empty(&self.import_batch_id, "evidence import batch id")?;
        ensure_non_empty(&self.artifact_root, "evidence artifact root")?;
        ensure_non_empty(&self.acceptance_root, "evidence acceptance root")?;
        ensure_non_empty(&self.accepted_by, "evidence accepted by")?;
        ensure_non_zero(self.accepted_at_height, "evidence accepted height")?;
        ensure_non_zero(self.observed_height, "evidence observed height")?;
        ensure_status(&self.status, "evidence status")?;
        ensure_in_set(&self.severity, ACCEPTED_SEVERITIES, "evidence severity")?;
        ensure_non_empty(&self.metadata_root, "evidence metadata root")?;
        ensure_unique_non_empty(&self.attester_ids, "evidence attester")?;
        Ok(())
    }

    pub fn is_accepted(&self) -> bool {
        self.status == STATUS_ACCEPTED
    }

    pub fn is_warning_or_critical(&self) -> bool {
        self.severity == "warning" || self.severity == "critical"
    }

    pub fn is_stale(&self, current_height: u64, max_age: u64) -> bool {
        current_height.saturating_sub(self.observed_height) > max_age
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_evidence_import",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "domain": self.domain.as_str(),
            "release_gate": self.domain.release_gate_name(),
            "source_system": self.source_system,
            "import_batch_id": self.import_batch_id,
            "artifact_root": self.artifact_root,
            "acceptance_root": self.acceptance_root,
            "accepted_by": self.accepted_by,
            "accepted_at_height": self.accepted_at_height,
            "observed_height": self.observed_height,
            "status": self.status,
            "severity": self.severity,
            "attester_ids": self.attester_ids,
            "attester_count": self.attester_ids.len() as u64,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqQuorumReview {
    pub review_id: String,
    pub key_epoch: u64,
    pub quorum_root: String,
    pub signer_count: u16,
    pub signer_weight_bps: u16,
    pub threshold_bps: u16,
    pub security_bits: u16,
    pub ml_dsa_policy_root: String,
    pub slh_dsa_fallback_root: String,
    pub reviewer_ids: Vec<String>,
    pub evidence_id: String,
    pub reviewed_at_height: u64,
    pub accepted: bool,
}

impl PqQuorumReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key_epoch: u64,
        quorum_root: impl Into<String>,
        signer_count: u16,
        signer_weight_bps: u16,
        threshold_bps: u16,
        security_bits: u16,
        ml_dsa_policy_root: impl Into<String>,
        slh_dsa_fallback_root: impl Into<String>,
        reviewer_ids: Vec<String>,
        evidence_id: impl Into<String>,
        reviewed_at_height: u64,
        accepted: bool,
    ) -> Result<Self> {
        let quorum_root = quorum_root.into();
        let ml_dsa_policy_root = ml_dsa_policy_root.into();
        let slh_dsa_fallback_root = slh_dsa_fallback_root.into();
        let evidence_id = evidence_id.into();
        let review_id = runtime_id(
            "PQ-QUORUM-REVIEW-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(key_epoch as i128),
                HashPart::Str(&quorum_root),
                HashPart::Str(&evidence_id),
            ],
        );
        let review = Self {
            review_id,
            key_epoch,
            quorum_root,
            signer_count,
            signer_weight_bps,
            threshold_bps,
            security_bits,
            ml_dsa_policy_root,
            slh_dsa_fallback_root,
            reviewer_ids: sorted_unique(reviewer_ids),
            evidence_id,
            reviewed_at_height,
            accepted,
        };
        review.validate()?;
        Ok(review)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.review_id, "pq quorum review id")?;
        ensure_non_zero(self.key_epoch, "pq quorum key epoch")?;
        ensure_non_empty(&self.quorum_root, "pq quorum root")?;
        ensure_non_zero(self.signer_count as u64, "pq signer count")?;
        ensure_bps(self.signer_weight_bps, "pq signer weight bps")?;
        ensure_bps(self.threshold_bps, "pq threshold bps")?;
        ensure_non_zero(self.security_bits as u64, "pq security bits")?;
        ensure_non_empty(&self.ml_dsa_policy_root, "ml-dsa policy root")?;
        ensure_non_empty(&self.slh_dsa_fallback_root, "slh-dsa fallback root")?;
        ensure_unique_non_empty(&self.reviewer_ids, "pq quorum reviewer")?;
        ensure_non_empty(&self.evidence_id, "pq quorum evidence id")?;
        ensure_non_zero(self.reviewed_at_height, "pq quorum reviewed height")
    }

    pub fn satisfies(&self, config: &Config) -> bool {
        self.accepted
            && self.key_epoch == config.expected_key_epoch
            && self.signer_count >= config.min_pq_quorum_signers
            && self.signer_weight_bps >= config.min_pq_quorum_weight_bps
            && self.signer_weight_bps >= self.threshold_bps
            && self.security_bits >= config.min_pq_security_bits
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_pq_quorum_review",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "review_id": self.review_id,
            "key_epoch": self.key_epoch,
            "quorum_root": self.quorum_root,
            "signer_count": self.signer_count,
            "signer_weight_bps": self.signer_weight_bps,
            "threshold_bps": self.threshold_bps,
            "security_bits": self.security_bits,
            "ml_dsa_policy_root": self.ml_dsa_policy_root,
            "slh_dsa_fallback_root": self.slh_dsa_fallback_root,
            "reviewer_ids": self.reviewer_ids,
            "reviewer_count": self.reviewer_ids.len() as u64,
            "evidence_id": self.evidence_id,
            "reviewed_at_height": self.reviewed_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEpochReview {
    pub review_id: String,
    pub key_epoch: u64,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub rotation_transcript_root: String,
    pub retired_epoch_root: String,
    pub active_keyset_root: String,
    pub rollback_key_disabled_root: String,
    pub evidence_id: String,
    pub reviewed_by: String,
    pub reviewed_at_height: u64,
    pub accepted: bool,
}

impl KeyEpochReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key_epoch: u64,
        activation_height: u64,
        expiry_height: u64,
        rotation_transcript_root: impl Into<String>,
        retired_epoch_root: impl Into<String>,
        active_keyset_root: impl Into<String>,
        rollback_key_disabled_root: impl Into<String>,
        evidence_id: impl Into<String>,
        reviewed_by: impl Into<String>,
        reviewed_at_height: u64,
        accepted: bool,
    ) -> Result<Self> {
        let rotation_transcript_root = rotation_transcript_root.into();
        let retired_epoch_root = retired_epoch_root.into();
        let active_keyset_root = active_keyset_root.into();
        let rollback_key_disabled_root = rollback_key_disabled_root.into();
        let evidence_id = evidence_id.into();
        let reviewed_by = reviewed_by.into();
        let review_id = runtime_id(
            "KEY-EPOCH-REVIEW-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(key_epoch as i128),
                HashPart::Str(&rotation_transcript_root),
                HashPart::Str(&active_keyset_root),
            ],
        );
        let review = Self {
            review_id,
            key_epoch,
            activation_height,
            expiry_height,
            rotation_transcript_root,
            retired_epoch_root,
            active_keyset_root,
            rollback_key_disabled_root,
            evidence_id,
            reviewed_by,
            reviewed_at_height,
            accepted,
        };
        review.validate()?;
        Ok(review)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.review_id, "key epoch review id")?;
        ensure_non_zero(self.key_epoch, "key epoch")?;
        ensure_non_zero(self.activation_height, "key epoch activation height")?;
        ensure_non_zero(self.expiry_height, "key epoch expiry height")?;
        if self.expiry_height <= self.activation_height {
            return Err("key epoch expiry must be after activation".to_string());
        }
        ensure_non_empty(
            &self.rotation_transcript_root,
            "key epoch rotation transcript root",
        )?;
        ensure_non_empty(&self.retired_epoch_root, "key epoch retired epoch root")?;
        ensure_non_empty(&self.active_keyset_root, "key epoch active keyset root")?;
        ensure_non_empty(
            &self.rollback_key_disabled_root,
            "key epoch rollback key disabled root",
        )?;
        ensure_non_empty(&self.evidence_id, "key epoch evidence id")?;
        ensure_non_empty(&self.reviewed_by, "key epoch reviewed by")?;
        ensure_non_zero(self.reviewed_at_height, "key epoch reviewed height")
    }

    pub fn covers_height(&self, height: u64) -> bool {
        self.activation_height <= height && height <= self.expiry_height
    }

    pub fn satisfies(&self, config: &Config, current_height: u64) -> bool {
        self.accepted
            && self.key_epoch == config.expected_key_epoch
            && self.covers_height(current_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_key_epoch_review",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "review_id": self.review_id,
            "key_epoch": self.key_epoch,
            "activation_height": self.activation_height,
            "expiry_height": self.expiry_height,
            "rotation_transcript_root": self.rotation_transcript_root,
            "retired_epoch_root": self.retired_epoch_root,
            "active_keyset_root": self.active_keyset_root,
            "rollback_key_disabled_root": self.rollback_key_disabled_root,
            "evidence_id": self.evidence_id,
            "reviewed_by": self.reviewed_by,
            "reviewed_at_height": self.reviewed_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveCoverageConfirmation {
    pub confirmation_id: String,
    pub reserve_asset_id: String,
    pub liability_root: String,
    pub reserve_proof_root: String,
    pub oracle_snapshot_root: String,
    pub covered_atomic_units: u128,
    pub required_atomic_units: u128,
    pub coverage_bps: u16,
    pub haircut_bps: u16,
    pub evidence_id: String,
    pub confirmed_by: String,
    pub confirmed_at_height: u64,
    pub accepted: bool,
}

impl ReserveCoverageConfirmation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reserve_asset_id: impl Into<String>,
        liability_root: impl Into<String>,
        reserve_proof_root: impl Into<String>,
        oracle_snapshot_root: impl Into<String>,
        covered_atomic_units: u128,
        required_atomic_units: u128,
        haircut_bps: u16,
        evidence_id: impl Into<String>,
        confirmed_by: impl Into<String>,
        confirmed_at_height: u64,
        accepted: bool,
    ) -> Result<Self> {
        let reserve_asset_id = reserve_asset_id.into();
        let liability_root = liability_root.into();
        let reserve_proof_root = reserve_proof_root.into();
        let oracle_snapshot_root = oracle_snapshot_root.into();
        let evidence_id = evidence_id.into();
        let confirmed_by = confirmed_by.into();
        let coverage_bps = coverage_bps(covered_atomic_units, required_atomic_units);
        let confirmation_id = runtime_id(
            "RESERVE-COVERAGE-CONFIRMATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&reserve_asset_id),
                HashPart::Str(&liability_root),
                HashPart::Str(&reserve_proof_root),
                HashPart::Int(clamped_i128(coverage_bps as u128)),
            ],
        );
        let confirmation = Self {
            confirmation_id,
            reserve_asset_id,
            liability_root,
            reserve_proof_root,
            oracle_snapshot_root,
            covered_atomic_units,
            required_atomic_units,
            coverage_bps,
            haircut_bps,
            evidence_id,
            confirmed_by,
            confirmed_at_height,
            accepted,
        };
        confirmation.validate()?;
        Ok(confirmation)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.confirmation_id, "reserve confirmation id")?;
        ensure_non_empty(&self.reserve_asset_id, "reserve asset id")?;
        ensure_non_empty(&self.liability_root, "reserve liability root")?;
        ensure_non_empty(&self.reserve_proof_root, "reserve proof root")?;
        ensure_non_empty(&self.oracle_snapshot_root, "reserve oracle snapshot root")?;
        ensure_non_zero_u128(self.covered_atomic_units, "covered atomic units")?;
        ensure_non_zero_u128(self.required_atomic_units, "required atomic units")?;
        ensure_bps(self.haircut_bps, "reserve haircut bps")?;
        ensure_non_empty(&self.evidence_id, "reserve evidence id")?;
        ensure_non_empty(&self.confirmed_by, "reserve confirmed by")?;
        ensure_non_zero(self.confirmed_at_height, "reserve confirmed height")
    }

    pub fn satisfies(&self, config: &Config) -> bool {
        self.accepted && self.coverage_bps >= config.min_reserve_coverage_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_reserve_coverage_confirmation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "confirmation_id": self.confirmation_id,
            "reserve_asset_id": self.reserve_asset_id,
            "liability_root": self.liability_root,
            "reserve_proof_root": self.reserve_proof_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "covered_atomic_units": self.covered_atomic_units.to_string(),
            "required_atomic_units": self.required_atomic_units.to_string(),
            "coverage_bps": self.coverage_bps,
            "haircut_bps": self.haircut_bps,
            "evidence_id": self.evidence_id,
            "confirmed_by": self.confirmed_by,
            "confirmed_at_height": self.confirmed_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetAttestation {
    pub attestation_id: String,
    pub accounting_window_id: String,
    pub private_note_set_root: String,
    pub disclosure_event_root: String,
    pub privacy_budget_limit_bps: u16,
    pub privacy_budget_consumed_bps: u16,
    pub min_anonymity_set_size: u64,
    pub sampled_anonymity_set_size: u64,
    pub evidence_id: String,
    pub attested_by: String,
    pub attested_at_height: u64,
    pub accepted: bool,
}

impl PrivacyBudgetAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounting_window_id: impl Into<String>,
        private_note_set_root: impl Into<String>,
        disclosure_event_root: impl Into<String>,
        privacy_budget_limit_bps: u16,
        privacy_budget_consumed_bps: u16,
        min_anonymity_set_size: u64,
        sampled_anonymity_set_size: u64,
        evidence_id: impl Into<String>,
        attested_by: impl Into<String>,
        attested_at_height: u64,
        accepted: bool,
    ) -> Result<Self> {
        let accounting_window_id = accounting_window_id.into();
        let private_note_set_root = private_note_set_root.into();
        let disclosure_event_root = disclosure_event_root.into();
        let evidence_id = evidence_id.into();
        let attested_by = attested_by.into();
        let attestation_id = runtime_id(
            "PRIVACY-BUDGET-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&accounting_window_id),
                HashPart::Str(&private_note_set_root),
                HashPart::Int(privacy_budget_consumed_bps as i128),
            ],
        );
        let attestation = Self {
            attestation_id,
            accounting_window_id,
            private_note_set_root,
            disclosure_event_root,
            privacy_budget_limit_bps,
            privacy_budget_consumed_bps,
            min_anonymity_set_size,
            sampled_anonymity_set_size,
            evidence_id,
            attested_by,
            attested_at_height,
            accepted,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.attestation_id, "privacy budget attestation id")?;
        ensure_non_empty(&self.accounting_window_id, "privacy accounting window id")?;
        ensure_non_empty(&self.private_note_set_root, "private note set root")?;
        ensure_non_empty(&self.disclosure_event_root, "disclosure event root")?;
        ensure_bps(self.privacy_budget_limit_bps, "privacy budget limit bps")?;
        ensure_bps(
            self.privacy_budget_consumed_bps,
            "privacy budget consumed bps",
        )?;
        ensure_non_zero(self.min_anonymity_set_size, "minimum anonymity set size")?;
        ensure_non_zero(
            self.sampled_anonymity_set_size,
            "sampled anonymity set size",
        )?;
        ensure_non_empty(&self.evidence_id, "privacy budget evidence id")?;
        ensure_non_empty(&self.attested_by, "privacy budget attested by")?;
        ensure_non_zero(self.attested_at_height, "privacy budget attested height")
    }

    pub fn satisfies(&self, config: &Config) -> bool {
        self.accepted
            && self.privacy_budget_consumed_bps <= config.max_privacy_budget_bps
            && self.privacy_budget_consumed_bps <= self.privacy_budget_limit_bps
            && self.sampled_anonymity_set_size >= config.min_privacy_set_size
            && self.sampled_anonymity_set_size >= self.min_anonymity_set_size
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_privacy_budget_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "accounting_window_id": self.accounting_window_id,
            "private_note_set_root": self.private_note_set_root,
            "disclosure_event_root": self.disclosure_event_root,
            "privacy_budget_limit_bps": self.privacy_budget_limit_bps,
            "privacy_budget_consumed_bps": self.privacy_budget_consumed_bps,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "sampled_anonymity_set_size": self.sampled_anonymity_set_size,
            "evidence_id": self.evidence_id,
            "attested_by": self.attested_by,
            "attested_at_height": self.attested_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonLinkageAttestation {
    pub attestation_id: String,
    pub deposit_note_root: String,
    pub exit_claim_root: String,
    pub nullifier_set_root: String,
    pub linkage_probe_root: String,
    pub collision_count: u64,
    pub sampled_path_count: u64,
    pub min_privacy_set_size: u64,
    pub evidence_id: String,
    pub attested_by: String,
    pub attested_at_height: u64,
    pub accepted: bool,
}

impl NonLinkageAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deposit_note_root: impl Into<String>,
        exit_claim_root: impl Into<String>,
        nullifier_set_root: impl Into<String>,
        linkage_probe_root: impl Into<String>,
        collision_count: u64,
        sampled_path_count: u64,
        min_privacy_set_size: u64,
        evidence_id: impl Into<String>,
        attested_by: impl Into<String>,
        attested_at_height: u64,
        accepted: bool,
    ) -> Result<Self> {
        let deposit_note_root = deposit_note_root.into();
        let exit_claim_root = exit_claim_root.into();
        let nullifier_set_root = nullifier_set_root.into();
        let linkage_probe_root = linkage_probe_root.into();
        let evidence_id = evidence_id.into();
        let attested_by = attested_by.into();
        let attestation_id = runtime_id(
            "NON-LINKAGE-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&deposit_note_root),
                HashPart::Str(&exit_claim_root),
                HashPart::Str(&linkage_probe_root),
            ],
        );
        let attestation = Self {
            attestation_id,
            deposit_note_root,
            exit_claim_root,
            nullifier_set_root,
            linkage_probe_root,
            collision_count,
            sampled_path_count,
            min_privacy_set_size,
            evidence_id,
            attested_by,
            attested_at_height,
            accepted,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.attestation_id, "non-linkage attestation id")?;
        ensure_non_empty(&self.deposit_note_root, "non-linkage deposit note root")?;
        ensure_non_empty(&self.exit_claim_root, "non-linkage exit claim root")?;
        ensure_non_empty(&self.nullifier_set_root, "non-linkage nullifier set root")?;
        ensure_non_empty(&self.linkage_probe_root, "non-linkage probe root")?;
        ensure_non_zero(self.sampled_path_count, "non-linkage sampled path count")?;
        ensure_non_zero(self.min_privacy_set_size, "non-linkage minimum privacy set")?;
        ensure_non_empty(&self.evidence_id, "non-linkage evidence id")?;
        ensure_non_empty(&self.attested_by, "non-linkage attested by")?;
        ensure_non_zero(self.attested_at_height, "non-linkage attested height")
    }

    pub fn satisfies(&self, config: &Config) -> bool {
        self.accepted
            && self.collision_count == 0
            && self.sampled_path_count >= self.min_privacy_set_size
            && self.min_privacy_set_size >= config.min_privacy_set_size
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_non_linkage_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "deposit_note_root": self.deposit_note_root,
            "exit_claim_root": self.exit_claim_root,
            "nullifier_set_root": self.nullifier_set_root,
            "linkage_probe_root": self.linkage_probe_root,
            "collision_count": self.collision_count,
            "sampled_path_count": self.sampled_path_count,
            "min_privacy_set_size": self.min_privacy_set_size,
            "evidence_id": self.evidence_id,
            "attested_by": self.attested_by,
            "attested_at_height": self.attested_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookBinding {
    pub binding_id: String,
    pub operator_id: String,
    pub runbook_package_id: String,
    pub runbook_version: String,
    pub force_exit_package_root: String,
    pub release_dashboard_id: String,
    pub dashboard_panel_root: String,
    pub evidence_manifest_root: String,
    pub command_receipt_root: String,
    pub dry_run_receipt_root: String,
    pub bound_by: String,
    pub bound_at_height: u64,
    pub accepted: bool,
}

impl RunbookBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        runbook_package_id: impl Into<String>,
        runbook_version: impl Into<String>,
        force_exit_package_root: impl Into<String>,
        release_dashboard_id: impl Into<String>,
        dashboard_panel_root: impl Into<String>,
        evidence_manifest_root: impl Into<String>,
        command_receipt_root: impl Into<String>,
        dry_run_receipt_root: impl Into<String>,
        bound_by: impl Into<String>,
        bound_at_height: u64,
        accepted: bool,
    ) -> Result<Self> {
        let operator_id = operator_id.into();
        let runbook_package_id = runbook_package_id.into();
        let runbook_version = runbook_version.into();
        let force_exit_package_root = force_exit_package_root.into();
        let release_dashboard_id = release_dashboard_id.into();
        let dashboard_panel_root = dashboard_panel_root.into();
        let evidence_manifest_root = evidence_manifest_root.into();
        let command_receipt_root = command_receipt_root.into();
        let dry_run_receipt_root = dry_run_receipt_root.into();
        let bound_by = bound_by.into();
        let binding_id = runtime_id(
            "RUNBOOK-BINDING-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&operator_id),
                HashPart::Str(&runbook_package_id),
                HashPart::Str(&release_dashboard_id),
                HashPart::Str(&evidence_manifest_root),
            ],
        );
        let binding = Self {
            binding_id,
            operator_id,
            runbook_package_id,
            runbook_version,
            force_exit_package_root,
            release_dashboard_id,
            dashboard_panel_root,
            evidence_manifest_root,
            command_receipt_root,
            dry_run_receipt_root,
            bound_by,
            bound_at_height,
            accepted,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.binding_id, "runbook binding id")?;
        ensure_non_empty(&self.operator_id, "runbook binding operator id")?;
        ensure_non_empty(&self.runbook_package_id, "runbook package id")?;
        ensure_non_empty(&self.runbook_version, "runbook version")?;
        ensure_non_empty(&self.force_exit_package_root, "force exit package root")?;
        ensure_non_empty(&self.release_dashboard_id, "release dashboard id")?;
        ensure_non_empty(&self.dashboard_panel_root, "dashboard panel root")?;
        ensure_non_empty(&self.evidence_manifest_root, "evidence manifest root")?;
        ensure_non_empty(&self.command_receipt_root, "command receipt root")?;
        ensure_non_empty(&self.dry_run_receipt_root, "dry run receipt root")?;
        ensure_non_empty(&self.bound_by, "runbook bound by")?;
        ensure_non_zero(self.bound_at_height, "runbook bound height")
    }

    pub fn satisfies(&self, config: &Config) -> bool {
        self.accepted
            && self.operator_id == config.operator_id
            && self.runbook_package_id == config.runbook_package_id
            && self.force_exit_package_root == config.force_exit_package_root
            && self.release_dashboard_id == config.release_dashboard_id
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_binding",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "binding_id": self.binding_id,
            "operator_id": self.operator_id,
            "runbook_package_id": self.runbook_package_id,
            "runbook_version": self.runbook_version,
            "force_exit_package_root": self.force_exit_package_root,
            "release_dashboard_id": self.release_dashboard_id,
            "dashboard_panel_root": self.dashboard_panel_root,
            "evidence_manifest_root": self.evidence_manifest_root,
            "command_receipt_root": self.command_receipt_root,
            "dry_run_receipt_root": self.dry_run_receipt_root,
            "bound_by": self.bound_by,
            "bound_at_height": self.bound_at_height,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailClosedBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub gate: String,
    pub evidence_id: Option<String>,
    pub reason: String,
    pub opened_at_height: u64,
    pub blocking: bool,
}

impl FailClosedBlocker {
    pub fn new(
        kind: BlockerKind,
        gate: impl Into<String>,
        evidence_id: Option<String>,
        reason: impl Into<String>,
        opened_at_height: u64,
    ) -> Result<Self> {
        let gate = gate.into();
        let reason = reason.into();
        let evidence_part = evidence_id.as_deref().unwrap_or("none");
        let blocker_id = runtime_id(
            "FAIL-CLOSED-BLOCKER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&gate),
                HashPart::Str(evidence_part),
                HashPart::Str(&reason),
            ],
        );
        let blocker = Self {
            blocker_id,
            kind,
            gate,
            evidence_id,
            reason,
            opened_at_height,
            blocking: true,
        };
        blocker.validate()?;
        Ok(blocker)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.blocker_id, "fail-closed blocker id")?;
        ensure_non_empty(&self.gate, "fail-closed blocker gate")?;
        ensure_non_empty(&self.reason, "fail-closed blocker reason")?;
        ensure_non_zero(self.opened_at_height, "fail-closed blocker opened height")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_fail_closed_blocker",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "blocker_id": self.blocker_id,
            "blocker_kind": self.kind.as_str(),
            "gate": self.gate,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "opened_at_height": self.opened_at_height,
            "blocking": self.blocking,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDashboardReadiness {
    pub readiness_id: String,
    pub release_dashboard_id: String,
    pub current_height: u64,
    pub config_root: String,
    pub evidence_root: String,
    pub pq_review_root: String,
    pub key_epoch_review_root: String,
    pub reserve_confirmation_root: String,
    pub privacy_budget_root: String,
    pub non_linkage_root: String,
    pub runbook_binding_root: String,
    pub blocker_root: String,
    pub ready: bool,
    pub status: String,
    pub ready_gate_count: u64,
    pub blocker_count: u64,
}

impl ReleaseDashboardReadiness {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_runbook_release_dashboard_readiness",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "readiness_id": self.readiness_id,
            "release_dashboard_id": self.release_dashboard_id,
            "current_height": self.current_height,
            "config_root": self.config_root,
            "evidence_root": self.evidence_root,
            "pq_review_root": self.pq_review_root,
            "key_epoch_review_root": self.key_epoch_review_root,
            "reserve_confirmation_root": self.reserve_confirmation_root,
            "privacy_budget_root": self.privacy_budget_root,
            "non_linkage_root": self.non_linkage_root,
            "runbook_binding_root": self.runbook_binding_root,
            "blocker_root": self.blocker_root,
            "ready": self.ready,
            "status": self.status,
            "ready_gate_count": self.ready_gate_count,
            "blocker_count": self.blocker_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub evidence_imports: BTreeMap<String, EvidenceImport>,
    pub pq_quorum_reviews: BTreeMap<String, PqQuorumReview>,
    pub key_epoch_reviews: BTreeMap<String, KeyEpochReview>,
    pub reserve_confirmations: BTreeMap<String, ReserveCoverageConfirmation>,
    pub privacy_budget_attestations: BTreeMap<String, PrivacyBudgetAttestation>,
    pub non_linkage_attestations: BTreeMap<String, NonLinkageAttestation>,
    pub runbook_bindings: BTreeMap<String, RunbookBinding>,
    pub fail_closed_blockers: BTreeMap<String, FailClosedBlocker>,
    pub audit_events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        ensure_non_zero(current_height, "current height")?;
        Ok(Self {
            config,
            current_height,
            evidence_imports: BTreeMap::new(),
            pq_quorum_reviews: BTreeMap::new(),
            key_epoch_reviews: BTreeMap::new(),
            reserve_confirmations: BTreeMap::new(),
            privacy_budget_attestations: BTreeMap::new(),
            non_linkage_attestations: BTreeMap::new(),
            runbook_bindings: BTreeMap::new(),
            fail_closed_blockers: BTreeMap::new(),
            audit_events: Vec::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let config = Config::devnet();
        let mut state = Self::new(config.clone(), 1_000)?;
        let batch_root = runtime_id(
            "DEVNET-LIVE-EVIDENCE-BATCH",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.runbook_package_id),
            ],
        );
        let pq_evidence = EvidenceImport::new(
            EvidenceDomain::PqQuorum,
            "operator-live-evidence-ingest",
            &batch_root,
            runtime_id("DEVNET-PQ-ARTIFACT", &[HashPart::Str("pq-quorum")]),
            runtime_id("DEVNET-PQ-ACCEPTANCE", &[HashPart::Str("accepted")]),
            "release-auditor-pq",
            990,
            986,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "pq-auditor-1".to_string(),
                "pq-auditor-2".to_string(),
                "pq-auditor-3".to_string(),
            ],
            &json!({"gate": "pq_quorum_review", "source": "devnet"}),
        )?;
        let key_evidence = EvidenceImport::new(
            EvidenceDomain::KeyEpoch,
            "operator-live-evidence-ingest",
            &batch_root,
            runtime_id("DEVNET-KEY-EPOCH-ARTIFACT", &[HashPart::Str("epoch")]),
            runtime_id("DEVNET-KEY-EPOCH-ACCEPTANCE", &[HashPart::Str("accepted")]),
            "release-auditor-key-epoch",
            991,
            987,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "key-auditor-1".to_string(),
                "key-auditor-2".to_string(),
                "key-auditor-3".to_string(),
            ],
            &json!({"gate": "key_epoch_review", "source": "devnet"}),
        )?;
        let reserve_evidence = EvidenceImport::new(
            EvidenceDomain::ReserveCoverage,
            "reserve-proof-feed",
            &batch_root,
            runtime_id("DEVNET-RESERVE-ARTIFACT", &[HashPart::Str("coverage")]),
            runtime_id("DEVNET-RESERVE-ACCEPTANCE", &[HashPart::Str("accepted")]),
            "release-auditor-reserve",
            992,
            988,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "reserve-auditor-1".to_string(),
                "reserve-auditor-2".to_string(),
                "reserve-auditor-3".to_string(),
            ],
            &json!({"gate": "reserve_coverage_confirmation", "source": "devnet"}),
        )?;
        let privacy_evidence = EvidenceImport::new(
            EvidenceDomain::PrivacyBudget,
            "privacy-budget-feed",
            &batch_root,
            runtime_id("DEVNET-PRIVACY-ARTIFACT", &[HashPart::Str("budget")]),
            runtime_id("DEVNET-PRIVACY-ACCEPTANCE", &[HashPart::Str("accepted")]),
            "release-auditor-privacy",
            993,
            989,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "privacy-auditor-1".to_string(),
                "privacy-auditor-2".to_string(),
                "privacy-auditor-3".to_string(),
            ],
            &json!({"gate": "privacy_budget_attestation", "source": "devnet"}),
        )?;
        let non_linkage_evidence = EvidenceImport::new(
            EvidenceDomain::NonLinkage,
            "non-linkage-feed",
            &batch_root,
            runtime_id("DEVNET-NON-LINKAGE-ARTIFACT", &[HashPart::Str("probe")]),
            runtime_id(
                "DEVNET-NON-LINKAGE-ACCEPTANCE",
                &[HashPart::Str("accepted")],
            ),
            "release-auditor-non-linkage",
            994,
            990,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "non-linkage-auditor-1".to_string(),
                "non-linkage-auditor-2".to_string(),
                "non-linkage-auditor-3".to_string(),
            ],
            &json!({"gate": "non_linkage_attestation", "source": "devnet"}),
        )?;
        let runbook_evidence = EvidenceImport::new(
            EvidenceDomain::RunbookOperator,
            "runbook-binding-feed",
            &batch_root,
            runtime_id("DEVNET-RUNBOOK-ARTIFACT", &[HashPart::Str("binding")]),
            runtime_id("DEVNET-RUNBOOK-ACCEPTANCE", &[HashPart::Str("accepted")]),
            "release-auditor-runbook",
            995,
            991,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "runbook-auditor-1".to_string(),
                "runbook-auditor-2".to_string(),
                "runbook-auditor-3".to_string(),
            ],
            &json!({"gate": "operator_runbook_binding", "source": "devnet"}),
        )?;
        let dashboard_evidence = EvidenceImport::new(
            EvidenceDomain::ReleaseDashboard,
            "release-dashboard-live-import",
            &batch_root,
            runtime_id(
                "DEVNET-DASHBOARD-ARTIFACT",
                &[HashPart::Str("dashboard-readiness")],
            ),
            runtime_id("DEVNET-DASHBOARD-ACCEPTANCE", &[HashPart::Str("accepted")]),
            "release-auditor-dashboard",
            996,
            992,
            STATUS_ACCEPTED,
            "notice",
            vec![
                "dashboard-auditor-1".to_string(),
                "dashboard-auditor-2".to_string(),
                "dashboard-auditor-3".to_string(),
            ],
            &json!({"gate": "release_dashboard_import", "source": "devnet"}),
        )?;
        state.import_evidence(pq_evidence.clone())?;
        state.import_evidence(key_evidence.clone())?;
        state.import_evidence(reserve_evidence.clone())?;
        state.import_evidence(privacy_evidence.clone())?;
        state.import_evidence(non_linkage_evidence.clone())?;
        state.import_evidence(runbook_evidence.clone())?;
        state.import_evidence(dashboard_evidence)?;
        state.record_pq_quorum_review(PqQuorumReview::new(
            config.expected_key_epoch,
            runtime_id("DEVNET-PQ-QUORUM-ROOT", &[HashPart::Str("ml-dsa")]),
            7,
            8_400,
            config.min_pq_quorum_weight_bps,
            192,
            runtime_id("DEVNET-ML-DSA-POLICY", &[HashPart::Str("ml-dsa-65")]),
            runtime_id("DEVNET-SLH-DSA-FALLBACK", &[HashPart::Str("slh-dsa")]),
            vec![
                "pq-reviewer-1".to_string(),
                "pq-reviewer-2".to_string(),
                "pq-reviewer-3".to_string(),
            ],
            &pq_evidence.evidence_id,
            996,
            true,
        )?)?;
        state.record_key_epoch_review(KeyEpochReview::new(
            config.expected_key_epoch,
            900,
            1_200,
            runtime_id("DEVNET-ROTATION-TRANSCRIPT", &[HashPart::Str("epoch-82")]),
            runtime_id("DEVNET-RETIRED-EPOCH", &[HashPart::Str("epoch-81")]),
            runtime_id("DEVNET-ACTIVE-KEYSET", &[HashPart::Str("epoch-82")]),
            runtime_id("DEVNET-ROLLBACK-DISABLED", &[HashPart::Str("disabled")]),
            &key_evidence.evidence_id,
            "key-epoch-release-auditor",
            997,
            true,
        )?)?;
        state.record_reserve_confirmation(ReserveCoverageConfirmation::new(
            "xmr-atomic-units",
            runtime_id("DEVNET-LIABILITY-ROOT", &[HashPart::Str("claims")]),
            runtime_id("DEVNET-RESERVE-PROOF", &[HashPart::Str("proof")]),
            runtime_id("DEVNET-ORACLE-SNAPSHOT", &[HashPart::Str("snapshot")]),
            115_000_000_000,
            100_000_000_000,
            250,
            &reserve_evidence.evidence_id,
            "reserve-release-auditor",
            998,
            true,
        )?)?;
        state.record_privacy_budget_attestation(PrivacyBudgetAttestation::new(
            "devnet-window-82",
            runtime_id("DEVNET-PRIVATE-NOTE-SET", &[HashPart::Str("notes")]),
            runtime_id("DEVNET-DISCLOSURE-EVENTS", &[HashPart::Str("events")]),
            config.max_privacy_budget_bps,
            1_200,
            256,
            512,
            &privacy_evidence.evidence_id,
            "privacy-release-auditor",
            999,
            true,
        )?)?;
        state.record_non_linkage_attestation(NonLinkageAttestation::new(
            runtime_id("DEVNET-DEPOSIT-NOTE-ROOT", &[HashPart::Str("deposit")]),
            runtime_id("DEVNET-EXIT-CLAIM-ROOT", &[HashPart::Str("exit")]),
            runtime_id("DEVNET-NULLIFIER-SET", &[HashPart::Str("nullifier")]),
            runtime_id("DEVNET-LINKAGE-PROBE", &[HashPart::Str("probe")]),
            0,
            512,
            256,
            &non_linkage_evidence.evidence_id,
            "non-linkage-release-auditor",
            999,
            true,
        )?)?;
        state.record_runbook_binding(RunbookBinding::new(
            &config.operator_id,
            &config.runbook_package_id,
            "wave-82-force-exit-runbook",
            &config.force_exit_package_root,
            &config.release_dashboard_id,
            runtime_id("DEVNET-DASHBOARD-PANEL", &[HashPart::Str("readiness")]),
            runtime_id("DEVNET-EVIDENCE-MANIFEST", &[HashPart::Str("manifest")]),
            runtime_id("DEVNET-COMMAND-RECEIPT", &[HashPart::Str("receipt")]),
            runtime_id("DEVNET-DRY-RUN-RECEIPT", &[HashPart::Str("dry-run")]),
            "operator-release-captain",
            1_000,
            true,
        )?)?;
        state.recompute_fail_closed_blockers()?;
        Ok(state)
    }

    pub fn import_evidence(&mut self, evidence: EvidenceImport) -> Result<String> {
        evidence.validate()?;
        let evidence_id = evidence.evidence_id.clone();
        self.audit_events.push(json!({
            "kind": "operator_runbook_audit_event",
            "event": "evidence_imported",
            "evidence_id": evidence_id,
            "domain": evidence.domain.as_str(),
            "height": self.current_height,
        }));
        self.evidence_imports.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn record_pq_quorum_review(&mut self, review: PqQuorumReview) -> Result<String> {
        review.validate()?;
        self.require_evidence(&review.evidence_id, EvidenceDomain::PqQuorum)?;
        let review_id = review.review_id.clone();
        self.pq_quorum_reviews.insert(review_id.clone(), review);
        Ok(review_id)
    }

    pub fn record_key_epoch_review(&mut self, review: KeyEpochReview) -> Result<String> {
        review.validate()?;
        self.require_evidence(&review.evidence_id, EvidenceDomain::KeyEpoch)?;
        let review_id = review.review_id.clone();
        self.key_epoch_reviews.insert(review_id.clone(), review);
        Ok(review_id)
    }

    pub fn record_reserve_confirmation(
        &mut self,
        confirmation: ReserveCoverageConfirmation,
    ) -> Result<String> {
        confirmation.validate()?;
        self.require_evidence(&confirmation.evidence_id, EvidenceDomain::ReserveCoverage)?;
        let confirmation_id = confirmation.confirmation_id.clone();
        self.reserve_confirmations
            .insert(confirmation_id.clone(), confirmation);
        Ok(confirmation_id)
    }

    pub fn record_privacy_budget_attestation(
        &mut self,
        attestation: PrivacyBudgetAttestation,
    ) -> Result<String> {
        attestation.validate()?;
        self.require_evidence(&attestation.evidence_id, EvidenceDomain::PrivacyBudget)?;
        let attestation_id = attestation.attestation_id.clone();
        self.privacy_budget_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn record_non_linkage_attestation(
        &mut self,
        attestation: NonLinkageAttestation,
    ) -> Result<String> {
        attestation.validate()?;
        self.require_evidence(&attestation.evidence_id, EvidenceDomain::NonLinkage)?;
        let attestation_id = attestation.attestation_id.clone();
        self.non_linkage_attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn record_runbook_binding(&mut self, binding: RunbookBinding) -> Result<String> {
        binding.validate()?;
        let binding_id = binding.binding_id.clone();
        self.runbook_bindings.insert(binding_id.clone(), binding);
        Ok(binding_id)
    }

    pub fn require_evidence(&self, evidence_id: &str, domain: EvidenceDomain) -> Result<()> {
        let evidence = self
            .evidence_imports
            .get(evidence_id)
            .ok_or_else(|| format!("missing evidence import: {evidence_id}"))?;
        if evidence.domain != domain {
            return Err(format!(
                "evidence domain mismatch for {evidence_id}: expected {} got {}",
                domain.as_str(),
                evidence.domain.as_str()
            ));
        }
        if !evidence.is_accepted() {
            return Err(format!("evidence import is not accepted: {evidence_id}"));
        }
        if evidence.attester_ids.len() < self.config.min_attester_count as usize {
            return Err(format!(
                "evidence import has too few attesters: {evidence_id}"
            ));
        }
        Ok(())
    }

    pub fn recompute_fail_closed_blockers(&mut self) -> Result<()> {
        let blockers = self.compute_fail_closed_blockers()?;
        self.fail_closed_blockers = blockers
            .into_iter()
            .map(|blocker| (blocker.blocker_id.clone(), blocker))
            .collect();
        Ok(())
    }

    pub fn compute_fail_closed_blockers(&self) -> Result<Vec<FailClosedBlocker>> {
        let mut blockers = Vec::new();
        self.push_evidence_blockers(&mut blockers)?;
        self.push_review_blockers(&mut blockers)?;
        self.push_binding_blockers(&mut blockers)?;
        Ok(blockers)
    }

    pub fn readiness(&self) -> Result<ReleaseDashboardReadiness> {
        let blockers = self.compute_fail_closed_blockers()?;
        let blocker_root = records_root(
            "OPERATOR-RUNBOOK-BLOCKER-ROOT",
            blockers
                .iter()
                .map(FailClosedBlocker::public_record)
                .collect(),
        );
        let ready = blockers.iter().all(|blocker| !blocker.blocking);
        let ready_gate_count = self.ready_gate_count();
        let status = if ready {
            STATUS_READY
        } else {
            STATUS_FAIL_CLOSED
        }
        .to_string();
        let config_root = self.config.config_root();
        let evidence_root = self.evidence_root();
        let pq_review_root = self.pq_quorum_review_root();
        let key_epoch_review_root = self.key_epoch_review_root();
        let reserve_confirmation_root = self.reserve_confirmation_root();
        let privacy_budget_root = self.privacy_budget_root();
        let non_linkage_root = self.non_linkage_root();
        let runbook_binding_root = self.runbook_binding_root();
        let readiness_id = runtime_id(
            "RELEASE-DASHBOARD-READINESS-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.config.release_dashboard_id),
                HashPart::Str(&config_root),
                HashPart::Str(&evidence_root),
                HashPart::Str(&blocker_root),
            ],
        );
        Ok(ReleaseDashboardReadiness {
            readiness_id,
            release_dashboard_id: self.config.release_dashboard_id.clone(),
            current_height: self.current_height,
            config_root,
            evidence_root,
            pq_review_root,
            key_epoch_review_root,
            reserve_confirmation_root,
            privacy_budget_root,
            non_linkage_root,
            runbook_binding_root,
            blocker_root,
            ready,
            status,
            ready_gate_count,
            blocker_count: blockers.len() as u64,
        })
    }

    pub fn assert_release_dashboard_ready(&self) -> Result<String> {
        let readiness = self.readiness()?;
        if !readiness.ready {
            return Err(format!(
                "release dashboard is fail-closed with {} blocker(s)",
                readiness.blocker_count
            ));
        }
        Ok(readiness.readiness_id)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let readiness = self.readiness().ok().map(|value| value.public_record());
        json!({
            "kind": "operator_runbook_audit_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "readiness": readiness,
            "evidence_imports": self.evidence_imports.values().map(EvidenceImport::public_record).collect::<Vec<_>>(),
            "pq_quorum_reviews": self.pq_quorum_reviews.values().map(PqQuorumReview::public_record).collect::<Vec<_>>(),
            "key_epoch_reviews": self.key_epoch_reviews.values().map(KeyEpochReview::public_record).collect::<Vec<_>>(),
            "reserve_confirmations": self.reserve_confirmations.values().map(ReserveCoverageConfirmation::public_record).collect::<Vec<_>>(),
            "privacy_budget_attestations": self.privacy_budget_attestations.values().map(PrivacyBudgetAttestation::public_record).collect::<Vec<_>>(),
            "non_linkage_attestations": self.non_linkage_attestations.values().map(NonLinkageAttestation::public_record).collect::<Vec<_>>(),
            "runbook_bindings": self.runbook_bindings.values().map(RunbookBinding::public_record).collect::<Vec<_>>(),
            "fail_closed_blockers": self.fail_closed_blockers.values().map(FailClosedBlocker::public_record).collect::<Vec<_>>(),
            "audit_events": self.audit_events,
            "roots": {
                "evidence_root": self.evidence_root(),
                "pq_quorum_review_root": self.pq_quorum_review_root(),
                "key_epoch_review_root": self.key_epoch_review_root(),
                "reserve_confirmation_root": self.reserve_confirmation_root(),
                "privacy_budget_root": self.privacy_budget_root(),
                "non_linkage_root": self.non_linkage_root(),
                "runbook_binding_root": self.runbook_binding_root(),
                "blocker_root": self.blocker_root(),
                "audit_event_root": self.audit_event_root(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "OPERATOR-RUNBOOK-AUDIT-STATE",
            &self.public_record_without_root(),
        )
    }

    pub fn evidence_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-EVIDENCE-ROOT",
            self.evidence_imports
                .values()
                .map(EvidenceImport::public_record)
                .collect(),
        )
    }

    pub fn pq_quorum_review_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-PQ-REVIEW-ROOT",
            self.pq_quorum_reviews
                .values()
                .map(PqQuorumReview::public_record)
                .collect(),
        )
    }

    pub fn key_epoch_review_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-KEY-EPOCH-ROOT",
            self.key_epoch_reviews
                .values()
                .map(KeyEpochReview::public_record)
                .collect(),
        )
    }

    pub fn reserve_confirmation_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-RESERVE-ROOT",
            self.reserve_confirmations
                .values()
                .map(ReserveCoverageConfirmation::public_record)
                .collect(),
        )
    }

    pub fn privacy_budget_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-PRIVACY-BUDGET-ROOT",
            self.privacy_budget_attestations
                .values()
                .map(PrivacyBudgetAttestation::public_record)
                .collect(),
        )
    }

    pub fn non_linkage_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-NON-LINKAGE-ROOT",
            self.non_linkage_attestations
                .values()
                .map(NonLinkageAttestation::public_record)
                .collect(),
        )
    }

    pub fn runbook_binding_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-BINDING-ROOT",
            self.runbook_bindings
                .values()
                .map(RunbookBinding::public_record)
                .collect(),
        )
    }

    pub fn blocker_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-BLOCKER-ROOT",
            self.fail_closed_blockers
                .values()
                .map(FailClosedBlocker::public_record)
                .collect(),
        )
    }

    pub fn audit_event_root(&self) -> String {
        records_root(
            "OPERATOR-RUNBOOK-AUDIT-EVENT-ROOT",
            self.audit_events.clone(),
        )
    }

    fn push_evidence_blockers(&self, blockers: &mut Vec<FailClosedBlocker>) -> Result<()> {
        for domain in ACCEPTED_DOMAINS {
            let accepted = self
                .evidence_imports
                .values()
                .filter(|evidence| evidence.domain == *domain)
                .filter(|evidence| evidence.is_accepted())
                .collect::<Vec<_>>();
            if accepted.is_empty() {
                blockers.push(FailClosedBlocker::new(
                    BlockerKind::MissingEvidence,
                    domain.release_gate_name(),
                    None,
                    format!("missing accepted live evidence for {}", domain.as_str()),
                    self.current_height,
                )?);
                continue;
            }
            for evidence in accepted {
                if evidence.is_stale(self.current_height, self.config.max_evidence_age_blocks) {
                    blockers.push(FailClosedBlocker::new(
                        BlockerKind::StaleEvidence,
                        domain.release_gate_name(),
                        Some(evidence.evidence_id.clone()),
                        format!("accepted evidence is stale for {}", domain.as_str()),
                        self.current_height,
                    )?);
                }
                if evidence.attester_ids.len() < self.config.min_attester_count as usize {
                    blockers.push(FailClosedBlocker::new(
                        BlockerKind::MissingEvidence,
                        domain.release_gate_name(),
                        Some(evidence.evidence_id.clone()),
                        format!(
                            "accepted evidence lacks attester quorum for {}",
                            domain.as_str()
                        ),
                        self.current_height,
                    )?);
                }
                if self.config.fail_closed_on_warning && evidence.is_warning_or_critical() {
                    blockers.push(FailClosedBlocker::new(
                        BlockerKind::RejectedEvidence,
                        domain.release_gate_name(),
                        Some(evidence.evidence_id.clone()),
                        format!(
                            "warning or critical evidence must be resolved for {}",
                            domain.as_str()
                        ),
                        self.current_height,
                    )?);
                }
            }
        }
        for evidence in self.evidence_imports.values() {
            if !evidence.is_accepted() {
                blockers.push(FailClosedBlocker::new(
                    BlockerKind::RejectedEvidence,
                    evidence.domain.release_gate_name(),
                    Some(evidence.evidence_id.clone()),
                    format!("evidence status is {}", evidence.status),
                    self.current_height,
                )?);
            }
        }
        Ok(())
    }

    fn push_review_blockers(&self, blockers: &mut Vec<FailClosedBlocker>) -> Result<()> {
        if !self
            .pq_quorum_reviews
            .values()
            .any(|review| review.satisfies(&self.config))
        {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::PqQuorumShortfall,
                EvidenceDomain::PqQuorum.release_gate_name(),
                self.pq_quorum_reviews
                    .values()
                    .next()
                    .map(|review| review.evidence_id.clone()),
                "pq quorum/key security review does not satisfy release policy",
                self.current_height,
            )?);
        }
        if !self
            .key_epoch_reviews
            .values()
            .any(|review| review.satisfies(&self.config, self.current_height))
        {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::KeyEpochMismatch,
                EvidenceDomain::KeyEpoch.release_gate_name(),
                self.key_epoch_reviews
                    .values()
                    .next()
                    .map(|review| review.evidence_id.clone()),
                "accepted key epoch review does not cover current release height",
                self.current_height,
            )?);
        }
        if !self
            .reserve_confirmations
            .values()
            .any(|confirmation| confirmation.satisfies(&self.config))
        {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::ReserveUnderCovered,
                EvidenceDomain::ReserveCoverage.release_gate_name(),
                self.reserve_confirmations
                    .values()
                    .next()
                    .map(|confirmation| confirmation.evidence_id.clone()),
                "reserve coverage confirmation is below release threshold",
                self.current_height,
            )?);
        }
        if !self
            .privacy_budget_attestations
            .values()
            .any(|attestation| attestation.satisfies(&self.config))
        {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::PrivacyBudgetExceeded,
                EvidenceDomain::PrivacyBudget.release_gate_name(),
                self.privacy_budget_attestations
                    .values()
                    .next()
                    .map(|attestation| attestation.evidence_id.clone()),
                "privacy budget attestation exceeds release threshold",
                self.current_height,
            )?);
        }
        if !self
            .non_linkage_attestations
            .values()
            .any(|attestation| attestation.satisfies(&self.config))
        {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::LinkageRisk,
                EvidenceDomain::NonLinkage.release_gate_name(),
                self.non_linkage_attestations
                    .values()
                    .next()
                    .map(|attestation| attestation.evidence_id.clone()),
                "non-linkage attestation does not clear linkage risk",
                self.current_height,
            )?);
        }
        Ok(())
    }

    fn push_binding_blockers(&self, blockers: &mut Vec<FailClosedBlocker>) -> Result<()> {
        if self.runbook_bindings.is_empty() {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::DashboardNotBound,
                EvidenceDomain::RunbookOperator.release_gate_name(),
                None,
                "operator runbook is not bound to release dashboard",
                self.current_height,
            )?);
            return Ok(());
        }
        if !self
            .runbook_bindings
            .values()
            .any(|binding| binding.satisfies(&self.config))
        {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::OperatorRunbookMismatch,
                EvidenceDomain::RunbookOperator.release_gate_name(),
                None,
                "runbook binding does not match configured operator/package/dashboard",
                self.current_height,
            )?);
        }
        Ok(())
    }

    fn ready_gate_count(&self) -> u64 {
        let mut count = 0_u64;
        if self
            .pq_quorum_reviews
            .values()
            .any(|review| review.satisfies(&self.config))
        {
            count += 1;
        }
        if self
            .key_epoch_reviews
            .values()
            .any(|review| review.satisfies(&self.config, self.current_height))
        {
            count += 1;
        }
        if self
            .reserve_confirmations
            .values()
            .any(|confirmation| confirmation.satisfies(&self.config))
        {
            count += 1;
        }
        if self
            .privacy_budget_attestations
            .values()
            .any(|attestation| attestation.satisfies(&self.config))
        {
            count += 1;
        }
        if self
            .non_linkage_attestations
            .values()
            .any(|attestation| attestation.satisfies(&self.config))
        {
            count += 1;
        }
        if self
            .runbook_bindings
            .values()
            .any(|binding| binding.satisfies(&self.config))
        {
            count += 1;
        }
        count
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn evidence_id(
    domain: EvidenceDomain,
    source_system: &str,
    import_batch_id: &str,
    artifact_root: &str,
    acceptance_root: &str,
    accepted_at_height: u64,
) -> String {
    runtime_id(
        "LIVE-EVIDENCE-IMPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain.as_str()),
            HashPart::Str(source_system),
            HashPart::Str(import_batch_id),
            HashPart::Str(artifact_root),
            HashPart::Str(acceptance_root),
            HashPart::Int(accepted_at_height as i128),
        ],
    )
}

pub fn release_dashboard_readiness_record(state: &State) -> Result<Value> {
    Ok(state.readiness()?.public_record())
}

pub fn fail_closed_blocker_records(state: &State) -> Result<Vec<Value>> {
    Ok(state
        .compute_fail_closed_blockers()?
        .iter()
        .map(FailClosedBlocker::public_record)
        .collect())
}

fn runtime_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
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

fn sorted_unique(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_non_zero(value: u64, label: &str) -> Result<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn ensure_non_zero_u128(value: u128, label: &str) -> Result<()> {
    if value == 0 {
        return Err(format!("{label} must be non-zero"));
    }
    Ok(())
}

fn ensure_bps(value: u16, label: &str) -> Result<()> {
    if value > 10_000 {
        return Err(format!("{label} must be <= 10000"));
    }
    Ok(())
}

fn ensure_status(value: &str, label: &str) -> Result<()> {
    ensure_in_set(
        value,
        &[
            STATUS_ACCEPTED,
            STATUS_REJECTED,
            STATUS_PENDING,
            STATUS_BLOCKED,
        ],
        label,
    )
}

fn ensure_in_set(value: &str, accepted: &[&str], label: &str) -> Result<()> {
    if accepted.iter().any(|item| *item == value) {
        return Ok(());
    }
    Err(format!("{label} has unsupported value: {value}"))
}

fn ensure_unique_non_empty(values: &[String], label: &str) -> Result<()> {
    if values.is_empty() {
        return Err(format!("{label} list must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value) {
            return Err(format!("{label} list contains duplicate value"));
        }
    }
    Ok(())
}
