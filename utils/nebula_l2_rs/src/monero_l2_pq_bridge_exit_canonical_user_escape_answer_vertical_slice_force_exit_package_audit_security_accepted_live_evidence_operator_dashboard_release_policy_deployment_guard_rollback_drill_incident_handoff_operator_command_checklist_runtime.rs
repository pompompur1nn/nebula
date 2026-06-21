use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageAuditSecurityAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillIncidentHandoffOperatorCommandChecklistRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-audit-security-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-incident-handoff-operator-command-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_AUDIT_SECURITY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CHECKLIST_SUITE: &str =
    "monero-l2-pq-bridge-force-exit-audit-security-operator-command-checklist-v1";
pub const DEFAULT_HEIGHT: u64 = 96_087;
pub const DEFAULT_MIN_THREAT_MODEL_ITEMS: u64 = 6;
pub const DEFAULT_MIN_PRIVACY_BLOCKERS: u64 = 6;
pub const DEFAULT_MIN_SIGNER_QUORUM_REVIEWS: u64 = 4;
pub const DEFAULT_MIN_DEFERRED_AUDIT_PLACEHOLDERS: u64 = 3;
pub const DEFAULT_MIN_INCIDENT_COMMANDER_SIGNOFFS: u64 = 3;
pub const DEFAULT_MIN_RELEASE_AUTHORITY_GATES: u64 = 4;
pub const DEFAULT_MAX_OPEN_CHECKLIST_BLOCKERS: u64 = 0;
pub const DEFAULT_MAX_PRIVACY_LEAKS: u64 = 0;
pub const DEFAULT_MAX_UNSIGNED_SIGNOFFS: u64 = 0;
pub const DEFAULT_MAX_RECORDS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistLane {
    ThreatModelItem,
    PrivacyLeakBlocker,
    SignerQuorumReview,
    DeferredAuditPlaceholder,
    IncidentCommanderSignoff,
    ReleaseAuthorityGate,
    OperatorChecklistVerdict,
}

impl ChecklistLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThreatModelItem => "threat_model_item",
            Self::PrivacyLeakBlocker => "privacy_leak_blocker",
            Self::SignerQuorumReview => "signer_quorum_review",
            Self::DeferredAuditPlaceholder => "deferred_audit_placeholder",
            Self::IncidentCommanderSignoff => "incident_commander_signoff",
            Self::ReleaseAuthorityGate => "release_authority_gate",
            Self::OperatorChecklistVerdict => "operator_checklist_verdict",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistBlockerKind {
    MissingThreatModelItem,
    OpenThreatModelItem,
    MissingPrivacyLeakBlocker,
    PrivacyLeakUnresolved,
    MissingSignerQuorumReview,
    SignerQuorumRejected,
    MissingDeferredAuditPlaceholder,
    DeferredAuditPlaceholderUnowned,
    MissingIncidentCommanderSignoff,
    IncidentCommanderSignoffUnsigned,
    MissingReleaseAuthorityGate,
    ReleaseAuthorityNotFailClosed,
    ReleaseAuthorityEscalated,
    RawPrivateMaterialReferenced,
    HandoffRootMismatch,
}

impl ChecklistBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingThreatModelItem => "missing_threat_model_item",
            Self::OpenThreatModelItem => "open_threat_model_item",
            Self::MissingPrivacyLeakBlocker => "missing_privacy_leak_blocker",
            Self::PrivacyLeakUnresolved => "privacy_leak_unresolved",
            Self::MissingSignerQuorumReview => "missing_signer_quorum_review",
            Self::SignerQuorumRejected => "signer_quorum_rejected",
            Self::MissingDeferredAuditPlaceholder => "missing_deferred_audit_placeholder",
            Self::DeferredAuditPlaceholderUnowned => "deferred_audit_placeholder_unowned",
            Self::MissingIncidentCommanderSignoff => "missing_incident_commander_signoff",
            Self::IncidentCommanderSignoffUnsigned => "incident_commander_signoff_unsigned",
            Self::MissingReleaseAuthorityGate => "missing_release_authority_gate",
            Self::ReleaseAuthorityNotFailClosed => "release_authority_not_fail_closed",
            Self::ReleaseAuthorityEscalated => "release_authority_escalated",
            Self::RawPrivateMaterialReferenced => "raw_private_material_referenced",
            Self::HandoffRootMismatch => "handoff_root_mismatch",
        }
    }

    pub fn fail_closed(self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistStatus {
    Satisfied,
    Mitigated,
    DeferredWithOwner,
    Open,
}

impl ChecklistStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Mitigated => "mitigated",
            Self::DeferredWithOwner => "deferred_with_owner",
            Self::Open => "open",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBoundary {
    MoneroAddress,
    PrivatePayload,
    RouteMetadata,
    SignerKeyMaterial,
    OperatorDashboardExport,
    IncidentArchive,
}

impl PrivacyBoundary {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroAddress => "monero_address",
            Self::PrivatePayload => "private_payload",
            Self::RouteMetadata => "route_metadata",
            Self::SignerKeyMaterial => "signer_key_material",
            Self::OperatorDashboardExport => "operator_dashboard_export",
            Self::IncidentArchive => "incident_archive",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseAuthority {
    FreezeReleaseWindow,
    DisableExitPublication,
    RequireSecurityReacceptance,
    RequireCommanderAck,
    SealAuditArchive,
    RevokeOperatorOverride,
}

impl ReleaseAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreezeReleaseWindow => "freeze_release_window",
            Self::DisableExitPublication => "disable_exit_publication",
            Self::RequireSecurityReacceptance => "require_security_reacceptance",
            Self::RequireCommanderAck => "require_commander_ack",
            Self::SealAuditArchive => "seal_audit_archive",
            Self::RevokeOperatorOverride => "revoke_operator_override",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistVerdictKind {
    ReleaseAuthorized,
    HoldFailClosed,
}

impl ChecklistVerdictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseAuthorized => "release_authorized",
            Self::HoldFailClosed => "hold_fail_closed",
        }
    }

    pub fn allows_release(self) -> bool {
        matches!(self, Self::ReleaseAuthorized)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub checklist_suite: String,
    pub checklist_id: String,
    pub incident_handoff_root: String,
    pub rollback_drill_root: String,
    pub release_policy_root: String,
    pub operator_dashboard_root: String,
    pub height: u64,
    pub min_threat_model_items: u64,
    pub min_privacy_blockers: u64,
    pub min_signer_quorum_reviews: u64,
    pub min_deferred_audit_placeholders: u64,
    pub min_incident_commander_signoffs: u64,
    pub min_release_authority_gates: u64,
    pub max_open_checklist_blockers: u64,
    pub max_privacy_leaks: u64,
    pub max_unsigned_signoffs: u64,
    pub max_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            checklist_suite: CHECKLIST_SUITE.to_string(),
            checklist_id: stable_id("operator-command-checklist", "wave87-devnet"),
            incident_handoff_root: fixture_root("wave86-incident-handoff-root"),
            rollback_drill_root: fixture_root("wave85-rollback-drill-root"),
            release_policy_root: fixture_root("wave84-release-policy-root"),
            operator_dashboard_root: fixture_root("wave84-operator-dashboard-root"),
            height: DEFAULT_HEIGHT,
            min_threat_model_items: DEFAULT_MIN_THREAT_MODEL_ITEMS,
            min_privacy_blockers: DEFAULT_MIN_PRIVACY_BLOCKERS,
            min_signer_quorum_reviews: DEFAULT_MIN_SIGNER_QUORUM_REVIEWS,
            min_deferred_audit_placeholders: DEFAULT_MIN_DEFERRED_AUDIT_PLACEHOLDERS,
            min_incident_commander_signoffs: DEFAULT_MIN_INCIDENT_COMMANDER_SIGNOFFS,
            min_release_authority_gates: DEFAULT_MIN_RELEASE_AUTHORITY_GATES,
            max_open_checklist_blockers: DEFAULT_MAX_OPEN_CHECKLIST_BLOCKERS,
            max_privacy_leaks: DEFAULT_MAX_PRIVACY_LEAKS,
            max_unsigned_signoffs: DEFAULT_MAX_UNSIGNED_SIGNOFFS,
            max_records: DEFAULT_MAX_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "checklist_suite": self.checklist_suite,
            "checklist_id": self.checklist_id,
            "incident_handoff_root": self.incident_handoff_root,
            "rollback_drill_root": self.rollback_drill_root,
            "release_policy_root": self.release_policy_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "height": self.height,
            "min_threat_model_items": self.min_threat_model_items,
            "min_privacy_blockers": self.min_privacy_blockers,
            "min_signer_quorum_reviews": self.min_signer_quorum_reviews,
            "min_deferred_audit_placeholders": self.min_deferred_audit_placeholders,
            "min_incident_commander_signoffs": self.min_incident_commander_signoffs,
            "min_release_authority_gates": self.min_release_authority_gates,
            "max_open_checklist_blockers": self.max_open_checklist_blockers,
            "max_privacy_leaks": self.max_privacy_leaks,
            "max_unsigned_signoffs": self.max_unsigned_signoffs,
            "max_records": self.max_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR-COMMAND-CHECKLIST-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("checklist_id", &self.checklist_id)?;
        ensure_root("incident_handoff_root", &self.incident_handoff_root)?;
        ensure_root("rollback_drill_root", &self.rollback_drill_root)?;
        ensure_root("release_policy_root", &self.release_policy_root)?;
        ensure_root("operator_dashboard_root", &self.operator_dashboard_root)?;
        if self.schema_version != SCHEMA_VERSION {
            Err("unsupported operator command checklist schema version".to_string())
        } else if self.max_records == 0 {
            Err("max_records must be greater than zero".to_string())
        } else {
            Ok(())
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThreatModelChecklistItem {
    pub item_id: String,
    pub handoff_root: String,
    pub threat_area: String,
    pub checklist_root: String,
    pub mitigation_root: String,
    pub owner_commitment_root: String,
    pub status: ChecklistStatus,
}

impl ThreatModelChecklistItem {
    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "handoff_root": self.handoff_root,
            "threat_area": self.threat_area,
            "checklist_root": self.checklist_root,
            "mitigation_root": self.mitigation_root,
            "owner_commitment_root": self.owner_commitment_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-THREAT-MODEL-ITEM",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("item_id", &self.item_id)?;
        ensure_non_empty("threat_area", &self.threat_area)?;
        ensure_root("handoff_root", &self.handoff_root)?;
        ensure_root("checklist_root", &self.checklist_root)?;
        ensure_root("mitigation_root", &self.mitigation_root)?;
        ensure_root("owner_commitment_root", &self.owner_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyLeakBlocker {
    pub blocker_id: String,
    pub boundary: PrivacyBoundary,
    pub sanitized_subject_root: String,
    pub evidence_redaction_root: String,
    pub blocker_root: String,
    pub leak_confirmed: bool,
    pub resolved: bool,
}

impl PrivacyLeakBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "boundary": self.boundary.as_str(),
            "sanitized_subject_root": self.sanitized_subject_root,
            "evidence_redaction_root": self.evidence_redaction_root,
            "blocker_root": self.blocker_root,
            "leak_confirmed": self.leak_confirmed,
            "resolved": self.resolved,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-PRIVACY-LEAK-BLOCKER",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("blocker_id", &self.blocker_id)?;
        ensure_root("sanitized_subject_root", &self.sanitized_subject_root)?;
        ensure_root("evidence_redaction_root", &self.evidence_redaction_root)?;
        ensure_root("blocker_root", &self.blocker_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SignerQuorumReview {
    pub review_id: String,
    pub command_root: String,
    pub signer_set_root: String,
    pub quorum_attestation_root: String,
    pub required_signers: u64,
    pub observed_signers: u64,
    pub accepted: bool,
}

impl SignerQuorumReview {
    pub fn public_record(&self) -> Value {
        json!({
            "review_id": self.review_id,
            "command_root": self.command_root,
            "signer_set_root": self.signer_set_root,
            "quorum_attestation_root": self.quorum_attestation_root,
            "required_signers": self.required_signers,
            "observed_signers": self.observed_signers,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-SIGNER-QUORUM-REVIEW",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("review_id", &self.review_id)?;
        ensure_root("command_root", &self.command_root)?;
        ensure_root("signer_set_root", &self.signer_set_root)?;
        ensure_root("quorum_attestation_root", &self.quorum_attestation_root)?;
        if self.required_signers == 0 {
            Err("required_signers must be greater than zero".to_string())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeferredAuditPlaceholder {
    pub placeholder_id: String,
    pub scope_root: String,
    pub deferral_reason_root: String,
    pub owner_root: String,
    pub due_height: u64,
    pub sealed: bool,
}

impl DeferredAuditPlaceholder {
    pub fn public_record(&self) -> Value {
        json!({
            "placeholder_id": self.placeholder_id,
            "scope_root": self.scope_root,
            "deferral_reason_root": self.deferral_reason_root,
            "owner_root": self.owner_root,
            "due_height": self.due_height,
            "sealed": self.sealed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-DEFERRED-AUDIT-PLACEHOLDER",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("placeholder_id", &self.placeholder_id)?;
        ensure_root("scope_root", &self.scope_root)?;
        ensure_root("deferral_reason_root", &self.deferral_reason_root)?;
        ensure_root("owner_root", &self.owner_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncidentCommanderSignoff {
    pub signoff_id: String,
    pub commander_role: String,
    pub commander_commitment_root: String,
    pub checklist_root: String,
    pub signed_at_height: u64,
    pub signed: bool,
}

impl IncidentCommanderSignoff {
    pub fn public_record(&self) -> Value {
        json!({
            "signoff_id": self.signoff_id,
            "commander_role": self.commander_role,
            "commander_commitment_root": self.commander_commitment_root,
            "checklist_root": self.checklist_root,
            "signed_at_height": self.signed_at_height,
            "signed": self.signed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-INCIDENT-COMMANDER-SIGNOFF",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("signoff_id", &self.signoff_id)?;
        ensure_non_empty("commander_role", &self.commander_role)?;
        ensure_root("commander_commitment_root", &self.commander_commitment_root)?;
        ensure_root("checklist_root", &self.checklist_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseAuthorityGate {
    pub gate_id: String,
    pub authority: ReleaseAuthority,
    pub command_root: String,
    pub policy_root: String,
    pub authority_root: String,
    pub fail_closed: bool,
    pub escalation_open: bool,
}

impl ReleaseAuthorityGate {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "authority": self.authority.as_str(),
            "command_root": self.command_root,
            "policy_root": self.policy_root,
            "authority_root": self.authority_root,
            "fail_closed": self.fail_closed,
            "escalation_open": self.escalation_open,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-RELEASE-AUTHORITY-GATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("gate_id", &self.gate_id)?;
        ensure_root("command_root", &self.command_root)?;
        ensure_root("policy_root", &self.policy_root)?;
        ensure_root("authority_root", &self.authority_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChecklistCounters {
    pub threat_model_items: u64,
    pub open_threat_model_items: u64,
    pub privacy_blockers: u64,
    pub unresolved_privacy_leaks: u64,
    pub signer_quorum_reviews: u64,
    pub accepted_signer_quorum_reviews: u64,
    pub deferred_audit_placeholders: u64,
    pub owned_deferred_audit_placeholders: u64,
    pub incident_commander_signoffs: u64,
    pub signed_incident_commander_signoffs: u64,
    pub release_authority_gates: u64,
    pub fail_closed_release_authority_gates: u64,
    pub release_authority_escalations: u64,
    pub unsigned_signoffs: u64,
    pub fail_closed_blockers: u64,
}

impl ChecklistCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "threat_model_items": self.threat_model_items,
            "open_threat_model_items": self.open_threat_model_items,
            "privacy_blockers": self.privacy_blockers,
            "unresolved_privacy_leaks": self.unresolved_privacy_leaks,
            "signer_quorum_reviews": self.signer_quorum_reviews,
            "accepted_signer_quorum_reviews": self.accepted_signer_quorum_reviews,
            "deferred_audit_placeholders": self.deferred_audit_placeholders,
            "owned_deferred_audit_placeholders": self.owned_deferred_audit_placeholders,
            "incident_commander_signoffs": self.incident_commander_signoffs,
            "signed_incident_commander_signoffs": self.signed_incident_commander_signoffs,
            "release_authority_gates": self.release_authority_gates,
            "fail_closed_release_authority_gates": self.fail_closed_release_authority_gates,
            "release_authority_escalations": self.release_authority_escalations,
            "unsigned_signoffs": self.unsigned_signoffs,
            "fail_closed_blockers": self.fail_closed_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR-COMMAND-CHECKLIST-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorChecklistVerdict {
    pub verdict: ChecklistVerdictKind,
    pub release_allowed: bool,
    pub fail_closed: bool,
    pub incident_handoff_root: String,
    pub blocker_root: String,
    pub lane_root: String,
    pub release_authority_root: String,
    pub commander_signoff_root: String,
}

impl OperatorChecklistVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
            "incident_handoff_root": self.incident_handoff_root,
            "blocker_root": self.blocker_root,
            "lane_root": self.lane_root,
            "release_authority_root": self.release_authority_root,
            "commander_signoff_root": self.commander_signoff_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR-COMMAND-CHECKLIST-VERDICT", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_root("incident_handoff_root", &self.incident_handoff_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        ensure_root("lane_root", &self.lane_root)?;
        ensure_root("release_authority_root", &self.release_authority_root)?;
        ensure_root("commander_signoff_root", &self.commander_signoff_root)?;
        if self.release_allowed && !self.fail_closed {
            Err("release cannot be allowed without fail-closed authority".to_string())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub threat_model_items: BTreeMap<String, ThreatModelChecklistItem>,
    pub privacy_leak_blockers: BTreeMap<String, PrivacyLeakBlocker>,
    pub signer_quorum_reviews: BTreeMap<String, SignerQuorumReview>,
    pub deferred_audit_placeholders: BTreeMap<String, DeferredAuditPlaceholder>,
    pub incident_commander_signoffs: BTreeMap<String, IncidentCommanderSignoff>,
    pub release_authority_gates: BTreeMap<String, ReleaseAuthorityGate>,
    pub lane_roots: BTreeMap<String, String>,
    pub blockers: BTreeMap<String, Vec<ChecklistBlockerKind>>,
    pub counters: ChecklistCounters,
    pub verdict: OperatorChecklistVerdict,
}

impl State {
    pub fn new(
        config: Config,
        threat_model_items: BTreeMap<String, ThreatModelChecklistItem>,
        privacy_leak_blockers: BTreeMap<String, PrivacyLeakBlocker>,
        signer_quorum_reviews: BTreeMap<String, SignerQuorumReview>,
        deferred_audit_placeholders: BTreeMap<String, DeferredAuditPlaceholder>,
        incident_commander_signoffs: BTreeMap<String, IncidentCommanderSignoff>,
        release_authority_gates: BTreeMap<String, ReleaseAuthorityGate>,
    ) -> Result<Self> {
        config.validate()?;
        ensure_capacity(threat_model_items.len(), config.max_records)?;
        ensure_capacity(privacy_leak_blockers.len(), config.max_records)?;
        ensure_capacity(signer_quorum_reviews.len(), config.max_records)?;
        ensure_capacity(deferred_audit_placeholders.len(), config.max_records)?;
        ensure_capacity(incident_commander_signoffs.len(), config.max_records)?;
        ensure_capacity(release_authority_gates.len(), config.max_records)?;
        validate_records(&threat_model_items, ThreatModelChecklistItem::validate)?;
        validate_records(&privacy_leak_blockers, PrivacyLeakBlocker::validate)?;
        validate_records(&signer_quorum_reviews, SignerQuorumReview::validate)?;
        validate_records(
            &deferred_audit_placeholders,
            DeferredAuditPlaceholder::validate,
        )?;
        validate_records(
            &incident_commander_signoffs,
            IncidentCommanderSignoff::validate,
        )?;
        validate_records(&release_authority_gates, ReleaseAuthorityGate::validate)?;

        let counters = build_counters(
            &threat_model_items,
            &privacy_leak_blockers,
            &signer_quorum_reviews,
            &deferred_audit_placeholders,
            &incident_commander_signoffs,
            &release_authority_gates,
        );
        let blockers = build_blockers(&config, &counters);
        let lane_roots = build_lane_roots(
            &config,
            &threat_model_items,
            &privacy_leak_blockers,
            &signer_quorum_reviews,
            &deferred_audit_placeholders,
            &incident_commander_signoffs,
            &release_authority_gates,
            &counters,
        );
        let verdict = build_verdict(&config, &blockers, &lane_roots, &counters);
        verdict.validate()?;

        Ok(Self {
            config,
            threat_model_items,
            privacy_leak_blockers,
            signer_quorum_reviews,
            deferred_audit_placeholders,
            incident_commander_signoffs,
            release_authority_gates,
            lane_roots,
            blockers,
            counters,
            verdict,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        match Self::new(
            config.clone(),
            devnet_threat_model_items(&config),
            devnet_privacy_leak_blockers(),
            devnet_signer_quorum_reviews(),
            devnet_deferred_audit_placeholders(),
            devnet_incident_commander_signoffs(),
            devnet_release_authority_gates(),
        ) {
            Ok(state) => state,
            Err(error) => fail_closed_state(error),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "threat_model_items": records_map(
                &self.threat_model_items,
                ThreatModelChecklistItem::public_record
            ),
            "privacy_leak_blockers": records_map(
                &self.privacy_leak_blockers,
                PrivacyLeakBlocker::public_record
            ),
            "signer_quorum_reviews": records_map(
                &self.signer_quorum_reviews,
                SignerQuorumReview::public_record
            ),
            "deferred_audit_placeholders": records_map(
                &self.deferred_audit_placeholders,
                DeferredAuditPlaceholder::public_record
            ),
            "incident_commander_signoffs": records_map(
                &self.incident_commander_signoffs,
                IncidentCommanderSignoff::public_record
            ),
            "release_authority_gates": records_map(
                &self.release_authority_gates,
                ReleaseAuthorityGate::public_record
            ),
            "lane_roots": self.lane_roots,
            "blockers": blockers_record(&self.blockers),
            "counters": self.counters.public_record(),
            "verdict": self.verdict.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR-COMMAND-CHECKLIST-STATE", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        let rebuilt = Self::new(
            self.config.clone(),
            self.threat_model_items.clone(),
            self.privacy_leak_blockers.clone(),
            self.signer_quorum_reviews.clone(),
            self.deferred_audit_placeholders.clone(),
            self.incident_commander_signoffs.clone(),
            self.release_authority_gates.clone(),
        )?;
        if rebuilt.state_root() != self.state_root() {
            Err("operator command checklist state root mismatch".to_string())
        } else {
            Ok(())
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

fn devnet_threat_model_items(config: &Config) -> BTreeMap<String, ThreatModelChecklistItem> {
    let areas = [
        "escape_route_authority",
        "force_exit_delay_surface",
        "audit_evidence_redaction",
        "operator_override_revocation",
        "rollback_command_replay",
        "dashboard_export_minimization",
    ];
    areas
        .iter()
        .enumerate()
        .map(|(index, area)| {
            let item_id = stable_id("threat-model-item", &format!("wave87-{index}"));
            (
                item_id.clone(),
                ThreatModelChecklistItem {
                    item_id,
                    handoff_root: config.incident_handoff_root.clone(),
                    threat_area: (*area).to_string(),
                    checklist_root: fixture_root(&format!("threat-checklist-{index}")),
                    mitigation_root: fixture_root(&format!("threat-mitigation-{index}")),
                    owner_commitment_root: fixture_root(&format!("threat-owner-{index}")),
                    status: ChecklistStatus::Mitigated,
                },
            )
        })
        .collect()
}

fn devnet_privacy_leak_blockers() -> BTreeMap<String, PrivacyLeakBlocker> {
    let boundaries = [
        PrivacyBoundary::MoneroAddress,
        PrivacyBoundary::PrivatePayload,
        PrivacyBoundary::RouteMetadata,
        PrivacyBoundary::SignerKeyMaterial,
        PrivacyBoundary::OperatorDashboardExport,
        PrivacyBoundary::IncidentArchive,
    ];
    boundaries
        .iter()
        .enumerate()
        .map(|(index, boundary)| {
            let blocker_id = stable_id("privacy-leak-blocker", &format!("wave87-{index}"));
            (
                blocker_id.clone(),
                PrivacyLeakBlocker {
                    blocker_id,
                    boundary: *boundary,
                    sanitized_subject_root: fixture_root(&format!("privacy-subject-{index}")),
                    evidence_redaction_root: fixture_root(&format!(
                        "privacy-evidence-redaction-{index}"
                    )),
                    blocker_root: fixture_root(&format!("privacy-blocker-{index}")),
                    leak_confirmed: false,
                    resolved: true,
                },
            )
        })
        .collect()
}

fn devnet_signer_quorum_reviews() -> BTreeMap<String, SignerQuorumReview> {
    (0..DEFAULT_MIN_SIGNER_QUORUM_REVIEWS)
        .map(|index| {
            let review_id = stable_id("signer-quorum-review", &format!("wave87-{index}"));
            (
                review_id.clone(),
                SignerQuorumReview {
                    review_id,
                    command_root: fixture_root(&format!("quorum-command-{index}")),
                    signer_set_root: fixture_root(&format!("quorum-signer-set-{index}")),
                    quorum_attestation_root: fixture_root(&format!("quorum-attestation-{index}")),
                    required_signers: 3,
                    observed_signers: 4,
                    accepted: true,
                },
            )
        })
        .collect()
}

fn devnet_deferred_audit_placeholders() -> BTreeMap<String, DeferredAuditPlaceholder> {
    (0..DEFAULT_MIN_DEFERRED_AUDIT_PLACEHOLDERS)
        .map(|index| {
            let placeholder_id =
                stable_id("deferred-audit-placeholder", &format!("wave87-{index}"));
            (
                placeholder_id.clone(),
                DeferredAuditPlaceholder {
                    placeholder_id,
                    scope_root: fixture_root(&format!("deferred-audit-scope-{index}")),
                    deferral_reason_root: fixture_root(&format!("deferred-audit-reason-{index}")),
                    owner_root: fixture_root(&format!("deferred-audit-owner-{index}")),
                    due_height: DEFAULT_HEIGHT + 144 + index,
                    sealed: true,
                },
            )
        })
        .collect()
}

fn devnet_incident_commander_signoffs() -> BTreeMap<String, IncidentCommanderSignoff> {
    let roles = ["incident_commander", "security_lead", "release_captain"];
    roles
        .iter()
        .enumerate()
        .map(|(index, role)| {
            let signoff_id = stable_id("incident-commander-signoff", &format!("wave87-{index}"));
            (
                signoff_id.clone(),
                IncidentCommanderSignoff {
                    signoff_id,
                    commander_role: (*role).to_string(),
                    commander_commitment_root: fixture_root(&format!(
                        "commander-commitment-{index}"
                    )),
                    checklist_root: fixture_root(&format!("commander-checklist-{index}")),
                    signed_at_height: DEFAULT_HEIGHT + index as u64,
                    signed: true,
                },
            )
        })
        .collect()
}

fn devnet_release_authority_gates() -> BTreeMap<String, ReleaseAuthorityGate> {
    let authorities = [
        ReleaseAuthority::FreezeReleaseWindow,
        ReleaseAuthority::DisableExitPublication,
        ReleaseAuthority::RequireSecurityReacceptance,
        ReleaseAuthority::RequireCommanderAck,
    ];
    authorities
        .iter()
        .enumerate()
        .map(|(index, authority)| {
            let gate_id = stable_id("release-authority-gate", &format!("wave87-{index}"));
            (
                gate_id.clone(),
                ReleaseAuthorityGate {
                    gate_id,
                    authority: *authority,
                    command_root: fixture_root(&format!("release-command-{index}")),
                    policy_root: fixture_root(&format!("release-policy-{index}")),
                    authority_root: fixture_root(&format!("release-authority-{index}")),
                    fail_closed: true,
                    escalation_open: false,
                },
            )
        })
        .collect()
}

fn fail_closed_state(error: String) -> State {
    let config = Config::devnet();
    let mut blockers = BTreeMap::new();
    blockers.insert(
        ChecklistLane::OperatorChecklistVerdict.as_str().to_string(),
        vec![ChecklistBlockerKind::HandoffRootMismatch],
    );
    let counters = ChecklistCounters {
        threat_model_items: 0,
        open_threat_model_items: 1,
        privacy_blockers: 0,
        unresolved_privacy_leaks: 1,
        signer_quorum_reviews: 0,
        accepted_signer_quorum_reviews: 0,
        deferred_audit_placeholders: 0,
        owned_deferred_audit_placeholders: 0,
        incident_commander_signoffs: 0,
        signed_incident_commander_signoffs: 0,
        release_authority_gates: 0,
        fail_closed_release_authority_gates: 0,
        release_authority_escalations: 1,
        unsigned_signoffs: 1,
        fail_closed_blockers: 1,
    };
    let mut lane_roots = BTreeMap::new();
    lane_roots.insert(
        ChecklistLane::OperatorChecklistVerdict.as_str().to_string(),
        fixture_root(&format!("fail-closed-{error}")),
    );
    let verdict = build_verdict(&config, &blockers, &lane_roots, &counters);
    State {
        config,
        threat_model_items: BTreeMap::new(),
        privacy_leak_blockers: BTreeMap::new(),
        signer_quorum_reviews: BTreeMap::new(),
        deferred_audit_placeholders: BTreeMap::new(),
        incident_commander_signoffs: BTreeMap::new(),
        release_authority_gates: BTreeMap::new(),
        lane_roots,
        blockers,
        counters,
        verdict,
    }
}

fn build_counters(
    threat_model_items: &BTreeMap<String, ThreatModelChecklistItem>,
    privacy_leak_blockers: &BTreeMap<String, PrivacyLeakBlocker>,
    signer_quorum_reviews: &BTreeMap<String, SignerQuorumReview>,
    deferred_audit_placeholders: &BTreeMap<String, DeferredAuditPlaceholder>,
    incident_commander_signoffs: &BTreeMap<String, IncidentCommanderSignoff>,
    release_authority_gates: &BTreeMap<String, ReleaseAuthorityGate>,
) -> ChecklistCounters {
    let open_threat_model_items = threat_model_items
        .values()
        .filter(|item| item.status.blocks_release())
        .count() as u64;
    let unresolved_privacy_leaks = privacy_leak_blockers
        .values()
        .filter(|item| item.leak_confirmed && !item.resolved)
        .count() as u64;
    let accepted_signer_quorum_reviews = signer_quorum_reviews
        .values()
        .filter(|item| item.accepted && item.observed_signers >= item.required_signers)
        .count() as u64;
    let owned_deferred_audit_placeholders = deferred_audit_placeholders
        .values()
        .filter(|item| item.sealed)
        .count() as u64;
    let signed_incident_commander_signoffs = incident_commander_signoffs
        .values()
        .filter(|item| item.signed)
        .count() as u64;
    let fail_closed_release_authority_gates = release_authority_gates
        .values()
        .filter(|item| item.fail_closed && !item.escalation_open)
        .count() as u64;
    let unsigned_signoffs = incident_commander_signoffs
        .values()
        .filter(|item| !item.signed)
        .count() as u64;
    let release_authority_escalations = release_authority_gates
        .values()
        .filter(|item| item.escalation_open)
        .count() as u64;
    let fail_closed_blockers = release_authority_gates
        .values()
        .filter(|item| !item.fail_closed)
        .count() as u64;

    ChecklistCounters {
        threat_model_items: threat_model_items.len() as u64,
        open_threat_model_items,
        privacy_blockers: privacy_leak_blockers.len() as u64,
        unresolved_privacy_leaks,
        signer_quorum_reviews: signer_quorum_reviews.len() as u64,
        accepted_signer_quorum_reviews,
        deferred_audit_placeholders: deferred_audit_placeholders.len() as u64,
        owned_deferred_audit_placeholders,
        incident_commander_signoffs: incident_commander_signoffs.len() as u64,
        signed_incident_commander_signoffs,
        release_authority_gates: release_authority_gates.len() as u64,
        fail_closed_release_authority_gates,
        release_authority_escalations,
        unsigned_signoffs,
        fail_closed_blockers,
    }
}

fn build_blockers(
    config: &Config,
    counters: &ChecklistCounters,
) -> BTreeMap<String, Vec<ChecklistBlockerKind>> {
    let mut blockers = BTreeMap::new();
    insert_if_any(
        &mut blockers,
        ChecklistLane::ThreatModelItem,
        threshold_blockers(
            counters.threat_model_items,
            config.min_threat_model_items,
            ChecklistBlockerKind::MissingThreatModelItem,
        )
        .into_iter()
        .chain(limit_blockers(
            counters.open_threat_model_items,
            config.max_open_checklist_blockers,
            ChecklistBlockerKind::OpenThreatModelItem,
        ))
        .collect(),
    );
    insert_if_any(
        &mut blockers,
        ChecklistLane::PrivacyLeakBlocker,
        threshold_blockers(
            counters.privacy_blockers,
            config.min_privacy_blockers,
            ChecklistBlockerKind::MissingPrivacyLeakBlocker,
        )
        .into_iter()
        .chain(limit_blockers(
            counters.unresolved_privacy_leaks,
            config.max_privacy_leaks,
            ChecklistBlockerKind::PrivacyLeakUnresolved,
        ))
        .collect(),
    );
    insert_if_any(
        &mut blockers,
        ChecklistLane::SignerQuorumReview,
        threshold_blockers(
            counters.accepted_signer_quorum_reviews,
            config.min_signer_quorum_reviews,
            ChecklistBlockerKind::MissingSignerQuorumReview,
        )
        .into_iter()
        .chain(limit_blockers(
            counters.signer_quorum_reviews - counters.accepted_signer_quorum_reviews,
            0,
            ChecklistBlockerKind::SignerQuorumRejected,
        ))
        .collect(),
    );
    insert_if_any(
        &mut blockers,
        ChecklistLane::DeferredAuditPlaceholder,
        threshold_blockers(
            counters.owned_deferred_audit_placeholders,
            config.min_deferred_audit_placeholders,
            ChecklistBlockerKind::MissingDeferredAuditPlaceholder,
        )
        .into_iter()
        .chain(limit_blockers(
            counters.deferred_audit_placeholders - counters.owned_deferred_audit_placeholders,
            0,
            ChecklistBlockerKind::DeferredAuditPlaceholderUnowned,
        ))
        .collect(),
    );
    insert_if_any(
        &mut blockers,
        ChecklistLane::IncidentCommanderSignoff,
        threshold_blockers(
            counters.signed_incident_commander_signoffs,
            config.min_incident_commander_signoffs,
            ChecklistBlockerKind::MissingIncidentCommanderSignoff,
        )
        .into_iter()
        .chain(limit_blockers(
            counters.unsigned_signoffs,
            config.max_unsigned_signoffs,
            ChecklistBlockerKind::IncidentCommanderSignoffUnsigned,
        ))
        .collect(),
    );
    insert_if_any(
        &mut blockers,
        ChecklistLane::ReleaseAuthorityGate,
        threshold_blockers(
            counters.fail_closed_release_authority_gates,
            config.min_release_authority_gates,
            ChecklistBlockerKind::MissingReleaseAuthorityGate,
        )
        .into_iter()
        .chain(limit_blockers(
            counters.fail_closed_blockers,
            0,
            ChecklistBlockerKind::ReleaseAuthorityNotFailClosed,
        ))
        .chain(limit_blockers(
            counters.release_authority_escalations,
            0,
            ChecklistBlockerKind::ReleaseAuthorityEscalated,
        ))
        .collect(),
    );
    blockers
}

fn build_lane_roots(
    config: &Config,
    threat_model_items: &BTreeMap<String, ThreatModelChecklistItem>,
    privacy_leak_blockers: &BTreeMap<String, PrivacyLeakBlocker>,
    signer_quorum_reviews: &BTreeMap<String, SignerQuorumReview>,
    deferred_audit_placeholders: &BTreeMap<String, DeferredAuditPlaceholder>,
    incident_commander_signoffs: &BTreeMap<String, IncidentCommanderSignoff>,
    release_authority_gates: &BTreeMap<String, ReleaseAuthorityGate>,
    counters: &ChecklistCounters,
) -> BTreeMap<String, String> {
    let mut lane_roots = BTreeMap::new();
    lane_roots.insert(
        ChecklistLane::ThreatModelItem.as_str().to_string(),
        map_root(
            "OPERATOR-COMMAND-CHECKLIST-LANE-THREAT-MODEL",
            threat_model_items,
            ThreatModelChecklistItem::state_root,
        ),
    );
    lane_roots.insert(
        ChecklistLane::PrivacyLeakBlocker.as_str().to_string(),
        map_root(
            "OPERATOR-COMMAND-CHECKLIST-LANE-PRIVACY-BLOCKERS",
            privacy_leak_blockers,
            PrivacyLeakBlocker::state_root,
        ),
    );
    lane_roots.insert(
        ChecklistLane::SignerQuorumReview.as_str().to_string(),
        map_root(
            "OPERATOR-COMMAND-CHECKLIST-LANE-SIGNER-QUORUMS",
            signer_quorum_reviews,
            SignerQuorumReview::state_root,
        ),
    );
    lane_roots.insert(
        ChecklistLane::DeferredAuditPlaceholder.as_str().to_string(),
        map_root(
            "OPERATOR-COMMAND-CHECKLIST-LANE-DEFERRED-AUDITS",
            deferred_audit_placeholders,
            DeferredAuditPlaceholder::state_root,
        ),
    );
    lane_roots.insert(
        ChecklistLane::IncidentCommanderSignoff.as_str().to_string(),
        map_root(
            "OPERATOR-COMMAND-CHECKLIST-LANE-COMMANDER-SIGNOFFS",
            incident_commander_signoffs,
            IncidentCommanderSignoff::state_root,
        ),
    );
    lane_roots.insert(
        ChecklistLane::ReleaseAuthorityGate.as_str().to_string(),
        map_root(
            "OPERATOR-COMMAND-CHECKLIST-LANE-RELEASE-AUTHORITY",
            release_authority_gates,
            ReleaseAuthorityGate::state_root,
        ),
    );
    lane_roots.insert(
        ChecklistLane::OperatorChecklistVerdict.as_str().to_string(),
        domain_hash(
            "OPERATOR-COMMAND-CHECKLIST-LANE-VERDICT",
            &[
                HashPart::Str(&config.state_root()),
                HashPart::Str(&counters.state_root()),
            ],
        ),
    );
    lane_roots
}

fn build_verdict(
    config: &Config,
    blockers: &BTreeMap<String, Vec<ChecklistBlockerKind>>,
    lane_roots: &BTreeMap<String, String>,
    counters: &ChecklistCounters,
) -> OperatorChecklistVerdict {
    let has_blockers = blockers.values().any(|items| !items.is_empty());
    let fail_closed = counters.fail_closed_release_authority_gates
        >= config.min_release_authority_gates
        && counters.fail_closed_blockers == 0
        && counters.release_authority_escalations == 0;
    let verdict = if has_blockers || !fail_closed {
        ChecklistVerdictKind::HoldFailClosed
    } else {
        ChecklistVerdictKind::ReleaseAuthorized
    };
    let release_authority_root = match lane_roots.get(ChecklistLane::ReleaseAuthorityGate.as_str())
    {
        Some(root) => root.clone(),
        None => fixture_root("missing-release-authority-root"),
    };
    let commander_signoff_root =
        match lane_roots.get(ChecklistLane::IncidentCommanderSignoff.as_str()) {
            Some(root) => root.clone(),
            None => fixture_root("missing-commander-signoff-root"),
        };
    OperatorChecklistVerdict {
        verdict,
        release_allowed: verdict.allows_release() && !has_blockers && fail_closed,
        fail_closed,
        incident_handoff_root: config.incident_handoff_root.clone(),
        blocker_root: blockers_root(blockers),
        lane_root: map_string_root("OPERATOR-COMMAND-CHECKLIST-LANE-ROOTS", lane_roots),
        release_authority_root,
        commander_signoff_root,
    }
}

fn insert_if_any(
    blockers: &mut BTreeMap<String, Vec<ChecklistBlockerKind>>,
    lane: ChecklistLane,
    lane_blockers: Vec<ChecklistBlockerKind>,
) {
    if !lane_blockers.is_empty() {
        blockers.insert(lane.as_str().to_string(), dedup_blockers(lane_blockers));
    }
}

fn threshold_blockers(
    observed: u64,
    required: u64,
    blocker: ChecklistBlockerKind,
) -> Vec<ChecklistBlockerKind> {
    if observed < required {
        vec![blocker]
    } else {
        Vec::new()
    }
}

fn limit_blockers(
    observed: u64,
    allowed: u64,
    blocker: ChecklistBlockerKind,
) -> Vec<ChecklistBlockerKind> {
    if observed > allowed {
        vec![blocker]
    } else {
        Vec::new()
    }
}

fn dedup_blockers(blockers: Vec<ChecklistBlockerKind>) -> Vec<ChecklistBlockerKind> {
    let mut seen = BTreeSet::new();
    blockers
        .into_iter()
        .filter(|blocker| seen.insert(*blocker))
        .collect()
}

fn validate_records<T, F>(records: &BTreeMap<String, T>, validate: F) -> Result<()>
where
    F: Fn(&T) -> Result<()>,
{
    for record in records.values() {
        validate(record)?;
    }
    Ok(())
}

fn records_map<T, F>(records: &BTreeMap<String, T>, public_record: F) -> BTreeMap<String, Value>
where
    F: Fn(&T) -> Value,
{
    records
        .iter()
        .map(|(key, record)| (key.clone(), public_record(record)))
        .collect()
}

fn blockers_record(
    blockers: &BTreeMap<String, Vec<ChecklistBlockerKind>>,
) -> BTreeMap<String, Vec<&'static str>> {
    blockers
        .iter()
        .map(|(lane, lane_blockers)| {
            (
                lane.clone(),
                lane_blockers
                    .iter()
                    .map(|blocker| blocker.as_str())
                    .collect::<Vec<_>>(),
            )
        })
        .collect()
}

fn blockers_root(blockers: &BTreeMap<String, Vec<ChecklistBlockerKind>>) -> String {
    let leaves = blockers
        .iter()
        .flat_map(|(lane, lane_blockers)| {
            lane_blockers.iter().map(move |blocker| {
                domain_hash(
                    "OPERATOR-COMMAND-CHECKLIST-BLOCKER",
                    &[
                        HashPart::Str(lane),
                        HashPart::Str(blocker.as_str()),
                        HashPart::Str(if blocker.fail_closed() {
                            "fail_closed"
                        } else {
                            "open"
                        }),
                    ],
                )
            })
        })
        .collect::<Vec<_>>();
    merkle_or_empty("OPERATOR-COMMAND-CHECKLIST-BLOCKERS", leaves)
}

fn map_root<T, F>(label: &str, records: &BTreeMap<String, T>, state_root: F) -> String
where
    F: Fn(&T) -> String,
{
    let leaves = records
        .iter()
        .map(|(key, record)| {
            domain_hash(
                "OPERATOR-COMMAND-CHECKLIST-MAP-LEAF",
                &[HashPart::Str(key), HashPart::Str(&state_root(record))],
            )
        })
        .collect::<Vec<_>>();
    merkle_or_empty(label, leaves)
}

fn map_string_root(label: &str, records: &BTreeMap<String, String>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| {
            domain_hash(
                "OPERATOR-COMMAND-CHECKLIST-STRING-MAP-LEAF",
                &[HashPart::Str(key), HashPart::Str(value)],
            )
        })
        .collect::<Vec<_>>();
    merkle_or_empty(label, leaves)
}

fn merkle_or_empty(label: &str, leaves: Vec<String>) -> String {
    if leaves.is_empty() {
        domain_hash(label, &[HashPart::Str("empty")])
    } else {
        merkle_root(label, &leaves)
    }
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        label,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
    )
}

fn fixture_root(label: &str) -> String {
    domain_hash(
        "OPERATOR-COMMAND-CHECKLIST-FIXTURE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
    )
}

fn stable_id(prefix: &str, label: &str) -> String {
    format!(
        "{}-{}",
        prefix,
        domain_hash(
            "OPERATOR-COMMAND-CHECKLIST-STABLE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(prefix),
                HashPart::Str(label),
            ],
        )
    )
}

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(label: &str, value: &str) -> Result<()> {
    ensure_non_empty(label, value)?;
    if value.len() < 16 {
        Err(format!("{label} must look like a deterministic root"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(current: usize, max: usize) -> Result<()> {
    if current > max {
        Err(format!(
            "operator command checklist record capacity exceeded: {current} > {max}"
        ))
    } else {
        Ok(())
    }
}
