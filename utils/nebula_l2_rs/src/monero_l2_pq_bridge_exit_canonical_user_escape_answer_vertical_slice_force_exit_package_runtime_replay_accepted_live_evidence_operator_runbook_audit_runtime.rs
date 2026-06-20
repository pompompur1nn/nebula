use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageRuntimeReplayAcceptedLiveEvidenceOperatorRunbookAuditRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-runtime-replay-accepted-live-evidence-operator-runbook-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_AUDIT_SUITE: &str =
    "monero-l2-pq-bridge-exit-replay-accepted-live-evidence-runbook-audit-v1";
pub const DEFAULT_MIN_LIVE_EVIDENCE_IMPORTS: u64 = 6;
pub const DEFAULT_MIN_ACCEPTED_REPLAY_IMPORTS: u64 = 3;
pub const DEFAULT_MIN_OPERATOR_ATTESTATIONS: u64 = 4;
pub const DEFAULT_MIN_RELEASE_SCORE: u64 = 92;
pub const DEFAULT_MAX_OPEN_FINDINGS: u64 = 0;
pub const DEFAULT_MAX_WATCH_FINDINGS: u64 = 2;
pub const DEFAULT_MAX_IMPORTS: usize = 512;
pub const DEFAULT_MAX_AUDITS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ReplayAcceptedReceipt,
    UserEscapeAnswer,
    ForceExitPackage,
    VerticalSliceTranscript,
    OperatorRunbookBinding,
    ReleaseDashboardSignal,
    IncidentDrillReceipt,
    GovernanceApproval,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayAcceptedReceipt => "replay_accepted_receipt",
            Self::UserEscapeAnswer => "user_escape_answer",
            Self::ForceExitPackage => "force_exit_package",
            Self::VerticalSliceTranscript => "vertical_slice_transcript",
            Self::OperatorRunbookBinding => "operator_runbook_binding",
            Self::ReleaseDashboardSignal => "release_dashboard_signal",
            Self::IncidentDrillReceipt => "incident_drill_receipt",
            Self::GovernanceApproval => "governance_approval",
        }
    }

    pub fn required_for_release() -> [Self; 6] {
        [
            Self::ReplayAcceptedReceipt,
            Self::UserEscapeAnswer,
            Self::ForceExitPackage,
            Self::VerticalSliceTranscript,
            Self::OperatorRunbookBinding,
            Self::ReleaseDashboardSignal,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStatus {
    Accepted,
    Quarantined,
    Superseded,
}

impl ImportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingCheckKind {
    CanonicalUserEscapeAnswer,
    ForceExitPackageReplayAccepted,
    OperatorRunbookStepCoverage,
    LiveEvidenceImportIntegrity,
    ReleaseDashboardReadinessGate,
    PqAuthorizationContinuity,
    PrivacyPreservingPublicRecord,
    IncidentRollbackDrill,
    GovernanceFreezeAcknowledgement,
    CounterContinuity,
}

impl BindingCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalUserEscapeAnswer => "canonical_user_escape_answer",
            Self::ForceExitPackageReplayAccepted => "force_exit_package_replay_accepted",
            Self::OperatorRunbookStepCoverage => "operator_runbook_step_coverage",
            Self::LiveEvidenceImportIntegrity => "live_evidence_import_integrity",
            Self::ReleaseDashboardReadinessGate => "release_dashboard_readiness_gate",
            Self::PqAuthorizationContinuity => "pq_authorization_continuity",
            Self::PrivacyPreservingPublicRecord => "privacy_preserving_public_record",
            Self::IncidentRollbackDrill => "incident_rollback_drill",
            Self::GovernanceFreezeAcknowledgement => "governance_freeze_acknowledgement",
            Self::CounterContinuity => "counter_continuity",
        }
    }

    pub fn all() -> [Self; 10] {
        [
            Self::CanonicalUserEscapeAnswer,
            Self::ForceExitPackageReplayAccepted,
            Self::OperatorRunbookStepCoverage,
            Self::LiveEvidenceImportIntegrity,
            Self::ReleaseDashboardReadinessGate,
            Self::PqAuthorizationContinuity,
            Self::PrivacyPreservingPublicRecord,
            Self::IncidentRollbackDrill,
            Self::GovernanceFreezeAcknowledgement,
            Self::CounterContinuity,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Passed,
    Watch,
    Failed,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReadiness {
    Ready,
    Watch,
    Blocked,
}

impl ReleaseReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_audit_suite: String,
    pub min_live_evidence_imports: u64,
    pub min_accepted_replay_imports: u64,
    pub min_operator_attestations: u64,
    pub min_release_score: u64,
    pub max_open_findings: u64,
    pub max_watch_findings: u64,
    pub max_imports: usize,
    pub max_audits: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_audit_suite: RUNBOOK_AUDIT_SUITE.to_string(),
            min_live_evidence_imports: DEFAULT_MIN_LIVE_EVIDENCE_IMPORTS,
            min_accepted_replay_imports: DEFAULT_MIN_ACCEPTED_REPLAY_IMPORTS,
            min_operator_attestations: DEFAULT_MIN_OPERATOR_ATTESTATIONS,
            min_release_score: DEFAULT_MIN_RELEASE_SCORE,
            max_open_findings: DEFAULT_MAX_OPEN_FINDINGS,
            max_watch_findings: DEFAULT_MAX_WATCH_FINDINGS,
            max_imports: DEFAULT_MAX_IMPORTS,
            max_audits: DEFAULT_MAX_AUDITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "runbook_audit_suite": self.runbook_audit_suite,
            "min_live_evidence_imports": self.min_live_evidence_imports,
            "min_accepted_replay_imports": self.min_accepted_replay_imports,
            "min_operator_attestations": self.min_operator_attestations,
            "min_release_score": self.min_release_score,
            "max_open_findings": self.max_open_findings,
            "max_watch_findings": self.max_watch_findings,
            "max_imports": self.max_imports,
            "max_audits": self.max_audits,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveEvidenceImport {
    pub import_id: String,
    pub kind: EvidenceKind,
    pub status: ImportStatus,
    pub source_runtime: String,
    pub source_state_root: String,
    pub evidence_root: String,
    pub replay_acceptance_root: String,
    pub runbook_step_id: String,
    pub operator_id: String,
    pub imported_at_height: u64,
    pub observed_at_unix_seconds: u64,
    pub release_dashboard_label: String,
    pub public_payload: Value,
}

impl LiveEvidenceImport {
    pub fn new(input: LiveEvidenceImportInput) -> Result<Self> {
        ensure_non_empty("source_runtime", &input.source_runtime)?;
        ensure_non_empty("source_state_root", &input.source_state_root)?;
        ensure_non_empty("runbook_step_id", &input.runbook_step_id)?;
        ensure_non_empty("operator_id", &input.operator_id)?;
        ensure_non_empty("release_dashboard_label", &input.release_dashboard_label)?;
        let evidence_root = evidence_payload_root(input.kind, &input.public_payload);
        let replay_acceptance_root = replay_acceptance_root(
            input.kind,
            &input.source_runtime,
            &input.source_state_root,
            &evidence_root,
            input.imported_at_height,
        );
        let import_id = live_evidence_import_id(
            input.kind,
            &input.source_runtime,
            &input.source_state_root,
            &evidence_root,
            &input.runbook_step_id,
            input.imported_at_height,
        );
        Ok(Self {
            import_id,
            kind: input.kind,
            status: input.status,
            source_runtime: input.source_runtime,
            source_state_root: input.source_state_root,
            evidence_root,
            replay_acceptance_root,
            runbook_step_id: input.runbook_step_id,
            operator_id: input.operator_id,
            imported_at_height: input.imported_at_height,
            observed_at_unix_seconds: input.observed_at_unix_seconds,
            release_dashboard_label: input.release_dashboard_label,
            public_payload: input.public_payload,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "import_id": self.import_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "source_runtime": self.source_runtime,
            "source_state_root": self.source_state_root,
            "evidence_root": self.evidence_root,
            "replay_acceptance_root": self.replay_acceptance_root,
            "runbook_step_id": self.runbook_step_id,
            "operator_id": self.operator_id,
            "imported_at_height": self.imported_at_height,
            "observed_at_unix_seconds": self.observed_at_unix_seconds,
            "release_dashboard_label": self.release_dashboard_label,
            "public_payload": self.public_payload,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_evidence_import", &self.public_record())
    }

    pub fn is_accepted_replay(&self) -> bool {
        self.status == ImportStatus::Accepted && self.kind == EvidenceKind::ReplayAcceptedReceipt
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveEvidenceImportInput {
    pub kind: EvidenceKind,
    pub status: ImportStatus,
    pub source_runtime: String,
    pub source_state_root: String,
    pub runbook_step_id: String,
    pub operator_id: String,
    pub imported_at_height: u64,
    pub observed_at_unix_seconds: u64,
    pub release_dashboard_label: String,
    pub public_payload: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorRunbookStep {
    pub step_id: String,
    pub title: String,
    pub owner_role: String,
    pub required_kind: EvidenceKind,
    pub required: bool,
    pub release_gate: String,
    pub acknowledgement_root: String,
}

impl OperatorRunbookStep {
    pub fn new(
        title: impl Into<String>,
        owner_role: impl Into<String>,
        required_kind: EvidenceKind,
        required: bool,
        release_gate: impl Into<String>,
        acknowledgement_record: Value,
    ) -> Result<Self> {
        let title = title.into();
        let owner_role = owner_role.into();
        let release_gate = release_gate.into();
        ensure_non_empty("title", &title)?;
        ensure_non_empty("owner_role", &owner_role)?;
        ensure_non_empty("release_gate", &release_gate)?;
        let acknowledgement_root = record_root("runbook_acknowledgement", &acknowledgement_record);
        let step_id = runbook_step_id(&title, &owner_role, required_kind, &release_gate);
        Ok(Self {
            step_id,
            title,
            owner_role,
            required_kind,
            required,
            release_gate,
            acknowledgement_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "title": self.title,
            "owner_role": self.owner_role,
            "required_kind": self.required_kind.as_str(),
            "required": bool_label(self.required),
            "release_gate": self.release_gate,
            "acknowledgement_root": self.acknowledgement_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator_runbook_step", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorAttestation {
    pub attestation_id: String,
    pub operator_id: String,
    pub runbook_step_id: String,
    pub evidence_import_id: String,
    pub attestation_root: String,
    pub signed_at_height: u64,
    pub pq_authorization_root: String,
}

impl OperatorAttestation {
    pub fn new(
        operator_id: impl Into<String>,
        runbook_step_id: impl Into<String>,
        evidence_import_id: impl Into<String>,
        signed_at_height: u64,
        pq_authorization_record: Value,
    ) -> Result<Self> {
        let operator_id = operator_id.into();
        let runbook_step_id = runbook_step_id.into();
        let evidence_import_id = evidence_import_id.into();
        ensure_non_empty("operator_id", &operator_id)?;
        ensure_non_empty("runbook_step_id", &runbook_step_id)?;
        ensure_non_empty("evidence_import_id", &evidence_import_id)?;
        let pq_authorization_root = record_root("pq_authorization", &pq_authorization_record);
        let attestation_root = operator_attestation_root(
            &operator_id,
            &runbook_step_id,
            &evidence_import_id,
            &pq_authorization_root,
            signed_at_height,
        );
        let attestation_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-OPERATOR-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&attestation_root),
            ],
            32,
        );
        Ok(Self {
            attestation_id,
            operator_id,
            runbook_step_id,
            evidence_import_id,
            attestation_root,
            signed_at_height,
            pq_authorization_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "operator_id": self.operator_id,
            "runbook_step_id": self.runbook_step_id,
            "evidence_import_id": self.evidence_import_id,
            "attestation_root": self.attestation_root,
            "signed_at_height": self.signed_at_height,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator_attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditFinding {
    pub finding_id: String,
    pub kind: BindingCheckKind,
    pub status: CheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub release_blocking: bool,
}

impl AuditFinding {
    pub fn new(
        kind: BindingCheckKind,
        status: CheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_record: Value,
        release_blocking: bool,
    ) -> Self {
        let evidence_root = record_root(kind.as_str(), &evidence_record);
        let finding_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-FINDING-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(&evidence_root),
            ],
            32,
        );
        Self {
            finding_id,
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            evidence_root,
            release_blocking,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "release_blocking": bool_label(self.release_blocking),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("audit_finding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseDashboardReadiness {
    pub dashboard_id: String,
    pub readiness: ReleaseReadiness,
    pub release_score: u64,
    pub live_evidence_import_root: String,
    pub accepted_replay_root: String,
    pub runbook_step_root: String,
    pub operator_attestation_root: String,
    pub finding_root: String,
    pub gate_summary_root: String,
    pub generated_at_height: u64,
}

impl ReleaseDashboardReadiness {
    pub fn public_record(&self) -> Value {
        json!({
            "dashboard_id": self.dashboard_id,
            "readiness": self.readiness.as_str(),
            "release_score": self.release_score,
            "live_evidence_import_root": self.live_evidence_import_root,
            "accepted_replay_root": self.accepted_replay_root,
            "runbook_step_root": self.runbook_step_root,
            "operator_attestation_root": self.operator_attestation_root,
            "finding_root": self.finding_root,
            "gate_summary_root": self.gate_summary_root,
            "generated_at_height": self.generated_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_dashboard_readiness", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub live_evidence_imports: u64,
    pub accepted_replay_imports: u64,
    pub quarantined_imports: u64,
    pub runbook_steps: u64,
    pub operator_attestations: u64,
    pub audits: u64,
    pub passed_findings: u64,
    pub watch_findings: u64,
    pub failed_findings: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "live_evidence_imports": self.live_evidence_imports,
            "accepted_replay_imports": self.accepted_replay_imports,
            "quarantined_imports": self.quarantined_imports,
            "runbook_steps": self.runbook_steps,
            "operator_attestations": self.operator_attestations,
            "audits": self.audits,
            "passed_findings": self.passed_findings,
            "watch_findings": self.watch_findings,
            "failed_findings": self.failed_findings,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub runbook_steps: BTreeMap<String, OperatorRunbookStep>,
    pub live_evidence_imports: BTreeMap<String, LiveEvidenceImport>,
    pub operator_attestations: BTreeMap<String, OperatorAttestation>,
    pub findings: BTreeMap<String, AuditFinding>,
    pub dashboards: BTreeMap<String, ReleaseDashboardReadiness>,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            runbook_steps: BTreeMap::new(),
            live_evidence_imports: BTreeMap::new(),
            operator_attestations: BTreeMap::new(),
            findings: BTreeMap::new(),
            dashboards: BTreeMap::new(),
            counters: Counters::default(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        for step in default_devnet_runbook_steps() {
            state.counters.runbook_steps = state.counters.runbook_steps.saturating_add(1);
            state.runbook_steps.insert(step.step_id.clone(), step);
        }
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "runbook_step_root": self.runbook_step_root(),
            "live_evidence_import_root": self.live_evidence_import_root(),
            "accepted_replay_root": self.accepted_replay_root(),
            "operator_attestation_root": self.operator_attestation_root(),
            "finding_root": self.finding_root(),
            "release_dashboard_root": self.release_dashboard_root(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-RUNTIME-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.runbook_step_root()),
                HashPart::Str(&self.live_evidence_import_root()),
                HashPart::Str(&self.operator_attestation_root()),
                HashPart::Str(&self.finding_root()),
                HashPart::Str(&self.release_dashboard_root()),
                HashPart::Str(&self.counters.state_root()),
            ],
            32,
        )
    }

    pub fn add_runbook_step(&mut self, step: OperatorRunbookStep) -> Result<String> {
        if self.runbook_steps.contains_key(&step.step_id) {
            return Err(format!("runbook step already exists: {}", step.step_id));
        }
        let step_id = step.step_id.clone();
        self.runbook_steps.insert(step_id.clone(), step);
        self.counters.runbook_steps = self.runbook_steps.len() as u64;
        Ok(step_id)
    }

    pub fn import_live_evidence(&mut self, input: LiveEvidenceImportInput) -> Result<String> {
        if self.live_evidence_imports.len() >= self.config.max_imports {
            return Err("live evidence import capacity exhausted".to_string());
        }
        let import = LiveEvidenceImport::new(input)?;
        if !self.runbook_steps.contains_key(&import.runbook_step_id) {
            return Err(format!(
                "runbook step missing for live evidence import: {}",
                import.runbook_step_id
            ));
        }
        if self.live_evidence_imports.contains_key(&import.import_id) {
            return Err(format!(
                "live evidence import already exists: {}",
                import.import_id
            ));
        }
        let import_id = import.import_id.clone();
        self.live_evidence_imports.insert(import_id.clone(), import);
        self.refresh_import_counters();
        Ok(import_id)
    }

    pub fn attest_operator_binding(
        &mut self,
        operator_id: impl Into<String>,
        runbook_step_id: impl Into<String>,
        evidence_import_id: impl Into<String>,
        signed_at_height: u64,
        pq_authorization_record: Value,
    ) -> Result<String> {
        let attestation = OperatorAttestation::new(
            operator_id,
            runbook_step_id,
            evidence_import_id,
            signed_at_height,
            pq_authorization_record,
        )?;
        if !self
            .runbook_steps
            .contains_key(&attestation.runbook_step_id)
        {
            return Err(format!(
                "runbook step missing for operator attestation: {}",
                attestation.runbook_step_id
            ));
        }
        if !self
            .live_evidence_imports
            .contains_key(&attestation.evidence_import_id)
        {
            return Err(format!(
                "live evidence import missing for operator attestation: {}",
                attestation.evidence_import_id
            ));
        }
        if self
            .operator_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err(format!(
                "operator attestation already exists: {}",
                attestation.attestation_id
            ));
        }
        let attestation_id = attestation.attestation_id.clone();
        self.operator_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.operator_attestations = self.operator_attestations.len() as u64;
        Ok(attestation_id)
    }

    pub fn audit_release_dashboard(&mut self, generated_at_height: u64) -> Result<String> {
        if self.dashboards.len() >= self.config.max_audits {
            return Err("release dashboard audit capacity exhausted".to_string());
        }
        let findings = self.compute_findings();
        self.findings.clear();
        for finding in findings {
            self.findings.insert(finding.finding_id.clone(), finding);
        }
        self.refresh_finding_counters();
        self.counters.audits = self.counters.audits.saturating_add(1);

        let release_score = self.release_score();
        let readiness = self.release_readiness(release_score);
        let gate_summary = self.gate_summary_record(release_score, readiness);
        let gate_summary_root = record_root("gate_summary", &gate_summary);
        let dashboard_id = release_dashboard_id(
            readiness,
            release_score,
            &self.live_evidence_import_root(),
            &self.finding_root(),
            generated_at_height,
        );
        let dashboard = ReleaseDashboardReadiness {
            dashboard_id: dashboard_id.clone(),
            readiness,
            release_score,
            live_evidence_import_root: self.live_evidence_import_root(),
            accepted_replay_root: self.accepted_replay_root(),
            runbook_step_root: self.runbook_step_root(),
            operator_attestation_root: self.operator_attestation_root(),
            finding_root: self.finding_root(),
            gate_summary_root,
            generated_at_height,
        };
        self.dashboards.insert(dashboard_id.clone(), dashboard);
        Ok(dashboard_id)
    }

    pub fn latest_dashboard(&self) -> Option<&ReleaseDashboardReadiness> {
        self.dashboards.values().max_by_key(|dashboard| {
            (
                dashboard.generated_at_height,
                dashboard.release_score,
                dashboard.dashboard_id.clone(),
            )
        })
    }

    pub fn runbook_step_root(&self) -> String {
        let leaves: Vec<Value> = self
            .runbook_steps
            .values()
            .map(OperatorRunbookStep::public_record)
            .collect();
        merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-STEPS", &leaves)
    }

    pub fn live_evidence_import_root(&self) -> String {
        let leaves: Vec<Value> = self
            .live_evidence_imports
            .values()
            .map(LiveEvidenceImport::public_record)
            .collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-LIVE-EVIDENCE-IMPORTS",
            &leaves,
        )
    }

    pub fn accepted_replay_root(&self) -> String {
        let leaves: Vec<Value> = self
            .live_evidence_imports
            .values()
            .filter(|import| import.is_accepted_replay())
            .map(LiveEvidenceImport::public_record)
            .collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-ACCEPTED-REPLAYS",
            &leaves,
        )
    }

    pub fn operator_attestation_root(&self) -> String {
        let leaves: Vec<Value> = self
            .operator_attestations
            .values()
            .map(OperatorAttestation::public_record)
            .collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-OPERATOR-ATTESTATIONS",
            &leaves,
        )
    }

    pub fn finding_root(&self) -> String {
        let leaves: Vec<Value> = self
            .findings
            .values()
            .map(AuditFinding::public_record)
            .collect();
        merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-FINDINGS", &leaves)
    }

    pub fn release_dashboard_root(&self) -> String {
        let leaves: Vec<Value> = self
            .dashboards
            .values()
            .map(ReleaseDashboardReadiness::public_record)
            .collect();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-RELEASE-DASHBOARDS",
            &leaves,
        )
    }

    fn compute_findings(&self) -> Vec<AuditFinding> {
        BindingCheckKind::all()
            .iter()
            .map(|kind| self.compute_finding(*kind))
            .collect()
    }

    fn compute_finding(&self, kind: BindingCheckKind) -> AuditFinding {
        match kind {
            BindingCheckKind::CanonicalUserEscapeAnswer => {
                let count = self.count_accepted_kind(EvidenceKind::UserEscapeAnswer);
                status_finding(
                    kind,
                    count > 0,
                    count > 1,
                    "canonical user escape answer evidence is imported and unique",
                    format!("accepted_user_escape_answer_imports={}", count),
                    json!({"accepted_user_escape_answer_imports": count}),
                )
            }
            BindingCheckKind::ForceExitPackageReplayAccepted => {
                let force_exit_count = self.count_accepted_kind(EvidenceKind::ForceExitPackage);
                let replay_count = self.counters.accepted_replay_imports;
                let passed =
                    force_exit_count > 0 && replay_count >= self.config.min_accepted_replay_imports;
                status_finding(
                    kind,
                    passed,
                    force_exit_count > 0 && replay_count > 0,
                    "force-exit package is backed by accepted replay evidence",
                    format!(
                        "accepted_force_exit_packages={}, accepted_replay_imports={}",
                        force_exit_count, replay_count
                    ),
                    json!({
                        "accepted_force_exit_packages": force_exit_count,
                        "accepted_replay_imports": replay_count,
                        "min_accepted_replay_imports": self.config.min_accepted_replay_imports,
                    }),
                )
            }
            BindingCheckKind::OperatorRunbookStepCoverage => {
                let missing = self.missing_required_runbook_kinds();
                status_finding(
                    kind,
                    missing.is_empty(),
                    missing.len() <= 1,
                    "all required runbook steps have accepted live evidence",
                    format!("missing_required_kinds={}", missing.join(",")),
                    json!({"missing_required_kinds": missing}),
                )
            }
            BindingCheckKind::LiveEvidenceImportIntegrity => {
                let accepted = self.count_status(ImportStatus::Accepted);
                status_finding(
                    kind,
                    accepted >= self.config.min_live_evidence_imports,
                    accepted > 0,
                    "minimum accepted live evidence import count is satisfied",
                    format!(
                        "accepted_live_evidence_imports={}, min_live_evidence_imports={}",
                        accepted, self.config.min_live_evidence_imports
                    ),
                    json!({
                        "accepted_live_evidence_imports": accepted,
                        "min_live_evidence_imports": self.config.min_live_evidence_imports,
                        "quarantined_imports": self.counters.quarantined_imports,
                    }),
                )
            }
            BindingCheckKind::ReleaseDashboardReadinessGate => {
                let score = self.release_score_without_dashboard_gate();
                status_finding(
                    kind,
                    score >= self.config.min_release_score,
                    score.saturating_add(5) >= self.config.min_release_score,
                    "release dashboard score meets readiness threshold",
                    format!(
                        "release_score={}, min_release_score={}",
                        score, self.config.min_release_score
                    ),
                    json!({"release_score": score, "min_release_score": self.config.min_release_score}),
                )
            }
            BindingCheckKind::PqAuthorizationContinuity => {
                let authorized = self
                    .operator_attestations
                    .values()
                    .filter(|attestation| !attestation.pq_authorization_root.is_empty())
                    .count() as u64;
                status_finding(
                    kind,
                    authorized >= self.config.min_operator_attestations,
                    authorized > 0,
                    "operator attestations carry PQ authorization roots",
                    format!(
                        "pq_authorized_attestations={}, min_operator_attestations={}",
                        authorized, self.config.min_operator_attestations
                    ),
                    json!({
                        "pq_authorized_attestations": authorized,
                        "min_operator_attestations": self.config.min_operator_attestations,
                    }),
                )
            }
            BindingCheckKind::PrivacyPreservingPublicRecord => {
                let flagged = self
                    .live_evidence_imports
                    .values()
                    .filter(|import| {
                        public_payload_mentions_private_material(&import.public_payload)
                    })
                    .count() as u64;
                status_finding(
                    kind,
                    flagged == 0,
                    flagged <= 1,
                    "public records do not expose private keys, seeds, or raw secrets",
                    format!("privacy_flagged_public_payloads={}", flagged),
                    json!({"privacy_flagged_public_payloads": flagged}),
                )
            }
            BindingCheckKind::IncidentRollbackDrill => {
                let drills = self.count_accepted_kind(EvidenceKind::IncidentDrillReceipt);
                status_finding(
                    kind,
                    drills > 0,
                    self.counters.accepted_replay_imports > 0,
                    "incident rollback drill receipt is imported or replay path is watch-listed",
                    format!("accepted_incident_drill_receipts={}", drills),
                    json!({"accepted_incident_drill_receipts": drills}),
                )
            }
            BindingCheckKind::GovernanceFreezeAcknowledgement => {
                let approvals = self.count_accepted_kind(EvidenceKind::GovernanceApproval);
                status_finding(
                    kind,
                    approvals > 0,
                    self.counters.operator_attestations >= self.config.min_operator_attestations,
                    "governance approval or operator quorum acknowledges release freeze boundary",
                    format!("accepted_governance_approvals={}", approvals),
                    json!({
                        "accepted_governance_approvals": approvals,
                        "operator_attestations": self.counters.operator_attestations,
                    }),
                )
            }
            BindingCheckKind::CounterContinuity => {
                let recomputed = self.recomputed_counters();
                let passed = recomputed.public_record() == self.counters.public_record();
                status_finding(
                    kind,
                    passed,
                    false,
                    "stored counters match recomputed live evidence, attestation, and finding counts",
                    format!(
                        "stored_counter_root={}, recomputed_counter_root={}",
                        self.counters.state_root(),
                        recomputed.state_root()
                    ),
                    json!({
                        "stored_counters": self.counters.public_record(),
                        "recomputed_counters": recomputed.public_record(),
                    }),
                )
            }
        }
    }

    fn release_readiness(&self, release_score: u64) -> ReleaseReadiness {
        if self.counters.failed_findings > self.config.max_open_findings {
            return ReleaseReadiness::Blocked;
        }
        if release_score < self.config.min_release_score {
            return ReleaseReadiness::Blocked;
        }
        if self.counters.watch_findings > self.config.max_watch_findings {
            return ReleaseReadiness::Watch;
        }
        if self.counters.quarantined_imports > 0 {
            return ReleaseReadiness::Watch;
        }
        ReleaseReadiness::Ready
    }

    fn release_score(&self) -> u64 {
        let passed = self.counters.passed_findings;
        let watch = self.counters.watch_findings;
        let failed = self.counters.failed_findings;
        score_from_findings(passed, watch, failed)
    }

    fn release_score_without_dashboard_gate(&self) -> u64 {
        let findings = self.compute_findings();
        let mut passed = 0_u64;
        let mut watch = 0_u64;
        let mut failed = 0_u64;
        for finding in findings {
            if finding.kind == BindingCheckKind::ReleaseDashboardReadinessGate {
                continue;
            }
            match finding.status {
                CheckStatus::Passed => passed = passed.saturating_add(1),
                CheckStatus::Watch => watch = watch.saturating_add(1),
                CheckStatus::Failed => failed = failed.saturating_add(1),
            }
        }
        score_from_findings(passed, watch, failed)
    }

    fn gate_summary_record(&self, release_score: u64, readiness: ReleaseReadiness) -> Value {
        json!({
            "readiness": readiness.as_str(),
            "release_score": release_score,
            "required_kind_coverage": self.required_kind_coverage_record(),
            "live_evidence_import_root": self.live_evidence_import_root(),
            "accepted_replay_root": self.accepted_replay_root(),
            "operator_attestation_root": self.operator_attestation_root(),
            "finding_root": self.finding_root(),
            "counters": self.counters.public_record(),
        })
    }

    fn required_kind_coverage_record(&self) -> Value {
        let coverage: Vec<Value> = EvidenceKind::required_for_release()
            .iter()
            .map(|kind| {
                json!({
                    "kind": kind.as_str(),
                    "accepted_imports": self.count_accepted_kind(*kind),
                })
            })
            .collect();
        json!(coverage)
    }

    fn count_accepted_kind(&self, kind: EvidenceKind) -> u64 {
        self.live_evidence_imports
            .values()
            .filter(|import| import.kind == kind && import.status == ImportStatus::Accepted)
            .count() as u64
    }

    fn count_status(&self, status: ImportStatus) -> u64 {
        self.live_evidence_imports
            .values()
            .filter(|import| import.status == status)
            .count() as u64
    }

    fn missing_required_runbook_kinds(&self) -> Vec<String> {
        let accepted_kinds: BTreeSet<EvidenceKind> = self
            .live_evidence_imports
            .values()
            .filter(|import| import.status == ImportStatus::Accepted)
            .map(|import| import.kind)
            .collect();
        EvidenceKind::required_for_release()
            .iter()
            .filter(|kind| !accepted_kinds.contains(kind))
            .map(|kind| kind.as_str().to_string())
            .collect()
    }

    fn refresh_import_counters(&mut self) {
        self.counters.live_evidence_imports = self.live_evidence_imports.len() as u64;
        self.counters.accepted_replay_imports = self
            .live_evidence_imports
            .values()
            .filter(|import| import.is_accepted_replay())
            .count() as u64;
        self.counters.quarantined_imports = self.count_status(ImportStatus::Quarantined);
    }

    fn refresh_finding_counters(&mut self) {
        self.counters.passed_findings = self
            .findings
            .values()
            .filter(|finding| finding.status == CheckStatus::Passed)
            .count() as u64;
        self.counters.watch_findings = self
            .findings
            .values()
            .filter(|finding| finding.status == CheckStatus::Watch)
            .count() as u64;
        self.counters.failed_findings = self
            .findings
            .values()
            .filter(|finding| finding.status == CheckStatus::Failed)
            .count() as u64;
    }

    fn recomputed_counters(&self) -> Counters {
        let mut counters = Counters {
            live_evidence_imports: self.live_evidence_imports.len() as u64,
            accepted_replay_imports: self
                .live_evidence_imports
                .values()
                .filter(|import| import.is_accepted_replay())
                .count() as u64,
            quarantined_imports: self
                .live_evidence_imports
                .values()
                .filter(|import| import.status == ImportStatus::Quarantined)
                .count() as u64,
            runbook_steps: self.runbook_steps.len() as u64,
            operator_attestations: self.operator_attestations.len() as u64,
            audits: self.counters.audits,
            passed_findings: 0,
            watch_findings: 0,
            failed_findings: 0,
        };
        for finding in self.findings.values() {
            match finding.status {
                CheckStatus::Passed => {
                    counters.passed_findings = counters.passed_findings.saturating_add(1)
                }
                CheckStatus::Watch => {
                    counters.watch_findings = counters.watch_findings.saturating_add(1)
                }
                CheckStatus::Failed => {
                    counters.failed_findings = counters.failed_findings.saturating_add(1)
                }
            }
        }
        counters
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn default_devnet_runbook_steps() -> Vec<OperatorRunbookStep> {
    let specs = [
        (
            "Replay accepted live evidence import",
            "bridge-operator",
            EvidenceKind::ReplayAcceptedReceipt,
            "replay-accepted",
        ),
        (
            "Canonical user escape answer publication",
            "escape-desk",
            EvidenceKind::UserEscapeAnswer,
            "user-escape-answer",
        ),
        (
            "Force exit package runtime binding",
            "exit-operator",
            EvidenceKind::ForceExitPackage,
            "force-exit-package",
        ),
        (
            "Vertical slice transcript release proof",
            "release-engineer",
            EvidenceKind::VerticalSliceTranscript,
            "vertical-slice",
        ),
        (
            "Operator runbook evidence binding",
            "runbook-owner",
            EvidenceKind::OperatorRunbookBinding,
            "operator-runbook",
        ),
        (
            "Release dashboard readiness export",
            "release-manager",
            EvidenceKind::ReleaseDashboardSignal,
            "release-dashboard",
        ),
        (
            "Incident rollback drill receipt",
            "incident-commander",
            EvidenceKind::IncidentDrillReceipt,
            "incident-drill",
        ),
        (
            "Governance freeze acknowledgement",
            "governance-relay",
            EvidenceKind::GovernanceApproval,
            "governance-freeze",
        ),
    ];
    specs
        .iter()
        .filter_map(|(title, owner, kind, gate)| {
            OperatorRunbookStep::new(
                *title,
                *owner,
                *kind,
                true,
                *gate,
                json!({
                    "devnet_acknowledgement": format!("{}:{}", owner, gate),
                    "protocol_version": PROTOCOL_VERSION,
                }),
            )
            .ok()
        })
        .collect()
}

fn status_finding(
    kind: BindingCheckKind,
    passed: bool,
    watch: bool,
    requirement: impl Into<String>,
    observed: impl Into<String>,
    evidence_record: Value,
) -> AuditFinding {
    let status = if passed {
        CheckStatus::Passed
    } else if watch {
        CheckStatus::Watch
    } else {
        CheckStatus::Failed
    };
    AuditFinding::new(
        kind,
        status,
        requirement,
        observed,
        evidence_record,
        status == CheckStatus::Failed,
    )
}

fn score_from_findings(passed: u64, watch: u64, failed: u64) -> u64 {
    let total = passed.saturating_add(watch).saturating_add(failed);
    if total == 0 {
        return 0;
    }
    let earned = passed
        .saturating_mul(100)
        .saturating_add(watch.saturating_mul(50));
    earned / total
}

fn live_evidence_import_id(
    kind: EvidenceKind,
    source_runtime: &str,
    source_state_root: &str,
    evidence_root: &str,
    runbook_step_id: &str,
    imported_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-LIVE-EVIDENCE-IMPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_state_root),
            HashPart::Str(evidence_root),
            HashPart::Str(runbook_step_id),
            HashPart::Int(imported_at_height as i128),
        ],
        32,
    )
}

fn evidence_payload_root(kind: EvidenceKind, payload: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-EVIDENCE-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn replay_acceptance_root(
    kind: EvidenceKind,
    source_runtime: &str,
    source_state_root: &str,
    evidence_root: &str,
    imported_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-REPLAY-ACCEPTANCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_state_root),
            HashPart::Str(evidence_root),
            HashPart::Int(imported_at_height as i128),
        ],
        32,
    )
}

fn runbook_step_id(
    title: &str,
    owner_role: &str,
    required_kind: EvidenceKind,
    release_gate: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-STEP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(title),
            HashPart::Str(owner_role),
            HashPart::Str(required_kind.as_str()),
            HashPart::Str(release_gate),
        ],
        32,
    )
}

fn operator_attestation_root(
    operator_id: &str,
    runbook_step_id: &str,
    evidence_import_id: &str,
    pq_authorization_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-OPERATOR-ATTESTATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(runbook_step_id),
            HashPart::Str(evidence_import_id),
            HashPart::Str(pq_authorization_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

fn release_dashboard_id(
    readiness: ReleaseReadiness,
    release_score: u64,
    live_evidence_import_root: &str,
    finding_root: &str,
    generated_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-RELEASE-DASHBOARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(readiness.as_str()),
            HashPart::Int(release_score as i128),
            HashPart::Str(live_evidence_import_root),
            HashPart::Str(finding_root),
            HashPart::Int(generated_at_height as i128),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RUNBOOK-AUDIT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{} must not be empty", field))
    } else {
        Ok(())
    }
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn public_payload_mentions_private_material(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, nested)| {
            let key = key.to_ascii_lowercase();
            key.contains("private_key")
                || key.contains("spend_key")
                || key.contains("seed")
                || key.contains("mnemonic")
                || key.contains("raw_secret")
                || public_payload_mentions_private_material(nested)
        }),
        Value::Array(items) => items.iter().any(public_payload_mentions_private_material),
        Value::String(text) => {
            let lowered = text.to_ascii_lowercase();
            lowered.contains("private_key=")
                || lowered.contains("seed=")
                || lowered.contains("mnemonic=")
                || lowered.contains("raw_secret=")
        }
        _ => false,
    }
}
