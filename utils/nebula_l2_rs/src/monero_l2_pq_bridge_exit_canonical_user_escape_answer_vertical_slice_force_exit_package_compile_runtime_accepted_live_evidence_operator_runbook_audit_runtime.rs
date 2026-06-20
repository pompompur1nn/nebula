use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeAcceptedLiveEvidenceOperatorRunbookAuditRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-accepted-live-evidence-operator-runbook-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_AUDIT_SUITE: &str =
    "monero-l2-pq-force-exit-compile-runtime-live-evidence-operator-runbook-audit-v1";
pub const DEFAULT_RELEASE_EPOCH: u64 = 82;
pub const DEFAULT_MIN_COMPILE_IMPORTS: u64 = 4;
pub const DEFAULT_MIN_RUNTIME_IMPORTS: u64 = 5;
pub const DEFAULT_MIN_OPERATOR_ACKS: u64 = 3;
pub const DEFAULT_MAX_ACCEPTED_LAG_BLOCKS: u64 = 18;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_audit_suite: String,
    pub release_epoch: u64,
    pub release_channel: String,
    pub min_compile_imports: u64,
    pub min_runtime_imports: u64,
    pub min_operator_acks: u64,
    pub max_accepted_lag_blocks: u64,
    pub require_compile_acceptance: bool,
    pub require_runtime_acceptance: bool,
    pub require_live_evidence: bool,
    pub require_operator_runbook_binding: bool,
    pub require_release_dashboard_ready: bool,
    pub fail_closed_on_missing_evidence: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_audit_suite: RUNBOOK_AUDIT_SUITE.to_string(),
            release_epoch: DEFAULT_RELEASE_EPOCH,
            release_channel: "devnet-release-dashboard".to_string(),
            min_compile_imports: DEFAULT_MIN_COMPILE_IMPORTS,
            min_runtime_imports: DEFAULT_MIN_RUNTIME_IMPORTS,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            max_accepted_lag_blocks: DEFAULT_MAX_ACCEPTED_LAG_BLOCKS,
            require_compile_acceptance: true,
            require_runtime_acceptance: true,
            require_live_evidence: true,
            require_operator_runbook_binding: true,
            require_release_dashboard_ready: true,
            fail_closed_on_missing_evidence: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "runbook_audit_suite": self.runbook_audit_suite,
            "release_epoch": self.release_epoch,
            "release_channel": self.release_channel,
            "min_compile_imports": self.min_compile_imports,
            "min_runtime_imports": self.min_runtime_imports,
            "min_operator_acks": self.min_operator_acks,
            "max_accepted_lag_blocks": self.max_accepted_lag_blocks,
            "require_compile_acceptance": self.require_compile_acceptance,
            "require_runtime_acceptance": self.require_runtime_acceptance,
            "require_live_evidence": self.require_live_evidence,
            "require_operator_runbook_binding": self.require_operator_runbook_binding,
            "require_release_dashboard_ready": self.require_release_dashboard_ready,
            "fail_closed_on_missing_evidence": self.fail_closed_on_missing_evidence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportLane {
    CompileAccepted,
    RuntimeAccepted,
    LiveEvidence,
    OperatorRunbook,
    ReleaseDashboard,
}

impl ImportLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileAccepted => "compile_accepted",
            Self::RuntimeAccepted => "runtime_accepted",
            Self::LiveEvidence => "live_evidence",
            Self::OperatorRunbook => "operator_runbook",
            Self::ReleaseDashboard => "release_dashboard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    EvidencePending,
    AuditPending,
    Ready,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidencePending => "evidence_pending",
            Self::AuditPending => "audit_pending",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompileAcceptedImport {
    pub import_id: String,
    pub ordinal: u64,
    pub package_id: String,
    pub artifact_root: String,
    pub compiler_profile_root: String,
    pub acceptance_receipt_root: String,
    pub source_tree_root: String,
    pub dependency_lock_root: String,
    pub accepted: bool,
    pub reproducible: bool,
}

impl CompileAcceptedImport {
    pub fn devnet(config: &Config, ordinal: u64, package_id: &str) -> Self {
        let artifact_root = seed_root("compile-artifact", package_id, ordinal);
        let compiler_profile_root = seed_root("compiler-profile", package_id, ordinal);
        let source_tree_root = seed_root("source-tree", package_id, ordinal);
        let dependency_lock_root = seed_root("dependency-lock", package_id, ordinal);
        let acceptance_receipt_root = compile_acceptance_root(
            config,
            package_id,
            ordinal,
            &artifact_root,
            &compiler_profile_root,
            &source_tree_root,
            &dependency_lock_root,
            true,
        );
        Self {
            import_id: format!("compile-accepted-{:04}", ordinal),
            ordinal,
            package_id: package_id.to_string(),
            artifact_root,
            compiler_profile_root,
            acceptance_receipt_root,
            source_tree_root,
            dependency_lock_root,
            accepted: true,
            reproducible: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "import_id": self.import_id,
            "ordinal": self.ordinal,
            "package_id": self.package_id,
            "artifact_root": self.artifact_root,
            "compiler_profile_root": self.compiler_profile_root,
            "acceptance_receipt_root": self.acceptance_receipt_root,
            "source_tree_root": self.source_tree_root,
            "dependency_lock_root": self.dependency_lock_root,
            "accepted": self.accepted,
            "reproducible": self.reproducible,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeAcceptedImport {
    pub import_id: String,
    pub ordinal: u64,
    pub runtime_id: String,
    pub runtime_state_root: String,
    pub runtime_receipt_root: String,
    pub accepted_event_root: String,
    pub live_signal_root: String,
    pub accepted_height: u64,
    pub accepted: bool,
    pub replay_protected: bool,
}

impl RuntimeAcceptedImport {
    pub fn devnet(config: &Config, ordinal: u64, runtime_id: &str) -> Self {
        let runtime_state_root = seed_root("runtime-state", runtime_id, ordinal);
        let accepted_event_root = seed_root("runtime-accepted-event", runtime_id, ordinal);
        let live_signal_root = seed_root("runtime-live-signal", runtime_id, ordinal);
        let accepted_height = release_height(config).saturating_add(ordinal);
        let runtime_receipt_root = runtime_acceptance_root(
            config,
            runtime_id,
            ordinal,
            &runtime_state_root,
            &accepted_event_root,
            &live_signal_root,
            accepted_height,
            true,
        );
        Self {
            import_id: format!("runtime-accepted-{:04}", ordinal),
            ordinal,
            runtime_id: runtime_id.to_string(),
            runtime_state_root,
            runtime_receipt_root,
            accepted_event_root,
            live_signal_root,
            accepted_height,
            accepted: true,
            replay_protected: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "import_id": self.import_id,
            "ordinal": self.ordinal,
            "runtime_id": self.runtime_id,
            "runtime_state_root": self.runtime_state_root,
            "runtime_receipt_root": self.runtime_receipt_root,
            "accepted_event_root": self.accepted_event_root,
            "live_signal_root": self.live_signal_root,
            "accepted_height": self.accepted_height,
            "accepted": self.accepted,
            "replay_protected": self.replay_protected,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveEvidenceImport {
    pub evidence_id: String,
    pub ordinal: u64,
    pub source_lane: String,
    pub observation_root: String,
    pub witness_bundle_root: String,
    pub operator_signature_root: String,
    pub freshness_window_blocks: u64,
    pub observed_height: u64,
    pub accepted_height: u64,
    pub live: bool,
    pub accepted: bool,
}

impl LiveEvidenceImport {
    pub fn devnet(config: &Config, ordinal: u64, source_lane: &str) -> Self {
        let observation_root = seed_root("live-observation", source_lane, ordinal);
        let witness_bundle_root = seed_root("live-witness-bundle", source_lane, ordinal);
        let operator_signature_root = seed_root("live-operator-signature", source_lane, ordinal);
        let observed_height = release_height(config).saturating_add(ordinal);
        let freshness_window_blocks = config.max_accepted_lag_blocks.saturating_sub(ordinal % 3);
        let accepted_height = observed_height.saturating_add(1);
        Self {
            evidence_id: format!("live-evidence-{:04}", ordinal),
            ordinal,
            source_lane: source_lane.to_string(),
            observation_root,
            witness_bundle_root,
            operator_signature_root,
            freshness_window_blocks,
            observed_height,
            accepted_height,
            live: true,
            accepted: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "ordinal": self.ordinal,
            "source_lane": self.source_lane,
            "observation_root": self.observation_root,
            "witness_bundle_root": self.witness_bundle_root,
            "operator_signature_root": self.operator_signature_root,
            "freshness_window_blocks": self.freshness_window_blocks,
            "observed_height": self.observed_height,
            "accepted_height": self.accepted_height,
            "live": self.live,
            "accepted": self.accepted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorRunbookBinding {
    pub binding_id: String,
    pub ordinal: u64,
    pub operator_id: String,
    pub role: String,
    pub runbook_step_root: String,
    pub compile_import_root: String,
    pub runtime_import_root: String,
    pub live_evidence_root: String,
    pub acknowledgement_root: String,
    pub escalation_path_root: String,
    pub acknowledged: bool,
    pub fail_closed_ready: bool,
}

impl OperatorRunbookBinding {
    pub fn bind(
        config: &Config,
        ordinal: u64,
        operator_id: &str,
        role: &str,
        compile_import: &CompileAcceptedImport,
        runtime_import: &RuntimeAcceptedImport,
        live_evidence: &LiveEvidenceImport,
    ) -> Self {
        let compile_import_root =
            record_root("compile-accepted-import", &compile_import.public_record());
        let runtime_import_root =
            record_root("runtime-accepted-import", &runtime_import.public_record());
        let live_evidence_root =
            record_root("live-evidence-import", &live_evidence.public_record());
        let runbook_step_root = runbook_step_root(
            config,
            operator_id,
            role,
            ordinal,
            &compile_import_root,
            &runtime_import_root,
            &live_evidence_root,
        );
        let escalation_path_root = seed_root("operator-escalation-path", operator_id, ordinal);
        let acknowledgement_root = operator_acknowledgement_root(
            config,
            operator_id,
            role,
            ordinal,
            &runbook_step_root,
            &escalation_path_root,
            true,
        );
        Self {
            binding_id: format!("operator-runbook-binding-{:04}", ordinal),
            ordinal,
            operator_id: operator_id.to_string(),
            role: role.to_string(),
            runbook_step_root,
            compile_import_root,
            runtime_import_root,
            live_evidence_root,
            acknowledgement_root,
            escalation_path_root,
            acknowledged: true,
            fail_closed_ready: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "ordinal": self.ordinal,
            "operator_id": self.operator_id,
            "role": self.role,
            "runbook_step_root": self.runbook_step_root,
            "compile_import_root": self.compile_import_root,
            "runtime_import_root": self.runtime_import_root,
            "live_evidence_root": self.live_evidence_root,
            "acknowledgement_root": self.acknowledgement_root,
            "escalation_path_root": self.escalation_path_root,
            "acknowledged": self.acknowledged,
            "fail_closed_ready": self.fail_closed_ready,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseDashboardGate {
    pub gate_id: String,
    pub lane: ImportLane,
    pub readiness_status: ReadinessStatus,
    pub required_count: u64,
    pub observed_count: u64,
    pub accepted_count: u64,
    pub rejected_count: u64,
    pub evidence_root: String,
    pub blocking_reason_root: String,
}

impl ReleaseDashboardGate {
    pub fn new(
        gate_id: &str,
        lane: ImportLane,
        required_count: u64,
        observed_count: u64,
        accepted_count: u64,
        evidence_root: String,
        blocking_reason: &str,
    ) -> Self {
        let readiness_status = if accepted_count >= required_count {
            ReadinessStatus::Ready
        } else if observed_count > 0 {
            ReadinessStatus::AuditPending
        } else {
            ReadinessStatus::EvidencePending
        };
        let rejected_count = observed_count.saturating_sub(accepted_count);
        Self {
            gate_id: gate_id.to_string(),
            lane,
            readiness_status,
            required_count,
            observed_count,
            accepted_count,
            rejected_count,
            evidence_root,
            blocking_reason_root: record_root(
                "dashboard-gate-blocking-reason",
                &json!({
                    "gate_id": gate_id,
                    "lane": lane.as_str(),
                    "blocking_reason": blocking_reason,
                    "readiness_status": readiness_status.as_str(),
                }),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "lane": self.lane,
            "readiness_status": self.readiness_status,
            "required_count": self.required_count,
            "observed_count": self.observed_count,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "evidence_root": self.evidence_root,
            "blocking_reason_root": self.blocking_reason_root,
        })
    }

    pub fn ready(&self) -> bool {
        self.readiness_status == ReadinessStatus::Ready
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub compile_import_root: String,
    pub runtime_import_root: String,
    pub live_evidence_root: String,
    pub operator_runbook_root: String,
    pub dashboard_gate_root: String,
    pub audit_finding_root: String,
    pub readiness_verdict_root: String,
    pub release_dashboard_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "compile_import_root": self.compile_import_root,
            "runtime_import_root": self.runtime_import_root,
            "live_evidence_root": self.live_evidence_root,
            "operator_runbook_root": self.operator_runbook_root,
            "dashboard_gate_root": self.dashboard_gate_root,
            "audit_finding_root": self.audit_finding_root,
            "readiness_verdict_root": self.readiness_verdict_root,
            "release_dashboard_root": self.release_dashboard_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub compile_import_count: u64,
    pub compile_accepted_count: u64,
    pub runtime_import_count: u64,
    pub runtime_accepted_count: u64,
    pub live_evidence_count: u64,
    pub live_evidence_accepted_count: u64,
    pub operator_binding_count: u64,
    pub operator_ack_count: u64,
    pub dashboard_gate_count: u64,
    pub ready_gate_count: u64,
    pub blocked_gate_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "compile_import_count": self.compile_import_count,
            "compile_accepted_count": self.compile_accepted_count,
            "runtime_import_count": self.runtime_import_count,
            "runtime_accepted_count": self.runtime_accepted_count,
            "live_evidence_count": self.live_evidence_count,
            "live_evidence_accepted_count": self.live_evidence_accepted_count,
            "operator_binding_count": self.operator_binding_count,
            "operator_ack_count": self.operator_ack_count,
            "dashboard_gate_count": self.dashboard_gate_count,
            "ready_gate_count": self.ready_gate_count,
            "blocked_gate_count": self.blocked_gate_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditFinding {
    pub finding_id: String,
    pub ordinal: u64,
    pub severity: String,
    pub lane: ImportLane,
    pub subject_root: String,
    pub finding_root: String,
    pub resolved: bool,
    pub release_blocking: bool,
}

impl AuditFinding {
    pub fn informational(ordinal: u64, lane: ImportLane, subject_root: &str, label: &str) -> Self {
        Self {
            finding_id: format!("audit-finding-{:04}", ordinal),
            ordinal,
            severity: "informational".to_string(),
            lane,
            subject_root: subject_root.to_string(),
            finding_root: record_root(
                "audit-finding",
                &json!({
                    "ordinal": ordinal,
                    "lane": lane.as_str(),
                    "label": label,
                    "subject_root": subject_root,
                    "resolved": true,
                }),
            ),
            resolved: true,
            release_blocking: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "finding_id": self.finding_id,
            "ordinal": self.ordinal,
            "severity": self.severity,
            "lane": self.lane,
            "subject_root": self.subject_root,
            "finding_root": self.finding_root,
            "resolved": self.resolved,
            "release_blocking": self.release_blocking,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReadinessVerdict {
    pub verdict_id: String,
    pub status: ReadinessStatus,
    pub release_dashboard_ready: bool,
    pub compile_ready: bool,
    pub runtime_ready: bool,
    pub live_evidence_ready: bool,
    pub operator_runbook_ready: bool,
    pub dashboard_ready: bool,
    pub fail_closed_hold: bool,
    pub verdict_root: String,
}

impl ReadinessVerdict {
    pub fn new(
        config: &Config,
        counters: &Counters,
        roots: &Roots,
        gates: &[ReleaseDashboardGate],
    ) -> Self {
        let compile_ready = counters.compile_accepted_count >= config.min_compile_imports;
        let runtime_ready = counters.runtime_accepted_count >= config.min_runtime_imports;
        let live_evidence_ready =
            counters.live_evidence_accepted_count >= config.min_runtime_imports;
        let operator_runbook_ready = counters.operator_ack_count >= config.min_operator_acks;
        let dashboard_ready = gates.iter().all(ReleaseDashboardGate::ready);
        let release_dashboard_ready = compile_ready
            && runtime_ready
            && live_evidence_ready
            && operator_runbook_ready
            && dashboard_ready;
        let fail_closed_hold = config.fail_closed_on_missing_evidence && !release_dashboard_ready;
        let status = if release_dashboard_ready {
            ReadinessStatus::Ready
        } else if counters.live_evidence_count < config.min_runtime_imports {
            ReadinessStatus::EvidencePending
        } else if counters.ready_gate_count < counters.dashboard_gate_count {
            ReadinessStatus::AuditPending
        } else {
            ReadinessStatus::AuditPending
        };
        let verdict_root = readiness_verdict_root(
            config,
            counters,
            roots,
            status,
            release_dashboard_ready,
            fail_closed_hold,
        );
        Self {
            verdict_id: format!("readiness-verdict-epoch-{}", config.release_epoch),
            status,
            release_dashboard_ready,
            compile_ready,
            runtime_ready,
            live_evidence_ready,
            operator_runbook_ready,
            dashboard_ready,
            fail_closed_hold,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "status": self.status,
            "release_dashboard_ready": self.release_dashboard_ready,
            "compile_ready": self.compile_ready,
            "runtime_ready": self.runtime_ready,
            "live_evidence_ready": self.live_evidence_ready,
            "operator_runbook_ready": self.operator_runbook_ready,
            "dashboard_ready": self.dashboard_ready,
            "fail_closed_hold": self.fail_closed_hold,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub compile_imports: Vec<CompileAcceptedImport>,
    pub runtime_imports: Vec<RuntimeAcceptedImport>,
    pub live_evidence_imports: Vec<LiveEvidenceImport>,
    pub operator_bindings: Vec<OperatorRunbookBinding>,
    pub dashboard_gates: Vec<ReleaseDashboardGate>,
    pub audit_findings: Vec<AuditFinding>,
    pub counters: Counters,
    pub roots: Roots,
    pub readiness_verdict: ReadinessVerdict,
    pub state_commitment_root: String,
}

impl State {
    pub fn new(
        config: Config,
        compile_imports: Vec<CompileAcceptedImport>,
        runtime_imports: Vec<RuntimeAcceptedImport>,
        live_evidence_imports: Vec<LiveEvidenceImport>,
        operator_bindings: Vec<OperatorRunbookBinding>,
    ) -> Result<Self> {
        validate_config(&config)?;
        validate_compile_imports(&config, &compile_imports)?;
        validate_runtime_imports(&config, &runtime_imports)?;
        validate_live_evidence(&config, &live_evidence_imports)?;
        validate_operator_bindings(&config, &operator_bindings)?;

        let mut counters = counters(
            &compile_imports,
            &runtime_imports,
            &live_evidence_imports,
            &operator_bindings,
        );
        let roots = roots(
            &compile_imports,
            &runtime_imports,
            &live_evidence_imports,
            &operator_bindings,
            &[],
            &[],
            "",
        );
        let dashboard_gates = dashboard_gates(&config, &counters, &roots);
        apply_dashboard_counts(&mut counters, &dashboard_gates);
        let audit_findings = audit_findings(&roots, &dashboard_gates);
        let mut roots = roots(
            &compile_imports,
            &runtime_imports,
            &live_evidence_imports,
            &operator_bindings,
            &dashboard_gates,
            &audit_findings,
            "",
        );
        let readiness_verdict = ReadinessVerdict::new(&config, &counters, &roots, &dashboard_gates);
        roots.readiness_verdict_root = readiness_verdict.verdict_root.clone();
        roots.release_dashboard_root = release_dashboard_root(
            &config,
            &counters,
            &roots,
            &dashboard_gates,
            &readiness_verdict,
        );
        let state_commitment_root =
            state_commitment_root(&config, &counters, &roots, &readiness_verdict);
        Ok(Self {
            config,
            compile_imports,
            runtime_imports,
            live_evidence_imports,
            operator_bindings,
            dashboard_gates,
            audit_findings,
            counters,
            roots,
            readiness_verdict,
            state_commitment_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "compile_imports": records(&self.compile_imports),
            "runtime_imports": records(&self.runtime_imports),
            "live_evidence_imports": records(&self.live_evidence_imports),
            "operator_bindings": records(&self.operator_bindings),
            "dashboard_gates": records(&self.dashboard_gates),
            "audit_findings": records(&self.audit_findings),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "readiness_verdict": self.readiness_verdict.public_record(),
            "state_commitment_root": self.state_commitment_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_commitment_root.clone()
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

macro_rules! impl_public_record {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl PublicRecord for $ty {
                fn public_record(&self) -> Value {
                    <$ty>::public_record(self)
                }
            }
        )+
    };
}

impl_public_record!(
    CompileAcceptedImport,
    RuntimeAcceptedImport,
    LiveEvidenceImport,
    OperatorRunbookBinding,
    ReleaseDashboardGate,
    AuditFinding,
);

pub fn devnet() -> State {
    match build_devnet() {
        Ok(state) => state,
        Err(reason) => fallback_state(reason),
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn build_devnet() -> Result<State> {
    let config = Config::devnet();
    let compile_imports = vec![
        CompileAcceptedImport::devnet(&config, 1, "force-exit-package-core"),
        CompileAcceptedImport::devnet(&config, 2, "force-exit-package-wallet-scan"),
        CompileAcceptedImport::devnet(&config, 3, "force-exit-package-settlement"),
        CompileAcceptedImport::devnet(&config, 4, "force-exit-package-recovery"),
    ];
    let runtime_imports = vec![
        RuntimeAcceptedImport::devnet(&config, 1, "exit-canonical-user-escape-runtime"),
        RuntimeAcceptedImport::devnet(&config, 2, "wallet-scan-receipt-observer-runtime"),
        RuntimeAcceptedImport::devnet(&config, 3, "settlement-observation-runtime"),
        RuntimeAcceptedImport::devnet(&config, 4, "recovery-playbook-receipt-runtime"),
        RuntimeAcceptedImport::devnet(&config, 5, "private-state-continuity-runtime"),
    ];
    let live_evidence_imports = vec![
        LiveEvidenceImport::devnet(&config, 1, "compile-artifacts"),
        LiveEvidenceImport::devnet(&config, 2, "runtime-receipts"),
        LiveEvidenceImport::devnet(&config, 3, "wallet-observer"),
        LiveEvidenceImport::devnet(&config, 4, "settlement-observer"),
        LiveEvidenceImport::devnet(&config, 5, "recovery-operator"),
    ];
    let operator_bindings = vec![
        OperatorRunbookBinding::bind(
            &config,
            1,
            "operator-release-captain",
            "release-captain",
            &compile_imports[0],
            &runtime_imports[0],
            &live_evidence_imports[0],
        ),
        OperatorRunbookBinding::bind(
            &config,
            2,
            "operator-evidence-auditor",
            "evidence-auditor",
            &compile_imports[1],
            &runtime_imports[1],
            &live_evidence_imports[1],
        ),
        OperatorRunbookBinding::bind(
            &config,
            3,
            "operator-dashboard-signer",
            "dashboard-signer",
            &compile_imports[2],
            &runtime_imports[2],
            &live_evidence_imports[2],
        ),
    ];
    State::new(
        config,
        compile_imports,
        runtime_imports,
        live_evidence_imports,
        operator_bindings,
    )
}

fn counters(
    compile_imports: &[CompileAcceptedImport],
    runtime_imports: &[RuntimeAcceptedImport],
    live_evidence_imports: &[LiveEvidenceImport],
    operator_bindings: &[OperatorRunbookBinding],
) -> Counters {
    let compile_accepted_count = compile_imports
        .iter()
        .filter(|import| import.accepted && import.reproducible)
        .count() as u64;
    let runtime_accepted_count = runtime_imports
        .iter()
        .filter(|import| import.accepted && import.replay_protected)
        .count() as u64;
    let live_evidence_accepted_count = live_evidence_imports
        .iter()
        .filter(|evidence| evidence.live && evidence.accepted)
        .count() as u64;
    let operator_ack_count = operator_bindings
        .iter()
        .filter(|binding| binding.acknowledged && binding.fail_closed_ready)
        .count() as u64;
    Counters {
        compile_import_count: compile_imports.len() as u64,
        compile_accepted_count,
        runtime_import_count: runtime_imports.len() as u64,
        runtime_accepted_count,
        live_evidence_count: live_evidence_imports.len() as u64,
        live_evidence_accepted_count,
        operator_binding_count: operator_bindings.len() as u64,
        operator_ack_count,
        dashboard_gate_count: 0,
        ready_gate_count: 0,
        blocked_gate_count: 0,
    }
}

fn dashboard_gates(
    config: &Config,
    counters: &Counters,
    roots: &Roots,
) -> Vec<ReleaseDashboardGate> {
    let mut gates = Vec::with_capacity(5);
    gates.push(ReleaseDashboardGate::new(
        "gate-compile-accepted",
        ImportLane::CompileAccepted,
        config.min_compile_imports,
        counters.compile_import_count,
        counters.compile_accepted_count,
        roots.compile_import_root.clone(),
        "compile imports must be reproducible and accepted",
    ));
    gates.push(ReleaseDashboardGate::new(
        "gate-runtime-accepted",
        ImportLane::RuntimeAccepted,
        config.min_runtime_imports,
        counters.runtime_import_count,
        counters.runtime_accepted_count,
        roots.runtime_import_root.clone(),
        "runtime imports must be accepted with replay protection",
    ));
    gates.push(ReleaseDashboardGate::new(
        "gate-live-evidence",
        ImportLane::LiveEvidence,
        config.min_runtime_imports,
        counters.live_evidence_count,
        counters.live_evidence_accepted_count,
        roots.live_evidence_root.clone(),
        "live evidence must be fresh and accepted",
    ));
    gates.push(ReleaseDashboardGate::new(
        "gate-operator-runbook",
        ImportLane::OperatorRunbook,
        config.min_operator_acks,
        counters.operator_binding_count,
        counters.operator_ack_count,
        roots.operator_runbook_root.clone(),
        "operators must acknowledge bound runbook steps",
    ));
    gates.push(ReleaseDashboardGate::new(
        "gate-release-dashboard",
        ImportLane::ReleaseDashboard,
        4,
        4,
        if counters.compile_accepted_count >= config.min_compile_imports
            && counters.runtime_accepted_count >= config.min_runtime_imports
            && counters.live_evidence_accepted_count >= config.min_runtime_imports
            && counters.operator_ack_count >= config.min_operator_acks
        {
            4
        } else {
            0
        },
        release_dashboard_projection_root(config, counters, roots),
        "release dashboard projection must show all readiness lanes green",
    ));
    gates
}

fn apply_dashboard_counts(counters: &mut Counters, gates: &[ReleaseDashboardGate]) {
    counters.dashboard_gate_count = gates.len() as u64;
    counters.ready_gate_count = gates.iter().filter(|gate| gate.ready()).count() as u64;
    counters.blocked_gate_count = gates
        .iter()
        .filter(|gate| gate.readiness_status != ReadinessStatus::Ready)
        .count() as u64;
}

fn audit_findings(roots: &Roots, gates: &[ReleaseDashboardGate]) -> Vec<AuditFinding> {
    gates
        .iter()
        .enumerate()
        .map(|(index, gate)| {
            AuditFinding::informational(
                (index as u64).saturating_add(1),
                gate.lane,
                &record_root("release-dashboard-gate", &gate.public_record()),
                &format!("{} bound into release dashboard", gate.gate_id),
            )
        })
        .chain([AuditFinding::informational(
            100,
            ImportLane::ReleaseDashboard,
            &roots.release_dashboard_root,
            "release dashboard root reserved for readiness projection",
        )])
        .collect()
}

fn roots(
    compile_imports: &[CompileAcceptedImport],
    runtime_imports: &[RuntimeAcceptedImport],
    live_evidence_imports: &[LiveEvidenceImport],
    operator_bindings: &[OperatorRunbookBinding],
    dashboard_gates: &[ReleaseDashboardGate],
    audit_findings: &[AuditFinding],
    readiness_verdict_root: &str,
) -> Roots {
    let compile_records = records(compile_imports);
    let runtime_records = records(runtime_imports);
    let live_records = records(live_evidence_imports);
    let operator_records = records(operator_bindings);
    let gate_records = records(dashboard_gates);
    let finding_records = records(audit_findings);
    Roots {
        compile_import_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-COMPILE-IMPORTS",
            &compile_records,
        ),
        runtime_import_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RUNTIME-IMPORTS",
            &runtime_records,
        ),
        live_evidence_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-LIVE-EVIDENCE",
            &live_records,
        ),
        operator_runbook_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-OPERATOR-BINDINGS",
            &operator_records,
        ),
        dashboard_gate_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-DASHBOARD-GATES",
            &gate_records,
        ),
        audit_finding_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-FINDINGS",
            &finding_records,
        ),
        readiness_verdict_root: readiness_verdict_root.to_string(),
        release_dashboard_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RELEASE-DASHBOARD",
            &[],
        ),
    }
}

fn validate_config(config: &Config) -> Result<()> {
    ensure(
        config.chain_id == CHAIN_ID,
        "operator runbook audit chain mismatch",
    )?;
    ensure(
        config.protocol_version == PROTOCOL_VERSION,
        "operator runbook audit protocol mismatch",
    )?;
    ensure(
        config.schema_version == SCHEMA_VERSION,
        "operator runbook audit schema mismatch",
    )?;
    ensure(
        config.min_compile_imports > 0,
        "operator runbook audit requires compile imports",
    )?;
    ensure(
        config.min_runtime_imports > 0,
        "operator runbook audit requires runtime imports",
    )?;
    ensure(
        config.min_operator_acks > 0,
        "operator runbook audit requires operator acknowledgements",
    )?;
    ensure(
        config.max_accepted_lag_blocks > 0,
        "operator runbook audit requires accepted lag bound",
    )?;
    Ok(())
}

fn validate_compile_imports(config: &Config, imports: &[CompileAcceptedImport]) -> Result<()> {
    ensure(
        imports.len() as u64 >= config.min_compile_imports,
        "operator runbook audit has too few compile imports",
    )?;
    if config.require_compile_acceptance {
        ensure(
            imports
                .iter()
                .all(|import| import.accepted && import.reproducible),
            "operator runbook audit compile import not accepted",
        )?;
    }
    Ok(())
}

fn validate_runtime_imports(config: &Config, imports: &[RuntimeAcceptedImport]) -> Result<()> {
    ensure(
        imports.len() as u64 >= config.min_runtime_imports,
        "operator runbook audit has too few runtime imports",
    )?;
    if config.require_runtime_acceptance {
        ensure(
            imports
                .iter()
                .all(|import| import.accepted && import.replay_protected),
            "operator runbook audit runtime import not accepted",
        )?;
    }
    Ok(())
}

fn validate_live_evidence(config: &Config, imports: &[LiveEvidenceImport]) -> Result<()> {
    ensure(
        imports.len() as u64 >= config.min_runtime_imports,
        "operator runbook audit has too few live evidence imports",
    )?;
    if config.require_live_evidence {
        ensure(
            imports.iter().all(|import| {
                import.live
                    && import.accepted
                    && import
                        .accepted_height
                        .saturating_sub(import.observed_height)
                        <= config.max_accepted_lag_blocks
            }),
            "operator runbook audit live evidence not fresh",
        )?;
    }
    Ok(())
}

fn validate_operator_bindings(config: &Config, bindings: &[OperatorRunbookBinding]) -> Result<()> {
    ensure(
        bindings.len() as u64 >= config.min_operator_acks,
        "operator runbook audit has too few operator bindings",
    )?;
    if config.require_operator_runbook_binding {
        ensure(
            bindings
                .iter()
                .all(|binding| binding.acknowledged && binding.fail_closed_ready),
            "operator runbook audit operator binding not acknowledged",
        )?;
    }
    Ok(())
}

fn compile_acceptance_root(
    config: &Config,
    package_id: &str,
    ordinal: u64,
    artifact_root: &str,
    compiler_profile_root: &str,
    source_tree_root: &str,
    dependency_lock_root: &str,
    accepted: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-COMPILE-ACCEPTANCE",
        &[
            HashPart::Str(&config.runbook_audit_suite),
            HashPart::Str(package_id),
            HashPart::U64(ordinal),
            HashPart::Str(artifact_root),
            HashPart::Str(compiler_profile_root),
            HashPart::Str(source_tree_root),
            HashPart::Str(dependency_lock_root),
            HashPart::Str(bool_str(accepted)),
        ],
        32,
    )
}

fn runtime_acceptance_root(
    config: &Config,
    runtime_id: &str,
    ordinal: u64,
    runtime_state_root: &str,
    accepted_event_root: &str,
    live_signal_root: &str,
    accepted_height: u64,
    accepted: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RUNTIME-ACCEPTANCE",
        &[
            HashPart::Str(&config.runbook_audit_suite),
            HashPart::Str(runtime_id),
            HashPart::U64(ordinal),
            HashPart::Str(runtime_state_root),
            HashPart::Str(accepted_event_root),
            HashPart::Str(live_signal_root),
            HashPart::U64(accepted_height),
            HashPart::Str(bool_str(accepted)),
        ],
        32,
    )
}

fn runbook_step_root(
    config: &Config,
    operator_id: &str,
    role: &str,
    ordinal: u64,
    compile_import_root: &str,
    runtime_import_root: &str,
    live_evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RUNBOOK-STEP",
        &[
            HashPart::Str(&config.runbook_audit_suite),
            HashPart::Str(operator_id),
            HashPart::Str(role),
            HashPart::U64(ordinal),
            HashPart::Str(compile_import_root),
            HashPart::Str(runtime_import_root),
            HashPart::Str(live_evidence_root),
        ],
        32,
    )
}

fn operator_acknowledgement_root(
    config: &Config,
    operator_id: &str,
    role: &str,
    ordinal: u64,
    runbook_step_root: &str,
    escalation_path_root: &str,
    acknowledged: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-OPERATOR-ACK",
        &[
            HashPart::Str(&config.runbook_audit_suite),
            HashPart::Str(operator_id),
            HashPart::Str(role),
            HashPart::U64(ordinal),
            HashPart::Str(runbook_step_root),
            HashPart::Str(escalation_path_root),
            HashPart::Str(bool_str(acknowledged)),
        ],
        32,
    )
}

fn readiness_verdict_root(
    config: &Config,
    counters: &Counters,
    roots: &Roots,
    status: ReadinessStatus,
    release_dashboard_ready: bool,
    fail_closed_hold: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-READINESS-VERDICT",
        &[
            HashPart::Str(&config.runbook_audit_suite),
            HashPart::Str(&config.release_channel),
            HashPart::U64(config.release_epoch),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(release_dashboard_ready)),
            HashPart::Str(bool_str(fail_closed_hold)),
        ],
        32,
    )
}

fn release_dashboard_projection_root(
    config: &Config,
    counters: &Counters,
    roots: &Roots,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-DASHBOARD-PROJECTION",
        &[
            HashPart::Str(&config.runbook_audit_suite),
            HashPart::Str(&config.release_channel),
            HashPart::U64(config.release_epoch),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&roots.compile_import_root),
            HashPart::Str(&roots.runtime_import_root),
            HashPart::Str(&roots.live_evidence_root),
            HashPart::Str(&roots.operator_runbook_root),
        ],
        32,
    )
}

fn release_dashboard_root(
    config: &Config,
    counters: &Counters,
    roots: &Roots,
    gates: &[ReleaseDashboardGate],
    readiness_verdict: &ReadinessVerdict,
) -> String {
    let gate_records = records(gates);
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RELEASE-DASHBOARD-ROOT",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&roots.dashboard_gate_root),
            HashPart::Str(&merkle_root(
                "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RELEASE-DASHBOARD-GATES",
                &gate_records,
            )),
            HashPart::Str(&readiness_verdict.verdict_root),
            HashPart::Str(bool_str(readiness_verdict.release_dashboard_ready)),
        ],
        32,
    )
}

fn state_commitment_root(
    config: &Config,
    counters: &Counters,
    roots: &Roots,
    readiness_verdict: &ReadinessVerdict,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&roots.state_root()),
            HashPart::Str(&record_root(
                "readiness-verdict",
                &readiness_verdict.public_record(),
            )),
            HashPart::Str(&roots.release_dashboard_root),
        ],
        32,
    )
}

fn seed_root(label: &str, seed: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-SEED",
        &[
            HashPart::Str(label),
            HashPart::Str(seed),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-FORCE-EXIT-RUNBOOK-AUDIT-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn records<T: PublicRecord>(items: &[T]) -> Vec<Value> {
    items.iter().map(PublicRecord::public_record).collect()
}

fn release_height(config: &Config) -> u64 {
    config.release_epoch.saturating_mul(10_000)
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let compile_imports = vec![CompileAcceptedImport::devnet(
        &config,
        1,
        "fallback-force-exit-package",
    )];
    let runtime_imports = vec![RuntimeAcceptedImport::devnet(
        &config,
        1,
        "fallback-force-exit-runtime",
    )];
    let live_evidence_imports = vec![LiveEvidenceImport::devnet(&config, 1, "fallback-evidence")];
    let operator_bindings = vec![OperatorRunbookBinding::bind(
        &config,
        1,
        "fallback-operator",
        "fallback-release-captain",
        &compile_imports[0],
        &runtime_imports[0],
        &live_evidence_imports[0],
    )];
    let mut counters = counters(
        &compile_imports,
        &runtime_imports,
        &live_evidence_imports,
        &operator_bindings,
    );
    counters.blocked_gate_count = 1;
    let mut roots = roots(
        &compile_imports,
        &runtime_imports,
        &live_evidence_imports,
        &operator_bindings,
        &[],
        &[],
        "",
    );
    roots.audit_finding_root = record_root(
        "fallback-audit-finding",
        &json!({
            "reason": reason,
            "fail_closed": true,
        }),
    );
    let dashboard_gates = vec![ReleaseDashboardGate::new(
        "gate-fallback-fail-closed",
        ImportLane::ReleaseDashboard,
        1,
        1,
        0,
        roots.audit_finding_root.clone(),
        "fallback state is fail closed",
    )];
    counters.dashboard_gate_count = dashboard_gates.len() as u64;
    counters.ready_gate_count = 0;
    counters.blocked_gate_count = dashboard_gates.len() as u64;
    let audit_findings = audit_findings(&roots, &dashboard_gates);
    roots = roots(
        &compile_imports,
        &runtime_imports,
        &live_evidence_imports,
        &operator_bindings,
        &dashboard_gates,
        &audit_findings,
        "",
    );
    let readiness_verdict = ReadinessVerdict::new(&config, &counters, &roots, &dashboard_gates);
    roots.readiness_verdict_root = readiness_verdict.verdict_root.clone();
    roots.release_dashboard_root = release_dashboard_root(
        &config,
        &counters,
        &roots,
        &dashboard_gates,
        &readiness_verdict,
    );
    let state_commitment_root =
        state_commitment_root(&config, &counters, &roots, &readiness_verdict);
    State {
        config,
        compile_imports,
        runtime_imports,
        live_evidence_imports,
        operator_bindings,
        dashboard_gates,
        audit_findings,
        counters,
        roots,
        readiness_verdict,
        state_commitment_root,
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
