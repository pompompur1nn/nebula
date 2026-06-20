use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime::{
        CargoRuntimeHarnessReport, CargoRuntimeHarnessReportStatus,
        State as CargoRuntimeHarnessState,
    },
    monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::{
        SafetyCaseReport, SafetyCaseVerdict, State as SafetyCaseState,
    },
    monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::{
        AdapterReadinessStatus, LiveAdapterKind, LiveAdapterRequirement,
        State as LiveAdapterMatrixState,
    },
    monero_l2_pq_bridge_exit_live_adapter_stub_registry_runtime::{
        AdapterStubStatus, LiveAdapterStub, State as LiveAdapterStubRegistryState,
    },
    monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime::{
        PqAuthorityKeyManagerReport, PqAuthorityKeyManagerReportStatus, State as PqAuthorityState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitSecurityAuditHarnessAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_SECURITY_AUDIT_HARNESS_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-security-audit-harness-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_SECURITY_AUDIT_HARNESS_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SECURITY_AUDIT_HARNESS_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-security-audit-harness-adapter-v1";
pub const DEFAULT_MIN_AUDIT_CASES: u64 = 15;
pub const DEFAULT_MAX_MEDIUM_FINDINGS: u64 = 0;
pub const DEFAULT_RETRY_AFTER_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAuditCaseStatus {
    Passed,
    Deferred,
    Rejected,
}

impl SecurityAuditCaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAuditFindingSeverity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl SecurityAuditFindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAuditHarnessReportStatus {
    Passed,
    Watch,
    Failed,
}

impl SecurityAuditHarnessReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub adapter_suite: String,
    pub min_audit_cases: u64,
    pub max_medium_findings: u64,
    pub live_security_audit_enabled: bool,
    pub security_audit_deferred: bool,
    pub require_cargo_execution: bool,
    pub require_pq_authority_green: bool,
    pub fail_closed_on_critical_finding: bool,
    pub retry_after_blocks: u64,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            adapter_suite: SECURITY_AUDIT_HARNESS_ADAPTER_SUITE.to_string(),
            min_audit_cases: DEFAULT_MIN_AUDIT_CASES,
            max_medium_findings: DEFAULT_MAX_MEDIUM_FINDINGS,
            live_security_audit_enabled: false,
            security_audit_deferred: true,
            require_cargo_execution: true,
            require_pq_authority_green: true,
            fail_closed_on_critical_finding: true,
            retry_after_blocks: DEFAULT_RETRY_AFTER_BLOCKS,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "adapter_suite": self.adapter_suite,
            "min_audit_cases": self.min_audit_cases,
            "max_medium_findings": self.max_medium_findings,
            "live_security_audit_enabled": self.live_security_audit_enabled,
            "security_audit_deferred": self.security_audit_deferred,
            "require_cargo_execution": self.require_cargo_execution,
            "require_pq_authority_green": self.require_pq_authority_green,
            "fail_closed_on_critical_finding": self.fail_closed_on_critical_finding,
            "retry_after_blocks": self.retry_after_blocks,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityAuditCase {
    pub case_id: String,
    pub status: SecurityAuditCaseStatus,
    pub severity: SecurityAuditFindingSeverity,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub audit_scope_root: String,
    pub pq_surface_root: String,
    pub privacy_surface_root: String,
    pub finding_root: String,
    pub residual_risk_root: String,
    pub signoff_root: String,
    pub safety_case_report_id: String,
    pub safety_case_verdict: SafetyCaseVerdict,
    pub cargo_harness_report_id: String,
    pub cargo_harness_status: CargoRuntimeHarnessReportStatus,
    pub pq_authority_report_id: String,
    pub pq_authority_status: PqAuthorityKeyManagerReportStatus,
    pub finding_count: u64,
    pub audit_passed: bool,
    pub release_blocks: bool,
    pub production_blocks: bool,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub case_root: String,
}

impl SecurityAuditCase {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        safety_report: &SafetyCaseReport,
        cargo_report: &CargoRuntimeHarnessReport,
        pq_report: &PqAuthorityKeyManagerReport,
        ordinal: u64,
    ) -> Self {
        let audit_scope_root = audit_scope_root(
            &safety_report.roots.source_root,
            &safety_report.roots.evidence_root,
            &cargo_report.roots.case_root,
            &requirement.fixture_root,
            ordinal,
        );
        let pq_surface_root = pq_surface_root(
            &pq_report.roots.observation_root,
            &pq_report.roots.response_root,
            &pq_report.roots.failure_root,
            pq_report.signatures_valid,
            pq_report.release_holds_required,
        );
        let privacy_surface_root = privacy_surface_root(
            &safety_report.transcript_root,
            &safety_report.bridge_spine_state_root,
            &safety_report.transfer_runtime_state_root,
            safety_report.watch_items,
            safety_report.production_blockers,
        );
        let status = audit_case_status(
            config,
            requirement.status,
            safety_report.verdict,
            cargo_report.status,
            pq_report.status,
        );
        let severity = finding_severity(
            status,
            safety_report.verdict,
            cargo_report.status,
            pq_report.status,
            cargo_report.tests_executed,
            pq_report.signatures_valid,
        );
        let finding_count = if severity == SecurityAuditFindingSeverity::None {
            0
        } else {
            1
        };
        let finding_root = finding_root(
            status,
            severity,
            &audit_scope_root,
            &pq_surface_root,
            &privacy_surface_root,
            finding_count,
        );
        let release_blocks = status == SecurityAuditCaseStatus::Rejected
            || severity >= SecurityAuditFindingSeverity::High
            || (config.require_pq_authority_green
                && pq_report.status != PqAuthorityKeyManagerReportStatus::Passed);
        let production_blocks = release_blocks
            || config.security_audit_deferred
            || cargo_report.tests_executed == 0
            || safety_report.production_blockers > 0
            || severity != SecurityAuditFindingSeverity::None;
        let audit_passed = config.live_security_audit_enabled
            && status == SecurityAuditCaseStatus::Passed
            && severity == SecurityAuditFindingSeverity::None
            && !production_blocks;
        let residual_risk_root = residual_risk_root(
            severity,
            finding_count,
            safety_report.deferred_gates,
            cargo_report.release_holds_required,
            pq_report.release_holds_required,
            production_blocks,
        );
        let signoff_root = signoff_root(
            audit_passed,
            &residual_risk_root,
            &finding_root,
            &cargo_report.roots.report_root,
            &pq_report.roots.report_root,
            config.security_audit_deferred,
        );
        let case_root = security_audit_case_root(
            status,
            severity,
            &requirement.requirement_id,
            &audit_scope_root,
            &finding_root,
            &residual_risk_root,
            &signoff_root,
            audit_passed,
        );
        let case_id = security_audit_case_id(
            &requirement.requirement_id,
            &safety_report.report_id,
            &case_root,
        );
        Self {
            case_id,
            status,
            severity,
            requirement_id: requirement.requirement_id.clone(),
            fixture_export_id: requirement.fixture_export_id.clone(),
            vector_id: requirement.vector_id.clone(),
            test_name: requirement.test_name.clone(),
            scenario_id: requirement.scenario_id.clone(),
            transfer_id: requirement.transfer_id.clone(),
            release_claim_id: requirement.release_claim_id.clone(),
            audit_scope_root,
            pq_surface_root,
            privacy_surface_root,
            finding_root,
            residual_risk_root,
            signoff_root,
            safety_case_report_id: safety_report.report_id.clone(),
            safety_case_verdict: safety_report.verdict,
            cargo_harness_report_id: cargo_report.report_id.clone(),
            cargo_harness_status: cargo_report.status,
            pq_authority_report_id: pq_report.report_id.clone(),
            pq_authority_status: pq_report.status,
            finding_count,
            audit_passed,
            release_blocks,
            production_blocks,
            fixture_root: requirement.fixture_root.clone(),
            adapter_input_root: requirement.adapter_input_root.clone(),
            readiness_root: requirement.readiness_root.clone(),
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "requirement_id": self.requirement_id,
            "fixture_export_id": self.fixture_export_id,
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "audit_scope_root": self.audit_scope_root,
            "pq_surface_root": self.pq_surface_root,
            "privacy_surface_root": self.privacy_surface_root,
            "finding_root": self.finding_root,
            "residual_risk_root": self.residual_risk_root,
            "signoff_root": self.signoff_root,
            "safety_case_report_id": self.safety_case_report_id,
            "safety_case_verdict": self.safety_case_verdict.as_str(),
            "cargo_harness_report_id": self.cargo_harness_report_id,
            "cargo_harness_status": self.cargo_harness_status.as_str(),
            "pq_authority_report_id": self.pq_authority_report_id,
            "pq_authority_status": self.pq_authority_status.as_str(),
            "finding_count": self.finding_count,
            "audit_passed": self.audit_passed,
            "release_blocks": self.release_blocks,
            "production_blocks": self.production_blocks,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "case_root": self.case_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("security_audit_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityAuditResponse {
    pub response_id: String,
    pub case_id: String,
    pub status: SecurityAuditCaseStatus,
    pub audit_passed: bool,
    pub finding_count: u64,
    pub residual_risk_root: String,
    pub signoff_root: String,
    pub release_hold_required: bool,
    pub adapter_root: String,
    pub response_label: String,
}

impl SecurityAuditResponse {
    pub fn from_case(config: &Config, case: &SecurityAuditCase) -> Self {
        let release_hold_required = !case.audit_passed || case.release_blocks;
        let response_label = response_label(config, case).to_string();
        let adapter_root = adapter_response_root(
            case.status,
            case.audit_passed,
            case.finding_count,
            &case.residual_risk_root,
            &case.signoff_root,
            release_hold_required,
            &response_label,
        );
        let response_id = adapter_response_id(&case.case_id, &adapter_root);
        Self {
            response_id,
            case_id: case.case_id.clone(),
            status: case.status,
            audit_passed: case.audit_passed,
            finding_count: case.finding_count,
            residual_risk_root: case.residual_risk_root.clone(),
            signoff_root: case.signoff_root.clone(),
            release_hold_required,
            adapter_root,
            response_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "case_id": self.case_id,
            "status": self.status.as_str(),
            "audit_passed": self.audit_passed,
            "finding_count": self.finding_count,
            "residual_risk_root": self.residual_risk_root,
            "signoff_root": self.signoff_root,
            "release_hold_required": self.release_hold_required,
            "adapter_root": self.adapter_root,
            "response_label": self.response_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("security_audit_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityAuditFailureSurface {
    pub failure_id: String,
    pub case_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_blocks: u64,
}

impl SecurityAuditFailureSurface {
    pub fn from_case(config: &Config, case: &SecurityAuditCase) -> Self {
        let error_code = error_code(config, case).to_string();
        let quarantine_required = case.status == SecurityAuditCaseStatus::Rejected
            || (config.fail_closed_on_critical_finding
                && case.severity >= SecurityAuditFindingSeverity::Critical);
        let retry_after_blocks = if error_code == "none" {
            0
        } else {
            config.retry_after_blocks
        };
        let failure_root = security_audit_failure_root(
            &case.case_id,
            &error_code,
            quarantine_required,
            retry_after_blocks,
        );
        let failure_id = security_audit_failure_id(&case.case_id, &failure_root);
        Self {
            failure_id,
            case_id: case.case_id.clone(),
            error_code,
            failure_root,
            quarantine_required,
            retry_after_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "failure_id": self.failure_id,
            "case_id": self.case_id,
            "error_code": self.error_code,
            "failure_root": self.failure_root,
            "quarantine_required": self.quarantine_required,
            "retry_after_blocks": self.retry_after_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("security_audit_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityAuditHarnessReport {
    pub report_id: String,
    pub status: SecurityAuditHarnessReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub safety_case_state_root: String,
    pub safety_case_report_root: String,
    pub cargo_harness_state_root: String,
    pub cargo_harness_report_root: String,
    pub pq_authority_state_root: String,
    pub pq_authority_report_root: String,
    pub security_audit_stub_id: String,
    pub security_audit_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub cases_total: u64,
    pub cases_passed: u64,
    pub cases_deferred: u64,
    pub cases_rejected: u64,
    pub audits_passed: u64,
    pub findings_total: u64,
    pub medium_findings: u64,
    pub high_or_critical_findings: u64,
    pub release_holds_required: u64,
    pub quarantine_required: u64,
    pub cases: BTreeMap<String, SecurityAuditCase>,
    pub responses: BTreeMap<String, SecurityAuditResponse>,
    pub failures: BTreeMap<String, SecurityAuditFailureSurface>,
    pub roots: SecurityAuditHarnessReportRoots,
}

impl SecurityAuditHarnessReport {
    pub fn public_record(&self) -> Value {
        let cases = self
            .cases
            .values()
            .map(SecurityAuditCase::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(SecurityAuditResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(SecurityAuditFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "safety_case_state_root": self.safety_case_state_root,
            "safety_case_report_root": self.safety_case_report_root,
            "cargo_harness_state_root": self.cargo_harness_state_root,
            "cargo_harness_report_root": self.cargo_harness_report_root,
            "pq_authority_state_root": self.pq_authority_state_root,
            "pq_authority_report_root": self.pq_authority_report_root,
            "security_audit_stub_id": self.security_audit_stub_id,
            "security_audit_stub_status": self.security_audit_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "cases_total": self.cases_total,
            "cases_passed": self.cases_passed,
            "cases_deferred": self.cases_deferred,
            "cases_rejected": self.cases_rejected,
            "audits_passed": self.audits_passed,
            "findings_total": self.findings_total,
            "medium_findings": self.medium_findings,
            "high_or_critical_findings": self.high_or_critical_findings,
            "release_holds_required": self.release_holds_required,
            "quarantine_required": self.quarantine_required,
            "cases": cases,
            "responses": responses,
            "failures": failures,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityAuditHarnessReportRoots {
    pub case_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl SecurityAuditHarnessReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "case_root": self.case_root,
            "response_root": self.response_root,
            "failure_root": self.failure_root,
            "source_root": self.source_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_passed: u64,
    pub reports_watch: u64,
    pub reports_failed: u64,
    pub cases_total: u64,
    pub cases_passed: u64,
    pub cases_deferred: u64,
    pub cases_rejected: u64,
    pub audits_passed: u64,
    pub findings_total: u64,
    pub medium_findings: u64,
    pub high_or_critical_findings: u64,
    pub release_holds_required: u64,
    pub quarantine_required: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "cases_total": self.cases_total,
            "cases_passed": self.cases_passed,
            "cases_deferred": self.cases_deferred,
            "cases_rejected": self.cases_rejected,
            "audits_passed": self.audits_passed,
            "findings_total": self.findings_total,
            "medium_findings": self.medium_findings,
            "high_or_critical_findings": self.high_or_critical_findings,
            "release_holds_required": self.release_holds_required,
            "quarantine_required": self.quarantine_required,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub report_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-HARNESS-EMPTY-REPORTS",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "report_root": self.report_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-HARNESS-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.report_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_report: Option<SecurityAuditHarnessReport>,
    pub report_history: Vec<SecurityAuditHarnessReport>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_report: None,
            report_history: Vec::new(),
            counters,
            roots,
        };
        let matrix =
            crate::monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::devnet();
        let stub_registry =
            crate::monero_l2_pq_bridge_exit_live_adapter_stub_registry_runtime::devnet();
        let safety_case = crate::monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::devnet();
        let cargo_harness =
            crate::monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime::devnet();
        let pq_authority =
            crate::monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime::devnet();
        state
            .process_security_audit_harness_adapter(
                &matrix,
                &stub_registry,
                &safety_case,
                &cargo_harness,
                &pq_authority,
            )
            .expect("devnet bridge exit security audit harness adapter");
        state
    }

    pub fn process_security_audit_harness_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        safety_case: &SafetyCaseState,
        cargo_harness: &CargoRuntimeHarnessState,
        pq_authority: &PqAuthorityState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let safety_report = safety_case
            .latest_report
            .as_ref()
            .ok_or_else(|| "bridge exit safety case has no latest report".to_string())?;
        let cargo_report = cargo_harness
            .latest_report
            .as_ref()
            .ok_or_else(|| "cargo runtime harness adapter has no latest report".to_string())?;
        let pq_report = pq_authority
            .latest_report
            .as_ref()
            .ok_or_else(|| "PQ authority adapter has no latest report".to_string())?;
        let security_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::SecurityAuditHarness)
            .ok_or_else(|| "security audit harness adapter stub is missing".to_string())?;
        let audit_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::SecurityAuditHarness)
            .collect::<Vec<_>>();
        ensure(
            audit_requirements.len() as u64 >= self.config.min_audit_cases,
            "security audit harness adapter omitted required audit cases",
        )?;
        let cases = audit_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                SecurityAuditCase::from_requirement(
                    &self.config,
                    *requirement,
                    safety_report,
                    cargo_report,
                    pq_report,
                    index as u64,
                )
            })
            .map(|case| (case.case_id.clone(), case))
            .collect::<BTreeMap<_, _>>();
        let responses = cases
            .values()
            .map(|case| SecurityAuditResponse::from_case(&self.config, case))
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = cases
            .values()
            .map(|case| SecurityAuditFailureSurface::from_case(&self.config, case))
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let cases_total = cases.len() as u64;
        let cases_passed = cases
            .values()
            .filter(|case| case.status == SecurityAuditCaseStatus::Passed)
            .count() as u64;
        let cases_deferred = cases
            .values()
            .filter(|case| case.status == SecurityAuditCaseStatus::Deferred)
            .count() as u64;
        let cases_rejected = cases
            .values()
            .filter(|case| case.status == SecurityAuditCaseStatus::Rejected)
            .count() as u64;
        let audits_passed = responses
            .values()
            .filter(|response| response.audit_passed)
            .count() as u64;
        let findings_total = cases.values().map(|case| case.finding_count).sum::<u64>();
        let medium_findings = cases
            .values()
            .filter(|case| case.severity == SecurityAuditFindingSeverity::Medium)
            .count() as u64;
        let high_or_critical_findings = cases
            .values()
            .filter(|case| case.severity >= SecurityAuditFindingSeverity::High)
            .count() as u64;
        let release_holds_required = responses
            .values()
            .filter(|response| response.release_hold_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            &self.config,
            security_stub,
            cases_deferred,
            cases_rejected,
            findings_total,
            medium_findings,
            high_or_critical_findings,
            release_holds_required,
        );
        let readiness_label = readiness_label(
            status,
            security_stub.status,
            self.config.live_security_audit_enabled,
        )
        .to_string();
        let case_records = cases
            .values()
            .map(SecurityAuditCase::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(SecurityAuditResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(SecurityAuditFailureSurface::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-HARNESS-CASES",
            &case_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-HARNESS-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-HARNESS-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &safety_case.state_root(),
            &safety_report.state_root(),
            &cargo_harness.state_root(),
            &cargo_report.state_root(),
            &pq_authority.state_root(),
            &pq_report.state_root(),
            &security_stub.stub_id,
            &security_stub.request_schema_root,
            &security_stub.response_schema_root,
            &security_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &case_root,
            &response_root,
            &failure_root,
            &cargo_report.release_claim_id,
        );
        let report_id =
            security_audit_harness_report_id(&cargo_report.release_claim_id, &report_root);
        let report = SecurityAuditHarnessReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            safety_case_state_root: safety_case.state_root(),
            safety_case_report_root: safety_report.state_root(),
            cargo_harness_state_root: cargo_harness.state_root(),
            cargo_harness_report_root: cargo_report.state_root(),
            pq_authority_state_root: pq_authority.state_root(),
            pq_authority_report_root: pq_report.state_root(),
            security_audit_stub_id: security_stub.stub_id.clone(),
            security_audit_stub_status: security_stub.status,
            release_claim_id: cargo_report.release_claim_id.clone(),
            cases_total,
            cases_passed,
            cases_deferred,
            cases_rejected,
            audits_passed,
            findings_total,
            medium_findings,
            high_or_critical_findings,
            release_holds_required,
            quarantine_required,
            cases,
            responses,
            failures,
            roots: SecurityAuditHarnessReportRoots {
                case_root,
                response_root,
                failure_root,
                source_root,
                report_root,
            },
        };
        self.record_report(report);
        Ok(report_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "adapter_suite": self.config.adapter_suite,
            "latest_report": self.latest_report.as_ref().map(SecurityAuditHarnessReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: SecurityAuditHarnessReport) {
        self.counters.reports_run += 1;
        self.counters.cases_total += report.cases_total;
        self.counters.cases_passed += report.cases_passed;
        self.counters.cases_deferred += report.cases_deferred;
        self.counters.cases_rejected += report.cases_rejected;
        self.counters.audits_passed += report.audits_passed;
        self.counters.findings_total += report.findings_total;
        self.counters.medium_findings += report.medium_findings;
        self.counters.high_or_critical_findings += report.high_or_critical_findings;
        self.counters.release_holds_required += report.release_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            SecurityAuditHarnessReportStatus::Passed => self.counters.reports_passed += 1,
            SecurityAuditHarnessReportStatus::Watch => self.counters.reports_watch += 1,
            SecurityAuditHarnessReportStatus::Failed => self.counters.reports_failed += 1,
        }
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_reports {
            self.report_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let report_records = self
            .report_history
            .iter()
            .map(SecurityAuditHarnessReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-HARNESS-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn audit_case_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    safety_verdict: SafetyCaseVerdict,
    cargo_status: CargoRuntimeHarnessReportStatus,
    pq_status: PqAuthorityKeyManagerReportStatus,
) -> SecurityAuditCaseStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || safety_verdict == SafetyCaseVerdict::Failed
        || cargo_status == CargoRuntimeHarnessReportStatus::Failed
        || pq_status == PqAuthorityKeyManagerReportStatus::Failed
    {
        SecurityAuditCaseStatus::Rejected
    } else if !config.live_security_audit_enabled
        || config.security_audit_deferred
        || requirement_status == AdapterReadinessStatus::Deferred
        || safety_verdict == SafetyCaseVerdict::Watch
        || cargo_status == CargoRuntimeHarnessReportStatus::Watch
        || pq_status == PqAuthorityKeyManagerReportStatus::Watch
    {
        SecurityAuditCaseStatus::Deferred
    } else {
        SecurityAuditCaseStatus::Passed
    }
}

fn finding_severity(
    status: SecurityAuditCaseStatus,
    safety_verdict: SafetyCaseVerdict,
    cargo_status: CargoRuntimeHarnessReportStatus,
    pq_status: PqAuthorityKeyManagerReportStatus,
    tests_executed: u64,
    signatures_valid: u64,
) -> SecurityAuditFindingSeverity {
    if safety_verdict == SafetyCaseVerdict::Failed
        || pq_status == PqAuthorityKeyManagerReportStatus::Failed
    {
        SecurityAuditFindingSeverity::Critical
    } else if cargo_status == CargoRuntimeHarnessReportStatus::Failed
        || status == SecurityAuditCaseStatus::Rejected
    {
        SecurityAuditFindingSeverity::High
    } else if safety_verdict == SafetyCaseVerdict::Watch
        || cargo_status == CargoRuntimeHarnessReportStatus::Watch
        || pq_status == PqAuthorityKeyManagerReportStatus::Watch
    {
        SecurityAuditFindingSeverity::Medium
    } else if tests_executed == 0 || signatures_valid == 0 {
        SecurityAuditFindingSeverity::Low
    } else {
        SecurityAuditFindingSeverity::None
    }
}

#[allow(clippy::too_many_arguments)]
fn report_status(
    config: &Config,
    security_stub: &LiveAdapterStub,
    cases_deferred: u64,
    cases_rejected: u64,
    findings_total: u64,
    medium_findings: u64,
    high_or_critical_findings: u64,
    release_holds_required: u64,
) -> SecurityAuditHarnessReportStatus {
    if cases_rejected > 0
        || high_or_critical_findings > 0
        || security_stub.status == AdapterStubStatus::Blocked
    {
        SecurityAuditHarnessReportStatus::Failed
    } else if cases_deferred > 0
        || findings_total > 0
        || medium_findings > config.max_medium_findings
        || release_holds_required > 0
        || security_stub.status == AdapterStubStatus::Deferred
        || !config.live_security_audit_enabled
        || config.security_audit_deferred
    {
        SecurityAuditHarnessReportStatus::Watch
    } else {
        SecurityAuditHarnessReportStatus::Passed
    }
}

fn readiness_label(
    status: SecurityAuditHarnessReportStatus,
    security_stub_status: AdapterStubStatus,
    live_security_audit_enabled: bool,
) -> &'static str {
    match status {
        SecurityAuditHarnessReportStatus::Failed => "security_audit_harness_adapter_failed",
        SecurityAuditHarnessReportStatus::Watch if !live_security_audit_enabled => {
            "security_audit_harness_adapter_watch_audit_deferred"
        }
        SecurityAuditHarnessReportStatus::Watch
            if security_stub_status == AdapterStubStatus::Deferred =>
        {
            "security_audit_harness_adapter_watch_stub_deferred"
        }
        SecurityAuditHarnessReportStatus::Watch => "security_audit_harness_adapter_watch",
        SecurityAuditHarnessReportStatus::Passed => "security_audit_harness_adapter_ready",
    }
}

fn response_label(config: &Config, case: &SecurityAuditCase) -> &'static str {
    if case.status == SecurityAuditCaseStatus::Rejected {
        "security_audit_case_rejected"
    } else if case.severity >= SecurityAuditFindingSeverity::High {
        "security_audit_high_risk_finding"
    } else if config.security_audit_deferred || !config.live_security_audit_enabled {
        "security_audit_deferred"
    } else if case.finding_count > 0 {
        "security_audit_findings_require_review"
    } else if case.audit_passed {
        "security_audit_passed"
    } else {
        "security_audit_watch"
    }
}

fn error_code(config: &Config, case: &SecurityAuditCase) -> &'static str {
    if case.safety_case_verdict == SafetyCaseVerdict::Failed {
        "safety_case_failed"
    } else if case.pq_authority_status == PqAuthorityKeyManagerReportStatus::Failed {
        "pq_authority_failed"
    } else if case.cargo_harness_status == CargoRuntimeHarnessReportStatus::Failed {
        "cargo_harness_failed"
    } else if case.severity >= SecurityAuditFindingSeverity::High {
        "security_audit_high_risk_finding"
    } else if config.security_audit_deferred || !config.live_security_audit_enabled {
        "security_audit_deferred"
    } else if case.finding_count > 0 {
        "security_audit_findings_open"
    } else {
        "none"
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

#[allow(clippy::too_many_arguments)]
pub fn audit_scope_root(
    safety_source_root: &str,
    safety_evidence_root: &str,
    cargo_case_root: &str,
    fixture_root: &str,
    ordinal: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SCOPE",
        &[
            HashPart::Str(safety_source_root),
            HashPart::Str(safety_evidence_root),
            HashPart::Str(cargo_case_root),
            HashPart::Str(fixture_root),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_surface_root(
    pq_observation_root: &str,
    pq_response_root: &str,
    pq_failure_root: &str,
    signatures_valid: u64,
    release_holds_required: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-PQ-SURFACE",
        &[
            HashPart::Str(pq_observation_root),
            HashPart::Str(pq_response_root),
            HashPart::Str(pq_failure_root),
            HashPart::U64(signatures_valid),
            HashPart::U64(release_holds_required),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn privacy_surface_root(
    transcript_root: &str,
    bridge_spine_state_root: &str,
    transfer_runtime_state_root: &str,
    watch_items: u64,
    production_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-PRIVACY-SURFACE",
        &[
            HashPart::Str(transcript_root),
            HashPart::Str(bridge_spine_state_root),
            HashPart::Str(transfer_runtime_state_root),
            HashPart::U64(watch_items),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn finding_root(
    status: SecurityAuditCaseStatus,
    severity: SecurityAuditFindingSeverity,
    audit_scope_root: &str,
    pq_surface_root: &str,
    privacy_surface_root: &str,
    finding_count: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-FINDING",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(audit_scope_root),
            HashPart::Str(pq_surface_root),
            HashPart::Str(privacy_surface_root),
            HashPart::U64(finding_count),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn residual_risk_root(
    severity: SecurityAuditFindingSeverity,
    finding_count: u64,
    deferred_gates: u64,
    cargo_release_holds: u64,
    pq_release_holds: u64,
    production_blocks: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-RESIDUAL-RISK",
        &[
            HashPart::Str(severity.as_str()),
            HashPart::U64(finding_count),
            HashPart::U64(deferred_gates),
            HashPart::U64(cargo_release_holds),
            HashPart::U64(pq_release_holds),
            HashPart::Str(bool_str(production_blocks)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn signoff_root(
    audit_passed: bool,
    residual_risk_root: &str,
    finding_root: &str,
    cargo_report_root: &str,
    pq_report_root: &str,
    security_audit_deferred: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SIGNOFF",
        &[
            HashPart::Str(bool_str(audit_passed)),
            HashPart::Str(residual_risk_root),
            HashPart::Str(finding_root),
            HashPart::Str(cargo_report_root),
            HashPart::Str(pq_report_root),
            HashPart::Str(bool_str(security_audit_deferred)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn security_audit_case_root(
    status: SecurityAuditCaseStatus,
    severity: SecurityAuditFindingSeverity,
    requirement_id: &str,
    audit_scope_root: &str,
    finding_root: &str,
    residual_risk_root: &str,
    signoff_root: &str,
    audit_passed: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-CASE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(audit_scope_root),
            HashPart::Str(finding_root),
            HashPart::Str(residual_risk_root),
            HashPart::Str(signoff_root),
            HashPart::Str(bool_str(audit_passed)),
        ],
        32,
    )
}

pub fn security_audit_case_id(
    requirement_id: &str,
    safety_case_report_id: &str,
    case_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-CASE-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(safety_case_report_id),
            HashPart::Str(case_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: SecurityAuditCaseStatus,
    audit_passed: bool,
    finding_count: u64,
    residual_risk_root: &str,
    signoff_root: &str,
    release_hold_required: bool,
    response_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-RESPONSE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(audit_passed)),
            HashPart::U64(finding_count),
            HashPart::Str(residual_risk_root),
            HashPart::Str(signoff_root),
            HashPart::Str(bool_str(release_hold_required)),
            HashPart::Str(response_label),
        ],
        32,
    )
}

pub fn adapter_response_id(case_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-RESPONSE-ID",
        &[HashPart::Str(case_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn security_audit_failure_root(
    case_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_blocks: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-FAILURE",
        &[
            HashPart::Str(case_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_blocks),
        ],
        32,
    )
}

pub fn security_audit_failure_id(case_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-FAILURE-ID",
        &[HashPart::Str(case_id), HashPart::Str(failure_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    matrix_state_root: &str,
    matrix_report_root: &str,
    stub_registry_state_root: &str,
    stub_registry_report_root: &str,
    safety_case_state_root: &str,
    safety_case_report_root: &str,
    cargo_harness_state_root: &str,
    cargo_harness_report_root: &str,
    pq_authority_state_root: &str,
    pq_authority_report_root: &str,
    security_audit_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-SOURCE",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(safety_case_state_root),
            HashPart::Str(safety_case_report_root),
            HashPart::Str(cargo_harness_state_root),
            HashPart::Str(cargo_harness_report_root),
            HashPart::Str(pq_authority_state_root),
            HashPart::Str(pq_authority_report_root),
            HashPart::Str(security_audit_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: SecurityAuditHarnessReportStatus,
    readiness_label: &str,
    source_root: &str,
    case_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(case_root),
            HashPart::Str(response_root),
            HashPart::Str(failure_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn security_audit_harness_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SECURITY-AUDIT-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
