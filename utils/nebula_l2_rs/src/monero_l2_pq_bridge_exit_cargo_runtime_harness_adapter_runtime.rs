use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::{
        FixtureExportRecord, FixtureExportReportStatus, FixtureExportStatus,
        State as FixtureExportState,
    },
    monero_l2_pq_bridge_exit_final_release_gate_runtime::{
        FinalGateDecisionStatus, FinalReleaseGateStatus,
    },
    monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::{
        AdapterReadinessStatus, LiveAdapterKind, LiveAdapterRequirement,
        State as LiveAdapterMatrixState,
    },
    monero_l2_pq_bridge_exit_live_adapter_stub_registry_runtime::{
        AdapterStubStatus, LiveAdapterStub, State as LiveAdapterStubRegistryState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCargoRuntimeHarnessAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CARGO_RUNTIME_HARNESS_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-cargo-runtime-harness-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CARGO_RUNTIME_HARNESS_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CARGO_RUNTIME_HARNESS_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-cargo-runtime-harness-adapter-v1";
pub const DEFAULT_MIN_HARNESS_CASES: u64 = 15;
pub const DEFAULT_LOG_REDACTION_BYTES: u64 = 0;
pub const DEFAULT_RETRY_AFTER_BLOCKS: u64 = 0;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoHarnessCaseStatus {
    Planned,
    Deferred,
    Rejected,
}

impl CargoHarnessCaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoHarnessObservedStatus {
    NotExecuted,
    MatchesExpected,
    Mismatched,
    Blocked,
}

impl CargoHarnessObservedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotExecuted => "not_executed",
            Self::MatchesExpected => "matches_expected",
            Self::Mismatched => "mismatched",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoRuntimeHarnessReportStatus {
    Passed,
    Watch,
    Failed,
}

impl CargoRuntimeHarnessReportStatus {
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
    pub min_harness_cases: u64,
    pub cargo_execution_enabled: bool,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub require_all_filters_indexed: bool,
    pub fail_closed_on_missing_fixture: bool,
    pub log_redaction_bytes: u64,
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
            adapter_suite: CARGO_RUNTIME_HARNESS_ADAPTER_SUITE.to_string(),
            min_harness_cases: DEFAULT_MIN_HARNESS_CASES,
            cargo_execution_enabled: false,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            require_all_filters_indexed: true,
            fail_closed_on_missing_fixture: true,
            log_redaction_bytes: DEFAULT_LOG_REDACTION_BYTES,
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
            "min_harness_cases": self.min_harness_cases,
            "cargo_execution_enabled": self.cargo_execution_enabled,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "require_all_filters_indexed": self.require_all_filters_indexed,
            "fail_closed_on_missing_fixture": self.fail_closed_on_missing_fixture,
            "log_redaction_bytes": self.log_redaction_bytes,
            "retry_after_blocks": self.retry_after_blocks,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CargoHarnessCase {
    pub case_id: String,
    pub status: CargoHarnessCaseStatus,
    pub observed_status: CargoHarnessObservedStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub cargo_test_path: String,
    pub cargo_test_filter: String,
    pub cargo_index_key: String,
    pub fixture_root: String,
    pub baseline_report_root: String,
    pub transcript_root: String,
    pub redacted_fixture_commitment: String,
    pub expected_final_status: FinalReleaseGateStatus,
    pub expected_user_release_status: FinalGateDecisionStatus,
    pub expected_production_status: FinalGateDecisionStatus,
    pub target_gate_root: String,
    pub blocker_surface_root: String,
    pub request_payload_root: String,
    pub assertion_root: String,
    pub log_commitment: String,
    pub test_executed: bool,
    pub release_safe_if_green: bool,
    pub production_safe_if_green: bool,
    pub case_root: String,
}

impl CargoHarnessCase {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        fixture_record: &FixtureExportRecord,
        fixture_status: FixtureExportReportStatus,
        ordinal: u64,
    ) -> Self {
        let request_payload_root = request_payload_root(
            &fixture_record.cargo_test_path,
            &fixture_record.cargo_test_filter,
            &fixture_record.fixture_root,
            fixture_record.expected_final_status,
            &requirement.adapter_input_root,
        );
        let status = case_status(
            config,
            requirement.status,
            fixture_status,
            fixture_record.status,
            &fixture_record.cargo_test_path,
            &fixture_record.cargo_test_filter,
        );
        let test_executed =
            config.cargo_execution_enabled && status == CargoHarnessCaseStatus::Planned;
        let observed_status = observed_status(config, status, test_executed);
        let assertion_root = assertion_root(
            &fixture_record.vector_id,
            &fixture_record.fixture_root,
            &fixture_record.baseline_report_root,
            fixture_record.expected_final_status,
            fixture_record.expected_user_release_status,
            fixture_record.expected_production_status,
            &fixture_record.target_gate_root,
            &fixture_record.blocker_surface_root,
        );
        let log_commitment = log_commitment_root(
            &fixture_record.cargo_test_path,
            &fixture_record.cargo_test_filter,
            observed_status,
            config.log_redaction_bytes,
            ordinal,
        );
        let release_safe_if_green = fixture_record.expected_final_status
            == FinalReleaseGateStatus::Passed
            && fixture_record.expected_user_release_status
                == FinalGateDecisionStatus::ReleaseAllowed;
        let production_safe_if_green = fixture_record.expected_production_status
            == FinalGateDecisionStatus::ReleaseAllowed
            && release_safe_if_green;
        let case_root = cargo_harness_case_root(
            status,
            observed_status,
            &requirement.requirement_id,
            &request_payload_root,
            &assertion_root,
            &log_commitment,
            test_executed,
        );
        let case_id = cargo_harness_case_id(
            &fixture_record.vector_id,
            &fixture_record.cargo_index_key,
            &case_root,
        );
        Self {
            case_id,
            status,
            observed_status,
            requirement_id: requirement.requirement_id.clone(),
            fixture_export_id: fixture_record.export_id.clone(),
            vector_id: fixture_record.vector_id.clone(),
            test_name: fixture_record.test_name.clone(),
            scenario_id: fixture_record.scenario_id.clone(),
            transfer_id: fixture_record.transfer_id.clone(),
            release_claim_id: fixture_record.release_claim_id.clone(),
            cargo_test_path: fixture_record.cargo_test_path.clone(),
            cargo_test_filter: fixture_record.cargo_test_filter.clone(),
            cargo_index_key: fixture_record.cargo_index_key.clone(),
            fixture_root: fixture_record.fixture_root.clone(),
            baseline_report_root: fixture_record.baseline_report_root.clone(),
            transcript_root: fixture_record.transcript_root.clone(),
            redacted_fixture_commitment: fixture_record.redacted_fixture_commitment.clone(),
            expected_final_status: fixture_record.expected_final_status,
            expected_user_release_status: fixture_record.expected_user_release_status,
            expected_production_status: fixture_record.expected_production_status,
            target_gate_root: fixture_record.target_gate_root.clone(),
            blocker_surface_root: fixture_record.blocker_surface_root.clone(),
            request_payload_root,
            assertion_root,
            log_commitment,
            test_executed,
            release_safe_if_green,
            production_safe_if_green,
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "status": self.status.as_str(),
            "observed_status": self.observed_status.as_str(),
            "requirement_id": self.requirement_id,
            "fixture_export_id": self.fixture_export_id,
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "cargo_test_path": self.cargo_test_path,
            "cargo_test_filter": self.cargo_test_filter,
            "cargo_index_key": self.cargo_index_key,
            "fixture_root": self.fixture_root,
            "baseline_report_root": self.baseline_report_root,
            "transcript_root": self.transcript_root,
            "redacted_fixture_commitment": self.redacted_fixture_commitment,
            "expected_final_status": self.expected_final_status.as_str(),
            "expected_user_release_status": self.expected_user_release_status.as_str(),
            "expected_production_status": self.expected_production_status.as_str(),
            "target_gate_root": self.target_gate_root,
            "blocker_surface_root": self.blocker_surface_root,
            "request_payload_root": self.request_payload_root,
            "assertion_root": self.assertion_root,
            "log_commitment": self.log_commitment,
            "test_executed": self.test_executed,
            "release_safe_if_green": self.release_safe_if_green,
            "production_safe_if_green": self.production_safe_if_green,
            "case_root": self.case_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("cargo_harness_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CargoHarnessResponse {
    pub response_id: String,
    pub case_id: String,
    pub status: CargoHarnessCaseStatus,
    pub test_executed: bool,
    pub observed_status: CargoHarnessObservedStatus,
    pub assertion_root: String,
    pub log_commitment: String,
    pub release_hold_required: bool,
    pub adapter_root: String,
    pub response_label: String,
}

impl CargoHarnessResponse {
    pub fn from_case(config: &Config, case: &CargoHarnessCase) -> Self {
        let release_hold_required =
            !case.test_executed || case.status != CargoHarnessCaseStatus::Planned;
        let response_label = response_label(config, case).to_string();
        let adapter_root = adapter_response_root(
            case.status,
            case.test_executed,
            case.observed_status,
            &case.assertion_root,
            &case.log_commitment,
            release_hold_required,
            &response_label,
        );
        let response_id = adapter_response_id(&case.case_id, &adapter_root);
        Self {
            response_id,
            case_id: case.case_id.clone(),
            status: case.status,
            test_executed: case.test_executed,
            observed_status: case.observed_status,
            assertion_root: case.assertion_root.clone(),
            log_commitment: case.log_commitment.clone(),
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
            "test_executed": self.test_executed,
            "observed_status": self.observed_status.as_str(),
            "assertion_root": self.assertion_root,
            "log_commitment": self.log_commitment,
            "release_hold_required": self.release_hold_required,
            "adapter_root": self.adapter_root,
            "response_label": self.response_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("cargo_harness_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CargoHarnessFailureSurface {
    pub failure_id: String,
    pub case_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_blocks: u64,
}

impl CargoHarnessFailureSurface {
    pub fn from_case(config: &Config, case: &CargoHarnessCase) -> Self {
        let error_code = error_code(config, case).to_string();
        let quarantine_required = case.status == CargoHarnessCaseStatus::Rejected
            || case.observed_status == CargoHarnessObservedStatus::Mismatched;
        let retry_after_blocks = if error_code == "none" {
            0
        } else {
            config.retry_after_blocks
        };
        let failure_root = cargo_harness_failure_root(
            &case.case_id,
            &error_code,
            quarantine_required,
            retry_after_blocks,
        );
        let failure_id = cargo_harness_failure_id(&case.case_id, &failure_root);
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
        record_root("cargo_harness_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CargoRuntimeHarnessReport {
    pub report_id: String,
    pub status: CargoRuntimeHarnessReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub fixture_export_state_root: String,
    pub fixture_export_report_root: String,
    pub cargo_harness_stub_id: String,
    pub cargo_harness_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub cases_total: u64,
    pub cases_planned: u64,
    pub cases_deferred: u64,
    pub cases_rejected: u64,
    pub tests_executed: u64,
    pub assertion_roots_bound: u64,
    pub release_holds_required: u64,
    pub quarantine_required: u64,
    pub cases: BTreeMap<String, CargoHarnessCase>,
    pub responses: BTreeMap<String, CargoHarnessResponse>,
    pub failures: BTreeMap<String, CargoHarnessFailureSurface>,
    pub roots: CargoRuntimeHarnessReportRoots,
}

impl CargoRuntimeHarnessReport {
    pub fn public_record(&self) -> Value {
        let cases = self
            .cases
            .values()
            .map(CargoHarnessCase::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(CargoHarnessResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(CargoHarnessFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "fixture_export_state_root": self.fixture_export_state_root,
            "fixture_export_report_root": self.fixture_export_report_root,
            "cargo_harness_stub_id": self.cargo_harness_stub_id,
            "cargo_harness_stub_status": self.cargo_harness_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "cases_total": self.cases_total,
            "cases_planned": self.cases_planned,
            "cases_deferred": self.cases_deferred,
            "cases_rejected": self.cases_rejected,
            "tests_executed": self.tests_executed,
            "assertion_roots_bound": self.assertion_roots_bound,
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
pub struct CargoRuntimeHarnessReportRoots {
    pub case_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl CargoRuntimeHarnessReportRoots {
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
    pub cases_planned: u64,
    pub cases_deferred: u64,
    pub cases_rejected: u64,
    pub tests_executed: u64,
    pub assertion_roots_bound: u64,
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
            "cases_planned": self.cases_planned,
            "cases_deferred": self.cases_deferred,
            "cases_rejected": self.cases_rejected,
            "tests_executed": self.tests_executed,
            "assertion_roots_bound": self.assertion_roots_bound,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-STATE",
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
    pub latest_report: Option<CargoRuntimeHarnessReport>,
    pub report_history: Vec<CargoRuntimeHarnessReport>,
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
        let fixture_export =
            crate::monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::devnet();
        state
            .process_cargo_runtime_harness_adapter(&matrix, &stub_registry, &fixture_export)
            .expect("devnet bridge exit cargo runtime harness adapter");
        state
    }

    pub fn process_cargo_runtime_harness_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        fixture_export: &FixtureExportState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let fixture_report = fixture_export
            .latest_report
            .as_ref()
            .ok_or_else(|| "final release fixture export has no latest report".to_string())?;
        let cargo_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::CargoRuntimeHarness)
            .ok_or_else(|| "cargo runtime harness adapter stub is missing".to_string())?;
        let harness_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::CargoRuntimeHarness)
            .collect::<Vec<_>>();
        ensure(
            harness_requirements.len() as u64 >= self.config.min_harness_cases,
            "cargo runtime harness adapter omitted required fixture cases",
        )?;
        let cases = harness_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                let fixture_record =
                    find_fixture_record(fixture_export, &requirement.fixture_export_id)?;
                Ok(CargoHarnessCase::from_requirement(
                    &self.config,
                    *requirement,
                    fixture_record,
                    fixture_report.status,
                    index as u64,
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|case| (case.case_id.clone(), case))
            .collect::<BTreeMap<_, _>>();
        let responses = cases
            .values()
            .map(|case| CargoHarnessResponse::from_case(&self.config, case))
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = cases
            .values()
            .map(|case| CargoHarnessFailureSurface::from_case(&self.config, case))
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let cases_total = cases.len() as u64;
        let cases_planned = cases
            .values()
            .filter(|case| case.status == CargoHarnessCaseStatus::Planned)
            .count() as u64;
        let cases_deferred = cases
            .values()
            .filter(|case| case.status == CargoHarnessCaseStatus::Deferred)
            .count() as u64;
        let cases_rejected = cases
            .values()
            .filter(|case| case.status == CargoHarnessCaseStatus::Rejected)
            .count() as u64;
        let tests_executed = responses
            .values()
            .filter(|response| response.test_executed)
            .count() as u64;
        let assertion_roots_bound = cases
            .values()
            .filter(|case| !case.assertion_root.is_empty())
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
            cargo_stub,
            fixture_report.status,
            cases_deferred,
            cases_rejected,
            release_holds_required,
            tests_executed,
            self.config.cargo_execution_enabled,
        );
        let readiness_label = readiness_label(
            status,
            cargo_stub.status,
            self.config.cargo_execution_enabled,
        )
        .to_string();
        let case_records = cases
            .values()
            .map(CargoHarnessCase::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(CargoHarnessResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(CargoHarnessFailureSurface::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-CASES",
            &case_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &fixture_export.state_root(),
            &fixture_report.state_root(),
            &cargo_stub.stub_id,
            &cargo_stub.request_schema_root,
            &cargo_stub.response_schema_root,
            &cargo_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &case_root,
            &response_root,
            &failure_root,
            &fixture_report.release_claim_id,
        );
        let report_id =
            cargo_runtime_harness_report_id(&fixture_report.release_claim_id, &report_root);
        let report = CargoRuntimeHarnessReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            fixture_export_state_root: fixture_export.state_root(),
            fixture_export_report_root: fixture_report.state_root(),
            cargo_harness_stub_id: cargo_stub.stub_id.clone(),
            cargo_harness_stub_status: cargo_stub.status,
            release_claim_id: fixture_report.release_claim_id.clone(),
            cases_total,
            cases_planned,
            cases_deferred,
            cases_rejected,
            tests_executed,
            assertion_roots_bound,
            release_holds_required,
            quarantine_required,
            cases,
            responses,
            failures,
            roots: CargoRuntimeHarnessReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(CargoRuntimeHarnessReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: CargoRuntimeHarnessReport) {
        self.counters.reports_run += 1;
        self.counters.cases_total += report.cases_total;
        self.counters.cases_planned += report.cases_planned;
        self.counters.cases_deferred += report.cases_deferred;
        self.counters.cases_rejected += report.cases_rejected;
        self.counters.tests_executed += report.tests_executed;
        self.counters.assertion_roots_bound += report.assertion_roots_bound;
        self.counters.release_holds_required += report.release_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            CargoRuntimeHarnessReportStatus::Passed => self.counters.reports_passed += 1,
            CargoRuntimeHarnessReportStatus::Watch => self.counters.reports_watch += 1,
            CargoRuntimeHarnessReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(CargoRuntimeHarnessReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn find_fixture_record<'a>(
    fixture_export: &'a FixtureExportState,
    fixture_export_id: &str,
) -> Result<&'a FixtureExportRecord> {
    fixture_export
        .latest_report
        .as_ref()
        .and_then(|report| report.export_records.get(fixture_export_id))
        .ok_or_else(|| format!("missing fixture export record {fixture_export_id}"))
}

fn case_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    fixture_report_status: FixtureExportReportStatus,
    fixture_status: FixtureExportStatus,
    cargo_test_path: &str,
    cargo_test_filter: &str,
) -> CargoHarnessCaseStatus {
    let filter_missing = cargo_test_path.is_empty() || cargo_test_filter.is_empty();
    if requirement_status == AdapterReadinessStatus::Blocked
        || fixture_report_status == FixtureExportReportStatus::Failed
        || fixture_status == FixtureExportStatus::Blocked
        || (config.require_all_filters_indexed && filter_missing)
    {
        CargoHarnessCaseStatus::Rejected
    } else if !config.cargo_execution_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || fixture_report_status == FixtureExportReportStatus::Watch
        || fixture_status == FixtureExportStatus::Deferred
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
    {
        CargoHarnessCaseStatus::Deferred
    } else {
        CargoHarnessCaseStatus::Planned
    }
}

fn observed_status(
    config: &Config,
    case_status: CargoHarnessCaseStatus,
    test_executed: bool,
) -> CargoHarnessObservedStatus {
    if case_status == CargoHarnessCaseStatus::Rejected {
        CargoHarnessObservedStatus::Blocked
    } else if !test_executed || !config.cargo_execution_enabled {
        CargoHarnessObservedStatus::NotExecuted
    } else if case_status == CargoHarnessCaseStatus::Planned {
        CargoHarnessObservedStatus::MatchesExpected
    } else {
        CargoHarnessObservedStatus::Mismatched
    }
}

#[allow(clippy::too_many_arguments)]
fn report_status(
    cargo_stub: &LiveAdapterStub,
    fixture_report_status: FixtureExportReportStatus,
    cases_deferred: u64,
    cases_rejected: u64,
    release_holds_required: u64,
    tests_executed: u64,
    cargo_execution_enabled: bool,
) -> CargoRuntimeHarnessReportStatus {
    if cases_rejected > 0
        || fixture_report_status == FixtureExportReportStatus::Failed
        || cargo_stub.status == AdapterStubStatus::Blocked
    {
        CargoRuntimeHarnessReportStatus::Failed
    } else if cases_deferred > 0
        || release_holds_required > 0
        || tests_executed == 0
        || fixture_report_status == FixtureExportReportStatus::Watch
        || cargo_stub.status == AdapterStubStatus::Deferred
        || !cargo_execution_enabled
    {
        CargoRuntimeHarnessReportStatus::Watch
    } else {
        CargoRuntimeHarnessReportStatus::Passed
    }
}

fn readiness_label(
    status: CargoRuntimeHarnessReportStatus,
    cargo_stub_status: AdapterStubStatus,
    cargo_execution_enabled: bool,
) -> &'static str {
    match status {
        CargoRuntimeHarnessReportStatus::Failed => "cargo_runtime_harness_adapter_failed",
        CargoRuntimeHarnessReportStatus::Watch if !cargo_execution_enabled => {
            "cargo_runtime_harness_adapter_watch_execution_deferred"
        }
        CargoRuntimeHarnessReportStatus::Watch
            if cargo_stub_status == AdapterStubStatus::Deferred =>
        {
            "cargo_runtime_harness_adapter_watch_stub_deferred"
        }
        CargoRuntimeHarnessReportStatus::Watch => "cargo_runtime_harness_adapter_watch",
        CargoRuntimeHarnessReportStatus::Passed => "cargo_runtime_harness_adapter_ready",
    }
}

fn response_label(config: &Config, case: &CargoHarnessCase) -> &'static str {
    if case.status == CargoHarnessCaseStatus::Rejected {
        "cargo_harness_case_rejected"
    } else if !config.cargo_execution_enabled {
        "cargo_execution_deferred"
    } else if case.observed_status == CargoHarnessObservedStatus::NotExecuted {
        "cargo_test_not_executed"
    } else if case.observed_status == CargoHarnessObservedStatus::MatchesExpected {
        "cargo_assertions_match_expected_status"
    } else {
        "cargo_assertions_require_attention"
    }
}

fn error_code(config: &Config, case: &CargoHarnessCase) -> &'static str {
    if case.cargo_test_path.is_empty() || case.cargo_test_filter.is_empty() {
        "cargo_filter_missing"
    } else if case.status == CargoHarnessCaseStatus::Rejected {
        "cargo_harness_case_rejected"
    } else if !config.cargo_execution_enabled {
        "cargo_execution_deferred"
    } else if case.observed_status == CargoHarnessObservedStatus::NotExecuted {
        "cargo_test_not_executed"
    } else if case.observed_status == CargoHarnessObservedStatus::Mismatched {
        "cargo_observed_status_mismatched"
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

pub fn request_payload_root(
    cargo_test_path: &str,
    cargo_test_filter: &str,
    fixture_root: &str,
    expected_status: FinalReleaseGateStatus,
    adapter_input_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-REQUEST",
        &[
            HashPart::Str(cargo_test_path),
            HashPart::Str(cargo_test_filter),
            HashPart::Str(fixture_root),
            HashPart::Str(expected_status.as_str()),
            HashPart::Str(adapter_input_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn assertion_root(
    vector_id: &str,
    fixture_root: &str,
    baseline_report_root: &str,
    expected_final_status: FinalReleaseGateStatus,
    expected_user_release_status: FinalGateDecisionStatus,
    expected_production_status: FinalGateDecisionStatus,
    target_gate_root: &str,
    blocker_surface_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-ASSERTION",
        &[
            HashPart::Str(vector_id),
            HashPart::Str(fixture_root),
            HashPart::Str(baseline_report_root),
            HashPart::Str(expected_final_status.as_str()),
            HashPart::Str(expected_user_release_status.as_str()),
            HashPart::Str(expected_production_status.as_str()),
            HashPart::Str(target_gate_root),
            HashPart::Str(blocker_surface_root),
        ],
        32,
    )
}

pub fn log_commitment_root(
    cargo_test_path: &str,
    cargo_test_filter: &str,
    observed_status: CargoHarnessObservedStatus,
    redaction_bytes: u64,
    ordinal: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-LOG-COMMITMENT",
        &[
            HashPart::Str(cargo_test_path),
            HashPart::Str(cargo_test_filter),
            HashPart::Str(observed_status.as_str()),
            HashPart::U64(redaction_bytes),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn cargo_harness_case_root(
    status: CargoHarnessCaseStatus,
    observed_status: CargoHarnessObservedStatus,
    requirement_id: &str,
    request_payload_root: &str,
    assertion_root: &str,
    log_commitment: &str,
    test_executed: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-CASE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(observed_status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(request_payload_root),
            HashPart::Str(assertion_root),
            HashPart::Str(log_commitment),
            HashPart::Str(bool_str(test_executed)),
        ],
        32,
    )
}

pub fn cargo_harness_case_id(vector_id: &str, cargo_index_key: &str, case_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-CASE-ID",
        &[
            HashPart::Str(vector_id),
            HashPart::Str(cargo_index_key),
            HashPart::Str(case_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: CargoHarnessCaseStatus,
    test_executed: bool,
    observed_status: CargoHarnessObservedStatus,
    assertion_root: &str,
    log_commitment: &str,
    release_hold_required: bool,
    response_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-RESPONSE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(test_executed)),
            HashPart::Str(observed_status.as_str()),
            HashPart::Str(assertion_root),
            HashPart::Str(log_commitment),
            HashPart::Str(bool_str(release_hold_required)),
            HashPart::Str(response_label),
        ],
        32,
    )
}

pub fn adapter_response_id(case_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-RESPONSE-ID",
        &[HashPart::Str(case_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn cargo_harness_failure_root(
    case_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_blocks: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-FAILURE",
        &[
            HashPart::Str(case_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_blocks),
        ],
        32,
    )
}

pub fn cargo_harness_failure_id(case_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-FAILURE-ID",
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
    fixture_export_state_root: &str,
    fixture_export_report_root: &str,
    cargo_harness_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-SOURCE",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(fixture_export_state_root),
            HashPart::Str(fixture_export_report_root),
            HashPart::Str(cargo_harness_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: CargoRuntimeHarnessReportStatus,
    readiness_label: &str,
    source_root: &str,
    case_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-REPORT",
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

pub fn cargo_runtime_harness_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CARGO-RUNTIME-HARNESS-RECORD",
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
