use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_gate_runtime::FinalReleaseGateStatus,
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
pub type MoneroL2PqBridgeExitMoneroHeaderReorgAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_MONERO_HEADER_REORG_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-monero-header-reorg-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_MONERO_HEADER_REORG_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HEADER_REORG_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-monero-header-reorg-adapter-v1";
pub const DEFAULT_MIN_HEADER_OBSERVATIONS: u64 = 15;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_REORG_WINDOW_DEPTH: u64 = 20;
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_500_000;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderObservationStatus {
    Accepted,
    Deferred,
    Rejected,
}

impl HeaderObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderReorgAdapterReportStatus {
    Passed,
    Watch,
    Failed,
}

impl HeaderReorgAdapterReportStatus {
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
    pub min_header_observations: u64,
    pub min_confirmations: u64,
    pub reorg_window_depth: u64,
    pub base_monero_height: u64,
    pub live_feed_enabled: bool,
    pub fail_closed_on_reorg: bool,
    pub cargo_checks_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            adapter_suite: HEADER_REORG_ADAPTER_SUITE.to_string(),
            min_header_observations: DEFAULT_MIN_HEADER_OBSERVATIONS,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_window_depth: DEFAULT_REORG_WINDOW_DEPTH,
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            live_feed_enabled: false,
            fail_closed_on_reorg: true,
            cargo_checks_deferred: true,
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
            "min_header_observations": self.min_header_observations,
            "min_confirmations": self.min_confirmations,
            "reorg_window_depth": self.reorg_window_depth,
            "base_monero_height": self.base_monero_height,
            "live_feed_enabled": self.live_feed_enabled,
            "fail_closed_on_reorg": self.fail_closed_on_reorg,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeaderObservation {
    pub observation_id: String,
    pub status: HeaderObservationStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub release_claim_id: String,
    pub monero_height: u64,
    pub observed_depth: u64,
    pub reorg_depth: u64,
    pub header_hash: String,
    pub previous_hash: String,
    pub chainwork_root: String,
    pub canonical_tip_root: String,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl HeaderObservation {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        ordinal: u64,
    ) -> Self {
        let monero_height = config.base_monero_height + ordinal;
        let observed_depth = if config.live_feed_enabled {
            config.min_confirmations + ordinal % 3
        } else {
            0
        };
        let reorg_depth = if requirement.expected_final_status == FinalReleaseGateStatus::Failed {
            config.reorg_window_depth + 1
        } else {
            ordinal % 2
        };
        let status = observation_status(config, requirement.status, observed_depth, reorg_depth);
        let header_hash = header_hash(&requirement.fixture_root, &requirement.adapter_input_root);
        let previous_hash = previous_header_hash(&requirement.fixture_root, ordinal);
        let chainwork_root = chainwork_root(&header_hash, monero_height, observed_depth);
        let canonical_tip_root = canonical_tip_root(&header_hash, monero_height, reorg_depth);
        let observation_root = header_observation_root(
            status,
            &requirement.requirement_id,
            monero_height,
            observed_depth,
            reorg_depth,
            &header_hash,
            &canonical_tip_root,
        );
        let observation_id =
            header_observation_id(&requirement.requirement_id, &header_hash, &observation_root);
        Self {
            observation_id,
            status,
            requirement_id: requirement.requirement_id.clone(),
            fixture_export_id: requirement.fixture_export_id.clone(),
            vector_id: requirement.vector_id.clone(),
            test_name: requirement.test_name.clone(),
            release_claim_id: requirement.release_claim_id.clone(),
            monero_height,
            observed_depth,
            reorg_depth,
            header_hash,
            previous_hash,
            chainwork_root,
            canonical_tip_root,
            fixture_root: requirement.fixture_root.clone(),
            adapter_input_root: requirement.adapter_input_root.clone(),
            readiness_root: requirement.readiness_root.clone(),
            observation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "requirement_id": self.requirement_id,
            "fixture_export_id": self.fixture_export_id,
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "release_claim_id": self.release_claim_id,
            "monero_height": self.monero_height,
            "observed_depth": self.observed_depth,
            "reorg_depth": self.reorg_depth,
            "header_hash": self.header_hash,
            "previous_hash": self.previous_hash,
            "chainwork_root": self.chainwork_root,
            "canonical_tip_root": self.canonical_tip_root,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("header_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeaderAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: HeaderObservationStatus,
    pub accepted_depth: u64,
    pub reorg_detected: bool,
    pub canonical_header_root: String,
    pub adapter_root: String,
    pub release_pause_required: bool,
    pub finality_label: String,
}

impl HeaderAdapterResponse {
    pub fn from_observation(config: &Config, observation: &HeaderObservation) -> Self {
        let reorg_detected = observation.reorg_depth > config.reorg_window_depth;
        let release_pause_required =
            reorg_detected || observation.status != HeaderObservationStatus::Accepted;
        let finality_label = finality_label(config, observation).to_string();
        let canonical_header_root = canonical_header_root(
            &observation.header_hash,
            observation.monero_height,
            observation.observed_depth,
            &observation.chainwork_root,
        );
        let adapter_root = adapter_response_root(
            observation.status,
            &canonical_header_root,
            &observation.observation_root,
            release_pause_required,
            &finality_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            accepted_depth: observation.observed_depth,
            reorg_detected,
            canonical_header_root,
            adapter_root,
            release_pause_required,
            finality_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "accepted_depth": self.accepted_depth,
            "reorg_detected": self.reorg_detected,
            "canonical_header_root": self.canonical_header_root,
            "adapter_root": self.adapter_root,
            "release_pause_required": self.release_pause_required,
            "finality_label": self.finality_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("header_adapter_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeaderAdapterFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_height: u64,
}

impl HeaderAdapterFailureSurface {
    pub fn from_observation(config: &Config, observation: &HeaderObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let quarantine_required = observation.status == HeaderObservationStatus::Rejected
            || (config.fail_closed_on_reorg && observation.reorg_depth > config.reorg_window_depth);
        let retry_after_height = observation.monero_height + config.min_confirmations;
        let failure_root = header_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_height,
        );
        let failure_id = header_failure_id(&observation.observation_id, &failure_root);
        Self {
            failure_id,
            observation_id: observation.observation_id.clone(),
            error_code,
            failure_root,
            quarantine_required,
            retry_after_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "failure_id": self.failure_id,
            "observation_id": self.observation_id,
            "error_code": self.error_code,
            "failure_root": self.failure_root,
            "quarantine_required": self.quarantine_required,
            "retry_after_height": self.retry_after_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("header_adapter_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeaderReorgAdapterReport {
    pub report_id: String,
    pub status: HeaderReorgAdapterReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub header_stub_id: String,
    pub header_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub observations_total: u64,
    pub observations_accepted: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub reorgs_detected: u64,
    pub release_pauses_required: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, HeaderObservation>,
    pub responses: BTreeMap<String, HeaderAdapterResponse>,
    pub failures: BTreeMap<String, HeaderAdapterFailureSurface>,
    pub roots: HeaderReorgAdapterReportRoots,
}

impl HeaderReorgAdapterReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(HeaderObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(HeaderAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(HeaderAdapterFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "header_stub_id": self.header_stub_id,
            "header_stub_status": self.header_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "observations_total": self.observations_total,
            "observations_accepted": self.observations_accepted,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "reorgs_detected": self.reorgs_detected,
            "release_pauses_required": self.release_pauses_required,
            "quarantine_required": self.quarantine_required,
            "observations": observations,
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
pub struct HeaderReorgAdapterReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl HeaderReorgAdapterReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_root": self.observation_root,
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
    pub observations_total: u64,
    pub observations_accepted: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub reorgs_detected: u64,
    pub release_pauses_required: u64,
    pub quarantine_required: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "observations_total": self.observations_total,
            "observations_accepted": self.observations_accepted,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "reorgs_detected": self.reorgs_detected,
            "release_pauses_required": self.release_pauses_required,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-STATE",
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
    pub latest_report: Option<HeaderReorgAdapterReport>,
    pub report_history: Vec<HeaderReorgAdapterReport>,
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
        state
            .process_header_reorg_adapter(&matrix, &stub_registry)
            .expect("devnet bridge exit Monero header reorg adapter");
        state
    }

    pub fn process_header_reorg_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let header_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::MoneroHeaderReorg)
            .ok_or_else(|| "Monero header reorg adapter stub is missing".to_string())?;
        let header_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::MoneroHeaderReorg)
            .collect::<Vec<_>>();
        ensure(
            header_requirements.len() as u64 >= self.config.min_header_observations,
            "Monero header adapter omitted required fixture observations",
        )?;
        let observations = header_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                HeaderObservation::from_requirement(&self.config, *requirement, index as u64)
            })
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| HeaderAdapterResponse::from_observation(&self.config, observation))
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                HeaderAdapterFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_accepted = observations
            .values()
            .filter(|observation| observation.status == HeaderObservationStatus::Accepted)
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| observation.status == HeaderObservationStatus::Deferred)
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| observation.status == HeaderObservationStatus::Rejected)
            .count() as u64;
        let reorgs_detected = responses
            .values()
            .filter(|response| response.reorg_detected)
            .count() as u64;
        let release_pauses_required = responses
            .values()
            .filter(|response| response.release_pause_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            header_stub,
            observations_deferred,
            observations_rejected,
            release_pauses_required,
            self.config.live_feed_enabled,
        );
        let readiness_label =
            readiness_label(status, header_stub.status, self.config.live_feed_enabled).to_string();
        let observation_records = observations
            .values()
            .map(HeaderObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(HeaderAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(HeaderAdapterFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &header_stub.stub_id,
            &header_stub.request_schema_root,
            &header_stub.response_schema_root,
            &header_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &observation_root,
            &response_root,
            &failure_root,
            &matrix_report.release_claim_id,
        );
        let report_id =
            header_reorg_adapter_report_id(&matrix_report.release_claim_id, &report_root);
        let report = HeaderReorgAdapterReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            header_stub_id: header_stub.stub_id.clone(),
            header_stub_status: header_stub.status,
            release_claim_id: matrix_report.release_claim_id.clone(),
            observations_total,
            observations_accepted,
            observations_deferred,
            observations_rejected,
            reorgs_detected,
            release_pauses_required,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: HeaderReorgAdapterReportRoots {
                observation_root,
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
            "latest_report": self.latest_report.as_ref().map(HeaderReorgAdapterReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: HeaderReorgAdapterReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_accepted += report.observations_accepted;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.reorgs_detected += report.reorgs_detected;
        self.counters.release_pauses_required += report.release_pauses_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            HeaderReorgAdapterReportStatus::Passed => self.counters.reports_passed += 1,
            HeaderReorgAdapterReportStatus::Watch => self.counters.reports_watch += 1,
            HeaderReorgAdapterReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(HeaderReorgAdapterReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn observation_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    observed_depth: u64,
    reorg_depth: u64,
) -> HeaderObservationStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || (config.fail_closed_on_reorg && reorg_depth > config.reorg_window_depth)
    {
        HeaderObservationStatus::Rejected
    } else if !config.live_feed_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || observed_depth < config.min_confirmations
    {
        HeaderObservationStatus::Deferred
    } else {
        HeaderObservationStatus::Accepted
    }
}

fn report_status(
    header_stub: &LiveAdapterStub,
    observations_deferred: u64,
    observations_rejected: u64,
    release_pauses_required: u64,
    live_feed_enabled: bool,
) -> HeaderReorgAdapterReportStatus {
    if observations_rejected > 0 || header_stub.status == AdapterStubStatus::Blocked {
        HeaderReorgAdapterReportStatus::Failed
    } else if observations_deferred > 0
        || release_pauses_required > 0
        || header_stub.status == AdapterStubStatus::Deferred
        || !live_feed_enabled
    {
        HeaderReorgAdapterReportStatus::Watch
    } else {
        HeaderReorgAdapterReportStatus::Passed
    }
}

fn readiness_label(
    status: HeaderReorgAdapterReportStatus,
    header_stub_status: AdapterStubStatus,
    live_feed_enabled: bool,
) -> &'static str {
    match status {
        HeaderReorgAdapterReportStatus::Failed => "monero_header_reorg_adapter_failed",
        HeaderReorgAdapterReportStatus::Watch if !live_feed_enabled => {
            "monero_header_reorg_adapter_watch_live_feed_deferred"
        }
        HeaderReorgAdapterReportStatus::Watch
            if header_stub_status == AdapterStubStatus::Deferred =>
        {
            "monero_header_reorg_adapter_watch_stub_deferred"
        }
        HeaderReorgAdapterReportStatus::Watch => "monero_header_reorg_adapter_watch",
        HeaderReorgAdapterReportStatus::Passed => "monero_header_reorg_adapter_ready",
    }
}

fn finality_label(config: &Config, observation: &HeaderObservation) -> &'static str {
    if observation.reorg_depth > config.reorg_window_depth {
        "reorg_exceeds_window"
    } else if observation.observed_depth >= config.min_confirmations {
        "confirmed"
    } else {
        "depth_deferred"
    }
}

fn error_code(config: &Config, observation: &HeaderObservation) -> &'static str {
    if observation.reorg_depth > config.reorg_window_depth {
        "reorg_depth_exceeds_window"
    } else if !config.live_feed_enabled {
        "live_header_feed_deferred"
    } else if observation.observed_depth < config.min_confirmations {
        "insufficient_confirmations"
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

pub fn header_hash(fixture_root: &str, adapter_input_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-HASH",
        &[
            HashPart::Str(fixture_root),
            HashPart::Str(adapter_input_root),
        ],
        32,
    )
}

pub fn previous_header_hash(fixture_root: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-PREVIOUS-HEADER-HASH",
        &[HashPart::Str(fixture_root), HashPart::U64(ordinal)],
        32,
    )
}

pub fn chainwork_root(header_hash: &str, monero_height: u64, observed_depth: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-CHAINWORK-ROOT",
        &[
            HashPart::Str(header_hash),
            HashPart::U64(monero_height),
            HashPart::U64(observed_depth),
        ],
        32,
    )
}

pub fn canonical_tip_root(header_hash: &str, monero_height: u64, reorg_depth: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-CANONICAL-TIP-ROOT",
        &[
            HashPart::Str(header_hash),
            HashPart::U64(monero_height),
            HashPart::U64(reorg_depth),
        ],
        32,
    )
}

pub fn canonical_header_root(
    header_hash: &str,
    monero_height: u64,
    observed_depth: u64,
    chainwork_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-CANONICAL-HEADER-ROOT",
        &[
            HashPart::Str(header_hash),
            HashPart::U64(monero_height),
            HashPart::U64(observed_depth),
            HashPart::Str(chainwork_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn header_observation_root(
    status: HeaderObservationStatus,
    requirement_id: &str,
    monero_height: u64,
    observed_depth: u64,
    reorg_depth: u64,
    header_hash: &str,
    canonical_tip_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-OBSERVATION-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::U64(monero_height),
            HashPart::U64(observed_depth),
            HashPart::U64(reorg_depth),
            HashPart::Str(header_hash),
            HashPart::Str(canonical_tip_root),
        ],
        32,
    )
}

pub fn header_observation_id(
    requirement_id: &str,
    header_hash: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-OBSERVATION-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(header_hash),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

pub fn adapter_response_root(
    status: HeaderObservationStatus,
    canonical_header_root: &str,
    observation_root: &str,
    release_pause_required: bool,
    finality_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-ADAPTER-RESPONSE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(canonical_header_root),
            HashPart::Str(observation_root),
            HashPart::Str(bool_str(release_pause_required)),
            HashPart::Str(finality_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-ADAPTER-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn header_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-FAILURE-ROOT",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_height),
        ],
        32,
    )
}

pub fn header_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-FAILURE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(failure_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    matrix_state_root: &str,
    matrix_report_root: &str,
    stub_registry_state_root: &str,
    stub_registry_report_root: &str,
    header_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-SOURCE-ROOT",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(header_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: HeaderReorgAdapterReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(observation_root),
            HashPart::Str(response_root),
            HashPart::Str(failure_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn header_reorg_adapter_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-MONERO-HEADER-REORG-ADAPTER-RECORD",
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
