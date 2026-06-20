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
pub type MoneroL2PqBridgeExitPrivateReceiptScannerAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_RECEIPT_SCANNER_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-private-receipt-scanner-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_RECEIPT_SCANNER_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_RECEIPT_SCANNER_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-private-receipt-scanner-adapter-v1";
pub const DEFAULT_MIN_RECEIPT_OBSERVATIONS: u64 = 15;
pub const DEFAULT_SCAN_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u64 = 2;
pub const DEFAULT_BASE_L2_HEIGHT: u64 = 42_000;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptScanStatus {
    Detected,
    Deferred,
    Rejected,
}

impl ReceiptScanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateReceiptScannerReportStatus {
    Passed,
    Watch,
    Failed,
}

impl PrivateReceiptScannerReportStatus {
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
    pub min_receipt_observations: u64,
    pub scan_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub max_metadata_leakage_units: u64,
    pub base_l2_height: u64,
    pub live_scanner_enabled: bool,
    pub fail_closed_on_metadata_leak: bool,
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
            adapter_suite: PRIVATE_RECEIPT_SCANNER_ADAPTER_SUITE.to_string(),
            min_receipt_observations: DEFAULT_MIN_RECEIPT_OBSERVATIONS,
            scan_window_blocks: DEFAULT_SCAN_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            base_l2_height: DEFAULT_BASE_L2_HEIGHT,
            live_scanner_enabled: false,
            fail_closed_on_metadata_leak: true,
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
            "min_receipt_observations": self.min_receipt_observations,
            "scan_window_blocks": self.scan_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "base_l2_height": self.base_l2_height,
            "live_scanner_enabled": self.live_scanner_enabled,
            "fail_closed_on_metadata_leak": self.fail_closed_on_metadata_leak,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptScanObservation {
    pub observation_id: String,
    pub status: ReceiptScanStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub view_tag_root: String,
    pub subaddress_hint_root: String,
    pub receipt_commitment_root: String,
    pub receipt_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub scan_depth: u64,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u64,
    pub scan_commitment_root: String,
    pub metadata_budget_root: String,
    pub exit_receipt_guard_root: String,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl ReceiptScanObservation {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        ordinal: u64,
    ) -> Self {
        let view_tag_root = view_tag_root(&requirement.fixture_root, &requirement.vector_id);
        let subaddress_hint_root =
            subaddress_hint_root(&requirement.fixture_root, &requirement.release_claim_id);
        let receipt_commitment_root = receipt_commitment_root(
            &requirement.adapter_input_root,
            &requirement.transfer_id,
            &requirement.release_claim_id,
        );
        let receipt_root = receipt_root(
            &requirement.transfer_id,
            &requirement.scenario_id,
            &receipt_commitment_root,
        );
        let scan_window_start = config.base_l2_height + ordinal * 2;
        let scan_window_end = scan_window_start + config.scan_window_blocks;
        let scan_depth = if config.live_scanner_enabled {
            config.scan_window_blocks.saturating_sub(ordinal % 7)
        } else {
            0
        };
        let privacy_set_size = privacy_set_size(config, requirement.expected_final_status, ordinal);
        let metadata_leakage_units =
            metadata_leakage_units(config, requirement.expected_final_status, ordinal);
        let scan_commitment_root = scan_commitment_root(
            &view_tag_root,
            &subaddress_hint_root,
            &receipt_commitment_root,
            scan_window_start,
            scan_window_end,
        );
        let metadata_budget_root = metadata_budget_root(
            &view_tag_root,
            metadata_leakage_units,
            config.max_metadata_leakage_units,
            privacy_set_size,
        );
        let exit_receipt_guard_root = exit_receipt_guard_root(
            &receipt_root,
            &requirement.release_claim_id,
            &metadata_budget_root,
        );
        let status = observation_status(
            config,
            requirement.status,
            scan_depth,
            privacy_set_size,
            metadata_leakage_units,
        );
        let observation_root = receipt_observation_root(
            status,
            &requirement.requirement_id,
            &receipt_root,
            &scan_commitment_root,
            &metadata_budget_root,
            scan_window_start,
            scan_window_end,
        );
        let observation_id = receipt_observation_id(
            &requirement.requirement_id,
            &receipt_root,
            &observation_root,
        );
        Self {
            observation_id,
            status,
            requirement_id: requirement.requirement_id.clone(),
            fixture_export_id: requirement.fixture_export_id.clone(),
            vector_id: requirement.vector_id.clone(),
            test_name: requirement.test_name.clone(),
            scenario_id: requirement.scenario_id.clone(),
            transfer_id: requirement.transfer_id.clone(),
            release_claim_id: requirement.release_claim_id.clone(),
            view_tag_root,
            subaddress_hint_root,
            receipt_commitment_root,
            receipt_root,
            scan_window_start,
            scan_window_end,
            scan_depth,
            privacy_set_size,
            metadata_leakage_units,
            scan_commitment_root,
            metadata_budget_root,
            exit_receipt_guard_root,
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
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "view_tag_root": self.view_tag_root,
            "subaddress_hint_root": self.subaddress_hint_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "receipt_root": self.receipt_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
            "scan_depth": self.scan_depth,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "scan_commitment_root": self.scan_commitment_root,
            "metadata_budget_root": self.metadata_budget_root,
            "exit_receipt_guard_root": self.exit_receipt_guard_root,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_scan_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptScannerAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: ReceiptScanStatus,
    pub receipt_detected: bool,
    pub scan_commitment_root: String,
    pub metadata_budget_root: String,
    pub exit_receipt_guard_root: String,
    pub exit_continuity_ready: bool,
    pub metadata_hold_required: bool,
    pub adapter_root: String,
    pub scanner_label: String,
}

impl ReceiptScannerAdapterResponse {
    pub fn from_observation(config: &Config, observation: &ReceiptScanObservation) -> Self {
        let receipt_detected =
            config.live_scanner_enabled && observation.status == ReceiptScanStatus::Detected;
        let exit_continuity_ready = receipt_detected
            && observation.metadata_leakage_units <= config.max_metadata_leakage_units
            && observation.privacy_set_size >= config.min_privacy_set_size;
        let metadata_hold_required = !exit_continuity_ready;
        let scanner_label = scanner_label(config, observation).to_string();
        let adapter_root = adapter_response_root(
            observation.status,
            receipt_detected,
            &observation.scan_commitment_root,
            &observation.metadata_budget_root,
            &observation.exit_receipt_guard_root,
            exit_continuity_ready,
            metadata_hold_required,
            &scanner_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            receipt_detected,
            scan_commitment_root: observation.scan_commitment_root.clone(),
            metadata_budget_root: observation.metadata_budget_root.clone(),
            exit_receipt_guard_root: observation.exit_receipt_guard_root.clone(),
            exit_continuity_ready,
            metadata_hold_required,
            adapter_root,
            scanner_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "receipt_detected": self.receipt_detected,
            "scan_commitment_root": self.scan_commitment_root,
            "metadata_budget_root": self.metadata_budget_root,
            "exit_receipt_guard_root": self.exit_receipt_guard_root,
            "exit_continuity_ready": self.exit_continuity_ready,
            "metadata_hold_required": self.metadata_hold_required,
            "adapter_root": self.adapter_root,
            "scanner_label": self.scanner_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_scanner_adapter_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptScannerFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_height: u64,
}

impl ReceiptScannerFailureSurface {
    pub fn from_observation(config: &Config, observation: &ReceiptScanObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let metadata_leak = observation.metadata_leakage_units > config.max_metadata_leakage_units;
        let quarantine_required = observation.status == ReceiptScanStatus::Rejected
            || (config.fail_closed_on_metadata_leak && metadata_leak);
        let retry_after_height = observation.scan_window_end + config.scan_window_blocks;
        let failure_root = receipt_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_height,
        );
        let failure_id = receipt_failure_id(&observation.observation_id, &failure_root);
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
        record_root("receipt_scanner_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateReceiptScannerReport {
    pub report_id: String,
    pub status: PrivateReceiptScannerReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub scanner_stub_id: String,
    pub scanner_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub observations_total: u64,
    pub observations_detected: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub receipts_detected: u64,
    pub exit_continuity_ready: u64,
    pub metadata_holds_required: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, ReceiptScanObservation>,
    pub responses: BTreeMap<String, ReceiptScannerAdapterResponse>,
    pub failures: BTreeMap<String, ReceiptScannerFailureSurface>,
    pub roots: PrivateReceiptScannerReportRoots,
}

impl PrivateReceiptScannerReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(ReceiptScanObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(ReceiptScannerAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(ReceiptScannerFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "scanner_stub_id": self.scanner_stub_id,
            "scanner_stub_status": self.scanner_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "observations_total": self.observations_total,
            "observations_detected": self.observations_detected,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "receipts_detected": self.receipts_detected,
            "exit_continuity_ready": self.exit_continuity_ready,
            "metadata_holds_required": self.metadata_holds_required,
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
pub struct PrivateReceiptScannerReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl PrivateReceiptScannerReportRoots {
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
    pub observations_detected: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub receipts_detected: u64,
    pub exit_continuity_ready: u64,
    pub metadata_holds_required: u64,
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
            "observations_detected": self.observations_detected,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "receipts_detected": self.receipts_detected,
            "exit_continuity_ready": self.exit_continuity_ready,
            "metadata_holds_required": self.metadata_holds_required,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-ADAPTER-STATE",
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
    pub latest_report: Option<PrivateReceiptScannerReport>,
    pub report_history: Vec<PrivateReceiptScannerReport>,
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
            .process_private_receipt_scanner_adapter(&matrix, &stub_registry)
            .expect("devnet bridge exit private receipt scanner adapter");
        state
    }

    pub fn process_private_receipt_scanner_adapter(
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
        let scanner_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::PrivateReceiptScanner)
            .ok_or_else(|| "private receipt scanner adapter stub is missing".to_string())?;
        let scanner_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| {
                requirement.adapter_kind == LiveAdapterKind::PrivateReceiptScanner
            })
            .collect::<Vec<_>>();
        ensure(
            scanner_requirements.len() as u64 >= self.config.min_receipt_observations,
            "private receipt scanner adapter omitted required fixture observations",
        )?;
        let observations = scanner_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                ReceiptScanObservation::from_requirement(&self.config, *requirement, index as u64)
            })
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| {
                ReceiptScannerAdapterResponse::from_observation(&self.config, observation)
            })
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                ReceiptScannerFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_detected = observations
            .values()
            .filter(|observation| observation.status == ReceiptScanStatus::Detected)
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| observation.status == ReceiptScanStatus::Deferred)
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| observation.status == ReceiptScanStatus::Rejected)
            .count() as u64;
        let receipts_detected = responses
            .values()
            .filter(|response| response.receipt_detected)
            .count() as u64;
        let exit_continuity_ready = responses
            .values()
            .filter(|response| response.exit_continuity_ready)
            .count() as u64;
        let metadata_holds_required = responses
            .values()
            .filter(|response| response.metadata_hold_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            scanner_stub,
            observations_deferred,
            observations_rejected,
            metadata_holds_required,
            self.config.live_scanner_enabled,
        );
        let readiness_label = readiness_label(
            status,
            scanner_stub.status,
            self.config.live_scanner_enabled,
        )
        .to_string();
        let observation_records = observations
            .values()
            .map(ReceiptScanObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(ReceiptScannerAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(ReceiptScannerFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCAN-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCAN-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCAN-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &scanner_stub.stub_id,
            &scanner_stub.request_schema_root,
            &scanner_stub.response_schema_root,
            &scanner_stub.failure_schema_root,
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
            private_receipt_scanner_report_id(&matrix_report.release_claim_id, &report_root);
        let report = PrivateReceiptScannerReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            scanner_stub_id: scanner_stub.stub_id.clone(),
            scanner_stub_status: scanner_stub.status,
            release_claim_id: matrix_report.release_claim_id.clone(),
            observations_total,
            observations_detected,
            observations_deferred,
            observations_rejected,
            receipts_detected,
            exit_continuity_ready,
            metadata_holds_required,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: PrivateReceiptScannerReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(PrivateReceiptScannerReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: PrivateReceiptScannerReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_detected += report.observations_detected;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.receipts_detected += report.receipts_detected;
        self.counters.exit_continuity_ready += report.exit_continuity_ready;
        self.counters.metadata_holds_required += report.metadata_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            PrivateReceiptScannerReportStatus::Passed => self.counters.reports_passed += 1,
            PrivateReceiptScannerReportStatus::Watch => self.counters.reports_watch += 1,
            PrivateReceiptScannerReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(PrivateReceiptScannerReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn privacy_set_size(config: &Config, final_status: FinalReleaseGateStatus, ordinal: u64) -> u64 {
    if final_status == FinalReleaseGateStatus::Failed {
        config.min_privacy_set_size.saturating_sub(1)
    } else {
        config.min_privacy_set_size + ordinal
    }
}

fn metadata_leakage_units(
    config: &Config,
    final_status: FinalReleaseGateStatus,
    ordinal: u64,
) -> u64 {
    if final_status == FinalReleaseGateStatus::Failed {
        config.max_metadata_leakage_units + 1
    } else {
        ordinal % (config.max_metadata_leakage_units + 1)
    }
}

fn observation_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    scan_depth: u64,
    privacy_set_size: u64,
    metadata_leakage_units: u64,
) -> ReceiptScanStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || privacy_set_size < config.min_privacy_set_size
        || metadata_leakage_units > config.max_metadata_leakage_units
    {
        ReceiptScanStatus::Rejected
    } else if !config.live_scanner_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || scan_depth == 0
    {
        ReceiptScanStatus::Deferred
    } else {
        ReceiptScanStatus::Detected
    }
}

fn report_status(
    scanner_stub: &LiveAdapterStub,
    observations_deferred: u64,
    observations_rejected: u64,
    metadata_holds_required: u64,
    live_scanner_enabled: bool,
) -> PrivateReceiptScannerReportStatus {
    if observations_rejected > 0 || scanner_stub.status == AdapterStubStatus::Blocked {
        PrivateReceiptScannerReportStatus::Failed
    } else if observations_deferred > 0
        || metadata_holds_required > 0
        || scanner_stub.status == AdapterStubStatus::Deferred
        || !live_scanner_enabled
    {
        PrivateReceiptScannerReportStatus::Watch
    } else {
        PrivateReceiptScannerReportStatus::Passed
    }
}

fn readiness_label(
    status: PrivateReceiptScannerReportStatus,
    scanner_stub_status: AdapterStubStatus,
    live_scanner_enabled: bool,
) -> &'static str {
    match status {
        PrivateReceiptScannerReportStatus::Failed => "private_receipt_scanner_adapter_failed",
        PrivateReceiptScannerReportStatus::Watch if !live_scanner_enabled => {
            "private_receipt_scanner_adapter_watch_live_scanner_deferred"
        }
        PrivateReceiptScannerReportStatus::Watch
            if scanner_stub_status == AdapterStubStatus::Deferred =>
        {
            "private_receipt_scanner_adapter_watch_stub_deferred"
        }
        PrivateReceiptScannerReportStatus::Watch => "private_receipt_scanner_adapter_watch",
        PrivateReceiptScannerReportStatus::Passed => "private_receipt_scanner_adapter_ready",
    }
}

fn scanner_label(config: &Config, observation: &ReceiptScanObservation) -> &'static str {
    if observation.metadata_leakage_units > config.max_metadata_leakage_units {
        "metadata_budget_rejected"
    } else if observation.privacy_set_size < config.min_privacy_set_size {
        "privacy_floor_rejected"
    } else if observation.scan_depth > 0 {
        "receipt_scan_detected"
    } else {
        "wallet_scan_deferred"
    }
}

fn error_code(config: &Config, observation: &ReceiptScanObservation) -> &'static str {
    if observation.metadata_leakage_units > config.max_metadata_leakage_units {
        "metadata_budget_exceeded"
    } else if observation.privacy_set_size < config.min_privacy_set_size {
        "privacy_set_below_floor"
    } else if !config.live_scanner_enabled {
        "live_private_receipt_scanner_deferred"
    } else if observation.scan_depth == 0 {
        "receipt_scan_window_empty"
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

pub fn view_tag_root(fixture_root: &str, vector_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-VIEW-TAG-ROOT",
        &[HashPart::Str(fixture_root), HashPart::Str(vector_id)],
        32,
    )
}

pub fn subaddress_hint_root(fixture_root: &str, release_claim_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SUBADDRESS-HINT-ROOT",
        &[HashPart::Str(fixture_root), HashPart::Str(release_claim_id)],
        32,
    )
}

pub fn receipt_commitment_root(
    adapter_input_root: &str,
    transfer_id: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-COMMITMENT-ROOT",
        &[
            HashPart::Str(adapter_input_root),
            HashPart::Str(transfer_id),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn receipt_root(transfer_id: &str, scenario_id: &str, receipt_commitment_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-ROOT",
        &[
            HashPart::Str(transfer_id),
            HashPart::Str(scenario_id),
            HashPart::Str(receipt_commitment_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scan_commitment_root(
    view_tag_root: &str,
    subaddress_hint_root: &str,
    receipt_commitment_root: &str,
    scan_window_start: u64,
    scan_window_end: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCAN-COMMITMENT-ROOT",
        &[
            HashPart::Str(view_tag_root),
            HashPart::Str(subaddress_hint_root),
            HashPart::Str(receipt_commitment_root),
            HashPart::U64(scan_window_start),
            HashPart::U64(scan_window_end),
        ],
        32,
    )
}

pub fn metadata_budget_root(
    view_tag_root: &str,
    metadata_leakage_units: u64,
    max_metadata_leakage_units: u64,
    privacy_set_size: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-METADATA-BUDGET-ROOT",
        &[
            HashPart::Str(view_tag_root),
            HashPart::U64(metadata_leakage_units),
            HashPart::U64(max_metadata_leakage_units),
            HashPart::U64(privacy_set_size),
        ],
        32,
    )
}

pub fn exit_receipt_guard_root(
    receipt_root: &str,
    release_claim_id: &str,
    metadata_budget_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-GUARD-ROOT",
        &[
            HashPart::Str(receipt_root),
            HashPart::Str(release_claim_id),
            HashPart::Str(metadata_budget_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn receipt_observation_root(
    status: ReceiptScanStatus,
    requirement_id: &str,
    receipt_root: &str,
    scan_commitment_root: &str,
    metadata_budget_root: &str,
    scan_window_start: u64,
    scan_window_end: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-OBSERVATION-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(receipt_root),
            HashPart::Str(scan_commitment_root),
            HashPart::Str(metadata_budget_root),
            HashPart::U64(scan_window_start),
            HashPart::U64(scan_window_end),
        ],
        32,
    )
}

pub fn receipt_observation_id(
    requirement_id: &str,
    receipt_root: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-OBSERVATION-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(receipt_root),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: ReceiptScanStatus,
    receipt_detected: bool,
    scan_commitment_root: &str,
    metadata_budget_root: &str,
    exit_receipt_guard_root: &str,
    exit_continuity_ready: bool,
    metadata_hold_required: bool,
    scanner_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-ADAPTER-RESPONSE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(receipt_detected)),
            HashPart::Str(scan_commitment_root),
            HashPart::Str(metadata_budget_root),
            HashPart::Str(exit_receipt_guard_root),
            HashPart::Str(bool_str(exit_continuity_ready)),
            HashPart::Str(bool_str(metadata_hold_required)),
            HashPart::Str(scanner_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-ADAPTER-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn receipt_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-FAILURE-ROOT",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_height),
        ],
        32,
    )
}

pub fn receipt_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-FAILURE-ID",
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
    scanner_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-SOURCE-ROOT",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(scanner_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: PrivateReceiptScannerReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-REPORT-ROOT",
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

pub fn private_receipt_scanner_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PRIVATE-RECEIPT-SCANNER-RECORD",
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
