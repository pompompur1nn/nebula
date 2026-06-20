use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::{
        AdapterMatrixReportStatus, AdapterReadinessStatus, LiveAdapterKind, LiveAdapterRequirement,
        State as LiveAdapterMatrixState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitLiveAdapterStubRegistryRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_LIVE_ADAPTER_STUB_REGISTRY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-live-adapter-stub-registry-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_LIVE_ADAPTER_STUB_REGISTRY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ADAPTER_STUB_REGISTRY_SUITE: &str =
    "monero-l2-pq-bridge-exit-live-adapter-stub-registry-v1";
pub const DEFAULT_MIN_ADAPTER_STUBS: u64 = 10;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStubStatus {
    Ready,
    Deferred,
    Blocked,
}

impl AdapterStubStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StubRegistryReportStatus {
    Passed,
    Watch,
    Failed,
}

impl StubRegistryReportStatus {
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
    pub adapter_stub_registry_suite: String,
    pub min_adapter_stubs: u64,
    pub live_adapter_handlers_enabled: bool,
    pub schema_freeze_complete: bool,
    pub cargo_harness_materialized: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            adapter_stub_registry_suite: ADAPTER_STUB_REGISTRY_SUITE.to_string(),
            min_adapter_stubs: DEFAULT_MIN_ADAPTER_STUBS,
            live_adapter_handlers_enabled: false,
            schema_freeze_complete: false,
            cargo_harness_materialized: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "adapter_stub_registry_suite": self.adapter_stub_registry_suite,
            "min_adapter_stubs": self.min_adapter_stubs,
            "live_adapter_handlers_enabled": self.live_adapter_handlers_enabled,
            "schema_freeze_complete": self.schema_freeze_complete,
            "cargo_harness_materialized": self.cargo_harness_materialized,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveAdapterStub {
    pub stub_id: String,
    pub adapter_kind: LiveAdapterKind,
    pub status: AdapterStubStatus,
    pub requirement_count: u64,
    pub ready_requirements: u64,
    pub deferred_requirements: u64,
    pub blocked_requirements: u64,
    pub requirement_ids: Vec<String>,
    pub requirement_root: String,
    pub request_schema_root: String,
    pub response_schema_root: String,
    pub failure_schema_root: String,
    pub fixture_binding_root: String,
    pub cargo_filter_root: String,
    pub handler_name: String,
    pub module_path: String,
    pub next_step: String,
    pub public_contract: Value,
}

impl LiveAdapterStub {
    pub fn from_requirements(
        config: &Config,
        adapter_kind: LiveAdapterKind,
        requirements: &[&LiveAdapterRequirement],
    ) -> Self {
        let requirement_count = requirements.len() as u64;
        let ready_requirements = requirements
            .iter()
            .filter(|requirement| requirement.status == AdapterReadinessStatus::Ready)
            .count() as u64;
        let deferred_requirements = requirements
            .iter()
            .filter(|requirement| requirement.status == AdapterReadinessStatus::Deferred)
            .count() as u64;
        let blocked_requirements = requirements
            .iter()
            .filter(|requirement| requirement.status == AdapterReadinessStatus::Blocked)
            .count() as u64;
        let status = stub_status(
            config,
            ready_requirements,
            deferred_requirements,
            blocked_requirements,
            requirement_count,
        );
        let requirement_ids = requirements
            .iter()
            .map(|requirement| requirement.requirement_id.clone())
            .collect::<Vec<_>>();
        let requirement_records = requirements
            .iter()
            .map(|requirement| requirement.public_record())
            .collect::<Vec<_>>();
        let requirement_root = requirement_binding_root(adapter_kind, &requirement_records);
        let request_schema = request_schema(adapter_kind);
        let response_schema = response_schema(adapter_kind);
        let failure_schema = failure_schema(adapter_kind);
        let request_schema_root = adapter_schema_root("request", adapter_kind, &request_schema);
        let response_schema_root = adapter_schema_root("response", adapter_kind, &response_schema);
        let failure_schema_root = adapter_schema_root("failure", adapter_kind, &failure_schema);
        let fixture_records = requirements
            .iter()
            .map(|requirement| {
                json!({
                    "fixture_root": requirement.fixture_root,
                    "adapter_input_root": requirement.adapter_input_root,
                    "readiness_root": requirement.readiness_root,
                })
            })
            .collect::<Vec<_>>();
        let fixture_binding_root = fixture_binding_root(adapter_kind, &fixture_records);
        let cargo_records = requirements
            .iter()
            .map(|requirement| {
                json!({
                    "cargo_index_key": requirement.cargo_index_key,
                    "test_name": requirement.test_name,
                    "expected_final_status": requirement.expected_final_status.as_str(),
                })
            })
            .collect::<Vec<_>>();
        let cargo_filter_root = cargo_filter_binding_root(adapter_kind, &cargo_records);
        let handler_name = handler_name(adapter_kind).to_string();
        let module_path = module_path(adapter_kind).to_string();
        let next_step = next_step(adapter_kind).to_string();
        let public_contract = json!({
            "adapter_kind": adapter_kind.as_str(),
            "handler_name": handler_name,
            "module_path": module_path,
            "request_schema_root": request_schema_root,
            "response_schema_root": response_schema_root,
            "failure_schema_root": failure_schema_root,
            "fixture_binding_root": fixture_binding_root,
            "cargo_filter_root": cargo_filter_root,
            "schema_payloads_deferred": true,
            "handler_enabled": config.live_adapter_handlers_enabled,
            "cargo_harness_materialized": config.cargo_harness_materialized,
        });
        let stub_id = adapter_stub_id(
            adapter_kind,
            &requirement_root,
            &request_schema_root,
            &response_schema_root,
            &failure_schema_root,
        );
        Self {
            stub_id,
            adapter_kind,
            status,
            requirement_count,
            ready_requirements,
            deferred_requirements,
            blocked_requirements,
            requirement_ids,
            requirement_root,
            request_schema_root,
            response_schema_root,
            failure_schema_root,
            fixture_binding_root,
            cargo_filter_root,
            handler_name,
            module_path,
            next_step,
            public_contract,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "stub_id": self.stub_id,
            "adapter_kind": self.adapter_kind.as_str(),
            "status": self.status.as_str(),
            "requirement_count": self.requirement_count,
            "ready_requirements": self.ready_requirements,
            "deferred_requirements": self.deferred_requirements,
            "blocked_requirements": self.blocked_requirements,
            "requirement_ids": self.requirement_ids,
            "requirement_root": self.requirement_root,
            "request_schema_root": self.request_schema_root,
            "response_schema_root": self.response_schema_root,
            "failure_schema_root": self.failure_schema_root,
            "fixture_binding_root": self.fixture_binding_root,
            "cargo_filter_root": self.cargo_filter_root,
            "handler_name": self.handler_name,
            "module_path": self.module_path,
            "next_step": self.next_step,
            "public_contract": self.public_contract,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_adapter_stub", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveAdapterStubRegistryReport {
    pub report_id: String,
    pub status: StubRegistryReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub matrix_report_id: String,
    pub matrix_status: AdapterMatrixReportStatus,
    pub release_claim_id: String,
    pub adapter_stubs: u64,
    pub stubs_ready: u64,
    pub stubs_deferred: u64,
    pub stubs_blocked: u64,
    pub requirements_bound: u64,
    pub cargo_filters_bound: u64,
    pub stubs: BTreeMap<String, LiveAdapterStub>,
    pub roots: StubRegistryReportRoots,
}

impl LiveAdapterStubRegistryReport {
    pub fn public_record(&self) -> Value {
        let stubs = self
            .stubs
            .values()
            .map(LiveAdapterStub::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "matrix_report_id": self.matrix_report_id,
            "matrix_status": self.matrix_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "adapter_stubs": self.adapter_stubs,
            "stubs_ready": self.stubs_ready,
            "stubs_deferred": self.stubs_deferred,
            "stubs_blocked": self.stubs_blocked,
            "requirements_bound": self.requirements_bound,
            "cargo_filters_bound": self.cargo_filters_bound,
            "stubs": stubs,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StubRegistryReportRoots {
    pub stub_root: String,
    pub schema_root: String,
    pub source_root: String,
    pub deferred_root: String,
    pub report_root: String,
}

impl StubRegistryReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "stub_root": self.stub_root,
            "schema_root": self.schema_root,
            "source_root": self.source_root,
            "deferred_root": self.deferred_root,
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
    pub adapter_stubs: u64,
    pub stubs_ready: u64,
    pub stubs_deferred: u64,
    pub stubs_blocked: u64,
    pub requirements_bound: u64,
    pub cargo_filters_bound: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "adapter_stubs": self.adapter_stubs,
            "stubs_ready": self.stubs_ready,
            "stubs_deferred": self.stubs_deferred,
            "stubs_blocked": self.stubs_blocked,
            "requirements_bound": self.requirements_bound,
            "cargo_filters_bound": self.cargo_filters_bound,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-STATE",
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
    pub latest_report: Option<LiveAdapterStubRegistryReport>,
    pub report_history: Vec<LiveAdapterStubRegistryReport>,
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
        state
            .register_stubs(&matrix)
            .expect("devnet bridge exit live adapter stub registry");
        state
    }

    pub fn register_stubs(&mut self, matrix: &LiveAdapterMatrixState) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter readiness matrix has no latest report".to_string())?;
        let stubs = build_stubs(&self.config, matrix_report)?;
        ensure(
            stubs.len() as u64 >= self.config.min_adapter_stubs,
            "live adapter stub registry omitted required adapter stubs",
        )?;
        let adapter_stubs = stubs.len() as u64;
        let stubs_ready = stubs
            .values()
            .filter(|stub| stub.status == AdapterStubStatus::Ready)
            .count() as u64;
        let stubs_deferred = stubs
            .values()
            .filter(|stub| stub.status == AdapterStubStatus::Deferred)
            .count() as u64;
        let stubs_blocked = stubs
            .values()
            .filter(|stub| stub.status == AdapterStubStatus::Blocked)
            .count() as u64;
        let requirements_bound = stubs
            .values()
            .map(|stub| stub.requirement_count)
            .sum::<u64>();
        let cargo_filters_bound = stubs
            .values()
            .filter(|stub| !stub.cargo_filter_root.is_empty())
            .count() as u64;
        let status = report_status(matrix_report.status, stubs_deferred, stubs_blocked);
        let readiness_label = readiness_label(status, matrix_report.status).to_string();
        let stub_records = stubs
            .values()
            .map(LiveAdapterStub::public_record)
            .collect::<Vec<_>>();
        let stub_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-STUBS",
            &stub_records,
        );
        let schema_root = schema_root(&stubs);
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &matrix_report.roots.requirement_root,
            &matrix_report.roots.missing_surface_root,
            &matrix_report.release_claim_id,
        );
        let deferred_root = deferred_root(
            self.config.live_adapter_handlers_enabled,
            self.config.schema_freeze_complete,
            self.config.cargo_harness_materialized,
            &stubs,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &stub_root,
            &schema_root,
            &deferred_root,
            &matrix_report.release_claim_id,
        );
        let report_id = stub_registry_report_id(&matrix_report.release_claim_id, &report_root);
        let report = LiveAdapterStubRegistryReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            matrix_report_id: matrix_report.report_id.clone(),
            matrix_status: matrix_report.status,
            release_claim_id: matrix_report.release_claim_id.clone(),
            adapter_stubs,
            stubs_ready,
            stubs_deferred,
            stubs_blocked,
            requirements_bound,
            cargo_filters_bound,
            stubs,
            roots: StubRegistryReportRoots {
                stub_root,
                schema_root,
                source_root,
                deferred_root,
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
            "adapter_stub_registry_suite": self.config.adapter_stub_registry_suite,
            "latest_report": self.latest_report.as_ref().map(LiveAdapterStubRegistryReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: LiveAdapterStubRegistryReport) {
        self.counters.reports_run += 1;
        self.counters.adapter_stubs += report.adapter_stubs;
        self.counters.stubs_ready += report.stubs_ready;
        self.counters.stubs_deferred += report.stubs_deferred;
        self.counters.stubs_blocked += report.stubs_blocked;
        self.counters.requirements_bound += report.requirements_bound;
        self.counters.cargo_filters_bound += report.cargo_filters_bound;
        match report.status {
            StubRegistryReportStatus::Passed => self.counters.reports_passed += 1,
            StubRegistryReportStatus::Watch => self.counters.reports_watch += 1,
            StubRegistryReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(LiveAdapterStubRegistryReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_stubs(
    config: &Config,
    matrix_report: &crate::monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::LiveAdapterReadinessMatrixReport,
) -> Result<BTreeMap<String, LiveAdapterStub>> {
    let mut stubs = BTreeMap::new();
    for adapter_kind in adapter_kind_order() {
        let matching_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == adapter_kind)
            .collect::<Vec<_>>();
        let stub = LiveAdapterStub::from_requirements(config, adapter_kind, &matching_requirements);
        stubs.insert(stub.stub_id.clone(), stub);
    }
    Ok(stubs)
}

fn adapter_kind_order() -> Vec<LiveAdapterKind> {
    vec![
        LiveAdapterKind::MoneroHeaderReorg,
        LiveAdapterKind::DepositLockWatcher,
        LiveAdapterKind::PrivateReceiptScanner,
        LiveAdapterKind::ReserveRelease,
        LiveAdapterKind::WatcherBondPool,
        LiveAdapterKind::SlashingSettlement,
        LiveAdapterKind::ExitClaimQueue,
        LiveAdapterKind::PqAuthorityKeyManager,
        LiveAdapterKind::CargoRuntimeHarness,
        LiveAdapterKind::SecurityAuditHarness,
    ]
}

fn stub_status(
    config: &Config,
    ready_requirements: u64,
    deferred_requirements: u64,
    blocked_requirements: u64,
    requirement_count: u64,
) -> AdapterStubStatus {
    if blocked_requirements > 0 {
        AdapterStubStatus::Blocked
    } else if deferred_requirements > 0
        || requirement_count == 0
        || !config.live_adapter_handlers_enabled
        || !config.schema_freeze_complete
        || !config.cargo_harness_materialized
    {
        AdapterStubStatus::Deferred
    } else if ready_requirements == requirement_count {
        AdapterStubStatus::Ready
    } else {
        AdapterStubStatus::Deferred
    }
}

fn report_status(
    matrix_status: AdapterMatrixReportStatus,
    stubs_deferred: u64,
    stubs_blocked: u64,
) -> StubRegistryReportStatus {
    if stubs_blocked > 0 || matrix_status == AdapterMatrixReportStatus::Failed {
        StubRegistryReportStatus::Failed
    } else if stubs_deferred > 0 || matrix_status == AdapterMatrixReportStatus::Watch {
        StubRegistryReportStatus::Watch
    } else {
        StubRegistryReportStatus::Passed
    }
}

fn readiness_label(
    status: StubRegistryReportStatus,
    matrix_status: AdapterMatrixReportStatus,
) -> &'static str {
    match status {
        StubRegistryReportStatus::Failed => "live_adapter_stub_registry_failed",
        StubRegistryReportStatus::Watch if matrix_status == AdapterMatrixReportStatus::Watch => {
            "live_adapter_stub_registry_watch_matrix"
        }
        StubRegistryReportStatus::Watch => "live_adapter_stub_registry_watch_handlers_deferred",
        StubRegistryReportStatus::Passed => "live_adapter_stub_registry_ready",
    }
}

fn request_schema(adapter_kind: LiveAdapterKind) -> Value {
    json!({
        "adapter_kind": adapter_kind.as_str(),
        "required_inputs": request_fields(adapter_kind),
        "input_encoding": "canonical_json_roots_plus_adapter_payload",
        "privacy_mode": "redacted_roots_by_default",
    })
}

fn response_schema(adapter_kind: LiveAdapterKind) -> Value {
    json!({
        "adapter_kind": adapter_kind.as_str(),
        "required_outputs": response_fields(adapter_kind),
        "output_encoding": "canonical_json_roots_plus_status",
        "commitment_required": true,
    })
}

fn failure_schema(adapter_kind: LiveAdapterKind) -> Value {
    json!({
        "adapter_kind": adapter_kind.as_str(),
        "failure_outputs": ["error_code", "failure_root", "quarantine_required", "retry_after_height"],
        "fail_closed": true,
    })
}

fn request_fields(adapter_kind: LiveAdapterKind) -> Vec<&'static str> {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => {
            vec![
                "header_hash",
                "height",
                "depth",
                "previous_hash",
                "chainwork_root",
            ]
        }
        LiveAdapterKind::DepositLockWatcher => {
            vec![
                "lock_txid",
                "amount_commitment",
                "watcher_quorum_root",
                "depth",
            ]
        }
        LiveAdapterKind::PrivateReceiptScanner => {
            vec![
                "view_tag_root",
                "subaddress_hint_root",
                "receipt_commitment",
                "scan_window",
            ]
        }
        LiveAdapterKind::ReserveRelease => {
            vec![
                "release_claim_id",
                "reserve_account_root",
                "coverage_bps",
                "backstop_root",
            ]
        }
        LiveAdapterKind::WatcherBondPool => {
            vec![
                "watcher_id_root",
                "bond_account_root",
                "evidence_root",
                "quarantine_bps",
            ]
        }
        LiveAdapterKind::SlashingSettlement => {
            vec![
                "slash_decision_id",
                "bond_account_root",
                "holdback_root",
                "settlement_root",
            ]
        }
        LiveAdapterKind::ExitClaimQueue => {
            vec![
                "release_claim_id",
                "timeout_height",
                "challenge_root",
                "queue_position",
            ]
        }
        LiveAdapterKind::PqAuthorityKeyManager => {
            vec!["authority_root", "pq_signer_root", "epoch", "rotation_root"]
        }
        LiveAdapterKind::CargoRuntimeHarness => {
            vec![
                "cargo_test_path",
                "cargo_test_filter",
                "fixture_root",
                "expected_status",
            ]
        }
        LiveAdapterKind::SecurityAuditHarness => {
            vec![
                "audit_scope_root",
                "pq_surface_root",
                "privacy_surface_root",
                "finding_root",
            ]
        }
    }
}

fn response_fields(adapter_kind: LiveAdapterKind) -> Vec<&'static str> {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => {
            vec![
                "accepted_depth",
                "reorg_detected",
                "canonical_header_root",
                "adapter_root",
            ]
        }
        LiveAdapterKind::DepositLockWatcher => {
            vec![
                "lock_confirmed",
                "watcher_certificate_root",
                "mint_authorization_root",
            ]
        }
        LiveAdapterKind::PrivateReceiptScanner => {
            vec![
                "receipt_detected",
                "scan_commitment_root",
                "metadata_budget_root",
            ]
        }
        LiveAdapterKind::ReserveRelease => {
            vec![
                "release_authorized",
                "coverage_root",
                "reserve_movement_root",
            ]
        }
        LiveAdapterKind::WatcherBondPool => {
            vec!["bond_sufficient", "quarantine_root", "watcher_status_root"]
        }
        LiveAdapterKind::SlashingSettlement => {
            vec![
                "slash_settled",
                "settlement_receipt_root",
                "release_holdback_root",
            ]
        }
        LiveAdapterKind::ExitClaimQueue => {
            vec!["queued", "challenge_window_root", "settlement_order_root"]
        }
        LiveAdapterKind::PqAuthorityKeyManager => {
            vec![
                "signature_valid",
                "rotation_status_root",
                "authority_epoch_root",
            ]
        }
        LiveAdapterKind::CargoRuntimeHarness => {
            vec![
                "test_executed",
                "observed_status",
                "assertion_root",
                "log_commitment",
            ]
        }
        LiveAdapterKind::SecurityAuditHarness => {
            vec![
                "audit_passed",
                "finding_count",
                "residual_risk_root",
                "signoff_root",
            ]
        }
    }
}

fn handler_name(adapter_kind: LiveAdapterKind) -> &'static str {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => "handle_monero_header_reorg_fixture",
        LiveAdapterKind::DepositLockWatcher => "handle_deposit_lock_watcher_fixture",
        LiveAdapterKind::PrivateReceiptScanner => "handle_private_receipt_scanner_fixture",
        LiveAdapterKind::ReserveRelease => "handle_reserve_release_fixture",
        LiveAdapterKind::WatcherBondPool => "handle_watcher_bond_pool_fixture",
        LiveAdapterKind::SlashingSettlement => "handle_slashing_settlement_fixture",
        LiveAdapterKind::ExitClaimQueue => "handle_exit_claim_queue_fixture",
        LiveAdapterKind::PqAuthorityKeyManager => "handle_pq_authority_key_manager_fixture",
        LiveAdapterKind::CargoRuntimeHarness => "handle_cargo_runtime_harness_fixture",
        LiveAdapterKind::SecurityAuditHarness => "handle_security_audit_harness_fixture",
    }
}

fn module_path(adapter_kind: LiveAdapterKind) -> &'static str {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => {
            "utils/nebula_l2_rs/src/bridge_adapters/monero_header_reorg.rs"
        }
        LiveAdapterKind::DepositLockWatcher => {
            "utils/nebula_l2_rs/src/bridge_adapters/deposit_lock_watcher.rs"
        }
        LiveAdapterKind::PrivateReceiptScanner => {
            "utils/nebula_l2_rs/src/bridge_adapters/private_receipt_scanner.rs"
        }
        LiveAdapterKind::ReserveRelease => {
            "utils/nebula_l2_rs/src/bridge_adapters/reserve_release.rs"
        }
        LiveAdapterKind::WatcherBondPool => {
            "utils/nebula_l2_rs/src/bridge_adapters/watcher_bond_pool.rs"
        }
        LiveAdapterKind::SlashingSettlement => {
            "utils/nebula_l2_rs/src/bridge_adapters/slashing_settlement.rs"
        }
        LiveAdapterKind::ExitClaimQueue => {
            "utils/nebula_l2_rs/src/bridge_adapters/exit_claim_queue.rs"
        }
        LiveAdapterKind::PqAuthorityKeyManager => {
            "utils/nebula_l2_rs/src/bridge_adapters/pq_authority_key_manager.rs"
        }
        LiveAdapterKind::CargoRuntimeHarness => {
            "utils/nebula_l2_rs/tests/bridge_exit_final_release/mod.rs"
        }
        LiveAdapterKind::SecurityAuditHarness => {
            "utils/nebula_l2_rs/audits/bridge_exit_security_privacy.md"
        }
    }
}

fn next_step(adapter_kind: LiveAdapterKind) -> &'static str {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => {
            "implement header depth, reorg, and canonical root ingestion"
        }
        LiveAdapterKind::DepositLockWatcher => "implement deposit lock certificate ingestion",
        LiveAdapterKind::PrivateReceiptScanner => {
            "implement wallet receipt scan hints with metadata leakage budgets"
        }
        LiveAdapterKind::ReserveRelease => {
            "implement reserve release and backstop settlement hooks"
        }
        LiveAdapterKind::WatcherBondPool => {
            "implement watcher bond accounting and quarantine hooks"
        }
        LiveAdapterKind::SlashingSettlement => "implement live slash receipt settlement hooks",
        LiveAdapterKind::ExitClaimQueue => {
            "implement forced-exit queue ordering and challenge windows"
        }
        LiveAdapterKind::PqAuthorityKeyManager => {
            "implement PQ authority verification and epoch rotation"
        }
        LiveAdapterKind::CargoRuntimeHarness => "materialize fixture cargo tests",
        LiveAdapterKind::SecurityAuditHarness => {
            "materialize PQ/privacy audit checklist and signoff roots"
        }
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

pub fn adapter_stub_id(
    adapter_kind: LiveAdapterKind,
    requirement_root: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-ID",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Str(requirement_root),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

pub fn adapter_schema_root(
    schema_kind: &str,
    adapter_kind: LiveAdapterKind,
    schema: &Value,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-SCHEMA-ROOT",
        &[
            HashPart::Str(schema_kind),
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Json(schema),
        ],
        32,
    )
}

pub fn requirement_binding_root(adapter_kind: LiveAdapterKind, requirements: &[Value]) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REQUIREMENT-BINDING",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Json(&json!(requirements)),
        ],
        32,
    )
}

pub fn fixture_binding_root(adapter_kind: LiveAdapterKind, fixtures: &[Value]) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-FIXTURE-BINDING",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Json(&json!(fixtures)),
        ],
        32,
    )
}

pub fn cargo_filter_binding_root(adapter_kind: LiveAdapterKind, cargo_filters: &[Value]) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-CARGO-FILTER-BINDING",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Json(&json!(cargo_filters)),
        ],
        32,
    )
}

pub fn schema_root(stubs: &BTreeMap<String, LiveAdapterStub>) -> String {
    let records = stubs
        .values()
        .map(|stub| {
            json!({
                "adapter_kind": stub.adapter_kind.as_str(),
                "request_schema_root": stub.request_schema_root,
                "response_schema_root": stub.response_schema_root,
                "failure_schema_root": stub.failure_schema_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-SCHEMA-ROOTS",
        &records,
    )
}

pub fn deferred_root(
    live_adapter_handlers_enabled: bool,
    schema_freeze_complete: bool,
    cargo_harness_materialized: bool,
    stubs: &BTreeMap<String, LiveAdapterStub>,
) -> String {
    let records = stubs
        .values()
        .filter(|stub| stub.status != AdapterStubStatus::Ready)
        .map(|stub| {
            json!({
                "adapter_kind": stub.adapter_kind.as_str(),
                "status": stub.status.as_str(),
                "next_step": stub.next_step,
            })
        })
        .collect::<Vec<_>>();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-DEFERRED-ROOT",
        &[
            HashPart::Str(bool_str(live_adapter_handlers_enabled)),
            HashPart::Str(bool_str(schema_freeze_complete)),
            HashPart::Str(bool_str(cargo_harness_materialized)),
            HashPart::Json(&json!(records)),
        ],
        32,
    )
}

pub fn stub_registry_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn source_root(
    matrix_state_root: &str,
    matrix_report_root: &str,
    requirement_root: &str,
    missing_surface_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-SOURCE-ROOT",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(requirement_root),
            HashPart::Str(missing_surface_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: StubRegistryReportStatus,
    readiness_label: &str,
    source_root: &str,
    stub_root: &str,
    schema_root: &str,
    deferred_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(stub_root),
            HashPart::Str(schema_root),
            HashPart::Str(deferred_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-STUB-REGISTRY-RECORD",
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
