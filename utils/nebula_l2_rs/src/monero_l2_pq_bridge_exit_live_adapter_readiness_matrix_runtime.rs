use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::{
        FixtureExportAudience, FixtureExportRecord, FixtureExportReportStatus, FixtureExportStatus,
        State as FixtureExportState,
    },
    monero_l2_pq_bridge_exit_final_release_gate_runtime::{
        FinalGateDecisionStatus, FinalReleaseGateStatus,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitLiveAdapterReadinessMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_LIVE_ADAPTER_READINESS_MATRIX_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-live-adapter-readiness-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_LIVE_ADAPTER_READINESS_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ADAPTER_MATRIX_SUITE: &str = "monero-l2-pq-bridge-exit-live-adapter-readiness-matrix-v1";
pub const DEFAULT_MIN_ADAPTER_REQUIREMENTS: u64 = 150;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveAdapterKind {
    MoneroHeaderReorg,
    DepositLockWatcher,
    PrivateReceiptScanner,
    ReserveRelease,
    WatcherBondPool,
    SlashingSettlement,
    ExitClaimQueue,
    PqAuthorityKeyManager,
    CargoRuntimeHarness,
    SecurityAuditHarness,
}

impl LiveAdapterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaderReorg => "monero_header_reorg",
            Self::DepositLockWatcher => "deposit_lock_watcher",
            Self::PrivateReceiptScanner => "private_receipt_scanner",
            Self::ReserveRelease => "reserve_release",
            Self::WatcherBondPool => "watcher_bond_pool",
            Self::SlashingSettlement => "slashing_settlement",
            Self::ExitClaimQueue => "exit_claim_queue",
            Self::PqAuthorityKeyManager => "pq_authority_key_manager",
            Self::CargoRuntimeHarness => "cargo_runtime_harness",
            Self::SecurityAuditHarness => "security_audit_harness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterReadinessStatus {
    Ready,
    Deferred,
    Blocked,
}

impl AdapterReadinessStatus {
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
pub enum AdapterMatrixReportStatus {
    Passed,
    Watch,
    Failed,
}

impl AdapterMatrixReportStatus {
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
    pub adapter_matrix_suite: String,
    pub min_adapter_requirements: u64,
    pub live_monero_header_reorg_ready: bool,
    pub live_deposit_lock_watcher_ready: bool,
    pub live_private_receipt_scanner_ready: bool,
    pub live_reserve_release_ready: bool,
    pub live_watcher_bond_pool_ready: bool,
    pub live_slashing_settlement_ready: bool,
    pub live_exit_claim_queue_ready: bool,
    pub live_pq_authority_key_manager_ready: bool,
    pub cargo_runtime_harness_ready: bool,
    pub security_audit_harness_ready: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            adapter_matrix_suite: ADAPTER_MATRIX_SUITE.to_string(),
            min_adapter_requirements: DEFAULT_MIN_ADAPTER_REQUIREMENTS,
            live_monero_header_reorg_ready: false,
            live_deposit_lock_watcher_ready: false,
            live_private_receipt_scanner_ready: false,
            live_reserve_release_ready: false,
            live_watcher_bond_pool_ready: false,
            live_slashing_settlement_ready: false,
            live_exit_claim_queue_ready: false,
            live_pq_authority_key_manager_ready: false,
            cargo_runtime_harness_ready: false,
            security_audit_harness_ready: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "adapter_matrix_suite": self.adapter_matrix_suite,
            "min_adapter_requirements": self.min_adapter_requirements,
            "live_monero_header_reorg_ready": self.live_monero_header_reorg_ready,
            "live_deposit_lock_watcher_ready": self.live_deposit_lock_watcher_ready,
            "live_private_receipt_scanner_ready": self.live_private_receipt_scanner_ready,
            "live_reserve_release_ready": self.live_reserve_release_ready,
            "live_watcher_bond_pool_ready": self.live_watcher_bond_pool_ready,
            "live_slashing_settlement_ready": self.live_slashing_settlement_ready,
            "live_exit_claim_queue_ready": self.live_exit_claim_queue_ready,
            "live_pq_authority_key_manager_ready": self.live_pq_authority_key_manager_ready,
            "cargo_runtime_harness_ready": self.cargo_runtime_harness_ready,
            "security_audit_harness_ready": self.security_audit_harness_ready,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveAdapterRequirement {
    pub requirement_id: String,
    pub adapter_kind: LiveAdapterKind,
    pub status: AdapterReadinessStatus,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub audience: FixtureExportAudience,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub fixture_root: String,
    pub cargo_index_key: String,
    pub expected_final_status: FinalReleaseGateStatus,
    pub expected_user_release_status: FinalGateDecisionStatus,
    pub expected_production_status: FinalGateDecisionStatus,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub missing_surface: String,
    pub next_step: String,
}

impl LiveAdapterRequirement {
    pub fn new(
        config: &Config,
        record: &FixtureExportRecord,
        adapter_kind: LiveAdapterKind,
    ) -> Self {
        let status = adapter_status(config, record.status, adapter_kind);
        let adapter_input_root = adapter_input_root(
            adapter_kind,
            &record.fixture_root,
            &record.cargo_index_key,
            record.expected_final_status,
            record.expected_user_release_status,
            record.expected_production_status,
        );
        let readiness_root = readiness_root(
            adapter_kind,
            status,
            &adapter_input_root,
            &record.redacted_fixture_commitment,
        );
        let requirement_id =
            adapter_requirement_id(adapter_kind, &record.export_id, &readiness_root);
        Self {
            requirement_id,
            adapter_kind,
            status,
            fixture_export_id: record.export_id.clone(),
            vector_id: record.vector_id.clone(),
            test_name: record.test_name.clone(),
            audience: record.audience,
            scenario_id: record.scenario_id.clone(),
            transfer_id: record.transfer_id.clone(),
            release_claim_id: record.release_claim_id.clone(),
            fixture_root: record.fixture_root.clone(),
            cargo_index_key: record.cargo_index_key.clone(),
            expected_final_status: record.expected_final_status,
            expected_user_release_status: record.expected_user_release_status,
            expected_production_status: record.expected_production_status,
            adapter_input_root,
            readiness_root,
            missing_surface: missing_surface(adapter_kind).to_string(),
            next_step: next_step(adapter_kind).to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "requirement_id": self.requirement_id,
            "adapter_kind": self.adapter_kind.as_str(),
            "status": self.status.as_str(),
            "fixture_export_id": self.fixture_export_id,
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "audience": self.audience.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "fixture_root": self.fixture_root,
            "cargo_index_key": self.cargo_index_key,
            "expected_final_status": self.expected_final_status.as_str(),
            "expected_user_release_status": self.expected_user_release_status.as_str(),
            "expected_production_status": self.expected_production_status.as_str(),
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "missing_surface": self.missing_surface,
            "next_step": self.next_step,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_adapter_requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveAdapterReadinessMatrixReport {
    pub report_id: String,
    pub status: AdapterMatrixReportStatus,
    pub readiness_label: String,
    pub fixture_export_state_root: String,
    pub fixture_export_report_root: String,
    pub fixture_export_report_id: String,
    pub fixture_export_status: FixtureExportReportStatus,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub adapter_requirements: u64,
    pub adapters_ready: u64,
    pub adapters_deferred: u64,
    pub adapters_blocked: u64,
    pub fixtures_covered: u64,
    pub cargo_filters_mapped: u64,
    pub requirements: BTreeMap<String, LiveAdapterRequirement>,
    pub roots: MatrixReportRoots,
}

impl LiveAdapterReadinessMatrixReport {
    pub fn public_record(&self) -> Value {
        let requirements = self
            .requirements
            .values()
            .map(LiveAdapterRequirement::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "fixture_export_state_root": self.fixture_export_state_root,
            "fixture_export_report_root": self.fixture_export_report_root,
            "fixture_export_report_id": self.fixture_export_report_id,
            "fixture_export_status": self.fixture_export_status.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "adapter_requirements": self.adapter_requirements,
            "adapters_ready": self.adapters_ready,
            "adapters_deferred": self.adapters_deferred,
            "adapters_blocked": self.adapters_blocked,
            "fixtures_covered": self.fixtures_covered,
            "cargo_filters_mapped": self.cargo_filters_mapped,
            "requirements": requirements,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MatrixReportRoots {
    pub requirement_root: String,
    pub adapter_kind_root: String,
    pub missing_surface_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl MatrixReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "requirement_root": self.requirement_root,
            "adapter_kind_root": self.adapter_kind_root,
            "missing_surface_root": self.missing_surface_root,
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
    pub adapter_requirements: u64,
    pub adapters_ready: u64,
    pub adapters_deferred: u64,
    pub adapters_blocked: u64,
    pub fixtures_covered: u64,
    pub cargo_filters_mapped: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "adapter_requirements": self.adapter_requirements,
            "adapters_ready": self.adapters_ready,
            "adapters_deferred": self.adapters_deferred,
            "adapters_blocked": self.adapters_blocked,
            "fixtures_covered": self.fixtures_covered,
            "cargo_filters_mapped": self.cargo_filters_mapped,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-STATE",
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
    pub latest_report: Option<LiveAdapterReadinessMatrixReport>,
    pub report_history: Vec<LiveAdapterReadinessMatrixReport>,
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
        let fixture_export =
            crate::monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::devnet();
        state
            .evaluate_readiness_matrix(&fixture_export)
            .expect("devnet bridge exit live adapter readiness matrix");
        state
    }

    pub fn evaluate_readiness_matrix(
        &mut self,
        fixture_export: &FixtureExportState,
    ) -> Result<String> {
        let fixture_report = fixture_export
            .latest_report
            .as_ref()
            .ok_or_else(|| "fixture export state has no latest report".to_string())?;
        let requirements = build_requirements(&self.config, fixture_report)?;
        ensure(
            requirements.len() as u64 >= self.config.min_adapter_requirements,
            "live adapter matrix omitted required fixture adapter requirements",
        )?;
        let adapter_requirements = requirements.len() as u64;
        let adapters_ready = requirements
            .values()
            .filter(|requirement| requirement.status == AdapterReadinessStatus::Ready)
            .count() as u64;
        let adapters_deferred = requirements
            .values()
            .filter(|requirement| requirement.status == AdapterReadinessStatus::Deferred)
            .count() as u64;
        let adapters_blocked = requirements
            .values()
            .filter(|requirement| requirement.status == AdapterReadinessStatus::Blocked)
            .count() as u64;
        let fixtures_covered = fixture_report.export_records.len() as u64;
        let cargo_filters_mapped = fixture_report.cargo_filters_indexed;
        let status = report_status(fixture_report.status, adapters_deferred, adapters_blocked);
        let readiness_label = readiness_label(status, fixture_report.status).to_string();
        let requirement_records = requirements
            .values()
            .map(LiveAdapterRequirement::public_record)
            .collect::<Vec<_>>();
        let requirement_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-REQUIREMENTS",
            &requirement_records,
        );
        let adapter_kind_root = adapter_kind_root(&requirements);
        let missing_surface_root = missing_surface_root(&requirements);
        let source_root = source_root(
            &fixture_export.state_root(),
            &fixture_report.state_root(),
            &fixture_report.roots.export_root,
            &fixture_report.roots.expected_outcome_root,
            &fixture_report.roots.redaction_root,
            &fixture_report.release_claim_id,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &requirement_root,
            &adapter_kind_root,
            &missing_surface_root,
            &fixture_report.release_claim_id,
        );
        let report_id = adapter_matrix_report_id(&fixture_report.release_claim_id, &report_root);
        let report = LiveAdapterReadinessMatrixReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            fixture_export_state_root: fixture_export.state_root(),
            fixture_export_report_root: fixture_report.state_root(),
            fixture_export_report_id: fixture_report.report_id.clone(),
            fixture_export_status: fixture_report.status,
            scenario_id: fixture_report.scenario_id.clone(),
            transfer_id: fixture_report.transfer_id.clone(),
            release_claim_id: fixture_report.release_claim_id.clone(),
            transcript_root: fixture_report.transcript_root.clone(),
            adapter_requirements,
            adapters_ready,
            adapters_deferred,
            adapters_blocked,
            fixtures_covered,
            cargo_filters_mapped,
            requirements,
            roots: MatrixReportRoots {
                requirement_root,
                adapter_kind_root,
                missing_surface_root,
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
            "adapter_matrix_suite": self.config.adapter_matrix_suite,
            "latest_report": self.latest_report.as_ref().map(LiveAdapterReadinessMatrixReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: LiveAdapterReadinessMatrixReport) {
        self.counters.reports_run += 1;
        self.counters.adapter_requirements += report.adapter_requirements;
        self.counters.adapters_ready += report.adapters_ready;
        self.counters.adapters_deferred += report.adapters_deferred;
        self.counters.adapters_blocked += report.adapters_blocked;
        self.counters.fixtures_covered += report.fixtures_covered;
        self.counters.cargo_filters_mapped += report.cargo_filters_mapped;
        match report.status {
            AdapterMatrixReportStatus::Passed => self.counters.reports_passed += 1,
            AdapterMatrixReportStatus::Watch => self.counters.reports_watch += 1,
            AdapterMatrixReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(LiveAdapterReadinessMatrixReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_requirements(
    config: &Config,
    fixture_report: &crate::monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::FixtureExportReport,
) -> Result<BTreeMap<String, LiveAdapterRequirement>> {
    let mut requirements = BTreeMap::new();
    for record in fixture_report.export_records.values() {
        for adapter_kind in adapter_kinds_for_record(record) {
            let requirement = LiveAdapterRequirement::new(config, record, adapter_kind);
            requirements.insert(requirement.requirement_id.clone(), requirement);
        }
    }
    Ok(requirements)
}

fn adapter_kinds_for_record(record: &FixtureExportRecord) -> Vec<LiveAdapterKind> {
    let mut adapters = vec![
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
    ];
    if record.expected_final_status == FinalReleaseGateStatus::Passed {
        adapters.sort();
    }
    adapters
}

fn adapter_status(
    config: &Config,
    export_status: FixtureExportStatus,
    adapter_kind: LiveAdapterKind,
) -> AdapterReadinessStatus {
    if export_status == FixtureExportStatus::Blocked {
        return AdapterReadinessStatus::Blocked;
    }
    if adapter_ready(config, adapter_kind) {
        AdapterReadinessStatus::Ready
    } else {
        AdapterReadinessStatus::Deferred
    }
}

fn adapter_ready(config: &Config, adapter_kind: LiveAdapterKind) -> bool {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => config.live_monero_header_reorg_ready,
        LiveAdapterKind::DepositLockWatcher => config.live_deposit_lock_watcher_ready,
        LiveAdapterKind::PrivateReceiptScanner => config.live_private_receipt_scanner_ready,
        LiveAdapterKind::ReserveRelease => config.live_reserve_release_ready,
        LiveAdapterKind::WatcherBondPool => config.live_watcher_bond_pool_ready,
        LiveAdapterKind::SlashingSettlement => config.live_slashing_settlement_ready,
        LiveAdapterKind::ExitClaimQueue => config.live_exit_claim_queue_ready,
        LiveAdapterKind::PqAuthorityKeyManager => config.live_pq_authority_key_manager_ready,
        LiveAdapterKind::CargoRuntimeHarness => config.cargo_runtime_harness_ready,
        LiveAdapterKind::SecurityAuditHarness => config.security_audit_harness_ready,
    }
}

fn report_status(
    fixture_status: FixtureExportReportStatus,
    adapters_deferred: u64,
    adapters_blocked: u64,
) -> AdapterMatrixReportStatus {
    if adapters_blocked > 0 || fixture_status == FixtureExportReportStatus::Failed {
        AdapterMatrixReportStatus::Failed
    } else if adapters_deferred > 0 || fixture_status == FixtureExportReportStatus::Watch {
        AdapterMatrixReportStatus::Watch
    } else {
        AdapterMatrixReportStatus::Passed
    }
}

fn readiness_label(
    status: AdapterMatrixReportStatus,
    fixture_status: FixtureExportReportStatus,
) -> &'static str {
    match status {
        AdapterMatrixReportStatus::Failed => "live_adapter_matrix_failed",
        AdapterMatrixReportStatus::Watch if fixture_status == FixtureExportReportStatus::Watch => {
            "live_adapter_matrix_watch_fixture_export"
        }
        AdapterMatrixReportStatus::Watch => "live_adapter_matrix_watch_missing_live_adapters",
        AdapterMatrixReportStatus::Passed => "live_adapter_matrix_ready",
    }
}

fn missing_surface(adapter_kind: LiveAdapterKind) -> &'static str {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => "live_monero_header_reorg_stream",
        LiveAdapterKind::DepositLockWatcher => "live_deposit_lock_watcher_certificate_stream",
        LiveAdapterKind::PrivateReceiptScanner => "wallet_private_receipt_scanner",
        LiveAdapterKind::ReserveRelease => "reserve_release_adapter",
        LiveAdapterKind::WatcherBondPool => "watcher_bond_pool_adapter",
        LiveAdapterKind::SlashingSettlement => "slashing_settlement_receipt_adapter",
        LiveAdapterKind::ExitClaimQueue => "exit_claim_queue_runtime_adapter",
        LiveAdapterKind::PqAuthorityKeyManager => "pq_authority_key_manager",
        LiveAdapterKind::CargoRuntimeHarness => "cargo_runtime_test_harness",
        LiveAdapterKind::SecurityAuditHarness => "security_privacy_audit_harness",
    }
}

fn next_step(adapter_kind: LiveAdapterKind) -> &'static str {
    match adapter_kind {
        LiveAdapterKind::MoneroHeaderReorg => {
            "connect fixture roots to live Monero headers, depth windows, and reorg events"
        }
        LiveAdapterKind::DepositLockWatcher => {
            "bind deposit lock certificates to watcher quorum and challenge windows"
        }
        LiveAdapterKind::PrivateReceiptScanner => {
            "export wallet scan hints for private receipt continuity without metadata leaks"
        }
        LiveAdapterKind::ReserveRelease => {
            "connect reserve release decisions to live reserves and emergency backstop escrow"
        }
        LiveAdapterKind::WatcherBondPool => {
            "bind watcher bond accounts to equivocation and withholding evidence"
        }
        LiveAdapterKind::SlashingSettlement => {
            "settle slashing receipts against watcher bonds and release holdbacks"
        }
        LiveAdapterKind::ExitClaimQueue => {
            "route forced-exit claims into a live queue with timeout and challenge ordering"
        }
        LiveAdapterKind::PqAuthorityKeyManager => {
            "enforce PQ signer roots for bridge authority, watcher quorum, and upgrades"
        }
        LiveAdapterKind::CargoRuntimeHarness => {
            "materialize fixture cargo filters into executable runtime tests"
        }
        LiveAdapterKind::SecurityAuditHarness => {
            "review PQ control-plane and privacy leakage surfaces before production"
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

pub fn adapter_requirement_id(
    adapter_kind: LiveAdapterKind,
    fixture_export_id: &str,
    readiness_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-REQUIREMENT-ID",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Str(fixture_export_id),
            HashPart::Str(readiness_root),
        ],
        32,
    )
}

pub fn adapter_input_root(
    adapter_kind: LiveAdapterKind,
    fixture_root: &str,
    cargo_index_key: &str,
    expected_final_status: FinalReleaseGateStatus,
    expected_user_release_status: FinalGateDecisionStatus,
    expected_production_status: FinalGateDecisionStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-INPUT-ROOT",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Str(fixture_root),
            HashPart::Str(cargo_index_key),
            HashPart::Str(expected_final_status.as_str()),
            HashPart::Str(expected_user_release_status.as_str()),
            HashPart::Str(expected_production_status.as_str()),
        ],
        32,
    )
}

pub fn readiness_root(
    adapter_kind: LiveAdapterKind,
    status: AdapterReadinessStatus,
    adapter_input_root: &str,
    redacted_fixture_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-READINESS-ROOT",
        &[
            HashPart::Str(adapter_kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(adapter_input_root),
            HashPart::Str(redacted_fixture_commitment),
        ],
        32,
    )
}

pub fn adapter_kind_root(requirements: &BTreeMap<String, LiveAdapterRequirement>) -> String {
    let records = requirements
        .values()
        .map(|requirement| {
            json!({
                "adapter_kind": requirement.adapter_kind.as_str(),
                "status": requirement.status.as_str(),
                "readiness_root": requirement.readiness_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-KIND-ROOT", &records)
}

pub fn missing_surface_root(requirements: &BTreeMap<String, LiveAdapterRequirement>) -> String {
    let records = requirements
        .values()
        .filter(|requirement| requirement.status != AdapterReadinessStatus::Ready)
        .map(|requirement| {
            json!({
                "adapter_kind": requirement.adapter_kind.as_str(),
                "missing_surface": requirement.missing_surface,
                "next_step": requirement.next_step,
                "fixture_root": requirement.fixture_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MISSING-SURFACE-ROOT",
        &records,
    )
}

pub fn adapter_matrix_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn source_root(
    fixture_export_state_root: &str,
    fixture_export_report_root: &str,
    export_root: &str,
    expected_outcome_root: &str,
    redaction_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-SOURCE-ROOT",
        &[
            HashPart::Str(fixture_export_state_root),
            HashPart::Str(fixture_export_report_root),
            HashPart::Str(export_root),
            HashPart::Str(expected_outcome_root),
            HashPart::Str(redaction_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: AdapterMatrixReportStatus,
    readiness_label: &str,
    source_root: &str,
    requirement_root: &str,
    adapter_kind_root: &str,
    missing_surface_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(requirement_root),
            HashPart::Str(adapter_kind_root),
            HashPart::Str(missing_surface_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-ADAPTER-MATRIX-RECORD",
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
