use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_gate_runtime::{
        FinalGateDecisionStatus, FinalReleaseGateStatus,
    },
    monero_l2_pq_bridge_exit_final_release_test_vector_manifest_runtime::{
        FinalReleaseTestVector, FinalReleaseTestVectorKind, State as TestVectorManifestState,
        TestVectorEntryStatus, TestVectorManifestStatus,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitFinalReleaseFixtureExportRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FINAL_RELEASE_FIXTURE_EXPORT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-final-release-fixture-export-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FINAL_RELEASE_FIXTURE_EXPORT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FIXTURE_EXPORT_SUITE: &str = "monero-l2-pq-bridge-exit-final-release-fixture-export-v1";
pub const DEFAULT_MIN_FIXTURE_EXPORTS: u64 = 15;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureExportAudience {
    Wallet,
    Operator,
    Auditor,
    CargoHarness,
    CompactIndex,
}

impl FixtureExportAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
            Self::CargoHarness => "cargo_harness",
            Self::CompactIndex => "compact_index",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureExportStatus {
    Exported,
    Deferred,
    Blocked,
}

impl FixtureExportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exported => "exported",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureExportReportStatus {
    Passed,
    Watch,
    Failed,
}

impl FixtureExportReportStatus {
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
    pub fixture_export_suite: String,
    pub min_fixture_exports: u64,
    pub include_public_fixture_payloads: bool,
    pub redact_mutation_details: bool,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_export_suite: FIXTURE_EXPORT_SUITE.to_string(),
            min_fixture_exports: DEFAULT_MIN_FIXTURE_EXPORTS,
            include_public_fixture_payloads: false,
            redact_mutation_details: true,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_export_suite": self.fixture_export_suite,
            "min_fixture_exports": self.min_fixture_exports,
            "include_public_fixture_payloads": self.include_public_fixture_payloads,
            "redact_mutation_details": self.redact_mutation_details,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureExportRecord {
    pub export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub kind: FinalReleaseTestVectorKind,
    pub status: FixtureExportStatus,
    pub manifest_entry_status: TestVectorEntryStatus,
    pub audience: FixtureExportAudience,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub fixture_root: String,
    pub baseline_report_root: String,
    pub baseline_decision_count: u64,
    pub expected_final_status: FinalReleaseGateStatus,
    pub expected_user_release_status: FinalGateDecisionStatus,
    pub expected_production_status: FinalGateDecisionStatus,
    pub target_gate_root: String,
    pub blocker_surface_root: String,
    pub cargo_test_path: String,
    pub cargo_test_filter: String,
    pub cargo_index_key: String,
    pub redacted_fixture_commitment: String,
    pub public_fixture_payload: Option<Value>,
}

impl FixtureExportRecord {
    pub fn from_vector(
        config: &Config,
        vector: &FinalReleaseTestVector,
        audience: FixtureExportAudience,
    ) -> Self {
        let status = export_status(vector.status);
        let target_gate_root = target_gate_root(
            &vector.vector_id,
            &vector
                .target_gates
                .iter()
                .map(|gate| gate.as_str())
                .collect::<Vec<_>>(),
        );
        let blocker_surface_root = blocker_surface_root(
            vector.kind,
            &vector.expected_blocker_surface,
            &vector.required_mutation,
            config.redact_mutation_details,
        );
        let cargo_index_key = cargo_index_key(&vector.cargo_test_path, &vector.cargo_test_filter);
        let redacted_fixture_commitment = redacted_fixture_commitment(
            vector.kind,
            &vector.fixture_root,
            &vector.baseline_report_root,
            config.redact_mutation_details,
        );
        let export_id = fixture_export_id(
            audience,
            vector.kind,
            &vector.vector_id,
            &vector.fixture_root,
            &cargo_index_key,
        );
        Self {
            export_id,
            vector_id: vector.vector_id.clone(),
            test_name: vector.test_name.clone(),
            kind: vector.kind,
            status,
            manifest_entry_status: vector.status,
            audience,
            scenario_id: vector.scenario_id.clone(),
            transfer_id: vector.transfer_id.clone(),
            release_claim_id: vector.release_claim_id.clone(),
            transcript_root: vector.transcript_root.clone(),
            fixture_root: vector.fixture_root.clone(),
            baseline_report_root: vector.baseline_report_root.clone(),
            baseline_decision_count: vector.baseline_decision_count,
            expected_final_status: vector.expected_final_status,
            expected_user_release_status: vector.expected_user_release_status,
            expected_production_status: vector.expected_production_status,
            target_gate_root,
            blocker_surface_root,
            cargo_test_path: vector.cargo_test_path.clone(),
            cargo_test_filter: vector.cargo_test_filter.clone(),
            cargo_index_key,
            redacted_fixture_commitment,
            public_fixture_payload: if config.include_public_fixture_payloads {
                Some(vector.public_fixture.clone())
            } else {
                None
            },
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "export_id": self.export_id,
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "manifest_entry_status": self.manifest_entry_status.as_str(),
            "audience": self.audience.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "fixture_root": self.fixture_root,
            "baseline_report_root": self.baseline_report_root,
            "baseline_decision_count": self.baseline_decision_count,
            "expected_final_status": self.expected_final_status.as_str(),
            "expected_user_release_status": self.expected_user_release_status.as_str(),
            "expected_production_status": self.expected_production_status.as_str(),
            "target_gate_root": self.target_gate_root,
            "blocker_surface_root": self.blocker_surface_root,
            "cargo_test_path": self.cargo_test_path,
            "cargo_test_filter": self.cargo_test_filter,
            "cargo_index_key": self.cargo_index_key,
            "redacted_fixture_commitment": self.redacted_fixture_commitment,
            "public_fixture_payload": self.public_fixture_payload,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fixture_export", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureExportReport {
    pub report_id: String,
    pub status: FixtureExportReportStatus,
    pub readiness_label: String,
    pub manifest_state_root: String,
    pub manifest_report_root: String,
    pub manifest_report_id: String,
    pub manifest_status: TestVectorManifestStatus,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub fixtures_exported: u64,
    pub fixtures_deferred: u64,
    pub fixtures_blocked: u64,
    pub cargo_filters_indexed: u64,
    pub release_allowed_expected: u64,
    pub watch_expected: u64,
    pub failed_expected: u64,
    pub redacted_payloads: u64,
    pub export_records: BTreeMap<String, FixtureExportRecord>,
    pub roots: FixtureExportReportRoots,
}

impl FixtureExportReport {
    pub fn public_record(&self) -> Value {
        let exports = self
            .export_records
            .values()
            .map(FixtureExportRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "manifest_state_root": self.manifest_state_root,
            "manifest_report_root": self.manifest_report_root,
            "manifest_report_id": self.manifest_report_id,
            "manifest_status": self.manifest_status.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "fixtures_exported": self.fixtures_exported,
            "fixtures_deferred": self.fixtures_deferred,
            "fixtures_blocked": self.fixtures_blocked,
            "cargo_filters_indexed": self.cargo_filters_indexed,
            "release_allowed_expected": self.release_allowed_expected,
            "watch_expected": self.watch_expected,
            "failed_expected": self.failed_expected,
            "redacted_payloads": self.redacted_payloads,
            "export_records": exports,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureExportReportRoots {
    pub export_root: String,
    pub cargo_index_root: String,
    pub expected_outcome_root: String,
    pub redaction_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl FixtureExportReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "export_root": self.export_root,
            "cargo_index_root": self.cargo_index_root,
            "expected_outcome_root": self.expected_outcome_root,
            "redaction_root": self.redaction_root,
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
    pub fixtures_exported: u64,
    pub fixtures_deferred: u64,
    pub fixtures_blocked: u64,
    pub cargo_filters_indexed: u64,
    pub release_allowed_expected: u64,
    pub watch_expected: u64,
    pub failed_expected: u64,
    pub redacted_payloads: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "fixtures_exported": self.fixtures_exported,
            "fixtures_deferred": self.fixtures_deferred,
            "fixtures_blocked": self.fixtures_blocked,
            "cargo_filters_indexed": self.cargo_filters_indexed,
            "release_allowed_expected": self.release_allowed_expected,
            "watch_expected": self.watch_expected,
            "failed_expected": self.failed_expected,
            "redacted_payloads": self.redacted_payloads,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-STATE",
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
    pub latest_report: Option<FixtureExportReport>,
    pub report_history: Vec<FixtureExportReport>,
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
        let manifest =
            crate::monero_l2_pq_bridge_exit_final_release_test_vector_manifest_runtime::devnet();
        state
            .export_fixtures(&manifest)
            .expect("devnet bridge exit final release fixture export");
        state
    }

    pub fn export_fixtures(&mut self, manifest: &TestVectorManifestState) -> Result<String> {
        let manifest_report = manifest
            .latest_report
            .as_ref()
            .ok_or_else(|| "final release test-vector manifest has no latest report".to_string())?;
        let export_records = build_exports(&self.config, manifest_report)?;
        ensure(
            export_records.len() as u64 >= self.config.min_fixture_exports,
            "fixture export omitted required final release vectors",
        )?;
        let fixtures_exported = export_records
            .values()
            .filter(|record| record.status == FixtureExportStatus::Exported)
            .count() as u64;
        let fixtures_deferred = export_records
            .values()
            .filter(|record| record.status == FixtureExportStatus::Deferred)
            .count() as u64;
        let fixtures_blocked = export_records
            .values()
            .filter(|record| record.status == FixtureExportStatus::Blocked)
            .count() as u64;
        let cargo_filters_indexed = export_records
            .values()
            .filter(|record| !record.cargo_test_filter.is_empty())
            .count() as u64;
        let release_allowed_expected = export_records
            .values()
            .filter(|record| record.expected_final_status == FinalReleaseGateStatus::Passed)
            .count() as u64;
        let watch_expected = export_records
            .values()
            .filter(|record| record.expected_final_status == FinalReleaseGateStatus::Watch)
            .count() as u64;
        let failed_expected = export_records
            .values()
            .filter(|record| record.expected_final_status == FinalReleaseGateStatus::Failed)
            .count() as u64;
        let redacted_payloads = export_records
            .values()
            .filter(|record| record.public_fixture_payload.is_none())
            .count() as u64;
        let status = report_status(
            &self.config,
            manifest_report.status,
            fixtures_deferred,
            fixtures_blocked,
        );
        let readiness_label =
            readiness_label(status, manifest_report.status, &self.config).to_string();
        let export_values = export_records
            .values()
            .map(FixtureExportRecord::public_record)
            .collect::<Vec<_>>();
        let export_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-RECORDS",
            &export_values,
        );
        let cargo_values = export_records
            .values()
            .map(|record| {
                json!({
                    "vector_id": record.vector_id,
                    "cargo_test_path": record.cargo_test_path,
                    "cargo_test_filter": record.cargo_test_filter,
                    "cargo_index_key": record.cargo_index_key,
                })
            })
            .collect::<Vec<_>>();
        let cargo_index_root = cargo_index_root(&cargo_values);
        let expected_values = export_records
            .values()
            .map(|record| {
                json!({
                    "vector_id": record.vector_id,
                    "expected_final_status": record.expected_final_status.as_str(),
                    "expected_user_release_status": record.expected_user_release_status.as_str(),
                    "expected_production_status": record.expected_production_status.as_str(),
                    "fixture_root": record.fixture_root,
                })
            })
            .collect::<Vec<_>>();
        let expected_outcome_root = expected_outcome_root(&expected_values);
        let redaction_values = export_records
            .values()
            .map(|record| {
                json!({
                    "vector_id": record.vector_id,
                    "redacted_fixture_commitment": record.redacted_fixture_commitment,
                    "payload_exported": record.public_fixture_payload.is_some(),
                })
            })
            .collect::<Vec<_>>();
        let redaction_root = redaction_root(
            self.config.include_public_fixture_payloads,
            self.config.redact_mutation_details,
            &redaction_values,
        );
        let source_root = source_root(
            &manifest.state_root(),
            &manifest_report.state_root(),
            &manifest_report.roots.vector_root,
            &manifest_report.roots.deferred_gate_root,
            &manifest_report.roots.report_root,
            &manifest_report.release_claim_id,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &export_root,
            &cargo_index_root,
            &expected_outcome_root,
            &redaction_root,
            &manifest_report.release_claim_id,
        );
        let report_id = fixture_export_report_id(&manifest_report.release_claim_id, &report_root);
        let report = FixtureExportReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            manifest_state_root: manifest.state_root(),
            manifest_report_root: manifest_report.state_root(),
            manifest_report_id: manifest_report.report_id.clone(),
            manifest_status: manifest_report.status,
            scenario_id: manifest_report.scenario_id.clone(),
            transfer_id: manifest_report.transfer_id.clone(),
            release_claim_id: manifest_report.release_claim_id.clone(),
            transcript_root: manifest_report.transcript_root.clone(),
            fixtures_exported,
            fixtures_deferred,
            fixtures_blocked,
            cargo_filters_indexed,
            release_allowed_expected,
            watch_expected,
            failed_expected,
            redacted_payloads,
            export_records,
            roots: FixtureExportReportRoots {
                export_root,
                cargo_index_root,
                expected_outcome_root,
                redaction_root,
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
            "fixture_export_suite": self.config.fixture_export_suite,
            "latest_report": self.latest_report.as_ref().map(FixtureExportReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: FixtureExportReport) {
        self.counters.reports_run += 1;
        self.counters.fixtures_exported += report.fixtures_exported;
        self.counters.fixtures_deferred += report.fixtures_deferred;
        self.counters.fixtures_blocked += report.fixtures_blocked;
        self.counters.cargo_filters_indexed += report.cargo_filters_indexed;
        self.counters.release_allowed_expected += report.release_allowed_expected;
        self.counters.watch_expected += report.watch_expected;
        self.counters.failed_expected += report.failed_expected;
        self.counters.redacted_payloads += report.redacted_payloads;
        match report.status {
            FixtureExportReportStatus::Passed => self.counters.reports_passed += 1,
            FixtureExportReportStatus::Watch => self.counters.reports_watch += 1,
            FixtureExportReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(FixtureExportReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_exports(
    config: &Config,
    manifest_report: &crate::monero_l2_pq_bridge_exit_final_release_test_vector_manifest_runtime::FinalReleaseTestVectorManifestReport,
) -> Result<BTreeMap<String, FixtureExportRecord>> {
    let mut export_records = BTreeMap::new();
    for vector in manifest_report.vectors.values() {
        let audience = audience_for_vector(vector);
        let record = FixtureExportRecord::from_vector(config, vector, audience);
        export_records.insert(record.export_id.clone(), record);
    }
    Ok(export_records)
}

fn audience_for_vector(vector: &FinalReleaseTestVector) -> FixtureExportAudience {
    if vector.cargo_test_filter.contains("deferred_cargo") {
        FixtureExportAudience::CargoHarness
    } else if vector.expected_final_status == FinalReleaseGateStatus::Failed {
        FixtureExportAudience::Auditor
    } else if vector.expected_production_status == FinalGateDecisionStatus::Blocked {
        FixtureExportAudience::Operator
    } else if vector.expected_user_release_status == FinalGateDecisionStatus::ReleaseAllowed {
        FixtureExportAudience::Wallet
    } else {
        FixtureExportAudience::CompactIndex
    }
}

fn export_status(status: TestVectorEntryStatus) -> FixtureExportStatus {
    match status {
        TestVectorEntryStatus::Declared => FixtureExportStatus::Exported,
        TestVectorEntryStatus::Deferred => FixtureExportStatus::Deferred,
        TestVectorEntryStatus::Blocked => FixtureExportStatus::Blocked,
    }
}

fn report_status(
    config: &Config,
    manifest_status: TestVectorManifestStatus,
    fixtures_deferred: u64,
    fixtures_blocked: u64,
) -> FixtureExportReportStatus {
    if fixtures_blocked > 0 || manifest_status == TestVectorManifestStatus::Failed {
        FixtureExportReportStatus::Failed
    } else if fixtures_deferred > 0
        || manifest_status == TestVectorManifestStatus::Watch
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
    {
        FixtureExportReportStatus::Watch
    } else {
        FixtureExportReportStatus::Passed
    }
}

fn readiness_label(
    status: FixtureExportReportStatus,
    manifest_status: TestVectorManifestStatus,
    config: &Config,
) -> &'static str {
    match status {
        FixtureExportReportStatus::Failed => "final_release_fixture_export_failed",
        FixtureExportReportStatus::Watch if config.cargo_checks_deferred => {
            "final_release_fixture_export_watch_cargo_deferred"
        }
        FixtureExportReportStatus::Watch if config.runtime_tests_deferred => {
            "final_release_fixture_export_watch_runtime_deferred"
        }
        FixtureExportReportStatus::Watch if manifest_status == TestVectorManifestStatus::Watch => {
            "final_release_fixture_export_watch_manifest"
        }
        FixtureExportReportStatus::Watch => "final_release_fixture_export_watch",
        FixtureExportReportStatus::Passed => "final_release_fixture_export_ready",
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

pub fn fixture_export_id(
    audience: FixtureExportAudience,
    kind: FinalReleaseTestVectorKind,
    vector_id: &str,
    fixture_root: &str,
    cargo_index_key: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-ID",
        &[
            HashPart::Str(audience.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Str(vector_id),
            HashPart::Str(fixture_root),
            HashPart::Str(cargo_index_key),
        ],
        32,
    )
}

pub fn cargo_index_key(cargo_test_path: &str, cargo_test_filter: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-CARGO-INDEX-KEY",
        &[
            HashPart::Str(cargo_test_path),
            HashPart::Str(cargo_test_filter),
        ],
        32,
    )
}

pub fn target_gate_root(vector_id: &str, target_gates: &[&str]) -> String {
    let gates = target_gates
        .iter()
        .map(|gate| json!({ "target_gate": gate }))
        .collect::<Vec<_>>();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-TARGET-GATE-ROOT",
        &[HashPart::Str(vector_id), HashPart::Json(&json!(gates))],
        32,
    )
}

pub fn blocker_surface_root(
    kind: FinalReleaseTestVectorKind,
    expected_blocker_surface: &str,
    required_mutation: &str,
    redact_mutation_details: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-BLOCKER-SURFACE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(expected_blocker_surface),
            HashPart::Str(if redact_mutation_details {
                "mutation_redacted"
            } else {
                required_mutation
            }),
        ],
        32,
    )
}

pub fn redacted_fixture_commitment(
    kind: FinalReleaseTestVectorKind,
    fixture_root: &str,
    baseline_report_root: &str,
    redact_mutation_details: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-REDACTED-COMMITMENT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(fixture_root),
            HashPart::Str(baseline_report_root),
            HashPart::Str(if redact_mutation_details {
                "redacted"
            } else {
                "full"
            }),
        ],
        32,
    )
}

pub fn fixture_export_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn cargo_index_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-CARGO-INDEX",
        records,
    )
}

pub fn expected_outcome_root(records: &[Value]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPECTED-OUTCOMES",
        records,
    )
}

pub fn redaction_root(
    include_public_fixture_payloads: bool,
    redact_mutation_details: bool,
    records: &[Value],
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-REDACTION-ROOT",
        &[
            HashPart::Str(bool_str(include_public_fixture_payloads)),
            HashPart::Str(bool_str(redact_mutation_details)),
            HashPart::Json(&json!(records)),
        ],
        32,
    )
}

pub fn source_root(
    manifest_state_root: &str,
    manifest_report_root: &str,
    manifest_vector_root: &str,
    manifest_deferred_gate_root: &str,
    manifest_report_root_again: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-SOURCE-ROOT",
        &[
            HashPart::Str(manifest_state_root),
            HashPart::Str(manifest_report_root),
            HashPart::Str(manifest_vector_root),
            HashPart::Str(manifest_deferred_gate_root),
            HashPart::Str(manifest_report_root_again),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: FixtureExportReportStatus,
    readiness_label: &str,
    source_root: &str,
    export_root: &str,
    cargo_index_root: &str,
    expected_outcome_root: &str,
    redaction_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(export_root),
            HashPart::Str(cargo_index_root),
            HashPart::Str(expected_outcome_root),
            HashPart::Str(redaction_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-FIXTURE-EXPORT-RECORD",
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
