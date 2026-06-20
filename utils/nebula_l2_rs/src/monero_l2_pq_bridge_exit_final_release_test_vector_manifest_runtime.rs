use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_gate_runtime::{
        FinalGateDecisionKind, FinalGateDecisionStatus, FinalReleaseGateStatus,
        State as FinalReleaseGateState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitFinalReleaseTestVectorManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FINAL_RELEASE_TEST_VECTOR_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-final-release-test-vector-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FINAL_RELEASE_TEST_VECTOR_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const TEST_VECTOR_MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-final-release-test-vector-manifest-v1";
pub const DEFAULT_MIN_TEST_VECTORS: u64 = 15;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalReleaseTestVectorKind {
    DevnetWatchPreservesEscape,
    AllEvidencePromotedAllowsRelease,
    SafetyCaseFailureBlocksRelease,
    AuthorityFailureBlocksRelease,
    LiquidityReserveFailureBlocksRelease,
    ReorgEscapeBlocksRelease,
    WatcherSlashingFailureBlocksRelease,
    DeferredCargoRuntimeKeepsWatch,
    DeferredSecurityAuditKeepsWatch,
    ProductionReleaseFlagKeepsWatch,
    MetadataLeakageBlocksProduction,
    ReserveExhaustionBlocksRelease,
    WatcherCollusionQuarantineBlocksProduction,
    ReceiptRootMismatchBlocksRelease,
    PqSignerQuorumRegressionBlocksProduction,
}

impl FinalReleaseTestVectorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DevnetWatchPreservesEscape => "devnet_watch_preserves_escape",
            Self::AllEvidencePromotedAllowsRelease => "all_evidence_promoted_allows_release",
            Self::SafetyCaseFailureBlocksRelease => "safety_case_failure_blocks_release",
            Self::AuthorityFailureBlocksRelease => "authority_failure_blocks_release",
            Self::LiquidityReserveFailureBlocksRelease => {
                "liquidity_reserve_failure_blocks_release"
            }
            Self::ReorgEscapeBlocksRelease => "reorg_escape_blocks_release",
            Self::WatcherSlashingFailureBlocksRelease => "watcher_slashing_failure_blocks_release",
            Self::DeferredCargoRuntimeKeepsWatch => "deferred_cargo_runtime_keeps_watch",
            Self::DeferredSecurityAuditKeepsWatch => "deferred_security_audit_keeps_watch",
            Self::ProductionReleaseFlagKeepsWatch => "production_release_flag_keeps_watch",
            Self::MetadataLeakageBlocksProduction => "metadata_leakage_blocks_production",
            Self::ReserveExhaustionBlocksRelease => "reserve_exhaustion_blocks_release",
            Self::WatcherCollusionQuarantineBlocksProduction => {
                "watcher_collusion_quarantine_blocks_production"
            }
            Self::ReceiptRootMismatchBlocksRelease => "receipt_root_mismatch_blocks_release",
            Self::PqSignerQuorumRegressionBlocksProduction => {
                "pq_signer_quorum_regression_blocks_production"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestVectorTargetGate {
    SafetyCase,
    AuthorityTransfer,
    LiquidityReserve,
    ReorgWatcherSimulation,
    WatcherBondSlashing,
    FinalReleaseGate,
    CargoRuntimeGate,
    SecurityAuditGate,
    ProductionReleaseGate,
    PublicReceiptModel,
    PrivacyMetadataModel,
    PqControlPlane,
}

impl TestVectorTargetGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SafetyCase => "safety_case",
            Self::AuthorityTransfer => "authority_transfer",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::ReorgWatcherSimulation => "reorg_watcher_simulation",
            Self::WatcherBondSlashing => "watcher_bond_slashing",
            Self::FinalReleaseGate => "final_release_gate",
            Self::CargoRuntimeGate => "cargo_runtime_gate",
            Self::SecurityAuditGate => "security_audit_gate",
            Self::ProductionReleaseGate => "production_release_gate",
            Self::PublicReceiptModel => "public_receipt_model",
            Self::PrivacyMetadataModel => "privacy_metadata_model",
            Self::PqControlPlane => "pq_control_plane",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestVectorEntryStatus {
    Declared,
    Deferred,
    Blocked,
}

impl TestVectorEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestVectorManifestStatus {
    Passed,
    Watch,
    Failed,
}

impl TestVectorManifestStatus {
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
    pub manifest_suite: String,
    pub min_test_vectors: u64,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub live_adapters_deferred: bool,
    pub security_audit_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: TEST_VECTOR_MANIFEST_SUITE.to_string(),
            min_test_vectors: DEFAULT_MIN_TEST_VECTORS,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            live_adapters_deferred: true,
            security_audit_deferred: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "min_test_vectors": self.min_test_vectors,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "live_adapters_deferred": self.live_adapters_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalReleaseTestVector {
    pub vector_id: String,
    pub test_name: String,
    pub kind: FinalReleaseTestVectorKind,
    pub status: TestVectorEntryStatus,
    pub target_gates: Vec<TestVectorTargetGate>,
    pub expected_decision_kinds: Vec<FinalGateDecisionKind>,
    pub expected_final_status: FinalReleaseGateStatus,
    pub expected_user_release_status: FinalGateDecisionStatus,
    pub expected_production_status: FinalGateDecisionStatus,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub baseline_report_id: String,
    pub baseline_report_root: String,
    pub baseline_readiness_label: String,
    pub baseline_decision_ids: Vec<String>,
    pub baseline_decision_count: u64,
    pub threat_model: String,
    pub required_mutation: String,
    pub expected_blocker_surface: String,
    pub cargo_test_path: String,
    pub cargo_test_filter: String,
    pub fixture_root: String,
    pub public_fixture: Value,
}

impl FinalReleaseTestVector {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        report: &crate::monero_l2_pq_bridge_exit_final_release_gate_runtime::FinalReleaseGateReport,
        kind: FinalReleaseTestVectorKind,
        status: TestVectorEntryStatus,
        target_gates: Vec<TestVectorTargetGate>,
        expected_decision_kinds: Vec<FinalGateDecisionKind>,
        expected_final_status: FinalReleaseGateStatus,
        expected_user_release_status: FinalGateDecisionStatus,
        expected_production_status: FinalGateDecisionStatus,
        threat_model: impl Into<String>,
        required_mutation: impl Into<String>,
        expected_blocker_surface: impl Into<String>,
    ) -> Self {
        let test_name = test_name(kind);
        let cargo_test_path = cargo_test_path(kind);
        let cargo_test_filter = format!("bridge_exit_final_release::{test_name}");
        let baseline_decision_ids = matching_decision_ids(report, &expected_decision_kinds);
        let threat_model = threat_model.into();
        let required_mutation = required_mutation.into();
        let expected_blocker_surface = expected_blocker_surface.into();
        let public_fixture = json!({
            "kind": kind.as_str(),
            "baseline_status": report.status.as_str(),
            "baseline_user_answer": report.user_answer,
            "baseline_readiness_label": report.readiness_label,
            "expected_final_status": expected_final_status.as_str(),
            "expected_user_release_status": expected_user_release_status.as_str(),
            "expected_production_status": expected_production_status.as_str(),
            "target_gates": target_gates.iter().map(|gate| gate.as_str()).collect::<Vec<_>>(),
            "expected_decision_kinds": expected_decision_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "baseline_decision_ids": baseline_decision_ids,
            "threat_model": threat_model,
            "required_mutation": required_mutation,
            "expected_blocker_surface": expected_blocker_surface,
            "roots": report.roots.public_record(),
        });
        let fixture_root = test_vector_fixture_root(
            kind,
            &report.release_claim_id,
            &report.roots.report_root,
            &public_fixture,
        );
        let vector_id = test_vector_id(kind, &report.release_claim_id, &fixture_root);
        Self {
            vector_id,
            test_name,
            kind,
            status,
            target_gates,
            expected_decision_kinds,
            expected_final_status,
            expected_user_release_status,
            expected_production_status,
            scenario_id: report.scenario_id.clone(),
            transfer_id: report.transfer_id.clone(),
            release_claim_id: report.release_claim_id.clone(),
            transcript_root: report.transcript_root.clone(),
            baseline_report_id: report.report_id.clone(),
            baseline_report_root: report.roots.report_root.clone(),
            baseline_readiness_label: report.readiness_label.clone(),
            baseline_decision_count: baseline_decision_ids.len() as u64,
            baseline_decision_ids,
            threat_model,
            required_mutation,
            expected_blocker_surface,
            cargo_test_path,
            cargo_test_filter,
            fixture_root,
            public_fixture,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "target_gates": self.target_gates.iter().map(|gate| gate.as_str()).collect::<Vec<_>>(),
            "expected_decision_kinds": self.expected_decision_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "expected_final_status": self.expected_final_status.as_str(),
            "expected_user_release_status": self.expected_user_release_status.as_str(),
            "expected_production_status": self.expected_production_status.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "baseline_report_id": self.baseline_report_id,
            "baseline_report_root": self.baseline_report_root,
            "baseline_readiness_label": self.baseline_readiness_label,
            "baseline_decision_ids": self.baseline_decision_ids,
            "baseline_decision_count": self.baseline_decision_count,
            "threat_model": self.threat_model,
            "required_mutation": self.required_mutation,
            "expected_blocker_surface": self.expected_blocker_surface,
            "cargo_test_path": self.cargo_test_path,
            "cargo_test_filter": self.cargo_test_filter,
            "fixture_root": self.fixture_root,
            "public_fixture": self.public_fixture,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("final_release_test_vector", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalReleaseTestVectorManifestReport {
    pub report_id: String,
    pub status: TestVectorManifestStatus,
    pub readiness_label: String,
    pub final_release_gate_state_root: String,
    pub final_release_gate_report_root: String,
    pub final_release_gate_report_id: String,
    pub baseline_final_status: FinalReleaseGateStatus,
    pub baseline_user_answer: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub vectors_declared: u64,
    pub vectors_deferred: u64,
    pub vectors_blocked: u64,
    pub expected_release_allowed_vectors: u64,
    pub expected_watch_vectors: u64,
    pub expected_failed_vectors: u64,
    pub baseline_decisions_referenced: u64,
    pub vectors: BTreeMap<String, FinalReleaseTestVector>,
    pub roots: ManifestReportRoots,
}

impl FinalReleaseTestVectorManifestReport {
    pub fn public_record(&self) -> Value {
        let vectors = self
            .vectors
            .values()
            .map(FinalReleaseTestVector::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "final_release_gate_state_root": self.final_release_gate_state_root,
            "final_release_gate_report_root": self.final_release_gate_report_root,
            "final_release_gate_report_id": self.final_release_gate_report_id,
            "baseline_final_status": self.baseline_final_status.as_str(),
            "baseline_user_answer": self.baseline_user_answer,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "vectors_declared": self.vectors_declared,
            "vectors_deferred": self.vectors_deferred,
            "vectors_blocked": self.vectors_blocked,
            "expected_release_allowed_vectors": self.expected_release_allowed_vectors,
            "expected_watch_vectors": self.expected_watch_vectors,
            "expected_failed_vectors": self.expected_failed_vectors,
            "baseline_decisions_referenced": self.baseline_decisions_referenced,
            "vectors": vectors,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestReportRoots {
    pub vector_root: String,
    pub source_root: String,
    pub deferred_gate_root: String,
    pub report_root: String,
}

impl ManifestReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "vector_root": self.vector_root,
            "source_root": self.source_root,
            "deferred_gate_root": self.deferred_gate_root,
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
    pub vectors_declared: u64,
    pub vectors_deferred: u64,
    pub vectors_blocked: u64,
    pub expected_release_allowed_vectors: u64,
    pub expected_watch_vectors: u64,
    pub expected_failed_vectors: u64,
    pub baseline_decisions_referenced: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "vectors_declared": self.vectors_declared,
            "vectors_deferred": self.vectors_deferred,
            "vectors_blocked": self.vectors_blocked,
            "expected_release_allowed_vectors": self.expected_release_allowed_vectors,
            "expected_watch_vectors": self.expected_watch_vectors,
            "expected_failed_vectors": self.expected_failed_vectors,
            "baseline_decisions_referenced": self.baseline_decisions_referenced,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-STATE",
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
    pub latest_report: Option<FinalReleaseTestVectorManifestReport>,
    pub report_history: Vec<FinalReleaseTestVectorManifestReport>,
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
        let final_release_gate =
            crate::monero_l2_pq_bridge_exit_final_release_gate_runtime::devnet();
        state
            .build_manifest(&final_release_gate)
            .expect("devnet bridge exit final release test vector manifest");
        state
    }

    pub fn build_manifest(&mut self, final_release_gate: &FinalReleaseGateState) -> Result<String> {
        let final_report = final_release_gate
            .latest_report
            .as_ref()
            .ok_or_else(|| "final release gate state has no latest report".to_string())?;
        let vectors = build_test_vectors(&self.config, final_report)?;
        ensure(
            vectors.len() as u64 >= self.config.min_test_vectors,
            "final release manifest omitted required test vectors",
        )?;
        let vectors_declared = vectors
            .values()
            .filter(|vector| vector.status == TestVectorEntryStatus::Declared)
            .count() as u64;
        let vectors_deferred = vectors
            .values()
            .filter(|vector| vector.status == TestVectorEntryStatus::Deferred)
            .count() as u64;
        let vectors_blocked = vectors
            .values()
            .filter(|vector| vector.status == TestVectorEntryStatus::Blocked)
            .count() as u64;
        let expected_release_allowed_vectors = vectors
            .values()
            .filter(|vector| vector.expected_final_status == FinalReleaseGateStatus::Passed)
            .count() as u64;
        let expected_watch_vectors = vectors
            .values()
            .filter(|vector| vector.expected_final_status == FinalReleaseGateStatus::Watch)
            .count() as u64;
        let expected_failed_vectors = vectors
            .values()
            .filter(|vector| vector.expected_final_status == FinalReleaseGateStatus::Failed)
            .count() as u64;
        let baseline_decisions_referenced = vectors
            .values()
            .map(|vector| vector.baseline_decision_count)
            .sum::<u64>();
        let status = manifest_status(
            &self.config,
            final_report.status,
            vectors_deferred,
            vectors_blocked,
        );
        let readiness_label =
            readiness_label(status, final_report.status, &self.config).to_string();
        let vector_records = vectors
            .values()
            .map(FinalReleaseTestVector::public_record)
            .collect::<Vec<_>>();
        let vector_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTORS",
            &vector_records,
        );
        let source_root = source_root(
            &final_release_gate.state_root(),
            &final_report.state_root(),
            &final_report.roots.source_root,
            &final_report.roots.decision_root,
            &final_report.roots.blocker_root,
            &final_report.transcript_root,
        );
        let deferred_gate_root = deferred_gate_root(&self.config, final_report.status);
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &vector_root,
            &deferred_gate_root,
            &final_report.release_claim_id,
        );
        let report_id =
            test_vector_manifest_report_id(&final_report.release_claim_id, &report_root);
        let report = FinalReleaseTestVectorManifestReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            final_release_gate_state_root: final_release_gate.state_root(),
            final_release_gate_report_root: final_report.state_root(),
            final_release_gate_report_id: final_report.report_id.clone(),
            baseline_final_status: final_report.status,
            baseline_user_answer: final_report.user_answer.clone(),
            scenario_id: final_report.scenario_id.clone(),
            transfer_id: final_report.transfer_id.clone(),
            release_claim_id: final_report.release_claim_id.clone(),
            transcript_root: final_report.transcript_root.clone(),
            vectors_declared,
            vectors_deferred,
            vectors_blocked,
            expected_release_allowed_vectors,
            expected_watch_vectors,
            expected_failed_vectors,
            baseline_decisions_referenced,
            vectors,
            roots: ManifestReportRoots {
                vector_root,
                source_root,
                deferred_gate_root,
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
            "manifest_suite": self.config.manifest_suite,
            "latest_report": self.latest_report.as_ref().map(FinalReleaseTestVectorManifestReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: FinalReleaseTestVectorManifestReport) {
        self.counters.reports_run += 1;
        self.counters.vectors_declared += report.vectors_declared;
        self.counters.vectors_deferred += report.vectors_deferred;
        self.counters.vectors_blocked += report.vectors_blocked;
        self.counters.expected_release_allowed_vectors += report.expected_release_allowed_vectors;
        self.counters.expected_watch_vectors += report.expected_watch_vectors;
        self.counters.expected_failed_vectors += report.expected_failed_vectors;
        self.counters.baseline_decisions_referenced += report.baseline_decisions_referenced;
        match report.status {
            TestVectorManifestStatus::Passed => self.counters.reports_passed += 1,
            TestVectorManifestStatus::Watch => self.counters.reports_watch += 1,
            TestVectorManifestStatus::Failed => self.counters.reports_failed += 1,
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
            .map(FinalReleaseTestVectorManifestReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_test_vectors(
    config: &Config,
    report: &crate::monero_l2_pq_bridge_exit_final_release_gate_runtime::FinalReleaseGateReport,
) -> Result<BTreeMap<String, FinalReleaseTestVector>> {
    let deferred = config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.live_adapters_deferred
        || config.security_audit_deferred
        || report.status == FinalReleaseGateStatus::Watch;
    let mut vectors = BTreeMap::new();
    let mut insert = |vector: FinalReleaseTestVector| {
        vectors.insert(vector.vector_id.clone(), vector);
    };

    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::DevnetWatchPreservesEscape,
        TestVectorEntryStatus::Deferred,
        vec![
            TestVectorTargetGate::FinalReleaseGate,
            TestVectorTargetGate::CargoRuntimeGate,
            TestVectorTargetGate::ProductionReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::UserForcedExitAnswer,
            FinalGateDecisionKind::DeferredCargoRuntimeGate,
            FinalGateDecisionKind::ProductionReleaseGate,
        ],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Watch,
        "devnet baseline must preserve user escape evidence while final checks are still deferred",
        "use the current devnet final gate report without mutating upstream evidence",
        "watch-only final gate, deferred cargo/runtime/security, and production flag false",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::AllEvidencePromotedAllowsRelease,
        if deferred {
            TestVectorEntryStatus::Deferred
        } else {
            TestVectorEntryStatus::Declared
        },
        vec![
            TestVectorTargetGate::SafetyCase,
            TestVectorTargetGate::AuthorityTransfer,
            TestVectorTargetGate::LiquidityReserve,
            TestVectorTargetGate::ReorgWatcherSimulation,
            TestVectorTargetGate::WatcherBondSlashing,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::SafetyCaseAccepted,
            FinalGateDecisionKind::AuthorityReleaseAccepted,
            FinalGateDecisionKind::LiquidityReserveAccepted,
            FinalGateDecisionKind::ReorgWatcherSimulationAccepted,
            FinalGateDecisionKind::WatcherBondSlashingAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Passed,
        FinalGateDecisionStatus::ReleaseAllowed,
        FinalGateDecisionStatus::ReleaseAllowed,
        "when every upstream surface is executable, audited, and passed, the final gate may allow release",
        "promote every watch-only upstream status and deferred config flag to passed in the fixture",
        "no blocker surface should remain; release allowed must be root-bound to the same claim",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::SafetyCaseFailureBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::SafetyCase,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::SafetyCaseAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "a broken end-to-end safety case means the user cannot trust the bridge/exit proof",
        "mutate safety verdict to failed or remove a required journey segment root",
        "safety_case_accepted and user_forced_exit_answer must block release",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::AuthorityFailureBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::AuthorityTransfer,
            TestVectorTargetGate::FinalReleaseGate,
            TestVectorTargetGate::PqControlPlane,
        ],
        vec![
            FinalGateDecisionKind::AuthorityReleaseAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "unilateral or missing bridge release authority must halt forced-exit release",
        "mutate authority transfer status to failed or drop PQ authority continuity",
        "authority_release_accepted must block user release and production promotion",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::LiquidityReserveFailureBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::LiquidityReserve,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::LiquidityReserveAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "forced exits are not credible if the reserve-release path cannot cover the claim",
        "mutate reserve coverage below the minimum or remove emergency backstop escrow",
        "liquidity_reserve_accepted must block release when coverage is exhausted",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::ReorgEscapeBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::ReorgWatcherSimulation,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::ReorgWatcherSimulationAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "Monero reorg scenarios must not permit release from stale or conflicting evidence",
        "mutate reorg simulation cases_escaped above zero or replace the transcript root",
        "reorg_watcher_simulation_accepted must block the forced-exit answer",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::WatcherSlashingFailureBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::WatcherBondSlashing,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::WatcherBondSlashingAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "watcher equivocation or withheld liveness evidence must have enforceable slashing",
        "mutate watcher slashing status to failed or remove bond coverage",
        "watcher_bond_slashing_accepted must block release if slashing evidence fails",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::DeferredCargoRuntimeKeepsWatch,
        TestVectorEntryStatus::Deferred,
        vec![
            TestVectorTargetGate::CargoRuntimeGate,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::DeferredCargoRuntimeGate,
            FinalGateDecisionKind::ProductionReleaseGate,
        ],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Watch,
        "the final gate cannot become release-ready while cargo and runtime execution are deferred",
        "set cargo_checks_deferred or runtime_tests_deferred to true while upstream evidence passes",
        "deferred_cargo_runtime_gate must keep the report in watch",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::DeferredSecurityAuditKeepsWatch,
        TestVectorEntryStatus::Deferred,
        vec![
            TestVectorTargetGate::SecurityAuditGate,
            TestVectorTargetGate::PrivacyMetadataModel,
            TestVectorTargetGate::PqControlPlane,
        ],
        vec![
            FinalGateDecisionKind::DeferredSecurityAuditGate,
            FinalGateDecisionKind::ProductionReleaseGate,
        ],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Watch,
        "PQ control-plane and metadata-leakage review must hold production at watch until audited",
        "leave security_audit_deferred true after otherwise passing release evidence",
        "deferred_security_audit_gate must keep production blocked",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::ProductionReleaseFlagKeepsWatch,
        TestVectorEntryStatus::Deferred,
        vec![
            TestVectorTargetGate::ProductionReleaseGate,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![FinalGateDecisionKind::ProductionReleaseGate],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Watch,
        "a prototype must not self-promote to production without an explicit release flag",
        "set production_release_allowed false while all evidence is otherwise passed",
        "production_release_gate must remain watch and block production readiness",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::MetadataLeakageBlocksProduction,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::PrivacyMetadataModel,
            TestVectorTargetGate::PublicReceiptModel,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::SafetyCaseAccepted,
            FinalGateDecisionKind::DeferredSecurityAuditGate,
            FinalGateDecisionKind::ProductionReleaseGate,
        ],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Blocked,
        "privacy metadata leakage cannot silently pass just because value release is covered",
        "mutate redaction budget or public receipt model to expose linkable deposit/exit metadata",
        "production blocker must remain even if user escape evidence is preserved",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::ReserveExhaustionBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::LiquidityReserve,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::LiquidityReserveAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "liquidity exhaustion must not be papered over by watcher or authority approvals",
        "set effective coverage to zero and remove reserve-release backstop paths",
        "user release must fail closed on reserve exhaustion",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::WatcherCollusionQuarantineBlocksProduction,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::ReorgWatcherSimulation,
            TestVectorTargetGate::WatcherBondSlashing,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::ReorgWatcherSimulationAccepted,
            FinalGateDecisionKind::WatcherBondSlashingAccepted,
            FinalGateDecisionKind::ProductionReleaseGate,
        ],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Blocked,
        "watcher collusion should quarantine production even when no single user claim is lost",
        "mutate collusion score above threshold while slash decisions are watch-only",
        "production_release_gate must stay blocked until live slashing settlement exists",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::ReceiptRootMismatchBlocksRelease,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::PublicReceiptModel,
            TestVectorTargetGate::SafetyCase,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::SafetyCaseAccepted,
            FinalGateDecisionKind::UserForcedExitAnswer,
        ],
        FinalReleaseGateStatus::Failed,
        FinalGateDecisionStatus::Blocked,
        FinalGateDecisionStatus::Blocked,
        "withdrawal release must be bound to the exact private-transfer receipt and forced-exit claim",
        "replace final release transcript root with a mismatched receipt or claim root",
        "user_forced_exit_answer must block release on receipt-root mismatch",
    ));
    insert(FinalReleaseTestVector::new(
        report,
        FinalReleaseTestVectorKind::PqSignerQuorumRegressionBlocksProduction,
        TestVectorEntryStatus::Declared,
        vec![
            TestVectorTargetGate::PqControlPlane,
            TestVectorTargetGate::AuthorityTransfer,
            TestVectorTargetGate::WatcherBondSlashing,
            TestVectorTargetGate::FinalReleaseGate,
        ],
        vec![
            FinalGateDecisionKind::AuthorityReleaseAccepted,
            FinalGateDecisionKind::WatcherBondSlashingAccepted,
            FinalGateDecisionKind::DeferredSecurityAuditGate,
        ],
        FinalReleaseGateStatus::Watch,
        FinalGateDecisionStatus::Watch,
        FinalGateDecisionStatus::Blocked,
        "PQ signer quorum regression should prevent production even if non-PQ evidence still matches",
        "downgrade signer quorum security bits or remove PQ signer root continuity",
        "security and production gates must reject PQ control-plane regression",
    ));

    Ok(vectors)
}

fn matching_decision_ids(
    report: &crate::monero_l2_pq_bridge_exit_final_release_gate_runtime::FinalReleaseGateReport,
    kinds: &[FinalGateDecisionKind],
) -> Vec<String> {
    report
        .decisions
        .values()
        .filter(|decision| kinds.iter().any(|kind| *kind == decision.kind))
        .map(|decision| decision.decision_id.clone())
        .collect()
}

fn manifest_status(
    config: &Config,
    baseline_status: FinalReleaseGateStatus,
    vectors_deferred: u64,
    vectors_blocked: u64,
) -> TestVectorManifestStatus {
    if vectors_blocked > 0 {
        TestVectorManifestStatus::Failed
    } else if vectors_deferred > 0
        || baseline_status != FinalReleaseGateStatus::Passed
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.live_adapters_deferred
        || config.security_audit_deferred
    {
        TestVectorManifestStatus::Watch
    } else {
        TestVectorManifestStatus::Passed
    }
}

fn readiness_label(
    status: TestVectorManifestStatus,
    baseline_status: FinalReleaseGateStatus,
    config: &Config,
) -> &'static str {
    match status {
        TestVectorManifestStatus::Failed => "final_release_test_vector_manifest_failed",
        TestVectorManifestStatus::Watch
            if config.cargo_checks_deferred || config.runtime_tests_deferred =>
        {
            "final_release_test_vector_manifest_watch_cargo_runtime_deferred"
        }
        TestVectorManifestStatus::Watch if config.live_adapters_deferred => {
            "final_release_test_vector_manifest_watch_live_adapters_deferred"
        }
        TestVectorManifestStatus::Watch if config.security_audit_deferred => {
            "final_release_test_vector_manifest_watch_security_audit_deferred"
        }
        TestVectorManifestStatus::Watch if baseline_status != FinalReleaseGateStatus::Passed => {
            "final_release_test_vector_manifest_watch_baseline_gate"
        }
        TestVectorManifestStatus::Watch => "final_release_test_vector_manifest_watch",
        TestVectorManifestStatus::Passed => "final_release_test_vector_manifest_ready",
    }
}

fn test_name(kind: FinalReleaseTestVectorKind) -> String {
    format!("final_release_{}", kind.as_str())
}

fn cargo_test_path(kind: FinalReleaseTestVectorKind) -> String {
    format!(
        "utils/nebula_l2_rs/tests/bridge_exit_final_release/{}.rs",
        kind.as_str()
    )
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

pub fn test_vector_id(
    kind: FinalReleaseTestVectorKind,
    release_claim_id: &str,
    fixture_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(fixture_root),
        ],
        32,
    )
}

pub fn test_vector_fixture_root(
    kind: FinalReleaseTestVectorKind,
    release_claim_id: &str,
    baseline_report_root: &str,
    fixture: &Value,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-FIXTURE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(baseline_report_root),
            HashPart::Json(fixture),
        ],
        32,
    )
}

pub fn test_vector_manifest_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    final_release_gate_state_root: &str,
    final_release_gate_report_root: &str,
    final_release_source_root: &str,
    final_release_decision_root: &str,
    final_release_blocker_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-SOURCE-ROOT",
        &[
            HashPart::Str(final_release_gate_state_root),
            HashPart::Str(final_release_gate_report_root),
            HashPart::Str(final_release_source_root),
            HashPart::Str(final_release_decision_root),
            HashPart::Str(final_release_blocker_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn deferred_gate_root(config: &Config, baseline_status: FinalReleaseGateStatus) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-DEFERRED-GATE-ROOT",
        &[
            HashPart::Str(baseline_status.as_str()),
            HashPart::Str(bool_str(config.cargo_checks_deferred)),
            HashPart::Str(bool_str(config.runtime_tests_deferred)),
            HashPart::Str(bool_str(config.live_adapters_deferred)),
            HashPart::Str(bool_str(config.security_audit_deferred)),
        ],
        32,
    )
}

pub fn report_root(
    status: TestVectorManifestStatus,
    readiness_label: &str,
    source_root: &str,
    vector_root: &str,
    deferred_gate_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(vector_root),
            HashPart::Str(deferred_gate_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-TEST-VECTOR-RECORD",
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
