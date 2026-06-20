use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_mutated_transcript_probe_runtime::{
        ExpectedRejection, MutatedProbeCase, MutationKind, ProbeStatus,
        State as MutatedTranscriptProbeState,
    },
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReportStatus, State as AuthorityTransferAdapterState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundTransferForcedExitNegativeFixtureTestManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_NEGATIVE_FIXTURE_TEST_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-bound-transfer-forced-exit-negative-fixture-test-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_NEGATIVE_FIXTURE_TEST_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-bound-transfer-forced-exit-negative-fixture-test-manifest-v1";
pub const DEFAULT_MIN_MANIFEST_ENTRIES: u64 = 14;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestTargetStage {
    StaticVerifier,
    FailclosedCrosscheck,
    SecurityBundle,
    AuthorityTransferAdapter,
    ReadinessGate,
    CounterContinuity,
}

impl TestTargetStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticVerifier => "static_verifier",
            Self::FailclosedCrosscheck => "failclosed_crosscheck",
            Self::SecurityBundle => "security_bundle",
            Self::AuthorityTransferAdapter => "authority_transfer_adapter",
            Self::ReadinessGate => "readiness_gate",
            Self::CounterContinuity => "counter_continuity",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestEntryStatus {
    Declared,
    Deferred,
    Blocked,
}

impl ManifestEntryStatus {
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
pub enum ManifestReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ManifestReportStatus {
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
    pub min_manifest_entries: u64,
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
            manifest_suite: MANIFEST_SUITE.to_string(),
            min_manifest_entries: DEFAULT_MIN_MANIFEST_ENTRIES,
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
            "manifest_suite": self.manifest_suite,
            "min_manifest_entries": self.min_manifest_entries,
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
pub struct NegativeFixtureTestEntry {
    pub entry_id: String,
    pub test_name: String,
    pub mutation_kind: MutationKind,
    pub expected_rejection: ExpectedRejection,
    pub target_stages: Vec<TestTargetStage>,
    pub status: ManifestEntryStatus,
    pub scenario_id: String,
    pub transcript_root: String,
    pub mutation_root: String,
    pub fixture_root: String,
    pub expected_error_surface: String,
    pub adapter_release_effect: String,
    pub cargo_test_path: String,
    pub cargo_test_filter: String,
    pub public_fixture: Value,
}

impl NegativeFixtureTestEntry {
    pub fn new(
        case: &MutatedProbeCase,
        target_stages: Vec<TestTargetStage>,
        status: ManifestEntryStatus,
        expected_error_surface: impl Into<String>,
        adapter_release_effect: impl Into<String>,
    ) -> Self {
        let test_name = test_name(case.kind, case.expected_rejection);
        let cargo_test_path = cargo_test_path(case.kind);
        let cargo_test_filter = format!("bridge_exit_negative_fixture::{test_name}");
        let fixture_root = fixture_root(
            &case.scenario_id,
            case.kind,
            &case.mutation_root,
            &case.public_fixture,
        );
        let entry_id = entry_id(&case.scenario_id, &test_name, &fixture_root);
        Self {
            entry_id,
            test_name,
            mutation_kind: case.kind,
            expected_rejection: case.expected_rejection,
            target_stages,
            status,
            scenario_id: case.scenario_id.clone(),
            transcript_root: case.transcript_root.clone(),
            mutation_root: case.mutation_root.clone(),
            fixture_root,
            expected_error_surface: expected_error_surface.into(),
            adapter_release_effect: adapter_release_effect.into(),
            cargo_test_path,
            cargo_test_filter,
            public_fixture: case.public_record(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "test_name": self.test_name,
            "mutation_kind": self.mutation_kind.as_str(),
            "expected_rejection": self.expected_rejection.as_str(),
            "target_stages": self.target_stages.iter().map(|stage| stage.as_str()).collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "scenario_id": self.scenario_id,
            "transcript_root": self.transcript_root,
            "mutation_root": self.mutation_root,
            "fixture_root": self.fixture_root,
            "expected_error_surface": self.expected_error_surface,
            "adapter_release_effect": self.adapter_release_effect,
            "cargo_test_path": self.cargo_test_path,
            "cargo_test_filter": self.cargo_test_filter,
            "public_fixture": self.public_fixture,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("negative_fixture_test_entry", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NegativeFixtureTestManifestReport {
    pub report_id: String,
    pub status: ManifestReportStatus,
    pub readiness_label: String,
    pub mutated_probe_state_root: String,
    pub mutated_probe_report_root: String,
    pub authority_adapter_state_root: String,
    pub authority_adapter_report_root: String,
    pub scenario_id: String,
    pub transcript_root: String,
    pub entries_declared: u64,
    pub entries_deferred: u64,
    pub entries_blocked: u64,
    pub entries: BTreeMap<String, NegativeFixtureTestEntry>,
    pub roots: ManifestReportRoots,
}

impl NegativeFixtureTestManifestReport {
    pub fn public_record(&self) -> Value {
        let entries = self
            .entries
            .values()
            .map(NegativeFixtureTestEntry::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "mutated_probe_state_root": self.mutated_probe_state_root,
            "mutated_probe_report_root": self.mutated_probe_report_root,
            "authority_adapter_state_root": self.authority_adapter_state_root,
            "authority_adapter_report_root": self.authority_adapter_report_root,
            "scenario_id": self.scenario_id,
            "transcript_root": self.transcript_root,
            "entries_declared": self.entries_declared,
            "entries_deferred": self.entries_deferred,
            "entries_blocked": self.entries_blocked,
            "entries": entries,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestReportRoots {
    pub entry_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl ManifestReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "entry_root": self.entry_root,
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
    pub entries_declared: u64,
    pub entries_deferred: u64,
    pub entries_blocked: u64,
    pub static_stage_entries: u64,
    pub security_bundle_entries: u64,
    pub authority_adapter_entries: u64,
    pub readiness_gate_entries: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "entries_declared": self.entries_declared,
            "entries_deferred": self.entries_deferred,
            "entries_blocked": self.entries_blocked,
            "static_stage_entries": self.static_stage_entries,
            "security_bundle_entries": self.security_bundle_entries,
            "authority_adapter_entries": self.authority_adapter_entries,
            "readiness_gate_entries": self.readiness_gate_entries,
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
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-EMPTY-MANIFESTS",
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
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-STATE",
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
    pub latest_report: Option<NegativeFixtureTestManifestReport>,
    pub report_history: Vec<NegativeFixtureTestManifestReport>,
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
        let mutated_probe =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_mutated_transcript_probe_runtime::devnet();
        let authority_adapter =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        state
            .build_test_manifest(&mutated_probe, &authority_adapter)
            .expect("devnet negative fixture test manifest");
        state
    }

    pub fn build_test_manifest(
        &mut self,
        mutated_probe: &MutatedTranscriptProbeState,
        authority_adapter: &AuthorityTransferAdapterState,
    ) -> Result<String> {
        let probe_report = mutated_probe
            .latest_report
            .as_ref()
            .ok_or_else(|| "mutated transcript probe state has no latest report".to_string())?;
        let authority_report = authority_adapter
            .latest_report
            .as_ref()
            .ok_or_else(|| "authority transfer adapter has no latest report".to_string())?;
        let entries = build_manifest_entries(&self.config, probe_report, authority_report)?;
        let entries_declared = entries
            .values()
            .filter(|entry| entry.status == ManifestEntryStatus::Declared)
            .count() as u64;
        let entries_deferred = entries
            .values()
            .filter(|entry| entry.status == ManifestEntryStatus::Deferred)
            .count() as u64;
        let entries_blocked = entries
            .values()
            .filter(|entry| entry.status == ManifestEntryStatus::Blocked)
            .count() as u64;
        let status = aggregate_manifest_status(&self.config, entries.len() as u64, entries_blocked);
        let readiness_label = readiness_label(status, &self.config).to_string();
        let entry_records = entries
            .values()
            .map(NegativeFixtureTestEntry::public_record)
            .collect::<Vec<_>>();
        let entry_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-ENTRIES",
            &entry_records,
        );
        let source_root = source_root(
            &mutated_probe.state_root(),
            &probe_report.state_root(),
            &authority_adapter.state_root(),
            &authority_report.state_root(),
            &probe_report.transcript_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &entry_root,
            &probe_report.scenario_id,
            &probe_report.transcript_root,
        );
        let report_id = manifest_report_id(&probe_report.scenario_id, &report_root);
        let report = NegativeFixtureTestManifestReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            mutated_probe_state_root: mutated_probe.state_root(),
            mutated_probe_report_root: probe_report.state_root(),
            authority_adapter_state_root: authority_adapter.state_root(),
            authority_adapter_report_root: authority_report.state_root(),
            scenario_id: probe_report.scenario_id.clone(),
            transcript_root: probe_report.transcript_root.clone(),
            entries_declared,
            entries_deferred,
            entries_blocked,
            entries,
            roots: ManifestReportRoots {
                entry_root,
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
            "manifest_suite": self.config.manifest_suite,
            "latest_report": self.latest_report.as_ref().map(NegativeFixtureTestManifestReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: NegativeFixtureTestManifestReport) {
        self.counters.reports_run += 1;
        self.counters.entries_declared += report.entries_declared;
        self.counters.entries_deferred += report.entries_deferred;
        self.counters.entries_blocked += report.entries_blocked;
        self.counters.static_stage_entries += count_stage(&report, TestTargetStage::StaticVerifier);
        self.counters.security_bundle_entries +=
            count_stage(&report, TestTargetStage::SecurityBundle);
        self.counters.authority_adapter_entries +=
            count_stage(&report, TestTargetStage::AuthorityTransferAdapter);
        self.counters.readiness_gate_entries +=
            count_stage(&report, TestTargetStage::ReadinessGate);
        match report.status {
            ManifestReportStatus::Passed => self.counters.reports_passed += 1,
            ManifestReportStatus::Watch => self.counters.reports_watch += 1,
            ManifestReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(NegativeFixtureTestManifestReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn build_manifest_entries(
    config: &Config,
    probe_report: &crate::monero_l2_pq_bridge_bound_transfer_forced_exit_mutated_transcript_probe_runtime::MutatedProbeReport,
    authority_report: &crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport,
) -> Result<BTreeMap<String, NegativeFixtureTestEntry>> {
    let authority_release_watch = authority_report.status == AuthorityTransferReportStatus::Watch
        && authority_report.readiness_label.contains("deferred");
    let mut entries = BTreeMap::new();
    for case in probe_report.cases.values() {
        let stages = target_stages(case.kind);
        let status = entry_status(config, case, authority_release_watch);
        let expected_error = expected_error_surface(case.kind, case.expected_rejection);
        let release_effect = adapter_release_effect(case.kind, status);
        let entry =
            NegativeFixtureTestEntry::new(case, stages, status, expected_error, release_effect);
        entries.insert(entry.entry_id.clone(), entry);
    }
    ensure(
        entries.len() as u64 >= config.min_manifest_entries,
        "negative fixture manifest does not cover enough mutated transcript cases",
    )?;
    ensure(
        MutationKind::all()
            .iter()
            .all(|kind| entries.values().any(|entry| entry.mutation_kind == *kind)),
        "negative fixture manifest omitted a required mutation kind",
    )?;
    Ok(entries)
}

fn target_stages(kind: MutationKind) -> Vec<TestTargetStage> {
    match kind {
        MutationKind::PreSealStepRootForged | MutationKind::ClaimRootForged => {
            vec![
                TestTargetStage::StaticVerifier,
                TestTargetStage::SecurityBundle,
            ]
        }
        MutationKind::ExitClaimRootForged
        | MutationKind::MissingForcedExitClaim
        | MutationKind::SettlementBeforeChallengeResolution
        | MutationKind::MissingTranscriptSeal
        | MutationKind::FinalSpineRootMismatch
        | MutationKind::FinalTransferRuntimeRootMismatch => {
            vec![
                TestTargetStage::StaticVerifier,
                TestTargetStage::FailclosedCrosscheck,
                TestTargetStage::SecurityBundle,
                TestTargetStage::AuthorityTransferAdapter,
            ]
        }
        MutationKind::AuthorityRootMismatch
        | MutationKind::PrivacySurfaceLeakage
        | MutationKind::PqControlPlaneGap
        | MutationKind::AdversarialCoverageGap => {
            vec![
                TestTargetStage::SecurityBundle,
                TestTargetStage::AuthorityTransferAdapter,
            ]
        }
        MutationKind::DeferredReadinessPromotion => {
            vec![
                TestTargetStage::ReadinessGate,
                TestTargetStage::AuthorityTransferAdapter,
            ]
        }
        MutationKind::CounterDrift => {
            vec![
                TestTargetStage::CounterContinuity,
                TestTargetStage::AuthorityTransferAdapter,
            ]
        }
    }
}

fn entry_status(
    config: &Config,
    case: &MutatedProbeCase,
    authority_release_watch: bool,
) -> ManifestEntryStatus {
    if case.status == ProbeStatus::Escaped {
        ManifestEntryStatus::Blocked
    } else if config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || authority_release_watch
        || case.status == ProbeStatus::Watch
    {
        ManifestEntryStatus::Deferred
    } else {
        ManifestEntryStatus::Declared
    }
}

fn expected_error_surface(kind: MutationKind, rejection: ExpectedRejection) -> String {
    format!("{}::{}::must_reject", kind.as_str(), rejection.as_str())
}

fn adapter_release_effect(kind: MutationKind, status: ManifestEntryStatus) -> String {
    let action = match kind {
        MutationKind::DeferredReadinessPromotion => "keep_release_gate_in_watch",
        MutationKind::PrivacySurfaceLeakage => "block_release_for_privacy_surface_leak",
        MutationKind::PqControlPlaneGap => "block_release_for_pq_control_plane_gap",
        MutationKind::AuthorityRootMismatch => "block_release_for_authority_root_mismatch",
        MutationKind::AdversarialCoverageGap => "block_release_for_adversarial_gap",
        MutationKind::CounterDrift => "block_release_for_counter_drift",
        _ => "block_release_for_invalid_transfer_exit_evidence",
    };
    format!("{action}:{}", status.as_str())
}

fn test_name(kind: MutationKind, rejection: ExpectedRejection) -> String {
    format!("reject_{}_{}", kind.as_str(), rejection.as_str())
}

fn cargo_test_path(kind: MutationKind) -> String {
    let file = match kind {
        MutationKind::PreSealStepRootForged
        | MutationKind::ClaimRootForged
        | MutationKind::ExitClaimRootForged
        | MutationKind::FinalSpineRootMismatch
        | MutationKind::FinalTransferRuntimeRootMismatch => "bridge_transfer_exit_roots.rs",
        MutationKind::MissingForcedExitClaim
        | MutationKind::SettlementBeforeChallengeResolution
        | MutationKind::MissingTranscriptSeal => "bridge_transfer_exit_liveness.rs",
        MutationKind::AuthorityRootMismatch
        | MutationKind::PqControlPlaneGap
        | MutationKind::AdversarialCoverageGap => "bridge_transfer_exit_authority.rs",
        MutationKind::PrivacySurfaceLeakage => "bridge_transfer_exit_privacy.rs",
        MutationKind::DeferredReadinessPromotion | MutationKind::CounterDrift => {
            "bridge_transfer_exit_readiness.rs"
        }
    };
    format!("utils/nebula_l2_rs/tests/{file}")
}

fn count_stage(report: &NegativeFixtureTestManifestReport, stage: TestTargetStage) -> u64 {
    report
        .entries
        .values()
        .filter(|entry| entry.target_stages.contains(&stage))
        .count() as u64
}

fn aggregate_manifest_status(
    config: &Config,
    entry_count: u64,
    blocked_entries: u64,
) -> ManifestReportStatus {
    if blocked_entries > 0 {
        ManifestReportStatus::Failed
    } else if entry_count < config.min_manifest_entries
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
    {
        ManifestReportStatus::Watch
    } else {
        ManifestReportStatus::Passed
    }
}

fn readiness_label(status: ManifestReportStatus, config: &Config) -> &'static str {
    match status {
        ManifestReportStatus::Failed => "negative_fixture_manifest_blocked_by_probe_escape",
        ManifestReportStatus::Watch
            if config.cargo_checks_deferred || config.runtime_tests_deferred =>
        {
            "negative_fixture_manifest_declared_runtime_execution_deferred"
        }
        ManifestReportStatus::Watch => "negative_fixture_manifest_watch_review_needed",
        ManifestReportStatus::Passed => "negative_fixture_manifest_ready_for_execution",
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

pub fn manifest_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn entry_id(scenario_id: &str, test_name: &str, fixture_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-ENTRY-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(test_name),
            HashPart::Str(fixture_root),
        ],
        32,
    )
}

pub fn fixture_root(
    scenario_id: &str,
    kind: MutationKind,
    mutation_root: &str,
    fixture: &Value,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-FIXTURE-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(mutation_root),
            HashPart::Json(fixture),
        ],
        32,
    )
}

pub fn source_root(
    mutated_probe_state_root: &str,
    mutated_probe_report_root: &str,
    authority_adapter_state_root: &str,
    authority_adapter_report_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-SOURCE-ROOT",
        &[
            HashPart::Str(mutated_probe_state_root),
            HashPart::Str(mutated_probe_report_root),
            HashPart::Str(authority_adapter_state_root),
            HashPart::Str(authority_adapter_report_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn report_root(
    status: ManifestReportStatus,
    readiness_label: &str,
    source_root: &str,
    entry_root: &str,
    scenario_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(entry_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-NEGATIVE-FIXTURE-MANIFEST-RECORD",
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
