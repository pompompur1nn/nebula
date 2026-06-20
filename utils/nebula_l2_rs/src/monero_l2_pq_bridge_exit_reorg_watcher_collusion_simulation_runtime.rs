use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ScenarioTranscript, State as ForcedExitScenarioState,
    },
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReportStatus, State as AuthorityTransferState,
    },
    monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::{
        SafetyCaseReport, SafetyCaseVerdict, State as SafetyCaseState,
    },
    monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::{
        LiquidityReleaseReport, LiquidityReleaseReportStatus, State as LiquidityReleaseState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReorgWatcherCollusionSimulationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_REORG_WATCHER_COLLUSION_SIMULATION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-reorg-watcher-collusion-simulation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_REORG_WATCHER_COLLUSION_SIMULATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SIMULATION_SUITE: &str = "monero-l2-pq-bridge-exit-reorg-watcher-collusion-simulation-v1";
pub const DEFAULT_MIN_SIMULATION_CASES: u64 = 10;
pub const DEFAULT_COLLUSION_THRESHOLD_BPS: u64 = 6_667;
pub const DEFAULT_MINOR_REORG_DEPTH_BLOCKS: u64 = 6;
pub const DEFAULT_MAJOR_REORG_MULTIPLIER: u64 = 3;
pub const DEFAULT_MAX_METADATA_LINKAGE_BPS: u64 = 25;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_REPORTS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationKind {
    ShallowReorgBelowFinality,
    DeepReorgAfterCertification,
    MinorityWatcherEquivocation,
    ThresholdWatcherCollusion,
    WithheldLivenessEvidence,
    DelayedChallengeResolution,
    LiquidityReserveStress,
    ReserveReleaseWithheld,
    MetadataLinkageLeak,
    PqSignerCompromise,
    CombinedReorgCollusionLiquidityStress,
}

impl SimulationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShallowReorgBelowFinality => "shallow_reorg_below_finality",
            Self::DeepReorgAfterCertification => "deep_reorg_after_certification",
            Self::MinorityWatcherEquivocation => "minority_watcher_equivocation",
            Self::ThresholdWatcherCollusion => "threshold_watcher_collusion",
            Self::WithheldLivenessEvidence => "withheld_liveness_evidence",
            Self::DelayedChallengeResolution => "delayed_challenge_resolution",
            Self::LiquidityReserveStress => "liquidity_reserve_stress",
            Self::ReserveReleaseWithheld => "reserve_release_withheld",
            Self::MetadataLinkageLeak => "metadata_linkage_leak",
            Self::PqSignerCompromise => "pq_signer_compromise",
            Self::CombinedReorgCollusionLiquidityStress => {
                "combined_reorg_collusion_liquidity_stress"
            }
        }
    }

    pub fn all() -> [Self; 11] {
        [
            Self::ShallowReorgBelowFinality,
            Self::DeepReorgAfterCertification,
            Self::MinorityWatcherEquivocation,
            Self::ThresholdWatcherCollusion,
            Self::WithheldLivenessEvidence,
            Self::DelayedChallengeResolution,
            Self::LiquidityReserveStress,
            Self::ReserveReleaseWithheld,
            Self::MetadataLinkageLeak,
            Self::PqSignerCompromise,
            Self::CombinedReorgCollusionLiquidityStress,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationOutcome {
    Contained,
    Watch,
    Escaped,
}

impl SimulationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contained => "contained",
            Self::Watch => "watch",
            Self::Escaped => "escaped",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationReportStatus {
    Passed,
    Watch,
    Failed,
}

impl SimulationReportStatus {
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
    pub simulation_suite: String,
    pub min_simulation_cases: u64,
    pub collusion_threshold_bps: u64,
    pub minor_reorg_depth_blocks: u64,
    pub major_reorg_multiplier: u64,
    pub max_metadata_linkage_bps: u64,
    pub min_pq_security_bits: u16,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub monero_reorg_adapter_deferred: bool,
    pub watcher_slashing_deferred: bool,
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
            simulation_suite: SIMULATION_SUITE.to_string(),
            min_simulation_cases: DEFAULT_MIN_SIMULATION_CASES,
            collusion_threshold_bps: DEFAULT_COLLUSION_THRESHOLD_BPS,
            minor_reorg_depth_blocks: DEFAULT_MINOR_REORG_DEPTH_BLOCKS,
            major_reorg_multiplier: DEFAULT_MAJOR_REORG_MULTIPLIER,
            max_metadata_linkage_bps: DEFAULT_MAX_METADATA_LINKAGE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            monero_reorg_adapter_deferred: true,
            watcher_slashing_deferred: true,
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
            "simulation_suite": self.simulation_suite,
            "min_simulation_cases": self.min_simulation_cases,
            "collusion_threshold_bps": self.collusion_threshold_bps,
            "minor_reorg_depth_blocks": self.minor_reorg_depth_blocks,
            "major_reorg_multiplier": self.major_reorg_multiplier,
            "max_metadata_linkage_bps": self.max_metadata_linkage_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "monero_reorg_adapter_deferred": self.monero_reorg_adapter_deferred,
            "watcher_slashing_deferred": self.watcher_slashing_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReorgWatcherSimulationCase {
    pub case_id: String,
    pub kind: SimulationKind,
    pub outcome: SimulationOutcome,
    pub scenario_id: String,
    pub transfer_id: String,
    pub transcript_root: String,
    pub simulated_reorg_depth: u64,
    pub simulated_collusion_bps: u64,
    pub liveness_delay_blocks: u64,
    pub liquidity_coverage_bps: u64,
    pub metadata_linkage_bps: u64,
    pub affected_surface: String,
    pub expected_containment: String,
    pub observed: String,
    pub evidence_root: String,
    pub remediation: String,
    pub blocks_release: bool,
    pub blocks_production: bool,
}

impl ReorgWatcherSimulationCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: SimulationKind,
        outcome: SimulationOutcome,
        transcript: &ScenarioTranscript,
        simulated_reorg_depth: u64,
        simulated_collusion_bps: u64,
        liveness_delay_blocks: u64,
        liquidity_coverage_bps: u64,
        metadata_linkage_bps: u64,
        affected_surface: impl Into<String>,
        expected_containment: impl Into<String>,
        observed: impl Into<String>,
        remediation: impl Into<String>,
        blocks_release: bool,
        blocks_production: bool,
    ) -> Self {
        let affected_surface = affected_surface.into();
        let expected_containment = expected_containment.into();
        let observed = observed.into();
        let remediation = remediation.into();
        let evidence_root = simulation_case_evidence_root(
            kind,
            outcome,
            &transcript.scenario_id,
            &transcript.transfer_id,
            &transcript.transcript_root,
            simulated_reorg_depth,
            simulated_collusion_bps,
            liveness_delay_blocks,
            liquidity_coverage_bps,
            metadata_linkage_bps,
            &affected_surface,
            &observed,
        );
        let case_id = simulation_case_id(kind, &transcript.scenario_id, &evidence_root);
        Self {
            case_id,
            kind,
            outcome,
            scenario_id: transcript.scenario_id.clone(),
            transfer_id: transcript.transfer_id.clone(),
            transcript_root: transcript.transcript_root.clone(),
            simulated_reorg_depth,
            simulated_collusion_bps,
            liveness_delay_blocks,
            liquidity_coverage_bps,
            metadata_linkage_bps,
            affected_surface,
            expected_containment,
            observed,
            evidence_root,
            remediation,
            blocks_release,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "outcome": self.outcome.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "transcript_root": self.transcript_root,
            "simulated_reorg_depth": self.simulated_reorg_depth,
            "simulated_collusion_bps": self.simulated_collusion_bps,
            "liveness_delay_blocks": self.liveness_delay_blocks,
            "liquidity_coverage_bps": self.liquidity_coverage_bps,
            "metadata_linkage_bps": self.metadata_linkage_bps,
            "affected_surface": self.affected_surface,
            "expected_containment": self.expected_containment,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
            "blocks_release": self.blocks_release,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reorg_watcher_simulation_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReorgWatcherSimulationReport {
    pub report_id: String,
    pub status: SimulationReportStatus,
    pub readiness_label: String,
    pub scenario_state_root: String,
    pub safety_case_state_root: String,
    pub safety_case_report_root: String,
    pub liquidity_release_state_root: String,
    pub liquidity_release_report_root: String,
    pub authority_transfer_state_root: String,
    pub authority_transfer_report_root: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub transcript_root: String,
    pub cases_run: u64,
    pub cases_contained: u64,
    pub cases_watch: u64,
    pub cases_escaped: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub max_simulated_reorg_depth: u64,
    pub max_simulated_collusion_bps: u64,
    pub min_liquidity_coverage_bps: u64,
    pub max_metadata_linkage_bps: u64,
    pub cases: BTreeMap<String, ReorgWatcherSimulationCase>,
    pub roots: ReorgWatcherSimulationReportRoots,
}

impl ReorgWatcherSimulationReport {
    pub fn public_record(&self) -> Value {
        let cases = self
            .cases
            .values()
            .map(ReorgWatcherSimulationCase::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "scenario_state_root": self.scenario_state_root,
            "safety_case_state_root": self.safety_case_state_root,
            "safety_case_report_root": self.safety_case_report_root,
            "liquidity_release_state_root": self.liquidity_release_state_root,
            "liquidity_release_report_root": self.liquidity_release_report_root,
            "authority_transfer_state_root": self.authority_transfer_state_root,
            "authority_transfer_report_root": self.authority_transfer_report_root,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "transcript_root": self.transcript_root,
            "cases_run": self.cases_run,
            "cases_contained": self.cases_contained,
            "cases_watch": self.cases_watch,
            "cases_escaped": self.cases_escaped,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "max_simulated_reorg_depth": self.max_simulated_reorg_depth,
            "max_simulated_collusion_bps": self.max_simulated_collusion_bps,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "max_metadata_linkage_bps": self.max_metadata_linkage_bps,
            "cases": cases,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReorgWatcherSimulationReportRoots {
    pub case_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub report_root: String,
}

impl ReorgWatcherSimulationReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "case_root": self.case_root,
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
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
    pub cases_run: u64,
    pub cases_contained: u64,
    pub cases_watch: u64,
    pub cases_escaped: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "cases_run": self.cases_run,
            "cases_contained": self.cases_contained,
            "cases_watch": self.cases_watch,
            "cases_escaped": self.cases_escaped,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-STATE",
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
    pub latest_report: Option<ReorgWatcherSimulationReport>,
    pub report_history: Vec<ReorgWatcherSimulationReport>,
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
        let scenario =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::devnet();
        let safety_case = crate::monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::devnet();
        let liquidity_release =
            crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::devnet();
        let authority_transfer =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        state
            .run_reorg_watcher_collusion_simulation(
                &scenario,
                &safety_case,
                &liquidity_release,
                &authority_transfer,
            )
            .expect("devnet reorg watcher collusion simulation");
        state
    }

    pub fn run_reorg_watcher_collusion_simulation(
        &mut self,
        scenario: &ForcedExitScenarioState,
        safety_case: &SafetyCaseState,
        liquidity_release: &LiquidityReleaseState,
        authority_transfer: &AuthorityTransferState,
    ) -> Result<String> {
        let transcript = latest_transcript(scenario)?;
        let safety_report = latest_safety_report(safety_case)?;
        let liquidity_report = latest_liquidity_report(liquidity_release)?;
        let authority_report = authority_transfer
            .latest_report
            .as_ref()
            .ok_or_else(|| "authority transfer state has no latest report".to_string())?;
        let cases = build_simulation_cases(
            &self.config,
            scenario,
            transcript,
            safety_report,
            liquidity_report,
            authority_report.status,
        )?;
        ensure(
            cases.len() as u64 >= self.config.min_simulation_cases,
            "reorg watcher simulation omitted required threat cases",
        )?;
        ensure(
            SimulationKind::all()
                .iter()
                .all(|kind| cases.values().any(|case| case.kind == *kind)),
            "reorg watcher simulation omitted a required simulation kind",
        )?;

        let cases_run = cases.len() as u64;
        let cases_contained = cases
            .values()
            .filter(|case| case.outcome == SimulationOutcome::Contained)
            .count() as u64;
        let cases_watch = cases
            .values()
            .filter(|case| case.outcome == SimulationOutcome::Watch)
            .count() as u64;
        let cases_escaped = cases
            .values()
            .filter(|case| case.outcome == SimulationOutcome::Escaped)
            .count() as u64;
        let release_blockers = cases.values().filter(|case| case.blocks_release).count() as u64;
        let production_blockers =
            cases.values().filter(|case| case.blocks_production).count() as u64;
        let max_simulated_reorg_depth = cases
            .values()
            .map(|case| case.simulated_reorg_depth)
            .max()
            .unwrap_or(0);
        let max_simulated_collusion_bps = cases
            .values()
            .map(|case| case.simulated_collusion_bps)
            .max()
            .unwrap_or(0);
        let min_liquidity_coverage_bps = cases
            .values()
            .map(|case| case.liquidity_coverage_bps)
            .min()
            .unwrap_or(0);
        let max_metadata_linkage_bps = cases
            .values()
            .map(|case| case.metadata_linkage_bps)
            .max()
            .unwrap_or(0);
        let status = aggregate_report_status(
            &self.config,
            cases_escaped,
            cases_watch,
            release_blockers,
            safety_report,
            liquidity_report,
        );
        let readiness_label =
            readiness_label(status, &self.config, production_blockers).to_string();
        let case_records = cases
            .values()
            .map(ReorgWatcherSimulationCase::public_record)
            .collect::<Vec<_>>();
        let blocker_records = cases
            .values()
            .filter(|case| case.blocks_release || case.blocks_production)
            .map(ReorgWatcherSimulationCase::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-CASES",
            &case_records,
        );
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-BLOCKERS",
            &blocker_records,
        );
        let source_root = source_root(
            &scenario.state_root(),
            &safety_case.state_root(),
            &safety_report.state_root(),
            &liquidity_release.state_root(),
            &liquidity_report.state_root(),
            &authority_transfer.state_root(),
            &authority_report.state_root(),
            &transcript.transcript_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &case_root,
            &blocker_root,
            &transcript.scenario_id,
            &transcript.transfer_id,
            &transcript.transcript_root,
        );
        let report_id = simulation_report_id(&transcript.scenario_id, &report_root);
        let report = ReorgWatcherSimulationReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            scenario_state_root: scenario.state_root(),
            safety_case_state_root: safety_case.state_root(),
            safety_case_report_root: safety_report.state_root(),
            liquidity_release_state_root: liquidity_release.state_root(),
            liquidity_release_report_root: liquidity_report.state_root(),
            authority_transfer_state_root: authority_transfer.state_root(),
            authority_transfer_report_root: authority_report.state_root(),
            scenario_id: transcript.scenario_id.clone(),
            transfer_id: transcript.transfer_id.clone(),
            transcript_root: transcript.transcript_root.clone(),
            cases_run,
            cases_contained,
            cases_watch,
            cases_escaped,
            release_blockers,
            production_blockers,
            max_simulated_reorg_depth,
            max_simulated_collusion_bps,
            min_liquidity_coverage_bps,
            max_metadata_linkage_bps,
            cases,
            roots: ReorgWatcherSimulationReportRoots {
                case_root,
                source_root,
                blocker_root,
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
            "simulation_suite": self.config.simulation_suite,
            "latest_report": self.latest_report.as_ref().map(ReorgWatcherSimulationReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: ReorgWatcherSimulationReport) {
        self.counters.reports_run += 1;
        self.counters.cases_run += report.cases_run;
        self.counters.cases_contained += report.cases_contained;
        self.counters.cases_watch += report.cases_watch;
        self.counters.cases_escaped += report.cases_escaped;
        self.counters.release_blockers += report.release_blockers;
        self.counters.production_blockers += report.production_blockers;
        match report.status {
            SimulationReportStatus::Passed => self.counters.reports_passed += 1,
            SimulationReportStatus::Watch => self.counters.reports_watch += 1,
            SimulationReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(ReorgWatcherSimulationReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn latest_transcript(state: &ForcedExitScenarioState) -> Result<&ScenarioTranscript> {
    state
        .transcripts
        .values()
        .next_back()
        .ok_or_else(|| "forced-exit scenario has no sealed transcript".to_string())
}

fn latest_safety_report(state: &SafetyCaseState) -> Result<&SafetyCaseReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "safety case state has no latest report".to_string())
}

fn latest_liquidity_report(state: &LiquidityReleaseState) -> Result<&LiquidityReleaseReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "liquidity release state has no latest report".to_string())
}

fn build_simulation_cases(
    config: &Config,
    scenario: &ForcedExitScenarioState,
    transcript: &ScenarioTranscript,
    safety_report: &SafetyCaseReport,
    liquidity_report: &LiquidityReleaseReport,
    authority_status: AuthorityTransferReportStatus,
) -> Result<BTreeMap<String, ReorgWatcherSimulationCase>> {
    let finality_depth = scenario.spine.config.monero_finality_depth;
    let shallow_depth = config
        .minor_reorg_depth_blocks
        .min(finality_depth.saturating_sub(1));
    let deep_depth = finality_depth.saturating_mul(config.major_reorg_multiplier);
    let liveness_window = scenario.spine.config.exit_liveness_window_blocks;
    let challenge_window = scenario.spine.config.challenge_window_blocks;
    let liquidity_coverage = liquidity_report.effective_coverage_bps;
    let safety_watch = safety_report.verdict == SafetyCaseVerdict::Watch;
    let liquidity_watch = liquidity_report.status == LiquidityReleaseReportStatus::Watch;
    let authority_watch = authority_status == AuthorityTransferReportStatus::Watch;
    let release_has_blockers = liquidity_report.release_blockers > 0;
    let mut cases = BTreeMap::new();
    let mut insert = |case: ReorgWatcherSimulationCase| {
        cases.insert(case.case_id.clone(), case);
    };

    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::ShallowReorgBelowFinality,
        if scenario.spine.counters.deposits_certified > 0 {
            SimulationOutcome::Contained
        } else {
            SimulationOutcome::Escaped
        },
        transcript,
        shallow_depth,
        0,
        0,
        liquidity_coverage,
        0,
        "deposit lock observation and finality certificate",
        "shallow reorg below configured finality remains contained by the watcher finality certificate",
        format!(
            "deposits_certified={} finality_depth={} simulated_reorg_depth={}",
            scenario.spine.counters.deposits_certified, finality_depth, shallow_depth
        ),
        "add real Monero header fixtures for shallow reorg replay",
        false,
        config.monero_reorg_adapter_deferred,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::DeepReorgAfterCertification,
        if config.monero_reorg_adapter_deferred {
            SimulationOutcome::Watch
        } else {
            SimulationOutcome::Contained
        },
        transcript,
        deep_depth,
        0,
        liveness_window,
        liquidity_coverage,
        0,
        "certified deposit path and forced-exit reserve release",
        "deep reorg after certification must trigger quarantine, reserve holdback, and reorg rescue before release",
        format!(
            "monero_reorg_adapter_deferred={} deep_depth={} release_blockers={}",
            config.monero_reorg_adapter_deferred, deep_depth, liquidity_report.release_blockers
        ),
        "connect a Monero header/reorg adapter and replay fixtures to the bridge safety case",
        false,
        true,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::MinorityWatcherEquivocation,
        SimulationOutcome::Contained,
        transcript,
        0,
        config.collusion_threshold_bps.saturating_sub(1_000),
        0,
        liquidity_coverage,
        0,
        "watcher attestations and bridge custody release gate",
        "minority equivocation stays below release threshold and remains slashable evidence",
        format!(
            "simulated_collusion_bps={} threshold_bps={} watcher_slashing_deferred={}",
            config.collusion_threshold_bps.saturating_sub(1_000),
            config.collusion_threshold_bps,
            config.watcher_slashing_deferred
        ),
        "materialize equivocation evidence fixtures and slashing receipts",
        false,
        config.watcher_slashing_deferred,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::ThresholdWatcherCollusion,
        if config.watcher_slashing_deferred {
            SimulationOutcome::Watch
        } else {
            SimulationOutcome::Contained
        },
        transcript,
        finality_depth,
        config.collusion_threshold_bps,
        liveness_window,
        liquidity_coverage,
        0,
        "watcher quorum threshold and forced-exit liveness evidence",
        "threshold collusion must be visible as a release blocker or slashing path before funds leave reserve",
        format!(
            "simulated_collusion_bps={} authority_status={} release_blockers={}",
            config.collusion_threshold_bps,
            authority_status.as_str(),
            liquidity_report.release_blockers
        ),
        "connect watcher bond/slashing enforcement to the authority and reserve release gates",
        false,
        true,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::WithheldLivenessEvidence,
        if scenario.counters.forced_exits_armed > 0 {
            SimulationOutcome::Contained
        } else {
            SimulationOutcome::Escaped
        },
        transcript,
        0,
        3_333,
        liveness_window.saturating_add(1),
        liquidity_coverage,
        0,
        "forced-exit liveness window and censorship evidence",
        "withheld sequencer/watcher liveness evidence must still arm forced exit after timeout",
        format!(
            "forced_exits_armed={} liveness_window={}",
            scenario.counters.forced_exits_armed, liveness_window
        ),
        "add boundary tests for withheld liveness evidence and delayed watcher publication",
        scenario.counters.forced_exits_armed == 0,
        config.runtime_tests_deferred,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::DelayedChallengeResolution,
        if scenario.counters.challenges_resolved > 0 {
            SimulationOutcome::Contained
        } else {
            SimulationOutcome::Escaped
        },
        transcript,
        0,
        0,
        challenge_window.saturating_add(6),
        liquidity_coverage,
        0,
        "challenge window and settlement holdback",
        "settlement must wait for challenge resolution before reserve release certificate is trusted",
        format!(
            "challenges_resolved={} challenge_window={}",
            scenario.counters.challenges_resolved, challenge_window
        ),
        "turn challenge-window ordering into executable reserve-release tests",
        scenario.counters.challenges_resolved == 0,
        config.runtime_tests_deferred,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::LiquidityReserveStress,
        if liquidity_coverage >= liquidity_report.effective_coverage_bps
            && liquidity_report.decisions_blocked == 0
        {
            if liquidity_watch {
                SimulationOutcome::Watch
            } else {
                SimulationOutcome::Contained
            }
        } else {
            SimulationOutcome::Escaped
        },
        transcript,
        finality_depth,
        2_500,
        liveness_window,
        liquidity_coverage,
        0,
        "forced-exit liquidity reserve and emergency buffer",
        "reserve stress must remain visible and must not silently strand a forced exit",
        format!(
            "liquidity_status={} coverage_bps={} decisions_blocked={}",
            liquidity_report.status.as_str(),
            liquidity_coverage,
            liquidity_report.decisions_blocked
        ),
        "connect reserve-release records to live reserve adapters and depletion tests",
        release_has_blockers,
        true,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::ReserveReleaseWithheld,
        if release_has_blockers {
            SimulationOutcome::Watch
        } else {
            SimulationOutcome::Contained
        },
        transcript,
        0,
        5_000,
        liveness_window,
        liquidity_coverage,
        0,
        "reserve release decision and authority continuity",
        "withheld reserve release must create a visible release blocker and emergency backstop path",
        format!(
            "release_blockers={} production_blockers={} authority_status={}",
            liquidity_report.release_blockers,
            liquidity_report.production_blockers,
            authority_status.as_str()
        ),
        "wire withheld-release disputes to a live reserve adapter and watcher slashing lane",
        release_has_blockers,
        true,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::MetadataLinkageLeak,
        if config.security_audit_deferred {
            SimulationOutcome::Watch
        } else {
            SimulationOutcome::Contained
        },
        transcript,
        0,
        0,
        0,
        liquidity_coverage,
        config.max_metadata_linkage_bps,
        "deposit, private transfer, forced-exit, and reserve-release public records",
        "public reorg/collusion evidence must expose roots and counters without linking note owners",
        format!(
            "privacy_set_size={} max_metadata_linkage_bps={} security_audit_deferred={}",
            transcript.privacy_set_size_observed,
            config.max_metadata_linkage_bps,
            config.security_audit_deferred
        ),
        "run metadata leakage audits across reorg, liveness, and reserve-release records",
        false,
        true,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::PqSignerCompromise,
        if authority_watch || safety_watch {
            SimulationOutcome::Watch
        } else {
            SimulationOutcome::Contained
        },
        transcript,
        finality_depth,
        5_000,
        liveness_window,
        liquidity_coverage,
        0,
        "PQ watcher, sequencer, authority, and reserve signer roots",
        "PQ signer compromise drill must keep release in watch until rotated or slashed",
        format!(
            "authority_watch={} safety_watch={} min_pq_security_bits={}",
            authority_watch, safety_watch, config.min_pq_security_bits
        ),
        "add PQ key compromise and rotation drills for watcher/reserve/authority roots",
        false,
        true,
    ));
    insert(ReorgWatcherSimulationCase::new(
        SimulationKind::CombinedReorgCollusionLiquidityStress,
        if safety_watch || liquidity_watch || authority_watch {
            SimulationOutcome::Watch
        } else {
            SimulationOutcome::Contained
        },
        transcript,
        deep_depth,
        config.collusion_threshold_bps,
        liveness_window.saturating_add(challenge_window),
        liquidity_coverage,
        config.max_metadata_linkage_bps,
        "combined Monero reorg, watcher collusion, liveness delay, liquidity reserve, and metadata surface",
        "combined stress must remain release-blocked or watch-classified until all adapters/tests/audits are live",
        format!(
            "safety_verdict={} liquidity_status={} authority_status={} deep_depth={}",
            safety_report.verdict.as_str(),
            liquidity_report.status.as_str(),
            authority_status.as_str(),
            deep_depth
        ),
        "promote the combined stress simulation into executable integration tests",
        false,
        true,
    ));

    Ok(cases)
}

fn aggregate_report_status(
    config: &Config,
    cases_escaped: u64,
    cases_watch: u64,
    release_blockers: u64,
    safety_report: &SafetyCaseReport,
    liquidity_report: &LiquidityReleaseReport,
) -> SimulationReportStatus {
    if cases_escaped > 0 || release_blockers > 0 {
        SimulationReportStatus::Failed
    } else if cases_watch > 0
        || safety_report.verdict == SafetyCaseVerdict::Watch
        || liquidity_report.status == LiquidityReleaseReportStatus::Watch
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.monero_reorg_adapter_deferred
        || config.watcher_slashing_deferred
        || config.security_audit_deferred
    {
        SimulationReportStatus::Watch
    } else {
        SimulationReportStatus::Passed
    }
}

fn readiness_label(
    status: SimulationReportStatus,
    config: &Config,
    production_blockers: u64,
) -> &'static str {
    match status {
        SimulationReportStatus::Failed => "reorg_watcher_collusion_simulation_failed",
        SimulationReportStatus::Watch
            if config.monero_reorg_adapter_deferred || config.watcher_slashing_deferred =>
        {
            "reorg_watcher_collusion_simulation_covered_adapters_deferred"
        }
        SimulationReportStatus::Watch if production_blockers > 0 => {
            "reorg_watcher_collusion_simulation_watch_production_blockers"
        }
        SimulationReportStatus::Watch => "reorg_watcher_collusion_simulation_watch",
        SimulationReportStatus::Passed => "reorg_watcher_collusion_simulation_passed",
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

pub fn simulation_case_id(kind: SimulationKind, scenario_id: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-CASE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(scenario_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn simulation_case_evidence_root(
    kind: SimulationKind,
    outcome: SimulationOutcome,
    scenario_id: &str,
    transfer_id: &str,
    transcript_root: &str,
    simulated_reorg_depth: u64,
    simulated_collusion_bps: u64,
    liveness_delay_blocks: u64,
    liquidity_coverage_bps: u64,
    metadata_linkage_bps: u64,
    affected_surface: &str,
    observed: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-CASE-EVIDENCE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(outcome.as_str()),
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
            HashPart::Str(transcript_root),
            HashPart::U64(simulated_reorg_depth),
            HashPart::U64(simulated_collusion_bps),
            HashPart::U64(liveness_delay_blocks),
            HashPart::U64(liquidity_coverage_bps),
            HashPart::U64(metadata_linkage_bps),
            HashPart::Str(affected_surface),
            HashPart::Str(observed),
        ],
        32,
    )
}

pub fn simulation_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    scenario_state_root: &str,
    safety_case_state_root: &str,
    safety_case_report_root: &str,
    liquidity_release_state_root: &str,
    liquidity_release_report_root: &str,
    authority_transfer_state_root: &str,
    authority_transfer_report_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-SOURCE-ROOT",
        &[
            HashPart::Str(scenario_state_root),
            HashPart::Str(safety_case_state_root),
            HashPart::Str(safety_case_report_root),
            HashPart::Str(liquidity_release_state_root),
            HashPart::Str(liquidity_release_report_root),
            HashPart::Str(authority_transfer_state_root),
            HashPart::Str(authority_transfer_report_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: SimulationReportStatus,
    readiness_label: &str,
    source_root: &str,
    case_root: &str,
    blocker_root: &str,
    scenario_id: &str,
    transfer_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(case_root),
            HashPart::Str(blocker_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-WATCHER-COLLUSION-RECORD",
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
