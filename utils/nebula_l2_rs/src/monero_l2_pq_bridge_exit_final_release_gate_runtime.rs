use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReportStatus, State as AuthorityTransferState,
    },
    monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::{
        SafetyCaseVerdict, State as SafetyCaseState,
    },
    monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::{
        LiquidityReleaseReportStatus, State as LiquidityReleaseState,
    },
    monero_l2_pq_bridge_exit_reorg_watcher_collusion_simulation_runtime::{
        SimulationReportStatus, State as ReorgWatcherSimulationState,
    },
    monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::{
        SlashingReportStatus, State as WatcherBondSlashingState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitFinalReleaseGateRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FINAL_RELEASE_GATE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-final-release-gate-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FINAL_RELEASE_GATE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FINAL_RELEASE_GATE_SUITE: &str = "monero-l2-pq-bridge-exit-final-release-gate-v1";
pub const DEFAULT_MIN_GATE_DECISIONS: u64 = 9;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalGateDecisionKind {
    SafetyCaseAccepted,
    AuthorityReleaseAccepted,
    LiquidityReserveAccepted,
    ReorgWatcherSimulationAccepted,
    WatcherBondSlashingAccepted,
    UserForcedExitAnswer,
    DeferredCargoRuntimeGate,
    DeferredSecurityAuditGate,
    ProductionReleaseGate,
}

impl FinalGateDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SafetyCaseAccepted => "safety_case_accepted",
            Self::AuthorityReleaseAccepted => "authority_release_accepted",
            Self::LiquidityReserveAccepted => "liquidity_reserve_accepted",
            Self::ReorgWatcherSimulationAccepted => "reorg_watcher_simulation_accepted",
            Self::WatcherBondSlashingAccepted => "watcher_bond_slashing_accepted",
            Self::UserForcedExitAnswer => "user_forced_exit_answer",
            Self::DeferredCargoRuntimeGate => "deferred_cargo_runtime_gate",
            Self::DeferredSecurityAuditGate => "deferred_security_audit_gate",
            Self::ProductionReleaseGate => "production_release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalGateDecisionStatus {
    ReleaseAllowed,
    Watch,
    Blocked,
}

impl FinalGateDecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseAllowed => "release_allowed",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalReleaseGateStatus {
    Passed,
    Watch,
    Failed,
}

impl FinalReleaseGateStatus {
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
    pub final_release_gate_suite: String,
    pub min_gate_decisions: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub security_audit_deferred: bool,
    pub production_release_allowed: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            final_release_gate_suite: FINAL_RELEASE_GATE_SUITE.to_string(),
            min_gate_decisions: DEFAULT_MIN_GATE_DECISIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            security_audit_deferred: true,
            production_release_allowed: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "final_release_gate_suite": self.final_release_gate_suite,
            "min_gate_decisions": self.min_gate_decisions,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalGateDecision {
    pub decision_id: String,
    pub kind: FinalGateDecisionKind,
    pub status: FinalGateDecisionStatus,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub source_report_root: String,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub remediation: String,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
}

impl FinalGateDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: FinalGateDecisionKind,
        status: FinalGateDecisionStatus,
        scenario_id: impl Into<String>,
        transfer_id: impl Into<String>,
        release_claim_id: impl Into<String>,
        transcript_root: impl Into<String>,
        source_report_root: impl Into<String>,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        remediation: impl Into<String>,
        blocks_user_release: bool,
        blocks_production: bool,
    ) -> Self {
        let scenario_id = scenario_id.into();
        let transfer_id = transfer_id.into();
        let release_claim_id = release_claim_id.into();
        let transcript_root = transcript_root.into();
        let source_report_root = source_report_root.into();
        let requirement = requirement.into();
        let observed = observed.into();
        let remediation = remediation.into();
        let evidence_root = final_gate_decision_evidence_root(
            kind,
            status,
            &scenario_id,
            &transfer_id,
            &release_claim_id,
            &source_report_root,
            &requirement,
            &observed,
        );
        let decision_id = final_gate_decision_id(kind, &release_claim_id, &evidence_root);
        Self {
            decision_id,
            kind,
            status,
            scenario_id,
            transfer_id,
            release_claim_id,
            transcript_root,
            source_report_root,
            requirement,
            observed,
            evidence_root,
            remediation,
            blocks_user_release,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "source_report_root": self.source_report_root,
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("final_gate_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalReleaseGateReport {
    pub report_id: String,
    pub status: FinalReleaseGateStatus,
    pub readiness_label: String,
    pub user_answer: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub safety_case_state_root: String,
    pub safety_case_report_root: String,
    pub authority_transfer_state_root: String,
    pub authority_transfer_report_root: String,
    pub liquidity_release_state_root: String,
    pub liquidity_release_report_root: String,
    pub reorg_simulation_state_root: String,
    pub reorg_simulation_report_root: String,
    pub watcher_slashing_state_root: String,
    pub watcher_slashing_report_root: String,
    pub decisions_allowed: u64,
    pub decisions_watch: u64,
    pub decisions_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub deferred_gates: u64,
    pub decisions: BTreeMap<String, FinalGateDecision>,
    pub roots: FinalReleaseGateReportRoots,
}

impl FinalReleaseGateReport {
    pub fn public_record(&self) -> Value {
        let decisions = self
            .decisions
            .values()
            .map(FinalGateDecision::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "user_answer": self.user_answer,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "safety_case_state_root": self.safety_case_state_root,
            "safety_case_report_root": self.safety_case_report_root,
            "authority_transfer_state_root": self.authority_transfer_state_root,
            "authority_transfer_report_root": self.authority_transfer_report_root,
            "liquidity_release_state_root": self.liquidity_release_state_root,
            "liquidity_release_report_root": self.liquidity_release_report_root,
            "reorg_simulation_state_root": self.reorg_simulation_state_root,
            "reorg_simulation_report_root": self.reorg_simulation_report_root,
            "watcher_slashing_state_root": self.watcher_slashing_state_root,
            "watcher_slashing_report_root": self.watcher_slashing_report_root,
            "decisions_allowed": self.decisions_allowed,
            "decisions_watch": self.decisions_watch,
            "decisions_blocked": self.decisions_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "deferred_gates": self.deferred_gates,
            "decisions": decisions,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalReleaseGateReportRoots {
    pub decision_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub report_root: String,
}

impl FinalReleaseGateReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_root": self.decision_root,
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
    pub decisions_allowed: u64,
    pub decisions_watch: u64,
    pub decisions_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub deferred_gates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "decisions_allowed": self.decisions_allowed,
            "decisions_watch": self.decisions_watch,
            "decisions_blocked": self.decisions_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "deferred_gates": self.deferred_gates,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-STATE",
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
    pub latest_report: Option<FinalReleaseGateReport>,
    pub report_history: Vec<FinalReleaseGateReport>,
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
        let safety_case = crate::monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::devnet();
        let authority_transfer =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        let liquidity_release =
            crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::devnet();
        let reorg_simulation =
            crate::monero_l2_pq_bridge_exit_reorg_watcher_collusion_simulation_runtime::devnet();
        let watcher_slashing =
            crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::devnet();
        state
            .evaluate_final_release_gate(
                &safety_case,
                &authority_transfer,
                &liquidity_release,
                &reorg_simulation,
                &watcher_slashing,
            )
            .expect("devnet bridge exit final release gate");
        state
    }

    pub fn evaluate_final_release_gate(
        &mut self,
        safety_case: &SafetyCaseState,
        authority_transfer: &AuthorityTransferState,
        liquidity_release: &LiquidityReleaseState,
        reorg_simulation: &ReorgWatcherSimulationState,
        watcher_slashing: &WatcherBondSlashingState,
    ) -> Result<String> {
        let safety_report = safety_case
            .latest_report
            .as_ref()
            .ok_or_else(|| "safety case state has no latest report".to_string())?;
        let authority_report = authority_transfer
            .latest_report
            .as_ref()
            .ok_or_else(|| "authority transfer state has no latest report".to_string())?;
        let liquidity_report = liquidity_release
            .latest_report
            .as_ref()
            .ok_or_else(|| "liquidity release state has no latest report".to_string())?;
        let reorg_report = reorg_simulation
            .latest_report
            .as_ref()
            .ok_or_else(|| "reorg simulation state has no latest report".to_string())?;
        let slashing_report = watcher_slashing
            .latest_report
            .as_ref()
            .ok_or_else(|| "watcher slashing state has no latest report".to_string())?;

        let decisions = build_gate_decisions(
            &self.config,
            safety_report,
            authority_report.status,
            authority_report.state_root(),
            liquidity_report,
            reorg_report,
            slashing_report,
        )?;
        ensure(
            decisions.len() as u64 >= self.config.min_gate_decisions,
            "final release gate omitted required decisions",
        )?;
        let decisions_allowed = decisions
            .values()
            .filter(|decision| decision.status == FinalGateDecisionStatus::ReleaseAllowed)
            .count() as u64;
        let decisions_watch = decisions
            .values()
            .filter(|decision| decision.status == FinalGateDecisionStatus::Watch)
            .count() as u64;
        let decisions_blocked = decisions
            .values()
            .filter(|decision| decision.status == FinalGateDecisionStatus::Blocked)
            .count() as u64;
        let user_release_blockers = decisions
            .values()
            .filter(|decision| decision.blocks_user_release)
            .count() as u64;
        let production_blockers = decisions
            .values()
            .filter(|decision| decision.blocks_production)
            .count() as u64;
        let deferred_gates = deferred_gate_count(&self.config, &decisions);
        let status = aggregate_report_status(
            decisions_watch,
            decisions_blocked,
            user_release_blockers,
            safety_report.verdict,
            liquidity_report.status,
            reorg_report.status,
            slashing_report.status,
        );
        let readiness_label =
            readiness_label(status, &self.config, production_blockers).to_string();
        let user_answer = user_answer(status, user_release_blockers, deferred_gates).to_string();

        let decision_records = decisions
            .values()
            .map(FinalGateDecision::public_record)
            .collect::<Vec<_>>();
        let blocker_records = decisions
            .values()
            .filter(|decision| decision.blocks_user_release || decision.blocks_production)
            .map(FinalGateDecision::public_record)
            .collect::<Vec<_>>();
        let decision_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-DECISIONS",
            &decision_records,
        );
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-BLOCKERS",
            &blocker_records,
        );
        let source_root = source_root(
            &safety_case.state_root(),
            &safety_report.state_root(),
            &authority_transfer.state_root(),
            &authority_report.state_root(),
            &liquidity_release.state_root(),
            &liquidity_report.state_root(),
            &reorg_simulation.state_root(),
            &reorg_report.state_root(),
            &watcher_slashing.state_root(),
            &slashing_report.state_root(),
            &slashing_report.transcript_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &decision_root,
            &blocker_root,
            &slashing_report.scenario_id,
            &slashing_report.transfer_id,
            &slashing_report.release_claim_id,
        );
        let report_id =
            final_release_gate_report_id(&slashing_report.release_claim_id, &report_root);
        let report = FinalReleaseGateReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            user_answer,
            scenario_id: slashing_report.scenario_id.clone(),
            transfer_id: slashing_report.transfer_id.clone(),
            release_claim_id: slashing_report.release_claim_id.clone(),
            transcript_root: slashing_report.transcript_root.clone(),
            safety_case_state_root: safety_case.state_root(),
            safety_case_report_root: safety_report.state_root(),
            authority_transfer_state_root: authority_transfer.state_root(),
            authority_transfer_report_root: authority_report.state_root(),
            liquidity_release_state_root: liquidity_release.state_root(),
            liquidity_release_report_root: liquidity_report.state_root(),
            reorg_simulation_state_root: reorg_simulation.state_root(),
            reorg_simulation_report_root: reorg_report.state_root(),
            watcher_slashing_state_root: watcher_slashing.state_root(),
            watcher_slashing_report_root: slashing_report.state_root(),
            decisions_allowed,
            decisions_watch,
            decisions_blocked,
            user_release_blockers,
            production_blockers,
            deferred_gates,
            decisions,
            roots: FinalReleaseGateReportRoots {
                decision_root,
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
            "final_release_gate_suite": self.config.final_release_gate_suite,
            "latest_report": self.latest_report.as_ref().map(FinalReleaseGateReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: FinalReleaseGateReport) {
        self.counters.reports_run += 1;
        self.counters.decisions_allowed += report.decisions_allowed;
        self.counters.decisions_watch += report.decisions_watch;
        self.counters.decisions_blocked += report.decisions_blocked;
        self.counters.user_release_blockers += report.user_release_blockers;
        self.counters.production_blockers += report.production_blockers;
        self.counters.deferred_gates += report.deferred_gates;
        match report.status {
            FinalReleaseGateStatus::Passed => self.counters.reports_passed += 1,
            FinalReleaseGateStatus::Watch => self.counters.reports_watch += 1,
            FinalReleaseGateStatus::Failed => self.counters.reports_failed += 1,
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
            .map(FinalReleaseGateReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_gate_decisions(
    config: &Config,
    safety_report: &crate::monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime::SafetyCaseReport,
    authority_status: AuthorityTransferReportStatus,
    authority_report_root: String,
    liquidity_report: &crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::LiquidityReleaseReport,
    reorg_report: &crate::monero_l2_pq_bridge_exit_reorg_watcher_collusion_simulation_runtime::ReorgWatcherSimulationReport,
    slashing_report: &crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::WatcherSlashingReport,
) -> Result<BTreeMap<String, FinalGateDecision>> {
    let scenario_id = &slashing_report.scenario_id;
    let transfer_id = &slashing_report.transfer_id;
    let release_claim_id = &slashing_report.release_claim_id;
    let transcript_root = &slashing_report.transcript_root;
    let mut decisions = BTreeMap::new();
    let mut insert = |decision: FinalGateDecision| {
        decisions.insert(decision.decision_id.clone(), decision);
    };

    insert(FinalGateDecision::new(
        FinalGateDecisionKind::SafetyCaseAccepted,
        status_from_safety(safety_report.verdict),
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        safety_report.state_root(),
        "the full bridge/exit safety case must be coherent before final release",
        format!(
            "safety_verdict={} production_blockers={} deferred_gates={}",
            safety_report.verdict.as_str(),
            safety_report.production_blockers,
            safety_report.deferred_gates
        ),
        "clear safety-case blockers and deferred gates before release promotion",
        safety_report.verdict == SafetyCaseVerdict::Failed,
        safety_report.verdict != SafetyCaseVerdict::Proven,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::AuthorityReleaseAccepted,
        status_from_authority(authority_status),
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        authority_report_root,
        "bridge release authority must consume the transfer bundle and avoid unilateral release",
        format!("authority_status={}", authority_status.as_str()),
        "promote authority release gate from watch to audited enforcement",
        authority_status == AuthorityTransferReportStatus::Failed,
        authority_status != AuthorityTransferReportStatus::Passed,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::LiquidityReserveAccepted,
        status_from_liquidity(liquidity_report.status),
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        liquidity_report.state_root(),
        "forced-exit release must have reserve coverage and emergency backstop visibility",
        format!(
            "liquidity_status={} effective_coverage_bps={} release_blockers={}",
            liquidity_report.status.as_str(),
            liquidity_report.effective_coverage_bps,
            liquidity_report.release_blockers
        ),
        "connect reserve-release records to live reserve adapters and depletion tests",
        liquidity_report.status == LiquidityReleaseReportStatus::Failed,
        liquidity_report.status != LiquidityReleaseReportStatus::Passed,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::ReorgWatcherSimulationAccepted,
        status_from_reorg(reorg_report.status),
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        reorg_report.state_root(),
        "Monero reorg, watcher collusion, liveness, liquidity, and metadata simulations must not escape",
        format!(
            "reorg_status={} cases_watch={} cases_escaped={} production_blockers={}",
            reorg_report.status.as_str(),
            reorg_report.cases_watch,
            reorg_report.cases_escaped,
            reorg_report.production_blockers
        ),
        "connect simulations to live Monero reorg adapters and watcher slashing receipts",
        reorg_report.status == SimulationReportStatus::Failed,
        reorg_report.status != SimulationReportStatus::Passed,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::WatcherBondSlashingAccepted,
        status_from_slashing(slashing_report.status),
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        slashing_report.state_root(),
        "watcher equivocation, liveness withholding, and reserve withholding must have slash/quarantine decisions",
        format!(
            "slashing_status={} decisions_watch={} decisions_blocked={} bond_coverage_bps={}",
            slashing_report.status.as_str(),
            slashing_report.decisions_watch,
            slashing_report.decisions_blocked,
            slashing_report.bond_coverage_bps
        ),
        "connect watcher bond decisions to live slashing settlement before production",
        slashing_report.status == SlashingReportStatus::Failed,
        slashing_report.status != SlashingReportStatus::Passed,
    ));

    let all_release_surfaces_non_failed = safety_report.verdict != SafetyCaseVerdict::Failed
        && authority_status != AuthorityTransferReportStatus::Failed
        && liquidity_report.status != LiquidityReleaseReportStatus::Failed
        && reorg_report.status != SimulationReportStatus::Failed
        && slashing_report.status != SlashingReportStatus::Failed;
    let any_watch = safety_report.verdict == SafetyCaseVerdict::Watch
        || authority_status == AuthorityTransferReportStatus::Watch
        || liquidity_report.status == LiquidityReleaseReportStatus::Watch
        || reorg_report.status == SimulationReportStatus::Watch
        || slashing_report.status == SlashingReportStatus::Watch;
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::UserForcedExitAnswer,
        if !all_release_surfaces_non_failed {
            FinalGateDecisionStatus::Blocked
        } else if any_watch {
            FinalGateDecisionStatus::Watch
        } else {
            FinalGateDecisionStatus::ReleaseAllowed
        },
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        slashing_report.state_root(),
        "answer whether a user can get in, transact privately, and force exit if everyone misbehaves",
        format!(
            "all_release_surfaces_non_failed={} any_watch={} release_claim_id={}",
            all_release_surfaces_non_failed, any_watch, release_claim_id
        ),
        "turn all watch-only gates into executable tests/adapters before claiming final release readiness",
        !all_release_surfaces_non_failed,
        any_watch || !config.production_release_allowed,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::DeferredCargoRuntimeGate,
        if config.cargo_checks_deferred || config.runtime_tests_deferred {
            FinalGateDecisionStatus::Watch
        } else {
            FinalGateDecisionStatus::ReleaseAllowed
        },
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        slashing_report.state_root(),
        "cargo check/test/clippy and runtime tests must run before release evidence is final",
        format!(
            "cargo_checks_deferred={} runtime_tests_deferred={}",
            config.cargo_checks_deferred, config.runtime_tests_deferred
        ),
        "run cargo check/test/clippy when heavier gates resume",
        false,
        config.cargo_checks_deferred || config.runtime_tests_deferred,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::DeferredSecurityAuditGate,
        if config.security_audit_deferred {
            FinalGateDecisionStatus::Watch
        } else {
            FinalGateDecisionStatus::ReleaseAllowed
        },
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        safety_report.state_root(),
        "PQ control plane, privacy leakage, and bridge authority must be audited before production",
        format!(
            "security_audit_deferred={} min_pq_security_bits={} min_privacy_set_size={}",
            config.security_audit_deferred,
            config.min_pq_security_bits,
            config.min_privacy_set_size
        ),
        "complete cryptographic and metadata leakage review",
        false,
        config.security_audit_deferred,
    ));
    insert(FinalGateDecision::new(
        FinalGateDecisionKind::ProductionReleaseGate,
        if config.production_release_allowed && !any_watch && all_release_surfaces_non_failed {
            FinalGateDecisionStatus::ReleaseAllowed
        } else {
            FinalGateDecisionStatus::Watch
        },
        scenario_id,
        transfer_id,
        release_claim_id,
        transcript_root,
        slashing_report.state_root(),
        "prototype must remain blocked from production while final release evidence is watch-only",
        format!(
            "production_release_allowed={} any_watch={} all_release_surfaces_non_failed={}",
            config.production_release_allowed, any_watch, all_release_surfaces_non_failed
        ),
        "keep progress panel readiness honest until all final release gate evidence is executable",
        false,
        !config.production_release_allowed || any_watch,
    ));

    Ok(decisions)
}

fn status_from_safety(status: SafetyCaseVerdict) -> FinalGateDecisionStatus {
    match status {
        SafetyCaseVerdict::Proven => FinalGateDecisionStatus::ReleaseAllowed,
        SafetyCaseVerdict::Watch => FinalGateDecisionStatus::Watch,
        SafetyCaseVerdict::Failed => FinalGateDecisionStatus::Blocked,
    }
}

fn status_from_authority(status: AuthorityTransferReportStatus) -> FinalGateDecisionStatus {
    match status {
        AuthorityTransferReportStatus::Passed => FinalGateDecisionStatus::ReleaseAllowed,
        AuthorityTransferReportStatus::Watch => FinalGateDecisionStatus::Watch,
        AuthorityTransferReportStatus::Failed => FinalGateDecisionStatus::Blocked,
    }
}

fn status_from_liquidity(status: LiquidityReleaseReportStatus) -> FinalGateDecisionStatus {
    match status {
        LiquidityReleaseReportStatus::Passed => FinalGateDecisionStatus::ReleaseAllowed,
        LiquidityReleaseReportStatus::Watch => FinalGateDecisionStatus::Watch,
        LiquidityReleaseReportStatus::Failed => FinalGateDecisionStatus::Blocked,
    }
}

fn status_from_reorg(status: SimulationReportStatus) -> FinalGateDecisionStatus {
    match status {
        SimulationReportStatus::Passed => FinalGateDecisionStatus::ReleaseAllowed,
        SimulationReportStatus::Watch => FinalGateDecisionStatus::Watch,
        SimulationReportStatus::Failed => FinalGateDecisionStatus::Blocked,
    }
}

fn status_from_slashing(status: SlashingReportStatus) -> FinalGateDecisionStatus {
    match status {
        SlashingReportStatus::Passed => FinalGateDecisionStatus::ReleaseAllowed,
        SlashingReportStatus::Watch => FinalGateDecisionStatus::Watch,
        SlashingReportStatus::Failed => FinalGateDecisionStatus::Blocked,
    }
}

fn aggregate_report_status(
    decisions_watch: u64,
    decisions_blocked: u64,
    user_release_blockers: u64,
    safety_status: SafetyCaseVerdict,
    liquidity_status: LiquidityReleaseReportStatus,
    reorg_status: SimulationReportStatus,
    slashing_status: SlashingReportStatus,
) -> FinalReleaseGateStatus {
    if decisions_blocked > 0
        || user_release_blockers > 0
        || safety_status == SafetyCaseVerdict::Failed
        || liquidity_status == LiquidityReleaseReportStatus::Failed
        || reorg_status == SimulationReportStatus::Failed
        || slashing_status == SlashingReportStatus::Failed
    {
        FinalReleaseGateStatus::Failed
    } else if decisions_watch > 0 {
        FinalReleaseGateStatus::Watch
    } else {
        FinalReleaseGateStatus::Passed
    }
}

fn deferred_gate_count(config: &Config, decisions: &BTreeMap<String, FinalGateDecision>) -> u64 {
    let config_deferred = [
        config.cargo_checks_deferred,
        config.runtime_tests_deferred,
        config.security_audit_deferred,
        !config.production_release_allowed,
    ]
    .iter()
    .filter(|item| **item)
    .count() as u64;
    config_deferred
        + decisions
            .values()
            .filter(|decision| decision.status == FinalGateDecisionStatus::Watch)
            .count() as u64
}

fn readiness_label(
    status: FinalReleaseGateStatus,
    config: &Config,
    production_blockers: u64,
) -> &'static str {
    match status {
        FinalReleaseGateStatus::Failed => "final_release_gate_blocked",
        FinalReleaseGateStatus::Watch
            if config.cargo_checks_deferred
                || config.runtime_tests_deferred
                || config.security_audit_deferred =>
        {
            "final_release_gate_watch_deferred_checks"
        }
        FinalReleaseGateStatus::Watch if production_blockers > 0 => {
            "final_release_gate_watch_production_blockers"
        }
        FinalReleaseGateStatus::Watch => "final_release_gate_watch",
        FinalReleaseGateStatus::Passed => "final_release_gate_ready",
    }
}

fn user_answer(
    status: FinalReleaseGateStatus,
    user_release_blockers: u64,
    deferred_gates: u64,
) -> &'static str {
    match status {
        FinalReleaseGateStatus::Passed => {
            "yes_final_gate_allows_this_forced_exit_under_current_evidence"
        }
        FinalReleaseGateStatus::Watch if user_release_blockers == 0 => {
            "not_yet_final_gate_preserves_user_escape_but_release_evidence_is_watch_only"
        }
        FinalReleaseGateStatus::Watch if deferred_gates > 0 => {
            "not_yet_deferred_checks_keep_final_release_in_watch"
        }
        FinalReleaseGateStatus::Watch => "not_yet_final_release_gate_requires_operator_review",
        FinalReleaseGateStatus::Failed => "no_final_release_gate_blocks_this_forced_exit_evidence",
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

pub fn final_gate_decision_id(
    kind: FinalGateDecisionKind,
    release_claim_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-DECISION-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn final_gate_decision_evidence_root(
    kind: FinalGateDecisionKind,
    status: FinalGateDecisionStatus,
    scenario_id: &str,
    transfer_id: &str,
    release_claim_id: &str,
    source_report_root: &str,
    requirement: &str,
    observed: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-DECISION-EVIDENCE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(source_report_root),
            HashPart::Str(requirement),
            HashPart::Str(observed),
        ],
        32,
    )
}

pub fn final_release_gate_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    safety_case_state_root: &str,
    safety_case_report_root: &str,
    authority_transfer_state_root: &str,
    authority_transfer_report_root: &str,
    liquidity_release_state_root: &str,
    liquidity_release_report_root: &str,
    reorg_simulation_state_root: &str,
    reorg_simulation_report_root: &str,
    watcher_slashing_state_root: &str,
    watcher_slashing_report_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-SOURCE-ROOT",
        &[
            HashPart::Str(safety_case_state_root),
            HashPart::Str(safety_case_report_root),
            HashPart::Str(authority_transfer_state_root),
            HashPart::Str(authority_transfer_report_root),
            HashPart::Str(liquidity_release_state_root),
            HashPart::Str(liquidity_release_report_root),
            HashPart::Str(reorg_simulation_state_root),
            HashPart::Str(reorg_simulation_report_root),
            HashPart::Str(watcher_slashing_state_root),
            HashPart::Str(watcher_slashing_report_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: FinalReleaseGateStatus,
    readiness_label: &str,
    source_root: &str,
    decision_root: &str,
    blocker_root: &str,
    scenario_id: &str,
    transfer_id: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(decision_root),
            HashPart::Str(blocker_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-FINAL-RELEASE-GATE-RECORD",
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
