use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReportStatus, State as AuthorityTransferState,
    },
    monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::{
        LiquidityReleaseReportStatus, State as LiquidityReleaseState,
    },
    monero_l2_pq_bridge_exit_reorg_watcher_collusion_simulation_runtime::{
        ReorgWatcherSimulationCase, ReorgWatcherSimulationReport, SimulationKind,
        SimulationOutcome, SimulationReportStatus, State as ReorgWatcherSimulationState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitWatcherBondSlashingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_WATCHER_BOND_SLASHING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-watcher-bond-slashing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_WATCHER_BOND_SLASHING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SLASHING_SUITE: &str = "monero-l2-pq-bridge-exit-watcher-bond-slashing-v1";
pub const DEFAULT_MIN_BOND_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_MIN_SLASH_DECISIONS: u64 = 11;
pub const DEFAULT_COLLUSION_SLASH_BPS: u64 = 5_000;
pub const DEFAULT_LIVENESS_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_REORG_MISREPORT_SLASH_BPS: u64 = 3_000;
pub const DEFAULT_METADATA_LEAK_SLASH_BPS: u64 = 1_000;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_REPORTS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondDomain {
    FinalityCertification,
    WatcherQuorum,
    ForcedExitLiveness,
    ReserveRelease,
    MetadataPrivacy,
    PqSignerControl,
}

impl BondDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FinalityCertification => "finality_certification",
            Self::WatcherQuorum => "watcher_quorum",
            Self::ForcedExitLiveness => "forced_exit_liveness",
            Self::ReserveRelease => "reserve_release",
            Self::MetadataPrivacy => "metadata_privacy",
            Self::PqSignerControl => "pq_signer_control",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Active,
    Watch,
    Quarantined,
}

impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Watch => "watch",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashDecisionKind {
    ReorgCertificationHoldback,
    MinorityEquivocationSlash,
    ThresholdCollusionQuarantine,
    LivenessWithholdingSlash,
    ChallengeDelayHoldback,
    LiquidityWithholdingSlash,
    ReserveReleaseQuarantine,
    MetadataLeakPenalty,
    PqSignerCompromiseQuarantine,
    CombinedStressReleaseBlock,
    DeferredAdapterWatch,
}

impl SlashDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReorgCertificationHoldback => "reorg_certification_holdback",
            Self::MinorityEquivocationSlash => "minority_equivocation_slash",
            Self::ThresholdCollusionQuarantine => "threshold_collusion_quarantine",
            Self::LivenessWithholdingSlash => "liveness_withholding_slash",
            Self::ChallengeDelayHoldback => "challenge_delay_holdback",
            Self::LiquidityWithholdingSlash => "liquidity_withholding_slash",
            Self::ReserveReleaseQuarantine => "reserve_release_quarantine",
            Self::MetadataLeakPenalty => "metadata_leak_penalty",
            Self::PqSignerCompromiseQuarantine => "pq_signer_compromise_quarantine",
            Self::CombinedStressReleaseBlock => "combined_stress_release_block",
            Self::DeferredAdapterWatch => "deferred_adapter_watch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashDecisionStatus {
    Enforced,
    Watch,
    Blocked,
}

impl SlashDecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReportStatus {
    Passed,
    Watch,
    Failed,
}

impl SlashingReportStatus {
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
    pub slashing_suite: String,
    pub min_bond_coverage_bps: u64,
    pub min_slash_decisions: u64,
    pub collusion_slash_bps: u64,
    pub liveness_slash_bps: u64,
    pub reorg_misreport_slash_bps: u64,
    pub metadata_leak_slash_bps: u64,
    pub max_public_redaction_bytes: u64,
    pub min_pq_security_bits: u16,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub watcher_bond_adapter_deferred: bool,
    pub slashing_settlement_deferred: bool,
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
            slashing_suite: SLASHING_SUITE.to_string(),
            min_bond_coverage_bps: DEFAULT_MIN_BOND_COVERAGE_BPS,
            min_slash_decisions: DEFAULT_MIN_SLASH_DECISIONS,
            collusion_slash_bps: DEFAULT_COLLUSION_SLASH_BPS,
            liveness_slash_bps: DEFAULT_LIVENESS_SLASH_BPS,
            reorg_misreport_slash_bps: DEFAULT_REORG_MISREPORT_SLASH_BPS,
            metadata_leak_slash_bps: DEFAULT_METADATA_LEAK_SLASH_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            watcher_bond_adapter_deferred: true,
            slashing_settlement_deferred: true,
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
            "slashing_suite": self.slashing_suite,
            "min_bond_coverage_bps": self.min_bond_coverage_bps,
            "min_slash_decisions": self.min_slash_decisions,
            "collusion_slash_bps": self.collusion_slash_bps,
            "liveness_slash_bps": self.liveness_slash_bps,
            "reorg_misreport_slash_bps": self.reorg_misreport_slash_bps,
            "metadata_leak_slash_bps": self.metadata_leak_slash_bps,
            "max_public_redaction_bytes": self.max_public_redaction_bytes,
            "min_pq_security_bits": self.min_pq_security_bits,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "watcher_bond_adapter_deferred": self.watcher_bond_adapter_deferred,
            "slashing_settlement_deferred": self.slashing_settlement_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherBondAccount {
    pub account_id: String,
    pub domain: BondDomain,
    pub status: BondStatus,
    pub bonded_amount: u128,
    pub quarantined_amount: u128,
    pub slashed_amount: u128,
    pub coverage_bps: u64,
    pub watcher_quorum_root: String,
    pub pq_signer_root: String,
    pub redaction_budget_root: String,
}

impl WatcherBondAccount {
    pub fn new(
        domain: BondDomain,
        bonded_amount: u128,
        requested_amount: u128,
        seed: &str,
    ) -> Self {
        let watcher_quorum_root = labeled_root("watcher-quorum", domain, seed);
        let pq_signer_root = labeled_root("pq-signer", domain, seed);
        let redaction_budget_root = labeled_root("redaction-budget", domain, seed);
        let coverage_bps = bps(bonded_amount, requested_amount.max(1));
        let account_id = watcher_bond_account_id(domain, &watcher_quorum_root, &pq_signer_root);
        Self {
            account_id,
            domain,
            status: BondStatus::Active,
            bonded_amount,
            quarantined_amount: 0,
            slashed_amount: 0,
            coverage_bps,
            watcher_quorum_root,
            pq_signer_root,
            redaction_budget_root,
        }
    }

    pub fn available_bond(&self) -> u128 {
        self.bonded_amount
            .saturating_sub(self.quarantined_amount)
            .saturating_sub(self.slashed_amount)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "bonded_amount": self.bonded_amount.to_string(),
            "quarantined_amount": self.quarantined_amount.to_string(),
            "slashed_amount": self.slashed_amount.to_string(),
            "coverage_bps": self.coverage_bps,
            "watcher_quorum_root": self.watcher_quorum_root,
            "pq_signer_root": self.pq_signer_root,
            "redaction_budget_root": self.redaction_budget_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_bond_account", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherSlashDecision {
    pub decision_id: String,
    pub kind: SlashDecisionKind,
    pub status: SlashDecisionStatus,
    pub simulation_case_id: String,
    pub simulation_kind: SimulationKind,
    pub simulation_outcome: SimulationOutcome,
    pub account_id: String,
    pub domain: BondDomain,
    pub release_claim_id: String,
    pub slash_bps: u64,
    pub slash_amount: u128,
    pub quarantine_amount: u128,
    pub release_holdback_root: String,
    pub evidence_root: String,
    pub observed: String,
    pub remediation: String,
    pub blocks_release: bool,
    pub blocks_production: bool,
}

impl WatcherSlashDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: SlashDecisionKind,
        status: SlashDecisionStatus,
        case: &ReorgWatcherSimulationCase,
        account: &WatcherBondAccount,
        release_claim_id: &str,
        slash_bps: u64,
        quarantine_bps: u64,
        observed: impl Into<String>,
        remediation: impl Into<String>,
        blocks_release: bool,
        blocks_production: bool,
    ) -> Self {
        let slash_amount = scale_amount(account.available_bond(), slash_bps);
        let quarantine_amount = scale_amount(account.available_bond(), quarantine_bps);
        let observed = observed.into();
        let remediation = remediation.into();
        let release_holdback_root = release_holdback_root(
            kind,
            release_claim_id,
            &account.account_id,
            slash_amount,
            quarantine_amount,
        );
        let evidence_root = slash_decision_evidence_root(
            kind,
            status,
            &case.case_id,
            &account.account_id,
            release_claim_id,
            slash_bps,
            slash_amount,
            quarantine_amount,
            &observed,
        );
        let decision_id =
            slash_decision_id(kind, &case.case_id, &account.account_id, &evidence_root);
        Self {
            decision_id,
            kind,
            status,
            simulation_case_id: case.case_id.clone(),
            simulation_kind: case.kind,
            simulation_outcome: case.outcome,
            account_id: account.account_id.clone(),
            domain: account.domain,
            release_claim_id: release_claim_id.to_string(),
            slash_bps,
            slash_amount,
            quarantine_amount,
            release_holdback_root,
            evidence_root,
            observed,
            remediation,
            blocks_release,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "simulation_case_id": self.simulation_case_id,
            "simulation_kind": self.simulation_kind.as_str(),
            "simulation_outcome": self.simulation_outcome.as_str(),
            "account_id": self.account_id,
            "domain": self.domain.as_str(),
            "release_claim_id": self.release_claim_id,
            "slash_bps": self.slash_bps,
            "slash_amount": self.slash_amount.to_string(),
            "quarantine_amount": self.quarantine_amount.to_string(),
            "release_holdback_root": self.release_holdback_root,
            "evidence_root": self.evidence_root,
            "observed": self.observed,
            "remediation": self.remediation,
            "blocks_release": self.blocks_release,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_slash_decision", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherSlashingReport {
    pub report_id: String,
    pub status: SlashingReportStatus,
    pub readiness_label: String,
    pub simulation_state_root: String,
    pub simulation_report_root: String,
    pub liquidity_release_state_root: String,
    pub liquidity_release_report_root: String,
    pub authority_transfer_state_root: String,
    pub authority_transfer_report_root: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub transcript_root: String,
    pub bond_accounts: BTreeMap<String, WatcherBondAccount>,
    pub decisions: BTreeMap<String, WatcherSlashDecision>,
    pub decisions_enforced: u64,
    pub decisions_watch: u64,
    pub decisions_blocked: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub total_bonded_amount: u128,
    pub total_slash_amount: u128,
    pub total_quarantine_amount: u128,
    pub bond_coverage_bps: u64,
    pub roots: WatcherSlashingReportRoots,
}

impl WatcherSlashingReport {
    pub fn public_record(&self) -> Value {
        let bond_accounts = self
            .bond_accounts
            .values()
            .map(WatcherBondAccount::public_record)
            .collect::<Vec<_>>();
        let decisions = self
            .decisions
            .values()
            .map(WatcherSlashDecision::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "simulation_state_root": self.simulation_state_root,
            "simulation_report_root": self.simulation_report_root,
            "liquidity_release_state_root": self.liquidity_release_state_root,
            "liquidity_release_report_root": self.liquidity_release_report_root,
            "authority_transfer_state_root": self.authority_transfer_state_root,
            "authority_transfer_report_root": self.authority_transfer_report_root,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "transcript_root": self.transcript_root,
            "bond_accounts": bond_accounts,
            "decisions": decisions,
            "decisions_enforced": self.decisions_enforced,
            "decisions_watch": self.decisions_watch,
            "decisions_blocked": self.decisions_blocked,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "total_bonded_amount": self.total_bonded_amount.to_string(),
            "total_slash_amount": self.total_slash_amount.to_string(),
            "total_quarantine_amount": self.total_quarantine_amount.to_string(),
            "bond_coverage_bps": self.bond_coverage_bps,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherSlashingReportRoots {
    pub bond_account_root: String,
    pub decision_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub report_root: String,
}

impl WatcherSlashingReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "bond_account_root": self.bond_account_root,
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
    pub bond_accounts_seen: u64,
    pub decisions_enforced: u64,
    pub decisions_watch: u64,
    pub decisions_blocked: u64,
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
            "bond_accounts_seen": self.bond_accounts_seen,
            "decisions_enforced": self.decisions_enforced,
            "decisions_watch": self.decisions_watch,
            "decisions_blocked": self.decisions_blocked,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-STATE",
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
    pub latest_report: Option<WatcherSlashingReport>,
    pub report_history: Vec<WatcherSlashingReport>,
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
        let simulation =
            crate::monero_l2_pq_bridge_exit_reorg_watcher_collusion_simulation_runtime::devnet();
        let liquidity_release =
            crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::devnet();
        let authority_transfer =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        state
            .evaluate_watcher_slashing(&simulation, &liquidity_release, &authority_transfer)
            .expect("devnet bridge exit watcher bond slashing");
        state
    }

    pub fn evaluate_watcher_slashing(
        &mut self,
        simulation: &ReorgWatcherSimulationState,
        liquidity_release: &LiquidityReleaseState,
        authority_transfer: &AuthorityTransferState,
    ) -> Result<String> {
        let simulation_report = latest_simulation_report(simulation)?;
        let liquidity_report = liquidity_release
            .latest_report
            .as_ref()
            .ok_or_else(|| "liquidity release state has no latest report".to_string())?;
        let authority_report = authority_transfer
            .latest_report
            .as_ref()
            .ok_or_else(|| "authority transfer state has no latest report".to_string())?;
        let bond_accounts = build_bond_accounts(&self.config, simulation_report, liquidity_report);
        let decisions = build_slash_decisions(
            &self.config,
            simulation_report,
            liquidity_report,
            authority_report.status,
            &bond_accounts,
        )?;
        ensure(
            decisions.len() as u64 >= self.config.min_slash_decisions,
            "watcher slashing report omitted required simulation decisions",
        )?;

        let decisions_enforced = decisions
            .values()
            .filter(|decision| decision.status == SlashDecisionStatus::Enforced)
            .count() as u64;
        let decisions_watch = decisions
            .values()
            .filter(|decision| decision.status == SlashDecisionStatus::Watch)
            .count() as u64;
        let decisions_blocked = decisions
            .values()
            .filter(|decision| decision.status == SlashDecisionStatus::Blocked)
            .count() as u64;
        let release_blockers = decisions
            .values()
            .filter(|decision| decision.blocks_release)
            .count() as u64;
        let production_blockers = decisions
            .values()
            .filter(|decision| decision.blocks_production)
            .count() as u64;
        let total_bonded_amount = bond_accounts
            .values()
            .map(|account| account.bonded_amount)
            .sum::<u128>();
        let total_slash_amount = decisions
            .values()
            .map(|decision| decision.slash_amount)
            .sum::<u128>();
        let total_quarantine_amount = decisions
            .values()
            .map(|decision| decision.quarantine_amount)
            .sum::<u128>();
        let bond_coverage_bps = bps(
            total_bonded_amount,
            liquidity_report.requested_amount.max(1),
        );
        let status = aggregate_report_status(
            &self.config,
            bond_coverage_bps,
            decisions_watch,
            decisions_blocked,
            release_blockers,
            simulation_report,
            liquidity_report.status,
            authority_report.status,
        );
        let readiness_label =
            readiness_label(status, &self.config, production_blockers).to_string();

        let bond_records = bond_accounts
            .values()
            .map(WatcherBondAccount::public_record)
            .collect::<Vec<_>>();
        let decision_records = decisions
            .values()
            .map(WatcherSlashDecision::public_record)
            .collect::<Vec<_>>();
        let blocker_records = decisions
            .values()
            .filter(|decision| decision.blocks_release || decision.blocks_production)
            .map(WatcherSlashDecision::public_record)
            .collect::<Vec<_>>();
        let bond_account_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-ACCOUNTS",
            &bond_records,
        );
        let decision_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-DECISIONS",
            &decision_records,
        );
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-BLOCKERS",
            &blocker_records,
        );
        let source_root = source_root(
            &simulation.state_root(),
            &simulation_report.state_root(),
            &liquidity_release.state_root(),
            &liquidity_report.state_root(),
            &authority_transfer.state_root(),
            &authority_report.state_root(),
            &simulation_report.transcript_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &bond_account_root,
            &decision_root,
            &blocker_root,
            &simulation_report.scenario_id,
            &simulation_report.transfer_id,
        );
        let report_id = watcher_slashing_report_id(&simulation_report.scenario_id, &report_root);
        let report = WatcherSlashingReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            simulation_state_root: simulation.state_root(),
            simulation_report_root: simulation_report.state_root(),
            liquidity_release_state_root: liquidity_release.state_root(),
            liquidity_release_report_root: liquidity_report.state_root(),
            authority_transfer_state_root: authority_transfer.state_root(),
            authority_transfer_report_root: authority_report.state_root(),
            scenario_id: simulation_report.scenario_id.clone(),
            transfer_id: simulation_report.transfer_id.clone(),
            release_claim_id: liquidity_report.release_claim_id.clone(),
            transcript_root: simulation_report.transcript_root.clone(),
            bond_accounts,
            decisions,
            decisions_enforced,
            decisions_watch,
            decisions_blocked,
            release_blockers,
            production_blockers,
            total_bonded_amount,
            total_slash_amount,
            total_quarantine_amount,
            bond_coverage_bps,
            roots: WatcherSlashingReportRoots {
                bond_account_root,
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
            "slashing_suite": self.config.slashing_suite,
            "latest_report": self.latest_report.as_ref().map(WatcherSlashingReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: WatcherSlashingReport) {
        self.counters.reports_run += 1;
        self.counters.bond_accounts_seen += report.bond_accounts.len() as u64;
        self.counters.decisions_enforced += report.decisions_enforced;
        self.counters.decisions_watch += report.decisions_watch;
        self.counters.decisions_blocked += report.decisions_blocked;
        self.counters.release_blockers += report.release_blockers;
        self.counters.production_blockers += report.production_blockers;
        match report.status {
            SlashingReportStatus::Passed => self.counters.reports_passed += 1,
            SlashingReportStatus::Watch => self.counters.reports_watch += 1,
            SlashingReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(WatcherSlashingReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn latest_simulation_report(
    simulation: &ReorgWatcherSimulationState,
) -> Result<&ReorgWatcherSimulationReport> {
    simulation
        .latest_report
        .as_ref()
        .ok_or_else(|| "reorg watcher simulation state has no latest report".to_string())
}

fn build_bond_accounts(
    config: &Config,
    simulation_report: &ReorgWatcherSimulationReport,
    liquidity_report: &crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::LiquidityReleaseReport,
) -> BTreeMap<String, WatcherBondAccount> {
    let requested_amount = liquidity_report.requested_amount.max(1);
    let stress_multiplier = if simulation_report.production_blockers > 0 {
        2
    } else {
        1
    };
    let seed = format!(
        "{}:{}:{}",
        simulation_report.report_id,
        liquidity_report.release_claim_id,
        simulation_report.transcript_root
    );
    [
        WatcherBondAccount::new(
            BondDomain::FinalityCertification,
            scale_amount(
                requested_amount,
                config.min_bond_coverage_bps * stress_multiplier,
            ),
            requested_amount,
            &seed,
        ),
        WatcherBondAccount::new(
            BondDomain::WatcherQuorum,
            scale_amount(requested_amount, 9_000 * stress_multiplier),
            requested_amount,
            &seed,
        ),
        WatcherBondAccount::new(
            BondDomain::ForcedExitLiveness,
            scale_amount(requested_amount, 6_000),
            requested_amount,
            &seed,
        ),
        WatcherBondAccount::new(
            BondDomain::ReserveRelease,
            scale_amount(requested_amount, 8_000),
            requested_amount,
            &seed,
        ),
        WatcherBondAccount::new(
            BondDomain::MetadataPrivacy,
            scale_amount(requested_amount, 3_000),
            requested_amount,
            &seed,
        ),
        WatcherBondAccount::new(
            BondDomain::PqSignerControl,
            scale_amount(requested_amount, 7_500),
            requested_amount,
            &seed,
        ),
    ]
    .into_iter()
    .map(|account| (account.account_id.clone(), account))
    .collect()
}

fn build_slash_decisions(
    config: &Config,
    simulation_report: &ReorgWatcherSimulationReport,
    liquidity_report: &crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::LiquidityReleaseReport,
    authority_status: AuthorityTransferReportStatus,
    accounts: &BTreeMap<String, WatcherBondAccount>,
) -> Result<BTreeMap<String, WatcherSlashDecision>> {
    let mut decisions = BTreeMap::new();
    let mut insert = |decision: WatcherSlashDecision| {
        decisions.insert(decision.decision_id.clone(), decision);
    };
    for case in simulation_report.cases.values() {
        let domain = domain_for_case(case.kind);
        let account = account_for_domain(accounts, domain)?;
        let kind = decision_kind_for_case(case.kind);
        let slash_bps = slash_bps_for_case(config, case.kind, case.outcome);
        let quarantine_bps = quarantine_bps_for_case(case.outcome, authority_status);
        let status = slash_status_for_case(config, case, authority_status, liquidity_report.status);
        let blocks_release = case.outcome == SimulationOutcome::Escaped
            || case.blocks_release
            || status == SlashDecisionStatus::Blocked;
        let blocks_production = case.blocks_production
            || status != SlashDecisionStatus::Enforced
            || config.watcher_bond_adapter_deferred
            || config.slashing_settlement_deferred;
        insert(WatcherSlashDecision::new(
            kind,
            status,
            case,
            account,
            &liquidity_report.release_claim_id,
            slash_bps,
            quarantine_bps,
            format!(
                "simulation_outcome={} authority_status={} liquidity_status={} adapter_deferred={}",
                case.outcome.as_str(),
                authority_status.as_str(),
                liquidity_report.status.as_str(),
                config.watcher_bond_adapter_deferred
            ),
            remediation_for_case(case.kind),
            blocks_release,
            blocks_production,
        ));
    }
    if simulation_report.status == SimulationReportStatus::Watch
        || liquidity_report.status == LiquidityReleaseReportStatus::Watch
        || authority_status == AuthorityTransferReportStatus::Watch
    {
        let case = simulation_report
            .cases
            .values()
            .next()
            .ok_or_else(|| "simulation report has no cases".to_string())?;
        let account = account_for_domain(accounts, BondDomain::WatcherQuorum)?;
        insert(WatcherSlashDecision::new(
            SlashDecisionKind::DeferredAdapterWatch,
            SlashDecisionStatus::Watch,
            case,
            account,
            &liquidity_report.release_claim_id,
            0,
            2_000,
            format!(
                "simulation_status={} liquidity_status={} authority_status={}",
                simulation_report.status.as_str(),
                liquidity_report.status.as_str(),
                authority_status.as_str()
            ),
            "clear deferred adapters before slashing evidence can promote to release-ready",
            false,
            true,
        ));
    }
    Ok(decisions)
}

fn domain_for_case(kind: SimulationKind) -> BondDomain {
    match kind {
        SimulationKind::ShallowReorgBelowFinality | SimulationKind::DeepReorgAfterCertification => {
            BondDomain::FinalityCertification
        }
        SimulationKind::MinorityWatcherEquivocation
        | SimulationKind::ThresholdWatcherCollusion
        | SimulationKind::CombinedReorgCollusionLiquidityStress => BondDomain::WatcherQuorum,
        SimulationKind::WithheldLivenessEvidence | SimulationKind::DelayedChallengeResolution => {
            BondDomain::ForcedExitLiveness
        }
        SimulationKind::LiquidityReserveStress | SimulationKind::ReserveReleaseWithheld => {
            BondDomain::ReserveRelease
        }
        SimulationKind::MetadataLinkageLeak => BondDomain::MetadataPrivacy,
        SimulationKind::PqSignerCompromise => BondDomain::PqSignerControl,
    }
}

fn decision_kind_for_case(kind: SimulationKind) -> SlashDecisionKind {
    match kind {
        SimulationKind::ShallowReorgBelowFinality | SimulationKind::DeepReorgAfterCertification => {
            SlashDecisionKind::ReorgCertificationHoldback
        }
        SimulationKind::MinorityWatcherEquivocation => SlashDecisionKind::MinorityEquivocationSlash,
        SimulationKind::ThresholdWatcherCollusion => {
            SlashDecisionKind::ThresholdCollusionQuarantine
        }
        SimulationKind::WithheldLivenessEvidence => SlashDecisionKind::LivenessWithholdingSlash,
        SimulationKind::DelayedChallengeResolution => SlashDecisionKind::ChallengeDelayHoldback,
        SimulationKind::LiquidityReserveStress => SlashDecisionKind::LiquidityWithholdingSlash,
        SimulationKind::ReserveReleaseWithheld => SlashDecisionKind::ReserveReleaseQuarantine,
        SimulationKind::MetadataLinkageLeak => SlashDecisionKind::MetadataLeakPenalty,
        SimulationKind::PqSignerCompromise => SlashDecisionKind::PqSignerCompromiseQuarantine,
        SimulationKind::CombinedReorgCollusionLiquidityStress => {
            SlashDecisionKind::CombinedStressReleaseBlock
        }
    }
}

fn slash_bps_for_case(config: &Config, kind: SimulationKind, outcome: SimulationOutcome) -> u64 {
    if outcome == SimulationOutcome::Contained {
        return 0;
    }
    match kind {
        SimulationKind::ShallowReorgBelowFinality | SimulationKind::DeepReorgAfterCertification => {
            config.reorg_misreport_slash_bps
        }
        SimulationKind::MinorityWatcherEquivocation | SimulationKind::ThresholdWatcherCollusion => {
            config.collusion_slash_bps
        }
        SimulationKind::WithheldLivenessEvidence | SimulationKind::DelayedChallengeResolution => {
            config.liveness_slash_bps
        }
        SimulationKind::MetadataLinkageLeak => config.metadata_leak_slash_bps,
        SimulationKind::PqSignerCompromise => config.collusion_slash_bps,
        SimulationKind::LiquidityReserveStress
        | SimulationKind::ReserveReleaseWithheld
        | SimulationKind::CombinedReorgCollusionLiquidityStress => config.collusion_slash_bps / 2,
    }
}

fn quarantine_bps_for_case(
    outcome: SimulationOutcome,
    authority_status: AuthorityTransferReportStatus,
) -> u64 {
    match (outcome, authority_status) {
        (SimulationOutcome::Escaped, _) => MAX_BPS,
        (SimulationOutcome::Watch, AuthorityTransferReportStatus::Watch) => 5_000,
        (SimulationOutcome::Watch, _) => 2_500,
        (SimulationOutcome::Contained, AuthorityTransferReportStatus::Watch) => 1_000,
        _ => 0,
    }
}

fn slash_status_for_case(
    config: &Config,
    case: &ReorgWatcherSimulationCase,
    authority_status: AuthorityTransferReportStatus,
    liquidity_status: LiquidityReleaseReportStatus,
) -> SlashDecisionStatus {
    if case.outcome == SimulationOutcome::Escaped
        || authority_status == AuthorityTransferReportStatus::Failed
    {
        SlashDecisionStatus::Blocked
    } else if case.outcome == SimulationOutcome::Watch
        || authority_status == AuthorityTransferReportStatus::Watch
        || liquidity_status == LiquidityReleaseReportStatus::Watch
        || config.watcher_bond_adapter_deferred
        || config.slashing_settlement_deferred
        || config.runtime_tests_deferred
    {
        SlashDecisionStatus::Watch
    } else {
        SlashDecisionStatus::Enforced
    }
}

fn remediation_for_case(kind: SimulationKind) -> &'static str {
    match kind {
        SimulationKind::ShallowReorgBelowFinality | SimulationKind::DeepReorgAfterCertification => {
            "connect Monero header reorg evidence to bond challenge and finality holdback"
        }
        SimulationKind::MinorityWatcherEquivocation | SimulationKind::ThresholdWatcherCollusion => {
            "materialize watcher equivocation receipts and threshold collusion slash settlement"
        }
        SimulationKind::WithheldLivenessEvidence | SimulationKind::DelayedChallengeResolution => {
            "connect liveness withholding evidence to forced-exit bond slash and challenge holdback"
        }
        SimulationKind::LiquidityReserveStress | SimulationKind::ReserveReleaseWithheld => {
            "bind reserve-release withholding to watcher bond slash and emergency release routing"
        }
        SimulationKind::MetadataLinkageLeak => {
            "run metadata leakage audit and slash public redaction budget violations"
        }
        SimulationKind::PqSignerCompromise => {
            "quarantine compromised PQ signer roots and require watcher quorum rotation"
        }
        SimulationKind::CombinedReorgCollusionLiquidityStress => {
            "promote combined stress into executable integration tests before production"
        }
    }
}

fn account_for_domain(
    accounts: &BTreeMap<String, WatcherBondAccount>,
    domain: BondDomain,
) -> Result<&WatcherBondAccount> {
    accounts
        .values()
        .find(|account| account.domain == domain)
        .ok_or_else(|| format!("missing watcher bond account for {}", domain.as_str()))
}

fn aggregate_report_status(
    config: &Config,
    bond_coverage_bps: u64,
    decisions_watch: u64,
    decisions_blocked: u64,
    release_blockers: u64,
    simulation_report: &ReorgWatcherSimulationReport,
    liquidity_status: LiquidityReleaseReportStatus,
    authority_status: AuthorityTransferReportStatus,
) -> SlashingReportStatus {
    if decisions_blocked > 0
        || release_blockers > 0
        || bond_coverage_bps < config.min_bond_coverage_bps
        || simulation_report.status == SimulationReportStatus::Failed
        || authority_status == AuthorityTransferReportStatus::Failed
    {
        SlashingReportStatus::Failed
    } else if decisions_watch > 0
        || simulation_report.status == SimulationReportStatus::Watch
        || liquidity_status == LiquidityReleaseReportStatus::Watch
        || authority_status == AuthorityTransferReportStatus::Watch
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.watcher_bond_adapter_deferred
        || config.slashing_settlement_deferred
        || config.security_audit_deferred
    {
        SlashingReportStatus::Watch
    } else {
        SlashingReportStatus::Passed
    }
}

fn readiness_label(
    status: SlashingReportStatus,
    config: &Config,
    production_blockers: u64,
) -> &'static str {
    match status {
        SlashingReportStatus::Failed => "watcher_bond_slashing_release_blocked",
        SlashingReportStatus::Watch
            if config.watcher_bond_adapter_deferred || config.slashing_settlement_deferred =>
        {
            "watcher_bond_slashing_covered_settlement_deferred"
        }
        SlashingReportStatus::Watch if production_blockers > 0 => {
            "watcher_bond_slashing_watch_production_blockers"
        }
        SlashingReportStatus::Watch => "watcher_bond_slashing_watch",
        SlashingReportStatus::Passed => "watcher_bond_slashing_ready",
    }
}

fn scale_amount(amount: u128, bps_value: u64) -> u128 {
    amount
        .saturating_mul(bps_value as u128)
        .saturating_add((MAX_BPS - 1) as u128)
        / MAX_BPS as u128
}

fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(MAX_BPS as u128)
        .checked_div(denominator)
        .unwrap_or(0)
        .min(u64::MAX as u128) as u64
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

pub fn watcher_bond_account_id(
    domain: BondDomain,
    watcher_quorum_root: &str,
    pq_signer_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-ACCOUNT-ID",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(pq_signer_root),
        ],
        32,
    )
}

pub fn slash_decision_id(
    kind: SlashDecisionKind,
    simulation_case_id: &str,
    account_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-DECISION-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(simulation_case_id),
            HashPart::Str(account_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn watcher_slashing_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn release_holdback_root(
    kind: SlashDecisionKind,
    release_claim_id: &str,
    account_id: &str,
    slash_amount: u128,
    quarantine_amount: u128,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-HOLDBACK-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(account_id),
            HashPart::U64((slash_amount & u64::MAX as u128) as u64),
            HashPart::U64((quarantine_amount & u64::MAX as u128) as u64),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn slash_decision_evidence_root(
    kind: SlashDecisionKind,
    status: SlashDecisionStatus,
    simulation_case_id: &str,
    account_id: &str,
    release_claim_id: &str,
    slash_bps: u64,
    slash_amount: u128,
    quarantine_amount: u128,
    observed: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-DECISION-EVIDENCE-ROOT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(simulation_case_id),
            HashPart::Str(account_id),
            HashPart::Str(release_claim_id),
            HashPart::U64(slash_bps),
            HashPart::U64((slash_amount & u64::MAX as u128) as u64),
            HashPart::U64((quarantine_amount & u64::MAX as u128) as u64),
            HashPart::Str(observed),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, domain: BondDomain, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-LABELED-ROOT",
        &[
            HashPart::Str(label),
            HashPart::Str(domain.as_str()),
            HashPart::Str(seed),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    simulation_state_root: &str,
    simulation_report_root: &str,
    liquidity_release_state_root: &str,
    liquidity_release_report_root: &str,
    authority_transfer_state_root: &str,
    authority_transfer_report_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-SOURCE-ROOT",
        &[
            HashPart::Str(simulation_state_root),
            HashPart::Str(simulation_report_root),
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
    status: SlashingReportStatus,
    readiness_label: &str,
    source_root: &str,
    bond_account_root: &str,
    decision_root: &str,
    blocker_root: &str,
    scenario_id: &str,
    transfer_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(bond_account_root),
            HashPart::Str(decision_root),
            HashPart::Str(blocker_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-SLASHING-RECORD",
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
