use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::{
        AdapterReadinessStatus, LiveAdapterKind, LiveAdapterRequirement,
        State as LiveAdapterMatrixState,
    },
    monero_l2_pq_bridge_exit_live_adapter_stub_registry_runtime::{
        AdapterStubStatus, LiveAdapterStub, State as LiveAdapterStubRegistryState,
    },
    monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::{
        BondStatus, SlashDecisionStatus, SlashingReportStatus, State as WatcherSlashingState,
        WatcherBondAccount, WatcherSlashDecision, WatcherSlashingReport,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitWatcherBondPoolAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_WATCHER_BOND_POOL_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-watcher-bond-pool-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_WATCHER_BOND_POOL_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const WATCHER_BOND_POOL_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-watcher-bond-pool-adapter-v1";
pub const DEFAULT_MIN_BOND_OBSERVATIONS: u64 = 15;
pub const DEFAULT_MIN_BOND_COVERAGE_BPS: u64 = 12_000;
pub const DEFAULT_MAX_QUARANTINE_BPS: u64 = 10_000;
pub const DEFAULT_SETTLEMENT_RETRY_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherBondObservationStatus {
    Accepted,
    Deferred,
    Rejected,
}

impl WatcherBondObservationStatus {
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
pub enum WatcherBondPoolAdapterReportStatus {
    Passed,
    Watch,
    Failed,
}

impl WatcherBondPoolAdapterReportStatus {
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
    pub min_bond_observations: u64,
    pub min_bond_coverage_bps: u64,
    pub max_quarantine_bps: u64,
    pub settlement_retry_blocks: u64,
    pub live_bond_pool_enabled: bool,
    pub fail_closed_on_collusion: bool,
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
            adapter_suite: WATCHER_BOND_POOL_ADAPTER_SUITE.to_string(),
            min_bond_observations: DEFAULT_MIN_BOND_OBSERVATIONS,
            min_bond_coverage_bps: DEFAULT_MIN_BOND_COVERAGE_BPS,
            max_quarantine_bps: DEFAULT_MAX_QUARANTINE_BPS,
            settlement_retry_blocks: DEFAULT_SETTLEMENT_RETRY_BLOCKS,
            live_bond_pool_enabled: false,
            fail_closed_on_collusion: true,
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
            "min_bond_observations": self.min_bond_observations,
            "min_bond_coverage_bps": self.min_bond_coverage_bps,
            "max_quarantine_bps": self.max_quarantine_bps,
            "settlement_retry_blocks": self.settlement_retry_blocks,
            "live_bond_pool_enabled": self.live_bond_pool_enabled,
            "fail_closed_on_collusion": self.fail_closed_on_collusion,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherBondObservation {
    pub observation_id: String,
    pub status: WatcherBondObservationStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub watcher_id_root: String,
    pub bond_account_id: String,
    pub bond_account_root: String,
    pub bond_account_status: BondStatus,
    pub slash_decision_id: String,
    pub slash_decision_status: SlashDecisionStatus,
    pub evidence_root: String,
    pub release_holdback_root: String,
    pub quarantine_root: String,
    pub watcher_status_root: String,
    pub bond_sufficient: bool,
    pub quarantine_required: bool,
    pub bonded_amount: u128,
    pub available_bond: u128,
    pub slash_amount: u128,
    pub quarantine_amount: u128,
    pub coverage_bps: u64,
    pub quarantine_bps: u64,
    pub release_blocks: bool,
    pub production_blocks: bool,
    pub slashing_report_status: SlashingReportStatus,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl WatcherBondObservation {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        slashing_report: &WatcherSlashingReport,
        account: &WatcherBondAccount,
        decision: &WatcherSlashDecision,
        ordinal: u64,
    ) -> Self {
        let available_bond = account.available_bond();
        let quarantine_bps =
            bps(decision.quarantine_amount, available_bond.max(1)).min(config.max_quarantine_bps);
        let bond_sufficient =
            account.coverage_bps >= config.min_bond_coverage_bps && available_bond > 0;
        let quarantine_required = decision.quarantine_amount > 0
            || decision.blocks_release
            || decision.blocks_production
            || account.status == BondStatus::Quarantined;
        let watcher_id_root = watcher_id_root(
            &account.watcher_quorum_root,
            &account.pq_signer_root,
            &requirement.release_claim_id,
            ordinal,
        );
        let bond_account_root = account.state_root();
        let quarantine_root = quarantine_root(
            &account.account_id,
            &decision.decision_id,
            decision.quarantine_amount,
            quarantine_bps,
            quarantine_required,
        );
        let watcher_status_root = watcher_status_root(
            account.status,
            decision.status,
            &watcher_id_root,
            &quarantine_root,
            bond_sufficient,
        );
        let status = observation_status(
            config,
            requirement.status,
            slashing_report.status,
            account.status,
            decision.status,
            bond_sufficient,
            quarantine_required,
        );
        let observation_root = watcher_bond_observation_root(
            status,
            &requirement.requirement_id,
            &watcher_id_root,
            &bond_account_root,
            &decision.evidence_root,
            &quarantine_root,
            bond_sufficient,
            quarantine_bps,
        );
        let observation_id = watcher_bond_observation_id(
            &requirement.requirement_id,
            &decision.decision_id,
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
            watcher_id_root,
            bond_account_id: account.account_id.clone(),
            bond_account_root,
            bond_account_status: account.status,
            slash_decision_id: decision.decision_id.clone(),
            slash_decision_status: decision.status,
            evidence_root: decision.evidence_root.clone(),
            release_holdback_root: decision.release_holdback_root.clone(),
            quarantine_root,
            watcher_status_root,
            bond_sufficient,
            quarantine_required,
            bonded_amount: account.bonded_amount,
            available_bond,
            slash_amount: decision.slash_amount,
            quarantine_amount: decision.quarantine_amount,
            coverage_bps: account.coverage_bps,
            quarantine_bps,
            release_blocks: decision.blocks_release,
            production_blocks: decision.blocks_production,
            slashing_report_status: slashing_report.status,
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
            "watcher_id_root": self.watcher_id_root,
            "bond_account_id": self.bond_account_id,
            "bond_account_root": self.bond_account_root,
            "bond_account_status": self.bond_account_status.as_str(),
            "slash_decision_id": self.slash_decision_id,
            "slash_decision_status": self.slash_decision_status.as_str(),
            "evidence_root": self.evidence_root,
            "release_holdback_root": self.release_holdback_root,
            "quarantine_root": self.quarantine_root,
            "watcher_status_root": self.watcher_status_root,
            "bond_sufficient": self.bond_sufficient,
            "quarantine_required": self.quarantine_required,
            "bonded_amount": self.bonded_amount.to_string(),
            "available_bond": self.available_bond.to_string(),
            "slash_amount": self.slash_amount.to_string(),
            "quarantine_amount": self.quarantine_amount.to_string(),
            "coverage_bps": self.coverage_bps,
            "quarantine_bps": self.quarantine_bps,
            "release_blocks": self.release_blocks,
            "production_blocks": self.production_blocks,
            "slashing_report_status": self.slashing_report_status.as_str(),
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_bond_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherBondPoolAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: WatcherBondObservationStatus,
    pub bond_sufficient: bool,
    pub quarantine_root: String,
    pub watcher_status_root: String,
    pub release_hold_required: bool,
    pub adapter_root: String,
    pub response_label: String,
}

impl WatcherBondPoolAdapterResponse {
    pub fn from_observation(config: &Config, observation: &WatcherBondObservation) -> Self {
        let bond_sufficient = config.live_bond_pool_enabled
            && observation.status == WatcherBondObservationStatus::Accepted
            && observation.bond_sufficient;
        let release_hold_required =
            !bond_sufficient || observation.release_blocks || observation.quarantine_required;
        let response_label = response_label(config, observation).to_string();
        let adapter_root = adapter_response_root(
            observation.status,
            bond_sufficient,
            &observation.quarantine_root,
            &observation.watcher_status_root,
            release_hold_required,
            &response_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            bond_sufficient,
            quarantine_root: observation.quarantine_root.clone(),
            watcher_status_root: observation.watcher_status_root.clone(),
            release_hold_required,
            adapter_root,
            response_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "bond_sufficient": self.bond_sufficient,
            "quarantine_root": self.quarantine_root,
            "watcher_status_root": self.watcher_status_root,
            "release_hold_required": self.release_hold_required,
            "adapter_root": self.adapter_root,
            "response_label": self.response_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_bond_pool_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherBondPoolFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_blocks: u64,
}

impl WatcherBondPoolFailureSurface {
    pub fn from_observation(config: &Config, observation: &WatcherBondObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let quarantine_required =
            observation.quarantine_required && config.fail_closed_on_collusion;
        let retry_after_blocks = if observation.status == WatcherBondObservationStatus::Accepted {
            0
        } else {
            config.settlement_retry_blocks
        };
        let failure_root = bond_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_blocks,
        );
        let failure_id = bond_failure_id(&observation.observation_id, &failure_root);
        Self {
            failure_id,
            observation_id: observation.observation_id.clone(),
            error_code,
            failure_root,
            quarantine_required,
            retry_after_blocks,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "failure_id": self.failure_id,
            "observation_id": self.observation_id,
            "error_code": self.error_code,
            "failure_root": self.failure_root,
            "quarantine_required": self.quarantine_required,
            "retry_after_blocks": self.retry_after_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_bond_pool_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherBondPoolAdapterReport {
    pub report_id: String,
    pub status: WatcherBondPoolAdapterReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub watcher_slashing_state_root: String,
    pub watcher_slashing_report_root: String,
    pub bond_pool_stub_id: String,
    pub bond_pool_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub observations_total: u64,
    pub observations_accepted: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub bonds_sufficient: u64,
    pub release_holds_required: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, WatcherBondObservation>,
    pub responses: BTreeMap<String, WatcherBondPoolAdapterResponse>,
    pub failures: BTreeMap<String, WatcherBondPoolFailureSurface>,
    pub roots: WatcherBondPoolAdapterReportRoots,
}

impl WatcherBondPoolAdapterReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(WatcherBondObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(WatcherBondPoolAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(WatcherBondPoolFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "watcher_slashing_state_root": self.watcher_slashing_state_root,
            "watcher_slashing_report_root": self.watcher_slashing_report_root,
            "bond_pool_stub_id": self.bond_pool_stub_id,
            "bond_pool_stub_status": self.bond_pool_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "observations_total": self.observations_total,
            "observations_accepted": self.observations_accepted,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "bonds_sufficient": self.bonds_sufficient,
            "release_holds_required": self.release_holds_required,
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
pub struct WatcherBondPoolAdapterReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl WatcherBondPoolAdapterReportRoots {
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
    pub bonds_sufficient: u64,
    pub release_holds_required: u64,
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
            "bonds_sufficient": self.bonds_sufficient,
            "release_holds_required": self.release_holds_required,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-ADAPTER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-ADAPTER-STATE",
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
    pub latest_report: Option<WatcherBondPoolAdapterReport>,
    pub report_history: Vec<WatcherBondPoolAdapterReport>,
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
        let watcher_slashing =
            crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::devnet();
        state
            .process_watcher_bond_pool_adapter(&matrix, &stub_registry, &watcher_slashing)
            .expect("devnet bridge exit watcher bond pool adapter");
        state
    }

    pub fn process_watcher_bond_pool_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        watcher_slashing: &WatcherSlashingState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let slashing_report = watcher_slashing
            .latest_report
            .as_ref()
            .ok_or_else(|| "watcher bond slashing state has no latest report".to_string())?;
        let bond_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::WatcherBondPool)
            .ok_or_else(|| "watcher bond pool adapter stub is missing".to_string())?;
        let bond_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::WatcherBondPool)
            .collect::<Vec<_>>();
        ensure(
            bond_requirements.len() as u64 >= self.config.min_bond_observations,
            "watcher bond pool adapter omitted required fixture observations",
        )?;
        let accounts = slashing_report.bond_accounts.values().collect::<Vec<_>>();
        ensure(
            !accounts.is_empty(),
            "watcher slashing report has no bond accounts",
        )?;
        let decisions = slashing_report.decisions.values().collect::<Vec<_>>();
        ensure(
            !decisions.is_empty(),
            "watcher slashing report has no slash decisions",
        )?;
        let observations = bond_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                let account = accounts[index % accounts.len()];
                let decision = decisions[index % decisions.len()];
                WatcherBondObservation::from_requirement(
                    &self.config,
                    *requirement,
                    slashing_report,
                    account,
                    decision,
                    index as u64,
                )
            })
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| {
                WatcherBondPoolAdapterResponse::from_observation(&self.config, observation)
            })
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                WatcherBondPoolFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_accepted = observations
            .values()
            .filter(|observation| observation.status == WatcherBondObservationStatus::Accepted)
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| observation.status == WatcherBondObservationStatus::Deferred)
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| observation.status == WatcherBondObservationStatus::Rejected)
            .count() as u64;
        let bonds_sufficient = responses
            .values()
            .filter(|response| response.bond_sufficient)
            .count() as u64;
        let release_holds_required = responses
            .values()
            .filter(|response| response.release_hold_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            bond_stub,
            slashing_report.status,
            observations_deferred,
            observations_rejected,
            release_holds_required,
            self.config.live_bond_pool_enabled,
        );
        let readiness_label =
            readiness_label(status, bond_stub.status, self.config.live_bond_pool_enabled)
                .to_string();
        let observation_records = observations
            .values()
            .map(WatcherBondObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(WatcherBondPoolAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(WatcherBondPoolFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &watcher_slashing.state_root(),
            &slashing_report.state_root(),
            &bond_stub.stub_id,
            &bond_stub.request_schema_root,
            &bond_stub.response_schema_root,
            &bond_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &observation_root,
            &response_root,
            &failure_root,
            &slashing_report.release_claim_id,
        );
        let report_id =
            watcher_bond_pool_adapter_report_id(&slashing_report.release_claim_id, &report_root);
        let report = WatcherBondPoolAdapterReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            watcher_slashing_state_root: watcher_slashing.state_root(),
            watcher_slashing_report_root: slashing_report.state_root(),
            bond_pool_stub_id: bond_stub.stub_id.clone(),
            bond_pool_stub_status: bond_stub.status,
            release_claim_id: slashing_report.release_claim_id.clone(),
            observations_total,
            observations_accepted,
            observations_deferred,
            observations_rejected,
            bonds_sufficient,
            release_holds_required,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: WatcherBondPoolAdapterReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(WatcherBondPoolAdapterReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: WatcherBondPoolAdapterReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_accepted += report.observations_accepted;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.bonds_sufficient += report.bonds_sufficient;
        self.counters.release_holds_required += report.release_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            WatcherBondPoolAdapterReportStatus::Passed => self.counters.reports_passed += 1,
            WatcherBondPoolAdapterReportStatus::Watch => self.counters.reports_watch += 1,
            WatcherBondPoolAdapterReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(WatcherBondPoolAdapterReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-ADAPTER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

#[allow(clippy::too_many_arguments)]
fn observation_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    slashing_status: SlashingReportStatus,
    account_status: BondStatus,
    decision_status: SlashDecisionStatus,
    bond_sufficient: bool,
    quarantine_required: bool,
) -> WatcherBondObservationStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || slashing_status == SlashingReportStatus::Failed
        || decision_status == SlashDecisionStatus::Blocked
        || !bond_sufficient
        || (config.fail_closed_on_collusion && account_status == BondStatus::Quarantined)
    {
        WatcherBondObservationStatus::Rejected
    } else if !config.live_bond_pool_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || slashing_status == SlashingReportStatus::Watch
        || decision_status == SlashDecisionStatus::Watch
        || quarantine_required
    {
        WatcherBondObservationStatus::Deferred
    } else {
        WatcherBondObservationStatus::Accepted
    }
}

#[allow(clippy::too_many_arguments)]
fn report_status(
    bond_stub: &LiveAdapterStub,
    slashing_status: SlashingReportStatus,
    observations_deferred: u64,
    observations_rejected: u64,
    release_holds_required: u64,
    live_bond_pool_enabled: bool,
) -> WatcherBondPoolAdapterReportStatus {
    if observations_rejected > 0
        || slashing_status == SlashingReportStatus::Failed
        || bond_stub.status == AdapterStubStatus::Blocked
    {
        WatcherBondPoolAdapterReportStatus::Failed
    } else if observations_deferred > 0
        || release_holds_required > 0
        || slashing_status == SlashingReportStatus::Watch
        || bond_stub.status == AdapterStubStatus::Deferred
        || !live_bond_pool_enabled
    {
        WatcherBondPoolAdapterReportStatus::Watch
    } else {
        WatcherBondPoolAdapterReportStatus::Passed
    }
}

fn readiness_label(
    status: WatcherBondPoolAdapterReportStatus,
    bond_stub_status: AdapterStubStatus,
    live_bond_pool_enabled: bool,
) -> &'static str {
    match status {
        WatcherBondPoolAdapterReportStatus::Failed => "watcher_bond_pool_adapter_failed",
        WatcherBondPoolAdapterReportStatus::Watch if !live_bond_pool_enabled => {
            "watcher_bond_pool_adapter_watch_live_pool_deferred"
        }
        WatcherBondPoolAdapterReportStatus::Watch
            if bond_stub_status == AdapterStubStatus::Deferred =>
        {
            "watcher_bond_pool_adapter_watch_stub_deferred"
        }
        WatcherBondPoolAdapterReportStatus::Watch => "watcher_bond_pool_adapter_watch",
        WatcherBondPoolAdapterReportStatus::Passed => "watcher_bond_pool_adapter_ready",
    }
}

fn response_label(config: &Config, observation: &WatcherBondObservation) -> &'static str {
    if observation.status == WatcherBondObservationStatus::Rejected {
        "watcher_bond_pool_rejected"
    } else if observation.bond_account_status == BondStatus::Quarantined {
        "watcher_account_quarantined"
    } else if !observation.bond_sufficient {
        "watcher_bond_coverage_insufficient"
    } else if observation.release_blocks {
        "watcher_bond_release_hold_required"
    } else if observation.quarantine_required {
        "watcher_quarantine_required"
    } else if !config.live_bond_pool_enabled {
        "live_watcher_bond_pool_deferred"
    } else {
        "watcher_bond_sufficient"
    }
}

fn error_code(config: &Config, observation: &WatcherBondObservation) -> &'static str {
    if observation.slashing_report_status == SlashingReportStatus::Failed {
        "watcher_slashing_report_failed"
    } else if observation.slash_decision_status == SlashDecisionStatus::Blocked {
        "slash_decision_blocked"
    } else if observation.bond_account_status == BondStatus::Quarantined {
        "watcher_account_quarantined"
    } else if !observation.bond_sufficient {
        "watcher_bond_coverage_insufficient"
    } else if observation.release_blocks {
        "watcher_bond_release_hold_required"
    } else if !config.live_bond_pool_enabled {
        "live_watcher_bond_pool_deferred"
    } else if observation.slash_decision_status == SlashDecisionStatus::Watch {
        "slash_decision_watch"
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

pub fn watcher_id_root(
    watcher_quorum_root: &str,
    pq_signer_root: &str,
    release_claim_id: &str,
    ordinal: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-WATCHER-ID",
        &[
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(pq_signer_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn quarantine_root(
    bond_account_id: &str,
    slash_decision_id: &str,
    quarantine_amount: u128,
    quarantine_bps: u64,
    quarantine_required: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-QUARANTINE",
        &[
            HashPart::Str(bond_account_id),
            HashPart::Str(slash_decision_id),
            HashPart::U64((quarantine_amount & u64::MAX as u128) as u64),
            HashPart::U64(quarantine_bps),
            HashPart::Str(bool_str(quarantine_required)),
        ],
        32,
    )
}

pub fn watcher_status_root(
    bond_status: BondStatus,
    decision_status: SlashDecisionStatus,
    watcher_id_root: &str,
    quarantine_root: &str,
    bond_sufficient: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-STATUS",
        &[
            HashPart::Str(bond_status.as_str()),
            HashPart::Str(decision_status.as_str()),
            HashPart::Str(watcher_id_root),
            HashPart::Str(quarantine_root),
            HashPart::Str(bool_str(bond_sufficient)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn watcher_bond_observation_root(
    status: WatcherBondObservationStatus,
    requirement_id: &str,
    watcher_id_root: &str,
    bond_account_root: &str,
    evidence_root: &str,
    quarantine_root: &str,
    bond_sufficient: bool,
    quarantine_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-OBSERVATION",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(watcher_id_root),
            HashPart::Str(bond_account_root),
            HashPart::Str(evidence_root),
            HashPart::Str(quarantine_root),
            HashPart::Str(bool_str(bond_sufficient)),
            HashPart::U64(quarantine_bps),
        ],
        32,
    )
}

pub fn watcher_bond_observation_id(
    requirement_id: &str,
    slash_decision_id: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-OBSERVATION-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(slash_decision_id),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: WatcherBondObservationStatus,
    bond_sufficient: bool,
    quarantine_root: &str,
    watcher_status_root: &str,
    release_hold_required: bool,
    response_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-RESPONSE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(bond_sufficient)),
            HashPart::Str(quarantine_root),
            HashPart::Str(watcher_status_root),
            HashPart::Str(bool_str(release_hold_required)),
            HashPart::Str(response_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn bond_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_blocks: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-FAILURE",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_blocks),
        ],
        32,
    )
}

pub fn bond_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-FAILURE-ID",
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
    watcher_slashing_state_root: &str,
    watcher_slashing_report_root: &str,
    bond_pool_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-SOURCE",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(watcher_slashing_state_root),
            HashPart::Str(watcher_slashing_report_root),
            HashPart::Str(bond_pool_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: WatcherBondPoolAdapterReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-REPORT",
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

pub fn watcher_bond_pool_adapter_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WATCHER-BOND-POOL-RECORD",
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

fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(10_000)
        .saturating_div(denominator)
        .min(u64::MAX as u128) as u64
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
