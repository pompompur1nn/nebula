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
    monero_l2_pq_bridge_exit_watcher_bond_pool_adapter_runtime::{
        State as WatcherBondPoolAdapterState, WatcherBondObservation, WatcherBondObservationStatus,
        WatcherBondPoolAdapterReport, WatcherBondPoolAdapterReportStatus,
        WatcherBondPoolAdapterResponse, WatcherBondPoolFailureSurface,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitSlashingSettlementAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_SLASHING_SETTLEMENT_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-slashing-settlement-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_SLASHING_SETTLEMENT_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SLASHING_SETTLEMENT_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-slashing-settlement-adapter-v1";
pub const DEFAULT_MIN_SETTLEMENT_OBSERVATIONS: u64 = 15;
pub const DEFAULT_SETTLEMENT_RETRY_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_SETTLEMENT_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_BATCH_SIZE: u64 = 64;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingSettlementObservationStatus {
    Settled,
    Deferred,
    Rejected,
}

impl SlashingSettlementObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Settled => "settled",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingSettlementAdapterReportStatus {
    Passed,
    Watch,
    Failed,
}

impl SlashingSettlementAdapterReportStatus {
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
    pub min_settlement_observations: u64,
    pub settlement_retry_blocks: u64,
    pub max_settlement_fee_bps: u64,
    pub max_batch_size: u64,
    pub live_slashing_settlement_enabled: bool,
    pub fail_closed_on_bond_rejection: bool,
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
            adapter_suite: SLASHING_SETTLEMENT_ADAPTER_SUITE.to_string(),
            min_settlement_observations: DEFAULT_MIN_SETTLEMENT_OBSERVATIONS,
            settlement_retry_blocks: DEFAULT_SETTLEMENT_RETRY_BLOCKS,
            max_settlement_fee_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            live_slashing_settlement_enabled: false,
            fail_closed_on_bond_rejection: true,
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
            "min_settlement_observations": self.min_settlement_observations,
            "settlement_retry_blocks": self.settlement_retry_blocks,
            "max_settlement_fee_bps": self.max_settlement_fee_bps,
            "max_batch_size": self.max_batch_size,
            "live_slashing_settlement_enabled": self.live_slashing_settlement_enabled,
            "fail_closed_on_bond_rejection": self.fail_closed_on_bond_rejection,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingSettlementObservation {
    pub observation_id: String,
    pub status: SlashingSettlementObservationStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub slash_decision_id: String,
    pub bond_observation_id: String,
    pub bond_response_id: String,
    pub bond_failure_id: String,
    pub bond_account_root: String,
    pub holdback_root: String,
    pub settlement_root: String,
    pub settlement_receipt_root: String,
    pub release_holdback_root: String,
    pub bond_quarantine_root: String,
    pub watcher_status_root: String,
    pub bond_pool_report_status: WatcherBondPoolAdapterReportStatus,
    pub bond_observation_status: WatcherBondObservationStatus,
    pub bond_sufficient: bool,
    pub bond_release_hold_required: bool,
    pub bond_quarantine_required: bool,
    pub slash_settled: bool,
    pub settlement_hold_required: bool,
    pub fee_bps: u64,
    pub retry_after_blocks: u64,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl SlashingSettlementObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        bond_report: &WatcherBondPoolAdapterReport,
        bond_observation: &WatcherBondObservation,
        bond_response: &WatcherBondPoolAdapterResponse,
        bond_failure: &WatcherBondPoolFailureSurface,
        ordinal: u64,
    ) -> Self {
        let status = observation_status(
            config,
            requirement.status,
            bond_report.status,
            bond_observation.status,
            bond_response.release_hold_required,
            bond_observation.quarantine_required,
        );
        let fee_bps = ordinal
            .saturating_add(bond_observation.quarantine_bps)
            .min(config.max_settlement_fee_bps);
        let slash_settled = config.live_slashing_settlement_enabled
            && status == SlashingSettlementObservationStatus::Settled;
        let settlement_hold_required = status != SlashingSettlementObservationStatus::Settled
            || bond_response.release_hold_required
            || bond_observation.quarantine_required;
        let retry_after_blocks = if settlement_hold_required {
            config.settlement_retry_blocks
        } else {
            0
        };
        let settlement_root = settlement_root(
            &bond_observation.slash_decision_id,
            &bond_observation.bond_account_root,
            &bond_observation.release_holdback_root,
            &bond_observation.quarantine_root,
            fee_bps,
            ordinal % config.max_batch_size.max(1),
        );
        let settlement_receipt_root = settlement_receipt_root(
            status,
            &settlement_root,
            &bond_response.adapter_root,
            &bond_failure.failure_root,
            slash_settled,
            settlement_hold_required,
        );
        let release_holdback_root = release_holdback_root(
            &bond_observation.release_holdback_root,
            &settlement_receipt_root,
            &bond_observation.watcher_status_root,
            bond_observation.release_blocks,
            settlement_hold_required,
        );
        let observation_root = slashing_settlement_observation_root(
            status,
            &requirement.requirement_id,
            &bond_observation.slash_decision_id,
            &bond_observation.bond_account_root,
            &settlement_root,
            &settlement_receipt_root,
            &release_holdback_root,
            slash_settled,
        );
        let observation_id = slashing_settlement_observation_id(
            &requirement.requirement_id,
            &bond_observation.slash_decision_id,
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
            slash_decision_id: bond_observation.slash_decision_id.clone(),
            bond_observation_id: bond_observation.observation_id.clone(),
            bond_response_id: bond_response.response_id.clone(),
            bond_failure_id: bond_failure.failure_id.clone(),
            bond_account_root: bond_observation.bond_account_root.clone(),
            holdback_root: bond_observation.release_holdback_root.clone(),
            settlement_root,
            settlement_receipt_root,
            release_holdback_root,
            bond_quarantine_root: bond_observation.quarantine_root.clone(),
            watcher_status_root: bond_observation.watcher_status_root.clone(),
            bond_pool_report_status: bond_report.status,
            bond_observation_status: bond_observation.status,
            bond_sufficient: bond_observation.bond_sufficient,
            bond_release_hold_required: bond_response.release_hold_required,
            bond_quarantine_required: bond_observation.quarantine_required,
            slash_settled,
            settlement_hold_required,
            fee_bps,
            retry_after_blocks,
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
            "slash_decision_id": self.slash_decision_id,
            "bond_observation_id": self.bond_observation_id,
            "bond_response_id": self.bond_response_id,
            "bond_failure_id": self.bond_failure_id,
            "bond_account_root": self.bond_account_root,
            "holdback_root": self.holdback_root,
            "settlement_root": self.settlement_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "release_holdback_root": self.release_holdback_root,
            "bond_quarantine_root": self.bond_quarantine_root,
            "watcher_status_root": self.watcher_status_root,
            "bond_pool_report_status": self.bond_pool_report_status.as_str(),
            "bond_observation_status": self.bond_observation_status.as_str(),
            "bond_sufficient": self.bond_sufficient,
            "bond_release_hold_required": self.bond_release_hold_required,
            "bond_quarantine_required": self.bond_quarantine_required,
            "slash_settled": self.slash_settled,
            "settlement_hold_required": self.settlement_hold_required,
            "fee_bps": self.fee_bps,
            "retry_after_blocks": self.retry_after_blocks,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("slashing_settlement_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingSettlementAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: SlashingSettlementObservationStatus,
    pub slash_settled: bool,
    pub settlement_receipt_root: String,
    pub release_holdback_root: String,
    pub settlement_hold_required: bool,
    pub adapter_root: String,
    pub response_label: String,
}

impl SlashingSettlementAdapterResponse {
    pub fn from_observation(config: &Config, observation: &SlashingSettlementObservation) -> Self {
        let slash_settled = config.live_slashing_settlement_enabled && observation.slash_settled;
        let settlement_hold_required = !slash_settled || observation.settlement_hold_required;
        let response_label = response_label(config, observation).to_string();
        let adapter_root = adapter_response_root(
            observation.status,
            slash_settled,
            &observation.settlement_receipt_root,
            &observation.release_holdback_root,
            settlement_hold_required,
            &response_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            slash_settled,
            settlement_receipt_root: observation.settlement_receipt_root.clone(),
            release_holdback_root: observation.release_holdback_root.clone(),
            settlement_hold_required,
            adapter_root,
            response_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "slash_settled": self.slash_settled,
            "settlement_receipt_root": self.settlement_receipt_root,
            "release_holdback_root": self.release_holdback_root,
            "settlement_hold_required": self.settlement_hold_required,
            "adapter_root": self.adapter_root,
            "response_label": self.response_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("slashing_settlement_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingSettlementFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_blocks: u64,
}

impl SlashingSettlementFailureSurface {
    pub fn from_observation(config: &Config, observation: &SlashingSettlementObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let quarantine_required = observation.bond_quarantine_required
            || observation.status == SlashingSettlementObservationStatus::Rejected;
        let retry_after_blocks = if error_code == "none" {
            0
        } else {
            observation
                .retry_after_blocks
                .max(config.settlement_retry_blocks)
        };
        let failure_root = settlement_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_blocks,
        );
        let failure_id = settlement_failure_id(&observation.observation_id, &failure_root);
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
        record_root("slashing_settlement_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SlashingSettlementAdapterReport {
    pub report_id: String,
    pub status: SlashingSettlementAdapterReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub bond_pool_state_root: String,
    pub bond_pool_report_root: String,
    pub slashing_stub_id: String,
    pub slashing_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub observations_total: u64,
    pub observations_settled: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub slash_settled: u64,
    pub settlement_holds_required: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, SlashingSettlementObservation>,
    pub responses: BTreeMap<String, SlashingSettlementAdapterResponse>,
    pub failures: BTreeMap<String, SlashingSettlementFailureSurface>,
    pub roots: SlashingSettlementAdapterReportRoots,
}

impl SlashingSettlementAdapterReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(SlashingSettlementObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(SlashingSettlementAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(SlashingSettlementFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "bond_pool_state_root": self.bond_pool_state_root,
            "bond_pool_report_root": self.bond_pool_report_root,
            "slashing_stub_id": self.slashing_stub_id,
            "slashing_stub_status": self.slashing_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "observations_total": self.observations_total,
            "observations_settled": self.observations_settled,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "slash_settled": self.slash_settled,
            "settlement_holds_required": self.settlement_holds_required,
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
pub struct SlashingSettlementAdapterReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl SlashingSettlementAdapterReportRoots {
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
    pub observations_settled: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub slash_settled: u64,
    pub settlement_holds_required: u64,
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
            "observations_settled": self.observations_settled,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "slash_settled": self.slash_settled,
            "settlement_holds_required": self.settlement_holds_required,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-ADAPTER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-ADAPTER-STATE",
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
    pub latest_report: Option<SlashingSettlementAdapterReport>,
    pub report_history: Vec<SlashingSettlementAdapterReport>,
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
        let bond_pool = crate::monero_l2_pq_bridge_exit_watcher_bond_pool_adapter_runtime::devnet();
        state
            .process_slashing_settlement_adapter(&matrix, &stub_registry, &bond_pool)
            .expect("devnet bridge exit slashing settlement adapter");
        state
    }

    pub fn process_slashing_settlement_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        bond_pool: &WatcherBondPoolAdapterState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let bond_report = bond_pool
            .latest_report
            .as_ref()
            .ok_or_else(|| "watcher bond pool adapter has no latest report".to_string())?;
        let slashing_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::SlashingSettlement)
            .ok_or_else(|| "slashing settlement adapter stub is missing".to_string())?;
        let settlement_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::SlashingSettlement)
            .collect::<Vec<_>>();
        ensure(
            settlement_requirements.len() as u64 >= self.config.min_settlement_observations,
            "slashing settlement adapter omitted required fixture observations",
        )?;
        let bond_observations = bond_report.observations.values().collect::<Vec<_>>();
        ensure(
            !bond_observations.is_empty(),
            "watcher bond pool report has no observations",
        )?;
        let observations = settlement_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                let bond_observation = bond_observations[index % bond_observations.len()];
                let bond_response =
                    find_bond_response(bond_report, &bond_observation.observation_id)?;
                let bond_failure =
                    find_bond_failure(bond_report, &bond_observation.observation_id)?;
                Ok(SlashingSettlementObservation::from_requirement(
                    &self.config,
                    *requirement,
                    bond_report,
                    bond_observation,
                    bond_response,
                    bond_failure,
                    index as u64,
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| {
                SlashingSettlementAdapterResponse::from_observation(&self.config, observation)
            })
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                SlashingSettlementFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_settled = observations
            .values()
            .filter(|observation| {
                observation.status == SlashingSettlementObservationStatus::Settled
            })
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| {
                observation.status == SlashingSettlementObservationStatus::Deferred
            })
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| {
                observation.status == SlashingSettlementObservationStatus::Rejected
            })
            .count() as u64;
        let slash_settled = responses
            .values()
            .filter(|response| response.slash_settled)
            .count() as u64;
        let settlement_holds_required = responses
            .values()
            .filter(|response| response.settlement_hold_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            slashing_stub,
            bond_report.status,
            observations_deferred,
            observations_rejected,
            settlement_holds_required,
            self.config.live_slashing_settlement_enabled,
        );
        let readiness_label = readiness_label(
            status,
            slashing_stub.status,
            self.config.live_slashing_settlement_enabled,
        )
        .to_string();
        let observation_records = observations
            .values()
            .map(SlashingSettlementObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(SlashingSettlementAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(SlashingSettlementFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &bond_pool.state_root(),
            &bond_report.state_root(),
            &slashing_stub.stub_id,
            &slashing_stub.request_schema_root,
            &slashing_stub.response_schema_root,
            &slashing_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &observation_root,
            &response_root,
            &failure_root,
            &bond_report.release_claim_id,
        );
        let report_id =
            slashing_settlement_adapter_report_id(&bond_report.release_claim_id, &report_root);
        let report = SlashingSettlementAdapterReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            bond_pool_state_root: bond_pool.state_root(),
            bond_pool_report_root: bond_report.state_root(),
            slashing_stub_id: slashing_stub.stub_id.clone(),
            slashing_stub_status: slashing_stub.status,
            release_claim_id: bond_report.release_claim_id.clone(),
            observations_total,
            observations_settled,
            observations_deferred,
            observations_rejected,
            slash_settled,
            settlement_holds_required,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: SlashingSettlementAdapterReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(SlashingSettlementAdapterReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: SlashingSettlementAdapterReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_settled += report.observations_settled;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.slash_settled += report.slash_settled;
        self.counters.settlement_holds_required += report.settlement_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            SlashingSettlementAdapterReportStatus::Passed => self.counters.reports_passed += 1,
            SlashingSettlementAdapterReportStatus::Watch => self.counters.reports_watch += 1,
            SlashingSettlementAdapterReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(SlashingSettlementAdapterReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-ADAPTER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn find_bond_response<'a>(
    bond_report: &'a WatcherBondPoolAdapterReport,
    observation_id: &str,
) -> Result<&'a WatcherBondPoolAdapterResponse> {
    bond_report
        .responses
        .values()
        .find(|response| response.observation_id == observation_id)
        .ok_or_else(|| format!("missing watcher bond response for observation {observation_id}"))
}

fn find_bond_failure<'a>(
    bond_report: &'a WatcherBondPoolAdapterReport,
    observation_id: &str,
) -> Result<&'a WatcherBondPoolFailureSurface> {
    bond_report
        .failures
        .values()
        .find(|failure| failure.observation_id == observation_id)
        .ok_or_else(|| format!("missing watcher bond failure for observation {observation_id}"))
}

fn observation_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    bond_report_status: WatcherBondPoolAdapterReportStatus,
    bond_observation_status: WatcherBondObservationStatus,
    bond_release_hold_required: bool,
    bond_quarantine_required: bool,
) -> SlashingSettlementObservationStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || bond_report_status == WatcherBondPoolAdapterReportStatus::Failed
        || bond_observation_status == WatcherBondObservationStatus::Rejected
        || (config.fail_closed_on_bond_rejection
            && bond_observation_status == WatcherBondObservationStatus::Rejected)
    {
        SlashingSettlementObservationStatus::Rejected
    } else if !config.live_slashing_settlement_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || bond_report_status == WatcherBondPoolAdapterReportStatus::Watch
        || bond_observation_status == WatcherBondObservationStatus::Deferred
        || bond_release_hold_required
        || bond_quarantine_required
    {
        SlashingSettlementObservationStatus::Deferred
    } else {
        SlashingSettlementObservationStatus::Settled
    }
}

fn report_status(
    slashing_stub: &LiveAdapterStub,
    bond_report_status: WatcherBondPoolAdapterReportStatus,
    observations_deferred: u64,
    observations_rejected: u64,
    settlement_holds_required: u64,
    live_slashing_settlement_enabled: bool,
) -> SlashingSettlementAdapterReportStatus {
    if observations_rejected > 0
        || bond_report_status == WatcherBondPoolAdapterReportStatus::Failed
        || slashing_stub.status == AdapterStubStatus::Blocked
    {
        SlashingSettlementAdapterReportStatus::Failed
    } else if observations_deferred > 0
        || settlement_holds_required > 0
        || bond_report_status == WatcherBondPoolAdapterReportStatus::Watch
        || slashing_stub.status == AdapterStubStatus::Deferred
        || !live_slashing_settlement_enabled
    {
        SlashingSettlementAdapterReportStatus::Watch
    } else {
        SlashingSettlementAdapterReportStatus::Passed
    }
}

fn readiness_label(
    status: SlashingSettlementAdapterReportStatus,
    slashing_stub_status: AdapterStubStatus,
    live_slashing_settlement_enabled: bool,
) -> &'static str {
    match status {
        SlashingSettlementAdapterReportStatus::Failed => "slashing_settlement_adapter_failed",
        SlashingSettlementAdapterReportStatus::Watch if !live_slashing_settlement_enabled => {
            "slashing_settlement_adapter_watch_live_settlement_deferred"
        }
        SlashingSettlementAdapterReportStatus::Watch
            if slashing_stub_status == AdapterStubStatus::Deferred =>
        {
            "slashing_settlement_adapter_watch_stub_deferred"
        }
        SlashingSettlementAdapterReportStatus::Watch => "slashing_settlement_adapter_watch",
        SlashingSettlementAdapterReportStatus::Passed => "slashing_settlement_adapter_ready",
    }
}

fn response_label(config: &Config, observation: &SlashingSettlementObservation) -> &'static str {
    if observation.status == SlashingSettlementObservationStatus::Rejected {
        "slashing_settlement_rejected"
    } else if observation.bond_quarantine_required {
        "watcher_bond_quarantine_holds_settlement"
    } else if observation.bond_release_hold_required {
        "watcher_bond_release_hold_required"
    } else if observation.status == SlashingSettlementObservationStatus::Deferred {
        "slashing_settlement_deferred"
    } else if !config.live_slashing_settlement_enabled {
        "live_slashing_settlement_deferred"
    } else {
        "slash_settlement_ready"
    }
}

fn error_code(config: &Config, observation: &SlashingSettlementObservation) -> &'static str {
    if observation.bond_pool_report_status == WatcherBondPoolAdapterReportStatus::Failed {
        "watcher_bond_pool_report_failed"
    } else if observation.bond_observation_status == WatcherBondObservationStatus::Rejected {
        "watcher_bond_observation_rejected"
    } else if observation.bond_quarantine_required {
        "watcher_bond_quarantine_required"
    } else if observation.bond_release_hold_required {
        "watcher_bond_release_hold_required"
    } else if !config.live_slashing_settlement_enabled {
        "live_slashing_settlement_deferred"
    } else if observation.status == SlashingSettlementObservationStatus::Deferred {
        "slashing_settlement_deferred"
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

#[allow(clippy::too_many_arguments)]
pub fn settlement_root(
    slash_decision_id: &str,
    bond_account_root: &str,
    holdback_root: &str,
    quarantine_root: &str,
    fee_bps: u64,
    batch_index: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-ROOT",
        &[
            HashPart::Str(slash_decision_id),
            HashPart::Str(bond_account_root),
            HashPart::Str(holdback_root),
            HashPart::Str(quarantine_root),
            HashPart::U64(fee_bps),
            HashPart::U64(batch_index),
        ],
        32,
    )
}

pub fn settlement_receipt_root(
    status: SlashingSettlementObservationStatus,
    settlement_root: &str,
    bond_response_root: &str,
    bond_failure_root: &str,
    slash_settled: bool,
    settlement_hold_required: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-RECEIPT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(settlement_root),
            HashPart::Str(bond_response_root),
            HashPart::Str(bond_failure_root),
            HashPart::Str(bool_str(slash_settled)),
            HashPart::Str(bool_str(settlement_hold_required)),
        ],
        32,
    )
}

pub fn release_holdback_root(
    bond_holdback_root: &str,
    settlement_receipt_root: &str,
    watcher_status_root: &str,
    release_blocks: bool,
    settlement_hold_required: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-RELEASE-HOLDBACK",
        &[
            HashPart::Str(bond_holdback_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(watcher_status_root),
            HashPart::Str(bool_str(release_blocks)),
            HashPart::Str(bool_str(settlement_hold_required)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn slashing_settlement_observation_root(
    status: SlashingSettlementObservationStatus,
    requirement_id: &str,
    slash_decision_id: &str,
    bond_account_root: &str,
    settlement_root: &str,
    settlement_receipt_root: &str,
    release_holdback_root: &str,
    slash_settled: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-OBSERVATION",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(slash_decision_id),
            HashPart::Str(bond_account_root),
            HashPart::Str(settlement_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(release_holdback_root),
            HashPart::Str(bool_str(slash_settled)),
        ],
        32,
    )
}

pub fn slashing_settlement_observation_id(
    requirement_id: &str,
    slash_decision_id: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-OBSERVATION-ID",
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
    status: SlashingSettlementObservationStatus,
    slash_settled: bool,
    settlement_receipt_root: &str,
    release_holdback_root: &str,
    settlement_hold_required: bool,
    response_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-RESPONSE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(slash_settled)),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(release_holdback_root),
            HashPart::Str(bool_str(settlement_hold_required)),
            HashPart::Str(response_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn settlement_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_blocks: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-FAILURE",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_blocks),
        ],
        32,
    )
}

pub fn settlement_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-FAILURE-ID",
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
    bond_pool_state_root: &str,
    bond_pool_report_root: &str,
    slashing_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-SOURCE",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(bond_pool_state_root),
            HashPart::Str(bond_pool_report_root),
            HashPart::Str(slashing_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: SlashingSettlementAdapterReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-REPORT",
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

pub fn slashing_settlement_adapter_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-SLASHING-SETTLEMENT-RECORD",
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
