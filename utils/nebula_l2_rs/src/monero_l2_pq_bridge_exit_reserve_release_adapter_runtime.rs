use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::{
        LiquidityReleaseReportStatus, ReleaseDecisionStatus, ReserveAccount, ReserveAccountStatus,
        State as LiquidityReleaseState,
    },
    monero_l2_pq_bridge_exit_live_adapter_readiness_matrix_runtime::{
        AdapterReadinessStatus, LiveAdapterKind, LiveAdapterRequirement,
        State as LiveAdapterMatrixState,
    },
    monero_l2_pq_bridge_exit_live_adapter_stub_registry_runtime::{
        AdapterStubStatus, LiveAdapterStub, State as LiveAdapterStubRegistryState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReserveReleaseAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_RESERVE_RELEASE_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-reserve-release-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_RESERVE_RELEASE_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RESERVE_RELEASE_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-reserve-release-adapter-v1";
pub const DEFAULT_MIN_RESERVE_OBSERVATIONS: u64 = 15;
pub const DEFAULT_MIN_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_UTILIZATION_BPS: u64 = 8_500;
pub const DEFAULT_MAX_RELEASE_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveReleaseObservationStatus {
    Authorized,
    Deferred,
    Rejected,
}

impl ReserveReleaseObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveReleaseAdapterReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ReserveReleaseAdapterReportStatus {
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
    pub min_reserve_observations: u64,
    pub min_coverage_bps: u64,
    pub max_utilization_bps: u64,
    pub max_release_fee_bps: u64,
    pub live_reserve_adapter_enabled: bool,
    pub fail_closed_on_liquidity_gap: bool,
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
            adapter_suite: RESERVE_RELEASE_ADAPTER_SUITE.to_string(),
            min_reserve_observations: DEFAULT_MIN_RESERVE_OBSERVATIONS,
            min_coverage_bps: DEFAULT_MIN_COVERAGE_BPS,
            max_utilization_bps: DEFAULT_MAX_UTILIZATION_BPS,
            max_release_fee_bps: DEFAULT_MAX_RELEASE_FEE_BPS,
            live_reserve_adapter_enabled: false,
            fail_closed_on_liquidity_gap: true,
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
            "min_reserve_observations": self.min_reserve_observations,
            "min_coverage_bps": self.min_coverage_bps,
            "max_utilization_bps": self.max_utilization_bps,
            "max_release_fee_bps": self.max_release_fee_bps,
            "live_reserve_adapter_enabled": self.live_reserve_adapter_enabled,
            "fail_closed_on_liquidity_gap": self.fail_closed_on_liquidity_gap,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveReleaseObservation {
    pub observation_id: String,
    pub status: ReserveReleaseObservationStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub reserve_account_id: String,
    pub reserve_account_root: String,
    pub release_claim_root: String,
    pub coverage_root: String,
    pub backstop_root: String,
    pub reserve_movement_root: String,
    pub requested_amount: u128,
    pub available_liquidity: u128,
    pub allocated_amount: u128,
    pub reserve_after_release: u128,
    pub coverage_bps: u64,
    pub utilization_bps: u64,
    pub fee_bps: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub liquidity_report_status: LiquidityReleaseReportStatus,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl ReserveReleaseObservation {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        liquidity_report: &crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::LiquidityReleaseReport,
        account: &ReserveAccount,
        ordinal: u64,
    ) -> Self {
        let requested_amount = liquidity_report.requested_amount;
        let available_liquidity = account.available_liquidity() + account.emergency_liquidity;
        let allocated_amount = available_liquidity.min(requested_amount);
        let reserve_after_release = available_liquidity.saturating_sub(allocated_amount);
        let coverage_bps = if liquidity_report.status == LiquidityReleaseReportStatus::Failed {
            config.min_coverage_bps.saturating_sub(1)
        } else {
            liquidity_report
                .effective_coverage_bps
                .max(account.coverage_bps)
        };
        let utilization_bps = bps(allocated_amount, account.committed_liquidity.max(1));
        let fee_bps = (ordinal % (config.max_release_fee_bps + 1)).min(config.max_release_fee_bps);
        let reserve_account_root = account.state_root();
        let release_claim_root = liquidity_report.release_claim.state_root();
        let coverage_root = coverage_root(
            &requirement.release_claim_id,
            &reserve_account_root,
            coverage_bps,
            utilization_bps,
            liquidity_report.release_blockers,
        );
        let backstop_root = backstop_root(
            &liquidity_report.roots.blocker_root,
            &account.privacy_bucket_root,
            account.emergency_liquidity,
            liquidity_report.production_blockers,
        );
        let reserve_movement_root = reserve_movement_root(
            &requirement.release_claim_id,
            &account.account_id,
            allocated_amount,
            reserve_after_release,
            &coverage_root,
            &backstop_root,
        );
        let status = observation_status(
            config,
            requirement.status,
            liquidity_report.status,
            account.status,
            coverage_bps,
            utilization_bps,
            liquidity_report.release_blockers,
            fee_bps,
        );
        let observation_root = reserve_observation_root(
            status,
            &requirement.requirement_id,
            &requirement.release_claim_id,
            &reserve_account_root,
            &coverage_root,
            &reserve_movement_root,
            coverage_bps,
            utilization_bps,
        );
        let observation_id = reserve_observation_id(
            &requirement.requirement_id,
            &requirement.release_claim_id,
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
            reserve_account_id: account.account_id.clone(),
            reserve_account_root,
            release_claim_root,
            coverage_root,
            backstop_root,
            reserve_movement_root,
            requested_amount,
            available_liquidity,
            allocated_amount,
            reserve_after_release,
            coverage_bps,
            utilization_bps,
            fee_bps,
            release_blockers: liquidity_report.release_blockers,
            production_blockers: liquidity_report.production_blockers,
            liquidity_report_status: liquidity_report.status,
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
            "reserve_account_id": self.reserve_account_id,
            "reserve_account_root": self.reserve_account_root,
            "release_claim_root": self.release_claim_root,
            "coverage_root": self.coverage_root,
            "backstop_root": self.backstop_root,
            "reserve_movement_root": self.reserve_movement_root,
            "requested_amount": self.requested_amount.to_string(),
            "available_liquidity": self.available_liquidity.to_string(),
            "allocated_amount": self.allocated_amount.to_string(),
            "reserve_after_release": self.reserve_after_release.to_string(),
            "coverage_bps": self.coverage_bps,
            "utilization_bps": self.utilization_bps,
            "fee_bps": self.fee_bps,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "liquidity_report_status": self.liquidity_report_status.as_str(),
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve_release_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveReleaseAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: ReserveReleaseObservationStatus,
    pub release_authorized: bool,
    pub coverage_root: String,
    pub reserve_movement_root: String,
    pub release_hold_required: bool,
    pub adapter_root: String,
    pub release_label: String,
}

impl ReserveReleaseAdapterResponse {
    pub fn from_observation(config: &Config, observation: &ReserveReleaseObservation) -> Self {
        let release_authorized = config.live_reserve_adapter_enabled
            && observation.status == ReserveReleaseObservationStatus::Authorized;
        let release_hold_required = !release_authorized;
        let release_label = release_label(config, observation).to_string();
        let adapter_root = adapter_response_root(
            observation.status,
            release_authorized,
            &observation.coverage_root,
            &observation.reserve_movement_root,
            release_hold_required,
            &release_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            release_authorized,
            coverage_root: observation.coverage_root.clone(),
            reserve_movement_root: observation.reserve_movement_root.clone(),
            release_hold_required,
            adapter_root,
            release_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "release_authorized": self.release_authorized,
            "coverage_root": self.coverage_root,
            "reserve_movement_root": self.reserve_movement_root,
            "release_hold_required": self.release_hold_required,
            "adapter_root": self.adapter_root,
            "release_label": self.release_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve_release_adapter_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveReleaseFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_height: u64,
}

impl ReserveReleaseFailureSurface {
    pub fn from_observation(config: &Config, observation: &ReserveReleaseObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let quarantine_required = observation.status == ReserveReleaseObservationStatus::Rejected
            && config.fail_closed_on_liquidity_gap;
        let retry_after_height = observation.production_blockers
            + observation.release_blockers
            + config.min_reserve_observations;
        let failure_root = reserve_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_height,
        );
        let failure_id = reserve_failure_id(&observation.observation_id, &failure_root);
        Self {
            failure_id,
            observation_id: observation.observation_id.clone(),
            error_code,
            failure_root,
            quarantine_required,
            retry_after_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "failure_id": self.failure_id,
            "observation_id": self.observation_id,
            "error_code": self.error_code,
            "failure_root": self.failure_root,
            "quarantine_required": self.quarantine_required,
            "retry_after_height": self.retry_after_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve_release_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveReleaseAdapterReport {
    pub report_id: String,
    pub status: ReserveReleaseAdapterReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub liquidity_release_state_root: String,
    pub liquidity_release_report_root: String,
    pub reserve_stub_id: String,
    pub reserve_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub observations_total: u64,
    pub observations_authorized: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub releases_authorized: u64,
    pub release_holds_required: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, ReserveReleaseObservation>,
    pub responses: BTreeMap<String, ReserveReleaseAdapterResponse>,
    pub failures: BTreeMap<String, ReserveReleaseFailureSurface>,
    pub roots: ReserveReleaseAdapterReportRoots,
}

impl ReserveReleaseAdapterReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(ReserveReleaseObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(ReserveReleaseAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(ReserveReleaseFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "liquidity_release_state_root": self.liquidity_release_state_root,
            "liquidity_release_report_root": self.liquidity_release_report_root,
            "reserve_stub_id": self.reserve_stub_id,
            "reserve_stub_status": self.reserve_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "observations_total": self.observations_total,
            "observations_authorized": self.observations_authorized,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "releases_authorized": self.releases_authorized,
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
pub struct ReserveReleaseAdapterReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl ReserveReleaseAdapterReportRoots {
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
    pub observations_authorized: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub releases_authorized: u64,
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
            "observations_authorized": self.observations_authorized,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "releases_authorized": self.releases_authorized,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-STATE",
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
    pub latest_report: Option<ReserveReleaseAdapterReport>,
    pub report_history: Vec<ReserveReleaseAdapterReport>,
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
        let liquidity_release =
            crate::monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime::devnet();
        state
            .process_reserve_release_adapter(&matrix, &stub_registry, &liquidity_release)
            .expect("devnet bridge exit reserve release adapter");
        state
    }

    pub fn process_reserve_release_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        liquidity_release: &LiquidityReleaseState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let liquidity_report = liquidity_release
            .latest_report
            .as_ref()
            .ok_or_else(|| "liquidity release state has no latest report".to_string())?;
        let reserve_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::ReserveRelease)
            .ok_or_else(|| "reserve release adapter stub is missing".to_string())?;
        let reserve_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::ReserveRelease)
            .collect::<Vec<_>>();
        ensure(
            reserve_requirements.len() as u64 >= self.config.min_reserve_observations,
            "reserve release adapter omitted required fixture observations",
        )?;
        let accounts = liquidity_report
            .reserve_accounts
            .values()
            .collect::<Vec<_>>();
        ensure(
            !accounts.is_empty(),
            "liquidity release report has no reserve accounts",
        )?;
        let observations = reserve_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                let account = accounts[index % accounts.len()];
                ReserveReleaseObservation::from_requirement(
                    &self.config,
                    *requirement,
                    liquidity_report,
                    account,
                    index as u64,
                )
            })
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| {
                ReserveReleaseAdapterResponse::from_observation(&self.config, observation)
            })
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                ReserveReleaseFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_authorized = observations
            .values()
            .filter(|observation| observation.status == ReserveReleaseObservationStatus::Authorized)
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| observation.status == ReserveReleaseObservationStatus::Deferred)
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| observation.status == ReserveReleaseObservationStatus::Rejected)
            .count() as u64;
        let releases_authorized = responses
            .values()
            .filter(|response| response.release_authorized)
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
            reserve_stub,
            observations_deferred,
            observations_rejected,
            release_holds_required,
            self.config.live_reserve_adapter_enabled,
        );
        let readiness_label = readiness_label(
            status,
            reserve_stub.status,
            self.config.live_reserve_adapter_enabled,
        )
        .to_string();
        let observation_records = observations
            .values()
            .map(ReserveReleaseObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(ReserveReleaseAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(ReserveReleaseFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &liquidity_release.state_root(),
            &liquidity_report.state_root(),
            &reserve_stub.stub_id,
            &reserve_stub.request_schema_root,
            &reserve_stub.response_schema_root,
            &reserve_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &observation_root,
            &response_root,
            &failure_root,
            &liquidity_report.release_claim_id,
        );
        let report_id =
            reserve_release_adapter_report_id(&liquidity_report.release_claim_id, &report_root);
        let report = ReserveReleaseAdapterReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            liquidity_release_state_root: liquidity_release.state_root(),
            liquidity_release_report_root: liquidity_report.state_root(),
            reserve_stub_id: reserve_stub.stub_id.clone(),
            reserve_stub_status: reserve_stub.status,
            release_claim_id: liquidity_report.release_claim_id.clone(),
            observations_total,
            observations_authorized,
            observations_deferred,
            observations_rejected,
            releases_authorized,
            release_holds_required,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: ReserveReleaseAdapterReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(ReserveReleaseAdapterReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: ReserveReleaseAdapterReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_authorized += report.observations_authorized;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.releases_authorized += report.releases_authorized;
        self.counters.release_holds_required += report.release_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            ReserveReleaseAdapterReportStatus::Passed => self.counters.reports_passed += 1,
            ReserveReleaseAdapterReportStatus::Watch => self.counters.reports_watch += 1,
            ReserveReleaseAdapterReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(ReserveReleaseAdapterReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-REPORTS",
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
    liquidity_status: LiquidityReleaseReportStatus,
    account_status: ReserveAccountStatus,
    coverage_bps: u64,
    utilization_bps: u64,
    release_blockers: u64,
    fee_bps: u64,
) -> ReserveReleaseObservationStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || liquidity_status == LiquidityReleaseReportStatus::Failed
        || account_status == ReserveAccountStatus::Exhausted
        || coverage_bps < config.min_coverage_bps
        || utilization_bps > config.max_utilization_bps
        || release_blockers > 0
        || fee_bps > config.max_release_fee_bps
    {
        ReserveReleaseObservationStatus::Rejected
    } else if !config.live_reserve_adapter_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || liquidity_status == LiquidityReleaseReportStatus::Watch
        || account_status == ReserveAccountStatus::Watch
    {
        ReserveReleaseObservationStatus::Deferred
    } else {
        ReserveReleaseObservationStatus::Authorized
    }
}

fn report_status(
    reserve_stub: &LiveAdapterStub,
    observations_deferred: u64,
    observations_rejected: u64,
    release_holds_required: u64,
    live_reserve_adapter_enabled: bool,
) -> ReserveReleaseAdapterReportStatus {
    if observations_rejected > 0 || reserve_stub.status == AdapterStubStatus::Blocked {
        ReserveReleaseAdapterReportStatus::Failed
    } else if observations_deferred > 0
        || release_holds_required > 0
        || reserve_stub.status == AdapterStubStatus::Deferred
        || !live_reserve_adapter_enabled
    {
        ReserveReleaseAdapterReportStatus::Watch
    } else {
        ReserveReleaseAdapterReportStatus::Passed
    }
}

fn readiness_label(
    status: ReserveReleaseAdapterReportStatus,
    reserve_stub_status: AdapterStubStatus,
    live_reserve_adapter_enabled: bool,
) -> &'static str {
    match status {
        ReserveReleaseAdapterReportStatus::Failed => "reserve_release_adapter_failed",
        ReserveReleaseAdapterReportStatus::Watch if !live_reserve_adapter_enabled => {
            "reserve_release_adapter_watch_live_adapter_deferred"
        }
        ReserveReleaseAdapterReportStatus::Watch
            if reserve_stub_status == AdapterStubStatus::Deferred =>
        {
            "reserve_release_adapter_watch_stub_deferred"
        }
        ReserveReleaseAdapterReportStatus::Watch => "reserve_release_adapter_watch",
        ReserveReleaseAdapterReportStatus::Passed => "reserve_release_adapter_ready",
    }
}

fn release_label(config: &Config, observation: &ReserveReleaseObservation) -> &'static str {
    if observation.coverage_bps < config.min_coverage_bps {
        "coverage_below_minimum"
    } else if observation.utilization_bps > config.max_utilization_bps {
        "reserve_utilization_too_high"
    } else if observation.release_blockers > 0 {
        "release_blocker_present"
    } else if observation.liquidity_report_status == LiquidityReleaseReportStatus::Watch {
        "liquidity_release_watch"
    } else if observation.status == ReserveReleaseObservationStatus::Authorized {
        "reserve_release_authorized"
    } else {
        "reserve_release_deferred"
    }
}

fn error_code(config: &Config, observation: &ReserveReleaseObservation) -> &'static str {
    if observation.coverage_bps < config.min_coverage_bps {
        "coverage_below_minimum"
    } else if observation.utilization_bps > config.max_utilization_bps {
        "reserve_utilization_above_cap"
    } else if observation.release_blockers > 0 {
        "release_blocker_present"
    } else if observation.liquidity_report_status == LiquidityReleaseReportStatus::Failed {
        "liquidity_release_failed"
    } else if !config.live_reserve_adapter_enabled {
        "live_reserve_release_adapter_deferred"
    } else if observation.liquidity_report_status == LiquidityReleaseReportStatus::Watch {
        "liquidity_release_watch"
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

pub fn bps(numerator: u128, denominator: u128) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator
            .saturating_mul(10_000)
            .saturating_div(denominator)
            .min(u64::MAX as u128) as u64
    }
}

#[allow(clippy::too_many_arguments)]
pub fn coverage_root(
    release_claim_id: &str,
    reserve_account_root: &str,
    coverage_bps: u64,
    utilization_bps: u64,
    release_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-COVERAGE-ROOT",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(reserve_account_root),
            HashPart::U64(coverage_bps),
            HashPart::U64(utilization_bps),
            HashPart::U64(release_blockers),
        ],
        32,
    )
}

pub fn backstop_root(
    blocker_root: &str,
    privacy_bucket_root: &str,
    emergency_liquidity: u128,
    production_blockers: u64,
) -> String {
    let emergency_liquidity = emergency_liquidity.to_string();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-BACKSTOP-ROOT",
        &[
            HashPart::Str(blocker_root),
            HashPart::Str(privacy_bucket_root),
            HashPart::Str(&emergency_liquidity),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

pub fn reserve_movement_root(
    release_claim_id: &str,
    reserve_account_id: &str,
    allocated_amount: u128,
    reserve_after_release: u128,
    coverage_root: &str,
    backstop_root: &str,
) -> String {
    let allocated_amount = allocated_amount.to_string();
    let reserve_after_release = reserve_after_release.to_string();
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-MOVEMENT-ROOT",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(reserve_account_id),
            HashPart::Str(&allocated_amount),
            HashPart::Str(&reserve_after_release),
            HashPart::Str(coverage_root),
            HashPart::Str(backstop_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn reserve_observation_root(
    status: ReserveReleaseObservationStatus,
    requirement_id: &str,
    release_claim_id: &str,
    reserve_account_root: &str,
    coverage_root: &str,
    reserve_movement_root: &str,
    coverage_bps: u64,
    utilization_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-OBSERVATION-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(reserve_account_root),
            HashPart::Str(coverage_root),
            HashPart::Str(reserve_movement_root),
            HashPart::U64(coverage_bps),
            HashPart::U64(utilization_bps),
        ],
        32,
    )
}

pub fn reserve_observation_id(
    requirement_id: &str,
    release_claim_id: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-OBSERVATION-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: ReserveReleaseObservationStatus,
    release_authorized: bool,
    coverage_root: &str,
    reserve_movement_root: &str,
    release_hold_required: bool,
    release_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-RESPONSE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(release_authorized)),
            HashPart::Str(coverage_root),
            HashPart::Str(reserve_movement_root),
            HashPart::Str(bool_str(release_hold_required)),
            HashPart::Str(release_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn reserve_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-FAILURE-ROOT",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_height),
        ],
        32,
    )
}

pub fn reserve_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-FAILURE-ID",
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
    liquidity_release_state_root: &str,
    liquidity_release_report_root: &str,
    reserve_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-SOURCE-ROOT",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(liquidity_release_state_root),
            HashPart::Str(liquidity_release_report_root),
            HashPart::Str(reserve_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: ReserveReleaseAdapterReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-REPORT-ROOT",
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

pub fn reserve_release_adapter_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RESERVE-RELEASE-ADAPTER-RECORD",
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
