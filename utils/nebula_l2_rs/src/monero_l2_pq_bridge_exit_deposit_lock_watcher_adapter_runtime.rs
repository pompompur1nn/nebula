use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_gate_runtime::FinalReleaseGateStatus,
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
pub type MoneroL2PqBridgeExitDepositLockWatcherAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_DEPOSIT_LOCK_WATCHER_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-deposit-lock-watcher-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_DEPOSIT_LOCK_WATCHER_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEPOSIT_LOCK_WATCHER_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-deposit-lock-watcher-adapter-v1";
pub const DEFAULT_MIN_DEPOSIT_OBSERVATIONS: u64 = 15;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_500_100;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositObservationStatus {
    Confirmed,
    Deferred,
    Rejected,
}

impl DepositObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositLockAdapterReportStatus {
    Passed,
    Watch,
    Failed,
}

impl DepositLockAdapterReportStatus {
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
    pub min_deposit_observations: u64,
    pub min_confirmations: u64,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub base_monero_height: u64,
    pub live_watcher_enabled: bool,
    pub fail_closed_on_quorum_gap: bool,
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
            adapter_suite: DEPOSIT_LOCK_WATCHER_ADAPTER_SUITE.to_string(),
            min_deposit_observations: DEFAULT_MIN_DEPOSIT_OBSERVATIONS,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            live_watcher_enabled: false,
            fail_closed_on_quorum_gap: true,
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
            "min_deposit_observations": self.min_deposit_observations,
            "min_confirmations": self.min_confirmations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "base_monero_height": self.base_monero_height,
            "live_watcher_enabled": self.live_watcher_enabled,
            "fail_closed_on_quorum_gap": self.fail_closed_on_quorum_gap,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockObservation {
    pub observation_id: String,
    pub status: DepositObservationStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub lock_txid: String,
    pub amount_commitment_root: String,
    pub deposit_commitment_root: String,
    pub watcher_quorum_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub observed_depth: u64,
    pub observed_monero_height: u64,
    pub user_fee_bps: u64,
    pub certificate_root: String,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl DepositLockObservation {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        ordinal: u64,
    ) -> Self {
        let lock_txid = deposit_lock_txid(&requirement.fixture_root, &requirement.vector_id);
        let amount_commitment_root =
            amount_commitment_root(&requirement.fixture_root, &requirement.adapter_input_root);
        let deposit_commitment_root = deposit_commitment_root(
            &requirement.requirement_id,
            &amount_commitment_root,
            &requirement.release_claim_id,
        );
        let watcher_quorum_root = watcher_quorum_root(&requirement.readiness_root, ordinal);
        let pq_authorization_root = pq_authorization_root(
            &requirement.fixture_root,
            &requirement.release_claim_id,
            ordinal,
        );
        let privacy_set_size = privacy_set_size(config, requirement.expected_final_status, ordinal);
        let observed_depth = if config.live_watcher_enabled {
            config.min_confirmations + ordinal % 4
        } else {
            0
        };
        let observed_monero_height = config.base_monero_height + ordinal;
        let user_fee_bps = user_fee_bps(config, requirement.expected_final_status, ordinal);
        let status = observation_status(
            config,
            requirement.status,
            observed_depth,
            privacy_set_size,
            user_fee_bps,
        );
        let certificate_root = deposit_certificate_root(
            &lock_txid,
            &watcher_quorum_root,
            observed_depth,
            observed_monero_height,
            &pq_authorization_root,
        );
        let observation_root = deposit_observation_root(
            status,
            &requirement.requirement_id,
            &lock_txid,
            &amount_commitment_root,
            &watcher_quorum_root,
            observed_depth,
            privacy_set_size,
            user_fee_bps,
        );
        let observation_id =
            deposit_observation_id(&requirement.requirement_id, &lock_txid, &observation_root);
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
            lock_txid,
            amount_commitment_root,
            deposit_commitment_root,
            watcher_quorum_root,
            pq_authorization_root,
            privacy_set_size,
            observed_depth,
            observed_monero_height,
            user_fee_bps,
            certificate_root,
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
            "lock_txid": self.lock_txid,
            "amount_commitment_root": self.amount_commitment_root,
            "deposit_commitment_root": self.deposit_commitment_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "observed_depth": self.observed_depth,
            "observed_monero_height": self.observed_monero_height,
            "user_fee_bps": self.user_fee_bps,
            "certificate_root": self.certificate_root,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_lock_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: DepositObservationStatus,
    pub lock_confirmed: bool,
    pub watcher_certificate_root: String,
    pub mint_authorization_root: String,
    pub credit_hold_required: bool,
    pub adapter_root: String,
    pub finality_label: String,
}

impl DepositLockAdapterResponse {
    pub fn from_observation(config: &Config, observation: &DepositLockObservation) -> Self {
        let lock_confirmed = config.live_watcher_enabled
            && observation.status == DepositObservationStatus::Confirmed;
        let credit_hold_required = !lock_confirmed;
        let finality_label = finality_label(config, observation).to_string();
        let mint_authorization_root = mint_authorization_root(
            &observation.deposit_commitment_root,
            &observation.certificate_root,
            &observation.pq_authorization_root,
            lock_confirmed,
        );
        let adapter_root = adapter_response_root(
            observation.status,
            lock_confirmed,
            &observation.certificate_root,
            &mint_authorization_root,
            credit_hold_required,
            &finality_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            lock_confirmed,
            watcher_certificate_root: observation.certificate_root.clone(),
            mint_authorization_root,
            credit_hold_required,
            adapter_root,
            finality_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "observation_id": self.observation_id,
            "status": self.status.as_str(),
            "lock_confirmed": self.lock_confirmed,
            "watcher_certificate_root": self.watcher_certificate_root,
            "mint_authorization_root": self.mint_authorization_root,
            "credit_hold_required": self.credit_hold_required,
            "adapter_root": self.adapter_root,
            "finality_label": self.finality_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_lock_adapter_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_height: u64,
}

impl DepositLockFailureSurface {
    pub fn from_observation(config: &Config, observation: &DepositLockObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let quorum_gap = observation.status == DepositObservationStatus::Rejected;
        let quarantine_required = config.fail_closed_on_quorum_gap && quorum_gap;
        let retry_after_height = observation.observed_monero_height + config.min_confirmations;
        let failure_root = deposit_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_height,
        );
        let failure_id = deposit_failure_id(&observation.observation_id, &failure_root);
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
        record_root("deposit_lock_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockAdapterReport {
    pub report_id: String,
    pub status: DepositLockAdapterReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub deposit_stub_id: String,
    pub deposit_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub observations_total: u64,
    pub observations_confirmed: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub locks_confirmed: u64,
    pub credit_holds_required: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, DepositLockObservation>,
    pub responses: BTreeMap<String, DepositLockAdapterResponse>,
    pub failures: BTreeMap<String, DepositLockFailureSurface>,
    pub roots: DepositLockAdapterReportRoots,
}

impl DepositLockAdapterReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(DepositLockObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(DepositLockAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(DepositLockFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "deposit_stub_id": self.deposit_stub_id,
            "deposit_stub_status": self.deposit_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "observations_total": self.observations_total,
            "observations_confirmed": self.observations_confirmed,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "locks_confirmed": self.locks_confirmed,
            "credit_holds_required": self.credit_holds_required,
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
pub struct DepositLockAdapterReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl DepositLockAdapterReportRoots {
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
    pub observations_confirmed: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub locks_confirmed: u64,
    pub credit_holds_required: u64,
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
            "observations_confirmed": self.observations_confirmed,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "locks_confirmed": self.locks_confirmed,
            "credit_holds_required": self.credit_holds_required,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-ADAPTER-STATE",
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
    pub latest_report: Option<DepositLockAdapterReport>,
    pub report_history: Vec<DepositLockAdapterReport>,
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
        state
            .process_deposit_lock_adapter(&matrix, &stub_registry)
            .expect("devnet bridge exit deposit lock watcher adapter");
        state
    }

    pub fn process_deposit_lock_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let deposit_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::DepositLockWatcher)
            .ok_or_else(|| "deposit lock watcher adapter stub is missing".to_string())?;
        let deposit_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::DepositLockWatcher)
            .collect::<Vec<_>>();
        ensure(
            deposit_requirements.len() as u64 >= self.config.min_deposit_observations,
            "deposit lock watcher adapter omitted required fixture observations",
        )?;
        let observations = deposit_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                DepositLockObservation::from_requirement(&self.config, *requirement, index as u64)
            })
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| {
                DepositLockAdapterResponse::from_observation(&self.config, observation)
            })
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                DepositLockFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_confirmed = observations
            .values()
            .filter(|observation| observation.status == DepositObservationStatus::Confirmed)
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| observation.status == DepositObservationStatus::Deferred)
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| observation.status == DepositObservationStatus::Rejected)
            .count() as u64;
        let locks_confirmed = responses
            .values()
            .filter(|response| response.lock_confirmed)
            .count() as u64;
        let credit_holds_required = responses
            .values()
            .filter(|response| response.credit_hold_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            deposit_stub,
            observations_deferred,
            observations_rejected,
            credit_holds_required,
            self.config.live_watcher_enabled,
        );
        let readiness_label = readiness_label(
            status,
            deposit_stub.status,
            self.config.live_watcher_enabled,
        )
        .to_string();
        let observation_records = observations
            .values()
            .map(DepositLockObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(DepositLockAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(DepositLockFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &deposit_stub.stub_id,
            &deposit_stub.request_schema_root,
            &deposit_stub.response_schema_root,
            &deposit_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &observation_root,
            &response_root,
            &failure_root,
            &matrix_report.release_claim_id,
        );
        let report_id =
            deposit_lock_watcher_report_id(&matrix_report.release_claim_id, &report_root);
        let report = DepositLockAdapterReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            deposit_stub_id: deposit_stub.stub_id.clone(),
            deposit_stub_status: deposit_stub.status,
            release_claim_id: matrix_report.release_claim_id.clone(),
            observations_total,
            observations_confirmed,
            observations_deferred,
            observations_rejected,
            locks_confirmed,
            credit_holds_required,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: DepositLockAdapterReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(DepositLockAdapterReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: DepositLockAdapterReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_confirmed += report.observations_confirmed;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.locks_confirmed += report.locks_confirmed;
        self.counters.credit_holds_required += report.credit_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            DepositLockAdapterReportStatus::Passed => self.counters.reports_passed += 1,
            DepositLockAdapterReportStatus::Watch => self.counters.reports_watch += 1,
            DepositLockAdapterReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(DepositLockAdapterReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn privacy_set_size(config: &Config, final_status: FinalReleaseGateStatus, ordinal: u64) -> u64 {
    if final_status == FinalReleaseGateStatus::Failed {
        config.min_privacy_set_size.saturating_sub(1)
    } else {
        config.min_privacy_set_size + ordinal
    }
}

fn user_fee_bps(config: &Config, final_status: FinalReleaseGateStatus, ordinal: u64) -> u64 {
    if final_status == FinalReleaseGateStatus::Failed {
        config.max_user_fee_bps + 1
    } else {
        config.max_user_fee_bps.saturating_sub(ordinal % 5)
    }
}

fn observation_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    observed_depth: u64,
    privacy_set_size: u64,
    user_fee_bps: u64,
) -> DepositObservationStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || privacy_set_size < config.min_privacy_set_size
        || user_fee_bps > config.max_user_fee_bps
    {
        DepositObservationStatus::Rejected
    } else if !config.live_watcher_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || observed_depth < config.min_confirmations
    {
        DepositObservationStatus::Deferred
    } else {
        DepositObservationStatus::Confirmed
    }
}

fn report_status(
    deposit_stub: &LiveAdapterStub,
    observations_deferred: u64,
    observations_rejected: u64,
    credit_holds_required: u64,
    live_watcher_enabled: bool,
) -> DepositLockAdapterReportStatus {
    if observations_rejected > 0 || deposit_stub.status == AdapterStubStatus::Blocked {
        DepositLockAdapterReportStatus::Failed
    } else if observations_deferred > 0
        || credit_holds_required > 0
        || deposit_stub.status == AdapterStubStatus::Deferred
        || !live_watcher_enabled
    {
        DepositLockAdapterReportStatus::Watch
    } else {
        DepositLockAdapterReportStatus::Passed
    }
}

fn readiness_label(
    status: DepositLockAdapterReportStatus,
    deposit_stub_status: AdapterStubStatus,
    live_watcher_enabled: bool,
) -> &'static str {
    match status {
        DepositLockAdapterReportStatus::Failed => "deposit_lock_watcher_adapter_failed",
        DepositLockAdapterReportStatus::Watch if !live_watcher_enabled => {
            "deposit_lock_watcher_adapter_watch_live_feed_deferred"
        }
        DepositLockAdapterReportStatus::Watch
            if deposit_stub_status == AdapterStubStatus::Deferred =>
        {
            "deposit_lock_watcher_adapter_watch_stub_deferred"
        }
        DepositLockAdapterReportStatus::Watch => "deposit_lock_watcher_adapter_watch",
        DepositLockAdapterReportStatus::Passed => "deposit_lock_watcher_adapter_ready",
    }
}

fn finality_label(config: &Config, observation: &DepositLockObservation) -> &'static str {
    if observation.privacy_set_size < config.min_privacy_set_size {
        "privacy_floor_rejected"
    } else if observation.user_fee_bps > config.max_user_fee_bps {
        "fee_cap_rejected"
    } else if observation.observed_depth >= config.min_confirmations {
        "deposit_lock_confirmed"
    } else {
        "watcher_depth_deferred"
    }
}

fn error_code(config: &Config, observation: &DepositLockObservation) -> &'static str {
    if observation.privacy_set_size < config.min_privacy_set_size {
        "privacy_set_below_floor"
    } else if observation.user_fee_bps > config.max_user_fee_bps {
        "user_fee_above_cap"
    } else if !config.live_watcher_enabled {
        "live_deposit_lock_watcher_deferred"
    } else if observation.observed_depth < config.min_confirmations {
        "insufficient_lock_depth"
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

pub fn deposit_lock_txid(fixture_root: &str, vector_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-TXID",
        &[HashPart::Str(fixture_root), HashPart::Str(vector_id)],
        32,
    )
}

pub fn amount_commitment_root(fixture_root: &str, adapter_input_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-AMOUNT-COMMITMENT-ROOT",
        &[
            HashPart::Str(fixture_root),
            HashPart::Str(adapter_input_root),
        ],
        32,
    )
}

pub fn deposit_commitment_root(
    requirement_id: &str,
    amount_commitment_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-COMMITMENT-ROOT",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(amount_commitment_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn watcher_quorum_root(readiness_root: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-WATCHER-QUORUM-ROOT",
        &[HashPart::Str(readiness_root), HashPart::U64(ordinal)],
        32,
    )
}

pub fn pq_authorization_root(fixture_root: &str, release_claim_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-PQ-AUTHORIZATION-ROOT",
        &[
            HashPart::Str(fixture_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

pub fn deposit_certificate_root(
    lock_txid: &str,
    watcher_quorum_root: &str,
    observed_depth: u64,
    observed_monero_height: u64,
    pq_authorization_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-CERTIFICATE-ROOT",
        &[
            HashPart::Str(lock_txid),
            HashPart::Str(watcher_quorum_root),
            HashPart::U64(observed_depth),
            HashPart::U64(observed_monero_height),
            HashPart::Str(pq_authorization_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn deposit_observation_root(
    status: DepositObservationStatus,
    requirement_id: &str,
    lock_txid: &str,
    amount_commitment_root: &str,
    watcher_quorum_root: &str,
    observed_depth: u64,
    privacy_set_size: u64,
    user_fee_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-OBSERVATION-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(lock_txid),
            HashPart::Str(amount_commitment_root),
            HashPart::Str(watcher_quorum_root),
            HashPart::U64(observed_depth),
            HashPart::U64(privacy_set_size),
            HashPart::U64(user_fee_bps),
        ],
        32,
    )
}

pub fn deposit_observation_id(
    requirement_id: &str,
    lock_txid: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-OBSERVATION-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(lock_txid),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

pub fn mint_authorization_root(
    deposit_commitment_root: &str,
    certificate_root: &str,
    pq_authorization_root: &str,
    lock_confirmed: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-MINT-AUTHORIZATION-ROOT",
        &[
            HashPart::Str(deposit_commitment_root),
            HashPart::Str(certificate_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(bool_str(lock_confirmed)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: DepositObservationStatus,
    lock_confirmed: bool,
    watcher_certificate_root: &str,
    mint_authorization_root: &str,
    credit_hold_required: bool,
    finality_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-ADAPTER-RESPONSE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(lock_confirmed)),
            HashPart::Str(watcher_certificate_root),
            HashPart::Str(mint_authorization_root),
            HashPart::Str(bool_str(credit_hold_required)),
            HashPart::Str(finality_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-ADAPTER-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn deposit_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-FAILURE-ROOT",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_height),
        ],
        32,
    )
}

pub fn deposit_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-FAILURE-ID",
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
    deposit_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-ADAPTER-SOURCE-ROOT",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(deposit_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: DepositLockAdapterReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-ADAPTER-REPORT-ROOT",
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

pub fn deposit_lock_watcher_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-ADAPTER-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DEPOSIT-LOCK-WATCHER-ADAPTER-RECORD",
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
