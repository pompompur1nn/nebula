use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReport, AuthorityTransferReportStatus,
        State as AuthorityTransferSecurityBundleState,
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
pub type MoneroL2PqBridgeExitPqAuthorityKeyManagerAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PQ_AUTHORITY_KEY_MANAGER_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-pq-authority-key-manager-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PQ_AUTHORITY_KEY_MANAGER_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTHORITY_KEY_MANAGER_ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-exit-pq-authority-key-manager-adapter-v1";
pub const DEFAULT_MIN_AUTHORITY_OBSERVATIONS: u64 = 15;
pub const DEFAULT_CURRENT_AUTHORITY_EPOCH: u64 = 42;
pub const DEFAULT_ROTATION_GRACE_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const DEFAULT_ROTATION_RETRY_EPOCHS: u64 = 1;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorityObservationStatus {
    Accepted,
    Deferred,
    Rejected,
}

impl PqAuthorityObservationStatus {
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
pub enum PqAuthorityKeyManagerReportStatus {
    Passed,
    Watch,
    Failed,
}

impl PqAuthorityKeyManagerReportStatus {
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
    pub min_authority_observations: u64,
    pub current_authority_epoch: u64,
    pub rotation_grace_epochs: u64,
    pub min_pq_security_bits: u64,
    pub rotation_retry_epochs: u64,
    pub live_pq_authority_enabled: bool,
    pub fail_closed_on_rotation_gap: bool,
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
            adapter_suite: PQ_AUTHORITY_KEY_MANAGER_ADAPTER_SUITE.to_string(),
            min_authority_observations: DEFAULT_MIN_AUTHORITY_OBSERVATIONS,
            current_authority_epoch: DEFAULT_CURRENT_AUTHORITY_EPOCH,
            rotation_grace_epochs: DEFAULT_ROTATION_GRACE_EPOCHS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            rotation_retry_epochs: DEFAULT_ROTATION_RETRY_EPOCHS,
            live_pq_authority_enabled: false,
            fail_closed_on_rotation_gap: true,
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
            "adapter_suite": self.adapter_suite,
            "min_authority_observations": self.min_authority_observations,
            "current_authority_epoch": self.current_authority_epoch,
            "rotation_grace_epochs": self.rotation_grace_epochs,
            "min_pq_security_bits": self.min_pq_security_bits,
            "rotation_retry_epochs": self.rotation_retry_epochs,
            "live_pq_authority_enabled": self.live_pq_authority_enabled,
            "fail_closed_on_rotation_gap": self.fail_closed_on_rotation_gap,
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
pub struct PqAuthorityObservation {
    pub observation_id: String,
    pub status: PqAuthorityObservationStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub authority_transfer_report_id: String,
    pub authority_transfer_status: AuthorityTransferReportStatus,
    pub authority_state_root: String,
    pub authority_report_root: String,
    pub security_bundle_state_root: String,
    pub security_bundle_report_root: String,
    pub authority_transfer_source_root: String,
    pub authority_transfer_check_root: String,
    pub transcript_root: String,
    pub authority_root: String,
    pub pq_signer_root: String,
    pub rotation_root: String,
    pub rotation_status_root: String,
    pub authority_epoch_root: String,
    pub signature_domain_root: String,
    pub verification_root: String,
    pub request_payload_root: String,
    pub authority_epoch: u64,
    pub current_authority_epoch: u64,
    pub rotation_grace_epochs: u64,
    pub pq_security_bits: u64,
    pub authority_fresh: bool,
    pub signature_required: bool,
    pub release_blocks: bool,
    pub production_blocks: bool,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub observation_root: String,
}

impl PqAuthorityObservation {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        authority_report: &AuthorityTransferReport,
        ordinal: u64,
    ) -> Self {
        let authority_epoch = authority_epoch_for(config, ordinal);
        let authority_fresh = authority_epoch.saturating_add(config.rotation_grace_epochs)
            >= config.current_authority_epoch;
        let pq_security_bits = config.min_pq_security_bits;
        let authority_root = authority_report.authority_state_root.clone();
        let pq_signer_root = pq_signer_root(
            &authority_report.authority_report_root,
            &authority_report.security_bundle_report_root,
            &requirement.release_claim_id,
            authority_epoch,
            pq_security_bits,
        );
        let rotation_root = rotation_root(
            &authority_root,
            &pq_signer_root,
            &authority_report.roots.source_root,
            authority_epoch,
            config.current_authority_epoch,
        );
        let rotation_status_root = rotation_status_root(
            authority_report.status,
            &rotation_root,
            authority_fresh,
            config.rotation_grace_epochs,
        );
        let authority_epoch_root = authority_epoch_root(
            &authority_root,
            &pq_signer_root,
            authority_epoch,
            config.current_authority_epoch,
            authority_fresh,
        );
        let signature_domain_root = signature_domain_root(
            &config.chain_id,
            &requirement.release_claim_id,
            &authority_report.scenario_id,
            &authority_report.transcript_root,
            authority_epoch,
        );
        let verification_root = verification_root(
            &authority_root,
            &pq_signer_root,
            &rotation_status_root,
            &authority_epoch_root,
            &signature_domain_root,
            pq_security_bits,
        );
        let request_payload_root = request_payload_root(
            &authority_root,
            &pq_signer_root,
            authority_epoch,
            &rotation_root,
            &requirement.adapter_input_root,
        );
        let signature_required =
            requirement.expected_final_status.as_str() != "failed" || authority_fresh;
        let release_blocks = !authority_fresh
            || authority_report.status == AuthorityTransferReportStatus::Failed
            || requirement.status == AdapterReadinessStatus::Blocked;
        let production_blocks = release_blocks
            || requirement.expected_production_status.as_str() != "passed"
            || config.cargo_checks_deferred
            || config.runtime_tests_deferred;
        let status = observation_status(
            config,
            requirement.status,
            authority_report.status,
            authority_fresh,
            pq_security_bits,
        );
        let observation_root = pq_authority_observation_root(
            status,
            &requirement.requirement_id,
            &authority_root,
            &pq_signer_root,
            &rotation_root,
            &verification_root,
            authority_epoch,
            pq_security_bits,
        );
        let observation_id = pq_authority_observation_id(
            &requirement.requirement_id,
            &authority_report.report_id,
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
            authority_transfer_report_id: authority_report.report_id.clone(),
            authority_transfer_status: authority_report.status,
            authority_state_root: authority_report.authority_state_root.clone(),
            authority_report_root: authority_report.authority_report_root.clone(),
            security_bundle_state_root: authority_report.security_bundle_state_root.clone(),
            security_bundle_report_root: authority_report.security_bundle_report_root.clone(),
            authority_transfer_source_root: authority_report.roots.source_root.clone(),
            authority_transfer_check_root: authority_report.roots.check_root.clone(),
            transcript_root: authority_report.transcript_root.clone(),
            authority_root,
            pq_signer_root,
            rotation_root,
            rotation_status_root,
            authority_epoch_root,
            signature_domain_root,
            verification_root,
            request_payload_root,
            authority_epoch,
            current_authority_epoch: config.current_authority_epoch,
            rotation_grace_epochs: config.rotation_grace_epochs,
            pq_security_bits,
            authority_fresh,
            signature_required,
            release_blocks,
            production_blocks,
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
            "authority_transfer_report_id": self.authority_transfer_report_id,
            "authority_transfer_status": self.authority_transfer_status.as_str(),
            "authority_state_root": self.authority_state_root,
            "authority_report_root": self.authority_report_root,
            "security_bundle_state_root": self.security_bundle_state_root,
            "security_bundle_report_root": self.security_bundle_report_root,
            "authority_transfer_source_root": self.authority_transfer_source_root,
            "authority_transfer_check_root": self.authority_transfer_check_root,
            "transcript_root": self.transcript_root,
            "authority_root": self.authority_root,
            "pq_signer_root": self.pq_signer_root,
            "rotation_root": self.rotation_root,
            "rotation_status_root": self.rotation_status_root,
            "authority_epoch_root": self.authority_epoch_root,
            "signature_domain_root": self.signature_domain_root,
            "verification_root": self.verification_root,
            "request_payload_root": self.request_payload_root,
            "authority_epoch": self.authority_epoch,
            "current_authority_epoch": self.current_authority_epoch,
            "rotation_grace_epochs": self.rotation_grace_epochs,
            "pq_security_bits": self.pq_security_bits,
            "authority_fresh": self.authority_fresh,
            "signature_required": self.signature_required,
            "release_blocks": self.release_blocks,
            "production_blocks": self.production_blocks,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "observation_root": self.observation_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq_authority_observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorityAdapterResponse {
    pub response_id: String,
    pub observation_id: String,
    pub status: PqAuthorityObservationStatus,
    pub signature_valid: bool,
    pub rotation_status_root: String,
    pub authority_epoch_root: String,
    pub verification_root: String,
    pub release_hold_required: bool,
    pub adapter_root: String,
    pub response_label: String,
}

impl PqAuthorityAdapterResponse {
    pub fn from_observation(config: &Config, observation: &PqAuthorityObservation) -> Self {
        let signature_valid = config.live_pq_authority_enabled
            && observation.status == PqAuthorityObservationStatus::Accepted
            && observation.authority_fresh
            && observation.pq_security_bits >= config.min_pq_security_bits;
        let release_hold_required = !signature_valid || observation.release_blocks;
        let response_label = response_label(config, observation).to_string();
        let adapter_root = adapter_response_root(
            observation.status,
            signature_valid,
            &observation.rotation_status_root,
            &observation.authority_epoch_root,
            &observation.verification_root,
            release_hold_required,
            &response_label,
        );
        let response_id = adapter_response_id(&observation.observation_id, &adapter_root);
        Self {
            response_id,
            observation_id: observation.observation_id.clone(),
            status: observation.status,
            signature_valid,
            rotation_status_root: observation.rotation_status_root.clone(),
            authority_epoch_root: observation.authority_epoch_root.clone(),
            verification_root: observation.verification_root.clone(),
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
            "signature_valid": self.signature_valid,
            "rotation_status_root": self.rotation_status_root,
            "authority_epoch_root": self.authority_epoch_root,
            "verification_root": self.verification_root,
            "release_hold_required": self.release_hold_required,
            "adapter_root": self.adapter_root,
            "response_label": self.response_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq_authority_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorityFailureSurface {
    pub failure_id: String,
    pub observation_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_epochs: u64,
}

impl PqAuthorityFailureSurface {
    pub fn from_observation(config: &Config, observation: &PqAuthorityObservation) -> Self {
        let error_code = error_code(config, observation).to_string();
        let quarantine_required = observation.status == PqAuthorityObservationStatus::Rejected
            || (config.fail_closed_on_rotation_gap && !observation.authority_fresh);
        let retry_after_epochs = if error_code == "none" {
            0
        } else {
            config.rotation_retry_epochs
        };
        let failure_root = pq_authority_failure_root(
            &observation.observation_id,
            &error_code,
            quarantine_required,
            retry_after_epochs,
        );
        let failure_id = pq_authority_failure_id(&observation.observation_id, &failure_root);
        Self {
            failure_id,
            observation_id: observation.observation_id.clone(),
            error_code,
            failure_root,
            quarantine_required,
            retry_after_epochs,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "failure_id": self.failure_id,
            "observation_id": self.observation_id,
            "error_code": self.error_code,
            "failure_root": self.failure_root,
            "quarantine_required": self.quarantine_required,
            "retry_after_epochs": self.retry_after_epochs,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq_authority_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorityKeyManagerReport {
    pub report_id: String,
    pub status: PqAuthorityKeyManagerReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub authority_transfer_state_root: String,
    pub authority_transfer_report_root: String,
    pub pq_authority_stub_id: String,
    pub pq_authority_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub scenario_id: String,
    pub observations_total: u64,
    pub observations_accepted: u64,
    pub observations_deferred: u64,
    pub observations_rejected: u64,
    pub signatures_valid: u64,
    pub release_holds_required: u64,
    pub stale_rotations: u64,
    pub quarantine_required: u64,
    pub observations: BTreeMap<String, PqAuthorityObservation>,
    pub responses: BTreeMap<String, PqAuthorityAdapterResponse>,
    pub failures: BTreeMap<String, PqAuthorityFailureSurface>,
    pub roots: PqAuthorityKeyManagerReportRoots,
}

impl PqAuthorityKeyManagerReport {
    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .values()
            .map(PqAuthorityObservation::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(PqAuthorityAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(PqAuthorityFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "authority_transfer_state_root": self.authority_transfer_state_root,
            "authority_transfer_report_root": self.authority_transfer_report_root,
            "pq_authority_stub_id": self.pq_authority_stub_id,
            "pq_authority_stub_status": self.pq_authority_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "scenario_id": self.scenario_id,
            "observations_total": self.observations_total,
            "observations_accepted": self.observations_accepted,
            "observations_deferred": self.observations_deferred,
            "observations_rejected": self.observations_rejected,
            "signatures_valid": self.signatures_valid,
            "release_holds_required": self.release_holds_required,
            "stale_rotations": self.stale_rotations,
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
pub struct PqAuthorityKeyManagerReportRoots {
    pub observation_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl PqAuthorityKeyManagerReportRoots {
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
    pub signatures_valid: u64,
    pub release_holds_required: u64,
    pub stale_rotations: u64,
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
            "signatures_valid": self.signatures_valid,
            "release_holds_required": self.release_holds_required,
            "stale_rotations": self.stale_rotations,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-KEY-MANAGER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-KEY-MANAGER-STATE",
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
    pub latest_report: Option<PqAuthorityKeyManagerReport>,
    pub report_history: Vec<PqAuthorityKeyManagerReport>,
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
        let authority_transfer =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        state
            .process_pq_authority_key_manager_adapter(&matrix, &stub_registry, &authority_transfer)
            .expect("devnet bridge exit PQ authority key manager adapter");
        state
    }

    pub fn process_pq_authority_key_manager_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        authority_transfer: &AuthorityTransferSecurityBundleState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let authority_report = authority_transfer
            .latest_report
            .as_ref()
            .ok_or_else(|| "authority transfer security bundle has no latest report".to_string())?;
        let pq_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::PqAuthorityKeyManager)
            .ok_or_else(|| "PQ authority key manager adapter stub is missing".to_string())?;
        let authority_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| {
                requirement.adapter_kind == LiveAdapterKind::PqAuthorityKeyManager
            })
            .collect::<Vec<_>>();
        ensure(
            authority_requirements.len() as u64 >= self.config.min_authority_observations,
            "PQ authority adapter omitted required fixture observations",
        )?;
        let observations = authority_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                PqAuthorityObservation::from_requirement(
                    &self.config,
                    *requirement,
                    authority_report,
                    index as u64,
                )
            })
            .map(|observation| (observation.observation_id.clone(), observation))
            .collect::<BTreeMap<_, _>>();
        let responses = observations
            .values()
            .map(|observation| {
                PqAuthorityAdapterResponse::from_observation(&self.config, observation)
            })
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = observations
            .values()
            .map(|observation| {
                PqAuthorityFailureSurface::from_observation(&self.config, observation)
            })
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let observations_total = observations.len() as u64;
        let observations_accepted = observations
            .values()
            .filter(|observation| observation.status == PqAuthorityObservationStatus::Accepted)
            .count() as u64;
        let observations_deferred = observations
            .values()
            .filter(|observation| observation.status == PqAuthorityObservationStatus::Deferred)
            .count() as u64;
        let observations_rejected = observations
            .values()
            .filter(|observation| observation.status == PqAuthorityObservationStatus::Rejected)
            .count() as u64;
        let signatures_valid = responses
            .values()
            .filter(|response| response.signature_valid)
            .count() as u64;
        let release_holds_required = responses
            .values()
            .filter(|response| response.release_hold_required)
            .count() as u64;
        let stale_rotations = observations
            .values()
            .filter(|observation| !observation.authority_fresh)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            pq_stub,
            authority_report.status,
            observations_deferred,
            observations_rejected,
            release_holds_required,
            stale_rotations,
            self.config.live_pq_authority_enabled,
        );
        let readiness_label = readiness_label(
            status,
            pq_stub.status,
            self.config.live_pq_authority_enabled,
        )
        .to_string();
        let observation_records = observations
            .values()
            .map(PqAuthorityObservation::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(PqAuthorityAdapterResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(PqAuthorityFailureSurface::public_record)
            .collect::<Vec<_>>();
        let observation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-OBSERVATIONS",
            &observation_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &authority_transfer.state_root(),
            &authority_report.state_root(),
            &pq_stub.stub_id,
            &pq_stub.request_schema_root,
            &pq_stub.response_schema_root,
            &pq_stub.failure_schema_root,
        );
        let release_claim_id = authority_report.release_claim_id();
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &observation_root,
            &response_root,
            &failure_root,
            &release_claim_id,
        );
        let report_id = pq_authority_key_manager_report_id(&release_claim_id, &report_root);
        let report = PqAuthorityKeyManagerReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            authority_transfer_state_root: authority_transfer.state_root(),
            authority_transfer_report_root: authority_report.state_root(),
            pq_authority_stub_id: pq_stub.stub_id.clone(),
            pq_authority_stub_status: pq_stub.status,
            release_claim_id,
            scenario_id: authority_report.scenario_id.clone(),
            observations_total,
            observations_accepted,
            observations_deferred,
            observations_rejected,
            signatures_valid,
            release_holds_required,
            stale_rotations,
            quarantine_required,
            observations,
            responses,
            failures,
            roots: PqAuthorityKeyManagerReportRoots {
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
            "latest_report": self.latest_report.as_ref().map(PqAuthorityKeyManagerReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: PqAuthorityKeyManagerReport) {
        self.counters.reports_run += 1;
        self.counters.observations_total += report.observations_total;
        self.counters.observations_accepted += report.observations_accepted;
        self.counters.observations_deferred += report.observations_deferred;
        self.counters.observations_rejected += report.observations_rejected;
        self.counters.signatures_valid += report.signatures_valid;
        self.counters.release_holds_required += report.release_holds_required;
        self.counters.stale_rotations += report.stale_rotations;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            PqAuthorityKeyManagerReportStatus::Passed => self.counters.reports_passed += 1,
            PqAuthorityKeyManagerReportStatus::Watch => self.counters.reports_watch += 1,
            PqAuthorityKeyManagerReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(PqAuthorityKeyManagerReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-KEY-MANAGER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

trait AuthorityTransferReportExt {
    fn release_claim_id(&self) -> String;
}

impl AuthorityTransferReportExt for AuthorityTransferReport {
    fn release_claim_id(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-RELEASE-CLAIM",
            &[
                HashPart::Str(&self.scenario_id),
                HashPart::Str(&self.authority_report_root),
                HashPart::Str(&self.security_bundle_report_root),
            ],
            32,
        )
    }
}

fn authority_epoch_for(config: &Config, ordinal: u64) -> u64 {
    let spread = config.rotation_grace_epochs.saturating_add(1).max(1);
    config
        .current_authority_epoch
        .saturating_sub(ordinal % spread)
}

fn observation_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    authority_status: AuthorityTransferReportStatus,
    authority_fresh: bool,
    pq_security_bits: u64,
) -> PqAuthorityObservationStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || authority_status == AuthorityTransferReportStatus::Failed
        || pq_security_bits < config.min_pq_security_bits
        || (config.fail_closed_on_rotation_gap && !authority_fresh)
    {
        PqAuthorityObservationStatus::Rejected
    } else if !config.live_pq_authority_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || authority_status == AuthorityTransferReportStatus::Watch
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
    {
        PqAuthorityObservationStatus::Deferred
    } else {
        PqAuthorityObservationStatus::Accepted
    }
}

#[allow(clippy::too_many_arguments)]
fn report_status(
    pq_stub: &LiveAdapterStub,
    authority_status: AuthorityTransferReportStatus,
    observations_deferred: u64,
    observations_rejected: u64,
    release_holds_required: u64,
    stale_rotations: u64,
    live_pq_authority_enabled: bool,
) -> PqAuthorityKeyManagerReportStatus {
    if observations_rejected > 0
        || stale_rotations > 0
        || authority_status == AuthorityTransferReportStatus::Failed
        || pq_stub.status == AdapterStubStatus::Blocked
    {
        PqAuthorityKeyManagerReportStatus::Failed
    } else if observations_deferred > 0
        || release_holds_required > 0
        || authority_status == AuthorityTransferReportStatus::Watch
        || pq_stub.status == AdapterStubStatus::Deferred
        || !live_pq_authority_enabled
    {
        PqAuthorityKeyManagerReportStatus::Watch
    } else {
        PqAuthorityKeyManagerReportStatus::Passed
    }
}

fn readiness_label(
    status: PqAuthorityKeyManagerReportStatus,
    pq_stub_status: AdapterStubStatus,
    live_pq_authority_enabled: bool,
) -> &'static str {
    match status {
        PqAuthorityKeyManagerReportStatus::Failed => "pq_authority_key_manager_adapter_failed",
        PqAuthorityKeyManagerReportStatus::Watch if !live_pq_authority_enabled => {
            "pq_authority_key_manager_adapter_watch_live_handler_deferred"
        }
        PqAuthorityKeyManagerReportStatus::Watch
            if pq_stub_status == AdapterStubStatus::Deferred =>
        {
            "pq_authority_key_manager_adapter_watch_stub_deferred"
        }
        PqAuthorityKeyManagerReportStatus::Watch => "pq_authority_key_manager_adapter_watch",
        PqAuthorityKeyManagerReportStatus::Passed => "pq_authority_key_manager_adapter_ready",
    }
}

fn response_label(config: &Config, observation: &PqAuthorityObservation) -> &'static str {
    if observation.status == PqAuthorityObservationStatus::Rejected {
        "pq_authority_rejected"
    } else if !observation.authority_fresh {
        "pq_authority_rotation_expired"
    } else if observation.pq_security_bits < config.min_pq_security_bits {
        "pq_authority_security_bits_below_floor"
    } else if observation.authority_transfer_status == AuthorityTransferReportStatus::Watch {
        "authority_transfer_watch"
    } else if !config.live_pq_authority_enabled {
        "live_pq_authority_deferred"
    } else if observation.status == PqAuthorityObservationStatus::Deferred {
        "pq_authority_deferred"
    } else {
        "pq_authority_signature_valid"
    }
}

fn error_code(config: &Config, observation: &PqAuthorityObservation) -> &'static str {
    if observation.authority_transfer_status == AuthorityTransferReportStatus::Failed {
        "authority_transfer_report_failed"
    } else if !observation.authority_fresh {
        "authority_rotation_epoch_expired"
    } else if observation.pq_security_bits < config.min_pq_security_bits {
        "pq_security_bits_below_floor"
    } else if !config.live_pq_authority_enabled {
        "live_pq_authority_deferred"
    } else if observation.authority_transfer_status == AuthorityTransferReportStatus::Watch {
        "authority_transfer_report_watch"
    } else if observation.status == PqAuthorityObservationStatus::Deferred {
        "pq_authority_deferred"
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

pub fn pq_signer_root(
    authority_report_root: &str,
    security_bundle_report_root: &str,
    release_claim_id: &str,
    authority_epoch: u64,
    pq_security_bits: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-SIGNER",
        &[
            HashPart::Str(authority_report_root),
            HashPart::Str(security_bundle_report_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(authority_epoch),
            HashPart::U64(pq_security_bits),
        ],
        32,
    )
}

pub fn rotation_root(
    authority_root: &str,
    pq_signer_root: &str,
    authority_transfer_source_root: &str,
    authority_epoch: u64,
    current_authority_epoch: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-ROTATION",
        &[
            HashPart::Str(authority_root),
            HashPart::Str(pq_signer_root),
            HashPart::Str(authority_transfer_source_root),
            HashPart::U64(authority_epoch),
            HashPart::U64(current_authority_epoch),
        ],
        32,
    )
}

pub fn rotation_status_root(
    authority_status: AuthorityTransferReportStatus,
    rotation_root: &str,
    authority_fresh: bool,
    rotation_grace_epochs: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-ROTATION-STATUS",
        &[
            HashPart::Str(authority_status.as_str()),
            HashPart::Str(rotation_root),
            HashPart::Str(bool_str(authority_fresh)),
            HashPart::U64(rotation_grace_epochs),
        ],
        32,
    )
}

pub fn authority_epoch_root(
    authority_root: &str,
    pq_signer_root: &str,
    authority_epoch: u64,
    current_authority_epoch: u64,
    authority_fresh: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-EPOCH",
        &[
            HashPart::Str(authority_root),
            HashPart::Str(pq_signer_root),
            HashPart::U64(authority_epoch),
            HashPart::U64(current_authority_epoch),
            HashPart::Str(bool_str(authority_fresh)),
        ],
        32,
    )
}

pub fn signature_domain_root(
    chain_id: &str,
    release_claim_id: &str,
    scenario_id: &str,
    transcript_root: &str,
    authority_epoch: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-SIGNATURE-DOMAIN",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(scenario_id),
            HashPart::Str(transcript_root),
            HashPart::U64(authority_epoch),
        ],
        32,
    )
}

pub fn verification_root(
    authority_root: &str,
    pq_signer_root: &str,
    rotation_status_root: &str,
    authority_epoch_root: &str,
    signature_domain_root: &str,
    pq_security_bits: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION",
        &[
            HashPart::Str(authority_root),
            HashPart::Str(pq_signer_root),
            HashPart::Str(rotation_status_root),
            HashPart::Str(authority_epoch_root),
            HashPart::Str(signature_domain_root),
            HashPart::U64(pq_security_bits),
        ],
        32,
    )
}

pub fn request_payload_root(
    authority_root: &str,
    pq_signer_root: &str,
    authority_epoch: u64,
    rotation_root: &str,
    adapter_input_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-REQUEST-PAYLOAD",
        &[
            HashPart::Str(authority_root),
            HashPart::Str(pq_signer_root),
            HashPart::U64(authority_epoch),
            HashPart::Str(rotation_root),
            HashPart::Str(adapter_input_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_authority_observation_root(
    status: PqAuthorityObservationStatus,
    requirement_id: &str,
    authority_root: &str,
    pq_signer_root: &str,
    rotation_root: &str,
    verification_root: &str,
    authority_epoch: u64,
    pq_security_bits: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-OBSERVATION",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(authority_root),
            HashPart::Str(pq_signer_root),
            HashPart::Str(rotation_root),
            HashPart::Str(verification_root),
            HashPart::U64(authority_epoch),
            HashPart::U64(pq_security_bits),
        ],
        32,
    )
}

pub fn pq_authority_observation_id(
    requirement_id: &str,
    authority_transfer_report_id: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-OBSERVATION-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(authority_transfer_report_id),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: PqAuthorityObservationStatus,
    signature_valid: bool,
    rotation_status_root: &str,
    authority_epoch_root: &str,
    verification_root: &str,
    release_hold_required: bool,
    response_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-RESPONSE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(signature_valid)),
            HashPart::Str(rotation_status_root),
            HashPart::Str(authority_epoch_root),
            HashPart::Str(verification_root),
            HashPart::Str(bool_str(release_hold_required)),
            HashPart::Str(response_label),
        ],
        32,
    )
}

pub fn adapter_response_id(observation_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-RESPONSE-ID",
        &[HashPart::Str(observation_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn pq_authority_failure_root(
    observation_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_epochs: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-FAILURE",
        &[
            HashPart::Str(observation_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_epochs),
        ],
        32,
    )
}

pub fn pq_authority_failure_id(observation_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-FAILURE-ID",
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
    authority_transfer_state_root: &str,
    authority_transfer_report_root: &str,
    pq_authority_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-SOURCE",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(authority_transfer_state_root),
            HashPart::Str(authority_transfer_report_root),
            HashPart::Str(pq_authority_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: PqAuthorityKeyManagerReportStatus,
    readiness_label: &str,
    source_root: &str,
    observation_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-REPORT",
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

pub fn pq_authority_key_manager_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-RECORD",
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
