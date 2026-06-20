use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_final_release_gate_runtime::{
        FinalReleaseGateStatus, State as FinalReleaseGateState,
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
pub type MoneroL2PqBridgeExitClaimQueueAdapterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CLAIM_QUEUE_ADAPTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-claim-queue-adapter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CLAIM_QUEUE_ADAPTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXIT_CLAIM_QUEUE_ADAPTER_SUITE: &str = "monero-l2-pq-bridge-exit-claim-queue-adapter-v1";
pub const DEFAULT_MIN_QUEUE_ENTRIES: u64 = 15;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 24;
pub const DEFAULT_BASE_TIMEOUT_HEIGHT: u64 = 4_200_000;
pub const DEFAULT_MAX_QUEUE_POSITION: u64 = 4_096;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitQueueEntryStatus {
    Queued,
    Deferred,
    Rejected,
}

impl ExitQueueEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClaimQueueReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ExitClaimQueueReportStatus {
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
    pub min_queue_entries: u64,
    pub challenge_window_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub base_timeout_height: u64,
    pub max_queue_position: u64,
    pub live_queue_enabled: bool,
    pub fail_closed_on_final_gate_block: bool,
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
            adapter_suite: EXIT_CLAIM_QUEUE_ADAPTER_SUITE.to_string(),
            min_queue_entries: DEFAULT_MIN_QUEUE_ENTRIES,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            settlement_delay_blocks: DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            base_timeout_height: DEFAULT_BASE_TIMEOUT_HEIGHT,
            max_queue_position: DEFAULT_MAX_QUEUE_POSITION,
            live_queue_enabled: false,
            fail_closed_on_final_gate_block: true,
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
            "min_queue_entries": self.min_queue_entries,
            "challenge_window_blocks": self.challenge_window_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "base_timeout_height": self.base_timeout_height,
            "max_queue_position": self.max_queue_position,
            "live_queue_enabled": self.live_queue_enabled,
            "fail_closed_on_final_gate_block": self.fail_closed_on_final_gate_block,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimQueueEntry {
    pub entry_id: String,
    pub status: ExitQueueEntryStatus,
    pub requirement_id: String,
    pub fixture_export_id: String,
    pub vector_id: String,
    pub test_name: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub release_claim_id: String,
    pub timeout_height: u64,
    pub challenge_window_start: u64,
    pub challenge_window_end: u64,
    pub queue_position: u64,
    pub challenge_root: String,
    pub challenge_window_root: String,
    pub settlement_order_root: String,
    pub final_gate_report_root: String,
    pub final_gate_status: FinalReleaseGateStatus,
    pub user_release_blockers: u64,
    pub deferred_gates: u64,
    pub production_blockers: u64,
    pub fixture_root: String,
    pub adapter_input_root: String,
    pub readiness_root: String,
    pub entry_root: String,
}

impl ExitClaimQueueEntry {
    pub fn from_requirement(
        config: &Config,
        requirement: &LiveAdapterRequirement,
        final_report: &crate::monero_l2_pq_bridge_exit_final_release_gate_runtime::FinalReleaseGateReport,
        ordinal: u64,
    ) -> Self {
        let queue_position = ordinal + 1;
        let timeout_height = config.base_timeout_height + ordinal + config.challenge_window_blocks;
        let challenge_window_start = timeout_height.saturating_sub(config.challenge_window_blocks);
        let challenge_window_end = timeout_height;
        let challenge_root = challenge_root(
            &requirement.release_claim_id,
            &final_report.roots.blocker_root,
            queue_position,
            final_report.user_release_blockers,
        );
        let challenge_window_root = challenge_window_root(
            &challenge_root,
            challenge_window_start,
            challenge_window_end,
            final_report.deferred_gates,
        );
        let settlement_order_root = settlement_order_root(
            &requirement.release_claim_id,
            queue_position,
            timeout_height + config.settlement_delay_blocks,
            &final_report.roots.decision_root,
            &challenge_window_root,
        );
        let status = queue_entry_status(
            config,
            requirement.status,
            final_report.status,
            final_report.user_release_blockers,
            final_report.deferred_gates,
            queue_position,
        );
        let final_gate_report_root = final_report.state_root();
        let entry_root = queue_entry_root(
            status,
            &requirement.requirement_id,
            &requirement.release_claim_id,
            &challenge_root,
            &settlement_order_root,
            timeout_height,
            queue_position,
        );
        let entry_id = queue_entry_id(
            &requirement.requirement_id,
            &requirement.release_claim_id,
            &entry_root,
        );
        Self {
            entry_id,
            status,
            requirement_id: requirement.requirement_id.clone(),
            fixture_export_id: requirement.fixture_export_id.clone(),
            vector_id: requirement.vector_id.clone(),
            test_name: requirement.test_name.clone(),
            scenario_id: requirement.scenario_id.clone(),
            transfer_id: requirement.transfer_id.clone(),
            release_claim_id: requirement.release_claim_id.clone(),
            timeout_height,
            challenge_window_start,
            challenge_window_end,
            queue_position,
            challenge_root,
            challenge_window_root,
            settlement_order_root,
            final_gate_report_root,
            final_gate_status: final_report.status,
            user_release_blockers: final_report.user_release_blockers,
            deferred_gates: final_report.deferred_gates,
            production_blockers: final_report.production_blockers,
            fixture_root: requirement.fixture_root.clone(),
            adapter_input_root: requirement.adapter_input_root.clone(),
            readiness_root: requirement.readiness_root.clone(),
            entry_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "status": self.status.as_str(),
            "requirement_id": self.requirement_id,
            "fixture_export_id": self.fixture_export_id,
            "vector_id": self.vector_id,
            "test_name": self.test_name,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "release_claim_id": self.release_claim_id,
            "timeout_height": self.timeout_height,
            "challenge_window_start": self.challenge_window_start,
            "challenge_window_end": self.challenge_window_end,
            "queue_position": self.queue_position,
            "challenge_root": self.challenge_root,
            "challenge_window_root": self.challenge_window_root,
            "settlement_order_root": self.settlement_order_root,
            "final_gate_report_root": self.final_gate_report_root,
            "final_gate_status": self.final_gate_status.as_str(),
            "user_release_blockers": self.user_release_blockers,
            "deferred_gates": self.deferred_gates,
            "production_blockers": self.production_blockers,
            "fixture_root": self.fixture_root,
            "adapter_input_root": self.adapter_input_root,
            "readiness_root": self.readiness_root,
            "entry_root": self.entry_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("exit_claim_queue_entry", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimQueueResponse {
    pub response_id: String,
    pub entry_id: String,
    pub status: ExitQueueEntryStatus,
    pub queued: bool,
    pub challenge_window_root: String,
    pub settlement_order_root: String,
    pub queue_hold_required: bool,
    pub adapter_root: String,
    pub queue_label: String,
}

impl ExitClaimQueueResponse {
    pub fn from_entry(config: &Config, entry: &ExitClaimQueueEntry) -> Self {
        let queued = config.live_queue_enabled && entry.status == ExitQueueEntryStatus::Queued;
        let queue_hold_required = !queued;
        let queue_label = queue_label(config, entry).to_string();
        let adapter_root = adapter_response_root(
            entry.status,
            queued,
            &entry.challenge_window_root,
            &entry.settlement_order_root,
            queue_hold_required,
            &queue_label,
        );
        let response_id = adapter_response_id(&entry.entry_id, &adapter_root);
        Self {
            response_id,
            entry_id: entry.entry_id.clone(),
            status: entry.status,
            queued,
            challenge_window_root: entry.challenge_window_root.clone(),
            settlement_order_root: entry.settlement_order_root.clone(),
            queue_hold_required,
            adapter_root,
            queue_label,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "response_id": self.response_id,
            "entry_id": self.entry_id,
            "status": self.status.as_str(),
            "queued": self.queued,
            "challenge_window_root": self.challenge_window_root,
            "settlement_order_root": self.settlement_order_root,
            "queue_hold_required": self.queue_hold_required,
            "adapter_root": self.adapter_root,
            "queue_label": self.queue_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("exit_claim_queue_response", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimQueueFailureSurface {
    pub failure_id: String,
    pub entry_id: String,
    pub error_code: String,
    pub failure_root: String,
    pub quarantine_required: bool,
    pub retry_after_height: u64,
}

impl ExitClaimQueueFailureSurface {
    pub fn from_entry(config: &Config, entry: &ExitClaimQueueEntry) -> Self {
        let error_code = error_code(config, entry).to_string();
        let quarantine_required = entry.status == ExitQueueEntryStatus::Rejected
            && config.fail_closed_on_final_gate_block;
        let retry_after_height = entry.timeout_height + config.settlement_delay_blocks;
        let failure_root = queue_failure_root(
            &entry.entry_id,
            &error_code,
            quarantine_required,
            retry_after_height,
        );
        let failure_id = queue_failure_id(&entry.entry_id, &failure_root);
        Self {
            failure_id,
            entry_id: entry.entry_id.clone(),
            error_code,
            failure_root,
            quarantine_required,
            retry_after_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "failure_id": self.failure_id,
            "entry_id": self.entry_id,
            "error_code": self.error_code,
            "failure_root": self.failure_root,
            "quarantine_required": self.quarantine_required,
            "retry_after_height": self.retry_after_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("exit_claim_queue_failure", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimQueueAdapterReport {
    pub report_id: String,
    pub status: ExitClaimQueueReportStatus,
    pub readiness_label: String,
    pub matrix_state_root: String,
    pub matrix_report_root: String,
    pub stub_registry_state_root: String,
    pub stub_registry_report_root: String,
    pub final_gate_state_root: String,
    pub final_gate_report_root: String,
    pub queue_stub_id: String,
    pub queue_stub_status: AdapterStubStatus,
    pub release_claim_id: String,
    pub entries_total: u64,
    pub entries_queued: u64,
    pub entries_deferred: u64,
    pub entries_rejected: u64,
    pub queued_responses: u64,
    pub queue_holds_required: u64,
    pub quarantine_required: u64,
    pub entries: BTreeMap<String, ExitClaimQueueEntry>,
    pub responses: BTreeMap<String, ExitClaimQueueResponse>,
    pub failures: BTreeMap<String, ExitClaimQueueFailureSurface>,
    pub roots: ExitClaimQueueAdapterReportRoots,
}

impl ExitClaimQueueAdapterReport {
    pub fn public_record(&self) -> Value {
        let entries = self
            .entries
            .values()
            .map(ExitClaimQueueEntry::public_record)
            .collect::<Vec<_>>();
        let responses = self
            .responses
            .values()
            .map(ExitClaimQueueResponse::public_record)
            .collect::<Vec<_>>();
        let failures = self
            .failures
            .values()
            .map(ExitClaimQueueFailureSurface::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "matrix_state_root": self.matrix_state_root,
            "matrix_report_root": self.matrix_report_root,
            "stub_registry_state_root": self.stub_registry_state_root,
            "stub_registry_report_root": self.stub_registry_report_root,
            "final_gate_state_root": self.final_gate_state_root,
            "final_gate_report_root": self.final_gate_report_root,
            "queue_stub_id": self.queue_stub_id,
            "queue_stub_status": self.queue_stub_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "entries_total": self.entries_total,
            "entries_queued": self.entries_queued,
            "entries_deferred": self.entries_deferred,
            "entries_rejected": self.entries_rejected,
            "queued_responses": self.queued_responses,
            "queue_holds_required": self.queue_holds_required,
            "quarantine_required": self.quarantine_required,
            "entries": entries,
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
pub struct ExitClaimQueueAdapterReportRoots {
    pub entry_root: String,
    pub response_root: String,
    pub failure_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl ExitClaimQueueAdapterReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "entry_root": self.entry_root,
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
    pub entries_total: u64,
    pub entries_queued: u64,
    pub entries_deferred: u64,
    pub entries_rejected: u64,
    pub queued_responses: u64,
    pub queue_holds_required: u64,
    pub quarantine_required: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "entries_total": self.entries_total,
            "entries_queued": self.entries_queued,
            "entries_deferred": self.entries_deferred,
            "entries_rejected": self.entries_rejected,
            "queued_responses": self.queued_responses,
            "queue_holds_required": self.queue_holds_required,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-STATE",
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
    pub latest_report: Option<ExitClaimQueueAdapterReport>,
    pub report_history: Vec<ExitClaimQueueAdapterReport>,
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
        let final_gate = crate::monero_l2_pq_bridge_exit_final_release_gate_runtime::devnet();
        state
            .process_exit_claim_queue_adapter(&matrix, &stub_registry, &final_gate)
            .expect("devnet bridge exit claim queue adapter");
        state
    }

    pub fn process_exit_claim_queue_adapter(
        &mut self,
        matrix: &LiveAdapterMatrixState,
        stub_registry: &LiveAdapterStubRegistryState,
        final_gate: &FinalReleaseGateState,
    ) -> Result<String> {
        let matrix_report = matrix
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter matrix has no latest report".to_string())?;
        let stub_report = stub_registry
            .latest_report
            .as_ref()
            .ok_or_else(|| "live adapter stub registry has no latest report".to_string())?;
        let final_report = final_gate
            .latest_report
            .as_ref()
            .ok_or_else(|| "final release gate state has no latest report".to_string())?;
        let queue_stub = stub_report
            .stubs
            .values()
            .find(|stub| stub.adapter_kind == LiveAdapterKind::ExitClaimQueue)
            .ok_or_else(|| "exit claim queue adapter stub is missing".to_string())?;
        let queue_requirements = matrix_report
            .requirements
            .values()
            .filter(|requirement| requirement.adapter_kind == LiveAdapterKind::ExitClaimQueue)
            .collect::<Vec<_>>();
        ensure(
            queue_requirements.len() as u64 >= self.config.min_queue_entries,
            "exit claim queue adapter omitted required fixture entries",
        )?;
        let entries = queue_requirements
            .iter()
            .enumerate()
            .map(|(index, requirement)| {
                ExitClaimQueueEntry::from_requirement(
                    &self.config,
                    *requirement,
                    final_report,
                    index as u64,
                )
            })
            .map(|entry| (entry.entry_id.clone(), entry))
            .collect::<BTreeMap<_, _>>();
        let responses = entries
            .values()
            .map(|entry| ExitClaimQueueResponse::from_entry(&self.config, entry))
            .map(|response| (response.response_id.clone(), response))
            .collect::<BTreeMap<_, _>>();
        let failures = entries
            .values()
            .map(|entry| ExitClaimQueueFailureSurface::from_entry(&self.config, entry))
            .map(|failure| (failure.failure_id.clone(), failure))
            .collect::<BTreeMap<_, _>>();
        let entries_total = entries.len() as u64;
        let entries_queued = entries
            .values()
            .filter(|entry| entry.status == ExitQueueEntryStatus::Queued)
            .count() as u64;
        let entries_deferred = entries
            .values()
            .filter(|entry| entry.status == ExitQueueEntryStatus::Deferred)
            .count() as u64;
        let entries_rejected = entries
            .values()
            .filter(|entry| entry.status == ExitQueueEntryStatus::Rejected)
            .count() as u64;
        let queued_responses = responses
            .values()
            .filter(|response| response.queued)
            .count() as u64;
        let queue_holds_required = responses
            .values()
            .filter(|response| response.queue_hold_required)
            .count() as u64;
        let quarantine_required = failures
            .values()
            .filter(|failure| failure.quarantine_required)
            .count() as u64;
        let status = report_status(
            queue_stub,
            entries_deferred,
            entries_rejected,
            queue_holds_required,
            self.config.live_queue_enabled,
        );
        let readiness_label =
            readiness_label(status, queue_stub.status, self.config.live_queue_enabled).to_string();
        let entry_records = entries
            .values()
            .map(ExitClaimQueueEntry::public_record)
            .collect::<Vec<_>>();
        let response_records = responses
            .values()
            .map(ExitClaimQueueResponse::public_record)
            .collect::<Vec<_>>();
        let failure_records = failures
            .values()
            .map(ExitClaimQueueFailureSurface::public_record)
            .collect::<Vec<_>>();
        let entry_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ENTRIES",
            &entry_records,
        );
        let response_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-RESPONSES",
            &response_records,
        );
        let failure_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-FAILURES",
            &failure_records,
        );
        let source_root = source_root(
            &matrix.state_root(),
            &matrix_report.state_root(),
            &stub_registry.state_root(),
            &stub_report.state_root(),
            &final_gate.state_root(),
            &final_report.state_root(),
            &queue_stub.stub_id,
            &queue_stub.request_schema_root,
            &queue_stub.response_schema_root,
            &queue_stub.failure_schema_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &entry_root,
            &response_root,
            &failure_root,
            &final_report.release_claim_id,
        );
        let report_id = exit_claim_queue_report_id(&final_report.release_claim_id, &report_root);
        let report = ExitClaimQueueAdapterReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            matrix_state_root: matrix.state_root(),
            matrix_report_root: matrix_report.state_root(),
            stub_registry_state_root: stub_registry.state_root(),
            stub_registry_report_root: stub_report.state_root(),
            final_gate_state_root: final_gate.state_root(),
            final_gate_report_root: final_report.state_root(),
            queue_stub_id: queue_stub.stub_id.clone(),
            queue_stub_status: queue_stub.status,
            release_claim_id: final_report.release_claim_id.clone(),
            entries_total,
            entries_queued,
            entries_deferred,
            entries_rejected,
            queued_responses,
            queue_holds_required,
            quarantine_required,
            entries,
            responses,
            failures,
            roots: ExitClaimQueueAdapterReportRoots {
                entry_root,
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
            "latest_report": self.latest_report.as_ref().map(ExitClaimQueueAdapterReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: ExitClaimQueueAdapterReport) {
        self.counters.reports_run += 1;
        self.counters.entries_total += report.entries_total;
        self.counters.entries_queued += report.entries_queued;
        self.counters.entries_deferred += report.entries_deferred;
        self.counters.entries_rejected += report.entries_rejected;
        self.counters.queued_responses += report.queued_responses;
        self.counters.queue_holds_required += report.queue_holds_required;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            ExitClaimQueueReportStatus::Passed => self.counters.reports_passed += 1,
            ExitClaimQueueReportStatus::Watch => self.counters.reports_watch += 1,
            ExitClaimQueueReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(ExitClaimQueueAdapterReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn queue_entry_status(
    config: &Config,
    requirement_status: AdapterReadinessStatus,
    final_status: FinalReleaseGateStatus,
    user_release_blockers: u64,
    deferred_gates: u64,
    queue_position: u64,
) -> ExitQueueEntryStatus {
    if requirement_status == AdapterReadinessStatus::Blocked
        || final_status == FinalReleaseGateStatus::Failed
        || (config.fail_closed_on_final_gate_block && user_release_blockers > 0)
        || queue_position > config.max_queue_position
    {
        ExitQueueEntryStatus::Rejected
    } else if !config.live_queue_enabled
        || requirement_status == AdapterReadinessStatus::Deferred
        || final_status == FinalReleaseGateStatus::Watch
        || deferred_gates > 0
    {
        ExitQueueEntryStatus::Deferred
    } else {
        ExitQueueEntryStatus::Queued
    }
}

fn report_status(
    queue_stub: &LiveAdapterStub,
    entries_deferred: u64,
    entries_rejected: u64,
    queue_holds_required: u64,
    live_queue_enabled: bool,
) -> ExitClaimQueueReportStatus {
    if entries_rejected > 0 || queue_stub.status == AdapterStubStatus::Blocked {
        ExitClaimQueueReportStatus::Failed
    } else if entries_deferred > 0
        || queue_holds_required > 0
        || queue_stub.status == AdapterStubStatus::Deferred
        || !live_queue_enabled
    {
        ExitClaimQueueReportStatus::Watch
    } else {
        ExitClaimQueueReportStatus::Passed
    }
}

fn readiness_label(
    status: ExitClaimQueueReportStatus,
    queue_stub_status: AdapterStubStatus,
    live_queue_enabled: bool,
) -> &'static str {
    match status {
        ExitClaimQueueReportStatus::Failed => "exit_claim_queue_adapter_failed",
        ExitClaimQueueReportStatus::Watch if !live_queue_enabled => {
            "exit_claim_queue_adapter_watch_live_queue_deferred"
        }
        ExitClaimQueueReportStatus::Watch if queue_stub_status == AdapterStubStatus::Deferred => {
            "exit_claim_queue_adapter_watch_stub_deferred"
        }
        ExitClaimQueueReportStatus::Watch => "exit_claim_queue_adapter_watch",
        ExitClaimQueueReportStatus::Passed => "exit_claim_queue_adapter_ready",
    }
}

fn queue_label(config: &Config, entry: &ExitClaimQueueEntry) -> &'static str {
    if entry.final_gate_status == FinalReleaseGateStatus::Failed {
        "final_gate_blocks_queue"
    } else if entry.user_release_blockers > 0 {
        "user_release_blocker_present"
    } else if entry.queue_position > config.max_queue_position {
        "queue_position_above_cap"
    } else if entry.deferred_gates > 0 {
        "deferred_gates_hold_queue"
    } else if entry.status == ExitQueueEntryStatus::Queued {
        "exit_claim_queued"
    } else {
        "exit_claim_queue_deferred"
    }
}

fn error_code(config: &Config, entry: &ExitClaimQueueEntry) -> &'static str {
    if entry.final_gate_status == FinalReleaseGateStatus::Failed {
        "final_release_gate_failed"
    } else if entry.user_release_blockers > 0 {
        "user_release_blocker_present"
    } else if entry.queue_position > config.max_queue_position {
        "queue_position_above_cap"
    } else if !config.live_queue_enabled {
        "live_exit_claim_queue_deferred"
    } else if entry.deferred_gates > 0 {
        "deferred_gates_hold_queue"
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

pub fn challenge_root(
    release_claim_id: &str,
    blocker_root: &str,
    queue_position: u64,
    user_release_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-CHALLENGE-ROOT",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(blocker_root),
            HashPart::U64(queue_position),
            HashPart::U64(user_release_blockers),
        ],
        32,
    )
}

pub fn challenge_window_root(
    challenge_root: &str,
    challenge_window_start: u64,
    challenge_window_end: u64,
    deferred_gates: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-CHALLENGE-WINDOW-ROOT",
        &[
            HashPart::Str(challenge_root),
            HashPart::U64(challenge_window_start),
            HashPart::U64(challenge_window_end),
            HashPart::U64(deferred_gates),
        ],
        32,
    )
}

pub fn settlement_order_root(
    release_claim_id: &str,
    queue_position: u64,
    settlement_height: u64,
    final_decision_root: &str,
    challenge_window_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-SETTLEMENT-ORDER-ROOT",
        &[
            HashPart::Str(release_claim_id),
            HashPart::U64(queue_position),
            HashPart::U64(settlement_height),
            HashPart::Str(final_decision_root),
            HashPart::Str(challenge_window_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn queue_entry_root(
    status: ExitQueueEntryStatus,
    requirement_id: &str,
    release_claim_id: &str,
    challenge_root: &str,
    settlement_order_root: &str,
    timeout_height: u64,
    queue_position: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ENTRY-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(requirement_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(challenge_root),
            HashPart::Str(settlement_order_root),
            HashPart::U64(timeout_height),
            HashPart::U64(queue_position),
        ],
        32,
    )
}

pub fn queue_entry_id(requirement_id: &str, release_claim_id: &str, entry_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ENTRY-ID",
        &[
            HashPart::Str(requirement_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(entry_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adapter_response_root(
    status: ExitQueueEntryStatus,
    queued: bool,
    challenge_window_root: &str,
    settlement_order_root: &str,
    queue_hold_required: bool,
    queue_label: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-RESPONSE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(bool_str(queued)),
            HashPart::Str(challenge_window_root),
            HashPart::Str(settlement_order_root),
            HashPart::Str(bool_str(queue_hold_required)),
            HashPart::Str(queue_label),
        ],
        32,
    )
}

pub fn adapter_response_id(entry_id: &str, adapter_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-RESPONSE-ID",
        &[HashPart::Str(entry_id), HashPart::Str(adapter_root)],
        32,
    )
}

pub fn queue_failure_root(
    entry_id: &str,
    error_code: &str,
    quarantine_required: bool,
    retry_after_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-FAILURE-ROOT",
        &[
            HashPart::Str(entry_id),
            HashPart::Str(error_code),
            HashPart::Str(bool_str(quarantine_required)),
            HashPart::U64(retry_after_height),
        ],
        32,
    )
}

pub fn queue_failure_id(entry_id: &str, failure_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-FAILURE-ID",
        &[HashPart::Str(entry_id), HashPart::Str(failure_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    matrix_state_root: &str,
    matrix_report_root: &str,
    stub_registry_state_root: &str,
    stub_registry_report_root: &str,
    final_gate_state_root: &str,
    final_gate_report_root: &str,
    queue_stub_id: &str,
    request_schema_root: &str,
    response_schema_root: &str,
    failure_schema_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-SOURCE-ROOT",
        &[
            HashPart::Str(matrix_state_root),
            HashPart::Str(matrix_report_root),
            HashPart::Str(stub_registry_state_root),
            HashPart::Str(stub_registry_report_root),
            HashPart::Str(final_gate_state_root),
            HashPart::Str(final_gate_report_root),
            HashPart::Str(queue_stub_id),
            HashPart::Str(request_schema_root),
            HashPart::Str(response_schema_root),
            HashPart::Str(failure_schema_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: ExitClaimQueueReportStatus,
    readiness_label: &str,
    source_root: &str,
    entry_root: &str,
    response_root: &str,
    failure_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(entry_root),
            HashPart::Str(response_root),
            HashPart::Str(failure_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn exit_claim_queue_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-ADAPTER-RECORD",
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
