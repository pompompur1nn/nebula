use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_claim_queue_handler_runtime::{
        ExitClaimQueueHandlerEnvelopeStatus, ExitClaimQueueHandlerReport,
        ExitClaimQueueHandlerReportStatus, State as ExitClaimQueueHandlerState,
    },
    monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::{
        BridgeExitReleaseReadinessReceipt, ReleaseReadinessStatus, State as ReleaseReadinessState,
    },
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        ReleaseRemediationPlan, RemediationActionKind, RemediationActionStatus,
        RemediationPlanStatus, State as ReleaseRemediationState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitLiveSettlementExecutionContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_LIVE_SETTLEMENT_EXECUTION_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-live-settlement-execution-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_LIVE_SETTLEMENT_EXECUTION_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_SETTLEMENT_EXECUTION_CONTRACT_SUITE: &str =
    "monero-l2-pq-bridge-exit-live-settlement-execution-contract-v1";
pub const DEFAULT_MIN_CONTRACTS: u64 = 4;
pub const DEFAULT_EXECUTION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MAX_EXECUTION_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveSettlementContractStatus {
    Executable,
    HeldForReadiness,
    HeldForRemediation,
    Cancelled,
}

impl LiveSettlementContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::HeldForReadiness => "held_for_readiness",
            Self::HeldForRemediation => "held_for_remediation",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveSettlementActionKind {
    ExecuteForcedExitRelease,
    HoldChallengeWindow,
    HoldReadinessGate,
    ApplyRemediationPlan,
    CancelRejectedClaim,
}

impl LiveSettlementActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteForcedExitRelease => "execute_forced_exit_release",
            Self::HoldChallengeWindow => "hold_challenge_window",
            Self::HoldReadinessGate => "hold_readiness_gate",
            Self::ApplyRemediationPlan => "apply_remediation_plan",
            Self::CancelRejectedClaim => "cancel_rejected_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveSettlementExecutionReportStatus {
    Ready,
    Watch,
    Blocked,
}

impl LiveSettlementExecutionReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub contract_suite: String,
    pub min_contracts: u64,
    pub execution_ttl_blocks: u64,
    pub max_execution_fee_bps: u64,
    pub live_execution_enabled: bool,
    pub require_readiness_ready: bool,
    pub require_remediation_clear: bool,
    pub fail_closed_on_queue_watch: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            contract_suite: LIVE_SETTLEMENT_EXECUTION_CONTRACT_SUITE.to_string(),
            min_contracts: DEFAULT_MIN_CONTRACTS,
            execution_ttl_blocks: DEFAULT_EXECUTION_TTL_BLOCKS,
            max_execution_fee_bps: DEFAULT_MAX_EXECUTION_FEE_BPS,
            live_execution_enabled: false,
            require_readiness_ready: true,
            require_remediation_clear: true,
            fail_closed_on_queue_watch: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "contract_suite": self.contract_suite,
            "min_contracts": self.min_contracts,
            "execution_ttl_blocks": self.execution_ttl_blocks,
            "max_execution_fee_bps": self.max_execution_fee_bps,
            "live_execution_enabled": self.live_execution_enabled,
            "require_readiness_ready": self.require_readiness_ready,
            "require_remediation_clear": self.require_remediation_clear,
            "fail_closed_on_queue_watch": self.fail_closed_on_queue_watch,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitSettlementContract {
    pub contract_id: String,
    pub status: LiveSettlementContractStatus,
    pub action_kind: LiveSettlementActionKind,
    pub envelope_id: String,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub scenario_id: String,
    pub queue_position: u64,
    pub executable_after_height: u64,
    pub expires_at_height: u64,
    pub fee_cap_bps: u64,
    pub live_execution_enabled: bool,
    pub readiness_status: ReleaseReadinessStatus,
    pub remediation_status: RemediationPlanStatus,
    pub queue_report_status: ExitClaimQueueHandlerReportStatus,
    pub queue_envelope_status: ExitClaimQueueHandlerEnvelopeStatus,
    pub settlement_call_root: String,
    pub settlement_receipt_root: String,
    pub readiness_receipt_root: String,
    pub remediation_plan_root: String,
    pub remediation_action_root: String,
    pub execution_precondition_root: String,
    pub execution_payload_root: String,
    pub execution_receipt_root: String,
    pub cancellation_root: String,
    pub contract_root: String,
    pub hold_reason: String,
}

impl ForcedExitSettlementContract {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "status": self.status.as_str(),
            "action_kind": self.action_kind.as_str(),
            "envelope_id": self.envelope_id,
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "scenario_id": self.scenario_id,
            "queue_position": self.queue_position,
            "executable_after_height": self.executable_after_height,
            "expires_at_height": self.expires_at_height,
            "fee_cap_bps": self.fee_cap_bps,
            "live_execution_enabled": self.live_execution_enabled,
            "readiness_status": self.readiness_status.as_str(),
            "remediation_status": self.remediation_status.as_str(),
            "queue_report_status": self.queue_report_status.as_str(),
            "queue_envelope_status": self.queue_envelope_status.as_str(),
            "settlement_call_root": self.settlement_call_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "readiness_receipt_root": self.readiness_receipt_root,
            "remediation_plan_root": self.remediation_plan_root,
            "remediation_action_root": self.remediation_action_root,
            "execution_precondition_root": self.execution_precondition_root,
            "execution_payload_root": self.execution_payload_root,
            "execution_receipt_root": self.execution_receipt_root,
            "cancellation_root": self.cancellation_root,
            "contract_root": self.contract_root,
            "hold_reason": self.hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        self.contract_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveSettlementExecutionReport {
    pub report_id: String,
    pub status: LiveSettlementExecutionReportStatus,
    pub release_claim_id: String,
    pub queue_handler_report_root: String,
    pub readiness_receipt_root: String,
    pub remediation_plan_root: String,
    pub contracts_total: u64,
    pub contracts_executable: u64,
    pub contracts_held_readiness: u64,
    pub contracts_held_remediation: u64,
    pub contracts_cancelled: u64,
    pub execution_payloads_ready: u64,
    pub forced_exit_release_actions: u64,
    pub remediation_actions_applied: u64,
    pub contracts: BTreeMap<String, ForcedExitSettlementContract>,
    pub roots: LiveSettlementExecutionReportRoots,
}

impl LiveSettlementExecutionReport {
    pub fn public_record(&self) -> Value {
        let contracts = self
            .contracts
            .values()
            .map(ForcedExitSettlementContract::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "queue_handler_report_root": self.queue_handler_report_root,
            "readiness_receipt_root": self.readiness_receipt_root,
            "remediation_plan_root": self.remediation_plan_root,
            "contracts_total": self.contracts_total,
            "contracts_executable": self.contracts_executable,
            "contracts_held_readiness": self.contracts_held_readiness,
            "contracts_held_remediation": self.contracts_held_remediation,
            "contracts_cancelled": self.contracts_cancelled,
            "execution_payloads_ready": self.execution_payloads_ready,
            "forced_exit_release_actions": self.forced_exit_release_actions,
            "remediation_actions_applied": self.remediation_actions_applied,
            "contracts": contracts,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveSettlementExecutionReportRoots {
    pub contract_root: String,
    pub payload_root: String,
    pub receipt_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl LiveSettlementExecutionReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_root": self.contract_root,
            "payload_root": self.payload_root,
            "receipt_root": self.receipt_root,
            "source_root": self.source_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_ready: u64,
    pub reports_watch: u64,
    pub reports_blocked: u64,
    pub contracts_total: u64,
    pub contracts_executable: u64,
    pub contracts_held_readiness: u64,
    pub contracts_held_remediation: u64,
    pub contracts_cancelled: u64,
    pub execution_payloads_ready: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_ready": self.reports_ready,
            "reports_watch": self.reports_watch,
            "reports_blocked": self.reports_blocked,
            "contracts_total": self.contracts_total,
            "contracts_executable": self.contracts_executable,
            "contracts_held_readiness": self.contracts_held_readiness,
            "contracts_held_remediation": self.contracts_held_remediation,
            "contracts_cancelled": self.contracts_cancelled,
            "execution_payloads_ready": self.execution_payloads_ready,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-STATE",
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
    pub latest_report: Option<LiveSettlementExecutionReport>,
    pub report_history: Vec<LiveSettlementExecutionReport>,
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
        let queue_handler = crate::monero_l2_pq_bridge_exit_claim_queue_handler_runtime::devnet();
        let readiness =
            crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::devnet();
        let remediation =
            crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let _ = state.compile_execution_contracts(&queue_handler, &readiness, &remediation);
        state
    }

    pub fn compile_execution_contracts(
        &mut self,
        queue_handler: &ExitClaimQueueHandlerState,
        readiness: &ReleaseReadinessState,
        remediation: &ReleaseRemediationState,
    ) -> Result<String> {
        let queue_report = queue_handler
            .latest_report
            .as_ref()
            .ok_or_else(|| "claim queue handler has no latest report".to_string())?;
        let readiness_receipt = readiness
            .latest_receipt
            .as_ref()
            .ok_or_else(|| "release readiness integrator has no latest receipt".to_string())?;
        let remediation_plan = remediation
            .latest_plan
            .as_ref()
            .ok_or_else(|| "release remediation planner has no latest plan".to_string())?;
        ensure(
            queue_report.release_claim_id == readiness_receipt.release_claim_id
                && readiness_receipt.release_claim_id == remediation_plan.release_claim_id,
            "live settlement sources disagree on release claim id",
        )?;
        let contracts = build_contracts(
            &self.config,
            queue_report,
            readiness_receipt,
            remediation_plan,
        );
        ensure(
            contracts.len() as u64 >= self.config.min_contracts,
            "live settlement execution contracts omitted required forced-exit actions",
        )?;
        let contracts_total = contracts.len() as u64;
        let contracts_executable =
            count_status(&contracts, LiveSettlementContractStatus::Executable);
        let contracts_held_readiness =
            count_status(&contracts, LiveSettlementContractStatus::HeldForReadiness);
        let contracts_held_remediation =
            count_status(&contracts, LiveSettlementContractStatus::HeldForRemediation);
        let contracts_cancelled = count_status(&contracts, LiveSettlementContractStatus::Cancelled);
        let execution_payloads_ready = contracts_executable;
        let forced_exit_release_actions = contracts
            .values()
            .filter(|contract| {
                contract.action_kind == LiveSettlementActionKind::ExecuteForcedExitRelease
            })
            .count() as u64;
        let remediation_actions_applied = contracts
            .values()
            .filter(|contract| {
                contract.action_kind == LiveSettlementActionKind::ApplyRemediationPlan
            })
            .count() as u64;
        let status = report_status(
            contracts_executable,
            contracts_held_readiness,
            contracts_held_remediation,
            contracts_cancelled,
        );
        let contract_records = contracts
            .values()
            .map(ForcedExitSettlementContract::public_record)
            .collect::<Vec<_>>();
        let payload_records = contracts
            .values()
            .map(|contract| {
                json!({
                    "contract_id": contract.contract_id,
                    "action_kind": contract.action_kind.as_str(),
                    "execution_payload_root": contract.execution_payload_root,
                    "release_claim_id": contract.release_claim_id,
                    "executable_after_height": contract.executable_after_height,
                    "expires_at_height": contract.expires_at_height,
                })
            })
            .collect::<Vec<_>>();
        let receipt_records = contracts
            .values()
            .map(|contract| {
                json!({
                    "contract_id": contract.contract_id,
                    "status": contract.status.as_str(),
                    "execution_receipt_root": contract.execution_receipt_root,
                    "cancellation_root": contract.cancellation_root,
                    "hold_reason": contract.hold_reason,
                })
            })
            .collect::<Vec<_>>();
        let contract_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-CONTRACTS",
            &contract_records,
        );
        let payload_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-PAYLOADS",
            &payload_records,
        );
        let receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-RECEIPTS",
            &receipt_records,
        );
        let source_root = source_root(
            &queue_handler.state_root(),
            &queue_report.state_root(),
            &readiness.state_root(),
            &readiness_receipt.state_root(),
            &remediation.state_root(),
            &remediation_plan.state_root(),
        );
        let report_root = live_settlement_execution_report_root(
            status,
            &source_root,
            &contract_root,
            &payload_root,
            &receipt_root,
            &queue_report.release_claim_id,
            contracts_executable,
            contracts_held_readiness,
            contracts_held_remediation,
            contracts_cancelled,
        );
        let report_id =
            live_settlement_execution_report_id(&queue_report.release_claim_id, &report_root);
        let report = LiveSettlementExecutionReport {
            report_id: report_id.clone(),
            status,
            release_claim_id: queue_report.release_claim_id.clone(),
            queue_handler_report_root: queue_report.state_root(),
            readiness_receipt_root: readiness_receipt.state_root(),
            remediation_plan_root: remediation_plan.state_root(),
            contracts_total,
            contracts_executable,
            contracts_held_readiness,
            contracts_held_remediation,
            contracts_cancelled,
            execution_payloads_ready,
            forced_exit_release_actions,
            remediation_actions_applied,
            contracts,
            roots: LiveSettlementExecutionReportRoots {
                contract_root,
                payload_root,
                receipt_root,
                source_root,
                report_root,
            },
        };
        self.record_report(report);
        Ok(report_id)
    }

    pub fn public_record(&self) -> Value {
        let reports = self
            .report_history
            .iter()
            .map(LiveSettlementExecutionReport::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "latest_report": self.latest_report.as_ref().map(LiveSettlementExecutionReport::public_record),
            "report_history": reports,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn validate(&self) -> Result<String> {
        ensure(
            self.config.protocol_version == PROTOCOL_VERSION,
            "live settlement execution contract protocol version mismatch",
        )?;
        ensure(
            self.config.schema_version == SCHEMA_VERSION,
            "live settlement execution contract schema version mismatch",
        )?;
        ensure(
            self.report_history.len() <= self.config.max_reports,
            "live settlement execution contract report history exceeds limit",
        )?;
        ensure(
            self.roots.state_root == self.roots.compute_state_root(),
            "live settlement execution contract state root mismatch",
        )?;
        Ok(self.state_root())
    }

    fn record_report(&mut self, report: LiveSettlementExecutionReport) {
        self.counters.reports_run = self.counters.reports_run.saturating_add(1);
        match report.status {
            LiveSettlementExecutionReportStatus::Ready => {
                self.counters.reports_ready = self.counters.reports_ready.saturating_add(1);
            }
            LiveSettlementExecutionReportStatus::Watch => {
                self.counters.reports_watch = self.counters.reports_watch.saturating_add(1);
            }
            LiveSettlementExecutionReportStatus::Blocked => {
                self.counters.reports_blocked = self.counters.reports_blocked.saturating_add(1);
            }
        }
        self.counters.contracts_total = self
            .counters
            .contracts_total
            .saturating_add(report.contracts_total);
        self.counters.contracts_executable = self
            .counters
            .contracts_executable
            .saturating_add(report.contracts_executable);
        self.counters.contracts_held_readiness = self
            .counters
            .contracts_held_readiness
            .saturating_add(report.contracts_held_readiness);
        self.counters.contracts_held_remediation = self
            .counters
            .contracts_held_remediation
            .saturating_add(report.contracts_held_remediation);
        self.counters.contracts_cancelled = self
            .counters
            .contracts_cancelled
            .saturating_add(report.contracts_cancelled);
        self.counters.execution_payloads_ready = self
            .counters
            .execution_payloads_ready
            .saturating_add(report.execution_payloads_ready);
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_reports {
            let excess = self.report_history.len() - self.config.max_reports;
            self.report_history.drain(0..excess);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let report_records = self
            .report_history
            .iter()
            .map(LiveSettlementExecutionReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-REPORT-HISTORY",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
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

fn build_contracts(
    config: &Config,
    queue_report: &ExitClaimQueueHandlerReport,
    readiness_receipt: &BridgeExitReleaseReadinessReceipt,
    remediation_plan: &ReleaseRemediationPlan,
) -> BTreeMap<String, ForcedExitSettlementContract> {
    let mut contracts = BTreeMap::new();
    let remediation_root = remediation_action_root(remediation_plan);
    for envelope in queue_report.envelopes.values() {
        let status = contract_status(
            config,
            queue_report,
            readiness_receipt,
            remediation_plan,
            envelope.status,
        );
        let action_kind = action_kind(status, envelope.status, envelope.challenge_window_elapsed);
        let hold_reason =
            hold_reason(config, readiness_receipt, remediation_plan, envelope.status).to_string();
        let executable_after_height = envelope.executable_after_height;
        let expires_at_height = executable_after_height
            .saturating_add(config.execution_ttl_blocks)
            .max(envelope.expires_at_height);
        let fee_cap_bps = envelope.fee_cap_bps.min(config.max_execution_fee_bps);
        let execution_precondition_root = execution_precondition_root(
            readiness_receipt.status,
            remediation_plan.status,
            queue_report.status,
            envelope.status,
            config.live_execution_enabled,
            &hold_reason,
        );
        let execution_payload_root = execution_payload_root(
            action_kind,
            &envelope.release_claim_id,
            &envelope.settlement_call_root,
            &execution_precondition_root,
            executable_after_height,
            expires_at_height,
            fee_cap_bps,
        );
        let execution_receipt_root = execution_receipt_root(
            status,
            action_kind,
            &execution_payload_root,
            &envelope.settlement_receipt_root,
            &readiness_receipt.roots.receipt_root,
            &remediation_plan.roots.plan_root,
        );
        let cancellation_root = cancellation_root(
            status,
            &envelope.release_claim_id,
            &envelope.envelope_id,
            &hold_reason,
        );
        let contract_root = forced_exit_settlement_contract_root(
            status,
            action_kind,
            &envelope.envelope_id,
            &envelope.release_claim_id,
            &execution_precondition_root,
            &execution_payload_root,
            &execution_receipt_root,
            &cancellation_root,
        );
        let contract_id = forced_exit_settlement_contract_id(
            &envelope.release_claim_id,
            &envelope.envelope_id,
            &contract_root,
        );
        let contract = ForcedExitSettlementContract {
            contract_id: contract_id.clone(),
            status,
            action_kind,
            envelope_id: envelope.envelope_id.clone(),
            release_claim_id: envelope.release_claim_id.clone(),
            transfer_id: envelope.transfer_id.clone(),
            scenario_id: envelope.scenario_id.clone(),
            queue_position: envelope.queue_position,
            executable_after_height,
            expires_at_height,
            fee_cap_bps,
            live_execution_enabled: config.live_execution_enabled,
            readiness_status: readiness_receipt.status,
            remediation_status: remediation_plan.status,
            queue_report_status: queue_report.status,
            queue_envelope_status: envelope.status,
            settlement_call_root: envelope.settlement_call_root.clone(),
            settlement_receipt_root: envelope.settlement_receipt_root.clone(),
            readiness_receipt_root: readiness_receipt.state_root(),
            remediation_plan_root: remediation_plan.state_root(),
            remediation_action_root: remediation_root.clone(),
            execution_precondition_root,
            execution_payload_root,
            execution_receipt_root,
            cancellation_root,
            contract_root,
            hold_reason,
        };
        contracts.insert(contract_id, contract);
    }
    contracts
}

fn count_status(
    contracts: &BTreeMap<String, ForcedExitSettlementContract>,
    status: LiveSettlementContractStatus,
) -> u64 {
    contracts
        .values()
        .filter(|contract| contract.status == status)
        .count() as u64
}

fn contract_status(
    config: &Config,
    queue_report: &ExitClaimQueueHandlerReport,
    readiness_receipt: &BridgeExitReleaseReadinessReceipt,
    remediation_plan: &ReleaseRemediationPlan,
    envelope_status: ExitClaimQueueHandlerEnvelopeStatus,
) -> LiveSettlementContractStatus {
    if envelope_status == ExitClaimQueueHandlerEnvelopeStatus::Rejected {
        return LiveSettlementContractStatus::Cancelled;
    }
    if config.fail_closed_on_queue_watch
        && queue_report.status != ExitClaimQueueHandlerReportStatus::Passed
    {
        return LiveSettlementContractStatus::HeldForReadiness;
    }
    if config.require_readiness_ready && readiness_receipt.status != ReleaseReadinessStatus::Ready {
        return LiveSettlementContractStatus::HeldForReadiness;
    }
    if config.require_remediation_clear && remediation_plan.status != RemediationPlanStatus::Clear {
        return LiveSettlementContractStatus::HeldForRemediation;
    }
    if !config.live_execution_enabled
        || envelope_status != ExitClaimQueueHandlerEnvelopeStatus::Prepared
    {
        return LiveSettlementContractStatus::HeldForReadiness;
    }
    LiveSettlementContractStatus::Executable
}

fn action_kind(
    status: LiveSettlementContractStatus,
    envelope_status: ExitClaimQueueHandlerEnvelopeStatus,
    challenge_window_elapsed: bool,
) -> LiveSettlementActionKind {
    match status {
        LiveSettlementContractStatus::Executable => {
            LiveSettlementActionKind::ExecuteForcedExitRelease
        }
        LiveSettlementContractStatus::HeldForRemediation => {
            LiveSettlementActionKind::ApplyRemediationPlan
        }
        LiveSettlementContractStatus::Cancelled => LiveSettlementActionKind::CancelRejectedClaim,
        LiveSettlementContractStatus::HeldForReadiness => {
            if envelope_status == ExitClaimQueueHandlerEnvelopeStatus::Held
                && !challenge_window_elapsed
            {
                LiveSettlementActionKind::HoldChallengeWindow
            } else {
                LiveSettlementActionKind::HoldReadinessGate
            }
        }
    }
}

fn hold_reason(
    config: &Config,
    readiness_receipt: &BridgeExitReleaseReadinessReceipt,
    remediation_plan: &ReleaseRemediationPlan,
    envelope_status: ExitClaimQueueHandlerEnvelopeStatus,
) -> &'static str {
    if envelope_status == ExitClaimQueueHandlerEnvelopeStatus::Rejected {
        "claim_queue_rejected"
    } else if !config.live_execution_enabled {
        "live_execution_disabled"
    } else if readiness_receipt.status != ReleaseReadinessStatus::Ready {
        "release_readiness_not_ready"
    } else if remediation_plan.status != RemediationPlanStatus::Clear {
        "release_remediation_plan_active"
    } else if envelope_status == ExitClaimQueueHandlerEnvelopeStatus::Held {
        "claim_queue_envelope_held"
    } else {
        "none"
    }
}

fn remediation_action_root(plan: &ReleaseRemediationPlan) -> String {
    let records = plan
        .actions
        .values()
        .filter(|action| {
            action.kind == RemediationActionKind::EnableLiveSettlementExecution
                || action.status != RemediationActionStatus::Complete
        })
        .map(|action| {
            json!({
                "action_id": action.action_id,
                "kind": action.kind.as_str(),
                "status": action.status.as_str(),
                "action_root": action.action_root,
                "priority_rank": action.priority_rank,
                "blocks_user_release": action.blocks_user_release,
                "blocks_production": action.blocks_production,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-REMEDIATION-ACTIONS",
        &records,
    )
}

fn report_status(
    executable: u64,
    held_readiness: u64,
    held_remediation: u64,
    cancelled: u64,
) -> LiveSettlementExecutionReportStatus {
    if executable > 0 && held_readiness == 0 && held_remediation == 0 && cancelled == 0 {
        LiveSettlementExecutionReportStatus::Ready
    } else if held_remediation > 0 || executable > 0 {
        LiveSettlementExecutionReportStatus::Watch
    } else {
        LiveSettlementExecutionReportStatus::Blocked
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execution_precondition_root(
    readiness_status: ReleaseReadinessStatus,
    remediation_status: RemediationPlanStatus,
    queue_report_status: ExitClaimQueueHandlerReportStatus,
    envelope_status: ExitClaimQueueHandlerEnvelopeStatus,
    live_execution_enabled: bool,
    hold_reason: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-PRECONDITION",
        &[
            HashPart::Str(readiness_status.as_str()),
            HashPart::Str(remediation_status.as_str()),
            HashPart::Str(queue_report_status.as_str()),
            HashPart::Str(envelope_status.as_str()),
            HashPart::Str(bool_str(live_execution_enabled)),
            HashPart::Str(hold_reason),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_payload_root(
    action_kind: LiveSettlementActionKind,
    release_claim_id: &str,
    settlement_call_root: &str,
    precondition_root: &str,
    executable_after_height: u64,
    expires_at_height: u64,
    fee_cap_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-PAYLOAD",
        &[
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(settlement_call_root),
            HashPart::Str(precondition_root),
            HashPart::U64(executable_after_height),
            HashPart::U64(expires_at_height),
            HashPart::U64(fee_cap_bps),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_receipt_root(
    status: LiveSettlementContractStatus,
    action_kind: LiveSettlementActionKind,
    payload_root: &str,
    settlement_receipt_root: &str,
    readiness_receipt_root: &str,
    remediation_plan_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-RECEIPT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(payload_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(readiness_receipt_root),
            HashPart::Str(remediation_plan_root),
        ],
        32,
    )
}

pub fn cancellation_root(
    status: LiveSettlementContractStatus,
    release_claim_id: &str,
    envelope_id: &str,
    hold_reason: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-CANCELLATION",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(envelope_id),
            HashPart::Str(hold_reason),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn forced_exit_settlement_contract_root(
    status: LiveSettlementContractStatus,
    action_kind: LiveSettlementActionKind,
    envelope_id: &str,
    release_claim_id: &str,
    precondition_root: &str,
    payload_root: &str,
    receipt_root: &str,
    cancellation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-CONTRACT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(envelope_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(precondition_root),
            HashPart::Str(payload_root),
            HashPart::Str(receipt_root),
            HashPart::Str(cancellation_root),
        ],
        32,
    )
}

pub fn forced_exit_settlement_contract_id(
    release_claim_id: &str,
    envelope_id: &str,
    contract_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-CONTRACT-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(envelope_id),
            HashPart::Str(contract_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    queue_state_root: &str,
    queue_report_root: &str,
    readiness_state_root: &str,
    readiness_receipt_root: &str,
    remediation_state_root: &str,
    remediation_plan_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-SOURCE",
        &[
            HashPart::Str(queue_state_root),
            HashPart::Str(queue_report_root),
            HashPart::Str(readiness_state_root),
            HashPart::Str(readiness_receipt_root),
            HashPart::Str(remediation_state_root),
            HashPart::Str(remediation_plan_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn live_settlement_execution_report_root(
    status: LiveSettlementExecutionReportStatus,
    source_root: &str,
    contract_root: &str,
    payload_root: &str,
    receipt_root: &str,
    release_claim_id: &str,
    contracts_executable: u64,
    contracts_held_readiness: u64,
    contracts_held_remediation: u64,
    contracts_cancelled: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(contract_root),
            HashPart::Str(payload_root),
            HashPart::Str(receipt_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(contracts_executable),
            HashPart::U64(contracts_held_readiness),
            HashPart::U64(contracts_held_remediation),
            HashPart::U64(contracts_cancelled),
        ],
        32,
    )
}

pub fn live_settlement_execution_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-LIVE-SETTLEMENT-EXECUTION-RECORD",
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
