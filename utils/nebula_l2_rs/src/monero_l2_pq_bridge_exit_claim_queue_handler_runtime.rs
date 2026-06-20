use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::{
        ExitClaimQueueAdapterReport, ExitClaimQueueReportStatus, ExitClaimQueueResponse,
        ExitQueueEntryStatus, State as ExitClaimQueueAdapterState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitClaimQueueHandlerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CLAIM_QUEUE_HANDLER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-claim-queue-handler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CLAIM_QUEUE_HANDLER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXIT_CLAIM_QUEUE_HANDLER_SUITE: &str = "monero-l2-pq-bridge-exit-claim-queue-handler-v1";
pub const DEFAULT_MIN_HANDLER_ENVELOPES: u64 = 15;
pub const DEFAULT_CURRENT_HANDLER_HEIGHT: u64 = 4_200_192;
pub const DEFAULT_SETTLEMENT_CALL_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_BATCH_SIZE: u64 = 64;
pub const DEFAULT_MAX_SETTLEMENT_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClaimQueueHandlerEnvelopeStatus {
    Prepared,
    Held,
    Rejected,
}

impl ExitClaimQueueHandlerEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClaimQueueHandlerCallKind {
    PrepareSettlement,
    HoldSettlement,
    RejectSettlement,
}

impl ExitClaimQueueHandlerCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrepareSettlement => "prepare_settlement",
            Self::HoldSettlement => "hold_settlement",
            Self::RejectSettlement => "reject_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitClaimQueueHandlerReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ExitClaimQueueHandlerReportStatus {
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
    pub handler_suite: String,
    pub min_handler_envelopes: u64,
    pub current_handler_height: u64,
    pub settlement_call_ttl_blocks: u64,
    pub max_batch_size: u64,
    pub max_settlement_fee_bps: u64,
    pub live_settlement_enabled: bool,
    pub require_challenge_window_elapsed: bool,
    pub fail_closed_on_adapter_failure: bool,
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
            handler_suite: EXIT_CLAIM_QUEUE_HANDLER_SUITE.to_string(),
            min_handler_envelopes: DEFAULT_MIN_HANDLER_ENVELOPES,
            current_handler_height: DEFAULT_CURRENT_HANDLER_HEIGHT,
            settlement_call_ttl_blocks: DEFAULT_SETTLEMENT_CALL_TTL_BLOCKS,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_settlement_fee_bps: DEFAULT_MAX_SETTLEMENT_FEE_BPS,
            live_settlement_enabled: false,
            require_challenge_window_elapsed: true,
            fail_closed_on_adapter_failure: true,
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
            "handler_suite": self.handler_suite,
            "min_handler_envelopes": self.min_handler_envelopes,
            "current_handler_height": self.current_handler_height,
            "settlement_call_ttl_blocks": self.settlement_call_ttl_blocks,
            "max_batch_size": self.max_batch_size,
            "max_settlement_fee_bps": self.max_settlement_fee_bps,
            "live_settlement_enabled": self.live_settlement_enabled,
            "require_challenge_window_elapsed": self.require_challenge_window_elapsed,
            "fail_closed_on_adapter_failure": self.fail_closed_on_adapter_failure,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimSettlementEnvelope {
    pub envelope_id: String,
    pub status: ExitClaimQueueHandlerEnvelopeStatus,
    pub call_kind: ExitClaimQueueHandlerCallKind,
    pub entry_id: String,
    pub response_id: String,
    pub failure_id: String,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub scenario_id: String,
    pub queue_position: u64,
    pub timeout_height: u64,
    pub executable_after_height: u64,
    pub expires_at_height: u64,
    pub challenge_window_elapsed: bool,
    pub live_settlement_enabled: bool,
    pub adapter_report_status: ExitClaimQueueReportStatus,
    pub entry_status: ExitQueueEntryStatus,
    pub response_queued: bool,
    pub queue_hold_required: bool,
    pub quarantine_required: bool,
    pub fee_cap_bps: u64,
    pub challenge_window_root: String,
    pub settlement_order_root: String,
    pub settlement_call_root: String,
    pub settlement_receipt_root: String,
    pub pq_authority_hint_root: String,
    pub privacy_budget_root: String,
    pub adapter_entry_root: String,
    pub adapter_response_root: String,
    pub adapter_failure_root: String,
    pub hold_reason: String,
    pub rejection_code: String,
    pub envelope_root: String,
}

impl ExitClaimSettlementEnvelope {
    pub fn from_adapter_records(
        config: &Config,
        adapter_report: &ExitClaimQueueAdapterReport,
        entry: &crate::monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::ExitClaimQueueEntry,
        response: &ExitClaimQueueResponse,
        failure: &crate::monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::ExitClaimQueueFailureSurface,
        ordinal: u64,
    ) -> Self {
        let challenge_window_elapsed = !config.require_challenge_window_elapsed
            || config.current_handler_height >= entry.challenge_window_end;
        let status = envelope_status(
            config,
            adapter_report.status,
            entry.status,
            response,
            failure,
            challenge_window_elapsed,
        );
        let call_kind = call_kind(status);
        let executable_after_height = entry
            .challenge_window_end
            .max(config.current_handler_height)
            .saturating_add(1);
        let expires_at_height = executable_after_height.saturating_add(
            config
                .settlement_call_ttl_blocks
                .saturating_add(ordinal % config.max_batch_size.max(1)),
        );
        let fee_cap_bps = ordinal
            .saturating_add(entry.queue_position)
            .min(config.max_settlement_fee_bps);
        let hold_reason = hold_reason(
            config,
            adapter_report.status,
            entry.status,
            response,
            challenge_window_elapsed,
        )
        .to_string();
        let rejection_code = rejection_code(config, entry.status, failure).to_string();
        let pq_authority_hint_root = pq_authority_hint_root(
            &config.chain_id,
            &entry.release_claim_id,
            &adapter_report.final_gate_report_root,
            &entry.settlement_order_root,
            entry.queue_position,
        );
        let privacy_budget_root = privacy_budget_root(
            &entry.fixture_root,
            &entry.adapter_input_root,
            &entry.readiness_root,
            &entry.release_claim_id,
            &hold_reason,
        );
        let adapter_entry_root = entry.state_root();
        let adapter_response_root = response.state_root();
        let adapter_failure_root = failure.state_root();
        let settlement_call_root = settlement_call_root(
            call_kind,
            &entry.release_claim_id,
            &entry.challenge_window_root,
            &entry.settlement_order_root,
            &pq_authority_hint_root,
            executable_after_height,
            expires_at_height,
            fee_cap_bps,
        );
        let settlement_receipt_root = settlement_receipt_root(
            status,
            &settlement_call_root,
            &adapter_entry_root,
            &adapter_response_root,
            &adapter_failure_root,
            config.live_settlement_enabled,
        );
        let envelope_root = settlement_envelope_root(
            status,
            call_kind,
            &entry.entry_id,
            &response.response_id,
            &failure.failure_id,
            &settlement_call_root,
            &settlement_receipt_root,
            &privacy_budget_root,
            &hold_reason,
            &rejection_code,
        );
        let envelope_id = settlement_envelope_id(
            &entry.release_claim_id,
            entry.queue_position,
            &envelope_root,
        );
        Self {
            envelope_id,
            status,
            call_kind,
            entry_id: entry.entry_id.clone(),
            response_id: response.response_id.clone(),
            failure_id: failure.failure_id.clone(),
            release_claim_id: entry.release_claim_id.clone(),
            transfer_id: entry.transfer_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            queue_position: entry.queue_position,
            timeout_height: entry.timeout_height,
            executable_after_height,
            expires_at_height,
            challenge_window_elapsed,
            live_settlement_enabled: config.live_settlement_enabled,
            adapter_report_status: adapter_report.status,
            entry_status: entry.status,
            response_queued: response.queued,
            queue_hold_required: response.queue_hold_required,
            quarantine_required: failure.quarantine_required,
            fee_cap_bps,
            challenge_window_root: entry.challenge_window_root.clone(),
            settlement_order_root: entry.settlement_order_root.clone(),
            settlement_call_root,
            settlement_receipt_root,
            pq_authority_hint_root,
            privacy_budget_root,
            adapter_entry_root,
            adapter_response_root,
            adapter_failure_root,
            hold_reason,
            rejection_code,
            envelope_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "status": self.status.as_str(),
            "call_kind": self.call_kind.as_str(),
            "entry_id": self.entry_id,
            "response_id": self.response_id,
            "failure_id": self.failure_id,
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "scenario_id": self.scenario_id,
            "queue_position": self.queue_position,
            "timeout_height": self.timeout_height,
            "executable_after_height": self.executable_after_height,
            "expires_at_height": self.expires_at_height,
            "challenge_window_elapsed": self.challenge_window_elapsed,
            "live_settlement_enabled": self.live_settlement_enabled,
            "adapter_report_status": self.adapter_report_status.as_str(),
            "entry_status": self.entry_status.as_str(),
            "response_queued": self.response_queued,
            "queue_hold_required": self.queue_hold_required,
            "quarantine_required": self.quarantine_required,
            "fee_cap_bps": self.fee_cap_bps,
            "challenge_window_root": self.challenge_window_root,
            "settlement_order_root": self.settlement_order_root,
            "settlement_call_root": self.settlement_call_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "pq_authority_hint_root": self.pq_authority_hint_root,
            "privacy_budget_root": self.privacy_budget_root,
            "adapter_entry_root": self.adapter_entry_root,
            "adapter_response_root": self.adapter_response_root,
            "adapter_failure_root": self.adapter_failure_root,
            "hold_reason": self.hold_reason,
            "rejection_code": self.rejection_code,
            "envelope_root": self.envelope_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.envelope_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimQueueHandlerReport {
    pub report_id: String,
    pub status: ExitClaimQueueHandlerReportStatus,
    pub readiness_label: String,
    pub adapter_state_root: String,
    pub adapter_report_root: String,
    pub adapter_report_id: String,
    pub adapter_report_status: ExitClaimQueueReportStatus,
    pub release_claim_id: String,
    pub envelopes_total: u64,
    pub envelopes_prepared: u64,
    pub envelopes_held: u64,
    pub envelopes_rejected: u64,
    pub settlement_calls_ready: u64,
    pub challenge_window_holds: u64,
    pub live_settlement_holds: u64,
    pub quarantine_required: u64,
    pub envelopes: BTreeMap<String, ExitClaimSettlementEnvelope>,
    pub roots: ExitClaimQueueHandlerReportRoots,
}

impl ExitClaimQueueHandlerReport {
    pub fn public_record(&self) -> Value {
        let envelopes = self
            .envelopes
            .values()
            .map(ExitClaimSettlementEnvelope::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "adapter_state_root": self.adapter_state_root,
            "adapter_report_root": self.adapter_report_root,
            "adapter_report_id": self.adapter_report_id,
            "adapter_report_status": self.adapter_report_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "envelopes_total": self.envelopes_total,
            "envelopes_prepared": self.envelopes_prepared,
            "envelopes_held": self.envelopes_held,
            "envelopes_rejected": self.envelopes_rejected,
            "settlement_calls_ready": self.settlement_calls_ready,
            "challenge_window_holds": self.challenge_window_holds,
            "live_settlement_holds": self.live_settlement_holds,
            "quarantine_required": self.quarantine_required,
            "envelopes": envelopes,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimQueueHandlerReportRoots {
    pub envelope_root: String,
    pub settlement_call_root: String,
    pub settlement_receipt_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl ExitClaimQueueHandlerReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_root": self.envelope_root,
            "settlement_call_root": self.settlement_call_root,
            "settlement_receipt_root": self.settlement_receipt_root,
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
    pub envelopes_total: u64,
    pub envelopes_prepared: u64,
    pub envelopes_held: u64,
    pub envelopes_rejected: u64,
    pub settlement_calls_ready: u64,
    pub challenge_window_holds: u64,
    pub live_settlement_holds: u64,
    pub quarantine_required: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "envelopes_total": self.envelopes_total,
            "envelopes_prepared": self.envelopes_prepared,
            "envelopes_held": self.envelopes_held,
            "envelopes_rejected": self.envelopes_rejected,
            "settlement_calls_ready": self.settlement_calls_ready,
            "challenge_window_holds": self.challenge_window_holds,
            "live_settlement_holds": self.live_settlement_holds,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-STATE",
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
    pub latest_report: Option<ExitClaimQueueHandlerReport>,
    pub report_history: Vec<ExitClaimQueueHandlerReport>,
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
        let adapter = crate::monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::devnet();
        state
            .process_claim_queue_handler(&adapter)
            .expect("devnet bridge exit claim queue handler");
        state
    }

    pub fn process_claim_queue_handler(
        &mut self,
        adapter: &ExitClaimQueueAdapterState,
    ) -> Result<String> {
        let adapter_report = adapter
            .latest_report
            .as_ref()
            .ok_or_else(|| "exit claim queue adapter has no latest report".to_string())?;
        ensure(
            adapter_report.entries_total >= self.config.min_handler_envelopes,
            "exit claim queue handler omitted required envelopes",
        )?;
        let mut envelopes = BTreeMap::new();
        for (ordinal, entry) in adapter_report.entries.values().enumerate() {
            let response = find_response(adapter_report, &entry.entry_id)?;
            let failure = find_failure(adapter_report, &entry.entry_id)?;
            let envelope = ExitClaimSettlementEnvelope::from_adapter_records(
                &self.config,
                adapter_report,
                entry,
                response,
                failure,
                ordinal as u64,
            );
            envelopes.insert(envelope.envelope_id.clone(), envelope);
        }
        let envelopes_total = envelopes.len() as u64;
        let envelopes_prepared = envelopes
            .values()
            .filter(|envelope| envelope.status == ExitClaimQueueHandlerEnvelopeStatus::Prepared)
            .count() as u64;
        let envelopes_held = envelopes
            .values()
            .filter(|envelope| envelope.status == ExitClaimQueueHandlerEnvelopeStatus::Held)
            .count() as u64;
        let envelopes_rejected = envelopes
            .values()
            .filter(|envelope| envelope.status == ExitClaimQueueHandlerEnvelopeStatus::Rejected)
            .count() as u64;
        let settlement_calls_ready = envelopes_prepared;
        let challenge_window_holds = envelopes
            .values()
            .filter(|envelope| {
                envelope.status == ExitClaimQueueHandlerEnvelopeStatus::Held
                    && !envelope.challenge_window_elapsed
            })
            .count() as u64;
        let live_settlement_holds = envelopes
            .values()
            .filter(|envelope| {
                envelope.status == ExitClaimQueueHandlerEnvelopeStatus::Held
                    && !envelope.live_settlement_enabled
            })
            .count() as u64;
        let quarantine_required = envelopes
            .values()
            .filter(|envelope| envelope.quarantine_required)
            .count() as u64;
        let status = report_status(
            adapter_report.status,
            envelopes_held,
            envelopes_rejected,
            self.config.live_settlement_enabled,
        );
        let readiness_label =
            readiness_label(status, self.config.live_settlement_enabled).to_string();
        let envelope_records = envelopes
            .values()
            .map(ExitClaimSettlementEnvelope::public_record)
            .collect::<Vec<_>>();
        let call_records = envelopes
            .values()
            .map(|envelope| {
                json!({
                    "envelope_id": envelope.envelope_id,
                    "call_kind": envelope.call_kind.as_str(),
                    "settlement_call_root": envelope.settlement_call_root,
                    "release_claim_id": envelope.release_claim_id,
                    "queue_position": envelope.queue_position,
                    "executable_after_height": envelope.executable_after_height,
                    "expires_at_height": envelope.expires_at_height,
                })
            })
            .collect::<Vec<_>>();
        let receipt_records = envelopes
            .values()
            .map(|envelope| {
                json!({
                    "envelope_id": envelope.envelope_id,
                    "status": envelope.status.as_str(),
                    "settlement_receipt_root": envelope.settlement_receipt_root,
                    "hold_reason": envelope.hold_reason,
                    "rejection_code": envelope.rejection_code,
                })
            })
            .collect::<Vec<_>>();
        let envelope_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-ENVELOPES",
            &envelope_records,
        );
        let settlement_call_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-CALLS",
            &call_records,
        );
        let settlement_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-RECEIPTS",
            &receipt_records,
        );
        let source_root = source_root(
            &adapter.state_root(),
            &adapter_report.state_root(),
            &adapter_report.roots.entry_root,
            &adapter_report.roots.response_root,
            &adapter_report.roots.failure_root,
            &adapter_report.roots.report_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &envelope_root,
            &settlement_call_root,
            &settlement_receipt_root,
            &adapter_report.release_claim_id,
        );
        let report_id =
            exit_claim_queue_handler_report_id(&adapter_report.release_claim_id, &report_root);
        let report = ExitClaimQueueHandlerReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            adapter_state_root: adapter.state_root(),
            adapter_report_root: adapter_report.state_root(),
            adapter_report_id: adapter_report.report_id.clone(),
            adapter_report_status: adapter_report.status,
            release_claim_id: adapter_report.release_claim_id.clone(),
            envelopes_total,
            envelopes_prepared,
            envelopes_held,
            envelopes_rejected,
            settlement_calls_ready,
            challenge_window_holds,
            live_settlement_holds,
            quarantine_required,
            envelopes,
            roots: ExitClaimQueueHandlerReportRoots {
                envelope_root,
                settlement_call_root,
                settlement_receipt_root,
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
            "handler_suite": self.config.handler_suite,
            "latest_report": self.latest_report.as_ref().map(ExitClaimQueueHandlerReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: ExitClaimQueueHandlerReport) {
        self.counters.reports_run += 1;
        self.counters.envelopes_total += report.envelopes_total;
        self.counters.envelopes_prepared += report.envelopes_prepared;
        self.counters.envelopes_held += report.envelopes_held;
        self.counters.envelopes_rejected += report.envelopes_rejected;
        self.counters.settlement_calls_ready += report.settlement_calls_ready;
        self.counters.challenge_window_holds += report.challenge_window_holds;
        self.counters.live_settlement_holds += report.live_settlement_holds;
        self.counters.quarantine_required += report.quarantine_required;
        match report.status {
            ExitClaimQueueHandlerReportStatus::Passed => self.counters.reports_passed += 1,
            ExitClaimQueueHandlerReportStatus::Watch => self.counters.reports_watch += 1,
            ExitClaimQueueHandlerReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(ExitClaimQueueHandlerReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn find_response<'a>(
    adapter_report: &'a ExitClaimQueueAdapterReport,
    entry_id: &str,
) -> Result<&'a ExitClaimQueueResponse> {
    adapter_report
        .responses
        .values()
        .find(|response| response.entry_id == entry_id)
        .ok_or_else(|| format!("missing claim queue response for entry {entry_id}"))
}

fn find_failure<'a>(
    adapter_report: &'a ExitClaimQueueAdapterReport,
    entry_id: &str,
) -> Result<
    &'a crate::monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::ExitClaimQueueFailureSurface,
> {
    adapter_report
        .failures
        .values()
        .find(|failure| failure.entry_id == entry_id)
        .ok_or_else(|| format!("missing claim queue failure surface for entry {entry_id}"))
}

fn envelope_status(
    config: &Config,
    adapter_status: ExitClaimQueueReportStatus,
    entry_status: ExitQueueEntryStatus,
    response: &ExitClaimQueueResponse,
    failure: &crate::monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::ExitClaimQueueFailureSurface,
    challenge_window_elapsed: bool,
) -> ExitClaimQueueHandlerEnvelopeStatus {
    if entry_status == ExitQueueEntryStatus::Rejected
        || failure.quarantine_required
        || (config.fail_closed_on_adapter_failure
            && adapter_status == ExitClaimQueueReportStatus::Failed)
    {
        ExitClaimQueueHandlerEnvelopeStatus::Rejected
    } else if entry_status != ExitQueueEntryStatus::Queued
        || response.queue_hold_required
        || adapter_status != ExitClaimQueueReportStatus::Passed
        || !challenge_window_elapsed
        || !config.live_settlement_enabled
    {
        ExitClaimQueueHandlerEnvelopeStatus::Held
    } else {
        ExitClaimQueueHandlerEnvelopeStatus::Prepared
    }
}

fn call_kind(status: ExitClaimQueueHandlerEnvelopeStatus) -> ExitClaimQueueHandlerCallKind {
    match status {
        ExitClaimQueueHandlerEnvelopeStatus::Prepared => {
            ExitClaimQueueHandlerCallKind::PrepareSettlement
        }
        ExitClaimQueueHandlerEnvelopeStatus::Held => ExitClaimQueueHandlerCallKind::HoldSettlement,
        ExitClaimQueueHandlerEnvelopeStatus::Rejected => {
            ExitClaimQueueHandlerCallKind::RejectSettlement
        }
    }
}

fn hold_reason(
    config: &Config,
    adapter_status: ExitClaimQueueReportStatus,
    entry_status: ExitQueueEntryStatus,
    response: &ExitClaimQueueResponse,
    challenge_window_elapsed: bool,
) -> &'static str {
    if entry_status == ExitQueueEntryStatus::Rejected {
        "entry_rejected"
    } else if entry_status == ExitQueueEntryStatus::Deferred {
        "entry_deferred"
    } else if response.queue_hold_required {
        "adapter_queue_hold_required"
    } else if adapter_status != ExitClaimQueueReportStatus::Passed {
        "adapter_report_not_passed"
    } else if !challenge_window_elapsed {
        "challenge_window_open"
    } else if !config.live_settlement_enabled {
        "live_settlement_deferred"
    } else {
        "none"
    }
}

fn rejection_code(
    config: &Config,
    entry_status: ExitQueueEntryStatus,
    failure: &crate::monero_l2_pq_bridge_exit_claim_queue_adapter_runtime::ExitClaimQueueFailureSurface,
) -> &'static str {
    if entry_status == ExitQueueEntryStatus::Rejected && failure.error_code != "none" {
        "adapter_rejected_entry"
    } else if failure.quarantine_required && config.fail_closed_on_adapter_failure {
        "adapter_quarantine_required"
    } else {
        "none"
    }
}

fn report_status(
    adapter_status: ExitClaimQueueReportStatus,
    envelopes_held: u64,
    envelopes_rejected: u64,
    live_settlement_enabled: bool,
) -> ExitClaimQueueHandlerReportStatus {
    if envelopes_rejected > 0 || adapter_status == ExitClaimQueueReportStatus::Failed {
        ExitClaimQueueHandlerReportStatus::Failed
    } else if envelopes_held > 0
        || adapter_status == ExitClaimQueueReportStatus::Watch
        || !live_settlement_enabled
    {
        ExitClaimQueueHandlerReportStatus::Watch
    } else {
        ExitClaimQueueHandlerReportStatus::Passed
    }
}

fn readiness_label(
    status: ExitClaimQueueHandlerReportStatus,
    live_settlement_enabled: bool,
) -> &'static str {
    match status {
        ExitClaimQueueHandlerReportStatus::Failed => "exit_claim_queue_handler_failed",
        ExitClaimQueueHandlerReportStatus::Watch if !live_settlement_enabled => {
            "exit_claim_queue_handler_watch_live_settlement_deferred"
        }
        ExitClaimQueueHandlerReportStatus::Watch => "exit_claim_queue_handler_watch",
        ExitClaimQueueHandlerReportStatus::Passed => "exit_claim_queue_handler_ready",
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
pub fn settlement_call_root(
    call_kind: ExitClaimQueueHandlerCallKind,
    release_claim_id: &str,
    challenge_window_root: &str,
    settlement_order_root: &str,
    pq_authority_hint_root: &str,
    executable_after_height: u64,
    expires_at_height: u64,
    fee_cap_bps: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-CALL-ROOT",
        &[
            HashPart::Str(call_kind.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(challenge_window_root),
            HashPart::Str(settlement_order_root),
            HashPart::Str(pq_authority_hint_root),
            HashPart::U64(executable_after_height),
            HashPart::U64(expires_at_height),
            HashPart::U64(fee_cap_bps),
        ],
        32,
    )
}

pub fn settlement_receipt_root(
    status: ExitClaimQueueHandlerEnvelopeStatus,
    settlement_call_root: &str,
    adapter_entry_root: &str,
    adapter_response_root: &str,
    adapter_failure_root: &str,
    live_settlement_enabled: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-RECEIPT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(settlement_call_root),
            HashPart::Str(adapter_entry_root),
            HashPart::Str(adapter_response_root),
            HashPart::Str(adapter_failure_root),
            HashPart::Str(bool_str(live_settlement_enabled)),
        ],
        32,
    )
}

pub fn pq_authority_hint_root(
    chain_id: &str,
    release_claim_id: &str,
    final_gate_report_root: &str,
    settlement_order_root: &str,
    queue_position: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-PQ-AUTHORITY-HINT",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(final_gate_report_root),
            HashPart::Str(settlement_order_root),
            HashPart::U64(queue_position),
        ],
        32,
    )
}

pub fn privacy_budget_root(
    fixture_root: &str,
    adapter_input_root: &str,
    readiness_root: &str,
    release_claim_id: &str,
    hold_reason: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-PRIVACY-BUDGET",
        &[
            HashPart::Str(fixture_root),
            HashPart::Str(adapter_input_root),
            HashPart::Str(readiness_root),
            HashPart::Str(release_claim_id),
            HashPart::Str(hold_reason),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn settlement_envelope_root(
    status: ExitClaimQueueHandlerEnvelopeStatus,
    call_kind: ExitClaimQueueHandlerCallKind,
    entry_id: &str,
    response_id: &str,
    failure_id: &str,
    settlement_call_root: &str,
    settlement_receipt_root: &str,
    privacy_budget_root: &str,
    hold_reason: &str,
    rejection_code: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-ENVELOPE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(call_kind.as_str()),
            HashPart::Str(entry_id),
            HashPart::Str(response_id),
            HashPart::Str(failure_id),
            HashPart::Str(settlement_call_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(privacy_budget_root),
            HashPart::Str(hold_reason),
            HashPart::Str(rejection_code),
        ],
        32,
    )
}

pub fn settlement_envelope_id(
    release_claim_id: &str,
    queue_position: u64,
    envelope_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-ENVELOPE-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::U64(queue_position),
            HashPart::Str(envelope_root),
        ],
        32,
    )
}

pub fn source_root(
    adapter_state_root: &str,
    adapter_report_root: &str,
    adapter_entry_root: &str,
    adapter_response_root: &str,
    adapter_failure_root: &str,
    adapter_full_report_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-SOURCE-ROOT",
        &[
            HashPart::Str(adapter_state_root),
            HashPart::Str(adapter_report_root),
            HashPart::Str(adapter_entry_root),
            HashPart::Str(adapter_response_root),
            HashPart::Str(adapter_failure_root),
            HashPart::Str(adapter_full_report_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: ExitClaimQueueHandlerReportStatus,
    readiness_label: &str,
    source_root: &str,
    envelope_root: &str,
    settlement_call_root: &str,
    settlement_receipt_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(envelope_root),
            HashPart::Str(settlement_call_root),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

pub fn exit_claim_queue_handler_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CLAIM-QUEUE-HANDLER-RECORD",
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
