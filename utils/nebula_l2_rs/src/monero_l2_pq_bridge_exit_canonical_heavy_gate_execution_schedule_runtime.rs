use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalHeavyGateExecutionScheduleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_EXECUTION_SCHEDULE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-schedule-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_EXECUTION_SCHEDULE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCHEDULE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-schedule-v1";
pub const DEFAULT_MIN_REQUIRED_STEPS: u64 = 10;
pub const DEFAULT_MIN_READY_STEPS: u64 = 8;
pub const DEFAULT_MAX_DEFERRED_STEPS: u64 = 5;
pub const DEFAULT_MAX_WATCH_STEPS: u64 = 2;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_LEAK_UNITS: u64 = 2;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 35_000_000;
pub const DEFAULT_MAX_SCHEDULE_ITEMS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleDomain {
    ReleaseCandidateEvidence,
    FixtureCaseSelector,
    FailureCaseHarness,
    LiveFeedStubSwap,
    WalletExitCliPayload,
    PqKeyRotationDrill,
    ReserveProofHandoff,
    PrivacyAuditArtifacts,
    GoNoGoMatrix,
    AuditScopeClosure,
    CargoRuntimeExecution,
    HeavyGateReceipt,
    ProductionReleaseDecision,
}

impl ScheduleDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCandidateEvidence => "release_candidate_evidence",
            Self::FixtureCaseSelector => "fixture_case_selector",
            Self::FailureCaseHarness => "failure_case_harness",
            Self::LiveFeedStubSwap => "live_feed_stub_swap",
            Self::WalletExitCliPayload => "wallet_exit_cli_payload",
            Self::PqKeyRotationDrill => "pq_key_rotation_drill",
            Self::ReserveProofHandoff => "reserve_proof_handoff",
            Self::PrivacyAuditArtifacts => "privacy_audit_artifacts",
            Self::GoNoGoMatrix => "go_no_go_matrix",
            Self::AuditScopeClosure => "audit_scope_closure",
            Self::CargoRuntimeExecution => "cargo_runtime_execution",
            Self::HeavyGateReceipt => "heavy_gate_receipt",
            Self::ProductionReleaseDecision => "production_release_decision",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::ReleaseCandidateEvidence => 0,
            Self::FixtureCaseSelector => 1,
            Self::FailureCaseHarness => 2,
            Self::LiveFeedStubSwap => 3,
            Self::WalletExitCliPayload => 4,
            Self::PqKeyRotationDrill => 5,
            Self::ReserveProofHandoff => 6,
            Self::PrivacyAuditArtifacts => 7,
            Self::GoNoGoMatrix => 8,
            Self::AuditScopeClosure => 9,
            Self::CargoRuntimeExecution => 10,
            Self::HeavyGateReceipt => 11,
            Self::ProductionReleaseDecision => 12,
        }
    }

    pub fn user_escape_critical(self) -> bool {
        matches!(
            self,
            Self::ReleaseCandidateEvidence
                | Self::FixtureCaseSelector
                | Self::FailureCaseHarness
                | Self::LiveFeedStubSwap
                | Self::WalletExitCliPayload
                | Self::PqKeyRotationDrill
                | Self::ReserveProofHandoff
                | Self::PrivacyAuditArtifacts
                | Self::GoNoGoMatrix
                | Self::AuditScopeClosure
                | Self::CargoRuntimeExecution
                | Self::HeavyGateReceipt
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Ready,
    Watch,
    Deferred,
    Blocked,
    Rejected,
}

impl ScheduleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_user_escape(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Deferred | Self::Blocked | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleBlocker {
    MissingEvidenceRoot,
    NonCanonicalOrder,
    OperatorCooperationRequired,
    FixtureSelectionMissing,
    FailureHarnessMissing,
    LiveFeedSwapDeferred,
    WalletPayloadMissing,
    PqWeightTooLow,
    ReserveCoverageTooLow,
    PrivacyBudgetExceeded,
    FeeCapExceeded,
    CargoRuntimeDeferred,
    HeavyGateNotExecuted,
    AuditScopeOpen,
    ProductionReleaseBlocked,
}

impl ScheduleBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingEvidenceRoot => "missing_evidence_root",
            Self::NonCanonicalOrder => "non_canonical_order",
            Self::OperatorCooperationRequired => "operator_cooperation_required",
            Self::FixtureSelectionMissing => "fixture_selection_missing",
            Self::FailureHarnessMissing => "failure_harness_missing",
            Self::LiveFeedSwapDeferred => "live_feed_swap_deferred",
            Self::WalletPayloadMissing => "wallet_payload_missing",
            Self::PqWeightTooLow => "pq_weight_too_low",
            Self::ReserveCoverageTooLow => "reserve_coverage_too_low",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::HeavyGateNotExecuted => "heavy_gate_not_executed",
            Self::AuditScopeOpen => "audit_scope_open",
            Self::ProductionReleaseBlocked => "production_release_blocked",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::MissingEvidenceRoot => "release_candidate_evidence",
            Self::NonCanonicalOrder => "heavy_gate_schedule",
            Self::OperatorCooperationRequired => "forced_exit_contract",
            Self::FixtureSelectionMissing => "fixture_case_selector",
            Self::FailureHarnessMissing => "failure_case_harness",
            Self::LiveFeedSwapDeferred => "live_feed_boundary",
            Self::WalletPayloadMissing => "wallet_cli_payload",
            Self::PqWeightTooLow => "pq_release_authority",
            Self::ReserveCoverageTooLow => "reserve_proof_handoff",
            Self::PrivacyBudgetExceeded => "privacy_audit",
            Self::FeeCapExceeded => "fee_policy",
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::HeavyGateNotExecuted => "heavy_gate_receipt",
            Self::AuditScopeOpen => "audit_scope_closure",
            Self::ProductionReleaseBlocked => "release_management",
        }
    }

    pub fn blocks_user_escape(self) -> bool {
        matches!(
            self,
            Self::MissingEvidenceRoot
                | Self::NonCanonicalOrder
                | Self::OperatorCooperationRequired
                | Self::FixtureSelectionMissing
                | Self::FailureHarnessMissing
                | Self::WalletPayloadMissing
                | Self::PqWeightTooLow
                | Self::ReserveCoverageTooLow
                | Self::PrivacyBudgetExceeded
                | Self::FeeCapExceeded
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleVerdict {
    ReadyToRunHeavyGate,
    ReadyButDeferredExecution,
    Watch,
    Blocked,
    Rejected,
}

impl ScheduleVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyToRunHeavyGate => "ready_to_run_heavy_gate",
            Self::ReadyButDeferredExecution => "ready_but_deferred_execution",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn user_answer(self) -> &'static str {
        match self {
            Self::ReadyToRunHeavyGate | Self::ReadyButDeferredExecution => {
                "schedule_preserves_get_in_move_private_force_out_evidence_path"
            }
            Self::Watch => "schedule_needs_followup_before_execution",
            Self::Blocked => "schedule_blocks_user_escape_verification",
            Self::Rejected => "schedule_rejected",
        }
    }

    pub fn production_answer(self) -> &'static str {
        match self {
            Self::ReadyToRunHeavyGate => {
                "heavy_gate_can_run_but_production_release_still_needs_execution_audit_signoff"
            }
            Self::ReadyButDeferredExecution => {
                "heavy_gate_schedule_is_ready_but_runtime_execution_is_deferred"
            }
            Self::Watch => "production_release_requires_watch_items_to_clear",
            Self::Blocked => "production_release_blocked_by_schedule",
            Self::Rejected => "production_release_rejected_by_schedule",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_required_steps: u64,
    pub min_ready_steps: u64,
    pub max_deferred_steps: u64,
    pub max_watch_steps: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_leak_units: u64,
    pub max_fee_atomic: u64,
    pub max_schedule_items: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_required_steps: DEFAULT_MIN_REQUIRED_STEPS,
            min_ready_steps: DEFAULT_MIN_READY_STEPS,
            max_deferred_steps: DEFAULT_MAX_DEFERRED_STEPS,
            max_watch_steps: DEFAULT_MAX_WATCH_STEPS,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_metadata_leak_units: DEFAULT_MAX_METADATA_LEAK_UNITS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            max_schedule_items: DEFAULT_MAX_SCHEDULE_ITEMS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleInput {
    pub domain: ScheduleDomain,
    pub required: bool,
    pub evidence_root: String,
    pub schedule_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub operator_independent: bool,
    pub fixture_selected: bool,
    pub failure_harness_selected: bool,
    pub live_feed_swap_ready: bool,
    pub wallet_payload_ready: bool,
    pub cargo_runtime_allowed: bool,
    pub heavy_gate_executed: bool,
    pub audit_scope_closed: bool,
    pub production_release_allowed: bool,
    pub pq_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub metadata_leak_units: u64,
    pub fee_atomic: u64,
}

impl ScheduleInput {
    pub fn leaf(&self) -> Value {
        json!({
            "domain": self.domain.as_str(),
            "domain_ordinal": self.domain.ordinal(),
            "required": self.required,
            "evidence_root": self.evidence_root,
            "schedule_root": self.schedule_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "operator_independent": self.operator_independent,
            "fixture_selected": self.fixture_selected,
            "failure_harness_selected": self.failure_harness_selected,
            "live_feed_swap_ready": self.live_feed_swap_ready,
            "wallet_payload_ready": self.wallet_payload_ready,
            "cargo_runtime_allowed": self.cargo_runtime_allowed,
            "heavy_gate_executed": self.heavy_gate_executed,
            "audit_scope_closed": self.audit_scope_closed,
            "production_release_allowed": self.production_release_allowed,
            "pq_weight_bps": self.pq_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "metadata_leak_units": self.metadata_leak_units,
            "fee_atomic": self.fee_atomic,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleItem {
    pub index: u64,
    pub domain: ScheduleDomain,
    pub required: bool,
    pub status: ScheduleStatus,
    pub blocker: Option<ScheduleBlocker>,
    pub owner_lane: Option<String>,
    pub evidence_root: String,
    pub schedule_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub item_root: String,
    pub user_escape_ready: bool,
    pub production_ready: bool,
}

impl ScheduleItem {
    pub fn from_input(index: u64, input: ScheduleInput, config: &Config) -> Self {
        let blocker = derive_blocker(index, &input, config);
        let status = derive_status(blocker, &input);
        let user_escape_ready = input.domain.user_escape_critical()
            && !status.blocks_user_escape()
            && input.operator_independent;
        let production_ready = !status.blocks_production()
            && input.cargo_runtime_allowed
            && input.heavy_gate_executed
            && input.audit_scope_closed
            && input.production_release_allowed;
        let owner_lane = blocker.map(|value| value.owner_lane().to_string());
        let item_leaf = json!({
            "index": index,
            "domain": input.domain.as_str(),
            "required": input.required,
            "status": status.as_str(),
            "blocker": blocker.map(ScheduleBlocker::as_str),
            "owner_lane": owner_lane,
            "evidence_root": input.evidence_root,
            "schedule_root": input.schedule_root,
            "public_root": input.public_root,
            "committed_root": input.committed_root,
            "encrypted_root": input.encrypted_root,
            "wallet_recovery_root": input.wallet_recovery_root,
            "user_escape_ready": user_escape_ready,
            "production_ready": production_ready,
        });
        let item_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-heavy-gate-schedule-item",
            &[HashPart::Json(&item_leaf)],
            32,
        );
        Self {
            index,
            domain: input.domain,
            required: input.required,
            status,
            blocker,
            owner_lane,
            evidence_root: input.evidence_root,
            schedule_root: input.schedule_root,
            public_root: input.public_root,
            committed_root: input.committed_root,
            encrypted_root: input.encrypted_root,
            wallet_recovery_root: input.wallet_recovery_root,
            item_root,
            user_escape_ready,
            production_ready,
        }
    }

    pub fn leaf(&self) -> Value {
        json!({
            "index": self.index,
            "domain": self.domain.as_str(),
            "required": self.required,
            "status": self.status.as_str(),
            "blocker": self.blocker.map(ScheduleBlocker::as_str),
            "owner_lane": self.owner_lane,
            "evidence_root": self.evidence_root,
            "schedule_root": self.schedule_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "item_root": self.item_root,
            "user_escape_ready": self.user_escape_ready,
            "production_ready": self.production_ready,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScheduleCounters {
    pub ready: u64,
    pub watch: u64,
    pub deferred: u64,
    pub blocked: u64,
    pub rejected: u64,
    pub required: u64,
    pub user_escape_ready: u64,
    pub production_ready: u64,
}

impl ScheduleCounters {
    pub fn ingest(&mut self, item: &ScheduleItem) {
        match item.status {
            ScheduleStatus::Ready => self.ready += 1,
            ScheduleStatus::Watch => self.watch += 1,
            ScheduleStatus::Deferred => self.deferred += 1,
            ScheduleStatus::Blocked => self.blocked += 1,
            ScheduleStatus::Rejected => self.rejected += 1,
        }
        if item.required {
            self.required += 1;
        }
        if item.user_escape_ready {
            self.user_escape_ready += 1;
        }
        if item.production_ready {
            self.production_ready += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.ready + self.watch + self.deferred + self.blocked + self.rejected
    }

    pub fn has_user_escape_blocker(&self) -> bool {
        self.blocked > 0 || self.rejected > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeavyGateExecutionSchedule {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub schedule_suite: String,
    pub verdict: ScheduleVerdict,
    pub user_answer: String,
    pub production_answer: String,
    pub schedule_plan_root: String,
    pub item_root: String,
    pub evidence_root: String,
    pub schedule_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub blocker_root: String,
    pub counters: ScheduleCounters,
    pub blocker_counts: BTreeMap<String, u64>,
    pub items: Vec<ScheduleItem>,
}

impl HeavyGateExecutionSchedule {
    pub fn from_items(config: &Config, items: Vec<ScheduleItem>) -> Self {
        let mut counters = ScheduleCounters::default();
        let mut blocker_counts = BTreeMap::new();
        for item in &items {
            counters.ingest(item);
            if let Some(blocker) = item.blocker {
                *blocker_counts
                    .entry(blocker.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }

        let item_leaves = items.iter().map(ScheduleItem::leaf).collect::<Vec<_>>();
        let evidence_leaves = root_leaves(&items, |item| &item.evidence_root);
        let schedule_leaves = root_leaves(&items, |item| &item.schedule_root);
        let public_leaves = root_leaves(&items, |item| &item.public_root);
        let committed_leaves = root_leaves(&items, |item| &item.committed_root);
        let encrypted_leaves = root_leaves(&items, |item| &item.encrypted_root);
        let wallet_leaves = root_leaves(&items, |item| &item.wallet_recovery_root);
        let blocker_leaves = blocker_counts
            .iter()
            .map(|(blocker, count)| json!({ "blocker": blocker, "count": count }))
            .collect::<Vec<_>>();

        let item_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-items",
            &item_leaves,
        );
        let evidence_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-evidence",
            &evidence_leaves,
        );
        let schedule_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-roots",
            &schedule_leaves,
        );
        let public_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-public",
            &public_leaves,
        );
        let committed_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-committed",
            &committed_leaves,
        );
        let encrypted_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-encrypted",
            &encrypted_leaves,
        );
        let wallet_recovery_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-wallet",
            &wallet_leaves,
        );
        let blocker_root = merkle_root(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-blockers",
            &blocker_leaves,
        );
        let verdict = derive_verdict(config, &counters);
        let schedule_payload = json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": config.chain_id,
            "schedule_suite": SCHEDULE_SUITE,
            "verdict": verdict.as_str(),
            "user_answer": verdict.user_answer(),
            "production_answer": verdict.production_answer(),
            "item_root": item_root,
            "evidence_root": evidence_root,
            "schedule_root": schedule_root,
            "public_root": public_root,
            "committed_root": committed_root,
            "encrypted_root": encrypted_root,
            "wallet_recovery_root": wallet_recovery_root,
            "blocker_root": blocker_root,
            "counters": counters,
        });
        let schedule_plan_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-schedule",
            &[HashPart::Json(&schedule_payload)],
            32,
        );
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: config.chain_id.clone(),
            schedule_suite: SCHEDULE_SUITE.to_string(),
            verdict,
            user_answer: verdict.user_answer().to_string(),
            production_answer: verdict.production_answer().to_string(),
            schedule_plan_root,
            item_root,
            evidence_root,
            schedule_root,
            public_root,
            committed_root,
            encrypted_root,
            wallet_recovery_root,
            blocker_root,
            counters,
            blocker_counts,
            items,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "schedule_suite": self.schedule_suite,
            "verdict": self.verdict.as_str(),
            "user_answer": self.user_answer,
            "production_answer": self.production_answer,
            "schedule_plan_root": self.schedule_plan_root,
            "item_root": self.item_root,
            "evidence_root": self.evidence_root,
            "schedule_root": self.schedule_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "blocker_root": self.blocker_root,
            "counters": self.counters,
            "blocker_counts": self.blocker_counts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub schedule: HeavyGateExecutionSchedule,
}

impl State {
    pub fn new() -> Self {
        Self::from_inputs(Config::default(), default_inputs())
    }

    pub fn from_inputs(config: Config, inputs: Vec<ScheduleInput>) -> Self {
        let items = inputs
            .into_iter()
            .enumerate()
            .map(|(index, input)| ScheduleItem::from_input(index as u64, input, &config))
            .collect::<Vec<_>>();
        let schedule = HeavyGateExecutionSchedule::from_items(&config, items);
        Self { config, schedule }
    }

    pub fn ingest(&mut self, input: ScheduleInput) -> Result<()> {
        if self.schedule.items.len() >= self.config.max_schedule_items {
            return Err("heavy-gate execution schedule item limit reached".to_string());
        }
        let mut inputs = self
            .schedule
            .items
            .iter()
            .map(schedule_item_to_input)
            .collect::<Vec<_>>();
        inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), inputs);
        Ok(())
    }

    pub fn ready_to_run_heavy_gate(&self) -> bool {
        matches!(
            self.schedule.verdict,
            ScheduleVerdict::ReadyToRunHeavyGate | ScheduleVerdict::ReadyButDeferredExecution
        )
    }

    pub fn production_blocked(&self) -> bool {
        !matches!(self.schedule.verdict, ScheduleVerdict::ReadyToRunHeavyGate)
            || self.schedule.counters.deferred > 0
            || self
                .schedule
                .blocker_counts
                .contains_key("production_release_blocked")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": {
                "chain_id": self.config.chain_id,
                "min_required_steps": self.config.min_required_steps,
                "min_ready_steps": self.config.min_ready_steps,
                "max_deferred_steps": self.config.max_deferred_steps,
                "max_watch_steps": self.config.max_watch_steps,
                "min_pq_weight_bps": self.config.min_pq_weight_bps,
                "min_reserve_coverage_bps": self.config.min_reserve_coverage_bps,
                "max_metadata_leak_units": self.config.max_metadata_leak_units,
                "max_fee_atomic": self.config.max_fee_atomic,
                "max_schedule_items": self.config.max_schedule_items,
            },
            "schedule": self.schedule.public_record(),
            "ready_to_run_heavy_gate": self.ready_to_run_heavy_gate(),
            "production_blocked": self.production_blocked(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_value(&self.public_record())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

pub fn devnet() -> State {
    State::new()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn state_root_from_value(value: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-schedule-state",
        &[HashPart::Json(value)],
        32,
    )
}

fn root_leaves(items: &[ScheduleItem], select: fn(&ScheduleItem) -> &String) -> Vec<Value> {
    items
        .iter()
        .map(|item| json!({ "domain": item.domain.as_str(), "root": select(item) }))
        .collect()
}

fn derive_blocker(index: u64, input: &ScheduleInput, config: &Config) -> Option<ScheduleBlocker> {
    if input.evidence_root.is_empty()
        || input.schedule_root.is_empty()
        || input.public_root.is_empty()
        || input.committed_root.is_empty()
    {
        return Some(ScheduleBlocker::MissingEvidenceRoot);
    }
    if index != input.domain.ordinal() {
        return Some(ScheduleBlocker::NonCanonicalOrder);
    }
    if !input.operator_independent && input.domain.user_escape_critical() {
        return Some(ScheduleBlocker::OperatorCooperationRequired);
    }
    if !input.fixture_selected
        && matches!(
            input.domain,
            ScheduleDomain::FixtureCaseSelector | ScheduleDomain::CargoRuntimeExecution
        )
    {
        return Some(ScheduleBlocker::FixtureSelectionMissing);
    }
    if !input.failure_harness_selected
        && matches!(
            input.domain,
            ScheduleDomain::FailureCaseHarness | ScheduleDomain::CargoRuntimeExecution
        )
    {
        return Some(ScheduleBlocker::FailureHarnessMissing);
    }
    if !input.live_feed_swap_ready && matches!(input.domain, ScheduleDomain::LiveFeedStubSwap) {
        return Some(ScheduleBlocker::LiveFeedSwapDeferred);
    }
    if !input.wallet_payload_ready && matches!(input.domain, ScheduleDomain::WalletExitCliPayload) {
        return Some(ScheduleBlocker::WalletPayloadMissing);
    }
    if input.pq_weight_bps < config.min_pq_weight_bps {
        return Some(ScheduleBlocker::PqWeightTooLow);
    }
    if input.reserve_coverage_bps < config.min_reserve_coverage_bps {
        return Some(ScheduleBlocker::ReserveCoverageTooLow);
    }
    if input.metadata_leak_units > config.max_metadata_leak_units {
        return Some(ScheduleBlocker::PrivacyBudgetExceeded);
    }
    if input.fee_atomic > config.max_fee_atomic {
        return Some(ScheduleBlocker::FeeCapExceeded);
    }
    if !input.cargo_runtime_allowed {
        return Some(ScheduleBlocker::CargoRuntimeDeferred);
    }
    if !input.heavy_gate_executed && matches!(input.domain, ScheduleDomain::HeavyGateReceipt) {
        return Some(ScheduleBlocker::HeavyGateNotExecuted);
    }
    if !input.audit_scope_closed && matches!(input.domain, ScheduleDomain::AuditScopeClosure) {
        return Some(ScheduleBlocker::AuditScopeOpen);
    }
    if !input.production_release_allowed
        && matches!(input.domain, ScheduleDomain::ProductionReleaseDecision)
    {
        return Some(ScheduleBlocker::ProductionReleaseBlocked);
    }
    None
}

fn derive_status(blocker: Option<ScheduleBlocker>, input: &ScheduleInput) -> ScheduleStatus {
    match blocker {
        None => ScheduleStatus::Ready,
        Some(ScheduleBlocker::LiveFeedSwapDeferred)
        | Some(ScheduleBlocker::CargoRuntimeDeferred)
        | Some(ScheduleBlocker::HeavyGateNotExecuted)
        | Some(ScheduleBlocker::AuditScopeOpen)
        | Some(ScheduleBlocker::ProductionReleaseBlocked) => ScheduleStatus::Deferred,
        Some(blocker) if blocker.blocks_user_escape() => ScheduleStatus::Blocked,
        Some(_) if input.required => ScheduleStatus::Blocked,
        Some(_) => ScheduleStatus::Rejected,
    }
}

fn derive_verdict(config: &Config, counters: &ScheduleCounters) -> ScheduleVerdict {
    if counters.rejected > 0 {
        return ScheduleVerdict::Rejected;
    }
    if counters.has_user_escape_blocker() {
        return ScheduleVerdict::Blocked;
    }
    if counters.watch > config.max_watch_steps {
        return ScheduleVerdict::Watch;
    }
    if counters.required < config.min_required_steps
        || counters.user_escape_ready < config.min_ready_steps
    {
        return ScheduleVerdict::Blocked;
    }
    if counters.deferred > config.max_deferred_steps {
        return ScheduleVerdict::Blocked;
    }
    if counters.watch > 0 {
        return ScheduleVerdict::Watch;
    }
    if counters.deferred > 0 {
        ScheduleVerdict::ReadyButDeferredExecution
    } else {
        ScheduleVerdict::ReadyToRunHeavyGate
    }
}

fn schedule_item_to_input(item: &ScheduleItem) -> ScheduleInput {
    ScheduleInput {
        domain: item.domain,
        required: item.required,
        evidence_root: item.evidence_root.clone(),
        schedule_root: item.schedule_root.clone(),
        public_root: item.public_root.clone(),
        committed_root: item.committed_root.clone(),
        encrypted_root: item.encrypted_root.clone(),
        wallet_recovery_root: item.wallet_recovery_root.clone(),
        operator_independent: item.user_escape_ready,
        fixture_selected: item.user_escape_ready,
        failure_harness_selected: item.user_escape_ready,
        live_feed_swap_ready: item.user_escape_ready,
        wallet_payload_ready: item.user_escape_ready,
        cargo_runtime_allowed: item.production_ready,
        heavy_gate_executed: item.production_ready,
        audit_scope_closed: item.production_ready,
        production_release_allowed: item.production_ready,
        pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
        metadata_leak_units: 1,
        fee_atomic: DEFAULT_MAX_FEE_ATOMIC / 2,
    }
}

fn default_inputs() -> Vec<ScheduleInput> {
    [
        ScheduleDomain::ReleaseCandidateEvidence,
        ScheduleDomain::FixtureCaseSelector,
        ScheduleDomain::FailureCaseHarness,
        ScheduleDomain::LiveFeedStubSwap,
        ScheduleDomain::WalletExitCliPayload,
        ScheduleDomain::PqKeyRotationDrill,
        ScheduleDomain::ReserveProofHandoff,
        ScheduleDomain::PrivacyAuditArtifacts,
        ScheduleDomain::GoNoGoMatrix,
        ScheduleDomain::AuditScopeClosure,
        ScheduleDomain::CargoRuntimeExecution,
        ScheduleDomain::HeavyGateReceipt,
        ScheduleDomain::ProductionReleaseDecision,
    ]
    .iter()
    .map(|domain| default_input(*domain))
    .collect()
}

fn default_input(domain: ScheduleDomain) -> ScheduleInput {
    let domain_name = domain.as_str();
    let evidence_payload = json!({
        "domain": domain_name,
        "artifact": "canonical-heavy-gate-schedule-evidence",
        "wallet_metadata": "redacted",
    });
    let schedule_payload = json!({
        "domain": domain_name,
        "sequence": domain.ordinal(),
        "action": "schedule-heavy-gate-step",
    });
    let public_payload = json!({
        "domain": domain_name,
        "public": "redacted-heavy-gate-anchor",
    });
    let committed_payload = json!({
        "domain": domain_name,
        "commitment": "heavy-gate-schedule-commitment",
    });
    let encrypted_payload = json!({
        "domain": domain_name,
        "encrypted": "wallet-safe-schedule-shard",
    });
    let wallet_payload = json!({
        "domain": domain_name,
        "wallet": "force-exit-reconstruction-root",
    });
    ScheduleInput {
        domain,
        required: domain != ScheduleDomain::ProductionReleaseDecision,
        evidence_root: domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-evidence-root",
            &[HashPart::Json(&evidence_payload)],
            32,
        ),
        schedule_root: domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-step-root",
            &[HashPart::Json(&schedule_payload)],
            32,
        ),
        public_root: domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-public-root",
            &[HashPart::Json(&public_payload)],
            32,
        ),
        committed_root: domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-committed-root",
            &[HashPart::Json(&committed_payload)],
            32,
        ),
        encrypted_root: domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-encrypted-root",
            &[HashPart::Json(&encrypted_payload)],
            32,
        ),
        wallet_recovery_root: domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-schedule-wallet-root",
            &[HashPart::Json(&wallet_payload)],
            32,
        ),
        operator_independent: true,
        fixture_selected: true,
        failure_harness_selected: true,
        live_feed_swap_ready: domain != ScheduleDomain::LiveFeedStubSwap,
        wallet_payload_ready: true,
        cargo_runtime_allowed: !matches!(
            domain,
            ScheduleDomain::CargoRuntimeExecution | ScheduleDomain::HeavyGateReceipt
        ),
        heavy_gate_executed: domain != ScheduleDomain::HeavyGateReceipt,
        audit_scope_closed: domain != ScheduleDomain::AuditScopeClosure,
        production_release_allowed: domain != ScheduleDomain::ProductionReleaseDecision,
        pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS + 900,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS + 1_500,
        metadata_leak_units: 1,
        fee_atomic: DEFAULT_MAX_FEE_ATOMIC / 2,
    }
}
