use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::{
        BridgeExitReleaseReadinessReceipt, ReleaseReadinessDimension, ReleaseReadinessItem,
        ReleaseReadinessStatus, State as ReleaseReadinessState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReleaseRemediationPlannerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_REMEDIATION_PLANNER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-release-remediation-planner-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_REMEDIATION_PLANNER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_REMEDIATION_PLANNER_SUITE: &str =
    "monero-l2-pq-bridge-exit-release-remediation-planner-v1";
pub const DEFAULT_MIN_REMEDIATION_ACTIONS: u64 = 4;
pub const DEFAULT_REMEDIATION_RETRY_BLOCKS: u64 = 30;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationActionKind {
    EnableLiveSettlementExecution,
    EnablePqAuthorityVerification,
    MaterializeCargoRuntimeTests,
    CompleteSecurityPrivacyAudit,
    ResolveForcedExitUserAnswer,
    ClearProductionReleaseGate,
    PreservePrivacyReceiptScanning,
}

impl RemediationActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnableLiveSettlementExecution => "enable_live_settlement_execution",
            Self::EnablePqAuthorityVerification => "enable_pq_authority_verification",
            Self::MaterializeCargoRuntimeTests => "materialize_cargo_runtime_tests",
            Self::CompleteSecurityPrivacyAudit => "complete_security_privacy_audit",
            Self::ResolveForcedExitUserAnswer => "resolve_forced_exit_user_answer",
            Self::ClearProductionReleaseGate => "clear_production_release_gate",
            Self::PreservePrivacyReceiptScanning => "preserve_privacy_receipt_scanning",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationActionStatus {
    ReadyToStart,
    WaitingOnDeferredGate,
    Blocked,
    Complete,
}

impl RemediationActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyToStart => "ready_to_start",
            Self::WaitingOnDeferredGate => "waiting_on_deferred_gate",
            Self::Blocked => "blocked",
            Self::Complete => "complete",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl RemediationSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationPlanStatus {
    Clear,
    Active,
    Blocked,
}

impl RemediationPlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::Active => "active",
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
    pub planner_suite: String,
    pub min_remediation_actions: u64,
    pub retry_after_blocks: u64,
    pub prioritize_user_exit: bool,
    pub prioritize_pq_authority: bool,
    pub prioritize_runtime_tests: bool,
    pub production_release_allowed: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            planner_suite: RELEASE_REMEDIATION_PLANNER_SUITE.to_string(),
            min_remediation_actions: DEFAULT_MIN_REMEDIATION_ACTIONS,
            retry_after_blocks: DEFAULT_REMEDIATION_RETRY_BLOCKS,
            prioritize_user_exit: true,
            prioritize_pq_authority: true,
            prioritize_runtime_tests: true,
            production_release_allowed: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "planner_suite": self.planner_suite,
            "min_remediation_actions": self.min_remediation_actions,
            "retry_after_blocks": self.retry_after_blocks,
            "prioritize_user_exit": self.prioritize_user_exit,
            "prioritize_pq_authority": self.prioritize_pq_authority,
            "prioritize_runtime_tests": self.prioritize_runtime_tests,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationAction {
    pub action_id: String,
    pub kind: RemediationActionKind,
    pub status: RemediationActionStatus,
    pub severity: RemediationSeverity,
    pub priority_rank: u64,
    pub release_claim_id: String,
    pub source_dimension: ReleaseReadinessDimension,
    pub source_status: ReleaseReadinessStatus,
    pub source_item_id: String,
    pub source_readiness_root: String,
    pub source_root: String,
    pub owner_lane: String,
    pub objective: String,
    pub acceptance_criteria: String,
    pub expected_unblock: String,
    pub expected_next_status: ReleaseReadinessStatus,
    pub retry_after_blocks: u64,
    pub manual_required: bool,
    pub evidence_root: String,
    pub dependency_root: String,
    pub acceptance_root: String,
    pub action_root: String,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
}

impl RemediationAction {
    pub fn from_item(
        config: &Config,
        release_claim_id: &str,
        item: &ReleaseReadinessItem,
        ordinal: u64,
    ) -> Self {
        let kind = action_kind(item.dimension);
        let status = action_status(item.status, item.blocks_user_release);
        let severity = severity(item);
        let priority_rank = priority_rank(config, item, ordinal);
        let owner_lane = owner_lane(kind).to_string();
        let objective = objective(kind, item).to_string();
        let acceptance_criteria = acceptance_criteria(kind).to_string();
        let expected_unblock = expected_unblock(item).to_string();
        let expected_next_status = expected_next_status(kind);
        let retry_after_blocks = retry_after_blocks(config, item);
        let manual_required = manual_required(kind, item);
        let evidence_root = remediation_evidence_root(
            release_claim_id,
            kind,
            item.dimension,
            item.status,
            &item.source_root,
            &item.readiness_root,
            item.blocks_user_release,
            item.blocks_production,
        );
        let dependency_root = dependency_root(
            kind,
            item.dimension,
            &item.source_root,
            &item.readiness_root,
            item.blocks_user_release,
            item.blocks_production,
        );
        let acceptance_root = acceptance_root(
            kind,
            &acceptance_criteria,
            &expected_unblock,
            &dependency_root,
            priority_rank,
        );
        let action_root = remediation_action_root(
            kind,
            status,
            severity,
            item.dimension,
            item.status,
            release_claim_id,
            &dependency_root,
            &acceptance_root,
            &evidence_root,
            retry_after_blocks,
            manual_required,
            item.blocks_user_release,
            item.blocks_production,
        );
        let action_id = remediation_action_id(kind, &item.item_id, &action_root);
        Self {
            action_id,
            kind,
            status,
            severity,
            priority_rank,
            release_claim_id: release_claim_id.to_string(),
            source_dimension: item.dimension,
            source_status: item.status,
            source_item_id: item.item_id.clone(),
            source_readiness_root: item.readiness_root.clone(),
            source_root: item.source_root.clone(),
            owner_lane,
            objective,
            acceptance_criteria,
            expected_unblock,
            expected_next_status,
            retry_after_blocks,
            manual_required,
            evidence_root,
            dependency_root,
            acceptance_root,
            action_root,
            blocks_user_release: item.blocks_user_release,
            blocks_production: item.blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "priority_rank": self.priority_rank,
            "release_claim_id": self.release_claim_id,
            "source_dimension": self.source_dimension.as_str(),
            "source_status": self.source_status.as_str(),
            "source_item_id": self.source_item_id,
            "source_readiness_root": self.source_readiness_root,
            "source_root": self.source_root,
            "owner_lane": self.owner_lane,
            "objective": self.objective,
            "acceptance_criteria": self.acceptance_criteria,
            "expected_unblock": self.expected_unblock,
            "expected_next_status": self.expected_next_status.as_str(),
            "retry_after_blocks": self.retry_after_blocks,
            "manual_required": self.manual_required,
            "evidence_root": self.evidence_root,
            "dependency_root": self.dependency_root,
            "acceptance_root": self.acceptance_root,
            "action_root": self.action_root,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("remediation_action", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseRemediationPlan {
    pub plan_id: String,
    pub status: RemediationPlanStatus,
    pub readiness_receipt_id: String,
    pub readiness_receipt_status: ReleaseReadinessStatus,
    pub release_claim_id: String,
    pub readiness_state_root: String,
    pub readiness_receipt_root: String,
    pub actions_total: u64,
    pub actions_ready: u64,
    pub actions_waiting: u64,
    pub actions_blocked: u64,
    pub actions_complete: u64,
    pub user_release_actions: u64,
    pub production_actions: u64,
    pub critical_actions: u64,
    pub manual_actions: u64,
    pub top_priority_action_id: String,
    pub top_priority_action_kind: RemediationActionKind,
    pub actions: BTreeMap<String, RemediationAction>,
    pub roots: ReleaseRemediationPlanRoots,
}

impl ReleaseRemediationPlan {
    pub fn public_record(&self) -> Value {
        let actions = self
            .actions
            .values()
            .map(RemediationAction::public_record)
            .collect::<Vec<_>>();
        json!({
            "plan_id": self.plan_id,
            "status": self.status.as_str(),
            "readiness_receipt_id": self.readiness_receipt_id,
            "readiness_receipt_status": self.readiness_receipt_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "readiness_state_root": self.readiness_state_root,
            "readiness_receipt_root": self.readiness_receipt_root,
            "actions_total": self.actions_total,
            "actions_ready": self.actions_ready,
            "actions_waiting": self.actions_waiting,
            "actions_blocked": self.actions_blocked,
            "actions_complete": self.actions_complete,
            "user_release_actions": self.user_release_actions,
            "production_actions": self.production_actions,
            "critical_actions": self.critical_actions,
            "manual_actions": self.manual_actions,
            "top_priority_action_id": self.top_priority_action_id,
            "top_priority_action_kind": self.top_priority_action_kind.as_str(),
            "actions": actions,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.plan_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseRemediationPlanRoots {
    pub action_root: String,
    pub priority_root: String,
    pub source_root: String,
    pub plan_root: String,
}

impl ReleaseRemediationPlanRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "action_root": self.action_root,
            "priority_root": self.priority_root,
            "source_root": self.source_root,
            "plan_root": self.plan_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub plans_run: u64,
    pub plans_clear: u64,
    pub plans_active: u64,
    pub plans_blocked: u64,
    pub actions_total: u64,
    pub actions_ready: u64,
    pub actions_waiting: u64,
    pub actions_blocked: u64,
    pub user_release_actions: u64,
    pub production_actions: u64,
    pub critical_actions: u64,
    pub manual_actions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "plans_run": self.plans_run,
            "plans_clear": self.plans_clear,
            "plans_active": self.plans_active,
            "plans_blocked": self.plans_blocked,
            "actions_total": self.actions_total,
            "actions_ready": self.actions_ready,
            "actions_waiting": self.actions_waiting,
            "actions_blocked": self.actions_blocked,
            "user_release_actions": self.user_release_actions,
            "production_actions": self.production_actions,
            "critical_actions": self.critical_actions,
            "manual_actions": self.manual_actions,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub plan_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            plan_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-EMPTY-PLANS",
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
            "plan_root": self.plan_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.plan_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_plan: Option<ReleaseRemediationPlan>,
    pub plan_history: Vec<ReleaseRemediationPlan>,
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
            latest_plan: None,
            plan_history: Vec::new(),
            counters,
            roots,
        };
        let readiness =
            crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::devnet();
        state
            .plan_release_remediation(&readiness)
            .expect("devnet bridge exit release remediation planner");
        state
    }

    pub fn plan_release_remediation(
        &mut self,
        readiness: &ReleaseReadinessState,
    ) -> Result<String> {
        let receipt = readiness
            .latest_receipt
            .as_ref()
            .ok_or_else(|| "release readiness integrator has no latest receipt".to_string())?;
        let actions = build_actions(&self.config, receipt);
        ensure(
            receipt.status == ReleaseReadinessStatus::Ready
                || actions.len() as u64 >= self.config.min_remediation_actions,
            "release remediation planner omitted required blocker actions",
        )?;
        let actions_total = actions.len() as u64;
        let actions_ready = actions
            .values()
            .filter(|action| action.status == RemediationActionStatus::ReadyToStart)
            .count() as u64;
        let actions_waiting = actions
            .values()
            .filter(|action| action.status == RemediationActionStatus::WaitingOnDeferredGate)
            .count() as u64;
        let actions_blocked = actions
            .values()
            .filter(|action| action.status == RemediationActionStatus::Blocked)
            .count() as u64;
        let actions_complete = actions
            .values()
            .filter(|action| action.status == RemediationActionStatus::Complete)
            .count() as u64;
        let user_release_actions = actions
            .values()
            .filter(|action| action.blocks_user_release)
            .count() as u64;
        let production_actions = actions
            .values()
            .filter(|action| action.blocks_production)
            .count() as u64;
        let critical_actions = actions
            .values()
            .filter(|action| action.severity == RemediationSeverity::Critical)
            .count() as u64;
        let manual_actions = actions
            .values()
            .filter(|action| action.manual_required)
            .count() as u64;
        let status = plan_status(receipt.status, actions_blocked, actions_total);
        let (top_priority_action_id, top_priority_action_kind) = top_priority(&actions);
        let action_records = actions
            .values()
            .map(RemediationAction::public_record)
            .collect::<Vec<_>>();
        let action_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-ACTIONS",
            &action_records,
        );
        let priority_root = priority_root(&actions);
        let source_root = source_root(
            &readiness.state_root(),
            &receipt.state_root(),
            &receipt.roots.source_root,
            &receipt.roots.blocker_root,
        );
        let plan_root = plan_root(
            status,
            &source_root,
            &action_root,
            &priority_root,
            &receipt.release_claim_id,
            actions_ready,
            actions_waiting,
            actions_blocked,
            critical_actions,
            manual_actions,
        );
        let plan_id = release_remediation_plan_id(&receipt.release_claim_id, &plan_root);
        let plan = ReleaseRemediationPlan {
            plan_id: plan_id.clone(),
            status,
            readiness_receipt_id: receipt.receipt_id.clone(),
            readiness_receipt_status: receipt.status,
            release_claim_id: receipt.release_claim_id.clone(),
            readiness_state_root: readiness.state_root(),
            readiness_receipt_root: receipt.state_root(),
            actions_total,
            actions_ready,
            actions_waiting,
            actions_blocked,
            actions_complete,
            user_release_actions,
            production_actions,
            critical_actions,
            manual_actions,
            top_priority_action_id,
            top_priority_action_kind,
            actions,
            roots: ReleaseRemediationPlanRoots {
                action_root,
                priority_root,
                source_root,
                plan_root,
            },
        };
        self.record_plan(plan);
        Ok(plan_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "planner_suite": self.config.planner_suite,
            "latest_plan": self.latest_plan.as_ref().map(ReleaseRemediationPlan::public_record),
            "plan_history_len": self.plan_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_plan(&mut self, plan: ReleaseRemediationPlan) {
        self.counters.plans_run += 1;
        self.counters.actions_total += plan.actions_total;
        self.counters.actions_ready += plan.actions_ready;
        self.counters.actions_waiting += plan.actions_waiting;
        self.counters.actions_blocked += plan.actions_blocked;
        self.counters.user_release_actions += plan.user_release_actions;
        self.counters.production_actions += plan.production_actions;
        self.counters.critical_actions += plan.critical_actions;
        self.counters.manual_actions += plan.manual_actions;
        match plan.status {
            RemediationPlanStatus::Clear => self.counters.plans_clear += 1,
            RemediationPlanStatus::Active => self.counters.plans_active += 1,
            RemediationPlanStatus::Blocked => self.counters.plans_blocked += 1,
        }
        self.latest_plan = Some(plan.clone());
        self.plan_history.push(plan);
        if self.plan_history.len() > self.config.max_reports {
            self.plan_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let plan_records = self
            .plan_history
            .iter()
            .map(ReleaseRemediationPlan::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            plan_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-PLANS",
                &plan_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_actions(
    config: &Config,
    receipt: &BridgeExitReleaseReadinessReceipt,
) -> BTreeMap<String, RemediationAction> {
    let mut actions = BTreeMap::new();
    for (index, item) in receipt
        .items
        .values()
        .filter(|item| item.status != ReleaseReadinessStatus::Ready)
        .enumerate()
    {
        let action =
            RemediationAction::from_item(config, &receipt.release_claim_id, item, index as u64);
        actions.insert(action.action_id.clone(), action);
    }
    if receipt.items.values().all(|item| {
        item.dimension != ReleaseReadinessDimension::ForcedExitUserAnswer
            || item.status == ReleaseReadinessStatus::Ready
    }) && receipt.status != ReleaseReadinessStatus::Ready
    {
        if let Some(item) = receipt
            .items
            .values()
            .find(|item| item.dimension == ReleaseReadinessDimension::ProductionRelease)
        {
            let action = RemediationAction::from_item(
                config,
                &receipt.release_claim_id,
                item,
                actions.len() as u64,
            );
            actions.insert(action.action_id.clone(), action);
        }
    }
    actions
}

fn action_kind(dimension: ReleaseReadinessDimension) -> RemediationActionKind {
    match dimension {
        ReleaseReadinessDimension::SettlementExecution => {
            RemediationActionKind::EnableLiveSettlementExecution
        }
        ReleaseReadinessDimension::PqAuthority => {
            RemediationActionKind::EnablePqAuthorityVerification
        }
        ReleaseReadinessDimension::CargoRuntime => {
            RemediationActionKind::MaterializeCargoRuntimeTests
        }
        ReleaseReadinessDimension::SecurityAudit => {
            RemediationActionKind::CompleteSecurityPrivacyAudit
        }
        ReleaseReadinessDimension::ForcedExitUserAnswer => {
            RemediationActionKind::ResolveForcedExitUserAnswer
        }
        ReleaseReadinessDimension::ProductionRelease => {
            RemediationActionKind::ClearProductionReleaseGate
        }
    }
}

fn action_status(
    readiness_status: ReleaseReadinessStatus,
    blocks_user_release: bool,
) -> RemediationActionStatus {
    match readiness_status {
        ReleaseReadinessStatus::Ready => RemediationActionStatus::Complete,
        ReleaseReadinessStatus::Watch if blocks_user_release => {
            RemediationActionStatus::ReadyToStart
        }
        ReleaseReadinessStatus::Watch => RemediationActionStatus::WaitingOnDeferredGate,
        ReleaseReadinessStatus::Blocked => RemediationActionStatus::Blocked,
    }
}

fn severity(item: &ReleaseReadinessItem) -> RemediationSeverity {
    if item.blocks_user_release {
        RemediationSeverity::Critical
    } else if item.blocks_production && item.status == ReleaseReadinessStatus::Blocked {
        RemediationSeverity::High
    } else if item.blocks_production {
        RemediationSeverity::Medium
    } else {
        RemediationSeverity::Low
    }
}

fn priority_rank(config: &Config, item: &ReleaseReadinessItem, ordinal: u64) -> u64 {
    let base = match item.dimension {
        ReleaseReadinessDimension::ForcedExitUserAnswer if config.prioritize_user_exit => 1,
        ReleaseReadinessDimension::SettlementExecution if config.prioritize_user_exit => 2,
        ReleaseReadinessDimension::PqAuthority if config.prioritize_pq_authority => 3,
        ReleaseReadinessDimension::CargoRuntime if config.prioritize_runtime_tests => 4,
        ReleaseReadinessDimension::SecurityAudit => 5,
        ReleaseReadinessDimension::ProductionRelease => 6,
        _ => 10,
    };
    base + ordinal
}

fn retry_after_blocks(config: &Config, item: &ReleaseReadinessItem) -> u64 {
    if item.blocks_user_release {
        1
    } else if item.status == ReleaseReadinessStatus::Blocked {
        (config.retry_after_blocks / 2).max(1)
    } else {
        config.retry_after_blocks
    }
}

fn manual_required(kind: RemediationActionKind, item: &ReleaseReadinessItem) -> bool {
    matches!(
        kind,
        RemediationActionKind::CompleteSecurityPrivacyAudit
            | RemediationActionKind::ClearProductionReleaseGate
            | RemediationActionKind::ResolveForcedExitUserAnswer
    ) || item.status == ReleaseReadinessStatus::Blocked
}

fn expected_next_status(kind: RemediationActionKind) -> ReleaseReadinessStatus {
    match kind {
        RemediationActionKind::PreservePrivacyReceiptScanning => ReleaseReadinessStatus::Watch,
        _ => ReleaseReadinessStatus::Ready,
    }
}

fn owner_lane(kind: RemediationActionKind) -> &'static str {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => "bridge_settlement_runtime",
        RemediationActionKind::EnablePqAuthorityVerification => "pq_authority_control_plane",
        RemediationActionKind::MaterializeCargoRuntimeTests => "bridge_final_release_tests",
        RemediationActionKind::CompleteSecurityPrivacyAudit => "security_privacy_review",
        RemediationActionKind::ResolveForcedExitUserAnswer => "bridge_exit_release_owner",
        RemediationActionKind::ClearProductionReleaseGate => "release_governance",
        RemediationActionKind::PreservePrivacyReceiptScanning => "wallet_receipt_privacy",
    }
}

fn objective(kind: RemediationActionKind, item: &ReleaseReadinessItem) -> &'static str {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => {
            "turn settlement-call roots into executable live settlement receipts"
        }
        RemediationActionKind::EnablePqAuthorityVerification => {
            "verify PQ signer, rotation, and epoch roots for release authority"
        }
        RemediationActionKind::MaterializeCargoRuntimeTests => {
            "convert final-release fixture contracts into executable cargo/runtime tests"
        }
        RemediationActionKind::CompleteSecurityPrivacyAudit => {
            "complete cryptographic and privacy audit signoff for bridge release"
        }
        RemediationActionKind::ResolveForcedExitUserAnswer if item.blocks_user_release => {
            "remove user-release blockers from the forced-exit path"
        }
        RemediationActionKind::ResolveForcedExitUserAnswer => {
            "collapse watch gates into an evidence-backed forced-exit answer"
        }
        RemediationActionKind::ClearProductionReleaseGate => {
            "keep production blocked until all release-readiness dimensions are green"
        }
        RemediationActionKind::PreservePrivacyReceiptScanning => {
            "preserve wallet receipt scanning without leaking metadata"
        }
    }
}

fn acceptance_criteria(kind: RemediationActionKind) -> &'static str {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => {
            "settlement handler reports passed with nonzero live settlement receipts and no live-settlement holds"
        }
        RemediationActionKind::EnablePqAuthorityVerification => {
            "PQ authority adapter reports passed with valid signatures, no stale rotations, and no release holds"
        }
        RemediationActionKind::MaterializeCargoRuntimeTests => {
            "cargo harness reports passed with executed tests for every final-release fixture"
        }
        RemediationActionKind::CompleteSecurityPrivacyAudit => {
            "security audit harness reports passed with signoff roots, zero findings, and no residual-risk holds"
        }
        RemediationActionKind::ResolveForcedExitUserAnswer => {
            "release readiness receipt answers yes or watch-without-user-release-blockers"
        }
        RemediationActionKind::ClearProductionReleaseGate => {
            "production release dimension is ready after live handlers, cargo/runtime tests, and audits are green"
        }
        RemediationActionKind::PreservePrivacyReceiptScanning => {
            "private receipt scanner execution proves receipt continuity with bounded metadata disclosure"
        }
    }
}

fn expected_unblock(item: &ReleaseReadinessItem) -> &'static str {
    if item.blocks_user_release {
        "user_release"
    } else if item.blocks_production {
        "production_release"
    } else {
        "readiness_watch"
    }
}

fn plan_status(
    receipt_status: ReleaseReadinessStatus,
    actions_blocked: u64,
    actions_total: u64,
) -> RemediationPlanStatus {
    if receipt_status == ReleaseReadinessStatus::Ready && actions_total == 0 {
        RemediationPlanStatus::Clear
    } else if actions_blocked > 0 || receipt_status == ReleaseReadinessStatus::Blocked {
        RemediationPlanStatus::Blocked
    } else {
        RemediationPlanStatus::Active
    }
}

fn top_priority(actions: &BTreeMap<String, RemediationAction>) -> (String, RemediationActionKind) {
    actions
        .values()
        .min_by_key(|action| action.priority_rank)
        .map(|action| (action.action_id.clone(), action.kind))
        .unwrap_or_else(|| {
            (
                "none".to_string(),
                RemediationActionKind::PreservePrivacyReceiptScanning,
            )
        })
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
pub fn dependency_root(
    kind: RemediationActionKind,
    dimension: ReleaseReadinessDimension,
    source_root: &str,
    readiness_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-DEPENDENCY",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(dimension.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(readiness_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn acceptance_root(
    kind: RemediationActionKind,
    acceptance_criteria: &str,
    expected_unblock: &str,
    dependency_root: &str,
    priority_rank: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-ACCEPTANCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(acceptance_criteria),
            HashPart::Str(expected_unblock),
            HashPart::Str(dependency_root),
            HashPart::U64(priority_rank),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn remediation_evidence_root(
    release_claim_id: &str,
    kind: RemediationActionKind,
    dimension: ReleaseReadinessDimension,
    source_status: ReleaseReadinessStatus,
    source_root: &str,
    readiness_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-EVIDENCE",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(dimension.as_str()),
            HashPart::Str(source_status.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(readiness_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn remediation_action_root(
    kind: RemediationActionKind,
    status: RemediationActionStatus,
    severity: RemediationSeverity,
    dimension: ReleaseReadinessDimension,
    source_status: ReleaseReadinessStatus,
    release_claim_id: &str,
    dependency_root: &str,
    acceptance_root: &str,
    evidence_root: &str,
    retry_after_blocks: u64,
    manual_required: bool,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-ACTION",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(dimension.as_str()),
            HashPart::Str(source_status.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(dependency_root),
            HashPart::Str(acceptance_root),
            HashPart::Str(evidence_root),
            HashPart::U64(retry_after_blocks),
            HashPart::Str(bool_str(manual_required)),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn remediation_action_id(
    kind: RemediationActionKind,
    readiness_item_id: &str,
    action_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-ACTION-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(readiness_item_id),
            HashPart::Str(action_root),
        ],
        32,
    )
}

pub fn priority_root(actions: &BTreeMap<String, RemediationAction>) -> String {
    let records = actions
        .values()
        .map(|action| {
            json!({
                "action_id": action.action_id,
                "kind": action.kind.as_str(),
                "priority_rank": action.priority_rank,
                "release_claim_id": action.release_claim_id,
                "severity": action.severity.as_str(),
                "status": action.status.as_str(),
                "expected_unblock": action.expected_unblock,
                "expected_next_status": action.expected_next_status.as_str(),
                "retry_after_blocks": action.retry_after_blocks,
                "manual_required": action.manual_required,
                "evidence_root": action.evidence_root,
                "owner_lane": action.owner_lane,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-PRIORITY",
        &records,
    )
}

pub fn source_root(
    readiness_state_root: &str,
    readiness_receipt_root: &str,
    readiness_source_root: &str,
    readiness_blocker_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-SOURCE",
        &[
            HashPart::Str(readiness_state_root),
            HashPart::Str(readiness_receipt_root),
            HashPart::Str(readiness_source_root),
            HashPart::Str(readiness_blocker_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn plan_root(
    status: RemediationPlanStatus,
    source_root: &str,
    action_root: &str,
    priority_root: &str,
    release_claim_id: &str,
    actions_ready: u64,
    actions_waiting: u64,
    actions_blocked: u64,
    critical_actions: u64,
    manual_actions: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-PLAN",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(action_root),
            HashPart::Str(priority_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(actions_ready),
            HashPart::U64(actions_waiting),
            HashPart::U64(actions_blocked),
            HashPart::U64(critical_actions),
            HashPart::U64(manual_actions),
        ],
        32,
    )
}

pub fn release_remediation_plan_id(release_claim_id: &str, plan_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-PLAN-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(plan_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-RECORD",
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
