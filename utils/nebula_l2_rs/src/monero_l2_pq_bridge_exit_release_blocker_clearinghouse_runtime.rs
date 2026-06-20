use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::{
        ReleaseReadinessDimension, ReleaseReadinessStatus, State as ReleaseReadinessState,
    },
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        ReleaseRemediationPlanStatus, RemediationAction, RemediationActionKind,
        RemediationActionStatus, RemediationSeverity, State as ReleaseRemediationPlannerState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReleaseBlockerClearinghouseRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_BLOCKER_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-release-blocker-clearinghouse-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_BLOCKER_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_BLOCKER_CLEARINGHOUSE_SUITE: &str =
    "monero-l2-pq-bridge-exit-release-blocker-clearinghouse-v1";
pub const DEFAULT_MIN_CLEARING_RECORDS: u64 = 4;
pub const DEFAULT_MAX_BATCHES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingLane {
    UserRelease,
    ProductionRelease,
    Pq,
    Settlement,
    CargoRuntime,
    Audit,
    Privacy,
}

impl ClearingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserRelease => "user_release",
            Self::ProductionRelease => "production_release",
            Self::Pq => "pq",
            Self::Settlement => "settlement",
            Self::CargoRuntime => "cargo_runtime",
            Self::Audit => "audit",
            Self::Privacy => "privacy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingStatus {
    Clear,
    ReadyToClear,
    Waiting,
    Blocked,
}

impl ClearingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::ReadyToClear => "ready_to_clear",
            Self::Waiting => "waiting",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearinghouseStatus {
    Clear,
    Active,
    Blocked,
}

impl ClearinghouseStatus {
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
    pub clearinghouse_suite: String,
    pub min_clearing_records: u64,
    pub user_release_first: bool,
    pub settlement_before_pq: bool,
    pub privacy_followup_enabled: bool,
    pub production_release_allowed: bool,
    pub max_batches: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            clearinghouse_suite: RELEASE_BLOCKER_CLEARINGHOUSE_SUITE.to_string(),
            min_clearing_records: DEFAULT_MIN_CLEARING_RECORDS,
            user_release_first: true,
            settlement_before_pq: true,
            privacy_followup_enabled: true,
            production_release_allowed: false,
            max_batches: DEFAULT_MAX_BATCHES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "clearinghouse_suite": self.clearinghouse_suite,
            "min_clearing_records": self.min_clearing_records,
            "user_release_first": self.user_release_first,
            "settlement_before_pq": self.settlement_before_pq,
            "privacy_followup_enabled": self.privacy_followup_enabled,
            "production_release_allowed": self.production_release_allowed,
            "max_batches": self.max_batches,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingRecord {
    pub clearing_id: String,
    pub lane: ClearingLane,
    pub status: ClearingStatus,
    pub severity: RemediationSeverity,
    pub clearing_rank: u64,
    pub release_claim_id: String,
    pub source_action_id: String,
    pub source_action_kind: RemediationActionKind,
    pub source_action_status: RemediationActionStatus,
    pub source_dimension: ReleaseReadinessDimension,
    pub source_readiness_status: ReleaseReadinessStatus,
    pub source_plan_status: ReleaseRemediationPlanStatus,
    pub source_readiness_root: String,
    pub source_action_root: String,
    pub source_evidence_root: String,
    pub lane_evidence_root: String,
    pub committed_evidence_root: String,
    pub dependency_root: String,
    pub clearing_order_root: String,
    pub acceptance_root: String,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
    pub manual_required: bool,
    pub owner_lane: String,
    pub clearing_step: String,
}

impl ClearingRecord {
    pub fn from_action(
        config: &Config,
        plan_status: ReleaseRemediationPlanStatus,
        action: &RemediationAction,
        ordinal: u64,
    ) -> Self {
        let lane = clearing_lane(config, action);
        let status = clearing_status(action);
        let clearing_rank = clearing_rank(config, lane, action, ordinal);
        let lane_evidence_root = clearing_lane_evidence_root(
            lane,
            &action.release_claim_id,
            &action.action_id,
            &action.evidence_root,
            &action.source_readiness_root,
            action.blocks_user_release,
            action.blocks_production,
        );
        let dependency_root = clearing_dependency_root(
            lane,
            action.kind,
            action.source_dimension,
            &action.dependency_root,
            &action.acceptance_root,
            &lane_evidence_root,
        );
        let clearing_order_root = clearing_order_root(
            lane,
            status,
            action.severity,
            clearing_rank,
            action.priority_rank,
            &action.action_id,
            &dependency_root,
        );
        let acceptance_root = clearing_acceptance_root(
            lane,
            status,
            &action.acceptance_root,
            &action.expected_unblock,
            &clearing_order_root,
        );
        let committed_evidence_root = committed_evidence_root(
            lane,
            status,
            &lane_evidence_root,
            &dependency_root,
            &clearing_order_root,
            &acceptance_root,
        );
        let clearing_id = clearing_record_id(lane, &action.action_id, &committed_evidence_root);
        Self {
            clearing_id,
            lane,
            status,
            severity: action.severity,
            clearing_rank,
            release_claim_id: action.release_claim_id.clone(),
            source_action_id: action.action_id.clone(),
            source_action_kind: action.kind,
            source_action_status: action.status,
            source_dimension: action.source_dimension,
            source_readiness_status: action.source_status,
            source_plan_status: plan_status,
            source_readiness_root: action.source_readiness_root.clone(),
            source_action_root: action.action_root.clone(),
            source_evidence_root: action.evidence_root.clone(),
            lane_evidence_root,
            committed_evidence_root,
            dependency_root,
            clearing_order_root,
            acceptance_root,
            blocks_user_release: action.blocks_user_release,
            blocks_production: action.blocks_production,
            manual_required: action.manual_required,
            owner_lane: action.owner_lane.clone(),
            clearing_step: clearing_step(lane, action).to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "clearing_id": self.clearing_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "clearing_rank": self.clearing_rank,
            "release_claim_id": self.release_claim_id,
            "source_action_id": self.source_action_id,
            "source_action_kind": self.source_action_kind.as_str(),
            "source_action_status": self.source_action_status.as_str(),
            "source_dimension": self.source_dimension.as_str(),
            "source_readiness_status": self.source_readiness_status.as_str(),
            "source_plan_status": self.source_plan_status.as_str(),
            "source_readiness_root": self.source_readiness_root,
            "source_action_root": self.source_action_root,
            "source_evidence_root": self.source_evidence_root,
            "lane_evidence_root": self.lane_evidence_root,
            "committed_evidence_root": self.committed_evidence_root,
            "dependency_root": self.dependency_root,
            "clearing_order_root": self.clearing_order_root,
            "acceptance_root": self.acceptance_root,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
            "manual_required": self.manual_required,
            "owner_lane": self.owner_lane,
            "clearing_step": self.clearing_step,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("clearing_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneGroup {
    pub lane: ClearingLane,
    pub records_total: u64,
    pub records_clear: u64,
    pub records_ready: u64,
    pub records_waiting: u64,
    pub records_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub first_clearing_rank: u64,
    pub group_evidence_root: String,
    pub group_root: String,
    pub records: BTreeMap<String, ClearingRecord>,
}

impl LaneGroup {
    pub fn public_record(&self) -> Value {
        let records = self
            .records
            .values()
            .map(ClearingRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "lane": self.lane.as_str(),
            "records_total": self.records_total,
            "records_clear": self.records_clear,
            "records_ready": self.records_ready,
            "records_waiting": self.records_waiting,
            "records_blocked": self.records_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "first_clearing_rank": self.first_clearing_rank,
            "group_evidence_root": self.group_evidence_root,
            "group_root": self.group_root,
            "records": records,
        })
    }

    pub fn state_root(&self) -> String {
        self.group_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingBatchRoots {
    pub source_root: String,
    pub record_root: String,
    pub lane_group_root: String,
    pub clearing_order_root: String,
    pub committed_evidence_root: String,
    pub batch_root: String,
}

impl ClearingBatchRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "source_root": self.source_root,
            "record_root": self.record_root,
            "lane_group_root": self.lane_group_root,
            "clearing_order_root": self.clearing_order_root,
            "committed_evidence_root": self.committed_evidence_root,
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClearingBatch {
    pub batch_id: String,
    pub status: ClearinghouseStatus,
    pub release_claim_id: String,
    pub readiness_state_root: String,
    pub remediation_planner_state_root: String,
    pub readiness_receipt_root: String,
    pub remediation_plan_root: String,
    pub records_total: u64,
    pub records_clear: u64,
    pub records_ready: u64,
    pub records_waiting: u64,
    pub records_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub pq_records: u64,
    pub settlement_records: u64,
    pub cargo_runtime_records: u64,
    pub audit_records: u64,
    pub privacy_records: u64,
    pub first_clearing_id: String,
    pub lane_groups: BTreeMap<String, LaneGroup>,
    pub roots: ClearingBatchRoots,
}

impl ClearingBatch {
    pub fn public_record(&self) -> Value {
        let lane_groups = self
            .lane_groups
            .values()
            .map(LaneGroup::public_record)
            .collect::<Vec<_>>();
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "readiness_state_root": self.readiness_state_root,
            "remediation_planner_state_root": self.remediation_planner_state_root,
            "readiness_receipt_root": self.readiness_receipt_root,
            "remediation_plan_root": self.remediation_plan_root,
            "records_total": self.records_total,
            "records_clear": self.records_clear,
            "records_ready": self.records_ready,
            "records_waiting": self.records_waiting,
            "records_blocked": self.records_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "pq_records": self.pq_records,
            "settlement_records": self.settlement_records,
            "cargo_runtime_records": self.cargo_runtime_records,
            "audit_records": self.audit_records,
            "privacy_records": self.privacy_records,
            "first_clearing_id": self.first_clearing_id,
            "lane_groups": lane_groups,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.batch_root.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub batches_run: u64,
    pub batches_clear: u64,
    pub batches_active: u64,
    pub batches_blocked: u64,
    pub records_total: u64,
    pub records_ready: u64,
    pub records_waiting: u64,
    pub records_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub pq_records: u64,
    pub settlement_records: u64,
    pub cargo_runtime_records: u64,
    pub audit_records: u64,
    pub privacy_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "batches_run": self.batches_run,
            "batches_clear": self.batches_clear,
            "batches_active": self.batches_active,
            "batches_blocked": self.batches_blocked,
            "records_total": self.records_total,
            "records_ready": self.records_ready,
            "records_waiting": self.records_waiting,
            "records_blocked": self.records_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "pq_records": self.pq_records,
            "settlement_records": self.settlement_records,
            "cargo_runtime_records": self.cargo_runtime_records,
            "audit_records": self.audit_records,
            "privacy_records": self.privacy_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub batch_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            batch_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-EMPTY-BATCHES",
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
            "batch_root": self.batch_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.batch_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_batch: Option<ClearingBatch>,
    pub batch_history: Vec<ClearingBatch>,
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
            latest_batch: None,
            batch_history: Vec::new(),
            counters,
            roots,
        };
        let readiness =
            crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::devnet();
        let planner = crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let _ = state.clear_release_blockers(&readiness, &planner);
        state
    }

    pub fn clear_release_blockers(
        &mut self,
        readiness: &ReleaseReadinessState,
        planner: &ReleaseRemediationPlannerState,
    ) -> Result<String> {
        let readiness_receipt = readiness
            .latest_receipt
            .as_ref()
            .ok_or_else(|| "release readiness integrator has no latest receipt".to_string())?;
        let plan = planner
            .latest_plan
            .as_ref()
            .ok_or_else(|| "release remediation planner has no latest plan".to_string())?;
        ensure(
            readiness_receipt.release_claim_id == plan.release_claim_id,
            "release clearinghouse source release claim mismatch",
        )?;
        let records = build_clearing_records(&self.config, plan.status, &plan.actions);
        ensure(
            readiness_receipt.status == ReleaseReadinessStatus::Ready
                || records.len() as u64 >= self.config.min_clearing_records,
            "release clearinghouse omitted required blocker lanes",
        )?;
        let lane_groups = build_lane_groups(&records);
        let records_total = records.len() as u64;
        let records_clear = count_status(&records, ClearingStatus::Clear);
        let records_ready = count_status(&records, ClearingStatus::ReadyToClear);
        let records_waiting = count_status(&records, ClearingStatus::Waiting);
        let records_blocked = count_status(&records, ClearingStatus::Blocked);
        let user_release_blockers = records
            .values()
            .filter(|record| record.blocks_user_release)
            .count() as u64;
        let production_blockers = records
            .values()
            .filter(|record| record.blocks_production)
            .count() as u64;
        let pq_records = count_lane(&records, ClearingLane::Pq);
        let settlement_records = count_lane(&records, ClearingLane::Settlement);
        let cargo_runtime_records = count_lane(&records, ClearingLane::CargoRuntime);
        let audit_records = count_lane(&records, ClearingLane::Audit);
        let privacy_records = count_lane(&records, ClearingLane::Privacy);
        let first_clearing_id = records
            .values()
            .min_by_key(|record| record.clearing_rank)
            .map(|record| record.clearing_id.clone())
            .unwrap_or_else(|| "none".to_string());
        let status = clearinghouse_status(records_total, records_blocked);
        let record_values = records
            .values()
            .map(ClearingRecord::public_record)
            .collect::<Vec<_>>();
        let lane_values = lane_groups
            .values()
            .map(LaneGroup::public_record)
            .collect::<Vec<_>>();
        let source_root = clearinghouse_source_root(
            &readiness.state_root(),
            &planner.state_root(),
            &readiness_receipt.state_root(),
            &plan.state_root(),
            &readiness_receipt.roots.blocker_root,
            &plan.roots.action_root,
        );
        let record_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-RECORDS",
            &record_values,
        );
        let lane_group_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-LANE-GROUPS",
            &lane_values,
        );
        let clearing_order_commitment_root = clearing_order_commitment_root(&records);
        let committed_evidence_root = clearing_committed_evidence_root(&records);
        let batch_root = clearing_batch_root(
            status,
            &source_root,
            &record_root,
            &lane_group_root,
            &clearing_order_commitment_root,
            &committed_evidence_root,
            &readiness_receipt.release_claim_id,
            records_total,
            records_blocked,
            user_release_blockers,
            production_blockers,
        );
        let batch_id = clearing_batch_id(&readiness_receipt.release_claim_id, &batch_root);
        let batch = ClearingBatch {
            batch_id: batch_id.clone(),
            status,
            release_claim_id: readiness_receipt.release_claim_id.clone(),
            readiness_state_root: readiness.state_root(),
            remediation_planner_state_root: planner.state_root(),
            readiness_receipt_root: readiness_receipt.state_root(),
            remediation_plan_root: plan.state_root(),
            records_total,
            records_clear,
            records_ready,
            records_waiting,
            records_blocked,
            user_release_blockers,
            production_blockers,
            pq_records,
            settlement_records,
            cargo_runtime_records,
            audit_records,
            privacy_records,
            first_clearing_id,
            lane_groups,
            roots: ClearingBatchRoots {
                source_root,
                record_root,
                lane_group_root,
                clearing_order_root: clearing_order_commitment_root,
                committed_evidence_root,
                batch_root,
            },
        };
        self.record_batch(batch);
        Ok(batch_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "clearinghouse_suite": self.config.clearinghouse_suite,
            "latest_batch": self.latest_batch.as_ref().map(ClearingBatch::public_record),
            "batch_history_len": self.batch_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_batch(&mut self, batch: ClearingBatch) {
        self.counters.batches_run += 1;
        self.counters.records_total += batch.records_total;
        self.counters.records_ready += batch.records_ready;
        self.counters.records_waiting += batch.records_waiting;
        self.counters.records_blocked += batch.records_blocked;
        self.counters.user_release_blockers += batch.user_release_blockers;
        self.counters.production_blockers += batch.production_blockers;
        self.counters.pq_records += batch.pq_records;
        self.counters.settlement_records += batch.settlement_records;
        self.counters.cargo_runtime_records += batch.cargo_runtime_records;
        self.counters.audit_records += batch.audit_records;
        self.counters.privacy_records += batch.privacy_records;
        match batch.status {
            ClearinghouseStatus::Clear => self.counters.batches_clear += 1,
            ClearinghouseStatus::Active => self.counters.batches_active += 1,
            ClearinghouseStatus::Blocked => self.counters.batches_blocked += 1,
        }
        self.latest_batch = Some(batch.clone());
        self.batch_history.push(batch);
        if self.batch_history.len() > self.config.max_batches {
            self.batch_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let batch_records = self
            .batch_history
            .iter()
            .map(ClearingBatch::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            batch_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-BATCHES",
                &batch_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_clearing_records(
    config: &Config,
    plan_status: ReleaseRemediationPlanStatus,
    actions: &BTreeMap<String, RemediationAction>,
) -> BTreeMap<String, ClearingRecord> {
    let mut pending = actions
        .values()
        .enumerate()
        .map(|(index, action)| {
            ClearingRecord::from_action(config, plan_status, action, index as u64)
        })
        .collect::<Vec<_>>();
    pending.sort_by_key(|record| {
        (
            record.clearing_rank,
            record.lane,
            record.source_action_kind,
            record.source_action_id.clone(),
        )
    });
    pending
        .into_iter()
        .map(|record| (record.clearing_id.clone(), record))
        .collect()
}

fn build_lane_groups(records: &BTreeMap<String, ClearingRecord>) -> BTreeMap<String, LaneGroup> {
    let mut grouped: BTreeMap<String, BTreeMap<String, ClearingRecord>> = BTreeMap::new();
    for lane in all_lanes() {
        grouped.insert(lane.as_str().to_string(), BTreeMap::new());
    }
    for record in records.values() {
        grouped
            .entry(record.lane.as_str().to_string())
            .or_default()
            .insert(record.clearing_id.clone(), record.clone());
    }
    grouped
        .into_iter()
        .map(|(lane_key, lane_records)| {
            let lane = lane_from_key(&lane_key);
            let records_total = lane_records.len() as u64;
            let records_clear = count_status(&lane_records, ClearingStatus::Clear);
            let records_ready = count_status(&lane_records, ClearingStatus::ReadyToClear);
            let records_waiting = count_status(&lane_records, ClearingStatus::Waiting);
            let records_blocked = count_status(&lane_records, ClearingStatus::Blocked);
            let user_release_blockers = lane_records
                .values()
                .filter(|record| record.blocks_user_release)
                .count() as u64;
            let production_blockers = lane_records
                .values()
                .filter(|record| record.blocks_production)
                .count() as u64;
            let first_clearing_rank = lane_records
                .values()
                .map(|record| record.clearing_rank)
                .min()
                .unwrap_or(0);
            let group_evidence_root = lane_group_evidence_root(lane, &lane_records);
            let group_root = lane_group_root(
                lane,
                &group_evidence_root,
                records_total,
                records_ready,
                records_waiting,
                records_blocked,
                user_release_blockers,
                production_blockers,
            );
            let group = LaneGroup {
                lane,
                records_total,
                records_clear,
                records_ready,
                records_waiting,
                records_blocked,
                user_release_blockers,
                production_blockers,
                first_clearing_rank,
                group_evidence_root,
                group_root,
                records: lane_records,
            };
            (lane_key, group)
        })
        .collect()
}

fn all_lanes() -> [ClearingLane; 7] {
    [
        ClearingLane::UserRelease,
        ClearingLane::ProductionRelease,
        ClearingLane::Pq,
        ClearingLane::Settlement,
        ClearingLane::CargoRuntime,
        ClearingLane::Audit,
        ClearingLane::Privacy,
    ]
}

fn lane_from_key(key: &str) -> ClearingLane {
    match key {
        "user_release" => ClearingLane::UserRelease,
        "production_release" => ClearingLane::ProductionRelease,
        "pq" => ClearingLane::Pq,
        "settlement" => ClearingLane::Settlement,
        "cargo_runtime" => ClearingLane::CargoRuntime,
        "audit" => ClearingLane::Audit,
        "privacy" => ClearingLane::Privacy,
        _ => ClearingLane::ProductionRelease,
    }
}

fn clearing_lane(config: &Config, action: &RemediationAction) -> ClearingLane {
    if action.blocks_user_release {
        return ClearingLane::UserRelease;
    }
    match action.kind {
        RemediationActionKind::EnableLiveSettlementExecution => ClearingLane::Settlement,
        RemediationActionKind::EnablePqAuthorityVerification => ClearingLane::Pq,
        RemediationActionKind::MaterializeCargoRuntimeTests => ClearingLane::CargoRuntime,
        RemediationActionKind::CompleteSecurityPrivacyAudit => ClearingLane::Audit,
        RemediationActionKind::ResolveForcedExitUserAnswer => ClearingLane::UserRelease,
        RemediationActionKind::ClearProductionReleaseGate => ClearingLane::ProductionRelease,
        RemediationActionKind::PreservePrivacyReceiptScanning => {
            if config.privacy_followup_enabled {
                ClearingLane::Privacy
            } else {
                ClearingLane::Audit
            }
        }
    }
}

fn clearing_status(action: &RemediationAction) -> ClearingStatus {
    match action.status {
        RemediationActionStatus::Complete => ClearingStatus::Clear,
        RemediationActionStatus::ReadyToStart => ClearingStatus::ReadyToClear,
        RemediationActionStatus::WaitingOnDeferredGate => ClearingStatus::Waiting,
        RemediationActionStatus::Blocked => ClearingStatus::Blocked,
    }
}

fn clearing_rank(
    config: &Config,
    lane: ClearingLane,
    action: &RemediationAction,
    ordinal: u64,
) -> u64 {
    let lane_weight = match lane {
        ClearingLane::UserRelease if config.user_release_first => 10,
        ClearingLane::Settlement if config.settlement_before_pq => 20,
        ClearingLane::Pq if config.settlement_before_pq => 30,
        ClearingLane::Pq => 20,
        ClearingLane::Settlement => 30,
        ClearingLane::CargoRuntime => 40,
        ClearingLane::Audit => 50,
        ClearingLane::Privacy => 60,
        ClearingLane::ProductionRelease => 70,
        ClearingLane::UserRelease => 80,
    };
    lane_weight + action.priority_rank.saturating_mul(100) + ordinal
}

fn clearinghouse_status(records_total: u64, records_blocked: u64) -> ClearinghouseStatus {
    if records_total == 0 {
        ClearinghouseStatus::Clear
    } else if records_blocked > 0 {
        ClearinghouseStatus::Blocked
    } else {
        ClearinghouseStatus::Active
    }
}

fn clearing_step(lane: ClearingLane, action: &RemediationAction) -> &'static str {
    match lane {
        ClearingLane::UserRelease => "clear user-facing forced-exit blockers before release claims",
        ClearingLane::ProductionRelease => {
            "hold production release until all committed evidence is green"
        }
        ClearingLane::Pq => "bind fresh PQ authority signatures, rotations, and epoch evidence",
        ClearingLane::Settlement => "materialize live settlement execution receipts",
        ClearingLane::CargoRuntime => {
            "turn deferred cargo and runtime gates into executed evidence"
        }
        ClearingLane::Audit if action.manual_required => {
            "complete manual security and privacy signoff"
        }
        ClearingLane::Audit => "commit audit harness evidence for release review",
        ClearingLane::Privacy => "preserve private receipt scanning and metadata disclosure bounds",
    }
}

fn count_status(records: &BTreeMap<String, ClearingRecord>, status: ClearingStatus) -> u64 {
    records
        .values()
        .filter(|record| record.status == status)
        .count() as u64
}

fn count_lane(records: &BTreeMap<String, ClearingRecord>, lane: ClearingLane) -> u64 {
    records
        .values()
        .filter(|record| record.lane == lane)
        .count() as u64
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
pub fn clearing_lane_evidence_root(
    lane: ClearingLane,
    release_claim_id: &str,
    action_id: &str,
    action_evidence_root: &str,
    readiness_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-LANE-EVIDENCE",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(action_id),
            HashPart::Str(action_evidence_root),
            HashPart::Str(readiness_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn clearing_dependency_root(
    lane: ClearingLane,
    action_kind: RemediationActionKind,
    dimension: ReleaseReadinessDimension,
    action_dependency_root: &str,
    action_acceptance_root: &str,
    lane_evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-DEPENDENCY",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(dimension.as_str()),
            HashPart::Str(action_dependency_root),
            HashPart::Str(action_acceptance_root),
            HashPart::Str(lane_evidence_root),
        ],
        32,
    )
}

pub fn clearing_order_root(
    lane: ClearingLane,
    status: ClearingStatus,
    severity: RemediationSeverity,
    clearing_rank: u64,
    action_priority_rank: u64,
    action_id: &str,
    dependency_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-ORDER",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::U64(clearing_rank),
            HashPart::U64(action_priority_rank),
            HashPart::Str(action_id),
            HashPart::Str(dependency_root),
        ],
        32,
    )
}

pub fn clearing_acceptance_root(
    lane: ClearingLane,
    status: ClearingStatus,
    action_acceptance_root: &str,
    expected_unblock: &str,
    clearing_order_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-ACCEPTANCE",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(action_acceptance_root),
            HashPart::Str(expected_unblock),
            HashPart::Str(clearing_order_root),
        ],
        32,
    )
}

pub fn committed_evidence_root(
    lane: ClearingLane,
    status: ClearingStatus,
    lane_evidence_root: &str,
    dependency_root: &str,
    clearing_order_root: &str,
    acceptance_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-COMMITTED-EVIDENCE",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(lane_evidence_root),
            HashPart::Str(dependency_root),
            HashPart::Str(clearing_order_root),
            HashPart::Str(acceptance_root),
        ],
        32,
    )
}

pub fn clearing_record_id(
    lane: ClearingLane,
    source_action_id: &str,
    committed_evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-RECORD-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(source_action_id),
            HashPart::Str(committed_evidence_root),
        ],
        32,
    )
}

pub fn lane_group_evidence_root(
    lane: ClearingLane,
    records: &BTreeMap<String, ClearingRecord>,
) -> String {
    let evidence = records
        .values()
        .map(|record| {
            json!({
                "clearing_id": record.clearing_id,
                "clearing_rank": record.clearing_rank,
                "committed_evidence_root": record.committed_evidence_root,
                "lane_evidence_root": record.lane_evidence_root,
                "source_action_id": record.source_action_id,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-LANE-{}",
            lane.as_str()
        ),
        &evidence,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn lane_group_root(
    lane: ClearingLane,
    group_evidence_root: &str,
    records_total: u64,
    records_ready: u64,
    records_waiting: u64,
    records_blocked: u64,
    user_release_blockers: u64,
    production_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-LANE-GROUP",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(group_evidence_root),
            HashPart::U64(records_total),
            HashPart::U64(records_ready),
            HashPart::U64(records_waiting),
            HashPart::U64(records_blocked),
            HashPart::U64(user_release_blockers),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

pub fn clearing_order_commitment_root(records: &BTreeMap<String, ClearingRecord>) -> String {
    let mut ordered = records.values().collect::<Vec<_>>();
    ordered.sort_by_key(|record| {
        (
            record.clearing_rank,
            record.lane,
            record.source_action_kind,
            record.source_action_id.clone(),
        )
    });
    let order = ordered
        .into_iter()
        .map(|record| {
            json!({
                "clearing_id": record.clearing_id,
                "lane": record.lane.as_str(),
                "clearing_rank": record.clearing_rank,
                "clearing_order_root": record.clearing_order_root,
                "committed_evidence_root": record.committed_evidence_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-ORDER-COMMITMENT",
        &order,
    )
}

pub fn clearing_committed_evidence_root(records: &BTreeMap<String, ClearingRecord>) -> String {
    let evidence = records
        .values()
        .map(|record| {
            json!({
                "clearing_id": record.clearing_id,
                "lane": record.lane.as_str(),
                "committed_evidence_root": record.committed_evidence_root,
                "source_evidence_root": record.source_evidence_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-COMMITTED-EVIDENCE-SET",
        &evidence,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn clearinghouse_source_root(
    readiness_state_root: &str,
    remediation_planner_state_root: &str,
    readiness_receipt_root: &str,
    remediation_plan_root: &str,
    readiness_blocker_root: &str,
    remediation_action_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-SOURCE",
        &[
            HashPart::Str(readiness_state_root),
            HashPart::Str(remediation_planner_state_root),
            HashPart::Str(readiness_receipt_root),
            HashPart::Str(remediation_plan_root),
            HashPart::Str(readiness_blocker_root),
            HashPart::Str(remediation_action_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn clearing_batch_root(
    status: ClearinghouseStatus,
    source_root: &str,
    record_root: &str,
    lane_group_root: &str,
    clearing_order_root: &str,
    committed_evidence_root: &str,
    release_claim_id: &str,
    records_total: u64,
    records_blocked: u64,
    user_release_blockers: u64,
    production_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-BATCH",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(record_root),
            HashPart::Str(lane_group_root),
            HashPart::Str(clearing_order_root),
            HashPart::Str(committed_evidence_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(records_total),
            HashPart::U64(records_blocked),
            HashPart::U64(user_release_blockers),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

pub fn clearing_batch_id(release_claim_id: &str, batch_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-BATCH-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(batch_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-BLOCKER-CLEARINGHOUSE-RECORD",
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
