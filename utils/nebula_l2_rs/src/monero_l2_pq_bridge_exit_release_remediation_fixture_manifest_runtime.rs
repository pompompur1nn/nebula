use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime::{
        CargoRuntimeHarnessReport, State as CargoRuntimeHarnessState,
    },
    monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::{
        FixtureExportRecord, FixtureExportReport, State as FixtureExportState,
    },
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        ReleaseRemediationPlan, RemediationAction, RemediationActionKind, RemediationActionStatus,
        RemediationPlanStatus, RemediationSeverity, State as RemediationPlannerState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReleaseRemediationFixtureManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_REMEDIATION_FIXTURE_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-release-remediation-fixture-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_REMEDIATION_FIXTURE_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_REMEDIATION_FIXTURE_MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-release-remediation-fixture-manifest-v1";
pub const DEFAULT_MIN_FIXTURE_CONTRACTS: u64 = 4;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationFixtureLane {
    SettlementExecution,
    PqAuthority,
    CargoRuntime,
    SecurityAudit,
    ForcedExitUserRecovery,
    ProductionGate,
    PrivacyReceiptScanning,
}

impl RemediationFixtureLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementExecution => "settlement_execution",
            Self::PqAuthority => "pq_authority",
            Self::CargoRuntime => "cargo_runtime",
            Self::SecurityAudit => "security_audit",
            Self::ForcedExitUserRecovery => "forced_exit_user_recovery",
            Self::ProductionGate => "production_gate",
            Self::PrivacyReceiptScanning => "privacy_receipt_scanning",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationFixtureStatus {
    Ready,
    Deferred,
    Blocked,
    Bound,
}

impl RemediationFixtureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Bound => "bound",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationFixtureExpectedOutcome {
    ReleaseUnblocked,
    ProductionUnblocked,
    WatchCleared,
    StillBlocked,
}

impl RemediationFixtureExpectedOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseUnblocked => "release_unblocked",
            Self::ProductionUnblocked => "production_unblocked",
            Self::WatchCleared => "watch_cleared",
            Self::StillBlocked => "still_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationFixtureManifestStatus {
    Clear,
    Active,
    Blocked,
}

impl RemediationFixtureManifestStatus {
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
    pub manifest_suite: String,
    pub min_fixture_contracts: u64,
    pub cargo_execution_deferred: bool,
    pub require_manual_gate_fixtures: bool,
    pub require_privacy_fixture: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: RELEASE_REMEDIATION_FIXTURE_MANIFEST_SUITE.to_string(),
            min_fixture_contracts: DEFAULT_MIN_FIXTURE_CONTRACTS,
            cargo_execution_deferred: true,
            require_manual_gate_fixtures: true,
            require_privacy_fixture: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "min_fixture_contracts": self.min_fixture_contracts,
            "cargo_execution_deferred": self.cargo_execution_deferred,
            "require_manual_gate_fixtures": self.require_manual_gate_fixtures,
            "require_privacy_fixture": self.require_privacy_fixture,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationFixtureContract {
    pub contract_id: String,
    pub action_id: String,
    pub release_claim_id: String,
    pub action_kind: RemediationActionKind,
    pub lane: RemediationFixtureLane,
    pub status: RemediationFixtureStatus,
    pub severity: RemediationSeverity,
    pub priority_rank: u64,
    pub owner_lane: String,
    pub objective: String,
    pub expected_outcome: RemediationFixtureExpectedOutcome,
    pub expected_unblock: String,
    pub cargo_test_path: String,
    pub cargo_test_filter: String,
    pub cargo_index_key: String,
    pub source_fixture_export_id: String,
    pub source_vector_id: String,
    pub source_test_name: String,
    pub fixture_root: String,
    pub baseline_report_root: String,
    pub transcript_root: String,
    pub blocker_surface_root: String,
    pub redacted_fixture_commitment: String,
    pub cargo_case_id: String,
    pub cargo_case_root: String,
    pub remediation_evidence_root: String,
    pub remediation_action_root: String,
    pub request_payload_root: String,
    pub assertion_root: String,
    pub cargo_binding_root: String,
    pub manual_required: bool,
    pub retry_after_blocks: u64,
    pub cargo_execution_deferred: bool,
    pub release_safe_if_green: bool,
    pub production_safe_if_green: bool,
    pub metadata_leakage_budget_bound: bool,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
    pub contract_root: String,
}

impl RemediationFixtureContract {
    #[allow(clippy::too_many_arguments)]
    pub fn from_action(
        config: &Config,
        action: &RemediationAction,
        fixture: Option<&FixtureExportRecord>,
        cargo_report: &CargoRuntimeHarnessReport,
        ordinal: u64,
    ) -> Self {
        let lane = lane_for_action(action.kind);
        let status = fixture_status(config, action, fixture);
        let expected_outcome = expected_outcome(action);
        let cargo_test_path = fixture
            .map(|record| record.cargo_test_path.clone())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| synthetic_cargo_path(lane).to_string());
        let cargo_test_filter = fixture
            .map(|record| record.cargo_test_filter.clone())
            .filter(|filter| !filter.is_empty())
            .unwrap_or_else(|| synthetic_cargo_filter(action.kind).to_string());
        let cargo_index_key = fixture
            .map(|record| record.cargo_index_key.clone())
            .filter(|key| !key.is_empty())
            .unwrap_or_else(|| cargo_index_key(&cargo_test_path, &cargo_test_filter));
        let source_fixture_export_id = fixture
            .map(|record| record.export_id.clone())
            .unwrap_or_else(|| "none".to_string());
        let source_vector_id = fixture
            .map(|record| record.vector_id.clone())
            .unwrap_or_else(|| synthetic_vector_id(action.kind, ordinal));
        let source_test_name = fixture
            .map(|record| record.test_name.clone())
            .unwrap_or_else(|| synthetic_test_name(action.kind).to_string());
        let fixture_root = fixture
            .map(|record| record.fixture_root.clone())
            .unwrap_or_else(|| synthetic_fixture_root(action, lane, ordinal));
        let baseline_report_root = fixture
            .map(|record| record.baseline_report_root.clone())
            .unwrap_or_else(|| action.source_readiness_root.clone());
        let transcript_root = fixture
            .map(|record| record.transcript_root.clone())
            .unwrap_or_else(|| action.source_root.clone());
        let blocker_surface_root = fixture
            .map(|record| record.blocker_surface_root.clone())
            .unwrap_or_else(|| action.dependency_root.clone());
        let redacted_fixture_commitment = fixture
            .map(|record| record.redacted_fixture_commitment.clone())
            .unwrap_or_else(|| redacted_fixture_commitment(action, &fixture_root));
        let (cargo_case_id, cargo_case_root) =
            cargo_case_binding(fixture, action, cargo_report, &cargo_index_key);
        let request_payload_root = request_payload_root(
            &cargo_test_path,
            &cargo_test_filter,
            &fixture_root,
            &action.evidence_root,
            &action.acceptance_root,
            action.manual_required,
            config.cargo_execution_deferred,
        );
        let assertion_root = assertion_root(
            action.kind,
            lane,
            status,
            expected_outcome,
            &action.evidence_root,
            &action.acceptance_root,
            &blocker_surface_root,
            action.blocks_user_release,
            action.blocks_production,
        );
        let cargo_binding_root = cargo_binding_root(
            &cargo_case_id,
            &cargo_case_root,
            &cargo_index_key,
            &request_payload_root,
            &assertion_root,
        );
        let release_safe_if_green = action.blocks_user_release
            && matches!(
                expected_outcome,
                RemediationFixtureExpectedOutcome::ReleaseUnblocked
            );
        let production_safe_if_green = action.blocks_production
            && matches!(
                expected_outcome,
                RemediationFixtureExpectedOutcome::ProductionUnblocked
                    | RemediationFixtureExpectedOutcome::ReleaseUnblocked
            );
        let metadata_leakage_budget_bound = config.require_privacy_fixture
            || lane == RemediationFixtureLane::PrivacyReceiptScanning;
        let contract_root = remediation_fixture_contract_root(
            action.kind,
            lane,
            status,
            expected_outcome,
            &action.action_id,
            &action.release_claim_id,
            &request_payload_root,
            &assertion_root,
            &cargo_binding_root,
            &action.evidence_root,
            action.manual_required,
            action.blocks_user_release,
            action.blocks_production,
        );
        let contract_id = remediation_fixture_contract_id(
            &action.release_claim_id,
            &action.action_id,
            &contract_root,
        );
        Self {
            contract_id,
            action_id: action.action_id.clone(),
            release_claim_id: action.release_claim_id.clone(),
            action_kind: action.kind,
            lane,
            status,
            severity: action.severity,
            priority_rank: action.priority_rank,
            owner_lane: action.owner_lane.clone(),
            objective: action.objective.clone(),
            expected_outcome,
            expected_unblock: action.expected_unblock.clone(),
            cargo_test_path,
            cargo_test_filter,
            cargo_index_key,
            source_fixture_export_id,
            source_vector_id,
            source_test_name,
            fixture_root,
            baseline_report_root,
            transcript_root,
            blocker_surface_root,
            redacted_fixture_commitment,
            cargo_case_id,
            cargo_case_root,
            remediation_evidence_root: action.evidence_root.clone(),
            remediation_action_root: action.action_root.clone(),
            request_payload_root,
            assertion_root,
            cargo_binding_root,
            manual_required: action.manual_required,
            retry_after_blocks: action.retry_after_blocks,
            cargo_execution_deferred: config.cargo_execution_deferred,
            release_safe_if_green,
            production_safe_if_green,
            metadata_leakage_budget_bound,
            blocks_user_release: action.blocks_user_release,
            blocks_production: action.blocks_production,
            contract_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "action_id": self.action_id,
            "release_claim_id": self.release_claim_id,
            "action_kind": self.action_kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "priority_rank": self.priority_rank,
            "owner_lane": self.owner_lane,
            "objective": self.objective,
            "expected_outcome": self.expected_outcome.as_str(),
            "expected_unblock": self.expected_unblock,
            "cargo_test_path": self.cargo_test_path,
            "cargo_test_filter": self.cargo_test_filter,
            "cargo_index_key": self.cargo_index_key,
            "source_fixture_export_id": self.source_fixture_export_id,
            "source_vector_id": self.source_vector_id,
            "source_test_name": self.source_test_name,
            "fixture_root": self.fixture_root,
            "baseline_report_root": self.baseline_report_root,
            "transcript_root": self.transcript_root,
            "blocker_surface_root": self.blocker_surface_root,
            "redacted_fixture_commitment": self.redacted_fixture_commitment,
            "cargo_case_id": self.cargo_case_id,
            "cargo_case_root": self.cargo_case_root,
            "remediation_evidence_root": self.remediation_evidence_root,
            "remediation_action_root": self.remediation_action_root,
            "request_payload_root": self.request_payload_root,
            "assertion_root": self.assertion_root,
            "cargo_binding_root": self.cargo_binding_root,
            "manual_required": self.manual_required,
            "retry_after_blocks": self.retry_after_blocks,
            "cargo_execution_deferred": self.cargo_execution_deferred,
            "release_safe_if_green": self.release_safe_if_green,
            "production_safe_if_green": self.production_safe_if_green,
            "metadata_leakage_budget_bound": self.metadata_leakage_budget_bound,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
            "contract_root": self.contract_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.contract_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationFixtureManifestReport {
    pub report_id: String,
    pub status: RemediationFixtureManifestStatus,
    pub readiness_label: String,
    pub release_claim_id: String,
    pub remediation_plan_id: String,
    pub remediation_plan_status: RemediationPlanStatus,
    pub fixture_export_report_id: String,
    pub cargo_harness_report_id: String,
    pub remediation_state_root: String,
    pub remediation_plan_root: String,
    pub fixture_export_state_root: String,
    pub fixture_export_report_root: String,
    pub cargo_harness_state_root: String,
    pub cargo_harness_report_root: String,
    pub actions_total: u64,
    pub contracts_total: u64,
    pub contracts_ready: u64,
    pub contracts_deferred: u64,
    pub contracts_blocked: u64,
    pub contracts_bound: u64,
    pub user_release_contracts: u64,
    pub production_contracts: u64,
    pub manual_contracts: u64,
    pub pq_contracts: u64,
    pub privacy_contracts: u64,
    pub deferred_cargo_contracts: u64,
    pub contracts: BTreeMap<String, RemediationFixtureContract>,
    pub roots: RemediationFixtureManifestRoots,
}

impl RemediationFixtureManifestReport {
    pub fn public_record(&self) -> Value {
        let contracts = self
            .contracts
            .values()
            .map(RemediationFixtureContract::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "release_claim_id": self.release_claim_id,
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_status": self.remediation_plan_status.as_str(),
            "fixture_export_report_id": self.fixture_export_report_id,
            "cargo_harness_report_id": self.cargo_harness_report_id,
            "remediation_state_root": self.remediation_state_root,
            "remediation_plan_root": self.remediation_plan_root,
            "fixture_export_state_root": self.fixture_export_state_root,
            "fixture_export_report_root": self.fixture_export_report_root,
            "cargo_harness_state_root": self.cargo_harness_state_root,
            "cargo_harness_report_root": self.cargo_harness_report_root,
            "actions_total": self.actions_total,
            "contracts_total": self.contracts_total,
            "contracts_ready": self.contracts_ready,
            "contracts_deferred": self.contracts_deferred,
            "contracts_blocked": self.contracts_blocked,
            "contracts_bound": self.contracts_bound,
            "user_release_contracts": self.user_release_contracts,
            "production_contracts": self.production_contracts,
            "manual_contracts": self.manual_contracts,
            "pq_contracts": self.pq_contracts,
            "privacy_contracts": self.privacy_contracts,
            "deferred_cargo_contracts": self.deferred_cargo_contracts,
            "contracts": contracts,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemediationFixtureManifestRoots {
    pub contract_root: String,
    pub cargo_index_root: String,
    pub assertion_root: String,
    pub manual_gate_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl RemediationFixtureManifestRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_root": self.contract_root,
            "cargo_index_root": self.cargo_index_root,
            "assertion_root": self.assertion_root,
            "manual_gate_root": self.manual_gate_root,
            "source_root": self.source_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_clear: u64,
    pub reports_active: u64,
    pub reports_blocked: u64,
    pub contracts_total: u64,
    pub contracts_ready: u64,
    pub contracts_deferred: u64,
    pub contracts_blocked: u64,
    pub contracts_bound: u64,
    pub user_release_contracts: u64,
    pub production_contracts: u64,
    pub manual_contracts: u64,
    pub pq_contracts: u64,
    pub privacy_contracts: u64,
    pub deferred_cargo_contracts: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_clear": self.reports_clear,
            "reports_active": self.reports_active,
            "reports_blocked": self.reports_blocked,
            "contracts_total": self.contracts_total,
            "contracts_ready": self.contracts_ready,
            "contracts_deferred": self.contracts_deferred,
            "contracts_blocked": self.contracts_blocked,
            "contracts_bound": self.contracts_bound,
            "user_release_contracts": self.user_release_contracts,
            "production_contracts": self.production_contracts,
            "manual_contracts": self.manual_contracts,
            "pq_contracts": self.pq_contracts,
            "privacy_contracts": self.privacy_contracts,
            "deferred_cargo_contracts": self.deferred_cargo_contracts,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-MANIFEST-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-MANIFEST-STATE",
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
    pub latest_report: Option<RemediationFixtureManifestReport>,
    pub report_history: Vec<RemediationFixtureManifestReport>,
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
        let remediation =
            crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let fixture_export =
            crate::monero_l2_pq_bridge_exit_final_release_fixture_export_runtime::devnet();
        let cargo_harness =
            crate::monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime::devnet();
        state
            .build_remediation_fixture_manifest(&remediation, &fixture_export, &cargo_harness)
            .expect("devnet bridge exit release remediation fixture manifest");
        state
    }

    pub fn build_remediation_fixture_manifest(
        &mut self,
        remediation: &RemediationPlannerState,
        fixture_export: &FixtureExportState,
        cargo_harness: &CargoHarnessState,
    ) -> Result<String> {
        let plan = remediation
            .latest_plan
            .as_ref()
            .ok_or_else(|| "release remediation planner has no latest plan".to_string())?;
        let fixture_report = fixture_export
            .latest_report
            .as_ref()
            .ok_or_else(|| "final release fixture export has no latest report".to_string())?;
        let cargo_report = cargo_harness
            .latest_report
            .as_ref()
            .ok_or_else(|| "cargo runtime harness has no latest report".to_string())?;
        ensure(
            plan.release_claim_id == fixture_report.release_claim_id,
            "remediation plan and fixture export release claim mismatch",
        )?;
        ensure(
            plan.release_claim_id == cargo_report.release_claim_id,
            "remediation plan and cargo harness release claim mismatch",
        )?;
        let contracts = build_contracts(&self.config, plan, fixture_report, cargo_report);
        ensure(
            plan.status == RemediationPlanStatus::Clear
                || contracts.len() as u64 >= self.config.min_fixture_contracts,
            "remediation fixture manifest omitted required action contracts",
        )?;
        let contracts_total = contracts.len() as u64;
        let contracts_ready = contracts
            .values()
            .filter(|contract| contract.status == RemediationFixtureStatus::Ready)
            .count() as u64;
        let contracts_deferred = contracts
            .values()
            .filter(|contract| contract.status == RemediationFixtureStatus::Deferred)
            .count() as u64;
        let contracts_blocked = contracts
            .values()
            .filter(|contract| contract.status == RemediationFixtureStatus::Blocked)
            .count() as u64;
        let contracts_bound = contracts
            .values()
            .filter(|contract| contract.status == RemediationFixtureStatus::Bound)
            .count() as u64;
        let user_release_contracts = contracts
            .values()
            .filter(|contract| contract.blocks_user_release)
            .count() as u64;
        let production_contracts = contracts
            .values()
            .filter(|contract| contract.blocks_production)
            .count() as u64;
        let manual_contracts = contracts
            .values()
            .filter(|contract| contract.manual_required)
            .count() as u64;
        let pq_contracts = contracts
            .values()
            .filter(|contract| contract.lane == RemediationFixtureLane::PqAuthority)
            .count() as u64;
        let privacy_contracts = contracts
            .values()
            .filter(|contract| contract.metadata_leakage_budget_bound)
            .count() as u64;
        let deferred_cargo_contracts = contracts
            .values()
            .filter(|contract| contract.cargo_execution_deferred)
            .count() as u64;
        let status = manifest_status(plan.status, contracts_blocked, contracts_deferred);
        let readiness_label = readiness_label(
            status,
            plan.status,
            contracts_total,
            deferred_cargo_contracts,
        )
        .to_string();
        let contract_records = contracts
            .values()
            .map(RemediationFixtureContract::public_record)
            .collect::<Vec<_>>();
        let contract_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-CONTRACTS",
            &contract_records,
        );
        let cargo_index_root = cargo_index_root(&contracts);
        let assertion_root = manifest_assertion_root(&contracts);
        let manual_gate_root = manual_gate_root(&contracts);
        let source_root = source_root(
            &remediation.state_root(),
            &plan.state_root(),
            &fixture_export.state_root(),
            &fixture_report.state_root(),
            &cargo_harness.state_root(),
            &cargo_report.state_root(),
            &plan.roots.action_root,
            &fixture_report.roots.export_root,
            &cargo_report.roots.case_root,
            &plan.release_claim_id,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &contract_root,
            &cargo_index_root,
            &assertion_root,
            &manual_gate_root,
            &plan.release_claim_id,
            contracts_ready,
            contracts_deferred,
            contracts_blocked,
        );
        let report_id =
            remediation_fixture_manifest_report_id(&plan.release_claim_id, &report_root);
        let report = RemediationFixtureManifestReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            release_claim_id: plan.release_claim_id.clone(),
            remediation_plan_id: plan.plan_id.clone(),
            remediation_plan_status: plan.status,
            fixture_export_report_id: fixture_report.report_id.clone(),
            cargo_harness_report_id: cargo_report.report_id.clone(),
            remediation_state_root: remediation.state_root(),
            remediation_plan_root: plan.state_root(),
            fixture_export_state_root: fixture_export.state_root(),
            fixture_export_report_root: fixture_report.state_root(),
            cargo_harness_state_root: cargo_harness.state_root(),
            cargo_harness_report_root: cargo_report.state_root(),
            actions_total: plan.actions_total,
            contracts_total,
            contracts_ready,
            contracts_deferred,
            contracts_blocked,
            contracts_bound,
            user_release_contracts,
            production_contracts,
            manual_contracts,
            pq_contracts,
            privacy_contracts,
            deferred_cargo_contracts,
            contracts,
            roots: RemediationFixtureManifestRoots {
                contract_root,
                cargo_index_root,
                assertion_root,
                manual_gate_root,
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
            "manifest_suite": self.config.manifest_suite,
            "latest_report": self.latest_report.as_ref().map(RemediationFixtureManifestReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: RemediationFixtureManifestReport) {
        self.counters.reports_run += 1;
        self.counters.contracts_total += report.contracts_total;
        self.counters.contracts_ready += report.contracts_ready;
        self.counters.contracts_deferred += report.contracts_deferred;
        self.counters.contracts_blocked += report.contracts_blocked;
        self.counters.contracts_bound += report.contracts_bound;
        self.counters.user_release_contracts += report.user_release_contracts;
        self.counters.production_contracts += report.production_contracts;
        self.counters.manual_contracts += report.manual_contracts;
        self.counters.pq_contracts += report.pq_contracts;
        self.counters.privacy_contracts += report.privacy_contracts;
        self.counters.deferred_cargo_contracts += report.deferred_cargo_contracts;
        match report.status {
            RemediationFixtureManifestStatus::Clear => self.counters.reports_clear += 1,
            RemediationFixtureManifestStatus::Active => self.counters.reports_active += 1,
            RemediationFixtureManifestStatus::Blocked => self.counters.reports_blocked += 1,
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
            .map(RemediationFixtureManifestReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-MANIFEST-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_contracts(
    config: &Config,
    plan: &ReleaseRemediationPlan,
    fixture_report: &FixtureExportReport,
    cargo_report: &CargoRuntimeHarnessReport,
) -> BTreeMap<String, RemediationFixtureContract> {
    let mut actions = plan.actions.values().collect::<Vec<_>>();
    actions.sort_by_key(|action| action.priority_rank);
    actions
        .into_iter()
        .enumerate()
        .map(|(index, action)| {
            let fixture = select_fixture_for_action(action, fixture_report, index as u64);
            RemediationFixtureContract::from_action(
                config,
                action,
                fixture,
                cargo_report,
                index as u64,
            )
        })
        .map(|contract| (contract.contract_id.clone(), contract))
        .collect()
}

fn select_fixture_for_action<'a>(
    action: &RemediationAction,
    fixture_report: &'a FixtureExportReport,
    ordinal: u64,
) -> Option<&'a FixtureExportRecord> {
    fixture_report
        .export_records
        .values()
        .filter(|record| record.release_claim_id == action.release_claim_id)
        .find(|record| fixture_matches_action(action.kind, record))
        .or_else(|| {
            let records = fixture_report
                .export_records
                .values()
                .filter(|record| record.release_claim_id == action.release_claim_id)
                .collect::<Vec<_>>();
            if records.is_empty() {
                None
            } else {
                Some(records[(ordinal as usize) % records.len()])
            }
        })
}

fn fixture_matches_action(kind: RemediationActionKind, record: &FixtureExportRecord) -> bool {
    let haystack = format!(
        "{} {} {} {}",
        record.test_name, record.cargo_test_path, record.cargo_test_filter, record.cargo_index_key
    )
    .to_ascii_lowercase();
    action_keywords(kind)
        .iter()
        .any(|keyword| haystack.contains(keyword))
}

fn action_keywords(kind: RemediationActionKind) -> &'static [&'static str] {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => &["settlement", "release", "exit"],
        RemediationActionKind::EnablePqAuthorityVerification => &["pq", "authority", "signer"],
        RemediationActionKind::MaterializeCargoRuntimeTests => &["cargo", "runtime", "harness"],
        RemediationActionKind::CompleteSecurityPrivacyAudit => &["audit", "security", "privacy"],
        RemediationActionKind::ResolveForcedExitUserAnswer => &["forced", "user", "exit"],
        RemediationActionKind::ClearProductionReleaseGate => &["production", "final", "gate"],
        RemediationActionKind::PreservePrivacyReceiptScanning => &["receipt", "privacy", "scan"],
    }
}

fn lane_for_action(kind: RemediationActionKind) -> RemediationFixtureLane {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => {
            RemediationFixtureLane::SettlementExecution
        }
        RemediationActionKind::EnablePqAuthorityVerification => RemediationFixtureLane::PqAuthority,
        RemediationActionKind::MaterializeCargoRuntimeTests => RemediationFixtureLane::CargoRuntime,
        RemediationActionKind::CompleteSecurityPrivacyAudit => {
            RemediationFixtureLane::SecurityAudit
        }
        RemediationActionKind::ResolveForcedExitUserAnswer => {
            RemediationFixtureLane::ForcedExitUserRecovery
        }
        RemediationActionKind::ClearProductionReleaseGate => RemediationFixtureLane::ProductionGate,
        RemediationActionKind::PreservePrivacyReceiptScanning => {
            RemediationFixtureLane::PrivacyReceiptScanning
        }
    }
}

fn fixture_status(
    config: &Config,
    action: &RemediationAction,
    fixture: Option<&FixtureExportRecord>,
) -> RemediationFixtureStatus {
    match action.status {
        RemediationActionStatus::Complete => RemediationFixtureStatus::Bound,
        RemediationActionStatus::Blocked => RemediationFixtureStatus::Blocked,
        RemediationActionStatus::WaitingOnDeferredGate => RemediationFixtureStatus::Deferred,
        RemediationActionStatus::ReadyToStart if config.cargo_execution_deferred => {
            RemediationFixtureStatus::Deferred
        }
        RemediationActionStatus::ReadyToStart if fixture.is_none() => {
            RemediationFixtureStatus::Blocked
        }
        RemediationActionStatus::ReadyToStart => RemediationFixtureStatus::Ready,
    }
}

fn expected_outcome(action: &RemediationAction) -> RemediationFixtureExpectedOutcome {
    if action.status == RemediationActionStatus::Blocked {
        RemediationFixtureExpectedOutcome::StillBlocked
    } else if action.blocks_user_release {
        RemediationFixtureExpectedOutcome::ReleaseUnblocked
    } else if action.blocks_production {
        RemediationFixtureExpectedOutcome::ProductionUnblocked
    } else {
        RemediationFixtureExpectedOutcome::WatchCleared
    }
}

fn cargo_case_binding(
    fixture: Option<&FixtureExportRecord>,
    action: &RemediationAction,
    cargo_report: &CargoRuntimeHarnessReport,
    cargo_index_key: &str,
) -> (String, String) {
    let by_fixture = fixture.and_then(|record| {
        cargo_report
            .cases
            .values()
            .find(|case| case.fixture_export_id == record.export_id)
    });
    let by_index = cargo_report
        .cases
        .values()
        .find(|case| case.cargo_index_key == cargo_index_key);
    let case = by_fixture.or(by_index);
    match case {
        Some(case) => (case.case_id.clone(), case.case_root.clone()),
        None => {
            let root = synthetic_cargo_case_root(action, cargo_index_key);
            let id = synthetic_cargo_case_id(&action.release_claim_id, cargo_index_key, &root);
            (id, root)
        }
    }
}

fn manifest_status(
    plan_status: RemediationPlanStatus,
    contracts_blocked: u64,
    contracts_deferred: u64,
) -> RemediationFixtureManifestStatus {
    if plan_status == RemediationPlanStatus::Clear && contracts_blocked == 0 {
        RemediationFixtureManifestStatus::Clear
    } else if contracts_blocked > 0 || plan_status == RemediationPlanStatus::Blocked {
        RemediationFixtureManifestStatus::Blocked
    } else if contracts_deferred > 0 || plan_status == RemediationPlanStatus::Active {
        RemediationFixtureManifestStatus::Active
    } else {
        RemediationFixtureManifestStatus::Clear
    }
}

fn readiness_label(
    status: RemediationFixtureManifestStatus,
    plan_status: RemediationPlanStatus,
    contracts_total: u64,
    deferred_cargo_contracts: u64,
) -> &'static str {
    if status == RemediationFixtureManifestStatus::Blocked {
        "remediation_fixture_manifest_blocked"
    } else if deferred_cargo_contracts > 0 {
        "remediation_fixture_manifest_deferred_until_cargo_execution"
    } else if plan_status == RemediationPlanStatus::Clear && contracts_total == 0 {
        "remediation_fixture_manifest_clear"
    } else {
        "remediation_fixture_manifest_active"
    }
}

fn synthetic_cargo_path(lane: RemediationFixtureLane) -> &'static str {
    match lane {
        RemediationFixtureLane::SettlementExecution => {
            "bridge_exit::release_remediation::settlement_execution"
        }
        RemediationFixtureLane::PqAuthority => "bridge_exit::release_remediation::pq_authority",
        RemediationFixtureLane::CargoRuntime => "bridge_exit::release_remediation::cargo_runtime",
        RemediationFixtureLane::SecurityAudit => "bridge_exit::release_remediation::security_audit",
        RemediationFixtureLane::ForcedExitUserRecovery => {
            "bridge_exit::release_remediation::forced_exit_user_recovery"
        }
        RemediationFixtureLane::ProductionGate => {
            "bridge_exit::release_remediation::production_gate"
        }
        RemediationFixtureLane::PrivacyReceiptScanning => {
            "bridge_exit::release_remediation::privacy_receipt_scanning"
        }
    }
}

fn synthetic_cargo_filter(kind: RemediationActionKind) -> &'static str {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => "settlement_execution_green",
        RemediationActionKind::EnablePqAuthorityVerification => "pq_authority_green",
        RemediationActionKind::MaterializeCargoRuntimeTests => "cargo_runtime_green",
        RemediationActionKind::CompleteSecurityPrivacyAudit => "security_privacy_audit_green",
        RemediationActionKind::ResolveForcedExitUserAnswer => "forced_exit_user_answer_green",
        RemediationActionKind::ClearProductionReleaseGate => "production_release_green",
        RemediationActionKind::PreservePrivacyReceiptScanning => "receipt_privacy_green",
    }
}

fn synthetic_test_name(kind: RemediationActionKind) -> &'static str {
    match kind {
        RemediationActionKind::EnableLiveSettlementExecution => {
            "bridge_exit_release_remediation_settlement_execution"
        }
        RemediationActionKind::EnablePqAuthorityVerification => {
            "bridge_exit_release_remediation_pq_authority"
        }
        RemediationActionKind::MaterializeCargoRuntimeTests => {
            "bridge_exit_release_remediation_cargo_runtime"
        }
        RemediationActionKind::CompleteSecurityPrivacyAudit => {
            "bridge_exit_release_remediation_security_audit"
        }
        RemediationActionKind::ResolveForcedExitUserAnswer => {
            "bridge_exit_release_remediation_forced_exit_user_recovery"
        }
        RemediationActionKind::ClearProductionReleaseGate => {
            "bridge_exit_release_remediation_production_gate"
        }
        RemediationActionKind::PreservePrivacyReceiptScanning => {
            "bridge_exit_release_remediation_receipt_privacy"
        }
    }
}

fn synthetic_vector_id(kind: RemediationActionKind, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-SYNTHETIC-VECTOR-ID",
        &[HashPart::Str(kind.as_str()), HashPart::U64(ordinal)],
        16,
    )
}

fn cargo_index_key(path: &str, filter: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-CARGO-INDEX-KEY",
        &[HashPart::Str(path), HashPart::Str(filter)],
        16,
    )
}

fn synthetic_fixture_root(
    action: &RemediationAction,
    lane: RemediationFixtureLane,
    ordinal: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-SYNTHETIC-FIXTURE",
        &[
            HashPart::Str(&action.action_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(&action.evidence_root),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn redacted_fixture_commitment(action: &RemediationAction, fixture_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-REDACTED-FIXTURE",
        &[
            HashPart::Str(&action.action_id),
            HashPart::Str(fixture_root),
            HashPart::Str(&action.evidence_root),
        ],
        32,
    )
}

fn synthetic_cargo_case_root(action: &RemediationAction, cargo_index_key: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-SYNTHETIC-CARGO-CASE",
        &[
            HashPart::Str(&action.action_id),
            HashPart::Str(cargo_index_key),
            HashPart::Str(&action.acceptance_root),
        ],
        32,
    )
}

fn synthetic_cargo_case_id(
    release_claim_id: &str,
    cargo_index_key: &str,
    case_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-SYNTHETIC-CARGO-CASE-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(cargo_index_key),
            HashPart::Str(case_root),
        ],
        32,
    )
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
pub fn request_payload_root(
    cargo_test_path: &str,
    cargo_test_filter: &str,
    fixture_root: &str,
    evidence_root: &str,
    acceptance_root: &str,
    manual_required: bool,
    cargo_execution_deferred: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-REQUEST",
        &[
            HashPart::Str(cargo_test_path),
            HashPart::Str(cargo_test_filter),
            HashPart::Str(fixture_root),
            HashPart::Str(evidence_root),
            HashPart::Str(acceptance_root),
            HashPart::Str(bool_str(manual_required)),
            HashPart::Str(bool_str(cargo_execution_deferred)),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn assertion_root(
    kind: RemediationActionKind,
    lane: RemediationFixtureLane,
    status: RemediationFixtureStatus,
    expected_outcome: RemediationFixtureExpectedOutcome,
    evidence_root: &str,
    acceptance_root: &str,
    blocker_surface_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-ASSERTION",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(acceptance_root),
            HashPart::Str(blocker_surface_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn cargo_binding_root(
    cargo_case_id: &str,
    cargo_case_root: &str,
    cargo_index_key: &str,
    request_payload_root: &str,
    assertion_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-CARGO-BINDING",
        &[
            HashPart::Str(cargo_case_id),
            HashPart::Str(cargo_case_root),
            HashPart::Str(cargo_index_key),
            HashPart::Str(request_payload_root),
            HashPart::Str(assertion_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn remediation_fixture_contract_root(
    kind: RemediationActionKind,
    lane: RemediationFixtureLane,
    status: RemediationFixtureStatus,
    expected_outcome: RemediationFixtureExpectedOutcome,
    action_id: &str,
    release_claim_id: &str,
    request_payload_root: &str,
    assertion_root: &str,
    cargo_binding_root: &str,
    evidence_root: &str,
    manual_required: bool,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-CONTRACT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::Str(action_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(request_payload_root),
            HashPart::Str(assertion_root),
            HashPart::Str(cargo_binding_root),
            HashPart::Str(evidence_root),
            HashPart::Str(bool_str(manual_required)),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn remediation_fixture_contract_id(
    release_claim_id: &str,
    action_id: &str,
    contract_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-CONTRACT-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(action_id),
            HashPart::Str(contract_root),
        ],
        32,
    )
}

pub fn cargo_index_root(contracts: &BTreeMap<String, RemediationFixtureContract>) -> String {
    let records = contracts
        .values()
        .map(|contract| {
            json!({
                "contract_id": contract.contract_id,
                "action_id": contract.action_id,
                "cargo_test_path": contract.cargo_test_path,
                "cargo_test_filter": contract.cargo_test_filter,
                "cargo_index_key": contract.cargo_index_key,
                "cargo_case_id": contract.cargo_case_id,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-CARGO-INDEX",
        &records,
    )
}

pub fn manifest_assertion_root(contracts: &BTreeMap<String, RemediationFixtureContract>) -> String {
    let records = contracts
        .values()
        .map(|contract| {
            json!({
                "contract_id": contract.contract_id,
                "lane": contract.lane.as_str(),
                "status": contract.status.as_str(),
                "expected_outcome": contract.expected_outcome.as_str(),
                "assertion_root": contract.assertion_root,
                "blocks_user_release": contract.blocks_user_release,
                "blocks_production": contract.blocks_production,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-ASSERTIONS",
        &records,
    )
}

pub fn manual_gate_root(contracts: &BTreeMap<String, RemediationFixtureContract>) -> String {
    let records = contracts
        .values()
        .filter(|contract| contract.manual_required)
        .map(|contract| {
            json!({
                "contract_id": contract.contract_id,
                "lane": contract.lane.as_str(),
                "owner_lane": contract.owner_lane,
                "severity": contract.severity.as_str(),
                "retry_after_blocks": contract.retry_after_blocks,
                "evidence_root": contract.remediation_evidence_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-MANUAL-GATES",
        &records,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    remediation_state_root: &str,
    remediation_plan_root: &str,
    fixture_export_state_root: &str,
    fixture_export_report_root: &str,
    cargo_harness_state_root: &str,
    cargo_harness_report_root: &str,
    remediation_action_root: &str,
    fixture_export_root: &str,
    cargo_case_root: &str,
    release_claim_id: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-SOURCE",
        &[
            HashPart::Str(remediation_state_root),
            HashPart::Str(remediation_plan_root),
            HashPart::Str(fixture_export_state_root),
            HashPart::Str(fixture_export_report_root),
            HashPart::Str(cargo_harness_state_root),
            HashPart::Str(cargo_harness_report_root),
            HashPart::Str(remediation_action_root),
            HashPart::Str(fixture_export_root),
            HashPart::Str(cargo_case_root),
            HashPart::Str(release_claim_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn report_root(
    status: RemediationFixtureManifestStatus,
    readiness_label: &str,
    source_root: &str,
    contract_root: &str,
    cargo_index_root: &str,
    assertion_root: &str,
    manual_gate_root: &str,
    release_claim_id: &str,
    contracts_ready: u64,
    contracts_deferred: u64,
    contracts_blocked: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(contract_root),
            HashPart::Str(cargo_index_root),
            HashPart::Str(assertion_root),
            HashPart::Str(manual_gate_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(contracts_ready),
            HashPart::U64(contracts_deferred),
            HashPart::U64(contracts_blocked),
        ],
        32,
    )
}

pub fn remediation_fixture_manifest_report_id(release_claim_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-REPORT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-REMEDIATION-FIXTURE-RECORD",
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
