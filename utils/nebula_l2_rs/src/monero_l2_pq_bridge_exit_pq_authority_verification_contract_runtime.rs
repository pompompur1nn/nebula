use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime::{
        PqAuthorityKeyManagerReport, PqAuthorityKeyManagerReportStatus,
        PqAuthorityObservationStatus, State as PqAuthorityKeyManagerState,
    },
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        ReleaseRemediationPlan, RemediationAction, RemediationActionKind, RemediationActionStatus,
        RemediationPlanStatus, State as ReleaseRemediationPlannerState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitPqAuthorityVerificationContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PQ_AUTHORITY_VERIFICATION_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-pq-authority-verification-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PQ_AUTHORITY_VERIFICATION_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTHORITY_VERIFICATION_CONTRACT_SUITE: &str =
    "monero-l2-pq-bridge-exit-pq-authority-verification-contract-v1";
pub const DEFAULT_CURRENT_AUTHORITY_EPOCH: u64 = 42;
pub const DEFAULT_MAX_SIGNER_AGE_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const DEFAULT_MIN_CONTRACT_CHECKS: u64 = 4;
pub const DEFAULT_MAX_CONTRACTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationContractKind {
    SignerFreshness,
    RotationContinuity,
    EpochBinding,
    WithdrawalAuthorization,
}

impl VerificationContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignerFreshness => "signer_freshness",
            Self::RotationContinuity => "rotation_continuity",
            Self::EpochBinding => "epoch_binding",
            Self::WithdrawalAuthorization => "withdrawal_authorization",
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::SignerFreshness,
            Self::RotationContinuity,
            Self::EpochBinding,
            Self::WithdrawalAuthorization,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationContractStatus {
    Enforced,
    Deferred,
    Blocked,
}

impl VerificationContractStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }

    pub fn allows_user_release(self) -> bool {
        matches!(self, Self::Enforced | Self::Deferred)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationContractReportStatus {
    Passed,
    Watch,
    Failed,
}

impl VerificationContractReportStatus {
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
    pub contract_suite: String,
    pub current_authority_epoch: u64,
    pub max_signer_age_epochs: u64,
    pub min_pq_security_bits: u64,
    pub min_contract_checks: u64,
    pub fail_closed_on_blocked_authorization: bool,
    pub allow_deferred_remediation_for_devnet: bool,
    pub max_contracts: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            contract_suite: PQ_AUTHORITY_VERIFICATION_CONTRACT_SUITE.to_string(),
            current_authority_epoch: DEFAULT_CURRENT_AUTHORITY_EPOCH,
            max_signer_age_epochs: DEFAULT_MAX_SIGNER_AGE_EPOCHS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_contract_checks: DEFAULT_MIN_CONTRACT_CHECKS,
            fail_closed_on_blocked_authorization: true,
            allow_deferred_remediation_for_devnet: true,
            max_contracts: DEFAULT_MAX_CONTRACTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "contract_suite": self.contract_suite,
            "current_authority_epoch": self.current_authority_epoch,
            "max_signer_age_epochs": self.max_signer_age_epochs,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_contract_checks": self.min_contract_checks,
            "fail_closed_on_blocked_authorization": self.fail_closed_on_blocked_authorization,
            "allow_deferred_remediation_for_devnet": self.allow_deferred_remediation_for_devnet,
            "max_contracts": self.max_contracts,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationContract {
    pub contract_id: String,
    pub kind: VerificationContractKind,
    pub status: VerificationContractStatus,
    pub release_claim_id: String,
    pub scenario_id: String,
    pub source_report_id: String,
    pub source_report_status: PqAuthorityKeyManagerReportStatus,
    pub remediation_action_id: String,
    pub remediation_action_kind: RemediationActionKind,
    pub remediation_action_status: RemediationActionStatus,
    pub authority_epoch: u64,
    pub current_authority_epoch: u64,
    pub max_signer_age_epochs: u64,
    pub pq_security_bits: u64,
    pub requirement: String,
    pub observed: String,
    pub signer_fresh: bool,
    pub rotation_bound: bool,
    pub epoch_bound: bool,
    pub withdrawal_authorized: bool,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
    pub signer_root: String,
    pub rotation_root: String,
    pub epoch_binding_root: String,
    pub withdrawal_authorization_root: String,
    pub remediation_root: String,
    pub evidence_root: String,
    pub contract_root: String,
}

impl VerificationContract {
    pub fn from_sources(
        config: &Config,
        report: &PqAuthorityKeyManagerReport,
        action: &RemediationAction,
        kind: VerificationContractKind,
        ordinal: u64,
    ) -> Self {
        let authority_epoch = authority_epoch_for(config, report, ordinal);
        let pq_security_bits = report
            .observations
            .values()
            .map(|observation| observation.pq_security_bits)
            .max()
            .unwrap_or(config.min_pq_security_bits);
        let signer_fresh = authority_epoch.saturating_add(config.max_signer_age_epochs)
            >= config.current_authority_epoch;
        let rotation_bound = report.stale_rotations == 0 && report.quarantine_required == 0;
        let epoch_bound = report
            .observations
            .values()
            .all(|observation| observation.authority_epoch <= config.current_authority_epoch);
        let withdrawal_authorized = !action.blocks_user_release
            && report.status != PqAuthorityKeyManagerReportStatus::Failed
            && report.release_holds_required == 0;
        let status = contract_status(
            config,
            kind,
            report.status,
            action.status,
            signer_fresh,
            rotation_bound,
            epoch_bound,
            withdrawal_authorized,
        );
        let signer_root = signer_freshness_root(
            &report.release_claim_id,
            &report.roots.observation_root,
            authority_epoch,
            config.current_authority_epoch,
            pq_security_bits,
            signer_fresh,
        );
        let rotation_root = rotation_continuity_root(
            &report.roots.response_root,
            &report.roots.failure_root,
            report.stale_rotations,
            report.quarantine_required,
            rotation_bound,
        );
        let epoch_binding_root = epoch_binding_root(
            &config.chain_id,
            &report.release_claim_id,
            &report.scenario_id,
            authority_epoch,
            config.current_authority_epoch,
            epoch_bound,
        );
        let withdrawal_authorization_root = withdrawal_authorization_root(
            &report.release_claim_id,
            &action.action_id,
            report.release_holds_required,
            action.blocks_user_release,
            withdrawal_authorized,
        );
        let remediation_root = remediation_contract_root(
            &action.action_id,
            action.kind,
            action.status,
            &action.action_root,
            action.blocks_user_release,
            action.blocks_production,
        );
        let (requirement, observed) = contract_text(
            kind,
            signer_fresh,
            rotation_bound,
            epoch_bound,
            withdrawal_authorized,
        );
        let evidence_root = verification_evidence_root(
            kind,
            status,
            &signer_root,
            &rotation_root,
            &epoch_binding_root,
            &withdrawal_authorization_root,
            &remediation_root,
        );
        let contract_root = verification_contract_root(
            kind,
            status,
            &report.release_claim_id,
            &report.report_id,
            &action.action_id,
            &evidence_root,
            status == VerificationContractStatus::Blocked,
            action.blocks_production,
        );
        let contract_id = verification_contract_id(kind, &report.release_claim_id, &contract_root);
        Self {
            contract_id,
            kind,
            status,
            release_claim_id: report.release_claim_id.clone(),
            scenario_id: report.scenario_id.clone(),
            source_report_id: report.report_id.clone(),
            source_report_status: report.status,
            remediation_action_id: action.action_id.clone(),
            remediation_action_kind: action.kind,
            remediation_action_status: action.status,
            authority_epoch,
            current_authority_epoch: config.current_authority_epoch,
            max_signer_age_epochs: config.max_signer_age_epochs,
            pq_security_bits,
            requirement,
            observed,
            signer_fresh,
            rotation_bound,
            epoch_bound,
            withdrawal_authorized,
            blocks_user_release: !status.allows_user_release(),
            blocks_production: status == VerificationContractStatus::Blocked
                || action.blocks_production,
            signer_root,
            rotation_root,
            epoch_binding_root,
            withdrawal_authorization_root,
            remediation_root,
            evidence_root,
            contract_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "scenario_id": self.scenario_id,
            "source_report_id": self.source_report_id,
            "source_report_status": self.source_report_status.as_str(),
            "remediation_action_id": self.remediation_action_id,
            "remediation_action_kind": self.remediation_action_kind.as_str(),
            "remediation_action_status": self.remediation_action_status.as_str(),
            "authority_epoch": self.authority_epoch,
            "current_authority_epoch": self.current_authority_epoch,
            "max_signer_age_epochs": self.max_signer_age_epochs,
            "pq_security_bits": self.pq_security_bits,
            "requirement": self.requirement,
            "observed": self.observed,
            "signer_fresh": self.signer_fresh,
            "rotation_bound": self.rotation_bound,
            "epoch_bound": self.epoch_bound,
            "withdrawal_authorized": self.withdrawal_authorized,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
            "signer_root": self.signer_root,
            "rotation_root": self.rotation_root,
            "epoch_binding_root": self.epoch_binding_root,
            "withdrawal_authorization_root": self.withdrawal_authorization_root,
            "remediation_root": self.remediation_root,
            "evidence_root": self.evidence_root,
            "contract_root": self.contract_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.contract_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationContractReport {
    pub report_id: String,
    pub status: VerificationContractReportStatus,
    pub release_claim_id: String,
    pub scenario_id: String,
    pub key_manager_report_id: String,
    pub key_manager_report_status: PqAuthorityKeyManagerReportStatus,
    pub remediation_plan_id: String,
    pub remediation_plan_status: RemediationPlanStatus,
    pub contracts_total: u64,
    pub contracts_enforced: u64,
    pub contracts_deferred: u64,
    pub contracts_blocked: u64,
    pub user_release_blocks: u64,
    pub production_blocks: u64,
    pub signer_freshness_failures: u64,
    pub rotation_failures: u64,
    pub epoch_binding_failures: u64,
    pub withdrawal_authorization_failures: u64,
    pub contracts: BTreeMap<String, VerificationContract>,
    pub roots: VerificationContractReportRoots,
}

impl VerificationContractReport {
    pub fn public_record(&self) -> Value {
        let contracts = self
            .contracts
            .values()
            .map(VerificationContract::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "scenario_id": self.scenario_id,
            "key_manager_report_id": self.key_manager_report_id,
            "key_manager_report_status": self.key_manager_report_status.as_str(),
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_status": self.remediation_plan_status.as_str(),
            "contracts_total": self.contracts_total,
            "contracts_enforced": self.contracts_enforced,
            "contracts_deferred": self.contracts_deferred,
            "contracts_blocked": self.contracts_blocked,
            "user_release_blocks": self.user_release_blocks,
            "production_blocks": self.production_blocks,
            "signer_freshness_failures": self.signer_freshness_failures,
            "rotation_failures": self.rotation_failures,
            "epoch_binding_failures": self.epoch_binding_failures,
            "withdrawal_authorization_failures": self.withdrawal_authorization_failures,
            "contracts": contracts,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationContractReportRoots {
    pub source_root: String,
    pub contract_root: String,
    pub control_plane_root: String,
    pub report_root: String,
}

impl VerificationContractReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "source_root": self.source_root,
            "contract_root": self.contract_root,
            "control_plane_root": self.control_plane_root,
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
    pub contracts_total: u64,
    pub contracts_enforced: u64,
    pub contracts_deferred: u64,
    pub contracts_blocked: u64,
    pub user_release_blocks: u64,
    pub production_blocks: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "contracts_total": self.contracts_total,
            "contracts_enforced": self.contracts_enforced,
            "contracts_deferred": self.contracts_deferred,
            "contracts_blocked": self.contracts_blocked,
            "user_release_blocks": self.user_release_blocks,
            "production_blocks": self.production_blocks,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTRACT-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTRACT-STATE",
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
    pub latest_report: Option<VerificationContractReport>,
    pub report_history: Vec<VerificationContractReport>,
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
        let key_manager =
            crate::monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime::devnet();
        let remediation =
            crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let _ = state.build_verification_contracts(&key_manager, &remediation);
        state
    }

    pub fn build_verification_contracts(
        &mut self,
        key_manager: &PqAuthorityKeyManagerState,
        remediation: &ReleaseRemediationPlannerState,
    ) -> Result<String> {
        let key_report = key_manager
            .latest_report
            .as_ref()
            .ok_or_else(|| "PQ authority key manager has no latest report".to_string())?;
        let plan = remediation
            .latest_plan
            .as_ref()
            .ok_or_else(|| "release remediation planner has no latest plan".to_string())?;
        let actions = pq_authority_actions(plan);
        ensure(
            actions.len() as u64 >= self.config.min_contract_checks,
            "PQ authority verification contract omitted required control-plane checks",
        )?;
        let contracts = build_contracts(&self.config, key_report, plan, &actions);
        ensure(
            contracts.len() <= self.config.max_contracts,
            "PQ authority verification contract exceeded maximum contract count",
        )?;
        let contracts_total = contracts.len() as u64;
        let contracts_enforced = contracts
            .values()
            .filter(|contract| contract.status == VerificationContractStatus::Enforced)
            .count() as u64;
        let contracts_deferred = contracts
            .values()
            .filter(|contract| contract.status == VerificationContractStatus::Deferred)
            .count() as u64;
        let contracts_blocked = contracts
            .values()
            .filter(|contract| contract.status == VerificationContractStatus::Blocked)
            .count() as u64;
        let user_release_blocks = contracts
            .values()
            .filter(|contract| contract.blocks_user_release)
            .count() as u64;
        let production_blocks = contracts
            .values()
            .filter(|contract| contract.blocks_production)
            .count() as u64;
        let signer_freshness_failures = contracts
            .values()
            .filter(|contract| {
                contract.kind == VerificationContractKind::SignerFreshness && !contract.signer_fresh
            })
            .count() as u64;
        let rotation_failures = contracts
            .values()
            .filter(|contract| {
                contract.kind == VerificationContractKind::RotationContinuity
                    && !contract.rotation_bound
            })
            .count() as u64;
        let epoch_binding_failures = contracts
            .values()
            .filter(|contract| {
                contract.kind == VerificationContractKind::EpochBinding && !contract.epoch_bound
            })
            .count() as u64;
        let withdrawal_authorization_failures = contracts
            .values()
            .filter(|contract| {
                contract.kind == VerificationContractKind::WithdrawalAuthorization
                    && !contract.withdrawal_authorized
            })
            .count() as u64;
        let status = report_status(contracts_blocked, contracts_deferred);
        let contract_records = contracts
            .values()
            .map(VerificationContract::public_record)
            .collect::<Vec<_>>();
        let contract_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTRACTS",
            &contract_records,
        );
        let source_root = source_root(
            &key_manager.state_root(),
            &key_report.state_root(),
            &remediation.state_root(),
            &plan.state_root(),
        );
        let control_plane_root = control_plane_root(
            &contract_root,
            &key_report.roots.report_root,
            &plan.roots.plan_root,
            contracts_total,
            user_release_blocks,
            production_blocks,
        );
        let report_root = report_root(
            status,
            &source_root,
            &contract_root,
            &control_plane_root,
            contracts_total,
            contracts_blocked,
        );
        let roots = VerificationContractReportRoots {
            source_root,
            contract_root,
            control_plane_root,
            report_root,
        };
        let report_id =
            verification_report_id(&key_report.report_id, &plan.plan_id, &roots.report_root);
        let report = VerificationContractReport {
            report_id,
            status,
            release_claim_id: key_report.release_claim_id.clone(),
            scenario_id: key_report.scenario_id.clone(),
            key_manager_report_id: key_report.report_id.clone(),
            key_manager_report_status: key_report.status,
            remediation_plan_id: plan.plan_id.clone(),
            remediation_plan_status: plan.status,
            contracts_total,
            contracts_enforced,
            contracts_deferred,
            contracts_blocked,
            user_release_blocks,
            production_blocks,
            signer_freshness_failures,
            rotation_failures,
            epoch_binding_failures,
            withdrawal_authorization_failures,
            contracts,
            roots,
        };
        let report_root = report.state_root();
        self.apply_report(report);
        Ok(report_root)
    }

    pub fn public_record(&self) -> Value {
        let history = self
            .report_history
            .iter()
            .map(VerificationContractReport::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "latest_report": self.latest_report.as_ref().map(VerificationContractReport::public_record),
            "report_history": history,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn apply_report(&mut self, report: VerificationContractReport) {
        self.counters.reports_run = self.counters.reports_run.saturating_add(1);
        match report.status {
            VerificationContractReportStatus::Passed => {
                self.counters.reports_passed = self.counters.reports_passed.saturating_add(1);
            }
            VerificationContractReportStatus::Watch => {
                self.counters.reports_watch = self.counters.reports_watch.saturating_add(1);
            }
            VerificationContractReportStatus::Failed => {
                self.counters.reports_failed = self.counters.reports_failed.saturating_add(1);
            }
        }
        self.counters.contracts_total = self
            .counters
            .contracts_total
            .saturating_add(report.contracts_total);
        self.counters.contracts_enforced = self
            .counters
            .contracts_enforced
            .saturating_add(report.contracts_enforced);
        self.counters.contracts_deferred = self
            .counters
            .contracts_deferred
            .saturating_add(report.contracts_deferred);
        self.counters.contracts_blocked = self
            .counters
            .contracts_blocked
            .saturating_add(report.contracts_blocked);
        self.counters.user_release_blocks = self
            .counters
            .user_release_blocks
            .saturating_add(report.user_release_blocks);
        self.counters.production_blocks = self
            .counters
            .production_blocks
            .saturating_add(report.production_blocks);
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_contracts {
            let keep_from = self.report_history.len() - self.config.max_contracts;
            self.report_history = self.report_history.split_off(keep_from);
        }
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTRACT-REPORT-HISTORY",
                &self
                    .report_history
                    .iter()
                    .map(VerificationContractReport::public_record)
                    .collect::<Vec<_>>(),
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

pub fn signer_freshness_root(
    release_claim_id: &str,
    observation_root: &str,
    authority_epoch: u64,
    current_authority_epoch: u64,
    pq_security_bits: u64,
    signer_fresh: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-SIGNER-FRESHNESS",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(observation_root),
            HashPart::U64(authority_epoch),
            HashPart::U64(current_authority_epoch),
            HashPart::U64(pq_security_bits),
            HashPart::Str(bool_str(signer_fresh)),
        ],
        32,
    )
}

pub fn rotation_continuity_root(
    response_root: &str,
    failure_root: &str,
    stale_rotations: u64,
    quarantine_required: u64,
    rotation_bound: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-ROTATION-CONTINUITY",
        &[
            HashPart::Str(response_root),
            HashPart::Str(failure_root),
            HashPart::U64(stale_rotations),
            HashPart::U64(quarantine_required),
            HashPart::Str(bool_str(rotation_bound)),
        ],
        32,
    )
}

pub fn epoch_binding_root(
    chain_id: &str,
    release_claim_id: &str,
    scenario_id: &str,
    authority_epoch: u64,
    current_authority_epoch: u64,
    epoch_bound: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-EPOCH-BINDING",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(scenario_id),
            HashPart::U64(authority_epoch),
            HashPart::U64(current_authority_epoch),
            HashPart::Str(bool_str(epoch_bound)),
        ],
        32,
    )
}

pub fn withdrawal_authorization_root(
    release_claim_id: &str,
    action_id: &str,
    release_holds_required: u64,
    action_blocks_user_release: bool,
    withdrawal_authorized: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-WITHDRAWAL-AUTHORIZATION",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(action_id),
            HashPart::U64(release_holds_required),
            HashPart::Str(bool_str(action_blocks_user_release)),
            HashPart::Str(bool_str(withdrawal_authorized)),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTRACT-RECORD",
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

fn build_contracts(
    config: &Config,
    report: &PqAuthorityKeyManagerReport,
    plan: &ReleaseRemediationPlan,
    actions: &[&RemediationAction],
) -> BTreeMap<String, VerificationContract> {
    VerificationContractKind::all()
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            let action = actions
                .get(index)
                .copied()
                .unwrap_or_else(|| fallback_action(plan, actions));
            VerificationContract::from_sources(config, report, action, *kind, index as u64)
        })
        .map(|contract| (contract.contract_id.clone(), contract))
        .collect()
}

fn pq_authority_actions(plan: &ReleaseRemediationPlan) -> Vec<&RemediationAction> {
    let mut actions = plan
        .actions
        .values()
        .filter(|action| {
            matches!(
                action.kind,
                RemediationActionKind::EnablePqAuthorityVerification
                    | RemediationActionKind::ClearProductionReleaseGate
                    | RemediationActionKind::EnableLiveSettlementExecution
            )
        })
        .collect::<Vec<_>>();
    if actions.len() < VerificationContractKind::all().len() {
        actions.extend(plan.actions.values());
    }
    actions.sort_by_key(|action| (action.priority_rank, action.action_id.clone()));
    actions.dedup_by(|left, right| left.action_id == right.action_id);
    actions
}

fn fallback_action<'a>(
    plan: &'a ReleaseRemediationPlan,
    actions: &[&'a RemediationAction],
) -> &'a RemediationAction {
    if let Some(action) = actions.first() {
        action
    } else if let Some(action) = plan.actions.values().next() {
        action
    } else {
        empty_action_reference()
    }
}

fn empty_action_reference() -> &'static RemediationAction {
    static EMPTY: std::sync::OnceLock<RemediationAction> = std::sync::OnceLock::new();
    EMPTY.get_or_init(|| RemediationAction {
        action_id: "empty-pq-authority-verification-action".to_string(),
        kind: RemediationActionKind::EnablePqAuthorityVerification,
        status: RemediationActionStatus::Blocked,
        severity: crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::RemediationSeverity::Critical,
        priority_rank: u64::MAX,
        release_claim_id: "empty-release-claim".to_string(),
        source_dimension: crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::ReleaseReadinessDimension::PqAuthority,
        source_status: crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::ReleaseReadinessStatus::Blocked,
        source_item_id: "empty-source-item".to_string(),
        source_readiness_root: "empty-source-readiness-root".to_string(),
        source_root: "empty-source-root".to_string(),
        owner_lane: "pq_authority_verification_contract".to_string(),
        objective: "materialize PQ authority verification contract source action".to_string(),
        acceptance_criteria: "planner supplies at least one PQ authority remediation action".to_string(),
        expected_unblock: "remediation action becomes available".to_string(),
        expected_next_status: crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::ReleaseReadinessStatus::Ready,
        retry_after_blocks: 0,
        manual_required: true,
        evidence_root: "empty-evidence-root".to_string(),
        dependency_root: "empty-dependency-root".to_string(),
        acceptance_root: "empty-acceptance-root".to_string(),
        action_root: "empty-action-root".to_string(),
        blocks_user_release: true,
        blocks_production: true,
    })
}

fn authority_epoch_for(config: &Config, report: &PqAuthorityKeyManagerReport, ordinal: u64) -> u64 {
    report
        .observations
        .values()
        .filter(|observation| observation.status != PqAuthorityObservationStatus::Rejected)
        .map(|observation| observation.authority_epoch)
        .min()
        .unwrap_or_else(|| config.current_authority_epoch.saturating_sub(ordinal))
}

#[allow(clippy::too_many_arguments)]
fn contract_status(
    config: &Config,
    kind: VerificationContractKind,
    report_status: PqAuthorityKeyManagerReportStatus,
    action_status: RemediationActionStatus,
    signer_fresh: bool,
    rotation_bound: bool,
    epoch_bound: bool,
    withdrawal_authorized: bool,
) -> VerificationContractStatus {
    let hard_failure = report_status == PqAuthorityKeyManagerReportStatus::Failed
        || action_status == RemediationActionStatus::Blocked;
    let condition_met = match kind {
        VerificationContractKind::SignerFreshness => signer_fresh,
        VerificationContractKind::RotationContinuity => rotation_bound,
        VerificationContractKind::EpochBinding => epoch_bound,
        VerificationContractKind::WithdrawalAuthorization => withdrawal_authorized,
    };
    if hard_failure || !condition_met {
        VerificationContractStatus::Blocked
    } else if config.allow_deferred_remediation_for_devnet
        && action_status == RemediationActionStatus::WaitingOnDeferredGate
    {
        VerificationContractStatus::Deferred
    } else {
        VerificationContractStatus::Enforced
    }
}

fn contract_text(
    kind: VerificationContractKind,
    signer_fresh: bool,
    rotation_bound: bool,
    epoch_bound: bool,
    withdrawal_authorized: bool,
) -> (String, String) {
    match kind {
        VerificationContractKind::SignerFreshness => (
            "PQ signer epoch must be inside the configured freshness window".to_string(),
            format!("signer_fresh={}", bool_str(signer_fresh)),
        ),
        VerificationContractKind::RotationContinuity => (
            "PQ authority rotation evidence must not require stale signer quarantine".to_string(),
            format!("rotation_bound={}", bool_str(rotation_bound)),
        ),
        VerificationContractKind::EpochBinding => (
            "verification transcript must bind authority epoch to release claim and chain".to_string(),
            format!("epoch_bound={}", bool_str(epoch_bound)),
        ),
        VerificationContractKind::WithdrawalAuthorization => (
            "withdrawal authorization must remain held unless control-plane remediation clears release blocks".to_string(),
            format!("withdrawal_authorized={}", bool_str(withdrawal_authorized)),
        ),
    }
}

fn report_status(
    contracts_blocked: u64,
    contracts_deferred: u64,
) -> VerificationContractReportStatus {
    if contracts_blocked > 0 {
        VerificationContractReportStatus::Failed
    } else if contracts_deferred > 0 {
        VerificationContractReportStatus::Watch
    } else {
        VerificationContractReportStatus::Passed
    }
}

fn remediation_contract_root(
    action_id: &str,
    kind: RemediationActionKind,
    status: RemediationActionStatus,
    action_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-REMEDIATION",
        &[
            HashPart::Str(action_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(action_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

fn verification_evidence_root(
    kind: VerificationContractKind,
    status: VerificationContractStatus,
    signer_root: &str,
    rotation_root: &str,
    epoch_binding_root: &str,
    withdrawal_authorization_root: &str,
    remediation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-EVIDENCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(signer_root),
            HashPart::Str(rotation_root),
            HashPart::Str(epoch_binding_root),
            HashPart::Str(withdrawal_authorization_root),
            HashPart::Str(remediation_root),
        ],
        32,
    )
}

fn verification_contract_root(
    kind: VerificationContractKind,
    status: VerificationContractStatus,
    release_claim_id: &str,
    report_id: &str,
    action_id: &str,
    evidence_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTRACT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(release_claim_id),
            HashPart::Str(report_id),
            HashPart::Str(action_id),
            HashPart::Str(evidence_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

fn source_root(
    key_manager_state_root: &str,
    key_manager_report_root: &str,
    remediation_state_root: &str,
    remediation_plan_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-SOURCE",
        &[
            HashPart::Str(key_manager_state_root),
            HashPart::Str(key_manager_report_root),
            HashPart::Str(remediation_state_root),
            HashPart::Str(remediation_plan_root),
        ],
        32,
    )
}

fn control_plane_root(
    contract_root: &str,
    key_manager_report_root: &str,
    remediation_plan_root: &str,
    contracts_total: u64,
    user_release_blocks: u64,
    production_blocks: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-CONTROL-PLANE",
        &[
            HashPart::Str(contract_root),
            HashPart::Str(key_manager_report_root),
            HashPart::Str(remediation_plan_root),
            HashPart::U64(contracts_total),
            HashPart::U64(user_release_blocks),
            HashPart::U64(production_blocks),
        ],
        32,
    )
}

fn report_root(
    status: VerificationContractReportStatus,
    source_root: &str,
    contract_root: &str,
    control_plane_root: &str,
    contracts_total: u64,
    contracts_blocked: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-PQ-AUTHORITY-VERIFICATION-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(contract_root),
            HashPart::Str(control_plane_root),
            HashPart::U64(contracts_total),
            HashPart::U64(contracts_blocked),
        ],
        32,
    )
}

fn verification_contract_id(
    kind: VerificationContractKind,
    release_claim_id: &str,
    contract_root: &str,
) -> String {
    format!(
        "pq-authority-verification-contract-{}-{}-{}",
        kind.as_str(),
        release_claim_id,
        short_hash(contract_root)
    )
}

fn verification_report_id(
    key_manager_report_id: &str,
    remediation_plan_id: &str,
    report_root: &str,
) -> String {
    format!(
        "pq-authority-verification-report-{}-{}-{}",
        key_manager_report_id,
        remediation_plan_id,
        short_hash(report_root)
    )
}

fn short_hash(root: &str) -> String {
    root.chars().take(16).collect()
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
