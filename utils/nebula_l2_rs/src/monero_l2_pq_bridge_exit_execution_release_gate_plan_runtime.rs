use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitExecutionReleaseGatePlanRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_EXECUTION_RELEASE_GATE_PLAN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-execution-release-gate-plan-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_EXECUTION_RELEASE_GATE_PLAN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PLAN_SUITE: &str = "monero-l2-pq-bridge-exit-execution-release-gate-plan-v1";
pub const DEFAULT_MIN_DRY_RUN_GATES: u64 = 8;
pub const DEFAULT_MIN_PASSING_GATES: u64 = 6;
pub const DEFAULT_MAX_WATCH_GATES: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MAX_PLANS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionGateDomain {
    DryRunExecutor,
    MoneroEvidencePolicy,
    ForcedWithdrawalAuthorization,
    PrivateTransferPrimitive,
    SettlementReceiptVerifier,
    AdversarialProofObligationLedger,
    WalletRecoveryDrill,
    PqAuthorityRotationDrill,
    LiquidityRunbook,
    PrivacyLeakRegression,
    SecurityAuditSignoff,
    CargoRuntimeExecution,
}

impl ExecutionGateDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRunExecutor => "dry_run_executor",
            Self::MoneroEvidencePolicy => "monero_evidence_policy",
            Self::ForcedWithdrawalAuthorization => "forced_withdrawal_authorization",
            Self::PrivateTransferPrimitive => "private_transfer_primitive",
            Self::SettlementReceiptVerifier => "settlement_receipt_verifier",
            Self::AdversarialProofObligationLedger => "adversarial_proof_obligation_ledger",
            Self::WalletRecoveryDrill => "wallet_recovery_drill",
            Self::PqAuthorityRotationDrill => "pq_authority_rotation_drill",
            Self::LiquidityRunbook => "liquidity_runbook",
            Self::PrivacyLeakRegression => "privacy_leak_regression",
            Self::SecurityAuditSignoff => "security_audit_signoff",
            Self::CargoRuntimeExecution => "cargo_runtime_execution",
        }
    }

    pub fn is_user_exit_critical(self) -> bool {
        matches!(
            self,
            Self::ForcedWithdrawalAuthorization
                | Self::SettlementReceiptVerifier
                | Self::WalletRecoveryDrill
                | Self::LiquidityRunbook
                | Self::MoneroEvidencePolicy
        )
    }

    pub fn is_production_critical(self) -> bool {
        matches!(
            self,
            Self::DryRunExecutor
                | Self::MoneroEvidencePolicy
                | Self::ForcedWithdrawalAuthorization
                | Self::PrivateTransferPrimitive
                | Self::SettlementReceiptVerifier
                | Self::AdversarialProofObligationLedger
                | Self::PqAuthorityRotationDrill
                | Self::PrivacyLeakRegression
                | Self::SecurityAuditSignoff
                | Self::CargoRuntimeExecution
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateEvidenceStatus {
    Present,
    Simulated,
    Missing,
    Deferred,
    Rejected,
}

impl GateEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Simulated => "simulated",
            Self::Missing => "missing",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_dry_run(self) -> bool {
        matches!(self, Self::Missing | Self::Rejected)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Simulated | Self::Missing | Self::Deferred | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionGateStatus {
    Pass,
    Watch,
    Blocked,
    Deferred,
}

impl ExecutionGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Deferred => "deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePlanStatus {
    DryRunReady,
    WatchOnly,
    Blocked,
}

impl ReleasePlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRunReady => "dry_run_ready",
            Self::WatchOnly => "watch_only",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlocker {
    CargoExecutionDeferred,
    NoBaseLayerVerifier,
    SimulatedLiquidityEvidence,
    SimulatedMoneroEvidence,
    MissingForcedExitDryRun,
    MissingPrivacyLeakExecution,
    MissingPqRotationExecution,
    MissingAuditSignoff,
}

impl ProductionBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoExecutionDeferred => "cargo_execution_deferred",
            Self::NoBaseLayerVerifier => "no_base_layer_verifier",
            Self::SimulatedLiquidityEvidence => "simulated_liquidity_evidence",
            Self::SimulatedMoneroEvidence => "simulated_monero_evidence",
            Self::MissingForcedExitDryRun => "missing_forced_exit_dry_run",
            Self::MissingPrivacyLeakExecution => "missing_privacy_leak_execution",
            Self::MissingPqRotationExecution => "missing_pq_rotation_execution",
            Self::MissingAuditSignoff => "missing_audit_signoff",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub plan_suite: String,
    pub min_dry_run_gates: u64,
    pub min_passing_gates: u64,
    pub max_watch_gates: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_plans: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            plan_suite: PLAN_SUITE.to_string(),
            min_dry_run_gates: DEFAULT_MIN_DRY_RUN_GATES,
            min_passing_gates: DEFAULT_MIN_PASSING_GATES,
            max_watch_gates: DEFAULT_MAX_WATCH_GATES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_plans: DEFAULT_MAX_PLANS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "plan_suite": self.plan_suite,
            "min_dry_run_gates": self.min_dry_run_gates,
            "min_passing_gates": self.min_passing_gates,
            "max_watch_gates": self.max_watch_gates,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_plans": self.max_plans,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionGateInput {
    pub domain: ExecutionGateDomain,
    pub evidence_status: GateEvidenceStatus,
    pub source_runtime: String,
    pub source_root: String,
    pub required_claim: String,
    pub observed_claim: String,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub cargo_execution_required: bool,
    pub user_exit_preserved: bool,
    pub production_blocker: Option<ProductionBlocker>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionGate {
    pub gate_id: String,
    pub domain: ExecutionGateDomain,
    pub evidence_status: GateEvidenceStatus,
    pub status: ExecutionGateStatus,
    pub source_runtime: String,
    pub source_root: String,
    pub required_claim: String,
    pub observed_claim: String,
    pub public_commitment_root: String,
    pub private_commitment_root: String,
    pub pq_control_root: String,
    pub wallet_scan_root: String,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub cargo_execution_required: bool,
    pub user_exit_preserved: bool,
    pub blocks_dry_run: bool,
    pub blocks_user_exit: bool,
    pub blocks_production: bool,
    pub production_blocker: Option<ProductionBlocker>,
    pub remediation: String,
    pub gate_root: String,
}

impl ExecutionGate {
    pub fn from_input(config: &Config, input: ExecutionGateInput) -> Self {
        let status = gate_status(config, &input);
        let blocks_dry_run =
            status == ExecutionGateStatus::Blocked || input.evidence_status.blocks_dry_run();
        let blocks_user_exit = input.domain.is_user_exit_critical() && !input.user_exit_preserved;
        let blocks_production = input.domain.is_production_critical()
            && (status != ExecutionGateStatus::Pass
                || input.evidence_status.blocks_production()
                || input.production_blocker.is_some()
                || config.cargo_checks_deferred);
        let public_commitment_root = public_commitment_root(
            input.domain,
            input.evidence_status,
            &input.source_runtime,
            &input.source_root,
            &input.required_claim,
        );
        let private_commitment_root = private_commitment_root(
            input.domain,
            &input.observed_claim,
            input.privacy_set_size,
            input.user_fee_bps,
        );
        let pq_control_root =
            pq_control_root(input.domain, &input.source_runtime, &input.source_root);
        let wallet_scan_root =
            wallet_scan_root(input.domain, input.privacy_set_size, &input.observed_claim);
        let gate_id = gate_id(
            input.domain,
            &public_commitment_root,
            &private_commitment_root,
        );
        let remediation = remediation_hint(input.domain, status, input.production_blocker);
        let public_record = json!({
            "gate_id": gate_id,
            "domain": input.domain.as_str(),
            "evidence_status": input.evidence_status.as_str(),
            "status": status.as_str(),
            "source_runtime": input.source_runtime,
            "source_root": input.source_root,
            "required_claim": input.required_claim,
            "observed_claim": input.observed_claim,
            "public_commitment_root": public_commitment_root,
            "private_commitment_root": private_commitment_root,
            "pq_control_root": pq_control_root,
            "wallet_scan_root": wallet_scan_root,
            "user_fee_bps": input.user_fee_bps,
            "privacy_set_size": input.privacy_set_size,
            "cargo_execution_required": input.cargo_execution_required,
            "user_exit_preserved": input.user_exit_preserved,
            "blocks_dry_run": blocks_dry_run,
            "blocks_user_exit": blocks_user_exit,
            "blocks_production": blocks_production,
            "production_blocker": input.production_blocker.map(ProductionBlocker::as_str),
            "remediation": remediation,
        });
        let gate_root = record_root("execution-gate", &public_record);

        Self {
            gate_id,
            domain: input.domain,
            evidence_status: input.evidence_status,
            status,
            source_runtime: input.source_runtime,
            source_root: input.source_root,
            required_claim: input.required_claim,
            observed_claim: input.observed_claim,
            public_commitment_root,
            private_commitment_root,
            pq_control_root,
            wallet_scan_root,
            user_fee_bps: input.user_fee_bps,
            privacy_set_size: input.privacy_set_size,
            cargo_execution_required: input.cargo_execution_required,
            user_exit_preserved: input.user_exit_preserved,
            blocks_dry_run,
            blocks_user_exit,
            blocks_production,
            production_blocker: input.production_blocker,
            remediation,
            gate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "domain": self.domain.as_str(),
            "evidence_status": self.evidence_status.as_str(),
            "status": self.status.as_str(),
            "source_runtime": self.source_runtime,
            "source_root": self.source_root,
            "required_claim": self.required_claim,
            "observed_claim": self.observed_claim,
            "public_commitment_root": self.public_commitment_root,
            "private_commitment_root": self.private_commitment_root,
            "pq_control_root": self.pq_control_root,
            "wallet_scan_root": self.wallet_scan_root,
            "user_fee_bps": self.user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "cargo_execution_required": self.cargo_execution_required,
            "user_exit_preserved": self.user_exit_preserved,
            "blocks_dry_run": self.blocks_dry_run,
            "blocks_user_exit": self.blocks_user_exit,
            "blocks_production": self.blocks_production,
            "production_blocker": self.production_blocker.map(ProductionBlocker::as_str),
            "remediation": self.remediation,
            "gate_root": self.gate_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PlanCounters {
    pub total_gates: u64,
    pub passing_gates: u64,
    pub watch_gates: u64,
    pub blocked_gates: u64,
    pub deferred_gates: u64,
    pub dry_run_blockers: u64,
    pub user_exit_blockers: u64,
    pub production_blockers: u64,
    pub cargo_execution_required: u64,
}

impl PlanCounters {
    pub fn from_gates(gates: &[ExecutionGate]) -> Self {
        let mut counters = Self {
            total_gates: gates.len() as u64,
            ..Self::default()
        };

        for gate in gates {
            match gate.status {
                ExecutionGateStatus::Pass => counters.passing_gates += 1,
                ExecutionGateStatus::Watch => counters.watch_gates += 1,
                ExecutionGateStatus::Blocked => counters.blocked_gates += 1,
                ExecutionGateStatus::Deferred => counters.deferred_gates += 1,
            }
            if gate.blocks_dry_run {
                counters.dry_run_blockers += 1;
            }
            if gate.blocks_user_exit {
                counters.user_exit_blockers += 1;
            }
            if gate.blocks_production {
                counters.production_blockers += 1;
            }
            if gate.cargo_execution_required {
                counters.cargo_execution_required += 1;
            }
        }

        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_gates": self.total_gates,
            "passing_gates": self.passing_gates,
            "watch_gates": self.watch_gates,
            "blocked_gates": self.blocked_gates,
            "deferred_gates": self.deferred_gates,
            "dry_run_blockers": self.dry_run_blockers,
            "user_exit_blockers": self.user_exit_blockers,
            "production_blockers": self.production_blockers,
            "cargo_execution_required": self.cargo_execution_required,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseGatePlan {
    pub plan_id: String,
    pub status: ReleasePlanStatus,
    pub dry_run_allowed: bool,
    pub production_release_allowed: bool,
    pub cargo_checks_deferred: bool,
    pub gates: Vec<ExecutionGate>,
    pub counters: PlanCounters,
    pub production_blockers: Vec<ProductionBlocker>,
    pub gate_root: String,
    pub counter_root: String,
    pub blocker_root: String,
    pub plan_root: String,
    pub operator_summary: String,
}

impl ReleaseGatePlan {
    pub fn new(config: &Config, gates: Vec<ExecutionGate>) -> Self {
        let counters = PlanCounters::from_gates(&gates);
        let production_blockers = production_blockers(config, &gates);
        let dry_run_allowed = counters.total_gates >= config.min_dry_run_gates
            && counters.passing_gates >= config.min_passing_gates
            && counters.watch_gates <= config.max_watch_gates
            && counters.dry_run_blockers == 0
            && counters.user_exit_blockers == 0;
        let production_release_allowed = dry_run_allowed
            && production_blockers.is_empty()
            && !config.cargo_checks_deferred
            && config.production_release_allowed;
        let status = if dry_run_allowed {
            ReleasePlanStatus::DryRunReady
        } else if counters.blocked_gates == 0 && counters.user_exit_blockers == 0 {
            ReleasePlanStatus::WatchOnly
        } else {
            ReleasePlanStatus::Blocked
        };
        let gate_root = gates_root(&gates);
        let counter_root = record_root("plan-counters", &counters.public_record());
        let blocker_root = blocker_root(&production_blockers);
        let plan_id = plan_id(&config.chain_id, status, &gate_root, &counter_root);
        let plan_root = domain_hash(
            "monero-l2-pq-bridge-exit-execution-release-plan-root",
            &[
                HashPart::Str(&plan_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&gate_root),
                HashPart::Str(&counter_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        let operator_summary = operator_summary(status, &counters, &production_blockers);

        Self {
            plan_id,
            status,
            dry_run_allowed,
            production_release_allowed,
            cargo_checks_deferred: config.cargo_checks_deferred,
            gates,
            counters,
            production_blockers,
            gate_root,
            counter_root,
            blocker_root,
            plan_root,
            operator_summary,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "status": self.status.as_str(),
            "dry_run_allowed": self.dry_run_allowed,
            "production_release_allowed": self.production_release_allowed,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "gates": self.gates.iter().map(ExecutionGate::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "production_blockers": self.production_blockers.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "gate_root": self.gate_root,
            "counter_root": self.counter_root,
            "blocker_root": self.blocker_root,
            "plan_root": self.plan_root,
            "operator_summary": self.operator_summary,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_plan: ReleaseGatePlan,
    pub plan_history: Vec<ReleaseGatePlan>,
}

impl State {
    pub fn new(config: Config, gates: Vec<ExecutionGate>) -> Self {
        let latest_plan = ReleaseGatePlan::new(&config, gates);
        Self {
            config,
            latest_plan: latest_plan.clone(),
            plan_history: vec![latest_plan],
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let gates = default_gates(&config);
        Self::new(config, gates)
    }

    pub fn ingest_gate(&mut self, gate: ExecutionGate) -> Result<String> {
        let mut gates = self.latest_plan.gates.clone();
        gates.retain(|item| item.domain != gate.domain);
        gates.push(gate);
        gates.sort_by_key(|item| item.domain);
        let plan = ReleaseGatePlan::new(&self.config, gates);
        let plan_id = plan.plan_id.clone();
        self.latest_plan = plan.clone();
        self.plan_history.push(plan);
        if self.plan_history.len() > self.config.max_plans {
            let overflow = self.plan_history.len() - self.config.max_plans;
            self.plan_history.drain(0..overflow);
        }
        Ok(plan_id)
    }

    pub fn gate_map(&self) -> BTreeMap<String, Value> {
        self.latest_plan
            .gates
            .iter()
            .map(|gate| (gate.domain.as_str().to_string(), gate.public_record()))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "latest_plan": self.latest_plan.public_record(),
            "plan_history_len": self.plan_history.len(),
            "gate_map": self.gate_map(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn default_gates(config: &Config) -> Vec<ExecutionGate> {
    default_gate_inputs()
        .into_iter()
        .map(|input| ExecutionGate::from_input(config, input))
        .collect()
}

pub fn default_gate_inputs() -> Vec<ExecutionGateInput> {
    vec![
        gate_input(
            ExecutionGateDomain::DryRunExecutor,
            GateEvidenceStatus::Simulated,
            "monero_l2_pq_bridge_exit_vertical_slice_dry_run_executor_runtime",
            "dry-run-executor-root",
            "full vertical slice executes deterministically",
            "executor plan exists but cargo/runtime result is deferred",
            22,
            96,
            true,
            true,
            Some(ProductionBlocker::CargoExecutionDeferred),
        ),
        gate_input(
            ExecutionGateDomain::MoneroEvidencePolicy,
            GateEvidenceStatus::Simulated,
            "monero_l2_pq_bridge_exit_monero_evidence_policy_runtime",
            "monero-evidence-policy-root",
            "lock, finality, reorg, and watcher evidence policy replaces a base-layer verifier",
            "policy is explicit but still carries no-base-layer-verifier residual risk",
            18,
            96,
            false,
            true,
            Some(ProductionBlocker::NoBaseLayerVerifier),
        ),
        gate_input(
            ExecutionGateDomain::ForcedWithdrawalAuthorization,
            GateEvidenceStatus::Present,
            "monero_l2_pq_bridge_exit_forced_withdrawal_authorization_runtime",
            "forced-withdrawal-authorization-root",
            "user-local evidence plus PQ quorum can authorize emergency exit",
            "authorization surface binds replay fences, nullifier fences, and denial reasons",
            20,
            96,
            false,
            true,
            None,
        ),
        gate_input(
            ExecutionGateDomain::PrivateTransferPrimitive,
            GateEvidenceStatus::Present,
            "monero_l2_pq_bridge_exit_private_transfer_minimal_primitive_runtime",
            "private-transfer-minimal-primitive-root",
            "one private transfer moves value without expanding DeFi scope",
            "note inputs, output commitments, encrypted receipts, fees, and forced-exit continuity are bound",
            18,
            128,
            false,
            true,
            None,
        ),
        gate_input(
            ExecutionGateDomain::SettlementReceiptVerifier,
            GateEvidenceStatus::Present,
            "monero_l2_pq_bridge_exit_settlement_receipt_verifier_runtime",
            "settlement-receipt-verifier-root",
            "settlement receipts bind private transfer output to exit claims",
            "receipt verifier defines release roots, dispute windows, encrypted wallet receipts, and denial causes",
            19,
            96,
            false,
            true,
            None,
        ),
        gate_input(
            ExecutionGateDomain::AdversarialProofObligationLedger,
            GateEvidenceStatus::Present,
            "monero_l2_pq_bridge_exit_adversarial_proof_obligation_ledger_runtime",
            "proof-obligation-ledger-root",
            "all adversarial cases have named proof obligations and missing-proof blockers",
            "ledger binds obligations for deposits, transfer, settlement, forced withdrawal, reorgs, liquidity, privacy, and PQ authority",
            18,
            96,
            false,
            true,
            None,
        ),
        gate_input(
            ExecutionGateDomain::WalletRecoveryDrill,
            GateEvidenceStatus::Present,
            "monero_l2_pq_bridge_exit_vertical_slice_wallet_recovery_drill_runtime",
            "wallet-recovery-drill-root",
            "wallet can reconstruct exit data from local encrypted receipt and scan material",
            "wallet recovery drill exists and preserves user exit continuity",
            18,
            128,
            false,
            true,
            None,
        ),
        gate_input(
            ExecutionGateDomain::PqAuthorityRotationDrill,
            GateEvidenceStatus::Simulated,
            "monero_l2_pq_bridge_exit_vertical_slice_pq_authority_rotation_drill_runtime",
            "pq-authority-rotation-drill-root",
            "PQ control-plane keys rotate under watcher quorum and rollback rules",
            "rotation drill exists but live execution evidence is deferred",
            18,
            96,
            true,
            true,
            Some(ProductionBlocker::MissingPqRotationExecution),
        ),
        gate_input(
            ExecutionGateDomain::LiquidityRunbook,
            GateEvidenceStatus::Simulated,
            "monero_l2_pq_bridge_exit_vertical_slice_liquidity_runbook_runtime",
            "liquidity-runbook-root",
            "liquidity exhaustion preserves partial settlement and escape continuity",
            "runbook exists but live reserve and backstop evidence are simulated",
            24,
            96,
            true,
            true,
            Some(ProductionBlocker::SimulatedLiquidityEvidence),
        ),
        gate_input(
            ExecutionGateDomain::PrivacyLeakRegression,
            GateEvidenceStatus::Simulated,
            "monero_l2_pq_bridge_exit_vertical_slice_privacy_leak_regression_runtime",
            "privacy-leak-regression-root",
            "timing, amount, scan-hint, receipt, and forced-exit disclosures stay within budget",
            "privacy regression exists but execution is deferred",
            18,
            96,
            true,
            true,
            Some(ProductionBlocker::MissingPrivacyLeakExecution),
        ),
        gate_input(
            ExecutionGateDomain::SecurityAuditSignoff,
            GateEvidenceStatus::Deferred,
            "monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime",
            "security-audit-signoff-root",
            "human security and privacy signoff must approve the executed vertical slice",
            "signoff remains deferred until runtime execution roots exist",
            18,
            96,
            true,
            true,
            Some(ProductionBlocker::MissingAuditSignoff),
        ),
        gate_input(
            ExecutionGateDomain::CargoRuntimeExecution,
            GateEvidenceStatus::Deferred,
            "monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime",
            "cargo-runtime-execution-root",
            "cargo/runtime gates must execute the bridge-exit vertical slice",
            "cargo checks are intentionally deferred by workflow",
            18,
            96,
            true,
            true,
            Some(ProductionBlocker::CargoExecutionDeferred),
        ),
    ]
}

pub fn gate_input(
    domain: ExecutionGateDomain,
    evidence_status: GateEvidenceStatus,
    source_runtime: &str,
    source_root: &str,
    required_claim: &str,
    observed_claim: &str,
    user_fee_bps: u64,
    privacy_set_size: u64,
    cargo_execution_required: bool,
    user_exit_preserved: bool,
    production_blocker: Option<ProductionBlocker>,
) -> ExecutionGateInput {
    ExecutionGateInput {
        domain,
        evidence_status,
        source_runtime: source_runtime.to_string(),
        source_root: source_root.to_string(),
        required_claim: required_claim.to_string(),
        observed_claim: observed_claim.to_string(),
        user_fee_bps,
        privacy_set_size,
        cargo_execution_required,
        user_exit_preserved,
        production_blocker,
    }
}

pub fn gate_status(config: &Config, input: &ExecutionGateInput) -> ExecutionGateStatus {
    if input.evidence_status == GateEvidenceStatus::Deferred {
        return ExecutionGateStatus::Deferred;
    }
    if input.evidence_status.blocks_dry_run()
        || input.user_fee_bps > config.max_user_fee_bps
        || input.privacy_set_size < config.min_privacy_set_size
        || (input.domain.is_user_exit_critical() && !input.user_exit_preserved)
    {
        return ExecutionGateStatus::Blocked;
    }
    if input.evidence_status == GateEvidenceStatus::Simulated || input.production_blocker.is_some()
    {
        return ExecutionGateStatus::Watch;
    }
    ExecutionGateStatus::Pass
}

pub fn production_blockers(config: &Config, gates: &[ExecutionGate]) -> Vec<ProductionBlocker> {
    let mut blockers = BTreeMap::<String, ProductionBlocker>::new();

    if config.cargo_checks_deferred {
        blockers.insert(
            ProductionBlocker::CargoExecutionDeferred
                .as_str()
                .to_string(),
            ProductionBlocker::CargoExecutionDeferred,
        );
    }
    if !config.production_release_allowed {
        blockers.insert(
            ProductionBlocker::MissingAuditSignoff.as_str().to_string(),
            ProductionBlocker::MissingAuditSignoff,
        );
    }

    for gate in gates {
        if let Some(blocker) = gate.production_blocker {
            blockers.insert(blocker.as_str().to_string(), blocker);
        }
        if gate.domain == ExecutionGateDomain::MoneroEvidencePolicy
            && gate.status != ExecutionGateStatus::Pass
        {
            blockers.insert(
                ProductionBlocker::NoBaseLayerVerifier.as_str().to_string(),
                ProductionBlocker::NoBaseLayerVerifier,
            );
        }
        if gate.domain == ExecutionGateDomain::LiquidityRunbook
            && gate.status != ExecutionGateStatus::Pass
        {
            blockers.insert(
                ProductionBlocker::SimulatedLiquidityEvidence
                    .as_str()
                    .to_string(),
                ProductionBlocker::SimulatedLiquidityEvidence,
            );
        }
        if gate.domain == ExecutionGateDomain::PrivacyLeakRegression
            && gate.status != ExecutionGateStatus::Pass
        {
            blockers.insert(
                ProductionBlocker::MissingPrivacyLeakExecution
                    .as_str()
                    .to_string(),
                ProductionBlocker::MissingPrivacyLeakExecution,
            );
        }
        if gate.blocks_user_exit {
            blockers.insert(
                ProductionBlocker::MissingForcedExitDryRun
                    .as_str()
                    .to_string(),
                ProductionBlocker::MissingForcedExitDryRun,
            );
        }
    }

    blockers.into_values().collect()
}

pub fn public_commitment_root(
    domain: ExecutionGateDomain,
    evidence_status: GateEvidenceStatus,
    source_runtime: &str,
    source_root: &str,
    required_claim: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-execution-gate-public-commitment",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(evidence_status.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_root),
            HashPart::Str(required_claim),
        ],
        32,
    )
}

pub fn private_commitment_root(
    domain: ExecutionGateDomain,
    observed_claim: &str,
    privacy_set_size: u64,
    user_fee_bps: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-execution-gate-private-commitment",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(observed_claim),
            HashPart::U64(privacy_set_size),
            HashPart::U64(user_fee_bps),
        ],
        32,
    )
}

pub fn pq_control_root(
    domain: ExecutionGateDomain,
    source_runtime: &str,
    source_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-execution-gate-pq-control",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_root),
            HashPart::Str("hybrid-ml-dsa-slh-dsa-release-control"),
        ],
        32,
    )
}

pub fn wallet_scan_root(
    domain: ExecutionGateDomain,
    privacy_set_size: u64,
    observed_claim: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-execution-gate-wallet-scan",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::U64(privacy_set_size),
            HashPart::Str(observed_claim),
        ],
        32,
    )
}

pub fn gate_id(
    domain: ExecutionGateDomain,
    public_commitment_root: &str,
    private_commitment_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-execution-gate-id",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(public_commitment_root),
            HashPart::Str(private_commitment_root),
        ],
        16,
    )
}

pub fn plan_id(
    chain_id: &str,
    status: ReleasePlanStatus,
    gate_root: &str,
    counter_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-execution-release-plan-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(gate_root),
            HashPart::Str(counter_root),
        ],
        16,
    )
}

pub fn gates_root(gates: &[ExecutionGate]) -> String {
    let leaves = gates
        .iter()
        .map(|gate| gate.gate_root.clone())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-execution-release-gates",
        leaves.as_slice(),
    )
}

pub fn blocker_root(blockers: &[ProductionBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| blocker.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-execution-release-blockers",
        leaves.as_slice(),
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-execution-release-gate-plan-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn remediation_hint(
    domain: ExecutionGateDomain,
    status: ExecutionGateStatus,
    blocker: Option<ProductionBlocker>,
) -> String {
    if status == ExecutionGateStatus::Pass {
        return format!(
            "{} gate is ready for the next release-plan stage",
            domain.as_str()
        );
    }

    match blocker {
        Some(ProductionBlocker::CargoExecutionDeferred) => {
            "resume cargo/runtime execution and bind the dry-run result root into this gate"
        }
        Some(ProductionBlocker::NoBaseLayerVerifier) => {
            "keep production blocked until Monero evidence policy replaces base-layer verifier assumptions"
        }
        Some(ProductionBlocker::SimulatedLiquidityEvidence) => {
            "replace simulated reserve/backstop evidence with live or reproducible liquidity evidence"
        }
        Some(ProductionBlocker::SimulatedMoneroEvidence) => {
            "replace simulated Monero lock/finality/reorg evidence with reproducible policy fixtures"
        }
        Some(ProductionBlocker::MissingForcedExitDryRun) => {
            "execute a forced-withdrawal dry run from user-local evidence"
        }
        Some(ProductionBlocker::MissingPrivacyLeakExecution) => {
            "execute privacy leak regression and bind metadata-budget roots"
        }
        Some(ProductionBlocker::MissingPqRotationExecution) => {
            "execute PQ authority rotation with rollback and quarantine evidence"
        }
        Some(ProductionBlocker::MissingAuditSignoff) => {
            "collect security and privacy signoff after execution roots exist"
        }
        None => "replace simulated or deferred evidence with a passing runtime root",
    }
    .to_string()
}

pub fn operator_summary(
    status: ReleasePlanStatus,
    counters: &PlanCounters,
    blockers: &[ProductionBlocker],
) -> String {
    let blocker_labels = blockers
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "status={} gates={} pass={} watch={} blocked={} deferred={} dry_run_blockers={} production_blockers=[{}]",
        status.as_str(),
        counters.total_gates,
        counters.passing_gates,
        counters.watch_gates,
        counters.blocked_gates,
        counters.deferred_gates,
        counters.dry_run_blockers,
        blocker_labels
    )
}
