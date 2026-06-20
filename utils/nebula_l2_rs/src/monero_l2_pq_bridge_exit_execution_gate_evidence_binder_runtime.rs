use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitExecutionGateEvidenceBinderRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_EXECUTION_GATE_EVIDENCE_BINDER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-execution-gate-evidence-binder-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_EXECUTION_GATE_EVIDENCE_BINDER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BINDER_SUITE: &str = "monero-l2-pq-bridge-exit-execution-gate-evidence-binder-v1";
pub const DEFAULT_MIN_BINDINGS: u64 = 9;
pub const DEFAULT_MIN_PASSING_BINDINGS: u64 = 6;
pub const DEFAULT_MAX_WATCH_BINDINGS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MAX_REPORTS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderDomain {
    DryRunFixtureResult,
    MoneroEvidenceNegativeFixture,
    ForcedWithdrawalFixtureReplay,
    PrivateTransferReceiptFixture,
    SettlementExitClaimFixture,
    ProofObligationFixtureCoverage,
    ExecutionReleaseGatePlan,
    WalletRecoveryDrill,
    PqAuthorityRotationDrill,
    PrivacyLeakRegression,
    LiquidityRunbook,
    SecurityAuditSignoff,
}

impl BinderDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRunFixtureResult => "dry_run_fixture_result",
            Self::MoneroEvidenceNegativeFixture => "monero_evidence_negative_fixture",
            Self::ForcedWithdrawalFixtureReplay => "forced_withdrawal_fixture_replay",
            Self::PrivateTransferReceiptFixture => "private_transfer_receipt_fixture",
            Self::SettlementExitClaimFixture => "settlement_exit_claim_fixture",
            Self::ProofObligationFixtureCoverage => "proof_obligation_fixture_coverage",
            Self::ExecutionReleaseGatePlan => "execution_release_gate_plan",
            Self::WalletRecoveryDrill => "wallet_recovery_drill",
            Self::PqAuthorityRotationDrill => "pq_authority_rotation_drill",
            Self::PrivacyLeakRegression => "privacy_leak_regression",
            Self::LiquidityRunbook => "liquidity_runbook",
            Self::SecurityAuditSignoff => "security_audit_signoff",
        }
    }

    pub fn is_user_exit_critical(self) -> bool {
        matches!(
            self,
            Self::ForcedWithdrawalFixtureReplay
                | Self::SettlementExitClaimFixture
                | Self::WalletRecoveryDrill
                | Self::LiquidityRunbook
                | Self::MoneroEvidenceNegativeFixture
        )
    }

    pub fn is_production_critical(self) -> bool {
        matches!(
            self,
            Self::DryRunFixtureResult
                | Self::MoneroEvidenceNegativeFixture
                | Self::ForcedWithdrawalFixtureReplay
                | Self::PrivateTransferReceiptFixture
                | Self::SettlementExitClaimFixture
                | Self::ProofObligationFixtureCoverage
                | Self::ExecutionReleaseGatePlan
                | Self::PqAuthorityRotationDrill
                | Self::PrivacyLeakRegression
                | Self::SecurityAuditSignoff
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBindingStatus {
    Bound,
    Watch,
    Missing,
    Rejected,
    Deferred,
}

impl EvidenceBindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Watch => "watch",
            Self::Missing => "missing",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
        }
    }

    pub fn blocks_dry_run(self) -> bool {
        matches!(self, Self::Missing | Self::Rejected)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Missing | Self::Rejected | Self::Deferred
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BinderGateStatus {
    Pass,
    Watch,
    Blocked,
    Deferred,
}

impl BinderGateStatus {
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
pub enum BinderReportStatus {
    DryRunEvidenceReady,
    WatchOnly,
    Blocked,
}

impl BinderReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DryRunEvidenceReady => "dry_run_evidence_ready",
            Self::WatchOnly => "watch_only",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlockerKind {
    CargoExecutionDeferred,
    NoBaseLayerVerifier,
    MissingDryRunFixture,
    MissingForcedWithdrawalReplay,
    MissingSettlementExitClaimFixture,
    MissingPrivacyLeakExecution,
    MissingPqRotationExecution,
    SimulatedLiquidityEvidence,
    MissingAuditSignoff,
}

impl ProductionBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoExecutionDeferred => "cargo_execution_deferred",
            Self::NoBaseLayerVerifier => "no_base_layer_verifier",
            Self::MissingDryRunFixture => "missing_dry_run_fixture",
            Self::MissingForcedWithdrawalReplay => "missing_forced_withdrawal_replay",
            Self::MissingSettlementExitClaimFixture => "missing_settlement_exit_claim_fixture",
            Self::MissingPrivacyLeakExecution => "missing_privacy_leak_execution",
            Self::MissingPqRotationExecution => "missing_pq_rotation_execution",
            Self::SimulatedLiquidityEvidence => "simulated_liquidity_evidence",
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
    pub binder_suite: String,
    pub min_bindings: u64,
    pub min_passing_bindings: u64,
    pub max_watch_bindings: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub cargo_checks_deferred: bool,
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
            binder_suite: BINDER_SUITE.to_string(),
            min_bindings: DEFAULT_MIN_BINDINGS,
            min_passing_bindings: DEFAULT_MIN_PASSING_BINDINGS,
            max_watch_bindings: DEFAULT_MAX_WATCH_BINDINGS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            cargo_checks_deferred: true,
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
            "binder_suite": self.binder_suite,
            "min_bindings": self.min_bindings,
            "min_passing_bindings": self.min_passing_bindings,
            "max_watch_bindings": self.max_watch_bindings,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceBindingInput {
    pub domain: BinderDomain,
    pub status: EvidenceBindingStatus,
    pub source_runtime: String,
    pub fixture_root: String,
    pub release_gate_root: String,
    pub required_claim: String,
    pub observed_claim: String,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub cargo_execution_required: bool,
    pub user_exit_preserved: bool,
    pub production_blocker: Option<ProductionBlockerKind>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceBinding {
    pub binding_id: String,
    pub domain: BinderDomain,
    pub status: EvidenceBindingStatus,
    pub gate_status: BinderGateStatus,
    pub source_runtime: String,
    pub fixture_root: String,
    pub release_gate_root: String,
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
    pub production_blocker: Option<ProductionBlockerKind>,
    pub remediation: String,
    pub binding_root: String,
}

impl EvidenceBinding {
    pub fn from_input(config: &Config, input: EvidenceBindingInput) -> Self {
        let gate_status = gate_status(config, &input);
        let blocks_dry_run =
            gate_status == BinderGateStatus::Blocked || input.status.blocks_dry_run();
        let blocks_user_exit = input.domain.is_user_exit_critical() && !input.user_exit_preserved;
        let blocks_production = input.domain.is_production_critical()
            && (gate_status != BinderGateStatus::Pass
                || input.status.blocks_production()
                || input.production_blocker.is_some()
                || config.cargo_checks_deferred);
        let public_commitment_root = public_commitment_root(
            input.domain,
            input.status,
            &input.source_runtime,
            &input.fixture_root,
            &input.release_gate_root,
        );
        let private_commitment_root = private_commitment_root(
            input.domain,
            &input.observed_claim,
            input.privacy_set_size,
            input.user_fee_bps,
        );
        let pq_control_root =
            pq_control_root(input.domain, &input.source_runtime, &input.fixture_root);
        let wallet_scan_root =
            wallet_scan_root(input.domain, &input.observed_claim, input.privacy_set_size);
        let binding_id = binding_id(
            input.domain,
            &public_commitment_root,
            &private_commitment_root,
            &input.release_gate_root,
        );
        let remediation = remediation_hint(input.domain, gate_status, input.production_blocker);
        let public_record = json!({
            "binding_id": binding_id,
            "domain": input.domain.as_str(),
            "status": input.status.as_str(),
            "gate_status": gate_status.as_str(),
            "source_runtime": input.source_runtime,
            "fixture_root": input.fixture_root,
            "release_gate_root": input.release_gate_root,
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
            "production_blocker": input.production_blocker.map(ProductionBlockerKind::as_str),
            "remediation": remediation,
        });
        let binding_root = record_root("evidence-binding", &public_record);

        Self {
            binding_id,
            domain: input.domain,
            status: input.status,
            gate_status,
            source_runtime: input.source_runtime,
            fixture_root: input.fixture_root,
            release_gate_root: input.release_gate_root,
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
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "gate_status": self.gate_status.as_str(),
            "source_runtime": self.source_runtime,
            "fixture_root": self.fixture_root,
            "release_gate_root": self.release_gate_root,
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
            "production_blocker": self.production_blocker.map(ProductionBlockerKind::as_str),
            "remediation": self.remediation,
            "binding_root": self.binding_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct BinderCounters {
    pub total_bindings: u64,
    pub passing_bindings: u64,
    pub watch_bindings: u64,
    pub blocked_bindings: u64,
    pub deferred_bindings: u64,
    pub dry_run_blockers: u64,
    pub user_exit_blockers: u64,
    pub production_blockers: u64,
    pub cargo_execution_required: u64,
}

impl BinderCounters {
    pub fn from_bindings(bindings: &[EvidenceBinding]) -> Self {
        let mut counters = Self {
            total_bindings: bindings.len() as u64,
            ..Self::default()
        };

        for binding in bindings {
            match binding.gate_status {
                BinderGateStatus::Pass => counters.passing_bindings += 1,
                BinderGateStatus::Watch => counters.watch_bindings += 1,
                BinderGateStatus::Blocked => counters.blocked_bindings += 1,
                BinderGateStatus::Deferred => counters.deferred_bindings += 1,
            }
            if binding.blocks_dry_run {
                counters.dry_run_blockers += 1;
            }
            if binding.blocks_user_exit {
                counters.user_exit_blockers += 1;
            }
            if binding.blocks_production {
                counters.production_blockers += 1;
            }
            if binding.cargo_execution_required {
                counters.cargo_execution_required += 1;
            }
        }

        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_bindings": self.total_bindings,
            "passing_bindings": self.passing_bindings,
            "watch_bindings": self.watch_bindings,
            "blocked_bindings": self.blocked_bindings,
            "deferred_bindings": self.deferred_bindings,
            "dry_run_blockers": self.dry_run_blockers,
            "user_exit_blockers": self.user_exit_blockers,
            "production_blockers": self.production_blockers,
            "cargo_execution_required": self.cargo_execution_required,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BinderReport {
    pub report_id: String,
    pub status: BinderReportStatus,
    pub dry_run_evidence_ready: bool,
    pub production_release_allowed: bool,
    pub cargo_checks_deferred: bool,
    pub bindings: Vec<EvidenceBinding>,
    pub counters: BinderCounters,
    pub production_blockers: Vec<ProductionBlockerKind>,
    pub binding_root: String,
    pub counter_root: String,
    pub blocker_root: String,
    pub report_root: String,
    pub operator_summary: String,
}

impl BinderReport {
    pub fn new(config: &Config, bindings: Vec<EvidenceBinding>) -> Self {
        let counters = BinderCounters::from_bindings(&bindings);
        let production_blockers = production_blockers(config, &bindings);
        let dry_run_evidence_ready = counters.total_bindings >= config.min_bindings
            && counters.passing_bindings >= config.min_passing_bindings
            && counters.watch_bindings <= config.max_watch_bindings
            && counters.dry_run_blockers == 0
            && counters.user_exit_blockers == 0;
        let production_release_allowed = dry_run_evidence_ready
            && production_blockers.is_empty()
            && !config.cargo_checks_deferred
            && config.production_release_allowed;
        let status = if dry_run_evidence_ready {
            BinderReportStatus::DryRunEvidenceReady
        } else if counters.blocked_bindings == 0 && counters.user_exit_blockers == 0 {
            BinderReportStatus::WatchOnly
        } else {
            BinderReportStatus::Blocked
        };
        let binding_root = bindings_root(&bindings);
        let counter_root = record_root("binder-counters", &counters.public_record());
        let blocker_root = blocker_root(&production_blockers);
        let report_id = report_id(&config.chain_id, status, &binding_root, &counter_root);
        let report_root = domain_hash(
            "monero-l2-pq-bridge-exit-evidence-binder-report-root",
            &[
                HashPart::Str(&report_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&binding_root),
                HashPart::Str(&counter_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        let operator_summary = operator_summary(status, &counters, &production_blockers);

        Self {
            report_id,
            status,
            dry_run_evidence_ready,
            production_release_allowed,
            cargo_checks_deferred: config.cargo_checks_deferred,
            bindings,
            counters,
            production_blockers,
            binding_root,
            counter_root,
            blocker_root,
            report_root,
            operator_summary,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "dry_run_evidence_ready": self.dry_run_evidence_ready,
            "production_release_allowed": self.production_release_allowed,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "bindings": self.bindings.iter().map(EvidenceBinding::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "production_blockers": self.production_blockers.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "binding_root": self.binding_root,
            "counter_root": self.counter_root,
            "blocker_root": self.blocker_root,
            "report_root": self.report_root,
            "operator_summary": self.operator_summary,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_report: BinderReport,
    pub report_history: Vec<BinderReport>,
}

impl State {
    pub fn new(config: Config, bindings: Vec<EvidenceBinding>) -> Self {
        let latest_report = BinderReport::new(&config, bindings);
        Self {
            config,
            latest_report: latest_report.clone(),
            report_history: vec![latest_report],
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let bindings = default_bindings(&config);
        Self::new(config, bindings)
    }

    pub fn ingest_binding(&mut self, binding: EvidenceBinding) -> Result<String> {
        let mut bindings = self.latest_report.bindings.clone();
        bindings.retain(|item| item.domain != binding.domain);
        bindings.push(binding);
        bindings.sort_by_key(|item| item.domain);
        let report = BinderReport::new(&self.config, bindings);
        let report_id = report.report_id.clone();
        self.latest_report = report.clone();
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_reports {
            let overflow = self.report_history.len() - self.config.max_reports;
            self.report_history.drain(0..overflow);
        }
        Ok(report_id)
    }

    pub fn binding_map(&self) -> BTreeMap<String, Value> {
        self.latest_report
            .bindings
            .iter()
            .map(|binding| (binding.domain.as_str().to_string(), binding.public_record()))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "latest_report": self.latest_report.public_record(),
            "report_history_len": self.report_history.len(),
            "binding_map": self.binding_map(),
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

pub fn default_bindings(config: &Config) -> Vec<EvidenceBinding> {
    default_binding_inputs()
        .into_iter()
        .map(|input| EvidenceBinding::from_input(config, input))
        .collect()
}

pub fn default_binding_inputs() -> Vec<EvidenceBindingInput> {
    vec![
        binding_input(
            BinderDomain::DryRunFixtureResult,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_dry_run_fixture_result_runtime",
            "dry-run-fixture-result-root",
            "execution-release-gate-plan-root",
            "dry-run fixture covers deposit/private-note/transfer/settlement/forced-exit path",
            "fixture roots bind all five vertical-slice stages with low-fee and privacy checks",
            22,
            96,
            true,
            true,
            Some(ProductionBlockerKind::CargoExecutionDeferred),
        ),
        binding_input(
            BinderDomain::MoneroEvidenceNegativeFixture,
            EvidenceBindingStatus::Watch,
            "monero_l2_pq_bridge_exit_monero_evidence_negative_fixture_runtime",
            "monero-negative-fixture-root",
            "monero-evidence-policy-gate-root",
            "negative lock/finality/reorg/watcher cases are explicit",
            "fixtures reject invalid confirmations and watcher equivocation but retain no-base-layer-verifier risk",
            18,
            96,
            false,
            true,
            Some(ProductionBlockerKind::NoBaseLayerVerifier),
        ),
        binding_input(
            BinderDomain::ForcedWithdrawalFixtureReplay,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_forced_withdrawal_fixture_replay_runtime",
            "forced-withdrawal-fixture-replay-root",
            "forced-withdrawal-authorization-gate-root",
            "user-local replay reconstructs emergency authorization and exit package roots",
            "replay binds PQ quorum, replay fence, nullifier fence, denial cases, and exit package roots",
            20,
            96,
            true,
            true,
            None,
        ),
        binding_input(
            BinderDomain::PrivateTransferReceiptFixture,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_private_transfer_receipt_fixture_runtime",
            "private-transfer-receipt-fixture-root",
            "private-transfer-minimal-primitive-gate-root",
            "minimal private transfer receipt preserves note, nullifier, wallet, and fee continuity",
            "fixture roots bind input/output notes, encrypted receipts, scan hints, fee cap, and forced-exit link",
            18,
            128,
            false,
            true,
            None,
        ),
        binding_input(
            BinderDomain::SettlementExitClaimFixture,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_settlement_exit_claim_fixture_runtime",
            "settlement-exit-claim-fixture-root",
            "settlement-receipt-verifier-gate-root",
            "settlement receipt verifier binds private output to exit claim",
            "fixture roots bind release authorization, dispute windows, encrypted receipt, fee cap, and denial cases",
            19,
            96,
            false,
            true,
            None,
        ),
        binding_input(
            BinderDomain::ProofObligationFixtureCoverage,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_proof_obligation_fixture_coverage_runtime",
            "proof-obligation-fixture-coverage-root",
            "adversarial-proof-obligation-ledger-root",
            "adversarial proof obligations have fixture-backed evidence roots",
            "coverage binds deposit, transfer, settlement, forced withdrawal, reorg, liquidity, privacy, and PQ obligations",
            18,
            96,
            false,
            true,
            None,
        ),
        binding_input(
            BinderDomain::ExecutionReleaseGatePlan,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_execution_release_gate_plan_runtime",
            "execution-release-gate-plan-fixture-root",
            "execution-release-gate-plan-root",
            "release plan consumes fixture-backed evidence roots",
            "binder links fixture roots into dry-run, production-blocker, cargo, privacy, PQ, and audit gates",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::CargoExecutionDeferred),
        ),
        binding_input(
            BinderDomain::WalletRecoveryDrill,
            EvidenceBindingStatus::Bound,
            "monero_l2_pq_bridge_exit_vertical_slice_wallet_recovery_drill_runtime",
            "wallet-recovery-drill-root",
            "wallet-recovery-gate-root",
            "wallet can reconstruct encrypted receipt and forced-exit data",
            "wallet recovery drill remains bound as user-exit continuity evidence",
            18,
            128,
            false,
            true,
            None,
        ),
        binding_input(
            BinderDomain::PqAuthorityRotationDrill,
            EvidenceBindingStatus::Watch,
            "monero_l2_pq_bridge_exit_vertical_slice_pq_authority_rotation_drill_runtime",
            "pq-authority-rotation-drill-root",
            "pq-authority-rotation-gate-root",
            "PQ authority rotation drill covers bridge release and emergency withdrawal control",
            "rotation evidence remains fixture-backed until heavy runtime execution resumes",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::MissingPqRotationExecution),
        ),
        binding_input(
            BinderDomain::PrivacyLeakRegression,
            EvidenceBindingStatus::Watch,
            "monero_l2_pq_bridge_exit_vertical_slice_privacy_leak_regression_runtime",
            "privacy-leak-regression-root",
            "privacy-leak-regression-gate-root",
            "privacy leak regression covers timing, amount, scan hint, receipt, and forced-exit leakage",
            "privacy regression remains fixture-backed until execution results are available",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::MissingPrivacyLeakExecution),
        ),
        binding_input(
            BinderDomain::LiquidityRunbook,
            EvidenceBindingStatus::Watch,
            "monero_l2_pq_bridge_exit_vertical_slice_liquidity_runbook_runtime",
            "liquidity-runbook-root",
            "liquidity-runbook-gate-root",
            "liquidity exhaustion preserves partial settlement and escape continuity",
            "reserve/backstop evidence remains simulated and blocks production",
            24,
            96,
            true,
            true,
            Some(ProductionBlockerKind::SimulatedLiquidityEvidence),
        ),
        binding_input(
            BinderDomain::SecurityAuditSignoff,
            EvidenceBindingStatus::Deferred,
            "monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime",
            "security-audit-signoff-root",
            "security-audit-signoff-gate-root",
            "human security and privacy signoff approves executed fixture results",
            "signoff remains deferred until cargo/runtime execution roots exist",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::MissingAuditSignoff),
        ),
    ]
}

pub fn binding_input(
    domain: BinderDomain,
    status: EvidenceBindingStatus,
    source_runtime: &str,
    fixture_root: &str,
    release_gate_root: &str,
    required_claim: &str,
    observed_claim: &str,
    user_fee_bps: u64,
    privacy_set_size: u64,
    cargo_execution_required: bool,
    user_exit_preserved: bool,
    production_blocker: Option<ProductionBlockerKind>,
) -> EvidenceBindingInput {
    EvidenceBindingInput {
        domain,
        status,
        source_runtime: source_runtime.to_string(),
        fixture_root: fixture_root.to_string(),
        release_gate_root: release_gate_root.to_string(),
        required_claim: required_claim.to_string(),
        observed_claim: observed_claim.to_string(),
        user_fee_bps,
        privacy_set_size,
        cargo_execution_required,
        user_exit_preserved,
        production_blocker,
    }
}

pub fn gate_status(config: &Config, input: &EvidenceBindingInput) -> BinderGateStatus {
    if input.status == EvidenceBindingStatus::Deferred {
        return BinderGateStatus::Deferred;
    }
    if input.status.blocks_dry_run()
        || input.user_fee_bps > config.max_user_fee_bps
        || input.privacy_set_size < config.min_privacy_set_size
        || (input.domain.is_user_exit_critical() && !input.user_exit_preserved)
    {
        return BinderGateStatus::Blocked;
    }
    if input.status == EvidenceBindingStatus::Watch || input.production_blocker.is_some() {
        return BinderGateStatus::Watch;
    }
    BinderGateStatus::Pass
}

pub fn production_blockers(
    config: &Config,
    bindings: &[EvidenceBinding],
) -> Vec<ProductionBlockerKind> {
    let mut blockers = BTreeMap::<String, ProductionBlockerKind>::new();

    if config.cargo_checks_deferred {
        blockers.insert(
            ProductionBlockerKind::CargoExecutionDeferred
                .as_str()
                .to_string(),
            ProductionBlockerKind::CargoExecutionDeferred,
        );
    }
    if !config.production_release_allowed {
        blockers.insert(
            ProductionBlockerKind::MissingAuditSignoff
                .as_str()
                .to_string(),
            ProductionBlockerKind::MissingAuditSignoff,
        );
    }

    for binding in bindings {
        if let Some(blocker) = binding.production_blocker {
            blockers.insert(blocker.as_str().to_string(), blocker);
        }
        if binding.domain == BinderDomain::MoneroEvidenceNegativeFixture
            && binding.gate_status != BinderGateStatus::Pass
        {
            blockers.insert(
                ProductionBlockerKind::NoBaseLayerVerifier
                    .as_str()
                    .to_string(),
                ProductionBlockerKind::NoBaseLayerVerifier,
            );
        }
        if binding.domain == BinderDomain::ForcedWithdrawalFixtureReplay
            && binding.gate_status == BinderGateStatus::Blocked
        {
            blockers.insert(
                ProductionBlockerKind::MissingForcedWithdrawalReplay
                    .as_str()
                    .to_string(),
                ProductionBlockerKind::MissingForcedWithdrawalReplay,
            );
        }
        if binding.domain == BinderDomain::SettlementExitClaimFixture
            && binding.gate_status == BinderGateStatus::Blocked
        {
            blockers.insert(
                ProductionBlockerKind::MissingSettlementExitClaimFixture
                    .as_str()
                    .to_string(),
                ProductionBlockerKind::MissingSettlementExitClaimFixture,
            );
        }
    }

    blockers.into_values().collect()
}

pub fn public_commitment_root(
    domain: BinderDomain,
    status: EvidenceBindingStatus,
    source_runtime: &str,
    fixture_root: &str,
    release_gate_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-binder-public-commitment",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(fixture_root),
            HashPart::Str(release_gate_root),
        ],
        32,
    )
}

pub fn private_commitment_root(
    domain: BinderDomain,
    observed_claim: &str,
    privacy_set_size: u64,
    user_fee_bps: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-binder-private-commitment",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(observed_claim),
            HashPart::U64(privacy_set_size),
            HashPart::U64(user_fee_bps),
        ],
        32,
    )
}

pub fn pq_control_root(domain: BinderDomain, source_runtime: &str, fixture_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-binder-pq-control",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(fixture_root),
            HashPart::Str("hybrid-ml-dsa-slh-dsa-fixture-evidence"),
        ],
        32,
    )
}

pub fn wallet_scan_root(
    domain: BinderDomain,
    observed_claim: &str,
    privacy_set_size: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-binder-wallet-scan",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(observed_claim),
            HashPart::U64(privacy_set_size),
        ],
        32,
    )
}

pub fn binding_id(
    domain: BinderDomain,
    public_commitment_root: &str,
    private_commitment_root: &str,
    release_gate_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-binder-binding-id",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(public_commitment_root),
            HashPart::Str(private_commitment_root),
            HashPart::Str(release_gate_root),
        ],
        16,
    )
}

pub fn report_id(
    chain_id: &str,
    status: BinderReportStatus,
    binding_root: &str,
    counter_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-binder-report-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(binding_root),
            HashPart::Str(counter_root),
        ],
        16,
    )
}

pub fn bindings_root(bindings: &[EvidenceBinding]) -> String {
    let leaves = bindings
        .iter()
        .map(|binding| binding.binding_root.clone())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-binder-evidence-bindings",
        leaves.as_slice(),
    )
}

pub fn blocker_root(blockers: &[ProductionBlockerKind]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| blocker.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-binder-production-blockers",
        leaves.as_slice(),
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-execution-gate-evidence-binder-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn remediation_hint(
    domain: BinderDomain,
    gate_status: BinderGateStatus,
    blocker: Option<ProductionBlockerKind>,
) -> String {
    if gate_status == BinderGateStatus::Pass {
        return format!(
            "{} evidence is bound for dry-run release gating",
            domain.as_str()
        );
    }

    match blocker {
        Some(ProductionBlockerKind::CargoExecutionDeferred) => {
            "resume cargo/runtime execution and replace fixture-only roots with executed result roots"
        }
        Some(ProductionBlockerKind::NoBaseLayerVerifier) => {
            "keep production blocked until Monero evidence policy has fixture-backed replacement assumptions"
        }
        Some(ProductionBlockerKind::MissingDryRunFixture) => {
            "bind dry-run fixture roots for every vertical-slice stage"
        }
        Some(ProductionBlockerKind::MissingForcedWithdrawalReplay) => {
            "replay forced-withdrawal fixture from user-local evidence"
        }
        Some(ProductionBlockerKind::MissingSettlementExitClaimFixture) => {
            "bind settlement receipt verification to exit claim fixture roots"
        }
        Some(ProductionBlockerKind::MissingPrivacyLeakExecution) => {
            "execute privacy leak regression against fixture-backed disclosure budgets"
        }
        Some(ProductionBlockerKind::MissingPqRotationExecution) => {
            "execute PQ authority rotation fixture with rollback and quarantine roots"
        }
        Some(ProductionBlockerKind::SimulatedLiquidityEvidence) => {
            "replace liquidity runbook simulation with fixture-backed reserve and backstop evidence"
        }
        Some(ProductionBlockerKind::MissingAuditSignoff) => {
            "collect security and privacy signoff after fixture results and runtime execution roots exist"
        }
        None => "replace watch, missing, or deferred binding with fixture-backed evidence roots",
    }
    .to_string()
}

pub fn operator_summary(
    status: BinderReportStatus,
    counters: &BinderCounters,
    blockers: &[ProductionBlockerKind],
) -> String {
    let blocker_labels = blockers
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "status={} bindings={} pass={} watch={} blocked={} deferred={} dry_run_blockers={} production_blockers=[{}]",
        status.as_str(),
        counters.total_bindings,
        counters.passing_bindings,
        counters.watch_bindings,
        counters.blocked_bindings,
        counters.deferred_bindings,
        counters.dry_run_blockers,
        blocker_labels
    )
}
