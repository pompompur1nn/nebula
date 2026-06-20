use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitHeavyGateExecutionPlanRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_HEAVY_GATE_EXECUTION_PLAN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-heavy-gate-execution-plan-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_HEAVY_GATE_EXECUTION_PLAN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_PLAN_SUITE: &str = "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-v1";
pub const DEFAULT_MIN_REQUIRED_STAGES: u64 = 11;
pub const DEFAULT_MIN_READY_STAGES: u64 = 8;
pub const DEFAULT_MAX_DEFERRED_STAGES: u64 = 4;
pub const DEFAULT_MAX_WATCH_STAGES: u64 = 3;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MIN_PQ_SIGNER_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MAX_PLANS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    DepositLockEvidence,
    MoneroFinalityCasebook,
    PqWatcherQuorumAttestation,
    PrivateNoteMint,
    PrivateTransferReceipt,
    SettlementReceiptVerification,
    ForcedExitClaimBuild,
    ChallengeWindowReplay,
    ReleaseAuthorization,
    WalletEscapeEvidencePack,
    PrivacyLeakRegression,
    LiquidityReserveCheck,
    CargoRuntimeInvocation,
    SecurityAuditSignoff,
}

impl ExecutionStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLockEvidence => "deposit_lock_evidence",
            Self::MoneroFinalityCasebook => "monero_finality_casebook",
            Self::PqWatcherQuorumAttestation => "pq_watcher_quorum_attestation",
            Self::PrivateNoteMint => "private_note_mint",
            Self::PrivateTransferReceipt => "private_transfer_receipt",
            Self::SettlementReceiptVerification => "settlement_receipt_verification",
            Self::ForcedExitClaimBuild => "forced_exit_claim_build",
            Self::ChallengeWindowReplay => "challenge_window_replay",
            Self::ReleaseAuthorization => "release_authorization",
            Self::WalletEscapeEvidencePack => "wallet_escape_evidence_pack",
            Self::PrivacyLeakRegression => "privacy_leak_regression",
            Self::LiquidityReserveCheck => "liquidity_reserve_check",
            Self::CargoRuntimeInvocation => "cargo_runtime_invocation",
            Self::SecurityAuditSignoff => "security_audit_signoff",
        }
    }

    pub fn is_user_exit_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLockEvidence
                | Self::MoneroFinalityCasebook
                | Self::PqWatcherQuorumAttestation
                | Self::SettlementReceiptVerification
                | Self::ForcedExitClaimBuild
                | Self::ChallengeWindowReplay
                | Self::ReleaseAuthorization
                | Self::WalletEscapeEvidencePack
                | Self::LiquidityReserveCheck
        )
    }

    pub fn requires_heavy_gate(self) -> bool {
        matches!(
            self,
            Self::CargoRuntimeInvocation
                | Self::SecurityAuditSignoff
                | Self::PrivacyLeakRegression
                | Self::LiquidityReserveCheck
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStageStatus {
    Ready,
    Watch,
    Blocked,
    Deferred,
    Rejected,
}

impl ExecutionStageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_execution(self) -> bool {
        matches!(self, Self::Blocked | Self::Rejected)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Blocked | Self::Deferred | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDomain {
    FixtureTranscriptPreflight,
    MoneroLockReorgCasebook,
    PqWatcherQuorumFixture,
    PrivateNoteReceiptLinkage,
    ForcedExitChallengeWindow,
    WalletEscapeEvidencePack,
    ExecutionGateBinder,
    ReleaseGatePlan,
    CargoHarness,
    SecurityAuditHarness,
}

impl EvidenceDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixtureTranscriptPreflight => "fixture_transcript_preflight",
            Self::MoneroLockReorgCasebook => "monero_lock_reorg_casebook",
            Self::PqWatcherQuorumFixture => "pq_watcher_quorum_fixture",
            Self::PrivateNoteReceiptLinkage => "private_note_receipt_linkage",
            Self::ForcedExitChallengeWindow => "forced_exit_challenge_window",
            Self::WalletEscapeEvidencePack => "wallet_escape_evidence_pack",
            Self::ExecutionGateBinder => "execution_gate_binder",
            Self::ReleaseGatePlan => "release_gate_plan",
            Self::CargoHarness => "cargo_harness",
            Self::SecurityAuditHarness => "security_audit_harness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlockerKind {
    CargoRuntimeDeferred,
    SecurityAuditDeferred,
    MoneroNoBaseLayerVerifier,
    MissingTranscriptPreflight,
    MissingMoneroCasebook,
    MissingPqWatcherQuorum,
    MissingPrivateReceiptLinkage,
    MissingForcedExitChallengeReplay,
    MissingWalletEscapePack,
    PrivacyLeakRegressionDeferred,
    LiquidityReserveExecutionDeferred,
    ReleaseGateStillSimulated,
}

impl ProductionBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::MoneroNoBaseLayerVerifier => "monero_no_base_layer_verifier",
            Self::MissingTranscriptPreflight => "missing_transcript_preflight",
            Self::MissingMoneroCasebook => "missing_monero_casebook",
            Self::MissingPqWatcherQuorum => "missing_pq_watcher_quorum",
            Self::MissingPrivateReceiptLinkage => "missing_private_receipt_linkage",
            Self::MissingForcedExitChallengeReplay => "missing_forced_exit_challenge_replay",
            Self::MissingWalletEscapePack => "missing_wallet_escape_pack",
            Self::PrivacyLeakRegressionDeferred => "privacy_leak_regression_deferred",
            Self::LiquidityReserveExecutionDeferred => "liquidity_reserve_execution_deferred",
            Self::ReleaseGateStillSimulated => "release_gate_still_simulated",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::SecurityAuditDeferred => "security_audit",
            Self::MoneroNoBaseLayerVerifier => "monero_evidence_policy",
            Self::MissingTranscriptPreflight => "fixture_transcript_preflight",
            Self::MissingMoneroCasebook => "monero_lock_reorg_casebook",
            Self::MissingPqWatcherQuorum => "pq_watcher_quorum",
            Self::MissingPrivateReceiptLinkage => "private_note_receipt_linkage",
            Self::MissingForcedExitChallengeReplay => "forced_exit_challenge_window",
            Self::MissingWalletEscapePack => "wallet_escape_evidence_pack",
            Self::PrivacyLeakRegressionDeferred => "privacy_leak_regression",
            Self::LiquidityReserveExecutionDeferred => "liquidity_reserve",
            Self::ReleaseGateStillSimulated => "release_gate",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_required_stages: u64,
    pub min_ready_stages: u64,
    pub max_deferred_stages: u64,
    pub max_watch_stages: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_signer_weight: u64,
    pub min_monero_confirmations: u64,
    pub max_plans: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_required_stages: DEFAULT_MIN_REQUIRED_STAGES,
            min_ready_stages: DEFAULT_MIN_READY_STAGES,
            max_deferred_stages: DEFAULT_MAX_DEFERRED_STAGES,
            max_watch_stages: DEFAULT_MAX_WATCH_STAGES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_signer_weight: DEFAULT_MIN_PQ_SIGNER_WEIGHT,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            max_plans: DEFAULT_MAX_PLANS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionPlanInput {
    pub stage: ExecutionStage,
    pub domain: EvidenceDomain,
    pub label: String,
    pub source_root: String,
    pub fixture_root: String,
    pub previous_stage_root: String,
    pub required_confirmations: u64,
    pub observed_confirmations: u64,
    pub pq_signer_weight: u64,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub heavy_gate_required: String,
    pub heavy_gate_available: String,
    pub simulated_evidence: String,
    pub user_exit_critical: String,
    pub operator_action: String,
}

impl ExecutionPlanInput {
    pub fn input_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-input",
            &[
                HashPart::Str(self.stage.as_str()),
                HashPart::Str(self.domain.as_str()),
                HashPart::Str(&self.label),
                HashPart::Str(&self.source_root),
                HashPart::Str(&self.fixture_root),
                HashPart::Str(&self.previous_stage_root),
                HashPart::U64(self.required_confirmations),
                HashPart::U64(self.observed_confirmations),
                HashPart::U64(self.pq_signer_weight),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.fee_bps),
                HashPart::Str(&self.heavy_gate_required),
                HashPart::Str(&self.heavy_gate_available),
                HashPart::Str(&self.simulated_evidence),
                HashPart::Str(&self.user_exit_critical),
                HashPart::Str(&self.operator_action),
            ],
            32,
        )
    }

    pub fn requires_heavy_gate(&self) -> bool {
        self.heavy_gate_required == "required"
    }

    pub fn heavy_gate_is_available(&self) -> bool {
        self.heavy_gate_available == "available"
    }

    pub fn is_simulated(&self) -> bool {
        self.simulated_evidence == "simulated"
    }

    pub fn user_exit_is_critical(&self) -> bool {
        self.user_exit_critical == "critical"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionStagePlan {
    pub stage: ExecutionStage,
    pub domain: EvidenceDomain,
    pub status: ExecutionStageStatus,
    pub label: String,
    pub input_root: String,
    pub execution_root: String,
    pub required_evidence_root: String,
    pub blocker: Option<ProductionBlockerKind>,
    pub remediation: String,
    pub sequence_index: u64,
    pub user_release_lane: String,
    pub production_release_lane: String,
    pub plan_root: String,
}

impl ExecutionStagePlan {
    pub fn blocks_user_execution(&self) -> bool {
        self.status.blocks_execution()
            && matches!(self.user_release_lane.as_str(), "critical" | "blocked")
    }

    pub fn blocks_production(&self) -> bool {
        self.status.blocks_production()
            || self.blocker.is_some()
            || self.production_release_lane != "ready"
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionPlanCounters {
    pub total_stages: u64,
    pub ready_stages: u64,
    pub watch_stages: u64,
    pub blocked_stages: u64,
    pub deferred_stages: u64,
    pub rejected_stages: u64,
    pub user_exit_critical_stages: u64,
    pub heavy_gate_required_stages: u64,
    pub simulated_evidence_stages: u64,
    pub production_blockers: u64,
}

impl ExecutionPlanCounters {
    pub fn observe(&mut self, plan: &ExecutionStagePlan, input: &ExecutionPlanInput) {
        self.total_stages += 1;
        match plan.status {
            ExecutionStageStatus::Ready => self.ready_stages += 1,
            ExecutionStageStatus::Watch => self.watch_stages += 1,
            ExecutionStageStatus::Blocked => self.blocked_stages += 1,
            ExecutionStageStatus::Deferred => self.deferred_stages += 1,
            ExecutionStageStatus::Rejected => self.rejected_stages += 1,
        }
        if input.user_exit_is_critical() {
            self.user_exit_critical_stages += 1;
        }
        if input.requires_heavy_gate() {
            self.heavy_gate_required_stages += 1;
        }
        if input.is_simulated() {
            self.simulated_evidence_stages += 1;
        }
        if plan.blocks_production() {
            self.production_blockers += 1;
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeavyGatePlanStatus {
    ReadyForLocalDryRun,
    ReadyButCargoDeferred,
    Watch,
    Blocked,
    Rejected,
}

impl HeavyGatePlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForLocalDryRun => "ready_for_local_dry_run",
            Self::ReadyButCargoDeferred => "ready_but_cargo_deferred",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeavyGateExecutionPlan {
    pub plan_id: String,
    pub status: HeavyGatePlanStatus,
    pub stage_root: String,
    pub input_root: String,
    pub blocker_root: String,
    pub counter_root: String,
    pub operator_summary: String,
    pub wallet_answer: String,
    pub production_answer: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub inputs: Vec<ExecutionPlanInput>,
    pub stages: Vec<ExecutionStagePlan>,
    pub counters: ExecutionPlanCounters,
    pub blockers: Vec<ProductionBlockerKind>,
    pub heavy_gate_plan: HeavyGateExecutionPlan,
    pub stage_index: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let inputs = default_execution_plan_inputs(&config);
        Self::from_inputs(config, inputs)
    }

    pub fn from_inputs(config: Config, inputs: Vec<ExecutionPlanInput>) -> Self {
        let limited_inputs = inputs
            .into_iter()
            .take(config.max_plans)
            .collect::<Vec<_>>();
        let mut counters = ExecutionPlanCounters::default();
        let mut blockers = Vec::new();
        let mut stages = Vec::new();
        let mut stage_index = BTreeMap::new();

        for (index, input) in limited_inputs.iter().enumerate() {
            let stage_plan = derive_stage_plan(&config, input, index as u64);
            counters.observe(&stage_plan, input);
            if let Some(blocker) = stage_plan.blocker {
                if !blockers.contains(&blocker) {
                    blockers.push(blocker);
                }
            }
            stage_index.insert(
                input.stage.as_str().to_string(),
                stage_plan.plan_root.clone(),
            );
            stages.push(stage_plan);
        }

        blockers.sort();
        let heavy_gate_plan =
            build_heavy_gate_plan(&config, &limited_inputs, &stages, &counters, &blockers);

        Self {
            config,
            inputs: limited_inputs,
            stages,
            counters,
            blockers,
            heavy_gate_plan,
            stage_index,
        }
    }

    pub fn ingest(&mut self, input: ExecutionPlanInput) -> Result<()> {
        if self.inputs.len() >= self.config.max_plans {
            return Err("heavy gate execution plan input capacity reached".to_string());
        }
        self.inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), self.inputs.clone());
        Ok(())
    }

    pub fn ready_for_user_dry_run(&self) -> bool {
        self.counters.ready_stages >= self.config.min_ready_stages
            && self.counters.blocked_stages == 0
            && self.counters.rejected_stages == 0
    }

    pub fn production_blocked(&self) -> bool {
        !self.blockers.is_empty()
            || self.counters.deferred_stages > 0
            || self.counters.watch_stages > 0
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-state",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.heavy_gate_plan.plan_id),
                HashPart::Str(&self.heavy_gate_plan.stage_root),
                HashPart::Str(&self.heavy_gate_plan.input_root),
                HashPart::Str(&self.heavy_gate_plan.blocker_root),
                HashPart::Str(&self.heavy_gate_plan.counter_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let stages = self
            .stages
            .iter()
            .map(stage_public_record)
            .collect::<Vec<_>>();
        let blockers = self
            .blockers
            .iter()
            .map(|blocker| {
                json!({
                    "kind": blocker.as_str(),
                    "owner_lane": blocker.owner_lane(),
                })
            })
            .collect::<Vec<_>>();

        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "execution_plan_suite": EXECUTION_PLAN_SUITE,
            "chain_id": self.config.chain_id,
            "state_root": self.state_root(),
            "heavy_gate_plan": {
                "plan_id": self.heavy_gate_plan.plan_id,
                "status": self.heavy_gate_plan.status.as_str(),
                "stage_root": self.heavy_gate_plan.stage_root,
                "input_root": self.heavy_gate_plan.input_root,
                "blocker_root": self.heavy_gate_plan.blocker_root,
                "counter_root": self.heavy_gate_plan.counter_root,
                "operator_summary": self.heavy_gate_plan.operator_summary,
                "wallet_answer": self.heavy_gate_plan.wallet_answer,
                "production_answer": self.heavy_gate_plan.production_answer,
            },
            "counters": {
                "total_stages": self.counters.total_stages,
                "ready_stages": self.counters.ready_stages,
                "watch_stages": self.counters.watch_stages,
                "blocked_stages": self.counters.blocked_stages,
                "deferred_stages": self.counters.deferred_stages,
                "rejected_stages": self.counters.rejected_stages,
                "user_exit_critical_stages": self.counters.user_exit_critical_stages,
                "heavy_gate_required_stages": self.counters.heavy_gate_required_stages,
                "simulated_evidence_stages": self.counters.simulated_evidence_stages,
                "production_blockers": self.counters.production_blockers,
            },
            "blockers": blockers,
            "stage_index": self.stage_index,
            "stages": stages,
            "readiness_split": {
                "feature_inventory": "high",
                "verified_runtime_execution": "deferred",
                "production_release": "blocked",
                "next_heavy_gate": "execute deposit -> private note -> private transfer -> settlement receipt -> forced exit",
            },
        })
    }
}

pub fn devnet() -> State {
    State::new(Config::default())
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn default_execution_plan_inputs(config: &Config) -> Vec<ExecutionPlanInput> {
    let seed = plan_seed_root(&config.chain_id);
    let deposit_root = evidence_root("deposit-lock", &seed, "monero-lock-output", 0);
    let casebook_root = evidence_root(
        "monero-casebook",
        &deposit_root,
        "deep-finality-plus-reorg-negative",
        1,
    );
    let quorum_root = evidence_root("pq-quorum", &casebook_root, "ml-dsa-slh-dsa-watchers", 2);
    let note_root = evidence_root("private-note", &quorum_root, "bridge-minted-note", 3);
    let transfer_root = evidence_root(
        "private-transfer",
        &note_root,
        "minimal-transfer-receipt",
        4,
    );
    let settlement_root = evidence_root(
        "settlement",
        &transfer_root,
        "settlement-receipt-verifier",
        5,
    );
    let forced_exit_root = evidence_root("forced-exit", &settlement_root, "claim-builder", 6);
    let challenge_root = evidence_root("challenge-window", &forced_exit_root, "timeout-replay", 7);
    let release_root = evidence_root("release-auth", &challenge_root, "pq-authorized-release", 8);
    let wallet_root = evidence_root("wallet-escape", &release_root, "local-evidence-pack", 9);
    let privacy_root = evidence_root(
        "privacy-regression",
        &wallet_root,
        "redaction-budget-check",
        10,
    );
    let liquidity_root = evidence_root(
        "liquidity-reserve",
        &privacy_root,
        "reserve-backstop-dry-run",
        11,
    );
    let cargo_root = evidence_root("cargo-runtime", &liquidity_root, "deferred-heavy-gate", 12);
    let audit_root = evidence_root("security-audit", &cargo_root, "deferred-signoff", 13);

    vec![
        ExecutionPlanInput {
            stage: ExecutionStage::DepositLockEvidence,
            domain: EvidenceDomain::FixtureTranscriptPreflight,
            label: "monero deposit lock evidence fixture is present".to_string(),
            source_root: deposit_root.clone(),
            fixture_root: deposit_root.clone(),
            previous_stage_root: seed.clone(),
            required_confirmations: config.min_monero_confirmations,
            observed_confirmations: config.min_monero_confirmations + 6,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 8,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "admit deposit lock into transcript preflight".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::MoneroFinalityCasebook,
            domain: EvidenceDomain::MoneroLockReorgCasebook,
            label: "Monero finality and reorg negative casebook is bound".to_string(),
            source_root: casebook_root.clone(),
            fixture_root: casebook_root.clone(),
            previous_stage_root: deposit_root.clone(),
            required_confirmations: config.min_monero_confirmations,
            observed_confirmations: config.min_monero_confirmations + 4,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 9,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "reject shallow finality and risky reorg cases".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::PqWatcherQuorumAttestation,
            domain: EvidenceDomain::PqWatcherQuorumFixture,
            label: "PQ watcher quorum fixture signs bridge evidence".to_string(),
            source_root: quorum_root.clone(),
            fixture_root: quorum_root.clone(),
            previous_stage_root: casebook_root.clone(),
            required_confirmations: config.min_monero_confirmations,
            observed_confirmations: config.min_monero_confirmations + 3,
            pq_signer_weight: config.min_pq_signer_weight + 8,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 10,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "bind signer epoch and release authority roots".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::PrivateNoteMint,
            domain: EvidenceDomain::PrivateNoteReceiptLinkage,
            label: "deposit-minted private note commits to bridge lock".to_string(),
            source_root: note_root.clone(),
            fixture_root: note_root.clone(),
            previous_stage_root: quorum_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 16,
            fee_bps: 11,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "mint private L2 note with wallet scan commitment".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::PrivateTransferReceipt,
            domain: EvidenceDomain::PrivateNoteReceiptLinkage,
            label: "minimal private transfer receipt keeps forced-exit continuity".to_string(),
            source_root: transfer_root.clone(),
            fixture_root: transfer_root.clone(),
            previous_stage_root: note_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 32,
            fee_bps: 12,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "bind encrypted receipt and nullifier commitment".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::SettlementReceiptVerification,
            domain: EvidenceDomain::ExecutionGateBinder,
            label: "settlement receipt verifier fixture accepts claim linkage".to_string(),
            source_root: settlement_root.clone(),
            fixture_root: settlement_root.clone(),
            previous_stage_root: transfer_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 24,
            fee_bps: 13,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "verify settlement receipt against exit claim fixture".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::ForcedExitClaimBuild,
            domain: EvidenceDomain::WalletEscapeEvidencePack,
            label: "wallet can build forced-exit claim from local evidence".to_string(),
            source_root: forced_exit_root.clone(),
            fixture_root: forced_exit_root.clone(),
            previous_stage_root: settlement_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 24,
            fee_bps: 14,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "assemble user-local forced-exit claim package".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::ChallengeWindowReplay,
            domain: EvidenceDomain::ForcedExitChallengeWindow,
            label: "challenge window replay rejects invalid disputes".to_string(),
            source_root: challenge_root.clone(),
            fixture_root: challenge_root.clone(),
            previous_stage_root: forced_exit_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 8,
            fee_bps: 15,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "replay timeout and malicious challenge fixtures".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::ReleaseAuthorization,
            domain: EvidenceDomain::PqWatcherQuorumFixture,
            label: "release authorization roots bind PQ quorum and settlement".to_string(),
            source_root: release_root.clone(),
            fixture_root: release_root.clone(),
            previous_stage_root: challenge_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight + 5,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 16,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "bind PQ withdrawal authorization to release lane".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::WalletEscapeEvidencePack,
            domain: EvidenceDomain::WalletEscapeEvidencePack,
            label: "wallet escape pack can be reconstructed after sequencer failure".to_string(),
            source_root: wallet_root.clone(),
            fixture_root: wallet_root.clone(),
            previous_stage_root: release_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 12,
            fee_bps: 17,
            heavy_gate_required: "not_required".to_string(),
            heavy_gate_available: "available".to_string(),
            simulated_evidence: "fixture".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "prove local wallet recovery inputs are sufficient".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::PrivacyLeakRegression,
            domain: EvidenceDomain::ReleaseGatePlan,
            label: "privacy regression must execute against final transcript".to_string(),
            source_root: privacy_root.clone(),
            fixture_root: privacy_root.clone(),
            previous_stage_root: wallet_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size + 4,
            fee_bps: 18,
            heavy_gate_required: "required".to_string(),
            heavy_gate_available: "deferred".to_string(),
            simulated_evidence: "simulated".to_string(),
            user_exit_critical: "supporting".to_string(),
            operator_action: "run privacy leak regression when heavy gates resume".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::LiquidityReserveCheck,
            domain: EvidenceDomain::ReleaseGatePlan,
            label: "liquidity reserve and backstop check needs execution".to_string(),
            source_root: liquidity_root.clone(),
            fixture_root: liquidity_root.clone(),
            previous_stage_root: privacy_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 19,
            heavy_gate_required: "required".to_string(),
            heavy_gate_available: "deferred".to_string(),
            simulated_evidence: "simulated".to_string(),
            user_exit_critical: "critical".to_string(),
            operator_action: "execute reserve and backstop release path".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::CargoRuntimeInvocation,
            domain: EvidenceDomain::CargoHarness,
            label: "cargo runtime invocation is intentionally deferred".to_string(),
            source_root: cargo_root.clone(),
            fixture_root: cargo_root.clone(),
            previous_stage_root: liquidity_root.clone(),
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 20,
            heavy_gate_required: "required".to_string(),
            heavy_gate_available: "deferred".to_string(),
            simulated_evidence: "simulated".to_string(),
            user_exit_critical: "supporting".to_string(),
            operator_action: "run cargo/runtime harness after lightweight-only phase".to_string(),
        },
        ExecutionPlanInput {
            stage: ExecutionStage::SecurityAuditSignoff,
            domain: EvidenceDomain::SecurityAuditHarness,
            label: "security and privacy audit signoff remains blocked".to_string(),
            source_root: audit_root,
            fixture_root: evidence_root("audit-fixture", &cargo_root, "deferred-audit-root", 14),
            previous_stage_root: cargo_root,
            required_confirmations: 0,
            observed_confirmations: 0,
            pq_signer_weight: config.min_pq_signer_weight,
            privacy_set_size: config.min_privacy_set_size,
            fee_bps: 21,
            heavy_gate_required: "required".to_string(),
            heavy_gate_available: "deferred".to_string(),
            simulated_evidence: "simulated".to_string(),
            user_exit_critical: "supporting".to_string(),
            operator_action: "collect independent audit signoff after execution roots exist"
                .to_string(),
        },
    ]
}

pub fn derive_stage_plan(
    config: &Config,
    input: &ExecutionPlanInput,
    sequence_index: u64,
) -> ExecutionStagePlan {
    let status = derive_stage_status(config, input);
    let blocker = derive_blocker(config, input, status);
    let input_root = input.input_root();
    let execution_root = execution_root(input, status, sequence_index);
    let required_evidence_root = required_evidence_root(input, &execution_root);
    let user_release_lane = if input.user_exit_is_critical() && status.blocks_execution() {
        "blocked"
    } else if input.user_exit_is_critical() {
        "critical"
    } else {
        "supporting"
    }
    .to_string();
    let production_release_lane = if status.blocks_production() || blocker.is_some() {
        "blocked"
    } else {
        "ready"
    }
    .to_string();
    let remediation = remediation_hint(input.stage, status, blocker);
    let plan_root = stage_plan_root(
        input.stage,
        input.domain,
        status,
        &input_root,
        &execution_root,
        &required_evidence_root,
        blocker,
        sequence_index,
    );

    ExecutionStagePlan {
        stage: input.stage,
        domain: input.domain,
        status,
        label: input.label.clone(),
        input_root,
        execution_root,
        required_evidence_root,
        blocker,
        remediation,
        sequence_index,
        user_release_lane,
        production_release_lane,
        plan_root,
    }
}

pub fn derive_stage_status(config: &Config, input: &ExecutionPlanInput) -> ExecutionStageStatus {
    if input.fee_bps > config.max_user_fee_bps {
        return ExecutionStageStatus::Rejected;
    }
    if input.privacy_set_size < config.min_privacy_set_size {
        return ExecutionStageStatus::Rejected;
    }
    if input.pq_signer_weight < config.min_pq_signer_weight {
        return ExecutionStageStatus::Rejected;
    }
    if input.required_confirmations > input.observed_confirmations {
        return ExecutionStageStatus::Blocked;
    }
    if input.requires_heavy_gate() && !input.heavy_gate_is_available() {
        return ExecutionStageStatus::Deferred;
    }
    if input.is_simulated() {
        return ExecutionStageStatus::Watch;
    }
    ExecutionStageStatus::Ready
}

pub fn derive_blocker(
    config: &Config,
    input: &ExecutionPlanInput,
    status: ExecutionStageStatus,
) -> Option<ProductionBlockerKind> {
    if status == ExecutionStageStatus::Rejected || status == ExecutionStageStatus::Blocked {
        return match input.stage {
            ExecutionStage::DepositLockEvidence | ExecutionStage::MoneroFinalityCasebook => {
                Some(ProductionBlockerKind::MissingMoneroCasebook)
            }
            ExecutionStage::PqWatcherQuorumAttestation | ExecutionStage::ReleaseAuthorization => {
                Some(ProductionBlockerKind::MissingPqWatcherQuorum)
            }
            ExecutionStage::PrivateNoteMint | ExecutionStage::PrivateTransferReceipt => {
                Some(ProductionBlockerKind::MissingPrivateReceiptLinkage)
            }
            ExecutionStage::ForcedExitClaimBuild | ExecutionStage::ChallengeWindowReplay => {
                Some(ProductionBlockerKind::MissingForcedExitChallengeReplay)
            }
            ExecutionStage::WalletEscapeEvidencePack => {
                Some(ProductionBlockerKind::MissingWalletEscapePack)
            }
            ExecutionStage::SettlementReceiptVerification => {
                Some(ProductionBlockerKind::MissingTranscriptPreflight)
            }
            ExecutionStage::PrivacyLeakRegression => {
                Some(ProductionBlockerKind::PrivacyLeakRegressionDeferred)
            }
            ExecutionStage::LiquidityReserveCheck => {
                Some(ProductionBlockerKind::LiquidityReserveExecutionDeferred)
            }
            ExecutionStage::CargoRuntimeInvocation => {
                Some(ProductionBlockerKind::CargoRuntimeDeferred)
            }
            ExecutionStage::SecurityAuditSignoff => {
                Some(ProductionBlockerKind::SecurityAuditDeferred)
            }
        };
    }

    if input.stage == ExecutionStage::MoneroFinalityCasebook {
        return Some(ProductionBlockerKind::MoneroNoBaseLayerVerifier);
    }
    if input.stage == ExecutionStage::CargoRuntimeInvocation {
        return Some(ProductionBlockerKind::CargoRuntimeDeferred);
    }
    if input.stage == ExecutionStage::SecurityAuditSignoff {
        return Some(ProductionBlockerKind::SecurityAuditDeferred);
    }
    if input.stage == ExecutionStage::PrivacyLeakRegression && input.requires_heavy_gate() {
        return Some(ProductionBlockerKind::PrivacyLeakRegressionDeferred);
    }
    if input.stage == ExecutionStage::LiquidityReserveCheck && input.requires_heavy_gate() {
        return Some(ProductionBlockerKind::LiquidityReserveExecutionDeferred);
    }
    if input.is_simulated() || input.requires_heavy_gate() {
        return Some(ProductionBlockerKind::ReleaseGateStillSimulated);
    }
    if input.required_confirmations < config.min_monero_confirmations
        && matches!(
            input.stage,
            ExecutionStage::DepositLockEvidence | ExecutionStage::MoneroFinalityCasebook
        )
    {
        return Some(ProductionBlockerKind::MoneroNoBaseLayerVerifier);
    }
    None
}

pub fn build_heavy_gate_plan(
    config: &Config,
    inputs: &[ExecutionPlanInput],
    stages: &[ExecutionStagePlan],
    counters: &ExecutionPlanCounters,
    blockers: &[ProductionBlockerKind],
) -> HeavyGateExecutionPlan {
    let status = derive_plan_status(config, counters, blockers);
    let input_root = inputs_root(inputs);
    let stage_root = stages_root(stages);
    let blocker_root = blockers_root(blockers);
    let counter_root = counters_root(counters);
    let plan_id = plan_id(
        &config.chain_id,
        status,
        &input_root,
        &stage_root,
        &blocker_root,
    );
    let operator_summary = operator_summary(status, counters, blockers);
    let wallet_answer = wallet_answer(status, counters);
    let production_answer = production_answer(status, blockers);

    HeavyGateExecutionPlan {
        plan_id,
        status,
        stage_root,
        input_root,
        blocker_root,
        counter_root,
        operator_summary,
        wallet_answer,
        production_answer,
    }
}

pub fn derive_plan_status(
    config: &Config,
    counters: &ExecutionPlanCounters,
    blockers: &[ProductionBlockerKind],
) -> HeavyGatePlanStatus {
    if counters.rejected_stages > 0 {
        return HeavyGatePlanStatus::Rejected;
    }
    if counters.blocked_stages > 0 {
        return HeavyGatePlanStatus::Blocked;
    }
    if counters.ready_stages < config.min_ready_stages {
        return HeavyGatePlanStatus::Watch;
    }
    if counters.deferred_stages > config.max_deferred_stages
        || counters.watch_stages > config.max_watch_stages
    {
        return HeavyGatePlanStatus::Watch;
    }
    if !blockers.is_empty() || counters.deferred_stages > 0 {
        return HeavyGatePlanStatus::ReadyButCargoDeferred;
    }
    HeavyGatePlanStatus::ReadyForLocalDryRun
}

pub fn stage_public_record(stage: &ExecutionStagePlan) -> Value {
    json!({
        "stage": stage.stage.as_str(),
        "domain": stage.domain.as_str(),
        "status": stage.status.as_str(),
        "label": stage.label,
        "input_root": stage.input_root,
        "execution_root": stage.execution_root,
        "required_evidence_root": stage.required_evidence_root,
        "blocker": stage.blocker.map(|blocker| blocker.as_str()),
        "remediation": stage.remediation,
        "sequence_index": stage.sequence_index,
        "user_release_lane": stage.user_release_lane,
        "production_release_lane": stage.production_release_lane,
        "plan_root": stage.plan_root,
    })
}

pub fn plan_seed_root(chain_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-heavy-gate-plan-seed",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(EXECUTION_PLAN_SUITE),
        ],
        32,
    )
}

pub fn evidence_root(domain: &str, prior_root: &str, label: &str, index: u64) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-heavy-gate-execution-evidence-{domain}"),
        &[
            HashPart::Str(prior_root),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}

pub fn execution_root(
    input: &ExecutionPlanInput,
    status: ExecutionStageStatus,
    sequence_index: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-heavy-gate-stage-execution-root",
        &[
            HashPart::Str(input.stage.as_str()),
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&input.input_root()),
            HashPart::Str(&input.fixture_root),
            HashPart::U64(sequence_index),
        ],
        32,
    )
}

pub fn required_evidence_root(input: &ExecutionPlanInput, execution_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-heavy-gate-required-evidence-root",
        &[
            HashPart::Str(input.stage.as_str()),
            HashPart::Str(input.domain.as_str()),
            HashPart::Str(&input.source_root),
            HashPart::Str(&input.fixture_root),
            HashPart::Str(&input.previous_stage_root),
            HashPart::Str(execution_root),
        ],
        32,
    )
}

pub fn stage_plan_root(
    stage: ExecutionStage,
    domain: EvidenceDomain,
    status: ExecutionStageStatus,
    input_root: &str,
    execution_root: &str,
    required_evidence_root: &str,
    blocker: Option<ProductionBlockerKind>,
    sequence_index: u64,
) -> String {
    let blocker_label = blocker.map(|kind| kind.as_str()).unwrap_or("none");
    domain_hash(
        "monero-l2-pq-bridge-exit-heavy-gate-stage-plan-root",
        &[
            HashPart::Str(stage.as_str()),
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(execution_root),
            HashPart::Str(required_evidence_root),
            HashPart::Str(blocker_label),
            HashPart::U64(sequence_index),
        ],
        32,
    )
}

pub fn inputs_root(inputs: &[ExecutionPlanInput]) -> String {
    let leaves = inputs
        .iter()
        .map(ExecutionPlanInput::input_root)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-inputs",
        leaves.as_slice(),
    )
}

pub fn stages_root(stages: &[ExecutionStagePlan]) -> String {
    let leaves = stages
        .iter()
        .map(|stage| stage.plan_root.clone())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-stages",
        leaves.as_slice(),
    )
}

pub fn blockers_root(blockers: &[ProductionBlockerKind]) -> String {
    let leaves = blockers
        .iter()
        .map(|blocker| blocker.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-blockers",
        leaves.as_slice(),
    )
}

pub fn counters_root(counters: &ExecutionPlanCounters) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-counters",
        &[
            HashPart::U64(counters.total_stages),
            HashPart::U64(counters.ready_stages),
            HashPart::U64(counters.watch_stages),
            HashPart::U64(counters.blocked_stages),
            HashPart::U64(counters.deferred_stages),
            HashPart::U64(counters.rejected_stages),
            HashPart::U64(counters.user_exit_critical_stages),
            HashPart::U64(counters.heavy_gate_required_stages),
            HashPart::U64(counters.simulated_evidence_stages),
            HashPart::U64(counters.production_blockers),
        ],
        32,
    )
}

pub fn plan_id(
    chain_id: &str,
    status: HeavyGatePlanStatus,
    input_root: &str,
    stage_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-heavy-gate-execution-plan-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(input_root),
            HashPart::Str(stage_root),
            HashPart::Str(blocker_root),
        ],
        16,
    )
}

pub fn remediation_hint(
    stage: ExecutionStage,
    status: ExecutionStageStatus,
    blocker: Option<ProductionBlockerKind>,
) -> String {
    if status == ExecutionStageStatus::Ready && blocker.is_none() {
        return format!(
            "{} is ready for the next local dry-run transcript",
            stage.as_str()
        );
    }

    match blocker {
        Some(ProductionBlockerKind::CargoRuntimeDeferred) => {
            "resume cargo/runtime execution and capture actual bridge/exit result roots"
        }
        Some(ProductionBlockerKind::SecurityAuditDeferred) => {
            "collect independent security and privacy signoff after execution roots exist"
        }
        Some(ProductionBlockerKind::MoneroNoBaseLayerVerifier) => {
            "keep the no-base-layer-verifier assumption explicit and require watcher/reorg negative fixtures"
        }
        Some(ProductionBlockerKind::MissingTranscriptPreflight) => {
            "bind every get-in/move-private/force-out stage into the transcript preflight runtime"
        }
        Some(ProductionBlockerKind::MissingMoneroCasebook) => {
            "attach accepted and rejected Monero lock/reorg/finality fixtures"
        }
        Some(ProductionBlockerKind::MissingPqWatcherQuorum) => {
            "attach PQ watcher quorum fixture roots with signer epoch and quarantine evidence"
        }
        Some(ProductionBlockerKind::MissingPrivateReceiptLinkage) => {
            "link private notes, nullifiers, encrypted receipts, scan hints, and exit claims"
        }
        Some(ProductionBlockerKind::MissingForcedExitChallengeReplay) => {
            "replay forced-exit challenge windows and timeout release eligibility"
        }
        Some(ProductionBlockerKind::MissingWalletEscapePack) => {
            "prove the wallet can reconstruct all local evidence required for force exit"
        }
        Some(ProductionBlockerKind::PrivacyLeakRegressionDeferred) => {
            "execute privacy leak regression against final transcript and wallet evidence"
        }
        Some(ProductionBlockerKind::LiquidityReserveExecutionDeferred) => {
            "execute liquidity reserve and backstop release checks against settlement claims"
        }
        Some(ProductionBlockerKind::ReleaseGateStillSimulated) => {
            "replace simulated release-gate inputs with executed or fixture-backed roots"
        }
        None => "move watch/deferred evidence into an executable heavy-gate transcript",
    }
    .to_string()
}

pub fn operator_summary(
    status: HeavyGatePlanStatus,
    counters: &ExecutionPlanCounters,
    blockers: &[ProductionBlockerKind],
) -> String {
    let blocker_labels = blockers
        .iter()
        .map(|blocker| blocker.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "status={} stages={} ready={} watch={} blocked={} deferred={} rejected={} user_exit_critical={} heavy_gate_required={} simulated={} production_blockers={} blockers=[{}]",
        status.as_str(),
        counters.total_stages,
        counters.ready_stages,
        counters.watch_stages,
        counters.blocked_stages,
        counters.deferred_stages,
        counters.rejected_stages,
        counters.user_exit_critical_stages,
        counters.heavy_gate_required_stages,
        counters.simulated_evidence_stages,
        counters.production_blockers,
        blocker_labels
    )
}

pub fn wallet_answer(status: HeavyGatePlanStatus, counters: &ExecutionPlanCounters) -> String {
    match status {
        HeavyGatePlanStatus::ReadyForLocalDryRun => {
            "wallet evidence is sufficient for local forced-exit dry run".to_string()
        }
        HeavyGatePlanStatus::ReadyButCargoDeferred => format!(
            "wallet path has {} ready stages, but {} deferred heavy-gate stages still need execution",
            counters.ready_stages, counters.deferred_stages
        ),
        HeavyGatePlanStatus::Watch => {
            "wallet path is watch-listed until deferred/simulated stages are reduced".to_string()
        }
        HeavyGatePlanStatus::Blocked => {
            "wallet path is blocked by missing or contradictory bridge/exit evidence".to_string()
        }
        HeavyGatePlanStatus::Rejected => {
            "wallet path rejected because a safety, privacy, fee, or PQ threshold failed".to_string()
        }
    }
}

pub fn production_answer(
    status: HeavyGatePlanStatus,
    blockers: &[ProductionBlockerKind],
) -> String {
    if blockers.is_empty() && status == HeavyGatePlanStatus::ReadyForLocalDryRun {
        return "production release still requires operator approval after dry-run evidence"
            .to_string();
    }

    let lanes = blockers
        .iter()
        .map(|blocker| blocker.owner_lane())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "production remains blocked while status={} and blocker_lanes=[{}]",
        status.as_str(),
        lanes
    )
}
