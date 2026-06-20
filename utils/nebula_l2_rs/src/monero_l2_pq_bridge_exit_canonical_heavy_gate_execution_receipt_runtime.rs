use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalHeavyGateExecutionReceiptRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_EXECUTION_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-receipt-v1";
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_FORCE_EXIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RELEASE_FINALITY_BLOCKS: u64 = 40;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_LEAK_UNITS: u64 = 2;
pub const DEFAULT_MAX_FEE_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MAX_RECEIPT_STEPS: usize = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    DepositLock,
    NoteMint,
    PrivateTransfer,
    ContractAction,
    SettlementReceipt,
    ForcedExitClaim,
    ChallengeWindow,
    ReleaseAuthorization,
    WalletRecovery,
}

impl ExecutionStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::NoteMint => "note_mint",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractAction => "contract_action",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedExitClaim => "forced_exit_claim",
            Self::ChallengeWindow => "challenge_window",
            Self::ReleaseAuthorization => "release_authorization",
            Self::WalletRecovery => "wallet_recovery",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::DepositLock => 0,
            Self::NoteMint => 1,
            Self::PrivateTransfer => 2,
            Self::ContractAction => 3,
            Self::SettlementReceipt => 4,
            Self::ForcedExitClaim => 5,
            Self::ChallengeWindow => 6,
            Self::ReleaseAuthorization => 7,
            Self::WalletRecovery => 8,
        }
    }

    pub fn is_force_exit_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLock
                | Self::NoteMint
                | Self::SettlementReceipt
                | Self::ForcedExitClaim
                | Self::ChallengeWindow
                | Self::ReleaseAuthorization
                | Self::WalletRecovery
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVisibility {
    Public,
    Committed,
    Encrypted,
    WalletLocal,
}

impl EvidenceVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Committed => "committed",
            Self::Encrypted => "encrypted",
            Self::WalletLocal => "wallet_local",
        }
    }

    pub fn hides_wallet_metadata(self) -> bool {
        matches!(self, Self::Committed | Self::Encrypted | Self::WalletLocal)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Watch,
    Deferred,
    Blocked,
    Rejected,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_wallet(self) -> bool {
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
pub enum ReceiptBlocker {
    CargoRuntimeDeferred,
    SecurityAuditDeferred,
    MoneroFinalityTooShallow,
    ReorgGuardMissing,
    MissingPrivateNoteRoot,
    MissingSettlementReceipt,
    ReceiptNotWalletReconstructable,
    ChallengeWindowOpen,
    PqReleaseQuorumTooLow,
    ReserveInsufficient,
    PrivacyBudgetExceeded,
    FeeCapExceeded,
    OperatorCooperationRequired,
    ProductionSimulationOnly,
    PublicWalletMetadataLeak,
}

impl ReceiptBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::MoneroFinalityTooShallow => "monero_finality_too_shallow",
            Self::ReorgGuardMissing => "reorg_guard_missing",
            Self::MissingPrivateNoteRoot => "missing_private_note_root",
            Self::MissingSettlementReceipt => "missing_settlement_receipt",
            Self::ReceiptNotWalletReconstructable => "receipt_not_wallet_reconstructable",
            Self::ChallengeWindowOpen => "challenge_window_open",
            Self::PqReleaseQuorumTooLow => "pq_release_quorum_too_low",
            Self::ReserveInsufficient => "reserve_insufficient",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::OperatorCooperationRequired => "operator_cooperation_required",
            Self::ProductionSimulationOnly => "production_simulation_only",
            Self::PublicWalletMetadataLeak => "public_wallet_metadata_leak",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::SecurityAuditDeferred => "security_audit",
            Self::MoneroFinalityTooShallow => "monero_finality_policy",
            Self::ReorgGuardMissing => "monero_reorg_guard",
            Self::MissingPrivateNoteRoot => "private_note_state",
            Self::MissingSettlementReceipt => "settlement_receipt_verifier",
            Self::ReceiptNotWalletReconstructable => "wallet_reconstruction",
            Self::ChallengeWindowOpen => "challenge_window",
            Self::PqReleaseQuorumTooLow => "pq_release_authority",
            Self::ReserveInsufficient => "liquidity_reserve",
            Self::PrivacyBudgetExceeded => "privacy_budget",
            Self::FeeCapExceeded => "fee_policy",
            Self::OperatorCooperationRequired => "forced_exit_contract",
            Self::ProductionSimulationOnly => "release_gate",
            Self::PublicWalletMetadataLeak => "wallet_privacy",
        }
    }

    pub fn blocks_wallet(self) -> bool {
        matches!(
            self,
            Self::MoneroFinalityTooShallow
                | Self::ReorgGuardMissing
                | Self::MissingPrivateNoteRoot
                | Self::MissingSettlementReceipt
                | Self::ReceiptNotWalletReconstructable
                | Self::PqReleaseQuorumTooLow
                | Self::ReserveInsufficient
                | Self::PrivacyBudgetExceeded
                | Self::FeeCapExceeded
                | Self::OperatorCooperationRequired
                | Self::PublicWalletMetadataLeak
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionVerdict {
    ReplayableForWallet,
    ReplayableButDeferred,
    Watch,
    Blocked,
    Rejected,
}

impl ExecutionVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayableForWallet => "replayable_for_wallet",
            Self::ReplayableButDeferred => "replayable_but_deferred",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
        }
    }

    pub fn wallet_answer(self) -> &'static str {
        match self {
            Self::ReplayableForWallet | Self::ReplayableButDeferred => {
                "wallet_can_reconstruct_and_force_exit"
            }
            Self::Watch => "wallet_escape_needs_operator_independent_watch",
            Self::Blocked => "wallet_escape_blocked_until_blockers_clear",
            Self::Rejected => "wallet_escape_rejected_by_receipt",
        }
    }

    pub fn production_answer(self) -> &'static str {
        match self {
            Self::ReplayableForWallet => "not_production_ready_without_audit_and_runtime_gate",
            Self::ReplayableButDeferred => "blocked_by_deferred_cargo_or_audit_gate",
            Self::Watch => "watch_before_release",
            Self::Blocked => "blocked_before_release",
            Self::Rejected => "rejected_before_release",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub min_monero_confirmations: u64,
    pub force_exit_window_blocks: u64,
    pub release_finality_blocks: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_leak_units: u64,
    pub max_fee_atomic: u128,
    pub max_receipt_steps: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            force_exit_window_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
            release_finality_blocks: DEFAULT_RELEASE_FINALITY_BLOCKS,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_metadata_leak_units: DEFAULT_MAX_METADATA_LEAK_UNITS,
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
            max_receipt_steps: DEFAULT_MAX_RECEIPT_STEPS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptInput {
    pub receipt_id: String,
    pub stage: ExecutionStage,
    pub visibility: EvidenceVisibility,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub monero_confirmations: u64,
    pub has_reorg_guard: bool,
    pub has_private_note_root: bool,
    pub has_settlement_receipt: bool,
    pub wallet_reconstructable: bool,
    pub challenge_window_elapsed_blocks: u64,
    pub challenge_open: bool,
    pub pq_release_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub fee_atomic: u128,
    pub metadata_leak_units: u64,
    pub operator_cooperation_required: bool,
    pub cargo_runtime_executed: bool,
    pub security_audit_signed: bool,
    pub simulated_release_only: bool,
}

impl ExecutionReceiptInput {
    pub fn leaf(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "stage": self.stage.as_str(),
            "stage_ordinal": self.stage.ordinal(),
            "visibility": self.visibility.as_str(),
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "monero_confirmations": self.monero_confirmations,
            "has_reorg_guard": self.has_reorg_guard,
            "has_private_note_root": self.has_private_note_root,
            "has_settlement_receipt": self.has_settlement_receipt,
            "wallet_reconstructable": self.wallet_reconstructable,
            "challenge_window_elapsed_blocks": self.challenge_window_elapsed_blocks,
            "challenge_open": self.challenge_open,
            "pq_release_weight_bps": self.pq_release_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "fee_atomic": self.fee_atomic,
            "metadata_leak_units": self.metadata_leak_units,
            "operator_cooperation_required": self.operator_cooperation_required,
            "cargo_runtime_executed": self.cargo_runtime_executed,
            "security_audit_signed": self.security_audit_signed,
            "simulated_release_only": self.simulated_release_only,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptStep {
    pub receipt_id: String,
    pub index: u64,
    pub stage: ExecutionStage,
    pub visibility: EvidenceVisibility,
    pub status: ReceiptStatus,
    pub blocker: Option<ReceiptBlocker>,
    pub blocker_owner: Option<String>,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub step_root: String,
    pub wallet_safe: bool,
    pub production_safe: bool,
    pub operator_independent: bool,
}

impl ExecutionReceiptStep {
    pub fn from_input(index: u64, input: ExecutionReceiptInput, config: &Config) -> Self {
        let blocker = derive_blocker(&input, config);
        let status = derive_status(blocker, &input);
        let operator_independent = !input.operator_cooperation_required;
        let wallet_safe = !status.blocks_wallet() && operator_independent;
        let production_safe = !status.blocks_production()
            && input.cargo_runtime_executed
            && input.security_audit_signed
            && !input.simulated_release_only;
        let blocker_owner = blocker.map(|value| value.owner_lane().to_string());
        let leaf = json!({
            "receipt_id": input.receipt_id,
            "index": index,
            "stage": input.stage.as_str(),
            "visibility": input.visibility.as_str(),
            "status": status.as_str(),
            "blocker": blocker.map(ReceiptBlocker::as_str),
            "public_root": input.public_root,
            "committed_root": input.committed_root,
            "encrypted_root": input.encrypted_root,
            "wallet_recovery_root": input.wallet_recovery_root,
            "wallet_safe": wallet_safe,
            "production_safe": production_safe,
            "operator_independent": operator_independent,
        });
        let step_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-step",
            &[HashPart::Json(&leaf)],
            32,
        );
        Self {
            receipt_id: input.receipt_id,
            index,
            stage: input.stage,
            visibility: input.visibility,
            status,
            blocker,
            blocker_owner,
            public_root: input.public_root,
            committed_root: input.committed_root,
            encrypted_root: input.encrypted_root,
            wallet_recovery_root: input.wallet_recovery_root,
            step_root,
            wallet_safe,
            production_safe,
            operator_independent,
        }
    }

    pub fn leaf(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "index": self.index,
            "stage": self.stage.as_str(),
            "visibility": self.visibility.as_str(),
            "status": self.status.as_str(),
            "blocker": self.blocker.map(ReceiptBlocker::as_str),
            "blocker_owner": self.blocker_owner,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "step_root": self.step_root,
            "wallet_safe": self.wallet_safe,
            "production_safe": self.production_safe,
            "operator_independent": self.operator_independent,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceiptCounters {
    pub accepted: u64,
    pub watch: u64,
    pub deferred: u64,
    pub blocked: u64,
    pub rejected: u64,
    pub wallet_safe: u64,
    pub operator_independent: u64,
    pub production_safe: u64,
    pub force_exit_critical: u64,
}

impl ExecutionReceiptCounters {
    pub fn ingest(&mut self, step: &ExecutionReceiptStep) {
        match step.status {
            ReceiptStatus::Accepted => self.accepted += 1,
            ReceiptStatus::Watch => self.watch += 1,
            ReceiptStatus::Deferred => self.deferred += 1,
            ReceiptStatus::Blocked => self.blocked += 1,
            ReceiptStatus::Rejected => self.rejected += 1,
        }
        if step.wallet_safe {
            self.wallet_safe += 1;
        }
        if step.operator_independent {
            self.operator_independent += 1;
        }
        if step.production_safe {
            self.production_safe += 1;
        }
        if step.stage.is_force_exit_critical() {
            self.force_exit_critical += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.accepted + self.watch + self.deferred + self.blocked + self.rejected
    }

    pub fn has_wallet_blocker(&self) -> bool {
        self.blocked > 0 || self.rejected > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeavyGateExecutionReceipt {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub receipt_suite: String,
    pub receipt_id: String,
    pub verdict: ExecutionVerdict,
    pub wallet_answer: String,
    pub production_answer: String,
    pub receipt_root: String,
    pub transcript_root: String,
    pub step_root: String,
    pub blocker_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_root: String,
    pub wallet_recovery_root: String,
    pub counters: ExecutionReceiptCounters,
    pub blocker_counts: BTreeMap<String, u64>,
    pub steps: Vec<ExecutionReceiptStep>,
}

impl HeavyGateExecutionReceipt {
    pub fn from_steps(
        config: &Config,
        receipt_id: impl Into<String>,
        steps: Vec<ExecutionReceiptStep>,
    ) -> Self {
        let receipt_id = receipt_id.into();
        let mut counters = ExecutionReceiptCounters::default();
        let mut blocker_counts = BTreeMap::new();
        for step in &steps {
            counters.ingest(step);
            if let Some(blocker) = step.blocker {
                *blocker_counts
                    .entry(blocker.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }

        let step_leaves = steps
            .iter()
            .map(ExecutionReceiptStep::leaf)
            .collect::<Vec<_>>();
        let blocker_leaves = blocker_counts
            .iter()
            .map(|(blocker, count)| json!({ "blocker": blocker, "count": count }))
            .collect::<Vec<_>>();
        let public_leaves = steps
            .iter()
            .map(|step| json!({ "stage": step.stage.as_str(), "root": step.public_root }))
            .collect::<Vec<_>>();
        let committed_leaves = steps
            .iter()
            .map(|step| json!({ "stage": step.stage.as_str(), "root": step.committed_root }))
            .collect::<Vec<_>>();
        let encrypted_leaves = steps
            .iter()
            .map(|step| json!({ "stage": step.stage.as_str(), "root": step.encrypted_root }))
            .collect::<Vec<_>>();
        let wallet_leaves = steps
            .iter()
            .map(|step| json!({ "stage": step.stage.as_str(), "root": step.wallet_recovery_root }))
            .collect::<Vec<_>>();

        let step_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-steps",
            &step_leaves,
        );
        let blocker_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-blockers",
            &blocker_leaves,
        );
        let public_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-public",
            &public_leaves,
        );
        let committed_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-committed",
            &committed_leaves,
        );
        let encrypted_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-encrypted",
            &encrypted_leaves,
        );
        let wallet_recovery_root = merkle_root(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-wallet",
            &wallet_leaves,
        );

        let verdict = derive_verdict(&counters, &steps);
        let transcript_payload = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": config.chain_id,
            "receipt_id": receipt_id,
            "step_root": step_root,
            "blocker_root": blocker_root,
            "public_root": public_root,
            "committed_root": committed_root,
            "encrypted_root": encrypted_root,
            "wallet_recovery_root": wallet_recovery_root,
            "verdict": verdict.as_str(),
            "counters": counters,
        });
        let transcript_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt-transcript",
            &[HashPart::Json(&transcript_payload)],
            32,
        );
        let receipt_payload = json!({
            "receipt_suite": RECEIPT_SUITE,
            "transcript_root": transcript_root,
            "wallet_answer": verdict.wallet_answer(),
            "production_answer": verdict.production_answer(),
        });
        let receipt_root = domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-receipt",
            &[HashPart::Json(&receipt_payload)],
            32,
        );

        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: config.chain_id.clone(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            receipt_id,
            verdict,
            wallet_answer: verdict.wallet_answer().to_string(),
            production_answer: verdict.production_answer().to_string(),
            receipt_root,
            transcript_root,
            step_root,
            blocker_root,
            public_root,
            committed_root,
            encrypted_root,
            wallet_recovery_root,
            counters,
            blocker_counts,
            steps,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "receipt_suite": self.receipt_suite,
            "receipt_id": self.receipt_id,
            "verdict": self.verdict.as_str(),
            "wallet_answer": self.wallet_answer,
            "production_answer": self.production_answer,
            "receipt_root": self.receipt_root,
            "transcript_root": self.transcript_root,
            "step_root": self.step_root,
            "blocker_root": self.blocker_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_root": self.encrypted_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "counters": self.counters,
            "blocker_counts": self.blocker_counts,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub receipt: HeavyGateExecutionReceipt,
}

impl State {
    pub fn new() -> Self {
        Self::from_inputs(Config::default(), default_inputs())
    }

    pub fn from_inputs(config: Config, inputs: Vec<ExecutionReceiptInput>) -> Self {
        let steps = inputs
            .into_iter()
            .enumerate()
            .map(|(index, input)| ExecutionReceiptStep::from_input(index as u64, input, &config))
            .collect::<Vec<_>>();
        let receipt =
            HeavyGateExecutionReceipt::from_steps(&config, "canonical-heavy-gate-receipt", steps);
        Self { config, receipt }
    }

    pub fn ingest(&mut self, input: ExecutionReceiptInput) -> Result<()> {
        if self.receipt.steps.len() >= self.config.max_receipt_steps {
            return Err("canonical execution receipt step limit reached".to_string());
        }
        let mut inputs = self
            .receipt
            .steps
            .iter()
            .map(receipt_step_to_input)
            .collect::<Vec<_>>();
        inputs.push(input);
        *self = Self::from_inputs(self.config.clone(), inputs);
        Ok(())
    }

    pub fn can_wallet_force_exit(&self) -> bool {
        matches!(
            self.receipt.verdict,
            ExecutionVerdict::ReplayableForWallet | ExecutionVerdict::ReplayableButDeferred
        )
    }

    pub fn production_blocked(&self) -> bool {
        !matches!(self.receipt.verdict, ExecutionVerdict::ReplayableForWallet)
            || self.receipt.counters.deferred > 0
            || self.receipt.counters.watch > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": {
                "chain_id": self.config.chain_id,
                "min_monero_confirmations": self.config.min_monero_confirmations,
                "force_exit_window_blocks": self.config.force_exit_window_blocks,
                "release_finality_blocks": self.config.release_finality_blocks,
                "min_pq_weight_bps": self.config.min_pq_weight_bps,
                "min_reserve_coverage_bps": self.config.min_reserve_coverage_bps,
                "max_metadata_leak_units": self.config.max_metadata_leak_units,
                "max_fee_atomic": self.config.max_fee_atomic,
                "max_receipt_steps": self.config.max_receipt_steps,
            },
            "receipt": self.receipt.public_record(),
            "can_wallet_force_exit": self.can_wallet_force_exit(),
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
        "monero-l2-pq-bridge-exit-canonical-heavy-gate-execution-receipt-state",
        &[HashPart::Json(value)],
        32,
    )
}

fn derive_blocker(input: &ExecutionReceiptInput, config: &Config) -> Option<ReceiptBlocker> {
    if input.operator_cooperation_required {
        return Some(ReceiptBlocker::OperatorCooperationRequired);
    }
    if input.metadata_leak_units > config.max_metadata_leak_units {
        return Some(ReceiptBlocker::PrivacyBudgetExceeded);
    }
    if input.visibility == EvidenceVisibility::Public && input.stage.is_force_exit_critical() {
        return Some(ReceiptBlocker::PublicWalletMetadataLeak);
    }
    if input.monero_confirmations < config.min_monero_confirmations {
        return Some(ReceiptBlocker::MoneroFinalityTooShallow);
    }
    if !input.has_reorg_guard {
        return Some(ReceiptBlocker::ReorgGuardMissing);
    }
    if !input.has_private_note_root {
        return Some(ReceiptBlocker::MissingPrivateNoteRoot);
    }
    if !input.has_settlement_receipt
        && input.stage.ordinal() >= ExecutionStage::SettlementReceipt.ordinal()
    {
        return Some(ReceiptBlocker::MissingSettlementReceipt);
    }
    if !input.wallet_reconstructable && input.stage.is_force_exit_critical() {
        return Some(ReceiptBlocker::ReceiptNotWalletReconstructable);
    }
    if input.challenge_open
        || input.challenge_window_elapsed_blocks < config.force_exit_window_blocks
    {
        return Some(ReceiptBlocker::ChallengeWindowOpen);
    }
    if input.pq_release_weight_bps < config.min_pq_weight_bps
        && input.stage.ordinal() >= ExecutionStage::ReleaseAuthorization.ordinal()
    {
        return Some(ReceiptBlocker::PqReleaseQuorumTooLow);
    }
    if input.reserve_coverage_bps < config.min_reserve_coverage_bps
        && input.stage.ordinal() >= ExecutionStage::ForcedExitClaim.ordinal()
    {
        return Some(ReceiptBlocker::ReserveInsufficient);
    }
    if input.fee_atomic > config.max_fee_atomic {
        return Some(ReceiptBlocker::FeeCapExceeded);
    }
    if !input.cargo_runtime_executed {
        return Some(ReceiptBlocker::CargoRuntimeDeferred);
    }
    if !input.security_audit_signed {
        return Some(ReceiptBlocker::SecurityAuditDeferred);
    }
    if input.simulated_release_only {
        return Some(ReceiptBlocker::ProductionSimulationOnly);
    }
    None
}

fn derive_status(blocker: Option<ReceiptBlocker>, input: &ExecutionReceiptInput) -> ReceiptStatus {
    match blocker {
        None => ReceiptStatus::Accepted,
        Some(ReceiptBlocker::CargoRuntimeDeferred)
        | Some(ReceiptBlocker::SecurityAuditDeferred)
        | Some(ReceiptBlocker::ProductionSimulationOnly) => ReceiptStatus::Deferred,
        Some(ReceiptBlocker::ChallengeWindowOpen) => ReceiptStatus::Watch,
        Some(blocker) if blocker.blocks_wallet() => ReceiptStatus::Blocked,
        Some(_) if input.stage.is_force_exit_critical() => ReceiptStatus::Blocked,
        Some(_) => ReceiptStatus::Rejected,
    }
}

fn derive_verdict(
    counters: &ExecutionReceiptCounters,
    steps: &[ExecutionReceiptStep],
) -> ExecutionVerdict {
    if counters.rejected > 0 {
        return ExecutionVerdict::Rejected;
    }
    if counters.has_wallet_blocker() {
        return ExecutionVerdict::Blocked;
    }
    if counters.watch > 0 {
        return ExecutionVerdict::Watch;
    }
    let critical_steps = steps
        .iter()
        .filter(|step| step.stage.is_force_exit_critical())
        .count() as u64;
    if critical_steps > 0 && counters.wallet_safe >= critical_steps {
        if counters.deferred > 0 {
            ExecutionVerdict::ReplayableButDeferred
        } else {
            ExecutionVerdict::ReplayableForWallet
        }
    } else {
        ExecutionVerdict::Blocked
    }
}

fn receipt_step_to_input(step: &ExecutionReceiptStep) -> ExecutionReceiptInput {
    ExecutionReceiptInput {
        receipt_id: step.receipt_id.clone(),
        stage: step.stage,
        visibility: step.visibility,
        public_root: step.public_root.clone(),
        committed_root: step.committed_root.clone(),
        encrypted_root: step.encrypted_root.clone(),
        wallet_recovery_root: step.wallet_recovery_root.clone(),
        monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
        has_reorg_guard: true,
        has_private_note_root: true,
        has_settlement_receipt: true,
        wallet_reconstructable: step.wallet_safe,
        challenge_window_elapsed_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
        challenge_open: false,
        pq_release_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
        fee_atomic: DEFAULT_MAX_FEE_ATOMIC / 2,
        metadata_leak_units: 1,
        operator_cooperation_required: !step.operator_independent,
        cargo_runtime_executed: false,
        security_audit_signed: false,
        simulated_release_only: true,
    }
}

fn default_inputs() -> Vec<ExecutionReceiptInput> {
    let stages = [
        ExecutionStage::DepositLock,
        ExecutionStage::NoteMint,
        ExecutionStage::PrivateTransfer,
        ExecutionStage::ContractAction,
        ExecutionStage::SettlementReceipt,
        ExecutionStage::ForcedExitClaim,
        ExecutionStage::ChallengeWindow,
        ExecutionStage::ReleaseAuthorization,
        ExecutionStage::WalletRecovery,
    ];
    stages
        .iter()
        .enumerate()
        .map(|(index, stage)| default_input(index as u64, *stage))
        .collect()
}

fn default_input(index: u64, stage: ExecutionStage) -> ExecutionReceiptInput {
    let stage_name = stage.as_str();
    let public_payload = json!({
        "stage": stage_name,
        "index": index,
        "public": "redacted-stage-anchor",
    });
    let committed_payload = json!({
        "stage": stage_name,
        "index": index,
        "commitment": "canonical-bridge-exit-commitment",
    });
    let encrypted_payload = json!({
        "stage": stage_name,
        "index": index,
        "ciphertext": "wallet-encrypted-receipt-shard",
    });
    let wallet_payload = json!({
        "stage": stage_name,
        "index": index,
        "wallet": "local-reconstruction-hint",
    });
    ExecutionReceiptInput {
        receipt_id: format!("canonical-heavy-gate-receipt-{stage_name}"),
        stage,
        visibility: match stage {
            ExecutionStage::DepositLock => EvidenceVisibility::Committed,
            ExecutionStage::NoteMint => EvidenceVisibility::Committed,
            ExecutionStage::PrivateTransfer => EvidenceVisibility::Encrypted,
            ExecutionStage::ContractAction => EvidenceVisibility::Encrypted,
            ExecutionStage::SettlementReceipt => EvidenceVisibility::Committed,
            ExecutionStage::ForcedExitClaim => EvidenceVisibility::Committed,
            ExecutionStage::ChallengeWindow => EvidenceVisibility::Committed,
            ExecutionStage::ReleaseAuthorization => EvidenceVisibility::Committed,
            ExecutionStage::WalletRecovery => EvidenceVisibility::WalletLocal,
        },
        public_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-public",
            &[HashPart::Json(&public_payload)],
            32,
        ),
        committed_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-committed",
            &[HashPart::Json(&committed_payload)],
            32,
        ),
        encrypted_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-encrypted",
            &[HashPart::Json(&encrypted_payload)],
            32,
        ),
        wallet_recovery_root: domain_hash(
            "monero-l2-pq-bridge-exit-canonical-execution-wallet",
            &[HashPart::Json(&wallet_payload)],
            32,
        ),
        monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS + 6,
        has_reorg_guard: true,
        has_private_note_root: true,
        has_settlement_receipt: true,
        wallet_reconstructable: true,
        challenge_window_elapsed_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
        challenge_open: false,
        pq_release_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS + 800,
        reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS + 1_500,
        fee_atomic: DEFAULT_MAX_FEE_ATOMIC / 2,
        metadata_leak_units: 1,
        operator_cooperation_required: false,
        cargo_runtime_executed: false,
        security_audit_signed: false,
        simulated_release_only: true,
    }
}
