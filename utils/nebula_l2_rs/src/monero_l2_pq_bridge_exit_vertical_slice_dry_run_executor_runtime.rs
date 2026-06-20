use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceDryRunExecutorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_DRY_RUN_EXECUTOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-vertical-slice-dry-run-executor-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_DRY_RUN_EXECUTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTOR_SUITE: &str = "monero-private-l2-bridge-exit-dry-run-security-spine-v1";
pub const DEVNET_RUN_LABEL: &str = "devnet-dry-run-deposit-note-action-receipt-exit";
pub const DEFAULT_MIN_SEQUENCE_STEPS: u64 = 5;
pub const DEFAULT_MIN_STEP_ROOTS: u64 = 5;
pub const DEFAULT_MIN_RELEASE_BLOCKERS: u64 = 3;
pub const DEFAULT_MAX_DRY_RUNS: usize = 64;
pub const DEFAULT_DEPOSIT_AMOUNT_PICONERO: u128 = 800_000_000_000;
pub const DEFAULT_ACTION_FEE_PICONERO: u128 = 18_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStage {
    DepositAdmission,
    PrivateNoteMint,
    PrivateTransferOrContractAction,
    SettlementReceipt,
    WithdrawalForcedExitPackage,
}

impl ExecutionStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAdmission => "deposit_admission",
            Self::PrivateNoteMint => "private_note_mint",
            Self::PrivateTransferOrContractAction => "private_transfer_or_contract_action",
            Self::SettlementReceipt => "settlement_receipt",
            Self::WithdrawalForcedExitPackage => "withdrawal_forced_exit_package",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceMode {
    DeterministicDryRun,
    SimulatedAdapter,
    LiveAdapterRequired,
}

impl EvidenceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicDryRun => "deterministic_dry_run",
            Self::SimulatedAdapter => "simulated_adapter",
            Self::LiveAdapterRequired => "live_adapter_required",
        }
    }

    pub fn is_simulated(self) -> bool {
        matches!(self, Self::DeterministicDryRun | Self::SimulatedAdapter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Accepted,
    Simulated,
    Blocked,
}

impl StepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Simulated => "simulated",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    MinimalPrivateTransfer,
    ContractAction,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinimalPrivateTransfer => "minimal_private_transfer",
            Self::ContractAction => "contract_action",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPackageKind {
    CooperativeWithdrawal,
    ForcedExitFallback,
    DualPathPackage,
}

impl ExitPackageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CooperativeWithdrawal => "cooperative_withdrawal",
            Self::ForcedExitFallback => "forced_exit_fallback",
            Self::DualPathPackage => "dual_path_package",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlockerKind {
    SimulatedDepositWatcher,
    SimulatedPrivateProver,
    SimulatedSettlementAdapter,
    SimulatedReleaseAuthority,
    CargoChecksDeferred,
    ProductionReleaseDisabled,
}

impl ReleaseBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SimulatedDepositWatcher => "simulated_deposit_watcher",
            Self::SimulatedPrivateProver => "simulated_private_prover",
            Self::SimulatedSettlementAdapter => "simulated_settlement_adapter",
            Self::SimulatedReleaseAuthority => "simulated_release_authority",
            Self::CargoChecksDeferred => "cargo_checks_deferred",
            Self::ProductionReleaseDisabled => "production_release_disabled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub executor_suite: String,
    pub run_label: String,
    pub min_sequence_steps: u64,
    pub min_step_roots: u64,
    pub min_release_blockers: u64,
    pub deposit_amount_piconero: u128,
    pub action_fee_piconero: u128,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub block_production_on_simulated_evidence: bool,
    pub max_dry_runs: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            executor_suite: EXECUTOR_SUITE.to_string(),
            run_label: DEVNET_RUN_LABEL.to_string(),
            min_sequence_steps: DEFAULT_MIN_SEQUENCE_STEPS,
            min_step_roots: DEFAULT_MIN_STEP_ROOTS,
            min_release_blockers: DEFAULT_MIN_RELEASE_BLOCKERS,
            deposit_amount_piconero: DEFAULT_DEPOSIT_AMOUNT_PICONERO,
            action_fee_piconero: DEFAULT_ACTION_FEE_PICONERO,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            block_production_on_simulated_evidence: true,
            max_dry_runs: DEFAULT_MAX_DRY_RUNS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "executor_suite": self.executor_suite,
            "run_label": self.run_label,
            "min_sequence_steps": self.min_sequence_steps,
            "min_step_roots": self.min_step_roots,
            "min_release_blockers": self.min_release_blockers,
            "deposit_amount_piconero": self.deposit_amount_piconero.to_string(),
            "action_fee_piconero": self.action_fee_piconero.to_string(),
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "block_production_on_simulated_evidence": self.block_production_on_simulated_evidence,
            "max_dry_runs": self.max_dry_runs,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositAdmission {
    pub deposit_id: String,
    pub monero_lock_txid: String,
    pub custody_output_commitment: String,
    pub depositor_viewtag_commitment: String,
    pub watcher_quorum_root: String,
    pub admission_height: u64,
    pub finality_depth: u64,
    pub amount_piconero: u128,
    pub evidence_mode: EvidenceMode,
}

impl DepositAdmission {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "monero_lock_txid": self.monero_lock_txid,
            "custody_output_commitment": self.custody_output_commitment,
            "depositor_viewtag_commitment": self.depositor_viewtag_commitment,
            "watcher_quorum_root": self.watcher_quorum_root,
            "admission_height": self.admission_height,
            "finality_depth": self.finality_depth,
            "amount_piconero": self.amount_piconero.to_string(),
            "evidence_mode": self.evidence_mode.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_admission", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateNoteMint {
    pub note_id: String,
    pub deposit_id: String,
    pub note_commitment: String,
    pub amount_commitment: String,
    pub encrypted_note_root: String,
    pub note_tree_root_before: String,
    pub note_tree_root_after: String,
    pub nullifier_reservation_root: String,
    pub minted_height: u64,
    pub evidence_mode: EvidenceMode,
}

impl PrivateNoteMint {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "deposit_id": self.deposit_id,
            "note_commitment": self.note_commitment,
            "amount_commitment": self.amount_commitment,
            "encrypted_note_root": self.encrypted_note_root,
            "note_tree_root_before": self.note_tree_root_before,
            "note_tree_root_after": self.note_tree_root_after,
            "nullifier_reservation_root": self.nullifier_reservation_root,
            "minted_height": self.minted_height,
            "evidence_mode": self.evidence_mode.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_note_mint", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateAction {
    pub action_id: String,
    pub note_id: String,
    pub kind: ActionKind,
    pub input_note_root: String,
    pub output_note_root: String,
    pub contract_call_root: String,
    pub transfer_receipt_root: String,
    pub proof_transcript_root: String,
    pub fee_piconero: u128,
    pub executed_height: u64,
    pub evidence_mode: EvidenceMode,
}

impl PrivateAction {
    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "note_id": self.note_id,
            "kind": self.kind.as_str(),
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "contract_call_root": self.contract_call_root,
            "transfer_receipt_root": self.transfer_receipt_root,
            "proof_transcript_root": self.proof_transcript_root,
            "fee_piconero": self.fee_piconero.to_string(),
            "executed_height": self.executed_height,
            "evidence_mode": self.evidence_mode.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_action", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub action_id: String,
    pub settlement_batch_id: String,
    pub private_state_root: String,
    pub bridge_receipt_root: String,
    pub receipt_nullifier_root: String,
    pub release_intent_root: String,
    pub settled_height: u64,
    pub evidence_mode: EvidenceMode,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "settlement_batch_id": self.settlement_batch_id,
            "private_state_root": self.private_state_root,
            "bridge_receipt_root": self.bridge_receipt_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "release_intent_root": self.release_intent_root,
            "settled_height": self.settled_height,
            "evidence_mode": self.evidence_mode.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("settlement_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalForcedExitPackage {
    pub package_id: String,
    pub receipt_id: String,
    pub kind: ExitPackageKind,
    pub withdrawal_claim_root: String,
    pub forced_exit_claim_root: String,
    pub release_authority_root: String,
    pub challenge_window_root: String,
    pub user_recovery_bundle_root: String,
    pub timeout_height: u64,
    pub package_height: u64,
    pub evidence_mode: EvidenceMode,
}

impl WithdrawalForcedExitPackage {
    pub fn public_record(&self) -> Value {
        json!({
            "package_id": self.package_id,
            "receipt_id": self.receipt_id,
            "kind": self.kind.as_str(),
            "withdrawal_claim_root": self.withdrawal_claim_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "release_authority_root": self.release_authority_root,
            "challenge_window_root": self.challenge_window_root,
            "user_recovery_bundle_root": self.user_recovery_bundle_root,
            "timeout_height": self.timeout_height,
            "package_height": self.package_height,
            "evidence_mode": self.evidence_mode.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("withdrawal_forced_exit_package", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionStep {
    pub step_id: String,
    pub run_id: String,
    pub sequence: u64,
    pub stage: ExecutionStage,
    pub status: StepStatus,
    pub actor: String,
    pub subject_id: String,
    pub subject_root: String,
    pub previous_step_root: String,
    pub step_root: String,
    pub production_blocking: bool,
    pub simulated_evidence: bool,
}

impl ExecutionStep {
    pub fn public_record_without_root(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "stage": self.stage.as_str(),
            "status": self.status.as_str(),
            "actor": self.actor,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "previous_step_root": self.previous_step_root,
            "production_blocking": self.production_blocking,
            "simulated_evidence": self.simulated_evidence,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert(
                "step_root".to_string(),
                Value::String(self.step_root.clone()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.step_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseBlocker {
    pub blocker_id: String,
    pub kind: ReleaseBlockerKind,
    pub source_step_id: String,
    pub evidence_root: String,
    pub remediation: String,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
}

impl ReleaseBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "source_step_id": self.source_step_id,
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_blocker", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub dry_runs_executed: u64,
    pub sequence_steps: u64,
    pub simulated_steps: u64,
    pub production_blocking_steps: u64,
    pub release_blockers: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "dry_runs_executed": self.dry_runs_executed,
            "sequence_steps": self.sequence_steps,
            "simulated_steps": self.simulated_steps,
            "production_blocking_steps": self.production_blocking_steps,
            "release_blockers": self.release_blockers,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DryRunExecution {
    pub run_id: String,
    pub label: String,
    pub deposit: DepositAdmission,
    pub note_mint: PrivateNoteMint,
    pub private_action: PrivateAction,
    pub settlement_receipt: SettlementReceipt,
    pub exit_package: WithdrawalForcedExitPackage,
    pub steps: Vec<ExecutionStep>,
    pub blockers: BTreeMap<String, ReleaseBlocker>,
    pub step_root: String,
    pub blocker_root: String,
    pub transcript_root: String,
    pub production_release_allowed: bool,
}

impl DryRunExecution {
    pub fn public_record(&self) -> Value {
        json!({
            "run_id": self.run_id,
            "label": self.label,
            "deposit": self.deposit.public_record(),
            "note_mint": self.note_mint.public_record(),
            "private_action": self.private_action.public_record(),
            "settlement_receipt": self.settlement_receipt.public_record(),
            "exit_package": self.exit_package.public_record(),
            "steps": self.steps.iter().map(ExecutionStep::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.values().map(ReleaseBlocker::public_record).collect::<Vec<_>>(),
            "step_root": self.step_root,
            "blocker_root": self.blocker_root,
            "transcript_root": self.transcript_root,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        self.transcript_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub dry_run_root: String,
    pub step_root: String,
    pub blocker_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            dry_run_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-EMPTY-RUNS", &[]),
            step_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-EMPTY-STEPS", &[]),
            blocker_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-EMPTY-BLOCKERS", &[]),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "dry_run_root": self.dry_run_root,
            "step_root": self.step_root,
            "blocker_root": self.blocker_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-EXECUTOR-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.dry_run_root),
                HashPart::Str(&self.step_root),
                HashPart::Str(&self.blocker_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub executions: BTreeMap<String, DryRunExecution>,
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
            executions: BTreeMap::new(),
            counters,
            roots,
        };
        let _ = state.execute_devnet_dry_run();
        state
    }

    pub fn execute_devnet_dry_run(&mut self) -> Result<String> {
        let label = self.config.run_label.clone();
        let run_id = execution_id(&label, self.counters.dry_runs_executed + 1);
        let base_height = 1_240_000;
        let deposit = DepositAdmission {
            deposit_id: scoped_id(&run_id, "deposit-admission"),
            monero_lock_txid: commitment(&run_id, "monero-lock-txid", &["devnet", "xmr-lock"]),
            custody_output_commitment: commitment(
                &run_id,
                "custody-output",
                &["custody", "reserve", "locked"],
            ),
            depositor_viewtag_commitment: commitment(
                &run_id,
                "depositor-viewtag",
                &["wallet", "viewtag", "private"],
            ),
            watcher_quorum_root: commitment(
                &run_id,
                "watcher-quorum",
                &["watcher-a", "watcher-b", "watcher-c"],
            ),
            admission_height: base_height,
            finality_depth: 72,
            amount_piconero: self.config.deposit_amount_piconero,
            evidence_mode: EvidenceMode::SimulatedAdapter,
        };
        let note_mint = PrivateNoteMint {
            note_id: scoped_id(&run_id, "private-note-mint"),
            deposit_id: deposit.deposit_id.clone(),
            note_commitment: commitment(&run_id, "note-commitment", &["minted", "shielded"]),
            amount_commitment: commitment(&run_id, "amount", &["800000000000", "blinded"]),
            encrypted_note_root: commitment(&run_id, "encrypted-note", &["jamtis", "blob"]),
            note_tree_root_before: commitment(&run_id, "note-tree-before", &["empty"]),
            note_tree_root_after: commitment(&run_id, "note-tree-after", &["one-note"]),
            nullifier_reservation_root: commitment(
                &run_id,
                "nullifier-reservation",
                &["reserved", "unspent"],
            ),
            minted_height: base_height + 6,
            evidence_mode: EvidenceMode::DeterministicDryRun,
        };
        let private_action = PrivateAction {
            action_id: scoped_id(&run_id, "minimal-private-action"),
            note_id: note_mint.note_id.clone(),
            kind: ActionKind::ContractAction,
            input_note_root: note_mint.note_tree_root_after.clone(),
            output_note_root: commitment(&run_id, "note-tree-action-output", &["receipt-ready"]),
            contract_call_root: commitment(
                &run_id,
                "contract-call",
                &["bridge-exit", "minimal-action"],
            ),
            transfer_receipt_root: commitment(
                &run_id,
                "transfer-receipt",
                &["private-transfer", "accepted"],
            ),
            proof_transcript_root: commitment(
                &run_id,
                "proof-transcript",
                &["range", "nullifier", "authorization"],
            ),
            fee_piconero: self.config.action_fee_piconero,
            executed_height: base_height + 10,
            evidence_mode: EvidenceMode::DeterministicDryRun,
        };
        let settlement_receipt = SettlementReceipt {
            receipt_id: scoped_id(&run_id, "settlement-receipt"),
            action_id: private_action.action_id.clone(),
            settlement_batch_id: scoped_id(&run_id, "settlement-batch"),
            private_state_root: private_action.output_note_root.clone(),
            bridge_receipt_root: commitment(
                &run_id,
                "bridge-receipt",
                &["anchored", "release-intent"],
            ),
            receipt_nullifier_root: commitment(
                &run_id,
                "receipt-nullifier",
                &["one-time", "exit-bound"],
            ),
            release_intent_root: commitment(&run_id, "release-intent", &["withdrawal", "ready"]),
            settled_height: base_height + 18,
            evidence_mode: EvidenceMode::SimulatedAdapter,
        };
        let exit_package = WithdrawalForcedExitPackage {
            package_id: scoped_id(&run_id, "withdrawal-forced-exit-package"),
            receipt_id: settlement_receipt.receipt_id.clone(),
            kind: ExitPackageKind::DualPathPackage,
            withdrawal_claim_root: commitment(
                &run_id,
                "withdrawal-claim",
                &["receipt", "owner", "release"],
            ),
            forced_exit_claim_root: commitment(
                &run_id,
                "forced-exit-claim",
                &["timeout", "watchtower", "available"],
            ),
            release_authority_root: commitment(
                &run_id,
                "release-authority",
                &["ml-dsa", "slh-dsa", "threshold"],
            ),
            challenge_window_root: commitment(
                &run_id,
                "challenge-window",
                &["bounded", "open", "finalizable"],
            ),
            user_recovery_bundle_root: commitment(
                &run_id,
                "user-recovery",
                &["wallet", "receipt", "claim"],
            ),
            timeout_height: base_height + 720,
            package_height: base_height + 724,
            evidence_mode: EvidenceMode::SimulatedAdapter,
        };

        assert_linked_sequence(
            &deposit,
            &note_mint,
            &private_action,
            &settlement_receipt,
            &exit_package,
        )?;

        let subjects = vec![
            (
                ExecutionStage::DepositAdmission,
                "deposit-admission-watcher",
                deposit.deposit_id.clone(),
                deposit.state_root(),
                deposit.evidence_mode,
            ),
            (
                ExecutionStage::PrivateNoteMint,
                "private-note-minter",
                note_mint.note_id.clone(),
                note_mint.state_root(),
                note_mint.evidence_mode,
            ),
            (
                ExecutionStage::PrivateTransferOrContractAction,
                "private-l2-action-executor",
                private_action.action_id.clone(),
                private_action.state_root(),
                private_action.evidence_mode,
            ),
            (
                ExecutionStage::SettlementReceipt,
                "settlement-receipt-anchor",
                settlement_receipt.receipt_id.clone(),
                settlement_receipt.state_root(),
                settlement_receipt.evidence_mode,
            ),
            (
                ExecutionStage::WithdrawalForcedExitPackage,
                "forced-exit-packager",
                exit_package.package_id.clone(),
                exit_package.state_root(),
                exit_package.evidence_mode,
            ),
        ];
        let mut steps = Vec::with_capacity(subjects.len());
        let mut previous_step_root = genesis_step_root(&run_id);
        for (index, (stage, actor, subject_id, subject_root, evidence_mode)) in
            subjects.into_iter().enumerate()
        {
            let sequence = index as u64 + 1;
            let simulated_evidence = evidence_mode.is_simulated();
            let production_blocking =
                simulated_evidence && self.config.block_production_on_simulated_evidence;
            let status = if production_blocking {
                StepStatus::Simulated
            } else {
                StepStatus::Accepted
            };
            let step_id = step_id(&run_id, sequence, stage, &subject_root);
            let seed = json!({
                "run_id": run_id,
                "sequence": sequence,
                "stage": stage.as_str(),
                "subject_id": subject_id,
                "subject_root": subject_root,
                "previous_step_root": previous_step_root,
                "simulated_evidence": simulated_evidence,
                "production_blocking": production_blocking,
            });
            let step_root = record_root("execution_step", &seed);
            let step = ExecutionStep {
                step_id,
                run_id: run_id.clone(),
                sequence,
                stage,
                status,
                actor: actor.to_string(),
                subject_id,
                subject_root,
                previous_step_root,
                step_root: step_root.clone(),
                production_blocking,
                simulated_evidence,
            };
            previous_step_root = step_root;
            steps.push(step);
        }

        let blockers = build_release_blockers(&self.config, &steps);
        let step_records = steps
            .iter()
            .map(ExecutionStep::public_record)
            .collect::<Vec<_>>();
        let blocker_records = blockers
            .values()
            .map(ReleaseBlocker::public_record)
            .collect::<Vec<_>>();
        let step_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-EXECUTION-STEPS",
            &step_records,
        );
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-BLOCKERS",
            &blocker_records,
        );
        let production_release_allowed = self.config.production_release_allowed
            && blockers.values().all(|blocker| !blocker.blocks_production);
        let transcript_seed = json!({
            "run_id": run_id,
            "step_root": step_root,
            "blocker_root": blocker_root,
            "production_release_allowed": production_release_allowed,
        });
        let transcript_root = record_root("dry_run_execution", &transcript_seed);
        let execution = DryRunExecution {
            run_id: run_id.clone(),
            label,
            deposit,
            note_mint,
            private_action,
            settlement_receipt,
            exit_package,
            steps,
            blockers,
            step_root,
            blocker_root,
            transcript_root,
            production_release_allowed,
        };
        self.record_execution(execution)?;
        Ok(run_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "executor_suite": self.config.executor_suite,
            "config": self.config.public_record(),
            "latest_execution": self.executions.values().next_back().map(DryRunExecution::public_record),
            "execution_count": self.executions.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_execution(&mut self, execution: DryRunExecution) -> Result<()> {
        if execution.steps.len() < self.config.min_sequence_steps as usize {
            return Err("dry-run sequence did not produce enough execution steps".to_string());
        }
        if execution.steps.len() < self.config.min_step_roots as usize {
            return Err("dry-run sequence did not produce enough step roots".to_string());
        }
        if execution.blockers.len() < self.config.min_release_blockers as usize {
            return Err("dry-run sequence did not produce enough release blockers".to_string());
        }
        self.counters.dry_runs_executed += 1;
        self.counters.sequence_steps += execution.steps.len() as u64;
        self.counters.simulated_steps += execution
            .steps
            .iter()
            .filter(|step| step.simulated_evidence)
            .count() as u64;
        self.counters.production_blocking_steps += execution
            .steps
            .iter()
            .filter(|step| step.production_blocking)
            .count() as u64;
        self.counters.release_blockers += execution.blockers.len() as u64;
        self.counters.user_release_blockers += execution
            .blockers
            .values()
            .filter(|blocker| blocker.blocks_user_release)
            .count() as u64;
        self.counters.production_blockers += execution
            .blockers
            .values()
            .filter(|blocker| blocker.blocks_production)
            .count() as u64;
        self.executions.insert(execution.run_id.clone(), execution);
        while self.executions.len() > self.config.max_dry_runs {
            let first_key = self.executions.keys().next().cloned();
            if let Some(key) = first_key {
                self.executions.remove(&key);
            } else {
                break;
            }
        }
        self.refresh_roots();
        Ok(())
    }

    fn refresh_roots(&mut self) {
        let executions = self
            .executions
            .values()
            .map(DryRunExecution::public_record)
            .collect::<Vec<_>>();
        let steps = self
            .executions
            .values()
            .flat_map(|execution| execution.steps.iter().map(ExecutionStep::public_record))
            .collect::<Vec<_>>();
        let blockers = self
            .executions
            .values()
            .flat_map(|execution| {
                execution
                    .blockers
                    .values()
                    .map(ReleaseBlocker::public_record)
            })
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            dry_run_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-EXECUTIONS",
                &executions,
            ),
            step_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-ALL-STEPS",
                &steps,
            ),
            blocker_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-ALL-BLOCKERS",
                &blockers,
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

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn execution_id(label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-EXECUTION-ID",
        &[HashPart::Str(label), HashPart::U64(ordinal)],
        32,
    )
}

pub fn step_id(run_id: &str, sequence: u64, stage: ExecutionStage, subject_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-STEP-ID",
        &[
            HashPart::Str(run_id),
            HashPart::U64(sequence),
            HashPart::Str(stage.as_str()),
            HashPart::Str(subject_root),
        ],
        32,
    )
}

pub fn blocker_id(kind: ReleaseBlockerKind, source_step_id: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-BLOCKER-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_step_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn commitment(run_id: &str, label: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({ "run_id": run_id, "label": label, "part": part }))
        .collect::<Vec<_>>();
    let root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-COMMITMENT-LEAVES",
        &leaves,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(run_id),
            HashPart::Str(label),
            HashPart::Str(&root),
        ],
        32,
    )
}

pub fn scoped_id(run_id: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-SCOPED-ID",
        &[HashPart::Str(run_id), HashPart::Str(label)],
        20,
    )
}

fn genesis_step_root(run_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-DRY-RUN-GENESIS-STEP",
        &[HashPart::Str(run_id)],
        32,
    )
}

fn build_release_blockers(
    config: &Config,
    steps: &[ExecutionStep],
) -> BTreeMap<String, ReleaseBlocker> {
    let mut blockers = BTreeMap::new();
    for step in steps.iter().filter(|step| step.production_blocking) {
        let kind = match step.stage {
            ExecutionStage::DepositAdmission => ReleaseBlockerKind::SimulatedDepositWatcher,
            ExecutionStage::PrivateNoteMint | ExecutionStage::PrivateTransferOrContractAction => {
                ReleaseBlockerKind::SimulatedPrivateProver
            }
            ExecutionStage::SettlementReceipt => ReleaseBlockerKind::SimulatedSettlementAdapter,
            ExecutionStage::WithdrawalForcedExitPackage => {
                ReleaseBlockerKind::SimulatedReleaseAuthority
            }
        };
        let evidence_root = record_root(
            "simulated_evidence_blocker",
            &json!({
                "step_id": step.step_id,
                "stage": step.stage.as_str(),
                "subject_root": step.subject_root,
                "step_root": step.step_root,
            }),
        );
        let blocker = ReleaseBlocker {
            blocker_id: blocker_id(kind, &step.step_id, &evidence_root),
            kind,
            source_step_id: step.step_id.clone(),
            evidence_root,
            remediation: remediation_for_kind(kind).to_string(),
            blocks_user_release: false,
            blocks_production: true,
        };
        blockers.insert(blocker.blocker_id.clone(), blocker);
    }
    if config.cargo_checks_deferred {
        let source_step_id = steps
            .last()
            .map(|step| step.step_id.clone())
            .unwrap_or_else(|| scoped_id("empty-dry-run", "cargo-deferred"));
        let evidence_root = record_root(
            "cargo_checks_deferred",
            &json!({
                "cargo_checks_deferred": config.cargo_checks_deferred,
                "executor_suite": config.executor_suite,
            }),
        );
        let kind = ReleaseBlockerKind::CargoChecksDeferred;
        let blocker = ReleaseBlocker {
            blocker_id: blocker_id(kind, &source_step_id, &evidence_root),
            kind,
            source_step_id,
            evidence_root,
            remediation: remediation_for_kind(kind).to_string(),
            blocks_user_release: false,
            blocks_production: true,
        };
        blockers.insert(blocker.blocker_id.clone(), blocker);
    }
    if !config.production_release_allowed {
        let source_step_id = steps
            .last()
            .map(|step| step.step_id.clone())
            .unwrap_or_else(|| scoped_id("empty-dry-run", "production-disabled"));
        let evidence_root = record_root(
            "production_release_disabled",
            &json!({
                "production_release_allowed": config.production_release_allowed,
                "block_production_on_simulated_evidence": config.block_production_on_simulated_evidence,
            }),
        );
        let kind = ReleaseBlockerKind::ProductionReleaseDisabled;
        let blocker = ReleaseBlocker {
            blocker_id: blocker_id(kind, &source_step_id, &evidence_root),
            kind,
            source_step_id,
            evidence_root,
            remediation: remediation_for_kind(kind).to_string(),
            blocks_user_release: false,
            blocks_production: true,
        };
        blockers.insert(blocker.blocker_id.clone(), blocker);
    }
    blockers
}

fn remediation_for_kind(kind: ReleaseBlockerKind) -> &'static str {
    match kind {
        ReleaseBlockerKind::SimulatedDepositWatcher => {
            "replace dry-run deposit watcher evidence with live Monero lock observations"
        }
        ReleaseBlockerKind::SimulatedPrivateProver => {
            "replace deterministic private-note and action proofs with live prover transcripts"
        }
        ReleaseBlockerKind::SimulatedSettlementAdapter => {
            "anchor settlement receipt through the live settlement adapter"
        }
        ReleaseBlockerKind::SimulatedReleaseAuthority => {
            "bind withdrawal and forced-exit package to live release authority signatures"
        }
        ReleaseBlockerKind::CargoChecksDeferred => {
            "run the cargo verification lane before production release"
        }
        ReleaseBlockerKind::ProductionReleaseDisabled => {
            "flip production release only after all dry-run blockers are cleared"
        }
    }
}

fn assert_linked_sequence(
    deposit: &DepositAdmission,
    note_mint: &PrivateNoteMint,
    private_action: &PrivateAction,
    settlement_receipt: &SettlementReceipt,
    exit_package: &WithdrawalForcedExitPackage,
) -> Result<()> {
    if note_mint.deposit_id != deposit.deposit_id {
        return Err("private note mint does not bind to deposit admission".to_string());
    }
    if private_action.note_id != note_mint.note_id {
        return Err("private action does not bind to minted private note".to_string());
    }
    if settlement_receipt.action_id != private_action.action_id {
        return Err("settlement receipt does not bind to private action".to_string());
    }
    if exit_package.receipt_id != settlement_receipt.receipt_id {
        return Err(
            "withdrawal/forced-exit package does not bind to settlement receipt".to_string(),
        );
    }
    Ok(())
}
