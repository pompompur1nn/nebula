use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceExecutionTraceHarnessRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_EXECUTION_TRACE_HARNESS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-vertical-slice-execution-trace-harness-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_EXECUTION_TRACE_HARNESS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const TRACE_SUITE: &str =
    "monero-l2-pq-bridge-exit-deposit-note-action-receipt-withdrawal-trace-v1";
pub const DEVNET_TRACE_LABEL: &str = "devnet-private-bridge-exit-execution-trace";
pub const DEFAULT_MIN_TRACE_STEPS: u64 = 5;
pub const DEFAULT_MIN_PQ_EVIDENCE_ITEMS: u64 = 4;
pub const DEFAULT_MIN_PRIVACY_BUDGETS: u64 = 4;
pub const DEFAULT_MAX_FEE_PICONERO: u128 = 40_000;
pub const DEFAULT_MAX_WITHDRAWAL_DELAY_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_TRACE_RECORDS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStepKind {
    DepositLockObserved,
    PrivateL2NoteState,
    PrivateTransferOrContractAction,
    SettlementReceipt,
    WithdrawalForcedExitEvidence,
}

impl TraceStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLockObserved => "deposit_lock_observed",
            Self::PrivateL2NoteState => "private_l2_note_state",
            Self::PrivateTransferOrContractAction => "private_transfer_or_contract_action",
            Self::SettlementReceipt => "settlement_receipt",
            Self::WithdrawalForcedExitEvidence => "withdrawal_forced_exit_evidence",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Recorded,
    Watch,
    Rejected,
}

impl TraceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }

    pub fn admits_release(self) -> bool {
        self == Self::Recorded
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateActionKind {
    Transfer,
    ContractCall,
    ContractSettlement,
    ForcedExitPreparation,
}

impl PrivateActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::ContractSettlement => "contract_settlement",
            Self::ForcedExitPreparation => "forced_exit_preparation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPathKind {
    CooperativeWithdrawal,
    ForcedExit,
    WatchtowerEscalation,
}

impl ExitPathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CooperativeWithdrawal => "cooperative_withdrawal",
            Self::ForcedExit => "forced_exit",
            Self::WatchtowerEscalation => "watchtower_escalation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqEvidenceKind {
    MlDsaAuthorityAttestation,
    SlhDsaFallbackAttestation,
    MerkleCheckpoint,
    WatcherQuorumCertificate,
    HybridKeyRotationReceipt,
    ReplayFenceNullifier,
}

impl PqEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsaAuthorityAttestation => "ml_dsa_authority_attestation",
            Self::SlhDsaFallbackAttestation => "slh_dsa_fallback_attestation",
            Self::MerkleCheckpoint => "merkle_checkpoint",
            Self::WatcherQuorumCertificate => "watcher_quorum_certificate",
            Self::HybridKeyRotationReceipt => "hybrid_key_rotation_receipt",
            Self::ReplayFenceNullifier => "replay_fence_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetKind {
    Linkability,
    ViewKeyDisclosure,
    ReceiptMetadata,
    DecoySetEntropy,
    TimingCorrelation,
}

impl PrivacyBudgetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linkability => "linkability",
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::ReceiptMetadata => "receipt_metadata",
            Self::DecoySetEntropy => "decoy_set_entropy",
            Self::TimingCorrelation => "timing_correlation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessVerdict {
    Pass,
    Watch,
    Fail,
}

impl HarnessVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Fail => "fail",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub trace_suite: String,
    pub trace_label: String,
    pub min_trace_steps: u64,
    pub min_pq_evidence_items: u64,
    pub min_privacy_budgets: u64,
    pub max_fee_piconero: u128,
    pub max_withdrawal_delay_blocks: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub low_fee_mode_required: bool,
    pub fail_closed_on_adversarial_flags: bool,
    pub max_trace_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            trace_suite: TRACE_SUITE.to_string(),
            trace_label: DEVNET_TRACE_LABEL.to_string(),
            min_trace_steps: DEFAULT_MIN_TRACE_STEPS,
            min_pq_evidence_items: DEFAULT_MIN_PQ_EVIDENCE_ITEMS,
            min_privacy_budgets: DEFAULT_MIN_PRIVACY_BUDGETS,
            max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
            max_withdrawal_delay_blocks: DEFAULT_MAX_WITHDRAWAL_DELAY_BLOCKS,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            low_fee_mode_required: true,
            fail_closed_on_adversarial_flags: true,
            max_trace_records: DEFAULT_MAX_TRACE_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "trace_suite": self.trace_suite,
            "trace_label": self.trace_label,
            "min_trace_steps": self.min_trace_steps,
            "min_pq_evidence_items": self.min_pq_evidence_items,
            "min_privacy_budgets": self.min_privacy_budgets,
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "max_withdrawal_delay_blocks": self.max_withdrawal_delay_blocks,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "low_fee_mode_required": self.low_fee_mode_required,
            "fail_closed_on_adversarial_flags": self.fail_closed_on_adversarial_flags,
            "max_trace_records": self.max_trace_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLockEvidence {
    pub deposit_id: String,
    pub monero_txid: String,
    pub lock_output_commitment: String,
    pub custody_address_commitment: String,
    pub amount_piconero: u128,
    pub observed_height: u64,
    pub finality_depth: u64,
    pub watcher_set_root: String,
    pub lock_transcript_root: String,
}

impl DepositLockEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "monero_txid": self.monero_txid,
            "lock_output_commitment": self.lock_output_commitment,
            "custody_address_commitment": self.custody_address_commitment,
            "amount_piconero": self.amount_piconero.to_string(),
            "observed_height": self.observed_height,
            "finality_depth": self.finality_depth,
            "watcher_set_root": self.watcher_set_root,
            "lock_transcript_root": self.lock_transcript_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deposit_lock", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateNoteState {
    pub note_id: String,
    pub deposit_id: String,
    pub note_commitment: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub nullifier_commitment: String,
    pub encrypted_note_blob_root: String,
    pub amount_commitment: String,
    pub minted_height: u64,
}

impl PrivateNoteState {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "deposit_id": self.deposit_id,
            "note_commitment": self.note_commitment,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "nullifier_commitment": self.nullifier_commitment,
            "encrypted_note_blob_root": self.encrypted_note_blob_root,
            "amount_commitment": self.amount_commitment,
            "minted_height": self.minted_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_note_state", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateActionTrace {
    pub action_id: String,
    pub note_id: String,
    pub action_kind: PrivateActionKind,
    pub contract_commitment: String,
    pub input_state_root: String,
    pub output_state_root: String,
    pub action_receipt_root: String,
    pub proof_root: String,
    pub fee_piconero: u128,
    pub sequencer_batch_id: String,
    pub executed_height: u64,
}

impl PrivateActionTrace {
    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "note_id": self.note_id,
            "action_kind": self.action_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "input_state_root": self.input_state_root,
            "output_state_root": self.output_state_root,
            "action_receipt_root": self.action_receipt_root,
            "proof_root": self.proof_root,
            "fee_piconero": self.fee_piconero.to_string(),
            "sequencer_batch_id": self.sequencer_batch_id,
            "executed_height": self.executed_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_action_trace", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub action_id: String,
    pub settlement_batch_id: String,
    pub bridge_receipt_root: String,
    pub l2_state_root: String,
    pub monero_release_commitment: String,
    pub settlement_height: u64,
    pub fee_paid_piconero: u128,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "settlement_batch_id": self.settlement_batch_id,
            "bridge_receipt_root": self.bridge_receipt_root,
            "l2_state_root": self.l2_state_root,
            "monero_release_commitment": self.monero_release_commitment,
            "settlement_height": self.settlement_height,
            "fee_paid_piconero": self.fee_paid_piconero.to_string(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("settlement_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawalForcedExitEvidence {
    pub evidence_id: String,
    pub receipt_id: String,
    pub exit_path: ExitPathKind,
    pub withdrawal_claim_root: String,
    pub forced_exit_claim_root: String,
    pub timeout_height: u64,
    pub evidence_height: u64,
    pub release_authority_root: String,
    pub challenge_window_root: String,
}

impl WithdrawalForcedExitEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "receipt_id": self.receipt_id,
            "exit_path": self.exit_path.as_str(),
            "withdrawal_claim_root": self.withdrawal_claim_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "timeout_height": self.timeout_height,
            "evidence_height": self.evidence_height,
            "release_authority_root": self.release_authority_root,
            "challenge_window_root": self.challenge_window_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("withdrawal_forced_exit_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqControlPlaneEvidence {
    pub evidence_id: String,
    pub trace_id: String,
    pub kind: PqEvidenceKind,
    pub authority_epoch: u64,
    pub signer_set_root: String,
    pub signature_commitment_root: String,
    pub transcript_root: String,
    pub accepted: bool,
}

impl PqControlPlaneEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "trace_id": self.trace_id,
            "kind": self.kind.as_str(),
            "authority_epoch": self.authority_epoch,
            "signer_set_root": self.signer_set_root,
            "signature_commitment_root": self.signature_commitment_root,
            "transcript_root": self.transcript_root,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("pq_control_plane_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyMetadataBudget {
    pub budget_id: String,
    pub trace_id: String,
    pub kind: PrivacyBudgetKind,
    pub limit_units: u64,
    pub consumed_units: u64,
    pub disclosure_root: String,
    pub mitigation_root: String,
}

impl PrivacyMetadataBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "trace_id": self.trace_id,
            "kind": self.kind.as_str(),
            "limit_units": self.limit_units,
            "consumed_units": self.consumed_units,
            "disclosure_root": self.disclosure_root,
            "mitigation_root": self.mitigation_root,
            "within_budget": self.within_budget(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("privacy_metadata_budget", &self.public_record())
    }

    pub fn within_budget(&self) -> bool {
        self.consumed_units <= self.limit_units
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeLimit {
    pub limit_id: String,
    pub trace_id: String,
    pub max_fee_piconero: u128,
    pub observed_fee_piconero: u128,
    pub sponsor_credit_piconero: u128,
    pub relay_delay_blocks: u64,
    pub within_limit: bool,
}

impl LowFeeLimit {
    pub fn public_record(&self) -> Value {
        json!({
            "limit_id": self.limit_id,
            "trace_id": self.trace_id,
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "observed_fee_piconero": self.observed_fee_piconero.to_string(),
            "sponsor_credit_piconero": self.sponsor_credit_piconero.to_string(),
            "relay_delay_blocks": self.relay_delay_blocks,
            "within_limit": self.within_limit,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("low_fee_limit", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AdversarialFlags {
    pub reorg_risk_detected: bool,
    pub watcher_quorum_split: bool,
    pub invalid_pq_signature_seen: bool,
    pub privacy_budget_exceeded: bool,
    pub fee_limit_exceeded: bool,
    pub forced_exit_censorship: bool,
    pub replay_attempt_detected: bool,
}

impl AdversarialFlags {
    pub fn public_record(&self) -> Value {
        json!({
            "reorg_risk_detected": self.reorg_risk_detected,
            "watcher_quorum_split": self.watcher_quorum_split,
            "invalid_pq_signature_seen": self.invalid_pq_signature_seen,
            "privacy_budget_exceeded": self.privacy_budget_exceeded,
            "fee_limit_exceeded": self.fee_limit_exceeded,
            "forced_exit_censorship": self.forced_exit_censorship,
            "replay_attempt_detected": self.replay_attempt_detected,
            "any": self.any(),
        })
    }

    pub fn any(&self) -> bool {
        self.reorg_risk_detected
            || self.watcher_quorum_split
            || self.invalid_pq_signature_seen
            || self.privacy_budget_exceeded
            || self.fee_limit_exceeded
            || self.forced_exit_censorship
            || self.replay_attempt_detected
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionTraceStep {
    pub step_id: String,
    pub trace_id: String,
    pub sequence: u64,
    pub kind: TraceStepKind,
    pub status: TraceStatus,
    pub actor: String,
    pub height: u64,
    pub subject_root: String,
    pub previous_step_root: Option<String>,
    pub notes: Vec<String>,
}

impl ExecutionTraceStep {
    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "trace_id": self.trace_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "actor": self.actor,
            "height": self.height,
            "subject_root": self.subject_root,
            "previous_step_root": self.previous_step_root,
            "notes": self.notes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution_trace_step", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionTrace {
    pub trace_id: String,
    pub label: String,
    pub deposit_lock: DepositLockEvidence,
    pub private_note: PrivateNoteState,
    pub private_action: PrivateActionTrace,
    pub settlement_receipt: SettlementReceipt,
    pub withdrawal_evidence: WithdrawalForcedExitEvidence,
    pub pq_evidence: Vec<PqControlPlaneEvidence>,
    pub privacy_budgets: Vec<PrivacyMetadataBudget>,
    pub low_fee_limit: LowFeeLimit,
    pub adversarial_flags: AdversarialFlags,
    pub steps: Vec<ExecutionTraceStep>,
    pub verdict: HarnessVerdict,
}

impl ExecutionTrace {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "label": self.label,
            "deposit_lock": self.deposit_lock.public_record(),
            "private_note": self.private_note.public_record(),
            "private_action": self.private_action.public_record(),
            "settlement_receipt": self.settlement_receipt.public_record(),
            "withdrawal_evidence": self.withdrawal_evidence.public_record(),
            "pq_evidence": self.pq_evidence.iter().map(PqControlPlaneEvidence::public_record).collect::<Vec<_>>(),
            "privacy_budgets": self.privacy_budgets.iter().map(PrivacyMetadataBudget::public_record).collect::<Vec<_>>(),
            "low_fee_limit": self.low_fee_limit.public_record(),
            "adversarial_flags": self.adversarial_flags.public_record(),
            "steps": self.steps.iter().map(ExecutionTraceStep::public_record).collect::<Vec<_>>(),
            "verdict": self.verdict.as_str(),
            "roots": {
                "deposit_lock_root": self.deposit_lock.state_root(),
                "private_note_root": self.private_note.state_root(),
                "private_action_root": self.private_action.state_root(),
                "settlement_receipt_root": self.settlement_receipt.state_root(),
                "withdrawal_evidence_root": self.withdrawal_evidence.state_root(),
                "pq_evidence_root": self.pq_evidence_root(),
                "privacy_budget_root": self.privacy_budget_root(),
                "step_root": self.step_root(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution_trace", &self.public_record())
    }

    pub fn pq_evidence_root(&self) -> String {
        list_root(
            "pq_control_plane_evidence",
            self.pq_evidence
                .iter()
                .map(PqControlPlaneEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn privacy_budget_root(&self) -> String {
        list_root(
            "privacy_metadata_budgets",
            self.privacy_budgets
                .iter()
                .map(PrivacyMetadataBudget::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn step_root(&self) -> String {
        list_root(
            "execution_trace_steps",
            self.steps
                .iter()
                .map(ExecutionTraceStep::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn successful_step_count(&self) -> u64 {
        self.steps
            .iter()
            .filter(|step| step.status.admits_release())
            .count() as u64
    }

    pub fn accepted_pq_evidence_count(&self) -> u64 {
        self.pq_evidence
            .iter()
            .filter(|evidence| evidence.accepted)
            .count() as u64
    }

    pub fn privacy_budget_count_within_limit(&self) -> u64 {
        self.privacy_budgets
            .iter()
            .filter(|budget| budget.within_budget())
            .count() as u64
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HarnessReport {
    pub report_id: String,
    pub trace_id: String,
    pub verdict: HarnessVerdict,
    pub trace_root: String,
    pub step_root: String,
    pub pq_evidence_root: String,
    pub privacy_budget_root: String,
    pub low_fee_limit_root: String,
    pub adversarial_flag_root: String,
    pub successful_steps: u64,
    pub accepted_pq_evidence: u64,
    pub privacy_budgets_within_limit: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub blockers: Vec<String>,
}

impl HarnessReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "trace_id": self.trace_id,
            "verdict": self.verdict.as_str(),
            "trace_root": self.trace_root,
            "step_root": self.step_root,
            "pq_evidence_root": self.pq_evidence_root,
            "privacy_budget_root": self.privacy_budget_root,
            "low_fee_limit_root": self.low_fee_limit_root,
            "adversarial_flag_root": self.adversarial_flag_root,
            "successful_steps": self.successful_steps,
            "accepted_pq_evidence": self.accepted_pq_evidence,
            "privacy_budgets_within_limit": self.privacy_budgets_within_limit,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "blockers": self.blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("harness_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub traces: BTreeMap<String, ExecutionTrace>,
    pub reports: BTreeMap<String, HarnessReport>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            traces: BTreeMap::new(),
            reports: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let trace = devnet_execution_trace();
        let report = state.assess_trace(&trace);
        state.traces.insert(trace.trace_id.clone(), trace);
        state.reports.insert(report.report_id.clone(), report);
        state
    }

    pub fn insert_trace(&mut self, trace: ExecutionTrace) -> Result<HarnessReport> {
        if self.traces.len() >= self.config.max_trace_records {
            return Err("trace record capacity exhausted".to_string());
        }
        self.validate_trace(&trace)?;
        let report = self.assess_trace(&trace);
        self.reports
            .insert(report.report_id.clone(), report.clone());
        self.traces.insert(trace.trace_id.clone(), trace);
        Ok(report)
    }

    pub fn validate_trace(&self, trace: &ExecutionTrace) -> Result<()> {
        if trace.steps.len() < self.config.min_trace_steps as usize {
            return Err("trace has fewer steps than the configured minimum".to_string());
        }
        if trace.accepted_pq_evidence_count() < self.config.min_pq_evidence_items {
            return Err("trace has insufficient accepted pq control-plane evidence".to_string());
        }
        if trace.privacy_budget_count_within_limit() < self.config.min_privacy_budgets {
            return Err("trace has insufficient privacy metadata budgets within limit".to_string());
        }
        if self.config.low_fee_mode_required && !trace.low_fee_limit.within_limit {
            return Err("trace exceeds low-fee execution limit".to_string());
        }
        if self.config.fail_closed_on_adversarial_flags && trace.adversarial_flags.any() {
            return Err("trace carries fail-closed adversarial flags".to_string());
        }
        assert_required_steps(trace)?;
        assert_trace_links(trace)?;
        Ok(())
    }

    pub fn assess_trace(&self, trace: &ExecutionTrace) -> HarnessReport {
        let mut blockers = Vec::new();
        if trace.successful_step_count() < self.config.min_trace_steps {
            blockers.push("min_trace_steps_not_met".to_string());
        }
        if trace.accepted_pq_evidence_count() < self.config.min_pq_evidence_items {
            blockers.push("min_pq_evidence_items_not_met".to_string());
        }
        if trace.privacy_budget_count_within_limit() < self.config.min_privacy_budgets {
            blockers.push("min_privacy_budgets_not_met".to_string());
        }
        if !trace.low_fee_limit.within_limit {
            blockers.push("low_fee_limit_exceeded".to_string());
        }
        if trace.adversarial_flags.any() {
            blockers.push("adversarial_flags_present".to_string());
        }
        if self.config.cargo_checks_deferred {
            blockers.push("cargo_checks_deferred".to_string());
        }
        if !self.config.production_release_allowed {
            blockers.push("production_release_blocked".to_string());
        }

        let verdict = if blockers.iter().any(|blocker| {
            blocker == "low_fee_limit_exceeded" || blocker == "adversarial_flags_present"
        }) {
            HarnessVerdict::Fail
        } else if blockers.is_empty() {
            HarnessVerdict::Pass
        } else {
            HarnessVerdict::Watch
        };

        HarnessReport {
            report_id: report_id(&trace.trace_id, trace.state_root().as_str()),
            trace_id: trace.trace_id.clone(),
            verdict,
            trace_root: trace.state_root(),
            step_root: trace.step_root(),
            pq_evidence_root: trace.pq_evidence_root(),
            privacy_budget_root: trace.privacy_budget_root(),
            low_fee_limit_root: trace.low_fee_limit.state_root(),
            adversarial_flag_root: record_root(
                "adversarial_flags",
                &trace.adversarial_flags.public_record(),
            ),
            successful_steps: trace.successful_step_count(),
            accepted_pq_evidence: trace.accepted_pq_evidence_count(),
            privacy_budgets_within_limit: trace.privacy_budget_count_within_limit(),
            cargo_checks_deferred: self.config.cargo_checks_deferred,
            production_release_allowed: self.config.production_release_allowed,
            blockers,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "traces": self.traces.values().map(ExecutionTrace::public_record).collect::<Vec<_>>(),
            "reports": self.reports.values().map(HarnessReport::public_record).collect::<Vec<_>>(),
            "roots": {
                "config_root": self.config.state_root(),
                "trace_root": self.trace_root(),
                "report_root": self.report_root(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.trace_root()),
                HashPart::Str(&self.report_root()),
            ],
            32,
        )
    }

    pub fn trace_root(&self) -> String {
        list_root(
            "state_traces",
            self.traces
                .values()
                .map(ExecutionTrace::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn report_root(&self) -> String {
        list_root(
            "state_reports",
            self.reports
                .values()
                .map(HarnessReport::public_record)
                .collect::<Vec<_>>(),
        )
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

pub fn config_root(config: &Config) -> String {
    config.state_root()
}

pub fn trace_root(trace: &ExecutionTrace) -> String {
    trace.state_root()
}

pub fn report_root(report: &HarnessReport) -> String {
    report.state_root()
}

pub fn pq_evidence_root(items: &[PqControlPlaneEvidence]) -> String {
    list_root(
        "pq_control_plane_evidence",
        items
            .iter()
            .map(PqControlPlaneEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_budget_root(items: &[PrivacyMetadataBudget]) -> String {
    list_root(
        "privacy_metadata_budgets",
        items
            .iter()
            .map(PrivacyMetadataBudget::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-RECORD",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

pub fn list_root(label: &str, records: Vec<Value>) -> String {
    let merkle = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-LIST",
        &records,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-LIST-ROOT",
        &[HashPart::Str(label), HashPart::Str(&merkle)],
        32,
    )
}

pub fn derive_commitment(label: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| json!({ "label": label, "part": part }))
        .collect::<Vec<_>>();
    let root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-COMMITMENT",
        &leaves,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-DERIVED-COMMITMENT",
        &[HashPart::Str(label), HashPart::Str(&root)],
        32,
    )
}

fn report_id(trace_id: &str, trace_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-REPORT-ID",
        &[HashPart::Str(trace_id), HashPart::Str(trace_root)],
        16,
    )
}

fn assert_required_steps(trace: &ExecutionTrace) -> Result<()> {
    let kinds = trace
        .steps
        .iter()
        .map(|step| step.kind)
        .collect::<BTreeSet<_>>();
    for required in [
        TraceStepKind::DepositLockObserved,
        TraceStepKind::PrivateL2NoteState,
        TraceStepKind::PrivateTransferOrContractAction,
        TraceStepKind::SettlementReceipt,
        TraceStepKind::WithdrawalForcedExitEvidence,
    ] {
        if !kinds.contains(&required) {
            return Err(format!(
                "required trace step missing: {}",
                required.as_str()
            ));
        }
    }
    Ok(())
}

fn assert_trace_links(trace: &ExecutionTrace) -> Result<()> {
    if trace.private_note.deposit_id != trace.deposit_lock.deposit_id {
        return Err("private note does not bind to deposit lock".to_string());
    }
    if trace.private_action.note_id != trace.private_note.note_id {
        return Err("private action does not bind to private note".to_string());
    }
    if trace.settlement_receipt.action_id != trace.private_action.action_id {
        return Err("settlement receipt does not bind to private action".to_string());
    }
    if trace.withdrawal_evidence.receipt_id != trace.settlement_receipt.receipt_id {
        return Err("withdrawal evidence does not bind to settlement receipt".to_string());
    }
    if trace.low_fee_limit.trace_id != trace.trace_id {
        return Err("low-fee limit does not bind to trace".to_string());
    }
    for evidence in &trace.pq_evidence {
        if evidence.trace_id != trace.trace_id {
            return Err("pq evidence does not bind to trace".to_string());
        }
    }
    for budget in &trace.privacy_budgets {
        if budget.trace_id != trace.trace_id {
            return Err("privacy budget does not bind to trace".to_string());
        }
    }
    Ok(())
}

fn devnet_execution_trace() -> ExecutionTrace {
    let trace_id = "devnet-monero-l2-pq-bridge-exit-trace-0001".to_string();
    let deposit_lock = DepositLockEvidence {
        deposit_id: "deposit-lock-devnet-0001".to_string(),
        monero_txid: derive_commitment("monero_txid", &["devnet", "deposit", "0001"]),
        lock_output_commitment: derive_commitment(
            "lock_output",
            &["custody", "xmr", "800000000000"],
        ),
        custody_address_commitment: derive_commitment(
            "custody_address",
            &["bridge", "reserve", "devnet"],
        ),
        amount_piconero: 800_000_000_000,
        observed_height: 1_240_000,
        finality_depth: 72,
        watcher_set_root: derive_commitment(
            "watcher_set",
            &["watcher-a", "watcher-b", "watcher-c"],
        ),
        lock_transcript_root: derive_commitment(
            "lock_transcript",
            &["deposit", "lock", "observed"],
        ),
    };
    let private_note = PrivateNoteState {
        note_id: "private-note-devnet-0001".to_string(),
        deposit_id: deposit_lock.deposit_id.clone(),
        note_commitment: derive_commitment("note", &["shielded", "mint", "0001"]),
        state_root_before: derive_commitment("state_before", &["empty", "bridge", "lane"]),
        state_root_after: derive_commitment("state_after", &["note", "minted", "0001"]),
        nullifier_commitment: derive_commitment("nullifier", &["note", "unspent", "0001"]),
        encrypted_note_blob_root: derive_commitment(
            "encrypted_note",
            &["jamtis", "viewtag", "blob"],
        ),
        amount_commitment: derive_commitment("amount", &["800000000000", "blinded"]),
        minted_height: 1_240_006,
    };
    let private_action = PrivateActionTrace {
        action_id: "private-action-devnet-0001".to_string(),
        note_id: private_note.note_id.clone(),
        action_kind: PrivateActionKind::ContractCall,
        contract_commitment: derive_commitment("contract", &["bridge_exit", "settlement", "call"]),
        input_state_root: private_note.state_root_after.clone(),
        output_state_root: derive_commitment(
            "state_after_action",
            &["contract", "receipt", "ready"],
        ),
        action_receipt_root: derive_commitment("action_receipt", &["private", "call", "accepted"]),
        proof_root: derive_commitment("action_proof", &["zk", "pq", "bounded"]),
        fee_piconero: 12_000,
        sequencer_batch_id: "private-batch-devnet-42".to_string(),
        executed_height: 1_240_010,
    };
    let settlement_receipt = SettlementReceipt {
        receipt_id: "settlement-receipt-devnet-0001".to_string(),
        action_id: private_action.action_id.clone(),
        settlement_batch_id: "settlement-batch-devnet-42".to_string(),
        bridge_receipt_root: derive_commitment(
            "bridge_receipt",
            &["receipt", "anchored", "release"],
        ),
        l2_state_root: private_action.output_state_root.clone(),
        monero_release_commitment: derive_commitment(
            "monero_release",
            &["withdrawal", "claim", "ready"],
        ),
        settlement_height: 1_240_018,
        fee_paid_piconero: 18_000,
    };
    let withdrawal_evidence = WithdrawalForcedExitEvidence {
        evidence_id: "forced-exit-evidence-devnet-0001".to_string(),
        receipt_id: settlement_receipt.receipt_id.clone(),
        exit_path: ExitPathKind::ForcedExit,
        withdrawal_claim_root: derive_commitment(
            "withdrawal_claim",
            &["claim", "receipt", "bound"],
        ),
        forced_exit_claim_root: derive_commitment(
            "forced_exit",
            &["timeout", "watcher", "available"],
        ),
        timeout_height: 1_240_720,
        evidence_height: 1_240_724,
        release_authority_root: derive_commitment(
            "release_authority",
            &["ml-dsa", "slh-dsa", "quorum"],
        ),
        challenge_window_root: derive_commitment(
            "challenge_window",
            &["open", "bounded", "settle"],
        ),
    };
    let pq_evidence = vec![
        pq_evidence(
            &trace_id,
            "pq-ml-dsa-devnet-0001",
            PqEvidenceKind::MlDsaAuthorityAttestation,
            7,
        ),
        pq_evidence(
            &trace_id,
            "pq-slh-dsa-devnet-0001",
            PqEvidenceKind::SlhDsaFallbackAttestation,
            7,
        ),
        pq_evidence(
            &trace_id,
            "pq-checkpoint-devnet-0001",
            PqEvidenceKind::MerkleCheckpoint,
            7,
        ),
        pq_evidence(
            &trace_id,
            "pq-quorum-devnet-0001",
            PqEvidenceKind::WatcherQuorumCertificate,
            7,
        ),
        pq_evidence(
            &trace_id,
            "pq-nullifier-devnet-0001",
            PqEvidenceKind::ReplayFenceNullifier,
            7,
        ),
    ];
    let privacy_budgets = vec![
        privacy_budget(
            &trace_id,
            "privacy-linkability-devnet-0001",
            PrivacyBudgetKind::Linkability,
            100,
            17,
        ),
        privacy_budget(
            &trace_id,
            "privacy-viewkey-devnet-0001",
            PrivacyBudgetKind::ViewKeyDisclosure,
            30,
            4,
        ),
        privacy_budget(
            &trace_id,
            "privacy-receipt-devnet-0001",
            PrivacyBudgetKind::ReceiptMetadata,
            60,
            18,
        ),
        privacy_budget(
            &trace_id,
            "privacy-decoy-devnet-0001",
            PrivacyBudgetKind::DecoySetEntropy,
            120,
            49,
        ),
        privacy_budget(
            &trace_id,
            "privacy-timing-devnet-0001",
            PrivacyBudgetKind::TimingCorrelation,
            80,
            21,
        ),
    ];
    let low_fee_limit = LowFeeLimit {
        limit_id: "low-fee-limit-devnet-0001".to_string(),
        trace_id: trace_id.clone(),
        max_fee_piconero: DEFAULT_MAX_FEE_PICONERO,
        observed_fee_piconero: 30_000,
        sponsor_credit_piconero: 8_000,
        relay_delay_blocks: 14,
        within_limit: true,
    };
    let adversarial_flags = AdversarialFlags::default();
    let step_roots = [
        deposit_lock.state_root(),
        private_note.state_root(),
        private_action.state_root(),
        settlement_receipt.state_root(),
        withdrawal_evidence.state_root(),
    ];
    let steps = vec![
        trace_step(
            &trace_id,
            1,
            TraceStepKind::DepositLockObserved,
            "watcher-quorum",
            deposit_lock.observed_height,
            &step_roots[0],
            None,
        ),
        trace_step(
            &trace_id,
            2,
            TraceStepKind::PrivateL2NoteState,
            "private-note-minter",
            private_note.minted_height,
            &step_roots[1],
            Some(step_roots[0].clone()),
        ),
        trace_step(
            &trace_id,
            3,
            TraceStepKind::PrivateTransferOrContractAction,
            "private-contract-executor",
            private_action.executed_height,
            &step_roots[2],
            Some(step_roots[1].clone()),
        ),
        trace_step(
            &trace_id,
            4,
            TraceStepKind::SettlementReceipt,
            "settlement-anchor",
            settlement_receipt.settlement_height,
            &step_roots[3],
            Some(step_roots[2].clone()),
        ),
        trace_step(
            &trace_id,
            5,
            TraceStepKind::WithdrawalForcedExitEvidence,
            "forced-exit-watchtower",
            withdrawal_evidence.evidence_height,
            &step_roots[4],
            Some(step_roots[3].clone()),
        ),
    ];
    ExecutionTrace {
        trace_id,
        label: DEVNET_TRACE_LABEL.to_string(),
        deposit_lock,
        private_note,
        private_action,
        settlement_receipt,
        withdrawal_evidence,
        pq_evidence,
        privacy_budgets,
        low_fee_limit,
        adversarial_flags,
        steps,
        verdict: HarnessVerdict::Watch,
    }
}

fn pq_evidence(
    trace_id: &str,
    evidence_id: &str,
    kind: PqEvidenceKind,
    authority_epoch: u64,
) -> PqControlPlaneEvidence {
    PqControlPlaneEvidence {
        evidence_id: evidence_id.to_string(),
        trace_id: trace_id.to_string(),
        kind,
        authority_epoch,
        signer_set_root: derive_commitment("pq_signer_set", &[evidence_id, kind.as_str()]),
        signature_commitment_root: derive_commitment("pq_signature", &[evidence_id, "accepted"]),
        transcript_root: derive_commitment("pq_transcript", &[trace_id, evidence_id]),
        accepted: true,
    }
}

fn privacy_budget(
    trace_id: &str,
    budget_id: &str,
    kind: PrivacyBudgetKind,
    limit_units: u64,
    consumed_units: u64,
) -> PrivacyMetadataBudget {
    PrivacyMetadataBudget {
        budget_id: budget_id.to_string(),
        trace_id: trace_id.to_string(),
        kind,
        limit_units,
        consumed_units,
        disclosure_root: derive_commitment("privacy_disclosure", &[budget_id, kind.as_str()]),
        mitigation_root: derive_commitment("privacy_mitigation", &[trace_id, budget_id]),
    }
}

fn trace_step(
    trace_id: &str,
    sequence: u64,
    kind: TraceStepKind,
    actor: &str,
    height: u64,
    subject_root: &str,
    previous_step_root: Option<String>,
) -> ExecutionTraceStep {
    ExecutionTraceStep {
        step_id: domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-EXECUTION-TRACE-HARNESS-STEP-ID",
            &[
                HashPart::Str(trace_id),
                HashPart::U64(sequence),
                HashPart::Str(kind.as_str()),
            ],
            16,
        ),
        trace_id: trace_id.to_string(),
        sequence,
        kind,
        status: TraceStatus::Recorded,
        actor: actor.to_string(),
        height,
        subject_root: subject_root.to_string(),
        previous_step_root,
        notes: vec![
            "rooted_public_trace_only".to_string(),
            "private_payloads_remain_committed".to_string(),
        ],
    }
}
