use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractPrivateStateSagaOrchestratorRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractPrivateStateSagaOrchestratorRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STATE_SAGA_ORCHESTRATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-private-state-saga-orchestrator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STATE_SAGA_ORCHESTRATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_STATE_SAGA_SUITE: &str =
    "confidential-contract-private-state-saga-orchestrator-v1";
pub const PQ_CONTINUATION_PROOF_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-state-continuation-proof-v1";
pub const SEALED_ROLLBACK_SUITE: &str = "sealed-confidential-private-state-rollback-root-v1";
pub const SEALED_COMPENSATION_SUITE: &str =
    "sealed-confidential-private-state-compensation-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-private-state-saga-batch-execution-v1";
pub const DETERMINISTIC_TRACE_SUITE: &str =
    "deterministic-private-state-saga-orchestrator-trace-v1";
pub const SAGA_SCHEME: &str = "private-state-saga-orchestrator-root-v1";
pub const CONTINUATION_PROOF_SCHEME: &str = "pq-private-state-continuation-proof-root-v1";
pub const ROLLBACK_PLAN_SCHEME: &str = "sealed-private-state-rollback-plan-root-v1";
pub const COMPENSATION_PLAN_SCHEME: &str = "sealed-private-state-compensation-plan-root-v1";
pub const EXECUTION_BATCH_SCHEME: &str = "low-fee-private-state-saga-execution-batch-root-v1";
pub const DETERMINISTIC_TRACE_SCHEME: &str = "private-state-saga-deterministic-trace-root-v1";
pub const FIXTURE_SCHEME: &str = "private-state-saga-orchestrator-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_284_352;
pub const DEVNET_EPOCH: u64 = 10_321;
pub const DEFAULT_SAGA_TTL_BLOCKS: u64 = 256;
pub const DEFAULT_CONTINUATION_TTL_BLOCKS: u64 = 80;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 5;
pub const DEFAULT_MAX_SAGAS_PER_BATCH: usize = 1_536;
pub const DEFAULT_MAX_STEPS_PER_SAGA: usize = 96;
pub const DEFAULT_MAX_CONTINUATION_PROOFS_PER_SAGA: usize = 192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 6;
pub const DEFAULT_BASE_ORCHESTRATION_MICRO_FEE: u64 = 10;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 36_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaKind {
    ContractStateTransition,
    CrossContractStateTransition,
    EscrowSettlement,
    OracleGuardedTransition,
    RollbackRecovery,
    CompensationWorkflow,
    GovernanceExecution,
    AccountRecovery,
}

impl SagaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractStateTransition => "contract_state_transition",
            Self::CrossContractStateTransition => "cross_contract_state_transition",
            Self::EscrowSettlement => "escrow_settlement",
            Self::OracleGuardedTransition => "oracle_guarded_transition",
            Self::RollbackRecovery => "rollback_recovery",
            Self::CompensationWorkflow => "compensation_workflow",
            Self::GovernanceExecution => "governance_execution",
            Self::AccountRecovery => "account_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaStatus {
    Open,
    AwaitingContinuationProof,
    Continuing,
    RollbackArmed,
    Compensating,
    Batched,
    Settled,
    RolledBack,
    Expired,
}

impl SagaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AwaitingContinuationProof => "awaiting_continuation_proof",
            Self::Continuing => "continuing",
            Self::RollbackArmed => "rollback_armed",
            Self::Compensating => "compensating",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::RolledBack => "rolled_back",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::AwaitingContinuationProof
                | Self::Continuing
                | Self::RollbackArmed
                | Self::Compensating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationProofStatus {
    Proposed,
    PqAuthenticated,
    StateApplied,
    Rejected,
    Expired,
}

impl ContinuationProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PqAuthenticated => "pq_authenticated",
            Self::StateApplied => "state_applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPlanStatus {
    Sealed,
    Armed,
    Executed,
    Cancelled,
}

impl RecoveryPlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Armed => "armed",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub private_state_saga_suite: String,
    pub pq_continuation_proof_suite: String,
    pub sealed_rollback_suite: String,
    pub sealed_compensation_suite: String,
    pub low_fee_batch_suite: String,
    pub deterministic_trace_suite: String,
    pub saga_ttl_blocks: u64,
    pub continuation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_sagas_per_batch: usize,
    pub max_steps_per_saga: usize,
    pub max_continuation_proofs_per_saga: usize,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub base_orchestration_micro_fee: u64,
    pub max_vm_steps_per_batch: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            private_state_saga_suite: PRIVATE_STATE_SAGA_SUITE.to_string(),
            pq_continuation_proof_suite: PQ_CONTINUATION_PROOF_SUITE.to_string(),
            sealed_rollback_suite: SEALED_ROLLBACK_SUITE.to_string(),
            sealed_compensation_suite: SEALED_COMPENSATION_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            deterministic_trace_suite: DETERMINISTIC_TRACE_SUITE.to_string(),
            saga_ttl_blocks: DEFAULT_SAGA_TTL_BLOCKS,
            continuation_ttl_blocks: DEFAULT_CONTINUATION_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_sagas_per_batch: DEFAULT_MAX_SAGAS_PER_BATCH,
            max_steps_per_saga: DEFAULT_MAX_STEPS_PER_SAGA,
            max_continuation_proofs_per_saga: DEFAULT_MAX_CONTINUATION_PROOFS_PER_SAGA,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            base_orchestration_micro_fee: DEFAULT_BASE_ORCHESTRATION_MICRO_FEE,
            max_vm_steps_per_batch: DEFAULT_MAX_VM_STEPS_PER_BATCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("schema version mismatch".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
        {
            return Err("basis point configuration exceeds MAX_BPS".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security below policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub sagas: u64,
    pub live_sagas: u64,
    pub pq_continuation_proofs: u64,
    pub applied_continuation_proofs: u64,
    pub sealed_rollback_plans: u64,
    pub executed_rollbacks: u64,
    pub sealed_compensation_plans: u64,
    pub executed_compensations: u64,
    pub execution_batches: u64,
    pub deterministic_traces: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub saga_root: String,
    pub pq_continuation_proof_root: String,
    pub sealed_rollback_plan_root: String,
    pub sealed_compensation_plan_root: String,
    pub execution_batch_root: String,
    pub deterministic_trace_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            saga_root: merkle_root(SAGA_SCHEME, &[]),
            pq_continuation_proof_root: merkle_root(CONTINUATION_PROOF_SCHEME, &[]),
            sealed_rollback_plan_root: merkle_root(ROLLBACK_PLAN_SCHEME, &[]),
            sealed_compensation_plan_root: merkle_root(COMPENSATION_PLAN_SCHEME, &[]),
            execution_batch_root: merkle_root(EXECUTION_BATCH_SCHEME, &[]),
            deterministic_trace_root: merkle_root(DETERMINISTIC_TRACE_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateStateSaga {
    pub saga_id: String,
    pub kind: SagaKind,
    pub status: SagaStatus,
    pub contract_id: String,
    pub orchestrator_commitment: String,
    pub participant_root: String,
    pub pre_state_root: String,
    pub private_state_root: String,
    pub continuation_proof_root: String,
    pub rollback_root: String,
    pub compensation_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivateStateSaga {
    pub fn public_record(&self) -> Value {
        json!({
            "saga_id": self.saga_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "contract_id": self.contract_id,
            "orchestrator_commitment": self.orchestrator_commitment,
            "participant_root": self.participant_root,
            "pre_state_root": self.pre_state_root,
            "private_state_root": self.private_state_root,
            "continuation_proof_root": self.continuation_proof_root,
            "rollback_root": self.rollback_root,
            "compensation_root": self.compensation_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqContinuationProof {
    pub proof_id: String,
    pub saga_id: String,
    pub predecessor_state_root: String,
    pub continuation_state_root: String,
    pub encrypted_delta_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub status: ContinuationProofStatus,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
    pub expires_height: u64,
}

impl PqContinuationProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "saga_id": self.saga_id,
            "predecessor_state_root": self.predecessor_state_root,
            "continuation_state_root": self.continuation_state_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "authenticated_height": self.authenticated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedRollbackPlan {
    pub rollback_id: String,
    pub saga_id: String,
    pub trigger_state_root: String,
    pub sealed_rollback_root: String,
    pub recovery_note_root: String,
    pub status: RecoveryPlanStatus,
    pub timelock_height: u64,
    pub executed_height: Option<u64>,
}

impl SealedRollbackPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "rollback_id": self.rollback_id,
            "saga_id": self.saga_id,
            "trigger_state_root": self.trigger_state_root,
            "sealed_rollback_root": self.sealed_rollback_root,
            "recovery_note_root": self.recovery_note_root,
            "status": self.status.as_str(),
            "timelock_height": self.timelock_height,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCompensationPlan {
    pub compensation_id: String,
    pub saga_id: String,
    pub trigger_state_root: String,
    pub sealed_compensation_root: String,
    pub beneficiary_note_root: String,
    pub status: RecoveryPlanStatus,
    pub timelock_height: u64,
    pub executed_height: Option<u64>,
}

impl SealedCompensationPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "compensation_id": self.compensation_id,
            "saga_id": self.saga_id,
            "trigger_state_root": self.trigger_state_root,
            "sealed_compensation_root": self.sealed_compensation_root,
            "beneficiary_note_root": self.beneficiary_note_root,
            "status": self.status.as_str(),
            "timelock_height": self.timelock_height,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExecutionBatch {
    pub batch_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub saga_root: String,
    pub continuation_proof_root: String,
    pub rollback_root: String,
    pub compensation_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub total_vm_steps: u64,
    pub aggregate_fee_micro_units: u64,
    pub low_fee_eligible: bool,
    pub executed_height: u64,
}

impl ExecutionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "saga_root": self.saga_root,
            "continuation_proof_root": self.continuation_proof_root,
            "rollback_root": self.rollback_root,
            "compensation_root": self.compensation_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "total_vm_steps": self.total_vm_steps,
            "aggregate_fee_micro_units": self.aggregate_fee_micro_units,
            "low_fee_eligible": self.low_fee_eligible,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DeterministicTraceCommitment {
    pub trace_id: String,
    pub batch_id: String,
    pub saga_id: String,
    pub proof_id: String,
    pub deterministic_replay_root: String,
    pub private_witness_access_root: String,
    pub rollback_branch_root: String,
    pub compensation_branch_root: String,
    pub fee_meter_root: String,
}

impl DeterministicTraceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "batch_id": self.batch_id,
            "saga_id": self.saga_id,
            "proof_id": self.proof_id,
            "deterministic_replay_root": self.deterministic_replay_root,
            "private_witness_access_root": self.private_witness_access_root,
            "rollback_branch_root": self.rollback_branch_root,
            "compensation_branch_root": self.compensation_branch_root,
            "fee_meter_root": self.fee_meter_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub deterministic_seed_root: String,
    pub expected_state_root: String,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "deterministic_seed_root": self.deterministic_seed_root,
            "expected_state_root": self.expected_state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub private_state_sagas: BTreeMap<String, PrivateStateSaga>,
    pub pq_continuation_proofs: BTreeMap<String, PqContinuationProof>,
    pub sealed_rollback_plans: BTreeMap<String, SealedRollbackPlan>,
    pub sealed_compensation_plans: BTreeMap<String, SealedCompensationPlan>,
    pub execution_batches: BTreeMap<String, ExecutionBatch>,
    pub deterministic_traces: BTreeMap<String, DeterministicTraceCommitment>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            private_state_sagas: BTreeMap::new(),
            pq_continuation_proofs: BTreeMap::new(),
            sealed_rollback_plans: BTreeMap::new(),
            sealed_compensation_plans: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            deterministic_traces: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let operator_id = operator_id("devnet-private-state-operator-alpha", DEVNET_EPOCH);
        let saga_id = saga_id(
            SagaKind::CrossContractStateTransition,
            "contract-private-state-router",
            "orchestrator-commitment-alice",
            DEVNET_HEIGHT,
        );
        let proof_id = continuation_proof_id(&saga_id, "vault-state-step-0001", 0);
        let rollback_id = rollback_plan_id(&saga_id, "vault-state-rollback", 0);
        let compensation_id = compensation_plan_id(&saga_id, "vault-state-compensation", 0);
        let batch_id = execution_batch_id(&operator_id, DEVNET_EPOCH, DEVNET_HEIGHT + 2);
        let trace_id = deterministic_trace_id(&batch_id, &saga_id, &proof_id);

        state.private_state_sagas.insert(
            saga_id.clone(),
            PrivateStateSaga {
                saga_id: saga_id.clone(),
                kind: SagaKind::CrossContractStateTransition,
                status: SagaStatus::Settled,
                contract_id: "contract-private-state-router".to_string(),
                orchestrator_commitment: "orchestrator-commitment-alice".to_string(),
                participant_root: deterministic_root("participants", "alice+vault+oracle", 0),
                pre_state_root: deterministic_root("pre-state", "vault-route", 0),
                private_state_root: deterministic_root("private-state", "vault-route", 1),
                continuation_proof_root: deterministic_root(
                    "continuation-proof",
                    "vault-state-step",
                    0,
                ),
                rollback_root: deterministic_root("rollback", "vault-state-rollback", 0),
                compensation_root: deterministic_root(
                    "compensation",
                    "vault-state-compensation",
                    0,
                ),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                opened_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_SAGA_TTL_BLOCKS,
            },
        );
        state.pq_continuation_proofs.insert(
            proof_id.clone(),
            PqContinuationProof {
                proof_id: proof_id.clone(),
                saga_id: saga_id.clone(),
                predecessor_state_root: deterministic_root("predecessor-state", "vault-route", 0),
                continuation_state_root: deterministic_root("continuation-state", "vault-route", 1),
                encrypted_delta_root: deterministic_root("encrypted-delta", "vault-route", 1),
                pq_public_key_root: deterministic_root("pq-public-key", "operator-alpha", 0),
                pq_signature_root: deterministic_root("pq-signature", "vault-continuation", 0),
                transcript_root: deterministic_root("pq-transcript", "vault-continuation", 0),
                status: ContinuationProofStatus::StateApplied,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT + 1,
                expires_height: DEVNET_HEIGHT + 1 + DEFAULT_CONTINUATION_TTL_BLOCKS,
            },
        );
        state.sealed_rollback_plans.insert(
            rollback_id.clone(),
            SealedRollbackPlan {
                rollback_id,
                saga_id: saga_id.clone(),
                trigger_state_root: deterministic_root("trigger-state", "vault-timeout", 0),
                sealed_rollback_root: deterministic_root("sealed-rollback", "vault-rewind", 0),
                recovery_note_root: deterministic_root("recovery-note", "vault-rewind", 0),
                status: RecoveryPlanStatus::Cancelled,
                timelock_height: DEVNET_HEIGHT + 48,
                executed_height: None,
            },
        );
        state.sealed_compensation_plans.insert(
            compensation_id.clone(),
            SealedCompensationPlan {
                compensation_id,
                saga_id: saga_id.clone(),
                trigger_state_root: deterministic_root("trigger-state", "vault-compensate", 0),
                sealed_compensation_root: deterministic_root(
                    "sealed-compensation",
                    "vault-credit",
                    0,
                ),
                beneficiary_note_root: deterministic_root("beneficiary-note", "alice-credit", 0),
                status: RecoveryPlanStatus::Cancelled,
                timelock_height: DEVNET_HEIGHT + 64,
                executed_height: None,
            },
        );
        state.execution_batches.insert(
            batch_id.clone(),
            ExecutionBatch {
                batch_id: batch_id.clone(),
                operator_id,
                epoch: DEVNET_EPOCH,
                saga_root: root_for_values(SAGA_SCHEME, &[json!(saga_id)]),
                continuation_proof_root: root_for_values(
                    CONTINUATION_PROOF_SCHEME,
                    &[json!(proof_id)],
                ),
                rollback_root: root_for_values(ROLLBACK_PLAN_SCHEME, &[json!("vault-rewind")]),
                compensation_root: root_for_values(
                    COMPENSATION_PLAN_SCHEME,
                    &[json!("alice-credit")],
                ),
                pre_state_root: deterministic_root(
                    "pre-state",
                    "private-state-batch",
                    DEVNET_EPOCH,
                ),
                post_state_root: deterministic_root(
                    "post-state",
                    "private-state-batch",
                    DEVNET_EPOCH,
                ),
                total_vm_steps: 684_032,
                aggregate_fee_micro_units: DEFAULT_BASE_ORCHESTRATION_MICRO_FEE,
                low_fee_eligible: true,
                executed_height: DEVNET_HEIGHT + 2,
            },
        );
        state.deterministic_traces.insert(
            trace_id.clone(),
            DeterministicTraceCommitment {
                trace_id,
                batch_id,
                saga_id,
                proof_id,
                deterministic_replay_root: deterministic_root("replay", "private-state-batch", 0),
                private_witness_access_root: deterministic_root(
                    "witness-access",
                    "private-state-batch",
                    0,
                ),
                rollback_branch_root: deterministic_root("rollback-branch", "vault-rewind", 0),
                compensation_branch_root: deterministic_root(
                    "compensation-branch",
                    "alice-credit",
                    0,
                ),
                fee_meter_root: deterministic_root("fee-meter", "private-state-batch", 0),
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("private-state-saga-orchestrator-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "private-state-saga-orchestrator-demo".to_string(),
                deterministic_seed_root: deterministic_root("fixture-seed", "demo", 1),
                expected_state_root,
            },
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_private_state_saga_orchestrator_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "private_state_saga_suite": PRIVATE_STATE_SAGA_SUITE,
            "pq_continuation_proof_suite": PQ_CONTINUATION_PROOF_SUITE,
            "sealed_rollback_suite": SEALED_ROLLBACK_SUITE,
            "sealed_compensation_suite": SEALED_COMPENSATION_SUITE,
            "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
            "deterministic_trace_suite": DETERMINISTIC_TRACE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "private_state_sagas": self.private_state_sagas.values().map(PrivateStateSaga::public_record).collect::<Vec<_>>(),
            "pq_continuation_proofs": self.pq_continuation_proofs.values().map(PqContinuationProof::public_record).collect::<Vec<_>>(),
            "sealed_rollback_plans": self.sealed_rollback_plans.values().map(SealedRollbackPlan::public_record).collect::<Vec<_>>(),
            "sealed_compensation_plans": self.sealed_compensation_plans.values().map(SealedCompensationPlan::public_record).collect::<Vec<_>>(),
            "execution_batches": self.execution_batches.values().map(ExecutionBatch::public_record).collect::<Vec<_>>(),
            "deterministic_traces": self.deterministic_traces.values().map(DeterministicTraceCommitment::public_record).collect::<Vec<_>>(),
            "devnet_fixtures": self.devnet_fixtures.values().map(DevnetFixture::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            sagas: self.private_state_sagas.len() as u64,
            live_sagas: self
                .private_state_sagas
                .values()
                .filter(|saga| saga.status.live())
                .count() as u64,
            pq_continuation_proofs: self.pq_continuation_proofs.len() as u64,
            applied_continuation_proofs: self
                .pq_continuation_proofs
                .values()
                .filter(|proof| proof.status == ContinuationProofStatus::StateApplied)
                .count() as u64,
            sealed_rollback_plans: self.sealed_rollback_plans.len() as u64,
            executed_rollbacks: self
                .sealed_rollback_plans
                .values()
                .filter(|plan| plan.status == RecoveryPlanStatus::Executed)
                .count() as u64,
            sealed_compensation_plans: self.sealed_compensation_plans.len() as u64,
            executed_compensations: self
                .sealed_compensation_plans
                .values()
                .filter(|plan| plan.status == RecoveryPlanStatus::Executed)
                .count() as u64,
            execution_batches: self.execution_batches.len() as u64,
            deterministic_traces: self.deterministic_traces.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            saga_root: record_root(
                SAGA_SCHEME,
                self.private_state_sagas
                    .values()
                    .map(PrivateStateSaga::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_continuation_proof_root: record_root(
                CONTINUATION_PROOF_SCHEME,
                self.pq_continuation_proofs
                    .values()
                    .map(PqContinuationProof::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_rollback_plan_root: record_root(
                ROLLBACK_PLAN_SCHEME,
                self.sealed_rollback_plans
                    .values()
                    .map(SealedRollbackPlan::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_compensation_plan_root: record_root(
                COMPENSATION_PLAN_SCHEME,
                self.sealed_compensation_plans
                    .values()
                    .map(SealedCompensationPlan::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            execution_batch_root: record_root(
                EXECUTION_BATCH_SCHEME,
                self.execution_batches
                    .values()
                    .map(ExecutionBatch::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            deterministic_trace_root: record_root(
                DETERMINISTIC_TRACE_SCHEME,
                self.deterministic_traces
                    .values()
                    .map(DeterministicTraceCommitment::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            fixture_root: record_root(
                FIXTURE_SCHEME,
                self.devnet_fixtures
                    .values()
                    .map(DevnetFixture::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        };
    }
}

pub fn saga_id(
    kind: SagaKind,
    contract_id: &str,
    orchestrator_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:SAGA-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(orchestrator_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn continuation_proof_id(saga_id: &str, step_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:CONTINUATION-PROOF-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(saga_id),
            HashPart::Str(step_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn rollback_plan_id(saga_id: &str, plan_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:ROLLBACK-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(saga_id),
            HashPart::Str(plan_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn compensation_plan_id(saga_id: &str, plan_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:COMPENSATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(saga_id),
            HashPart::Str(plan_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn operator_id(operator_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:OPERATOR-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn execution_batch_id(operator_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn deterministic_trace_id(batch_id: &str, saga_id: &str, proof_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:TRACE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(saga_id),
            HashPart::Str(proof_id),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:FIXTURE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn root_for_values(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STATE-SAGA-ORCHESTRATOR:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
