use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStateTransitionQueueRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStateTransitionQueueRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STATE_TRANSITION_QUEUE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-state-transition-queue-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STATE_TRANSITION_QUEUE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_TRANSITION_QUEUE_SUITE: &str =
    "confidential-contract-sealed-state-transition-queue-v1";
pub const PQ_TRANSITION_PROOF_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-state-transition-proof-v1";
pub const SEALED_ROLLBACK_SUITE: &str = "sealed-confidential-state-transition-rollback-root-v1";
pub const SEALED_COMPENSATION_SUITE: &str =
    "sealed-confidential-state-transition-compensation-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-sealed-state-transition-batch-execution-v1";
pub const DETERMINISTIC_QUEUE_SUITE: &str =
    "deterministic-confidential-state-transition-queue-root-v1";
pub const CONTRACT_LANE_SCHEME: &str = "sealed-state-transition-contract-lane-root-v1";
pub const QUEUED_TRANSITION_SCHEME: &str = "sealed-state-transition-queue-entry-root-v1";
pub const PQ_PROOF_SCHEME: &str = "pq-authenticated-state-transition-proof-root-v1";
pub const ROLLBACK_ROOT_SCHEME: &str = "sealed-state-transition-rollback-root-v1";
pub const COMPENSATION_ROOT_SCHEME: &str = "sealed-state-transition-compensation-root-v1";
pub const EXECUTION_BATCH_SCHEME: &str = "low-fee-state-transition-execution-batch-root-v1";
pub const DETERMINISTIC_TRACE_SCHEME: &str = "sealed-state-transition-deterministic-trace-root-v1";
pub const FIXTURE_SCHEME: &str = "sealed-state-transition-queue-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_284_608;
pub const DEVNET_EPOCH: u64 = 10_322;
pub const DEFAULT_QUEUE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_COMPENSATION_WINDOW_BLOCKS: u64 = 80;
pub const DEFAULT_MAX_TRANSITIONS_PER_BATCH: usize = 2_048;
pub const DEFAULT_MAX_CONTRACT_LANES: usize = 512;
pub const DEFAULT_MAX_VM_STEPS_PER_TRANSITION: u64 = 750_000;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 48_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_BASE_QUEUE_MICRO_FEE: u64 = 7;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    ContractCall,
    CrossContractCall,
    VaultMutation,
    OracleGuardedMutation,
    GovernanceExecution,
    AccountRecovery,
    RollbackCompensation,
    EmergencyPatch,
}

impl TransitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::CrossContractCall => "cross_contract_call",
            Self::VaultMutation => "vault_mutation",
            Self::OracleGuardedMutation => "oracle_guarded_mutation",
            Self::GovernanceExecution => "governance_execution",
            Self::AccountRecovery => "account_recovery",
            Self::RollbackCompensation => "rollback_compensation",
            Self::EmergencyPatch => "emergency_patch",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPatch => 10_000,
            Self::RollbackCompensation => 9_400,
            Self::OracleGuardedMutation => 8_900,
            Self::VaultMutation => 8_400,
            Self::CrossContractCall => 8_000,
            Self::ContractCall => 7_600,
            Self::AccountRecovery => 7_200,
            Self::GovernanceExecution => 5_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Sealed,
    Queued,
    PqProofAttached,
    BatchReady,
    Executed,
    RolledBack,
    Compensated,
    Expired,
    Rejected,
}

impl TransitionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Queued => "queued",
            Self::PqProofAttached => "pq_proof_attached",
            Self::BatchReady => "batch_ready",
            Self::Executed => "executed",
            Self::RolledBack => "rolled_back",
            Self::Compensated => "compensated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::Queued | Self::PqProofAttached | Self::BatchReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqProofStatus {
    Proposed,
    Authenticated,
    Applied,
    Challenged,
    Rejected,
}

impl PqProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authenticated => "authenticated",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRootStatus {
    Sealed,
    Armed,
    Applied,
    Cancelled,
}

impl RecoveryRootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Armed => "armed",
            Self::Applied => "applied",
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
    pub sealed_transition_queue_suite: String,
    pub pq_transition_proof_suite: String,
    pub sealed_rollback_suite: String,
    pub sealed_compensation_suite: String,
    pub low_fee_batch_suite: String,
    pub deterministic_queue_suite: String,
    pub queue_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub rollback_window_blocks: u64,
    pub compensation_window_blocks: u64,
    pub max_transitions_per_batch: usize,
    pub max_contract_lanes: usize,
    pub max_vm_steps_per_transition: u64,
    pub max_vm_steps_per_batch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub base_queue_micro_fee: u64,
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
            sealed_transition_queue_suite: SEALED_TRANSITION_QUEUE_SUITE.to_string(),
            pq_transition_proof_suite: PQ_TRANSITION_PROOF_SUITE.to_string(),
            sealed_rollback_suite: SEALED_ROLLBACK_SUITE.to_string(),
            sealed_compensation_suite: SEALED_COMPENSATION_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            deterministic_queue_suite: DETERMINISTIC_QUEUE_SUITE.to_string(),
            queue_ttl_blocks: DEFAULT_QUEUE_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            compensation_window_blocks: DEFAULT_COMPENSATION_WINDOW_BLOCKS,
            max_transitions_per_batch: DEFAULT_MAX_TRANSITIONS_PER_BATCH,
            max_contract_lanes: DEFAULT_MAX_CONTRACT_LANES,
            max_vm_steps_per_transition: DEFAULT_MAX_VM_STEPS_PER_TRANSITION,
            max_vm_steps_per_batch: DEFAULT_MAX_VM_STEPS_PER_BATCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            base_queue_micro_fee: DEFAULT_BASE_QUEUE_MICRO_FEE,
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
        if self.max_vm_steps_per_transition > self.max_vm_steps_per_batch {
            return Err("transition vm step limit exceeds batch vm step limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub contract_lanes: u64,
    pub queued_transitions: u64,
    pub pending_transitions: u64,
    pub pq_transition_proofs: u64,
    pub authenticated_pq_proofs: u64,
    pub sealed_rollback_roots: u64,
    pub applied_rollbacks: u64,
    pub sealed_compensation_roots: u64,
    pub applied_compensations: u64,
    pub execution_batches: u64,
    pub deterministic_traces: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub contract_lane_root: String,
    pub queued_transition_root: String,
    pub pq_transition_proof_root: String,
    pub sealed_rollback_root: String,
    pub sealed_compensation_root: String,
    pub execution_batch_root: String,
    pub deterministic_trace_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            contract_lane_root: merkle_root(CONTRACT_LANE_SCHEME, &[]),
            queued_transition_root: merkle_root(QUEUED_TRANSITION_SCHEME, &[]),
            pq_transition_proof_root: merkle_root(PQ_PROOF_SCHEME, &[]),
            sealed_rollback_root: merkle_root(ROLLBACK_ROOT_SCHEME, &[]),
            sealed_compensation_root: merkle_root(COMPENSATION_ROOT_SCHEME, &[]),
            execution_batch_root: merkle_root(EXECUTION_BATCH_SCHEME, &[]),
            deterministic_trace_root: merkle_root(DETERMINISTIC_TRACE_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ContractLane {
    pub lane_id: String,
    pub contract_id: String,
    pub transition_kind: TransitionKind,
    pub contract_code_root: String,
    pub verifier_key_root: String,
    pub queue_policy_root: String,
    pub priority_weight: u64,
    pub enabled: bool,
}

impl ContractLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "contract_id": self.contract_id,
            "transition_kind": self.transition_kind.as_str(),
            "contract_code_root": self.contract_code_root,
            "verifier_key_root": self.verifier_key_root,
            "queue_policy_root": self.queue_policy_root,
            "priority_weight": self.priority_weight,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct QueuedTransition {
    pub transition_id: String,
    pub lane_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub sealed_call_root: String,
    pub encrypted_witness_root: String,
    pub pre_state_root: String,
    pub expected_post_state_root: String,
    pub rollback_root: String,
    pub compensation_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub estimated_vm_steps: u64,
    pub status: TransitionStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl QueuedTransition {
    pub fn public_record(&self) -> Value {
        json!({
            "transition_id": self.transition_id,
            "lane_id": self.lane_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "sealed_call_root": self.sealed_call_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "pre_state_root": self.pre_state_root,
            "expected_post_state_root": self.expected_post_state_root,
            "rollback_root": self.rollback_root,
            "compensation_root": self.compensation_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "estimated_vm_steps": self.estimated_vm_steps,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqTransitionProof {
    pub proof_id: String,
    pub transition_id: String,
    pub predecessor_state_root: String,
    pub successor_state_root: String,
    pub encrypted_delta_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub status: PqProofStatus,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
}

impl PqTransitionProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "transition_id": self.transition_id,
            "predecessor_state_root": self.predecessor_state_root,
            "successor_state_root": self.successor_state_root,
            "encrypted_delta_root": self.encrypted_delta_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "authenticated_height": self.authenticated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedRollbackRoot {
    pub rollback_id: String,
    pub transition_id: String,
    pub trigger_state_root: String,
    pub sealed_rollback_root: String,
    pub rollback_note_root: String,
    pub status: RecoveryRootStatus,
    pub available_height: u64,
    pub applied_height: Option<u64>,
}

impl SealedRollbackRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "rollback_id": self.rollback_id,
            "transition_id": self.transition_id,
            "trigger_state_root": self.trigger_state_root,
            "sealed_rollback_root": self.sealed_rollback_root,
            "rollback_note_root": self.rollback_note_root,
            "status": self.status.as_str(),
            "available_height": self.available_height,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCompensationRoot {
    pub compensation_id: String,
    pub transition_id: String,
    pub trigger_state_root: String,
    pub sealed_compensation_root: String,
    pub beneficiary_note_root: String,
    pub status: RecoveryRootStatus,
    pub available_height: u64,
    pub applied_height: Option<u64>,
}

impl SealedCompensationRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "compensation_id": self.compensation_id,
            "transition_id": self.transition_id,
            "trigger_state_root": self.trigger_state_root,
            "sealed_compensation_root": self.sealed_compensation_root,
            "beneficiary_note_root": self.beneficiary_note_root,
            "status": self.status.as_str(),
            "available_height": self.available_height,
            "applied_height": self.applied_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExecutionBatch {
    pub batch_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub transition_root: String,
    pub proof_root: String,
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
            "transition_root": self.transition_root,
            "proof_root": self.proof_root,
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
pub struct DeterministicTrace {
    pub trace_id: String,
    pub batch_id: String,
    pub transition_id: String,
    pub proof_id: String,
    pub queue_position_root: String,
    pub deterministic_replay_root: String,
    pub rollback_branch_root: String,
    pub compensation_branch_root: String,
    pub fee_meter_root: String,
}

impl DeterministicTrace {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "batch_id": self.batch_id,
            "transition_id": self.transition_id,
            "proof_id": self.proof_id,
            "queue_position_root": self.queue_position_root,
            "deterministic_replay_root": self.deterministic_replay_root,
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
    pub contract_lanes: BTreeMap<String, ContractLane>,
    pub queued_transitions: BTreeMap<String, QueuedTransition>,
    pub pq_transition_proofs: BTreeMap<String, PqTransitionProof>,
    pub sealed_rollback_roots: BTreeMap<String, SealedRollbackRoot>,
    pub sealed_compensation_roots: BTreeMap<String, SealedCompensationRoot>,
    pub execution_batches: BTreeMap<String, ExecutionBatch>,
    pub deterministic_traces: BTreeMap<String, DeterministicTrace>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            contract_lanes: BTreeMap::new(),
            queued_transitions: BTreeMap::new(),
            pq_transition_proofs: BTreeMap::new(),
            sealed_rollback_roots: BTreeMap::new(),
            sealed_compensation_roots: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            deterministic_traces: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let transition_kind = TransitionKind::CrossContractCall;
        let lane_id = lane_id(transition_kind, "contract-private-router", 0);
        let transition_id = queued_transition_id(
            &lane_id,
            "caller-commitment-alice",
            DEVNET_HEIGHT,
            "vault-route-call",
        );
        let proof_id = pq_transition_proof_id(&transition_id, "devnet-transition-proof", 0);
        let rollback_id = rollback_root_id(&transition_id, "vault-route-rollback", 0);
        let compensation_id = compensation_root_id(&transition_id, "vault-route-compensation", 0);
        let operator_id = operator_id("devnet-state-transition-operator-alpha", DEVNET_EPOCH);
        let batch_id = execution_batch_id(&operator_id, DEVNET_EPOCH, DEVNET_HEIGHT + 2);
        let trace_id = deterministic_trace_id(&batch_id, &transition_id, &proof_id);

        state.contract_lanes.insert(
            lane_id.clone(),
            ContractLane {
                lane_id: lane_id.clone(),
                contract_id: "contract-private-router".to_string(),
                transition_kind,
                contract_code_root: deterministic_root("contract-code", "private-router", 0),
                verifier_key_root: deterministic_root("verifier-key", "private-router", 0),
                queue_policy_root: deterministic_root("queue-policy", "low-fee-cross-call", 0),
                priority_weight: transition_kind.priority_weight(),
                enabled: true,
            },
        );
        state.queued_transitions.insert(
            transition_id.clone(),
            QueuedTransition {
                transition_id: transition_id.clone(),
                lane_id: lane_id.clone(),
                contract_id: "contract-private-router".to_string(),
                caller_commitment: "caller-commitment-alice".to_string(),
                sealed_call_root: deterministic_root("sealed-call", "vault-route-call", 0),
                encrypted_witness_root: deterministic_root("encrypted-witness", "vault-route", 0),
                pre_state_root: deterministic_root("pre-state", "vault-route", 0),
                expected_post_state_root: deterministic_root("post-state", "vault-route", 1),
                rollback_root: deterministic_root("rollback", "vault-route", 0),
                compensation_root: deterministic_root("compensation", "vault-route", 0),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                estimated_vm_steps: 612_448,
                status: TransitionStatus::Executed,
                submitted_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_QUEUE_TTL_BLOCKS,
            },
        );
        state.pq_transition_proofs.insert(
            proof_id.clone(),
            PqTransitionProof {
                proof_id: proof_id.clone(),
                transition_id: transition_id.clone(),
                predecessor_state_root: deterministic_root("predecessor-state", "vault-route", 0),
                successor_state_root: deterministic_root("successor-state", "vault-route", 1),
                encrypted_delta_root: deterministic_root("encrypted-delta", "vault-route", 1),
                pq_public_key_root: deterministic_root("pq-public-key", "operator-alpha", 0),
                pq_signature_root: deterministic_root("pq-signature", "vault-route-proof", 0),
                transcript_root: deterministic_root("pq-transcript", "vault-route-proof", 0),
                status: PqProofStatus::Applied,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT + 1,
            },
        );
        state.sealed_rollback_roots.insert(
            rollback_id.clone(),
            SealedRollbackRoot {
                rollback_id,
                transition_id: transition_id.clone(),
                trigger_state_root: deterministic_root("rollback-trigger", "vault-timeout", 0),
                sealed_rollback_root: deterministic_root("sealed-rollback", "vault-rewind", 0),
                rollback_note_root: deterministic_root("rollback-note", "vault-rewind", 0),
                status: RecoveryRootStatus::Cancelled,
                available_height: DEVNET_HEIGHT + DEFAULT_ROLLBACK_WINDOW_BLOCKS,
                applied_height: None,
            },
        );
        state.sealed_compensation_roots.insert(
            compensation_id.clone(),
            SealedCompensationRoot {
                compensation_id,
                transition_id: transition_id.clone(),
                trigger_state_root: deterministic_root(
                    "compensation-trigger",
                    "vault-compensate",
                    0,
                ),
                sealed_compensation_root: deterministic_root(
                    "sealed-compensation",
                    "vault-credit",
                    0,
                ),
                beneficiary_note_root: deterministic_root("beneficiary-note", "alice-credit", 0),
                status: RecoveryRootStatus::Cancelled,
                available_height: DEVNET_HEIGHT + DEFAULT_COMPENSATION_WINDOW_BLOCKS,
                applied_height: None,
            },
        );
        state.execution_batches.insert(
            batch_id.clone(),
            ExecutionBatch {
                batch_id: batch_id.clone(),
                operator_id,
                epoch: DEVNET_EPOCH,
                transition_root: root_for_values(QUEUED_TRANSITION_SCHEME, &[json!(transition_id)]),
                proof_root: root_for_values(PQ_PROOF_SCHEME, &[json!(proof_id)]),
                rollback_root: root_for_values(ROLLBACK_ROOT_SCHEME, &[json!("vault-rewind")]),
                compensation_root: root_for_values(
                    COMPENSATION_ROOT_SCHEME,
                    &[json!("alice-credit")],
                ),
                pre_state_root: deterministic_root("batch-pre-state", "vault-route", DEVNET_EPOCH),
                post_state_root: deterministic_root(
                    "batch-post-state",
                    "vault-route",
                    DEVNET_EPOCH,
                ),
                total_vm_steps: 612_448,
                aggregate_fee_micro_units: DEFAULT_BASE_QUEUE_MICRO_FEE,
                low_fee_eligible: true,
                executed_height: DEVNET_HEIGHT + 2,
            },
        );
        state.deterministic_traces.insert(
            trace_id.clone(),
            DeterministicTrace {
                trace_id,
                batch_id,
                transition_id,
                proof_id,
                queue_position_root: deterministic_root("queue-position", "vault-route", 0),
                deterministic_replay_root: deterministic_root("replay", "vault-route", 0),
                rollback_branch_root: deterministic_root("rollback-branch", "vault-rewind", 0),
                compensation_branch_root: deterministic_root(
                    "compensation-branch",
                    "alice-credit",
                    0,
                ),
                fee_meter_root: deterministic_root("fee-meter", "vault-route", 0),
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("sealed-state-transition-queue-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "sealed-state-transition-queue-demo".to_string(),
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
            "kind": "private_l2_pq_confidential_contract_sealed_state_transition_queue_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_transition_queue_suite": SEALED_TRANSITION_QUEUE_SUITE,
            "pq_transition_proof_suite": PQ_TRANSITION_PROOF_SUITE,
            "sealed_rollback_suite": SEALED_ROLLBACK_SUITE,
            "sealed_compensation_suite": SEALED_COMPENSATION_SUITE,
            "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
            "deterministic_queue_suite": DETERMINISTIC_QUEUE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "contract_lanes": self.contract_lanes.values().map(ContractLane::public_record).collect::<Vec<_>>(),
            "queued_transitions": self.queued_transitions.values().map(QueuedTransition::public_record).collect::<Vec<_>>(),
            "pq_transition_proofs": self.pq_transition_proofs.values().map(PqTransitionProof::public_record).collect::<Vec<_>>(),
            "sealed_rollback_roots": self.sealed_rollback_roots.values().map(SealedRollbackRoot::public_record).collect::<Vec<_>>(),
            "sealed_compensation_roots": self.sealed_compensation_roots.values().map(SealedCompensationRoot::public_record).collect::<Vec<_>>(),
            "execution_batches": self.execution_batches.values().map(ExecutionBatch::public_record).collect::<Vec<_>>(),
            "deterministic_traces": self.deterministic_traces.values().map(DeterministicTrace::public_record).collect::<Vec<_>>(),
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
            contract_lanes: self.contract_lanes.len() as u64,
            queued_transitions: self.queued_transitions.len() as u64,
            pending_transitions: self
                .queued_transitions
                .values()
                .filter(|transition| transition.status.pending())
                .count() as u64,
            pq_transition_proofs: self.pq_transition_proofs.len() as u64,
            authenticated_pq_proofs: self
                .pq_transition_proofs
                .values()
                .filter(|proof| {
                    matches!(
                        proof.status,
                        PqProofStatus::Authenticated | PqProofStatus::Applied
                    )
                })
                .count() as u64,
            sealed_rollback_roots: self.sealed_rollback_roots.len() as u64,
            applied_rollbacks: self
                .sealed_rollback_roots
                .values()
                .filter(|root| root.status == RecoveryRootStatus::Applied)
                .count() as u64,
            sealed_compensation_roots: self.sealed_compensation_roots.len() as u64,
            applied_compensations: self
                .sealed_compensation_roots
                .values()
                .filter(|root| root.status == RecoveryRootStatus::Applied)
                .count() as u64,
            execution_batches: self.execution_batches.len() as u64,
            deterministic_traces: self.deterministic_traces.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            contract_lane_root: record_root(
                CONTRACT_LANE_SCHEME,
                self.contract_lanes
                    .values()
                    .map(ContractLane::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            queued_transition_root: record_root(
                QUEUED_TRANSITION_SCHEME,
                self.queued_transitions
                    .values()
                    .map(QueuedTransition::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_transition_proof_root: record_root(
                PQ_PROOF_SCHEME,
                self.pq_transition_proofs
                    .values()
                    .map(PqTransitionProof::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_rollback_root: record_root(
                ROLLBACK_ROOT_SCHEME,
                self.sealed_rollback_roots
                    .values()
                    .map(SealedRollbackRoot::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_compensation_root: record_root(
                COMPENSATION_ROOT_SCHEME,
                self.sealed_compensation_roots
                    .values()
                    .map(SealedCompensationRoot::public_record)
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
                    .map(DeterministicTrace::public_record)
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

pub fn lane_id(kind: TransitionKind, contract_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:LANE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(contract_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn queued_transition_id(
    lane_id: &str,
    caller_commitment: &str,
    height: u64,
    call_label: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:TRANSITION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(caller_commitment),
            HashPart::U64(height),
            HashPart::Str(call_label),
        ],
        32,
    )
}

pub fn pq_transition_proof_id(transition_id: &str, proof_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:PQ-PROOF-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transition_id),
            HashPart::Str(proof_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn rollback_root_id(transition_id: &str, root_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:ROLLBACK-ROOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transition_id),
            HashPart::Str(root_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn compensation_root_id(transition_id: &str, root_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:COMPENSATION-ROOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transition_id),
            HashPart::Str(root_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn operator_id(operator_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:OPERATOR-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn deterministic_trace_id(batch_id: &str, transition_id: &str, proof_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:TRACE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(transition_id),
            HashPart::Str(proof_id),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:FIXTURE-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:DETERMINISTIC-ROOT",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STATE-TRANSITION-QUEUE:STATE-ROOT",
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
