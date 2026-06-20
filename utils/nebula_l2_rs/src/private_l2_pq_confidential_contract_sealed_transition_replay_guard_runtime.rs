use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedTransitionReplayGuardRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedTransitionReplayGuardRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_TRANSITION_REPLAY_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-transition-replay-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_TRANSITION_REPLAY_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_TRANSITION_REPLAY_GUARD_SUITE: &str =
    "confidential-contract-sealed-transition-replay-guard-v1";
pub const PQ_REPLAY_PROOF_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-sealed-transition-replay-proof-v1";
pub const SEALED_ROLLBACK_SUITE: &str = "sealed-confidential-transition-rollback-root-v1";
pub const SEALED_COMPENSATION_SUITE: &str = "sealed-confidential-transition-compensation-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-sealed-transition-replay-batch-execution-v1";
pub const DETERMINISTIC_REPLAY_SUITE: &str = "deterministic-sealed-transition-replay-root-v1";
pub const TRANSITION_FENCE_SCHEME: &str = "sealed-transition-replay-fence-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-transition-replay-nullifier-root-v1";
pub const PQ_REPLAY_PROOF_SCHEME: &str = "pq-sealed-transition-replay-proof-root-v1";
pub const ROLLBACK_ROOT_SCHEME: &str = "sealed-transition-replay-rollback-root-v1";
pub const COMPENSATION_ROOT_SCHEME: &str = "sealed-transition-replay-compensation-root-v1";
pub const EXECUTION_BATCH_SCHEME: &str = "low-fee-sealed-transition-replay-batch-root-v1";
pub const DETERMINISTIC_TRACE_SCHEME: &str = "sealed-transition-replay-deterministic-trace-root-v1";
pub const FIXTURE_SCHEME: &str = "sealed-transition-replay-guard-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_284_864;
pub const DEVNET_EPOCH: u64 = 10_323;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_ROLLBACK_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_COMPENSATION_WINDOW_BLOCKS: u64 = 80;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_FENCES: usize = 4_096;
pub const DEFAULT_MAX_NULLIFIERS_PER_BATCH: usize = 8_192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_BASE_GUARD_MICRO_FEE: u64 = 5;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 24_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionDomain {
    ContractCall,
    CrossContractCall,
    VaultMutation,
    OracleGuardedMutation,
    GovernanceExecution,
    AccountRecovery,
    RollbackCompensation,
    EmergencyPatch,
}

impl TransitionDomain {
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGuardStatus {
    Open,
    PqProofAttached,
    Accepted,
    DuplicateQuarantined,
    RolledBack,
    Compensated,
    Expired,
}

impl ReplayGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PqProofAttached => "pq_proof_attached",
            Self::Accepted => "accepted",
            Self::DuplicateQuarantined => "duplicate_quarantined",
            Self::RolledBack => "rolled_back",
            Self::Compensated => "compensated",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::PqProofAttached | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqReplayProofStatus {
    Proposed,
    Authenticated,
    Applied,
    Challenged,
    Rejected,
}

impl PqReplayProofStatus {
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
    pub sealed_transition_replay_guard_suite: String,
    pub pq_replay_proof_suite: String,
    pub sealed_rollback_suite: String,
    pub sealed_compensation_suite: String,
    pub low_fee_batch_suite: String,
    pub deterministic_replay_suite: String,
    pub replay_window_blocks: u64,
    pub rollback_window_blocks: u64,
    pub compensation_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_fences: usize,
    pub max_nullifiers_per_batch: usize,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub base_guard_micro_fee: u64,
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
            sealed_transition_replay_guard_suite: SEALED_TRANSITION_REPLAY_GUARD_SUITE.to_string(),
            pq_replay_proof_suite: PQ_REPLAY_PROOF_SUITE.to_string(),
            sealed_rollback_suite: SEALED_ROLLBACK_SUITE.to_string(),
            sealed_compensation_suite: SEALED_COMPENSATION_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            deterministic_replay_suite: DETERMINISTIC_REPLAY_SUITE.to_string(),
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            rollback_window_blocks: DEFAULT_ROLLBACK_WINDOW_BLOCKS,
            compensation_window_blocks: DEFAULT_COMPENSATION_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_fences: DEFAULT_MAX_FENCES,
            max_nullifiers_per_batch: DEFAULT_MAX_NULLIFIERS_PER_BATCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            base_guard_micro_fee: DEFAULT_BASE_GUARD_MICRO_FEE,
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
    pub transition_fences: u64,
    pub active_transition_fences: u64,
    pub replay_nullifiers: u64,
    pub duplicate_nullifiers: u64,
    pub pq_replay_proofs: u64,
    pub authenticated_pq_replay_proofs: u64,
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
    pub transition_fence_root: String,
    pub replay_nullifier_root: String,
    pub pq_replay_proof_root: String,
    pub sealed_rollback_root: String,
    pub sealed_compensation_root: String,
    pub execution_batch_root: String,
    pub deterministic_trace_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            transition_fence_root: merkle_root(TRANSITION_FENCE_SCHEME, &[]),
            replay_nullifier_root: merkle_root(REPLAY_NULLIFIER_SCHEME, &[]),
            pq_replay_proof_root: merkle_root(PQ_REPLAY_PROOF_SCHEME, &[]),
            sealed_rollback_root: merkle_root(ROLLBACK_ROOT_SCHEME, &[]),
            sealed_compensation_root: merkle_root(COMPENSATION_ROOT_SCHEME, &[]),
            execution_batch_root: merkle_root(EXECUTION_BATCH_SCHEME, &[]),
            deterministic_trace_root: merkle_root(DETERMINISTIC_TRACE_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct TransitionFence {
    pub fence_id: String,
    pub contract_id: String,
    pub domain: TransitionDomain,
    pub caller_commitment: String,
    pub sealed_transition_root: String,
    pub pre_state_root: String,
    pub expected_post_state_root: String,
    pub replay_window_start_height: u64,
    pub replay_window_end_height: u64,
    pub status: ReplayGuardStatus,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
}

impl TransitionFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "caller_commitment": self.caller_commitment,
            "sealed_transition_root": self.sealed_transition_root,
            "pre_state_root": self.pre_state_root,
            "expected_post_state_root": self.expected_post_state_root,
            "replay_window_start_height": self.replay_window_start_height,
            "replay_window_end_height": self.replay_window_end_height,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub fence_id: String,
    pub transition_commitment: String,
    pub caller_commitment: String,
    pub first_seen_height: u64,
    pub expires_height: u64,
    pub duplicate: bool,
    pub duplicate_evidence_root: Option<String>,
}

impl ReplayNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "fence_id": self.fence_id,
            "transition_commitment": self.transition_commitment,
            "caller_commitment": self.caller_commitment,
            "first_seen_height": self.first_seen_height,
            "expires_height": self.expires_height,
            "duplicate": self.duplicate,
            "duplicate_evidence_root": self.duplicate_evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqReplayProof {
    pub proof_id: String,
    pub nullifier_id: String,
    pub fence_id: String,
    pub predecessor_state_root: String,
    pub successor_state_root: String,
    pub replay_transcript_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub status: PqReplayProofStatus,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
}

impl PqReplayProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "nullifier_id": self.nullifier_id,
            "fence_id": self.fence_id,
            "predecessor_state_root": self.predecessor_state_root,
            "successor_state_root": self.successor_state_root,
            "replay_transcript_root": self.replay_transcript_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "authenticated_height": self.authenticated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedRollbackRoot {
    pub rollback_id: String,
    pub fence_id: String,
    pub nullifier_id: String,
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
            "fence_id": self.fence_id,
            "nullifier_id": self.nullifier_id,
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
    pub fence_id: String,
    pub nullifier_id: String,
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
            "fence_id": self.fence_id,
            "nullifier_id": self.nullifier_id,
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
    pub fence_root: String,
    pub nullifier_root: String,
    pub pq_proof_root: String,
    pub rollback_root: String,
    pub compensation_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub nullifier_count: u64,
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
            "fence_root": self.fence_root,
            "nullifier_root": self.nullifier_root,
            "pq_proof_root": self.pq_proof_root,
            "rollback_root": self.rollback_root,
            "compensation_root": self.compensation_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "nullifier_count": self.nullifier_count,
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
    pub fence_id: String,
    pub nullifier_id: String,
    pub proof_id: String,
    pub deterministic_replay_root: String,
    pub replay_window_root: String,
    pub rollback_branch_root: String,
    pub compensation_branch_root: String,
    pub fee_meter_root: String,
}

impl DeterministicTrace {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "batch_id": self.batch_id,
            "fence_id": self.fence_id,
            "nullifier_id": self.nullifier_id,
            "proof_id": self.proof_id,
            "deterministic_replay_root": self.deterministic_replay_root,
            "replay_window_root": self.replay_window_root,
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
    pub transition_fences: BTreeMap<String, TransitionFence>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub pq_replay_proofs: BTreeMap<String, PqReplayProof>,
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
            transition_fences: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            pq_replay_proofs: BTreeMap::new(),
            sealed_rollback_roots: BTreeMap::new(),
            sealed_compensation_roots: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            deterministic_traces: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let domain = TransitionDomain::CrossContractCall;
        let fence_id = transition_fence_id(
            domain,
            "contract-private-router",
            "caller-commitment-alice",
            DEVNET_HEIGHT,
        );
        let nullifier_id = replay_nullifier_id(&fence_id, "sealed-vault-route-call", 0);
        let proof_id = pq_replay_proof_id(&nullifier_id, "devnet-replay-proof", 0);
        let rollback_id = rollback_root_id(&fence_id, &nullifier_id, "vault-route-rollback", 0);
        let compensation_id =
            compensation_root_id(&fence_id, &nullifier_id, "vault-route-compensation", 0);
        let operator_id = operator_id("devnet-replay-guard-operator-alpha", DEVNET_EPOCH);
        let batch_id = execution_batch_id(&operator_id, DEVNET_EPOCH, DEVNET_HEIGHT + 2);
        let trace_id = deterministic_trace_id(&batch_id, &fence_id, &nullifier_id, &proof_id);

        state.transition_fences.insert(
            fence_id.clone(),
            TransitionFence {
                fence_id: fence_id.clone(),
                contract_id: "contract-private-router".to_string(),
                domain,
                caller_commitment: "caller-commitment-alice".to_string(),
                sealed_transition_root: deterministic_root("sealed-transition", "vault-route", 0),
                pre_state_root: deterministic_root("pre-state", "vault-route", 0),
                expected_post_state_root: deterministic_root("post-state", "vault-route", 1),
                replay_window_start_height: DEVNET_HEIGHT,
                replay_window_end_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
                status: ReplayGuardStatus::Accepted,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            },
        );
        state.replay_nullifiers.insert(
            nullifier_id.clone(),
            ReplayNullifier {
                nullifier_id: nullifier_id.clone(),
                fence_id: fence_id.clone(),
                transition_commitment: deterministic_root(
                    "transition-commitment",
                    "sealed-vault-route-call",
                    0,
                ),
                caller_commitment: "caller-commitment-alice".to_string(),
                first_seen_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
                duplicate: false,
                duplicate_evidence_root: None,
            },
        );
        state.pq_replay_proofs.insert(
            proof_id.clone(),
            PqReplayProof {
                proof_id: proof_id.clone(),
                nullifier_id: nullifier_id.clone(),
                fence_id: fence_id.clone(),
                predecessor_state_root: deterministic_root("predecessor-state", "vault-route", 0),
                successor_state_root: deterministic_root("successor-state", "vault-route", 1),
                replay_transcript_root: deterministic_root("replay-transcript", "vault-route", 0),
                pq_public_key_root: deterministic_root("pq-public-key", "operator-alpha", 0),
                pq_signature_root: deterministic_root("pq-signature", "replay-proof", 0),
                status: PqReplayProofStatus::Applied,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT + 1,
            },
        );
        state.sealed_rollback_roots.insert(
            rollback_id.clone(),
            SealedRollbackRoot {
                rollback_id,
                fence_id: fence_id.clone(),
                nullifier_id: nullifier_id.clone(),
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
                fence_id: fence_id.clone(),
                nullifier_id: nullifier_id.clone(),
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
                fence_root: root_for_values(TRANSITION_FENCE_SCHEME, &[json!(fence_id)]),
                nullifier_root: root_for_values(REPLAY_NULLIFIER_SCHEME, &[json!(nullifier_id)]),
                pq_proof_root: root_for_values(PQ_REPLAY_PROOF_SCHEME, &[json!(proof_id)]),
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
                nullifier_count: 1,
                aggregate_fee_micro_units: DEFAULT_BASE_GUARD_MICRO_FEE,
                low_fee_eligible: true,
                executed_height: DEVNET_HEIGHT + 2,
            },
        );
        state.deterministic_traces.insert(
            trace_id.clone(),
            DeterministicTrace {
                trace_id,
                batch_id,
                fence_id,
                nullifier_id,
                proof_id,
                deterministic_replay_root: deterministic_root("replay", "vault-route", 0),
                replay_window_root: deterministic_root("replay-window", "vault-route", 0),
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
        let fixture_id = fixture_id("sealed-transition-replay-guard-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "sealed-transition-replay-guard-demo".to_string(),
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
            "kind": "private_l2_pq_confidential_contract_sealed_transition_replay_guard_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_transition_replay_guard_suite": SEALED_TRANSITION_REPLAY_GUARD_SUITE,
            "pq_replay_proof_suite": PQ_REPLAY_PROOF_SUITE,
            "sealed_rollback_suite": SEALED_ROLLBACK_SUITE,
            "sealed_compensation_suite": SEALED_COMPENSATION_SUITE,
            "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
            "deterministic_replay_suite": DETERMINISTIC_REPLAY_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "transition_fences": self.transition_fences.values().map(TransitionFence::public_record).collect::<Vec<_>>(),
            "replay_nullifiers": self.replay_nullifiers.values().map(ReplayNullifier::public_record).collect::<Vec<_>>(),
            "pq_replay_proofs": self.pq_replay_proofs.values().map(PqReplayProof::public_record).collect::<Vec<_>>(),
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
            transition_fences: self.transition_fences.len() as u64,
            active_transition_fences: self
                .transition_fences
                .values()
                .filter(|fence| fence.status.active())
                .count() as u64,
            replay_nullifiers: self.replay_nullifiers.len() as u64,
            duplicate_nullifiers: self
                .replay_nullifiers
                .values()
                .filter(|nullifier| nullifier.duplicate)
                .count() as u64,
            pq_replay_proofs: self.pq_replay_proofs.len() as u64,
            authenticated_pq_replay_proofs: self
                .pq_replay_proofs
                .values()
                .filter(|proof| {
                    matches!(
                        proof.status,
                        PqReplayProofStatus::Authenticated | PqReplayProofStatus::Applied
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
            transition_fence_root: record_root(
                TRANSITION_FENCE_SCHEME,
                self.transition_fences
                    .values()
                    .map(TransitionFence::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                self.replay_nullifiers
                    .values()
                    .map(ReplayNullifier::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_replay_proof_root: record_root(
                PQ_REPLAY_PROOF_SCHEME,
                self.pq_replay_proofs
                    .values()
                    .map(PqReplayProof::public_record)
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

pub fn transition_fence_id(
    domain: TransitionDomain,
    contract_id: &str,
    caller_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:FENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(caller_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn replay_nullifier_id(fence_id: &str, transition_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:NULLIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(fence_id),
            HashPart::Str(transition_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_replay_proof_id(nullifier_id: &str, proof_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:PQ-PROOF-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(nullifier_id),
            HashPart::Str(proof_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn rollback_root_id(
    fence_id: &str,
    nullifier_id: &str,
    root_label: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:ROLLBACK-ROOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(fence_id),
            HashPart::Str(nullifier_id),
            HashPart::Str(root_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn compensation_root_id(
    fence_id: &str,
    nullifier_id: &str,
    root_label: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:COMPENSATION-ROOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(fence_id),
            HashPart::Str(nullifier_id),
            HashPart::Str(root_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn operator_id(operator_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:OPERATOR-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn deterministic_trace_id(
    batch_id: &str,
    fence_id: &str,
    nullifier_id: &str,
    proof_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:TRACE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(fence_id),
            HashPart::Str(nullifier_id),
            HashPart::Str(proof_id),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:FIXTURE-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:DETERMINISTIC-ROOT",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-TRANSITION-REPLAY-GUARD:STATE-ROOT",
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
