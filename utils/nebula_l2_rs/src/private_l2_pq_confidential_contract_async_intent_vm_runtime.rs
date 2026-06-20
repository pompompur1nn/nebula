use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractAsyncIntentVmRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractAsyncIntentVmRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ASYNC_INTENT_VM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-async-intent-vm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_ASYNC_INTENT_VM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ASYNC_INTENT_SUITE: &str = "ML-KEM-1024+confidential-async-contract-intent-v1";
pub const PRIVATE_RECEIPT_SUITE: &str = "zk-private-contract-call-receipt-with-redacted-events-v1";
pub const PQ_SOLVER_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-authenticated-solver-session-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-confidential-async-intent-batch-execution-v1";
pub const VM_TRACE_SUITE: &str = "deterministic-confidential-async-intent-vm-trace-v1";
pub const INTENT_QUEUE_SCHEME: &str = "confidential-async-intent-queue-root-v1";
pub const SOLVER_AUTH_SCHEME: &str = "pq-authenticated-solver-root-v1";
pub const PRIVATE_RECEIPT_SCHEME: &str = "private-contract-call-receipt-root-v1";
pub const EXECUTION_BATCH_SCHEME: &str = "low-fee-async-intent-execution-batch-root-v1";
pub const VM_TRACE_SCHEME: &str = "async-intent-vm-trace-root-v1";
pub const FEE_REBATE_SCHEME: &str = "async-intent-low-fee-rebate-root-v1";
pub const FIXTURE_SCHEME: &str = "async-intent-vm-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 4_720_128;
pub const DEVNET_EPOCH: u64 = 9_216;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_INTENTS_PER_BATCH: usize = 2_048;
pub const DEFAULT_MAX_CALLS_PER_INTENT: usize = 32;
pub const DEFAULT_MAX_RECEIPTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_SOLVER_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_BASE_EXECUTION_MICRO_FEE: u64 = 7;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 25_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncIntentKind {
    ContractCall,
    CrossContractCall,
    DeferredSettlement,
    OracleCallback,
    AccountAbstraction,
    VaultRebalance,
    LiquidationBackstop,
    GovernanceExecution,
}

impl AsyncIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::CrossContractCall => "cross_contract_call",
            Self::DeferredSettlement => "deferred_settlement",
            Self::OracleCallback => "oracle_callback",
            Self::AccountAbstraction => "account_abstraction",
            Self::VaultRebalance => "vault_rebalance",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::GovernanceExecution => "governance_execution",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Queued,
    SolverLocked,
    Batched,
    Executing,
    ReceiptCommitted,
    Finalized,
    Reverted,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::SolverLocked => "solver_locked",
            Self::Batched => "batched",
            Self::Executing => "executing",
            Self::ReceiptCommitted => "receipt_committed",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::SolverLocked | Self::Batched | Self::Executing
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverAuthStatus {
    Pending,
    Active,
    RateLimited,
    Quarantined,
    Slashed,
    Retired,
}

impl SolverAuthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Quarantined => "quarantined",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    PrivateCommitted,
    ProofReady,
    Finalized,
    Reverted,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCommitted => "private_committed",
            Self::ProofReady => "proof_ready",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Challenged => "challenged",
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
    pub async_intent_suite: String,
    pub private_receipt_suite: String,
    pub pq_solver_auth_suite: String,
    pub low_fee_batch_suite: String,
    pub vm_trace_suite: String,
    pub intent_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_calls_per_intent: usize,
    pub max_receipts_per_batch: usize,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub solver_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub base_execution_micro_fee: u64,
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
            async_intent_suite: ASYNC_INTENT_SUITE.to_string(),
            private_receipt_suite: PRIVATE_RECEIPT_SUITE.to_string(),
            pq_solver_auth_suite: PQ_SOLVER_AUTH_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            vm_trace_suite: VM_TRACE_SUITE.to_string(),
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_intents_per_batch: DEFAULT_MAX_INTENTS_PER_BATCH,
            max_calls_per_intent: DEFAULT_MAX_CALLS_PER_INTENT,
            max_receipts_per_batch: DEFAULT_MAX_RECEIPTS_PER_BATCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            solver_fee_bps: DEFAULT_SOLVER_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            base_execution_micro_fee: DEFAULT_BASE_EXECUTION_MICRO_FEE,
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
            || self.solver_fee_bps > MAX_BPS
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
    pub async_intents: u64,
    pub live_intents: u64,
    pub pq_solver_authentications: u64,
    pub execution_batches: u64,
    pub private_call_receipts: u64,
    pub finalized_receipts: u64,
    pub vm_traces: u64,
    pub low_fee_rebates: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub async_intent_root: String,
    pub pq_solver_auth_root: String,
    pub execution_batch_root: String,
    pub private_call_receipt_root: String,
    pub vm_trace_root: String,
    pub low_fee_rebate_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            async_intent_root: merkle_root(INTENT_QUEUE_SCHEME, &[]),
            pq_solver_auth_root: merkle_root(SOLVER_AUTH_SCHEME, &[]),
            execution_batch_root: merkle_root(EXECUTION_BATCH_SCHEME, &[]),
            private_call_receipt_root: merkle_root(PRIVATE_RECEIPT_SCHEME, &[]),
            vm_trace_root: merkle_root(VM_TRACE_SCHEME, &[]),
            low_fee_rebate_root: merkle_root(FEE_REBATE_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AsyncIntent {
    pub intent_id: String,
    pub kind: AsyncIntentKind,
    pub status: IntentStatus,
    pub sender_commitment: String,
    pub contract_id: String,
    pub encrypted_call_root: String,
    pub dependency_root: String,
    pub nullifier_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl AsyncIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "sender_commitment": self.sender_commitment,
            "contract_id": self.contract_id,
            "encrypted_call_root": self.encrypted_call_root,
            "dependency_root": self.dependency_root,
            "nullifier_root": self.nullifier_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqSolverAuthentication {
    pub solver_id: String,
    pub status: SolverAuthStatus,
    pub ml_kem_public_key_root: String,
    pub ml_dsa_public_key_root: String,
    pub slh_dsa_public_key_root: String,
    pub session_transcript_root: String,
    pub stake_commitment: String,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
    pub expires_height: u64,
}

impl PqSolverAuthentication {
    pub fn public_record(&self) -> Value {
        json!({
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "ml_kem_public_key_root": self.ml_kem_public_key_root,
            "ml_dsa_public_key_root": self.ml_dsa_public_key_root,
            "slh_dsa_public_key_root": self.slh_dsa_public_key_root,
            "session_transcript_root": self.session_transcript_root,
            "stake_commitment": self.stake_commitment,
            "pq_security_bits": self.pq_security_bits,
            "authenticated_height": self.authenticated_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ExecutionBatch {
    pub batch_id: String,
    pub solver_id: String,
    pub epoch: u64,
    pub intent_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub receipt_root: String,
    pub total_vm_steps: u64,
    pub aggregate_fee_micro_units: u64,
    pub low_fee_eligible: bool,
    pub executed_height: u64,
}

impl ExecutionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "solver_id": self.solver_id,
            "epoch": self.epoch,
            "intent_root": self.intent_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "receipt_root": self.receipt_root,
            "total_vm_steps": self.total_vm_steps,
            "aggregate_fee_micro_units": self.aggregate_fee_micro_units,
            "low_fee_eligible": self.low_fee_eligible,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateCallReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub solver_id: String,
    pub status: ReceiptStatus,
    pub private_event_root: String,
    pub state_delta_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub proof_root: String,
    pub redaction_policy_root: String,
    pub committed_height: u64,
}

impl PrivateCallReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "solver_id": self.solver_id,
            "status": self.status.as_str(),
            "private_event_root": self.private_event_root,
            "state_delta_root": self.state_delta_root,
            "output_note_root": self.output_note_root,
            "fee_note_root": self.fee_note_root,
            "proof_root": self.proof_root,
            "redaction_policy_root": self.redaction_policy_root,
            "committed_height": self.committed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VmTraceCommitment {
    pub trace_id: String,
    pub batch_id: String,
    pub receipt_id: String,
    pub opcode_histogram_root: String,
    pub witness_access_root: String,
    pub deterministic_replay_root: String,
    pub gas_commitment_root: String,
}

impl VmTraceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "opcode_histogram_root": self.opcode_histogram_root,
            "witness_access_root": self.witness_access_root,
            "deterministic_replay_root": self.deterministic_replay_root,
            "gas_commitment_root": self.gas_commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub rebate_note_root: String,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "rebate_note_root": self.rebate_note_root,
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
    pub async_intents: BTreeMap<String, AsyncIntent>,
    pub pq_solver_authentications: BTreeMap<String, PqSolverAuthentication>,
    pub execution_batches: BTreeMap<String, ExecutionBatch>,
    pub private_call_receipts: BTreeMap<String, PrivateCallReceipt>,
    pub vm_traces: BTreeMap<String, VmTraceCommitment>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            async_intents: BTreeMap::new(),
            pq_solver_authentications: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            private_call_receipts: BTreeMap::new(),
            vm_traces: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let solver_id = solver_id("devnet-solver-alpha", DEVNET_EPOCH);
        let intent_id = async_intent_id(
            AsyncIntentKind::CrossContractCall,
            "sender-commitment-alice",
            "contract-vault-router",
            DEVNET_HEIGHT,
        );
        let batch_id = execution_batch_id(&solver_id, DEVNET_EPOCH, DEVNET_HEIGHT);
        let receipt_id = private_receipt_id(&batch_id, &intent_id, &solver_id);
        let trace_id = vm_trace_id(&batch_id, &receipt_id, 0);
        let rebate_id = low_fee_rebate_id(&batch_id, "sender-commitment-alice", DEVNET_HEIGHT);

        state.async_intents.insert(
            intent_id.clone(),
            AsyncIntent {
                intent_id: intent_id.clone(),
                kind: AsyncIntentKind::CrossContractCall,
                status: IntentStatus::Finalized,
                sender_commitment: "sender-commitment-alice".to_string(),
                contract_id: "contract-vault-router".to_string(),
                encrypted_call_root: deterministic_root("encrypted-call", "alice-vault-route", 0),
                dependency_root: deterministic_root("dependency", "vault-router+oracle", 0),
                nullifier_root: deterministic_root("nullifier", "alice-async-intent", 0),
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                submitted_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_INTENT_TTL_BLOCKS,
            },
        );
        state.pq_solver_authentications.insert(
            solver_id.clone(),
            PqSolverAuthentication {
                solver_id: solver_id.clone(),
                status: SolverAuthStatus::Active,
                ml_kem_public_key_root: deterministic_root("ml-kem-pk", "solver-alpha", 0),
                ml_dsa_public_key_root: deterministic_root("ml-dsa-pk", "solver-alpha", 0),
                slh_dsa_public_key_root: deterministic_root("slh-dsa-pk", "solver-alpha", 0),
                session_transcript_root: deterministic_root("session", "solver-alpha", 0),
                stake_commitment: deterministic_root("stake", "solver-alpha", 0),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_RECEIPT_TTL_BLOCKS,
            },
        );
        state.private_call_receipts.insert(
            receipt_id.clone(),
            PrivateCallReceipt {
                receipt_id: receipt_id.clone(),
                batch_id: batch_id.clone(),
                intent_id: intent_id.clone(),
                solver_id: solver_id.clone(),
                status: ReceiptStatus::Finalized,
                private_event_root: deterministic_root("private-events", "alice-vault-route", 0),
                state_delta_root: deterministic_root("state-delta", "alice-vault-route", 0),
                output_note_root: deterministic_root("output-note", "alice-vault-route", 0),
                fee_note_root: deterministic_root("fee-note", "alice-vault-route", 0),
                proof_root: deterministic_root("receipt-proof", "alice-vault-route", 0),
                redaction_policy_root: deterministic_root(
                    "redaction-policy",
                    "alice-vault-route",
                    0,
                ),
                committed_height: DEVNET_HEIGHT + 1,
            },
        );
        state.execution_batches.insert(
            batch_id.clone(),
            ExecutionBatch {
                batch_id: batch_id.clone(),
                solver_id: solver_id.clone(),
                epoch: DEVNET_EPOCH,
                intent_root: root_for_values(INTENT_QUEUE_SCHEME, &[json!(intent_id)]),
                pre_state_root: deterministic_root("pre-state", "async-batch", DEVNET_EPOCH),
                post_state_root: deterministic_root("post-state", "async-batch", DEVNET_EPOCH),
                receipt_root: root_for_values(PRIVATE_RECEIPT_SCHEME, &[json!(receipt_id)]),
                total_vm_steps: 418_304,
                aggregate_fee_micro_units: DEFAULT_BASE_EXECUTION_MICRO_FEE,
                low_fee_eligible: true,
                executed_height: DEVNET_HEIGHT + 1,
            },
        );
        state.vm_traces.insert(
            trace_id.clone(),
            VmTraceCommitment {
                trace_id,
                batch_id: batch_id.clone(),
                receipt_id,
                opcode_histogram_root: deterministic_root("opcode-histogram", "async-batch", 0),
                witness_access_root: deterministic_root("witness-access", "async-batch", 0),
                deterministic_replay_root: deterministic_root("replay", "async-batch", 0),
                gas_commitment_root: deterministic_root("gas", "async-batch", 0),
            },
        );
        state.low_fee_rebates.insert(
            rebate_id.clone(),
            LowFeeRebate {
                rebate_id,
                batch_id,
                beneficiary_commitment: "sender-commitment-alice".to_string(),
                fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
                rebate_bps: DEFAULT_BATCH_REBATE_BPS,
                rebate_note_root: deterministic_root("rebate-note", "alice-vault-route", 0),
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("async-intent-vm-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "async-intent-vm-demo".to_string(),
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
            "kind": "private_l2_pq_confidential_contract_async_intent_vm_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "async_intent_suite": ASYNC_INTENT_SUITE,
            "private_receipt_suite": PRIVATE_RECEIPT_SUITE,
            "pq_solver_auth_suite": PQ_SOLVER_AUTH_SUITE,
            "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
            "vm_trace_suite": VM_TRACE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "async_intents": self.async_intents.values().map(AsyncIntent::public_record).collect::<Vec<_>>(),
            "pq_solver_authentications": self.pq_solver_authentications.values().map(PqSolverAuthentication::public_record).collect::<Vec<_>>(),
            "execution_batches": self.execution_batches.values().map(ExecutionBatch::public_record).collect::<Vec<_>>(),
            "private_call_receipts": self.private_call_receipts.values().map(PrivateCallReceipt::public_record).collect::<Vec<_>>(),
            "vm_traces": self.vm_traces.values().map(VmTraceCommitment::public_record).collect::<Vec<_>>(),
            "low_fee_rebates": self.low_fee_rebates.values().map(LowFeeRebate::public_record).collect::<Vec<_>>(),
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
            async_intents: self.async_intents.len() as u64,
            live_intents: self
                .async_intents
                .values()
                .filter(|intent| intent.status.live())
                .count() as u64,
            pq_solver_authentications: self.pq_solver_authentications.len() as u64,
            execution_batches: self.execution_batches.len() as u64,
            private_call_receipts: self.private_call_receipts.len() as u64,
            finalized_receipts: self
                .private_call_receipts
                .values()
                .filter(|receipt| receipt.status == ReceiptStatus::Finalized)
                .count() as u64,
            vm_traces: self.vm_traces.len() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            async_intent_root: record_root(
                INTENT_QUEUE_SCHEME,
                self.async_intents
                    .values()
                    .map(AsyncIntent::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_solver_auth_root: record_root(
                SOLVER_AUTH_SCHEME,
                self.pq_solver_authentications
                    .values()
                    .map(PqSolverAuthentication::public_record)
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
            private_call_receipt_root: record_root(
                PRIVATE_RECEIPT_SCHEME,
                self.private_call_receipts
                    .values()
                    .map(PrivateCallReceipt::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            vm_trace_root: record_root(
                VM_TRACE_SCHEME,
                self.vm_traces
                    .values()
                    .map(VmTraceCommitment::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            low_fee_rebate_root: record_root(
                FEE_REBATE_SCHEME,
                self.low_fee_rebates
                    .values()
                    .map(LowFeeRebate::public_record)
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

pub fn async_intent_id(
    kind: AsyncIntentKind,
    sender_commitment: &str,
    contract_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(contract_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn solver_id(solver_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-SOLVER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(solver_commitment),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn execution_batch_id(solver_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(solver_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn private_receipt_id(batch_id: &str, intent_id: &str, solver_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-PRIVATE-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(intent_id),
            HashPart::Str(solver_id),
        ],
        32,
    )
}

pub fn vm_trace_id(batch_id: &str, receipt_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-VM-TRACE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(receipt_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(batch_id: &str, beneficiary_commitment: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-FIXTURE-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-DETERMINISTIC-ROOT",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-ASYNC-INTENT-VM-STATE-ROOT",
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
