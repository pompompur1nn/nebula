use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractPrivateEventSagaVmRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractPrivateEventSagaVmRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_SAGA_VM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-private-event-saga-vm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_EVENT_SAGA_VM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_EVENT_SAGA_SUITE: &str =
    "confidential-contract-private-event-saga-vm-continuation-v1";
pub const PQ_CONTINUATION_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-event-continuation-v1";
pub const SEALED_COMPENSATION_SUITE: &str = "sealed-confidential-saga-compensating-action-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "low-fee-private-event-saga-settlement-batch-v1";
pub const VM_TRACE_SUITE: &str = "deterministic-private-event-saga-vm-trace-v1";
pub const SAGA_SCHEME: &str = "private-event-saga-root-v1";
pub const CONTINUATION_SCHEME: &str = "pq-event-continuation-root-v1";
pub const COMPENSATION_SCHEME: &str = "sealed-compensating-action-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str = "low-fee-saga-settlement-batch-root-v1";
pub const VM_TRACE_SCHEME: &str = "private-event-saga-vm-trace-root-v1";
pub const FIXTURE_SCHEME: &str = "private-event-saga-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_041_920;
pub const DEVNET_EPOCH: u64 = 10_004;
pub const DEFAULT_SAGA_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_CONTINUATION_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_MAX_SAGAS_PER_BATCH: usize = 1_024;
pub const DEFAULT_MAX_CONTINUATIONS_PER_SAGA: usize = 128;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 10;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 4;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 6;
pub const DEFAULT_BASE_SAGA_MICRO_FEE: u64 = 11;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 40_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaKind {
    ContractWorkflow,
    CrossContractWorkflow,
    OracleMediatedWorkflow,
    BridgeEscrowWorkflow,
    LiquidationWorkflow,
    GovernanceWorkflow,
    AccountRecoveryWorkflow,
}

impl SagaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractWorkflow => "contract_workflow",
            Self::CrossContractWorkflow => "cross_contract_workflow",
            Self::OracleMediatedWorkflow => "oracle_mediated_workflow",
            Self::BridgeEscrowWorkflow => "bridge_escrow_workflow",
            Self::LiquidationWorkflow => "liquidation_workflow",
            Self::GovernanceWorkflow => "governance_workflow",
            Self::AccountRecoveryWorkflow => "account_recovery_workflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaStatus {
    Open,
    AwaitingContinuation,
    Continuing,
    Compensating,
    Batched,
    Settled,
    Reverted,
    Expired,
}

impl SagaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AwaitingContinuation => "awaiting_continuation",
            Self::Continuing => "continuing",
            Self::Compensating => "compensating",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::AwaitingContinuation | Self::Continuing | Self::Compensating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationStatus {
    Proposed,
    PqAuthenticated,
    Applied,
    Rejected,
    Expired,
}

impl ContinuationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PqAuthenticated => "pq_authenticated",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompensationStatus {
    Sealed,
    Armed,
    Executed,
    Cancelled,
}

impl CompensationStatus {
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
    pub private_event_saga_suite: String,
    pub pq_continuation_auth_suite: String,
    pub sealed_compensation_suite: String,
    pub low_fee_batch_suite: String,
    pub vm_trace_suite: String,
    pub saga_ttl_blocks: u64,
    pub continuation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_sagas_per_batch: usize,
    pub max_continuations_per_saga: usize,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub base_saga_micro_fee: u64,
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
            private_event_saga_suite: PRIVATE_EVENT_SAGA_SUITE.to_string(),
            pq_continuation_auth_suite: PQ_CONTINUATION_AUTH_SUITE.to_string(),
            sealed_compensation_suite: SEALED_COMPENSATION_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            vm_trace_suite: VM_TRACE_SUITE.to_string(),
            saga_ttl_blocks: DEFAULT_SAGA_TTL_BLOCKS,
            continuation_ttl_blocks: DEFAULT_CONTINUATION_TTL_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            max_sagas_per_batch: DEFAULT_MAX_SAGAS_PER_BATCH,
            max_continuations_per_saga: DEFAULT_MAX_CONTINUATIONS_PER_SAGA,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            base_saga_micro_fee: DEFAULT_BASE_SAGA_MICRO_FEE,
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
    pub pq_event_continuations: u64,
    pub applied_continuations: u64,
    pub sealed_compensating_actions: u64,
    pub executed_compensations: u64,
    pub settlement_batches: u64,
    pub vm_traces: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub saga_root: String,
    pub pq_event_continuation_root: String,
    pub sealed_compensating_action_root: String,
    pub settlement_batch_root: String,
    pub vm_trace_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            saga_root: merkle_root(SAGA_SCHEME, &[]),
            pq_event_continuation_root: merkle_root(CONTINUATION_SCHEME, &[]),
            sealed_compensating_action_root: merkle_root(COMPENSATION_SCHEME, &[]),
            settlement_batch_root: merkle_root(SETTLEMENT_BATCH_SCHEME, &[]),
            vm_trace_root: merkle_root(VM_TRACE_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateEventSaga {
    pub saga_id: String,
    pub kind: SagaKind,
    pub status: SagaStatus,
    pub contract_id: String,
    pub initiator_commitment: String,
    pub private_event_root: String,
    pub encrypted_state_root: String,
    pub continuation_root: String,
    pub compensation_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivateEventSaga {
    pub fn public_record(&self) -> Value {
        json!({
            "saga_id": self.saga_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "contract_id": self.contract_id,
            "initiator_commitment": self.initiator_commitment,
            "private_event_root": self.private_event_root,
            "encrypted_state_root": self.encrypted_state_root,
            "continuation_root": self.continuation_root,
            "compensation_root": self.compensation_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqEventContinuation {
    pub continuation_id: String,
    pub saga_id: String,
    pub predecessor_event_root: String,
    pub continuation_event_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub status: ContinuationStatus,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
    pub expires_height: u64,
}

impl PqEventContinuation {
    pub fn public_record(&self) -> Value {
        json!({
            "continuation_id": self.continuation_id,
            "saga_id": self.saga_id,
            "predecessor_event_root": self.predecessor_event_root,
            "continuation_event_root": self.continuation_event_root,
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
pub struct SealedCompensatingAction {
    pub action_id: String,
    pub saga_id: String,
    pub trigger_event_root: String,
    pub sealed_action_root: String,
    pub recovery_note_root: String,
    pub status: CompensationStatus,
    pub timelock_height: u64,
    pub executed_height: Option<u64>,
}

impl SealedCompensatingAction {
    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "saga_id": self.saga_id,
            "trigger_event_root": self.trigger_event_root,
            "sealed_action_root": self.sealed_action_root,
            "recovery_note_root": self.recovery_note_root,
            "status": self.status.as_str(),
            "timelock_height": self.timelock_height,
            "executed_height": self.executed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub saga_root: String,
    pub continuation_root: String,
    pub compensation_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub total_vm_steps: u64,
    pub aggregate_fee_micro_units: u64,
    pub low_fee_eligible: bool,
    pub settled_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "saga_root": self.saga_root,
            "continuation_root": self.continuation_root,
            "compensation_root": self.compensation_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "total_vm_steps": self.total_vm_steps,
            "aggregate_fee_micro_units": self.aggregate_fee_micro_units,
            "low_fee_eligible": self.low_fee_eligible,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VmTraceCommitment {
    pub trace_id: String,
    pub batch_id: String,
    pub saga_id: String,
    pub continuation_id: String,
    pub deterministic_replay_root: String,
    pub witness_access_root: String,
    pub compensation_branch_root: String,
    pub fee_meter_root: String,
}

impl VmTraceCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "trace_id": self.trace_id,
            "batch_id": self.batch_id,
            "saga_id": self.saga_id,
            "continuation_id": self.continuation_id,
            "deterministic_replay_root": self.deterministic_replay_root,
            "witness_access_root": self.witness_access_root,
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
    pub private_event_sagas: BTreeMap<String, PrivateEventSaga>,
    pub pq_event_continuations: BTreeMap<String, PqEventContinuation>,
    pub sealed_compensating_actions: BTreeMap<String, SealedCompensatingAction>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub vm_traces: BTreeMap<String, VmTraceCommitment>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            private_event_sagas: BTreeMap::new(),
            pq_event_continuations: BTreeMap::new(),
            sealed_compensating_actions: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            vm_traces: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let operator_id = operator_id("devnet-saga-operator-alpha", DEVNET_EPOCH);
        let saga_id = saga_id(
            SagaKind::CrossContractWorkflow,
            "contract-private-escrow-router",
            "initiator-commitment-alice",
            DEVNET_HEIGHT,
        );
        let continuation_id = continuation_id(&saga_id, "escrow-private-event-0001", 0);
        let action_id = compensating_action_id(&saga_id, "refund-branch", 0);
        let batch_id = settlement_batch_id(&operator_id, DEVNET_EPOCH, DEVNET_HEIGHT + 2);
        let trace_id = vm_trace_id(&batch_id, &saga_id, &continuation_id);

        state.private_event_sagas.insert(
            saga_id.clone(),
            PrivateEventSaga {
                saga_id: saga_id.clone(),
                kind: SagaKind::CrossContractWorkflow,
                status: SagaStatus::Settled,
                contract_id: "contract-private-escrow-router".to_string(),
                initiator_commitment: "initiator-commitment-alice".to_string(),
                private_event_root: deterministic_root("private-event", "escrow-opened", 0),
                encrypted_state_root: deterministic_root("encrypted-state", "escrow-saga", 0),
                continuation_root: deterministic_root("continuation", "escrow-fulfilled", 0),
                compensation_root: deterministic_root("compensation", "refund-branch", 0),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                opened_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_SAGA_TTL_BLOCKS,
            },
        );
        state.pq_event_continuations.insert(
            continuation_id.clone(),
            PqEventContinuation {
                continuation_id: continuation_id.clone(),
                saga_id: saga_id.clone(),
                predecessor_event_root: deterministic_root("predecessor-event", "escrow-opened", 0),
                continuation_event_root: deterministic_root(
                    "continuation-event",
                    "escrow-fulfilled",
                    0,
                ),
                pq_public_key_root: deterministic_root("pq-public-key", "operator-alpha", 0),
                pq_signature_root: deterministic_root("pq-signature", "escrow-continuation", 0),
                transcript_root: deterministic_root("pq-transcript", "escrow-continuation", 0),
                status: ContinuationStatus::Applied,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT + 1,
                expires_height: DEVNET_HEIGHT + 1 + DEFAULT_CONTINUATION_TTL_BLOCKS,
            },
        );
        state.sealed_compensating_actions.insert(
            action_id.clone(),
            SealedCompensatingAction {
                action_id,
                saga_id: saga_id.clone(),
                trigger_event_root: deterministic_root("trigger-event", "escrow-timeout", 0),
                sealed_action_root: deterministic_root("sealed-action", "refund-alice", 0),
                recovery_note_root: deterministic_root("recovery-note", "refund-alice", 0),
                status: CompensationStatus::Cancelled,
                timelock_height: DEVNET_HEIGHT + 32,
                executed_height: None,
            },
        );
        state.settlement_batches.insert(
            batch_id.clone(),
            SettlementBatch {
                batch_id: batch_id.clone(),
                operator_id,
                epoch: DEVNET_EPOCH,
                saga_root: root_for_values(SAGA_SCHEME, &[json!(saga_id)]),
                continuation_root: root_for_values(CONTINUATION_SCHEME, &[json!(continuation_id)]),
                compensation_root: root_for_values(COMPENSATION_SCHEME, &[json!("refund-branch")]),
                pre_state_root: deterministic_root("pre-state", "saga-batch", DEVNET_EPOCH),
                post_state_root: deterministic_root("post-state", "saga-batch", DEVNET_EPOCH),
                total_vm_steps: 733_184,
                aggregate_fee_micro_units: DEFAULT_BASE_SAGA_MICRO_FEE,
                low_fee_eligible: true,
                settled_height: DEVNET_HEIGHT + 2,
            },
        );
        state.vm_traces.insert(
            trace_id.clone(),
            VmTraceCommitment {
                trace_id,
                batch_id,
                saga_id,
                continuation_id,
                deterministic_replay_root: deterministic_root("replay", "saga-batch", 0),
                witness_access_root: deterministic_root("witness-access", "saga-batch", 0),
                compensation_branch_root: deterministic_root("compensation-branch", "refund", 0),
                fee_meter_root: deterministic_root("fee-meter", "saga-batch", 0),
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("private-event-saga-vm-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "private-event-saga-vm-demo".to_string(),
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
            "kind": "private_l2_pq_confidential_contract_private_event_saga_vm_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "private_event_saga_suite": PRIVATE_EVENT_SAGA_SUITE,
            "pq_continuation_auth_suite": PQ_CONTINUATION_AUTH_SUITE,
            "sealed_compensation_suite": SEALED_COMPENSATION_SUITE,
            "low_fee_batch_suite": LOW_FEE_BATCH_SUITE,
            "vm_trace_suite": VM_TRACE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "private_event_sagas": self.private_event_sagas.values().map(PrivateEventSaga::public_record).collect::<Vec<_>>(),
            "pq_event_continuations": self.pq_event_continuations.values().map(PqEventContinuation::public_record).collect::<Vec<_>>(),
            "sealed_compensating_actions": self.sealed_compensating_actions.values().map(SealedCompensatingAction::public_record).collect::<Vec<_>>(),
            "settlement_batches": self.settlement_batches.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),
            "vm_traces": self.vm_traces.values().map(VmTraceCommitment::public_record).collect::<Vec<_>>(),
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
            sagas: self.private_event_sagas.len() as u64,
            live_sagas: self
                .private_event_sagas
                .values()
                .filter(|saga| saga.status.live())
                .count() as u64,
            pq_event_continuations: self.pq_event_continuations.len() as u64,
            applied_continuations: self
                .pq_event_continuations
                .values()
                .filter(|continuation| continuation.status == ContinuationStatus::Applied)
                .count() as u64,
            sealed_compensating_actions: self.sealed_compensating_actions.len() as u64,
            executed_compensations: self
                .sealed_compensating_actions
                .values()
                .filter(|action| action.status == CompensationStatus::Executed)
                .count() as u64,
            settlement_batches: self.settlement_batches.len() as u64,
            vm_traces: self.vm_traces.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            saga_root: record_root(
                SAGA_SCHEME,
                self.private_event_sagas
                    .values()
                    .map(PrivateEventSaga::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_event_continuation_root: record_root(
                CONTINUATION_SCHEME,
                self.pq_event_continuations
                    .values()
                    .map(PqEventContinuation::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            sealed_compensating_action_root: record_root(
                COMPENSATION_SCHEME,
                self.sealed_compensating_actions
                    .values()
                    .map(SealedCompensatingAction::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            settlement_batch_root: record_root(
                SETTLEMENT_BATCH_SCHEME,
                self.settlement_batches
                    .values()
                    .map(SettlementBatch::public_record)
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
    initiator_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:SAGA-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(initiator_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn continuation_id(saga_id: &str, event_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:CONTINUATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(saga_id),
            HashPart::Str(event_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn compensating_action_id(saga_id: &str, action_label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:COMPENSATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(saga_id),
            HashPart::Str(action_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn operator_id(operator_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:OPERATOR-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn settlement_batch_id(operator_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn vm_trace_id(batch_id: &str, saga_id: &str, continuation_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:TRACE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(saga_id),
            HashPart::Str(continuation_id),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:FIXTURE-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:DETERMINISTIC-ROOT",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-EVENT-SAGA-VM:STATE-ROOT",
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
