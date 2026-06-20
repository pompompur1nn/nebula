use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedCallgraphFeeMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedCallgraphFeeMarketRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_CALLGRAPH_FEE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-callgraph-fee-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_CALLGRAPH_FEE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_CALLGRAPH_FEE_MARKET_SUITE: &str =
    "sealed-confidential-smart-contract-callgraph-fee-market-v1";
pub const PQ_CALLGRAPH_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-callgraph-commitment-attestation-v1";
pub const PRIVATE_EXECUTION_LANE_SUITE: &str = "private-execution-lane-fair-share-v1";
pub const LOW_FEE_BATCHING_SUITE: &str = "low-fee-confidential-callgraph-batching-v1";
pub const REPLAY_RESISTANCE_SUITE: &str = "sealed-callgraph-replay-nullifier-v1";
pub const DETERMINISTIC_ROOT_SUITE: &str = "deterministic-sealed-callgraph-fee-market-root-v1";
pub const CALLGRAPH_COMMITMENT_SCHEME: &str = "sealed-smart-contract-callgraph-commitment-root-v1";
pub const PRIVATE_EXECUTION_LANE_SCHEME: &str = "private-contract-execution-lane-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-callgraph-attestation-root-v1";
pub const REPLAY_GUARD_SCHEME: &str = "sealed-callgraph-replay-guard-root-v1";
pub const FEE_QUOTE_SCHEME: &str = "confidential-callgraph-fee-quote-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-callgraph-batch-root-v1";
pub const STATE_COMMITMENT_SCHEME: &str = "privacy-preserving-callgraph-state-commitment-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "sealed-callgraph-settlement-receipt-root-v1";
pub const FIXTURE_SCHEME: &str = "sealed-callgraph-fee-market-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_314_112;
pub const DEVNET_EPOCH: u64 = 10_381;
pub const DEFAULT_CALLGRAPH_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_LANE_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_CALLS_PER_GRAPH: usize = 512;
pub const DEFAULT_MAX_GRAPH_DEPTH: u8 = 32;
pub const DEFAULT_MAX_PRIVATE_LANES: usize = 128;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 12;
pub const DEFAULT_BASE_CALL_MICRO_FEE: u64 = 7;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 36_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallgraphDomain {
    ContractCall,
    CrossContractCall,
    DefiRoute,
    VaultMutation,
    OracleRead,
    GovernanceExecution,
    AccountRecovery,
    EmergencyPatch,
}

impl CallgraphDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::CrossContractCall => "cross_contract_call",
            Self::DefiRoute => "defi_route",
            Self::VaultMutation => "vault_mutation",
            Self::OracleRead => "oracle_read",
            Self::GovernanceExecution => "governance_execution",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyPatch => "emergency_patch",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPatch => 10_000,
            Self::AccountRecovery => 9_500,
            Self::OracleRead => 8_900,
            Self::VaultMutation => 8_600,
            Self::DefiRoute => 8_250,
            Self::CrossContractCall => 7_900,
            Self::ContractCall => 7_500,
            Self::GovernanceExecution => 6_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneClass {
    Interactive,
    LowFeeBatch,
    OracleGuarded,
    Governance,
    Recovery,
    Emergency,
}

impl LaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::LowFeeBatch => "low_fee_batch",
            Self::OracleGuarded => "oracle_guarded",
            Self::Governance => "governance",
            Self::Recovery => "recovery",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallgraphStatus {
    Sealed,
    LaneReserved,
    PqAttested,
    ReplayGuarded,
    BatchReady,
    Executed,
    Repriced,
    Expired,
    DuplicateRejected,
}

impl CallgraphStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::LaneReserved => "lane_reserved",
            Self::PqAttested => "pq_attested",
            Self::ReplayGuarded => "replay_guarded",
            Self::BatchReady => "batch_ready",
            Self::Executed => "executed",
            Self::Repriced => "repriced",
            Self::Expired => "expired",
            Self::DuplicateRejected => "duplicate_rejected",
        }
    }

    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::LaneReserved
                | Self::PqAttested
                | Self::ReplayGuarded
                | Self::BatchReady
                | Self::Repriced
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Authenticated,
    QuorumSigned,
    Applied,
    Challenged,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authenticated => "authenticated",
            Self::QuorumSigned => "quorum_signed",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayGuardStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

impl ReplayGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Armed => "armed",
            Self::Consumed => "consumed",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Attested,
    Settled,
    Repriced,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Settled => "settled",
            Self::Repriced => "repriced",
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
    pub sealed_callgraph_fee_market_suite: String,
    pub pq_callgraph_attestation_suite: String,
    pub private_execution_lane_suite: String,
    pub low_fee_batching_suite: String,
    pub replay_resistance_suite: String,
    pub deterministic_root_suite: String,
    pub callgraph_window_blocks: u64,
    pub lane_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_calls_per_graph: usize,
    pub max_graph_depth: u8,
    pub max_private_lanes: usize,
    pub max_commitments_per_batch: usize,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_call_micro_fee: u64,
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
            sealed_callgraph_fee_market_suite: SEALED_CALLGRAPH_FEE_MARKET_SUITE.to_string(),
            pq_callgraph_attestation_suite: PQ_CALLGRAPH_ATTESTATION_SUITE.to_string(),
            private_execution_lane_suite: PRIVATE_EXECUTION_LANE_SUITE.to_string(),
            low_fee_batching_suite: LOW_FEE_BATCHING_SUITE.to_string(),
            replay_resistance_suite: REPLAY_RESISTANCE_SUITE.to_string(),
            deterministic_root_suite: DETERMINISTIC_ROOT_SUITE.to_string(),
            callgraph_window_blocks: DEFAULT_CALLGRAPH_WINDOW_BLOCKS,
            lane_window_blocks: DEFAULT_LANE_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_calls_per_graph: DEFAULT_MAX_CALLS_PER_GRAPH,
            max_graph_depth: DEFAULT_MAX_GRAPH_DEPTH,
            max_private_lanes: DEFAULT_MAX_PRIVATE_LANES,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_call_micro_fee: DEFAULT_BASE_CALL_MICRO_FEE,
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
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("post-quantum security below policy".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("privacy set below policy".to_string());
        }
        if self.max_calls_per_graph == 0
            || self.max_graph_depth == 0
            || self.max_private_lanes == 0
            || self.max_commitments_per_batch == 0
        {
            return Err("callgraph, lane, and batch limits must be nonzero".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
            || self.congestion_surcharge_bps > MAX_BPS
        {
            return Err("basis point configuration exceeds MAX_BPS".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub callgraph_commitments: u64,
    pub pending_callgraph_commitments: u64,
    pub private_execution_lanes: u64,
    pub active_private_execution_lanes: u64,
    pub pq_attestations: u64,
    pub authenticated_pq_attestations: u64,
    pub replay_guards: u64,
    pub consumed_replay_guards: u64,
    pub fee_quotes: u64,
    pub low_fee_batches: u64,
    pub settled_low_fee_batches: u64,
    pub state_commitments: u64,
    pub settlement_receipts: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub callgraph_commitment_root: String,
    pub private_execution_lane_root: String,
    pub pq_attestation_root: String,
    pub replay_guard_root: String,
    pub fee_quote_root: String,
    pub low_fee_batch_root: String,
    pub state_commitment_root: String,
    pub settlement_receipt_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            callgraph_commitment_root: merkle_root(CALLGRAPH_COMMITMENT_SCHEME, &[]),
            private_execution_lane_root: merkle_root(PRIVATE_EXECUTION_LANE_SCHEME, &[]),
            pq_attestation_root: merkle_root(PQ_ATTESTATION_SCHEME, &[]),
            replay_guard_root: merkle_root(REPLAY_GUARD_SCHEME, &[]),
            fee_quote_root: merkle_root(FEE_QUOTE_SCHEME, &[]),
            low_fee_batch_root: merkle_root(LOW_FEE_BATCH_SCHEME, &[]),
            state_commitment_root: merkle_root(STATE_COMMITMENT_SCHEME, &[]),
            settlement_receipt_root: merkle_root(SETTLEMENT_RECEIPT_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCallgraphCommitmentInput {
    pub contract_id: String,
    pub caller_commitment: String,
    pub domain: CallgraphDomain,
    pub sealed_entrypoint_root: String,
    pub sealed_callgraph_root: String,
    pub dependency_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateExecutionLaneInput {
    pub lane_operator_commitment: String,
    pub lane_class: LaneClass,
    pub capacity_units: u64,
    pub fair_share_weight: u64,
    pub congestion_oracle_root: String,
    pub opened_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqCallgraphAttestationInput {
    pub callgraph_id: String,
    pub lane_id: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeBatchInput {
    pub operator_id: String,
    pub lane_id: String,
    pub batch_epoch: u64,
    pub opened_height: u64,
    pub commitment_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCallgraphCommitment {
    pub callgraph_id: String,
    pub contract_id: String,
    pub caller_commitment: String,
    pub domain: CallgraphDomain,
    pub sealed_entrypoint_root: String,
    pub sealed_callgraph_root: String,
    pub dependency_root: String,
    pub read_set_root: String,
    pub write_set_root: String,
    pub replay_nullifier_root: String,
    pub lane_id: String,
    pub fee_quote_id: String,
    pub prior_state_root: String,
    pub expected_state_root: String,
    pub privacy_set_size: u64,
    pub call_count: u64,
    pub graph_depth: u8,
    pub max_fee_bps: u64,
    pub status: CallgraphStatus,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl SealedCallgraphCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "callgraph_id": self.callgraph_id,
            "contract_id": self.contract_id,
            "caller_commitment": self.caller_commitment,
            "domain": self.domain.as_str(),
            "sealed_entrypoint_root": self.sealed_entrypoint_root,
            "sealed_callgraph_root": self.sealed_callgraph_root,
            "dependency_root": self.dependency_root,
            "read_set_root": self.read_set_root,
            "write_set_root": self.write_set_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "lane_id": self.lane_id,
            "fee_quote_id": self.fee_quote_id,
            "prior_state_root": self.prior_state_root,
            "expected_state_root": self.expected_state_root,
            "privacy_set_size": self.privacy_set_size,
            "call_count": self.call_count,
            "graph_depth": self.graph_depth,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateExecutionLane {
    pub lane_id: String,
    pub lane_operator_commitment: String,
    pub lane_class: LaneClass,
    pub capacity_units: u64,
    pub fair_share_weight: u64,
    pub reserved_units: u64,
    pub committed_units: u64,
    pub congestion_oracle_root: String,
    pub current_fee_bps: u64,
    pub low_fee_eligible: bool,
    pub opened_height: u64,
    pub closes_height: u64,
    pub enabled: bool,
}

impl PrivateExecutionLane {
    pub fn available_units(&self) -> u64 {
        self.capacity_units.saturating_sub(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane_operator_commitment": self.lane_operator_commitment,
            "lane_class": self.lane_class.as_str(),
            "capacity_units": self.capacity_units,
            "fair_share_weight": self.fair_share_weight,
            "reserved_units": self.reserved_units,
            "committed_units": self.committed_units,
            "congestion_oracle_root": self.congestion_oracle_root,
            "current_fee_bps": self.current_fee_bps,
            "low_fee_eligible": self.low_fee_eligible,
            "opened_height": self.opened_height,
            "closes_height": self.closes_height,
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqCallgraphAttestation {
    pub attestation_id: String,
    pub callgraph_id: String,
    pub lane_id: String,
    pub callgraph_commitment_root: String,
    pub lane_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub predecessor_state_root: String,
    pub successor_state_root: String,
    pub status: AttestationStatus,
    pub pq_security_bits: u16,
    pub authenticated_height: u64,
}

impl PqCallgraphAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "callgraph_id": self.callgraph_id,
            "lane_id": self.lane_id,
            "callgraph_commitment_root": self.callgraph_commitment_root,
            "lane_commitment_root": self.lane_commitment_root,
            "transcript_root": self.transcript_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "predecessor_state_root": self.predecessor_state_root,
            "successor_state_root": self.successor_state_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "authenticated_height": self.authenticated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayGuard {
    pub replay_guard_id: String,
    pub callgraph_id: String,
    pub replay_nullifier_root: String,
    pub epoch_root: String,
    pub lane_id: String,
    pub status: ReplayGuardStatus,
    pub armed_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
}

impl ReplayGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "replay_guard_id": self.replay_guard_id,
            "callgraph_id": self.callgraph_id,
            "replay_nullifier_root": self.replay_nullifier_root,
            "epoch_root": self.epoch_root,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "armed_height": self.armed_height,
            "expires_height": self.expires_height,
            "consumed_height": self.consumed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeeQuote {
    pub fee_quote_id: String,
    pub callgraph_id: String,
    pub lane_id: String,
    pub base_micro_fee: u64,
    pub congestion_bps: u64,
    pub user_max_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub estimated_micro_fee: u64,
    pub low_fee_eligible: bool,
    pub quoted_height: u64,
    pub expires_height: u64,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_quote_id": self.fee_quote_id,
            "callgraph_id": self.callgraph_id,
            "lane_id": self.lane_id,
            "base_micro_fee": self.base_micro_fee,
            "congestion_bps": self.congestion_bps,
            "user_max_fee_bps": self.user_max_fee_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "estimated_micro_fee": self.estimated_micro_fee,
            "low_fee_eligible": self.low_fee_eligible,
            "quoted_height": self.quoted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub operator_id: String,
    pub lane_id: String,
    pub batch_epoch: u64,
    pub commitment_root: String,
    pub attestation_root: String,
    pub replay_guard_root: String,
    pub fee_quote_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub commitment_count: u64,
    pub aggregate_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
}

impl LowFeeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "lane_id": self.lane_id,
            "batch_epoch": self.batch_epoch,
            "commitment_root": self.commitment_root,
            "attestation_root": self.attestation_root,
            "replay_guard_root": self.replay_guard_root,
            "fee_quote_root": self.fee_quote_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "commitment_count": self.commitment_count,
            "aggregate_fee_micro_units": self.aggregate_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StateCommitment {
    pub state_commitment_id: String,
    pub subject_id: String,
    pub private_state_root: String,
    pub public_state_root: String,
    pub redaction_root: String,
    pub witness_commitment_root: String,
    pub committed_height: u64,
}

impl StateCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "state_commitment_id": self.state_commitment_id,
            "subject_id": self.subject_id,
            "private_state_root": self.private_state_root,
            "public_state_root": self.public_state_root,
            "redaction_root": self.redaction_root,
            "witness_commitment_root": self.witness_commitment_root,
            "committed_height": self.committed_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub settlement_root: String,
    pub fee_distribution_root: String,
    pub replay_guard_root: String,
    pub public_state_root: String,
    pub settled_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "settlement_root": self.settlement_root,
            "fee_distribution_root": self.fee_distribution_root,
            "replay_guard_root": self.replay_guard_root,
            "public_state_root": self.public_state_root,
            "settled_height": self.settled_height,
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
    pub callgraph_commitments: BTreeMap<String, SealedCallgraphCommitment>,
    pub private_execution_lanes: BTreeMap<String, PrivateExecutionLane>,
    pub pq_attestations: BTreeMap<String, PqCallgraphAttestation>,
    pub replay_guards: BTreeMap<String, ReplayGuard>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatch>,
    pub state_commitments: BTreeMap<String, StateCommitment>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            callgraph_commitments: BTreeMap::new(),
            private_execution_lanes: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_guards: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            state_commitments: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let lane_id = private_execution_lane_id(
            "devnet-callgraph-lane-operator-alpha",
            LaneClass::LowFeeBatch,
            DEVNET_EPOCH,
        );
        let callgraph_id = sealed_callgraph_commitment_id(
            CallgraphDomain::DefiRoute,
            "contract-private-router",
            "caller-commitment-alice",
            0,
        );
        let replay_nullifier_root = deterministic_root("replay-nullifier", "alice-route", 0);
        let fee_quote_id = fee_quote_id(&callgraph_id, &lane_id, DEVNET_HEIGHT);
        let replay_guard_id = replay_guard_id(&callgraph_id, &replay_nullifier_root, DEVNET_EPOCH);
        let attestation_id = pq_callgraph_attestation_id(&callgraph_id, &lane_id, 0);
        let operator_id = operator_id("devnet-callgraph-fee-market-operator", DEVNET_EPOCH);
        let batch_id = low_fee_batch_id(&operator_id, &lane_id, DEVNET_EPOCH, DEVNET_HEIGHT + 3);
        let state_commitment_id = state_commitment_id(&callgraph_id, "private-router-state", 0);
        let receipt_id = settlement_receipt_id(&batch_id, &lane_id, DEVNET_HEIGHT + 4);

        state.private_execution_lanes.insert(
            lane_id.clone(),
            PrivateExecutionLane {
                lane_id: lane_id.clone(),
                lane_operator_commitment: "devnet-callgraph-lane-operator-alpha".to_string(),
                lane_class: LaneClass::LowFeeBatch,
                capacity_units: 1_000_000,
                fair_share_weight: CallgraphDomain::DefiRoute.priority_weight(),
                reserved_units: 128_000,
                committed_units: 96_000,
                congestion_oracle_root: deterministic_root("congestion-oracle", "low-fee", 0),
                current_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
                low_fee_eligible: true,
                opened_height: DEVNET_HEIGHT,
                closes_height: DEVNET_HEIGHT + DEFAULT_LANE_WINDOW_BLOCKS,
                enabled: true,
            },
        );
        state.callgraph_commitments.insert(
            callgraph_id.clone(),
            SealedCallgraphCommitment {
                callgraph_id: callgraph_id.clone(),
                contract_id: "contract-private-router".to_string(),
                caller_commitment: "caller-commitment-alice".to_string(),
                domain: CallgraphDomain::DefiRoute,
                sealed_entrypoint_root: deterministic_root("sealed-entrypoint", "swap-route", 0),
                sealed_callgraph_root: deterministic_root("sealed-callgraph", "swap-route", 0),
                dependency_root: deterministic_root("dependency-root", "amm-vault-oracle", 0),
                read_set_root: deterministic_root("read-set", "private-router", 0),
                write_set_root: deterministic_root("write-set", "private-router", 0),
                replay_nullifier_root: replay_nullifier_root.clone(),
                lane_id: lane_id.clone(),
                fee_quote_id: fee_quote_id.clone(),
                prior_state_root: deterministic_root("prior-state", "private-router", 0),
                expected_state_root: deterministic_root("expected-state", "private-router", 1),
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                call_count: 7,
                graph_depth: 4,
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                status: CallgraphStatus::Executed,
                submitted_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_CALLGRAPH_WINDOW_BLOCKS,
            },
        );
        state.fee_quotes.insert(
            fee_quote_id.clone(),
            FeeQuote {
                fee_quote_id: fee_quote_id.clone(),
                callgraph_id: callgraph_id.clone(),
                lane_id: lane_id.clone(),
                base_micro_fee: DEFAULT_BASE_CALL_MICRO_FEE * 7,
                congestion_bps: DEFAULT_OPERATOR_FEE_BPS,
                user_max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
                batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
                estimated_micro_fee: 49,
                low_fee_eligible: true,
                quoted_height: DEVNET_HEIGHT,
                expires_height: DEVNET_HEIGHT + DEFAULT_BATCH_WINDOW_BLOCKS,
            },
        );
        state.replay_guards.insert(
            replay_guard_id.clone(),
            ReplayGuard {
                replay_guard_id: replay_guard_id.clone(),
                callgraph_id: callgraph_id.clone(),
                replay_nullifier_root: replay_nullifier_root.clone(),
                epoch_root: deterministic_root("epoch-root", "devnet-callgraph", DEVNET_EPOCH),
                lane_id: lane_id.clone(),
                status: ReplayGuardStatus::Consumed,
                armed_height: DEVNET_HEIGHT + 1,
                expires_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
                consumed_height: Some(DEVNET_HEIGHT + 4),
            },
        );
        state.pq_attestations.insert(
            attestation_id.clone(),
            PqCallgraphAttestation {
                attestation_id: attestation_id.clone(),
                callgraph_id: callgraph_id.clone(),
                lane_id: lane_id.clone(),
                callgraph_commitment_root: deterministic_root(
                    "callgraph-commitment",
                    "swap-route",
                    0,
                ),
                lane_commitment_root: deterministic_root("lane-commitment", "low-fee", 0),
                transcript_root: deterministic_root("pq-transcript", "swap-route", 0),
                pq_public_key_root: deterministic_root("pq-public-key", "operator-alpha", 0),
                pq_signature_root: deterministic_root("pq-signature", "callgraph-attestation", 0),
                predecessor_state_root: deterministic_root(
                    "predecessor-state",
                    "private-router",
                    0,
                ),
                successor_state_root: deterministic_root("successor-state", "private-router", 1),
                status: AttestationStatus::Applied,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                authenticated_height: DEVNET_HEIGHT + 2,
            },
        );
        state.low_fee_batches.insert(
            batch_id.clone(),
            LowFeeBatch {
                batch_id: batch_id.clone(),
                operator_id,
                lane_id: lane_id.clone(),
                batch_epoch: DEVNET_EPOCH,
                commitment_root: root_for_values(
                    CALLGRAPH_COMMITMENT_SCHEME,
                    &[json!(callgraph_id)],
                ),
                attestation_root: root_for_values(PQ_ATTESTATION_SCHEME, &[json!(attestation_id)]),
                replay_guard_root: root_for_values(REPLAY_GUARD_SCHEME, &[json!(replay_guard_id)]),
                fee_quote_root: root_for_values(FEE_QUOTE_SCHEME, &[json!(fee_quote_id)]),
                pre_state_root: deterministic_root(
                    "batch-pre-state",
                    "private-router",
                    DEVNET_EPOCH,
                ),
                post_state_root: deterministic_root(
                    "batch-post-state",
                    "private-router",
                    DEVNET_EPOCH,
                ),
                commitment_count: 1,
                aggregate_fee_micro_units: 49,
                rebate_micro_units: 1,
                status: BatchStatus::Settled,
                opened_height: DEVNET_HEIGHT,
                sealed_height: DEVNET_HEIGHT + 3,
            },
        );
        state.state_commitments.insert(
            state_commitment_id.clone(),
            StateCommitment {
                state_commitment_id,
                subject_id: callgraph_id.clone(),
                private_state_root: deterministic_root("private-state", "private-router", 1),
                public_state_root: deterministic_root("public-state", "private-router", 1),
                redaction_root: deterministic_root("redaction", "privacy-preserving", 0),
                witness_commitment_root: deterministic_root("witness", "private-router", 0),
                committed_height: DEVNET_HEIGHT + 4,
            },
        );
        state.settlement_receipts.insert(
            receipt_id.clone(),
            SettlementReceipt {
                receipt_id,
                batch_id,
                lane_id,
                settlement_root: deterministic_root("settlement", "low-fee-batch", 0),
                fee_distribution_root: deterministic_root("fee-distribution", "operator-rebate", 0),
                replay_guard_root: deterministic_root("receipt-replay-guard", "consumed", 0),
                public_state_root: deterministic_root("public-state", "private-router", 1),
                settled_height: DEVNET_HEIGHT + 4,
            },
        );

        state.recompute_counters();
        state.recompute_roots();
        let expected_state_root = state.state_root();
        let fixture_id = fixture_id("sealed-callgraph-fee-market-demo", 1);
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                label: "sealed-callgraph-fee-market-demo".to_string(),
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
            "kind": "private_l2_pq_confidential_contract_sealed_callgraph_fee_market_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_callgraph_fee_market_suite": SEALED_CALLGRAPH_FEE_MARKET_SUITE,
            "pq_callgraph_attestation_suite": PQ_CALLGRAPH_ATTESTATION_SUITE,
            "private_execution_lane_suite": PRIVATE_EXECUTION_LANE_SUITE,
            "low_fee_batching_suite": LOW_FEE_BATCHING_SUITE,
            "replay_resistance_suite": REPLAY_RESISTANCE_SUITE,
            "deterministic_root_suite": DETERMINISTIC_ROOT_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "callgraph_commitments": self.callgraph_commitments.values().map(SealedCallgraphCommitment::public_record).collect::<Vec<_>>(),
            "private_execution_lanes": self.private_execution_lanes.values().map(PrivateExecutionLane::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqCallgraphAttestation::public_record).collect::<Vec<_>>(),
            "replay_guards": self.replay_guards.values().map(ReplayGuard::public_record).collect::<Vec<_>>(),
            "fee_quotes": self.fee_quotes.values().map(FeeQuote::public_record).collect::<Vec<_>>(),
            "low_fee_batches": self.low_fee_batches.values().map(LowFeeBatch::public_record).collect::<Vec<_>>(),
            "state_commitments": self.state_commitments.values().map(StateCommitment::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
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
            callgraph_commitments: self.callgraph_commitments.len() as u64,
            pending_callgraph_commitments: self
                .callgraph_commitments
                .values()
                .filter(|commitment| commitment.status.pending())
                .count() as u64,
            private_execution_lanes: self.private_execution_lanes.len() as u64,
            active_private_execution_lanes: self
                .private_execution_lanes
                .values()
                .filter(|lane| lane.enabled)
                .count() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            authenticated_pq_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    matches!(
                        attestation.status,
                        AttestationStatus::Authenticated
                            | AttestationStatus::QuorumSigned
                            | AttestationStatus::Applied
                    )
                })
                .count() as u64,
            replay_guards: self.replay_guards.len() as u64,
            consumed_replay_guards: self
                .replay_guards
                .values()
                .filter(|guard| guard.status == ReplayGuardStatus::Consumed)
                .count() as u64,
            fee_quotes: self.fee_quotes.len() as u64,
            low_fee_batches: self.low_fee_batches.len() as u64,
            settled_low_fee_batches: self
                .low_fee_batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Settled)
                .count() as u64,
            state_commitments: self.state_commitments.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            callgraph_commitment_root: record_root(
                CALLGRAPH_COMMITMENT_SCHEME,
                &self
                    .callgraph_commitments
                    .values()
                    .map(SealedCallgraphCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            private_execution_lane_root: record_root(
                PRIVATE_EXECUTION_LANE_SCHEME,
                &self
                    .private_execution_lanes
                    .values()
                    .map(PrivateExecutionLane::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                &self
                    .pq_attestations
                    .values()
                    .map(PqCallgraphAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_guard_root: record_root(
                REPLAY_GUARD_SCHEME,
                &self
                    .replay_guards
                    .values()
                    .map(ReplayGuard::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_quote_root: record_root(
                FEE_QUOTE_SCHEME,
                &self
                    .fee_quotes
                    .values()
                    .map(FeeQuote::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_root: record_root(
                LOW_FEE_BATCH_SCHEME,
                &self
                    .low_fee_batches
                    .values()
                    .map(LowFeeBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            state_commitment_root: record_root(
                STATE_COMMITMENT_SCHEME,
                &self
                    .state_commitments
                    .values()
                    .map(StateCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_receipt_root: record_root(
                SETTLEMENT_RECEIPT_SCHEME,
                &self
                    .settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            fixture_root: record_root(
                FIXTURE_SCHEME,
                &self
                    .devnet_fixtures
                    .values()
                    .map(DevnetFixture::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }
}

pub fn sealed_callgraph_commitment_id(
    domain: CallgraphDomain,
    contract_id: &str,
    caller_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:CALLGRAPH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(caller_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn private_execution_lane_id(
    lane_operator_commitment: &str,
    lane_class: LaneClass,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:LANE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_operator_commitment),
            HashPart::Str(lane_class.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_callgraph_attestation_id(callgraph_id: &str, lane_id: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(callgraph_id),
            HashPart::Str(lane_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn replay_guard_id(callgraph_id: &str, replay_nullifier_root: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:REPLAY-GUARD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(callgraph_id),
            HashPart::Str(replay_nullifier_root),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn fee_quote_id(callgraph_id: &str, lane_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:FEE-QUOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(callgraph_id),
            HashPart::Str(lane_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn operator_id(operator_commitment: &str, epoch: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:OPERATOR-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::U64(epoch),
        ],
        32,
    )
}

pub fn low_fee_batch_id(operator_id: &str, lane_id: &str, epoch: u64, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_id),
            HashPart::Str(lane_id),
            HashPart::U64(epoch),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn state_commitment_id(subject_id: &str, label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:STATE-COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_id),
            HashPart::Str(label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, lane_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(lane_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:FIXTURE-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn estimate_call_count(sealed_callgraph_root: &str, max_calls_per_graph: usize) -> u64 {
    let ceiling = max_calls_per_graph.max(1) as u64;
    let score = sealed_callgraph_root
        .as_bytes()
        .iter()
        .fold(0u64, |acc, byte| acc.wrapping_add(*byte as u64));
    1 + (score % ceiling)
}

pub fn estimate_graph_depth(dependency_root: &str, max_graph_depth: u8) -> u8 {
    let ceiling = max_graph_depth.max(1);
    let score = dependency_root
        .as_bytes()
        .iter()
        .fold(0u8, |acc, byte| acc.wrapping_add(*byte));
    1 + (score % ceiling)
}

pub fn estimate_fee_micro_units(
    base_micro_fee: u64,
    congestion_bps: u64,
    operator_fee_bps: u64,
    rebate_bps: u64,
) -> u64 {
    let surcharge =
        base_micro_fee.saturating_mul(congestion_bps.saturating_add(operator_fee_bps)) / MAX_BPS;
    let rebate = base_micro_fee.saturating_mul(rebate_bps) / MAX_BPS;
    base_micro_fee
        .saturating_add(surcharge)
        .saturating_sub(rebate)
}

pub fn root_for_values(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-CALLGRAPH-FEE-MARKET:STATE-ROOT",
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
